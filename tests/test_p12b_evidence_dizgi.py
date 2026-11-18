"""P12b kalem 6 — ``tarif/evidence.py``: dizgi sabitindeki ``FUN_…`` metni geri çağrı değildir.

Sorun (P22a yan bulgusu): ``build_evidence`` geri çağrı kaydını çağrı argümanlarının HAM metninden
çıkarıyordu; argümandaki dizgi sabitinde geçen ``FUN_<hex>`` / ``LAB_<hex>`` geri çağrı sayılıyordu.
Gerçek veride (14 çalışma alanı, 403 kayıt) 0 örnek; ama düşman bir ikili (dizgilerine adres
yazan) KaradulLM kanıt paketine sahte "geri çağrı olarak verildi" ilişkisi sokabilirdi.

Onarım: dizgi ve karakter sabitlerinin içi çağrı aranmadan önce boşaltılır.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_tarif import _static_dir  # noqa: E402

from karadul.reconstruction.tarif.evidence import build_evidence  # noqa: E402

FONKSIYONLAR = [
    {"name": "_event_set", "address": "100009000", "is_external": True},
    {"name": "_printf", "address": "100009100", "is_external": True},
    {"name": "FUN_100001000", "address": "100001000"},
    {"name": "FUN_100002000", "address": "100002000"},
    {"name": "FUN_100003000", "address": "100003000"},
]


def _xrefs():
    bos = {"functions_called": [], "called_by": [], "strings_used": []}
    return {a: {"name": f"FUN_{a}", **bos} for a in ("100001000", "100002000", "100003000")}


def _paketler(tmp_path, govde):
    return build_evidence(_static_dir(tmp_path, FONKSIYONLAR, _xrefs(), {"100001000": govde}))


def test_dizgi_icindeki_fun_geri_cagri_sayilmaz(tmp_path):
    p = _paketler(tmp_path, 'void f(void){ _printf("handler=FUN_100002000 at LAB_100003000\\n"); }')
    assert p["100001000"].callback_registrations == []
    assert p["100002000"].registered_as_callback == []
    assert p["100003000"].registered_as_callback == []


def test_gercek_argumandaki_fun_sayilmaya_devam_eder(tmp_path):
    govde = ('void f(void){ _event_set(e,"FUN_100003000;{x}",0,FUN_100002000,q);'
             " _printf('\"',FUN_100003000); }")
    p = _paketler(tmp_path, govde)
    # dizgideki ``;`` ``{`` çağrı eşleşmesini bozmaz; gerçek başvurular kalır, dizgideki düşer
    assert p["100001000"].callback_registrations == [
        {"api": "event_set", "target": "100002000"}, {"api": "printf", "target": "100003000"}]
    assert p["100002000"].registered_as_callback == [{"api": "event_set", "registrar": "100001000"}]
    assert p["100003000"].registered_as_callback == [{"api": "printf", "registrar": "100001000"}]


def test_kacisli_tirnak_dizgiyi_erken_bitirmez(tmp_path):
    p = _paketler(tmp_path, r'void f(void){ _printf("a\"FUN_100002000\" b"); }')
    assert p["100001000"].callback_registrations == []
