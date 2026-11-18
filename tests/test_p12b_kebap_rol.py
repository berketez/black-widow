"""P12b — AD-01: kebap dizgisi (``monitor-silence``) fonksiyon adı değil; rolü köken kaydında kanıt.

Sorun (AD-01, ölçüldü): ``string_context`` klasik yolu fonksiyonun başvurduğu tireli küçük harf
dizgiden ad kuruyordu; dizgi fonksiyonun okuduğu SEÇENEĞİN ya da yaydığı OLAYIN adıdır. urun-yeni2'de
239 ad, tam eşitlikte 0 doğru; N0b'nin kör etiketlerinde gevşek başarı 6 / 76. N0b'nin ``belirsiz``
kararı "yalnız alan" etiketini yanlış saymadığı için kanal açık kalmıştı.

Kural (P12b ön kaydı §2-§3): ``kebap_ad`` kararı ``zayif`` (ürün susturma kümesinde); her genel
anahtarın kebap adayı için dizginin rolü ``naming_provenance.json`` → ``string_roles``'a yazılır
(anahtar erişimi / olay yayar / karşılaştırma / az örnekli çağrı / çağrı dışı), susturma açık da
kapalı da. Ad seçimi bu kayıttan etkilenmez.

Mutasyon koruması: ``scripts/measurement/mutation_specs_p12b.json``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_ad_gecerliligi as G  # noqa: E402
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal as A  # noqa: E402


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _govde(ad: str, satirlar: str) -> str:
    return f"void {ad}(long param_1)\n{{\n{satirlar}  return;\n}}\n"


def _alan(root: Path):
    """tmux biçiminde küçük ikili: bir anahtarlı erişimci (FUN_00009000), bir olay yayıcı
    (FUN_00008000), ``strcmp`` ile karşılaştırma ve çağrı dışı bir kebap dizgisi."""
    f = [
        ("FUN_00001000", "00001000", ["monitor-silence", "silence-action"],
         '  FUN_00009000(param_1,"monitor-silence");\n  FUN_00009000(param_1,"silence-action");\n'),
        ("FUN_00002000", "00002000", ["bell-action"],
         '  lVar1 = FUN_00009000(*(long *)(param_1 + 8),"bell-action");\n'),
        ("FUN_00003000", "00003000", ["window-renamed"],
         '  FUN_00008000("window-renamed",param_1);\n'),
        ("FUN_00004000", "00004000", ["window-linked"],
         '  FUN_00008000("window-linked",param_1);\n'),
        ("FUN_00005000", "00005000", ["read-only"],
         '  iVar1 = strcmp((char *)param_1,"read-only");\n'),
        ("FUN_00006000", "00006000", ["even-horizontal"],
         '  DAT_00030000 = "even-horizontal";\n'),
    ]
    return G._calisma_alani(root, [G._fonk(ad, adres, dizgiler=d, govde=_govde(ad, g))
                                   for ad, adres, d, g in f]
                            + [G._fonk("FUN_00008000", "00008000"), G._fonk("FUN_00009000", "00009000")])


BEKLENEN_ROLLER = {
    "FUN_00001000": [{"string": "monitor-silence", "role": "anahtar_erisimi", "api": "FUN_00009000",
                      "arg_index": 1, "api_distinct_strings": 3, "emitters": 1,
                      "function_kebab_strings": 2}],
    "FUN_00002000": [{"string": "bell-action", "role": "anahtar_erisimi", "api": "FUN_00009000",
                      "arg_index": 1, "api_distinct_strings": 3, "emitters": 1,
                      "function_kebab_strings": 1}],
    "FUN_00003000": [{"string": "window-renamed", "role": "olay_yayar", "api": "FUN_00008000",
                      "arg_index": 0, "api_distinct_strings": 2, "emitters": 1,
                      "function_kebab_strings": 1}],
    "FUN_00004000": [{"string": "window-linked", "role": "olay_yayar", "api": "FUN_00008000",
                      "arg_index": 0, "api_distinct_strings": 2, "emitters": 1,
                      "function_kebab_strings": 1}],
    "FUN_00005000": [{"string": "read-only", "role": "karsilastirma", "api": "strcmp",
                      "arg_index": 1, "api_distinct_strings": 1, "emitters": 1,
                      "function_kebab_strings": 1}],
    "FUN_00006000": [{"string": "even-horizontal", "role": "cagri_disi", "api": None,
                      "arg_index": None, "api_distinct_strings": 0, "emitters": 0,
                      "function_kebab_strings": 1}],
}


def test_kebap_adi_urunde_ad_olmaz_rol_kanit_olur(tmp_path, seri):
    # Ürün ayarı: hat susan kümeyi ve ürün eşiğini verir (feedback_loop).
    res, prov, harita = S._kos(_alan(tmp_path / "ws"), tmp_path / "out",
                               silenced_subchannels=A.SILENCED_SUBCHANNELS, global_min_confidence=0.7)
    for anahtar in BEKLENEN_ROLLER:
        assert anahtar not in harita["global"], (anahtar, harita["global"].get(anahtar))
    assert prov["silencing"]["candidates_dropped"].get("kebap_ad") == len(BEKLENEN_ROLLER)
    assert prov["string_roles"] == BEKLENEN_ROLLER
    assert prov["string_role_version"] == A.STRING_ROLE_VERSION == 1
    assert S._hesap_tutar(prov)


def test_rol_kaydi_susturmadan_bagimsiz_ve_secimi_degistirmez(tmp_path, seri):
    # Susturma kapalı (öntanımlı kurucu): eski davranış (kebap adı verilir), rol kaydı yine yazılır.
    res, prov, harita = S._kos(_alan(tmp_path / "ws"), tmp_path / "out")
    assert harita["global"]["FUN_00001000"] == "monitor_silence"
    assert prov["string_roles"] == BEKLENEN_ROLLER


def test_kebap_karari_zayif_ve_susar():
    assert A.SUBCHANNEL_DECISIONS["kebap_ad"] == A.DECISION_WEAK
    assert A.is_silenced("kebap_ad") and A.label_for("kebap_ad") is None
    assert A.KEPT_SUBCHANNELS == ("oz_ad",)


def test_literal_call_site_sinirlari():
    g = 'x = FUN_1(a, g(b, c), "k-a"); y = "k-b"; if (strcmp(s,"k-c") == 0) { return FUN_2("k-d"); }'
    yerler = A.kebab_call_sites(g)
    assert yerler == [("k-a", "FUN_1", 2), ("k-b", "", -1), ("k-c", "strcmp", 1), ("k-d", "FUN_2", 0)]
    # anahtar sözcük çağrı sayılmaz; köşeli parantez derinliği sayılır
    assert A.kebab_call_sites('if ("k-e") {}') == [("k-e", "", -1)]
    assert A.kebab_call_sites('f(t[i], "k-f")') == [("k-f", "f", 1)]
    # kebap olmayan literal (büyük harf, tek parça, alt çizgi) alınmaz
    assert A.kebab_call_sites('f("Mon-Act", "word", "a_b")') == []


def test_rol_esikleri():
    def idx(govdeler):
        return A.KebabIndex(dict(govdeler))
    # iki farklı anahtar alan erişimci: anahtar erişimi değil (eşik 3)
    i = idx({"F1": 'g(o,"a-b");', "F2": 'g(o,"c-d");'})
    assert i.role("F1", "a-b")["role"] == A.ROLE_SPARSE_CALL
    i = idx({"F1": 'g(o,"a-b");', "F2": 'g(o,"c-d");', "F3": 'g(o,"e-f");'})
    assert i.role("F1", "a-b")["role"] == A.ROLE_KEYED_ACCESS
    # olay: bütün dizgiler -ed; biri değilse olay değil
    i = idx({"F1": 'n("w-changed",p);', "F2": 'n("w-linked",p);'})
    assert i.role("F1", "w-changed")["role"] == A.ROLE_EVENT_EMIT
    i = idx({"F1": 'n("w-changed",p);', "F2": 'n("w-link",p);'})
    assert i.role("F1", "w-changed")["role"] == A.ROLE_SPARSE_CALL
    # tek -ed dizgisi olay sayılmaz (eşik 2)
    i = idx({"F1": 'n("w-changed",p);'})
    assert i.role("F1", "w-changed")["role"] == A.ROLE_SPARSE_CALL
    # aynı olayı iki fonksiyon yayar
    i = idx({"F1": 'n("w-changed",p);', "F2": 'n("w-changed",q);', "F3": 'n("x-linked",q);'})
    assert i.role("F1", "w-changed")["emitters"] == 2
    # Mach-O: baştaki alt çizgi soyulur
    i = idx({"F1": 'iVar1 = _strcmp(s,"k-a");'})
    assert i.role("F1", "k-a")["role"] == A.ROLE_COMPARISON
    # gövdede olmayan fonksiyon: çağrı dışı
    assert i.role("YOK", "k-a")["role"] == A.ROLE_NOT_CALL_ARG
    # fonksiyondaki farklı kebap dizgisi sayısı: aynı literalin tekrarı bir sayılır
    i = idx({"F1": 'g(o,"a-b"); g(o,"a-b"); h("c-d");'})
    assert i.role("F1", "a-b")["function_kebab_strings"] == 2


def test_rol_sozluk_sirasindan_bagimsiz():
    govdeler = {f"F{n}": f'g(o,"k-{n % 4}"); n("e{n % 2}-done",p);' for n in range(12)}
    ters = dict(reversed(list(govdeler.items())))
    a, b = A.KebabIndex(govdeler), A.KebabIndex(ters)
    for f in govdeler:
        for s, _, _ in a.sites[f]:
            assert a.role(f, s) == b.role(f, s)
