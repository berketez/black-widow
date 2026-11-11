"""Arayüz, temiz ad haritasının 1.1 biçimini okur: koda uygulanmamış kayıtlar ``candidates``
bölümündedir ve kütüphane çağrısı ipucu ``library`` alanını oradan da bulmalıdır.

Biçim 1.1 ``karadul/core/output_formatter.py``'de yazılır (``_build_naming_map``). Arayüz yalnız
``mappings``'e baksaydı ipucu satırları sessizce kaybolurdu (ölçüm: tree'de 219 ipucu → 0;
``docs/arge/2026-11-11_temiz_harita/sonuc.md``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parents[1] / "ui" / "server.py"


@pytest.fixture()
def srv():
    spec = importlib.util.spec_from_file_location("ui_server_temiz_harita", SERVER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop(spec.name, None)


def _kosu(tmp_path: Path, harita: dict) -> str:
    """``<kosu>/clean/{report.json,naming_map.json}`` ve altında bir çalışma alanı dizini."""
    temiz = tmp_path / "kosu" / "clean"
    temiz.mkdir(parents=True)
    (temiz / "report.json").write_text("{}", encoding="utf-8")
    (temiz / "naming_map.json").write_text(json.dumps(harita), encoding="utf-8")
    ws = tmp_path / "kosu" / "ws"
    ws.mkdir()
    return str(ws)


HARITA_1_1 = {
    "version": "1.1",
    "mappings": {"FUN_00101000": {"new_name": "parse_args", "source": "c_namer"}},
    "candidates": {
        "strlen": {"new_name": "strlen", "source": "signature_db", "library": "libc",
                   "reason": "same_as_original"},
        "_malloc": {"new_name": "malloc", "source": "signature_db", "library": "libc",
                    "reason": "not_in_code"},
    },
}


def test_bicim_1_1_adaylar_ve_eslemeler_birlikte_okunur(srv, tmp_path):
    ws = _kosu(tmp_path, HARITA_1_1)
    cmap = srv._clean_mappings(ws)
    assert set(cmap) == {"FUN_00101000", "strlen", "_malloc"}
    assert cmap["FUN_00101000"]["new_name"] == "parse_args"


def test_kutuphane_ipucu_aday_kaydindan_gelir(srv, tmp_path):
    ws = _kosu(tmp_path, HARITA_1_1)
    cmap = srv._clean_mappings(ws)
    ipuclari = srv._external_call_hints("x = strlen(p); q = _malloc(x); FUN_00101000();", cmap)
    assert sorted(ipuclari) == ["_malloc çağrılıyor", "strlen çağrılıyor"]


def test_ayni_anahtarda_esleme_adayi_ezer(srv, tmp_path):
    harita = {"version": "1.1",
              "mappings": {"FUN_1": {"new_name": "uygulanan"}},
              "candidates": {"FUN_1": {"new_name": "aday"}}}
    ws = _kosu(tmp_path, harita)
    assert srv._clean_mappings(ws)["FUN_1"]["new_name"] == "uygulanan"


def test_bicim_1_0_haritasi_aynen_okunur(srv, tmp_path):
    harita = {"version": "1.0",
              "mappings": {"strlen": {"new_name": "strlen", "library": "libc"}}}
    ws = _kosu(tmp_path, harita)
    cmap = srv._clean_mappings(ws)
    assert set(cmap) == {"strlen"}
    assert srv._external_call_hints("strlen(p);", cmap) == ["strlen çağrılıyor"]
