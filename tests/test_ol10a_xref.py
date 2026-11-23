"""OL10A: ``ghidra_xrefs.json``'ın K1 çıktılarından türetilmesi (``OL10_TASARIM.md`` §1.3)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from karadul.core import tembel_xref as tx

DEPO = Path(__file__).resolve().parents[1]


def _kuru():
    spec = importlib.util.spec_from_file_location(
        "tembel_kuru_xtest", DEPO / "scripts" / "measurement" / "tembel_kuru.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tembel_kuru_xtest"] = mod
    spec.loader.exec_module(mod)
    return mod


FDOC = {"program": "p", "functions": [
    {"address": "00001000", "name": "FUN_00001000"},
    {"address": "00002000", "name": "FUN_00002000"},
    {"address": "00003000", "name": "puts", "is_thunk": True},
]}
SDOC = {"program": "p", "strings": [
    {"address": "00009000", "value": "b", "xrefs": [
        {"from_address": "00001010", "from_func_addr": "00001000"},
        {"from_address": "_elfSectionHeaders::000000d0", "from_func_addr": None}]},
    {"address": "00008000", "value": "a", "xrefs": [
        {"from_address": "00001020", "from_func_addr": "00001000"},
        {"from_address": "00001008", "from_func_addr": "00001000"},
        {"from_address": "00002004", "from_func_addr": "00002000"}]},
    {"address": "00007000", "value": "yalniz", "xrefs": []},
]}
CDOC = {"program": "p", "nodes": {
    "00001000": {"name": "FUN_00001000", "address": "00001000",
                 "callers": [], "callees": [{"name": "puts", "address": "00003000"},
                                            {"name": "FUN_00002000", "address": "00002000"}]},
    "00002000": {"name": "FUN_00002000", "address": "00002000",
                 "callers": [{"name": "zz", "address": "00001000"},
                             {"name": "aa", "address": "000009f0"}],
                 "callees": []},
}}

BEKLENEN_XREF = {
    "program": "p",
    "statistics": {"total_functions": 3, "total_strings_with_xrefs": 2,
                   "total_globals_with_xrefs": None},
    "function_xrefs": {
        "00001000": {"name": "FUN_00001000", "address": "00001000",
                     "strings_used": [{"address": "00008000", "value": "a"},
                                      {"address": "00009000", "value": "b"}],
                     "functions_called": [{"name": "puts", "address": "00003000"},
                                          {"name": "FUN_00002000", "address": "00002000"}],
                     "called_by": []},
        "00002000": {"name": "FUN_00002000", "address": "00002000",
                     "strings_used": [{"address": "00008000", "value": "a"}],
                     "functions_called": [],
                     "called_by": [{"name": "aa", "address": "000009f0"},
                                   {"name": "zz", "address": "00001000"}]},
        "00003000": {"name": "puts", "address": "00003000", "strings_used": [],
                     "functions_called": [], "called_by": []},
    },
    "kapsam": "tam_nufus",
    "kaynak": "turetildi",
}


def test_turetme_beklenen_belgeyle_esit():
    assert tx.turet(FDOC, SDOC, CDOC) == BEKLENEN_XREF


def test_strings_used_baskuranin_adresine_gore_ve_tekil():
    su = tx.turet(FDOC, SDOC, CDOC)["function_xrefs"]["00001000"]["strings_used"]
    # 00001008 (a) < 00001010 (b) < 00001020 (a, yinelenen): a önce, bir kez
    assert [s["address"] for s in su] == ["00008000", "00009000"]


def test_called_by_adrese_gore_tam_sayiyla_functions_called_sirasi_korunur():
    fx = tx.turet(FDOC, SDOC, CDOC)["function_xrefs"]
    assert [c["address"] for c in fx["00002000"]["called_by"]] == ["000009f0", "00001000"]
    assert [c["address"] for c in fx["00001000"]["functions_called"]] == ["00003000", "00002000"]


def test_istatistik_globals_null_kapsam_kaynak():
    d = tx.turet(FDOC, SDOC, CDOC)
    assert d["statistics"]["total_globals_with_xrefs"] is None
    assert d["kapsam"] == tx.KAPSAM_TAM_NUFUS and d["kaynak"] == tx.KAYNAK_TURETILDI
    assert list(d)[:3] == ["program", "statistics", "function_xrefs"]


def test_bos_belgeler():
    d = tx.turet({"functions": []}, None, None)
    assert d["function_xrefs"] == {} and d["statistics"]["total_functions"] == 0


def _ws(tmp_path: Path, xrefs: dict) -> Path:
    st = tmp_path / "ws" / "static"
    st.mkdir(parents=True)
    for ad, doc in (("functions", FDOC), ("strings", SDOC), ("call_graph", CDOC), ("xrefs", xrefs)):
        (st / f"ghidra_{ad}.json").write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path / "ws"


def test_kuru_arac_xref_denetimi_esit_ve_fark_sayimi(tmp_path):
    kuru = _kuru()
    dokum = json.loads(json.dumps(BEKLENEN_XREF))
    dokum["statistics"]["total_globals_with_xrefs"] = 5
    ws = _ws(tmp_path, dokum)
    docs = tuple(json.loads((ws / "static" / f"ghidra_{a}.json").read_text())
                 for a in ("functions", "strings", "call_graph"))
    r = kuru.xref_denetle(ws / "static", docs)
    assert r["json_esit_sira_normal"] and r["json_esit_ham"]
    # P16e öncesi döküm: çağıran sırası farklı → ham fark, sıra-normal eşit
    dokum["function_xrefs"]["00002000"]["called_by"].reverse()
    dokum["function_xrefs"]["00001000"]["strings_used"].reverse()
    (ws / "static" / "ghidra_xrefs.json").write_text(json.dumps(dokum), encoding="utf-8")
    r = kuru.xref_denetle(ws / "static", docs)
    assert r["sayim"]["called_by_ham"] == 1 and "called_by_sira_normal" not in r["sayim"]
    assert r["sayim"]["strings_used_sira"] == 1
    assert not r["json_esit_sira_normal"]


def test_kuru_arac_uctan_uca(tmp_path):
    kuru = _kuru()
    ws = _ws(tmp_path, BEKLENEN_XREF)
    cikti = tmp_path / "o.json"
    assert kuru.main(["--ws", str(ws), "--permutasyon", "3", "--xref-denetle",
                      "--ust-sinir", "1", "--cikti", str(cikti)]) == 0
    d = json.loads(cikti.read_text())
    assert d["kunye"]["sinif_sayimi"]["TASLAK"] == 1
    assert d["kunye"]["basamak_sayimi"]["B3"] == 2 and d["kunye"]["basamak_sayimi"]["B6"] == 1
    assert d["permutasyon"]["hepsi_ayni_ve_esit"] is True
    assert d["kesim"]["secili"] == 1
    assert d["xref"]["json_esit_sira_normal"] is True
