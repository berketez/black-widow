"""P12d D1: susacak agresif aday klasik dizgi aşamasının önünü kesmez (K-2).

``_strategy_string_context`` agresif adayın güveni >= 0,75 olunca klasik aşamaya geçmeden
dönüyordu. Agresif alt kanal N0b kararıyla susar (``olculemedi``); dönüş, susacak bir aday
yüzünden klasik aşamanın kalan alt kanala düşen adayını hiç kurdurmuyordu. Onarım: erken dönüş
yalnız agresif aday susmayacaksa. Susturma kapalıyken davranış aynı (tek aday).

Not: tanıda (``docs/arge/2026-11-18_onarim/P12d.md``) birleşik ölçümün 27 kayıp adının hiçbiri
bu yoldan değildi; 119 ikilide bu dönüşün örttüğü kalan aday 1.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer
from karadul.reconstruction.tarif import alt_kanal

ED_SUSAN = alt_kanal.SILENCED_SUBCHANNELS
ED_AGRESIF = "helperFunc()"          # func_paren 0,80 → helperfunc (agresif: susar)
ED_OZ_AD = "cycle_check_state"       # klasik: cycle, check, state → oz_ad (kalır), puan 15
ED_SINIF = "CFoo::BarBaz"            # class_method 0,85; klasik adayı da susar (diger)


def _adaylar(strings: list[str], *, susan=ED_SUSAN) -> list:
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=susan)
    namer._string_refs_by_func["0x1000"] = list(strings)
    namer._func_bodies["FUN_00001000"] = ""
    namer._strategy_string_context(
        SimpleNamespace(name="FUN_00001000", address="0x1000", params=[]))
    return namer._candidates.get("FUN_00001000", [])


def _susturma_sonrasi(strings: list[str]) -> list:
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=ED_SUSAN)
    namer._string_refs_by_func["0x1000"] = list(strings)
    namer._func_bodies["FUN_00001000"] = ""
    namer._strategy_string_context(
        SimpleNamespace(name="FUN_00001000", address="0x1000", params=[]))
    namer._silence_candidates(ED_SUSAN, None)
    return namer._candidates.get("FUN_00001000", [])


def test_susan_agresif_075_klasigi_durdurmaz():
    """Susturma açık: agresif 0,80 (susar) + klasik aday kurulur."""
    c = _adaylar([ED_AGRESIF, ED_OZ_AD])
    assert [(x.code_path, x.new_name) for x in c] == [
        ("aggressive", "helperfunc"), ("classic", "cycle_check_state")]


def test_susturma_kapaliyken_erken_doner():
    """Susturma kapalı: eski davranış, yalnız agresif aday."""
    c = _adaylar([ED_AGRESIF, ED_OZ_AD], susan=frozenset())
    assert [(x.code_path, x.new_name) for x in c] == [("aggressive", "helperfunc")]


def test_agresif_susmuyorsa_erken_doner():
    """Agresif alt kanal susan kümede değilse (ör. yalnız kebap susuyor) erken dönüş kalır."""
    c = _adaylar([ED_AGRESIF, ED_OZ_AD], susan=frozenset({alt_kanal.SUB_KEBAB_NAME}))
    assert [x.code_path for x in c] == ["aggressive"]


def test_agresif_ve_klasik_aday_klasik_ad_cikar():
    """Paket §5: agresif aday var + klasik aday var → susturmadan sonra klasik ad kalır."""
    kalan = _susturma_sonrasi([ED_AGRESIF, ED_OZ_AD])
    assert [(x.new_name, x.code_path) for x in kalan] == [("cycle_check_state", "classic")]


def test_yalniz_agresif_ad_yok():
    """Paket §5: yalnız agresif (ve klasik adayı da susan dizgi) → ad yok."""
    assert _adaylar([ED_SINIF])[0].code_path == "aggressive"
    assert _susturma_sonrasi([ED_SINIF]) == []


def test_hicbiri_ad_yok():
    assert _susturma_sonrasi([]) == []


def _calisma_alani(kok: Path) -> dict[str, Path]:
    static = kok / "static"
    dec = static / "decompiled"
    dec.mkdir(parents=True)
    fonks = [("FUN_00001000", "00001000"), ("FUN_00002000", "00002000")]
    dizgiler = [("00010000", ED_AGRESIF, "00001000"), ("00010100", ED_OZ_AD, "00001000"),
                ("00010200", ED_SINIF, "00002000")]
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": n, "address": a, "size": 64, "parameters": [], "return_type": "void",
         "calling_convention": "cdecl"} for n, a in fonks]}), encoding="utf-8")
    (static / "ghidra_strings.json").write_text(json.dumps({"strings": [
        {"address": a, "value": v, "length": len(v), "type": "string", "function": None,
         "xrefs": [{"from_address": a, "from_function": "FUN_" + f, "from_func_addr": f}]}
        for a, v, f in dizgiler]}), encoding="utf-8")
    (static / "ghidra_call_graph.json").write_text(json.dumps({
        "nodes": {a: {"name": n, "address": a} for n, a in fonks}, "edges": []}),
        encoding="utf-8")
    for n, a in fonks:
        (dec / f"{n}.c").write_text(
            f"// Function: {n}\n// Address: {a}\n\nvoid {n}(void)\n{{\n  return;\n}}\n",
            encoding="utf-8")
    return {"dec": dec, "functions": static / "ghidra_functions.json",
            "strings": static / "ghidra_strings.json",
            "call_graph": static / "ghidra_call_graph.json"}


def test_gercek_havuzda_klasik_ad_verilir(tmp_path):
    """Gerçek ProcessPool + susturma + ürün eşiği (0,7): işçi süreç susan kümeyi görmeli;
    FUN_1000 klasik öz-ad adını alır, FUN_2000 (yalnız susan adaylar) adsız kalır."""
    ws = _calisma_alani(tmp_path / "ws")
    out = tmp_path / "out"
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=ED_SUSAN,
                           global_min_confidence=0.7)
    res = namer.analyze_and_rename(ws["dec"], ws["functions"], ws["strings"],
                                   ws["call_graph"], out)
    assert res.success, res.errors
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))["global"]
    prov = json.loads((out / "naming_provenance.json").read_text(encoding="utf-8"))["global"]
    assert nm.get("FUN_00001000") == "cycle_check_state"
    assert prov["FUN_00001000"]["code_path"] == "classic"
    assert prov["FUN_00001000"]["sub_channel"] == alt_kanal.SUB_OWN_NAME
    assert "FUN_00002000" not in nm
