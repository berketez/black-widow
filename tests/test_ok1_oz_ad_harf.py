"""ÖK-1: ``string_context`` klasik aşamasında kanıt dizgisi tek bir C tanımlayıcısıysa ad dizginin
kendisi (harf, rakam ve belirteç sayısı korunur); bayrak ``binary_reconstruction.oz_ad_verbatim``.

Kusur (``docs/arge/2026-11-19_mythos/ozkod/BULGULAR.md`` §1.2): kanıt zaten tanımlayıcıyken ad
anahtar sözcüklerden yeniden kurulup küçük harfe çevriliyordu (``ZSTD_getCParamsFromCDict`` →
``zstd_getcparamsfromcdict``). Alt kanal yüklemi (``alt_kanal._is_own_name``, tanım sürümü 2)
harfi korunan adı da ``oz_ad`` sayar; yoksa ad ``tanimlayici``'ya düşer ve susar.

Kilitlenen davranışlar (plan adım 5'in (a)–(g) satırları):
  (a) karışık harfli tanımlayıcı aynen ad olur; (b) rakamlı tanımlayıcı aynen;
  (c) küçük harfli üç parçalı tanımlayıcıda bayrak açık / kapalı aynı ad;
  (d) düz metin kanıtta yol değişmez; (e) tamamı büyük harf → bugünkü yol;
  (f) bayrak kapalıyken (a) bugünkü küçük harfli ad; (g) alt kanal ``oz_ad``, uçtan uca da
  (gerçek süreç havuzu: bayrak işçiye config ile gider).
Mutasyon koruması: ``scripts/measurement/mutation_specs_ok1.json``.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer
from karadul.reconstruction.tarif import alt_kanal

SUSAN = alt_kanal.SILENCED_SUBCHANNELS


def _config(verbatim: bool) -> Config:
    cfg = Config()
    cfg.binary_reconstruction.oz_ad_verbatim = verbatim
    return cfg


def _klasik(strings: list[str], *, verbatim: bool = True, susan=SUSAN):
    """Gerçek _strategy_string_context; dizgiler fonksiyonun dizgi bağları (string_ref)."""
    namer = CVariableNamer(_config(verbatim), min_confidence=0.15, silenced_subchannels=susan)
    namer._string_refs_by_func["0x1000"] = list(strings)
    namer._func_bodies["FUN_00001000"] = ""
    namer._strategy_string_context(
        SimpleNamespace(name="FUN_00001000", address="0x1000", params=[]))
    adaylar = [c for c in namer._candidates.get("FUN_00001000", []) if c.code_path == "classic"]
    assert len(adaylar) == 1, adaylar
    return adaylar[0]


def _alt(c) -> str:
    return CVariableNamer._string_sub_channel(c)


# --- (a) … (f): ad ---------------------------------------------------------------------------


def test_a_karisik_harfli_tanimlayici_aynen():
    c = _klasik(["ZSTD_getCParamsFromCDict"])
    assert c.new_name == "ZSTD_getCParamsFromCDict"
    assert c.evidence == "ZSTD_getCParamsFromCDict"
    assert (c.strategy, c.code_path, c.rule) == ("string_context", "classic", "keywords")
    # Güven formülü değişmez: anahtar sözcük sayısından (zstd, getcparamsfromcdict → 2).
    assert c.confidence == pytest.approx(0.8)
    assert _alt(c) == alt_kanal.SUB_OWN_NAME


def test_b_rakamli_tanimlayici_aynen():
    c = _klasik(["ieee754_from_blob"])
    assert c.new_name == "ieee754_from_blob"
    assert _alt(c) == alt_kanal.SUB_OWN_NAME
    # Bayrak kapalıyken anahtar sözcük yolu rakamı düşürür ve aday susar (tanimlayici).
    k = _klasik(["ieee754_from_blob"], verbatim=False)
    assert k.new_name == "ieee_blob"  # rakam ve durak sözcük düşer
    assert _alt(k) == alt_kanal.SUB_IDENTIFIER


def test_c_kucuk_harfli_uc_parca_bayraktan_bagimsiz():
    acik = _klasik(["screen_write_scrollregion"])
    kapali = _klasik(["screen_write_scrollregion"], verbatim=False)
    assert acik.new_name == kapali.new_name == "screen_write_scrollregion"
    assert _alt(acik) == _alt(kapali) == alt_kanal.SUB_OWN_NAME
    assert acik.confidence == kapali.confidence


def test_d_duz_metin_kanitta_yol_degismez():
    acik = _klasik(["Failed to open database"])
    kapali = _klasik(["Failed to open database"], verbatim=False)
    assert acik.new_name == kapali.new_name == "open_database"
    assert _alt(acik) == _alt(kapali)


@pytest.mark.parametrize("kanit", ["EXIT_FAILURE", "window", "_private", "trailing_ ",
                                   "has space_x y"])
def test_e_kosulu_tutmayan_kanitta_bugunku_yol(kanit):
    """Tamamı büyük harf, alt çizgisiz tek sözcük, yalnız baştaki / sondaki alt çizgi, boşluk."""
    acik = _klasik([kanit])
    kapali = _klasik([kanit], verbatim=False)
    assert acik.new_name == kapali.new_name
    assert acik.new_name != kanit.strip() or kanit.strip() == kanit.strip().lower()


def test_e2_bastaki_sondaki_bosluk_atilir():
    c = _klasik(["  ZSTD_compressBlock_lazy2\n"])
    assert c.new_name == "ZSTD_compressBlock_lazy2"
    assert _alt(c) == alt_kanal.SUB_OWN_NAME


def test_f_bayrak_kapaliyken_bugunku_kucuk_harfli_ad():
    c = _klasik(["ZSTD_getCParamsFromCDict"], verbatim=False)
    assert c.new_name == "zstd_getcparamsfromcdict"
    assert _alt(c) == alt_kanal.SUB_OWN_NAME


def test_f2_bayrak_alani_yoksa_kapali_sayilir():
    namer = CVariableNamer(_config(True))
    namer._config = SimpleNamespace(binary_reconstruction=SimpleNamespace())
    assert namer._oz_ad_verbatim_name("ZSTD_getCParamsFromCDict") is None
    namer._config = None
    assert namer._oz_ad_verbatim_name("ZSTD_getCParamsFromCDict") is None


# --- (g): alt kanal yüklemi (sürüm 2) -------------------------------------------------------


def test_g_is_own_name_surum_2():
    assert alt_kanal.DEFINITION_VERSION == 2
    e = "ZSTD_getCParamsFromCDict"
    assert alt_kanal.classify(evidence=e, name=e, code_path="classic",
                              evidence_origin="string_ref") == alt_kanal.SUB_OWN_NAME
    assert alt_kanal.classify(evidence=e, name=e.lower(), code_path="classic",
                              evidence_origin="string_ref") == alt_kanal.SUB_OWN_NAME
    # Başka harf karışımı ya da başka ad öz-ad değildir.
    assert alt_kanal.classify(evidence=e, name="Zstd_GetCParamsFromCDict", code_path="classic",
                              evidence_origin="string_ref") != alt_kanal.SUB_OWN_NAME
    assert alt_kanal.classify(evidence=e, name="zstd_getcparams", code_path="classic",
                              evidence_origin="string_ref") != alt_kanal.SUB_OWN_NAME


def test_g2_surum_1_kabul_ettigini_surum_2_de_kabul_eder():
    """Küçük harfli ad için yüklem eskisiyle aynı (bayrak kapalı kolun sınıflaması değişmez)."""
    for e in ("cmdq_append", "grid_set_cells", "TERM_PROGRAM_VERSION", "ZSTD_x_y", "a_b"):
        s = alt_kanal.classify(evidence=e, name=e.lower(), code_path="classic",
                               evidence_origin="string_ref")
        eski = (alt_kanal.IDENTIFIER_RE.match(e) is not None and "_" in e
                and any(ch.islower() for ch in e))
        assert (s == alt_kanal.SUB_OWN_NAME) == eski, e


# --- uçtan uca: gerçek süreç havuzu ---------------------------------------------------------


def _calisma_alani(kok: Path) -> dict[str, Path]:
    static = kok / "static"
    dec = static / "decompiled"
    dec.mkdir(parents=True)
    fonks = [("FUN_00001000", "00001000"), ("FUN_00002000", "00002000")]
    dizgiler = [("00010000", "ZSTD_getCParamsFromCDict", "00001000"),
                ("00010100", "EXIT_FAILURE", "00002000")]
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


@pytest.mark.parametrize("verbatim, beklenen", [
    (True, "ZSTD_getCParamsFromCDict"), (False, "zstd_getcparamsfromcdict")])
def test_gercek_havuzda_harf_korunur(tmp_path, verbatim, beklenen):
    ws = _calisma_alani(tmp_path / "ws")
    out = tmp_path / "out"
    namer = CVariableNamer(_config(verbatim), min_confidence=0.15, silenced_subchannels=SUSAN,
                           global_min_confidence=0.7)
    res = namer.analyze_and_rename(ws["dec"], ws["functions"], ws["strings"],
                                   ws["call_graph"], out)
    assert res.success, res.errors
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))["global"]
    prov = json.loads((out / "naming_provenance.json").read_text(encoding="utf-8"))["global"]
    assert nm.get("FUN_00001000") == beklenen
    assert prov["FUN_00001000"]["sub_channel"] == alt_kanal.SUB_OWN_NAME
    assert prov["FUN_00001000"]["evidence"] == "ZSTD_getCParamsFromCDict"
    # Tamamı büyük harfli kanıt bu yola girmez (ad yok ya da bayraktan bağımsız).
    assert nm.get("FUN_00002000") in (None, "exit_failure")
