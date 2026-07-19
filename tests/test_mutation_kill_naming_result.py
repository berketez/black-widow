"""Mutation-kill testleri -- reconstruction/naming karar delikleri (TAM-SUITE).

Sonraki-kademe mutasyon denetiminde TAM suite'e karsi HAYATTA kalan (masking
yok, gercek) iki delik:

  RA  result.NamingManifest.add_result esitlik-kirilimi: `result.confidence >
      existing.confidence` (STRICT). Esit guvende ILK gelen korunur (deterministik,
      "ilk kazanir"). Mutant `>=` sonuncuyu yazar -> deterministik olmayan/son-kazanir
      davranis. Hicbir test esit-guven senaryosunu kurmuyordu.

  N1  npm_fingerprinter.NpmFingerprinter._match_module esik kapisi:
      `if matched < min_match: continue` (STRICT). matched == min_match INCLUSIVE
      kabul edilir (tam esik = eslesme). Mutant `<=` bu sinir vakasini eler ->
      esik-degeri modul eslesmeden dusuruludur. npm scoring yalnizca tek testte
      (fingerprint_all mock'lu) kullanildigi icin _match_module gecidi olcumsuzdu.
"""

from __future__ import annotations

from karadul.reconstruction.naming.npm_fingerprinter import NpmFingerprinter
from karadul.reconstruction.naming.result import NamingManifest, NamingResult


def _mk(module_id: str, new_filename: str, confidence: float,
        source: str) -> NamingResult:
    return NamingResult(
        module_id=module_id,
        original_file=f"{module_id}.js",
        new_filename=new_filename,
        category="tools",
        description="d",
        confidence=confidence,
        source=source,
    )


# ---------------------------------------------------------------------------
# RA: add_result esitlik-kirilimi -- esitlikte ILK korunur
# ---------------------------------------------------------------------------


def test_add_result_equal_confidence_keeps_first() -> None:
    """Esit guvende ILK eklenen korunur (`>` strict). Mutant `>=` sonuncuyu yazar.

    Esit guven yaygin (ayni katmanin iki adayi). "Ilk kazanir" deterministik
    davranistir; `>=`'e kayma sessizce son-kazanir yapar.
    """
    m = NamingManifest()
    m.add_result(_mk("modX", "first-name.js", 0.5, "npm_fingerprint"))
    m.add_result(_mk("modX", "second-name.js", 0.5, "structural"))
    # Orijinal: 0.5 > 0.5 False -> ilk korunur. Mutant `>=`: ikinci ezer.
    assert m.results["modX"].new_filename == "first-name.js"
    assert m.results["modX"].source == "npm_fingerprint"

    # Regresyon capasi: KESIN daha yuksek guven yine de gunceller.
    m.add_result(_mk("modX", "third-name.js", 0.9, "structural"))
    assert m.results["modX"].new_filename == "third-name.js"


# ---------------------------------------------------------------------------
# N1: min_match esik kapisi -- matched == min_match INCLUSIVE
# ---------------------------------------------------------------------------


def test_min_match_boundary_is_inclusive() -> None:
    """matched == min_match tam sinirinda eslesme URETILMELI (`<` strict gate).

    Mutant `matched <= min_match` bu sinir vakasini `continue` ile eler -> None.
    """
    sigs = {
        "pkgfoo": {
            "strings": ["ALPHA_TOKEN_XZ", "BETA_TOKEN_QW"],
            "category": "vendor/foo",
            "min_match": 2,
        },
    }
    fp = NpmFingerprinter(signatures=sigs)

    # Iki anchor da var -> matched == 2 == min_match (tam sinir).
    content = "function m(){ return ALPHA_TOKEN_XZ + BETA_TOKEN_QW; }"
    result = fp._match_module(content, "mod1")
    assert result is not None, "tam-esik (matched==min_match) eslesme uretmeli"
    assert result.npm_package == "pkgfoo"

    # Kapi yonu capasi: esik ALTI (matched=1 < 2) eslesmemeli.
    content_below = "function m(){ return ALPHA_TOKEN_XZ; }"
    assert fp._match_module(content_below, "mod2") is None
