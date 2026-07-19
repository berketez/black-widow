"""Mutasyon-oldurucu testler: signature_db confidence hesaplama.

Faz-1 mutasyon denetimi 3 GERCEK deligi (tam-suite survived) buldu:

  B1  signature_db.py:2635  match_function final:
        `return max(candidates, key=lambda m: m.confidence)`  -> `min`
  B2  signature_db.py:2453  _match_by_strings:
        `conf = min(0.92, 0.65 + len(keywords)*0.07)`  -> `min(0.92, 0.65)`
  B3  signature_db.py:2523  _match_by_calls:
        `conf = base_conf * (0.7 + 0.3*coverage)`  -> `base_conf`

Testler builtin sig'leri temizleyip SADECE kontrollu imza(lar) ekler; boylece
sonuc deterministik ve tek bir formul dalina baglidir.

Kanit (mutation_probe, TUM suite):
  python scripts/mutation_probe.py --spec docs/mutation_specs.json \
      --id b1_match_function_max_to_min,b2_match_strings_keyword_bonus,\
b3_match_calls_coverage_factor
"""
from __future__ import annotations

import pytest

from karadul.analyzers.signature_db import SignatureDB


def _clean_db() -> SignatureDB:
    """Builtin imzalari temizlenmis, izole bir SignatureDB.

    Boylece testte eklenen imzalar disinda hicbir eslesme olusmaz -> sonuc
    deterministik. LMDB/byte/symbol yollari da bosaltilir.
    """
    db = SignatureDB()
    with db._lock:
        db._string_sigs = {}
        db._call_sigs = []
        db._byte_signatures = []
        db._symbol_db = {}
        db._lmdb_backend = None
        # AC automaton'i bayatlat -> lazy yeniden build (bos DB).
        db._string_sigs_version += 1
    return db


# ---------------------------------------------------------------------------
# B1: match_function final secim = max(confidence)
# ---------------------------------------------------------------------------

def test_match_function_returns_highest_confidence_candidate() -> None:
    """Iki katman ayni fonksiyona eslesirse YUKSEK guvenli olan donmeli.

    string katmani -> conf 0.72 ("STRING_LOW")
    call   katmani -> conf 0.90 ("CALL_HIGH", base 0.90 x tam coverage)
    max -> CALL_HIGH. Mutant `min` -> STRING_LOW -> assert patlar (KILLED).
    """
    db = _clean_db()
    # string sig: tek keyword -> conf = min(0.92, 0.65+1*0.07) = 0.72
    db.add_string_signature(
        frozenset({"onlymarkerstr"}), "STRING_LOW", "libtest", "low path",
    )
    # call sig: base_conf 0.90, tam coverage -> conf = 0.90*(0.7+0.3*1.0) = 0.90
    db.add_call_pattern(
        frozenset({"onlymarkercall"}), "CALL_HIGH", "libtest", "high path",
        confidence=0.90,
    )

    match = db.match_function(
        func_name="FUN_00abcdef",
        strings_used=["onlymarkerstr"],
        callees=["onlymarkercall"],
    )

    assert match is not None
    assert match.matched_name == "CALL_HIGH", (
        f"max(confidence) YUKSEK adayi (CALL_HIGH 0.90) secmeliydi, "
        f"donen: {match.matched_name!r} @ {match.confidence}"
    )
    assert match.confidence == pytest.approx(0.90)


# ---------------------------------------------------------------------------
# B2: _match_by_strings keyword-sayisi bonusu
# ---------------------------------------------------------------------------

def test_match_by_strings_confidence_scales_with_keyword_count() -> None:
    """3-keyword string imzasi -> conf = min(0.92, 0.65 + 3*0.07) = 0.86.

    Mutant `min(0.92, 0.65)` -> 0.65 (keyword bonusu silinir) -> KILLED.
    """
    db = _clean_db()
    db.add_string_signature(
        frozenset({"kw_alpha", "kw_beta", "kw_gamma"}),
        "THREE_KW", "libtest", "3-keyword sig",
    )

    match = db._match_by_strings(["kw_alpha", "kw_beta", "kw_gamma"])

    assert match is not None
    assert match.matched_name == "THREE_KW"
    assert match.confidence == pytest.approx(0.86), (
        f"3-keyword conf 0.65+3*0.07=0.86 olmaliydi, donen: {match.confidence}"
    )


# ---------------------------------------------------------------------------
# B3: _match_by_calls coverage carpani
# ---------------------------------------------------------------------------

def test_match_by_calls_confidence_scaled_by_coverage() -> None:
    """Pattern, fonksiyon callee'lerinin STRICT subset'i (coverage < 1).

    pattern = {a, b}, callees = [a, b, c, d] -> coverage = 2/4 = 0.5
    conf = base(0.80) * (0.7 + 0.3*0.5) = 0.80 * 0.85 = 0.68 < base.
    Mutant `conf = base_conf` -> 0.80 (coverage cezasi kaybolur) -> KILLED.
    """
    db = _clean_db()
    base = 0.80
    db.add_call_pattern(
        frozenset({"a", "b"}), "SUBSET_HIT", "libtest", "strict subset",
        confidence=base,
    )

    match = db._match_by_calls(["a", "b", "c", "d"])

    assert match is not None
    assert match.matched_name == "SUBSET_HIT"
    expected = base * (0.7 + 0.3 * 0.5)  # 0.68
    assert match.confidence == pytest.approx(expected), (
        f"coverage=0.5 -> conf {expected} olmaliydi, donen: {match.confidence}"
    )
    assert match.confidence < base, (
        "STRICT subset (coverage<1) icin conf base_conf'un ALTINDA olmali; "
        f"donen {match.confidence} >= base {base}"
    )
