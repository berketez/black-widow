"""sig_db Strings/STL/Boost migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.strings_module import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. Cross-key kesişme yok
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_STRINGS_MODULE_SIGS`` referansi VAR.

Kapsam (4 alt-kategori, 193 imza):
  - cpp_stl   (60 entry)  -> _CPP_STL_SIGNATURES
  - boost     (58 entry)  -> _BOOST_SIGNATURES
  - abseil    (43 entry)  -> _ABSEIL_SIGNATURES
  - folly     (32 entry)  -> _FOLLY_SIGNATURES
"""
from __future__ import annotations

import pytest


_KEY_TO_ORIG: dict[str, str] = {
    "cpp_stl": "_CPP_STL_SIGNATURES",
    "boost": "_BOOST_SIGNATURES",
    "abseil": "_ABSEIL_SIGNATURES",
    "folly": "_FOLLY_SIGNATURES",
}

_EXPECTED_COUNTS: dict[str, int] = {
    "cpp_stl": 60,
    "boost": 58,
    "abseil": 43,
    "folly": 32,
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilirlik
# ---------------------------------------------------------------------------

def test_sigdb_builtin_strings_module_importable() -> None:
    """sigdb_builtin.strings_module import edilebilir ve dolu SIGNATURES var."""
    from karadul.analyzers.sigdb_builtin import strings_module as mod

    assert hasattr(mod, "SIGNATURES")
    assert isinstance(mod.SIGNATURES, dict)
    assert len(mod.SIGNATURES) == 4


def test_sigdb_builtin_strings_module_has_expected_keys() -> None:
    """SIGNATURES tam olarak 4 beklenen anahtari icerir."""
    from karadul.analyzers.sigdb_builtin import strings_module as mod

    assert set(mod.SIGNATURES.keys()) == set(_KEY_TO_ORIG.keys())


def test_coverage_count() -> None:
    """Her alt-kategori beklenen entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import strings_module as mod

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in mod.SIGNATURES.values())
    assert total == 193, f"Total strings_module entry count: expected 193, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher
# ---------------------------------------------------------------------------

def test_get_category_strings_module_returns_data() -> None:
    """Dispatcher dolu strings_module kategori verisi dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("strings_module")
    assert isinstance(sigs, dict)
    assert len(sigs) == 4
    for key in _KEY_TO_ORIG:
        assert key in sigs
    assert sum(len(v) for v in sigs.values()) == 193


# ---------------------------------------------------------------------------
# 3. Runtime identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin strings_module[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    legacy = getattr(sdb, legacy_name)
    migrated = SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Modul-ici saglik
# ---------------------------------------------------------------------------

def test_no_duplicate_keys() -> None:
    """Bir sembol birden fazla alt-kategoride durmamali."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    seen: dict[str, str] = {}
    duplicates: list[tuple[str, str, str]] = []
    for cat, entries in SIGNATURES.items():
        for sym in entries:
            if sym in seen:
                duplicates.append((sym, seen[sym], cat))
            else:
                seen[sym] = cat
    assert not duplicates, f"Anahtar kesişimi tespit edildi: {duplicates[:5]}"


def test_all_entries_have_required_fields() -> None:
    """Her entry {lib, purpose, category} icermeli."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    required = {"lib", "purpose", "category"}
    bad: list[tuple[str, str, set]] = []
    for cat, entries in SIGNATURES.items():
        for sym, data in entries.items():
            missing = required - set(data.keys())
            if missing:
                bad.append((cat, sym, missing))
    assert not bad, f"Eksik alan tespit edildi: {bad[:5]}"


def test_known_stl_symbols_present() -> None:
    """Klasik STL/ABI sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    stl = SIGNATURES["cpp_stl"]
    for sym in (
        "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev",
        "___cxa_throw",
        "___cxa_pure_virtual",
        "__Znwm",
        "__ZdlPv",
        "__ZSt9terminatev",
    ):
        assert sym in stl, f"{sym} cpp_stl dict'inde olmali"
    libs = {entry["lib"] for entry in stl.values()}
    assert {"libc++", "libc++abi"}.issubset(libs), (
        f"cpp_stl hem libc++ hem libc++abi icermeli, mevcut: {libs}"
    )


def test_known_boost_symbols_present() -> None:
    """Boost klasik sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    boost = SIGNATURES["boost"]
    for sym in (
        "__ZN5boost4asio10io_context",
        "__ZN5boost10filesystem4path",
        "__ZN5boost6thread",
        "__ZN5boost5regex",
    ):
        assert sym in boost, f"{sym} boost dict'inde olmali"
        assert boost[sym]["lib"] == "boost"


def test_known_abseil_symbols_present() -> None:
    """Abseil klasik sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    absl = SIGNATURES["abseil"]
    for sym in (
        "__ZN4absl6StrCat",
        "__ZN4absl6Status",
        "__ZN4absl5Mutex",
        "__ZN4absl3Now",
    ):
        assert sym in absl, f"{sym} abseil dict'inde olmali"
        assert absl[sym]["lib"] == "abseil"


def test_known_folly_symbols_present() -> None:
    """Folly klasik sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES

    folly = SIGNATURES["folly"]
    for sym in (
        "__ZN5folly6Future",
        "__ZN5folly5IOBuf",
        "__ZN5folly9Singleton",
        "__ZN5folly9parseJson",
    ):
        assert sym in folly, f"{sym} folly dict'inde olmali"
        assert folly[sym]["lib"] == "folly"


# ---------------------------------------------------------------------------
# 5. Post-A-DELETE: legacy literal silindi, dogrudan referans
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_CPP_STL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_STRINGS_MODULE_SIGS["cpp_stl"]'
    ) in text
    assert (
        '_BOOST_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_STRINGS_MODULE_SIGS["boost"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py strings_module SIGNATURES'i ``sigdb_builtin.strings_module``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_STRINGS_MODULE_SIGS" in text
    assert "sigdb_builtin" in text and "strings_module" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
