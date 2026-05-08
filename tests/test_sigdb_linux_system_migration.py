"""sig_db Linux/system migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.linux_system import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. Cross-dict overlap kontrolu
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_LINUX_SYSTEM_SIGS`` referansi VAR.

Kapsam:
  - linux_syscall_signatures        (36 entry)
  - linux_syscall_ext_signatures    (213 entry)
  - libc_ext_signatures             (150 entry)

Toplam: 399 imza.
"""
from __future__ import annotations

import pytest


_EXPECTED_KEYS = {
    "linux_syscall_signatures",
    "linux_syscall_ext_signatures",
    "libc_ext_signatures",
}

_EXPECTED_COUNTS = {
    "linux_syscall_signatures": 36,
    "linux_syscall_ext_signatures": 213,
    "libc_ext_signatures": 150,
}

_TOTAL_EXPECTED = 399

_KEY_TO_ORIG = {
    "linux_syscall_signatures": "_LINUX_SYSCALL_SIGNATURES",
    "linux_syscall_ext_signatures": "_LINUX_SYSCALL_EXT_SIGNATURES",
    "libc_ext_signatures": "_LIBC_EXT_SIGNATURES",
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_linux_system_importable() -> None:
    """sigdb_builtin.linux_system import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import linux_system

    assert hasattr(linux_system, "SIGNATURES")
    assert isinstance(linux_system.SIGNATURES, dict)
    assert len(linux_system.SIGNATURES) == 3


def test_sigdb_builtin_linux_system_has_expected_keys() -> None:
    """SIGNATURES 3 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import linux_system

    assert set(linux_system.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_sigdb_builtin_linux_system_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import linux_system

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(linux_system.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in linux_system.SIGNATURES.values())
    assert total == _TOTAL_EXPECTED, (
        f"Total LINUX entry count: expected {_TOTAL_EXPECTED}, got {total}"
    )


# ---------------------------------------------------------------------------
# 2. Cross-dict overlap kontrolu
# ---------------------------------------------------------------------------

def test_no_duplicate_keys_within_dicts() -> None:
    """Python dict olarak tekildirler; sayim birebir."""
    from karadul.analyzers.sigdb_builtin import linux_system

    for key, dct in linux_system.SIGNATURES.items():
        assert len(dct) == _EXPECTED_COUNTS[key]


def test_syscall_vs_syscall_ext_no_overlap() -> None:
    """linux_syscall ve linux_syscall_ext anahtar kesişimi olmamali."""
    from karadul.analyzers.sigdb_builtin import linux_system

    sc = set(linux_system.SIGNATURES["linux_syscall_signatures"])
    sc_ext = set(linux_system.SIGNATURES["linux_syscall_ext_signatures"])
    overlap = sc & sc_ext
    assert not overlap, f"linux_syscall <-> linux_syscall_ext kesişimi: {overlap}"


# ---------------------------------------------------------------------------
# 3. Runtime identity — signature_db legacy attribute == builtin SIGNATURES alt-key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin linux_system[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import linux_system

    legacy = getattr(sdb, legacy_name)
    migrated = linux_system.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Bilindik sembol noktasal kontrolleri
# ---------------------------------------------------------------------------

def test_known_linux_syscall_symbols_present() -> None:
    """Klasik Linux-only syscall'lar yerinde."""
    from karadul.analyzers.sigdb_builtin import linux_system

    sc = linux_system.SIGNATURES["linux_syscall_signatures"]
    assert "epoll_create" in sc
    assert sc["epoll_create"]["category"] == "linux_io"
    assert "prctl" in sc
    assert "seccomp" in sc
    assert "io_uring_setup" in sc
    assert "inotify_init" in sc
    assert "memfd_create" in sc
    assert "unshare" in sc


def test_known_libc_ext_symbols_present() -> None:
    """libc_ext: dlmopen, memmem, fmemopen vs."""
    from karadul.analyzers.sigdb_builtin import linux_system

    libc = linux_system.SIGNATURES["libc_ext_signatures"]
    assert len(libc) == 150
    assert "dlmopen" in libc or "dlinfo" in libc
    sample_key = next(iter(libc))
    sample_entry = libc[sample_key]
    assert "lib" in sample_entry
    assert "purpose" in sample_entry
    assert "category" in sample_entry


def test_entry_schema_consistency() -> None:
    """Her entry {lib, purpose, category} string anahtar tasimali."""
    from karadul.analyzers.sigdb_builtin import linux_system

    required_keys = {"lib", "purpose", "category"}
    for cat_key, dct in linux_system.SIGNATURES.items():
        for sym, entry in dct.items():
            assert isinstance(entry, dict), f"{cat_key}::{sym} entry dict degil"
            assert required_keys <= set(entry.keys()), (
                f"{cat_key}::{sym} eksik anahtar: {required_keys - set(entry.keys())}"
            )
            for k in required_keys:
                assert isinstance(entry[k], str), f"{cat_key}::{sym}::{k} string degil"


# ---------------------------------------------------------------------------
# 5. Post-A-DELETE: legacy literal silindi, dogrudan referans kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_LINUX_SYSCALL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_LINUX_SYSTEM_SIGS["linux_syscall_signatures"]'
    ) in text
    assert (
        '_LIBC_EXT_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_LINUX_SYSTEM_SIGS["libc_ext_signatures"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py LINUX SIGNATURES'i ``sigdb_builtin.linux_system``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_LINUX_SYSTEM_SIGS" in text
    assert "sigdb_builtin" in text and "linux_system" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
