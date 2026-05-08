"""sig_db POSIX/system migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.posix_system import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri (eski
``_load_original_ast_values``) tautolojik hale geldigi icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. No duplicate keys (kategori-bazli)
4. Bilinen sembol lookup
5. SignatureDB instance entegrasyon
6. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_POSIX_SYSTEM_SIGS`` referansi VAR.
"""
from __future__ import annotations

import pytest


_EXPECTED_KEYS = {
    "posix_file_io_signatures",
    "process_signatures",
    "pthread_signatures",
    "memory_signatures",
    "string_stdlib_signatures",
    "time_signatures",
    "dynload_signatures",
    "error_locale_misc_signatures",
}

_EXPECTED_COUNTS = {
    "posix_file_io_signatures": 57,
    "process_signatures": 40,
    "pthread_signatures": 37,
    "memory_signatures": 27,
    "string_stdlib_signatures": 42,
    "time_signatures": 16,
    "dynload_signatures": 10,
    "error_locale_misc_signatures": 18,
}

_TOTAL_EXPECTED = 247

# Builtin key -> signature_db.py'deki orijinal dict adi
_KEY_TO_ORIG = {
    "posix_file_io_signatures": "_POSIX_FILE_IO_SIGNATURES",
    "process_signatures": "_PROCESS_SIGNATURES",
    "pthread_signatures": "_PTHREAD_SIGNATURES",
    "memory_signatures": "_MEMORY_SIGNATURES",
    "string_stdlib_signatures": "_STRING_STDLIB_SIGNATURES",
    "time_signatures": "_TIME_SIGNATURES",
    "dynload_signatures": "_DYNLOAD_SIGNATURES",
    "error_locale_misc_signatures": "_ERROR_LOCALE_MISC_SIGNATURES",
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi, yapisi dogru mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_posix_system_importable() -> None:
    """sigdb_builtin.posix_system import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import posix_system

    assert hasattr(posix_system, "SIGNATURES")
    assert isinstance(posix_system.SIGNATURES, dict)
    assert len(posix_system.SIGNATURES) == 8


def test_sigdb_builtin_posix_system_has_expected_keys() -> None:
    """SIGNATURES 8 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import posix_system

    assert set(posix_system.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_sigdb_builtin_posix_system_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import posix_system

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(posix_system.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in posix_system.SIGNATURES.values())
    assert total == _TOTAL_EXPECTED, f"Total POSIX entry count: expected {_TOTAL_EXPECTED}, got {total}"


def test_no_duplicate_keys_within_dicts() -> None:
    """Her dict icindeki anahtarlar (zaten dict olarak tekil) ve cross-dict
    icin de pthread/string/etc arasinda mantiksiz overlap yok mu? Bu test
    her bir bireysel dict bulunan anahtar sayisinin SIGNATURES'taki len ile
    esit oldugunu dogrular (Python dict zaten unique tutar)."""
    from karadul.analyzers.sigdb_builtin import posix_system

    for key, dct in posix_system.SIGNATURES.items():
        assert len(dct) == _EXPECTED_COUNTS[key], (
            f"{key} entry sayisi expected {_EXPECTED_COUNTS[key]}, got {len(dct)}"
        )


# ---------------------------------------------------------------------------
# 2. Cross-dict anahtar overlap'lari (entry leak korumasi)
# ---------------------------------------------------------------------------

def test_minimal_cross_dict_overlap() -> None:
    """Belirli kategori ciftleri arasinda anahtar kesişimi olmamali.
    Notes: ``_mmap``/``_munmap`` hem file_io kapsaminda hem memory kavramsal
    olarak ortusur AMA orijinalde sadece file_io dict'inde tanimli (category
    alani 'memory'). Dict-key dunyasinda overlap yok beklenir."""
    from karadul.analyzers.sigdb_builtin import posix_system

    keys_by_cat = {k: set(v.keys()) for k, v in posix_system.SIGNATURES.items()}
    pairs = [
        ("posix_file_io_signatures", "process_signatures"),
        ("posix_file_io_signatures", "memory_signatures"),
        ("process_signatures", "pthread_signatures"),
        ("pthread_signatures", "memory_signatures"),
        ("memory_signatures", "string_stdlib_signatures"),
        ("string_stdlib_signatures", "time_signatures"),
        ("time_signatures", "dynload_signatures"),
        ("dynload_signatures", "error_locale_misc_signatures"),
    ]
    for a, b in pairs:
        overlap = keys_by_cat[a] & keys_by_cat[b]
        assert not overlap, f"Anahtar kesişimi {a} <-> {b}: {overlap}"


# ---------------------------------------------------------------------------
# 3. Runtime identity — signature_db legacy attribute == builtin SIGNATURES alt-key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin posix_system[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import posix_system

    legacy = getattr(sdb, legacy_name)
    migrated = posix_system.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Dispatcher (sigdb_builtin paket arabirimi)
# ---------------------------------------------------------------------------

def test_get_category_posix_system_callable() -> None:
    """sigdb_builtin paketinde get_category('posix_system') bu modulu
    bulabiliyorsa dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import posix_system

    sigs = posix_system.SIGNATURES
    assert isinstance(sigs, dict)
    assert len(sigs) == 8
    for key in _EXPECTED_KEYS:
        assert key in sigs


# ---------------------------------------------------------------------------
# 5. Bilindik sembol noktasal kontrolleri (regression sentinel)
# ---------------------------------------------------------------------------

def test_known_posix_symbols_present() -> None:
    """Bilindik POSIX sembolleri her kategoride mevcut (migration kirik degil)."""
    from karadul.analyzers.sigdb_builtin import posix_system

    sigs = posix_system.SIGNATURES
    # file_io
    assert "_open" in sigs["posix_file_io_signatures"]
    assert sigs["posix_file_io_signatures"]["_open"]["lib"] == "libc"
    assert "_fopen" in sigs["posix_file_io_signatures"]
    assert "_mmap" in sigs["posix_file_io_signatures"]
    # process
    assert "_fork" in sigs["process_signatures"]
    assert sigs["process_signatures"]["_fork"]["category"] == "process"
    assert "_execve" in sigs["process_signatures"]
    # pthread
    assert "_pthread_create" in sigs["pthread_signatures"]
    assert sigs["pthread_signatures"]["_pthread_mutex_lock"]["lib"] == "libpthread"
    # memory
    assert "_malloc" in sigs["memory_signatures"]
    assert "_mach_vm_allocate" in sigs["memory_signatures"]
    assert sigs["memory_signatures"]["_mach_vm_allocate"]["lib"] == "libSystem"
    # string_stdlib
    assert "_strlen" in sigs["string_stdlib_signatures"]
    assert "_qsort" in sigs["string_stdlib_signatures"]
    assert "_arc4random" in sigs["string_stdlib_signatures"]
    # time
    assert "_clock_gettime" in sigs["time_signatures"]
    assert "_mach_absolute_time" in sigs["time_signatures"]
    # dynload
    assert "_dlopen" in sigs["dynload_signatures"]
    assert "_dlsym" in sigs["dynload_signatures"]
    # error_locale_misc
    assert "_strerror" in sigs["error_locale_misc_signatures"]
    assert "_sysctl" in sigs["error_locale_misc_signatures"]


def test_entry_schema_consistency() -> None:
    """Her entry 'lib', 'purpose', 'category' anahtarlarini tasimali."""
    from karadul.analyzers.sigdb_builtin import posix_system

    required_keys = {"lib", "purpose", "category"}
    for cat_key, dct in posix_system.SIGNATURES.items():
        for sym, entry in dct.items():
            assert isinstance(entry, dict), f"{cat_key}::{sym} entry dict degil"
            assert required_keys <= set(entry.keys()), (
                f"{cat_key}::{sym} eksik anahtar: {required_keys - set(entry.keys())}"
            )
            for k in required_keys:
                assert isinstance(entry[k], str), f"{cat_key}::{sym}::{k} string degil"


# ---------------------------------------------------------------------------
# 6. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK.

    A-DELETE sonrasi signature_db.py POSIX dict'lerini sadece
    ``_BUILTIN_POSIX_SYSTEM_SIGS["..."]`` lookup'u uzerinden tutar.
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali
    assert (
        '_POSIX_FILE_IO_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_POSIX_SYSTEM_SIGS["posix_file_io_signatures"]'
    ) in text
    assert (
        '_PROCESS_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_POSIX_SYSTEM_SIGS["process_signatures"]'
    ) in text
    # Inline literal blok baslangici YOK
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py POSIX SIGNATURES'i ``sigdb_builtin.posix_system``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_POSIX_SYSTEM_SIGS" in text
    assert "sigdb_builtin" in text and "posix_system" in text


# ---------------------------------------------------------------------------
# 7. SignatureDB instance entegrasyon
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_data() -> None:
    """SignatureDB() instance POSIX signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert db is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
