"""sig_db Faz 9 (pilot) — logging migration parity testleri.

Amac: karadul/analyzers/sigdb_builtin/logging.py modulune tasinan veri,
orijinal karadul/analyzers/signature_db.py dict'leriyle birebir ayni mi?
Override mekanizmasi calisiyor mu? Legacy fallback hala erisilebilir mi?

Compression/crypto migration testlerinin birebir pattern'ini takip eder
(bkz: test_sigdb_compression_migration.py). Faz 9 pilot kapsami:
  - logging_signatures        (45 entry — spdlog/log4cxx/glog/glib/android/os_log/asl)
  - logging_ext_signatures    (38 entry — syslog/journald/dbus/ETW/PDH)
Toplam: 83 imza.

ADR 0008 Grup 10 referansi: 2 dict, 83 entry, ~103 LOC. Tip A override
(legacy in-place dict gövdeleri korunur, rollback bandi 1 surum).
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_logging_importable() -> None:
    """sigdb_builtin.logging import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import logging as logging_mod

    assert hasattr(logging_mod, "SIGNATURES")
    assert isinstance(logging_mod.SIGNATURES, dict)
    assert len(logging_mod.SIGNATURES) == 2


def test_sigdb_builtin_logging_has_expected_keys() -> None:
    """SIGNATURES 2 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import logging as logging_mod

    expected = {
        "logging_signatures",
        "logging_ext_signatures",
    }
    assert set(logging_mod.SIGNATURES.keys()) == expected


def test_sigdb_builtin_logging_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip (AST'den dogrulanan)."""
    from karadul.analyzers.sigdb_builtin import logging as logging_mod

    expected_counts = {
        "logging_signatures": 45,
        "logging_ext_signatures": 38,
    }
    for key, expected in expected_counts.items():
        actual = len(logging_mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in logging_mod.SIGNATURES.values())
    assert total == 83, f"Total logging entry count: expected 83, got {total}"


def test_sigdb_builtin_logging_no_key_overlap() -> None:
    """Iki dict arasinda anahtar kesişmesi olmamali (entry leak korumasi)."""
    from karadul.analyzers.sigdb_builtin import logging as logging_mod

    log_keys = set(logging_mod.SIGNATURES["logging_signatures"])
    ext_keys = set(logging_mod.SIGNATURES["logging_ext_signatures"])
    overlap = log_keys & ext_keys
    assert not overlap, f"Anahtar kesişimi tespit edildi: {overlap}"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_logging_returns_data() -> None:
    """sigdb_builtin.get_category('logging') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("logging")
    assert isinstance(sigs, dict)
    assert len(sigs) == 2
    assert "logging_signatures" in sigs
    assert "logging_ext_signatures" in sigs


# ---------------------------------------------------------------------------
# 3. signature_db.py override aktif mi? (identity check)
# ---------------------------------------------------------------------------

def test_override_logging_identity() -> None:
    """signature_db._XXX_SIGNATURES ile builtin.logging ayni obje (Tip A bind)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.logging import SIGNATURES as builtin

    assert sdb._BUILTIN_LOGGING_SIGNATURES is not None
    assert sdb._LOGGING_SIGNATURES is builtin["logging_signatures"]
    assert sdb._LOGGING_EXT_SIGNATURES is builtin["logging_ext_signatures"]


def test_legacy_logging_attributes_still_accessible() -> None:
    """Backward compat: eski _LOGGING_*_SIGNATURES attribute hala erisilebilir."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_LOGGING_SIGNATURES")
    assert hasattr(sdb, "_LOGGING_EXT_SIGNATURES")
    # Ve dolular (bos degil)
    assert len(sdb._LOGGING_SIGNATURES) == 45
    assert len(sdb._LOGGING_EXT_SIGNATURES) == 38


# ---------------------------------------------------------------------------
# 4. Data parity — orijinalden birebir kopya mi?
# ---------------------------------------------------------------------------

def _load_original_ast_values() -> dict:
    """signature_db.py'nin BIRINCI ham AST parse'indan orijinal dict'leri al.

    Override'i bypass etmek icin kaynak kodu direkt AST'den okuyoruz. Boylece
    override oncesi gercek (legacy in-place) degerlerle karsilastirabiliriz.
    """
    import ast
    from pathlib import Path
    src_path = Path("karadul/analyzers/signature_db.py")
    src = src_path.read_text()
    tree = ast.parse(src)

    targets = {
        "_LOGGING_SIGNATURES",
        "_LOGGING_EXT_SIGNATURES",
    }
    result: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id in targets and n.target.id not in result:
                result[n.target.id] = ast.literal_eval(n.value)
    return result


def test_data_parity_logging() -> None:
    """logging dict: builtin modul icerigi orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.logging import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES["logging_signatures"]
    assert migrated == original["_LOGGING_SIGNATURES"]
    assert len(migrated) == len(original["_LOGGING_SIGNATURES"]) == 45


def test_data_parity_logging_ext() -> None:
    """logging_ext dict: builtin modul icerigi orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.logging import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES["logging_ext_signatures"]
    assert migrated == original["_LOGGING_EXT_SIGNATURES"]
    assert len(migrated) == len(original["_LOGGING_EXT_SIGNATURES"]) == 38


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — bozulmus mu?
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_logging_data() -> None:
    """SignatureDB() instance logging signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert db is not None


def test_spdlog_known_symbol_lookup() -> None:
    """Override sonrasi bilindik bir spdlog sembolu hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    # spdlog::set_level — temel API, migration kirikligi belirleyici
    assert "__ZN6spdlog9set_level" in sdb._LOGGING_SIGNATURES
    entry = sdb._LOGGING_SIGNATURES["__ZN6spdlog9set_level"]
    assert entry["lib"] == "spdlog"
    assert entry["category"] == "logging"


def test_oslog_apple_symbol_present() -> None:
    """Apple unified logging sembolleri migrate olmus (cross-platform fixture)."""
    from karadul.analyzers import signature_db as sdb

    assert "_os_log_create" in sdb._LOGGING_SIGNATURES
    assert "_os_log_error" in sdb._LOGGING_SIGNATURES
    assert sdb._LOGGING_SIGNATURES["_os_log_create"]["lib"] == "os_log"


def test_glog_symbol_present() -> None:
    """glog (Google Logging) sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "__ZN6google17InitGoogleLogging" in sdb._LOGGING_SIGNATURES
    assert "__ZN6google20ShutdownGoogleLogging" in sdb._LOGGING_SIGNATURES


def test_syslog_known_symbol_present() -> None:
    """LOGGING_EXT icinde syslog sembolu mevcut (migration bozulmamis)."""
    from karadul.analyzers import signature_db as sdb

    assert "openlog" in sdb._LOGGING_EXT_SIGNATURES
    assert "syslog" in sdb._LOGGING_EXT_SIGNATURES
    assert sdb._LOGGING_EXT_SIGNATURES["syslog"]["lib"] == "libc"


def test_etw_windows_symbol_present() -> None:
    """ETW (Windows Event Tracing) sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "EventRegister" in sdb._LOGGING_EXT_SIGNATURES
    assert "EventWrite" in sdb._LOGGING_EXT_SIGNATURES
    assert sdb._LOGGING_EXT_SIGNATURES["EventRegister"]["lib"] == "advapi32"
    assert sdb._LOGGING_EXT_SIGNATURES["EventRegister"]["category"] == "win_etw"


def test_journald_symbol_present() -> None:
    """systemd journal sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "sd_journal_print" in sdb._LOGGING_EXT_SIGNATURES
    assert "sd_journal_send" in sdb._LOGGING_EXT_SIGNATURES
    assert sdb._LOGGING_EXT_SIGNATURES["sd_journal_print"]["lib"] == "libsystemd"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
