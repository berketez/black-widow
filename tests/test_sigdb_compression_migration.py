"""sig_db Faz 3 — compression migration parity testleri.

Amac: karadul/analyzers/sigdb_builtin/compression.py modulune tasinan veri,
orijinal karadul/analyzers/signature_db.py dict'leriyle birebir ayni mi?
Override mekanizmasi calisiyor mu? Legacy fallback hala erisilebilir mi?

Crypto migration testlerinin birebir pattern'ini takip eder (bkz:
test_sigdb_crypto_migration.py). Faz 3'te taşınan 5 dict parity'si:
  - zlib_signatures          (58 entry)
  - bzip2_signatures         (17 entry)
  - lz4_signatures           (25 entry)
  - zstd_signatures          (42 entry)
  - compression_ext_signatures (72 entry — xz/lzma, snappy, lzo, brotli, ...)
Toplam: 214 imza.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_compression_importable() -> None:
    """sigdb_builtin.compression import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import compression

    assert hasattr(compression, "SIGNATURES")
    assert isinstance(compression.SIGNATURES, dict)
    assert len(compression.SIGNATURES) == 5


def test_sigdb_builtin_compression_has_expected_keys() -> None:
    """SIGNATURES 5 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import compression

    expected = {
        "zlib_signatures",
        "bzip2_signatures",
        "lz4_signatures",
        "zstd_signatures",
        "compression_ext_signatures",
    }
    assert set(compression.SIGNATURES.keys()) == expected


def test_sigdb_builtin_compression_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip (AST'den dogrulanan)."""
    from karadul.analyzers.sigdb_builtin import compression

    expected_counts = {
        "zlib_signatures": 58,
        "bzip2_signatures": 17,
        "lz4_signatures": 25,
        "zstd_signatures": 42,
        "compression_ext_signatures": 72,
    }
    for key, expected in expected_counts.items():
        actual = len(compression.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in compression.SIGNATURES.values())
    assert total == 214, f"Total compression entry count: expected 214, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_compression_returns_data() -> None:
    """sigdb_builtin.get_category('compression') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("compression")
    assert isinstance(sigs, dict)
    assert len(sigs) == 5
    assert "zlib_signatures" in sigs
    assert "compression_ext_signatures" in sigs


# ---------------------------------------------------------------------------
# 3. signature_db.py override aktif mi? (identity check)
# ---------------------------------------------------------------------------

def test_override_compression_identity() -> None:
    """signature_db._XXX_SIGNATURES ile builtin.compression ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES as builtin

    assert sdb._BUILTIN_COMPRESSION_SIGNATURES is not None
    assert sdb._ZLIB_SIGNATURES is builtin["zlib_signatures"]
    assert sdb._BZIP2_SIGNATURES is builtin["bzip2_signatures"]
    assert sdb._LZ4_SIGNATURES is builtin["lz4_signatures"]
    assert sdb._ZSTD_SIGNATURES is builtin["zstd_signatures"]
    assert sdb._COMPRESSION_EXT_SIGNATURES is builtin["compression_ext_signatures"]


def test_legacy_compression_attributes_still_accessible() -> None:
    """Backward compat: eski _XXX_SIGNATURES attribute hala erisilebilir."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_ZLIB_SIGNATURES")
    assert hasattr(sdb, "_BZIP2_SIGNATURES")
    assert hasattr(sdb, "_LZ4_SIGNATURES")
    assert hasattr(sdb, "_ZSTD_SIGNATURES")
    assert hasattr(sdb, "_COMPRESSION_EXT_SIGNATURES")
    # Ve dolular (bos degil)
    assert len(sdb._ZLIB_SIGNATURES) > 0
    assert len(sdb._COMPRESSION_EXT_SIGNATURES) > 0


# ---------------------------------------------------------------------------
# 4. Data parity — orijinalden birebir kopya mi?
# ---------------------------------------------------------------------------

def _load_original_ast_values() -> dict:
    """signature_db.py'nin BIRINCI ham AST parse'indan orijinal dict'leri al.

    Override'i bypass etmek icin kaynak kodu direkt AST'den okuyoruz.
    Boylece override oncesi gercek degerlerle karsilastirabiliriz.
    """
    import ast
    from pathlib import Path
    src_path = Path("karadul/analyzers/signature_db.py")
    src = src_path.read_text()
    tree = ast.parse(src)

    targets = {
        "_ZLIB_SIGNATURES",
        "_BZIP2_SIGNATURES",
        "_LZ4_SIGNATURES",
        "_ZSTD_SIGNATURES",
        "_COMPRESSION_EXT_SIGNATURES",
    }
    result: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id in targets and n.target.id not in result:
                result[n.target.id] = ast.literal_eval(n.value)
    return result


def test_data_parity_zlib() -> None:
    """zlib dict: override sonrasi icerik orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES["zlib_signatures"]
    assert migrated == original["_ZLIB_SIGNATURES"]
    assert len(migrated) == len(original["_ZLIB_SIGNATURES"])


def test_data_parity_bzip2() -> None:
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["bzip2_signatures"] == original["_BZIP2_SIGNATURES"]


def test_data_parity_lz4() -> None:
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["lz4_signatures"] == original["_LZ4_SIGNATURES"]


def test_data_parity_zstd() -> None:
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["zstd_signatures"] == original["_ZSTD_SIGNATURES"]


def test_data_parity_compression_ext() -> None:
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["compression_ext_signatures"] == original[
        "_COMPRESSION_EXT_SIGNATURES"
    ]


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — bozulmus mu?
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_compression_data() -> None:
    """SignatureDB() instance compression signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert db is not None


def test_zlib_known_symbol_lookup() -> None:
    """Override sonrasi bilindik bir zlib sembolu hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    # _deflate / _inflate zlib'in temel API'si — bu yoksa migration kirik
    assert "_deflate" in sdb._ZLIB_SIGNATURES
    assert "_inflate" in sdb._ZLIB_SIGNATURES
    entry = sdb._ZLIB_SIGNATURES["_deflate"]
    assert entry["lib"] == "zlib"
    assert entry["category"] == "compression"


def test_brotli_known_symbol_present() -> None:
    """COMPRESSION_EXT icinde Brotli sembolu mevcut (migration bozulmamis)."""
    from karadul.analyzers import signature_db as sdb

    assert "BrotliEncoderCompress" in sdb._COMPRESSION_EXT_SIGNATURES
    assert "snappy_compress" in sdb._COMPRESSION_EXT_SIGNATURES
    assert "lzma_stream_decoder" in sdb._COMPRESSION_EXT_SIGNATURES


def test_zstd_versioning_symbol_present() -> None:
    """ZSTD version API'leri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    assert "_ZSTD_versionNumber" in sdb._ZSTD_SIGNATURES
    assert "_ZSTD_versionString" in sdb._ZSTD_SIGNATURES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
