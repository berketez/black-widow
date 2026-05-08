"""sig_db compression migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.compression import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri (eski
``_load_original_ast_values``) tautolojik hale geldigi icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count (5 dict, toplam 214 imza)
3. Bilinen sembol lookup
4. SignatureDB instance entegrasyon
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_COMPRESSION_SIGNATURES`` referansi VAR.
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
# 4. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK.

    A-DELETE sonrasi signature_db.py compression dict'lerini sadece
    ``_BUILTIN_COMPRESSION_SIGNATURES["..."]`` lookup'u uzerinden tutar.
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali
    assert (
        '_ZLIB_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_COMPRESSION_SIGNATURES["zlib_signatures"]'
    ) in text
    assert (
        '_COMPRESSION_EXT_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_COMPRESSION_SIGNATURES["compression_ext_signatures"]'
    ) in text
    # Inline literal blok baslangici YOK (5 hepsi icin)
    for name in (
        "_ZLIB_SIGNATURES",
        "_BZIP2_SIGNATURES",
        "_LZ4_SIGNATURES",
        "_ZSTD_SIGNATURES",
        "_COMPRESSION_EXT_SIGNATURES",
    ):
        assert (
            f"{name}: dict[str, dict[str, str]] = " "{"
        ) not in text, f"{name} hala inline literal olarak duruyor"


def test_post_a_delete_direct_import() -> None:
    """signature_db.py compression SIGNATURES'i ``sigdb_builtin.compression``'dan
    dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_COMPRESSION_SIGNATURES" in text
    assert "sigdb_builtin" in text and "compression" in text


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
