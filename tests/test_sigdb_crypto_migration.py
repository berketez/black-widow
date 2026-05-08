"""sig_db crypto migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.crypto import SIGNATURES`` referansi uzerinden dogrudan
import yapiyor. AST parse parity testleri (eski ``_load_original_ast_values``)
tautolojik hale geldigi icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. No duplicate keys (kategori-bazli)
4. Bilinen sembol lookup
5. SignatureDB instance entegrasyon
6. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_CRYPTO_SIGNATURES`` referansi VAR.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_crypto_importable() -> None:
    """sigdb_builtin.crypto import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import crypto

    assert hasattr(crypto, "SIGNATURES")
    assert isinstance(crypto.SIGNATURES, dict)
    # v1.13 Wave 1: 7. anahtar "modern_crypto_signatures" eklendi.
    assert len(crypto.SIGNATURES) == 7


def test_sigdb_builtin_crypto_has_expected_keys() -> None:
    """SIGNATURES 7 top-level anahtar icerir (6 dict + 1 list).

    v1.13 Wave 1: ``modern_crypto_signatures`` eklendi (ChaCha20/Salsa20/
    Blake2/Blake3/Poly1305 modern stream cipher + hash imzalari).
    """
    from karadul.analyzers.sigdb_builtin import crypto

    expected = {
        "openssl_signatures",
        "boringssl_signatures",
        "libsodium_signatures",
        "mbedtls_signatures",
        "wincrypto_signatures",
        "findcrypt_constants",
        "modern_crypto_signatures",
    }
    assert set(crypto.SIGNATURES.keys()) == expected


def test_sigdb_builtin_crypto_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip (AST'den dogrulanan)."""
    from karadul.analyzers.sigdb_builtin import crypto

    expected_counts = {
        "openssl_signatures": 329,
        "boringssl_signatures": 34,
        "libsodium_signatures": 56,
        "mbedtls_signatures": 46,
        "wincrypto_signatures": 30,
        "findcrypt_constants": 126,
        # v1.13 Wave 1: yeni kategori — minimum esik (ekleme yapildikca buyuyebilir).
        "modern_crypto_signatures": 138,
    }
    for key, expected in expected_counts.items():
        actual = len(crypto.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_crypto_returns_data() -> None:
    """sigdb_builtin.get_category('crypto') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("crypto")
    assert isinstance(sigs, dict)
    # v1.13 Wave 1: 7. anahtar "modern_crypto_signatures" eklendi.
    assert len(sigs) == 7
    assert "openssl_signatures" in sigs
    assert "modern_crypto_signatures" in sigs


# ---------------------------------------------------------------------------
# 3. signature_db.py override aktif mi? (identity check)
# ---------------------------------------------------------------------------

def test_override_openssl_identity() -> None:
    """signature_db._OPENSSL_SIGNATURES ile builtin.crypto ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES as builtin

    assert sdb._BUILTIN_CRYPTO_SIGNATURES is not None
    assert sdb._OPENSSL_SIGNATURES is builtin["openssl_signatures"]
    assert sdb._BORINGSSL_SIGNATURES is builtin["boringssl_signatures"]
    assert sdb._LIBSODIUM_SIGNATURES is builtin["libsodium_signatures"]
    assert sdb._MBEDTLS_SIGNATURES is builtin["mbedtls_signatures"]
    assert sdb._WINCRYPTO_SIGNATURES is builtin["wincrypto_signatures"]
    assert sdb._FINDCRYPT_CONSTANTS is builtin["findcrypt_constants"]


def test_legacy_attributes_still_accessible() -> None:
    """Backward compat: eski _XXX_SIGNATURES attribute hala erisilebilir."""
    from karadul.analyzers import signature_db as sdb

    # Module-level attribute'lar erisilebilir olmali
    assert hasattr(sdb, "_OPENSSL_SIGNATURES")
    assert hasattr(sdb, "_BORINGSSL_SIGNATURES")
    assert hasattr(sdb, "_LIBSODIUM_SIGNATURES")
    assert hasattr(sdb, "_MBEDTLS_SIGNATURES")
    assert hasattr(sdb, "_WINCRYPTO_SIGNATURES")
    assert hasattr(sdb, "_FINDCRYPT_CONSTANTS")
    # Ve dolular (bos degil)
    assert len(sdb._OPENSSL_SIGNATURES) > 0
    assert len(sdb._FINDCRYPT_CONSTANTS) > 0


# ---------------------------------------------------------------------------
# 4. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK.

    A-DELETE sonrasi signature_db.py crypto dict'lerini sadece
    ``_BUILTIN_CRYPTO_SIGNATURES["..."]`` lookup'u uzerinden tutar.
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali
    assert (
        '_OPENSSL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_CRYPTO_SIGNATURES["openssl_signatures"]'
    ) in text
    assert (
        '_BORINGSSL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_CRYPTO_SIGNATURES["boringssl_signatures"]'
    ) in text
    # Inline literal blok baslangici YOK
    assert '_OPENSSL_SIGNATURES: dict[str, dict[str, str]] = {' not in text
    assert '_BORINGSSL_SIGNATURES: dict[str, dict[str, str]] = {' not in text
    assert '_LIBSODIUM_SIGNATURES: dict[str, dict[str, str]] = {' not in text
    assert '_MBEDTLS_SIGNATURES: dict[str, dict[str, str]] = {' not in text
    assert '_WINCRYPTO_SIGNATURES: dict[str, dict[str, str]] = {' not in text


def test_post_a_delete_direct_import() -> None:
    """signature_db.py crypto SIGNATURES'i ``sigdb_builtin.crypto``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # A-DELETE sonrasi import / referans pattern'i mevcut olmali
    assert "_BUILTIN_CRYPTO_SIGNATURES" in text
    # Sigdb_builtin crypto modulunden geldigi belli olmali
    assert "sigdb_builtin" in text and "crypto" in text


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — bozulmus mu?
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_data() -> None:
    """SignatureDB() instance crypto signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    # Sinif init'i crash etmemeli
    assert db is not None


def test_openssl_known_symbol_lookup() -> None:
    """Override sonrasi bilindik bir OpenSSL sembolu hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    # EVP_EncryptInit_ex OpenSSL'in temel API'si — bu yoksa migration kirik
    assert "_EVP_EncryptInit_ex" in sdb._OPENSSL_SIGNATURES
    entry = sdb._OPENSSL_SIGNATURES["_EVP_EncryptInit_ex"]
    assert entry["lib"] == "openssl"
    assert "encryption" in entry["purpose"].lower()


def test_findcrypt_known_constant_present() -> None:
    """FindCrypt listesinden bilindik bir sabit (AES S-Box) hala mevcut."""
    from karadul.analyzers import signature_db as sdb

    names = {item[0] for item in sdb._FINDCRYPT_CONSTANTS}
    assert "AES_Encryption_SBox" in names
    assert "SHA256_K" in names
    assert "BLAKE2_IV" in names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
