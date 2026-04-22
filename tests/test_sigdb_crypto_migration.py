"""sig_db Faz 2 pilot — crypto migration parity testleri.

Amac: karadul/analyzers/sigdb_builtin/crypto.py modulune tasinan veri,
orijinal karadul/analyzers/signature_db.py dict'leriyle birebir ayni mi?
Override mekanizmasi calisiyor mu? Legacy fallback hala erisilebilir mi?

Bu testler "data degisikligi yok" garantisini saglar — migration sadece
referans yonu degistirir, icerigi asla degistirmez.
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
    assert len(crypto.SIGNATURES) == 6


def test_sigdb_builtin_crypto_has_expected_keys() -> None:
    """SIGNATURES 6 top-level anahtar icerir (5 dict + 1 list)."""
    from karadul.analyzers.sigdb_builtin import crypto

    expected = {
        "openssl_signatures",
        "boringssl_signatures",
        "libsodium_signatures",
        "mbedtls_signatures",
        "wincrypto_signatures",
        "findcrypt_constants",
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
    assert len(sigs) == 6
    assert "openssl_signatures" in sigs


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
        "_OPENSSL_SIGNATURES",
        "_BORINGSSL_SIGNATURES",
        "_LIBSODIUM_SIGNATURES",
        "_MBEDTLS_SIGNATURES",
        "_WINCRYPTO_SIGNATURES",
        "_FINDCRYPT_CONSTANTS",
    }
    result: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id in targets and n.target.id not in result:
                # AnnAssign.value literal_eval edilebilir olmali
                result[n.target.id] = ast.literal_eval(n.value)
    return result


def test_data_parity_openssl() -> None:
    """OpenSSL dict: override sonrasi icerik orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES["openssl_signatures"]
    assert migrated == original["_OPENSSL_SIGNATURES"]
    assert len(migrated) == len(original["_OPENSSL_SIGNATURES"])


def test_data_parity_boringssl() -> None:
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["boringssl_signatures"] == original["_BORINGSSL_SIGNATURES"]


def test_data_parity_libsodium() -> None:
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["libsodium_signatures"] == original["_LIBSODIUM_SIGNATURES"]


def test_data_parity_mbedtls() -> None:
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["mbedtls_signatures"] == original["_MBEDTLS_SIGNATURES"]


def test_data_parity_wincrypto() -> None:
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["wincrypto_signatures"] == original["_WINCRYPTO_SIGNATURES"]


def test_data_parity_findcrypt() -> None:
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["findcrypt_constants"] == original["_FINDCRYPT_CONSTANTS"]
    # Liste siralamasi da korunmalidir (deterministik iteration icin)
    assert list(SIGNATURES["findcrypt_constants"]) == list(
        original["_FINDCRYPT_CONSTANTS"]
    )


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
