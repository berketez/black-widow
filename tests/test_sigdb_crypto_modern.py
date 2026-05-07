"""sig_db v1.13 Wave 1 — modern crypto signatures (ChaCha/Salsa/Blake2/Blake3/Poly1305).

Hedef: ``_MODERN_CRYPTO_SIGNATURES_DATA`` dict'inin yapisini, kapsamini ve
kutuphane ayrimini dogrulamak. Mevcut crypto migration testleri
(test_sigdb_crypto_migration.py) ile bagimsiz; sadece yeni 7. anahtara odaklanir.

Kapsam (v1.13 Wave 1):
  - libsodium ChaCha20 / XChaCha20 / Salsa20 / XSalsa20 stream API
  - libsodium Poly1305 onetimeauth
  - libsodium Blake2b ek varyantlar (keygen, salt_personal, secretstream)
  - OpenSSL/BoringSSL low-level ChaCha20/Blake2/Poly1305 internalleri
  - BLAKE3 referans + SIMD batch (sse2/sse41/avx2/avx512/neon)
  - Bare reference impl: chacha20_block, salsa20_block, poly1305_init, blake2b, ...
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Import ve dispatcher entegrasyonu
# ---------------------------------------------------------------------------

def test_modern_crypto_signatures_present() -> None:
    """``modern_crypto_signatures`` SIGNATURES dict'inde yer alir ve dolu."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    assert "modern_crypto_signatures" in SIGNATURES
    modern = SIGNATURES["modern_crypto_signatures"]
    assert isinstance(modern, dict)
    # Wave 1 minimum esik
    assert len(modern) >= 100


def test_modern_crypto_accessible_via_get_category() -> None:
    """``get_category('crypto')`` modern_crypto_signatures'i da dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("crypto")
    assert "modern_crypto_signatures" in sigs
    modern = sigs["modern_crypto_signatures"]
    # Smoke: ChaCha20 referans implementasyonu burada
    assert "_chacha20_block" in modern


# ---------------------------------------------------------------------------
# 2. Smoke lookup — temel sembol bulunabilirlik
# ---------------------------------------------------------------------------

def test_chacha20_block_lookup_smoke() -> None:
    """``_chacha20_block`` (RFC 7539 reference) bulunabilir, lib=reference."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]
    assert "_chacha20_block" in modern
    entry = modern["_chacha20_block"]
    assert entry["lib"] == "reference"
    assert entry["category"] == "crypto"
    assert "ChaCha20" in entry["purpose"]


def test_evp_chacha20_openssl_identification() -> None:
    """``_EVP_chacha20`` OpenSSL kutuphanesi ile etiketlenmis (no Poly1305 variant)."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]
    assert "_EVP_chacha20" in modern
    entry = modern["_EVP_chacha20"]
    assert entry["lib"] == "openssl"
    # _EVP_chacha20_poly1305 zaten OpenSSL ana dict'inde, modern'de yok
    assert "_EVP_chacha20_poly1305" not in modern, (
        "Cakisma: _EVP_chacha20_poly1305 hem ana OpenSSL hem modern dict'inde olmamali"
    )


# ---------------------------------------------------------------------------
# 3. Library namespace ayrimi — ayni sembol farkli lib'lerde karismiyor
# ---------------------------------------------------------------------------

def test_blake2_vs_blake3_disambiguation() -> None:
    """Blake2 ve Blake3 ayri kutuphane tag'leri ile ayrilmis (binary'de ikisi
    yan yana olabilir, isim kurtarma karistirmaz)."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]

    # Blake2 reference variants
    blake2_entries = [
        "_blake2b", "_blake2s", "_blake2bp", "_blake2sp",
        "_blake2b_init", "_blake2s_init",
    ]
    for sym in blake2_entries:
        assert sym in modern, f"Blake2 sembol eksik: {sym}"
        # Blake2 entry'leri "blake2" iceren purpose VEYA reference/openssl lib'inde
        purpose = modern[sym]["purpose"].lower()
        assert "blake2" in purpose

    # Blake3 entries — hepsi blake3 lib'inde (ya da reference)
    blake3_official = [
        "_blake3_hasher_init", "_blake3_hasher_update",
        "_blake3_hasher_finalize", "_blake3_compress_in_place",
    ]
    for sym in blake3_official:
        assert sym in modern, f"Blake3 sembol eksik: {sym}"
        assert modern[sym]["lib"] == "blake3"
        assert "BLAKE3" in modern[sym]["purpose"]

    # Blake3 reference (bare)
    assert modern["_blake3"]["lib"] == "reference"
    assert "Blake3" in modern["_blake3"]["purpose"]


def test_libsodium_chacha20_family_namespace() -> None:
    """``crypto_stream_chacha20*`` familyasi tamamen libsodium namespace'inde."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]

    expected_family = [
        "_crypto_stream_chacha20",
        "_crypto_stream_chacha20_xor",
        "_crypto_stream_chacha20_xor_ic",
        "_crypto_stream_chacha20_keygen",
        "_crypto_stream_chacha20_ietf",
        "_crypto_stream_chacha20_ietf_xor",
        "_crypto_stream_chacha20_ietf_xor_ic",
        "_crypto_stream_chacha20_ietf_keygen",
    ]
    for sym in expected_family:
        assert sym in modern, f"libsodium ChaCha20 familya eksik: {sym}"
        assert modern[sym]["lib"] == "libsodium"
        assert modern[sym]["category"] == "crypto"


def test_xchacha20_extended_nonce_variants() -> None:
    """XChaCha20 (24-byte nonce) varyantlari mevcut ve libsodium ile etiketli."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]

    xchacha_syms = [
        "_crypto_stream_xchacha20",
        "_crypto_stream_xchacha20_xor",
        "_crypto_core_hchacha20",
    ]
    for sym in xchacha_syms:
        assert sym in modern
        assert modern[sym]["lib"] == "libsodium"


def test_salsa20_xsalsa20_family() -> None:
    """Salsa20 / XSalsa20 stream API + core fonksiyonlari mevcut."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]

    salsa_syms = [
        "_crypto_stream_salsa20",
        "_crypto_stream_xsalsa20",
        "_crypto_core_salsa20",
        "_crypto_core_hsalsa20",
        "_salsa20_block",
        "_xsalsa20_encrypt",
    ]
    for sym in salsa_syms:
        assert sym in modern, f"Salsa20 sembol eksik: {sym}"


def test_poly1305_layered_implementations() -> None:
    """Poly1305 hem libsodium (crypto_onetimeauth) hem OpenSSL (Poly1305_*) hem
    reference (poly1305_init/_mac) seviyelerinde eksiksiz."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]

    # libsodium katmani
    assert modern["_crypto_onetimeauth"]["lib"] == "libsodium"
    assert "Poly1305" in modern["_crypto_onetimeauth"]["purpose"]

    # OpenSSL low-level katmani
    assert modern["_Poly1305_Init"]["lib"] == "openssl"
    assert modern["_Poly1305_Update"]["lib"] == "openssl"
    assert modern["_Poly1305_Final"]["lib"] == "openssl"

    # Reference katmani
    assert modern["_poly1305_init"]["lib"] == "reference"
    assert modern["_poly1305_mac"]["lib"] == "reference"


# ---------------------------------------------------------------------------
# 4. Cakismayi onleme — eski dict'lere mukerrer yazim yok
# ---------------------------------------------------------------------------

def test_no_duplicate_with_openssl_signatures() -> None:
    """Modern dict ile mevcut OpenSSL dict arasinda ortak anahtar olmamali."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    openssl = set(SIGNATURES["openssl_signatures"].keys())
    modern = set(SIGNATURES["modern_crypto_signatures"].keys())
    overlap = openssl & modern
    assert overlap == set(), (
        f"OpenSSL ve modern_crypto arasinda mukerrer anahtar: {sorted(overlap)}"
    )


def test_no_duplicate_with_libsodium_signatures() -> None:
    """Modern dict ile mevcut libsodium dict arasinda ortak anahtar olmamali."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    libsodium = set(SIGNATURES["libsodium_signatures"].keys())
    modern = set(SIGNATURES["modern_crypto_signatures"].keys())
    overlap = libsodium & modern
    assert overlap == set(), (
        f"libsodium ve modern_crypto arasinda mukerrer anahtar: {sorted(overlap)}"
    )


# ---------------------------------------------------------------------------
# 5. Schema kontrolu — her entry zorunlu alanlara sahip
# ---------------------------------------------------------------------------

def test_all_modern_entries_have_required_fields() -> None:
    """Her modern entry: lib + purpose + category alanlarina sahip ve crypto kategorisinde."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]
    required = {"lib", "purpose", "category"}

    for sym, entry in modern.items():
        assert isinstance(entry, dict), f"{sym}: entry dict olmali"
        missing = required - set(entry.keys())
        assert not missing, f"{sym}: eksik alanlar {missing}"
        assert entry["category"] == "crypto", (
            f"{sym}: category 'crypto' olmali, {entry['category']!r} bulundu"
        )
        # Hosgorulu lib whitelist (yeni kutuphaneler eklenirse buraya yazilmali)
        assert entry["lib"] in {
            "openssl", "boringssl", "libsodium", "blake3", "reference",
        }, f"{sym}: bilinmeyen lib {entry['lib']!r}"


def test_all_modern_keys_use_underscore_prefix() -> None:
    """Tum semboller leading underscore ile baslar (signature_db konvansiyonu)."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    modern = SIGNATURES["modern_crypto_signatures"]
    for sym in modern:
        assert sym.startswith("_"), (
            f"Sembol leading underscore olmadan: {sym!r} "
            "(signature_db konvansiyonu mach-O/ELF unmangled isim)"
        )


# ---------------------------------------------------------------------------
# 6. Mevcut migration testleriyle birlikte calisma — regresyon yok
# ---------------------------------------------------------------------------

def test_legacy_six_categories_still_intact() -> None:
    """Mevcut 6 kategori (openssl/boringssl/libsodium/mbedtls/wincrypto/findcrypt)
    eski entry sayilarini koruyor — modern dict eklenmesi diger dict'leri bozmadi."""
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES

    assert len(SIGNATURES["openssl_signatures"]) == 329
    assert len(SIGNATURES["boringssl_signatures"]) == 34
    assert len(SIGNATURES["libsodium_signatures"]) == 56
    assert len(SIGNATURES["mbedtls_signatures"]) == 46
    assert len(SIGNATURES["wincrypto_signatures"]) == 30
    assert len(SIGNATURES["findcrypt_constants"]) == 126


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
