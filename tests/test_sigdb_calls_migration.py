"""sig_db ``calls`` kategorisi migrasyon testleri (v1.13 Dalga 2 / ADR 0007 A13).

Bu kategori diger migrate edilenlerden FARKLI yapida:
- ``STRING_REFERENCE_SIGNATURES`` -> ``dict[frozenset[str], tuple[str, str, str]]``
- ``CALL_PATTERN_SIGNATURES``     -> ``list[tuple[frozenset[str], str, str, str, float]]``

Yapilar matchlemek icin set semantigine ihtiyac duyar; bu nedenle
``dict[str, dict[str, str]]`` formuna donusturulmemistir.

Parity katmanlari:
1. Modul import + iki ozel veri yapisi mevcut
2. Yapi dogrulama (frozenset key / tuple-of-list)
3. Entry sayilari: 246 string_ref + 98 call_pattern
4. Birebir icerik parity (signature_db.py kaynak ile ``==``)
5. ``SIGNATURES`` dict iki alt-anahtara sahip ve identity (``is``) korunuyor
6. Bilinen sembol lookup (regression guard)
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Modul import edilebilir + beklenen attribute'lar mevcut
# ---------------------------------------------------------------------------

def test_sigdb_builtin_calls_importable() -> None:
    """``sigdb_builtin.calls`` import edilebilir."""
    from karadul.analyzers.sigdb_builtin import calls

    assert hasattr(calls, "SIGNATURES")
    assert hasattr(calls, "STRING_REFERENCE_SIGNATURES")
    assert hasattr(calls, "CALL_PATTERN_SIGNATURES")


def test_sigdb_builtin_calls_top_level_keys() -> None:
    """``SIGNATURES`` ust dict iki alt-anahtara sahip."""
    from karadul.analyzers.sigdb_builtin import calls

    assert isinstance(calls.SIGNATURES, dict)
    assert set(calls.SIGNATURES.keys()) == {"string_reference", "call_pattern"}


# ---------------------------------------------------------------------------
# 2. Yapi dogrulama — frozenset / tuple / list (dict'e DONUSTURULMEDI)
# ---------------------------------------------------------------------------

def test_string_reference_uses_frozenset_keys() -> None:
    """``STRING_REFERENCE_SIGNATURES`` anahtarlari ``frozenset[str]``."""
    from karadul.analyzers.sigdb_builtin import calls

    assert isinstance(calls.STRING_REFERENCE_SIGNATURES, dict)
    # Bos olmamali ve TUM keyler frozenset olmali
    assert len(calls.STRING_REFERENCE_SIGNATURES) > 0
    for key in calls.STRING_REFERENCE_SIGNATURES:
        assert isinstance(key, frozenset), f"Key {key!r} frozenset degil"
        for elem in key:
            assert isinstance(elem, str)


def test_string_reference_values_are_3tuple() -> None:
    """``STRING_REFERENCE_SIGNATURES`` degerleri ``tuple[str, str, str]``."""
    from karadul.analyzers.sigdb_builtin import calls

    for key, val in calls.STRING_REFERENCE_SIGNATURES.items():
        assert isinstance(val, tuple), f"{key} -> {val!r} tuple degil"
        assert len(val) == 3, f"{key} -> {val!r} 3-tuple degil"
        for elem in val:
            assert isinstance(elem, str)


def test_call_pattern_is_list_of_tuples() -> None:
    """``CALL_PATTERN_SIGNATURES`` ``list[tuple]`` (dict DEĞIL)."""
    from karadul.analyzers.sigdb_builtin import calls

    assert isinstance(calls.CALL_PATTERN_SIGNATURES, list)
    assert len(calls.CALL_PATTERN_SIGNATURES) > 0

    for entry in calls.CALL_PATTERN_SIGNATURES:
        assert isinstance(entry, tuple), f"{entry!r} tuple degil"
        assert len(entry) == 5, f"{entry!r} 5-tuple degil"
        callee_set, name, lib, purpose, conf = entry
        assert isinstance(callee_set, frozenset)
        assert isinstance(name, str)
        assert isinstance(lib, str)
        assert isinstance(purpose, str)
        assert isinstance(conf, float)
        assert 0.0 <= conf <= 1.0


# ---------------------------------------------------------------------------
# 3. Entry sayilari — AST'den dogrulanan baseline
# ---------------------------------------------------------------------------

def test_string_reference_count() -> None:
    """``STRING_REFERENCE_SIGNATURES`` 246 entry icerir."""
    from karadul.analyzers.sigdb_builtin import calls

    assert len(calls.STRING_REFERENCE_SIGNATURES) == 246


def test_call_pattern_count() -> None:
    """``CALL_PATTERN_SIGNATURES`` 98 entry icerir."""
    from karadul.analyzers.sigdb_builtin import calls

    assert len(calls.CALL_PATTERN_SIGNATURES) == 98


# ---------------------------------------------------------------------------
# 4. Birebir parity — orijinal signature_db.py ile ``==`` esitlik
# ---------------------------------------------------------------------------

def test_string_reference_parity_with_signature_db() -> None:
    """Migrate edilen dict, signature_db.py'daki orijinal ile birebir esit."""
    from karadul.analyzers import signature_db
    from karadul.analyzers.sigdb_builtin import calls

    assert calls.STRING_REFERENCE_SIGNATURES == signature_db._STRING_REFERENCE_SIGNATURES


def test_call_pattern_parity_with_signature_db() -> None:
    """Migrate edilen list, signature_db.py'daki orijinal ile birebir esit."""
    from karadul.analyzers import signature_db
    from karadul.analyzers.sigdb_builtin import calls

    assert calls.CALL_PATTERN_SIGNATURES == signature_db._CALL_PATTERN_SIGNATURES


# ---------------------------------------------------------------------------
# 5. SIGNATURES alt-anahtar identity — yalin degisken ile ayni nesne
# ---------------------------------------------------------------------------

def test_signatures_dict_identity() -> None:
    """``SIGNATURES`` alt-anahtarlari yalın degiskenlerle ``is`` esitligine sahip."""
    from karadul.analyzers.sigdb_builtin import calls

    assert calls.SIGNATURES["string_reference"] is calls.STRING_REFERENCE_SIGNATURES
    assert calls.SIGNATURES["call_pattern"] is calls.CALL_PATTERN_SIGNATURES


# ---------------------------------------------------------------------------
# 6. Bilinen sembol lookup — regression guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "key, expected",
    [
        (frozenset({"BIO_new", "SSL_CTX_new"}),
         ("ssl_ctx_setup", "openssl", "TLS context setup")),
        (frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}),
         ("sha256_hash", "openssl", "SHA-256 computation")),
        (frozenset({"sqlite3_open", "sqlite3_exec"}),
         ("sqlite_exec_query", "sqlite3", "database query execution")),
        (frozenset({"fork", "exec", "waitpid"}),
         ("process_spawn", "libc", "process spawn + wait")),
    ],
)
def test_string_reference_known_lookups(
    key: frozenset[str], expected: tuple[str, str, str]
) -> None:
    """Bilinen string-reference imzalari dogru deger donduruyor."""
    from karadul.analyzers.sigdb_builtin import calls

    assert calls.STRING_REFERENCE_SIGNATURES[key] == expected


def test_call_pattern_known_entry() -> None:
    """Bilinen bir call_pattern entry'si beklenen formatta."""
    from karadul.analyzers.sigdb_builtin import calls

    # TLS client setup pattern (ilk entry)
    expected = (
        frozenset({"SSL_CTX_new", "SSL_new", "SSL_set_fd", "SSL_connect"}),
        "tls_client_connect",
        "openssl",
        "complete TLS client handshake",
        0.90,
    )
    assert expected in calls.CALL_PATTERN_SIGNATURES
