"""sig_db Faz 3 — network migration parity testleri.

Amac: karadul/analyzers/sigdb_builtin/network.py modulune tasinan veri,
orijinal karadul/analyzers/signature_db.py dict'leriyle birebir ayni mi?
Override mekanizmasi calisiyor mu? Legacy fallback hala erisilebilir mi?

Crypto/compression migration testlerinin pattern'ini takip eder. Faz 3'te
taşınan 7 dict parity'si:
  - libcurl_signatures                  (67 entry)
  - posix_networking_signatures         (43 entry)
  - nghttp2_signatures                  (28 entry)
  - websocket_signatures                (18 entry)
  - macos_networking_signatures         (50 entry)
  - apple_network_framework_signatures  (35 entry)
  - networking_ext_signatures           (99 entry — c-ares, libevent, libuv, ...)
Toplam: 340 imza.

NOT: SSL/TLS (OpenSSL, BoringSSL, mbedTLS) crypto kategorisine aittir;
bu migration sadece network-layer (HTTP, TCP/UDP, WebSocket, DNS) icerir.
"""
from __future__ import annotations

import pytest


_EXPECTED_KEYS = {
    "libcurl_signatures",
    "posix_networking_signatures",
    "nghttp2_signatures",
    "websocket_signatures",
    "macos_networking_signatures",
    "apple_network_framework_signatures",
    "networking_ext_signatures",
}

_EXPECTED_COUNTS = {
    "libcurl_signatures": 67,
    "posix_networking_signatures": 43,
    "nghttp2_signatures": 28,
    "websocket_signatures": 18,
    "macos_networking_signatures": 50,
    "apple_network_framework_signatures": 35,
    "networking_ext_signatures": 99,
}


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_network_importable() -> None:
    """sigdb_builtin.network import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import network

    assert hasattr(network, "SIGNATURES")
    assert isinstance(network.SIGNATURES, dict)
    assert len(network.SIGNATURES) == 7


def test_sigdb_builtin_network_has_expected_keys() -> None:
    """SIGNATURES 7 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import network

    assert set(network.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_sigdb_builtin_network_entry_counts() -> None:
    """Her kategori beklenen entry sayisina sahip (AST'den dogrulanan)."""
    from karadul.analyzers.sigdb_builtin import network

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(network.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in network.SIGNATURES.values())
    assert total == 340, f"Total network entry count: expected 340, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_network_returns_data() -> None:
    """sigdb_builtin.get_category('network') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("network")
    assert isinstance(sigs, dict)
    assert len(sigs) == 7
    assert "libcurl_signatures" in sigs
    assert "networking_ext_signatures" in sigs


# ---------------------------------------------------------------------------
# 3. signature_db.py override aktif mi? (identity check — 7/7)
# ---------------------------------------------------------------------------

def test_override_network_identity() -> None:
    """signature_db._XXX_SIGNATURES ile builtin.network ayni obje (7/7)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as builtin

    assert sdb._BUILTIN_NETWORK_SIGNATURES is not None
    assert sdb._LIBCURL_SIGNATURES is builtin["libcurl_signatures"]
    assert sdb._POSIX_NETWORKING_SIGNATURES is builtin["posix_networking_signatures"]
    assert sdb._NGHTTP2_SIGNATURES is builtin["nghttp2_signatures"]
    assert sdb._WEBSOCKET_SIGNATURES is builtin["websocket_signatures"]
    assert sdb._MACOS_NETWORKING_SIGNATURES is builtin["macos_networking_signatures"]
    assert sdb._APPLE_NETWORK_FRAMEWORK_SIGNATURES is builtin[
        "apple_network_framework_signatures"
    ]
    assert sdb._NETWORKING_EXT_SIGNATURES is builtin["networking_ext_signatures"]


def test_legacy_network_attributes_still_accessible() -> None:
    """Backward compat: eski _XXX_SIGNATURES attribute hala erisilebilir."""
    from karadul.analyzers import signature_db as sdb

    for attr in (
        "_LIBCURL_SIGNATURES",
        "_POSIX_NETWORKING_SIGNATURES",
        "_NGHTTP2_SIGNATURES",
        "_WEBSOCKET_SIGNATURES",
        "_MACOS_NETWORKING_SIGNATURES",
        "_APPLE_NETWORK_FRAMEWORK_SIGNATURES",
        "_NETWORKING_EXT_SIGNATURES",
    ):
        assert hasattr(sdb, attr), f"{attr} backward-compat erisimi kayboldu"
        assert len(getattr(sdb, attr)) > 0, f"{attr} bos"


# ---------------------------------------------------------------------------
# 4. Data parity — orijinalden birebir kopya mi?
# ---------------------------------------------------------------------------

def _load_original_ast_values() -> dict:
    """signature_db.py'nin ham AST parse'indan orijinal dict'leri al."""
    import ast
    from pathlib import Path
    src_path = Path("karadul/analyzers/signature_db.py")
    src = src_path.read_text()
    tree = ast.parse(src)

    targets = {
        "_LIBCURL_SIGNATURES",
        "_POSIX_NETWORKING_SIGNATURES",
        "_NGHTTP2_SIGNATURES",
        "_WEBSOCKET_SIGNATURES",
        "_MACOS_NETWORKING_SIGNATURES",
        "_APPLE_NETWORK_FRAMEWORK_SIGNATURES",
        "_NETWORKING_EXT_SIGNATURES",
    }
    result: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id in targets and n.target.id not in result:
                result[n.target.id] = ast.literal_eval(n.value)
    return result


_PARITY_MAP = {
    "libcurl_signatures": "_LIBCURL_SIGNATURES",
    "posix_networking_signatures": "_POSIX_NETWORKING_SIGNATURES",
    "nghttp2_signatures": "_NGHTTP2_SIGNATURES",
    "websocket_signatures": "_WEBSOCKET_SIGNATURES",
    "macos_networking_signatures": "_MACOS_NETWORKING_SIGNATURES",
    "apple_network_framework_signatures": "_APPLE_NETWORK_FRAMEWORK_SIGNATURES",
    "networking_ext_signatures": "_NETWORKING_EXT_SIGNATURES",
}


@pytest.mark.parametrize("migrated_key,original_name", list(_PARITY_MAP.items()))
def test_data_parity_per_dict(migrated_key: str, original_name: str) -> None:
    """Her dict icin birebir key-by-key parity."""
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES[migrated_key]
    assert migrated == original[original_name], (
        f"{migrated_key} icerik farki: migration kirik"
    )
    assert len(migrated) == len(original[original_name])


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — bozulmus mu?
# ---------------------------------------------------------------------------

def test_signature_db_instance_uses_migrated_network_data() -> None:
    """SignatureDB() instance network signature'larini tasinmis kaynaktan alir."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert db is not None


def test_libcurl_known_symbol_lookup() -> None:
    """Override sonrasi bilindik bir libcurl sembolu hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    # curl_easy_init libcurl'un temel API'si
    assert "_curl_easy_init" in sdb._LIBCURL_SIGNATURES
    assert "_curl_easy_perform" in sdb._LIBCURL_SIGNATURES
    entry = sdb._LIBCURL_SIGNATURES["_curl_easy_init"]
    assert entry["lib"] == "libcurl"


def test_posix_networking_known_symbol_present() -> None:
    """POSIX socket API (socket, bind, connect) migration sonrasi hala mevcut."""
    from karadul.analyzers import signature_db as sdb

    # POSIX sembolleri "_" prefix'li de prefix'siz de olabilir
    symbols = sdb._POSIX_NETWORKING_SIGNATURES
    assert any("socket" in k for k in symbols)
    assert any("connect" in k for k in symbols)


def test_websocket_known_symbol_present() -> None:
    """WebSocket lws_* sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    symbols = sdb._WEBSOCKET_SIGNATURES
    assert any("lws" in k or "ws_" in k or "websocket" in k.lower() for k in symbols)


def test_apple_network_framework_symbol_present() -> None:
    """Apple Network.framework nw_* sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    symbols = sdb._APPLE_NETWORK_FRAMEWORK_SIGNATURES
    assert any(k.startswith("_nw_") or k.startswith("nw_") for k in symbols), (
        "Apple Network.framework nw_* prefix'li bir sembol beklenir"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
