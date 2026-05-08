"""sig_db network migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.network import SIGNATURES`` referansi uzerinden dogrudan
import yapiyor. AST parse parity testleri (eski ``_load_original_ast_values``
+ ``test_data_parity_per_dict[...]`` parametrize) tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check, 7/7)
2. Coverage count (7 dict, toplam 340 imza)
3. Bilinen sembol lookup (libcurl, POSIX, websocket, Apple nw_*)
4. SignatureDB instance entegrasyon
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_NETWORK_SIGNATURES`` referansi VAR.

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
    # v1.14 Dalga 0 cleanup: _CARES_SIGNATURES + _GRPC_SIGNATURES tasindi
    "cares",
    "grpc",
}

_EXPECTED_COUNTS = {
    "libcurl_signatures": 67,
    "posix_networking_signatures": 43,
    "nghttp2_signatures": 28,
    "websocket_signatures": 18,
    "macos_networking_signatures": 50,
    "apple_network_framework_signatures": 35,
    "networking_ext_signatures": 99,
    "cares": 26,
    "grpc": 39,
}


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_network_importable() -> None:
    """sigdb_builtin.network import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import network

    assert hasattr(network, "SIGNATURES")
    assert isinstance(network.SIGNATURES, dict)
    # v1.14 Dalga 0: cares + grpc eklendi (7 -> 9)
    assert len(network.SIGNATURES) == 9


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
    # v1.14 Dalga 0: 340 + 26 (cares) + 39 (grpc) = 405
    assert total == 405, f"Total network entry count: expected 405, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher (get_category) calisiyor mu?
# ---------------------------------------------------------------------------

def test_get_category_network_returns_data() -> None:
    """sigdb_builtin.get_category('network') dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("network")
    assert isinstance(sigs, dict)
    # v1.14 Dalga 0: cares + grpc eklendi (7 -> 9)
    assert len(sigs) == 9
    assert "libcurl_signatures" in sigs
    assert "networking_ext_signatures" in sigs
    assert "cares" in sigs
    assert "grpc" in sigs


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
    # v1.14 Dalga 0 cleanup: cares + grpc identity
    assert sdb._CARES_SIGNATURES is builtin["cares"]
    assert sdb._GRPC_SIGNATURES is builtin["grpc"]


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
        # v1.14 Dalga 0 cleanup
        "_CARES_SIGNATURES",
        "_GRPC_SIGNATURES",
    ):
        assert hasattr(sdb, attr), f"{attr} backward-compat erisimi kayboldu"
        assert len(getattr(sdb, attr)) > 0, f"{attr} bos"


# ---------------------------------------------------------------------------
# 4. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

_LEGACY_NETWORK_NAMES = (
    "_LIBCURL_SIGNATURES",
    "_POSIX_NETWORKING_SIGNATURES",
    "_NGHTTP2_SIGNATURES",
    "_WEBSOCKET_SIGNATURES",
    "_MACOS_NETWORKING_SIGNATURES",
    "_APPLE_NETWORK_FRAMEWORK_SIGNATURES",
    "_NETWORKING_EXT_SIGNATURES",
    # v1.14 Dalga 0 cleanup: legacy inline literal silindi
    "_CARES_SIGNATURES",
    "_GRPC_SIGNATURES",
)


def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK.

    A-DELETE sonrasi signature_db.py network dict'lerini sadece
    ``_BUILTIN_NETWORK_SIGNATURES["..."]`` lookup'u uzerinden tutar (7/7).
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali (spot-check)
    assert (
        '_LIBCURL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_NETWORK_SIGNATURES["libcurl_signatures"]'
    ) in text
    assert (
        '_NETWORKING_EXT_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_NETWORK_SIGNATURES["networking_ext_signatures"]'
    ) in text
    # v1.14 Dalga 0 cleanup: cares + grpc da reference assignment
    assert (
        '_CARES_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_NETWORK_SIGNATURES["cares"]'
    ) in text
    assert (
        '_GRPC_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_NETWORK_SIGNATURES["grpc"]'
    ) in text
    # Inline literal blok baslangici YOK (9 hepsi icin)
    for name in _LEGACY_NETWORK_NAMES:
        assert (
            f"{name}: dict[str, dict[str, str]] = " "{"
        ) not in text, f"{name} hala inline literal olarak duruyor"


def test_post_a_delete_direct_import() -> None:
    """signature_db.py network SIGNATURES'i ``sigdb_builtin.network``'tan
    dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_NETWORK_SIGNATURES" in text
    assert "sigdb_builtin" in text and "network" in text


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


# ---------------------------------------------------------------------------
# 6. v1.14 Dalga 0 cleanup — CARES + GRPC kapsama testleri
# ---------------------------------------------------------------------------

def test_cares_known_symbols_present() -> None:
    """c-ares async DNS resolver kritik sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    cares = sdb._CARES_SIGNATURES
    assert len(cares) == 26, f"_CARES_SIGNATURES boyutu 26 bekleniyor; {len(cares)}"

    must_have = {
        "_ares_init", "_ares_init_options", "_ares_destroy",
        "_ares_gethostbyname", "_ares_getaddrinfo",
        "_ares_query", "_ares_search", "_ares_strerror",
    }
    missing = must_have - set(cares)
    assert not missing, f"c-ares eksik kritik semboller: {missing}"

    # Lib + category etiketleri tutarli
    entry = cares["_ares_init"]
    assert entry["lib"] == "c-ares"
    assert entry["category"] == "network"


def test_grpc_known_symbols_present() -> None:
    """gRPC C core kritik sembolleri migrate olmus."""
    from karadul.analyzers import signature_db as sdb

    grpc = sdb._GRPC_SIGNATURES
    assert len(grpc) == 39, f"_GRPC_SIGNATURES boyutu 39 bekleniyor; {len(grpc)}"

    must_have = {
        "_grpc_init", "_grpc_shutdown",
        "_grpc_channel_create", "_grpc_channel_destroy",
        "_grpc_call_start_batch", "_grpc_call_cancel",
        "_grpc_server_create", "_grpc_server_start",
        "_grpc_completion_queue_next",
    }
    missing = must_have - set(grpc)
    assert not missing, f"gRPC eksik kritik semboller: {missing}"

    # Lib + category etiketleri tutarli
    entry = grpc["_grpc_init"]
    assert entry["lib"] == "grpc"
    assert entry["category"] == "network"


def test_cares_grpc_lib_labels_consistent() -> None:
    """CARES + GRPC her entry'si dogru ``lib`` etiketi tasir."""
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as N

    bad_cares = {n: e["lib"] for n, e in N["cares"].items() if e["lib"] != "c-ares"}
    bad_grpc = {n: e["lib"] for n, e in N["grpc"].items() if e["lib"] != "grpc"}
    assert not bad_cares, f"cares yanlis lib etiketli entry'ler: {bad_cares}"
    assert not bad_grpc, f"grpc yanlis lib etiketli entry'ler: {bad_grpc}"


def test_cares_grpc_schema_fields() -> None:
    """CARES + GRPC her entry'si lib/purpose/category alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as N

    required = {"lib", "purpose", "category"}
    for bucket in ("cares", "grpc"):
        for name, info in N[bucket].items():
            assert isinstance(info, dict), f"{bucket}/{name}: dict degil"
            assert required.issubset(info.keys()), (
                f"{bucket}/{name}: eksik alan(lar) {required - info.keys()}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
