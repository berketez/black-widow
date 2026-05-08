"""Fonksiyon Imza Veritabani -- Binary'deki isimsiz fonksiyonlari tanimak icin.

Ghidra'nin FLIRT (Fast Library Identification and Recognition Technology)
yaklasimina benzer, ama 3 katmanli:

  Katman 1: Byte Pattern Signatures   -- Fonksiyonun ilk N byte'i ile eslestirme
  Katman 2: String Reference Signatures -- Fonksiyonun kullandigi string'lerden tanimlama
  Katman 3: Structural Signatures       -- Call graph pattern'lerinden tanimlama

Ek olarak, symbol-based hizli eslestirme de yapar (export tablosundaki
bilinen kutupahane fonksiyon isimleri).

Builtin DB ~6100+ imza icerir (v2.0 expansion) + 126 FindCrypt kripto sabiti:
  - macOS system libs (~100)
  - CoreFoundation (~60)
  - Foundation/ObjC runtime (~70)
  - Swift runtime (~50)
  - Grand Central Dispatch (~40)
  - Apple Security.framework (~35)
  - IOKit (~15)
  - Apple CoreData (~16)
  - Apple WebKit (~13)
  - Apple CoreLocation (~9)
  - Apple CoreBluetooth (~11)
  - Apple StoreKit (~10)
  - Apple UserNotifications (~11)
  - Apple Network.framework extended (~35)
  - Apple EndpointSecurity extended (~14)
  - Apple SystemExtensions (~3)
  - Apple AppKit / Foundation classes (~80)
  - OpenSSL/BoringSSL (~200)
  - zlib (~45)
  - bzip2 (~17)
  - lz4 (~25)
  - zstd (~42)
  - libcurl (~67)
  - protobuf (~90, demangled + mangled names)
  - SQLite (~155)
  - JSON parsers: cJSON (~50), yyjson (~18), jansson (~45)
  - XML parsers: libxml2 (~65), expat (~25)
  - C++ STL / libc++ (~60)
  - Boost C++ (~60)
  - Google Abseil (~45)
  - Facebook Folly (~33)
  - Logging: spdlog, log4cxx, glog, GLib, Android, os_log (~45)
  - Serialization: FlatBuffers + Cap'n Proto + MessagePack (~40)
  - POSIX File I/O (~65)
  - POSIX Networking (~43)
  - c-ares async DNS (~26)
  - nghttp2 HTTP/2 (~28)
  - libwebsockets WebSocket (~18)
  - gRPC C core (~39)
  - macOS Network.framework + CFNetwork (~50)
  - IPC / XPC (~51)
  - Process management (~35)
  - POSIX threads / pthreads (~37)
  - Memory management (~27)
  - String / stdlib (~44)
  - Time (~17)
  - Dynamic loading / dyld (~10)
  - Error / locale / misc (~15)
  - OpenGL / Metal / GPU (~60)
  - CoreGraphics (~35)
  - CoreImage + CoreML (~10)
  - Image libs: libpng (~20), libjpeg (~17), libwebp (~8), ImageIO (~6)
  - Audio: CoreAudio (~27), AVFoundation (~6), OpenAL (~17)
  - FFmpeg / libav (~35)
  - SDL2 (~30)
  - Windows API: kernel32 (~55)
  - Windows API: ws2_32 / Winsock (~20)
  - Windows API: advapi32 (~20)
  - Windows API: user32 + gdi32 (~25)
  - Windows API: ntdll (~14)
  - Linux-specific syscall wrappers (~35)
  - Rust standard library (~50)
  - Go runtime + stdlib (~55)
  - libuv event loop (~57)
  - libevent I/O (~26)
  - PCRE2 / POSIX regex / RE2 (~18)
  - ICU Unicode (~30)
  - Math / BLAS / LAPACK / Accelerate (~76)
  - Qt Framework (~16)
  - Logging: spdlog, GLib, Android, os_log (~16)
  - Testing: gtest, Catch2, CUnit (~9)
  - Misc: getopt, iconv, readline, termios, uuid, GLib (~46)
  - FindCrypt-Ghidra crypto constants (~126 byte pattern signatures):
    AES S-Box, SHA-1/256/512, MD4/5, DES, Blowfish, Twofish, Camellia,
    Rijndael T-tables, Curve25519 ECC, BLAKE2, Whirlpool, GOST, SEED,
    Keccak/SHA-3, ChaCha, Salsa20, CAST, MARS, Tiger, CRC32, zlib, etc.

Kullanim:
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    sig_db = SignatureDB(Config())
    matches = sig_db.match_all(
        functions_json=Path("workspace/static/ghidra_functions.json"),
        strings_json=Path("workspace/static/ghidra_strings.json"),
        call_graph_json=Path("workspace/static/ghidra_call_graph.json"),
        decompiled_dir=Path("workspace/static/ghidra_output/decompiled"),
    )
    for m in matches:
        print(f"{m.original_name} -> {m.matched_name} ({m.library}, {m.confidence:.0%})")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Prefer ujson for faster JSON parsing (~2x on large files), fallback to stdlib.
# ujson icin tip stub'i mevcut degil -> import-untyped sustur.
try:
    import ujson as json  # type: ignore[import-untyped]
except ImportError:
    import json

from karadul.config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# v1.13 Dalga 2: 11 yeni kategori için doğrudan sigdb_builtin importu (A-DELETE Tip B).
# Inline legacy literal'ler silindi; tek kaynak sigdb_builtin/<modul>.py.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.database import SIGNATURES as _BUILTIN_DATABASE_SIGS
from karadul.analyzers.sigdb_builtin.posix_system import SIGNATURES as _BUILTIN_POSIX_SYSTEM_SIGS
from karadul.analyzers.sigdb_builtin.linux_system import SIGNATURES as _BUILTIN_LINUX_SYSTEM_SIGS
from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES as _BUILTIN_MACOS_APPLE_SIGS
from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES as _BUILTIN_WINDOWS_API_SIGS
from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES as _BUILTIN_RUNTIMES_SIGS
from karadul.analyzers.sigdb_builtin.graphics_media import SIGNATURES as _BUILTIN_GRAPHICS_MEDIA_SIGS
from karadul.analyzers.sigdb_builtin.event_utils import SIGNATURES as _BUILTIN_EVENT_UTILS_SIGS
from karadul.analyzers.sigdb_builtin.game_ml import SIGNATURES as _BUILTIN_GAME_ML_SIGS
from karadul.analyzers.sigdb_builtin.strings_module import SIGNATURES as _BUILTIN_STRINGS_MODULE_SIGS
from karadul.analyzers.sigdb_builtin.calls import SIGNATURES as _BUILTIN_CALLS_SIGS



# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class FunctionSignature:
    """Bilinen bir kutupahane fonksiyonunun imzasi.

    byte_pattern ve byte_mask: Fonksiyonun ilk N byte'i ile karsilastirilir.
    byte_mask'teki 0xFF olan byte'lar birebir eslesmelidir (sabit),
    0x00 olan byte'lar wildcard'dir (herhangi deger olabilir, ornegin
    relative offset'ler veya relocatable adresler).
    """

    name: str                          # "EVP_EncryptInit_ex"
    library: str                       # "openssl"
    version: str = ""                  # "3.0"
    byte_pattern: bytes = b""          # ilk 32 byte
    byte_mask: bytes = b""             # FF=sabit, 00=wildcard
    size_range: tuple[int, int] = (0, 0)  # (min_size, max_size)
    purpose: str = ""                  # "AES encryption initialization"
    category: str = ""                 # "crypto", "compression", "network"


@dataclass
class SignatureMatch:
    """Bir fonksiyon icin bulunan eslestirme sonucu."""

    original_name: str      # Ghidra'nin verdigi isim (FUN_xxx)
    matched_name: str       # DB'deki gercek isim
    library: str            # Hangi kutuphane
    confidence: float       # 0.0-1.0
    match_method: str       # "byte_pattern", "string_ref", "call_pattern", "symbol"
    purpose: str = ""       # "SHA-256 hash computation"
    category: str = ""      # "crypto", "compression"
    version: str = ""       # Kutuphane versiyonu (biliniyorsa)
    # v1.10.0 M2 T4: bilinen sig DB'den tasinan parametre metadata'si.
    # Format: [{"name": str, "type": str, "index": int}, ...]
    # None = sig DB'de params bilgisi yok (fallback'e API_PARAM_DB yolu kullanilir).
    params: list[dict] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_name": self.original_name,
            "matched_name": self.matched_name,
            "library": self.library,
            "confidence": self.confidence,
            "match_method": self.match_method,
            "purpose": self.purpose,
            "category": self.category,
            "version": self.version,
            "params": self.params,
        }


# ---------------------------------------------------------------------------
# Platform-Aware Signature Filtering  (v1.8.0 Bug 7 fix)
# ---------------------------------------------------------------------------
#
# macOS binary'de Windows API (msvcrt, kernel32) false-positive engellemek
# icin lib ve category bazinda platform filtreleme. Her signature entry'yi
# degistirmek yerine, lib/category adi uzerinden toplu filtreleme yapariz.
#
# Kullanim:  _is_platform_compatible(lib, category, target_platform)
#   target_platform: "macho" | "elf" | "pe" | None (None = filtre yok)

_PE_ONLY_LIBS: frozenset[str] = frozenset({
    "kernel32", "user32", "gdi32", "advapi32", "ntdll", "ws2_32",
    "ole32", "oleaut32", "msvcrt", "wincrypt", "wincng", "crypt32",
    "shell32", "d3d11", "d3d12", "dxgi", "winhttp", "wininet",
    "dbghelp", "iphlpapi", "secur32", "psapi", "pdh", "bcrypt",
})

_MACHO_ONLY_LIBS: frozenset[str] = frozenset({
    "libdispatch", "libobjc", "swift_runtime", "libswiftCore",
    "CoreFoundation", "Foundation", "AppKit",
    "CoreGraphics", "CoreImage", "CoreML", "CoreData",
    "CoreBluetooth", "CoreLocation", "CoreAudio", "CoreVideo",
    "StoreKit", "UserNotifications", "WebKit", "Security",
    "IOKit", "EndpointSecurity", "SystemExtensions",
    "Network", "NetworkExtension", "SystemConfiguration",
    "LaunchServices", "DiskArbitration", "Metal", "ImageIO",
    "CFNetwork", "AVFoundation", "CommonCrypto",
    "libSystem", "libsandbox", "libxpc", "mach", "asl", "os_log",
    "libdyld", "accelerate",
})

_ELF_ONLY_LIBS: frozenset[str] = frozenset({
    "libsystemd", "libdbus",
})

# Category prefix -> platform mapping.
# Eger category bu prefix'lerden biri ile basliyorsa, o platform'a ozeldir.
_PE_ONLY_CATEGORY_PREFIXES: tuple[str, ...] = ("win_",)
_MACHO_ONLY_CATEGORY_PREFIXES: tuple[str, ...] = ("macos_", "objc_runtime", "swift_runtime")
_ELF_ONLY_CATEGORY_PREFIXES: tuple[str, ...] = ("linux_",)


def _is_platform_compatible(
    lib: str,
    category: str,
    target_platform: str | None,
    platforms: list[str] | None = None,
) -> bool:
    """Signature'in hedef platform ile uyumlu olup olmadigini kontrol et.

    Args:
        lib: Signature'in kutuphane adi (ornegin "kernel32").
        category: Signature'in kategorisi (ornegin "win_file").
        target_platform: "macho", "elf", "pe" veya None (filtre yok).
        platforms: Explicit platform listesi (external JSON'dan gelen).
                   Ornegin ["pe"] veya ["macho", "elf"].
                   None veya bos liste = lib/category bazli otomatik tespit.

    Returns:
        True  -> eslestirme kullanilabilir.
        False -> platform uyumsuz, skip edilmeli.
    """
    if target_platform is None:
        return True

    # External JSON'dan gelen explicit platform listesi varsa onu kullan
    if platforms:
        return target_platform in platforms

    # PE-only kontrol
    if lib in _PE_ONLY_LIBS or any(
        category.startswith(p) for p in _PE_ONLY_CATEGORY_PREFIXES
    ):
        return target_platform == "pe"

    # Mach-O-only kontrol
    if lib in _MACHO_ONLY_LIBS or any(
        category.startswith(p) for p in _MACHO_ONLY_CATEGORY_PREFIXES
    ):
        return target_platform == "macho"

    # ELF-only kontrol
    if lib in _ELF_ONLY_LIBS or any(
        category.startswith(p) for p in _ELF_ONLY_CATEGORY_PREFIXES
    ):
        return target_platform == "elf"

    # Cross-platform: her platformda kullanilabilir
    return True


def _infer_platform_from_filename(filename: str) -> list[str] | None:
    """Dosya adindan platform tahmini yap.

    Args:
        filename: JSON dosyasinin adi (ornegin "windows_crypto.json").

    Returns:
        Platform listesi veya None (tahmin yapilamadi).
    """
    name_lower = filename.lower()
    if name_lower.startswith("windows_") or name_lower.startswith("win_"):
        return ["pe"]
    if name_lower.startswith("linux_"):
        return ["elf"]
    if name_lower.startswith("macos_") or name_lower.startswith("darwin_"):
        return ["macho"]
    return None


# ---------------------------------------------------------------------------
# Builtin Signature Database -- macOS System Libraries
# ---------------------------------------------------------------------------

# Format: name -> {lib, purpose, category}
# Bunlar symbol tablosundan direk eslestirme icin.

_MACOS_SYSTEM_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["macos_system"]


# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — crypto kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.crypto (tek kaynak).
# ADR 0007 Faz A-DELETE: legacy inline dict gövdeleri silindi; veri
# sigdb_builtin/crypto.py icinden gelir. Rollback gerekirse `git revert`
# ile bu commit geri alinir, override pattern devreye doner.
# v1.13 Wave 1: modern_crypto_signatures eklendi (ChaCha/Salsa/Blake2,
# 138 entry).
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.crypto import (
    SIGNATURES as _BUILTIN_CRYPTO_SIGNATURES,
)

_OPENSSL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["openssl_signatures"]
_BORINGSSL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["boringssl_signatures"]
_LIBSODIUM_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["libsodium_signatures"]
_MBEDTLS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["mbedtls_signatures"]
_WINCRYPTO_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["wincrypto_signatures"]
_MODERN_CRYPTO_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_CRYPTO_SIGNATURES["modern_crypto_signatures"]




# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — compression kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.compression (tek kaynak).
# ADR 0007 Faz A-DELETE: zlib/bzip2/lz4/zstd/compression_ext legacy inline
# dict gövdeleri silindi.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.compression import (
    SIGNATURES as _BUILTIN_COMPRESSION_SIGNATURES,
)

_ZLIB_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_COMPRESSION_SIGNATURES["zlib_signatures"]
_BZIP2_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_COMPRESSION_SIGNATURES["bzip2_signatures"]
_LZ4_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_COMPRESSION_SIGNATURES["lz4_signatures"]
_ZSTD_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_COMPRESSION_SIGNATURES["zstd_signatures"]
_COMPRESSION_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_COMPRESSION_SIGNATURES["compression_ext_signatures"]




# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — network kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.network (tek kaynak).
# ADR 0007 Faz A-DELETE: legacy inline dict gövdeleri silindi.
# Not: _CARES_SIGNATURES ve _GRPC_SIGNATURES henuz migrate edilmedi
# (ADR 0008 kapsami), legacy inline tanimi olarak burada kalmaya devam eder.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.network import (
    SIGNATURES as _BUILTIN_NETWORK_SIGNATURES,
)

_LIBCURL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["libcurl_signatures"]
_POSIX_NETWORKING_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["posix_networking_signatures"]
_NGHTTP2_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["nghttp2_signatures"]
_WEBSOCKET_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["websocket_signatures"]
_MACOS_NETWORKING_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["macos_networking_signatures"]
_APPLE_NETWORK_FRAMEWORK_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["apple_network_framework_signatures"]
_NETWORKING_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_NETWORK_SIGNATURES["networking_ext_signatures"]




# ---------------------------------------------------------------------------
# Builtin Signature Database -- Protocol Buffers
# ---------------------------------------------------------------------------

_PROTOBUF_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["protobuf_signatures"]


# v1.10.0 M6 (perf fix): Modul-level basename index.
# _match_by_symbol icinde her C++ symbol icin 90+ protobuf imzasi uzerinde
# linear scan yapiliyordu. Bu index basename -> (sym_name, info) eslesmesini
# O(1) dict.get ile yapiyor. Insertion-order korundugu icin ilk eslesme
# deterministik donulur (eski behavior ile ayni).
#
# Format: {"SerializeToString": ("google::protobuf::MessageLite::SerializeToString",
#                                 {"lib": "protobuf", ...})}
_PROTOBUF_BASENAME_INDEX: dict[str, tuple[str, dict[str, Any]]] = {}


def _build_protobuf_basename_index() -> None:
    """_PROTOBUF_SIGNATURES icinden basename -> (full_name, info) index'i insa et.

    Sadece "::"-li (namespace'li) isimler icin calisir; basename, son "::"den
    sonraki parcadir. First-wins: ayni basename'e sahip birden fazla sembol
    varsa insertion-order ilk eslesen tutulur (eski loop semantigi ile ayni).
    """
    _PROTOBUF_BASENAME_INDEX.clear()
    for _sym_name, _info in _PROTOBUF_SIGNATURES.items():
        if "::" not in _sym_name:
            continue
        _basename = _sym_name.rsplit("::", 1)[-1]
        if _basename and _basename not in _PROTOBUF_BASENAME_INDEX:
            _PROTOBUF_BASENAME_INDEX[_basename] = (_sym_name, _info)


# Modul yuklenirken bir kez insa et (protobuf sigs sabit, instance-bagimsiz).
_build_protobuf_basename_index()


# ---------------------------------------------------------------------------
# Builtin Signature Database -- SQLite
# ---------------------------------------------------------------------------

_SQLITE_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["sqlite_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- JSON parsers (cJSON, yyjson, jansson)
# ---------------------------------------------------------------------------

_JSON_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["json_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- XML parsers (libxml2, expat)
# ---------------------------------------------------------------------------

_XML_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["xml_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- POSIX File I/O
# ---------------------------------------------------------------------------

_POSIX_FILE_IO_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["posix_file_io_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Process Management
# ---------------------------------------------------------------------------

_PROCESS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["process_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- POSIX Threads (pthreads)
# ---------------------------------------------------------------------------

_PTHREAD_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["pthread_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Memory Management
# ---------------------------------------------------------------------------

_MEMORY_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["memory_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- String / stdlib
# ---------------------------------------------------------------------------

_STRING_STDLIB_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["string_stdlib_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Time
# ---------------------------------------------------------------------------

_TIME_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["time_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Dynamic Loading (dlopen / dyld)
# ---------------------------------------------------------------------------

_DYNLOAD_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["dynload_signatures"]


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Error / Locale / Misc
# ---------------------------------------------------------------------------

_ERROR_LOCALE_MISC_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_POSIX_SYSTEM_SIGS["error_locale_misc_signatures"]





# ---------------------------------------------------------------------------
# Builtin Signature Database -- c-ares (Async DNS)
# ---------------------------------------------------------------------------

_CARES_SIGNATURES: dict[str, dict[str, str]] = {
    "_ares_init": {"lib": "c-ares", "purpose": "init resolver channel", "category": "network"},
    "_ares_init_options": {"lib": "c-ares", "purpose": "init resolver with options", "category": "network"},
    "_ares_destroy": {"lib": "c-ares", "purpose": "destroy resolver channel", "category": "network"},
    "_ares_gethostbyname": {"lib": "c-ares", "purpose": "async DNS lookup", "category": "network"},
    "_ares_gethostbyaddr": {"lib": "c-ares", "purpose": "async reverse DNS", "category": "network"},
    "_ares_getaddrinfo": {"lib": "c-ares", "purpose": "async getaddrinfo", "category": "network"},
    "_ares_freeaddrinfo": {"lib": "c-ares", "purpose": "free ares addrinfo", "category": "network"},
    "_ares_process": {"lib": "c-ares", "purpose": "process pending queries", "category": "network"},
    "_ares_process_fd": {"lib": "c-ares", "purpose": "process queries on fd", "category": "network"},
    "_ares_send": {"lib": "c-ares", "purpose": "send raw DNS query", "category": "network"},
    "_ares_query": {"lib": "c-ares", "purpose": "send DNS query by type", "category": "network"},
    "_ares_search": {"lib": "c-ares", "purpose": "DNS search with domain list", "category": "network"},
    "_ares_cancel": {"lib": "c-ares", "purpose": "cancel pending queries", "category": "network"},
    "_ares_strerror": {"lib": "c-ares", "purpose": "error string lookup", "category": "network"},
    "_ares_free_string": {"lib": "c-ares", "purpose": "free ares string", "category": "network"},
    "_ares_set_socket_callback": {"lib": "c-ares", "purpose": "set socket creation callback", "category": "network"},
    "_ares_set_socket_configure_callback": {"lib": "c-ares", "purpose": "set socket config callback", "category": "network"},
    "_ares_getsock": {"lib": "c-ares", "purpose": "get active socket fds", "category": "network"},
    "_ares_timeout": {"lib": "c-ares", "purpose": "get query timeout value", "category": "network"},
    "_ares_expand_name": {"lib": "c-ares", "purpose": "expand compressed DNS name", "category": "network"},
    "_ares_parse_a_reply": {"lib": "c-ares", "purpose": "parse A record reply", "category": "network"},
    "_ares_parse_aaaa_reply": {"lib": "c-ares", "purpose": "parse AAAA record reply", "category": "network"},
    "_ares_parse_ptr_reply": {"lib": "c-ares", "purpose": "parse PTR record reply", "category": "network"},
    "_ares_parse_mx_reply": {"lib": "c-ares", "purpose": "parse MX record reply", "category": "network"},
    "_ares_parse_txt_reply": {"lib": "c-ares", "purpose": "parse TXT record reply", "category": "network"},
    "_ares_parse_srv_reply": {"lib": "c-ares", "purpose": "parse SRV record reply", "category": "network"},
}






# ---------------------------------------------------------------------------
# Builtin Signature Database -- gRPC C core
# ---------------------------------------------------------------------------

_GRPC_SIGNATURES: dict[str, dict[str, str]] = {
    "_grpc_init": {"lib": "grpc", "purpose": "gRPC library init", "category": "network"},
    "_grpc_shutdown": {"lib": "grpc", "purpose": "gRPC library shutdown", "category": "network"},
    "_grpc_channel_create": {"lib": "grpc", "purpose": "create gRPC channel", "category": "network"},
    "_grpc_channel_destroy": {"lib": "grpc", "purpose": "destroy gRPC channel", "category": "network"},
    "_grpc_channel_check_connectivity_state": {"lib": "grpc", "purpose": "check channel connectivity", "category": "network"},
    "_grpc_channel_watch_connectivity_state": {"lib": "grpc", "purpose": "watch connectivity changes", "category": "network"},
    "_grpc_insecure_channel_create": {"lib": "grpc", "purpose": "create insecure channel", "category": "network"},
    "_grpc_ssl_channel_create": {"lib": "grpc", "purpose": "create SSL channel", "category": "network"},
    "_grpc_call_start_batch": {"lib": "grpc", "purpose": "start RPC operation batch", "category": "network"},
    "_grpc_call_cancel": {"lib": "grpc", "purpose": "cancel RPC call", "category": "network"},
    "_grpc_call_cancel_with_status": {"lib": "grpc", "purpose": "cancel RPC with status", "category": "network"},
    "_grpc_call_unref": {"lib": "grpc", "purpose": "release RPC call ref", "category": "network"},
    "_grpc_call_ref": {"lib": "grpc", "purpose": "retain RPC call ref", "category": "network"},
    "_grpc_call_get_peer": {"lib": "grpc", "purpose": "get RPC peer address", "category": "network"},
    "_grpc_completion_queue_create_for_next": {"lib": "grpc", "purpose": "create completion queue (next)", "category": "network"},
    "_grpc_completion_queue_create_for_pluck": {"lib": "grpc", "purpose": "create completion queue (pluck)", "category": "network"},
    "_grpc_completion_queue_next": {"lib": "grpc", "purpose": "poll completion queue", "category": "network"},
    "_grpc_completion_queue_pluck": {"lib": "grpc", "purpose": "pluck completion event", "category": "network"},
    "_grpc_completion_queue_shutdown": {"lib": "grpc", "purpose": "shutdown completion queue", "category": "network"},
    "_grpc_completion_queue_destroy": {"lib": "grpc", "purpose": "destroy completion queue", "category": "network"},
    "_grpc_server_create": {"lib": "grpc", "purpose": "create gRPC server", "category": "network"},
    "_grpc_server_add_insecure_http2_port": {"lib": "grpc", "purpose": "add insecure server port", "category": "network"},
    "_grpc_server_add_secure_http2_port": {"lib": "grpc", "purpose": "add secure server port", "category": "network"},
    "_grpc_server_start": {"lib": "grpc", "purpose": "start gRPC server", "category": "network"},
    "_grpc_server_shutdown_and_notify": {"lib": "grpc", "purpose": "shutdown gRPC server", "category": "network"},
    "_grpc_server_cancel_all_calls": {"lib": "grpc", "purpose": "cancel all server calls", "category": "network"},
    "_grpc_server_destroy": {"lib": "grpc", "purpose": "destroy gRPC server", "category": "network"},
    "_grpc_server_request_call": {"lib": "grpc", "purpose": "request incoming RPC", "category": "network"},
    "_grpc_byte_buffer_reader_init": {"lib": "grpc", "purpose": "init byte buffer reader", "category": "network"},
    "_grpc_byte_buffer_reader_next": {"lib": "grpc", "purpose": "read next byte buffer slice", "category": "network"},
    "_grpc_byte_buffer_reader_destroy": {"lib": "grpc", "purpose": "destroy byte buffer reader", "category": "network"},
    "_grpc_byte_buffer_destroy": {"lib": "grpc", "purpose": "destroy byte buffer", "category": "network"},
    "_grpc_byte_buffer_length": {"lib": "grpc", "purpose": "byte buffer length", "category": "network"},
    "_grpc_raw_byte_buffer_create": {"lib": "grpc", "purpose": "create raw byte buffer", "category": "network"},
    "_grpc_metadata_array_init": {"lib": "grpc", "purpose": "init metadata array", "category": "network"},
    "_grpc_metadata_array_destroy": {"lib": "grpc", "purpose": "destroy metadata array", "category": "network"},
    "_grpc_ssl_credentials_create": {"lib": "grpc", "purpose": "create SSL credentials", "category": "network"},
    "_grpc_composite_channel_credentials_create": {"lib": "grpc", "purpose": "create composite credentials", "category": "network"},
    "_grpc_google_default_credentials_create": {"lib": "grpc", "purpose": "Google default credentials", "category": "network"},
}




# ---------------------------------------------------------------------------
# Builtin Signature Database -- IPC / XPC (Extended)
# ---------------------------------------------------------------------------

_IPC_XPC_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["ipc_xpc"]


# ---------------------------------------------------------------------------
# C++ STL (libc++ mangled names)
# ---------------------------------------------------------------------------

_CPP_STL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_STRINGS_MODULE_SIGS["cpp_stl"]


# ---------------------------------------------------------------------------
# OpenGL / Metal / GPU (~60)
# ---------------------------------------------------------------------------

_OPENGL_METAL_GPU_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["opengl_metal_gpu_signatures"]


# ---------------------------------------------------------------------------
# CoreGraphics (~40)
# ---------------------------------------------------------------------------

_COREGRAPHICS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["coregraphics_signatures"]


# ---------------------------------------------------------------------------
# CoreImage + CoreML (~10)
# ---------------------------------------------------------------------------

_COREIMAGE_COREML_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["coreimage_coreml_signatures"]


# ---------------------------------------------------------------------------
# Image Libraries: libpng, libjpeg, libwebp, ImageIO (~50)
# ---------------------------------------------------------------------------

_IMAGE_LIB_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["image_lib_signatures"]


# ---------------------------------------------------------------------------
# Audio: CoreAudio, AVFoundation, OpenAL (~50)
# ---------------------------------------------------------------------------

_AUDIO_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["audio_signatures"]


# ---------------------------------------------------------------------------
# FFmpeg / libav (~35)
# ---------------------------------------------------------------------------

_FFMPEG_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["ffmpeg_signatures"]


# ---------------------------------------------------------------------------
# SDL2 (~30)
# ---------------------------------------------------------------------------

_SDL2_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["sdl2_signatures"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreData (~16)
# ---------------------------------------------------------------------------

_APPLE_COREDATA_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_coredata"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- WebKit (~13)
# ---------------------------------------------------------------------------

_APPLE_WEBKIT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_webkit"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreLocation (~9)
# ---------------------------------------------------------------------------

_APPLE_CORELOCATION_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_corelocation"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreBluetooth (~11)
# ---------------------------------------------------------------------------

_APPLE_COREBLUETOOTH_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_corebluetooth"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- StoreKit (~10)
# ---------------------------------------------------------------------------

_APPLE_STOREKIT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_storekit"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- UserNotifications (~11)
# ---------------------------------------------------------------------------

_APPLE_USERNOTIFICATIONS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_usernotifications"]




# ---------------------------------------------------------------------------
# Apple Frameworks -- EndpointSecurity extended (~14)
# ---------------------------------------------------------------------------

_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_endpoint_security_ext"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- SystemExtensions (~3)
# ---------------------------------------------------------------------------

_APPLE_SYSTEMEXTENSIONS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_systemextensions"]


# ---------------------------------------------------------------------------
# Apple Frameworks -- AppKit macOS UI (~80)
# ---------------------------------------------------------------------------

_APPLE_APPKIT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["apple_appkit"]


# ---------------------------------------------------------------------------
# Boost C++ Libraries (~60)
# ---------------------------------------------------------------------------

_BOOST_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_STRINGS_MODULE_SIGS["boost"]


# ---------------------------------------------------------------------------
# Google Abseil (~45)
# ---------------------------------------------------------------------------

_ABSEIL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_STRINGS_MODULE_SIGS["abseil"]


# ---------------------------------------------------------------------------
# Facebook Folly (~33)
# ---------------------------------------------------------------------------

_FOLLY_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_STRINGS_MODULE_SIGS["folly"]


# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — logging kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.logging (tek kaynak).
# Kapsam: syslog, journald, ETW, DTrace, libdbus, PDH (toplam 83 entry).
# ADR 0007 Faz A-DELETE: legacy inline gövdeleri silindi.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.logging import (
    SIGNATURES as _BUILTIN_LOGGING_SIGNATURES,
)

_LOGGING_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LOGGING_SIGNATURES["logging_signatures"]
_LOGGING_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LOGGING_SIGNATURES["logging_ext_signatures"]




# ---------------------------------------------------------------------------
# Serialization -- FlatBuffers, Cap'n Proto, MessagePack (~40)
# ---------------------------------------------------------------------------

_SERIALIZATION_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["serialization_signatures"]


# ---------------------------------------------------------------------------
# Windows API -- kernel32 (~55)
# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — pe_runtime kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.pe_runtime (tek kaynak).
# Kapsam: kernel32, ntdll, msvc_crt (180+ MSVCRT/UCRT/VCRUNTIME entry).
# ADR 0007 Faz A-DELETE: legacy inline gövdeleri silindi.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.pe_runtime import (
    SIGNATURES as _BUILTIN_PE_RUNTIME_SIGNATURES,
)

_WIN32_KERNEL32_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_PE_RUNTIME_SIGNATURES["kernel32_signatures"]
_WIN32_NTDLL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_PE_RUNTIME_SIGNATURES["ntdll_signatures"]
_MSVC_CRT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_PE_RUNTIME_SIGNATURES["msvc_crt_signatures"]




# ---------------------------------------------------------------------------
# Windows API -- ws2_32 (Winsock) (~20)
# ---------------------------------------------------------------------------

_WIN32_WS2_32_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_WINDOWS_API_SIGS["win32_ws2_32_signatures"]


# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — windows_gui kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.windows_gui (tek kaynak).
# Kapsam: user32 (GUI/mesaj/menu/dialog/input/clipboard/hook), advapi32
# (registry/service/token/CryptoAPI/event-log/ACL), gdi32 (DC/pen/brush/
# font/text/bitmap/region/path). Toplam ~560 entry.
# ADR 0007 Faz A-DELETE: legacy inline gövdeleri silindi.
# Türev dict'ler:
#   _WIN32_USER32_GDI32_SIGNATURES = user32 + gdi32 birlesik (legacy alias)
#   _WIN32_ADVAPI32_SIGNATURES     = advapi32 (legacy alias, full sürüm)
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.windows_gui import (
    SIGNATURES as _BUILTIN_WINDOWS_GUI_SIGNATURES,
)

_WIN32_USER32_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_WINDOWS_GUI_SIGNATURES["user32_signatures"]
_WIN32_ADVAPI32_FULL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_WINDOWS_GUI_SIGNATURES["advapi32_signatures"]
_WIN32_GDI32_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_WINDOWS_GUI_SIGNATURES["gdi32_signatures"]
_WIN32_USER32_GDI32_SIGNATURES: dict[str, dict[str, str]] = {
    **_WIN32_USER32_SIGNATURES,
    **_WIN32_GDI32_SIGNATURES,
}
_WIN32_ADVAPI32_SIGNATURES: dict[str, dict[str, str]] = _WIN32_ADVAPI32_FULL_SIGNATURES












# ---------------------------------------------------------------------------
# Fallback dict'ler — Faz 7 modern_runtime override oncesi bos tanimlanir.
# `sigdb_builtin.modern_runtime` import basarisiz olursa bos kalir; legacy
# `_RUST_STDLIB_SIGNATURES` / `_GO_RUNTIME_SIGNATURES` BOZULMAZ, bu iki
# dict onlara EK genisleme getirir (idempotent update).
# ---------------------------------------------------------------------------
_MODERN_RUST_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = {}
_MODERN_GO_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = {}


# ---------------------------------------------------------------------------
# sig_db Faz 7 — Modern runtime (Rust + Go) kategori override (dalga 7)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.modern_runtime` modulune tasindi.
# Mevcut `_RUST_STDLIB_SIGNATURES` / `_GO_RUNTIME_SIGNATURES` /
# `_RUST_EXT_SIGNATURES` / `_GO_EXT_SIGNATURES` dict'leri KORUNUR —
# bu iki yeni dict EK genisleme saglar (demangled core::* / std::* isim
# formlari, tokio/reqwest/hyper, serde, clap, aes-gcm, chacha20poly1305,
# Go scheduler/GC/map-fast-path, net/http, crypto/tls, encoding).
#
# Malware-specific framework (Sliver, BlackCat, Chisel vb.) iceriK YOK;
# v1.13+ malware_signatures modulune birakilir.
#
# Cakisan anahtarlar ayni ``lib`` / ``purpose`` tasir; tuple siralama
# dict.update idempotent'tir. Platform-bagimsiz etiketler kullanilir
# (``rust_*`` / ``go_*``); filter blocklamaz.
try:
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        SIGNATURES as _BUILTIN_MODERN_RUNTIME_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_MODERN_RUNTIME_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_MODERN_RUNTIME_SIGNATURES is not None:
    _MODERN_RUST_RUNTIME_SIGNATURES = _BUILTIN_MODERN_RUNTIME_SIGNATURES.get(
        "rust_runtime_signatures", _MODERN_RUST_RUNTIME_SIGNATURES
    )
    _MODERN_GO_RUNTIME_SIGNATURES = _BUILTIN_MODERN_RUNTIME_SIGNATURES.get(
        "go_runtime_signatures", _MODERN_GO_RUNTIME_SIGNATURES
    )


# ---------------------------------------------------------------------------
# Fallback dict'ler — Faz 6 apple_runtime override oncesi bos tanimlanir.
# `sigdb_builtin.apple_runtime` import basarisiz olursa bos kalir; legacy
# `_MACOS_SYSTEM_SIGNATURES` / `_MACOS_EXT_SIGNATURES` BOZULMAZ, bu uc dict
# onlara EK genisleme getirir (idempotent update).
# ---------------------------------------------------------------------------
_APPLE_OBJC_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = {}
_APPLE_SWIFT_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = {}
_APPLE_COREFOUNDATION_SIGNATURES: dict[str, dict[str, str]] = {}


# ---------------------------------------------------------------------------
# sig_db Faz 6 — Apple runtime (Obj-C + Swift + CoreFoundation) override
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.apple_runtime` modulune tasindi.
# macOS/iOS Mach-O binary analizi icin kritik uc dict:
#   - objc_runtime  -> libobjc ARC + dispatch + introspection (~185 entry)
#   - swift_runtime -> libswiftCore ARC + cast + metadata + stdlib (~130)
#   - corefoundation -> CFString/Array/Dict/Data/URL/Bundle/RunLoop (~195)
#
# Legacy `_MACOS_SYSTEM_SIGNATURES` icinde `_objc_*` / `_swift_*` mangled
# Mach-O sembolleri (leading underscore) zaten mevcut; bu modul UNMANGLED
# isim formlari eklediginden AYRI anahtar kumesidir (cakisma yok).
# Legacy `_MACOS_EXT_SIGNATURES` icindeki CoreFoundation entry'leri ile
# cakisan anahtarlar ayni ``lib`` / ``category="macos_cf"`` tasir —
# idempotent update.
#
# Platform filtrelemesi:
#   - `objc_runtime` kategorisi `_MACHO_ONLY_CATEGORY_PREFIXES` ile macho-only.
#   - `swift_runtime` kategorisi ayni tuple'a eklendi (yukarida).
#   - `macos_cf` zaten `macos_` prefix'i ile macho-only.
#   - `libswiftCore` lib'i `_MACHO_ONLY_LIBS` frozenset'ine eklendi.
try:
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        SIGNATURES as _BUILTIN_APPLE_RUNTIME_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_APPLE_RUNTIME_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_APPLE_RUNTIME_SIGNATURES is not None:
    _APPLE_OBJC_RUNTIME_SIGNATURES = _BUILTIN_APPLE_RUNTIME_SIGNATURES.get(
        "objc_runtime_signatures", _APPLE_OBJC_RUNTIME_SIGNATURES
    )
    _APPLE_SWIFT_RUNTIME_SIGNATURES = _BUILTIN_APPLE_RUNTIME_SIGNATURES.get(
        "swift_runtime_signatures", _APPLE_SWIFT_RUNTIME_SIGNATURES
    )
    _APPLE_COREFOUNDATION_SIGNATURES = _BUILTIN_APPLE_RUNTIME_SIGNATURES.get(
        "corefoundation_signatures", _APPLE_COREFOUNDATION_SIGNATURES
    )


# ---------------------------------------------------------------------------
# Linux-specific syscall wrappers (~35)
# glibc/musl wrapper'lari.  macOS binary'lerinde bulunmaz ama
# cross-platform analiz icin gerekli.
# ---------------------------------------------------------------------------

_LINUX_SYSCALL_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LINUX_SYSTEM_SIGS["linux_syscall_signatures"]


# ---------------------------------------------------------------------------
# Rust standard library (~50)
# v0 mangling (_RN...) ve legacy mangling (__ZN...) pattern'leri.
# Partial prefix eslestirme ile calisir -- symbol adinin basi bu prefix ile
# baslarsa eslestirme olur.
# ---------------------------------------------------------------------------

_RUST_STDLIB_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_RUNTIMES_SIGS["rust_stdlib_signatures"]


# ---------------------------------------------------------------------------
# Go runtime (~55)
# Go binary'lerinde distinctive symbol isimleri.
# Go linker strip etmezse symbol tablosunda gorunur.
# ---------------------------------------------------------------------------

_GO_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_RUNTIMES_SIGS["go_runtime_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Linux System Calls (~200 imza)
# Temel POSIX syscall wrapper'lari, mevcut _LINUX_SYSCALL_SIGNATURES'i
# tamamlar. glibc/musl'da bulunan tum onemli syscall'lar.
# ---------------------------------------------------------------------------

_LINUX_SYSCALL_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LINUX_SYSTEM_SIGS["linux_syscall_ext_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Windows API (~300 imza)
# kernel32, ws2_32, advapi32, user32, gdi32 genisletme + yeni DLL'ler
# (crypt32, ole32, shell32, version, comctl32, winhttp, bcrypt)
# ---------------------------------------------------------------------------

_WIN32_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_WINDOWS_API_SIGS["win32_ext_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Rust Standard Library (~100 imza)
# Tokio async runtime, serde, popular crate patterns.
# ---------------------------------------------------------------------------

_RUST_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_RUNTIMES_SIGS["rust_ext_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Go Runtime + stdlib (~100 imza)
# Go binary'lerde gorulen ek paket fonksiyonlari.
# ---------------------------------------------------------------------------

_GO_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_RUNTIMES_SIGS["go_ext_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: ELF/Linux libc functions (~100 imza)
# C standard library (glibc/musl), dlopen/dlsym, pthread extended
# ---------------------------------------------------------------------------

_LIBC_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LINUX_SYSTEM_SIGS["libc_ext_signatures"]


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# EXTENDED: Database Libraries (~100 imza)
# MySQL, PostgreSQL, Redis, LMDB, LevelDB, MongoDB
# ---------------------------------------------------------------------------

_DATABASE_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_DATABASE_SIGS["database_ext_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Python C API (~80 imza)
# CPython embedded runtime fonksiyonlari.
# ---------------------------------------------------------------------------

_PYTHON_CAPI_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Interpreter ---
    "Py_Initialize": {"lib": "python", "purpose": "initialize Python interpreter", "category": "python"},
    "Py_InitializeEx": {"lib": "python", "purpose": "initialize with signal config", "category": "python"},
    "Py_Finalize": {"lib": "python", "purpose": "finalize Python interpreter", "category": "python"},
    "Py_FinalizeEx": {"lib": "python", "purpose": "finalize with status return", "category": "python"},
    "Py_IsInitialized": {"lib": "python", "purpose": "check if interpreter initialized", "category": "python"},
    "PyRun_SimpleString": {"lib": "python", "purpose": "execute Python string", "category": "python"},
    "PyRun_SimpleFile": {"lib": "python", "purpose": "execute Python file", "category": "python"},
    "PyRun_String": {"lib": "python", "purpose": "execute string and return result", "category": "python"},
    "Py_CompileString": {"lib": "python", "purpose": "compile Python source to code object", "category": "python"},
    "PyEval_EvalCode": {"lib": "python", "purpose": "evaluate compiled code object", "category": "python"},

    # --- Object protocol ---
    "PyObject_CallObject": {"lib": "python", "purpose": "call Python callable with args tuple", "category": "python"},
    "PyObject_CallFunction": {"lib": "python", "purpose": "call Python callable with format args", "category": "python"},
    "PyObject_CallMethod": {"lib": "python", "purpose": "call method on Python object", "category": "python"},
    "PyObject_GetAttrString": {"lib": "python", "purpose": "get attribute by name", "category": "python"},
    "PyObject_SetAttrString": {"lib": "python", "purpose": "set attribute by name", "category": "python"},
    "PyObject_HasAttrString": {"lib": "python", "purpose": "check attribute exists", "category": "python"},
    "PyObject_Str": {"lib": "python", "purpose": "str() on Python object", "category": "python"},
    "PyObject_Repr": {"lib": "python", "purpose": "repr() on Python object", "category": "python"},
    "PyObject_IsTrue": {"lib": "python", "purpose": "bool() on Python object", "category": "python"},
    "PyObject_Length": {"lib": "python", "purpose": "len() on Python object", "category": "python"},
    "PyObject_GetItem": {"lib": "python", "purpose": "subscript operator obj[key]", "category": "python"},
    "PyObject_SetItem": {"lib": "python", "purpose": "subscript assignment obj[key]=val", "category": "python"},
    "PyObject_RichCompare": {"lib": "python", "purpose": "rich comparison (==, <, > etc)", "category": "python"},

    # --- Reference counting ---
    "Py_IncRef": {"lib": "python", "purpose": "increment reference count", "category": "python"},
    "Py_DecRef": {"lib": "python", "purpose": "decrement reference count", "category": "python"},
    "Py_XINCREF": {"lib": "python", "purpose": "increment refcount (NULL-safe)", "category": "python"},
    "Py_XDECREF": {"lib": "python", "purpose": "decrement refcount (NULL-safe)", "category": "python"},

    # --- Module ---
    "PyImport_ImportModule": {"lib": "python", "purpose": "import Python module", "category": "python"},
    "PyImport_AddModule": {"lib": "python", "purpose": "get or create module", "category": "python"},
    "PyModule_GetDict": {"lib": "python", "purpose": "get module's __dict__", "category": "python"},
    "PyModule_Create2": {"lib": "python", "purpose": "create extension module", "category": "python"},

    # --- Types: int, float, str, bytes ---
    "PyLong_FromLong": {"lib": "python", "purpose": "create Python int from C long", "category": "python"},
    "PyLong_AsLong": {"lib": "python", "purpose": "convert Python int to C long", "category": "python"},
    "PyLong_FromLongLong": {"lib": "python", "purpose": "create Python int from C long long", "category": "python"},
    "PyFloat_FromDouble": {"lib": "python", "purpose": "create Python float from C double", "category": "python"},
    "PyFloat_AsDouble": {"lib": "python", "purpose": "convert Python float to C double", "category": "python"},
    "PyUnicode_FromString": {"lib": "python", "purpose": "create Python str from C string", "category": "python"},
    "PyUnicode_AsUTF8": {"lib": "python", "purpose": "get UTF-8 from Python str", "category": "python"},
    "PyUnicode_FromFormat": {"lib": "python", "purpose": "create str from format string", "category": "python"},
    "PyBytes_FromString": {"lib": "python", "purpose": "create bytes from C string", "category": "python"},
    "PyBytes_FromStringAndSize": {"lib": "python", "purpose": "create bytes with size", "category": "python"},
    "PyBytes_AsString": {"lib": "python", "purpose": "get C char* from bytes", "category": "python"},
    "PyBool_FromLong": {"lib": "python", "purpose": "create Python bool from C long", "category": "python"},

    # --- Container types ---
    "PyList_New": {"lib": "python", "purpose": "create new Python list", "category": "python"},
    "PyList_Append": {"lib": "python", "purpose": "append to Python list", "category": "python"},
    "PyList_GetItem": {"lib": "python", "purpose": "get list item (borrowed ref)", "category": "python"},
    "PyList_SetItem": {"lib": "python", "purpose": "set list item (steals ref)", "category": "python"},
    "PyList_Size": {"lib": "python", "purpose": "get list length", "category": "python"},
    "PyDict_New": {"lib": "python", "purpose": "create new Python dict", "category": "python"},
    "PyDict_SetItemString": {"lib": "python", "purpose": "set dict item by string key", "category": "python"},
    "PyDict_GetItemString": {"lib": "python", "purpose": "get dict item by string key", "category": "python"},
    "PyDict_SetItem": {"lib": "python", "purpose": "set dict item", "category": "python"},
    "PyDict_GetItem": {"lib": "python", "purpose": "get dict item (borrowed ref)", "category": "python"},
    "PyDict_Keys": {"lib": "python", "purpose": "get dict keys list", "category": "python"},
    "PyDict_Size": {"lib": "python", "purpose": "get dict size", "category": "python"},
    "PyTuple_New": {"lib": "python", "purpose": "create new Python tuple", "category": "python"},
    "PyTuple_SetItem": {"lib": "python", "purpose": "set tuple item (steals ref)", "category": "python"},
    "PyTuple_GetItem": {"lib": "python", "purpose": "get tuple item (borrowed ref)", "category": "python"},
    "PyTuple_Size": {"lib": "python", "purpose": "get tuple length", "category": "python"},
    "PySet_New": {"lib": "python", "purpose": "create new Python set", "category": "python"},
    "PySet_Add": {"lib": "python", "purpose": "add item to set", "category": "python"},

    # --- Error handling ---
    "PyErr_SetString": {"lib": "python", "purpose": "set exception with message", "category": "python"},
    "PyErr_Occurred": {"lib": "python", "purpose": "check if exception is set", "category": "python"},
    "PyErr_Clear": {"lib": "python", "purpose": "clear current exception", "category": "python"},
    "PyErr_Print": {"lib": "python", "purpose": "print exception to stderr", "category": "python"},
    "PyErr_Fetch": {"lib": "python", "purpose": "fetch current exception", "category": "python"},
    "PyErr_Restore": {"lib": "python", "purpose": "restore exception state", "category": "python"},
    "PyErr_Format": {"lib": "python", "purpose": "set exception with formatted message", "category": "python"},
    "PyErr_NoMemory": {"lib": "python", "purpose": "set MemoryError exception", "category": "python"},

    # --- GIL ---
    "PyGILState_Ensure": {"lib": "python", "purpose": "acquire GIL and return state", "category": "python"},
    "PyGILState_Release": {"lib": "python", "purpose": "release GIL", "category": "python"},
    "PyEval_SaveThread": {"lib": "python", "purpose": "release GIL (Py_BEGIN_ALLOW_THREADS)", "category": "python"},
    "PyEval_RestoreThread": {"lib": "python", "purpose": "acquire GIL (Py_END_ALLOW_THREADS)", "category": "python"},

    # --- Arg parsing ---
    "PyArg_ParseTuple": {"lib": "python", "purpose": "parse positional args tuple", "category": "python"},
    "PyArg_ParseTupleAndKeywords": {"lib": "python", "purpose": "parse args and kwargs", "category": "python"},
    "Py_BuildValue": {"lib": "python", "purpose": "build Python value from C values", "category": "python"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Java JNI (~50 imza)
# Java Native Interface - native binary'ler icinde JNI cagrilari.
# ---------------------------------------------------------------------------

_JAVA_JNI_SIGNATURES: dict[str, dict[str, str]] = {
    "JNI_CreateJavaVM": {"lib": "jni", "purpose": "create Java Virtual Machine", "category": "java"},
    "JNI_GetCreatedJavaVMs": {"lib": "jni", "purpose": "get list of created JVMs", "category": "java"},
    "JNI_GetDefaultJavaVMInitArgs": {"lib": "jni", "purpose": "get default JVM init args", "category": "java"},
    "JNI_OnLoad": {"lib": "jni", "purpose": "native library loaded by JVM", "category": "java"},
    "JNI_OnUnload": {"lib": "jni", "purpose": "native library unloaded by JVM", "category": "java"},
    # Env functions (commonly resolved via function pointer table)
    "FindClass": {"lib": "jni", "purpose": "find Java class by name", "category": "java"},
    "GetMethodID": {"lib": "jni", "purpose": "get Java method ID", "category": "java"},
    "GetStaticMethodID": {"lib": "jni", "purpose": "get static Java method ID", "category": "java"},
    "GetFieldID": {"lib": "jni", "purpose": "get Java field ID", "category": "java"},
    "GetStaticFieldID": {"lib": "jni", "purpose": "get static Java field ID", "category": "java"},
    "CallObjectMethod": {"lib": "jni", "purpose": "call Java object method", "category": "java"},
    "CallVoidMethod": {"lib": "jni", "purpose": "call Java void method", "category": "java"},
    "CallIntMethod": {"lib": "jni", "purpose": "call Java int method", "category": "java"},
    "CallBooleanMethod": {"lib": "jni", "purpose": "call Java boolean method", "category": "java"},
    "CallStaticObjectMethod": {"lib": "jni", "purpose": "call static Java method (Object)", "category": "java"},
    "CallStaticVoidMethod": {"lib": "jni", "purpose": "call static Java void method", "category": "java"},
    "NewObject": {"lib": "jni", "purpose": "create new Java object", "category": "java"},
    "NewStringUTF": {"lib": "jni", "purpose": "create Java string from UTF-8", "category": "java"},
    "GetStringUTFChars": {"lib": "jni", "purpose": "get UTF-8 chars from Java string", "category": "java"},
    "ReleaseStringUTFChars": {"lib": "jni", "purpose": "release UTF-8 chars", "category": "java"},
    "GetArrayLength": {"lib": "jni", "purpose": "get Java array length", "category": "java"},
    "GetByteArrayElements": {"lib": "jni", "purpose": "get Java byte array elements", "category": "java"},
    "ReleaseByteArrayElements": {"lib": "jni", "purpose": "release byte array elements", "category": "java"},
    "NewByteArray": {"lib": "jni", "purpose": "create Java byte array", "category": "java"},
    "SetByteArrayRegion": {"lib": "jni", "purpose": "copy bytes into Java array", "category": "java"},
    "GetByteArrayRegion": {"lib": "jni", "purpose": "copy bytes from Java array", "category": "java"},
    "NewGlobalRef": {"lib": "jni", "purpose": "create global JNI reference", "category": "java"},
    "DeleteGlobalRef": {"lib": "jni", "purpose": "delete global JNI reference", "category": "java"},
    "NewLocalRef": {"lib": "jni", "purpose": "create local JNI reference", "category": "java"},
    "DeleteLocalRef": {"lib": "jni", "purpose": "delete local JNI reference", "category": "java"},
    "ExceptionCheck": {"lib": "jni", "purpose": "check for pending Java exception", "category": "java"},
    "ExceptionDescribe": {"lib": "jni", "purpose": "print Java exception to stderr", "category": "java"},
    "ExceptionClear": {"lib": "jni", "purpose": "clear pending Java exception", "category": "java"},
    "ThrowNew": {"lib": "jni", "purpose": "throw new Java exception", "category": "java"},
    "RegisterNatives": {"lib": "jni", "purpose": "register native methods with class", "category": "java"},
    "UnregisterNatives": {"lib": "jni", "purpose": "unregister native methods", "category": "java"},
    "GetObjectClass": {"lib": "jni", "purpose": "get class of Java object", "category": "java"},
    "IsInstanceOf": {"lib": "jni", "purpose": "check Java instanceof", "category": "java"},
    "MonitorEnter": {"lib": "jni", "purpose": "enter Java synchronized block", "category": "java"},
    "MonitorExit": {"lib": "jni", "purpose": "exit Java synchronized block", "category": "java"},
    "GetJavaVM": {"lib": "jni", "purpose": "get JavaVM interface pointer", "category": "java"},
    "AttachCurrentThread": {"lib": "jni", "purpose": "attach native thread to JVM", "category": "java"},
    "DetachCurrentThread": {"lib": "jni", "purpose": "detach native thread from JVM", "category": "java"},
    "GetEnv": {"lib": "jni", "purpose": "get JNI environment for current thread", "category": "java"},
    "GetObjectField": {"lib": "jni", "purpose": "get Java object field value", "category": "java"},
    "SetObjectField": {"lib": "jni", "purpose": "set Java object field value", "category": "java"},
    "GetIntField": {"lib": "jni", "purpose": "get Java int field value", "category": "java"},
    "SetIntField": {"lib": "jni", "purpose": "set Java int field value", "category": "java"},
    "GetLongField": {"lib": "jni", "purpose": "get Java long field value", "category": "java"},
    "SetLongField": {"lib": "jni", "purpose": "set Java long field value", "category": "java"},
}


# ---------------------------------------------------------------------------
# EXTENDED: .NET CLR / CoreCLR (~60 imza)
# Mono ve CoreCLR native fonksiyonlari.
# ---------------------------------------------------------------------------

_DOTNET_CLR_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_RUNTIMES_SIGS["dotnet_clr_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Anti-Reversing / Obfuscation Patterns (~50 imza)
# Binary'lerde gorulen anti-debugging, anti-tampering teknikleri.
# ---------------------------------------------------------------------------

_ANTI_ANALYSIS_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GAME_ML_SIGS["anti_analysis_signatures"]


# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# sig_db Faz 8 — VM runtime (JNI + Python C API) override (dalga 8)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.vm_runtime` modulune tasindi. Legacy
# `_JAVA_JNI_SIGNATURES` (~50 entry) ve `_PYTHON_CAPI_SIGNATURES` (~80 entry)
# override EDILIR. Yeni modul kanonik etiketleme kullanir:
#   - JNI:           lib=jvm/libjvm, category=jni       (legacy: jni/java)
#   - Python C API:  lib=python/libpython, category=python_c_api  (legacy: python/python)
#
# Hybrid binary analizi (libjvm.so / libpython.so embed) icin genisletilmis
# kapsama saglar. Legacy dict'ler SILINMEDI; rollback icin override yontemi
# kullanilir (crypto/compression/network/pe_runtime/windows_gui ile ayni desen).
try:
    from karadul.analyzers.sigdb_builtin.vm_runtime import (
        SIGNATURES as _BUILTIN_VM_RUNTIME_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_VM_RUNTIME_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_VM_RUNTIME_SIGNATURES is not None:
    _JAVA_JNI_SIGNATURES = _BUILTIN_VM_RUNTIME_SIGNATURES.get(
        "jni_signatures", _JAVA_JNI_SIGNATURES
    )
    _PYTHON_CAPI_SIGNATURES = _BUILTIN_VM_RUNTIME_SIGNATURES.get(
        "python_c_api_signatures", _PYTHON_CAPI_SIGNATURES
    )


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# EXTENDED: Multimedia/Graphics Extra (~100 imza)
# Vulkan, Direct3D, DirectX, FreeType, Harfbuzz, Cairo
# ---------------------------------------------------------------------------

_GRAPHICS_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GRAPHICS_MEDIA_SIGS["graphics_ext_signatures"]


# ---------------------------------------------------------------------------
# sig_db Faz A-DELETE (v1.13) — languages kategori dogrudan import
# ---------------------------------------------------------------------------
# Veri kaynagi: karadul.analyzers.sigdb_builtin.languages (tek kaynak).
# Kapsam: V8/Node.js (73), Lua (52), Ruby (30) — toplam 155 imza.
# ADR 0007 Faz A-DELETE: legacy inline gövdeleri silindi.
# ---------------------------------------------------------------------------
from karadul.analyzers.sigdb_builtin.languages import (
    SIGNATURES as _BUILTIN_LANG_SIGNATURES,
)

_V8_NODE_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LANG_SIGNATURES["v8_node"]
_LUA_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LANG_SIGNATURES["lua"]
_RUBY_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_LANG_SIGNATURES["ruby"]








# ---------------------------------------------------------------------------
# v1.13 Dalga 1 — malware_tier1 content pack (Sliver + Cobalt Strike)
# ---------------------------------------------------------------------------
# Tier-1 imza paketi tamamen yeni veridir; signature_db.py icinde inline legacy
# kaynak YOK (Tip A "rollback bandi" pattern'i UYGUN DEGIL). Tip B "yeni dict
# bind" pattern'i kullanilir: import basarisiz olursa bos dict'lerle no-op
# fallback. Toplam 87 entry: Sliver 54 + Cobalt Strike 33.
#
# Veri konumu: karadul/analyzers/sigdb_builtin/malware_tier1.py
# Defansif kullanim: forensics / IOC / pentest fingerprinting (LLM yok,
# deterministic sembol/string lookup).
try:
    from karadul.analyzers.sigdb_builtin.malware_tier1 import (
        SIGNATURES as _BUILTIN_MALWARE_TIER1_SIGS,
    )
    _SLIVER_SIGNATURES = _BUILTIN_MALWARE_TIER1_SIGS.get("sliver", {})
    _COBALTSTRIKE_SIGNATURES = _BUILTIN_MALWARE_TIER1_SIGS.get("cobaltstrike", {})
except ImportError:  # pragma: no cover - paket yoksa bos fallback (no-op)
    _BUILTIN_MALWARE_TIER1_SIGS = None  # type: ignore[assignment]
    _SLIVER_SIGNATURES = {}
    _COBALTSTRIKE_SIGNATURES = {}


# ---------------------------------------------------------------------------
# EXTENDED: Message Queue / Event Systems (~60 imza)
# ZeroMQ, RabbitMQ/AMQP, Kafka, MQTT
# ---------------------------------------------------------------------------

_MSGQUEUE_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["msgqueue_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: ML/AI Libraries (~80 imza)
# CUDA runtime, cuDNN, TensorRT, ONNX Runtime, OpenCV
# ---------------------------------------------------------------------------

_ML_COMPUTE_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GAME_ML_SIGS["ml_compute_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: Game Engines / Physics (~80 imza)
# Unreal, Godot, Box2D, Bullet patterns
# ---------------------------------------------------------------------------

_GAME_ENGINE_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GAME_ML_SIGS["game_engine_signatures"]


# ---------------------------------------------------------------------------
# EXTENDED: macOS/iOS System Calls Extra (~100 imza)
# Mach kernel, IOKit extended, launchd, sandbox
# ---------------------------------------------------------------------------

_MACOS_EXT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_MACOS_APPLE_SIGS["macos_ext"]


# ---------------------------------------------------------------------------
# MEGA BATCH: Additional well-known library functions
# Windows CRT, POSIX extended, Crypto extended, C++ ABI, etc.
# Total: ~4500 new entries to reach 10,000+
# ---------------------------------------------------------------------------

_MEGA_BATCH_1_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GAME_ML_SIGS["mega_batch_1_signatures"]


# ---------------------------------------------------------------------------
# MEGA BATCH 2: Objective-C Runtime, Swift, Foundation, UIKit, AppKit
# macOS prefix ("_") applied where needed.
# ---------------------------------------------------------------------------

_MEGA_BATCH_2_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_GAME_ML_SIGS["mega_batch_2_signatures"]


_LIBUV_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["libuv_signatures"]


# ---------------------------------------------------------------------------
# libevent (event-driven I/O)  ~26 imza
# ---------------------------------------------------------------------------

_LIBEVENT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["libevent_signatures"]


# ---------------------------------------------------------------------------
# PCRE2 / POSIX regex / RE2  ~18 imza
# ---------------------------------------------------------------------------

_REGEX_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["regex_signatures"]


# ---------------------------------------------------------------------------
# ICU (International Components for Unicode)  ~30 imza
# ---------------------------------------------------------------------------

_ICU_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["icu_signatures"]


# ---------------------------------------------------------------------------
# Math / BLAS / LAPACK / Accelerate  ~76 imza
# ---------------------------------------------------------------------------

_MATH_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["math_signatures"]


# ---------------------------------------------------------------------------
# Qt Framework (C++ mangled names)  ~16 imza
# ---------------------------------------------------------------------------

_QT_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["qt_signatures"]




# ---------------------------------------------------------------------------
# Testing frameworks  ~9 imza
# ---------------------------------------------------------------------------

_TESTING_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["testing_signatures"]


# ---------------------------------------------------------------------------
# Misc widely-used: getopt, iconv, readline, termios, uuid, GLib  ~46 imza
# ---------------------------------------------------------------------------

_MISC_SIGNATURES: dict[str, dict[str, str]] = _BUILTIN_EVENT_UTILS_SIGS["misc_signatures"]


# ---------------------------------------------------------------------------
# Katman 2: String Reference Signatures
# ---------------------------------------------------------------------------
# frozenset(string_keywords) -> (fonksiyon_adi, kutuphane)
# Bir fonksiyon bu string'lerin HEPSINI referans olarak kullaniyorsa eslestir.

_STRING_REFERENCE_SIGNATURES: dict[frozenset[str], tuple[str, str, str]] = _BUILTIN_CALLS_SIGS["string_reference"]


# ---------------------------------------------------------------------------
# Katman 3: Call Pattern Signatures (Structural)
# ---------------------------------------------------------------------------
# Fonksiyonun cagirdigi API'lerin sirali kombinasyonundan tanimlama.
# tuple(callee_names) -> (matched_name, library, purpose)
# NOT: Burada sira ONEMLI degil, set olarak eslestirilir.

_CALL_PATTERN_SIGNATURES: list[tuple[frozenset[str], str, str, str, float]] = _BUILTIN_CALLS_SIGS["call_pattern"]


# ---------------------------------------------------------------------------
# Yardimci: regex pattern'ler
# ---------------------------------------------------------------------------

# Ghidra'nin verdigi otomatik isimler
_GHIDRA_AUTO_NAME_RE = re.compile(
    r"^(FUN_|thunk_FUN_|switch_|case_|LAB_|DAT_|PTR_|SUB_)[0-9a-fA-F]+$"
)

# Underscore-prefixed C symbol (macOS convention)
_C_SYMBOL_RE = re.compile(r"^_[a-zA-Z]")


# ---------------------------------------------------------------------------
# FindCrypt-Ghidra Crypto Constants (v1.2.2)
# 126 entry -- kripto sabitleri icin byte pattern eslestirme
# Kaynak: FindCrypt/data/database.json (Ghidra FindCrypt plugini)
# Format: (name, hex_pattern_first_64_bytes, category, purpose)
# Pattern'ler max 64 byte'a truncate edilmistir; tam eslesmede mask=0xFF.
# ---------------------------------------------------------------------------

_FINDCRYPT_CONSTANTS: list[tuple[str, str, str, str]] = [
    ("AES_Encryption_SBox", "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275", "crypto", "AES S-Box (FindCrypt)"),
    ("AES_Decryption_SBox_Inverse", "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125", "crypto", "AES inverse S-Box (FindCrypt)"),
    ("SHA_1", "0123456789abcdeffedcba9876543210f0e1d2c3", "crypto", "SHA-1 init vector (FindCrypt)"),
    ("RC5_RC6", "6351e1b7b979379e", "crypto", "RC5/RC6 magic constant (FindCrypt)"),
    ("MD5", "78a46ad756b7c7e8db702024eecebdc1af0f7cf52ac68747134630a8019546fdd8988069aff7448bb15bffffbed75c892211906b937198fd8e4379a62108b449", "crypto", "MD5 T-table (FindCrypt)"),
    ("MD4", "0123456789abcdeffedcba9876543210", "crypto", "MD4 init vector (FindCrypt)"),
    ("HAVAL", "886a3f24d308a3852e8a191344737003223809a4d0319f2998fa2e08896c4eec", "crypto", "HAVAL constant (FindCrypt)"),
    ("TEA_DELTA", "b979379e", "crypto", "TEA delta constant (FindCrypt)"),
    ("TEA_ALTERNATIVE_DELTA", "4786c861", "crypto", "TEA alternative delta (FindCrypt)"),
    ("Sosemanuk_MulTables_B32", "0000000013cf9fe12637976b35f8088a4c6e87d65fa118376a5910bd79968f5c98dca7058b1338e4beeb306ead24af8fd4b220d3c77dbf32f285b7b8e14a2859", "crypto", "Sosemanuk multiplication table (FindCrypt)"),
    ("Sosemanuk_MulTables_B86", "0000000012cf9fe12437976b36f8088a486e87d65aa118376c5910bd7e968f5c90dca705821338e4b4eb306ea624af8fd8b220d3ca7dbf32fc85b7b8ee4a2859", "crypto", "Sosemanuk multiplication table (FindCrypt)"),
    ("Sosemanuk_MulTabl_B64", "00000000cd400f1833801e30fec0112866a93c60abe933785529225098692d48ccfb78c001bb77d8ff7b66f0323b69e8aa5244a067124bb899d25a9054925588", "crypto", "Sosemanuk multiplication table (FindCrypt)"),
    ("SIMON64_128_3w", "f50e2c1985f86973", "crypto", "SIMON block cipher constant (FindCrypt)"),
    ("SIMON64_128_3w_2", "f50e2c1985f86973", "crypto", "SIMON block cipher constant (FindCrypt)"),
    ("SHACAL2_K", "982f8a4291443771cffbc0b5a5dbb5e95bc25639f111f159a4823f92d55e1cab98aa07d8015b8312be853124c37d0c55745dbe72feb1de80a706dc9b74f19bc1", "crypto", "SHACAL-2 key schedule constant (FindCrypt)"),
    ("SEED_kc", "b979379e73f36e3ce6e6dd78cccdbbf1999b77e33337efc6676ede8dcfdcbc1b9eb979373c73f36e78e6e6ddf1cccdbbe3999b77c63337ef8d676ede1bcfdcbc", "crypto", "SEED key constant (FindCrypt)"),
    ("SEED_s0", "a985d6d3541dac255d43181e51fcca632844209de0e2c817a58f037bbb13d2ee708c3fa832ddf674ec950b575c5bbd01241c739810ccf2d92ce772839bd186c9", "crypto", "SEED S-Box (FindCrypt)"),
    ("SEED_s1", "38e82da6cfdeb3b8af6055c7446f6b5bc36233b529a0e2a7d39111061cbc364bef886ca817c416f4c245e1d63f3d8e98284ef63ea5f90ddfd82b667a272ff172", "crypto", "SEED S-Box (FindCrypt)"),
    ("Salsa_exp16k", "657870616e642031362d62797465206b", "crypto", "Salsa20 expand constant (FindCrypt)"),
    ("Salsa_exp32k", "657870616e642033322d6279b979379e", "crypto", "Salsa20 expand constant (FindCrypt)"),
    ("Lea_delta", "dbe9efc3b7d3df876fa7bf0fde4e7f1fbc9dfe3e783bfd7df076fafbe1edf4f7c3dbe9ef87b7d3df0f6fa7bf1fde4e7f3ebc9dfe7d783bfdfbf076faf7e1edf4", "crypto", "LEA delta constant (FindCrypt)"),
    ("Keccak_rho8", "07000102030405060f08090a0b0c0d0e", "crypto", "Keccak/SHA-3 constant (FindCrypt)"),
    ("Keccak_rho56", "0102030405060700090a0b0c0d0e0f08", "crypto", "Keccak/SHA-3 constant (FindCrypt)"),
    ("KeccakF1600Constants", "010000000000000082800000000000008a8000000000008000800080000000808b80000000000000010000800000000081800080000000800980000000000080", "crypto", "Keccak/SHA-3 constant (FindCrypt)"),
    ("Kalyna_IS", "a4a2a9c54ec903d97e0fd2ade7d3275be3a1e8e67c2a550c8639d78db8126f28cd8a705672f9bf4f73e9f75716ac50c09db7477160c474436c1f9377dcce208c", "crypto", "Kalyna cipher table (FindCrypt)"),
    ("Kalyna_IT", "9a8a5f9f2b942678530c9734c9430f21b851059ddd8f025f3bc894b482cdfa14c068dd6e88ab722bb4d919ff5b7ea8a6ea4364db71e59aa2b6e5e81b912c9b03", "crypto", "Kalyna cipher table (FindCrypt)"),
    ("Kalyna_S", "a8435f066b756c5971df879517f0d8096df31dcbc94d2caf79e097fd6f4b45393edda34fb4b69a0e1fbf15e149d293c692729e61d163faeef419d5ad58a4bba1", "crypto", "Kalyna cipher table (FindCrypt)"),
    ("Kalyna_T", "a89a7fd729a832a84311d497224352435f6180dfc25f3e5f0618121430061e066bb10c677f6bda6b75c956238f75bc756cad1975476cc16c597992cbf2592059", "crypto", "Kalyna cipher table (FindCrypt)"),
    ("HIGHT_DELTA", "5a6d361b0d0603416030184c6633592c562b154a6572391c4e6773793c5e6f375b2d160b0542215028542a556a757a7d3e5f2f174b255229140a456231586c76", "crypto", "HIGHT cipher constant (FindCrypt)"),
    ("HIGHT_F0", "00860d8b1a9c179134b239bf2ea823a568ee65e372f47ff95cda51d746c04bcdd056dd5bca4cc741e462e96ffe78f375b83eb533a224af298c0a810796109b1d", "crypto", "HIGHT cipher constant (FindCrypt)"),
    ("HIGHT_F1", "0058b0e86139d189c29a722aa3fb134b85dd356de4bc540c471ff7af267e96ce0b53bbe36a32da82c9917921a8f018408ed63e66efb75f074c14fca42d759dc5", "crypto", "HIGHT cipher constant (FindCrypt)"),
    ("ge25519_basepoint_64", "1ad5258f602d06002a59f6b4a41204001db3a471715b0700fe18715260ff0100e5d63c6d931602005866666666660600cccccccccccc04009999999999990100", "crypto", "Curve25519 ECC point (FindCrypt)"),
    ("ge25519_ecd_64", "a3785913ca4d0300bd6e153b28a8010029c00160a2e70500bb3ca063c6390700ffb6e2ce36200500", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_ec2d_64", "59f1b226949b06007add2a7650500300528003c044cf0300777940c78c730600ff6dc59d6d400200", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_sqrtneg1_64", "b0a00e4a271b06009d188ffca5d50000600cbd9c5eef07009e4c80a6958507001dfc044832b80200", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_niels_sliding_multiples_64", "3e9140d705390000a273d61728ba00007ce6f427283e0200341ac2e0d2330100818f29f9d24f0400853b8cf5c6930400f725c38171df0000b74c3e0b0bf50000", "crypto", "Curve25519 ECC precomputed table (FindCrypt)"),
    ("modm_m_64", "edd3f55c1a63120058d69cf7a2def900de1400000000000000000000000000000000001000000000", "crypto", "Curve25519 modular constant (FindCrypt)"),
    ("modm_mu_64", "1b132c0aa3e59c00eda72963085d21000621ebffffffff00ffffffffffffff00ffffffff0f000000", "crypto", "Curve25519 modular constant (FindCrypt)"),
    ("ge25519_niels_base_multiples", "3e9140d70539109db3be40d1059f39fd098a8f683484c1a56712f898922ffd44853b8cf5c693bc2f190e8cfbc62d93cfc2423d6498480b2765bad4333a9dcf07", "crypto", "Curve25519 ECC base multiples (FindCrypt)"),
    ("ge25519_basepoint", "1ad525030000000023588b01000000002a59f600000000002da90401000000001db3a401000000005cdcd60100000000fe1871020000000014d87f0000000000", "crypto", "Curve25519 ECC basepoint (FindCrypt)"),
    ("ge25519_ecd", "a3785903000000008472d30000000000bd6e1503000000000e0a6a000000000029c001000000000098e8790100000000bb3ca003000000009871ce0100000000", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_ec2d", "59f1b2020000000009e5a601000000007add2a02000000001d14d40000000000528003000000000030d1f30000000000777940030000000031e39c0100000000", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_sqrtneg1", "b0a00e0200000000d2c98601000000009d188f00000000007f69350000000000600cbd0000000000a7d7fb01000000009e4c8002000000006965e10100000000", "crypto", "Curve25519 ECC constant (FindCrypt)"),
    ("ge25519_niels_sliding_multiples", "3e9140030000000075410e0000000000a273d60300000000058a2e00000000007ce6f40300000000098a8f0000000000341ac20000000000b8f44c0000000000", "crypto", "Curve25519 ECC precomputed table (FindCrypt)"),
    ("modm_m", "edd3f51c00000000698c49200000000065cd792f00000000a877be37000000001400000000000000000000000000000000000000000000000000000000000000", "crypto", "Curve25519 modular constant (FindCrypt)"),
    ("modm_mu", "1b132c0a000000008c967336000000007e9a320600000000425788010000000021ebff3f00000000ffffff3f00000000ffffff3f00000000ffffff3f00000000", "crypto", "Curve25519 modular constant (FindCrypt)"),
    ("ChaChaInitStates_expanded32k", "657870616e642033322d62797465206b", "crypto", "ChaCha expand constant (FindCrypt)"),
    ("ChaChaInitStates_expanded16k", "657870616e642031362d62797465206b", "crypto", "ChaCha expand constant (FindCrypt)"),
    ("BLAKE2_IV", "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b", "crypto", "BLAKE2 init vector (FindCrypt)"),
    ("BLAKE2_IV_64", "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b", "crypto", "BLAKE2 init vector 64-bit (FindCrypt)"),
    ("BLAKE2S_SIGMA", "000102030405060708090a0b0c0d0e0f0e0a0408090f0d06010c00020b0705030b080c0005020f0d0a0e030607010904070903010d0c0b0e0206050a04000f08", "crypto", "BLAKE2s sigma permutation (FindCrypt)"),
    ("BLAKE2B_SIGMA", "000102030405060708090a0b0c0d0e0f0e0a0408090f0d06010c00020b0705030b080c0005020f0d0a0e030607010904070903010d0c0b0e0206050a04000f08", "crypto", "BLAKE2b sigma permutation (FindCrypt)"),
    ("Blowfish_p_init", "886a3f24d308a3852e8a191344737003223809a4d0319f2998fa2e08896c4eece62128457713d038cf6654be6c0ce934b729acc0dd507cc9b5d5843f170947b5", "crypto", "Blowfish P-array init (FindCrypt)"),
    ("Blowfish_s_init", "a60b31d1acb5df98db72fd2fb7df1ad0edafe1b8967e266a45907cba997f2cf14799a124f76c91b3e2f2010816fc8e85d8206963694e5771a3fe58a47e3d93f4", "crypto", "Blowfish S-Box init (FindCrypt)"),
    ("Camellia_s1", "70822cecb327c0e5e4855735ea0cae4123ef6b934519a521ed0e4f4e1d6592bd86b8af8f7ceb1fce3e30dc5f5ec50b1aa6e139cad5475d3dd9015ad651566c4d", "crypto", "Camellia S-Box (FindCrypt)"),
    ("Camellia_s2", "e00558d9674e81cbc90bae6ad5185d8246dfd6278a324b42db1c9e9c3aca257b0d715f1ff8d73e9d7c60b9bebc8b16344dc37295ab8eba7ab302b4ada2acd89a", "crypto", "Camellia S-Box (FindCrypt)"),
    ("Camellia_s3", "38411676d99360f272c2ab9a750657a091f7b5c9a28cd290f607a7278eb249de435cd7c73ef58f671f186eaf2fe2850d53f09c65eaa3ae9eec802d6ba82b36a6", "crypto", "Camellia S-Box (FindCrypt)"),
    ("Camellia_s4", "702cb3c0e457eaae236b45a5ed4f1d9286af7c1f3edc5e0ba639d55dd95a516c8b9afbb0742bf084dfcb34766da9d104143ade11329c53f2fecfc37a24e86069", "crypto", "Camellia S-Box (FindCrypt)"),
    ("CAST_S", "d440fb300bffa09f2fcdec6b7a8c253f2f3f211ed34d009c40e5036049c99fcf27afd4bfb5bdbb88904003e27596d098e0a0636ed261c3151d66e7c28effd422", "crypto", "CAST S-Box (FindCrypt)"),
    ("CAST256_t_m", "9979825aa1d651d1a9332148b190f0beb9edbf35c14a8facc9a75e23d1042e9ad961fd10e1becc87e91b9cfef1786b75f9d53aec01330a630990d9d911eda850", "crypto", "CAST-256 constant (FindCrypt)"),
    ("CAST256_t_r", "130000001b000000030000000b000000130000001b000000030000000b000000130000001b000000030000000b000000130000001b000000030000000b000000", "crypto", "CAST-256 constant (FindCrypt)"),
    ("CRC32_m_tab", "00000000963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e3288db0ea4b8dc791ee9d5e088d9d2972b4cb609bd7cb17e072db8e7911dbf90", "compression", "CRC32 table (FindCrypt)"),
    ("DES_ei", "20010203040504050607080908090a0b0c0d0c0d0e0f101110111213141514151617181918191a1b1c1d1c1d1e1f2001", "crypto", "DES expansion permutation (FindCrypt)"),
    ("DES_fp", "280830103818402027072f0f37173f1f26062e0e36163e1e25052d0d35153d1d24042c0c34143c1c23032b0b33133b1b22022a0a32123a1a2101290931113919", "crypto", "DES final permutation (FindCrypt)"),
    ("DES_ip", "3a322a221a120a023c342c241c140c043e362e261e160e06403830282018100839312921191109013b332b231b130b033d352d251d150d053f372f271f170f07", "crypto", "DES initial permutation (FindCrypt)"),
    ("DES_p32i", "100714151d0c1c11010f171a05121f0a0208180e201b0309130d1e06160b0419", "crypto", "DES P-box permutation (FindCrypt)"),
    ("DES_pc1", "39312921191109013a322a221a120a023b332b231b130b033c342c243f372f271f170f073e362e261e160e063d352d251d150d051c140c04", "crypto", "DES PC-1 permutation (FindCrypt)"),
    ("DES_pc2", "0e110b180105031c0f06150a17130c041a0810071b140d0229341f252f371e28332d21302c31273822352e2a32241d20", "crypto", "DES PC-2 permutation (FindCrypt)"),
    ("DES_sbox", "0e040d01020f0b08030a060c05090007000f07040e020d010a060c0b0905030804010e080d06020b0f0c0907030a05000f0c080204090107050b030e0a00060d", "crypto", "DES S-Box (FindCrypt)"),
    ("GOST_sBox", "040a09020d08000e060b010c070f05030e0b040c060d0f0a02030801000705090508010d0a0304020e0f0c070600090b070d0a010008090f0e04060c0b020503", "crypto", "GOST S-Box (FindCrypt)"),
    ("HAVAL_mc2", "e62128457713d038cf6654be6c0ce934b729acc0dd507cc9b5d5843f170947b5d9d516921bfb7989a60b31d1acb5df98db72fd2fb7df1ad0edafe1b8967e266a", "crypto", "HAVAL mixing constant (FindCrypt)"),
    ("HAVAL_mc3", "39d5309c1360f22a23b0d1c5f0856028187941caef38dbb8b0dc798e0e183a608b0e9e6c3e8a1eb0c17715d7274b31bdda2faf78605c6055f32555e694ab55aa", "crypto", "HAVAL mixing constant (FindCrypt)"),
    ("HAVAL_mc4", "8153327a7786952898488f3bafb94b6b1be8bfc493212866cc09d86191a921fb60ac7c483280ec5d5d5d84efb17585e9022326dc881b65eb813e8923c5ac96d3", "crypto", "HAVAL mixing constant (FindCrypt)"),
    ("HAVAL_mc5", "50f03bba982afb7e1d65f1a17601af393e59ca66880e43821986ee8cb49f6f45c3a5847dbe5e8b3bd8756fe07320c1859f441a40a66ac15662aad34e06773f36", "crypto", "HAVAL mixing constant (FindCrypt)"),
    ("HAVAL_wi2", "050000000e0000001a000000120000000b0000001c000000070000001000000000000000170000001400000016000000010000000a0000000400000008000000", "crypto", "HAVAL word index (FindCrypt)"),
    ("HAVAL_wi3", "130000000900000004000000140000001c0000001100000008000000160000001d0000000e000000190000000c000000180000001e000000100000001a000000", "crypto", "HAVAL word index (FindCrypt)"),
    ("HAVAL_wi4", "1800000004000000000000000e00000002000000070000001c000000170000001a000000060000001e0000001400000012000000190000001300000003000000", "crypto", "HAVAL word index (FindCrypt)"),
    ("HAVAL_wi5", "1b00000003000000150000001a000000110000000b000000140000001d00000013000000000000000c000000070000000d000000080000001f0000000a000000", "crypto", "HAVAL word index (FindCrypt)"),
    ("MARS_Sbox", "79c4d009e0ffc828396caa848772ad9de39bff7d618326d4d4a16dc993cc74792e58d08505574b2a626aa11c9d27bdc3e5251f0f2f376051fbc195c6e4f17f4d", "crypto", "MARS S-Box (FindCrypt)"),
    ("MD2_S", "292e43c9a2d87c013d3654a1ecf0061362a705f3c0c7738c98932bd9bc4c82ca1e9b573cfdd4e01667426f188a17e512be4ec4d6da9ede49a0fbf58ebb2fee7a", "crypto", "MD2 S-Box (FindCrypt)"),
    ("MD5MAC_T", "97ef45ac290f43cd457e1b551c801134b177ce962e728e7c5f5aab0a3643be189d21b421bc87b94da29d27bdc75bd7c3", "crypto", "MD5-MAC T-table (FindCrypt)"),
    ("PKCS_DigestDecoration_MD2", "3020300c06082a864886f70d020205000410", "crypto", "PKCS digest decoration MD2 (FindCrypt)"),
    ("PKCS_DigestDecoration_MD5", "3020300c06082a864886f70d020505000410", "crypto", "PKCS digest decoration MD5 (FindCrypt)"),
    ("PKCS_DigestDecoration_RIPEMD160", "3021300906052b2403020105000414", "crypto", "PKCS digest decoration RIPEMD-160 (FindCrypt)"),
    ("PKCS_DigestDecoration_SHA256", "3031300d060960864801650304020105000420", "crypto", "PKCS digest decoration SHA-256 (FindCrypt)"),
    ("PKCS_DigestDecoration_SHA384", "3041300d060960864801650304020205000430", "crypto", "PKCS digest decoration SHA-384 (FindCrypt)"),
    ("PKCS_DigestDecoration_SHA512", "3051300d060960864801650304020305000440", "crypto", "PKCS digest decoration SHA-512 (FindCrypt)"),
    ("PKCS_DigestDecoration_Tiger", "3029300d06092b06010401da470c0205000418", "crypto", "PKCS digest decoration Tiger (FindCrypt)"),
    ("RawDES_Spbox", "00040101000000000000010004040101040001010404010004000000000001000004000000040101040401010004000004040001040001010000000104000000", "crypto", "DES combined S-P box (FindCrypt)"),
    ("rc2_PITABLE", "d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82", "crypto", "RC2 PI table (FindCrypt)"),
    ("Rijndael_Td0", "50a7f4515365417ec3a4171a965e273acb6bab3bf1459d1fab58faac9303e34b55fa3020f66d76ad9176cc88254c02f5fcd7e54fd7cb2ac5804435268fa362b5", "crypto", "AES/Rijndael Td0 table (FindCrypt)"),
    ("Rijndael_Td1", "a7f4515065417e53a4171ac35e273a966bab3bcb459d1ff158faacab03e34b93fa3020556d76adf676cc88914c02f525d7e54ffccb2ac5d744352680a362b58f", "crypto", "AES/Rijndael Td1 table (FindCrypt)"),
    ("Rijndael_Td2", "f45150a7417e5365171ac3a4273a965eab3bcb6b9d1ff145faacab58e34b9303302055fa76adf66dcc88917602f5254ce54ffcd72ac5d7cb3526804462b58fa3", "crypto", "AES/Rijndael Td2 table (FindCrypt)"),
    ("Rijndael_Td3", "5150a7f47e5365411ac3a4173a965e273bcb6bab1ff1459dacab58fa4b9303e32055fa30adf66d76889176ccf5254c024ffcd7e5c5d7cb2a26804435b58fa362", "crypto", "AES/Rijndael Td3 table (FindCrypt)"),
    ("Rijndael_Td4", "52525252090909096a6a6a6ad5d5d5d53030303036363636a5a5a5a538383838bfbfbfbf40404040a3a3a3a39e9e9e9e81818181f3f3f3f3d7d7d7d7fbfbfbfb", "crypto", "AES/Rijndael Td4 table (FindCrypt)"),
    ("Rijndael_Te0", "a56363c6847c7cf8997777ee8d7b7bf60df2f2ffbd6b6bd6b16f6fde54c5c5915030306003010102a96767ce7d2b2b5619fefee762d7d7b5e6abab4d9a7676ec", "crypto", "AES/Rijndael Te0 table (FindCrypt)"),
    ("Rijndael_Te1", "6363c6a57c7cf8847777ee997b7bf68df2f2ff0d6b6bd6bd6f6fdeb1c5c5915430306050010102036767cea92b2b567dfefee719d7d7b562abab4de67676ec9a", "crypto", "AES/Rijndael Te1 table (FindCrypt)"),
    ("Rijndael_Te2", "63c6a5637cf8847c77ee99777bf68d7bf2ff0df26bd6bd6b6fdeb16fc59154c5306050300102030167cea9672b567d2bfee719fed7b562d7ab4de6ab76ec9a76", "crypto", "AES/Rijndael Te2 table (FindCrypt)"),
    ("Rijndael_Te3", "c6a56363f8847c7cee997777f68d7b7bff0df2f2d6bd6b6bdeb16f6f9154c5c56050303002030101cea96767567d2b2be719fefeb562d7d74de6ababec9a7676", "crypto", "AES/Rijndael Te3 table (FindCrypt)"),
    ("Rijndael_Te4", "636363637c7c7c7c777777777b7b7b7bf2f2f2f26b6b6b6b6f6f6f6fc5c5c5c53030303001010101676767672b2b2b2bfefefefed7d7d7d7abababab76767676", "crypto", "AES/Rijndael Te4 table (FindCrypt)"),
    ("SAFER_exp_tab", "012de293be4515ae780387a4b838cf3f08670994eb26a86bbd18341bbbbf72f74035489c512f3b55e3c09fd8d3f38db1ffa73edc8677d7a611fbf4ba92916483", "crypto", "SAFER exp table (FindCrypt)"),
    ("SAFER_log_tab", "8000b00960efb9fd10129fe469baadf8c038c2654f0694fc19de6a1b5d4ea88270ede8ec72b315c3ffabb6474401ac25c9fa8e411a21cbd30d6efe2658da320f", "crypto", "SAFER log table (FindCrypt)"),
    ("SHA256_K", "982f8a4291443771cffbc0b5a5dbb5e95bc25639f111f159a4823f92d55e1cab98aa07d8015b8312be853124c37d0c55745dbe72feb1de80a706dc9b74f19bc1", "crypto", "SHA-256 round constant (FindCrypt)"),
    ("SHA512_K", "22ae28d7982f8a42cd65ef23914437712f3b4deccffbc0b5bcdb8981a5dbb5e538b548f35bc2563919d005b6f111f1599b4f19afa4823f9218816ddad55e1cab", "crypto", "SHA-512 round constant (FindCrypt)"),
    ("SHARK_dec_cbox", "f3af555ef06a12e635080b313f896c4b578dfceb840e4caa0d09b3f37b5c9bfbe25cbacca9a60845e9bdc64d06d2d1e5deed8852754383340c256be45d5084b6", "crypto", "SHARK decryption box (FindCrypt)"),
    ("SHARK_enc_cbox", "65a3f3168f830d06f656ae5cee5788a6894d2c3c3516f5ebdc5be888be7421652179c186809a4e0da158facf337dba2730b537a204e1d98816e8fba455873b69", "crypto", "SHARK encryption box (FindCrypt)"),
    ("SHARK_iG", "e7309085d04b914153959ba596bca1680245f7655c1fb652a2ca229444632aa2fc678e10297585712445a2cf2f22c10ea1f17140912718a556f4af32d2a4dc71", "crypto", "SHARK inverse G matrix (FindCrypt)"),
    ("SKIPJACK_fTable", "a3d70983f848f6f4b321157899b1aff9e72d4d8ace4cca2e5295d91e4e3844280adf02a017f1606812b77ac3e9fa3d5396846bbaf2639a197caee5f5f7166aa2", "crypto", "SKIPJACK F-table (FindCrypt)"),
    ("Square_Sd_or_SHARK_dec_sbox", "35be072e5369db286fb7766b0c7d368b92bca932ac389c4263c81e4f24e5f7c9618d2f3fb3657f70af9aeaf55b9890b1877172ed374568a3e3ef5cc550c1d6ca", "crypto", "Square/SHARK decrypt S-Box (FindCrypt)"),
    ("Square_Se_or_SHARK_enc_sbox", "b1cec3955aade7024d44fb910c87a150cb6754dd468fe14ef0fdfcebf9c41a6e5ef5cc8d1c5643fe0761f87559ff03228ad113ee88000e34158094e3edb55323", "crypto", "Square/SHARK encrypt S-Box (FindCrypt)"),
    ("Square_Td", "02bc68e30c62855531233f2af713ab61726dd498199acb2161a4223ccd3d9d4523b4fd055f07c42bc0012c9b0f80d93d745c6c48857e7ff91fab73f10edeedb6", "crypto", "Square decrypt T-table (FindCrypt)"),
    ("Square_Te", "26b1b197a7cece69b0c3c3734a9595dfee5a5ab402adadafdce7e73b06020204d74d4d9acc444488f8fbfb03469191d7140c0c187c8787fb16a1a1b7f05050a0", "crypto", "Square encrypt T-table (FindCrypt)"),
    ("Tiger_table", "5e0ce9f77cb1aa02eca843e2034b42acd3fcd50de35bcd723a7ff9f6939b016d93911fd2ff7899cde2298070c9a17375c3832a926b3264b170589104ee3e8846", "crypto", "Tiger hash table (FindCrypt)"),
    ("Twofish_mds", "7532bcbcf321ececc6432020f4c9b3b3db03dada7b8b0202fb2be2e2c8fa9e9e4aecc9c9d309d4d4e66b18186b9f1e1e450e98987d38b2b2e8d2a6a64bb72626", "crypto", "Twofish MDS matrix (FindCrypt)"),
    ("Twofish_q", "a967b3e804fda3769a928078e4ddd1380dc6359818f7ec6c43753726fa139448f2d08b308454df23195b3d59f3aea2826301832ed9519b7ca6eba5be160ce361", "crypto", "Twofish Q permutation (FindCrypt)"),
    ("WAKE_tt", "3b8f6a725c3b9ae6e51fc7d3d2733cabb38e3a4de8d696037a2f4c3df37ce29e0000000000000000", "crypto", "WAKE TT table (FindCrypt)"),
    ("Whirlpool_C0", "78d8c07818281818af2605af23652323f9b87ef9c657c6c66ffb136fe825e8e8a1cb4ca1879487876211a962b8d5b8b805090805010301016e0d426e4fd14f4f", "crypto", "Whirlpool C0 constant (FindCrypt)"),
    ("Whirlpool_C1", "d8c07818281818782605af23652323afb87ef9c657c6c6f9fb136fe825e8e86fcb4ca187948787a111a962b8d5b8b86209080501030101050d426e4fd14f4f6e", "crypto", "Whirlpool C1 constant (FindCrypt)"),
    ("Whirlpool_C2", "c0781828181878d805af23652323af267ef9c657c6c6f9b8136fe825e8e86ffb4ca187948787a1cba962b8d5b8b862110805010301010509426e4fd14f4f6e0d", "crypto", "Whirlpool C2 constant (FindCrypt)"),
    ("Whirlpool_C3", "781828181878d8c0af23652323af2605f9c657c6c6f9b87e6fe825e8e86ffb13a187948787a1cb4c62b8d5b8b86211a905010301010509086e4fd14f4f6e0d42", "crypto", "Whirlpool C3 constant (FindCrypt)"),
    ("Whirlpool_rc", "4f01b887e8c6231852916f79f5d2a636357b0ca38e9bbc6057fe4b2ec2d7e01dda4af09fe5377715856ba0b10a29c95867053ecbf4105dbdd8957da78b4127e4", "crypto", "Whirlpool round constant (FindCrypt)"),
    ("zdeflate_lengthCodes", "010100000201000003010000040100000501000006010000070100000801000009010000090100000a0100000a0100000b0100000b0100000c0100000c010000", "compression", "zlib deflate length codes (FindCrypt)"),
    ("zinflate_distanceExtraBits", "00000000000000000000000000000000010000000100000002000000020000000300000003000000040000000400000005000000050000000600000006000000", "compression", "zlib inflate distance extra bits (FindCrypt)"),
    ("zinflate_distanceStarts", "010000000200000003000000040000000500000007000000090000000d00000011000000190000002100000031000000410000006100000081000000c1000000", "compression", "zlib inflate distance starts (FindCrypt)"),
    ("zinflate_lengthexBytestraBits", "00000000000000000000000000000000000000000000000000000000000000000100000001000000010000000100000002000000020000000200000002000000", "compression", "zlib inflate length extra bits (FindCrypt)"),
    ("zinflate_lengthStarts", "030000000400000005000000060000000700000008000000090000000a0000000b0000000d0000000f0000001100000013000000170000001b0000001f000000", "compression", "zlib inflate length starts (FindCrypt)"),
]


# sig_db Faz A-DELETE (v1.13) — _FINDCRYPT_CONSTANTS dogrudan import
_FINDCRYPT_CONSTANTS = _BUILTIN_CRYPTO_SIGNATURES["findcrypt_constants"]


# ---------------------------------------------------------------------------
# Ana sinif: SignatureDB
# ---------------------------------------------------------------------------

class SignatureDB:
    """Fonksiyon imza veritabani -- binary'deki fonksiyonlari tanimak icin.

    3 katmanli matching:
      1. Symbol tablosundan bilinen kutuphane fonksiyonlarini direkt eslestir
      2. Fonksiyonun kullandigi string'lerden eslestir
      3. Fonksiyonun cagirdigi API kombinasyonundan eslestir

    Byte pattern matching (Katman 1) kullanici tarafindan eklenen
    FunctionSignature'lar uzerinden yapilir. Builtin DB'de byte pattern yok
    cunku byte pattern'ler architecture (ARM64/x86_64) ve compiler version'a
    bagli -- kullanici belli bir target icin ekleyebilir.

    Args:
        config: Karadul merkezi konfigurasyon. None ise varsayilan kullanilir.
    """

    # Class-level cache: builtin + external imzalar sadece 1 kez yuklenir.
    # Sonraki instance'lar shallow copy ile baslatilir (~0.01s vs ~1.3s).
    # Cache key = project_root str (farkli proje kokleri farkli external'lar yukler).
    _full_cache: dict[str, tuple[
        dict[str, dict[str, str]],                              # symbol_db
        dict[frozenset[str], tuple[str, str, str]],             # string_sigs
        list[tuple[frozenset[str], str, str, str, float]],      # call_sigs
    ]] = {}

    def __init__(self, config: Optional[Config] = None, target_platform: str | None = None) -> None:
        self._config = config or Config()
        self._target_platform = target_platform

        # Katman 1: Byte pattern imzalari (kullanici ekler, builtin bos)
        self._byte_signatures: list[FunctionSignature] = []

        # Symbol-based hizli lookup: name -> {lib, purpose, category, _platforms, params, ...}
        # Heterojen: string alanlar + _platforms (list[str]) + params (list[dict]) -> Any gerekiyor.
        self._symbol_db: dict[str, dict[str, Any]] = {}

        # Katman 2: String reference imzalari
        self._string_sigs: dict[frozenset[str], tuple[str, str, str]] = {}

        # Katman 3: Call pattern imzalari
        self._call_sigs: list[tuple[frozenset[str], str, str, str, float]] = []

        # v1.10.0: LMDB backend (opsiyonel, feature flag ile)
        self._lmdb_backend: Any = None  # Optional[LMDBSignatureDB]

        # Feature flag: config.perf.use_lmdb_sigdb
        # True ise LMDB backend kullanilir (dict RAM'e yuklenmez), False'da eski yol
        _perf = getattr(self._config, "perf", None)
        _use_lmdb = bool(_perf and getattr(_perf, "use_lmdb_sigdb", False))

        if _use_lmdb:
            self._init_lmdb_backend()

        # Builtin + external DB yukle (cache'ten veya ilk kez)
        # LMDB aktifken sadece builtin (kod-embedded) yuklenir, external yol atlanir
        self._load_builtin_signatures()

        # FindCrypt-Ghidra kripto sabitleri (byte pattern olarak)
        # LMDB backend'den bagimsiz -- kod-embedded kripto sabitleri
        self._load_findcrypt_constants()

    # ------------------------------------------------------------------
    # v1.10.0: LMDB backend init
    # ------------------------------------------------------------------

    def _init_lmdb_backend(self) -> None:
        """LMDB backend'i ac (config.perf.use_lmdb_sigdb=True iken).

        Hata durumunda None birakir ve eski yola dusurur (graceful fallback).
        """
        try:
            from karadul.analyzers.sigdb_lmdb import (
                LMDBSignatureDB,
                default_lmdb_path,
                is_lmdb_available,
            )
        except ImportError as exc:
            logger.warning(
                "LMDB backend import edilemedi: %s. Eski dict yolu kullaniliyor.", exc,
            )
            return

        if not is_lmdb_available():
            logger.warning("lmdb modulu yuklu degil. Eski dict yolu kullaniliyor.")
            return

        perf = self._config.perf
        path = perf.sig_lmdb_path or default_lmdb_path()

        try:
            self._lmdb_backend = LMDBSignatureDB(
                path,
                readonly=True,
                l1_cache_size=perf.lmdb_l1_cache_size,
            )
            stats = self._lmdb_backend.total_entries
            logger.info(
                "LMDB backend aktif: %s (symbols=%d, string_sigs=%d, "
                "call_sigs=%d, byte_sigs=%d)",
                path, stats["symbols"], stats["string_sigs"],
                stats["call_sigs"], stats["byte_sigs"],
            )
        except FileNotFoundError:
            # v1.10.0 M2: use_lmdb_sigdb=True default olunca LMDB dosyasi
            # olmayan kullanicilarda bu log her acilista tetiklenir -- gurultu
            # olmaması icin INFO seviyesine dusur. Graceful fallback zaten var.
            logger.info(
                "LMDB bulunamadi: %s. scripts/build_sig_lmdb.py ile olusturun. "
                "Simdilik eski dict yolu kullaniliyor.", path,
            )
        except Exception as exc:
            logger.warning(
                "LMDB acilamadi (%s). Eski dict yolu kullaniliyor.", exc,
            )

    # ------------------------------------------------------------------
    # DB yukleme
    # ------------------------------------------------------------------

    def _load_builtin_signatures(self) -> None:
        """Builtin imzalari yukle.

        Performans: Builtin + external dict merge ilk cagirida ~1.3s surer.
        Sonraki instance'lar (ayni project_root) class-level cache'ten
        shallow copy yapar (~0.01s). Bu, test suite'inde ~20s kazandirir.
        """
        cache_key = str(self._config.project_root)

        # Cache hit: onceden hesaplanmis full DB'yi kopyala
        if cache_key in SignatureDB._full_cache:
            cached_sym, cached_str, cached_call = SignatureDB._full_cache[cache_key]
            self._symbol_db = dict(cached_sym)
            self._string_sigs = dict(cached_str)
            self._call_sigs = list(cached_call)
            total = len(self._symbol_db)
            logger.info("SignatureDB: %d symbol imzasi cache'ten yuklendi", total)
            return

        # Cache miss: ilk kez builtin DB'yi olustur
        # Symbol DB: tum kutuphaneleri birlestir
        for db in (
            _MACOS_SYSTEM_SIGNATURES,
            _OPENSSL_SIGNATURES,
            # v1.13 W1: modern crypto (ChaCha20/Salsa20/Blake2/Argon2)
            _MODERN_CRYPTO_SIGNATURES,
            _ZLIB_SIGNATURES,
            _BZIP2_SIGNATURES,
            _LZ4_SIGNATURES,
            _ZSTD_SIGNATURES,
            _LIBCURL_SIGNATURES,
            _SQLITE_SIGNATURES,
            _JSON_SIGNATURES,
            _XML_SIGNATURES,
            _CPP_STL_SIGNATURES,
            _POSIX_FILE_IO_SIGNATURES,
            _PROCESS_SIGNATURES,
            _PTHREAD_SIGNATURES,
            _MEMORY_SIGNATURES,
            _STRING_STDLIB_SIGNATURES,
            _TIME_SIGNATURES,
            _DYNLOAD_SIGNATURES,
            _ERROR_LOCALE_MISC_SIGNATURES,
            _POSIX_NETWORKING_SIGNATURES,
            _CARES_SIGNATURES,
            _NGHTTP2_SIGNATURES,
            _WEBSOCKET_SIGNATURES,
            _GRPC_SIGNATURES,
            _MACOS_NETWORKING_SIGNATURES,
            _IPC_XPC_SIGNATURES,
            _BORINGSSL_SIGNATURES,
            _LIBSODIUM_SIGNATURES,
            _MBEDTLS_SIGNATURES,
            _WINCRYPTO_SIGNATURES,
            _OPENGL_METAL_GPU_SIGNATURES,
            _COREGRAPHICS_SIGNATURES,
            _COREIMAGE_COREML_SIGNATURES,
            _IMAGE_LIB_SIGNATURES,
            _AUDIO_SIGNATURES,
            _FFMPEG_SIGNATURES,
            _SDL2_SIGNATURES,
            # Apple Frameworks extended
            _APPLE_COREDATA_SIGNATURES,
            _APPLE_WEBKIT_SIGNATURES,
            _APPLE_CORELOCATION_SIGNATURES,
            _APPLE_COREBLUETOOTH_SIGNATURES,
            _APPLE_STOREKIT_SIGNATURES,
            _APPLE_USERNOTIFICATIONS_SIGNATURES,
            _APPLE_NETWORK_FRAMEWORK_SIGNATURES,
            _APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES,
            _APPLE_SYSTEMEXTENSIONS_SIGNATURES,
            _APPLE_APPKIT_SIGNATURES,
            # C++ third-party libs
            _BOOST_SIGNATURES,
            _ABSEIL_SIGNATURES,
            _FOLLY_SIGNATURES,
            _LOGGING_SIGNATURES,
            _SERIALIZATION_SIGNATURES,
            # Cross-platform: Windows API, Linux syscalls, Rust, Go
            _WIN32_KERNEL32_SIGNATURES,
            _WIN32_WS2_32_SIGNATURES,
            _WIN32_ADVAPI32_SIGNATURES,
            _WIN32_USER32_GDI32_SIGNATURES,
            _WIN32_NTDLL_SIGNATURES,
            _LINUX_SYSCALL_SIGNATURES,
            _RUST_STDLIB_SIGNATURES,
            _GO_RUNTIME_SIGNATURES,
            # Event loops, regex, math, UI, testing, misc
            _LIBUV_SIGNATURES,
            _LIBEVENT_SIGNATURES,
            _REGEX_SIGNATURES,
            _ICU_SIGNATURES,
            _MATH_SIGNATURES,
            _QT_SIGNATURES,
            _TESTING_SIGNATURES,
            _MISC_SIGNATURES,
            # v2 expansion: extended signatures
            _LINUX_SYSCALL_EXT_SIGNATURES,
            _WIN32_EXT_SIGNATURES,
            _RUST_EXT_SIGNATURES,
            _GO_EXT_SIGNATURES,
            # sig_db Faz 7 — modern_runtime expansion (Rust + Go)
            _MODERN_RUST_RUNTIME_SIGNATURES,
            _MODERN_GO_RUNTIME_SIGNATURES,
            _LIBC_EXT_SIGNATURES,
            _NETWORKING_EXT_SIGNATURES,
            _DATABASE_EXT_SIGNATURES,
            _PYTHON_CAPI_SIGNATURES,
            _JAVA_JNI_SIGNATURES,
            _DOTNET_CLR_SIGNATURES,
            _ANTI_ANALYSIS_SIGNATURES,
            _COMPRESSION_EXT_SIGNATURES,
            _LOGGING_EXT_SIGNATURES,
            _GRAPHICS_EXT_SIGNATURES,
            _V8_NODE_SIGNATURES,
            _LUA_SIGNATURES,
            _RUBY_SIGNATURES,
            _MSGQUEUE_SIGNATURES,
            _ML_COMPUTE_SIGNATURES,
            _GAME_ENGINE_SIGNATURES,
            _MACOS_EXT_SIGNATURES,
            _MEGA_BATCH_1_SIGNATURES,
            _MEGA_BATCH_2_SIGNATURES,
            # v1.12.0 Faz 6C: PE/MSVC runtime (yeni coverage)
            _MSVC_CRT_SIGNATURES,
            # v1.11.0 Faz 6: Apple runtime (Obj-C + Swift + CoreFoundation)
            _APPLE_OBJC_RUNTIME_SIGNATURES,
            _APPLE_SWIFT_RUNTIME_SIGNATURES,
            _APPLE_COREFOUNDATION_SIGNATURES,
            # v1.13 Dalga 1: Tier-1 malware content pack (Sliver + Cobalt Strike)
            _SLIVER_SIGNATURES,
            _COBALTSTRIKE_SIGNATURES,
        ):
            self._symbol_db.update(db)

        # Protobuf: isimler namespace'li, _ prefix yok
        for name, info in _PROTOBUF_SIGNATURES.items():
            self._symbol_db[name] = info

        # String reference sigs
        self._string_sigs = dict(_STRING_REFERENCE_SIGNATURES)

        # Call pattern sigs
        self._call_sigs = list(_CALL_PATTERN_SIGNATURES)

        total = len(self._symbol_db)
        logger.info("SignatureDB: %d symbol imzasi yuklendi", total)

        # Otomatik external signature yukleme (platform filtresi ile)
        self._load_external_auto(target_platform=self._target_platform)

        # Full DB'yi (builtin + external) class-level cache'e kaydet
        SignatureDB._full_cache[cache_key] = (
            dict(self._symbol_db),
            dict(self._string_sigs),
            list(self._call_sigs),
        )

    # ------------------------------------------------------------------
    # FindCrypt-Ghidra Crypto Constants (v1.2.2)
    # ------------------------------------------------------------------

    def _load_findcrypt_constants(self) -> None:
        """FindCrypt-Ghidra kripto sabit veritabanini byte signature olarak yukle.

        126 entry: AES S-Box, SHA sabitleri, DES permutasyonlari, Blowfish,
        Twofish, Camellia, Curve25519, BLAKE2, Whirlpool, vb.

        Pattern'ler max 64 byte'a truncate edilmistir (buyuk tablolarin
        ilk 64 byte'i yeterli -- kripto sabitleri yuksek entropi tasir).
        Mask tamamen 0xFF: birebir eslestirme.
        """
        # Mevcut byte signature isimlerini topla (cakisma kontrolu icin)
        existing_names = {sig.name for sig in self._byte_signatures}
        added = 0
        skipped = 0

        for name, hex_pattern, category, purpose in _FINDCRYPT_CONSTANTS:
            # Cakisma kontrolu: ayni isimde zaten varsa atla
            if name in existing_names:
                skipped += 1
                continue

            try:
                pattern_bytes = bytes.fromhex(hex_pattern)
            except ValueError:
                logger.warning(
                    "FindCrypt: gecersiz hex pattern atlaniyorz: %s", name
                )
                continue

            plen = len(pattern_bytes)
            if plen < 4:
                # 4 byte'tan kisa pattern'ler false positive yaratir
                # ama TEA_DELTA (4 byte) ve benzerleri onemli, o yuzden >= 4
                pass

            sig = FunctionSignature(
                name=name,
                library="crypto_constants",
                category=category,
                byte_pattern=pattern_bytes,
                byte_mask=b"\xff" * plen,
                purpose=purpose,
            )
            self._byte_signatures.append(sig)
            existing_names.add(name)
            added += 1

        logger.info(
            "FindCrypt: %d kripto sabiti byte signature olarak yuklendi "
            "(%d cakisma atlandi)",
            added,
            skipped,
        )

    # ------------------------------------------------------------------
    # External signature yukleme
    # ------------------------------------------------------------------

    def _load_external_auto(self, target_platform: str | None = None) -> None:
        """Config ve proje dizinindeki external signature'lari otomatik yukle.

        Yuklenecek kaynaklar (sirayla):
          1. config.binary_reconstruction.external_signature_paths
          2. Proje dizinindeki signatures_*.json dosyalari
          3. Proje dizinindeki sigs/**/*.json ve sigs/**/*.pat dosyalari (alt dizinler dahil)

        Her kaynak try/except ile korunur; birinin basarisiz olmasi
        diger kaynaklarin yuklenmesini engellemez.

        Args:
            target_platform: Hedef platform ("macho", "elf", "pe"). Verilmisse
                dosya adinda farkli platform belirtilen JSON'lar atlanir.
                "generic" platform her zaman yuklenir.
        """
        external_added = 0

        # 1. Config'teki explicit external path'ler
        try:
            ext_paths = self._config.binary_reconstruction.external_signature_paths
            if ext_paths:
                for path_str in ext_paths:
                    try:
                        p = Path(path_str)
                        if p.is_file() and p.suffix == ".json":
                            added = self.load_external_signatures(p)
                            external_added += added
                        elif p.is_dir():
                            added = self.load_flirt_signatures([str(p)])
                            external_added += added
                    except Exception as exc:
                        logger.debug("External path yuklenemedi: %s -- %s", path_str, exc)
        except Exception:
            logger.debug("Signature eslestirme basarisiz, atlaniyor", exc_info=True)

        # 2. Proje kokunde signatures_*.json dosyalari
        try:
            project_root = self._config.project_root
            for sig_file in sorted(project_root.glob("signatures_*.json")):
                try:
                    added = self.load_external_signatures(sig_file)
                    external_added += added
                except Exception as exc:
                    logger.debug("Signature dosyasi yuklenemedi: %s -- %s", sig_file, exc)
        except Exception:
            logger.debug("Signature eslestirme basarisiz, atlaniyor", exc_info=True)

        # 3. Proje kokunde sigs/ dizini (alt dizinler dahil -- rglob)
        try:
            sigs_dir = self._config.project_root / "sigs"
            if sigs_dir.is_dir():
                _skipped_platform = 0
                for sig_file in sorted(sigs_dir.rglob("*.json")):
                    # v1.9.2: Platform filtresi — hedef platformla uyumsuz dosyalari atla
                    if target_platform:
                        _file_platforms = _infer_platform_from_filename(sig_file.name)
                        if _file_platforms and target_platform not in _file_platforms and "generic" not in _file_platforms:
                            logger.debug(
                                "Platform filtresi: %s atlaniyor (hedef: %s)",
                                sig_file.name, target_platform,
                            )
                            _skipped_platform += 1
                            continue
                    try:
                        added = self.load_external_signatures(sig_file)
                        external_added += added
                    except Exception as exc:
                        logger.debug("sigs/ dosyasi yuklenemedi: %s -- %s", sig_file, exc)
                if _skipped_platform > 0:
                    logger.info(
                        "SignatureDB: %d external JSON platform filtresiyle atlandi (hedef: %s)",
                        _skipped_platform, target_platform,
                    )
                # .pat dosyalari FLIRTParser ile (alt dizinler dahil)
                pat_files = sorted(sigs_dir.rglob("*.pat"))
                if pat_files:
                    try:
                        added = self.load_flirt_signatures([str(f) for f in pat_files])
                        external_added += added
                    except Exception as exc:
                        logger.debug("sigs/*.pat yuklenemedi: %s", exc)
        except Exception:
            logger.debug("Signature eslestirme basarisiz, atlaniyor", exc_info=True)

        if external_added > 0:
            logger.info(
                "SignatureDB: %d external signature otomatik yuklendi (toplam: %d)",
                external_added, len(self._symbol_db),
            )

    # ------------------------------------------------------------------
    # Kullanici API: byte pattern ekleme
    # ------------------------------------------------------------------

    def add_byte_signature(self, sig: FunctionSignature) -> None:
        """Kullanici tanimli byte pattern imzasi ekle.

        v1.10.0 Batch 3D MED: programmatic user bug'larini maskelememek icin
        bos sig.name ve bos byte_pattern reject edilir.
        """
        if not sig.name or not sig.name.strip():
            raise ValueError(
                "SignatureDB.add_byte_signature: sig.name bos olamaz"
            )
        if not sig.byte_pattern:
            raise ValueError(
                "SignatureDB.add_byte_signature: sig.byte_pattern bos olamaz"
            )
        if len(sig.byte_pattern) != len(sig.byte_mask):
            raise ValueError(
                f"byte_pattern ({len(sig.byte_pattern)}) ve byte_mask ({len(sig.byte_mask)}) "
                "uzunluklari esit olmali"
            )
        self._byte_signatures.append(sig)

    def add_string_signature(
        self,
        keywords: frozenset[str],
        matched_name: str,
        library: str,
        purpose: str = "",
    ) -> None:
        """Kullanici tanimli string reference imzasi ekle.

        v1.10.0 Batch 3D MED: bos matched_name veya bos keywords reject edilir.
        """
        if not matched_name or not matched_name.strip():
            raise ValueError(
                "SignatureDB.add_string_signature: matched_name bos olamaz"
            )
        if not keywords:
            raise ValueError(
                "SignatureDB.add_string_signature: keywords bos olamaz"
            )
        self._string_sigs[keywords] = (matched_name, library, purpose)

    def add_call_pattern(
        self,
        callees: frozenset[str],
        matched_name: str,
        library: str,
        purpose: str = "",
        confidence: float = 0.80,
    ) -> None:
        """Kullanici tanimli call pattern imzasi ekle.

        v1.10.0 Batch 3D MED: bos matched_name veya bos callees reject edilir.
        """
        if not matched_name or not matched_name.strip():
            raise ValueError(
                "SignatureDB.add_call_pattern: matched_name bos olamaz"
            )
        if not callees:
            raise ValueError(
                "SignatureDB.add_call_pattern: callees bos olamaz"
            )
        self._call_sigs.append((callees, matched_name, library, purpose, confidence))

    # ------------------------------------------------------------------
    # Katman 0: Symbol-based matching
    # ------------------------------------------------------------------

    def _match_by_symbol(
        self, func_name: str, *, target_platform: str | None = None,
    ) -> Optional[SignatureMatch]:
        """Symbol tablosundaki bilinen fonksiyon isimlerini direkt eslestir.

        Ghidra'nin FUN_xxx gibi otomatik isimler disinda, gercek isim tasiyorsa
        DB'de arar. macOS'ta C fonksiyonlari _ prefix ile baslar.

        Args:
            func_name: Fonksiyon adi.
            target_platform: "macho", "elf", "pe" veya None (filtre yok).
        """
        # Ghidra auto-name ise skip
        if _GHIDRA_AUTO_NAME_RE.match(func_name):
            return None

        # v1.12.0 sig_db Faz 2 fix: Builtin dict ONCE, LMDB sonra.
        # Sebep: LMDB fixture'i eski/coarse olabilir (orn: `_dispatch_once`
        # LMDB'de `libSystem` umbrella, dict'te `libdispatch` spesifik).
        # Builtin dict curated source-of-truth; LMDB sadece eksik sembolleri
        # tamamlar (external FLIRT/JSON). Bu sayede LMDB stale iken de
        # dogru attribution dondurulur.
        # Platform uyumsuzluk builtin'de saptanirsa, LMDB fallback'e devam
        # eder -- LMDB farkli platform sinyali verebilir.

        # Direkt eslestirme (builtin)
        info = self._symbol_db.get(func_name)
        if info:
            if _is_platform_compatible(
                info["lib"], info.get("category", ""), target_platform,
                info.get("_platforms"),
            ):
                return SignatureMatch(
                    original_name=func_name,
                    matched_name=func_name.lstrip("_"),
                    library=info["lib"],
                    confidence=0.98,
                    match_method="symbol",
                    purpose=info.get("purpose", ""),
                    category=info.get("category", ""),
                    params=info.get("params"),  # v1.10.0 M2 T4
                )
            # Platform mismatch -> builtin return etme, LMDB fallback'e dus.
            # Ayni sembol LMDB'de farkli platform ile tanimlanmis olabilir.

        # _ prefix ile dene (macOS C convention, builtin)
        if not func_name.startswith("_"):
            prefixed = f"_{func_name}"
            info_p = self._symbol_db.get(prefixed)
            if info_p:
                if _is_platform_compatible(
                    info_p["lib"], info_p.get("category", ""), target_platform,
                    info_p.get("_platforms"),
                ):
                    return SignatureMatch(
                        original_name=func_name,
                        matched_name=func_name,
                        library=info_p["lib"],
                        confidence=0.97,
                        match_method="symbol",
                        purpose=info_p.get("purpose", ""),
                        category=info_p.get("category", ""),
                        params=info_p.get("params"),  # v1.10.0 M2 T4
                    )

        # Builtin miss -> LMDB backend (varsa). LMDB'nin amaci external
        # sigs (FLIRT/JSON) eklemek, builtin'i override etmemek.
        if self._lmdb_backend is not None:
            _lmdb_info = self._lmdb_backend.lookup_symbol(func_name)
            if _lmdb_info:
                if _is_platform_compatible(
                    _lmdb_info["lib"], _lmdb_info.get("category", ""),
                    target_platform, _lmdb_info.get("_platforms"),
                ):
                    return SignatureMatch(
                        original_name=func_name,
                        matched_name=func_name.lstrip("_"),
                        library=_lmdb_info["lib"],
                        confidence=0.98,
                        match_method="symbol",
                        purpose=_lmdb_info.get("purpose", ""),
                        category=_lmdb_info.get("category", ""),
                        params=_lmdb_info.get("params"),  # v1.10.0 M2 T4
                    )
                # v1.10.0 C2: LMDB'de platform uyumsuz -> devam et
            # macOS _ prefix: hem without hem with dene (LMDB)
            if not func_name.startswith("_"):
                _lmdb_info = self._lmdb_backend.lookup_symbol(f"_{func_name}")
                if _lmdb_info:
                    if _is_platform_compatible(
                        _lmdb_info["lib"], _lmdb_info.get("category", ""),
                        target_platform, _lmdb_info.get("_platforms"),
                    ):
                        return SignatureMatch(
                            original_name=func_name,
                            matched_name=func_name,
                            library=_lmdb_info["lib"],
                            confidence=0.97,
                            match_method="symbol",
                            purpose=_lmdb_info.get("purpose", ""),
                            category=_lmdb_info.get("category", ""),
                            params=_lmdb_info.get("params"),  # v1.10.0 M2 T4
                        )

        # Protobuf demangled isimleri icin partial match
        # v1.10.0 M6 (perf fix): Modul-level basename index ile O(1) lookup.
        # Eski O(n) loop ~60+ signature uzerinde her C++ symbol icin linear
        # scan yapiyordu. Artik: basename cikar -> dict.get. Deterministik
        # sonuc (insertion-order ilk eslesen).
        if "::" in func_name:
            _proto_basename = func_name.rsplit("::", 1)[-1]
        else:
            _proto_basename = func_name
        hit = _PROTOBUF_BASENAME_INDEX.get(_proto_basename)
        if hit is not None:
            sym_name, info = hit
            # Original semantic: func_name.endswith(basename). Basename zaten
            # _proto_basename; True. Ama ust-seviye "::"-li sembol oldugu
            # kontrolu korunsun (endswith eski formda da vardi).
            if "::" in sym_name and func_name.endswith(_proto_basename):
                if _is_platform_compatible(
                    info["lib"], info.get("category", ""), target_platform,
                    info.get("_platforms"),
                ):
                    return SignatureMatch(
                        original_name=func_name,
                        matched_name=sym_name,
                        library=info["lib"],
                        confidence=0.85,
                        match_method="symbol",
                        purpose=info.get("purpose", ""),
                        category=info.get("category", ""),
                        params=info.get("params"),  # v1.10.0 M2 T4
                    )

        return None

    # ------------------------------------------------------------------
    # Katman 1: Byte pattern matching
    # ------------------------------------------------------------------

    def _match_by_bytes(
        self, func_bytes: bytes, func_size: int = 0
    ) -> Optional[SignatureMatch]:
        """Fonksiyonun ilk N byte'ini byte pattern imzalariyla karsilastir.

        Masked compare: byte_mask'teki 0xFF olan pozisyonlarda birebir eslesme
        aranir, 0x00 olan pozisyonlar wildcard (herhangi deger olabilir).
        """
        if not func_bytes:
            return None
        # v1.10.0 C3: builtin bos olsa bile LMDB'de byte sigs olabilir.
        if not self._byte_signatures and self._lmdb_backend is None:
            return None

        best_match: Optional[SignatureMatch] = None
        best_conf = 0.0

        for sig in self._byte_signatures:
            if not sig.byte_pattern:
                continue

            pattern = sig.byte_pattern
            mask = sig.byte_mask
            plen = len(pattern)

            # func_bytes yeterli uzunlukta mi
            if len(func_bytes) < plen:
                continue

            # Size range kontrolu
            if sig.size_range != (0, 0) and func_size > 0:
                min_s, max_s = sig.size_range
                if func_size < min_s or func_size > max_s:
                    continue

            # Masked compare
            matched = True
            for i in range(plen):
                if mask[i] == 0xFF:
                    if func_bytes[i] != pattern[i]:
                        matched = False
                        break
                # mask[i] == 0x00 -> wildcard, skip

            if matched:
                # Confidence: mask'teki sabit byte orani
                fixed_bytes = sum(1 for b in mask if b == 0xFF)
                conf = min(0.95, 0.60 + (fixed_bytes / plen) * 0.35)

                if conf > best_conf:
                    best_conf = conf
                    best_match = SignatureMatch(
                        original_name="",  # caller dolduracak
                        matched_name=sig.name,
                        library=sig.library,
                        confidence=conf,
                        match_method="byte_pattern",
                        purpose=sig.purpose,
                        category=sig.category,
                        version=sig.version,
                    )

        # v1.10.0 C3: LMDB'de byte_sigs DB'sini de sorgula (builtin miss
        # veya ek dis kaynaklardan gelenler icin).
        if self._lmdb_backend is not None and best_match is None:
            try:
                from karadul.analyzers.sigdb_lmdb import BYTE_KEY_LEN as _BKL
                # Ilk BYTE_KEY_LEN byte prefix scan -> caller tarafinda mask check
                candidates = self._lmdb_backend.match_byte_prefix(
                    func_bytes[:_BKL], max_results=32,
                )
            except Exception:
                candidates = []
            for payload in candidates:
                try:
                    pattern = bytes.fromhex(payload.get("byte_pattern_hex", ""))
                    mask = bytes.fromhex(payload.get("byte_mask_hex", ""))
                except ValueError:
                    continue
                plen = len(pattern)
                if plen == 0 or plen != len(mask) or len(func_bytes) < plen:
                    continue
                size_range = payload.get("size_range")
                if size_range and func_size > 0:
                    try:
                        min_s, max_s = size_range
                        if func_size < min_s or func_size > max_s:
                            continue
                    except (TypeError, ValueError):
                        pass
                # Masked compare
                ok = True
                for i in range(plen):
                    if mask[i] == 0xFF and func_bytes[i] != pattern[i]:
                        ok = False
                        break
                if not ok:
                    continue
                fixed_bytes = sum(1 for b in mask if b == 0xFF)
                conf = min(0.95, 0.60 + (fixed_bytes / plen) * 0.35)
                if conf > best_conf:
                    best_conf = conf
                    best_match = SignatureMatch(
                        original_name="",
                        matched_name=payload.get("name", "unknown"),
                        library=payload.get("library", ""),
                        confidence=conf,
                        match_method="byte_pattern",
                        purpose=payload.get("purpose", ""),
                        category=payload.get("category", ""),
                        version=payload.get("version", ""),
                    )

        return best_match

    # ------------------------------------------------------------------
    # Katman 2: String reference matching
    # ------------------------------------------------------------------

    def _match_by_strings(
        self, strings_used: list[str]
    ) -> Optional[SignatureMatch]:
        """Fonksiyonun kullandigi string literal'lerden eslestir.

        Fonksiyonun referans verdigi string'ler, bilinen string imza
        kume'leriyle (frozenset) karsilastirilir. Tum anahtar kelimeler
        fonksiyonun string'leri icerisinde bulunursa eslestir.
        """
        if not strings_used:
            return None

        # Fonksiyonun tum string'lerini tek bir set'e al (hizli lookup icin)
        func_strings_lower = {s.lower() for s in strings_used}
        func_strings_set = set(strings_used)

        best_match: Optional[SignatureMatch] = None
        best_score = 0.0

        for keywords, (matched_name, library, purpose) in self._string_sigs.items():
            # Her keyword fonksiyonun string'leri icinde var mi kontrol et
            # Case-insensitive partial matching: keyword, herhangi bir string'in
            # icinde geciyorsa (substring match)
            match_count = 0
            for kw in keywords:
                kw_lower = kw.lower()
                # Oncelik 1: tam eslestirme
                if kw in func_strings_set:
                    match_count += 1
                # Oncelik 2: case-insensitive exact
                elif kw_lower in func_strings_lower:
                    match_count += 1
                # Oncelik 3: substring
                elif any(kw_lower in s.lower() for s in strings_used):
                    match_count += 1

            if match_count == len(keywords):
                # Tum keyword'ler eslesti
                # Confidence: keyword sayisina gore (daha fazla = daha kesin)
                conf = min(0.92, 0.65 + len(keywords) * 0.07)
                if conf > best_score:
                    best_score = conf
                    best_match = SignatureMatch(
                        original_name="",  # caller dolduracak
                        matched_name=matched_name,
                        library=library,
                        confidence=conf,
                        match_method="string_ref",
                        purpose=purpose,
                    )

        # v1.10.0 C3: LMDB'deki string_sigs DB'sini de sorgula (builtin
        # miss durumunda / builtin yuklenmedigi senaryolarda). Exact
        # canonical key araması: func_strings tam olarak bir imza kume'siyle
        # eslestiginde match.
        if self._lmdb_backend is not None and best_match is None:
            try:
                hit = self._lmdb_backend.lookup_string_sig(strings_used)
            except Exception:
                hit = None
            if hit:
                matched_name, library, purpose = hit
                # Exact-set match -> builtin "all keywords matched" ile ayni
                # confidence skalasi. Kume boyutunu bilmiyoruz; orta deger.
                conf = min(0.92, 0.65 + len(set(strings_used)) * 0.07)
                return SignatureMatch(
                    original_name="",
                    matched_name=matched_name,
                    library=library,
                    confidence=conf,
                    match_method="string_ref",
                    purpose=purpose,
                )

        return best_match

    # ------------------------------------------------------------------
    # Katman 3: Call pattern matching
    # ------------------------------------------------------------------

    def _match_by_calls(
        self, callees: list[str]
    ) -> Optional[SignatureMatch]:
        """Fonksiyonun cagirdigi API'lerin kombinasyonundan eslestir.

        Callees listesi, bilinen call pattern'leriyle karsilastirilir.
        Pattern'deki tum callee'ler fonksiyonun callees'i icinde olmalidir.
        """
        if not callees:
            return None

        callees_set = set(callees)
        # _ prefix'li versiyonlari da ekle
        callees_expanded = set(callees)
        for c in callees:
            if c.startswith("_"):
                callees_expanded.add(c[1:])
            else:
                callees_expanded.add(f"_{c}")

        best_match: Optional[SignatureMatch] = None
        best_conf = 0.0

        for pattern_callees, matched_name, library, purpose, base_conf in self._call_sigs:
            # Pattern'deki her callee, fonksiyonun callees'inde olmali
            if pattern_callees.issubset(callees_expanded):
                # Confidence: base_conf * coverage orani
                # Eger fonksiyon fazladan callee cagiriyorsa biraz dusur
                coverage = len(pattern_callees) / max(len(callees_set), 1)
                conf = base_conf * (0.7 + 0.3 * coverage)
                conf = min(0.95, conf)

                if conf > best_conf:
                    best_conf = conf
                    best_match = SignatureMatch(
                        original_name="",  # caller dolduracak
                        matched_name=matched_name,
                        library=library,
                        confidence=conf,
                        match_method="call_pattern",
                        purpose=purpose,
                    )

        # v1.10.0 C3: LMDB call_sigs DB'sini de sorgula (exact canonical
        # kume eslestirme). builtin miss ise LMDB'de dogrudan kume aranir.
        if self._lmdb_backend is not None and best_match is None:
            try:
                hit = self._lmdb_backend.lookup_call_sig(callees)
            except Exception:
                hit = None
            if hit:
                matched_name, library, purpose, base_conf = hit
                # Exact kume match -> coverage=1.0
                conf = min(0.95, base_conf * 1.0)
                return SignatureMatch(
                    original_name="",
                    matched_name=matched_name,
                    library=library,
                    confidence=conf,
                    match_method="call_pattern",
                    purpose=purpose,
                )

        return best_match

    # ------------------------------------------------------------------
    # Tek fonksiyon eslestirme (public)
    # ------------------------------------------------------------------

    def match_function(
        self,
        func_name: str,
        func_body: str = "",
        strings_used: Optional[list[str]] = None,
        callees: Optional[list[str]] = None,
        func_bytes: Optional[bytes] = None,
        func_size: int = 0,
        target_platform: str | None = None,
    ) -> Optional[SignatureMatch]:
        """3 katmanli eslestirme: symbol -> bytes -> strings -> calls.

        En yuksek confidence'li sonucu dondurur. Hicbir eslestirme bulamazsa
        None dondurur.

        Args:
            func_name: Fonksiyon adi (Ghidra'nin verdigi veya gercek).
            func_body: Decompiled C kodu (opsiyonel, string extraction icin).
            strings_used: Fonksiyonun referans verdigi string literaller.
            callees: Fonksiyonun cagirdigi diger fonksiyonlar.
            func_bytes: Fonksiyonun ilk N byte'i (opsiyonel).
            func_size: Fonksiyon boyutu byte olarak (opsiyonel).
            target_platform: "macho", "elf", "pe" veya None (filtre yok).

        Returns:
            SignatureMatch veya None.
        """
        candidates: list[SignatureMatch] = []

        # 0. Symbol-based (en hizli, en yuksek confidence)
        sym_match = self._match_by_symbol(func_name, target_platform=target_platform)
        if sym_match:
            candidates.append(sym_match)

        # 1. Byte pattern (eger func_bytes varsa)
        if func_bytes:
            byte_match = self._match_by_bytes(func_bytes, func_size)
            if byte_match:
                byte_match.original_name = func_name
                candidates.append(byte_match)

        # 2. String reference
        # func_body'den string cikart (eger strings_used verilmemisse)
        effective_strings = strings_used or []
        if not effective_strings and func_body:
            effective_strings = self._extract_strings_from_body(func_body)

        if effective_strings:
            str_match = self._match_by_strings(effective_strings)
            if str_match:
                str_match.original_name = func_name
                candidates.append(str_match)

        # 3. Call pattern
        effective_callees = callees or []
        if not effective_callees and func_body:
            effective_callees = self._extract_callees_from_body(func_body)

        if effective_callees:
            call_match = self._match_by_calls(effective_callees)
            if call_match:
                call_match.original_name = func_name
                candidates.append(call_match)

        if not candidates:
            return None

        # En yuksek confidence'li sonucu dondur
        return max(candidates, key=lambda m: m.confidence)

    # ------------------------------------------------------------------
    # Toplu eslestirme (public)
    # ------------------------------------------------------------------

    def match_all(
        self,
        functions_json: Path,
        strings_json: Path,
        call_graph_json: Path,
        decompiled_dir: Path,
        target_platform: str | None = None,
    ) -> list[SignatureMatch]:
        """Tum fonksiyonlari DB ile eslestir.

        Ghidra ciktisi dosyalarini okur ve her fonksiyon icin 3 katmanli
        eslestirme uygular.

        Args:
            functions_json: ghidra_functions.json yolu.
            strings_json: ghidra_strings.json yolu.
            call_graph_json: ghidra_call_graph.json yolu.
            decompiled_dir: Decompiled .c dosyalari dizini.
            target_platform: "macho", "elf", "pe" veya None (filtre yok).

        Returns:
            Eslestirme bulunan fonksiyonlarin listesi (confidence sirali).
        """
        matches: list[SignatureMatch] = []

        # JSON'lari yukle
        functions = self._load_json(functions_json)
        strings_data = self._load_json(strings_json)
        call_graph = self._load_json(call_graph_json)

        if functions is None:
            logger.error("functions_json okunamadi: %s", functions_json)
            return matches

        # Index: func_addr -> string_values
        string_refs_by_func: dict[str, list[str]] = {}
        if isinstance(strings_data, list):
            for entry in strings_data:
                if isinstance(entry, dict):
                    refs = entry.get("refs", [])
                    value = entry.get("value", "")
                    for addr in refs:
                        string_refs_by_func.setdefault(addr, []).append(value)

        # Index: func_addr -> callee_names
        callees_by_func: dict[str, list[str]] = {}
        if isinstance(call_graph, dict):
            edges = call_graph.get("edges", [])
            if isinstance(edges, list):
                for edge in edges:
                    if isinstance(edge, dict):
                        src = edge.get("source", "")
                        dst_name = edge.get("target_name", edge.get("target", ""))
                        callees_by_func.setdefault(src, []).append(dst_name)
            # Bazi formatlar: adjacency list
            elif not edges:
                for caller_addr, callee_list in call_graph.items():
                    if isinstance(callee_list, list):
                        callees_by_func[caller_addr] = callee_list

        # Decompiled body index: func_name -> body_text
        func_bodies: dict[str, str] = {}
        if decompiled_dir.is_dir():
            for cfile in decompiled_dir.glob("*.c"):
                try:
                    body = cfile.read_text(errors="replace")
                    # Dosya adi = fonksiyon adi (Ghidra convention)
                    fname = cfile.stem
                    func_bodies[fname] = body
                except OSError:
                    continue

        # Her fonksiyonu eslestir
        func_list = functions if isinstance(functions, list) else functions.get("functions", [])
        total = len(func_list)
        matched_count = 0

        for func_entry in func_list:
            if not isinstance(func_entry, dict):
                continue

            fname = func_entry.get("name", "")
            faddr = func_entry.get("address", func_entry.get("entry_point", ""))
            fsize = func_entry.get("size", 0)

            if not fname:
                continue

            # Bu fonksiyona ait veriler
            strings_used = string_refs_by_func.get(faddr, [])
            callees = callees_by_func.get(faddr, [])
            body = func_bodies.get(fname, "")

            match = self.match_function(
                func_name=fname,
                func_body=body,
                strings_used=strings_used,
                callees=callees,
                func_bytes=None,  # byte extraction ayri bir adim gerektirir
                func_size=fsize,
                target_platform=target_platform,
            )

            if match:
                matched_count += 1
                matches.append(match)

        # Confidence sirala (yuksekten dusuge)
        matches.sort(key=lambda m: m.confidence, reverse=True)

        logger.info(
            "SignatureDB: %d/%d fonksiyon eslesti (%.0f%%)",
            matched_count, total, (matched_count / max(total, 1)) * 100,
        )

        return matches

    # ------------------------------------------------------------------
    # Sonuclari kaydetme
    # ------------------------------------------------------------------

    def save_matches(self, matches: list[SignatureMatch], output_path: Path) -> None:
        """Eslestirmeleri JSON dosyasina kaydet."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "total_matches": len(matches),
            "by_method": self._count_by_method(matches),
            "by_library": self._count_by_library(matches),
            "matches": [m.to_dict() for m in matches],
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("SignatureDB sonuclari kaydedildi: %s", output_path)

    # ------------------------------------------------------------------
    # Istatistik
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Veritabani istatistiklerini dondur."""
        return {
            "total_symbol_signatures": len(self._symbol_db),
            "total_byte_signatures": len(self._byte_signatures),
            "total_string_signatures": len(self._string_sigs),
            "total_call_patterns": len(self._call_sigs),
            "libraries": self._unique_libraries(),
        }

    def _unique_libraries(self) -> list[str]:
        """Tum imzalardaki benzersiz kutuphane isimlerini dondur."""
        libs: set[str] = set()
        for info in self._symbol_db.values():
            libs.add(info["lib"])
        for _, lib, _ in self._string_sigs.values():
            libs.add(lib)
        for _, _, lib, _, _ in self._call_sigs:
            libs.add(lib)
        return sorted(libs)

    @staticmethod
    def _count_by_method(matches: list[SignatureMatch]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for m in matches:
            counts[m.match_method] = counts.get(m.match_method, 0) + 1
        return counts

    @staticmethod
    def _count_by_library(matches: list[SignatureMatch]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for m in matches:
            counts[m.library] = counts.get(m.library, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Yardimci: JSON okuma
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(path: Path) -> Any:
        """JSON dosyasini oku, hata durumunda None dondur."""
        if not path.exists():
            logger.warning("JSON bulunamadi: %s", path)
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("JSON okuma hatasi %s: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Yardimci: decompiled C kodundan string/callee extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_strings_from_body(body: str) -> list[str]:
        """Decompiled C kodundan string literal'leri cikart.

        "..." icindeki string'leri bulur. C escape'lerini yok sayar.
        """
        # Basit regex: cift tirnak icindeki string'ler
        return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', body)

    @staticmethod
    def _extract_callees_from_body(body: str) -> list[str]:
        """Decompiled C kodundan fonksiyon cagirillarini cikart.

        identifier( pattern'ini arar. C keyword'leri haric.
        """
        c_keywords = {
            "if", "else", "while", "for", "do", "switch", "case",
            "return", "sizeof", "typeof", "defined",
        }
        # fonksiyon_adi( pattern'i
        raw = re.findall(r"\b([a-zA-Z_]\w*)\s*\(", body)
        return [name for name in raw if name not in c_keywords]

    # ------------------------------------------------------------------
    # c_namer entegrasyonu icin: naming_map formatinda cikti
    # ------------------------------------------------------------------

    def matches_as_naming_map(
        self, matches: list[SignatureMatch], min_confidence: float = 0.5
    ) -> dict[str, str]:
        """SignatureMatch listesini c_namer uyumlu naming_map'e cevir.

        Sadece min_confidence ustundeki eslesmeleri dahil eder.
        Ghidra auto-name (FUN_xxx) olan fonksiyonlar icin old_name -> new_name.

        Returns:
            dict: {original_name: matched_name}
        """
        naming_map: dict[str, str] = {}
        for m in matches:
            if m.confidence >= min_confidence and m.original_name != m.matched_name:
                # Isimleri C-uyumlu yap (bosluk yok, ozel karakter yok)
                clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", m.matched_name)
                if clean_name and clean_name != m.original_name:
                    naming_map[m.original_name] = clean_name
        return naming_map

    # ------------------------------------------------------------------
    # Harici (external) signature yukleme
    # ------------------------------------------------------------------

    def load_external_signatures(self, json_path: str | Path) -> int:
        """Harici JSON dosyasindan signature'lari yukle.

        build-signature-db.py scriptinin urettigi formati okur ve
        _symbol_db'ye ekler. Duplikasyon kontrolu yapar: zaten var olan
        semboller atlanir (builtin DB onceligini korur).

        Desteklenen JSON formatlari:

        Format 1 - Liste (signatures key icinde list):
            {
                "meta": {...},
                "signatures": [
                    {"name": "func", "library": "lib", "category": "cat", ...},
                    ...
                ],
                "total": N
            }

        Format 2 - Dict (signatures key icinde dict):
            {
                "meta": {...},
                "signatures": {
                    "func_name": {"lib": "...", "purpose": "...", "category": "..."},
                    ...
                }
            }

        Format 3 - Flat dict (signatures key yok, top-level dict dogrudan):
            {
                "func_name": {"lib": "...", "purpose": "...", "category": "..."},
                ...
            }

        Args:
            json_path: Okunacak JSON dosyasinin yolu.

        Returns:
            Eklenen yeni signature sayisi.

        Raises:
            FileNotFoundError: JSON dosyasi bulunamadi.
            json.JSONDecodeError: JSON parse hatasi.
        """
        json_path = Path(json_path)
        if not json_path.exists():
            raise FileNotFoundError(f"External signature dosyasi bulunamadi: {json_path}")

        with open(json_path) as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.warning("External signature dosyasi dict degil: %s", json_path)
            return 0

        added = 0
        skipped = 0

        # v1.8.0: Dosya adindan platform tahmini
        # windows_crypto.json -> ["pe"], linux_syscalls.json -> ["elf"], vb.
        file_default_platforms = _infer_platform_from_filename(json_path.name)

        # Hangi formatta oldugunu tespit et
        signatures_value = data.get("signatures")

        if isinstance(signatures_value, list):
            # Format 1: signatures bir liste -- her eleman {"name": ..., "library": ..., ...}
            for entry in signatures_value:
                if not isinstance(entry, dict):
                    continue

                name = entry.get("name", "")
                if not name:
                    continue

                if name in self._symbol_db:
                    skipped += 1
                    continue

                lib = entry.get("library", "unknown")
                category = entry.get("category", lib)
                purpose = entry.get("purpose", "")

                entry_dict: dict[str, Any] = {
                    "lib": lib,
                    "purpose": purpose,
                    "category": category,
                }
                # Explicit platforms varsa onu kullan, yoksa dosya adindan tahmini
                _plat = entry.get("platforms") or file_default_platforms
                if _plat:
                    entry_dict["_platforms"] = _plat
                # v1.10.0 H4: Format 1 icin params propagation (Format 2
                # zaten yapiyordu). Fortran / typed param metadata kopyalanir.
                if "params" in entry:
                    entry_dict["params"] = entry["params"]

                self._symbol_db[name] = entry_dict
                added += 1

        elif isinstance(signatures_value, dict):
            # Format 2: signatures bir dict -- {"func_name": {"lib": ..., ...}, ...}
            for name, info in signatures_value.items():
                if not isinstance(info, dict):
                    continue

                if name in self._symbol_db:
                    skipped += 1
                    continue

                entry_dict = {
                    "lib": info.get("lib", info.get("library", "unknown")),
                    "purpose": info.get("purpose", ""),
                    "category": info.get("category", info.get("lib", "unknown")),
                }
                _plat = info.get("platforms") or file_default_platforms
                if _plat:
                    entry_dict["_platforms"] = _plat
                # v1.9.0: Fortran param isimleri varsa kaydet
                if "params" in info:
                    entry_dict["params"] = info["params"]

                self._symbol_db[name] = entry_dict
                added += 1

        elif signatures_value is None:
            # Format 3: Flat dict -- top-level key'ler dogrudan fonksiyon isimleri
            # "meta", "total", "version", "generator", "stats" gibi metadata key'lerini atla
            _META_KEYS = {"meta", "total", "version", "generator", "stats",
                          "framework_stats", "library_stats", "category_stats"}
            for name, info in data.items():
                if name in _META_KEYS:
                    continue
                if not isinstance(info, dict):
                    continue

                if name in self._symbol_db:
                    skipped += 1
                    continue

                entry_dict = {
                    "lib": info.get("lib", info.get("library", "unknown")),
                    "purpose": info.get("purpose", ""),
                    "category": info.get("category", info.get("lib", "unknown")),
                }
                _plat = info.get("platforms") or file_default_platforms
                if _plat:
                    entry_dict["_platforms"] = _plat
                # v1.10.0 H4: Format 3 (flat) icin params propagation.
                if "params" in info:
                    entry_dict["params"] = info["params"]

                self._symbol_db[name] = entry_dict
                added += 1
        else:
            logger.warning(
                "External signature dosyasinda tanimsiz 'signatures' tipi (%s): %s",
                type(signatures_value).__name__, json_path,
            )
            return 0

        logger.info(
            "External signatures yuklendi: %s -> %d eklendi, %d duplike atlandi (toplam: %d)",
            json_path.name, added, skipped, len(self._symbol_db),
        )
        return added

    def load_flirt_signatures(self, paths: list[str] | list[str | Path]) -> int:
        """FLIRT/JSON imzalarini external path'lerden yukle.

        FLIRTParser kullanarak .pat ve .json dosyalarini okur,
        SignatureDB'ye inject eder. Config'deki external_signature_paths
        ile birlikte kullanilir.

        Desteklenen formatlar:
          - .pat: IDA FLIRT text pattern dosyalari
          - .json: build-signature-db.py ciktilari
          - dizin: icindeki tum .pat ve .json dosyalari

        Args:
            paths: Dosya/dizin yollarinin listesi.

        Returns:
            Eklenen toplam yeni signature sayisi.
        """
        from karadul.analyzers.flirt_parser import FLIRTParser

        parser = FLIRTParser()
        # FLIRTParser.load_and_inject `list[str | Path]` bekliyor; caller'dan
        # list[str] gelirse invariant nedeniyle mypy hata verir, cast et.
        paths_union: list[str | Path] = list(paths)
        total_added = parser.load_and_inject(self, paths_union)
        logger.info(
            "FLIRT signatures yuklendi: %d yeni signature (toplam: %d)",
            total_added, len(self._symbol_db),
        )
        return total_added
