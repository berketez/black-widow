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

_MACOS_SYSTEM_SIGNATURES: dict[str, dict[str, str]] = {
    # libdispatch (Grand Central Dispatch)
    "_dispatch_once_f": {"lib": "libdispatch", "purpose": "thread-safe lazy init", "category": "concurrency"},
    "_dispatch_once": {"lib": "libdispatch", "purpose": "thread-safe lazy init", "category": "concurrency"},
    "_dispatch_async": {"lib": "libdispatch", "purpose": "async task dispatch", "category": "concurrency"},
    "_dispatch_sync": {"lib": "libdispatch", "purpose": "sync task dispatch", "category": "concurrency"},
    "_dispatch_group_create": {"lib": "libdispatch", "purpose": "dispatch group creation", "category": "concurrency"},
    "_dispatch_group_enter": {"lib": "libdispatch", "purpose": "dispatch group enter", "category": "concurrency"},
    "_dispatch_group_leave": {"lib": "libdispatch", "purpose": "dispatch group leave", "category": "concurrency"},
    "_dispatch_group_notify": {"lib": "libdispatch", "purpose": "dispatch group completion", "category": "concurrency"},
    "_dispatch_group_wait": {"lib": "libdispatch", "purpose": "dispatch group wait", "category": "concurrency"},
    "_dispatch_queue_create": {"lib": "libdispatch", "purpose": "dispatch queue creation", "category": "concurrency"},
    "_dispatch_semaphore_create": {"lib": "libdispatch", "purpose": "semaphore creation", "category": "concurrency"},
    "_dispatch_semaphore_signal": {"lib": "libdispatch", "purpose": "semaphore signal", "category": "concurrency"},
    "_dispatch_semaphore_wait": {"lib": "libdispatch", "purpose": "semaphore wait", "category": "concurrency"},
    "_dispatch_barrier_async": {"lib": "libdispatch", "purpose": "barrier async dispatch", "category": "concurrency"},
    "_dispatch_barrier_sync": {"lib": "libdispatch", "purpose": "barrier sync dispatch", "category": "concurrency"},
    "_dispatch_after": {"lib": "libdispatch", "purpose": "delayed execution", "category": "concurrency"},
    "_dispatch_apply": {"lib": "libdispatch", "purpose": "parallel for loop", "category": "concurrency"},
    "_dispatch_source_create": {"lib": "libdispatch", "purpose": "event source creation", "category": "concurrency"},
    "_dispatch_data_create": {"lib": "libdispatch", "purpose": "dispatch data creation", "category": "concurrency"},
    "_dispatch_io_create": {"lib": "libdispatch", "purpose": "dispatch I/O channel", "category": "concurrency"},
    "_dispatch_get_global_queue": {"lib": "libdispatch", "purpose": "global queue access", "category": "concurrency"},
    "_dispatch_get_main_queue": {"lib": "libdispatch", "purpose": "main queue access", "category": "concurrency"},
    "_dispatch_main": {"lib": "libdispatch", "purpose": "run main dispatch loop", "category": "concurrency"},
    "_dispatch_time": {"lib": "libdispatch", "purpose": "dispatch time calculation", "category": "concurrency"},
    "_dispatch_walltime": {"lib": "libdispatch", "purpose": "dispatch wall time", "category": "concurrency"},
    "_dispatch_block_create": {"lib": "libdispatch", "purpose": "dispatch block creation", "category": "concurrency"},
    "_dispatch_block_cancel": {"lib": "libdispatch", "purpose": "dispatch block cancel", "category": "concurrency"},
    "_dispatch_block_wait": {"lib": "libdispatch", "purpose": "dispatch block wait", "category": "concurrency"},
    "_dispatch_release": {"lib": "libdispatch", "purpose": "dispatch object release", "category": "concurrency"},
    "_dispatch_retain": {"lib": "libdispatch", "purpose": "dispatch object retain", "category": "concurrency"},

    # libobjc (Objective-C runtime)
    "_objc_msgSend": {"lib": "libobjc", "purpose": "ObjC message dispatch", "category": "runtime"},
    "_objc_msgSendSuper": {"lib": "libobjc", "purpose": "ObjC super dispatch", "category": "runtime"},
    "_objc_msgSendSuper2": {"lib": "libobjc", "purpose": "ObjC super2 dispatch", "category": "runtime"},
    "_objc_msgSend_stret": {"lib": "libobjc", "purpose": "ObjC struct return dispatch", "category": "runtime"},
    "_objc_release": {"lib": "libobjc", "purpose": "ObjC ARC release", "category": "runtime"},
    "_objc_retain": {"lib": "libobjc", "purpose": "ObjC ARC retain", "category": "runtime"},
    "_objc_retainAutoreleasedReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC autorelease opt", "category": "runtime"},
    "_objc_autoreleaseReturnValue": {"lib": "libobjc", "purpose": "ObjC autorelease return", "category": "runtime"},
    "_objc_autorelease": {"lib": "libobjc", "purpose": "ObjC autorelease", "category": "runtime"},
    "_objc_alloc": {"lib": "libobjc", "purpose": "ObjC alloc", "category": "runtime"},
    "_objc_alloc_init": {"lib": "libobjc", "purpose": "ObjC alloc+init", "category": "runtime"},
    "_objc_allocWithZone": {"lib": "libobjc", "purpose": "ObjC zoned alloc", "category": "runtime"},
    "_objc_getClass": {"lib": "libobjc", "purpose": "ObjC class lookup by name", "category": "runtime"},
    "_objc_getMetaClass": {"lib": "libobjc", "purpose": "ObjC metaclass lookup", "category": "runtime"},
    "_objc_lookUpClass": {"lib": "libobjc", "purpose": "ObjC optional class lookup", "category": "runtime"},
    "_objc_enumerationMutation": {"lib": "libobjc", "purpose": "ObjC mutation during enumeration", "category": "runtime"},
    "_objc_opt_class": {"lib": "libobjc", "purpose": "ObjC optimized class", "category": "runtime"},
    "_objc_opt_isKindOfClass": {"lib": "libobjc", "purpose": "ObjC optimized isKindOfClass", "category": "runtime"},
    "_objc_opt_respondsToSelector": {"lib": "libobjc", "purpose": "ObjC optimized respondsToSelector", "category": "runtime"},
    "_objc_storeStrong": {"lib": "libobjc", "purpose": "ObjC ARC strong store", "category": "runtime"},
    "_objc_storeWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak store", "category": "runtime"},
    "_objc_loadWeakRetained": {"lib": "libobjc", "purpose": "ObjC ARC weak load", "category": "runtime"},
    "_objc_destroyWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak destroy", "category": "runtime"},
    "_objc_copyWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak copy", "category": "runtime"},
    "_objc_moveWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak move", "category": "runtime"},
    "_objc_initWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak init", "category": "runtime"},
    "_objc_autoreleasePoolPush": {"lib": "libobjc", "purpose": "ObjC autorelease pool push", "category": "runtime"},
    "_objc_autoreleasePoolPop": {"lib": "libobjc", "purpose": "ObjC autorelease pool pop", "category": "runtime"},
    "_sel_registerName": {"lib": "libobjc", "purpose": "ObjC selector registration", "category": "runtime"},
    "_sel_getName": {"lib": "libobjc", "purpose": "ObjC selector name lookup", "category": "runtime"},
    "_class_getName": {"lib": "libobjc", "purpose": "ObjC class name lookup", "category": "runtime"},
    "_class_getSuperclass": {"lib": "libobjc", "purpose": "ObjC superclass lookup", "category": "runtime"},
    "_class_getInstanceMethod": {"lib": "libobjc", "purpose": "ObjC instance method lookup", "category": "runtime"},
    "_class_getClassMethod": {"lib": "libobjc", "purpose": "ObjC class method lookup", "category": "runtime"},
    "_class_addMethod": {"lib": "libobjc", "purpose": "ObjC dynamic method add", "category": "runtime"},
    "_class_replaceMethod": {"lib": "libobjc", "purpose": "ObjC method swizzle", "category": "runtime"},
    "_method_exchangeImplementations": {"lib": "libobjc", "purpose": "ObjC method exchange (swizzle)", "category": "runtime"},
    "_protocol_conformsToProtocol": {"lib": "libobjc", "purpose": "ObjC protocol conformance check", "category": "runtime"},
    "_object_getClass": {"lib": "libobjc", "purpose": "ObjC get object class", "category": "runtime"},
    "_NSLog": {"lib": "Foundation", "purpose": "ObjC console logging", "category": "runtime"},

    # Swift runtime
    "_swift_retain": {"lib": "swift_runtime", "purpose": "Swift ARC retain", "category": "runtime"},
    "_swift_release": {"lib": "swift_runtime", "purpose": "Swift ARC release", "category": "runtime"},
    "_swift_allocObject": {"lib": "swift_runtime", "purpose": "Swift object allocation", "category": "runtime"},
    "_swift_deallocObject": {"lib": "swift_runtime", "purpose": "Swift object deallocation", "category": "runtime"},
    "_swift_initStackObject": {"lib": "swift_runtime", "purpose": "Swift stack object init", "category": "runtime"},
    "_swift_bridgeObjectRetain": {"lib": "swift_runtime", "purpose": "Swift bridge object retain", "category": "runtime"},
    "_swift_bridgeObjectRelease": {"lib": "swift_runtime", "purpose": "Swift bridge object release", "category": "runtime"},
    "_swift_unknownObjectRetain": {"lib": "swift_runtime", "purpose": "Swift unknown object retain", "category": "runtime"},
    "_swift_unknownObjectRelease": {"lib": "swift_runtime", "purpose": "Swift unknown object release", "category": "runtime"},
    "_swift_isUniquelyReferenced_nonNull_native": {"lib": "swift_runtime", "purpose": "Swift COW uniqueness check", "category": "runtime"},
    "_swift_getObjectType": {"lib": "swift_runtime", "purpose": "Swift type metadata lookup", "category": "runtime"},
    "_swift_getTypeByMangledNameInContext": {"lib": "swift_runtime", "purpose": "Swift demangled type lookup", "category": "runtime"},
    "_swift_dynamicCast": {"lib": "swift_runtime", "purpose": "Swift dynamic cast (as?/as!)", "category": "runtime"},
    "_swift_conformsToProtocol": {"lib": "swift_runtime", "purpose": "Swift protocol conformance check", "category": "runtime"},
    "_swift_getWitnessTable": {"lib": "swift_runtime", "purpose": "Swift witness table lookup", "category": "runtime"},
    "_swift_getAssociatedTypeWitness": {"lib": "swift_runtime", "purpose": "Swift associated type witness", "category": "runtime"},
    "_swift_getTypeContextDescriptor": {"lib": "swift_runtime", "purpose": "Swift type descriptor lookup", "category": "runtime"},
    "_swift_once": {"lib": "swift_runtime", "purpose": "Swift one-time initialization", "category": "runtime"},
    "_swift_beginAccess": {"lib": "swift_runtime", "purpose": "Swift exclusivity access begin", "category": "runtime"},
    "_swift_endAccess": {"lib": "swift_runtime", "purpose": "Swift exclusivity access end", "category": "runtime"},
    "_swift_makeBoxUnique": {"lib": "swift_runtime", "purpose": "Swift box uniqueness", "category": "runtime"},
    "_swift_allocBox": {"lib": "swift_runtime", "purpose": "Swift box allocation", "category": "runtime"},
    "_swift_projectBox": {"lib": "swift_runtime", "purpose": "Swift box projection", "category": "runtime"},
    "_swift_deallocBox": {"lib": "swift_runtime", "purpose": "Swift box deallocation", "category": "runtime"},
    "_swift_getInitializedObjCClass": {"lib": "swift_runtime", "purpose": "Swift ObjC class init bridge", "category": "runtime"},
    "_swift_getObjCClassMetadata": {"lib": "swift_runtime", "purpose": "Swift ObjC metadata bridge", "category": "runtime"},
    "_swift_slowAlloc": {"lib": "swift_runtime", "purpose": "Swift slow-path alloc", "category": "runtime"},
    "_swift_slowDealloc": {"lib": "swift_runtime", "purpose": "Swift slow-path dealloc", "category": "runtime"},
    "_swift_task_create": {"lib": "swift_runtime", "purpose": "Swift async task creation", "category": "concurrency"},
    "_swift_task_switch": {"lib": "swift_runtime", "purpose": "Swift async task switch", "category": "concurrency"},
    "_swift_task_future_wait": {"lib": "swift_runtime", "purpose": "Swift async await", "category": "concurrency"},
    "_swift_asyncLet_begin": {"lib": "swift_runtime", "purpose": "Swift async let begin", "category": "concurrency"},
    "_swift_asyncLet_end": {"lib": "swift_runtime", "purpose": "Swift async let end", "category": "concurrency"},
    "_swift_task_group_create": {"lib": "swift_runtime", "purpose": "Swift task group creation", "category": "concurrency"},
    "_swift_task_group_addPending": {"lib": "swift_runtime", "purpose": "Swift task group add", "category": "concurrency"},
    "_swift_task_cancel": {"lib": "swift_runtime", "purpose": "Swift task cancellation", "category": "concurrency"},
    "_swift_task_isCancelled": {"lib": "swift_runtime", "purpose": "Swift task cancel check", "category": "concurrency"},
    "_swift_continuation_resume": {"lib": "swift_runtime", "purpose": "Swift continuation resume", "category": "concurrency"},
    "$ss17_assertionFailure": {"lib": "swift_runtime", "purpose": "Swift assertion failure", "category": "runtime"},
    "$ss18_fatalErrorMessage": {"lib": "swift_runtime", "purpose": "Swift fatal error", "category": "runtime"},
    "$ss27_allocateUninitializedArray": {"lib": "swift_runtime", "purpose": "Swift array allocation", "category": "runtime"},
    "$ss22_deallocateUninitializedArray": {"lib": "swift_runtime", "purpose": "Swift array deallocation", "category": "runtime"},
    "$sSS21_builtinStringLiteral": {"lib": "swift_runtime", "purpose": "Swift string literal", "category": "runtime"},
    "$sSa6appendyyxnF": {"lib": "swift_runtime", "purpose": "Swift Array.append", "category": "runtime"},
    "$sSa12reserveCapacityyySiF": {"lib": "swift_runtime", "purpose": "Swift Array.reserveCapacity", "category": "runtime"},
    "$sSD17dictionaryLiteral": {"lib": "swift_runtime", "purpose": "Swift Dictionary literal", "category": "runtime"},
    "$sSh13_rawHashValue": {"lib": "swift_runtime", "purpose": "Swift Hashable._rawHashValue", "category": "runtime"},

    # CommonCrypto
    "_CCCrypt": {"lib": "CommonCrypto", "purpose": "symmetric encryption (AES/DES/3DES)", "category": "crypto"},
    "_CCCryptorCreate": {"lib": "CommonCrypto", "purpose": "crypto context creation", "category": "crypto"},
    "_CCCryptorCreateFromData": {"lib": "CommonCrypto", "purpose": "crypto context from data", "category": "crypto"},
    "_CCCryptorUpdate": {"lib": "CommonCrypto", "purpose": "incremental encrypt/decrypt", "category": "crypto"},
    "_CCCryptorFinal": {"lib": "CommonCrypto", "purpose": "finalize encrypt/decrypt", "category": "crypto"},
    "_CCCryptorRelease": {"lib": "CommonCrypto", "purpose": "crypto context release", "category": "crypto"},
    "_CCHmac": {"lib": "CommonCrypto", "purpose": "HMAC computation", "category": "crypto"},
    "_CCHmacInit": {"lib": "CommonCrypto", "purpose": "HMAC context init", "category": "crypto"},
    "_CCHmacUpdate": {"lib": "CommonCrypto", "purpose": "HMAC incremental update", "category": "crypto"},
    "_CCHmacFinal": {"lib": "CommonCrypto", "purpose": "HMAC finalize", "category": "crypto"},
    "_CC_SHA1": {"lib": "CommonCrypto", "purpose": "SHA-1 hash (one-shot)", "category": "crypto"},
    "_CC_SHA1_Init": {"lib": "CommonCrypto", "purpose": "SHA-1 context init", "category": "crypto"},
    "_CC_SHA1_Update": {"lib": "CommonCrypto", "purpose": "SHA-1 incremental update", "category": "crypto"},
    "_CC_SHA1_Final": {"lib": "CommonCrypto", "purpose": "SHA-1 finalize", "category": "crypto"},
    "_CC_SHA256": {"lib": "CommonCrypto", "purpose": "SHA-256 hash (one-shot)", "category": "crypto"},
    "_CC_SHA256_Init": {"lib": "CommonCrypto", "purpose": "SHA-256 context init", "category": "crypto"},
    "_CC_SHA256_Update": {"lib": "CommonCrypto", "purpose": "SHA-256 incremental update", "category": "crypto"},
    "_CC_SHA256_Final": {"lib": "CommonCrypto", "purpose": "SHA-256 finalize", "category": "crypto"},
    "_CC_SHA384": {"lib": "CommonCrypto", "purpose": "SHA-384 hash (one-shot)", "category": "crypto"},
    "_CC_SHA512": {"lib": "CommonCrypto", "purpose": "SHA-512 hash (one-shot)", "category": "crypto"},
    "_CC_MD5": {"lib": "CommonCrypto", "purpose": "MD5 hash (one-shot, insecure)", "category": "crypto"},
    "_CC_MD5_Init": {"lib": "CommonCrypto", "purpose": "MD5 context init", "category": "crypto"},
    "_CC_MD5_Update": {"lib": "CommonCrypto", "purpose": "MD5 incremental update", "category": "crypto"},
    "_CC_MD5_Final": {"lib": "CommonCrypto", "purpose": "MD5 finalize", "category": "crypto"},
    "_CCKeyDerivationPBKDF": {"lib": "CommonCrypto", "purpose": "PBKDF2 key derivation", "category": "crypto"},
    "_CCRandomGenerateBytes": {"lib": "CommonCrypto", "purpose": "cryptographic RNG", "category": "crypto"},

    # Security.framework
    "_SecItemAdd": {"lib": "Security", "purpose": "Keychain item storage", "category": "security"},
    "_SecItemCopyMatching": {"lib": "Security", "purpose": "Keychain item lookup", "category": "security"},
    "_SecItemUpdate": {"lib": "Security", "purpose": "Keychain item update", "category": "security"},
    "_SecItemDelete": {"lib": "Security", "purpose": "Keychain item deletion", "category": "security"},
    "_SecKeyCreateRandomKey": {"lib": "Security", "purpose": "random key generation", "category": "security"},
    "_SecKeyCreateSignature": {"lib": "Security", "purpose": "digital signature creation", "category": "security"},
    "_SecKeyVerifySignature": {"lib": "Security", "purpose": "digital signature verification", "category": "security"},
    "_SecKeyCreateEncryptedData": {"lib": "Security", "purpose": "public-key encryption", "category": "security"},
    "_SecKeyCreateDecryptedData": {"lib": "Security", "purpose": "public-key decryption", "category": "security"},
    "_SecKeyCopyPublicKey": {"lib": "Security", "purpose": "extract public key", "category": "security"},
    "_SecKeyCopyExternalRepresentation": {"lib": "Security", "purpose": "export key data", "category": "security"},
    "_SecKeyCreateWithData": {"lib": "Security", "purpose": "import key data", "category": "security"},
    "_SecCertificateCreateWithData": {"lib": "Security", "purpose": "certificate from DER data", "category": "security"},
    "_SecCertificateCopySubjectSummary": {"lib": "Security", "purpose": "certificate subject", "category": "security"},
    "_SecTrustCreateWithCertificates": {"lib": "Security", "purpose": "trust evaluation setup", "category": "security"},
    "_SecTrustEvaluateWithError": {"lib": "Security", "purpose": "certificate trust evaluation", "category": "security"},
    "_SecTrustSetPolicies": {"lib": "Security", "purpose": "set trust policies", "category": "security"},
    "_SecPolicyCreateSSL": {"lib": "Security", "purpose": "SSL trust policy", "category": "security"},
    "_SecCodeCheckValidity": {"lib": "Security", "purpose": "code signature validation", "category": "security"},
    "_SecCodeCopySigningInformation": {"lib": "Security", "purpose": "code signing info", "category": "security"},
    "_SecStaticCodeCreateWithPath": {"lib": "Security", "purpose": "static code ref from path", "category": "security"},
    "_SecAccessControlCreateWithFlags": {"lib": "Security", "purpose": "access control creation (biometric)", "category": "security"},

    # Endpoint Security (macOS antivirus/EDR)
    "_es_new_client": {"lib": "EndpointSecurity", "purpose": "ES client creation", "category": "security"},
    "_es_subscribe": {"lib": "EndpointSecurity", "purpose": "ES event subscription", "category": "security"},
    "_es_unsubscribe": {"lib": "EndpointSecurity", "purpose": "ES event unsubscription", "category": "security"},
    "_es_respond_auth_result": {"lib": "EndpointSecurity", "purpose": "ES auth response", "category": "security"},
    "_es_respond_flags_result": {"lib": "EndpointSecurity", "purpose": "ES flags response", "category": "security"},
    "_es_delete_client": {"lib": "EndpointSecurity", "purpose": "ES client teardown", "category": "security"},
    "_es_mute_process": {"lib": "EndpointSecurity", "purpose": "ES process muting", "category": "security"},
    "_es_clear_cache": {"lib": "EndpointSecurity", "purpose": "ES cache clear", "category": "security"},

    # Network Extension
    "_NEFilterDataProvider": {"lib": "NetworkExtension", "purpose": "network content filter", "category": "network"},
    "_NEDNSProxyProvider": {"lib": "NetworkExtension", "purpose": "DNS proxy provider", "category": "network"},
    "_NETunnelProviderManager": {"lib": "NetworkExtension", "purpose": "VPN tunnel manager", "category": "network"},
    "_NEVPNManager": {"lib": "NetworkExtension", "purpose": "VPN configuration manager", "category": "network"},

    # XPC
    "_xpc_connection_create_mach_service": {"lib": "libxpc", "purpose": "XPC Mach service connection", "category": "ipc"},
    "_xpc_connection_send_message": {"lib": "libxpc", "purpose": "XPC message send", "category": "ipc"},
    "_xpc_connection_send_message_with_reply": {"lib": "libxpc", "purpose": "XPC message send+reply", "category": "ipc"},
    "_xpc_connection_set_event_handler": {"lib": "libxpc", "purpose": "XPC event handler", "category": "ipc"},
    "_xpc_connection_resume": {"lib": "libxpc", "purpose": "XPC connection resume", "category": "ipc"},
    "_xpc_connection_cancel": {"lib": "libxpc", "purpose": "XPC connection cancel", "category": "ipc"},
    "_xpc_dictionary_create": {"lib": "libxpc", "purpose": "XPC dict creation", "category": "ipc"},
    "_xpc_dictionary_set_string": {"lib": "libxpc", "purpose": "XPC dict set string", "category": "ipc"},
    "_xpc_dictionary_get_string": {"lib": "libxpc", "purpose": "XPC dict get string", "category": "ipc"},
    "_xpc_dictionary_set_data": {"lib": "libxpc", "purpose": "XPC dict set data", "category": "ipc"},
    "_xpc_dictionary_get_data": {"lib": "libxpc", "purpose": "XPC dict get data", "category": "ipc"},

    # IOKit
    "_IOServiceGetMatchingServices": {"lib": "IOKit", "purpose": "IOKit service matching", "category": "hardware"},
    "_IOServiceMatching": {"lib": "IOKit", "purpose": "IOKit matching dict", "category": "hardware"},
    "_IORegistryEntryCreateCFProperty": {"lib": "IOKit", "purpose": "IOKit registry property", "category": "hardware"},
    "_IOObjectRelease": {"lib": "IOKit", "purpose": "IOKit object release", "category": "hardware"},
    "_IOServiceOpen": {"lib": "IOKit", "purpose": "IOKit service open", "category": "hardware"},
    "_IOServiceClose": {"lib": "IOKit", "purpose": "IOKit service close", "category": "hardware"},
    "_IOServiceGetMatchingService": {"lib": "IOKit", "purpose": "IOKit single service match", "category": "hardware"},
    "_IORegistryEntryCreateCFProperties": {"lib": "IOKit", "purpose": "IOKit all registry properties", "category": "hardware"},
    "_IOIteratorNext": {"lib": "IOKit", "purpose": "IOKit iterator advance", "category": "hardware"},
    "_IOIteratorReset": {"lib": "IOKit", "purpose": "IOKit iterator reset", "category": "hardware"},
    "_IOConnectCallMethod": {"lib": "IOKit", "purpose": "IOKit user client method call", "category": "hardware"},
    "_IOPMAssertionCreateWithName": {"lib": "IOKit", "purpose": "power management assertion create", "category": "hardware"},
    "_IOPMAssertionRelease": {"lib": "IOKit", "purpose": "power management assertion release", "category": "hardware"},

    # CoreFoundation -- String
    "_CFStringCreateWithCString": {"lib": "CoreFoundation", "purpose": "create CFString from C string", "category": "foundation"},
    "_CFStringGetCString": {"lib": "CoreFoundation", "purpose": "extract C string from CFString", "category": "foundation"},
    "_CFStringGetLength": {"lib": "CoreFoundation", "purpose": "get CFString length", "category": "foundation"},
    "_CFStringCreateCopy": {"lib": "CoreFoundation", "purpose": "copy immutable CFString", "category": "foundation"},
    "_CFStringCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFString", "category": "foundation"},
    "_CFStringAppend": {"lib": "CoreFoundation", "purpose": "append to mutable CFString", "category": "foundation"},
    "_CFStringCompare": {"lib": "CoreFoundation", "purpose": "compare two CFStrings", "category": "foundation"},

    # CoreFoundation -- Array
    "_CFArrayCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFArray", "category": "foundation"},
    "_CFArrayCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFArray", "category": "foundation"},
    "_CFArrayGetCount": {"lib": "CoreFoundation", "purpose": "get CFArray element count", "category": "foundation"},
    "_CFArrayGetValueAtIndex": {"lib": "CoreFoundation", "purpose": "get CFArray element at index", "category": "foundation"},
    "_CFArrayAppendValue": {"lib": "CoreFoundation", "purpose": "append to mutable CFArray", "category": "foundation"},
    "_CFArrayContainsValue": {"lib": "CoreFoundation", "purpose": "check CFArray membership", "category": "foundation"},

    # CoreFoundation -- Dictionary
    "_CFDictionaryCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFDictionary", "category": "foundation"},
    "_CFDictionaryCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFDictionary", "category": "foundation"},
    "_CFDictionaryGetValue": {"lib": "CoreFoundation", "purpose": "get CFDictionary value for key", "category": "foundation"},
    "_CFDictionarySetValue": {"lib": "CoreFoundation", "purpose": "set CFDictionary key-value pair", "category": "foundation"},
    "_CFDictionaryGetCount": {"lib": "CoreFoundation", "purpose": "get CFDictionary entry count", "category": "foundation"},
    "_CFDictionaryContainsKey": {"lib": "CoreFoundation", "purpose": "check CFDictionary key presence", "category": "foundation"},

    # CoreFoundation -- Data
    "_CFDataCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFData", "category": "foundation"},
    "_CFDataCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFData", "category": "foundation"},
    "_CFDataGetBytePtr": {"lib": "CoreFoundation", "purpose": "get CFData byte pointer", "category": "foundation"},
    "_CFDataGetLength": {"lib": "CoreFoundation", "purpose": "get CFData length", "category": "foundation"},
    "_CFDataAppendBytes": {"lib": "CoreFoundation", "purpose": "append bytes to mutable CFData", "category": "foundation"},

    # CoreFoundation -- Number / Boolean
    "_CFNumberCreate": {"lib": "CoreFoundation", "purpose": "create CFNumber from value", "category": "foundation"},
    "_CFNumberGetValue": {"lib": "CoreFoundation", "purpose": "extract value from CFNumber", "category": "foundation"},
    "_CFBooleanGetValue": {"lib": "CoreFoundation", "purpose": "extract bool from CFBoolean", "category": "foundation"},

    # CoreFoundation -- URL
    "_CFURLCreateWithString": {"lib": "CoreFoundation", "purpose": "create CFURL from string", "category": "foundation"},
    "_CFURLCreateWithFileSystemPath": {"lib": "CoreFoundation", "purpose": "create CFURL from file path", "category": "foundation"},
    "_CFURLGetString": {"lib": "CoreFoundation", "purpose": "get string from CFURL", "category": "foundation"},

    # CoreFoundation -- Preferences
    "_CFPreferencesCopyValue": {"lib": "CoreFoundation", "purpose": "read preference value", "category": "foundation"},
    "_CFPreferencesSetValue": {"lib": "CoreFoundation", "purpose": "write preference value", "category": "foundation"},
    "_CFPreferencesSynchronize": {"lib": "CoreFoundation", "purpose": "sync preferences to disk", "category": "foundation"},

    # CoreFoundation -- Notification Center
    "_CFNotificationCenterGetDistributedCenter": {"lib": "CoreFoundation", "purpose": "get distributed notification center", "category": "foundation"},
    "_CFNotificationCenterAddObserver": {"lib": "CoreFoundation", "purpose": "register notification observer", "category": "foundation"},
    "_CFNotificationCenterPostNotification": {"lib": "CoreFoundation", "purpose": "post notification", "category": "foundation"},

    # CoreFoundation -- RunLoop
    "_CFRunLoopGetCurrent": {"lib": "CoreFoundation", "purpose": "get current run loop", "category": "foundation"},
    "_CFRunLoopGetMain": {"lib": "CoreFoundation", "purpose": "get main run loop", "category": "foundation"},
    "_CFRunLoopRun": {"lib": "CoreFoundation", "purpose": "run the current run loop", "category": "foundation"},
    "_CFRunLoopStop": {"lib": "CoreFoundation", "purpose": "stop a run loop", "category": "foundation"},
    "_CFRunLoopAddSource": {"lib": "CoreFoundation", "purpose": "add source to run loop", "category": "foundation"},
    "_CFRunLoopAddTimer": {"lib": "CoreFoundation", "purpose": "add timer to run loop", "category": "foundation"},

    # CoreFoundation -- Bundle
    "_CFBundleGetMainBundle": {"lib": "CoreFoundation", "purpose": "get main application bundle", "category": "foundation"},
    "_CFBundleCopyResourceURL": {"lib": "CoreFoundation", "purpose": "get bundle resource URL", "category": "foundation"},
    "_CFBundleGetIdentifier": {"lib": "CoreFoundation", "purpose": "get bundle identifier", "category": "foundation"},
    "_CFBundleCopyBundleURL": {"lib": "CoreFoundation", "purpose": "get bundle URL", "category": "foundation"},

    # CoreFoundation -- Memory / Utility
    "_CFRelease": {"lib": "CoreFoundation", "purpose": "release CF object", "category": "foundation"},
    "_CFRetain": {"lib": "CoreFoundation", "purpose": "retain CF object", "category": "foundation"},
    "_CFGetRetainCount": {"lib": "CoreFoundation", "purpose": "get CF object retain count", "category": "foundation"},
    "_CFEqual": {"lib": "CoreFoundation", "purpose": "compare CF objects for equality", "category": "foundation"},
    "_CFHash": {"lib": "CoreFoundation", "purpose": "compute CF object hash", "category": "foundation"},
    "_CFCopyDescription": {"lib": "CoreFoundation", "purpose": "CF object description string", "category": "foundation"},
    "_CFShow": {"lib": "CoreFoundation", "purpose": "print CF object to stderr", "category": "foundation"},
    "_CFAllocatorAllocate": {"lib": "CoreFoundation", "purpose": "CF allocator allocate", "category": "foundation"},
    "_CFAllocatorDeallocate": {"lib": "CoreFoundation", "purpose": "CF allocator deallocate", "category": "foundation"},
    "_kCFBooleanTrue": {"lib": "CoreFoundation", "purpose": "CFBoolean true constant", "category": "foundation"},
    "_kCFBooleanFalse": {"lib": "CoreFoundation", "purpose": "CFBoolean false constant", "category": "foundation"},
    "_kCFAllocatorDefault": {"lib": "CoreFoundation", "purpose": "default CF allocator", "category": "foundation"},

    # Foundation / ObjC runtime -- eksik olanlar
    "_objc_exception_throw": {"lib": "libobjc", "purpose": "ObjC exception throw", "category": "runtime"},
    "_objc_setAssociatedObject": {"lib": "libobjc", "purpose": "ObjC associated object set", "category": "runtime"},
    "_objc_getAssociatedObject": {"lib": "libobjc", "purpose": "ObjC associated object get", "category": "runtime"},
    "_objc_removeAssociatedObjects": {"lib": "libobjc", "purpose": "ObjC remove all associated objects", "category": "runtime"},
    "_objc_sync_enter": {"lib": "libobjc", "purpose": "ObjC @synchronized enter", "category": "runtime"},
    "_objc_sync_exit": {"lib": "libobjc", "purpose": "ObjC @synchronized exit", "category": "runtime"},
    "_class_getInstanceVariable": {"lib": "libobjc", "purpose": "ObjC instance variable lookup", "category": "runtime"},
    "_method_getImplementation": {"lib": "libobjc", "purpose": "ObjC get method IMP pointer", "category": "runtime"},
    "_method_setImplementation": {"lib": "libobjc", "purpose": "ObjC set method IMP pointer", "category": "runtime"},
    "_sel_getUid": {"lib": "libobjc", "purpose": "ObjC selector UID lookup", "category": "runtime"},
    "_object_setClass": {"lib": "libobjc", "purpose": "ObjC change object isa class", "category": "runtime"},
    "_object_getInstanceVariable": {"lib": "libobjc", "purpose": "ObjC get instance variable value", "category": "runtime"},
    "_protocol_getMethodDescription": {"lib": "libobjc", "purpose": "ObjC protocol method description", "category": "runtime"},
    "_class_conformsToProtocol": {"lib": "libobjc", "purpose": "ObjC class protocol conformance", "category": "runtime"},
    "_property_getName": {"lib": "libobjc", "purpose": "ObjC property name", "category": "runtime"},
    "_property_getAttributes": {"lib": "libobjc", "purpose": "ObjC property attributes string", "category": "runtime"},
    "_class_copyPropertyList": {"lib": "libobjc", "purpose": "ObjC copy all class properties", "category": "runtime"},
    "_ivar_getName": {"lib": "libobjc", "purpose": "ObjC ivar name", "category": "runtime"},
    "_ivar_getOffset": {"lib": "libobjc", "purpose": "ObjC ivar memory offset", "category": "runtime"},
    "_class_copyIvarList": {"lib": "libobjc", "purpose": "ObjC copy all class ivars", "category": "runtime"},
    "_NSLogv": {"lib": "Foundation", "purpose": "ObjC variadic console logging", "category": "runtime"},

    # Swift runtime -- eksik olanlar
    "_swift_isUniquelyReferenced": {"lib": "swift_runtime", "purpose": "Swift COW uniqueness check", "category": "runtime"},
    "_swift_allocError": {"lib": "swift_runtime", "purpose": "Swift error box allocation", "category": "runtime"},
    "_swift_deallocError": {"lib": "swift_runtime", "purpose": "Swift error box deallocation", "category": "runtime"},
    "_swift_dynamicCastClass": {"lib": "swift_runtime", "purpose": "Swift class-only dynamic cast", "category": "runtime"},
    "_swift_task_escalate": {"lib": "swift_runtime", "purpose": "Swift task priority escalation", "category": "concurrency"},
    "_swift_job_run": {"lib": "swift_runtime", "purpose": "Swift concurrency job run", "category": "concurrency"},
    "_swift_task_enqueueGlobal": {"lib": "swift_runtime", "purpose": "Swift enqueue task to global executor", "category": "concurrency"},
    "$sSS": {"lib": "swift_runtime", "purpose": "Swift String type (mangled prefix)", "category": "runtime"},
    "$sSa": {"lib": "swift_runtime", "purpose": "Swift Array type (mangled prefix)", "category": "runtime"},
    "$sSD": {"lib": "swift_runtime", "purpose": "Swift Dictionary type (mangled prefix)", "category": "runtime"},

    # Grand Central Dispatch -- eksik olanlar
    "_dispatch_source_set_event_handler": {"lib": "libdispatch", "purpose": "set dispatch source event handler", "category": "concurrency"},
    "_dispatch_source_set_cancel_handler": {"lib": "libdispatch", "purpose": "set dispatch source cancel handler", "category": "concurrency"},
    "_dispatch_source_cancel": {"lib": "libdispatch", "purpose": "cancel dispatch source", "category": "concurrency"},
    "_dispatch_resume": {"lib": "libdispatch", "purpose": "resume dispatch object", "category": "concurrency"},
    "_dispatch_data_get_size": {"lib": "libdispatch", "purpose": "get dispatch data size", "category": "concurrency"},
    "_dispatch_data_apply": {"lib": "libdispatch", "purpose": "iterate dispatch data regions", "category": "concurrency"},
    "_dispatch_io_read": {"lib": "libdispatch", "purpose": "dispatch I/O read", "category": "concurrency"},
    "_dispatch_io_write": {"lib": "libdispatch", "purpose": "dispatch I/O write", "category": "concurrency"},
    "_dispatch_io_close": {"lib": "libdispatch", "purpose": "dispatch I/O channel close", "category": "concurrency"},

    # Security.framework -- eksik olanlar
    "_SecKeyGetBlockSize": {"lib": "Security", "purpose": "get key block size", "category": "security"},
    "_SecCertificateCopyData": {"lib": "Security", "purpose": "get certificate DER data", "category": "security"},
    "_SecTrustGetCertificateCount": {"lib": "Security", "purpose": "get trust chain cert count", "category": "security"},
    "_SecTrustGetCertificateAtIndex": {"lib": "Security", "purpose": "get cert from trust chain by index", "category": "security"},
    "_SecRandomCopyBytes": {"lib": "Security", "purpose": "generate secure random bytes", "category": "security"},
    "_SSLCreateContext": {"lib": "Security", "purpose": "create SSL/TLS context (deprecated)", "category": "security"},
    "_SSLSetIOFuncs": {"lib": "Security", "purpose": "set SSL I/O callbacks", "category": "security"},
    "_SSLHandshake": {"lib": "Security", "purpose": "perform SSL/TLS handshake", "category": "security"},
    "_SSLRead": {"lib": "Security", "purpose": "read from SSL connection", "category": "security"},
    "_SSLWrite": {"lib": "Security", "purpose": "write to SSL connection", "category": "security"},
    "_SSLClose": {"lib": "Security", "purpose": "close SSL connection", "category": "security"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- OpenSSL / BoringSSL
# ---------------------------------------------------------------------------

_OPENSSL_SIGNATURES: dict[str, dict[str, str]] = {
    # EVP high-level crypto API
    "_EVP_EncryptInit_ex": {"lib": "openssl", "purpose": "symmetric encryption init", "category": "crypto"},
    "_EVP_EncryptUpdate": {"lib": "openssl", "purpose": "symmetric encryption update", "category": "crypto"},
    "_EVP_EncryptFinal_ex": {"lib": "openssl", "purpose": "symmetric encryption finalize", "category": "crypto"},
    "_EVP_DecryptInit_ex": {"lib": "openssl", "purpose": "symmetric decryption init", "category": "crypto"},
    "_EVP_DecryptUpdate": {"lib": "openssl", "purpose": "symmetric decryption update", "category": "crypto"},
    "_EVP_DecryptFinal_ex": {"lib": "openssl", "purpose": "symmetric decryption finalize", "category": "crypto"},
    "_EVP_CipherInit_ex": {"lib": "openssl", "purpose": "cipher init (enc or dec)", "category": "crypto"},
    "_EVP_CipherUpdate": {"lib": "openssl", "purpose": "cipher update", "category": "crypto"},
    "_EVP_CipherFinal_ex": {"lib": "openssl", "purpose": "cipher finalize", "category": "crypto"},
    "_EVP_CIPHER_CTX_new": {"lib": "openssl", "purpose": "cipher context creation", "category": "crypto"},
    "_EVP_CIPHER_CTX_free": {"lib": "openssl", "purpose": "cipher context cleanup", "category": "crypto"},
    "_EVP_CIPHER_CTX_set_padding": {"lib": "openssl", "purpose": "cipher padding config", "category": "crypto"},
    "_EVP_CIPHER_CTX_ctrl": {"lib": "openssl", "purpose": "cipher context control", "category": "crypto"},
    "_EVP_aes_128_cbc": {"lib": "openssl", "purpose": "AES-128-CBC cipher", "category": "crypto"},
    "_EVP_aes_256_cbc": {"lib": "openssl", "purpose": "AES-256-CBC cipher", "category": "crypto"},
    "_EVP_aes_128_gcm": {"lib": "openssl", "purpose": "AES-128-GCM AEAD cipher", "category": "crypto"},
    "_EVP_aes_256_gcm": {"lib": "openssl", "purpose": "AES-256-GCM AEAD cipher", "category": "crypto"},
    "_EVP_chacha20_poly1305": {"lib": "openssl", "purpose": "ChaCha20-Poly1305 AEAD", "category": "crypto"},

    # EVP digest (hash)
    "_EVP_DigestInit_ex": {"lib": "openssl", "purpose": "hash init", "category": "crypto"},
    "_EVP_DigestUpdate": {"lib": "openssl", "purpose": "hash update", "category": "crypto"},
    "_EVP_DigestFinal_ex": {"lib": "openssl", "purpose": "hash finalize", "category": "crypto"},
    "_EVP_DigestSign": {"lib": "openssl", "purpose": "sign with digest", "category": "crypto"},
    "_EVP_DigestVerify": {"lib": "openssl", "purpose": "verify with digest", "category": "crypto"},
    "_EVP_DigestSignInit": {"lib": "openssl", "purpose": "digest sign init", "category": "crypto"},
    "_EVP_DigestVerifyInit": {"lib": "openssl", "purpose": "digest verify init", "category": "crypto"},
    "_EVP_MD_CTX_new": {"lib": "openssl", "purpose": "message digest context new", "category": "crypto"},
    "_EVP_MD_CTX_free": {"lib": "openssl", "purpose": "message digest context free", "category": "crypto"},
    "_EVP_sha1": {"lib": "openssl", "purpose": "SHA-1 digest method", "category": "crypto"},
    "_EVP_sha256": {"lib": "openssl", "purpose": "SHA-256 digest method", "category": "crypto"},
    "_EVP_sha384": {"lib": "openssl", "purpose": "SHA-384 digest method", "category": "crypto"},
    "_EVP_sha512": {"lib": "openssl", "purpose": "SHA-512 digest method", "category": "crypto"},
    "_EVP_md5": {"lib": "openssl", "purpose": "MD5 digest method", "category": "crypto"},

    # EVP PKEY (asymmetric keys)
    "_EVP_PKEY_new": {"lib": "openssl", "purpose": "public key creation", "category": "crypto"},
    "_EVP_PKEY_free": {"lib": "openssl", "purpose": "public key cleanup", "category": "crypto"},
    "_EVP_PKEY_CTX_new": {"lib": "openssl", "purpose": "PKEY context creation", "category": "crypto"},
    "_EVP_PKEY_CTX_free": {"lib": "openssl", "purpose": "PKEY context cleanup", "category": "crypto"},
    "_EVP_PKEY_keygen_init": {"lib": "openssl", "purpose": "key generation init", "category": "crypto"},
    "_EVP_PKEY_keygen": {"lib": "openssl", "purpose": "key generation", "category": "crypto"},
    "_EVP_PKEY_encrypt_init": {"lib": "openssl", "purpose": "PKEY encrypt init", "category": "crypto"},
    "_EVP_PKEY_encrypt": {"lib": "openssl", "purpose": "public key encryption", "category": "crypto"},
    "_EVP_PKEY_decrypt_init": {"lib": "openssl", "purpose": "PKEY decrypt init", "category": "crypto"},
    "_EVP_PKEY_decrypt": {"lib": "openssl", "purpose": "public key decryption", "category": "crypto"},
    "_EVP_PKEY_sign_init": {"lib": "openssl", "purpose": "PKEY sign init", "category": "crypto"},
    "_EVP_PKEY_sign": {"lib": "openssl", "purpose": "public key signing", "category": "crypto"},
    "_EVP_PKEY_verify_init": {"lib": "openssl", "purpose": "PKEY verify init", "category": "crypto"},
    "_EVP_PKEY_verify": {"lib": "openssl", "purpose": "public key verify", "category": "crypto"},
    "_EVP_PKEY_derive_init": {"lib": "openssl", "purpose": "key derivation init", "category": "crypto"},
    "_EVP_PKEY_derive": {"lib": "openssl", "purpose": "key derivation (DH/ECDH)", "category": "crypto"},

    # Raw hash functions (low level)
    "_SHA1": {"lib": "openssl", "purpose": "SHA-1 one-shot hash", "category": "crypto"},
    "_SHA1_Init": {"lib": "openssl", "purpose": "SHA-1 init", "category": "crypto"},
    "_SHA1_Update": {"lib": "openssl", "purpose": "SHA-1 update", "category": "crypto"},
    "_SHA1_Final": {"lib": "openssl", "purpose": "SHA-1 final", "category": "crypto"},
    "_SHA256_Init": {"lib": "openssl", "purpose": "SHA-256 init", "category": "crypto"},
    "_SHA256_Update": {"lib": "openssl", "purpose": "SHA-256 update", "category": "crypto"},
    "_SHA256_Final": {"lib": "openssl", "purpose": "SHA-256 final", "category": "crypto"},
    "_SHA384_Init": {"lib": "openssl", "purpose": "SHA-384 init", "category": "crypto"},
    "_SHA384_Update": {"lib": "openssl", "purpose": "SHA-384 update", "category": "crypto"},
    "_SHA384_Final": {"lib": "openssl", "purpose": "SHA-384 final", "category": "crypto"},
    "_SHA512_Init": {"lib": "openssl", "purpose": "SHA-512 init", "category": "crypto"},
    "_SHA512_Update": {"lib": "openssl", "purpose": "SHA-512 update", "category": "crypto"},
    "_SHA512_Final": {"lib": "openssl", "purpose": "SHA-512 final", "category": "crypto"},
    "_MD5": {"lib": "openssl", "purpose": "MD5 one-shot hash", "category": "crypto"},
    "_MD5_Init": {"lib": "openssl", "purpose": "MD5 init", "category": "crypto"},
    "_MD5_Update": {"lib": "openssl", "purpose": "MD5 update", "category": "crypto"},
    "_MD5_Final": {"lib": "openssl", "purpose": "MD5 final", "category": "crypto"},

    # HMAC
    "_HMAC": {"lib": "openssl", "purpose": "HMAC one-shot", "category": "crypto"},
    "_HMAC_Init_ex": {"lib": "openssl", "purpose": "HMAC init", "category": "crypto"},
    "_HMAC_Update": {"lib": "openssl", "purpose": "HMAC update", "category": "crypto"},
    "_HMAC_Final": {"lib": "openssl", "purpose": "HMAC final", "category": "crypto"},
    "_HMAC_CTX_new": {"lib": "openssl", "purpose": "HMAC context creation", "category": "crypto"},
    "_HMAC_CTX_free": {"lib": "openssl", "purpose": "HMAC context cleanup", "category": "crypto"},

    # SSL/TLS
    "_SSL_CTX_new": {"lib": "openssl", "purpose": "TLS context creation", "category": "network"},
    "_SSL_CTX_free": {"lib": "openssl", "purpose": "TLS context cleanup", "category": "network"},
    "_SSL_CTX_set_verify": {"lib": "openssl", "purpose": "TLS verify mode", "category": "network"},
    "_SSL_CTX_set_verify_depth": {"lib": "openssl", "purpose": "TLS verify chain depth", "category": "network"},
    "_SSL_CTX_load_verify_locations": {"lib": "openssl", "purpose": "TLS CA cert loading", "category": "network"},
    "_SSL_CTX_use_certificate_file": {"lib": "openssl", "purpose": "TLS client cert", "category": "network"},
    "_SSL_CTX_use_PrivateKey_file": {"lib": "openssl", "purpose": "TLS client key", "category": "network"},
    "_SSL_CTX_set_cipher_list": {"lib": "openssl", "purpose": "TLS cipher config", "category": "network"},
    "_SSL_CTX_set_ciphersuites": {"lib": "openssl", "purpose": "TLS 1.3 ciphersuite config", "category": "network"},
    "_SSL_CTX_set_options": {"lib": "openssl", "purpose": "TLS context options", "category": "network"},
    "_SSL_CTX_set_min_proto_version": {"lib": "openssl", "purpose": "TLS minimum version", "category": "network"},
    "_SSL_CTX_set_max_proto_version": {"lib": "openssl", "purpose": "TLS maximum version", "category": "network"},
    "_SSL_CTX_set_alpn_protos": {"lib": "openssl", "purpose": "TLS ALPN protocol list", "category": "network"},
    "_SSL_CTX_set_session_cache_mode": {"lib": "openssl", "purpose": "TLS session caching", "category": "network"},
    "_SSL_new": {"lib": "openssl", "purpose": "TLS connection creation", "category": "network"},
    "_SSL_free": {"lib": "openssl", "purpose": "TLS connection cleanup", "category": "network"},
    "_SSL_set_fd": {"lib": "openssl", "purpose": "TLS bind to socket fd", "category": "network"},
    "_SSL_set_bio": {"lib": "openssl", "purpose": "TLS bind to BIO pair", "category": "network"},
    "_SSL_connect": {"lib": "openssl", "purpose": "TLS client handshake", "category": "network"},
    "_SSL_accept": {"lib": "openssl", "purpose": "TLS server handshake", "category": "network"},
    "_SSL_do_handshake": {"lib": "openssl", "purpose": "TLS handshake", "category": "network"},
    "_SSL_read": {"lib": "openssl", "purpose": "TLS read decrypted data", "category": "network"},
    "_SSL_write": {"lib": "openssl", "purpose": "TLS write encrypted data", "category": "network"},
    "_SSL_shutdown": {"lib": "openssl", "purpose": "TLS shutdown", "category": "network"},
    "_SSL_get_error": {"lib": "openssl", "purpose": "TLS error code", "category": "network"},
    "_SSL_get_peer_certificate": {"lib": "openssl", "purpose": "TLS peer cert", "category": "network"},
    "_SSL_get_verify_result": {"lib": "openssl", "purpose": "TLS verify result", "category": "network"},
    "_SSL_set_tlsext_host_name": {"lib": "openssl", "purpose": "TLS SNI hostname", "category": "network"},

    # BIO
    "_BIO_new": {"lib": "openssl", "purpose": "BIO creation", "category": "io"},
    "_BIO_new_mem_buf": {"lib": "openssl", "purpose": "BIO from memory", "category": "io"},
    "_BIO_new_socket": {"lib": "openssl", "purpose": "BIO from socket", "category": "io"},
    "_BIO_new_ssl_connect": {"lib": "openssl", "purpose": "BIO SSL connect", "category": "io"},
    "_BIO_read": {"lib": "openssl", "purpose": "BIO read", "category": "io"},
    "_BIO_write": {"lib": "openssl", "purpose": "BIO write", "category": "io"},
    "_BIO_free": {"lib": "openssl", "purpose": "BIO cleanup", "category": "io"},
    "_BIO_free_all": {"lib": "openssl", "purpose": "BIO chain cleanup", "category": "io"},
    "_BIO_s_mem": {"lib": "openssl", "purpose": "BIO memory method", "category": "io"},
    "_BIO_s_file": {"lib": "openssl", "purpose": "BIO file method", "category": "io"},

    # X509
    "_X509_new": {"lib": "openssl", "purpose": "X509 certificate creation", "category": "crypto"},
    "_X509_free": {"lib": "openssl", "purpose": "X509 certificate cleanup", "category": "crypto"},
    "_X509_verify": {"lib": "openssl", "purpose": "X509 signature verify", "category": "crypto"},
    "_X509_get_subject_name": {"lib": "openssl", "purpose": "X509 subject name", "category": "crypto"},
    "_X509_get_issuer_name": {"lib": "openssl", "purpose": "X509 issuer name", "category": "crypto"},
    "_X509_STORE_new": {"lib": "openssl", "purpose": "X509 store creation", "category": "crypto"},
    "_X509_STORE_add_cert": {"lib": "openssl", "purpose": "X509 store add cert", "category": "crypto"},
    "_X509_STORE_CTX_new": {"lib": "openssl", "purpose": "X509 verify context", "category": "crypto"},
    "_d2i_X509": {"lib": "openssl", "purpose": "DER to X509 decode", "category": "crypto"},
    "_i2d_X509": {"lib": "openssl", "purpose": "X509 to DER encode", "category": "crypto"},
    "_PEM_read_bio_X509": {"lib": "openssl", "purpose": "PEM X509 read", "category": "crypto"},
    "_PEM_write_bio_X509": {"lib": "openssl", "purpose": "PEM X509 write", "category": "crypto"},
    "_PEM_read_bio_PrivateKey": {"lib": "openssl", "purpose": "PEM private key read", "category": "crypto"},
    "_PEM_write_bio_PrivateKey": {"lib": "openssl", "purpose": "PEM private key write", "category": "crypto"},

    # RSA
    "_RSA_new": {"lib": "openssl", "purpose": "RSA key creation", "category": "crypto"},
    "_RSA_free": {"lib": "openssl", "purpose": "RSA key cleanup", "category": "crypto"},
    "_RSA_generate_key_ex": {"lib": "openssl", "purpose": "RSA key generation", "category": "crypto"},
    "_RSA_public_encrypt": {"lib": "openssl", "purpose": "RSA public encrypt", "category": "crypto"},
    "_RSA_private_decrypt": {"lib": "openssl", "purpose": "RSA private decrypt", "category": "crypto"},
    "_RSA_sign": {"lib": "openssl", "purpose": "RSA signing", "category": "crypto"},
    "_RSA_verify": {"lib": "openssl", "purpose": "RSA verification", "category": "crypto"},
    "_RSA_size": {"lib": "openssl", "purpose": "RSA key size", "category": "crypto"},

    # EC (Elliptic Curve)
    "_EC_KEY_new_by_curve_name": {"lib": "openssl", "purpose": "EC key creation", "category": "crypto"},
    "_EC_KEY_generate_key": {"lib": "openssl", "purpose": "EC key generation", "category": "crypto"},
    "_EC_KEY_free": {"lib": "openssl", "purpose": "EC key cleanup", "category": "crypto"},
    "_ECDSA_sign": {"lib": "openssl", "purpose": "ECDSA signing", "category": "crypto"},
    "_ECDSA_verify": {"lib": "openssl", "purpose": "ECDSA verification", "category": "crypto"},
    "_ECDH_compute_key": {"lib": "openssl", "purpose": "ECDH key agreement", "category": "crypto"},
    "_EC_GROUP_new_by_curve_name": {"lib": "openssl", "purpose": "EC curve group", "category": "crypto"},
    "_EC_POINT_new": {"lib": "openssl", "purpose": "EC point creation", "category": "crypto"},
    "_EC_POINT_free": {"lib": "openssl", "purpose": "EC point cleanup", "category": "crypto"},

    # RAND
    "_RAND_bytes": {"lib": "openssl", "purpose": "cryptographic RNG", "category": "crypto"},
    "_RAND_seed": {"lib": "openssl", "purpose": "RNG seeding", "category": "crypto"},

    # Error
    "_ERR_get_error": {"lib": "openssl", "purpose": "error code retrieval", "category": "error"},
    "_ERR_error_string": {"lib": "openssl", "purpose": "error string lookup", "category": "error"},
    "_ERR_print_errors_fp": {"lib": "openssl", "purpose": "print error stack", "category": "error"},
    "_ERR_clear_error": {"lib": "openssl", "purpose": "clear error stack", "category": "error"},

    # Init / Cleanup
    "_OPENSSL_init_ssl": {"lib": "openssl", "purpose": "OpenSSL SSL init", "category": "init"},
    "_OPENSSL_init_crypto": {"lib": "openssl", "purpose": "OpenSSL crypto init", "category": "init"},
    "_OPENSSL_cleanup": {"lib": "openssl", "purpose": "OpenSSL cleanup", "category": "init"},

    # PKCS
    "_PKCS7_sign": {"lib": "openssl", "purpose": "PKCS#7 signing", "category": "crypto"},
    "_PKCS7_verify": {"lib": "openssl", "purpose": "PKCS#7 verification", "category": "crypto"},
    "_PKCS12_parse": {"lib": "openssl", "purpose": "PKCS#12 parsing", "category": "crypto"},
    "_PKCS12_create": {"lib": "openssl", "purpose": "PKCS#12 creation", "category": "crypto"},
    "_PKCS5_PBKDF2_HMAC": {"lib": "openssl", "purpose": "PBKDF2 key derivation", "category": "crypto"},
    "_PKCS5_PBKDF2_HMAC_SHA1": {"lib": "openssl", "purpose": "PBKDF2-SHA1 key derivation", "category": "crypto"},

    # ASN1 / DER
    "_ASN1_INTEGER_set": {"lib": "openssl", "purpose": "ASN1 integer set", "category": "encoding"},
    "_ASN1_INTEGER_get": {"lib": "openssl", "purpose": "ASN1 integer get", "category": "encoding"},
    "_ASN1_STRING_data": {"lib": "openssl", "purpose": "ASN1 string data", "category": "encoding"},
    "_ASN1_TIME_print": {"lib": "openssl", "purpose": "ASN1 time print", "category": "encoding"},

    # BIGNUM
    "_BN_new": {"lib": "openssl", "purpose": "big number creation", "category": "math"},
    "_BN_free": {"lib": "openssl", "purpose": "big number cleanup", "category": "math"},
    "_BN_set_word": {"lib": "openssl", "purpose": "big number from word", "category": "math"},
    "_BN_num_bits": {"lib": "openssl", "purpose": "big number bit count", "category": "math"},
    "_BN_bn2hex": {"lib": "openssl", "purpose": "big number to hex string", "category": "math"},
    "_BN_hex2bn": {"lib": "openssl", "purpose": "hex string to big number", "category": "math"},
    "_BN_CTX_new": {"lib": "openssl", "purpose": "BN context creation", "category": "math"},
    "_BN_CTX_free": {"lib": "openssl", "purpose": "BN context cleanup", "category": "math"},
    # --- OpenSSL additional signatures (crypto/TLS expansion) ---

    # EVP additional (legacy / convenience wrappers)
    "_EVP_DigestInit": {"lib": "openssl", "purpose": "hash init (legacy)", "category": "crypto"},
    "_EVP_DigestFinal": {"lib": "openssl", "purpose": "hash finalize (legacy)", "category": "crypto"},
    "_EVP_SignInit": {"lib": "openssl", "purpose": "sign init (legacy EVP)", "category": "crypto"},
    "_EVP_SignFinal": {"lib": "openssl", "purpose": "sign finalize (legacy EVP)", "category": "crypto"},
    "_EVP_VerifyInit": {"lib": "openssl", "purpose": "verify init (legacy EVP)", "category": "crypto"},
    "_EVP_VerifyFinal": {"lib": "openssl", "purpose": "verify finalize (legacy EVP)", "category": "crypto"},
    "_EVP_aes_128_ecb": {"lib": "openssl", "purpose": "AES-128-ECB cipher", "category": "crypto"},
    "_EVP_aes_192_cbc": {"lib": "openssl", "purpose": "AES-192-CBC cipher", "category": "crypto"},
    "_EVP_aes_256_ecb": {"lib": "openssl", "purpose": "AES-256-ECB cipher", "category": "crypto"},
    "_EVP_aes_128_ctr": {"lib": "openssl", "purpose": "AES-128-CTR cipher", "category": "crypto"},
    "_EVP_aes_256_ctr": {"lib": "openssl", "purpose": "AES-256-CTR cipher", "category": "crypto"},
    "_EVP_aes_128_cfb128": {"lib": "openssl", "purpose": "AES-128-CFB cipher", "category": "crypto"},
    "_EVP_aes_256_cfb128": {"lib": "openssl", "purpose": "AES-256-CFB cipher", "category": "crypto"},
    "_EVP_aes_128_ofb": {"lib": "openssl", "purpose": "AES-128-OFB cipher", "category": "crypto"},
    "_EVP_aes_256_ofb": {"lib": "openssl", "purpose": "AES-256-OFB cipher", "category": "crypto"},
    "_EVP_aes_128_xts": {"lib": "openssl", "purpose": "AES-128-XTS cipher", "category": "crypto"},
    "_EVP_aes_256_xts": {"lib": "openssl", "purpose": "AES-256-XTS cipher", "category": "crypto"},
    "_EVP_aes_128_ccm": {"lib": "openssl", "purpose": "AES-128-CCM AEAD cipher", "category": "crypto"},
    "_EVP_aes_256_ccm": {"lib": "openssl", "purpose": "AES-256-CCM AEAD cipher", "category": "crypto"},
    "_EVP_aes_128_wrap": {"lib": "openssl", "purpose": "AES-128 key wrap", "category": "crypto"},
    "_EVP_aes_256_wrap": {"lib": "openssl", "purpose": "AES-256 key wrap", "category": "crypto"},
    "_EVP_des_ede3_cbc": {"lib": "openssl", "purpose": "3DES-CBC cipher", "category": "crypto"},
    "_EVP_des_cbc": {"lib": "openssl", "purpose": "DES-CBC cipher (insecure)", "category": "crypto"},
    "_EVP_rc4": {"lib": "openssl", "purpose": "RC4 stream cipher (insecure)", "category": "crypto"},
    "_EVP_sha224": {"lib": "openssl", "purpose": "SHA-224 digest method", "category": "crypto"},
    "_EVP_sha3_256": {"lib": "openssl", "purpose": "SHA3-256 digest method", "category": "crypto"},
    "_EVP_sha3_384": {"lib": "openssl", "purpose": "SHA3-384 digest method", "category": "crypto"},
    "_EVP_sha3_512": {"lib": "openssl", "purpose": "SHA3-512 digest method", "category": "crypto"},
    "_EVP_blake2b512": {"lib": "openssl", "purpose": "BLAKE2b-512 digest method", "category": "crypto"},
    "_EVP_blake2s256": {"lib": "openssl", "purpose": "BLAKE2s-256 digest method", "category": "crypto"},
    "_EVP_PKEY_CTX_set_rsa_padding": {"lib": "openssl", "purpose": "RSA padding mode config", "category": "crypto"},
    "_EVP_PKEY_CTX_set_rsa_oaep_md": {"lib": "openssl", "purpose": "RSA OAEP hash config", "category": "crypto"},
    "_EVP_PKEY_CTX_set_rsa_keygen_bits": {"lib": "openssl", "purpose": "RSA keygen bit length", "category": "crypto"},
    "_EVP_PKEY_CTX_set_ec_paramgen_curve_nid": {"lib": "openssl", "purpose": "EC keygen curve selection", "category": "crypto"},
    "_EVP_PKEY_assign_RSA": {"lib": "openssl", "purpose": "assign RSA key to EVP_PKEY", "category": "crypto"},
    "_EVP_PKEY_assign_EC_KEY": {"lib": "openssl", "purpose": "assign EC key to EVP_PKEY", "category": "crypto"},
    "_EVP_PKEY_get1_RSA": {"lib": "openssl", "purpose": "extract RSA from EVP_PKEY", "category": "crypto"},
    "_EVP_PKEY_get1_EC_KEY": {"lib": "openssl", "purpose": "extract EC key from EVP_PKEY", "category": "crypto"},
    "_EVP_PKEY_id": {"lib": "openssl", "purpose": "get PKEY algorithm id", "category": "crypto"},
    "_EVP_PKEY_bits": {"lib": "openssl", "purpose": "get PKEY bit length", "category": "crypto"},
    "_EVP_PKEY_size": {"lib": "openssl", "purpose": "get PKEY output size", "category": "crypto"},
    "_EVP_PKEY_up_ref": {"lib": "openssl", "purpose": "increment PKEY ref count", "category": "crypto"},
    "_EVP_PKEY_CTX_new_id": {"lib": "openssl", "purpose": "PKEY context from algorithm id", "category": "crypto"},
    "_EVP_PKEY_paramgen_init": {"lib": "openssl", "purpose": "parameter generation init", "category": "crypto"},
    "_EVP_PKEY_paramgen": {"lib": "openssl", "purpose": "parameter generation", "category": "crypto"},
    "_EVP_CIPHER_CTX_set_key_length": {"lib": "openssl", "purpose": "set cipher key length", "category": "crypto"},
    "_EVP_CIPHER_CTX_iv_length": {"lib": "openssl", "purpose": "get cipher IV length", "category": "crypto"},
    "_EVP_CIPHER_CTX_key_length": {"lib": "openssl", "purpose": "get cipher key length", "category": "crypto"},
    "_EVP_CIPHER_CTX_block_size": {"lib": "openssl", "purpose": "get cipher block size", "category": "crypto"},
    "_EVP_CIPHER_nid": {"lib": "openssl", "purpose": "get cipher NID", "category": "crypto"},
    "_EVP_MD_size": {"lib": "openssl", "purpose": "get digest output size", "category": "crypto"},
    "_EVP_MD_CTX_md": {"lib": "openssl", "purpose": "get digest from context", "category": "crypto"},
    "_EVP_MD_CTX_copy_ex": {"lib": "openssl", "purpose": "copy digest context", "category": "crypto"},
    # SSL/TLS additional
    "_SSL_CTX_set_default_verify_paths": {"lib": "openssl", "purpose": "TLS use system CA store", "category": "network"},
    "_SSL_CTX_use_certificate_chain_file": {"lib": "openssl", "purpose": "TLS cert chain file", "category": "network"},
    "_SSL_CTX_use_certificate": {"lib": "openssl", "purpose": "TLS set certificate", "category": "network"},
    "_SSL_CTX_use_PrivateKey": {"lib": "openssl", "purpose": "TLS set private key", "category": "network"},
    "_SSL_CTX_check_private_key": {"lib": "openssl", "purpose": "TLS verify key matches cert", "category": "network"},
    "_SSL_CTX_set_keylog_callback": {"lib": "openssl", "purpose": "TLS key log callback (SSLKEYLOGFILE)", "category": "network"},
    "_SSL_CTX_set_mode": {"lib": "openssl", "purpose": "TLS mode flags", "category": "network"},
    "_SSL_CTX_ctrl": {"lib": "openssl", "purpose": "TLS context control", "category": "network"},
    "_SSL_CTX_get_cert_store": {"lib": "openssl", "purpose": "TLS get cert store", "category": "network"},
    "_SSL_CTX_set_timeout": {"lib": "openssl", "purpose": "TLS session timeout", "category": "network"},
    "_SSL_CTX_set_alpn_select_cb": {"lib": "openssl", "purpose": "TLS ALPN server callback", "category": "network"},
    "_SSL_read_ex": {"lib": "openssl", "purpose": "TLS read with byte count", "category": "network"},
    "_SSL_write_ex": {"lib": "openssl", "purpose": "TLS write with byte count", "category": "network"},
    "_SSL_peek": {"lib": "openssl", "purpose": "TLS peek data", "category": "network"},
    "_SSL_pending": {"lib": "openssl", "purpose": "TLS pending bytes", "category": "network"},
    "_SSL_get_version": {"lib": "openssl", "purpose": "TLS protocol version string", "category": "network"},
    "_SSL_get_current_cipher": {"lib": "openssl", "purpose": "TLS active cipher suite", "category": "network"},
    "_SSL_CIPHER_get_name": {"lib": "openssl", "purpose": "TLS cipher name", "category": "network"},
    "_SSL_get_servername": {"lib": "openssl", "purpose": "TLS SNI server name", "category": "network"},
    "_SSL_get0_alpn_selected": {"lib": "openssl", "purpose": "TLS selected ALPN protocol", "category": "network"},
    "_SSL_get_session": {"lib": "openssl", "purpose": "TLS get session object", "category": "network"},
    "_SSL_set_session": {"lib": "openssl", "purpose": "TLS resume session", "category": "network"},
    "_SSL_SESSION_free": {"lib": "openssl", "purpose": "TLS session cleanup", "category": "network"},
    "_SSL_get_fd": {"lib": "openssl", "purpose": "TLS get socket fd", "category": "network"},
    "_SSL_set_connect_state": {"lib": "openssl", "purpose": "TLS set client mode", "category": "network"},
    "_SSL_set_accept_state": {"lib": "openssl", "purpose": "TLS set server mode", "category": "network"},
    "_SSL_ctrl": {"lib": "openssl", "purpose": "TLS connection control", "category": "network"},
    "_SSL_get1_peer_certificate": {"lib": "openssl", "purpose": "TLS peer cert (refcounted)", "category": "network"},
    "_SSL_get_peer_cert_chain": {"lib": "openssl", "purpose": "TLS peer cert chain", "category": "network"},
    "_SSL_is_init_finished": {"lib": "openssl", "purpose": "TLS handshake complete check", "category": "network"},
    "_SSL_set_verify": {"lib": "openssl", "purpose": "TLS per-connection verify mode", "category": "network"},
    # BIO additional
    "_BIO_gets": {"lib": "openssl", "purpose": "BIO read line", "category": "io"},
    "_BIO_puts": {"lib": "openssl", "purpose": "BIO write string", "category": "io"},
    "_BIO_ctrl": {"lib": "openssl", "purpose": "BIO control operation", "category": "io"},
    "_BIO_new_file": {"lib": "openssl", "purpose": "BIO from file path", "category": "io"},
    "_BIO_new_fp": {"lib": "openssl", "purpose": "BIO from FILE pointer", "category": "io"},
    "_BIO_new_connect": {"lib": "openssl", "purpose": "BIO TCP connect", "category": "io"},
    "_BIO_push": {"lib": "openssl", "purpose": "BIO chain push", "category": "io"},
    "_BIO_pop": {"lib": "openssl", "purpose": "BIO chain pop", "category": "io"},
    "_BIO_flush": {"lib": "openssl", "purpose": "BIO flush", "category": "io"},
    "_BIO_pending": {"lib": "openssl", "purpose": "BIO pending bytes", "category": "io"},
    # X509 additional
    "_X509_NAME_oneline": {"lib": "openssl", "purpose": "X509 name one-line string", "category": "crypto"},
    "_X509_verify_cert": {"lib": "openssl", "purpose": "X509 certificate chain verify", "category": "crypto"},
    "_X509_STORE_CTX_init": {"lib": "openssl", "purpose": "X509 verify context init", "category": "crypto"},
    "_X509_STORE_CTX_free": {"lib": "openssl", "purpose": "X509 verify context cleanup", "category": "crypto"},
    "_X509_STORE_CTX_get_error": {"lib": "openssl", "purpose": "X509 verify error code", "category": "crypto"},
    "_X509_STORE_free": {"lib": "openssl", "purpose": "X509 store cleanup", "category": "crypto"},
    "_X509_check_host": {"lib": "openssl", "purpose": "X509 hostname verification", "category": "crypto"},
    "_X509_get_serialNumber": {"lib": "openssl", "purpose": "X509 serial number", "category": "crypto"},
    "_X509_get_notBefore": {"lib": "openssl", "purpose": "X509 validity start", "category": "crypto"},
    "_X509_get_notAfter": {"lib": "openssl", "purpose": "X509 validity end", "category": "crypto"},
    "_X509_get_pubkey": {"lib": "openssl", "purpose": "X509 extract public key", "category": "crypto"},
    "_X509_sign": {"lib": "openssl", "purpose": "X509 sign certificate", "category": "crypto"},
    "_X509_print_ex": {"lib": "openssl", "purpose": "X509 human-readable print", "category": "crypto"},
    # EC additional
    "_EC_KEY_new": {"lib": "openssl", "purpose": "EC key creation (no curve)", "category": "crypto"},
    "_EC_KEY_set_group": {"lib": "openssl", "purpose": "EC key set curve group", "category": "crypto"},
    "_EC_KEY_get0_private_key": {"lib": "openssl", "purpose": "EC get private key BIGNUM", "category": "crypto"},
    "_EC_KEY_get0_public_key": {"lib": "openssl", "purpose": "EC get public key point", "category": "crypto"},
    "_EC_KEY_check_key": {"lib": "openssl", "purpose": "EC key validity check", "category": "crypto"},
    "_EC_GROUP_free": {"lib": "openssl", "purpose": "EC group cleanup", "category": "crypto"},
    "_EC_GROUP_get_degree": {"lib": "openssl", "purpose": "EC group bit size", "category": "crypto"},
    "_EC_GROUP_get_curve_name": {"lib": "openssl", "purpose": "EC group curve NID", "category": "crypto"},
    "_EC_POINT_mul": {"lib": "openssl", "purpose": "EC point multiplication", "category": "crypto"},
    "_EC_POINT_oct2point": {"lib": "openssl", "purpose": "EC point from octet string", "category": "crypto"},
    "_EC_POINT_point2oct": {"lib": "openssl", "purpose": "EC point to octet string", "category": "crypto"},
    "_ECDSA_SIG_new": {"lib": "openssl", "purpose": "ECDSA signature creation", "category": "crypto"},
    "_ECDSA_SIG_free": {"lib": "openssl", "purpose": "ECDSA signature cleanup", "category": "crypto"},
    # RAND additional
    "_RAND_status": {"lib": "openssl", "purpose": "RNG seeded status check", "category": "crypto"},
    "_RAND_poll": {"lib": "openssl", "purpose": "RNG entropy gathering", "category": "crypto"},
    "_RAND_add": {"lib": "openssl", "purpose": "add entropy to RNG", "category": "crypto"},
    # ERR additional
    "_ERR_peek_error": {"lib": "openssl", "purpose": "peek error without removing", "category": "error"},
    "_ERR_peek_last_error": {"lib": "openssl", "purpose": "peek last error", "category": "error"},
    "_ERR_error_string_n": {"lib": "openssl", "purpose": "error string (bounded)", "category": "error"},
    "_ERR_reason_error_string": {"lib": "openssl", "purpose": "error reason string", "category": "error"},
    "_ERR_print_errors": {"lib": "openssl", "purpose": "print errors to BIO", "category": "error"},
    # PEM additional
    "_PEM_read_PrivateKey": {"lib": "openssl", "purpose": "PEM private key read (FILE)", "category": "crypto"},
    "_PEM_write_PrivateKey": {"lib": "openssl", "purpose": "PEM private key write (FILE)", "category": "crypto"},
    "_PEM_read_X509": {"lib": "openssl", "purpose": "PEM X509 read (FILE)", "category": "crypto"},
    "_PEM_read_bio_RSAPrivateKey": {"lib": "openssl", "purpose": "PEM RSA private key read", "category": "crypto"},
    "_PEM_read_bio_ECPrivateKey": {"lib": "openssl", "purpose": "PEM EC private key read", "category": "crypto"},
    "_PEM_read_bio_PUBKEY": {"lib": "openssl", "purpose": "PEM public key read (generic)", "category": "crypto"},
    "_PEM_read_bio_DHparams": {"lib": "openssl", "purpose": "PEM DH parameters read", "category": "crypto"},
    # DH (Diffie-Hellman)
    "_DH_new": {"lib": "openssl", "purpose": "DH parameter creation", "category": "crypto"},
    "_DH_free": {"lib": "openssl", "purpose": "DH parameter cleanup", "category": "crypto"},
    "_DH_generate_parameters_ex": {"lib": "openssl", "purpose": "DH parameter generation", "category": "crypto"},
    "_DH_generate_key": {"lib": "openssl", "purpose": "DH key generation", "category": "crypto"},
    "_DH_compute_key": {"lib": "openssl", "purpose": "DH shared secret computation", "category": "crypto"},
    "_DH_size": {"lib": "openssl", "purpose": "DH output size", "category": "crypto"},
    "_DH_check": {"lib": "openssl", "purpose": "DH parameter validation", "category": "crypto"},
    # PKCS additional
    "_PKCS7_encrypt": {"lib": "openssl", "purpose": "PKCS#7 encryption", "category": "crypto"},
    "_PKCS7_decrypt": {"lib": "openssl", "purpose": "PKCS#7 decryption", "category": "crypto"},
    "_PKCS12_free": {"lib": "openssl", "purpose": "PKCS#12 cleanup", "category": "crypto"},
    # OPENSSL misc
    "_OPENSSL_malloc": {"lib": "openssl", "purpose": "OpenSSL memory allocation", "category": "memory"},
    "_OPENSSL_free": {"lib": "openssl", "purpose": "OpenSSL memory free", "category": "memory"},
    "_OPENSSL_cleanse": {"lib": "openssl", "purpose": "secure memory wipe", "category": "memory"},
    "_OpenSSL_version": {"lib": "openssl", "purpose": "OpenSSL version string", "category": "init"},
    # CMAC
    "_CMAC_CTX_new": {"lib": "openssl", "purpose": "CMAC context creation", "category": "crypto"},
    "_CMAC_CTX_free": {"lib": "openssl", "purpose": "CMAC context cleanup", "category": "crypto"},
    "_CMAC_Init": {"lib": "openssl", "purpose": "CMAC init", "category": "crypto"},
    "_CMAC_Update": {"lib": "openssl", "purpose": "CMAC update", "category": "crypto"},
    "_CMAC_Final": {"lib": "openssl", "purpose": "CMAC finalize", "category": "crypto"},
    # HKDF
    "_EVP_PKEY_CTX_set_hkdf_md": {"lib": "openssl", "purpose": "HKDF set hash", "category": "crypto"},
    "_EVP_PKEY_CTX_set1_hkdf_salt": {"lib": "openssl", "purpose": "HKDF set salt", "category": "crypto"},
    "_EVP_PKEY_CTX_set1_hkdf_key": {"lib": "openssl", "purpose": "HKDF set input key", "category": "crypto"},
    "_EVP_PKEY_CTX_add1_hkdf_info": {"lib": "openssl", "purpose": "HKDF add info", "category": "crypto"},
    # CMS
    "_CMS_sign": {"lib": "openssl", "purpose": "CMS signing", "category": "crypto"},
    "_CMS_verify": {"lib": "openssl", "purpose": "CMS verification", "category": "crypto"},
    "_CMS_encrypt": {"lib": "openssl", "purpose": "CMS encryption", "category": "crypto"},
    "_CMS_decrypt": {"lib": "openssl", "purpose": "CMS decryption", "category": "crypto"},

}



# ---------------------------------------------------------------------------
# Builtin Signature Database -- BoringSSL (Google fork extras)
# ---------------------------------------------------------------------------

_BORINGSSL_SIGNATURES: dict[str, dict[str, str]] = {
    "_CRYPTO_BUFFER_new": {"lib": "boringssl", "purpose": "ref-counted buffer creation", "category": "memory"},
    "_CRYPTO_BUFFER_free": {"lib": "boringssl", "purpose": "ref-counted buffer cleanup", "category": "memory"},
    "_CRYPTO_BUFFER_data": {"lib": "boringssl", "purpose": "buffer data pointer", "category": "memory"},
    "_CRYPTO_BUFFER_len": {"lib": "boringssl", "purpose": "buffer length", "category": "memory"},
    "_CBS_init": {"lib": "boringssl", "purpose": "CBS reader init from buffer", "category": "encoding"},
    "_CBS_len": {"lib": "boringssl", "purpose": "CBS remaining bytes", "category": "encoding"},
    "_CBS_data": {"lib": "boringssl", "purpose": "CBS data pointer", "category": "encoding"},
    "_CBS_get_u8": {"lib": "boringssl", "purpose": "CBS read uint8", "category": "encoding"},
    "_CBS_get_u16": {"lib": "boringssl", "purpose": "CBS read uint16 big-endian", "category": "encoding"},
    "_CBS_get_u24": {"lib": "boringssl", "purpose": "CBS read uint24 big-endian", "category": "encoding"},
    "_CBS_get_u32": {"lib": "boringssl", "purpose": "CBS read uint32 big-endian", "category": "encoding"},
    "_CBS_get_bytes": {"lib": "boringssl", "purpose": "CBS read N bytes", "category": "encoding"},
    "_CBS_get_asn1": {"lib": "boringssl", "purpose": "CBS read ASN.1 element", "category": "encoding"},
    "_CBS_skip": {"lib": "boringssl", "purpose": "CBS skip bytes", "category": "encoding"},
    "_CBB_init": {"lib": "boringssl", "purpose": "CBB builder init", "category": "encoding"},
    "_CBB_init_fixed": {"lib": "boringssl", "purpose": "CBB builder init fixed-size", "category": "encoding"},
    "_CBB_cleanup": {"lib": "boringssl", "purpose": "CBB builder cleanup", "category": "encoding"},
    "_CBB_finish": {"lib": "boringssl", "purpose": "CBB builder finalize", "category": "encoding"},
    "_CBB_flush": {"lib": "boringssl", "purpose": "CBB builder flush", "category": "encoding"},
    "_CBB_data": {"lib": "boringssl", "purpose": "CBB data pointer", "category": "encoding"},
    "_CBB_len": {"lib": "boringssl", "purpose": "CBB current length", "category": "encoding"},
    "_CBB_add_u8": {"lib": "boringssl", "purpose": "CBB write uint8", "category": "encoding"},
    "_CBB_add_u16": {"lib": "boringssl", "purpose": "CBB write uint16 big-endian", "category": "encoding"},
    "_CBB_add_u24": {"lib": "boringssl", "purpose": "CBB write uint24 big-endian", "category": "encoding"},
    "_CBB_add_bytes": {"lib": "boringssl", "purpose": "CBB write byte array", "category": "encoding"},
    "_CBB_add_asn1": {"lib": "boringssl", "purpose": "CBB add ASN.1 element", "category": "encoding"},
    "_OPENSSL_memdup": {"lib": "boringssl", "purpose": "memory dup with OPENSSL_malloc", "category": "memory"},
    "_SSL_CTX_set_grease_enabled": {"lib": "boringssl", "purpose": "TLS GREASE extension", "category": "network"},
    "_SSL_CTX_set_permute_extensions": {"lib": "boringssl", "purpose": "TLS randomize extensions", "category": "network"},
    "_SSL_set_quic_method": {"lib": "boringssl", "purpose": "QUIC TLS method", "category": "network"},
    "_SSL_set_quic_transport_params": {"lib": "boringssl", "purpose": "QUIC transport params", "category": "network"},
    "_SSL_process_quic_post_handshake": {"lib": "boringssl", "purpose": "QUIC post-handshake", "category": "network"},
    "_SSL_early_data_accepted": {"lib": "boringssl", "purpose": "TLS 0-RTT accepted check", "category": "network"},
    "_SSL_set_early_data_enabled": {"lib": "boringssl", "purpose": "TLS 0-RTT enable", "category": "network"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- libsodium / NaCl
# ---------------------------------------------------------------------------

_LIBSODIUM_SIGNATURES: dict[str, dict[str, str]] = {
    "_sodium_init": {"lib": "libsodium", "purpose": "library initialization", "category": "init"},
    "_crypto_secretbox": {"lib": "libsodium", "purpose": "secret-key authenticated encrypt", "category": "crypto"},
    "_crypto_secretbox_open": {"lib": "libsodium", "purpose": "secret-key authenticated decrypt", "category": "crypto"},
    "_crypto_secretbox_easy": {"lib": "libsodium", "purpose": "secret-key encrypt (easy API)", "category": "crypto"},
    "_crypto_secretbox_open_easy": {"lib": "libsodium", "purpose": "secret-key decrypt (easy API)", "category": "crypto"},
    "_crypto_secretbox_keygen": {"lib": "libsodium", "purpose": "secret-key keygen", "category": "crypto"},
    "_crypto_box": {"lib": "libsodium", "purpose": "public-key authenticated encrypt", "category": "crypto"},
    "_crypto_box_open": {"lib": "libsodium", "purpose": "public-key authenticated decrypt", "category": "crypto"},
    "_crypto_box_easy": {"lib": "libsodium", "purpose": "public-key encrypt (easy API)", "category": "crypto"},
    "_crypto_box_open_easy": {"lib": "libsodium", "purpose": "public-key decrypt (easy API)", "category": "crypto"},
    "_crypto_box_keypair": {"lib": "libsodium", "purpose": "public-key keypair generation", "category": "crypto"},
    "_crypto_box_seal": {"lib": "libsodium", "purpose": "anonymous public-key encrypt", "category": "crypto"},
    "_crypto_box_seal_open": {"lib": "libsodium", "purpose": "anonymous public-key decrypt", "category": "crypto"},
    "_crypto_sign": {"lib": "libsodium", "purpose": "Ed25519 sign (combined)", "category": "crypto"},
    "_crypto_sign_open": {"lib": "libsodium", "purpose": "Ed25519 verify+open", "category": "crypto"},
    "_crypto_sign_detached": {"lib": "libsodium", "purpose": "Ed25519 detached signature", "category": "crypto"},
    "_crypto_sign_verify_detached": {"lib": "libsodium", "purpose": "Ed25519 detached verify", "category": "crypto"},
    "_crypto_sign_keypair": {"lib": "libsodium", "purpose": "Ed25519 keypair generation", "category": "crypto"},
    "_crypto_sign_seed_keypair": {"lib": "libsodium", "purpose": "Ed25519 deterministic keypair", "category": "crypto"},
    "_crypto_hash": {"lib": "libsodium", "purpose": "SHA-512 hash (default)", "category": "crypto"},
    "_crypto_hash_sha256": {"lib": "libsodium", "purpose": "SHA-256 hash", "category": "crypto"},
    "_crypto_hash_sha512": {"lib": "libsodium", "purpose": "SHA-512 hash", "category": "crypto"},
    "_crypto_generichash": {"lib": "libsodium", "purpose": "BLAKE2b hash (one-shot)", "category": "crypto"},
    "_crypto_generichash_init": {"lib": "libsodium", "purpose": "BLAKE2b multi-part init", "category": "crypto"},
    "_crypto_generichash_update": {"lib": "libsodium", "purpose": "BLAKE2b multi-part update", "category": "crypto"},
    "_crypto_generichash_final": {"lib": "libsodium", "purpose": "BLAKE2b multi-part finalize", "category": "crypto"},
    "_crypto_shorthash": {"lib": "libsodium", "purpose": "SipHash-2-4 short hash", "category": "crypto"},
    "_crypto_aead_chacha20poly1305_encrypt": {"lib": "libsodium", "purpose": "ChaCha20-Poly1305 encrypt", "category": "crypto"},
    "_crypto_aead_chacha20poly1305_decrypt": {"lib": "libsodium", "purpose": "ChaCha20-Poly1305 decrypt", "category": "crypto"},
    "_crypto_aead_chacha20poly1305_ietf_encrypt": {"lib": "libsodium", "purpose": "ChaCha20-Poly1305 IETF encrypt", "category": "crypto"},
    "_crypto_aead_chacha20poly1305_ietf_decrypt": {"lib": "libsodium", "purpose": "ChaCha20-Poly1305 IETF decrypt", "category": "crypto"},
    "_crypto_aead_xchacha20poly1305_ietf_encrypt": {"lib": "libsodium", "purpose": "XChaCha20-Poly1305 encrypt", "category": "crypto"},
    "_crypto_aead_xchacha20poly1305_ietf_decrypt": {"lib": "libsodium", "purpose": "XChaCha20-Poly1305 decrypt", "category": "crypto"},
    "_crypto_pwhash": {"lib": "libsodium", "purpose": "Argon2 password hash (key derive)", "category": "crypto"},
    "_crypto_pwhash_str": {"lib": "libsodium", "purpose": "Argon2 password hash (storage)", "category": "crypto"},
    "_crypto_pwhash_str_verify": {"lib": "libsodium", "purpose": "Argon2 password verification", "category": "crypto"},
    "_crypto_kx_keypair": {"lib": "libsodium", "purpose": "key exchange keypair", "category": "crypto"},
    "_crypto_kx_client_session_keys": {"lib": "libsodium", "purpose": "derive client session keys", "category": "crypto"},
    "_crypto_kx_server_session_keys": {"lib": "libsodium", "purpose": "derive server session keys", "category": "crypto"},
    "_crypto_scalarmult": {"lib": "libsodium", "purpose": "X25519 scalar multiplication", "category": "crypto"},
    "_crypto_scalarmult_base": {"lib": "libsodium", "purpose": "X25519 base point multiplication", "category": "crypto"},
    "_crypto_kdf_keygen": {"lib": "libsodium", "purpose": "KDF master key generation", "category": "crypto"},
    "_crypto_kdf_derive_from_key": {"lib": "libsodium", "purpose": "KDF subkey derivation", "category": "crypto"},
    "_sodium_memzero": {"lib": "libsodium", "purpose": "secure memory wipe", "category": "memory"},
    "_sodium_memcmp": {"lib": "libsodium", "purpose": "constant-time memory compare", "category": "memory"},
    "_sodium_malloc": {"lib": "libsodium", "purpose": "guarded memory allocation", "category": "memory"},
    "_sodium_free": {"lib": "libsodium", "purpose": "guarded memory free", "category": "memory"},
    "_sodium_mlock": {"lib": "libsodium", "purpose": "lock memory (prevent swap)", "category": "memory"},
    "_sodium_increment": {"lib": "libsodium", "purpose": "increment nonce (little-endian)", "category": "memory"},
    "_randombytes_buf": {"lib": "libsodium", "purpose": "fill buffer with random bytes", "category": "crypto"},
    "_randombytes_buf_deterministic": {"lib": "libsodium", "purpose": "deterministic random fill", "category": "crypto"},
    "_randombytes_uniform": {"lib": "libsodium", "purpose": "uniform random uint32 in range", "category": "crypto"},
    "_sodium_bin2hex": {"lib": "libsodium", "purpose": "binary to hex string", "category": "encoding"},
    "_sodium_hex2bin": {"lib": "libsodium", "purpose": "hex string to binary", "category": "encoding"},
    "_sodium_bin2base64": {"lib": "libsodium", "purpose": "binary to base64", "category": "encoding"},
    "_sodium_base642bin": {"lib": "libsodium", "purpose": "base64 to binary", "category": "encoding"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- mbedTLS (ARM)
# ---------------------------------------------------------------------------

_MBEDTLS_SIGNATURES: dict[str, dict[str, str]] = {
    "_mbedtls_ssl_init": {"lib": "mbedtls", "purpose": "SSL context init", "category": "network"},
    "_mbedtls_ssl_setup": {"lib": "mbedtls", "purpose": "SSL context setup from config", "category": "network"},
    "_mbedtls_ssl_handshake": {"lib": "mbedtls", "purpose": "TLS handshake", "category": "network"},
    "_mbedtls_ssl_read": {"lib": "mbedtls", "purpose": "TLS read decrypted data", "category": "network"},
    "_mbedtls_ssl_write": {"lib": "mbedtls", "purpose": "TLS write encrypted data", "category": "network"},
    "_mbedtls_ssl_close_notify": {"lib": "mbedtls", "purpose": "TLS close notify", "category": "network"},
    "_mbedtls_ssl_free": {"lib": "mbedtls", "purpose": "SSL context cleanup", "category": "network"},
    "_mbedtls_ssl_config_init": {"lib": "mbedtls", "purpose": "SSL config struct init", "category": "network"},
    "_mbedtls_ssl_config_defaults": {"lib": "mbedtls", "purpose": "SSL config load defaults", "category": "network"},
    "_mbedtls_ssl_conf_authmode": {"lib": "mbedtls", "purpose": "SSL config auth mode", "category": "network"},
    "_mbedtls_ssl_conf_ca_chain": {"lib": "mbedtls", "purpose": "SSL config CA certificate chain", "category": "network"},
    "_mbedtls_ssl_conf_rng": {"lib": "mbedtls", "purpose": "SSL config RNG callback", "category": "network"},
    "_mbedtls_x509_crt_init": {"lib": "mbedtls", "purpose": "X509 cert chain init", "category": "crypto"},
    "_mbedtls_x509_crt_parse": {"lib": "mbedtls", "purpose": "X509 cert parse (PEM/DER)", "category": "crypto"},
    "_mbedtls_x509_crt_free": {"lib": "mbedtls", "purpose": "X509 cert chain cleanup", "category": "crypto"},
    "_mbedtls_pk_init": {"lib": "mbedtls", "purpose": "PK context init", "category": "crypto"},
    "_mbedtls_pk_parse_key": {"lib": "mbedtls", "purpose": "parse private key (PEM/DER)", "category": "crypto"},
    "_mbedtls_pk_free": {"lib": "mbedtls", "purpose": "PK context cleanup", "category": "crypto"},
    "_mbedtls_entropy_init": {"lib": "mbedtls", "purpose": "entropy context init", "category": "crypto"},
    "_mbedtls_entropy_free": {"lib": "mbedtls", "purpose": "entropy context cleanup", "category": "crypto"},
    "_mbedtls_entropy_func": {"lib": "mbedtls", "purpose": "entropy gathering callback", "category": "crypto"},
    "_mbedtls_ctr_drbg_init": {"lib": "mbedtls", "purpose": "CTR-DRBG context init", "category": "crypto"},
    "_mbedtls_ctr_drbg_seed": {"lib": "mbedtls", "purpose": "CTR-DRBG seed from entropy", "category": "crypto"},
    "_mbedtls_ctr_drbg_random": {"lib": "mbedtls", "purpose": "CTR-DRBG generate random", "category": "crypto"},
    "_mbedtls_ctr_drbg_free": {"lib": "mbedtls", "purpose": "CTR-DRBG context cleanup", "category": "crypto"},
    "_mbedtls_net_init": {"lib": "mbedtls", "purpose": "net context init", "category": "network"},
    "_mbedtls_net_connect": {"lib": "mbedtls", "purpose": "TCP connect", "category": "network"},
    "_mbedtls_net_bind": {"lib": "mbedtls", "purpose": "TCP bind", "category": "network"},
    "_mbedtls_net_accept": {"lib": "mbedtls", "purpose": "TCP accept", "category": "network"},
    "_mbedtls_net_free": {"lib": "mbedtls", "purpose": "net context cleanup", "category": "network"},
    "_mbedtls_aes_init": {"lib": "mbedtls", "purpose": "AES context init", "category": "crypto"},
    "_mbedtls_aes_setkey_enc": {"lib": "mbedtls", "purpose": "AES set encryption key", "category": "crypto"},
    "_mbedtls_aes_crypt_cbc": {"lib": "mbedtls", "purpose": "AES-CBC encrypt/decrypt", "category": "crypto"},
    "_mbedtls_aes_free": {"lib": "mbedtls", "purpose": "AES context cleanup", "category": "crypto"},
    "_mbedtls_sha256": {"lib": "mbedtls", "purpose": "SHA-256 one-shot", "category": "crypto"},
    "_mbedtls_md5": {"lib": "mbedtls", "purpose": "MD5 one-shot", "category": "crypto"},
    "_mbedtls_md_init": {"lib": "mbedtls", "purpose": "MD context init", "category": "crypto"},
    "_mbedtls_md_setup": {"lib": "mbedtls", "purpose": "MD context setup", "category": "crypto"},
    "_mbedtls_md_starts": {"lib": "mbedtls", "purpose": "MD hash start", "category": "crypto"},
    "_mbedtls_md_update": {"lib": "mbedtls", "purpose": "MD hash update", "category": "crypto"},
    "_mbedtls_md_finish": {"lib": "mbedtls", "purpose": "MD hash finish", "category": "crypto"},
    "_mbedtls_md_free": {"lib": "mbedtls", "purpose": "MD context cleanup", "category": "crypto"},
    "_mbedtls_pk_sign": {"lib": "mbedtls", "purpose": "PK digital signature", "category": "crypto"},
    "_mbedtls_pk_verify": {"lib": "mbedtls", "purpose": "PK signature verification", "category": "crypto"},
    "_mbedtls_strerror": {"lib": "mbedtls", "purpose": "error code to string", "category": "error"},
    "_mbedtls_debug_set_threshold": {"lib": "mbedtls", "purpose": "set debug verbosity level", "category": "init"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Windows CryptoAPI / CNG
# ---------------------------------------------------------------------------

_WINCRYPTO_SIGNATURES: dict[str, dict[str, str]] = {
    "_CryptAcquireContextA": {"lib": "wincrypt", "purpose": "acquire crypto provider handle", "category": "crypto"},
    "_CryptAcquireContextW": {"lib": "wincrypt", "purpose": "acquire crypto provider handle (wide)", "category": "crypto"},
    "_CryptAcquireContext": {"lib": "wincrypt", "purpose": "acquire crypto provider handle", "category": "crypto"},
    "_CryptReleaseContext": {"lib": "wincrypt", "purpose": "release crypto provider handle", "category": "crypto"},
    "_CryptGenRandom": {"lib": "wincrypt", "purpose": "cryptographic RNG", "category": "crypto"},
    "_CryptCreateHash": {"lib": "wincrypt", "purpose": "create hash object", "category": "crypto"},
    "_CryptHashData": {"lib": "wincrypt", "purpose": "hash data buffer", "category": "crypto"},
    "_CryptGetHashParam": {"lib": "wincrypt", "purpose": "get hash value/params", "category": "crypto"},
    "_CryptDestroyHash": {"lib": "wincrypt", "purpose": "destroy hash object", "category": "crypto"},
    "_CryptEncrypt": {"lib": "wincrypt", "purpose": "encrypt data", "category": "crypto"},
    "_CryptDecrypt": {"lib": "wincrypt", "purpose": "decrypt data", "category": "crypto"},
    "_CryptImportKey": {"lib": "wincrypt", "purpose": "import crypto key", "category": "crypto"},
    "_CryptExportKey": {"lib": "wincrypt", "purpose": "export crypto key", "category": "crypto"},
    "_CryptDestroyKey": {"lib": "wincrypt", "purpose": "destroy crypto key", "category": "crypto"},
    "_CryptSignHash": {"lib": "wincrypt", "purpose": "sign hash value", "category": "crypto"},
    "_CryptVerifySignature": {"lib": "wincrypt", "purpose": "verify digital signature", "category": "crypto"},
    "_BCryptOpenAlgorithmProvider": {"lib": "wincng", "purpose": "open CNG algorithm provider", "category": "crypto"},
    "_BCryptCloseAlgorithmProvider": {"lib": "wincng", "purpose": "close CNG algorithm provider", "category": "crypto"},
    "_BCryptGenerateSymmetricKey": {"lib": "wincng", "purpose": "generate CNG symmetric key", "category": "crypto"},
    "_BCryptEncrypt": {"lib": "wincng", "purpose": "CNG encrypt data", "category": "crypto"},
    "_BCryptDecrypt": {"lib": "wincng", "purpose": "CNG decrypt data", "category": "crypto"},
    "_BCryptCreateHash": {"lib": "wincng", "purpose": "CNG create hash object", "category": "crypto"},
    "_BCryptHashData": {"lib": "wincng", "purpose": "CNG hash data", "category": "crypto"},
    "_BCryptFinishHash": {"lib": "wincng", "purpose": "CNG finish hash", "category": "crypto"},
    "_BCryptDestroyHash": {"lib": "wincng", "purpose": "CNG destroy hash", "category": "crypto"},
    "_BCryptGenRandom": {"lib": "wincng", "purpose": "CNG cryptographic RNG", "category": "crypto"},
    "_BCryptSignHash": {"lib": "wincng", "purpose": "CNG sign hash", "category": "crypto"},
    "_BCryptVerifySignature": {"lib": "wincng", "purpose": "CNG verify signature", "category": "crypto"},
    "_BCryptDestroyKey": {"lib": "wincng", "purpose": "destroy CNG key", "category": "crypto"},
    "_BCryptDeriveKeyPBKDF2": {"lib": "wincng", "purpose": "CNG PBKDF2 key derivation", "category": "crypto"},
}


# ---------------------------------------------------------------------------
# sig_db Faz 2 — crypto kategori override (pilot migration)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.crypto` modulune tasindi. Asagidaki
# override, eski dict'leri silmeden yeni kaynak-of-truth'a baglar. Import
# basarisiz olursa (ornek: sigdb_builtin paketi yok / bozuk) eski inline
# dict'ler kullanilmaya devam eder — geriye uyumlu, rollback kolay.
try:
    from karadul.analyzers.sigdb_builtin.crypto import (
        SIGNATURES as _BUILTIN_CRYPTO_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_CRYPTO_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_CRYPTO_SIGNATURES is not None:
    _OPENSSL_SIGNATURES = _BUILTIN_CRYPTO_SIGNATURES.get(
        "openssl_signatures", _OPENSSL_SIGNATURES
    )
    _BORINGSSL_SIGNATURES = _BUILTIN_CRYPTO_SIGNATURES.get(
        "boringssl_signatures", _BORINGSSL_SIGNATURES
    )
    _LIBSODIUM_SIGNATURES = _BUILTIN_CRYPTO_SIGNATURES.get(
        "libsodium_signatures", _LIBSODIUM_SIGNATURES
    )
    _MBEDTLS_SIGNATURES = _BUILTIN_CRYPTO_SIGNATURES.get(
        "mbedtls_signatures", _MBEDTLS_SIGNATURES
    )
    _WINCRYPTO_SIGNATURES = _BUILTIN_CRYPTO_SIGNATURES.get(
        "wincrypto_signatures", _WINCRYPTO_SIGNATURES
    )


# ---------------------------------------------------------------------------
# Builtin Signature Database -- zlib
# ---------------------------------------------------------------------------

_ZLIB_SIGNATURES: dict[str, dict[str, str]] = {
    "_deflateInit_": {"lib": "zlib", "purpose": "deflate init (compression)", "category": "compression"},
    "_deflateInit2_": {"lib": "zlib", "purpose": "deflate init with params", "category": "compression"},
    "_deflate": {"lib": "zlib", "purpose": "deflate compress", "category": "compression"},
    "_deflateEnd": {"lib": "zlib", "purpose": "deflate cleanup", "category": "compression"},
    "_deflateReset": {"lib": "zlib", "purpose": "deflate state reset", "category": "compression"},
    "_deflateBound": {"lib": "zlib", "purpose": "deflate output bound", "category": "compression"},
    "_deflateSetDictionary": {"lib": "zlib", "purpose": "deflate set dictionary", "category": "compression"},
    "_inflateInit_": {"lib": "zlib", "purpose": "inflate init (decompression)", "category": "compression"},
    "_inflateInit2_": {"lib": "zlib", "purpose": "inflate init with params", "category": "compression"},
    "_inflate": {"lib": "zlib", "purpose": "inflate decompress", "category": "compression"},
    "_inflateEnd": {"lib": "zlib", "purpose": "inflate cleanup", "category": "compression"},
    "_inflateReset": {"lib": "zlib", "purpose": "inflate state reset", "category": "compression"},
    "_inflateSync": {"lib": "zlib", "purpose": "inflate sync to next block", "category": "compression"},
    "_inflateSetDictionary": {"lib": "zlib", "purpose": "inflate set dictionary", "category": "compression"},
    "_compress": {"lib": "zlib", "purpose": "one-shot compress", "category": "compression"},
    "_compress2": {"lib": "zlib", "purpose": "one-shot compress with level", "category": "compression"},
    "_compressBound": {"lib": "zlib", "purpose": "compress output bound", "category": "compression"},
    "_uncompress": {"lib": "zlib", "purpose": "one-shot decompress", "category": "compression"},
    "_uncompress2": {"lib": "zlib", "purpose": "one-shot decompress (with src len)", "category": "compression"},
    "_crc32": {"lib": "zlib", "purpose": "CRC-32 checksum", "category": "checksum"},
    "_crc32_combine": {"lib": "zlib", "purpose": "CRC-32 combine", "category": "checksum"},
    "_adler32": {"lib": "zlib", "purpose": "Adler-32 checksum", "category": "checksum"},
    "_adler32_combine": {"lib": "zlib", "purpose": "Adler-32 combine", "category": "checksum"},
    "_gzopen": {"lib": "zlib", "purpose": "gzip file open", "category": "compression"},
    "_gzclose": {"lib": "zlib", "purpose": "gzip file close", "category": "compression"},
    "_gzread": {"lib": "zlib", "purpose": "gzip file read", "category": "compression"},
    "_gzwrite": {"lib": "zlib", "purpose": "gzip file write", "category": "compression"},
    "_gzgets": {"lib": "zlib", "purpose": "gzip read line", "category": "compression"},
    "_gzputs": {"lib": "zlib", "purpose": "gzip write string", "category": "compression"},
    "_gzeof": {"lib": "zlib", "purpose": "gzip end-of-file check", "category": "compression"},
    "_zlibVersion": {"lib": "zlib", "purpose": "zlib version string", "category": "info"},
    "_zlibCompileFlags": {"lib": "zlib", "purpose": "zlib compile-time flags", "category": "info"},
    "_gztell": {"lib": "zlib", "purpose": "gzip file position", "category": "compression"},
    "_gzseek": {"lib": "zlib", "purpose": "gzip file seek", "category": "compression"},
    "_gzflush": {"lib": "zlib", "purpose": "gzip flush output", "category": "compression"},
    "_gzprintf": {"lib": "zlib", "purpose": "gzip formatted write", "category": "compression"},
    "_gzdopen": {"lib": "zlib", "purpose": "gzip open from fd", "category": "compression"},
    "_gzbuffer": {"lib": "zlib", "purpose": "gzip set buffer size", "category": "compression"},
    "_gzoffset": {"lib": "zlib", "purpose": "gzip raw file offset", "category": "compression"},
    "_gzdirect": {"lib": "zlib", "purpose": "gzip direct mode check", "category": "compression"},
    "_gzerror": {"lib": "zlib", "purpose": "gzip error string", "category": "compression"},
    "_gzclearerr": {"lib": "zlib", "purpose": "gzip clear error", "category": "compression"},
    "_crc32_z": {"lib": "zlib", "purpose": "CRC-32 checksum (size_t len)", "category": "checksum"},
    "_adler32_z": {"lib": "zlib", "purpose": "Adler-32 checksum (size_t len)", "category": "checksum"},
    "_inflateCopy": {"lib": "zlib", "purpose": "inflate state copy", "category": "compression"},
    "_inflateGetHeader": {"lib": "zlib", "purpose": "inflate get gzip header", "category": "compression"},
    "_deflateCopy": {"lib": "zlib", "purpose": "deflate state copy", "category": "compression"},
    "_deflateSetHeader": {"lib": "zlib", "purpose": "deflate set gzip header", "category": "compression"},
    "_deflateTune": {"lib": "zlib", "purpose": "deflate tuning parameters", "category": "compression"},
    "_deflatePending": {"lib": "zlib", "purpose": "deflate pending output bytes", "category": "compression"},
    "_deflatePrime": {"lib": "zlib", "purpose": "deflate insert bits", "category": "compression"},
    "_inflateBackInit_": {"lib": "zlib", "purpose": "inflate back init (raw)", "category": "compression"},
    "_inflateBack": {"lib": "zlib", "purpose": "inflate back (callback)", "category": "compression"},
    "_inflateBackEnd": {"lib": "zlib", "purpose": "inflate back cleanup", "category": "compression"},
    "_inflatePrime": {"lib": "zlib", "purpose": "inflate insert bits", "category": "compression"},
    "_inflateMark": {"lib": "zlib", "purpose": "inflate mark position", "category": "compression"},
    "_inflateReset2": {"lib": "zlib", "purpose": "inflate reset with window bits", "category": "compression"},
    "_inflateGetDictionary": {"lib": "zlib", "purpose": "inflate get dictionary", "category": "compression"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- bzip2
# ---------------------------------------------------------------------------

_BZIP2_SIGNATURES: dict[str, dict[str, str]] = {
    "_BZ2_bzCompressInit": {"lib": "bzip2", "purpose": "bzip2 compressor init", "category": "compression"},
    "_BZ2_bzCompress": {"lib": "bzip2", "purpose": "bzip2 compress step", "category": "compression"},
    "_BZ2_bzCompressEnd": {"lib": "bzip2", "purpose": "bzip2 compressor cleanup", "category": "compression"},
    "_BZ2_bzDecompressInit": {"lib": "bzip2", "purpose": "bzip2 decompressor init", "category": "compression"},
    "_BZ2_bzDecompress": {"lib": "bzip2", "purpose": "bzip2 decompress step", "category": "compression"},
    "_BZ2_bzDecompressEnd": {"lib": "bzip2", "purpose": "bzip2 decompressor cleanup", "category": "compression"},
    "_BZ2_bzReadOpen": {"lib": "bzip2", "purpose": "bzip2 file read open", "category": "compression"},
    "_BZ2_bzRead": {"lib": "bzip2", "purpose": "bzip2 file read", "category": "compression"},
    "_BZ2_bzReadClose": {"lib": "bzip2", "purpose": "bzip2 file read close", "category": "compression"},
    "_BZ2_bzReadGetUnused": {"lib": "bzip2", "purpose": "bzip2 get unused bytes after read", "category": "compression"},
    "_BZ2_bzWriteOpen": {"lib": "bzip2", "purpose": "bzip2 file write open", "category": "compression"},
    "_BZ2_bzWrite": {"lib": "bzip2", "purpose": "bzip2 file write", "category": "compression"},
    "_BZ2_bzWriteClose": {"lib": "bzip2", "purpose": "bzip2 file write close", "category": "compression"},
    "_BZ2_bzWriteClose64": {"lib": "bzip2", "purpose": "bzip2 file write close (64-bit counts)", "category": "compression"},
    "_BZ2_bzBuffToBuffCompress": {"lib": "bzip2", "purpose": "bzip2 one-shot compress", "category": "compression"},
    "_BZ2_bzBuffToBuffDecompress": {"lib": "bzip2", "purpose": "bzip2 one-shot decompress", "category": "compression"},
    "_BZ2_bzlibVersion": {"lib": "bzip2", "purpose": "bzip2 library version", "category": "info"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- lz4
# ---------------------------------------------------------------------------

_LZ4_SIGNATURES: dict[str, dict[str, str]] = {
    "_LZ4_compress_default": {"lib": "lz4", "purpose": "LZ4 compress (default)", "category": "compression"},
    "_LZ4_compress_fast": {"lib": "lz4", "purpose": "LZ4 compress (fast)", "category": "compression"},
    "_LZ4_compress_fast_extState": {"lib": "lz4", "purpose": "LZ4 compress fast with external state", "category": "compression"},
    "_LZ4_compress_HC": {"lib": "lz4", "purpose": "LZ4 high-compression compress", "category": "compression"},
    "_LZ4_compress_HC_extStateHC": {"lib": "lz4", "purpose": "LZ4 HC compress with external state", "category": "compression"},
    "_LZ4_compress_destSize": {"lib": "lz4", "purpose": "LZ4 compress to target size", "category": "compression"},
    "_LZ4_decompress_safe": {"lib": "lz4", "purpose": "LZ4 decompress (safe)", "category": "compression"},
    "_LZ4_decompress_fast": {"lib": "lz4", "purpose": "LZ4 decompress (legacy, unsafe)", "category": "compression"},
    "_LZ4_decompress_safe_partial": {"lib": "lz4", "purpose": "LZ4 partial decompress", "category": "compression"},
    "_LZ4_compressBound": {"lib": "lz4", "purpose": "LZ4 max compressed size", "category": "compression"},
    "_LZ4_versionNumber": {"lib": "lz4", "purpose": "LZ4 version number", "category": "info"},
    "_LZ4_versionString": {"lib": "lz4", "purpose": "LZ4 version string", "category": "info"},
    "_LZ4F_createCompressionContext": {"lib": "lz4", "purpose": "LZ4 frame compression context create", "category": "compression"},
    "_LZ4F_compressBegin": {"lib": "lz4", "purpose": "LZ4 frame compress begin", "category": "compression"},
    "_LZ4F_compressUpdate": {"lib": "lz4", "purpose": "LZ4 frame compress update", "category": "compression"},
    "_LZ4F_compressEnd": {"lib": "lz4", "purpose": "LZ4 frame compress end", "category": "compression"},
    "_LZ4F_flush": {"lib": "lz4", "purpose": "LZ4 frame flush", "category": "compression"},
    "_LZ4F_freeCompressionContext": {"lib": "lz4", "purpose": "LZ4 frame compression context free", "category": "compression"},
    "_LZ4F_createDecompressionContext": {"lib": "lz4", "purpose": "LZ4 frame decompression context create", "category": "compression"},
    "_LZ4F_decompress": {"lib": "lz4", "purpose": "LZ4 frame decompress", "category": "compression"},
    "_LZ4F_freeDecompressionContext": {"lib": "lz4", "purpose": "LZ4 frame decompression context free", "category": "compression"},
    "_LZ4F_compressFrameBound": {"lib": "lz4", "purpose": "LZ4 frame max compressed size", "category": "compression"},
    "_LZ4F_isError": {"lib": "lz4", "purpose": "LZ4 frame error check", "category": "info"},
    "_LZ4F_getErrorName": {"lib": "lz4", "purpose": "LZ4 frame error name", "category": "info"},
    "_LZ4F_getVersion": {"lib": "lz4", "purpose": "LZ4 frame API version", "category": "info"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- zstd (Zstandard)
# ---------------------------------------------------------------------------

_ZSTD_SIGNATURES: dict[str, dict[str, str]] = {
    "_ZSTD_compress": {"lib": "zstd", "purpose": "zstd one-shot compress", "category": "compression"},
    "_ZSTD_decompress": {"lib": "zstd", "purpose": "zstd one-shot decompress", "category": "compression"},
    "_ZSTD_compressBound": {"lib": "zstd", "purpose": "zstd max compressed size", "category": "compression"},
    "_ZSTD_getFrameContentSize": {"lib": "zstd", "purpose": "zstd get decompressed size", "category": "compression"},
    "_ZSTD_findFrameCompressedSize": {"lib": "zstd", "purpose": "zstd find compressed frame size", "category": "compression"},
    "_ZSTD_createCCtx": {"lib": "zstd", "purpose": "zstd compression context create", "category": "compression"},
    "_ZSTD_freeCCtx": {"lib": "zstd", "purpose": "zstd compression context free", "category": "compression"},
    "_ZSTD_compressCCtx": {"lib": "zstd", "purpose": "zstd compress with context", "category": "compression"},
    "_ZSTD_compress2": {"lib": "zstd", "purpose": "zstd compress with parameters", "category": "compression"},
    "_ZSTD_CCtx_setParameter": {"lib": "zstd", "purpose": "zstd set compression parameter", "category": "compression"},
    "_ZSTD_CCtx_setPledgedSrcSize": {"lib": "zstd", "purpose": "zstd set pledged source size", "category": "compression"},
    "_ZSTD_createDCtx": {"lib": "zstd", "purpose": "zstd decompression context create", "category": "compression"},
    "_ZSTD_freeDCtx": {"lib": "zstd", "purpose": "zstd decompression context free", "category": "compression"},
    "_ZSTD_decompressDCtx": {"lib": "zstd", "purpose": "zstd decompress with context", "category": "compression"},
    "_ZSTD_DCtx_setParameter": {"lib": "zstd", "purpose": "zstd set decompression parameter", "category": "compression"},
    "_ZSTD_createCStream": {"lib": "zstd", "purpose": "zstd compression stream create", "category": "compression"},
    "_ZSTD_freeCStream": {"lib": "zstd", "purpose": "zstd compression stream free", "category": "compression"},
    "_ZSTD_initCStream": {"lib": "zstd", "purpose": "zstd init compression stream", "category": "compression"},
    "_ZSTD_compressStream": {"lib": "zstd", "purpose": "zstd streaming compress", "category": "compression"},
    "_ZSTD_compressStream2": {"lib": "zstd", "purpose": "zstd streaming compress (v2)", "category": "compression"},
    "_ZSTD_flushStream": {"lib": "zstd", "purpose": "zstd flush compression stream", "category": "compression"},
    "_ZSTD_endStream": {"lib": "zstd", "purpose": "zstd end compression stream", "category": "compression"},
    "_ZSTD_createDStream": {"lib": "zstd", "purpose": "zstd decompression stream create", "category": "compression"},
    "_ZSTD_freeDStream": {"lib": "zstd", "purpose": "zstd decompression stream free", "category": "compression"},
    "_ZSTD_initDStream": {"lib": "zstd", "purpose": "zstd init decompression stream", "category": "compression"},
    "_ZSTD_decompressStream": {"lib": "zstd", "purpose": "zstd streaming decompress", "category": "compression"},
    "_ZSTD_compress_usingDict": {"lib": "zstd", "purpose": "zstd compress with dictionary", "category": "compression"},
    "_ZSTD_decompress_usingDict": {"lib": "zstd", "purpose": "zstd decompress with dictionary", "category": "compression"},
    "_ZSTD_createCDict": {"lib": "zstd", "purpose": "zstd compiled compression dict", "category": "compression"},
    "_ZSTD_freeCDict": {"lib": "zstd", "purpose": "zstd free compression dict", "category": "compression"},
    "_ZSTD_compress_usingCDict": {"lib": "zstd", "purpose": "zstd compress with compiled dict", "category": "compression"},
    "_ZSTD_createDDict": {"lib": "zstd", "purpose": "zstd compiled decompression dict", "category": "compression"},
    "_ZSTD_freeDDict": {"lib": "zstd", "purpose": "zstd free decompression dict", "category": "compression"},
    "_ZSTD_decompress_usingDDict": {"lib": "zstd", "purpose": "zstd decompress with compiled dict", "category": "compression"},
    "_ZSTD_versionNumber": {"lib": "zstd", "purpose": "zstd version number", "category": "info"},
    "_ZSTD_versionString": {"lib": "zstd", "purpose": "zstd version string", "category": "info"},
    "_ZSTD_isError": {"lib": "zstd", "purpose": "zstd error code check", "category": "info"},
    "_ZSTD_getErrorName": {"lib": "zstd", "purpose": "zstd error name string", "category": "info"},
    "_ZSTD_getErrorCode": {"lib": "zstd", "purpose": "zstd error code from result", "category": "info"},
    "_ZSTD_maxCLevel": {"lib": "zstd", "purpose": "zstd max compression level", "category": "info"},
    "_ZSTD_minCLevel": {"lib": "zstd", "purpose": "zstd min compression level", "category": "info"},
    "_ZSTD_defaultCLevel": {"lib": "zstd", "purpose": "zstd default compression level", "category": "info"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- libcurl
# ---------------------------------------------------------------------------

_LIBCURL_SIGNATURES: dict[str, dict[str, str]] = {
    "_curl_easy_init": {"lib": "libcurl", "purpose": "easy handle creation", "category": "network"},
    "_curl_easy_cleanup": {"lib": "libcurl", "purpose": "easy handle cleanup", "category": "network"},
    "_curl_easy_setopt": {"lib": "libcurl", "purpose": "easy option set", "category": "network"},
    "_curl_easy_perform": {"lib": "libcurl", "purpose": "execute HTTP request", "category": "network"},
    "_curl_easy_getinfo": {"lib": "libcurl", "purpose": "get transfer info", "category": "network"},
    "_curl_easy_reset": {"lib": "libcurl", "purpose": "easy handle reset", "category": "network"},
    "_curl_easy_duphandle": {"lib": "libcurl", "purpose": "duplicate easy handle", "category": "network"},
    "_curl_easy_strerror": {"lib": "libcurl", "purpose": "error string lookup", "category": "network"},
    "_curl_multi_init": {"lib": "libcurl", "purpose": "multi handle creation", "category": "network"},
    "_curl_multi_cleanup": {"lib": "libcurl", "purpose": "multi handle cleanup", "category": "network"},
    "_curl_multi_add_handle": {"lib": "libcurl", "purpose": "add easy to multi", "category": "network"},
    "_curl_multi_remove_handle": {"lib": "libcurl", "purpose": "remove easy from multi", "category": "network"},
    "_curl_multi_perform": {"lib": "libcurl", "purpose": "multi perform transfers", "category": "network"},
    "_curl_multi_wait": {"lib": "libcurl", "purpose": "multi wait for activity", "category": "network"},
    "_curl_multi_poll": {"lib": "libcurl", "purpose": "multi poll for activity", "category": "network"},
    "_curl_multi_info_read": {"lib": "libcurl", "purpose": "multi read status info", "category": "network"},
    "_curl_multi_setopt": {"lib": "libcurl", "purpose": "multi option set", "category": "network"},
    "_curl_multi_strerror": {"lib": "libcurl", "purpose": "multi error string", "category": "network"},
    "_curl_global_init": {"lib": "libcurl", "purpose": "global init", "category": "network"},
    "_curl_global_cleanup": {"lib": "libcurl", "purpose": "global cleanup", "category": "network"},
    "_curl_slist_append": {"lib": "libcurl", "purpose": "string list append (headers)", "category": "network"},
    "_curl_slist_free_all": {"lib": "libcurl", "purpose": "string list cleanup", "category": "network"},
    "_curl_url": {"lib": "libcurl", "purpose": "URL handle creation", "category": "network"},
    "_curl_url_cleanup": {"lib": "libcurl", "purpose": "URL handle cleanup", "category": "network"},
    "_curl_url_set": {"lib": "libcurl", "purpose": "URL component set", "category": "network"},
    "_curl_url_get": {"lib": "libcurl", "purpose": "URL component get", "category": "network"},
    "_curl_mime_init": {"lib": "libcurl", "purpose": "MIME init (multipart)", "category": "network"},
    "_curl_mime_free": {"lib": "libcurl", "purpose": "MIME cleanup", "category": "network"},
    "_curl_mime_addpart": {"lib": "libcurl", "purpose": "MIME add part", "category": "network"},
    "_curl_mime_data": {"lib": "libcurl", "purpose": "MIME set data", "category": "network"},
    "_curl_mime_name": {"lib": "libcurl", "purpose": "MIME set name", "category": "network"},
    "_curl_mime_filename": {"lib": "libcurl", "purpose": "MIME set filename", "category": "network"},
    "_curl_mime_type": {"lib": "libcurl", "purpose": "MIME set content type", "category": "network"},
    "_curl_mime_filedata": {"lib": "libcurl", "purpose": "MIME set file data", "category": "network"},
    "_curl_share_init": {"lib": "libcurl", "purpose": "share handle creation", "category": "network"},
    "_curl_share_cleanup": {"lib": "libcurl", "purpose": "share handle cleanup", "category": "network"},
    "_curl_share_setopt": {"lib": "libcurl", "purpose": "share option set", "category": "network"},
    "_curl_version": {"lib": "libcurl", "purpose": "version string", "category": "network"},
    "_curl_version_info": {"lib": "libcurl", "purpose": "version info struct", "category": "network"},
    "_curl_free": {"lib": "libcurl", "purpose": "curl memory free", "category": "network"},
    "_curl_escape": {"lib": "libcurl", "purpose": "URL-encode string", "category": "network"},
    "_curl_unescape": {"lib": "libcurl", "purpose": "URL-decode string", "category": "network"},
    "_curl_easy_escape": {"lib": "libcurl", "purpose": "URL-encode string (easy)", "category": "network"},
    "_curl_easy_unescape": {"lib": "libcurl", "purpose": "URL-decode string (easy)", "category": "network"},
    "_curl_ws_recv": {"lib": "libcurl", "purpose": "WebSocket receive", "category": "network"},
    "_curl_ws_send": {"lib": "libcurl", "purpose": "WebSocket send", "category": "network"},
    "_curl_ws_meta": {"lib": "libcurl", "purpose": "WebSocket frame metadata", "category": "network"},
    "_curl_formadd": {"lib": "libcurl", "purpose": "add form section (deprecated)", "category": "network"},
    "_curl_formfree": {"lib": "libcurl", "purpose": "free form data (deprecated)", "category": "network"},
    "_curl_easy_send": {"lib": "libcurl", "purpose": "raw send over easy handle", "category": "network"},
    "_curl_easy_recv": {"lib": "libcurl", "purpose": "raw recv over easy handle", "category": "network"},
    "_curl_easy_pause": {"lib": "libcurl", "purpose": "pause/unpause transfer", "category": "network"},
    "_curl_easy_upkeep": {"lib": "libcurl", "purpose": "connection upkeep", "category": "network"},
    "_curl_multi_socket_action": {"lib": "libcurl", "purpose": "multi socket action", "category": "network"},
    "_curl_multi_assign": {"lib": "libcurl", "purpose": "multi assign socket data", "category": "network"},
    "_curl_multi_timeout": {"lib": "libcurl", "purpose": "multi get timeout value", "category": "network"},
    "_curl_multi_fdset": {"lib": "libcurl", "purpose": "multi extract fd_set", "category": "network"},
    "_curl_mime_subparts": {"lib": "libcurl", "purpose": "MIME set subparts", "category": "network"},
    "_curl_mime_headers": {"lib": "libcurl", "purpose": "MIME set custom headers", "category": "network"},
    "_curl_mime_encoder": {"lib": "libcurl", "purpose": "MIME set transfer encoding", "category": "network"},
    "_curl_getdate": {"lib": "libcurl", "purpose": "parse date string", "category": "network"},
    "_curl_easy_option_by_name": {"lib": "libcurl", "purpose": "lookup option by name", "category": "network"},
    "_curl_easy_option_by_id": {"lib": "libcurl", "purpose": "lookup option by id", "category": "network"},
    "_curl_easy_option_next": {"lib": "libcurl", "purpose": "iterate curl options", "category": "network"},
    "_curl_url_dup": {"lib": "libcurl", "purpose": "duplicate URL handle", "category": "network"},
    "_curl_pushheader_bynum": {"lib": "libcurl", "purpose": "server push header by index", "category": "network"},
    "_curl_pushheader_byname": {"lib": "libcurl", "purpose": "server push header by name", "category": "network"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Protocol Buffers
# ---------------------------------------------------------------------------

_PROTOBUF_SIGNATURES: dict[str, dict[str, str]] = {
    # C++ API (mangled names usually, but symbol table may demangle)
    "google::protobuf::MessageLite::SerializeToString": {"lib": "protobuf", "purpose": "serialize message to string", "category": "serialization"},
    "google::protobuf::MessageLite::ParseFromString": {"lib": "protobuf", "purpose": "parse message from string", "category": "serialization"},
    "google::protobuf::MessageLite::SerializeToArray": {"lib": "protobuf", "purpose": "serialize to byte array", "category": "serialization"},
    "google::protobuf::MessageLite::ParseFromArray": {"lib": "protobuf", "purpose": "parse from byte array", "category": "serialization"},
    "google::protobuf::MessageLite::ByteSizeLong": {"lib": "protobuf", "purpose": "compute serialized size", "category": "serialization"},
    "google::protobuf::MessageLite::MergeFromString": {"lib": "protobuf", "purpose": "merge from serialized", "category": "serialization"},
    "google::protobuf::MessageLite::SerializeWithCachedSizesToArray": {"lib": "protobuf", "purpose": "serialize with cached sizes", "category": "serialization"},
    "google::protobuf::Message::DebugString": {"lib": "protobuf", "purpose": "message debug string", "category": "serialization"},
    "google::protobuf::Message::ShortDebugString": {"lib": "protobuf", "purpose": "message short debug", "category": "serialization"},
    "google::protobuf::Message::CopyFrom": {"lib": "protobuf", "purpose": "copy message", "category": "serialization"},
    "google::protobuf::Message::MergeFrom": {"lib": "protobuf", "purpose": "merge message", "category": "serialization"},
    "google::protobuf::Message::Clear": {"lib": "protobuf", "purpose": "clear message fields", "category": "serialization"},
    "google::protobuf::Message::IsInitialized": {"lib": "protobuf", "purpose": "check required fields", "category": "serialization"},
    "google::protobuf::Message::GetDescriptor": {"lib": "protobuf", "purpose": "message descriptor", "category": "serialization"},
    "google::protobuf::Message::GetReflection": {"lib": "protobuf", "purpose": "message reflection", "category": "serialization"},
    "google::protobuf::DescriptorPool::FindFileByName": {"lib": "protobuf", "purpose": "find proto file", "category": "serialization"},
    "google::protobuf::DescriptorPool::FindMessageTypeByName": {"lib": "protobuf", "purpose": "find message type", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteVarint32": {"lib": "protobuf", "purpose": "write varint32", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteVarint64": {"lib": "protobuf", "purpose": "write varint64", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteTag": {"lib": "protobuf", "purpose": "write field tag", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteLittleEndian32": {"lib": "protobuf", "purpose": "write LE 32-bit", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteLittleEndian64": {"lib": "protobuf", "purpose": "write LE 64-bit", "category": "serialization"},
    "google::protobuf::io::CodedOutputStream::WriteString": {"lib": "protobuf", "purpose": "write length-delimited string", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadVarint32": {"lib": "protobuf", "purpose": "read varint32", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadVarint64": {"lib": "protobuf", "purpose": "read varint64", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadTag": {"lib": "protobuf", "purpose": "read field tag", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadLittleEndian32": {"lib": "protobuf", "purpose": "read LE 32-bit", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadLittleEndian64": {"lib": "protobuf", "purpose": "read LE 64-bit", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::ReadString": {"lib": "protobuf", "purpose": "read length-delimited string", "category": "serialization"},
    "google::protobuf::io::CodedInputStream::Skip": {"lib": "protobuf", "purpose": "skip bytes", "category": "serialization"},
    "google::protobuf::io::ZeroCopyOutputStream::Next": {"lib": "protobuf", "purpose": "zero-copy output next", "category": "serialization"},
    "google::protobuf::io::ZeroCopyInputStream::Next": {"lib": "protobuf", "purpose": "zero-copy input next", "category": "serialization"},
    "google::protobuf::Arena::CreateMessage": {"lib": "protobuf", "purpose": "arena-allocated message", "category": "serialization"},
    "google::protobuf::Arena::~Arena": {"lib": "protobuf", "purpose": "arena destruction", "category": "serialization"},
    "google::protobuf::Map": {"lib": "protobuf", "purpose": "protobuf map field", "category": "serialization"},
    "google::protobuf::RepeatedField": {"lib": "protobuf", "purpose": "protobuf repeated field", "category": "serialization"},
    "google::protobuf::RepeatedPtrField": {"lib": "protobuf", "purpose": "protobuf repeated ptr field", "category": "serialization"},
    "google::protobuf::internal::WireFormatLite::WriteBytes": {"lib": "protobuf", "purpose": "wire format write bytes", "category": "serialization"},
    "google::protobuf::internal::WireFormatLite::ReadBytes": {"lib": "protobuf", "purpose": "wire format read bytes", "category": "serialization"},
    "google::protobuf::internal::ArenaStringPtr::Set": {"lib": "protobuf", "purpose": "arena string set", "category": "serialization"},
    "google::protobuf::internal::ArenaStringPtr::Get": {"lib": "protobuf", "purpose": "arena string get", "category": "serialization"},
    # Mangled C++ name versions (as seen in stripped binaries)
    "_ZN6google8protobuf7MessageC1Ev": {"lib": "protobuf", "purpose": "Message default constructor", "category": "serialization"},
    "_ZN6google8protobuf7MessageC2Ev": {"lib": "protobuf", "purpose": "Message base constructor", "category": "serialization"},
    "_ZN6google8protobuf7MessageD0Ev": {"lib": "protobuf", "purpose": "Message deleting destructor", "category": "serialization"},
    "_ZN6google8protobuf7MessageD1Ev": {"lib": "protobuf", "purpose": "Message complete destructor", "category": "serialization"},
    "_ZN6google8protobuf7Message5ClearEv": {"lib": "protobuf", "purpose": "Message::Clear()", "category": "serialization"},
    "_ZN6google8protobuf7Message9MergeFromERKS1_": {"lib": "protobuf", "purpose": "Message::MergeFrom()", "category": "serialization"},
    "_ZN6google8protobuf7Message8CopyFromERKS1_": {"lib": "protobuf", "purpose": "Message::CopyFrom()", "category": "serialization"},
    "_ZN6google8protobuf7Message11ByteSizeLongEv": {"lib": "protobuf", "purpose": "Message::ByteSizeLong()", "category": "serialization"},
    "_ZN6google8protobuf7Message13IsInitializedEv": {"lib": "protobuf", "purpose": "Message::IsInitialized()", "category": "serialization"},
    "_ZN6google8protobuf11MessageLite18SerializeToStringEPNSt": {"lib": "protobuf", "purpose": "MessageLite::SerializeToString()", "category": "serialization"},
    "_ZN6google8protobuf11MessageLite16ParseFromStringERKNSt": {"lib": "protobuf", "purpose": "MessageLite::ParseFromString()", "category": "serialization"},
    "_ZN6google8protobuf11MessageLite17SerializeToArrayEPhi": {"lib": "protobuf", "purpose": "MessageLite::SerializeToArray()", "category": "serialization"},
    "_ZN6google8protobuf11MessageLite14ParseFromArrayEPKvi": {"lib": "protobuf", "purpose": "MessageLite::ParseFromArray()", "category": "serialization"},
    "_ZN6google8protobuf11MessageLite15MergeFromStringERKNSt": {"lib": "protobuf", "purpose": "MessageLite::MergeFromString()", "category": "serialization"},
    "_ZN6google8protobuf10ReflectionC": {"lib": "protobuf", "purpose": "Reflection constructor", "category": "serialization"},
    "_ZN6google8protobuf10Reflection": {"lib": "protobuf", "purpose": "Reflection methods", "category": "serialization"},
    "_ZN6google8protobuf10DescriptorE": {"lib": "protobuf", "purpose": "Descriptor operations", "category": "serialization"},
    "_ZN6google8protobuf14DescriptorPool": {"lib": "protobuf", "purpose": "DescriptorPool operations", "category": "serialization"},
    "_ZN6google8protobuf2io16CodedOutputStream": {"lib": "protobuf", "purpose": "CodedOutputStream operations", "category": "serialization"},
    "_ZN6google8protobuf2io15CodedInputStream": {"lib": "protobuf", "purpose": "CodedInputStream operations", "category": "serialization"},
    "_ZN6google8protobuf2io20ZeroCopyOutputStream": {"lib": "protobuf", "purpose": "ZeroCopyOutputStream operations", "category": "serialization"},
    "_ZN6google8protobuf2io19ZeroCopyInputStream": {"lib": "protobuf", "purpose": "ZeroCopyInputStream operations", "category": "serialization"},
    "_ZN6google8protobuf5Arena13CreateMessageE": {"lib": "protobuf", "purpose": "Arena::CreateMessage()", "category": "serialization"},
    "_ZN6google8protobuf5ArenaD": {"lib": "protobuf", "purpose": "Arena destructor", "category": "serialization"},
    "_ZN6google8protobuf5Arena10CreateMaybeE": {"lib": "protobuf", "purpose": "Arena::CreateMaybe()", "category": "serialization"},
    "_ZN6google8protobuf5Arena17CreateMaybeMessageE": {"lib": "protobuf", "purpose": "Arena::CreateMaybeMessage()", "category": "serialization"},
    "_ZN6google8protobuf8internal14WireFormatLite": {"lib": "protobuf", "purpose": "WireFormatLite operations", "category": "serialization"},
    "_ZN6google8protobuf8internal12MapFieldBase": {"lib": "protobuf", "purpose": "MapFieldBase operations", "category": "serialization"},
    "_ZN6google8protobuf8internal13RepeatedField": {"lib": "protobuf", "purpose": "RepeatedField operations", "category": "serialization"},
    # Additional demangled names for common protobuf symbols
    "google::protobuf::MessageLite::SerializeAsString": {"lib": "protobuf", "purpose": "serialize message as string", "category": "serialization"},
    "google::protobuf::MessageLite::AppendToString": {"lib": "protobuf", "purpose": "append serialized to string", "category": "serialization"},
    "google::protobuf::MessageLite::ParsePartialFromString": {"lib": "protobuf", "purpose": "partial parse from string", "category": "serialization"},
    "google::protobuf::MessageLite::ParsePartialFromArray": {"lib": "protobuf", "purpose": "partial parse from array", "category": "serialization"},
    "google::protobuf::Message::DebugString": {"lib": "protobuf", "purpose": "message debug string", "category": "serialization"},
    "google::protobuf::Message::Utf8DebugString": {"lib": "protobuf", "purpose": "message UTF-8 debug string", "category": "serialization"},
    "google::protobuf::Message::FindInitializationErrors": {"lib": "protobuf", "purpose": "find unset required fields", "category": "serialization"},
    "google::protobuf::Message::InitializationErrorString": {"lib": "protobuf", "purpose": "list unset required fields", "category": "serialization"},
    "google::protobuf::Message::SpaceUsedLong": {"lib": "protobuf", "purpose": "memory usage of message", "category": "serialization"},
    "google::protobuf::Arena::Init": {"lib": "protobuf", "purpose": "arena init", "category": "serialization"},
    "google::protobuf::Arena::Reset": {"lib": "protobuf", "purpose": "arena reset (free all)", "category": "serialization"},
    "google::protobuf::Arena::SpaceUsed": {"lib": "protobuf", "purpose": "arena memory usage", "category": "serialization"},
    "google::protobuf::Arena::SpaceAllocated": {"lib": "protobuf", "purpose": "arena total allocated", "category": "serialization"},
    "google::protobuf::TextFormat::PrintToString": {"lib": "protobuf", "purpose": "text format serialize", "category": "serialization"},
    "google::protobuf::TextFormat::ParseFromString": {"lib": "protobuf", "purpose": "text format parse", "category": "serialization"},
    "google::protobuf::util::JsonStringToMessage": {"lib": "protobuf", "purpose": "JSON to protobuf conversion", "category": "serialization"},
    "google::protobuf::util::MessageToJsonString": {"lib": "protobuf", "purpose": "protobuf to JSON conversion", "category": "serialization"},
}


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

_SQLITE_SIGNATURES: dict[str, dict[str, str]] = {
    "_sqlite3_open": {"lib": "sqlite3", "purpose": "open database", "category": "database"},
    "_sqlite3_open_v2": {"lib": "sqlite3", "purpose": "open database (v2 flags)", "category": "database"},
    "_sqlite3_close": {"lib": "sqlite3", "purpose": "close database", "category": "database"},
    "_sqlite3_close_v2": {"lib": "sqlite3", "purpose": "close database (deferred)", "category": "database"},
    "_sqlite3_exec": {"lib": "sqlite3", "purpose": "execute SQL one-shot", "category": "database"},
    "_sqlite3_prepare_v2": {"lib": "sqlite3", "purpose": "prepare SQL statement", "category": "database"},
    "_sqlite3_prepare_v3": {"lib": "sqlite3", "purpose": "prepare SQL statement (v3)", "category": "database"},
    "_sqlite3_step": {"lib": "sqlite3", "purpose": "step prepared statement", "category": "database"},
    "_sqlite3_finalize": {"lib": "sqlite3", "purpose": "finalize statement", "category": "database"},
    "_sqlite3_reset": {"lib": "sqlite3", "purpose": "reset statement", "category": "database"},
    "_sqlite3_bind_blob": {"lib": "sqlite3", "purpose": "bind blob parameter", "category": "database"},
    "_sqlite3_bind_double": {"lib": "sqlite3", "purpose": "bind double parameter", "category": "database"},
    "_sqlite3_bind_int": {"lib": "sqlite3", "purpose": "bind int parameter", "category": "database"},
    "_sqlite3_bind_int64": {"lib": "sqlite3", "purpose": "bind int64 parameter", "category": "database"},
    "_sqlite3_bind_null": {"lib": "sqlite3", "purpose": "bind null parameter", "category": "database"},
    "_sqlite3_bind_text": {"lib": "sqlite3", "purpose": "bind text parameter", "category": "database"},
    "_sqlite3_bind_text16": {"lib": "sqlite3", "purpose": "bind UTF-16 text", "category": "database"},
    "_sqlite3_bind_parameter_count": {"lib": "sqlite3", "purpose": "parameter count", "category": "database"},
    "_sqlite3_bind_parameter_name": {"lib": "sqlite3", "purpose": "parameter name", "category": "database"},
    "_sqlite3_bind_parameter_index": {"lib": "sqlite3", "purpose": "parameter index", "category": "database"},
    "_sqlite3_column_blob": {"lib": "sqlite3", "purpose": "column blob result", "category": "database"},
    "_sqlite3_column_bytes": {"lib": "sqlite3", "purpose": "column byte count", "category": "database"},
    "_sqlite3_column_count": {"lib": "sqlite3", "purpose": "result column count", "category": "database"},
    "_sqlite3_column_double": {"lib": "sqlite3", "purpose": "column double result", "category": "database"},
    "_sqlite3_column_int": {"lib": "sqlite3", "purpose": "column int result", "category": "database"},
    "_sqlite3_column_int64": {"lib": "sqlite3", "purpose": "column int64 result", "category": "database"},
    "_sqlite3_column_name": {"lib": "sqlite3", "purpose": "column name", "category": "database"},
    "_sqlite3_column_text": {"lib": "sqlite3", "purpose": "column text result", "category": "database"},
    "_sqlite3_column_text16": {"lib": "sqlite3", "purpose": "column UTF-16 result", "category": "database"},
    "_sqlite3_column_type": {"lib": "sqlite3", "purpose": "column type code", "category": "database"},
    "_sqlite3_column_value": {"lib": "sqlite3", "purpose": "column generic value", "category": "database"},
    "_sqlite3_errmsg": {"lib": "sqlite3", "purpose": "error message", "category": "database"},
    "_sqlite3_errcode": {"lib": "sqlite3", "purpose": "error code", "category": "database"},
    "_sqlite3_extended_errcode": {"lib": "sqlite3", "purpose": "extended error code", "category": "database"},
    "_sqlite3_errstr": {"lib": "sqlite3", "purpose": "error string from code", "category": "database"},
    "_sqlite3_changes": {"lib": "sqlite3", "purpose": "changed row count", "category": "database"},
    "_sqlite3_total_changes": {"lib": "sqlite3", "purpose": "total changed rows", "category": "database"},
    "_sqlite3_last_insert_rowid": {"lib": "sqlite3", "purpose": "last insert rowid", "category": "database"},
    "_sqlite3_busy_timeout": {"lib": "sqlite3", "purpose": "busy timeout config", "category": "database"},
    "_sqlite3_busy_handler": {"lib": "sqlite3", "purpose": "busy handler callback", "category": "database"},
    "_sqlite3_db_config": {"lib": "sqlite3", "purpose": "database config", "category": "database"},
    "_sqlite3_db_handle": {"lib": "sqlite3", "purpose": "get db handle from stmt", "category": "database"},
    "_sqlite3_free": {"lib": "sqlite3", "purpose": "free sqlite memory", "category": "database"},
    "_sqlite3_malloc": {"lib": "sqlite3", "purpose": "sqlite memory allocation", "category": "database"},
    "_sqlite3_realloc": {"lib": "sqlite3", "purpose": "sqlite memory realloc", "category": "database"},
    "_sqlite3_mprintf": {"lib": "sqlite3", "purpose": "formatted string (sqlite alloc)", "category": "database"},
    "_sqlite3_snprintf": {"lib": "sqlite3", "purpose": "formatted string (buffer)", "category": "database"},
    "_sqlite3_create_function_v2": {"lib": "sqlite3", "purpose": "register SQL function", "category": "database"},
    "_sqlite3_create_collation_v2": {"lib": "sqlite3", "purpose": "register collation", "category": "database"},
    "_sqlite3_result_blob": {"lib": "sqlite3", "purpose": "SQL function return blob", "category": "database"},
    "_sqlite3_result_double": {"lib": "sqlite3", "purpose": "SQL function return double", "category": "database"},
    "_sqlite3_result_error": {"lib": "sqlite3", "purpose": "SQL function return error", "category": "database"},
    "_sqlite3_result_int": {"lib": "sqlite3", "purpose": "SQL function return int", "category": "database"},
    "_sqlite3_result_int64": {"lib": "sqlite3", "purpose": "SQL function return int64", "category": "database"},
    "_sqlite3_result_null": {"lib": "sqlite3", "purpose": "SQL function return null", "category": "database"},
    "_sqlite3_result_text": {"lib": "sqlite3", "purpose": "SQL function return text", "category": "database"},
    "_sqlite3_value_blob": {"lib": "sqlite3", "purpose": "SQL function arg blob", "category": "database"},
    "_sqlite3_value_bytes": {"lib": "sqlite3", "purpose": "SQL function arg bytes", "category": "database"},
    "_sqlite3_value_double": {"lib": "sqlite3", "purpose": "SQL function arg double", "category": "database"},
    "_sqlite3_value_int": {"lib": "sqlite3", "purpose": "SQL function arg int", "category": "database"},
    "_sqlite3_value_int64": {"lib": "sqlite3", "purpose": "SQL function arg int64", "category": "database"},
    "_sqlite3_value_text": {"lib": "sqlite3", "purpose": "SQL function arg text", "category": "database"},
    "_sqlite3_value_type": {"lib": "sqlite3", "purpose": "SQL function arg type", "category": "database"},
    "_sqlite3_blob_open": {"lib": "sqlite3", "purpose": "blob open for I/O", "category": "database"},
    "_sqlite3_blob_close": {"lib": "sqlite3", "purpose": "blob close", "category": "database"},
    "_sqlite3_blob_read": {"lib": "sqlite3", "purpose": "blob read", "category": "database"},
    "_sqlite3_blob_write": {"lib": "sqlite3", "purpose": "blob write", "category": "database"},
    "_sqlite3_blob_bytes": {"lib": "sqlite3", "purpose": "blob size", "category": "database"},
    "_sqlite3_wal_checkpoint_v2": {"lib": "sqlite3", "purpose": "WAL checkpoint", "category": "database"},
    "_sqlite3_wal_autocheckpoint": {"lib": "sqlite3", "purpose": "WAL auto-checkpoint config", "category": "database"},
    "_sqlite3_backup_init": {"lib": "sqlite3", "purpose": "online backup init", "category": "database"},
    "_sqlite3_backup_step": {"lib": "sqlite3", "purpose": "online backup step", "category": "database"},
    "_sqlite3_backup_finish": {"lib": "sqlite3", "purpose": "online backup finish", "category": "database"},
    "_sqlite3_libversion": {"lib": "sqlite3", "purpose": "sqlite version string", "category": "database"},
    "_sqlite3_libversion_number": {"lib": "sqlite3", "purpose": "sqlite version number", "category": "database"},
    "_sqlite3_threadsafe": {"lib": "sqlite3", "purpose": "thread safety level", "category": "database"},
    "_sqlite3_config": {"lib": "sqlite3", "purpose": "global config", "category": "database"},
    "_sqlite3_initialize": {"lib": "sqlite3", "purpose": "sqlite init", "category": "database"},
    "_sqlite3_shutdown": {"lib": "sqlite3", "purpose": "sqlite shutdown", "category": "database"},
    "_sqlite3_key": {"lib": "sqlite3", "purpose": "database encryption key (SEE/sqlcipher)", "category": "database"},
    "_sqlite3_rekey": {"lib": "sqlite3", "purpose": "change encryption key", "category": "database"},
    "_sqlite3_set_authorizer": {"lib": "sqlite3", "purpose": "SQL authorizer callback", "category": "database"},
    "_sqlite3_trace_v2": {"lib": "sqlite3", "purpose": "SQL trace callback", "category": "database"},
    "_sqlite3_stmt_status": {"lib": "sqlite3", "purpose": "statement status counters", "category": "database"},
    "_sqlite3_table_column_metadata": {"lib": "sqlite3", "purpose": "table column metadata", "category": "database"},
    "_sqlite3_expanded_sql": {"lib": "sqlite3", "purpose": "expanded SQL text", "category": "database"},
    "_sqlite3_normalized_sql": {"lib": "sqlite3", "purpose": "normalized SQL text", "category": "database"},
    "_sqlite3_enable_load_extension": {"lib": "sqlite3", "purpose": "enable extension loading", "category": "database"},
    "_sqlite3_load_extension": {"lib": "sqlite3", "purpose": "load extension", "category": "database"},
    # SQLite genisleme: create_function, wal_checkpoint, vb.
    "_sqlite3_create_function": {"lib": "sqlite3", "purpose": "register SQL function (v1)", "category": "database"},
    "_sqlite3_wal_checkpoint": {"lib": "sqlite3", "purpose": "WAL checkpoint (basic)", "category": "database"},
    "_sqlite3_blob_reopen": {"lib": "sqlite3", "purpose": "reopen blob on new row", "category": "database"},
    "_sqlite3_backup_remaining": {"lib": "sqlite3", "purpose": "online backup remaining pages", "category": "database"},
    "_sqlite3_backup_pagecount": {"lib": "sqlite3", "purpose": "online backup total pages", "category": "database"},
    "_sqlite3_db_filename": {"lib": "sqlite3", "purpose": "get database filename", "category": "database"},
    "_sqlite3_db_readonly": {"lib": "sqlite3", "purpose": "check if database is read-only", "category": "database"},
    "_sqlite3_db_status": {"lib": "sqlite3", "purpose": "database status counters", "category": "database"},
    "_sqlite3_status": {"lib": "sqlite3", "purpose": "global sqlite status", "category": "database"},
    "_sqlite3_status64": {"lib": "sqlite3", "purpose": "global sqlite status (64-bit)", "category": "database"},
    "_sqlite3_memory_used": {"lib": "sqlite3", "purpose": "current memory usage", "category": "database"},
    "_sqlite3_memory_highwater": {"lib": "sqlite3", "purpose": "peak memory usage", "category": "database"},
    "_sqlite3_soft_heap_limit64": {"lib": "sqlite3", "purpose": "set soft heap limit", "category": "database"},
    "_sqlite3_hard_heap_limit64": {"lib": "sqlite3", "purpose": "set hard heap limit", "category": "database"},
    "_sqlite3_compileoption_used": {"lib": "sqlite3", "purpose": "check compile option", "category": "database"},
    "_sqlite3_compileoption_get": {"lib": "sqlite3", "purpose": "get compile option by index", "category": "database"},
    "_sqlite3_complete": {"lib": "sqlite3", "purpose": "check SQL completeness", "category": "database"},
    "_sqlite3_interrupt": {"lib": "sqlite3", "purpose": "interrupt running query", "category": "database"},
    "_sqlite3_progress_handler": {"lib": "sqlite3", "purpose": "register progress callback", "category": "database"},
    "_sqlite3_commit_hook": {"lib": "sqlite3", "purpose": "register commit callback", "category": "database"},
    "_sqlite3_rollback_hook": {"lib": "sqlite3", "purpose": "register rollback callback", "category": "database"},
    "_sqlite3_update_hook": {"lib": "sqlite3", "purpose": "register update callback", "category": "database"},
    "_sqlite3_unlock_notify": {"lib": "sqlite3", "purpose": "register unlock notify callback", "category": "database"},
    "_sqlite3_data_count": {"lib": "sqlite3", "purpose": "result data column count", "category": "database"},
    "_sqlite3_sql": {"lib": "sqlite3", "purpose": "get SQL text from statement", "category": "database"},
    "_sqlite3_clear_bindings": {"lib": "sqlite3", "purpose": "clear all statement bindings", "category": "database"},
    "_sqlite3_bind_blob64": {"lib": "sqlite3", "purpose": "bind blob parameter (64-bit len)", "category": "database"},
    "_sqlite3_bind_text64": {"lib": "sqlite3", "purpose": "bind text parameter (64-bit len)", "category": "database"},
    "_sqlite3_bind_zeroblob": {"lib": "sqlite3", "purpose": "bind zero-filled blob", "category": "database"},
    "_sqlite3_bind_zeroblob64": {"lib": "sqlite3", "purpose": "bind zero-filled blob (64-bit)", "category": "database"},
    "_sqlite3_bind_value": {"lib": "sqlite3", "purpose": "bind generic sqlite3_value", "category": "database"},
    "_sqlite3_bind_pointer": {"lib": "sqlite3", "purpose": "bind pointer value", "category": "database"},
    "_sqlite3_column_bytes16": {"lib": "sqlite3", "purpose": "column UTF-16 byte count", "category": "database"},
    "_sqlite3_column_database_name": {"lib": "sqlite3", "purpose": "column database name", "category": "database"},
    "_sqlite3_column_table_name": {"lib": "sqlite3", "purpose": "column table name", "category": "database"},
    "_sqlite3_column_origin_name": {"lib": "sqlite3", "purpose": "column origin name", "category": "database"},
    "_sqlite3_result_error_code": {"lib": "sqlite3", "purpose": "SQL function return error code", "category": "database"},
    "_sqlite3_result_error_nomem": {"lib": "sqlite3", "purpose": "SQL function return NOMEM error", "category": "database"},
    "_sqlite3_result_error_toobig": {"lib": "sqlite3", "purpose": "SQL function return TOOBIG error", "category": "database"},
    "_sqlite3_result_int64": {"lib": "sqlite3", "purpose": "SQL function return int64", "category": "database"},
    "_sqlite3_result_text16": {"lib": "sqlite3", "purpose": "SQL function return UTF-16 text", "category": "database"},
    "_sqlite3_result_value": {"lib": "sqlite3", "purpose": "SQL function return sqlite3_value", "category": "database"},
    "_sqlite3_result_zeroblob": {"lib": "sqlite3", "purpose": "SQL function return zero blob", "category": "database"},
    "_sqlite3_result_subtype": {"lib": "sqlite3", "purpose": "SQL function return subtype", "category": "database"},
    "_sqlite3_aggregate_context": {"lib": "sqlite3", "purpose": "get aggregate function context", "category": "database"},
    "_sqlite3_user_data": {"lib": "sqlite3", "purpose": "get function user data", "category": "database"},
    "_sqlite3_context_db_handle": {"lib": "sqlite3", "purpose": "get db handle from context", "category": "database"},
    "_sqlite3_create_module_v2": {"lib": "sqlite3", "purpose": "register virtual table module", "category": "database"},
    "_sqlite3_declare_vtab": {"lib": "sqlite3", "purpose": "declare virtual table schema", "category": "database"},
    "_sqlite3_overload_function": {"lib": "sqlite3", "purpose": "overload function for vtab", "category": "database"},
    "_sqlite3_vtab_config": {"lib": "sqlite3", "purpose": "virtual table config", "category": "database"},
    "_sqlite3_vtab_on_conflict": {"lib": "sqlite3", "purpose": "virtual table conflict mode", "category": "database"},
    "_sqlite3_sourceid": {"lib": "sqlite3", "purpose": "sqlite source ID string", "category": "database"},
    "_sqlite3_auto_extension": {"lib": "sqlite3", "purpose": "register auto-load extension", "category": "database"},
    "_sqlite3_cancel_auto_extension": {"lib": "sqlite3", "purpose": "cancel auto-load extension", "category": "database"},
    "_sqlite3_reset_auto_extension": {"lib": "sqlite3", "purpose": "reset all auto-load extensions", "category": "database"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- JSON parsers (cJSON, yyjson, jansson)
# ---------------------------------------------------------------------------

_JSON_SIGNATURES: dict[str, dict[str, str]] = {
    # --- cJSON ---
    "_cJSON_Parse": {"lib": "cJSON", "purpose": "parse JSON string", "category": "serialization"},
    "_cJSON_ParseWithLength": {"lib": "cJSON", "purpose": "parse JSON with length", "category": "serialization"},
    "_cJSON_Delete": {"lib": "cJSON", "purpose": "delete JSON tree", "category": "serialization"},
    "_cJSON_Print": {"lib": "cJSON", "purpose": "print JSON (formatted)", "category": "serialization"},
    "_cJSON_PrintUnformatted": {"lib": "cJSON", "purpose": "print JSON (compact)", "category": "serialization"},
    "_cJSON_PrintBuffered": {"lib": "cJSON", "purpose": "print JSON to preallocated buffer", "category": "serialization"},
    "_cJSON_CreateObject": {"lib": "cJSON", "purpose": "create JSON object", "category": "serialization"},
    "_cJSON_CreateArray": {"lib": "cJSON", "purpose": "create JSON array", "category": "serialization"},
    "_cJSON_CreateString": {"lib": "cJSON", "purpose": "create JSON string", "category": "serialization"},
    "_cJSON_CreateNumber": {"lib": "cJSON", "purpose": "create JSON number", "category": "serialization"},
    "_cJSON_CreateBool": {"lib": "cJSON", "purpose": "create JSON boolean", "category": "serialization"},
    "_cJSON_CreateNull": {"lib": "cJSON", "purpose": "create JSON null", "category": "serialization"},
    "_cJSON_CreateTrue": {"lib": "cJSON", "purpose": "create JSON true", "category": "serialization"},
    "_cJSON_CreateFalse": {"lib": "cJSON", "purpose": "create JSON false", "category": "serialization"},
    "_cJSON_CreateIntArray": {"lib": "cJSON", "purpose": "create JSON int array", "category": "serialization"},
    "_cJSON_CreateFloatArray": {"lib": "cJSON", "purpose": "create JSON float array", "category": "serialization"},
    "_cJSON_CreateStringArray": {"lib": "cJSON", "purpose": "create JSON string array", "category": "serialization"},
    "_cJSON_AddItemToObject": {"lib": "cJSON", "purpose": "add item to JSON object", "category": "serialization"},
    "_cJSON_AddItemToArray": {"lib": "cJSON", "purpose": "add item to JSON array", "category": "serialization"},
    "_cJSON_AddItemReferenceToObject": {"lib": "cJSON", "purpose": "add reference to JSON object", "category": "serialization"},
    "_cJSON_AddItemReferenceToArray": {"lib": "cJSON", "purpose": "add reference to JSON array", "category": "serialization"},
    "_cJSON_DetachItemFromObject": {"lib": "cJSON", "purpose": "detach item from JSON object", "category": "serialization"},
    "_cJSON_DetachItemFromArray": {"lib": "cJSON", "purpose": "detach item from JSON array", "category": "serialization"},
    "_cJSON_DeleteItemFromObject": {"lib": "cJSON", "purpose": "delete item from JSON object", "category": "serialization"},
    "_cJSON_DeleteItemFromArray": {"lib": "cJSON", "purpose": "delete item from JSON array", "category": "serialization"},
    "_cJSON_GetObjectItem": {"lib": "cJSON", "purpose": "get JSON object member", "category": "serialization"},
    "_cJSON_GetObjectItemCaseSensitive": {"lib": "cJSON", "purpose": "get JSON object member (case-sensitive)", "category": "serialization"},
    "_cJSON_GetArrayItem": {"lib": "cJSON", "purpose": "get JSON array element", "category": "serialization"},
    "_cJSON_GetArraySize": {"lib": "cJSON", "purpose": "get JSON array length", "category": "serialization"},
    "_cJSON_HasObjectItem": {"lib": "cJSON", "purpose": "check JSON object has key", "category": "serialization"},
    "_cJSON_IsObject": {"lib": "cJSON", "purpose": "check if JSON object", "category": "serialization"},
    "_cJSON_IsArray": {"lib": "cJSON", "purpose": "check if JSON array", "category": "serialization"},
    "_cJSON_IsString": {"lib": "cJSON", "purpose": "check if JSON string", "category": "serialization"},
    "_cJSON_IsNumber": {"lib": "cJSON", "purpose": "check if JSON number", "category": "serialization"},
    "_cJSON_IsBool": {"lib": "cJSON", "purpose": "check if JSON boolean", "category": "serialization"},
    "_cJSON_IsNull": {"lib": "cJSON", "purpose": "check if JSON null", "category": "serialization"},
    "_cJSON_IsTrue": {"lib": "cJSON", "purpose": "check if JSON true", "category": "serialization"},
    "_cJSON_IsFalse": {"lib": "cJSON", "purpose": "check if JSON false", "category": "serialization"},
    "_cJSON_IsInvalid": {"lib": "cJSON", "purpose": "check if JSON invalid", "category": "serialization"},
    "_cJSON_Duplicate": {"lib": "cJSON", "purpose": "deep copy JSON tree", "category": "serialization"},
    "_cJSON_Compare": {"lib": "cJSON", "purpose": "compare two JSON trees", "category": "serialization"},
    "_cJSON_ReplaceItemInObject": {"lib": "cJSON", "purpose": "replace item in JSON object", "category": "serialization"},
    "_cJSON_ReplaceItemInArray": {"lib": "cJSON", "purpose": "replace item in JSON array", "category": "serialization"},
    "_cJSON_AddNumberToObject": {"lib": "cJSON", "purpose": "add number to JSON object", "category": "serialization"},
    "_cJSON_AddStringToObject": {"lib": "cJSON", "purpose": "add string to JSON object", "category": "serialization"},
    "_cJSON_AddBoolToObject": {"lib": "cJSON", "purpose": "add bool to JSON object", "category": "serialization"},
    "_cJSON_AddNullToObject": {"lib": "cJSON", "purpose": "add null to JSON object", "category": "serialization"},
    "_cJSON_SetValuestring": {"lib": "cJSON", "purpose": "set JSON string value", "category": "serialization"},
    "_cJSON_SetNumberHelper": {"lib": "cJSON", "purpose": "set JSON number value", "category": "serialization"},
    "_cJSON_Version": {"lib": "cJSON", "purpose": "cJSON version string", "category": "info"},
    "_cJSON_Minify": {"lib": "cJSON", "purpose": "minify JSON string in-place", "category": "serialization"},
    # --- yyjson ---
    "_yyjson_read": {"lib": "yyjson", "purpose": "parse JSON (immutable)", "category": "serialization"},
    "_yyjson_read_opts": {"lib": "yyjson", "purpose": "parse JSON with options", "category": "serialization"},
    "_yyjson_read_file": {"lib": "yyjson", "purpose": "parse JSON from file", "category": "serialization"},
    "_yyjson_write": {"lib": "yyjson", "purpose": "serialize JSON to string", "category": "serialization"},
    "_yyjson_write_opts": {"lib": "yyjson", "purpose": "serialize JSON with options", "category": "serialization"},
    "_yyjson_write_file": {"lib": "yyjson", "purpose": "serialize JSON to file", "category": "serialization"},
    "_yyjson_doc_free": {"lib": "yyjson", "purpose": "free JSON document", "category": "serialization"},
    "_yyjson_doc_get_root": {"lib": "yyjson", "purpose": "get JSON document root", "category": "serialization"},
    "_yyjson_mut_doc_new": {"lib": "yyjson", "purpose": "create mutable JSON document", "category": "serialization"},
    "_yyjson_mut_doc_free": {"lib": "yyjson", "purpose": "free mutable JSON document", "category": "serialization"},
    "_yyjson_mut_write": {"lib": "yyjson", "purpose": "serialize mutable JSON", "category": "serialization"},
    "_yyjson_val_get_type": {"lib": "yyjson", "purpose": "get JSON value type", "category": "serialization"},
    "_yyjson_obj_get": {"lib": "yyjson", "purpose": "get object member by key", "category": "serialization"},
    "_yyjson_arr_get": {"lib": "yyjson", "purpose": "get array element by index", "category": "serialization"},
    "_yyjson_get_str": {"lib": "yyjson", "purpose": "get string value", "category": "serialization"},
    "_yyjson_get_int": {"lib": "yyjson", "purpose": "get integer value", "category": "serialization"},
    "_yyjson_get_real": {"lib": "yyjson", "purpose": "get double value", "category": "serialization"},
    "_yyjson_get_bool": {"lib": "yyjson", "purpose": "get boolean value", "category": "serialization"},
    # --- jansson ---
    "_json_loads": {"lib": "jansson", "purpose": "parse JSON string", "category": "serialization"},
    "_json_loadb": {"lib": "jansson", "purpose": "parse JSON buffer", "category": "serialization"},
    "_json_loadf": {"lib": "jansson", "purpose": "parse JSON from FILE*", "category": "serialization"},
    "_json_load_file": {"lib": "jansson", "purpose": "parse JSON from file path", "category": "serialization"},
    "_json_dumps": {"lib": "jansson", "purpose": "serialize JSON to string", "category": "serialization"},
    "_json_dumpf": {"lib": "jansson", "purpose": "serialize JSON to FILE*", "category": "serialization"},
    "_json_dump_file": {"lib": "jansson", "purpose": "serialize JSON to file path", "category": "serialization"},
    "_json_object": {"lib": "jansson", "purpose": "create JSON object", "category": "serialization"},
    "_json_array": {"lib": "jansson", "purpose": "create JSON array", "category": "serialization"},
    "_json_string": {"lib": "jansson", "purpose": "create JSON string", "category": "serialization"},
    "_json_stringn": {"lib": "jansson", "purpose": "create JSON string (with length)", "category": "serialization"},
    "_json_integer": {"lib": "jansson", "purpose": "create JSON integer", "category": "serialization"},
    "_json_real": {"lib": "jansson", "purpose": "create JSON real", "category": "serialization"},
    "_json_true": {"lib": "jansson", "purpose": "create JSON true", "category": "serialization"},
    "_json_false": {"lib": "jansson", "purpose": "create JSON false", "category": "serialization"},
    "_json_null": {"lib": "jansson", "purpose": "create JSON null", "category": "serialization"},
    "_json_object_get": {"lib": "jansson", "purpose": "get JSON object member", "category": "serialization"},
    "_json_object_set_new": {"lib": "jansson", "purpose": "set JSON object member (steal ref)", "category": "serialization"},
    "_json_object_set": {"lib": "jansson", "purpose": "set JSON object member", "category": "serialization"},
    "_json_object_del": {"lib": "jansson", "purpose": "delete JSON object member", "category": "serialization"},
    "_json_object_size": {"lib": "jansson", "purpose": "get JSON object size", "category": "serialization"},
    "_json_object_iter": {"lib": "jansson", "purpose": "JSON object iterator begin", "category": "serialization"},
    "_json_object_iter_next": {"lib": "jansson", "purpose": "JSON object iterator next", "category": "serialization"},
    "_json_object_iter_key": {"lib": "jansson", "purpose": "JSON object iterator key", "category": "serialization"},
    "_json_object_iter_value": {"lib": "jansson", "purpose": "JSON object iterator value", "category": "serialization"},
    "_json_array_get": {"lib": "jansson", "purpose": "get JSON array element", "category": "serialization"},
    "_json_array_append_new": {"lib": "jansson", "purpose": "append to JSON array (steal ref)", "category": "serialization"},
    "_json_array_append": {"lib": "jansson", "purpose": "append to JSON array", "category": "serialization"},
    "_json_array_size": {"lib": "jansson", "purpose": "get JSON array length", "category": "serialization"},
    "_json_array_insert_new": {"lib": "jansson", "purpose": "insert into JSON array (steal ref)", "category": "serialization"},
    "_json_array_remove": {"lib": "jansson", "purpose": "remove from JSON array", "category": "serialization"},
    "_json_decref": {"lib": "jansson", "purpose": "decrement JSON reference count", "category": "serialization"},
    "_json_incref": {"lib": "jansson", "purpose": "increment JSON reference count", "category": "serialization"},
    "_json_deep_copy": {"lib": "jansson", "purpose": "deep copy JSON value", "category": "serialization"},
    "_json_equal": {"lib": "jansson", "purpose": "compare JSON values", "category": "serialization"},
    "_json_string_value": {"lib": "jansson", "purpose": "get string from JSON string", "category": "serialization"},
    "_json_integer_value": {"lib": "jansson", "purpose": "get int from JSON integer", "category": "serialization"},
    "_json_real_value": {"lib": "jansson", "purpose": "get double from JSON real", "category": "serialization"},
    "_json_number_value": {"lib": "jansson", "purpose": "get number as double", "category": "serialization"},
    "_json_is_object": {"lib": "jansson", "purpose": "check if JSON object", "category": "serialization"},
    "_json_is_array": {"lib": "jansson", "purpose": "check if JSON array", "category": "serialization"},
    "_json_is_string": {"lib": "jansson", "purpose": "check if JSON string", "category": "serialization"},
    "_json_is_integer": {"lib": "jansson", "purpose": "check if JSON integer", "category": "serialization"},
    "_json_is_real": {"lib": "jansson", "purpose": "check if JSON real", "category": "serialization"},
    "_json_is_true": {"lib": "jansson", "purpose": "check if JSON true", "category": "serialization"},
    "_json_is_false": {"lib": "jansson", "purpose": "check if JSON false", "category": "serialization"},
    "_json_is_null": {"lib": "jansson", "purpose": "check if JSON null", "category": "serialization"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- XML parsers (libxml2, expat)
# ---------------------------------------------------------------------------

_XML_SIGNATURES: dict[str, dict[str, str]] = {
    # --- libxml2: Parsing ---
    "_xmlReadMemory": {"lib": "libxml2", "purpose": "parse XML from memory", "category": "serialization"},
    "_xmlReadFile": {"lib": "libxml2", "purpose": "parse XML from file", "category": "serialization"},
    "_xmlReadDoc": {"lib": "libxml2", "purpose": "parse XML from string", "category": "serialization"},
    "_xmlReadFd": {"lib": "libxml2", "purpose": "parse XML from fd", "category": "serialization"},
    "_xmlReadIO": {"lib": "libxml2", "purpose": "parse XML from I/O callbacks", "category": "serialization"},
    "_xmlCtxtReadMemory": {"lib": "libxml2", "purpose": "parse XML from memory with context", "category": "serialization"},
    "_xmlCtxtReadFile": {"lib": "libxml2", "purpose": "parse XML from file with context", "category": "serialization"},
    "_xmlParseMemory": {"lib": "libxml2", "purpose": "parse XML from memory (legacy)", "category": "serialization"},
    "_xmlParseFile": {"lib": "libxml2", "purpose": "parse XML from file (legacy)", "category": "serialization"},
    "_xmlParseDoc": {"lib": "libxml2", "purpose": "parse XML from string (legacy)", "category": "serialization"},
    # --- libxml2: Document/tree ---
    "_xmlFreeDoc": {"lib": "libxml2", "purpose": "free XML document", "category": "serialization"},
    "_xmlDocGetRootElement": {"lib": "libxml2", "purpose": "get root element", "category": "serialization"},
    "_xmlDocSetRootElement": {"lib": "libxml2", "purpose": "set root element", "category": "serialization"},
    "_xmlNewDoc": {"lib": "libxml2", "purpose": "create new XML document", "category": "serialization"},
    "_xmlCopyDoc": {"lib": "libxml2", "purpose": "copy XML document", "category": "serialization"},
    # --- libxml2: Nodes ---
    "_xmlNewNode": {"lib": "libxml2", "purpose": "create XML element node", "category": "serialization"},
    "_xmlNewText": {"lib": "libxml2", "purpose": "create XML text node", "category": "serialization"},
    "_xmlNewComment": {"lib": "libxml2", "purpose": "create XML comment node", "category": "serialization"},
    "_xmlNewCDataBlock": {"lib": "libxml2", "purpose": "create XML CDATA node", "category": "serialization"},
    "_xmlNewPI": {"lib": "libxml2", "purpose": "create XML processing instruction", "category": "serialization"},
    "_xmlAddChild": {"lib": "libxml2", "purpose": "add child node", "category": "serialization"},
    "_xmlAddNextSibling": {"lib": "libxml2", "purpose": "add next sibling node", "category": "serialization"},
    "_xmlAddPrevSibling": {"lib": "libxml2", "purpose": "add previous sibling node", "category": "serialization"},
    "_xmlUnlinkNode": {"lib": "libxml2", "purpose": "unlink node from tree", "category": "serialization"},
    "_xmlFreeNode": {"lib": "libxml2", "purpose": "free XML node", "category": "serialization"},
    "_xmlCopyNode": {"lib": "libxml2", "purpose": "copy XML node", "category": "serialization"},
    "_xmlNodeGetContent": {"lib": "libxml2", "purpose": "get node text content", "category": "serialization"},
    "_xmlNodeSetContent": {"lib": "libxml2", "purpose": "set node text content", "category": "serialization"},
    "_xmlNodeListGetString": {"lib": "libxml2", "purpose": "get node list as string", "category": "serialization"},
    # --- libxml2: Attributes ---
    "_xmlGetProp": {"lib": "libxml2", "purpose": "get XML attribute value", "category": "serialization"},
    "_xmlSetProp": {"lib": "libxml2", "purpose": "set XML attribute", "category": "serialization"},
    "_xmlNewProp": {"lib": "libxml2", "purpose": "create XML attribute", "category": "serialization"},
    "_xmlHasProp": {"lib": "libxml2", "purpose": "check XML attribute exists", "category": "serialization"},
    "_xmlRemoveProp": {"lib": "libxml2", "purpose": "remove XML attribute", "category": "serialization"},
    # --- libxml2: Serialization ---
    "_xmlSaveFormatFile": {"lib": "libxml2", "purpose": "save XML to file (formatted)", "category": "serialization"},
    "_xmlSaveFile": {"lib": "libxml2", "purpose": "save XML to file", "category": "serialization"},
    "_xmlDocDumpMemory": {"lib": "libxml2", "purpose": "dump XML doc to memory", "category": "serialization"},
    "_xmlDocDumpFormatMemory": {"lib": "libxml2", "purpose": "dump XML doc to memory (formatted)", "category": "serialization"},
    "_xmlNodeDump": {"lib": "libxml2", "purpose": "dump XML node to buffer", "category": "serialization"},
    "_xmlBufferCreate": {"lib": "libxml2", "purpose": "create XML buffer", "category": "serialization"},
    "_xmlBufferFree": {"lib": "libxml2", "purpose": "free XML buffer", "category": "serialization"},
    "_xmlBufferContent": {"lib": "libxml2", "purpose": "get XML buffer content", "category": "serialization"},
    # --- libxml2: Namespaces ---
    "_xmlNewNs": {"lib": "libxml2", "purpose": "create XML namespace", "category": "serialization"},
    "_xmlSearchNs": {"lib": "libxml2", "purpose": "search XML namespace", "category": "serialization"},
    "_xmlSearchNsByHref": {"lib": "libxml2", "purpose": "search namespace by URI", "category": "serialization"},
    # --- libxml2: XPath ---
    "_xmlXPathNewContext": {"lib": "libxml2", "purpose": "create XPath context", "category": "serialization"},
    "_xmlXPathFreeContext": {"lib": "libxml2", "purpose": "free XPath context", "category": "serialization"},
    "_xmlXPathEvalExpression": {"lib": "libxml2", "purpose": "evaluate XPath expression", "category": "serialization"},
    "_xmlXPathEval": {"lib": "libxml2", "purpose": "evaluate XPath expression (alt)", "category": "serialization"},
    "_xmlXPathFreeObject": {"lib": "libxml2", "purpose": "free XPath result object", "category": "serialization"},
    "_xmlXPathRegisterNs": {"lib": "libxml2", "purpose": "register XPath namespace", "category": "serialization"},
    "_xmlXPathCompile": {"lib": "libxml2", "purpose": "compile XPath expression", "category": "serialization"},
    "_xmlXPathCompiledEval": {"lib": "libxml2", "purpose": "evaluate compiled XPath", "category": "serialization"},
    "_xmlXPathFreeCompExpr": {"lib": "libxml2", "purpose": "free compiled XPath", "category": "serialization"},
    # --- libxml2: SAX/Push parser ---
    "_xmlCreatePushParserCtxt": {"lib": "libxml2", "purpose": "create push parser context", "category": "serialization"},
    "_xmlParseChunk": {"lib": "libxml2", "purpose": "parse XML chunk (push)", "category": "serialization"},
    "_xmlFreeParserCtxt": {"lib": "libxml2", "purpose": "free parser context", "category": "serialization"},
    # --- libxml2: Cleanup/init ---
    "_xmlCleanupParser": {"lib": "libxml2", "purpose": "cleanup global parser state", "category": "serialization"},
    "_xmlInitParser": {"lib": "libxml2", "purpose": "init parser subsystem", "category": "serialization"},
    "_xmlMemoryDump": {"lib": "libxml2", "purpose": "dump memory debug info", "category": "serialization"},
    "_xmlFree": {"lib": "libxml2", "purpose": "free libxml2 memory", "category": "serialization"},
    # --- libxml2: Error ---
    "_xmlGetLastError": {"lib": "libxml2", "purpose": "get last XML error", "category": "serialization"},
    "_xmlResetLastError": {"lib": "libxml2", "purpose": "reset last XML error", "category": "serialization"},
    "_xmlSetStructuredErrorFunc": {"lib": "libxml2", "purpose": "set structured error handler", "category": "serialization"},
    # --- expat ---
    "_XML_ParserCreate": {"lib": "expat", "purpose": "create XML parser", "category": "serialization"},
    "_XML_ParserCreateNS": {"lib": "expat", "purpose": "create XML parser with namespace", "category": "serialization"},
    "_XML_ParserCreate_MM": {"lib": "expat", "purpose": "create XML parser (custom mem)", "category": "serialization"},
    "_XML_ParserFree": {"lib": "expat", "purpose": "free XML parser", "category": "serialization"},
    "_XML_ParserReset": {"lib": "expat", "purpose": "reset XML parser", "category": "serialization"},
    "_XML_Parse": {"lib": "expat", "purpose": "parse XML buffer", "category": "serialization"},
    "_XML_ParseBuffer": {"lib": "expat", "purpose": "parse XML from internal buffer", "category": "serialization"},
    "_XML_GetBuffer": {"lib": "expat", "purpose": "get internal parse buffer", "category": "serialization"},
    "_XML_SetElementHandler": {"lib": "expat", "purpose": "set element start/end handlers", "category": "serialization"},
    "_XML_SetCharacterDataHandler": {"lib": "expat", "purpose": "set character data handler", "category": "serialization"},
    "_XML_SetStartElementHandler": {"lib": "expat", "purpose": "set element start handler", "category": "serialization"},
    "_XML_SetEndElementHandler": {"lib": "expat", "purpose": "set element end handler", "category": "serialization"},
    "_XML_SetCommentHandler": {"lib": "expat", "purpose": "set comment handler", "category": "serialization"},
    "_XML_SetCdataSectionHandler": {"lib": "expat", "purpose": "set CDATA section handler", "category": "serialization"},
    "_XML_SetProcessingInstructionHandler": {"lib": "expat", "purpose": "set PI handler", "category": "serialization"},
    "_XML_SetDefaultHandler": {"lib": "expat", "purpose": "set default handler", "category": "serialization"},
    "_XML_SetUserData": {"lib": "expat", "purpose": "set user data pointer", "category": "serialization"},
    "_XML_GetErrorCode": {"lib": "expat", "purpose": "get parse error code", "category": "serialization"},
    "_XML_ErrorString": {"lib": "expat", "purpose": "get error description", "category": "serialization"},
    "_XML_GetCurrentLineNumber": {"lib": "expat", "purpose": "get current parse line", "category": "serialization"},
    "_XML_GetCurrentColumnNumber": {"lib": "expat", "purpose": "get current parse column", "category": "serialization"},
    "_XML_GetCurrentByteIndex": {"lib": "expat", "purpose": "get current byte offset", "category": "serialization"},
    "_XML_ExpatVersion": {"lib": "expat", "purpose": "expat version string", "category": "info"},
    "_XML_ExpatVersionInfo": {"lib": "expat", "purpose": "expat version struct", "category": "info"},
    "_XML_SetNamespaceDeclHandler": {"lib": "expat", "purpose": "set namespace declaration handler", "category": "serialization"},
    "_XML_SetExternalEntityRefHandler": {"lib": "expat", "purpose": "set external entity handler", "category": "serialization"},
    "_XML_StopParser": {"lib": "expat", "purpose": "stop parsing", "category": "serialization"},
    "_XML_ResumeParser": {"lib": "expat", "purpose": "resume parsing", "category": "serialization"},
    "_XML_GetParsingStatus": {"lib": "expat", "purpose": "get parser status", "category": "serialization"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- POSIX File I/O
# ---------------------------------------------------------------------------

_POSIX_FILE_IO_SIGNATURES: dict[str, dict[str, str]] = {
    # Low-level file descriptors
    "_open": {"lib": "libc", "purpose": "open file descriptor", "category": "file_io"},
    "_close": {"lib": "libc", "purpose": "close file descriptor", "category": "file_io"},
    "_read": {"lib": "libc", "purpose": "read from file descriptor", "category": "file_io"},
    "_write": {"lib": "libc", "purpose": "write to file descriptor", "category": "file_io"},
    "_lseek": {"lib": "libc", "purpose": "seek file descriptor offset", "category": "file_io"},
    "_pread": {"lib": "libc", "purpose": "read at offset (atomic)", "category": "file_io"},
    "_pwrite": {"lib": "libc", "purpose": "write at offset (atomic)", "category": "file_io"},

    # Buffered stdio
    "_fopen": {"lib": "libc", "purpose": "open buffered file stream", "category": "file_io"},
    "_fclose": {"lib": "libc", "purpose": "close buffered file stream", "category": "file_io"},
    "_fread": {"lib": "libc", "purpose": "buffered read from stream", "category": "file_io"},
    "_fwrite": {"lib": "libc", "purpose": "buffered write to stream", "category": "file_io"},
    "_fseek": {"lib": "libc", "purpose": "seek stream position", "category": "file_io"},
    "_ftell": {"lib": "libc", "purpose": "get stream position", "category": "file_io"},
    "_fflush": {"lib": "libc", "purpose": "flush stream buffer", "category": "file_io"},
    "_rewind": {"lib": "libc", "purpose": "rewind stream to beginning", "category": "file_io"},
    "_feof": {"lib": "libc", "purpose": "check end-of-file indicator", "category": "file_io"},
    "_ferror": {"lib": "libc", "purpose": "check stream error indicator", "category": "file_io"},
    "_fgets": {"lib": "libc", "purpose": "read line from stream", "category": "file_io"},
    "_fputs": {"lib": "libc", "purpose": "write string to stream", "category": "file_io"},
    "_fprintf": {"lib": "libc", "purpose": "formatted write to stream", "category": "file_io"},
    "_fscanf": {"lib": "libc", "purpose": "formatted read from stream", "category": "file_io"},
    "_fgetc": {"lib": "libc", "purpose": "read character from stream", "category": "file_io"},
    "_fputc": {"lib": "libc", "purpose": "write character to stream", "category": "file_io"},
    "_ungetc": {"lib": "libc", "purpose": "push character back to stream", "category": "file_io"},

    # File metadata / permissions
    "_stat": {"lib": "libc", "purpose": "get file status by path", "category": "file_io"},
    "_fstat": {"lib": "libc", "purpose": "get file status by fd", "category": "file_io"},
    "_lstat": {"lib": "libc", "purpose": "get symlink status (no follow)", "category": "file_io"},
    "_access": {"lib": "libc", "purpose": "check file accessibility", "category": "file_io"},
    "_chmod": {"lib": "libc", "purpose": "change file permissions", "category": "file_io"},
    "_chown": {"lib": "libc", "purpose": "change file ownership", "category": "file_io"},
    "_chdir": {"lib": "libc", "purpose": "change working directory", "category": "file_io"},
    "_getcwd": {"lib": "libc", "purpose": "get current working directory", "category": "file_io"},

    # Directory operations
    "_mkdir": {"lib": "libc", "purpose": "create directory", "category": "file_io"},
    "_rmdir": {"lib": "libc", "purpose": "remove directory", "category": "file_io"},
    "_opendir": {"lib": "libc", "purpose": "open directory stream", "category": "file_io"},
    "_readdir": {"lib": "libc", "purpose": "read directory entry", "category": "file_io"},
    "_closedir": {"lib": "libc", "purpose": "close directory stream", "category": "file_io"},
    "_scandir": {"lib": "libc", "purpose": "scan directory with filter", "category": "file_io"},

    # File manipulation
    "_rename": {"lib": "libc", "purpose": "rename/move file", "category": "file_io"},
    "_unlink": {"lib": "libc", "purpose": "remove file (delete)", "category": "file_io"},
    "_remove": {"lib": "libc", "purpose": "remove file or directory", "category": "file_io"},
    "_truncate": {"lib": "libc", "purpose": "truncate file by path", "category": "file_io"},
    "_ftruncate": {"lib": "libc", "purpose": "truncate file by fd", "category": "file_io"},

    # Symlinks / paths
    "_symlink": {"lib": "libc", "purpose": "create symbolic link", "category": "file_io"},
    "_readlink": {"lib": "libc", "purpose": "read symbolic link target", "category": "file_io"},
    "_realpath": {"lib": "libc", "purpose": "resolve absolute pathname", "category": "file_io"},

    # File control
    "_fcntl": {"lib": "libc", "purpose": "file descriptor control (lock/flags)", "category": "file_io"},
    "_ioctl": {"lib": "libc", "purpose": "device I/O control", "category": "file_io"},

    # Memory-mapped I/O
    "_mmap": {"lib": "libc", "purpose": "map file/device into memory", "category": "memory"},
    "_munmap": {"lib": "libc", "purpose": "unmap memory region", "category": "memory"},
    "_mprotect": {"lib": "libc", "purpose": "set memory region protection", "category": "memory"},
    "_msync": {"lib": "libc", "purpose": "sync memory-mapped file to disk", "category": "file_io"},
    "_mlock": {"lib": "libc", "purpose": "lock memory pages (prevent swap)", "category": "memory"},
    "_munlock": {"lib": "libc", "purpose": "unlock memory pages", "category": "memory"},

    # Pipe / dup
    "_dup": {"lib": "libc", "purpose": "duplicate file descriptor", "category": "file_io"},
    "_dup2": {"lib": "libc", "purpose": "duplicate fd to specific number", "category": "file_io"},
    "_pipe": {"lib": "libc", "purpose": "create unidirectional pipe", "category": "file_io"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Process Management
# ---------------------------------------------------------------------------

_PROCESS_SIGNATURES: dict[str, dict[str, str]] = {
    # Process creation
    "_fork": {"lib": "libc", "purpose": "create child process (copy)", "category": "process"},
    "_vfork": {"lib": "libc", "purpose": "create child (shared memory, deprecated)", "category": "process"},
    "_execve": {"lib": "libc", "purpose": "execute program (replace process image)", "category": "process"},
    "_execvp": {"lib": "libc", "purpose": "execute program (PATH search)", "category": "process"},
    "_execl": {"lib": "libc", "purpose": "execute program (variadic args)", "category": "process"},
    "_execlp": {"lib": "libc", "purpose": "execute program (PATH + variadic)", "category": "process"},

    # Process wait
    "_waitpid": {"lib": "libc", "purpose": "wait for child process", "category": "process"},
    "_wait": {"lib": "libc", "purpose": "wait for any child process", "category": "process"},
    "_wait4": {"lib": "libc", "purpose": "wait with resource usage", "category": "process"},
    "_waitid": {"lib": "libc", "purpose": "wait for child (extended)", "category": "process"},

    # Signals
    "_kill": {"lib": "libc", "purpose": "send signal to process", "category": "process"},
    "_raise": {"lib": "libc", "purpose": "send signal to self", "category": "process"},
    "_signal": {"lib": "libc", "purpose": "set signal handler (legacy)", "category": "process"},
    "_sigaction": {"lib": "libc", "purpose": "set signal handler (POSIX)", "category": "process"},
    "_sigprocmask": {"lib": "libc", "purpose": "block/unblock signals", "category": "process"},
    "_sigsuspend": {"lib": "libc", "purpose": "suspend until signal", "category": "process"},

    # Process identity
    "_getpid": {"lib": "libc", "purpose": "get process ID", "category": "process"},
    "_getppid": {"lib": "libc", "purpose": "get parent process ID", "category": "process"},
    "_getuid": {"lib": "libc", "purpose": "get real user ID", "category": "process"},
    "_geteuid": {"lib": "libc", "purpose": "get effective user ID", "category": "process"},
    "_getgid": {"lib": "libc", "purpose": "get real group ID", "category": "process"},
    "_getegid": {"lib": "libc", "purpose": "get effective group ID", "category": "process"},

    # Privilege management
    "_setuid": {"lib": "libc", "purpose": "set user ID (privilege change)", "category": "process"},
    "_setgid": {"lib": "libc", "purpose": "set group ID", "category": "process"},
    "_seteuid": {"lib": "libc", "purpose": "set effective user ID", "category": "process"},
    "_setegid": {"lib": "libc", "purpose": "set effective group ID", "category": "process"},

    # POSIX spawn
    "_posix_spawn": {"lib": "libc", "purpose": "spawn new process (POSIX)", "category": "process"},
    "_posix_spawnp": {"lib": "libc", "purpose": "spawn new process (PATH search)", "category": "process"},
    "_posix_spawn_file_actions_addopen": {"lib": "libc", "purpose": "posix_spawn file action: open", "category": "process"},

    # Shell / popen
    "_system": {"lib": "libc", "purpose": "execute shell command", "category": "process"},
    "_popen": {"lib": "libc", "purpose": "open pipe to shell command", "category": "process"},
    "_pclose": {"lib": "libc", "purpose": "close pipe to shell command", "category": "process"},

    # Process exit
    "__exit": {"lib": "libc", "purpose": "immediate process exit (no cleanup)", "category": "process"},
    "_exit": {"lib": "libc", "purpose": "terminate process with cleanup", "category": "process"},
    "_atexit": {"lib": "libc", "purpose": "register exit handler", "category": "process"},
    "_abort": {"lib": "libc", "purpose": "abort process (SIGABRT)", "category": "process"},

    # Session / process group
    "_setsid": {"lib": "libc", "purpose": "create new session (daemon)", "category": "process"},
    "_setpgid": {"lib": "libc", "purpose": "set process group ID", "category": "process"},
    "_getpgid": {"lib": "libc", "purpose": "get process group ID", "category": "process"},
    "_tcsetpgrp": {"lib": "libc", "purpose": "set foreground process group", "category": "process"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- POSIX Threads (pthreads)
# ---------------------------------------------------------------------------

_PTHREAD_SIGNATURES: dict[str, dict[str, str]] = {
    # Thread lifecycle
    "_pthread_create": {"lib": "libpthread", "purpose": "create new thread", "category": "threading"},
    "_pthread_join": {"lib": "libpthread", "purpose": "wait for thread termination", "category": "threading"},
    "_pthread_detach": {"lib": "libpthread", "purpose": "detach thread (auto-cleanup)", "category": "threading"},
    "_pthread_exit": {"lib": "libpthread", "purpose": "terminate calling thread", "category": "threading"},

    # Mutex
    "_pthread_mutex_init": {"lib": "libpthread", "purpose": "initialize mutex", "category": "threading"},
    "_pthread_mutex_lock": {"lib": "libpthread", "purpose": "lock mutex (blocking)", "category": "threading"},
    "_pthread_mutex_trylock": {"lib": "libpthread", "purpose": "try lock mutex (non-blocking)", "category": "threading"},
    "_pthread_mutex_unlock": {"lib": "libpthread", "purpose": "unlock mutex", "category": "threading"},
    "_pthread_mutex_destroy": {"lib": "libpthread", "purpose": "destroy mutex", "category": "threading"},

    # Read-write lock
    "_pthread_rwlock_init": {"lib": "libpthread", "purpose": "initialize read-write lock", "category": "threading"},
    "_pthread_rwlock_rdlock": {"lib": "libpthread", "purpose": "acquire read lock", "category": "threading"},
    "_pthread_rwlock_wrlock": {"lib": "libpthread", "purpose": "acquire write lock", "category": "threading"},
    "_pthread_rwlock_unlock": {"lib": "libpthread", "purpose": "release read-write lock", "category": "threading"},
    "_pthread_rwlock_destroy": {"lib": "libpthread", "purpose": "destroy read-write lock", "category": "threading"},

    # Condition variable
    "_pthread_cond_init": {"lib": "libpthread", "purpose": "initialize condition variable", "category": "threading"},
    "_pthread_cond_wait": {"lib": "libpthread", "purpose": "wait on condition variable", "category": "threading"},
    "_pthread_cond_timedwait": {"lib": "libpthread", "purpose": "timed wait on condition variable", "category": "threading"},
    "_pthread_cond_signal": {"lib": "libpthread", "purpose": "signal one waiting thread", "category": "threading"},
    "_pthread_cond_broadcast": {"lib": "libpthread", "purpose": "signal all waiting threads", "category": "threading"},
    "_pthread_cond_destroy": {"lib": "libpthread", "purpose": "destroy condition variable", "category": "threading"},

    # Thread-local storage
    "_pthread_key_create": {"lib": "libpthread", "purpose": "create thread-local storage key", "category": "threading"},
    "_pthread_key_delete": {"lib": "libpthread", "purpose": "delete thread-local storage key", "category": "threading"},
    "_pthread_getspecific": {"lib": "libpthread", "purpose": "get thread-local value", "category": "threading"},
    "_pthread_setspecific": {"lib": "libpthread", "purpose": "set thread-local value", "category": "threading"},

    # Thread utility
    "_pthread_once": {"lib": "libpthread", "purpose": "one-time initialization", "category": "threading"},
    "_pthread_self": {"lib": "libpthread", "purpose": "get current thread ID", "category": "threading"},
    "_pthread_equal": {"lib": "libpthread", "purpose": "compare thread IDs", "category": "threading"},

    # Thread attributes
    "_pthread_attr_init": {"lib": "libpthread", "purpose": "initialize thread attributes", "category": "threading"},
    "_pthread_attr_destroy": {"lib": "libpthread", "purpose": "destroy thread attributes", "category": "threading"},
    "_pthread_attr_setdetachstate": {"lib": "libpthread", "purpose": "set thread detach state", "category": "threading"},
    "_pthread_attr_setstacksize": {"lib": "libpthread", "purpose": "set thread stack size", "category": "threading"},

    # POSIX semaphores
    "_sem_open": {"lib": "libpthread", "purpose": "open named semaphore", "category": "threading"},
    "_sem_close": {"lib": "libpthread", "purpose": "close named semaphore", "category": "threading"},
    "_sem_wait": {"lib": "libpthread", "purpose": "decrement semaphore (blocking)", "category": "threading"},
    "_sem_trywait": {"lib": "libpthread", "purpose": "try decrement semaphore (non-blocking)", "category": "threading"},
    "_sem_post": {"lib": "libpthread", "purpose": "increment semaphore (signal)", "category": "threading"},
    "_sem_unlink": {"lib": "libpthread", "purpose": "remove named semaphore", "category": "threading"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Memory Management
# ---------------------------------------------------------------------------

_MEMORY_SIGNATURES: dict[str, dict[str, str]] = {
    # Standard C allocator
    "_malloc": {"lib": "libc", "purpose": "allocate heap memory", "category": "memory"},
    "_calloc": {"lib": "libc", "purpose": "allocate zeroed heap memory", "category": "memory"},
    "_realloc": {"lib": "libc", "purpose": "resize heap allocation", "category": "memory"},
    "_free": {"lib": "libc", "purpose": "free heap memory", "category": "memory"},
    "_posix_memalign": {"lib": "libc", "purpose": "aligned memory allocation (POSIX)", "category": "memory"},
    "_aligned_alloc": {"lib": "libc", "purpose": "aligned memory allocation (C11)", "category": "memory"},

    # Virtual memory (POSIX)
    "_madvise": {"lib": "libc", "purpose": "advise kernel on memory usage pattern", "category": "memory"},
    "_mincore": {"lib": "libc", "purpose": "check pages in core (resident)", "category": "memory"},

    # Legacy heap
    "_brk": {"lib": "libc", "purpose": "set data segment break", "category": "memory"},
    "_sbrk": {"lib": "libc", "purpose": "increment data segment break", "category": "memory"},

    # macOS Mach VM
    "_vm_allocate": {"lib": "libSystem", "purpose": "Mach VM region allocation", "category": "memory"},
    "_vm_deallocate": {"lib": "libSystem", "purpose": "Mach VM region deallocation", "category": "memory"},
    "_vm_protect": {"lib": "libSystem", "purpose": "Mach VM region protection change", "category": "memory"},
    "_vm_read": {"lib": "libSystem", "purpose": "Mach VM read from task", "category": "memory"},
    "_vm_write": {"lib": "libSystem", "purpose": "Mach VM write to task", "category": "memory"},
    "_mach_vm_allocate": {"lib": "libSystem", "purpose": "Mach VM allocate (64-bit)", "category": "memory"},
    "_mach_vm_deallocate": {"lib": "libSystem", "purpose": "Mach VM deallocate (64-bit)", "category": "memory"},
    "_mach_vm_protect": {"lib": "libSystem", "purpose": "Mach VM protect (64-bit)", "category": "memory"},

    # Legacy aligned alloc
    "_valloc": {"lib": "libc", "purpose": "page-aligned allocation (deprecated)", "category": "memory"},
    "_memalign": {"lib": "libc", "purpose": "aligned allocation (legacy)", "category": "memory"},

    # Memory operations
    "_memcpy": {"lib": "libc", "purpose": "copy memory block (non-overlapping)", "category": "memory"},
    "_memmove": {"lib": "libc", "purpose": "copy memory block (overlap-safe)", "category": "memory"},
    "_memset": {"lib": "libc", "purpose": "fill memory block with byte", "category": "memory"},
    "_memcmp": {"lib": "libc", "purpose": "compare memory blocks", "category": "memory"},
    "_memchr": {"lib": "libc", "purpose": "search byte in memory", "category": "memory"},
    "_bzero": {"lib": "libc", "purpose": "zero memory block (BSD legacy)", "category": "memory"},
    "_bcopy": {"lib": "libc", "purpose": "copy memory block (BSD legacy)", "category": "memory"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- String / stdlib
# ---------------------------------------------------------------------------

_STRING_STDLIB_SIGNATURES: dict[str, dict[str, str]] = {
    # String operations
    "_strlen": {"lib": "libc", "purpose": "compute string length", "category": "string"},
    "_strcmp": {"lib": "libc", "purpose": "compare strings", "category": "string"},
    "_strncmp": {"lib": "libc", "purpose": "compare strings (bounded)", "category": "string"},
    "_strcpy": {"lib": "libc", "purpose": "copy string (unsafe)", "category": "string"},
    "_strncpy": {"lib": "libc", "purpose": "copy string (bounded)", "category": "string"},
    "_strcat": {"lib": "libc", "purpose": "concatenate strings (unsafe)", "category": "string"},
    "_strncat": {"lib": "libc", "purpose": "concatenate strings (bounded)", "category": "string"},
    "_strstr": {"lib": "libc", "purpose": "find substring", "category": "string"},
    "_strchr": {"lib": "libc", "purpose": "find character in string", "category": "string"},
    "_strrchr": {"lib": "libc", "purpose": "find last character in string", "category": "string"},
    "_strdup": {"lib": "libc", "purpose": "duplicate string (heap alloc)", "category": "string"},
    "_strndup": {"lib": "libc", "purpose": "duplicate string (bounded, heap alloc)", "category": "string"},
    "_strtok": {"lib": "libc", "purpose": "tokenize string (not thread-safe)", "category": "string"},
    "_strtok_r": {"lib": "libc", "purpose": "tokenize string (reentrant)", "category": "string"},

    # Formatted I/O
    "_sprintf": {"lib": "libc", "purpose": "formatted string write (unsafe)", "category": "string"},
    "_snprintf": {"lib": "libc", "purpose": "formatted string write (bounded)", "category": "string"},
    "_sscanf": {"lib": "libc", "purpose": "formatted string parse", "category": "string"},
    "_printf": {"lib": "libc", "purpose": "formatted stdout print", "category": "string"},
    "_puts": {"lib": "libc", "purpose": "write string to stdout", "category": "string"},
    "_putchar": {"lib": "libc", "purpose": "write character to stdout", "category": "string"},

    # String-to-number conversion
    "_atoi": {"lib": "libc", "purpose": "string to int (no error check)", "category": "string"},
    "_atol": {"lib": "libc", "purpose": "string to long (no error check)", "category": "string"},
    "_atof": {"lib": "libc", "purpose": "string to double (no error check)", "category": "string"},
    "_strtol": {"lib": "libc", "purpose": "string to long (with error check)", "category": "string"},
    "_strtoul": {"lib": "libc", "purpose": "string to unsigned long", "category": "string"},
    "_strtod": {"lib": "libc", "purpose": "string to double (with error check)", "category": "string"},
    "_strtoll": {"lib": "libc", "purpose": "string to long long", "category": "string"},
    "_strtoull": {"lib": "libc", "purpose": "string to unsigned long long", "category": "string"},

    # Sorting / searching
    "_qsort": {"lib": "libc", "purpose": "quicksort array", "category": "stdlib"},
    "_bsearch": {"lib": "libc", "purpose": "binary search sorted array", "category": "stdlib"},
    "_abs": {"lib": "libc", "purpose": "absolute value (int)", "category": "stdlib"},
    "_labs": {"lib": "libc", "purpose": "absolute value (long)", "category": "stdlib"},

    # Random number generation
    "_rand": {"lib": "libc", "purpose": "pseudo-random number (not crypto-safe)", "category": "stdlib"},
    "_srand": {"lib": "libc", "purpose": "seed pseudo-random generator", "category": "stdlib"},
    "_random": {"lib": "libc", "purpose": "better pseudo-random (BSD)", "category": "stdlib"},
    "_srandom": {"lib": "libc", "purpose": "seed BSD random generator", "category": "stdlib"},
    "_arc4random": {"lib": "libc", "purpose": "crypto-quality random number", "category": "stdlib"},
    "_arc4random_uniform": {"lib": "libc", "purpose": "crypto-quality random in range", "category": "stdlib"},

    # Environment
    "_getenv": {"lib": "libc", "purpose": "get environment variable", "category": "stdlib"},
    "_setenv": {"lib": "libc", "purpose": "set environment variable", "category": "stdlib"},
    "_unsetenv": {"lib": "libc", "purpose": "remove environment variable", "category": "stdlib"},
    "_putenv": {"lib": "libc", "purpose": "set environment variable (legacy)", "category": "stdlib"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Time
# ---------------------------------------------------------------------------

_TIME_SIGNATURES: dict[str, dict[str, str]] = {
    # Getting time
    "_time": {"lib": "libc", "purpose": "get calendar time (seconds)", "category": "time"},
    "_gettimeofday": {"lib": "libc", "purpose": "get time with microseconds", "category": "time"},
    "_clock_gettime": {"lib": "libc", "purpose": "get time with nanoseconds (POSIX)", "category": "time"},
    "_clock_getres": {"lib": "libc", "purpose": "get clock resolution", "category": "time"},

    # Time conversion
    "_localtime": {"lib": "libc", "purpose": "convert to local time struct", "category": "time"},
    "_localtime_r": {"lib": "libc", "purpose": "convert to local time (reentrant)", "category": "time"},
    "_gmtime": {"lib": "libc", "purpose": "convert to UTC time struct", "category": "time"},
    "_gmtime_r": {"lib": "libc", "purpose": "convert to UTC time (reentrant)", "category": "time"},
    "_mktime": {"lib": "libc", "purpose": "convert time struct to calendar time", "category": "time"},

    # Time formatting
    "_strftime": {"lib": "libc", "purpose": "format time as string", "category": "time"},
    "_strptime": {"lib": "libc", "purpose": "parse time from string", "category": "time"},

    # Sleep / delay
    "_nanosleep": {"lib": "libc", "purpose": "sleep with nanosecond precision", "category": "time"},
    "_usleep": {"lib": "libc", "purpose": "sleep with microsecond precision", "category": "time"},
    "_sleep": {"lib": "libc", "purpose": "sleep with second precision", "category": "time"},

    # macOS Mach time
    "_mach_absolute_time": {"lib": "libSystem", "purpose": "high-resolution monotonic time (macOS)", "category": "time"},
    "_mach_timebase_info": {"lib": "libSystem", "purpose": "Mach time to nanoseconds conversion factor", "category": "time"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Dynamic Loading (dlopen / dyld)
# ---------------------------------------------------------------------------

_DYNLOAD_SIGNATURES: dict[str, dict[str, str]] = {
    # POSIX dynamic loading
    "_dlopen": {"lib": "libdl", "purpose": "load shared library at runtime", "category": "dynload"},
    "_dlclose": {"lib": "libdl", "purpose": "unload shared library", "category": "dynload"},
    "_dlsym": {"lib": "libdl", "purpose": "lookup symbol in shared library", "category": "dynload"},
    "_dlerror": {"lib": "libdl", "purpose": "get dynamic loader error string", "category": "dynload"},
    "_dladdr": {"lib": "libdl", "purpose": "resolve address to symbol info", "category": "dynload"},

    # macOS legacy NSModule
    "_NSLookupSymbolInModule": {"lib": "libSystem", "purpose": "lookup symbol in NSModule (legacy)", "category": "dynload"},
    "_NSAddressOfSymbol": {"lib": "libSystem", "purpose": "get address of NSSymbol (legacy)", "category": "dynload"},

    # macOS dyld
    "__dyld_get_image_name": {"lib": "libdyld", "purpose": "get loaded image path by index", "category": "dynload"},
    "__dyld_image_count": {"lib": "libdyld", "purpose": "get number of loaded images", "category": "dynload"},
    "__dyld_get_image_header": {"lib": "libdyld", "purpose": "get Mach-O header of loaded image", "category": "dynload"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- Error / Locale / Misc
# ---------------------------------------------------------------------------

_ERROR_LOCALE_MISC_SIGNATURES: dict[str, dict[str, str]] = {
    # Error reporting
    "_strerror": {"lib": "libc", "purpose": "convert errno to error string", "category": "error"},
    "_strerror_r": {"lib": "libc", "purpose": "convert errno to error string (reentrant)", "category": "error"},
    "_perror": {"lib": "libc", "purpose": "print error message to stderr", "category": "error"},

    # Locale
    "_setlocale": {"lib": "libc", "purpose": "set program locale", "category": "locale"},
    "_localeconv": {"lib": "libc", "purpose": "get locale numeric formatting", "category": "locale"},

    # Character classification
    "_isalpha": {"lib": "libc", "purpose": "test for alphabetic character", "category": "ctype"},
    "_isdigit": {"lib": "libc", "purpose": "test for decimal digit", "category": "ctype"},
    "_isalnum": {"lib": "libc", "purpose": "test for alphanumeric character", "category": "ctype"},
    "_isspace": {"lib": "libc", "purpose": "test for whitespace character", "category": "ctype"},
    "_toupper": {"lib": "libc", "purpose": "convert to uppercase", "category": "ctype"},
    "_tolower": {"lib": "libc", "purpose": "convert to lowercase", "category": "ctype"},

    # Assertions
    "_assert": {"lib": "libc", "purpose": "runtime assertion check", "category": "error"},
    "___assert_rtn": {"lib": "libc", "purpose": "macOS assertion failure handler", "category": "error"},

    # Syslog
    "_syslog": {"lib": "libc", "purpose": "write to system log", "category": "logging"},
    "_openlog": {"lib": "libc", "purpose": "open syslog connection", "category": "logging"},
    "_closelog": {"lib": "libc", "purpose": "close syslog connection", "category": "logging"},

    # System info
    "_sysctl": {"lib": "libc", "purpose": "get/set kernel parameters", "category": "system"},
    "_sysctlbyname": {"lib": "libc", "purpose": "get/set kernel parameters by name", "category": "system"},
}



# ---------------------------------------------------------------------------
# Builtin Signature Database -- POSIX Networking
# ---------------------------------------------------------------------------

_POSIX_NETWORKING_SIGNATURES: dict[str, dict[str, str]] = {
    "_socket": {"lib": "libc", "purpose": "create socket", "category": "network"},
    "_bind": {"lib": "libc", "purpose": "bind socket to address", "category": "network"},
    "_listen": {"lib": "libc", "purpose": "listen for connections", "category": "network"},
    "_accept": {"lib": "libc", "purpose": "accept incoming connection", "category": "network"},
    "_connect": {"lib": "libc", "purpose": "connect to remote host", "category": "network"},
    "_shutdown": {"lib": "libc", "purpose": "shutdown socket", "category": "network"},
    "_close": {"lib": "libc", "purpose": "close file descriptor", "category": "io"},
    "_send": {"lib": "libc", "purpose": "send data on socket", "category": "network"},
    "_recv": {"lib": "libc", "purpose": "receive data from socket", "category": "network"},
    "_sendto": {"lib": "libc", "purpose": "send datagram to address", "category": "network"},
    "_recvfrom": {"lib": "libc", "purpose": "receive datagram with sender", "category": "network"},
    "_sendmsg": {"lib": "libc", "purpose": "send message with ancillary data", "category": "network"},
    "_recvmsg": {"lib": "libc", "purpose": "receive message with ancillary data", "category": "network"},
    "_setsockopt": {"lib": "libc", "purpose": "set socket option", "category": "network"},
    "_getsockopt": {"lib": "libc", "purpose": "get socket option", "category": "network"},
    "_getsockname": {"lib": "libc", "purpose": "get local socket address", "category": "network"},
    "_getpeername": {"lib": "libc", "purpose": "get remote peer address", "category": "network"},
    "_select": {"lib": "libc", "purpose": "synchronous I/O multiplexing", "category": "network"},
    "_poll": {"lib": "libc", "purpose": "poll file descriptors", "category": "network"},
    # epoll Linux-only syscall ailesi: linux_network category ile ELF-only filtre
    "_epoll_create": {"lib": "libc", "purpose": "create epoll instance", "category": "linux_network"},
    "_epoll_create1": {"lib": "libc", "purpose": "create epoll instance (flags)", "category": "linux_network"},
    "_epoll_ctl": {"lib": "libc", "purpose": "control epoll instance", "category": "linux_network"},
    "_epoll_wait": {"lib": "libc", "purpose": "wait for epoll events", "category": "linux_network"},
    # kqueue BSD/macOS-only: macos_io category ile Mach-O-only filtre
    "_kqueue": {"lib": "libc", "purpose": "create kqueue instance (BSD)", "category": "macos_io"},
    "_kevent": {"lib": "libc", "purpose": "register/poll kqueue events", "category": "macos_io"},
    "_kevent64": {"lib": "libc", "purpose": "register/poll kqueue events (64-bit)", "category": "macos_io"},
    "_getaddrinfo": {"lib": "libc", "purpose": "DNS name resolution", "category": "network"},
    "_freeaddrinfo": {"lib": "libc", "purpose": "free addrinfo list", "category": "network"},
    "_gai_strerror": {"lib": "libc", "purpose": "getaddrinfo error string", "category": "network"},
    "_getnameinfo": {"lib": "libc", "purpose": "reverse DNS lookup", "category": "network"},
    "_gethostbyname": {"lib": "libc", "purpose": "DNS lookup (deprecated)", "category": "network"},
    "_gethostbyaddr": {"lib": "libc", "purpose": "reverse DNS (deprecated)", "category": "network"},
    "_inet_aton": {"lib": "libc", "purpose": "dotted-decimal to in_addr", "category": "network"},
    "_inet_ntoa": {"lib": "libc", "purpose": "in_addr to dotted-decimal", "category": "network"},
    "_inet_pton": {"lib": "libc", "purpose": "text to binary address", "category": "network"},
    "_inet_ntop": {"lib": "libc", "purpose": "binary address to text", "category": "network"},
    "_htons": {"lib": "libc", "purpose": "host to network short", "category": "network"},
    "_htonl": {"lib": "libc", "purpose": "host to network long", "category": "network"},
    "_ntohs": {"lib": "libc", "purpose": "network to host short", "category": "network"},
    "_ntohl": {"lib": "libc", "purpose": "network to host long", "category": "network"},
    "_socketpair": {"lib": "libc", "purpose": "create connected socket pair", "category": "ipc"},
    "_pipe": {"lib": "libc", "purpose": "create pipe", "category": "ipc"},
    "_pipe2": {"lib": "libc", "purpose": "create pipe (with flags)", "category": "ipc"},
}


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
# Builtin Signature Database -- nghttp2 (HTTP/2)
# ---------------------------------------------------------------------------

_NGHTTP2_SIGNATURES: dict[str, dict[str, str]] = {
    "_nghttp2_session_client_new": {"lib": "nghttp2", "purpose": "create HTTP/2 client session", "category": "network"},
    "_nghttp2_session_server_new": {"lib": "nghttp2", "purpose": "create HTTP/2 server session", "category": "network"},
    "_nghttp2_session_del": {"lib": "nghttp2", "purpose": "delete HTTP/2 session", "category": "network"},
    "_nghttp2_session_recv": {"lib": "nghttp2", "purpose": "receive HTTP/2 frames", "category": "network"},
    "_nghttp2_session_send": {"lib": "nghttp2", "purpose": "send HTTP/2 frames", "category": "network"},
    "_nghttp2_session_mem_recv": {"lib": "nghttp2", "purpose": "process HTTP/2 data from buffer", "category": "network"},
    "_nghttp2_session_mem_send": {"lib": "nghttp2", "purpose": "serialize HTTP/2 frames to buffer", "category": "network"},
    "_nghttp2_submit_request": {"lib": "nghttp2", "purpose": "submit HTTP/2 request", "category": "network"},
    "_nghttp2_submit_response": {"lib": "nghttp2", "purpose": "submit HTTP/2 response", "category": "network"},
    "_nghttp2_submit_headers": {"lib": "nghttp2", "purpose": "submit HTTP/2 headers", "category": "network"},
    "_nghttp2_submit_data": {"lib": "nghttp2", "purpose": "submit HTTP/2 data frame", "category": "network"},
    "_nghttp2_submit_settings": {"lib": "nghttp2", "purpose": "submit HTTP/2 SETTINGS", "category": "network"},
    "_nghttp2_submit_ping": {"lib": "nghttp2", "purpose": "submit HTTP/2 PING", "category": "network"},
    "_nghttp2_submit_goaway": {"lib": "nghttp2", "purpose": "submit HTTP/2 GOAWAY", "category": "network"},
    "_nghttp2_submit_rst_stream": {"lib": "nghttp2", "purpose": "submit HTTP/2 RST_STREAM", "category": "network"},
    "_nghttp2_submit_priority": {"lib": "nghttp2", "purpose": "submit HTTP/2 PRIORITY", "category": "network"},
    "_nghttp2_submit_window_update": {"lib": "nghttp2", "purpose": "submit HTTP/2 WINDOW_UPDATE", "category": "network"},
    "_nghttp2_session_want_read": {"lib": "nghttp2", "purpose": "check if session wants to read", "category": "network"},
    "_nghttp2_session_want_write": {"lib": "nghttp2", "purpose": "check if session wants to write", "category": "network"},
    "_nghttp2_session_get_stream_user_data": {"lib": "nghttp2", "purpose": "get stream user data", "category": "network"},
    "_nghttp2_hd_inflate_new": {"lib": "nghttp2", "purpose": "HPACK inflater creation", "category": "network"},
    "_nghttp2_hd_inflate_hd": {"lib": "nghttp2", "purpose": "HPACK header decompression", "category": "network"},
    "_nghttp2_hd_inflate_del": {"lib": "nghttp2", "purpose": "HPACK inflater cleanup", "category": "network"},
    "_nghttp2_hd_deflate_new": {"lib": "nghttp2", "purpose": "HPACK deflater creation", "category": "network"},
    "_nghttp2_hd_deflate_hd": {"lib": "nghttp2", "purpose": "HPACK header compression", "category": "network"},
    "_nghttp2_hd_deflate_del": {"lib": "nghttp2", "purpose": "HPACK deflater cleanup", "category": "network"},
    "_nghttp2_strerror": {"lib": "nghttp2", "purpose": "error string lookup", "category": "network"},
    "_nghttp2_version": {"lib": "nghttp2", "purpose": "nghttp2 version info", "category": "network"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- libwebsockets (WebSocket)
# ---------------------------------------------------------------------------

_WEBSOCKET_SIGNATURES: dict[str, dict[str, str]] = {
    "_lws_create_context": {"lib": "libwebsockets", "purpose": "create LWS context", "category": "network"},
    "_lws_context_destroy": {"lib": "libwebsockets", "purpose": "destroy LWS context", "category": "network"},
    "_lws_service": {"lib": "libwebsockets", "purpose": "service pending WebSocket events", "category": "network"},
    "_lws_callback_on_writable": {"lib": "libwebsockets", "purpose": "request writable callback", "category": "network"},
    "_lws_write": {"lib": "libwebsockets", "purpose": "write WebSocket frame", "category": "network"},
    "_lws_remaining_packet_payload": {"lib": "libwebsockets", "purpose": "remaining payload bytes", "category": "network"},
    "_lws_client_connect_via_info": {"lib": "libwebsockets", "purpose": "WebSocket client connect", "category": "network"},
    "_lws_cancel_service": {"lib": "libwebsockets", "purpose": "cancel LWS service", "category": "network"},
    "_lws_set_log_level": {"lib": "libwebsockets", "purpose": "set LWS log level", "category": "network"},
    "_lws_get_protocol": {"lib": "libwebsockets", "purpose": "get protocol for connection", "category": "network"},
    "_lws_frame_is_binary": {"lib": "libwebsockets", "purpose": "check if frame is binary", "category": "network"},
    "_lws_is_final_fragment": {"lib": "libwebsockets", "purpose": "check if last fragment", "category": "network"},
    "_lws_ring_create": {"lib": "libwebsockets", "purpose": "create ring buffer", "category": "network"},
    "_lws_ring_destroy": {"lib": "libwebsockets", "purpose": "destroy ring buffer", "category": "network"},
    "_lws_ring_insert": {"lib": "libwebsockets", "purpose": "insert into ring buffer", "category": "network"},
    "_lws_ring_consume": {"lib": "libwebsockets", "purpose": "consume from ring buffer", "category": "network"},
    "_lws_hdr_total_length": {"lib": "libwebsockets", "purpose": "header total length", "category": "network"},
    "_lws_hdr_copy": {"lib": "libwebsockets", "purpose": "copy header value", "category": "network"},
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
# Builtin Signature Database -- macOS Networking (Network.framework, CFNetwork)
# ---------------------------------------------------------------------------

_MACOS_NETWORKING_SIGNATURES: dict[str, dict[str, str]] = {
    "_CFSocketCreate": {"lib": "CFNetwork", "purpose": "create CFSocket", "category": "network"},
    "_CFSocketCreateWithNative": {"lib": "CFNetwork", "purpose": "CFSocket from native fd", "category": "network"},
    "_CFSocketGetNative": {"lib": "CFNetwork", "purpose": "get native fd from CFSocket", "category": "network"},
    "_CFSocketInvalidate": {"lib": "CFNetwork", "purpose": "invalidate CFSocket", "category": "network"},
    "_CFSocketSetAddress": {"lib": "CFNetwork", "purpose": "set CFSocket address", "category": "network"},
    "_CFSocketCopyAddress": {"lib": "CFNetwork", "purpose": "copy CFSocket address", "category": "network"},
    "_CFSocketCreateRunLoopSource": {"lib": "CFNetwork", "purpose": "CFSocket run loop source", "category": "network"},
    "_CFStreamCreatePairWithSocketToHost": {"lib": "CFNetwork", "purpose": "create stream pair to host", "category": "network"},
    "_CFReadStreamOpen": {"lib": "CFNetwork", "purpose": "open CFReadStream", "category": "network"},
    "_CFReadStreamClose": {"lib": "CFNetwork", "purpose": "close CFReadStream", "category": "network"},
    "_CFReadStreamRead": {"lib": "CFNetwork", "purpose": "read from CFReadStream", "category": "network"},
    "_CFReadStreamHasBytesAvailable": {"lib": "CFNetwork", "purpose": "check CFReadStream bytes", "category": "network"},
    "_CFWriteStreamOpen": {"lib": "CFNetwork", "purpose": "open CFWriteStream", "category": "network"},
    "_CFWriteStreamClose": {"lib": "CFNetwork", "purpose": "close CFWriteStream", "category": "network"},
    "_CFWriteStreamWrite": {"lib": "CFNetwork", "purpose": "write to CFWriteStream", "category": "network"},
    "_CFWriteStreamCanAcceptBytes": {"lib": "CFNetwork", "purpose": "check CFWriteStream capacity", "category": "network"},
    "_CFHTTPMessageCreateRequest": {"lib": "CFNetwork", "purpose": "create HTTP request message", "category": "network"},
    "_CFHTTPMessageCreateResponse": {"lib": "CFNetwork", "purpose": "create HTTP response message", "category": "network"},
    "_CFHTTPMessageSetBody": {"lib": "CFNetwork", "purpose": "set HTTP message body", "category": "network"},
    "_CFHTTPMessageSetHeaderFieldValue": {"lib": "CFNetwork", "purpose": "set HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyHeaderFieldValue": {"lib": "CFNetwork", "purpose": "get HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyAllHeaderFields": {"lib": "CFNetwork", "purpose": "get all HTTP headers", "category": "network"},
    "_CFHTTPMessageGetResponseStatusCode": {"lib": "CFNetwork", "purpose": "get HTTP status code", "category": "network"},
    "_CFHTTPMessageCopyBody": {"lib": "CFNetwork", "purpose": "get HTTP message body", "category": "network"},
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data from connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "connection state handler", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "listener state handler", "category": "network"},
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP params", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP params", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint", "category": "network"},
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel path monitor", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
}


# ---------------------------------------------------------------------------
# Builtin Signature Database -- IPC / XPC (Extended)
# ---------------------------------------------------------------------------

_IPC_XPC_SIGNATURES: dict[str, dict[str, str]] = {
    "_xpc_connection_create": {"lib": "libxpc", "purpose": "create XPC connection", "category": "ipc"},
    "_xpc_connection_suspend": {"lib": "libxpc", "purpose": "suspend XPC connection", "category": "ipc"},
    "_xpc_connection_send_message_with_reply_sync": {"lib": "libxpc", "purpose": "XPC send + sync reply", "category": "ipc"},
    "_xpc_connection_set_target_queue": {"lib": "libxpc", "purpose": "XPC set target queue", "category": "ipc"},
    "_xpc_connection_get_pid": {"lib": "libxpc", "purpose": "XPC get peer PID", "category": "ipc"},
    "_xpc_connection_get_euid": {"lib": "libxpc", "purpose": "XPC get peer EUID", "category": "ipc"},
    "_xpc_connection_get_egid": {"lib": "libxpc", "purpose": "XPC get peer EGID", "category": "ipc"},
    "_xpc_dictionary_create_reply": {"lib": "libxpc", "purpose": "create XPC reply dict", "category": "ipc"},
    "_xpc_dictionary_set_int64": {"lib": "libxpc", "purpose": "XPC dict set int64", "category": "ipc"},
    "_xpc_dictionary_set_uint64": {"lib": "libxpc", "purpose": "XPC dict set uint64", "category": "ipc"},
    "_xpc_dictionary_set_bool": {"lib": "libxpc", "purpose": "XPC dict set bool", "category": "ipc"},
    "_xpc_dictionary_set_double": {"lib": "libxpc", "purpose": "XPC dict set double", "category": "ipc"},
    "_xpc_dictionary_set_value": {"lib": "libxpc", "purpose": "XPC dict set value", "category": "ipc"},
    "_xpc_dictionary_get_int64": {"lib": "libxpc", "purpose": "XPC dict get int64", "category": "ipc"},
    "_xpc_dictionary_get_uint64": {"lib": "libxpc", "purpose": "XPC dict get uint64", "category": "ipc"},
    "_xpc_dictionary_get_bool": {"lib": "libxpc", "purpose": "XPC dict get bool", "category": "ipc"},
    "_xpc_dictionary_get_double": {"lib": "libxpc", "purpose": "XPC dict get double", "category": "ipc"},
    "_xpc_dictionary_get_value": {"lib": "libxpc", "purpose": "XPC dict get value", "category": "ipc"},
    "_xpc_dictionary_get_count": {"lib": "libxpc", "purpose": "XPC dict entry count", "category": "ipc"},
    "_xpc_dictionary_apply": {"lib": "libxpc", "purpose": "XPC dict iterate", "category": "ipc"},
    "_xpc_array_create": {"lib": "libxpc", "purpose": "create XPC array", "category": "ipc"},
    "_xpc_array_append_value": {"lib": "libxpc", "purpose": "XPC array append", "category": "ipc"},
    "_xpc_array_get_count": {"lib": "libxpc", "purpose": "XPC array count", "category": "ipc"},
    "_xpc_array_get_value": {"lib": "libxpc", "purpose": "XPC array get value", "category": "ipc"},
    "_xpc_array_apply": {"lib": "libxpc", "purpose": "XPC array iterate", "category": "ipc"},
    "_xpc_string_create": {"lib": "libxpc", "purpose": "create XPC string", "category": "ipc"},
    "_xpc_string_get_string_ptr": {"lib": "libxpc", "purpose": "get XPC string ptr", "category": "ipc"},
    "_xpc_string_get_length": {"lib": "libxpc", "purpose": "get XPC string length", "category": "ipc"},
    "_xpc_int64_create": {"lib": "libxpc", "purpose": "create XPC int64", "category": "ipc"},
    "_xpc_int64_get_value": {"lib": "libxpc", "purpose": "get XPC int64 value", "category": "ipc"},
    "_xpc_uint64_create": {"lib": "libxpc", "purpose": "create XPC uint64", "category": "ipc"},
    "_xpc_uint64_get_value": {"lib": "libxpc", "purpose": "get XPC uint64 value", "category": "ipc"},
    "_xpc_bool_create": {"lib": "libxpc", "purpose": "create XPC bool", "category": "ipc"},
    "_xpc_bool_get_value": {"lib": "libxpc", "purpose": "get XPC bool value", "category": "ipc"},
    "_xpc_data_create": {"lib": "libxpc", "purpose": "create XPC data", "category": "ipc"},
    "_xpc_data_get_bytes_ptr": {"lib": "libxpc", "purpose": "get XPC data bytes", "category": "ipc"},
    "_xpc_data_get_length": {"lib": "libxpc", "purpose": "get XPC data length", "category": "ipc"},
    "_xpc_double_create": {"lib": "libxpc", "purpose": "create XPC double", "category": "ipc"},
    "_xpc_double_get_value": {"lib": "libxpc", "purpose": "get XPC double value", "category": "ipc"},
    "_xpc_date_create": {"lib": "libxpc", "purpose": "create XPC date", "category": "ipc"},
    "_xpc_date_get_value": {"lib": "libxpc", "purpose": "get XPC date value", "category": "ipc"},
    "_xpc_release": {"lib": "libxpc", "purpose": "release XPC object", "category": "ipc"},
    "_xpc_retain": {"lib": "libxpc", "purpose": "retain XPC object", "category": "ipc"},
    "_xpc_copy_description": {"lib": "libxpc", "purpose": "XPC object description", "category": "ipc"},
    "_xpc_get_type": {"lib": "libxpc", "purpose": "get XPC object type", "category": "ipc"},
    "_xpc_equal": {"lib": "libxpc", "purpose": "compare XPC objects", "category": "ipc"},
    "_xpc_hash": {"lib": "libxpc", "purpose": "XPC object hash", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCConnection": {"lib": "Foundation", "purpose": "NSXPCConnection class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCInterface": {"lib": "Foundation", "purpose": "NSXPCInterface class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCListener": {"lib": "Foundation", "purpose": "NSXPCListener class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCListenerEndpoint": {"lib": "Foundation", "purpose": "NSXPCListenerEndpoint class ref", "category": "ipc"},
}


# ---------------------------------------------------------------------------
# C++ STL (libc++ mangled names)
# ---------------------------------------------------------------------------

_CPP_STL_SIGNATURES: dict[str, dict[str, str]] = {
    # std::string
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::string default constructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1EPKc": {
        "lib": "libc++", "purpose": "std::string(const char*) constructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::string destructor", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc": {
        "lib": "libc++", "purpose": "std::string::append(const char*)", "category": "stl",
    },
    "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc": {
        "lib": "libc++", "purpose": "std::string::assign(const char*)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcm": {
        "lib": "libc++", "purpose": "std::string::find(const char*, pos)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6substrEmm": {
        "lib": "libc++", "purpose": "std::string::substr(pos, len)", "category": "stl",
    },
    "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv": {
        "lib": "libc++", "purpose": "std::string::c_str()", "category": "stl",
    },

    # std::vector (partial mangled prefixes -- pattern match yapilabilir)
    "__ZNSt3__16vectorI": {
        "lib": "libc++", "purpose": "std::vector<T> method (partial mangled)", "category": "stl",
    },

    # std::map
    "__ZNSt3__13mapI": {
        "lib": "libc++", "purpose": "std::map<K,V> method (partial mangled)", "category": "stl",
    },

    # std::unordered_map
    "__ZNSt3__113unordered_mapI": {
        "lib": "libc++", "purpose": "std::unordered_map<K,V> method (partial mangled)", "category": "stl",
    },

    # std::list
    "__ZNSt3__14listI": {
        "lib": "libc++", "purpose": "std::list<T> method (partial mangled)", "category": "stl",
    },

    # std::deque
    "__ZNSt3__15dequeI": {
        "lib": "libc++", "purpose": "std::deque<T> method (partial mangled)", "category": "stl",
    },

    # std::set
    "__ZNSt3__13setI": {
        "lib": "libc++", "purpose": "std::set<T> method (partial mangled)", "category": "stl",
    },

    # std::sort
    "__ZNSt3__14sortI": {
        "lib": "libc++", "purpose": "std::sort<Iter> (partial mangled)", "category": "stl",
    },

    # std::mutex
    "__ZNSt3__15mutexC1Ev": {
        "lib": "libc++", "purpose": "std::mutex default constructor", "category": "stl",
    },
    "__ZNSt3__15mutex4lockEv": {
        "lib": "libc++", "purpose": "std::mutex::lock()", "category": "stl",
    },
    "__ZNSt3__15mutex6unlockEv": {
        "lib": "libc++", "purpose": "std::mutex::unlock()", "category": "stl",
    },
    "__ZNSt3__15mutex8try_lockEv": {
        "lib": "libc++", "purpose": "std::mutex::try_lock()", "category": "stl",
    },
    "__ZNSt3__15mutexD1Ev": {
        "lib": "libc++", "purpose": "std::mutex destructor", "category": "stl",
    },

    # std::condition_variable
    "__ZNSt3__118condition_variableC1Ev": {
        "lib": "libc++", "purpose": "std::condition_variable constructor", "category": "stl",
    },
    "__ZNSt3__118condition_variableD1Ev": {
        "lib": "libc++", "purpose": "std::condition_variable destructor", "category": "stl",
    },
    "__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE": {
        "lib": "libc++", "purpose": "std::condition_variable::wait(unique_lock&)", "category": "stl",
    },
    "__ZNSt3__118condition_variable10notify_oneEv": {
        "lib": "libc++", "purpose": "std::condition_variable::notify_one()", "category": "stl",
    },
    "__ZNSt3__118condition_variable10notify_allEv": {
        "lib": "libc++", "purpose": "std::condition_variable::notify_all()", "category": "stl",
    },

    # std::thread
    "__ZNSt3__16threadC1I": {
        "lib": "libc++", "purpose": "std::thread constructor (partial mangled)", "category": "stl",
    },
    "__ZNSt3__16threadD1Ev": {
        "lib": "libc++", "purpose": "std::thread destructor", "category": "stl",
    },
    "__ZNSt3__16thread4joinEv": {
        "lib": "libc++", "purpose": "std::thread::join()", "category": "stl",
    },
    "__ZNSt3__16thread6detachEv": {
        "lib": "libc++", "purpose": "std::thread::detach()", "category": "stl",
    },

    # I/O streams
    "__ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::ifstream default constructor", "category": "stl",
    },
    "__ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::ifstream destructor", "category": "stl",
    },
    "__ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::ofstream default constructor", "category": "stl",
    },
    "__ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::ofstream destructor", "category": "stl",
    },
    "__ZNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev": {
        "lib": "libc++", "purpose": "std::stringstream default constructor", "category": "stl",
    },
    "__ZNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev": {
        "lib": "libc++", "purpose": "std::stringstream destructor", "category": "stl",
    },

    # std::cerr, std::cout globals
    "__ZNSt3__14cerrE": {
        "lib": "libc++", "purpose": "std::cerr global error stream", "category": "stl",
    },
    "__ZNSt3__14coutE": {
        "lib": "libc++", "purpose": "std::cout global output stream", "category": "stl",
    },
    "__ZNSt3__14clogE": {
        "lib": "libc++", "purpose": "std::clog global log stream", "category": "stl",
    },
    "__ZNSt3__14cinE": {
        "lib": "libc++", "purpose": "std::cin global input stream", "category": "stl",
    },

    # C++ exception handling (ABI)
    "___cxa_throw": {
        "lib": "libc++abi", "purpose": "C++ throw exception", "category": "stl",
    },
    "___cxa_begin_catch": {
        "lib": "libc++abi", "purpose": "C++ catch block begin", "category": "stl",
    },
    "___cxa_end_catch": {
        "lib": "libc++abi", "purpose": "C++ catch block end", "category": "stl",
    },
    "___cxa_rethrow": {
        "lib": "libc++abi", "purpose": "C++ rethrow exception", "category": "stl",
    },
    "___cxa_allocate_exception": {
        "lib": "libc++abi", "purpose": "C++ allocate exception object", "category": "stl",
    },
    "___cxa_free_exception": {
        "lib": "libc++abi", "purpose": "C++ free exception object", "category": "stl",
    },
    "___cxa_pure_virtual": {
        "lib": "libc++abi", "purpose": "C++ pure virtual function called (abort)", "category": "stl",
    },

    # terminate / unexpected
    "__ZSt9terminatev": {
        "lib": "libc++abi", "purpose": "std::terminate()", "category": "stl",
    },
    "__ZSt14set_unexpectedPFvvE": {
        "lib": "libc++abi", "purpose": "std::set_unexpected(handler)", "category": "stl",
    },
    "__ZSt13set_terminatePFvvE": {
        "lib": "libc++abi", "purpose": "std::set_terminate(handler)", "category": "stl",
    },

    # operator new / delete
    "__Znwm": {
        "lib": "libc++", "purpose": "operator new(size_t)", "category": "stl",
    },
    "__ZnwmRKSt9nothrow_t": {
        "lib": "libc++", "purpose": "operator new(size_t, nothrow_t)", "category": "stl",
    },
    "__Znam": {
        "lib": "libc++", "purpose": "operator new[](size_t)", "category": "stl",
    },
    "__ZdlPv": {
        "lib": "libc++", "purpose": "operator delete(void*)", "category": "stl",
    },
    "__ZdlPvm": {
        "lib": "libc++", "purpose": "operator delete(void*, size_t)", "category": "stl",
    },
    "__ZdaPv": {
        "lib": "libc++", "purpose": "operator delete[](void*)", "category": "stl",
    },

    # RTTI
    "__ZTI": {
        "lib": "libc++abi", "purpose": "C++ typeinfo (partial mangled prefix)", "category": "stl",
    },
    "__ZTS": {
        "lib": "libc++abi", "purpose": "C++ typeinfo name (partial mangled prefix)", "category": "stl",
    },
    "__ZTV": {
        "lib": "libc++abi", "purpose": "C++ vtable (partial mangled prefix)", "category": "stl",
    },

    # std::shared_ptr / weak_ptr internals
    "__ZNSt3__120__shared_ptr_emplace": {
        "lib": "libc++", "purpose": "std::shared_ptr emplace (partial mangled)", "category": "stl",
    },
    "__ZNSt3__115__thread_struct": {
        "lib": "libc++", "purpose": "std::__thread_struct internal (partial mangled)", "category": "stl",
    },
}


# ---------------------------------------------------------------------------
# OpenGL / Metal / GPU (~60)
# ---------------------------------------------------------------------------

_OPENGL_METAL_GPU_SIGNATURES: dict[str, dict[str, str]] = {
    "_glGenBuffers": {"lib": "OpenGL", "purpose": "generate buffer object names", "category": "graphics"},
    "_glBindBuffer": {"lib": "OpenGL", "purpose": "bind a named buffer object", "category": "graphics"},
    "_glBufferData": {"lib": "OpenGL", "purpose": "create/initialize buffer data store", "category": "graphics"},
    "_glDeleteBuffers": {"lib": "OpenGL", "purpose": "delete named buffer objects", "category": "graphics"},
    "_glGenTextures": {"lib": "OpenGL", "purpose": "generate texture names", "category": "graphics"},
    "_glBindTexture": {"lib": "OpenGL", "purpose": "bind a named texture", "category": "graphics"},
    "_glTexImage2D": {"lib": "OpenGL", "purpose": "specify 2D texture image", "category": "graphics"},
    "_glTexParameteri": {"lib": "OpenGL", "purpose": "set texture parameter (integer)", "category": "graphics"},
    "_glDeleteTextures": {"lib": "OpenGL", "purpose": "delete named textures", "category": "graphics"},
    "_glCreateShader": {"lib": "OpenGL", "purpose": "create a shader object", "category": "graphics"},
    "_glShaderSource": {"lib": "OpenGL", "purpose": "set shader source code", "category": "graphics"},
    "_glCompileShader": {"lib": "OpenGL", "purpose": "compile a shader object", "category": "graphics"},
    "_glDeleteShader": {"lib": "OpenGL", "purpose": "delete a shader object", "category": "graphics"},
    "_glCreateProgram": {"lib": "OpenGL", "purpose": "create a program object", "category": "graphics"},
    "_glAttachShader": {"lib": "OpenGL", "purpose": "attach shader to program", "category": "graphics"},
    "_glLinkProgram": {"lib": "OpenGL", "purpose": "link a program object", "category": "graphics"},
    "_glUseProgram": {"lib": "OpenGL", "purpose": "install a program object as current", "category": "graphics"},
    "_glDeleteProgram": {"lib": "OpenGL", "purpose": "delete a program object", "category": "graphics"},
    "_glGetUniformLocation": {"lib": "OpenGL", "purpose": "get uniform variable location", "category": "graphics"},
    "_glUniform1f": {"lib": "OpenGL", "purpose": "set float uniform value", "category": "graphics"},
    "_glUniform1i": {"lib": "OpenGL", "purpose": "set integer uniform value", "category": "graphics"},
    "_glUniform2f": {"lib": "OpenGL", "purpose": "set vec2 uniform value", "category": "graphics"},
    "_glUniform3f": {"lib": "OpenGL", "purpose": "set vec3 uniform value", "category": "graphics"},
    "_glUniform4f": {"lib": "OpenGL", "purpose": "set vec4 uniform value", "category": "graphics"},
    "_glUniformMatrix4fv": {"lib": "OpenGL", "purpose": "set 4x4 matrix uniform value", "category": "graphics"},
    "_glVertexAttribPointer": {"lib": "OpenGL", "purpose": "define vertex attribute data layout", "category": "graphics"},
    "_glEnableVertexAttribArray": {"lib": "OpenGL", "purpose": "enable vertex attribute array", "category": "graphics"},
    "_glDisableVertexAttribArray": {"lib": "OpenGL", "purpose": "disable vertex attribute array", "category": "graphics"},
    "_glDrawArrays": {"lib": "OpenGL", "purpose": "render primitives from array data", "category": "graphics"},
    "_glDrawElements": {"lib": "OpenGL", "purpose": "render indexed primitives", "category": "graphics"},
    "_glDrawArraysInstanced": {"lib": "OpenGL", "purpose": "draw multiple instances of primitives", "category": "graphics"},
    "_glEnable": {"lib": "OpenGL", "purpose": "enable server-side GL capability", "category": "graphics"},
    "_glDisable": {"lib": "OpenGL", "purpose": "disable server-side GL capability", "category": "graphics"},
    "_glBlendFunc": {"lib": "OpenGL", "purpose": "specify pixel blending factors", "category": "graphics"},
    "_glDepthFunc": {"lib": "OpenGL", "purpose": "specify depth comparison function", "category": "graphics"},
    "_glCullFace": {"lib": "OpenGL", "purpose": "specify face culling mode", "category": "graphics"},
    "_glViewport": {"lib": "OpenGL", "purpose": "set the viewport", "category": "graphics"},
    "_glClear": {"lib": "OpenGL", "purpose": "clear buffers to preset values", "category": "graphics"},
    "_glClearColor": {"lib": "OpenGL", "purpose": "specify clear values for color buffer", "category": "graphics"},
    "_glFlush": {"lib": "OpenGL", "purpose": "force execution of GL commands", "category": "graphics"},
    "_glFinish": {"lib": "OpenGL", "purpose": "block until all GL execution is complete", "category": "graphics"},
    "_glGenFramebuffers": {"lib": "OpenGL", "purpose": "generate framebuffer object names", "category": "graphics"},
    "_glBindFramebuffer": {"lib": "OpenGL", "purpose": "bind a framebuffer object", "category": "graphics"},
    "_glFramebufferTexture2D": {"lib": "OpenGL", "purpose": "attach texture to framebuffer", "category": "graphics"},
    "_glCheckFramebufferStatus": {"lib": "OpenGL", "purpose": "check framebuffer completeness", "category": "graphics"},
    "_glGetError": {"lib": "OpenGL", "purpose": "return error information", "category": "graphics"},
    "_glGetString": {"lib": "OpenGL", "purpose": "return a string describing GL", "category": "graphics"},
    "_glGetIntegerv": {"lib": "OpenGL", "purpose": "return integer GL parameter value", "category": "graphics"},
    "_MTLCreateSystemDefaultDevice": {"lib": "Metal", "purpose": "create default Metal GPU device", "category": "graphics"},
    "_newCommandQueue": {"lib": "Metal", "purpose": "create Metal command queue", "category": "graphics"},
    "_newRenderPipelineStateWithDescriptor": {"lib": "Metal", "purpose": "create Metal render pipeline state", "category": "graphics"},
    "_newBufferWithBytes": {"lib": "Metal", "purpose": "create Metal buffer with initial data", "category": "graphics"},
    "_newTextureWithDescriptor": {"lib": "Metal", "purpose": "create Metal texture object", "category": "graphics"},
    "_newLibraryWithSource": {"lib": "Metal", "purpose": "create Metal shader library from source", "category": "graphics"},
    "_CVDisplayLinkCreateWithActiveCGDisplays": {"lib": "CoreVideo", "purpose": "create display link for active displays", "category": "graphics"},
    "_CVDisplayLinkStart": {"lib": "CoreVideo", "purpose": "start display link callbacks", "category": "graphics"},
    "_CVDisplayLinkStop": {"lib": "CoreVideo", "purpose": "stop display link callbacks", "category": "graphics"},
}


# ---------------------------------------------------------------------------
# CoreGraphics (~40)
# ---------------------------------------------------------------------------

_COREGRAPHICS_SIGNATURES: dict[str, dict[str, str]] = {
    "_CGContextRef": {"lib": "CoreGraphics", "purpose": "graphics context reference type", "category": "graphics"},
    "_CGImageRef": {"lib": "CoreGraphics", "purpose": "image reference type", "category": "graphics"},
    "_CGColorSpaceRef": {"lib": "CoreGraphics", "purpose": "color space reference type", "category": "graphics"},
    "_CGBitmapContextCreate": {"lib": "CoreGraphics", "purpose": "create bitmap graphics context", "category": "graphics"},
    "_CGBitmapContextCreateImage": {"lib": "CoreGraphics", "purpose": "create image from bitmap context", "category": "graphics"},
    "_CGContextRelease": {"lib": "CoreGraphics", "purpose": "release graphics context", "category": "graphics"},
    "_CGContextSetFillColorWithColor": {"lib": "CoreGraphics", "purpose": "set fill color", "category": "graphics"},
    "_CGContextFillRect": {"lib": "CoreGraphics", "purpose": "fill a rectangle", "category": "graphics"},
    "_CGContextStrokeRect": {"lib": "CoreGraphics", "purpose": "stroke a rectangle outline", "category": "graphics"},
    "_CGContextDrawImage": {"lib": "CoreGraphics", "purpose": "draw image into context", "category": "graphics"},
    "_CGContextDrawPath": {"lib": "CoreGraphics", "purpose": "draw current path", "category": "graphics"},
    "_CGContextAddPath": {"lib": "CoreGraphics", "purpose": "add path to context", "category": "graphics"},
    "_CGContextMoveToPoint": {"lib": "CoreGraphics", "purpose": "begin new subpath at point", "category": "graphics"},
    "_CGContextAddLineToPoint": {"lib": "CoreGraphics", "purpose": "add line segment to path", "category": "graphics"},
    "_CGContextAddCurveToPoint": {"lib": "CoreGraphics", "purpose": "add cubic Bezier curve to path", "category": "graphics"},
    "_CGContextSaveGState": {"lib": "CoreGraphics", "purpose": "save current graphics state", "category": "graphics"},
    "_CGContextRestoreGState": {"lib": "CoreGraphics", "purpose": "restore saved graphics state", "category": "graphics"},
    "_CGContextTranslateCTM": {"lib": "CoreGraphics", "purpose": "translate current transform matrix", "category": "graphics"},
    "_CGContextScaleCTM": {"lib": "CoreGraphics", "purpose": "scale current transform matrix", "category": "graphics"},
    "_CGContextRotateCTM": {"lib": "CoreGraphics", "purpose": "rotate current transform matrix", "category": "graphics"},
    "_CGPathCreateMutable": {"lib": "CoreGraphics", "purpose": "create mutable graphics path", "category": "graphics"},
    "_CGPathAddRect": {"lib": "CoreGraphics", "purpose": "add rectangle to path", "category": "graphics"},
    "_CGPathAddEllipseInRect": {"lib": "CoreGraphics", "purpose": "add ellipse to path", "category": "graphics"},
    "_CGPathRelease": {"lib": "CoreGraphics", "purpose": "release graphics path", "category": "graphics"},
    "_CGColorSpaceCreateDeviceRGB": {"lib": "CoreGraphics", "purpose": "create device RGB color space", "category": "graphics"},
    "_CGColorSpaceCreateDeviceGray": {"lib": "CoreGraphics", "purpose": "create device gray color space", "category": "graphics"},
    "_CGColorSpaceRelease": {"lib": "CoreGraphics", "purpose": "release color space", "category": "graphics"},
    "_CGImageCreate": {"lib": "CoreGraphics", "purpose": "create image from bitmap data", "category": "graphics"},
    "_CGImageRelease": {"lib": "CoreGraphics", "purpose": "release image", "category": "graphics"},
    "_CGImageGetWidth": {"lib": "CoreGraphics", "purpose": "get image width in pixels", "category": "graphics"},
    "_CGImageGetHeight": {"lib": "CoreGraphics", "purpose": "get image height in pixels", "category": "graphics"},
    "_CGRectMake": {"lib": "CoreGraphics", "purpose": "construct CGRect from components", "category": "graphics"},
    "_CGPointMake": {"lib": "CoreGraphics", "purpose": "construct CGPoint from components", "category": "graphics"},
    "_CGSizeMake": {"lib": "CoreGraphics", "purpose": "construct CGSize from components", "category": "graphics"},
}


# ---------------------------------------------------------------------------
# CoreImage + CoreML (~10)
# ---------------------------------------------------------------------------

_COREIMAGE_COREML_SIGNATURES: dict[str, dict[str, str]] = {
    "_CIFilter": {"lib": "CoreImage", "purpose": "image processing filter object", "category": "image_processing"},
    "_CIImage": {"lib": "CoreImage", "purpose": "immutable image representation", "category": "image_processing"},
    "_CIContext": {"lib": "CoreImage", "purpose": "image processing evaluation context", "category": "image_processing"},
    "_CIFilter_filterWithName": {"lib": "CoreImage", "purpose": "create filter by name", "category": "image_processing"},
    "_CIContext_render": {"lib": "CoreImage", "purpose": "render filtered image to output", "category": "image_processing"},
    "_MLModel": {"lib": "CoreML", "purpose": "machine learning model object", "category": "ml"},
    "_MLPrediction": {"lib": "CoreML", "purpose": "ML prediction result", "category": "ml"},
    "_MLFeatureValue": {"lib": "CoreML", "purpose": "ML feature value wrapper", "category": "ml"},
    "_CoreML_loadModel": {"lib": "CoreML", "purpose": "load compiled ML model", "category": "ml"},
    "_CoreML_prediction": {"lib": "CoreML", "purpose": "run ML model prediction", "category": "ml"},
}


# ---------------------------------------------------------------------------
# Image Libraries: libpng, libjpeg, libwebp, ImageIO (~50)
# ---------------------------------------------------------------------------

_IMAGE_LIB_SIGNATURES: dict[str, dict[str, str]] = {
    # libpng
    "_png_create_read_struct": {"lib": "libpng", "purpose": "allocate PNG read structure", "category": "image"},
    "_png_create_write_struct": {"lib": "libpng", "purpose": "allocate PNG write structure", "category": "image"},
    "_png_destroy_read_struct": {"lib": "libpng", "purpose": "free PNG read structure", "category": "image"},
    "_png_destroy_write_struct": {"lib": "libpng", "purpose": "free PNG write structure", "category": "image"},
    "_png_init_io": {"lib": "libpng", "purpose": "initialize PNG I/O with FILE pointer", "category": "image"},
    "_png_set_sig_bytes": {"lib": "libpng", "purpose": "set number of signature bytes already read", "category": "image"},
    "_png_read_info": {"lib": "libpng", "purpose": "read PNG file info chunks", "category": "image"},
    "_png_read_image": {"lib": "libpng", "purpose": "read entire PNG image into memory", "category": "image"},
    "_png_read_end": {"lib": "libpng", "purpose": "finish reading PNG file", "category": "image"},
    "_png_write_info": {"lib": "libpng", "purpose": "write PNG info chunks", "category": "image"},
    "_png_write_image": {"lib": "libpng", "purpose": "write entire PNG image", "category": "image"},
    "_png_write_end": {"lib": "libpng", "purpose": "finish writing PNG file", "category": "image"},
    "_png_get_image_width": {"lib": "libpng", "purpose": "get image width from info struct", "category": "image"},
    "_png_get_image_height": {"lib": "libpng", "purpose": "get image height from info struct", "category": "image"},
    "_png_get_bit_depth": {"lib": "libpng", "purpose": "get image bit depth", "category": "image"},
    "_png_get_color_type": {"lib": "libpng", "purpose": "get image color type", "category": "image"},
    "_png_set_IHDR": {"lib": "libpng", "purpose": "set image header parameters", "category": "image"},
    "_png_set_rows": {"lib": "libpng", "purpose": "set row pointers for writing", "category": "image"},
    "_png_malloc": {"lib": "libpng", "purpose": "allocate memory via PNG allocator", "category": "image"},
    "_png_free": {"lib": "libpng", "purpose": "free memory via PNG allocator", "category": "image"},
    # libjpeg
    "_jpeg_create_compress": {"lib": "libjpeg", "purpose": "allocate JPEG compression struct", "category": "image"},
    "_jpeg_create_decompress": {"lib": "libjpeg", "purpose": "allocate JPEG decompression struct", "category": "image"},
    "_jpeg_destroy_compress": {"lib": "libjpeg", "purpose": "free JPEG compression struct", "category": "image"},
    "_jpeg_destroy_decompress": {"lib": "libjpeg", "purpose": "free JPEG decompression struct", "category": "image"},
    "_jpeg_stdio_dest": {"lib": "libjpeg", "purpose": "set FILE as JPEG output destination", "category": "image"},
    "_jpeg_stdio_src": {"lib": "libjpeg", "purpose": "set FILE as JPEG input source", "category": "image"},
    "_jpeg_mem_dest": {"lib": "libjpeg", "purpose": "set memory buffer as JPEG output", "category": "image"},
    "_jpeg_mem_src": {"lib": "libjpeg", "purpose": "set memory buffer as JPEG input", "category": "image"},
    "_jpeg_set_defaults": {"lib": "libjpeg", "purpose": "set default JPEG compression parameters", "category": "image"},
    "_jpeg_set_quality": {"lib": "libjpeg", "purpose": "set JPEG output quality (0-100)", "category": "image"},
    "_jpeg_start_compress": {"lib": "libjpeg", "purpose": "start JPEG compression", "category": "image"},
    "_jpeg_write_scanlines": {"lib": "libjpeg", "purpose": "write scanlines during compression", "category": "image"},
    "_jpeg_finish_compress": {"lib": "libjpeg", "purpose": "finish JPEG compression", "category": "image"},
    "_jpeg_read_header": {"lib": "libjpeg", "purpose": "read JPEG file header", "category": "image"},
    "_jpeg_start_decompress": {"lib": "libjpeg", "purpose": "start JPEG decompression", "category": "image"},
    "_jpeg_read_scanlines": {"lib": "libjpeg", "purpose": "read scanlines during decompression", "category": "image"},
    "_jpeg_finish_decompress": {"lib": "libjpeg", "purpose": "finish JPEG decompression", "category": "image"},
    # libwebp
    "_WebPDecodeRGBA": {"lib": "libwebp", "purpose": "decode WebP image to RGBA", "category": "image"},
    "_WebPDecodeRGB": {"lib": "libwebp", "purpose": "decode WebP image to RGB", "category": "image"},
    "_WebPDecodeBGRA": {"lib": "libwebp", "purpose": "decode WebP image to BGRA", "category": "image"},
    "_WebPEncodeRGBA": {"lib": "libwebp", "purpose": "encode RGBA data as WebP", "category": "image"},
    "_WebPEncodeRGB": {"lib": "libwebp", "purpose": "encode RGB data as WebP", "category": "image"},
    "_WebPEncodeLosslessRGBA": {"lib": "libwebp", "purpose": "encode RGBA as lossless WebP", "category": "image"},
    "_WebPGetInfo": {"lib": "libwebp", "purpose": "get WebP image dimensions without decoding", "category": "image"},
    "_WebPFree": {"lib": "libwebp", "purpose": "free WebP allocated memory", "category": "image"},
    # ImageIO (macOS)
    "_CGImageSourceCreateWithData": {"lib": "ImageIO", "purpose": "create image source from data", "category": "image"},
    "_CGImageSourceCreateWithURL": {"lib": "ImageIO", "purpose": "create image source from URL", "category": "image"},
    "_CGImageSourceCreateImageAtIndex": {"lib": "ImageIO", "purpose": "create image from source at index", "category": "image"},
    "_CGImageDestinationCreateWithURL": {"lib": "ImageIO", "purpose": "create image destination for URL", "category": "image"},
    "_CGImageDestinationAddImage": {"lib": "ImageIO", "purpose": "add image to destination", "category": "image"},
    "_CGImageDestinationFinalize": {"lib": "ImageIO", "purpose": "finalize and write image destination", "category": "image"},
}


# ---------------------------------------------------------------------------
# Audio: CoreAudio, AVFoundation, OpenAL (~50)
# ---------------------------------------------------------------------------

_AUDIO_SIGNATURES: dict[str, dict[str, str]] = {
    # CoreAudio: Audio Component
    "_AudioComponentFindNext": {"lib": "CoreAudio", "purpose": "find next matching audio component", "category": "audio"},
    "_AudioComponentInstanceNew": {"lib": "CoreAudio", "purpose": "create audio component instance", "category": "audio"},
    "_AudioComponentInstanceDispose": {"lib": "CoreAudio", "purpose": "dispose audio component instance", "category": "audio"},
    # CoreAudio: Audio Unit
    "_AudioUnitInitialize": {"lib": "CoreAudio", "purpose": "initialize audio unit", "category": "audio"},
    "_AudioUnitUninitialize": {"lib": "CoreAudio", "purpose": "uninitialize audio unit", "category": "audio"},
    "_AudioUnitRender": {"lib": "CoreAudio", "purpose": "render audio unit output", "category": "audio"},
    "_AudioOutputUnitStart": {"lib": "CoreAudio", "purpose": "start audio output unit", "category": "audio"},
    "_AudioOutputUnitStop": {"lib": "CoreAudio", "purpose": "stop audio output unit", "category": "audio"},
    # CoreAudio: Audio Queue
    "_AudioQueueNewOutput": {"lib": "CoreAudio", "purpose": "create new output audio queue", "category": "audio"},
    "_AudioQueueNewInput": {"lib": "CoreAudio", "purpose": "create new input audio queue", "category": "audio"},
    "_AudioQueueStart": {"lib": "CoreAudio", "purpose": "start audio queue processing", "category": "audio"},
    "_AudioQueueStop": {"lib": "CoreAudio", "purpose": "stop audio queue processing", "category": "audio"},
    "_AudioQueueDispose": {"lib": "CoreAudio", "purpose": "dispose audio queue", "category": "audio"},
    "_AudioQueueAllocateBuffer": {"lib": "CoreAudio", "purpose": "allocate audio queue buffer", "category": "audio"},
    "_AudioQueueEnqueueBuffer": {"lib": "CoreAudio", "purpose": "enqueue buffer for audio queue", "category": "audio"},
    "_AudioQueueFreeBuffer": {"lib": "CoreAudio", "purpose": "free audio queue buffer", "category": "audio"},
    # CoreAudio: Audio File
    "_AudioFileOpenURL": {"lib": "CoreAudio", "purpose": "open audio file from URL", "category": "audio"},
    "_AudioFileClose": {"lib": "CoreAudio", "purpose": "close audio file", "category": "audio"},
    "_AudioFileReadPacketData": {"lib": "CoreAudio", "purpose": "read packet data from audio file", "category": "audio"},
    # CoreAudio: Extended Audio File
    "_ExtAudioFileOpenURL": {"lib": "CoreAudio", "purpose": "open extended audio file from URL", "category": "audio"},
    "_ExtAudioFileRead": {"lib": "CoreAudio", "purpose": "read from extended audio file", "category": "audio"},
    "_ExtAudioFileWrite": {"lib": "CoreAudio", "purpose": "write to extended audio file", "category": "audio"},
    "_ExtAudioFileDispose": {"lib": "CoreAudio", "purpose": "dispose extended audio file", "category": "audio"},
    # AVFoundation
    "_AVAudioPlayer": {"lib": "AVFoundation", "purpose": "audio player object", "category": "audio"},
    "_AVAudioEngine": {"lib": "AVFoundation", "purpose": "audio processing graph engine", "category": "audio"},
    "_AVAudioSession": {"lib": "AVFoundation", "purpose": "audio session configuration", "category": "audio"},
    "_AVCaptureSession": {"lib": "AVFoundation", "purpose": "media capture session", "category": "media"},
    "_AVCaptureDevice": {"lib": "AVFoundation", "purpose": "capture device (camera/mic)", "category": "media"},
    "_AVCaptureVideoDataOutput": {"lib": "AVFoundation", "purpose": "video frame capture output", "category": "media"},
    # OpenAL: Sources
    "_alGenSources": {"lib": "OpenAL", "purpose": "generate audio source names", "category": "audio"},
    "_alDeleteSources": {"lib": "OpenAL", "purpose": "delete audio sources", "category": "audio"},
    "_alSourcePlay": {"lib": "OpenAL", "purpose": "play audio source", "category": "audio"},
    "_alSourceStop": {"lib": "OpenAL", "purpose": "stop audio source", "category": "audio"},
    "_alSourcePause": {"lib": "OpenAL", "purpose": "pause audio source", "category": "audio"},
    # OpenAL: Buffers
    "_alGenBuffers": {"lib": "OpenAL", "purpose": "generate audio buffer names", "category": "audio"},
    "_alDeleteBuffers": {"lib": "OpenAL", "purpose": "delete audio buffers", "category": "audio"},
    "_alBufferData": {"lib": "OpenAL", "purpose": "fill buffer with audio data", "category": "audio"},
    # OpenAL: Listener & Source Properties
    "_alListenerf": {"lib": "OpenAL", "purpose": "set listener float property", "category": "audio"},
    "_alSourcef": {"lib": "OpenAL", "purpose": "set source float property", "category": "audio"},
    "_alSourcei": {"lib": "OpenAL", "purpose": "set source integer property", "category": "audio"},
    "_alSource3f": {"lib": "OpenAL", "purpose": "set source 3-float property (position/velocity)", "category": "audio"},
    # OpenAL: Device & Context
    "_alcOpenDevice": {"lib": "OpenAL", "purpose": "open audio device", "category": "audio"},
    "_alcCloseDevice": {"lib": "OpenAL", "purpose": "close audio device", "category": "audio"},
    "_alcCreateContext": {"lib": "OpenAL", "purpose": "create audio context", "category": "audio"},
    "_alcDestroyContext": {"lib": "OpenAL", "purpose": "destroy audio context", "category": "audio"},
}


# ---------------------------------------------------------------------------
# FFmpeg / libav (~35)
# ---------------------------------------------------------------------------

_FFMPEG_SIGNATURES: dict[str, dict[str, str]] = {
    # Format I/O
    "_avformat_open_input": {"lib": "libavformat", "purpose": "open input media file/stream", "category": "media"},
    "_avformat_close_input": {"lib": "libavformat", "purpose": "close input media file/stream", "category": "media"},
    "_avformat_find_stream_info": {"lib": "libavformat", "purpose": "read stream info from media", "category": "media"},
    "_avformat_alloc_output_context2": {"lib": "libavformat", "purpose": "allocate output format context", "category": "media"},
    "_av_read_frame": {"lib": "libavformat", "purpose": "read next packet from media", "category": "media"},
    "_av_write_frame": {"lib": "libavformat", "purpose": "write packet to output media", "category": "media"},
    "_av_interleaved_write_frame": {"lib": "libavformat", "purpose": "write interleaved packet to output", "category": "media"},
    # Codec Discovery
    "_avcodec_find_decoder": {"lib": "libavcodec", "purpose": "find registered decoder by ID", "category": "media"},
    "_avcodec_find_encoder": {"lib": "libavcodec", "purpose": "find registered encoder by ID", "category": "media"},
    "_avcodec_open2": {"lib": "libavcodec", "purpose": "open codec for encoding/decoding", "category": "media"},
    "_avcodec_close": {"lib": "libavcodec", "purpose": "close codec", "category": "media"},
    # Codec Send/Receive API
    "_avcodec_send_packet": {"lib": "libavcodec", "purpose": "send packet to decoder", "category": "media"},
    "_avcodec_receive_frame": {"lib": "libavcodec", "purpose": "receive decoded frame from decoder", "category": "media"},
    "_avcodec_send_frame": {"lib": "libavcodec", "purpose": "send frame to encoder", "category": "media"},
    "_avcodec_receive_packet": {"lib": "libavcodec", "purpose": "receive encoded packet from encoder", "category": "media"},
    # Codec Context
    "_avcodec_alloc_context3": {"lib": "libavcodec", "purpose": "allocate codec context", "category": "media"},
    "_avcodec_free_context": {"lib": "libavcodec", "purpose": "free codec context", "category": "media"},
    "_avcodec_parameters_to_context": {"lib": "libavcodec", "purpose": "copy codec parameters to context", "category": "media"},
    # Frame Management
    "_av_frame_alloc": {"lib": "libavutil", "purpose": "allocate AVFrame", "category": "media"},
    "_av_frame_free": {"lib": "libavutil", "purpose": "free AVFrame", "category": "media"},
    "_av_frame_unref": {"lib": "libavutil", "purpose": "unreference frame data", "category": "media"},
    # Packet Management
    "_av_packet_alloc": {"lib": "libavcodec", "purpose": "allocate AVPacket", "category": "media"},
    "_av_packet_free": {"lib": "libavcodec", "purpose": "free AVPacket", "category": "media"},
    "_av_packet_unref": {"lib": "libavcodec", "purpose": "unreference packet data", "category": "media"},
    # Software Scaler
    "_sws_getContext": {"lib": "libswscale", "purpose": "create software scaler context", "category": "media"},
    "_sws_scale": {"lib": "libswscale", "purpose": "scale/convert video frame", "category": "media"},
    "_sws_freeContext": {"lib": "libswscale", "purpose": "free software scaler context", "category": "media"},
    # Software Resampler
    "_swr_alloc": {"lib": "libswresample", "purpose": "allocate audio resampler context", "category": "media"},
    "_swr_init": {"lib": "libswresample", "purpose": "initialize audio resampler", "category": "media"},
    "_swr_convert": {"lib": "libswresample", "purpose": "convert/resample audio samples", "category": "media"},
    "_swr_free": {"lib": "libswresample", "purpose": "free audio resampler context", "category": "media"},
    # Utility
    "_av_malloc": {"lib": "libavutil", "purpose": "allocate memory with alignment", "category": "media"},
    "_av_free": {"lib": "libavutil", "purpose": "free av-allocated memory", "category": "media"},
    "_av_log": {"lib": "libavutil", "purpose": "FFmpeg logging function", "category": "media"},
}


# ---------------------------------------------------------------------------
# SDL2 (~30)
# ---------------------------------------------------------------------------

_SDL2_SIGNATURES: dict[str, dict[str, str]] = {
    # Init / Quit
    "_SDL_Init": {"lib": "SDL2", "purpose": "initialize SDL subsystems", "category": "multimedia"},
    "_SDL_Quit": {"lib": "SDL2", "purpose": "shut down all SDL subsystems", "category": "multimedia"},
    # Window
    "_SDL_CreateWindow": {"lib": "SDL2", "purpose": "create a window", "category": "multimedia"},
    "_SDL_DestroyWindow": {"lib": "SDL2", "purpose": "destroy a window", "category": "multimedia"},
    # Renderer
    "_SDL_CreateRenderer": {"lib": "SDL2", "purpose": "create 2D rendering context", "category": "multimedia"},
    "_SDL_DestroyRenderer": {"lib": "SDL2", "purpose": "destroy 2D rendering context", "category": "multimedia"},
    "_SDL_RenderPresent": {"lib": "SDL2", "purpose": "present renderer to screen", "category": "multimedia"},
    "_SDL_RenderClear": {"lib": "SDL2", "purpose": "clear renderer with draw color", "category": "multimedia"},
    # Texture
    "_SDL_CreateTexture": {"lib": "SDL2", "purpose": "create texture for renderer", "category": "multimedia"},
    "_SDL_DestroyTexture": {"lib": "SDL2", "purpose": "destroy texture", "category": "multimedia"},
    "_SDL_UpdateTexture": {"lib": "SDL2", "purpose": "update texture with new pixel data", "category": "multimedia"},
    "_SDL_RenderCopy": {"lib": "SDL2", "purpose": "copy texture to renderer", "category": "multimedia"},
    # Events
    "_SDL_PollEvent": {"lib": "SDL2", "purpose": "poll for pending events", "category": "multimedia"},
    "_SDL_WaitEvent": {"lib": "SDL2", "purpose": "wait for next event", "category": "multimedia"},
    "_SDL_PushEvent": {"lib": "SDL2", "purpose": "push event onto event queue", "category": "multimedia"},
    # Timer
    "_SDL_GetTicks": {"lib": "SDL2", "purpose": "get milliseconds since SDL init", "category": "multimedia"},
    "_SDL_Delay": {"lib": "SDL2", "purpose": "wait specified milliseconds", "category": "multimedia"},
    "_SDL_GetPerformanceCounter": {"lib": "SDL2", "purpose": "get high-resolution counter value", "category": "multimedia"},
    "_SDL_GetPerformanceFrequency": {"lib": "SDL2", "purpose": "get high-resolution counter frequency", "category": "multimedia"},
    # Surface
    "_SDL_LoadBMP": {"lib": "SDL2", "purpose": "load BMP image to surface", "category": "multimedia"},
    "_SDL_FreeSurface": {"lib": "SDL2", "purpose": "free surface memory", "category": "multimedia"},
    "_SDL_ConvertSurface": {"lib": "SDL2", "purpose": "convert surface to different format", "category": "multimedia"},
    # Audio
    "_SDL_OpenAudio": {"lib": "SDL2", "purpose": "open audio device", "category": "multimedia"},
    "_SDL_CloseAudio": {"lib": "SDL2", "purpose": "close audio device", "category": "multimedia"},
    "_SDL_PauseAudio": {"lib": "SDL2", "purpose": "pause/unpause audio playback", "category": "multimedia"},
    "_SDL_MixAudio": {"lib": "SDL2", "purpose": "mix audio data into buffer", "category": "multimedia"},
    # Threading
    "_SDL_CreateThread": {"lib": "SDL2", "purpose": "create a new thread", "category": "multimedia"},
    "_SDL_WaitThread": {"lib": "SDL2", "purpose": "wait for thread to finish", "category": "multimedia"},
    "_SDL_CreateMutex": {"lib": "SDL2", "purpose": "create a mutex", "category": "multimedia"},
    "_SDL_LockMutex": {"lib": "SDL2", "purpose": "lock a mutex", "category": "multimedia"},
    "_SDL_UnlockMutex": {"lib": "SDL2", "purpose": "unlock a mutex", "category": "multimedia"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreData (~16)
# ---------------------------------------------------------------------------

_APPLE_COREDATA_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_NSManagedObjectContext": {"lib": "CoreData", "purpose": "managed object context class", "category": "persistence"},
    "_OBJC_CLASS_$_NSManagedObjectModel": {"lib": "CoreData", "purpose": "managed object model class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentStoreCoordinator": {"lib": "CoreData", "purpose": "persistent store coordinator class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentContainer": {"lib": "CoreData", "purpose": "persistent container class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentCloudKitContainer": {"lib": "CoreData", "purpose": "CloudKit persistent container class", "category": "persistence"},
    "_OBJC_CLASS_$_NSFetchRequest": {"lib": "CoreData", "purpose": "fetch request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSEntityDescription": {"lib": "CoreData", "purpose": "entity description class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPredicate": {"lib": "Foundation", "purpose": "query predicate class", "category": "persistence"},
    "_OBJC_CLASS_$_NSSortDescriptor": {"lib": "Foundation", "purpose": "sort descriptor class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchDeleteRequest": {"lib": "CoreData", "purpose": "batch delete request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchInsertRequest": {"lib": "CoreData", "purpose": "batch insert request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchUpdateRequest": {"lib": "CoreData", "purpose": "batch update request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSFetchedResultsController": {"lib": "CoreData", "purpose": "fetched results controller class", "category": "persistence"},
    "_OBJC_CLASS_$_NSManagedObject": {"lib": "CoreData", "purpose": "managed object base class", "category": "persistence"},
    "_OBJC_CLASS_$_NSMigrationManager": {"lib": "CoreData", "purpose": "model migration manager class", "category": "persistence"},
    "_OBJC_CLASS_$_NSMappingModel": {"lib": "CoreData", "purpose": "model mapping class", "category": "persistence"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- WebKit (~13)
# ---------------------------------------------------------------------------

_APPLE_WEBKIT_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_WKWebView": {"lib": "WebKit", "purpose": "modern web view class", "category": "ui"},
    "_OBJC_CLASS_$_WKWebViewConfiguration": {"lib": "WebKit", "purpose": "web view configuration class", "category": "ui"},
    "_OBJC_CLASS_$_WKUserContentController": {"lib": "WebKit", "purpose": "user content controller class", "category": "ui"},
    "_OBJC_CLASS_$_WKUserScript": {"lib": "WebKit", "purpose": "injected user script class", "category": "ui"},
    "_OBJC_CLASS_$_WKScriptMessage": {"lib": "WebKit", "purpose": "JS-to-native message class", "category": "ui"},
    "_OBJC_CLASS_$_WKPreferences": {"lib": "WebKit", "purpose": "web view preferences class", "category": "ui"},
    "_OBJC_CLASS_$_WKProcessPool": {"lib": "WebKit", "purpose": "web process pool class", "category": "ui"},
    "_OBJC_CLASS_$_WKWebsiteDataStore": {"lib": "WebKit", "purpose": "website data store class", "category": "ui"},
    "_OBJC_CLASS_$_WKHTTPCookieStore": {"lib": "WebKit", "purpose": "HTTP cookie store class", "category": "ui"},
    "_OBJC_CLASS_$_WKContentRuleListStore": {"lib": "WebKit", "purpose": "content blocker rule list store", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKNavigationDelegate": {"lib": "WebKit", "purpose": "navigation delegate protocol", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKUIDelegate": {"lib": "WebKit", "purpose": "UI delegate protocol", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKScriptMessageHandler": {"lib": "WebKit", "purpose": "script message handler protocol", "category": "ui"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreLocation (~9)
# ---------------------------------------------------------------------------

_APPLE_CORELOCATION_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_CLLocationManager": {"lib": "CoreLocation", "purpose": "location manager class", "category": "location"},
    "_OBJC_CLASS_$_CLLocation": {"lib": "CoreLocation", "purpose": "location data class", "category": "location"},
    "_OBJC_CLASS_$_CLGeocoder": {"lib": "CoreLocation", "purpose": "geocoder class", "category": "location"},
    "_OBJC_CLASS_$_CLPlacemark": {"lib": "CoreLocation", "purpose": "placemark class", "category": "location"},
    "_OBJC_CLASS_$_CLCircularRegion": {"lib": "CoreLocation", "purpose": "circular geofence region class", "category": "location"},
    "_OBJC_CLASS_$_CLBeaconRegion": {"lib": "CoreLocation", "purpose": "iBeacon region class", "category": "location"},
    "_OBJC_CLASS_$_CLVisit": {"lib": "CoreLocation", "purpose": "visit monitoring class", "category": "location"},
    "_CLLocationCoordinate2DMake": {"lib": "CoreLocation", "purpose": "create CLLocationCoordinate2D", "category": "location"},
    "_OBJC_PROTOCOL_$_CLLocationManagerDelegate": {"lib": "CoreLocation", "purpose": "location manager delegate protocol", "category": "location"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- CoreBluetooth (~11)
# ---------------------------------------------------------------------------

_APPLE_COREBLUETOOTH_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_CBCentralManager": {"lib": "CoreBluetooth", "purpose": "BLE central manager class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBPeripheral": {"lib": "CoreBluetooth", "purpose": "BLE peripheral class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBCharacteristic": {"lib": "CoreBluetooth", "purpose": "BLE characteristic class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBService": {"lib": "CoreBluetooth", "purpose": "BLE service class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBPeripheralManager": {"lib": "CoreBluetooth", "purpose": "BLE peripheral manager class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBDescriptor": {"lib": "CoreBluetooth", "purpose": "BLE descriptor class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBUUID": {"lib": "CoreBluetooth", "purpose": "BLE UUID class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBMutableCharacteristic": {"lib": "CoreBluetooth", "purpose": "BLE mutable characteristic class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBMutableService": {"lib": "CoreBluetooth", "purpose": "BLE mutable service class", "category": "bluetooth"},
    "_OBJC_PROTOCOL_$_CBCentralManagerDelegate": {"lib": "CoreBluetooth", "purpose": "BLE central delegate protocol", "category": "bluetooth"},
    "_OBJC_PROTOCOL_$_CBPeripheralDelegate": {"lib": "CoreBluetooth", "purpose": "BLE peripheral delegate protocol", "category": "bluetooth"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- StoreKit (~10)
# ---------------------------------------------------------------------------

_APPLE_STOREKIT_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_SKProductsRequest": {"lib": "StoreKit", "purpose": "IAP products request class", "category": "iap"},
    "_OBJC_CLASS_$_SKPaymentQueue": {"lib": "StoreKit", "purpose": "IAP payment queue class", "category": "iap"},
    "_OBJC_CLASS_$_SKPayment": {"lib": "StoreKit", "purpose": "IAP payment class", "category": "iap"},
    "_OBJC_CLASS_$_SKProduct": {"lib": "StoreKit", "purpose": "IAP product class", "category": "iap"},
    "_OBJC_CLASS_$_SKReceiptRefreshRequest": {"lib": "StoreKit", "purpose": "IAP receipt refresh request class", "category": "iap"},
    "_OBJC_CLASS_$_SKPaymentTransaction": {"lib": "StoreKit", "purpose": "IAP payment transaction class", "category": "iap"},
    "_OBJC_CLASS_$_SKStoreProductViewController": {"lib": "StoreKit", "purpose": "App Store product view controller", "category": "iap"},
    "_OBJC_CLASS_$_SKCloudServiceController": {"lib": "StoreKit", "purpose": "Apple Music cloud service controller", "category": "iap"},
    "_OBJC_PROTOCOL_$_SKProductsRequestDelegate": {"lib": "StoreKit", "purpose": "products request delegate protocol", "category": "iap"},
    "_OBJC_PROTOCOL_$_SKPaymentTransactionObserver": {"lib": "StoreKit", "purpose": "payment transaction observer protocol", "category": "iap"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- UserNotifications (~11)
# ---------------------------------------------------------------------------

_APPLE_USERNOTIFICATIONS_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_UNUserNotificationCenter": {"lib": "UserNotifications", "purpose": "notification center class", "category": "notification"},
    "_OBJC_CLASS_$_UNMutableNotificationContent": {"lib": "UserNotifications", "purpose": "mutable notification content class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationRequest": {"lib": "UserNotifications", "purpose": "notification request class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationAction": {"lib": "UserNotifications", "purpose": "notification action class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationCategory": {"lib": "UserNotifications", "purpose": "notification category class", "category": "notification"},
    "_OBJC_CLASS_$_UNTimeIntervalNotificationTrigger": {"lib": "UserNotifications", "purpose": "time interval trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNCalendarNotificationTrigger": {"lib": "UserNotifications", "purpose": "calendar trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNLocationNotificationTrigger": {"lib": "UserNotifications", "purpose": "location trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationSound": {"lib": "UserNotifications", "purpose": "notification sound class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationAttachment": {"lib": "UserNotifications", "purpose": "notification attachment class", "category": "notification"},
    "_OBJC_PROTOCOL_$_UNUserNotificationCenterDelegate": {"lib": "UserNotifications", "purpose": "notification center delegate protocol", "category": "notification"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- Network.framework (modern networking, ~35)
# ---------------------------------------------------------------------------

_APPLE_NETWORK_FRAMEWORK_SIGNATURES: dict[str, dict[str, str]] = {
    # Connection lifecycle
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data on connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message on connection", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "set connection state handler", "category": "network"},
    "_nw_connection_copy_endpoint": {"lib": "Network", "purpose": "copy connection endpoint", "category": "network"},
    "_nw_connection_copy_current_path": {"lib": "Network", "purpose": "copy current network path", "category": "network"},
    "_nw_connection_restart": {"lib": "Network", "purpose": "restart network connection", "category": "network"},
    # Listener
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "set listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "set listener state handler", "category": "network"},
    # Endpoint & parameters
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_create_bonjour_service": {"lib": "Network", "purpose": "create Bonjour endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP parameters", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP parameters", "category": "network"},
    "_nw_parameters_create": {"lib": "Network", "purpose": "create custom network parameters", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint on parameters", "category": "network"},
    # Path monitor
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create network path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start network path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel network path monitor", "category": "network"},
    "_nw_path_monitor_set_queue": {"lib": "Network", "purpose": "set path monitor dispatch queue", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "set path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
    "_nw_path_uses_interface_type": {"lib": "Network", "purpose": "check if path uses interface type", "category": "network"},
    "_nw_path_is_expensive": {"lib": "Network", "purpose": "check if path is expensive (cellular)", "category": "network"},
    "_nw_path_is_constrained": {"lib": "Network", "purpose": "check if path is constrained (low data)", "category": "network"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- EndpointSecurity extended (~14)
# ---------------------------------------------------------------------------

_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    "_es_mute_path": {"lib": "EndpointSecurity", "purpose": "ES path muting", "category": "security"},
    "_es_mute_path_prefix": {"lib": "EndpointSecurity", "purpose": "ES path prefix muting", "category": "security"},
    "_es_unmute_all_paths": {"lib": "EndpointSecurity", "purpose": "ES unmute all paths", "category": "security"},
    "_es_unmute_all_target_paths": {"lib": "EndpointSecurity", "purpose": "ES unmute all target paths", "category": "security"},
    "_es_mute_process_events": {"lib": "EndpointSecurity", "purpose": "ES mute specific process events", "category": "security"},
    "_es_respond_result": {"lib": "EndpointSecurity", "purpose": "ES respond with result", "category": "security"},
    "_es_message_size": {"lib": "EndpointSecurity", "purpose": "ES get message size", "category": "security"},
    "_es_retain_message": {"lib": "EndpointSecurity", "purpose": "ES retain message", "category": "security"},
    "_es_release_message": {"lib": "EndpointSecurity", "purpose": "ES release message", "category": "security"},
    "_es_copy_message": {"lib": "EndpointSecurity", "purpose": "ES copy message", "category": "security"},
    "_es_exec_arg_count": {"lib": "EndpointSecurity", "purpose": "ES get exec argument count", "category": "security"},
    "_es_exec_arg": {"lib": "EndpointSecurity", "purpose": "ES get exec argument", "category": "security"},
    "_es_exec_env_count": {"lib": "EndpointSecurity", "purpose": "ES get exec env count", "category": "security"},
    "_es_exec_env": {"lib": "EndpointSecurity", "purpose": "ES get exec environment variable", "category": "security"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- SystemExtensions (~3)
# ---------------------------------------------------------------------------

_APPLE_SYSTEMEXTENSIONS_SIGNATURES: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_OSSystemExtensionRequest": {"lib": "SystemExtensions", "purpose": "system extension request class", "category": "security"},
    "_OBJC_CLASS_$_OSSystemExtensionManager": {"lib": "SystemExtensions", "purpose": "system extension manager class", "category": "security"},
    "_OBJC_PROTOCOL_$_OSSystemExtensionRequestDelegate": {"lib": "SystemExtensions", "purpose": "system extension delegate protocol", "category": "security"},
}


# ---------------------------------------------------------------------------
# Apple Frameworks -- AppKit macOS UI (~80)
# ---------------------------------------------------------------------------

_APPLE_APPKIT_SIGNATURES: dict[str, dict[str, str]] = {
    # Application & Window
    "_OBJC_CLASS_$_NSApplication": {"lib": "AppKit", "purpose": "application singleton class", "category": "ui"},
    "_OBJC_CLASS_$_NSWindow": {"lib": "AppKit", "purpose": "window class", "category": "ui"},
    "_OBJC_CLASS_$_NSView": {"lib": "AppKit", "purpose": "base view class", "category": "ui"},
    "_OBJC_CLASS_$_NSViewController": {"lib": "AppKit", "purpose": "view controller class", "category": "ui"},
    "_OBJC_CLASS_$_NSWindowController": {"lib": "AppKit", "purpose": "window controller class", "category": "ui"},
    # Controls
    "_OBJC_CLASS_$_NSButton": {"lib": "AppKit", "purpose": "button control class", "category": "ui"},
    "_OBJC_CLASS_$_NSTextField": {"lib": "AppKit", "purpose": "text field class", "category": "ui"},
    "_OBJC_CLASS_$_NSTextView": {"lib": "AppKit", "purpose": "rich text view class", "category": "ui"},
    "_OBJC_CLASS_$_NSSearchField": {"lib": "AppKit", "purpose": "search field class", "category": "ui"},
    "_OBJC_CLASS_$_NSComboBox": {"lib": "AppKit", "purpose": "combo box class", "category": "ui"},
    "_OBJC_CLASS_$_NSPopUpButton": {"lib": "AppKit", "purpose": "popup button class", "category": "ui"},
    "_OBJC_CLASS_$_NSSlider": {"lib": "AppKit", "purpose": "slider class", "category": "ui"},
    "_OBJC_CLASS_$_NSProgressIndicator": {"lib": "AppKit", "purpose": "progress indicator class", "category": "ui"},
    "_OBJC_CLASS_$_NSSegmentedControl": {"lib": "AppKit", "purpose": "segmented control class", "category": "ui"},
    "_OBJC_CLASS_$_NSSwitch": {"lib": "AppKit", "purpose": "switch control class", "category": "ui"},
    # Dialogs & Panels
    "_OBJC_CLASS_$_NSAlert": {"lib": "AppKit", "purpose": "alert dialog class", "category": "ui"},
    "_OBJC_CLASS_$_NSOpenPanel": {"lib": "AppKit", "purpose": "file open panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSSavePanel": {"lib": "AppKit", "purpose": "file save panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSColorPanel": {"lib": "AppKit", "purpose": "color picker panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSFontPanel": {"lib": "AppKit", "purpose": "font picker panel class", "category": "ui"},
    # Menus & Toolbar
    "_OBJC_CLASS_$_NSMenu": {"lib": "AppKit", "purpose": "menu class", "category": "ui"},
    "_OBJC_CLASS_$_NSMenuItem": {"lib": "AppKit", "purpose": "menu item class", "category": "ui"},
    "_OBJC_CLASS_$_NSToolbar": {"lib": "AppKit", "purpose": "toolbar class", "category": "ui"},
    "_OBJC_CLASS_$_NSToolbarItem": {"lib": "AppKit", "purpose": "toolbar item class", "category": "ui"},
    "_OBJC_CLASS_$_NSTouchBar": {"lib": "AppKit", "purpose": "Touch Bar class", "category": "ui"},
    # Layout
    "_OBJC_CLASS_$_NSSplitView": {"lib": "AppKit", "purpose": "split view class", "category": "ui"},
    "_OBJC_CLASS_$_NSSplitViewController": {"lib": "AppKit", "purpose": "split view controller class", "category": "ui"},
    "_OBJC_CLASS_$_NSStackView": {"lib": "AppKit", "purpose": "stack view class", "category": "ui"},
    "_OBJC_CLASS_$_NSScrollView": {"lib": "AppKit", "purpose": "scroll view class", "category": "ui"},
    "_OBJC_CLASS_$_NSTabView": {"lib": "AppKit", "purpose": "tab view class", "category": "ui"},
    # Table & Collection
    "_OBJC_CLASS_$_NSTableView": {"lib": "AppKit", "purpose": "table view class", "category": "ui"},
    "_OBJC_CLASS_$_NSOutlineView": {"lib": "AppKit", "purpose": "outline (tree) view class", "category": "ui"},
    "_OBJC_CLASS_$_NSCollectionView": {"lib": "AppKit", "purpose": "collection view class", "category": "ui"},
    "_OBJC_CLASS_$_NSTableColumn": {"lib": "AppKit", "purpose": "table column class", "category": "ui"},
    # Drawing
    "_OBJC_CLASS_$_NSColor": {"lib": "AppKit", "purpose": "color class", "category": "ui"},
    "_OBJC_CLASS_$_NSFont": {"lib": "AppKit", "purpose": "font class", "category": "ui"},
    "_OBJC_CLASS_$_NSImage": {"lib": "AppKit", "purpose": "image class", "category": "ui"},
    "_OBJC_CLASS_$_NSBezierPath": {"lib": "AppKit", "purpose": "bezier path class", "category": "ui"},
    "_OBJC_CLASS_$_NSGradient": {"lib": "AppKit", "purpose": "gradient class", "category": "ui"},
    "_OBJC_CLASS_$_NSShadow": {"lib": "AppKit", "purpose": "shadow class", "category": "ui"},
    # Foundation-level (often used with AppKit)
    "_OBJC_CLASS_$_NSRunLoop": {"lib": "Foundation", "purpose": "run loop class", "category": "foundation"},
    "_OBJC_CLASS_$_NSTimer": {"lib": "Foundation", "purpose": "timer class", "category": "foundation"},
    "_OBJC_CLASS_$_NSThread": {"lib": "Foundation", "purpose": "thread class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSOperationQueue": {"lib": "Foundation", "purpose": "operation queue class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSBlockOperation": {"lib": "Foundation", "purpose": "block operation class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSNotificationCenter": {"lib": "Foundation", "purpose": "notification center class", "category": "foundation"},
    "_OBJC_CLASS_$_NSDistributedNotificationCenter": {"lib": "Foundation", "purpose": "distributed notification center class", "category": "foundation"},
    "_OBJC_CLASS_$_NSFileManager": {"lib": "Foundation", "purpose": "file manager class", "category": "filesystem"},
    "_OBJC_CLASS_$_NSBundle": {"lib": "Foundation", "purpose": "bundle class", "category": "foundation"},
    "_OBJC_CLASS_$_NSProcessInfo": {"lib": "Foundation", "purpose": "process info class", "category": "foundation"},
    "_OBJC_CLASS_$_NSUserDefaults": {"lib": "Foundation", "purpose": "user defaults class", "category": "persistence"},
    "_OBJC_CLASS_$_NSData": {"lib": "Foundation", "purpose": "data class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableData": {"lib": "Foundation", "purpose": "mutable data class", "category": "foundation"},
    "_OBJC_CLASS_$_NSString": {"lib": "Foundation", "purpose": "string class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableString": {"lib": "Foundation", "purpose": "mutable string class", "category": "foundation"},
    "_OBJC_CLASS_$_NSArray": {"lib": "Foundation", "purpose": "array class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableArray": {"lib": "Foundation", "purpose": "mutable array class", "category": "foundation"},
    "_OBJC_CLASS_$_NSDictionary": {"lib": "Foundation", "purpose": "dictionary class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableDictionary": {"lib": "Foundation", "purpose": "mutable dictionary class", "category": "foundation"},
    "_OBJC_CLASS_$_NSSet": {"lib": "Foundation", "purpose": "set class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableSet": {"lib": "Foundation", "purpose": "mutable set class", "category": "foundation"},
    "_OBJC_CLASS_$_NSURLSession": {"lib": "Foundation", "purpose": "URL session class", "category": "network"},
    "_OBJC_CLASS_$_NSURLRequest": {"lib": "Foundation", "purpose": "URL request class", "category": "network"},
    "_OBJC_CLASS_$_NSMutableURLRequest": {"lib": "Foundation", "purpose": "mutable URL request class", "category": "network"},
    "_OBJC_CLASS_$_NSURLSessionConfiguration": {"lib": "Foundation", "purpose": "URL session configuration class", "category": "network"},
    "_OBJC_CLASS_$_NSJSONSerialization": {"lib": "Foundation", "purpose": "JSON serialization class", "category": "foundation"},
    "_OBJC_CLASS_$_NSPropertyListSerialization": {"lib": "Foundation", "purpose": "plist serialization class", "category": "foundation"},
    "_OBJC_CLASS_$_NSKeyedArchiver": {"lib": "Foundation", "purpose": "keyed archiver class", "category": "persistence"},
    "_OBJC_CLASS_$_NSKeyedUnarchiver": {"lib": "Foundation", "purpose": "keyed unarchiver class", "category": "persistence"},
    "_OBJC_CLASS_$_NSTask": {"lib": "Foundation", "purpose": "subprocess task class", "category": "process"},
    "_OBJC_CLASS_$_NSPipe": {"lib": "Foundation", "purpose": "pipe class for IPC", "category": "process"},
    "_OBJC_CLASS_$_NSPasteboard": {"lib": "AppKit", "purpose": "pasteboard (clipboard) class", "category": "ui"},
    "_OBJC_CLASS_$_NSStatusBar": {"lib": "AppKit", "purpose": "status bar class", "category": "ui"},
    "_OBJC_CLASS_$_NSStatusItem": {"lib": "AppKit", "purpose": "status bar item class", "category": "ui"},
    "_OBJC_CLASS_$_NSDraggingItem": {"lib": "AppKit", "purpose": "dragging item class", "category": "ui"},
    "_OBJC_CLASS_$_NSWorkspace": {"lib": "AppKit", "purpose": "workspace class (open URLs, apps)", "category": "ui"},
    "_OBJC_CLASS_$_NSAppearance": {"lib": "AppKit", "purpose": "appearance class (dark/light mode)", "category": "ui"},
}


# ---------------------------------------------------------------------------
# Boost C++ Libraries (~60)
# ---------------------------------------------------------------------------

_BOOST_SIGNATURES: dict[str, dict[str, str]] = {
    # boost::asio
    "__ZN5boost4asio10io_context": {"lib": "boost", "purpose": "boost::asio::io_context (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp6socket": {"lib": "boost", "purpose": "boost::asio::ip::tcp::socket (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp8acceptor": {"lib": "boost", "purpose": "boost::asio::ip::tcp::acceptor (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3tcp8resolver": {"lib": "boost", "purpose": "boost::asio::ip::tcp::resolver (partial mangled)", "category": "network"},
    "__ZN5boost4asio2ip3udp6socket": {"lib": "boost", "purpose": "boost::asio::ip::udp::socket (partial mangled)", "category": "network"},
    "__ZN5boost4asio3ssl6stream": {"lib": "boost", "purpose": "boost::asio::ssl::stream (partial mangled)", "category": "network"},
    "__ZN5boost4asio14deadline_timer": {"lib": "boost", "purpose": "boost::asio::deadline_timer (partial mangled)", "category": "network"},
    "__ZN5boost4asio12steady_timer": {"lib": "boost", "purpose": "boost::asio::steady_timer (partial mangled)", "category": "network"},
    "__ZN5boost4asio10async_read": {"lib": "boost", "purpose": "boost::asio::async_read (partial mangled)", "category": "network"},
    "__ZN5boost4asio11async_write": {"lib": "boost", "purpose": "boost::asio::async_write (partial mangled)", "category": "network"},
    "__ZN5boost4asio13async_connect": {"lib": "boost", "purpose": "boost::asio::async_connect (partial mangled)", "category": "network"},
    "__ZN5boost4asio": {"lib": "boost", "purpose": "boost::asio namespace (partial mangled prefix)", "category": "network"},
    # boost::filesystem
    "__ZN5boost10filesystem4path": {"lib": "boost", "purpose": "boost::filesystem::path (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem18directory_iterator": {"lib": "boost", "purpose": "boost::filesystem::directory_iterator (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem28recursive_directory_iterator": {"lib": "boost", "purpose": "boost::filesystem::recursive_directory_iterator (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem18create_directories": {"lib": "boost", "purpose": "boost::filesystem::create_directories (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem10remove_all": {"lib": "boost", "purpose": "boost::filesystem::remove_all (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem9copy_file": {"lib": "boost", "purpose": "boost::filesystem::copy_file (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem6exists": {"lib": "boost", "purpose": "boost::filesystem::exists (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem12is_directory": {"lib": "boost", "purpose": "boost::filesystem::is_directory (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem12is_regular_f": {"lib": "boost", "purpose": "boost::filesystem::is_regular_file (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem9file_size": {"lib": "boost", "purpose": "boost::filesystem::file_size (partial mangled)", "category": "filesystem"},
    "__ZN5boost10filesystem": {"lib": "boost", "purpose": "boost::filesystem namespace (partial mangled prefix)", "category": "filesystem"},
    # boost::thread
    "__ZN5boost6thread": {"lib": "boost", "purpose": "boost::thread (partial mangled)", "category": "concurrency"},
    "__ZN5boost5mutex": {"lib": "boost", "purpose": "boost::mutex (partial mangled)", "category": "concurrency"},
    "__ZN5boost12shared_mutex": {"lib": "boost", "purpose": "boost::shared_mutex (partial mangled)", "category": "concurrency"},
    "__ZN5boost18condition_variable": {"lib": "boost", "purpose": "boost::condition_variable (partial mangled)", "category": "concurrency"},
    "__ZN5boost6future": {"lib": "boost", "purpose": "boost::future (partial mangled)", "category": "concurrency"},
    "__ZN5boost7promise": {"lib": "boost", "purpose": "boost::promise (partial mangled)", "category": "concurrency"},
    # boost::algorithm
    "__ZN5boost9algorithm8to_lower": {"lib": "boost", "purpose": "boost::algorithm::to_lower (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm8to_upper": {"lib": "boost", "purpose": "boost::algorithm::to_upper (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm4trim": {"lib": "boost", "purpose": "boost::algorithm::trim (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm5split": {"lib": "boost", "purpose": "boost::algorithm::split (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm4join": {"lib": "boost", "purpose": "boost::algorithm::join (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm11replace_all": {"lib": "boost", "purpose": "boost::algorithm::replace_all (partial mangled)", "category": "string"},
    "__ZN5boost9algorithm": {"lib": "boost", "purpose": "boost::algorithm namespace (partial mangled prefix)", "category": "string"},
    # boost::program_options
    "__ZN5boost15program_options19options_description": {"lib": "boost", "purpose": "boost::program_options::options_description (partial mangled)", "category": "config"},
    "__ZN5boost15program_options13variables_map": {"lib": "boost", "purpose": "boost::program_options::variables_map (partial mangled)", "category": "config"},
    "__ZN5boost15program_options5store": {"lib": "boost", "purpose": "boost::program_options::store (partial mangled)", "category": "config"},
    "__ZN5boost15program_options6notify": {"lib": "boost", "purpose": "boost::program_options::notify (partial mangled)", "category": "config"},
    "__ZN5boost15program_options": {"lib": "boost", "purpose": "boost::program_options namespace (partial mangled prefix)", "category": "config"},
    # boost::beast
    "__ZN5boost5beast4http7request": {"lib": "boost", "purpose": "boost::beast::http::request (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http8response": {"lib": "boost", "purpose": "boost::beast::http::response (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http4read": {"lib": "boost", "purpose": "boost::beast::http::read (partial mangled)", "category": "network"},
    "__ZN5boost5beast4http5write": {"lib": "boost", "purpose": "boost::beast::http::write (partial mangled)", "category": "network"},
    "__ZN5boost5beast9websocket6stream": {"lib": "boost", "purpose": "boost::beast::websocket::stream (partial mangled)", "category": "network"},
    "__ZN5boost5beast": {"lib": "boost", "purpose": "boost::beast namespace (partial mangled prefix)", "category": "network"},
    # boost::json
    "__ZN5boost4json5parse": {"lib": "boost", "purpose": "boost::json::parse (partial mangled)", "category": "serialization"},
    "__ZN5boost4json9serialize": {"lib": "boost", "purpose": "boost::json::serialize (partial mangled)", "category": "serialization"},
    "__ZN5boost4json5value": {"lib": "boost", "purpose": "boost::json::value (partial mangled)", "category": "serialization"},
    "__ZN5boost4json6object": {"lib": "boost", "purpose": "boost::json::object (partial mangled)", "category": "serialization"},
    "__ZN5boost4json5array": {"lib": "boost", "purpose": "boost::json::array (partial mangled)", "category": "serialization"},
    "__ZN5boost4json": {"lib": "boost", "purpose": "boost::json namespace (partial mangled prefix)", "category": "serialization"},
    # boost::log
    "__ZN5boost3log": {"lib": "boost", "purpose": "boost::log namespace (partial mangled prefix)", "category": "logging"},
    # boost::regex
    "__ZN5boost5regex": {"lib": "boost", "purpose": "boost::regex (partial mangled)", "category": "string"},
    "__ZN5boost11regex_match": {"lib": "boost", "purpose": "boost::regex_match (partial mangled)", "category": "string"},
    "__ZN5boost12regex_search": {"lib": "boost", "purpose": "boost::regex_search (partial mangled)", "category": "string"},
    "__ZN5boost13regex_replace": {"lib": "boost", "purpose": "boost::regex_replace (partial mangled)", "category": "string"},
}


# ---------------------------------------------------------------------------
# Google Abseil (~45)
# ---------------------------------------------------------------------------

_ABSEIL_SIGNATURES: dict[str, dict[str, str]] = {
    "__ZN4absl": {"lib": "abseil", "purpose": "absl:: namespace (partial mangled prefix)", "category": "utility"},
    # String utilities
    "__ZN4absl6StrCat": {"lib": "abseil", "purpose": "absl::StrCat (partial mangled)", "category": "string"},
    "__ZN4absl7StrJoin": {"lib": "abseil", "purpose": "absl::StrJoin (partial mangled)", "category": "string"},
    "__ZN4absl8StrSplit": {"lib": "abseil", "purpose": "absl::StrSplit (partial mangled)", "category": "string"},
    "__ZN4absl9StrFormat": {"lib": "abseil", "purpose": "absl::StrFormat (partial mangled)", "category": "string"},
    "__ZN4absl10Substitute": {"lib": "abseil", "purpose": "absl::Substitute (partial mangled)", "category": "string"},
    "__ZN4absl9StrAppend": {"lib": "abseil", "purpose": "absl::StrAppend (partial mangled)", "category": "string"},
    "__ZN4absl11string_view": {"lib": "abseil", "purpose": "absl::string_view (partial mangled)", "category": "string"},
    # Containers
    "__ZN4absl13flat_hash_map": {"lib": "abseil", "purpose": "absl::flat_hash_map (partial mangled)", "category": "container"},
    "__ZN4absl13flat_hash_set": {"lib": "abseil", "purpose": "absl::flat_hash_set (partial mangled)", "category": "container"},
    "__ZN4absl13node_hash_map": {"lib": "abseil", "purpose": "absl::node_hash_map (partial mangled)", "category": "container"},
    "__ZN4absl13node_hash_set": {"lib": "abseil", "purpose": "absl::node_hash_set (partial mangled)", "category": "container"},
    "__ZN4absl13InlinedVector": {"lib": "abseil", "purpose": "absl::InlinedVector (partial mangled)", "category": "container"},
    "__ZN4absl10FixedArray": {"lib": "abseil", "purpose": "absl::FixedArray (partial mangled)", "category": "container"},
    "__ZN4absl4Span": {"lib": "abseil", "purpose": "absl::Span (partial mangled)", "category": "container"},
    "__ZN4absl15btree_multimap": {"lib": "abseil", "purpose": "absl::btree_multimap (partial mangled)", "category": "container"},
    "__ZN4absl9btree_map": {"lib": "abseil", "purpose": "absl::btree_map (partial mangled)", "category": "container"},
    "__ZN4absl9btree_set": {"lib": "abseil", "purpose": "absl::btree_set (partial mangled)", "category": "container"},
    # Status
    "__ZN4absl6Status": {"lib": "abseil", "purpose": "absl::Status (partial mangled)", "category": "error"},
    "__ZN4absl8StatusOr": {"lib": "abseil", "purpose": "absl::StatusOr (partial mangled)", "category": "error"},
    "__ZN4absl8OkStatus": {"lib": "abseil", "purpose": "absl::OkStatus (partial mangled)", "category": "error"},
    "__ZN4absl15AbortedError": {"lib": "abseil", "purpose": "absl::AbortedError (partial mangled)", "category": "error"},
    "__ZN4absl18InvalidArgumentError": {"lib": "abseil", "purpose": "absl::InvalidArgumentError (partial mangled)", "category": "error"},
    "__ZN4absl14NotFoundError": {"lib": "abseil", "purpose": "absl::NotFoundError (partial mangled)", "category": "error"},
    # Synchronization
    "__ZN4absl5Mutex": {"lib": "abseil", "purpose": "absl::Mutex (partial mangled)", "category": "concurrency"},
    "__ZN4absl9MutexLock": {"lib": "abseil", "purpose": "absl::MutexLock (partial mangled)", "category": "concurrency"},
    "__ZN4absl7CondVar": {"lib": "abseil", "purpose": "absl::CondVar (partial mangled)", "category": "concurrency"},
    "__ZN4absl13base_internal8SpinLock": {"lib": "abseil", "purpose": "absl::base_internal::SpinLock (partial mangled)", "category": "concurrency"},
    "__ZN4absl11Notification": {"lib": "abseil", "purpose": "absl::Notification (partial mangled)", "category": "concurrency"},
    # Time
    "__ZN4absl8Duration": {"lib": "abseil", "purpose": "absl::Duration (partial mangled)", "category": "time"},
    "__ZN4absl4Time": {"lib": "abseil", "purpose": "absl::Time (partial mangled)", "category": "time"},
    "__ZN4absl3Now": {"lib": "abseil", "purpose": "absl::Now (partial mangled)", "category": "time"},
    "__ZN4absl8SleepFor": {"lib": "abseil", "purpose": "absl::SleepFor (partial mangled)", "category": "time"},
    "__ZN4absl7Seconds": {"lib": "abseil", "purpose": "absl::Seconds (partial mangled)", "category": "time"},
    "__ZN4absl12Milliseconds": {"lib": "abseil", "purpose": "absl::Milliseconds (partial mangled)", "category": "time"},
    "__ZN4absl12Microseconds": {"lib": "abseil", "purpose": "absl::Microseconds (partial mangled)", "category": "time"},
    "__ZN4absl11Nanoseconds": {"lib": "abseil", "purpose": "absl::Nanoseconds (partial mangled)", "category": "time"},
    # Flags
    "__ZN4absl7GetFlag": {"lib": "abseil", "purpose": "absl::GetFlag (partial mangled)", "category": "config"},
    "__ZN4absl7SetFlag": {"lib": "abseil", "purpose": "absl::SetFlag (partial mangled)", "category": "config"},
    "__ZN4absl16ParseCommandLine": {"lib": "abseil", "purpose": "absl::ParseCommandLine (partial mangled)", "category": "config"},
    # Logging
    "__ZN4absl10LogMessage": {"lib": "abseil", "purpose": "absl::LogMessage (partial mangled)", "category": "logging"},
    # Hashing
    "__ZN4absl7HashOf": {"lib": "abseil", "purpose": "absl::HashOf (partial mangled)", "category": "utility"},
    "__ZN4absl11MakeHashState": {"lib": "abseil", "purpose": "absl::MakeHashState (partial mangled)", "category": "utility"},
}


# ---------------------------------------------------------------------------
# Facebook Folly (~33)
# ---------------------------------------------------------------------------

_FOLLY_SIGNATURES: dict[str, dict[str, str]] = {
    "__ZN5folly": {"lib": "folly", "purpose": "folly:: namespace (partial mangled prefix)", "category": "utility"},
    # Futures & Promises
    "__ZN5folly6Future": {"lib": "folly", "purpose": "folly::Future (partial mangled)", "category": "concurrency"},
    "__ZN5folly7Promise": {"lib": "folly", "purpose": "folly::Promise (partial mangled)", "category": "concurrency"},
    "__ZN5folly10makeFuture": {"lib": "folly", "purpose": "folly::makeFuture (partial mangled)", "category": "concurrency"},
    "__ZN5folly12SemiFuture": {"lib": "folly", "purpose": "folly::SemiFuture (partial mangled)", "category": "concurrency"},
    # Strings & Data
    "__ZN5folly8fbstring": {"lib": "folly", "purpose": "folly::fbstring (partial mangled)", "category": "string"},
    "__ZN5folly8fbvector": {"lib": "folly", "purpose": "folly::fbvector (partial mangled)", "category": "container"},
    "__ZN5folly7dynamic": {"lib": "folly", "purpose": "folly::dynamic (partial mangled)", "category": "serialization"},
    "__ZN5folly9parseJson": {"lib": "folly", "purpose": "folly::parseJson (partial mangled)", "category": "serialization"},
    "__ZN5folly6toJson": {"lib": "folly", "purpose": "folly::toJson (partial mangled)", "category": "serialization"},
    "__ZN5folly11toPrettyJson": {"lib": "folly", "purpose": "folly::toPrettyJson (partial mangled)", "category": "serialization"},
    # IO
    "__ZN5folly5IOBuf": {"lib": "folly", "purpose": "folly::IOBuf (partial mangled)", "category": "io"},
    "__ZN5folly10IOBufQueue": {"lib": "folly", "purpose": "folly::IOBufQueue (partial mangled)", "category": "io"},
    # Event & Async
    "__ZN5folly9EventBase": {"lib": "folly", "purpose": "folly::EventBase (partial mangled)", "category": "network"},
    "__ZN5folly11AsyncSocket": {"lib": "folly", "purpose": "folly::AsyncSocket (partial mangled)", "category": "network"},
    "__ZN5folly17AsyncServerSocket": {"lib": "folly", "purpose": "folly::AsyncServerSocket (partial mangled)", "category": "network"},
    "__ZN5folly17AsyncSSLSocket": {"lib": "folly", "purpose": "folly::AsyncSSLSocket (partial mangled)", "category": "network"},
    # Executors
    "__ZN5folly8Executor": {"lib": "folly", "purpose": "folly::Executor (partial mangled)", "category": "concurrency"},
    "__ZN5folly21CPUThreadPoolExecutor": {"lib": "folly", "purpose": "folly::CPUThreadPoolExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly20IOThreadPoolExecutor": {"lib": "folly", "purpose": "folly::IOThreadPoolExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly13ManualExecutor": {"lib": "folly", "purpose": "folly::ManualExecutor (partial mangled)", "category": "concurrency"},
    "__ZN5folly15InlineExecutor": {"lib": "folly", "purpose": "folly::InlineExecutor (partial mangled)", "category": "concurrency"},
    # Singleton & Init
    "__ZN5folly9Singleton": {"lib": "folly", "purpose": "folly::Singleton (partial mangled)", "category": "utility"},
    "__ZN5folly4init": {"lib": "folly", "purpose": "folly::init (partial mangled)", "category": "utility"},
    # Optional / Expected
    "__ZN5folly8Optional": {"lib": "folly", "purpose": "folly::Optional (partial mangled)", "category": "utility"},
    "__ZN5folly8Expected": {"lib": "folly", "purpose": "folly::Expected (partial mangled)", "category": "utility"},
    # Concurrent containers
    "__ZN5folly17ConcurrentHashMap": {"lib": "folly", "purpose": "folly::ConcurrentHashMap (partial mangled)", "category": "container"},
    "__ZN5folly14AtomicHashMap": {"lib": "folly", "purpose": "folly::AtomicHashMap (partial mangled)", "category": "container"},
    "__ZN5folly17AtomicLinkedList": {"lib": "folly", "purpose": "folly::AtomicLinkedList (partial mangled)", "category": "container"},
    # Conv (type conversion)
    "__ZN5folly2to": {"lib": "folly", "purpose": "folly::to<T> conversion (partial mangled)", "category": "utility"},
    # Format
    "__ZN5folly6format": {"lib": "folly", "purpose": "folly::format (partial mangled)", "category": "string"},
    "__ZN5folly7sformat": {"lib": "folly", "purpose": "folly::sformat (partial mangled)", "category": "string"},
}


# ---------------------------------------------------------------------------
# Logging Frameworks -- spdlog, log4cxx, glog (~30)
# ---------------------------------------------------------------------------

_LOGGING_SIGNATURES: dict[str, dict[str, str]] = {
    # spdlog
    "__ZN6spdlog3get": {"lib": "spdlog", "purpose": "spdlog::get (get logger by name)", "category": "logging"},
    "__ZN6spdlog11set_pattern": {"lib": "spdlog", "purpose": "spdlog::set_pattern (set log format)", "category": "logging"},
    "__ZN6spdlog9set_level": {"lib": "spdlog", "purpose": "spdlog::set_level (set log level)", "category": "logging"},
    "__ZN6spdlog6logger3log": {"lib": "spdlog", "purpose": "spdlog::logger::log (write log entry)", "category": "logging"},
    "__ZN6spdlog6logger5flush": {"lib": "spdlog", "purpose": "spdlog::logger::flush (flush log buffer)", "category": "logging"},
    "__ZN6spdlog6logger4info": {"lib": "spdlog", "purpose": "spdlog::logger::info (log info level)", "category": "logging"},
    "__ZN6spdlog6logger4warn": {"lib": "spdlog", "purpose": "spdlog::logger::warn (log warn level)", "category": "logging"},
    "__ZN6spdlog6logger5error": {"lib": "spdlog", "purpose": "spdlog::logger::error (log error level)", "category": "logging"},
    "__ZN6spdlog6logger5debug": {"lib": "spdlog", "purpose": "spdlog::logger::debug (log debug level)", "category": "logging"},
    "__ZN6spdlog6logger8critical": {"lib": "spdlog", "purpose": "spdlog::logger::critical (log critical level)", "category": "logging"},
    "__ZN6spdlog7details11thread_pool": {"lib": "spdlog", "purpose": "spdlog::details::thread_pool (async logging)", "category": "logging"},
    "__ZN6spdlog5sinks": {"lib": "spdlog", "purpose": "spdlog::sinks namespace (partial mangled)", "category": "logging"},
    "__ZN6spdlog10basic_logger_mt": {"lib": "spdlog", "purpose": "spdlog::basic_logger_mt (create file logger)", "category": "logging"},
    "__ZN6spdlog12rotating_logger_mt": {"lib": "spdlog", "purpose": "spdlog::rotating_logger_mt (rotating file logger)", "category": "logging"},
    "__ZN6spdlog11daily_logger_mt": {"lib": "spdlog", "purpose": "spdlog::daily_logger_mt (daily rotating logger)", "category": "logging"},
    "__ZN6spdlog13stdout_color_mt": {"lib": "spdlog", "purpose": "spdlog::stdout_color_mt (colored stdout logger)", "category": "logging"},
    "__ZN6spdlog": {"lib": "spdlog", "purpose": "spdlog:: namespace (partial mangled prefix)", "category": "logging"},
    # log4cxx
    "__ZN7log4cxx6Logger": {"lib": "log4cxx", "purpose": "log4cxx::Logger (partial mangled)", "category": "logging"},
    "__ZN7log4cxx10BasicConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::BasicConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx20PropertyConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::PropertyConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx18DOMConfigurator": {"lib": "log4cxx", "purpose": "log4cxx::DOMConfigurator (partial mangled)", "category": "logging"},
    "__ZN7log4cxx5Level": {"lib": "log4cxx", "purpose": "log4cxx::Level (partial mangled)", "category": "logging"},
    "__ZN7log4cxx": {"lib": "log4cxx", "purpose": "log4cxx:: namespace (partial mangled prefix)", "category": "logging"},
    # glog
    "__ZN6google17InitGoogleLogging": {"lib": "glog", "purpose": "google::InitGoogleLogging (init glog)", "category": "logging"},
    "__ZN6google10LogMessage": {"lib": "glog", "purpose": "google::LogMessage (log message class)", "category": "logging"},
    "__ZN6google20ShutdownGoogleLogging": {"lib": "glog", "purpose": "google::ShutdownGoogleLogging (shutdown glog)", "category": "logging"},
    "__ZN6google11SetLogDestination": {"lib": "glog", "purpose": "google::SetLogDestination (set log output)", "category": "logging"},
    "__ZN6google17SetLogFilenameExtension": {"lib": "glog", "purpose": "google::SetLogFilenameExtension (set log extension)", "category": "logging"},
    "__ZN6google15InstallFailureSignalHandler": {"lib": "glog", "purpose": "google::InstallFailureSignalHandler (crash handler)", "category": "logging"},
    "__ZN6google8RawLog__": {"lib": "glog", "purpose": "google::RawLog__ (raw log without allocations)", "category": "logging"},
    # GLib logging
    "_g_log": {"lib": "glib", "purpose": "GLib structured log message", "category": "logging"},
    "_g_warning": {"lib": "glib", "purpose": "GLib warning message", "category": "logging"},
    "_g_error": {"lib": "glib", "purpose": "GLib error message (aborts)", "category": "logging"},
    "_g_message": {"lib": "glib", "purpose": "GLib informational message", "category": "logging"},
    "_g_debug": {"lib": "glib", "purpose": "GLib debug message", "category": "logging"},
    # Android logging
    "___android_log_print": {"lib": "android", "purpose": "Android logcat print (printf-style)", "category": "logging"},
    "___android_log_write": {"lib": "android", "purpose": "Android logcat write (simple string)", "category": "logging"},
    # macOS unified logging (os_log)
    "_os_log_create": {"lib": "os_log", "purpose": "Create os_log object (subsystem+category)", "category": "logging"},
    "_os_log": {"lib": "os_log", "purpose": "Log message via unified logging", "category": "logging"},
    "_os_log_error": {"lib": "os_log", "purpose": "Log error via unified logging", "category": "logging"},
    "_os_log_debug": {"lib": "os_log", "purpose": "Log debug via unified logging", "category": "logging"},
    "_os_log_info": {"lib": "os_log", "purpose": "Log info via unified logging", "category": "logging"},
    # Apple System Log (legacy)
    "_asl_open": {"lib": "asl", "purpose": "Open ASL client handle (legacy)", "category": "logging"},
    "_asl_log": {"lib": "asl", "purpose": "Log message via ASL (legacy)", "category": "logging"},
    "_asl_close": {"lib": "asl", "purpose": "Close ASL client handle (legacy)", "category": "logging"},
}


# ---------------------------------------------------------------------------
# Serialization -- FlatBuffers, Cap'n Proto, MessagePack (~40)
# ---------------------------------------------------------------------------

_SERIALIZATION_SIGNATURES: dict[str, dict[str, str]] = {
    # FlatBuffers
    "__ZN11flatbuffers17FlatBufferBuilder": {"lib": "flatbuffers", "purpose": "flatbuffers::FlatBufferBuilder (partial mangled)", "category": "serialization"},
    "__ZN11flatbuffers8Verifier": {"lib": "flatbuffers", "purpose": "flatbuffers::Verifier (partial mangled)", "category": "serialization"},
    "__ZN11flatbuffers7GetRoot": {"lib": "flatbuffers", "purpose": "flatbuffers::GetRoot (partial mangled)", "category": "serialization"},
    "__ZN11flatbuffers12CreateString": {"lib": "flatbuffers", "purpose": "flatbuffers::CreateString (partial mangled)", "category": "serialization"},
    "__ZN11flatbuffers12CreateVector": {"lib": "flatbuffers", "purpose": "flatbuffers::CreateVector (partial mangled)", "category": "serialization"},
    "__ZN11flatbuffers": {"lib": "flatbuffers", "purpose": "flatbuffers:: namespace (partial mangled prefix)", "category": "serialization"},
    # Cap'n Proto
    "__ZN5capnp14MessageBuilder": {"lib": "capnproto", "purpose": "capnp::MessageBuilder (partial mangled)", "category": "serialization"},
    "__ZN5capnp13MessageReader": {"lib": "capnproto", "purpose": "capnp::MessageReader (partial mangled)", "category": "serialization"},
    "__ZN5capnp19MallocMessageBuilder": {"lib": "capnproto", "purpose": "capnp::MallocMessageBuilder (partial mangled)", "category": "serialization"},
    "__ZN5capnp20StreamFdMessageReader": {"lib": "capnproto", "purpose": "capnp::StreamFdMessageReader (partial mangled)", "category": "serialization"},
    "__ZN5capnp17PackedMessageReader": {"lib": "capnproto", "purpose": "capnp::PackedMessageReader (partial mangled)", "category": "serialization"},
    "__ZN5capnp11writeMessage": {"lib": "capnproto", "purpose": "capnp::writeMessage (partial mangled)", "category": "serialization"},
    "__ZN5capnp": {"lib": "capnproto", "purpose": "capnp:: namespace (partial mangled prefix)", "category": "serialization"},
    # MessagePack (C API)
    "_msgpack_pack_int": {"lib": "msgpack", "purpose": "pack integer value", "category": "serialization"},
    "_msgpack_pack_int8": {"lib": "msgpack", "purpose": "pack int8 value", "category": "serialization"},
    "_msgpack_pack_int16": {"lib": "msgpack", "purpose": "pack int16 value", "category": "serialization"},
    "_msgpack_pack_int32": {"lib": "msgpack", "purpose": "pack int32 value", "category": "serialization"},
    "_msgpack_pack_int64": {"lib": "msgpack", "purpose": "pack int64 value", "category": "serialization"},
    "_msgpack_pack_uint8": {"lib": "msgpack", "purpose": "pack uint8 value", "category": "serialization"},
    "_msgpack_pack_uint16": {"lib": "msgpack", "purpose": "pack uint16 value", "category": "serialization"},
    "_msgpack_pack_uint32": {"lib": "msgpack", "purpose": "pack uint32 value", "category": "serialization"},
    "_msgpack_pack_uint64": {"lib": "msgpack", "purpose": "pack uint64 value", "category": "serialization"},
    "_msgpack_pack_float": {"lib": "msgpack", "purpose": "pack float value", "category": "serialization"},
    "_msgpack_pack_double": {"lib": "msgpack", "purpose": "pack double value", "category": "serialization"},
    "_msgpack_pack_str": {"lib": "msgpack", "purpose": "pack string header", "category": "serialization"},
    "_msgpack_pack_str_body": {"lib": "msgpack", "purpose": "pack string body", "category": "serialization"},
    "_msgpack_pack_bin": {"lib": "msgpack", "purpose": "pack binary header", "category": "serialization"},
    "_msgpack_pack_bin_body": {"lib": "msgpack", "purpose": "pack binary body", "category": "serialization"},
    "_msgpack_pack_array": {"lib": "msgpack", "purpose": "pack array header", "category": "serialization"},
    "_msgpack_pack_map": {"lib": "msgpack", "purpose": "pack map header", "category": "serialization"},
    "_msgpack_pack_nil": {"lib": "msgpack", "purpose": "pack nil value", "category": "serialization"},
    "_msgpack_pack_true": {"lib": "msgpack", "purpose": "pack true value", "category": "serialization"},
    "_msgpack_pack_false": {"lib": "msgpack", "purpose": "pack false value", "category": "serialization"},
    "_msgpack_unpack": {"lib": "msgpack", "purpose": "unpack message", "category": "serialization"},
    "_msgpack_unpack_next": {"lib": "msgpack", "purpose": "unpack next object", "category": "serialization"},
    "_msgpack_unpacked_init": {"lib": "msgpack", "purpose": "init unpacked object", "category": "serialization"},
    "_msgpack_unpacked_destroy": {"lib": "msgpack", "purpose": "destroy unpacked object", "category": "serialization"},
    "_msgpack_sbuffer_init": {"lib": "msgpack", "purpose": "init simple buffer", "category": "serialization"},
    "_msgpack_sbuffer_destroy": {"lib": "msgpack", "purpose": "destroy simple buffer", "category": "serialization"},
    "_msgpack_packer_init": {"lib": "msgpack", "purpose": "init packer", "category": "serialization"},
    "_msgpack_packer_new": {"lib": "msgpack", "purpose": "create new packer", "category": "serialization"},
    "_msgpack_packer_free": {"lib": "msgpack", "purpose": "free packer", "category": "serialization"},
    "_msgpack_zone_init": {"lib": "msgpack", "purpose": "init memory zone", "category": "serialization"},
    "_msgpack_zone_destroy": {"lib": "msgpack", "purpose": "destroy memory zone", "category": "serialization"},
}


# ---------------------------------------------------------------------------
# Windows API -- kernel32 (~55)
# Cross-compiled binary'lerde veya Wine wrapper'larda gorulen temel API'ler.
# DLL export isimleri oldugu gibi kullanilir (prefix yok).
# ---------------------------------------------------------------------------

_WIN32_KERNEL32_SIGNATURES: dict[str, dict[str, str]] = {
    # File I/O
    "CreateFileA": {"lib": "kernel32", "purpose": "open/create file (ANSI)", "category": "win_file"},
    "CreateFileW": {"lib": "kernel32", "purpose": "open/create file (Unicode)", "category": "win_file"},
    "ReadFile": {"lib": "kernel32", "purpose": "read data from file or I/O device", "category": "win_file"},
    "WriteFile": {"lib": "kernel32", "purpose": "write data to file or I/O device", "category": "win_file"},
    "CloseHandle": {"lib": "kernel32", "purpose": "close an open object handle", "category": "win_file"},

    # Process management
    "CreateProcessA": {"lib": "kernel32", "purpose": "create new process (ANSI)", "category": "win_process"},
    "CreateProcessW": {"lib": "kernel32", "purpose": "create new process (Unicode)", "category": "win_process"},
    "TerminateProcess": {"lib": "kernel32", "purpose": "terminate a process", "category": "win_process"},
    "ExitProcess": {"lib": "kernel32", "purpose": "end calling process and all threads", "category": "win_process"},
    "GetExitCodeProcess": {"lib": "kernel32", "purpose": "get termination status of process", "category": "win_process"},

    # Virtual memory
    "VirtualAlloc": {"lib": "kernel32", "purpose": "reserve/commit virtual memory pages", "category": "win_memory"},
    "VirtualFree": {"lib": "kernel32", "purpose": "release/decommit virtual memory pages", "category": "win_memory"},
    "VirtualProtect": {"lib": "kernel32", "purpose": "change access protection on memory pages", "category": "win_memory"},
    "VirtualQuery": {"lib": "kernel32", "purpose": "query information about memory pages", "category": "win_memory"},

    # Heap
    "HeapCreate": {"lib": "kernel32", "purpose": "create private heap object", "category": "win_memory"},
    "HeapDestroy": {"lib": "kernel32", "purpose": "destroy private heap object", "category": "win_memory"},
    "HeapAlloc": {"lib": "kernel32", "purpose": "allocate memory block from heap", "category": "win_memory"},
    "HeapReAlloc": {"lib": "kernel32", "purpose": "reallocate memory block from heap", "category": "win_memory"},
    "HeapFree": {"lib": "kernel32", "purpose": "free memory block allocated from heap", "category": "win_memory"},

    # Thread management
    "CreateThread": {"lib": "kernel32", "purpose": "create new thread in calling process", "category": "win_thread"},
    "ExitThread": {"lib": "kernel32", "purpose": "end calling thread", "category": "win_thread"},
    "SuspendThread": {"lib": "kernel32", "purpose": "suspend a thread", "category": "win_thread"},
    "ResumeThread": {"lib": "kernel32", "purpose": "decrement thread suspend count", "category": "win_thread"},
    "WaitForSingleObject": {"lib": "kernel32", "purpose": "wait until object is signaled or timeout", "category": "win_sync"},
    "WaitForMultipleObjects": {"lib": "kernel32", "purpose": "wait for multiple objects to be signaled", "category": "win_sync"},

    # Synchronization primitives
    "CreateMutexA": {"lib": "kernel32", "purpose": "create named/unnamed mutex (ANSI)", "category": "win_sync"},
    "ReleaseMutex": {"lib": "kernel32", "purpose": "release ownership of mutex", "category": "win_sync"},
    "CreateEventA": {"lib": "kernel32", "purpose": "create named/unnamed event (ANSI)", "category": "win_sync"},
    "SetEvent": {"lib": "kernel32", "purpose": "set event object to signaled state", "category": "win_sync"},
    "ResetEvent": {"lib": "kernel32", "purpose": "set event object to nonsignaled state", "category": "win_sync"},
    "CreateSemaphoreA": {"lib": "kernel32", "purpose": "create named/unnamed semaphore (ANSI)", "category": "win_sync"},
    "ReleaseSemaphore": {"lib": "kernel32", "purpose": "increase semaphore count", "category": "win_sync"},
    "InitializeCriticalSection": {"lib": "kernel32", "purpose": "initialize critical section object", "category": "win_sync"},
    "EnterCriticalSection": {"lib": "kernel32", "purpose": "enter critical section (blocking)", "category": "win_sync"},
    "LeaveCriticalSection": {"lib": "kernel32", "purpose": "leave critical section", "category": "win_sync"},
    "DeleteCriticalSection": {"lib": "kernel32", "purpose": "release critical section resources", "category": "win_sync"},

    # Module / dynamic loading
    "GetModuleHandleA": {"lib": "kernel32", "purpose": "get handle to loaded module (ANSI)", "category": "win_module"},
    "GetModuleHandleW": {"lib": "kernel32", "purpose": "get handle to loaded module (Unicode)", "category": "win_module"},
    "GetProcAddress": {"lib": "kernel32", "purpose": "get address of exported function", "category": "win_module"},
    "LoadLibraryA": {"lib": "kernel32", "purpose": "load DLL into process (ANSI)", "category": "win_module"},
    "LoadLibraryW": {"lib": "kernel32", "purpose": "load DLL into process (Unicode)", "category": "win_module"},
    "FreeLibrary": {"lib": "kernel32", "purpose": "unload DLL from process", "category": "win_module"},

    # Error handling
    "GetLastError": {"lib": "kernel32", "purpose": "get last Win32 error code", "category": "win_error"},
    "SetLastError": {"lib": "kernel32", "purpose": "set last Win32 error code", "category": "win_error"},
    "FormatMessageA": {"lib": "kernel32", "purpose": "format error message string (ANSI)", "category": "win_error"},

    # System info / timing
    "GetSystemInfo": {"lib": "kernel32", "purpose": "get system hardware information", "category": "win_system"},
    "GetVersionExA": {"lib": "kernel32", "purpose": "get OS version information (ANSI)", "category": "win_system"},
    "GetTickCount": {"lib": "kernel32", "purpose": "get milliseconds since system start (32-bit)", "category": "win_time"},
    "GetTickCount64": {"lib": "kernel32", "purpose": "get milliseconds since system start (64-bit)", "category": "win_time"},
    "QueryPerformanceCounter": {"lib": "kernel32", "purpose": "query high-resolution performance counter", "category": "win_time"},
    "QueryPerformanceFrequency": {"lib": "kernel32", "purpose": "get performance counter frequency", "category": "win_time"},
    "Sleep": {"lib": "kernel32", "purpose": "suspend thread execution for milliseconds", "category": "win_time"},
    "SleepEx": {"lib": "kernel32", "purpose": "suspend thread execution (alertable)", "category": "win_time"},

    # Process / thread info
    "GetCurrentProcess": {"lib": "kernel32", "purpose": "get pseudo handle of current process", "category": "win_process"},
    "GetCurrentProcessId": {"lib": "kernel32", "purpose": "get PID of calling process", "category": "win_process"},
    "GetCurrentThread": {"lib": "kernel32", "purpose": "get pseudo handle of current thread", "category": "win_thread"},
    "GetCurrentThreadId": {"lib": "kernel32", "purpose": "get TID of calling thread", "category": "win_thread"},

    # Debug
    "OutputDebugStringA": {"lib": "kernel32", "purpose": "send string to debugger (ANSI)", "category": "win_debug"},
    "IsDebuggerPresent": {"lib": "kernel32", "purpose": "check if process is being debugged", "category": "win_debug"},
    "DebugBreak": {"lib": "kernel32", "purpose": "cause breakpoint exception in process", "category": "win_debug"},
}


# ---------------------------------------------------------------------------
# Windows API -- ws2_32 (Winsock) (~20)
# ---------------------------------------------------------------------------

_WIN32_WS2_32_SIGNATURES: dict[str, dict[str, str]] = {
    # Startup / cleanup
    "WSAStartup": {"lib": "ws2_32", "purpose": "initialize Winsock DLL", "category": "win_network"},
    "WSACleanup": {"lib": "ws2_32", "purpose": "terminate Winsock DLL usage", "category": "win_network"},
    "WSAGetLastError": {"lib": "ws2_32", "purpose": "get last Winsock error code", "category": "win_network"},

    # Socket basics
    "closesocket": {"lib": "ws2_32", "purpose": "close a socket", "category": "win_network"},

    # Data transfer
    "send": {"lib": "ws2_32", "purpose": "send data on connected socket", "category": "win_network"},
    "recv": {"lib": "ws2_32", "purpose": "receive data from connected socket", "category": "win_network"},
    "sendto": {"lib": "ws2_32", "purpose": "send data to specific destination", "category": "win_network"},
    "recvfrom": {"lib": "ws2_32", "purpose": "receive data and source address", "category": "win_network"},

    # Async / event-based I/O
    "select": {"lib": "ws2_32", "purpose": "monitor sockets for readability/writability", "category": "win_network"},
    "WSAEventSelect": {"lib": "ws2_32", "purpose": "associate event object with network events", "category": "win_network"},
    "WSAWaitForMultipleEvents": {"lib": "ws2_32", "purpose": "wait for multiple Winsock events", "category": "win_network"},

    # Socket control
    "ioctlsocket": {"lib": "ws2_32", "purpose": "control socket I/O mode", "category": "win_network"},
    "getaddrinfo": {"lib": "ws2_32", "purpose": "resolve host/service to address (protocol-independent)", "category": "win_network"},
    "freeaddrinfo": {"lib": "ws2_32", "purpose": "free addrinfo linked list", "category": "win_network"},
    "gethostbyname": {"lib": "ws2_32", "purpose": "resolve hostname to address (deprecated)", "category": "win_network"},

    # Address conversion
    "inet_addr": {"lib": "ws2_32", "purpose": "convert dotted-decimal IPv4 to in_addr", "category": "win_network"},
    "inet_ntoa": {"lib": "ws2_32", "purpose": "convert in_addr to dotted-decimal string", "category": "win_network"},
    "htons": {"lib": "ws2_32", "purpose": "host-to-network byte order (short)", "category": "win_network"},
    "ntohs": {"lib": "ws2_32", "purpose": "network-to-host byte order (short)", "category": "win_network"},
}


# ---------------------------------------------------------------------------
# Windows API -- advapi32 (~20)
# Registry, security, crypto, services.
# ---------------------------------------------------------------------------

_WIN32_ADVAPI32_SIGNATURES: dict[str, dict[str, str]] = {
    # Registry
    "RegOpenKeyExA": {"lib": "advapi32", "purpose": "open registry key (ANSI)", "category": "win_registry"},
    "RegCloseKey": {"lib": "advapi32", "purpose": "close registry key handle", "category": "win_registry"},
    "RegQueryValueExA": {"lib": "advapi32", "purpose": "query registry value data (ANSI)", "category": "win_registry"},
    "RegSetValueExA": {"lib": "advapi32", "purpose": "set registry value data (ANSI)", "category": "win_registry"},
    "RegDeleteValueA": {"lib": "advapi32", "purpose": "delete registry value (ANSI)", "category": "win_registry"},
    "RegCreateKeyExA": {"lib": "advapi32", "purpose": "create or open registry key (ANSI)", "category": "win_registry"},
    "RegEnumKeyExA": {"lib": "advapi32", "purpose": "enumerate registry subkeys (ANSI)", "category": "win_registry"},
    "RegEnumValueA": {"lib": "advapi32", "purpose": "enumerate registry values (ANSI)", "category": "win_registry"},

    # Token / privilege
    "OpenProcessToken": {"lib": "advapi32", "purpose": "open access token of a process", "category": "win_security"},
    "GetTokenInformation": {"lib": "advapi32", "purpose": "query process token information", "category": "win_security"},
    "AdjustTokenPrivileges": {"lib": "advapi32", "purpose": "enable/disable token privileges", "category": "win_security"},
    "LookupPrivilegeValueA": {"lib": "advapi32", "purpose": "look up privilege LUID (ANSI)", "category": "win_security"},

    # Cryptography (legacy CryptoAPI)
    "CryptAcquireContextA": {"lib": "advapi32", "purpose": "acquire handle to crypto provider (ANSI)", "category": "win_crypto"},
    "CryptReleaseContext": {"lib": "advapi32", "purpose": "release crypto provider handle", "category": "win_crypto"},
    "CryptGenRandom": {"lib": "advapi32", "purpose": "generate cryptographic random bytes", "category": "win_crypto"},
    "CryptCreateHash": {"lib": "advapi32", "purpose": "create hash object", "category": "win_crypto"},
    "CryptHashData": {"lib": "advapi32", "purpose": "add data to hash object", "category": "win_crypto"},

    # Service control
    "StartServiceCtrlDispatcherA": {"lib": "advapi32", "purpose": "connect service process to SCM (ANSI)", "category": "win_service"},
    "RegisterServiceCtrlHandlerA": {"lib": "advapi32", "purpose": "register service control handler (ANSI)", "category": "win_service"},
    "SetServiceStatus": {"lib": "advapi32", "purpose": "update service status to SCM", "category": "win_service"},
}


# ---------------------------------------------------------------------------
# Windows API -- user32 + gdi32 (~25)
# GUI, messaging, painting.
# ---------------------------------------------------------------------------

_WIN32_USER32_GDI32_SIGNATURES: dict[str, dict[str, str]] = {
    # Window management
    "CreateWindowExA": {"lib": "user32", "purpose": "create overlapped/popup/child window (ANSI)", "category": "win_gui"},
    "DestroyWindow": {"lib": "user32", "purpose": "destroy a window", "category": "win_gui"},
    "ShowWindow": {"lib": "user32", "purpose": "set window show state", "category": "win_gui"},
    "UpdateWindow": {"lib": "user32", "purpose": "send WM_PAINT if update region non-empty", "category": "win_gui"},

    # Message loop
    "GetMessageA": {"lib": "user32", "purpose": "retrieve message from queue (ANSI)", "category": "win_msg"},
    "TranslateMessage": {"lib": "user32", "purpose": "translate virtual-key messages to character messages", "category": "win_msg"},
    "DispatchMessageA": {"lib": "user32", "purpose": "dispatch message to window procedure (ANSI)", "category": "win_msg"},
    "PostMessageA": {"lib": "user32", "purpose": "post message to thread message queue (ANSI)", "category": "win_msg"},
    "SendMessageA": {"lib": "user32", "purpose": "send message directly to window procedure (ANSI)", "category": "win_msg"},
    "PostQuitMessage": {"lib": "user32", "purpose": "post WM_QUIT to message queue", "category": "win_msg"},

    # Window class / procedure
    "DefWindowProcA": {"lib": "user32", "purpose": "default window procedure (ANSI)", "category": "win_gui"},
    "RegisterClassExA": {"lib": "user32", "purpose": "register window class (ANSI)", "category": "win_gui"},

    # Dialog
    "MessageBoxA": {"lib": "user32", "purpose": "display modal dialog box (ANSI)", "category": "win_gui"},
    "MessageBoxW": {"lib": "user32", "purpose": "display modal dialog box (Unicode)", "category": "win_gui"},

    # Device context (GDI)
    "GetDC": {"lib": "user32", "purpose": "get device context for window client area", "category": "win_gdi"},
    "ReleaseDC": {"lib": "user32", "purpose": "release device context", "category": "win_gdi"},
    "BeginPaint": {"lib": "user32", "purpose": "prepare window for painting", "category": "win_gdi"},
    "EndPaint": {"lib": "user32", "purpose": "mark end of painting in window", "category": "win_gdi"},

    # Timer
    "SetTimer": {"lib": "user32", "purpose": "create timer with specified interval", "category": "win_gui"},
    "KillTimer": {"lib": "user32", "purpose": "destroy a timer", "category": "win_gui"},

    # Window queries
    "GetDesktopWindow": {"lib": "user32", "purpose": "get handle to desktop window", "category": "win_gui"},
    "GetForegroundWindow": {"lib": "user32", "purpose": "get handle to foreground window", "category": "win_gui"},
    "SetForegroundWindow": {"lib": "user32", "purpose": "bring window to foreground", "category": "win_gui"},
}


# ---------------------------------------------------------------------------
# Windows API -- ntdll (~14)
# Native API, lowest user-mode layer (below Win32 subsystem).
# ---------------------------------------------------------------------------

_WIN32_NTDLL_SIGNATURES: dict[str, dict[str, str]] = {
    # File I/O
    "NtCreateFile": {"lib": "ntdll", "purpose": "native file open/create (below CreateFile)", "category": "win_native"},
    "NtReadFile": {"lib": "ntdll", "purpose": "native file read", "category": "win_native"},
    "NtWriteFile": {"lib": "ntdll", "purpose": "native file write", "category": "win_native"},
    "NtClose": {"lib": "ntdll", "purpose": "native handle close", "category": "win_native"},

    # Virtual memory
    "NtAllocateVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory allocate", "category": "win_native"},
    "NtFreeVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory free", "category": "win_native"},
    "NtProtectVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory protect", "category": "win_native"},

    # System / process info
    "NtQuerySystemInformation": {"lib": "ntdll", "purpose": "query system information classes", "category": "win_native"},
    "NtQueryInformationProcess": {"lib": "ntdll", "purpose": "query process information classes", "category": "win_native"},

    # Unicode string
    "RtlInitUnicodeString": {"lib": "ntdll", "purpose": "initialize UNICODE_STRING structure", "category": "win_native"},
    "RtlFreeUnicodeString": {"lib": "ntdll", "purpose": "free UNICODE_STRING buffer", "category": "win_native"},

    # Thread / process
    "NtCreateThread": {"lib": "ntdll", "purpose": "native thread creation", "category": "win_native"},
    "NtTerminateThread": {"lib": "ntdll", "purpose": "native thread termination", "category": "win_native"},
    "NtTerminateProcess": {"lib": "ntdll", "purpose": "native process termination", "category": "win_native"},
}


# ---------------------------------------------------------------------------
# MSVC CRT fallback (sig_db Faz 6C) — legacy'de karsiligi yok.
# `sigdb_builtin.pe_runtime` import basarisiz olursa bos kalir.
# `_load_builtin_signatures` tuple'i bu sembolu bekler.
# ---------------------------------------------------------------------------
_MSVC_CRT_SIGNATURES: dict[str, dict[str, str]] = {}


# ---------------------------------------------------------------------------
# sig_db Faz 6C — PE/MSVC runtime kategori override (dalga 6C)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.pe_runtime` modulune tasindi. Ayni
# rollback-guvenli override pattern'i (crypto/compression/network ile ozdes).
# Uc dict hedefler:
#   - kernel32 / ntdll   -> legacy uzerine identity parity (veri degismez)
#   - msvc_crt           -> YENI coverage (180+ MSVCRT/UCRT/VCRUNTIME entry)
# NOT: msvc_crt entry'lerinin bir alt kumesi (~77) legacy
#      `_MEGA_BATCH_1_SIGNATURES` icinde mevcuttur; ayni icerikle cakisir
#      (idempotent update).
try:
    from karadul.analyzers.sigdb_builtin.pe_runtime import (
        SIGNATURES as _BUILTIN_PE_RUNTIME_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_PE_RUNTIME_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_PE_RUNTIME_SIGNATURES is not None:
    _WIN32_KERNEL32_SIGNATURES = _BUILTIN_PE_RUNTIME_SIGNATURES.get(
        "kernel32_signatures", _WIN32_KERNEL32_SIGNATURES
    )
    _WIN32_NTDLL_SIGNATURES = _BUILTIN_PE_RUNTIME_SIGNATURES.get(
        "ntdll_signatures", _WIN32_NTDLL_SIGNATURES
    )
    _MSVC_CRT_SIGNATURES = _BUILTIN_PE_RUNTIME_SIGNATURES.get(
        "msvc_crt_signatures", _MSVC_CRT_SIGNATURES
    )


# ---------------------------------------------------------------------------
# sig_db Faz 7D — Windows GUI / security / graphics override (dalga 7D)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.windows_gui` modulune tasindi.
# Kapsama: user32 (GUI core + mesaj + menu + dialog + input + clipboard +
# hook), advapi32 (registry + service + token + legacy CryptoAPI + event
# log + ACL), gdi32 (DC + pen/brush + font/text + bitmap/blit + region +
# path + metafile). Yaklasik 560+ entry.
#
# Legacy `_WIN32_USER32_GDI32_SIGNATURES` (25 entry) ve
# `_WIN32_ADVAPI32_SIGNATURES` (20 entry) override EDILIR. Overlap entry'ler
# ayni `lib` etiketi tasir (idempotent); genisleme agirlikli olarak YENI
# Unicode/ANSI eslenikleri ve alt kategorileri ekler.
#
# Legacy dict'ler SILINMEDI; import basarisiz olursa inline fallback aktif
# kalir (crypto/compression/network/pe_runtime ile ayni desen).

# Fallback: windows_gui modulu yoksa bos dict (legacy override uygulanmaz).
_WIN32_USER32_SIGNATURES: dict[str, dict[str, str]] = {}
_WIN32_ADVAPI32_FULL_SIGNATURES: dict[str, dict[str, str]] = {}
_WIN32_GDI32_SIGNATURES: dict[str, dict[str, str]] = {}

try:
    from karadul.analyzers.sigdb_builtin.windows_gui import (
        SIGNATURES as _BUILTIN_WINDOWS_GUI_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_WINDOWS_GUI_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_WINDOWS_GUI_SIGNATURES is not None:
    _WIN32_USER32_SIGNATURES = _BUILTIN_WINDOWS_GUI_SIGNATURES.get(
        "user32_signatures", _WIN32_USER32_SIGNATURES
    )
    _WIN32_ADVAPI32_FULL_SIGNATURES = _BUILTIN_WINDOWS_GUI_SIGNATURES.get(
        "advapi32_signatures", _WIN32_ADVAPI32_FULL_SIGNATURES
    )
    _WIN32_GDI32_SIGNATURES = _BUILTIN_WINDOWS_GUI_SIGNATURES.get(
        "gdi32_signatures", _WIN32_GDI32_SIGNATURES
    )
    # Legacy kucuk dict'leri de override et (identity parity + genisleme).
    # _WIN32_USER32_GDI32_SIGNATURES: user32 + gdi32 birlesik
    _WIN32_USER32_GDI32_SIGNATURES = {
        **_WIN32_USER32_SIGNATURES,
        **_WIN32_GDI32_SIGNATURES,
    }
    _WIN32_ADVAPI32_SIGNATURES = _WIN32_ADVAPI32_FULL_SIGNATURES


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

_LINUX_SYSCALL_SIGNATURES: dict[str, dict[str, str]] = {
    # epoll
    "epoll_create": {"lib": "libc", "purpose": "create epoll instance (deprecated)", "category": "linux_io"},
    "epoll_create1": {"lib": "libc", "purpose": "create epoll instance with flags", "category": "linux_io"},
    "epoll_ctl": {"lib": "libc", "purpose": "add/modify/remove epoll interest list entry", "category": "linux_io"},
    "epoll_wait": {"lib": "libc", "purpose": "wait for I/O events on epoll instance", "category": "linux_io"},

    # inotify
    "inotify_init": {"lib": "libc", "purpose": "create inotify instance (deprecated)", "category": "linux_io"},
    "inotify_init1": {"lib": "libc", "purpose": "create inotify instance with flags", "category": "linux_io"},
    "inotify_add_watch": {"lib": "libc", "purpose": "add watch to inotify instance", "category": "linux_io"},
    "inotify_rm_watch": {"lib": "libc", "purpose": "remove watch from inotify instance", "category": "linux_io"},

    # eventfd
    "eventfd": {"lib": "libc", "purpose": "create eventfd file descriptor", "category": "linux_io"},
    "eventfd_read": {"lib": "libc", "purpose": "read eventfd counter value", "category": "linux_io"},
    "eventfd_write": {"lib": "libc", "purpose": "write to eventfd counter", "category": "linux_io"},

    # timerfd
    "timerfd_create": {"lib": "libc", "purpose": "create timerfd file descriptor", "category": "linux_io"},
    "timerfd_settime": {"lib": "libc", "purpose": "arm/disarm timerfd timer", "category": "linux_io"},
    "timerfd_gettime": {"lib": "libc", "purpose": "get timerfd current timer value", "category": "linux_io"},

    # signalfd
    "signalfd": {"lib": "libc", "purpose": "create file descriptor for signal delivery", "category": "linux_io"},
    "signalfd4": {"lib": "libc", "purpose": "create signalfd with flags (internal)", "category": "linux_io"},

    # Advanced socket
    "accept4": {"lib": "libc", "purpose": "accept connection with flags (SOCK_NONBLOCK etc)", "category": "linux_network"},
    "recvmmsg": {"lib": "libc", "purpose": "receive multiple messages in single syscall", "category": "linux_network"},
    "sendmmsg": {"lib": "libc", "purpose": "send multiple messages in single syscall", "category": "linux_network"},

    # Splice / zero-copy
    "splice": {"lib": "libc", "purpose": "zero-copy data transfer between fds via pipe", "category": "linux_io"},
    "tee": {"lib": "libc", "purpose": "duplicate pipe content without consuming", "category": "linux_io"},
    "vmsplice": {"lib": "libc", "purpose": "splice user pages into pipe", "category": "linux_io"},

    # Security / sandboxing
    "prctl": {"lib": "libc", "purpose": "process control operations", "category": "linux_security"},
    "seccomp": {"lib": "libc", "purpose": "operate on seccomp BPF filters", "category": "linux_security"},

    # Namespaces / clone
    "clone": {"lib": "libc", "purpose": "create child process (low-level fork with flags)", "category": "linux_process"},
    "clone3": {"lib": "libc", "purpose": "create child process (extensible clone)", "category": "linux_process"},
    "unshare": {"lib": "libc", "purpose": "disassociate parts of process execution context", "category": "linux_process"},
    "setns": {"lib": "libc", "purpose": "reassociate thread with a namespace", "category": "linux_process"},

    # io_uring
    "io_uring_setup": {"lib": "libc", "purpose": "setup io_uring submission/completion queues", "category": "linux_io"},
    "io_uring_enter": {"lib": "libc", "purpose": "submit and/or wait for io_uring completions", "category": "linux_io"},
    "io_uring_register": {"lib": "libc", "purpose": "register resources with io_uring instance", "category": "linux_io"},

    # Misc modern syscalls
    "getrandom": {"lib": "libc", "purpose": "obtain random bytes from kernel", "category": "linux_security"},
    "memfd_create": {"lib": "libc", "purpose": "create anonymous file in memory", "category": "linux_io"},
    "userfaultfd": {"lib": "libc", "purpose": "create userfaultfd for userspace page fault handling", "category": "linux_io"},

    # fanotify
    "fanotify_init": {"lib": "libc", "purpose": "create fanotify notification group", "category": "linux_io"},
    "fanotify_mark": {"lib": "libc", "purpose": "add/remove/modify fanotify mark", "category": "linux_io"},
}


# ---------------------------------------------------------------------------
# Rust standard library (~50)
# v0 mangling (_RN...) ve legacy mangling (__ZN...) pattern'leri.
# Partial prefix eslestirme ile calisir -- symbol adinin basi bu prefix ile
# baslarsa eslestirme olur.
# ---------------------------------------------------------------------------

_RUST_STDLIB_SIGNATURES: dict[str, dict[str, str]] = {
    # -- v0 mangling prefixes --
    "_RNvNtCs": {"lib": "rust-std", "purpose": "Rust v0 mangled symbol (core/std crate)", "category": "rust"},

    # -- Legacy mangling: std::io --
    "__ZN3std2io5stdio6_print": {"lib": "rust-std", "purpose": "std::io::stdio::_print (formatted output)", "category": "rust_io"},
    "__ZN3std2io5stdio7_eprint": {"lib": "rust-std", "purpose": "std::io::stdio::_eprint (formatted stderr)", "category": "rust_io"},
    "__ZN3std2io4Read": {"lib": "rust-std", "purpose": "std::io::Read trait methods", "category": "rust_io"},
    "__ZN3std2io5Write": {"lib": "rust-std", "purpose": "std::io::Write trait methods", "category": "rust_io"},
    "__ZN3std2io5Error": {"lib": "rust-std", "purpose": "std::io::Error methods", "category": "rust_io"},
    "__ZN3std2io6BufRead": {"lib": "rust-std", "purpose": "std::io::BufRead trait methods", "category": "rust_io"},

    # -- Legacy mangling: std::panic --
    "__ZN3std5panic15begin_panic": {"lib": "rust-std", "purpose": "std::panic::begin_panic (panic entry)", "category": "rust_panic"},
    "__ZN3std9panicking": {"lib": "rust-std", "purpose": "std::panicking internal machinery", "category": "rust_panic"},
    "__ZN4core9panicking": {"lib": "rust-core", "purpose": "core::panicking (panic in no-std)", "category": "rust_panic"},

    # -- Legacy mangling: core::fmt --
    "__ZN4core3fmt": {"lib": "rust-core", "purpose": "core::fmt formatting infrastructure", "category": "rust_fmt"},
    "__ZN4core3fmt5Write": {"lib": "rust-core", "purpose": "core::fmt::Write trait methods", "category": "rust_fmt"},
    "__ZN4core3fmt9Formatter": {"lib": "rust-core", "purpose": "core::fmt::Formatter methods", "category": "rust_fmt"},
    "__ZN4core3fmt10ArgumentV1": {"lib": "rust-core", "purpose": "core::fmt::ArgumentV1 (format args)", "category": "rust_fmt"},

    # -- Legacy mangling: core::result --
    "__ZN4core6result": {"lib": "rust-core", "purpose": "core::result::Result methods", "category": "rust_core"},

    # -- Legacy mangling: core::option --
    "__ZN4core6option": {"lib": "rust-core", "purpose": "core::option::Option methods", "category": "rust_core"},

    # -- Legacy mangling: core::slice --
    "__ZN4core5slice": {"lib": "rust-core", "purpose": "core::slice methods", "category": "rust_core"},

    # -- Legacy mangling: core::str --
    "__ZN4core3str": {"lib": "rust-core", "purpose": "core::str string slice methods", "category": "rust_core"},

    # -- Legacy mangling: core::ptr --
    "__ZN4core3ptr": {"lib": "rust-core", "purpose": "core::ptr raw pointer operations", "category": "rust_core"},

    # -- Legacy mangling: core::ops --
    "__ZN4core3ops": {"lib": "rust-core", "purpose": "core::ops operator trait impls", "category": "rust_core"},

    # -- Legacy mangling: core::iter --
    "__ZN4core4iter": {"lib": "rust-core", "purpose": "core::iter iterator infrastructure", "category": "rust_core"},

    # -- Legacy mangling: alloc::vec --
    "__ZN5alloc3vec": {"lib": "rust-alloc", "purpose": "alloc::vec::Vec methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::string --
    "__ZN5alloc6string": {"lib": "rust-alloc", "purpose": "alloc::string::String methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::boxed --
    "__ZN5alloc5boxed": {"lib": "rust-alloc", "purpose": "alloc::boxed::Box methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::rc --
    "__ZN5alloc2rc": {"lib": "rust-alloc", "purpose": "alloc::rc::Rc reference counting", "category": "rust_collections"},

    # -- Legacy mangling: alloc::sync --
    "__ZN5alloc4sync": {"lib": "rust-alloc", "purpose": "alloc::sync::Arc atomic reference counting", "category": "rust_collections"},

    # -- Legacy mangling: std::fs --
    "__ZN3std2fs": {"lib": "rust-std", "purpose": "std::fs file system operations", "category": "rust_io"},

    # -- Legacy mangling: std::net --
    "__ZN3std3net": {"lib": "rust-std", "purpose": "std::net networking (TCP/UDP)", "category": "rust_net"},

    # -- Legacy mangling: std::sync --
    "__ZN3std4sync5mutex": {"lib": "rust-std", "purpose": "std::sync::Mutex methods", "category": "rust_sync"},
    "__ZN3std4sync6rwlock": {"lib": "rust-std", "purpose": "std::sync::RwLock methods", "category": "rust_sync"},
    "__ZN3std4sync4mpsc": {"lib": "rust-std", "purpose": "std::sync::mpsc channel methods", "category": "rust_sync"},
    "__ZN3std4sync7condvar": {"lib": "rust-std", "purpose": "std::sync::Condvar methods", "category": "rust_sync"},
    "__ZN3std4sync6atomic": {"lib": "rust-std", "purpose": "std::sync::atomic operations", "category": "rust_sync"},
    "__ZN3std4sync4Once": {"lib": "rust-std", "purpose": "std::sync::Once one-time init", "category": "rust_sync"},

    # -- Legacy mangling: std::thread --
    "__ZN3std6thread": {"lib": "rust-std", "purpose": "std::thread thread management", "category": "rust_thread"},

    # -- Legacy mangling: std::time --
    "__ZN3std4time": {"lib": "rust-std", "purpose": "std::time (Duration, Instant, SystemTime)", "category": "rust_time"},

    # -- Legacy mangling: std::process --
    "__ZN3std7process": {"lib": "rust-std", "purpose": "std::process (Command, Child, exit)", "category": "rust_process"},

    # -- Legacy mangling: std::env --
    "__ZN3std3env": {"lib": "rust-std", "purpose": "std::env environment variables", "category": "rust_env"},

    # -- Legacy mangling: std::collections --
    "__ZN3std11collections4hash3map": {"lib": "rust-std", "purpose": "std::collections::HashMap methods", "category": "rust_collections"},
    "__ZN3std11collections4hash3set": {"lib": "rust-std", "purpose": "std::collections::HashSet methods", "category": "rust_collections"},
    "__ZN3std11collections6btree": {"lib": "rust-std", "purpose": "std::collections::BTreeMap/Set methods", "category": "rust_collections"},
    "__ZN5alloc11collections7vec_deque": {"lib": "rust-alloc", "purpose": "alloc::collections::VecDeque methods", "category": "rust_collections"},
    "__ZN5alloc11collections10linked_list": {"lib": "rust-alloc", "purpose": "alloc::collections::LinkedList methods", "category": "rust_collections"},
    "__ZN5alloc11collections12binary_heap": {"lib": "rust-alloc", "purpose": "alloc::collections::BinaryHeap methods", "category": "rust_collections"},

    # -- Rust runtime support --
    "__ZN3std2rt": {"lib": "rust-std", "purpose": "std::rt runtime initialization", "category": "rust_runtime"},
    "__ZN3std10sys_common": {"lib": "rust-std", "purpose": "std::sys_common platform abstraction", "category": "rust_runtime"},
    "__ZN3std3sys": {"lib": "rust-std", "purpose": "std::sys platform-specific code", "category": "rust_runtime"},
}


# ---------------------------------------------------------------------------
# Go runtime (~55)
# Go binary'lerinde distinctive symbol isimleri.
# Go linker strip etmezse symbol tablosunda gorunur.
# ---------------------------------------------------------------------------

_GO_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = {
    # Core runtime
    "runtime.main": {"lib": "go-runtime", "purpose": "Go program main entry (calls main.main)", "category": "go_runtime"},
    "runtime.goexit": {"lib": "go-runtime", "purpose": "goroutine exit point", "category": "go_runtime"},
    "runtime.newproc": {"lib": "go-runtime", "purpose": "create new goroutine (go statement)", "category": "go_runtime"},
    "runtime.newproc1": {"lib": "go-runtime", "purpose": "create new goroutine (internal)", "category": "go_runtime"},

    # Memory allocation
    "runtime.mallocgc": {"lib": "go-runtime", "purpose": "GC-aware memory allocation", "category": "go_memory"},
    "runtime.makeslice": {"lib": "go-runtime", "purpose": "allocate and initialize slice", "category": "go_memory"},
    "runtime.makemap": {"lib": "go-runtime", "purpose": "allocate and initialize map", "category": "go_memory"},
    "runtime.makechan": {"lib": "go-runtime", "purpose": "allocate and initialize channel", "category": "go_memory"},

    # Channel operations
    "runtime.chansend": {"lib": "go-runtime", "purpose": "send value on channel (ch <- v)", "category": "go_channel"},
    "runtime.chanrecv": {"lib": "go-runtime", "purpose": "receive value from channel (<-ch)", "category": "go_channel"},
    "runtime.closechan": {"lib": "go-runtime", "purpose": "close a channel", "category": "go_channel"},

    # Slice operations
    "runtime.growslice": {"lib": "go-runtime", "purpose": "grow slice backing array (append)", "category": "go_slice"},
    "runtime.slicecopy": {"lib": "go-runtime", "purpose": "copy elements between slices", "category": "go_slice"},
    "runtime.slicebytetostring": {"lib": "go-runtime", "purpose": "convert []byte to string", "category": "go_slice"},

    # Map operations
    "runtime.mapaccess1": {"lib": "go-runtime", "purpose": "map lookup returning value (m[k])", "category": "go_map"},
    "runtime.mapaccess2": {"lib": "go-runtime", "purpose": "map lookup returning value+ok (v,ok=m[k])", "category": "go_map"},
    "runtime.mapassign": {"lib": "go-runtime", "purpose": "map assignment (m[k]=v)", "category": "go_map"},
    "runtime.mapdelete": {"lib": "go-runtime", "purpose": "map deletion (delete(m,k))", "category": "go_map"},

    # Synchronization
    "runtime.lock": {"lib": "go-runtime", "purpose": "runtime internal lock acquire", "category": "go_sync"},
    "runtime.unlock": {"lib": "go-runtime", "purpose": "runtime internal lock release", "category": "go_sync"},
    "runtime.semacquire": {"lib": "go-runtime", "purpose": "semaphore acquire (used by sync pkg)", "category": "go_sync"},
    "runtime.semrelease": {"lib": "go-runtime", "purpose": "semaphore release", "category": "go_sync"},

    # Garbage collection
    "runtime.gcStart": {"lib": "go-runtime", "purpose": "start garbage collection cycle", "category": "go_gc"},
    "runtime.gcDrain": {"lib": "go-runtime", "purpose": "drain GC mark work queue", "category": "go_gc"},
    "runtime.gcMarkDone": {"lib": "go-runtime", "purpose": "signal GC marking phase complete", "category": "go_gc"},

    # Type conversion
    "runtime.convT": {"lib": "go-runtime", "purpose": "convert concrete type to interface", "category": "go_runtime"},
    "runtime.convTstring": {"lib": "go-runtime", "purpose": "convert string to interface", "category": "go_runtime"},
    "runtime.convTslice": {"lib": "go-runtime", "purpose": "convert slice to interface", "category": "go_runtime"},

    # Stack management
    "runtime.morestack": {"lib": "go-runtime", "purpose": "goroutine stack growth", "category": "go_runtime"},
    "runtime.morestack_noctxt": {"lib": "go-runtime", "purpose": "goroutine stack growth (no closure context)", "category": "go_runtime"},
    "runtime.rt0_go": {"lib": "go-runtime", "purpose": "Go bootstrap entry point (before runtime.main)", "category": "go_runtime"},

    # Error / panic
    "runtime.throw": {"lib": "go-runtime", "purpose": "runtime fatal error (unrecoverable)", "category": "go_panic"},
    "runtime.gopanic": {"lib": "go-runtime", "purpose": "Go panic() entry point", "category": "go_panic"},
    "runtime.gorecover": {"lib": "go-runtime", "purpose": "Go recover() entry point", "category": "go_panic"},

    # Print (used by runtime.throw)
    "runtime.printstring": {"lib": "go-runtime", "purpose": "runtime internal string print", "category": "go_runtime"},
    "runtime.printint": {"lib": "go-runtime", "purpose": "runtime internal int print", "category": "go_runtime"},
    "runtime.printnl": {"lib": "go-runtime", "purpose": "runtime internal newline print", "category": "go_runtime"},

    # fmt package
    "fmt.Fprintf": {"lib": "go-fmt", "purpose": "formatted I/O to io.Writer", "category": "go_fmt"},
    "fmt.Sprintf": {"lib": "go-fmt", "purpose": "formatted string return", "category": "go_fmt"},
    "fmt.Printf": {"lib": "go-fmt", "purpose": "formatted I/O to stdout", "category": "go_fmt"},
    "fmt.Println": {"lib": "go-fmt", "purpose": "print with newline to stdout", "category": "go_fmt"},

    # os package
    "os.Open": {"lib": "go-os", "purpose": "open file for reading", "category": "go_os"},
    "os.Create": {"lib": "go-os", "purpose": "create or truncate file", "category": "go_os"},
    "os.Exit": {"lib": "go-os", "purpose": "exit process with status code", "category": "go_os"},
    "os.Getenv": {"lib": "go-os", "purpose": "get environment variable", "category": "go_os"},

    # net package
    "net.Dial": {"lib": "go-net", "purpose": "connect to network address", "category": "go_net"},
    "net.Listen": {"lib": "go-net", "purpose": "listen on network address", "category": "go_net"},
    "net.(*TCPConn).Read": {"lib": "go-net", "purpose": "read data from TCP connection", "category": "go_net"},
    "net.(*TCPConn).Write": {"lib": "go-net", "purpose": "write data to TCP connection", "category": "go_net"},

    # sync package
    "sync.(*Mutex).Lock": {"lib": "go-sync", "purpose": "acquire mutex lock", "category": "go_sync"},
    "sync.(*Mutex).Unlock": {"lib": "go-sync", "purpose": "release mutex lock", "category": "go_sync"},
    "sync.(*WaitGroup).Add": {"lib": "go-sync", "purpose": "add delta to WaitGroup counter", "category": "go_sync"},
    "sync.(*WaitGroup).Wait": {"lib": "go-sync", "purpose": "block until WaitGroup counter is zero", "category": "go_sync"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Linux System Calls (~200 imza)
# Temel POSIX syscall wrapper'lari, mevcut _LINUX_SYSCALL_SIGNATURES'i
# tamamlar. glibc/musl'da bulunan tum onemli syscall'lar.
# ---------------------------------------------------------------------------

_LINUX_SYSCALL_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Core file I/O syscalls ---
    "read": {"lib": "libc", "purpose": "read bytes from file descriptor", "category": "linux_io"},
    "write": {"lib": "libc", "purpose": "write bytes to file descriptor", "category": "linux_io"},
    "open": {"lib": "libc", "purpose": "open file and return fd", "category": "linux_io"},
    "close": {"lib": "libc", "purpose": "close file descriptor", "category": "linux_io"},
    "lseek": {"lib": "libc", "purpose": "reposition file offset", "category": "linux_io"},
    "pread": {"lib": "libc", "purpose": "read from fd at offset without seeking", "category": "linux_io"},
    "pread64": {"lib": "libc", "purpose": "read from fd at 64-bit offset", "category": "linux_io"},
    "pwrite": {"lib": "libc", "purpose": "write to fd at offset without seeking", "category": "linux_io"},
    "pwrite64": {"lib": "libc", "purpose": "write to fd at 64-bit offset", "category": "linux_io"},
    "readv": {"lib": "libc", "purpose": "scatter read from fd into multiple buffers", "category": "linux_io"},
    "writev": {"lib": "libc", "purpose": "gather write to fd from multiple buffers", "category": "linux_io"},
    "preadv": {"lib": "libc", "purpose": "scatter read at offset", "category": "linux_io"},
    "pwritev": {"lib": "libc", "purpose": "gather write at offset", "category": "linux_io"},
    "preadv2": {"lib": "libc", "purpose": "scatter read with flags", "category": "linux_io"},
    "pwritev2": {"lib": "libc", "purpose": "gather write with flags", "category": "linux_io"},
    "openat": {"lib": "libc", "purpose": "open file relative to directory fd", "category": "linux_io"},
    "openat2": {"lib": "libc", "purpose": "open file with extended flags (resolve restrictions)", "category": "linux_io"},
    "creat": {"lib": "libc", "purpose": "create file (equivalent to open with O_CREAT|O_TRUNC)", "category": "linux_io"},

    # --- File metadata syscalls ---
    "stat": {"lib": "libc", "purpose": "get file status by path", "category": "linux_fs"},
    "fstat": {"lib": "libc", "purpose": "get file status by fd", "category": "linux_fs"},
    "lstat": {"lib": "libc", "purpose": "get file status (no symlink follow)", "category": "linux_fs"},
    "stat64": {"lib": "libc", "purpose": "get file status (64-bit)", "category": "linux_fs"},
    "fstat64": {"lib": "libc", "purpose": "get file status by fd (64-bit)", "category": "linux_fs"},
    "lstat64": {"lib": "libc", "purpose": "get file status no follow (64-bit)", "category": "linux_fs"},
    "statx": {"lib": "libc", "purpose": "extended file status (birth time, mount id)", "category": "linux_fs"},
    "fstatat": {"lib": "libc", "purpose": "get file status relative to dir fd", "category": "linux_fs"},
    "newfstatat": {"lib": "libc", "purpose": "get file status relative to dir fd (new)", "category": "linux_fs"},
    "access": {"lib": "libc", "purpose": "check file access permissions", "category": "linux_fs"},
    "faccessat": {"lib": "libc", "purpose": "check file access relative to dir fd", "category": "linux_fs"},
    "faccessat2": {"lib": "libc", "purpose": "check file access with flags", "category": "linux_fs"},

    # --- Directory operations ---
    "mkdir": {"lib": "libc", "purpose": "create directory", "category": "linux_fs"},
    "mkdirat": {"lib": "libc", "purpose": "create directory relative to dir fd", "category": "linux_fs"},
    "rmdir": {"lib": "libc", "purpose": "remove empty directory", "category": "linux_fs"},
    "getcwd": {"lib": "libc", "purpose": "get current working directory", "category": "linux_fs"},
    "chdir": {"lib": "libc", "purpose": "change working directory", "category": "linux_fs"},
    "fchdir": {"lib": "libc", "purpose": "change working directory by fd", "category": "linux_fs"},
    "chroot": {"lib": "libc", "purpose": "change root directory", "category": "linux_fs"},
    "getdents": {"lib": "libc", "purpose": "get directory entries", "category": "linux_fs"},
    "getdents64": {"lib": "libc", "purpose": "get directory entries (64-bit)", "category": "linux_fs"},

    # --- File manipulation ---
    "unlink": {"lib": "libc", "purpose": "remove file or directory entry", "category": "linux_fs"},
    "unlinkat": {"lib": "libc", "purpose": "remove file relative to dir fd", "category": "linux_fs"},
    "rename": {"lib": "libc", "purpose": "rename file or directory", "category": "linux_fs"},
    "renameat": {"lib": "libc", "purpose": "rename relative to dir fds", "category": "linux_fs"},
    "renameat2": {"lib": "libc", "purpose": "rename with flags (RENAME_NOREPLACE etc)", "category": "linux_fs"},
    "link": {"lib": "libc", "purpose": "create hard link", "category": "linux_fs"},
    "linkat": {"lib": "libc", "purpose": "create hard link relative to dir fds", "category": "linux_fs"},
    "symlink": {"lib": "libc", "purpose": "create symbolic link", "category": "linux_fs"},
    "symlinkat": {"lib": "libc", "purpose": "create symbolic link relative to dir fd", "category": "linux_fs"},
    "readlink": {"lib": "libc", "purpose": "read symbolic link target", "category": "linux_fs"},
    "readlinkat": {"lib": "libc", "purpose": "read symlink target relative to dir fd", "category": "linux_fs"},
    "truncate": {"lib": "libc", "purpose": "truncate file to specified length", "category": "linux_fs"},
    "ftruncate": {"lib": "libc", "purpose": "truncate file by fd to specified length", "category": "linux_fs"},
    "fallocate": {"lib": "libc", "purpose": "preallocate or deallocate file space", "category": "linux_fs"},
    "copy_file_range": {"lib": "libc", "purpose": "server-side file copy (zero-copy)", "category": "linux_fs"},

    # --- Permission/ownership ---
    "chmod": {"lib": "libc", "purpose": "change file permission bits", "category": "linux_fs"},
    "fchmod": {"lib": "libc", "purpose": "change file permissions by fd", "category": "linux_fs"},
    "fchmodat": {"lib": "libc", "purpose": "change permissions relative to dir fd", "category": "linux_fs"},
    "chown": {"lib": "libc", "purpose": "change file owner and group", "category": "linux_fs"},
    "fchown": {"lib": "libc", "purpose": "change owner/group by fd", "category": "linux_fs"},
    "fchownat": {"lib": "libc", "purpose": "change owner/group relative to dir fd", "category": "linux_fs"},
    "lchown": {"lib": "libc", "purpose": "change symlink owner/group (no follow)", "category": "linux_fs"},
    "umask": {"lib": "libc", "purpose": "set file mode creation mask", "category": "linux_fs"},

    # --- Memory management ---
    "mmap": {"lib": "libc", "purpose": "map files or devices into memory", "category": "linux_memory"},
    "mmap2": {"lib": "libc", "purpose": "map files into memory (page-aligned offset)", "category": "linux_memory"},
    "munmap": {"lib": "libc", "purpose": "unmap pages of memory", "category": "linux_memory"},
    "mprotect": {"lib": "libc", "purpose": "set protection on memory region", "category": "linux_memory"},
    "mlock": {"lib": "libc", "purpose": "lock pages in memory (prevent swap)", "category": "linux_memory"},
    "mlock2": {"lib": "libc", "purpose": "lock pages with flags", "category": "linux_memory"},
    "munlock": {"lib": "libc", "purpose": "unlock pages allowing swap", "category": "linux_memory"},
    "mlockall": {"lib": "libc", "purpose": "lock all process pages in memory", "category": "linux_memory"},
    "munlockall": {"lib": "libc", "purpose": "unlock all process pages", "category": "linux_memory"},
    "mremap": {"lib": "libc", "purpose": "remap virtual memory address", "category": "linux_memory"},
    "msync": {"lib": "libc", "purpose": "synchronize memory-mapped file to disk", "category": "linux_memory"},
    "madvise": {"lib": "libc", "purpose": "advise kernel about memory usage patterns", "category": "linux_memory"},
    "mincore": {"lib": "libc", "purpose": "determine if pages are resident in memory", "category": "linux_memory"},
    "brk": {"lib": "libc", "purpose": "change data segment size (program break)", "category": "linux_memory"},
    "sbrk": {"lib": "libc", "purpose": "increment program break (data segment)", "category": "linux_memory"},

    # --- Process management ---
    "fork": {"lib": "libc", "purpose": "create child process (copy-on-write)", "category": "linux_process"},
    "vfork": {"lib": "libc", "purpose": "create child process (shared memory, deprecated)", "category": "linux_process"},
    "execve": {"lib": "libc", "purpose": "execute program replacing current process", "category": "linux_process"},
    "execvp": {"lib": "libc", "purpose": "execute program with PATH search", "category": "linux_process"},
    "execvpe": {"lib": "libc", "purpose": "execute program with PATH and custom env", "category": "linux_process"},
    "execl": {"lib": "libc", "purpose": "execute program with variadic args", "category": "linux_process"},
    "execlp": {"lib": "libc", "purpose": "execute program with PATH and variadic args", "category": "linux_process"},
    "execle": {"lib": "libc", "purpose": "execute program with variadic args and env", "category": "linux_process"},
    "wait": {"lib": "libc", "purpose": "wait for any child process to terminate", "category": "linux_process"},
    "waitpid": {"lib": "libc", "purpose": "wait for specific child process", "category": "linux_process"},
    "wait4": {"lib": "libc", "purpose": "wait for child with resource usage info", "category": "linux_process"},
    "waitid": {"lib": "libc", "purpose": "wait for child process state change", "category": "linux_process"},
    "getpid": {"lib": "libc", "purpose": "get process ID", "category": "linux_process"},
    "getppid": {"lib": "libc", "purpose": "get parent process ID", "category": "linux_process"},
    "getpgid": {"lib": "libc", "purpose": "get process group ID", "category": "linux_process"},
    "setpgid": {"lib": "libc", "purpose": "set process group ID", "category": "linux_process"},
    "getsid": {"lib": "libc", "purpose": "get session ID", "category": "linux_process"},
    "setsid": {"lib": "libc", "purpose": "create new session", "category": "linux_process"},
    "getuid": {"lib": "libc", "purpose": "get real user ID", "category": "linux_process"},
    "geteuid": {"lib": "libc", "purpose": "get effective user ID", "category": "linux_process"},
    "getgid": {"lib": "libc", "purpose": "get real group ID", "category": "linux_process"},
    "getegid": {"lib": "libc", "purpose": "get effective group ID", "category": "linux_process"},
    "setuid": {"lib": "libc", "purpose": "set real user ID", "category": "linux_process"},
    "seteuid": {"lib": "libc", "purpose": "set effective user ID", "category": "linux_process"},
    "setgid": {"lib": "libc", "purpose": "set real group ID", "category": "linux_process"},
    "setegid": {"lib": "libc", "purpose": "set effective group ID", "category": "linux_process"},
    "setreuid": {"lib": "libc", "purpose": "set real and effective user IDs", "category": "linux_process"},
    "setregid": {"lib": "libc", "purpose": "set real and effective group IDs", "category": "linux_process"},
    "setresuid": {"lib": "libc", "purpose": "set real, effective, and saved user IDs", "category": "linux_process"},
    "setresgid": {"lib": "libc", "purpose": "set real, effective, and saved group IDs", "category": "linux_process"},
    "getresuid": {"lib": "libc", "purpose": "get real, effective, and saved user IDs", "category": "linux_process"},
    "getresgid": {"lib": "libc", "purpose": "get real, effective, and saved group IDs", "category": "linux_process"},
    "getgroups": {"lib": "libc", "purpose": "get supplementary group IDs", "category": "linux_process"},
    "setgroups": {"lib": "libc", "purpose": "set supplementary group IDs", "category": "linux_process"},

    # --- Signal handling ---
    "kill": {"lib": "libc", "purpose": "send signal to process or process group", "category": "linux_signal"},
    "tgkill": {"lib": "libc", "purpose": "send signal to specific thread", "category": "linux_signal"},
    "tkill": {"lib": "libc", "purpose": "send signal to thread (deprecated, use tgkill)", "category": "linux_signal"},
    "sigaction": {"lib": "libc", "purpose": "examine and change signal action", "category": "linux_signal"},
    "rt_sigaction": {"lib": "libc", "purpose": "examine/change signal action (realtime)", "category": "linux_signal"},
    "sigprocmask": {"lib": "libc", "purpose": "examine/change blocked signals", "category": "linux_signal"},
    "rt_sigprocmask": {"lib": "libc", "purpose": "examine/change blocked signals (realtime)", "category": "linux_signal"},
    "sigpending": {"lib": "libc", "purpose": "examine pending signals", "category": "linux_signal"},
    "sigsuspend": {"lib": "libc", "purpose": "wait for signal with mask", "category": "linux_signal"},
    "sigwait": {"lib": "libc", "purpose": "synchronously wait for signal", "category": "linux_signal"},
    "sigwaitinfo": {"lib": "libc", "purpose": "synchronously wait for signal with info", "category": "linux_signal"},
    "sigtimedwait": {"lib": "libc", "purpose": "synchronously wait for signal with timeout", "category": "linux_signal"},
    "raise": {"lib": "libc", "purpose": "send signal to calling thread", "category": "linux_signal"},
    "alarm": {"lib": "libc", "purpose": "set alarm clock for SIGALRM delivery", "category": "linux_signal"},
    "pause": {"lib": "libc", "purpose": "wait for signal", "category": "linux_signal"},

    # --- Socket syscalls ---
    "socket": {"lib": "libc", "purpose": "create network socket endpoint", "category": "linux_network"},
    "bind": {"lib": "libc", "purpose": "bind socket to address", "category": "linux_network"},
    "listen": {"lib": "libc", "purpose": "mark socket as passive (server)", "category": "linux_network"},
    "accept": {"lib": "libc", "purpose": "accept incoming connection on socket", "category": "linux_network"},
    "connect": {"lib": "libc", "purpose": "initiate connection on socket", "category": "linux_network"},
    "sendmsg": {"lib": "libc", "purpose": "send message on socket with ancillary data", "category": "linux_network"},
    "recvmsg": {"lib": "libc", "purpose": "receive message from socket with ancillary data", "category": "linux_network"},
    "shutdown": {"lib": "libc", "purpose": "shut down part of full-duplex connection", "category": "linux_network"},
    "getsockopt": {"lib": "libc", "purpose": "get socket option value", "category": "linux_network"},
    "setsockopt": {"lib": "libc", "purpose": "set socket option value", "category": "linux_network"},
    "getsockname": {"lib": "libc", "purpose": "get socket local address", "category": "linux_network"},
    "getpeername": {"lib": "libc", "purpose": "get socket peer address", "category": "linux_network"},
    "socketpair": {"lib": "libc", "purpose": "create pair of connected sockets", "category": "linux_network"},

    # --- Pipe/dup ---
    "pipe": {"lib": "libc", "purpose": "create unidirectional pipe", "category": "linux_io"},
    "pipe2": {"lib": "libc", "purpose": "create pipe with flags (O_CLOEXEC, O_NONBLOCK)", "category": "linux_io"},
    "dup": {"lib": "libc", "purpose": "duplicate file descriptor", "category": "linux_io"},
    "dup2": {"lib": "libc", "purpose": "duplicate fd to specific number", "category": "linux_io"},
    "dup3": {"lib": "libc", "purpose": "duplicate fd with flags", "category": "linux_io"},

    # --- Polling/select ---
    "poll": {"lib": "libc", "purpose": "wait for events on file descriptors", "category": "linux_io"},
    "ppoll": {"lib": "libc", "purpose": "poll with signal mask and timespec", "category": "linux_io"},
    "pselect": {"lib": "libc", "purpose": "synchronous I/O multiplexing with sigmask", "category": "linux_io"},

    # --- ioctl/fcntl ---
    "ioctl": {"lib": "libc", "purpose": "device-specific I/O control", "category": "linux_io"},
    "fcntl": {"lib": "libc", "purpose": "file descriptor control operations", "category": "linux_io"},
    "fcntl64": {"lib": "libc", "purpose": "file descriptor control (64-bit)", "category": "linux_io"},

    # --- Time ---
    "gettimeofday": {"lib": "libc", "purpose": "get current time (microsecond precision)", "category": "linux_time"},
    "settimeofday": {"lib": "libc", "purpose": "set current time", "category": "linux_time"},
    "clock_gettime": {"lib": "libc", "purpose": "get clock time (nanosecond precision)", "category": "linux_time"},
    "clock_settime": {"lib": "libc", "purpose": "set clock time", "category": "linux_time"},
    "clock_getres": {"lib": "libc", "purpose": "get clock resolution", "category": "linux_time"},
    "clock_nanosleep": {"lib": "libc", "purpose": "high-resolution sleep with clock ID", "category": "linux_time"},
    "nanosleep": {"lib": "libc", "purpose": "high-resolution sleep", "category": "linux_time"},
    "time": {"lib": "libc", "purpose": "get time in seconds since epoch", "category": "linux_time"},
    "times": {"lib": "libc", "purpose": "get process/children CPU times", "category": "linux_time"},
    "timer_create": {"lib": "libc", "purpose": "create POSIX per-process timer", "category": "linux_time"},
    "timer_settime": {"lib": "libc", "purpose": "arm/disarm POSIX timer", "category": "linux_time"},
    "timer_gettime": {"lib": "libc", "purpose": "get POSIX timer current value", "category": "linux_time"},
    "timer_delete": {"lib": "libc", "purpose": "delete POSIX timer", "category": "linux_time"},
    "timer_getoverrun": {"lib": "libc", "purpose": "get POSIX timer overrun count", "category": "linux_time"},

    # --- Resource limits ---
    "getrlimit": {"lib": "libc", "purpose": "get resource usage limits", "category": "linux_process"},
    "setrlimit": {"lib": "libc", "purpose": "set resource usage limits", "category": "linux_process"},
    "prlimit64": {"lib": "libc", "purpose": "get/set resource limits (64-bit, per-process)", "category": "linux_process"},
    "getrusage": {"lib": "libc", "purpose": "get resource usage statistics", "category": "linux_process"},
    "sysinfo": {"lib": "libc", "purpose": "get system memory/load information", "category": "linux_process"},
    "uname": {"lib": "libc", "purpose": "get system identification info", "category": "linux_process"},

    # --- Misc modern syscalls ---
    "sendfile": {"lib": "libc", "purpose": "zero-copy data transfer between fds", "category": "linux_io"},
    "sendfile64": {"lib": "libc", "purpose": "zero-copy data transfer (64-bit offset)", "category": "linux_io"},
    "sync": {"lib": "libc", "purpose": "flush all filesystem caches to disk", "category": "linux_io"},
    "fsync": {"lib": "libc", "purpose": "flush file data and metadata to disk", "category": "linux_io"},
    "fdatasync": {"lib": "libc", "purpose": "flush file data to disk (no metadata)", "category": "linux_io"},
    "syncfs": {"lib": "libc", "purpose": "flush filesystem containing fd to disk", "category": "linux_io"},
    "fadvise64": {"lib": "libc", "purpose": "advise kernel about file access patterns", "category": "linux_io"},
    "posix_fadvise": {"lib": "libc", "purpose": "advise kernel on file access pattern", "category": "linux_io"},

    # --- Extended attributes ---
    "setxattr": {"lib": "libc", "purpose": "set extended file attribute", "category": "linux_fs"},
    "getxattr": {"lib": "libc", "purpose": "get extended file attribute", "category": "linux_fs"},
    "listxattr": {"lib": "libc", "purpose": "list extended file attributes", "category": "linux_fs"},
    "removexattr": {"lib": "libc", "purpose": "remove extended file attribute", "category": "linux_fs"},
    "fsetxattr": {"lib": "libc", "purpose": "set extended attribute by fd", "category": "linux_fs"},
    "fgetxattr": {"lib": "libc", "purpose": "get extended attribute by fd", "category": "linux_fs"},
    "flistxattr": {"lib": "libc", "purpose": "list extended attributes by fd", "category": "linux_fs"},
    "fremovexattr": {"lib": "libc", "purpose": "remove extended attribute by fd", "category": "linux_fs"},

    # --- Mount / filesystem ---
    "mount": {"lib": "libc", "purpose": "mount filesystem", "category": "linux_fs"},
    "umount2": {"lib": "libc", "purpose": "unmount filesystem with flags", "category": "linux_fs"},
    "pivot_root": {"lib": "libc", "purpose": "change root filesystem", "category": "linux_fs"},
    "statfs": {"lib": "libc", "purpose": "get filesystem statistics", "category": "linux_fs"},
    "fstatfs": {"lib": "libc", "purpose": "get filesystem statistics by fd", "category": "linux_fs"},

    # --- Futex (fast userspace mutex) ---
    "futex": {"lib": "libc", "purpose": "fast userspace locking primitive", "category": "linux_sync"},
    "futex_waitv": {"lib": "libc", "purpose": "wait on multiple futexes", "category": "linux_sync"},

    # --- ptrace / debugging ---
    "ptrace": {"lib": "libc", "purpose": "process trace (debugging/tracing)", "category": "linux_debug"},
    "process_vm_readv": {"lib": "libc", "purpose": "read from another process memory", "category": "linux_debug"},
    "process_vm_writev": {"lib": "libc", "purpose": "write to another process memory", "category": "linux_debug"},

    # --- cgroup / scheduling ---
    "sched_setaffinity": {"lib": "libc", "purpose": "set CPU affinity mask", "category": "linux_sched"},
    "sched_getaffinity": {"lib": "libc", "purpose": "get CPU affinity mask", "category": "linux_sched"},
    "sched_yield": {"lib": "libc", "purpose": "yield processor to other threads", "category": "linux_sched"},
    "sched_setscheduler": {"lib": "libc", "purpose": "set scheduling policy and priority", "category": "linux_sched"},
    "sched_getscheduler": {"lib": "libc", "purpose": "get scheduling policy", "category": "linux_sched"},
    "nice": {"lib": "libc", "purpose": "change process priority (nice value)", "category": "linux_sched"},
    "getpriority": {"lib": "libc", "purpose": "get scheduling priority", "category": "linux_sched"},
    "setpriority": {"lib": "libc", "purpose": "set scheduling priority", "category": "linux_sched"},

    # --- Misc ---
    "exit_group": {"lib": "libc", "purpose": "exit all threads in process", "category": "linux_process"},
    "_exit": {"lib": "libc", "purpose": "terminate process immediately", "category": "linux_process"},
    "set_tid_address": {"lib": "libc", "purpose": "set pointer to thread ID (for futex wake)", "category": "linux_process"},
    "arch_prctl": {"lib": "libc", "purpose": "set architecture-specific thread state", "category": "linux_process"},
    "set_thread_area": {"lib": "libc", "purpose": "set thread-local storage entry", "category": "linux_process"},
    "get_thread_area": {"lib": "libc", "purpose": "get thread-local storage entry", "category": "linux_process"},
    "personality": {"lib": "libc", "purpose": "set process execution domain", "category": "linux_process"},
    "capget": {"lib": "libc", "purpose": "get process capabilities", "category": "linux_security"},
    "capset": {"lib": "libc", "purpose": "set process capabilities", "category": "linux_security"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Windows API (~300 imza)
# kernel32, ws2_32, advapi32, user32, gdi32 genisletme + yeni DLL'ler
# (crypt32, ole32, shell32, version, comctl32, winhttp, bcrypt)
# ---------------------------------------------------------------------------

_WIN32_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- kernel32 extended ---
    "CreateFileTransactedW": {"lib": "kernel32", "purpose": "create file within transaction (Unicode)", "category": "win_file"},
    "SetFilePointer": {"lib": "kernel32", "purpose": "move file pointer position", "category": "win_file"},
    "SetFilePointerEx": {"lib": "kernel32", "purpose": "move file pointer (64-bit)", "category": "win_file"},
    "GetFileSize": {"lib": "kernel32", "purpose": "get file size (32-bit)", "category": "win_file"},
    "GetFileSizeEx": {"lib": "kernel32", "purpose": "get file size (64-bit)", "category": "win_file"},
    "SetEndOfFile": {"lib": "kernel32", "purpose": "truncate or extend file at current position", "category": "win_file"},
    "FlushFileBuffers": {"lib": "kernel32", "purpose": "flush file buffers to disk", "category": "win_file"},
    "LockFile": {"lib": "kernel32", "purpose": "lock region of file for exclusive access", "category": "win_file"},
    "UnlockFile": {"lib": "kernel32", "purpose": "unlock previously locked file region", "category": "win_file"},
    "GetFileAttributesA": {"lib": "kernel32", "purpose": "get file attributes (ANSI)", "category": "win_file"},
    "GetFileAttributesW": {"lib": "kernel32", "purpose": "get file attributes (Unicode)", "category": "win_file"},
    "SetFileAttributesA": {"lib": "kernel32", "purpose": "set file attributes (ANSI)", "category": "win_file"},
    "SetFileAttributesW": {"lib": "kernel32", "purpose": "set file attributes (Unicode)", "category": "win_file"},
    "GetFileType": {"lib": "kernel32", "purpose": "determine type of file object", "category": "win_file"},
    "CreateDirectoryA": {"lib": "kernel32", "purpose": "create directory (ANSI)", "category": "win_file"},
    "CreateDirectoryW": {"lib": "kernel32", "purpose": "create directory (Unicode)", "category": "win_file"},
    "RemoveDirectoryA": {"lib": "kernel32", "purpose": "remove empty directory (ANSI)", "category": "win_file"},
    "RemoveDirectoryW": {"lib": "kernel32", "purpose": "remove empty directory (Unicode)", "category": "win_file"},
    "DeleteFileA": {"lib": "kernel32", "purpose": "delete file (ANSI)", "category": "win_file"},
    "DeleteFileW": {"lib": "kernel32", "purpose": "delete file (Unicode)", "category": "win_file"},
    "CopyFileA": {"lib": "kernel32", "purpose": "copy file (ANSI)", "category": "win_file"},
    "CopyFileW": {"lib": "kernel32", "purpose": "copy file (Unicode)", "category": "win_file"},
    "MoveFileA": {"lib": "kernel32", "purpose": "move or rename file (ANSI)", "category": "win_file"},
    "MoveFileW": {"lib": "kernel32", "purpose": "move or rename file (Unicode)", "category": "win_file"},
    "MoveFileExA": {"lib": "kernel32", "purpose": "move file with options (ANSI)", "category": "win_file"},
    "MoveFileExW": {"lib": "kernel32", "purpose": "move file with options (Unicode)", "category": "win_file"},
    "FindFirstFileA": {"lib": "kernel32", "purpose": "start file search (ANSI)", "category": "win_file"},
    "FindFirstFileW": {"lib": "kernel32", "purpose": "start file search (Unicode)", "category": "win_file"},
    "FindNextFileA": {"lib": "kernel32", "purpose": "continue file search (ANSI)", "category": "win_file"},
    "FindNextFileW": {"lib": "kernel32", "purpose": "continue file search (Unicode)", "category": "win_file"},
    "FindClose": {"lib": "kernel32", "purpose": "close file search handle", "category": "win_file"},
    "GetFullPathNameA": {"lib": "kernel32", "purpose": "get full path name (ANSI)", "category": "win_file"},
    "GetFullPathNameW": {"lib": "kernel32", "purpose": "get full path name (Unicode)", "category": "win_file"},
    "GetTempPathA": {"lib": "kernel32", "purpose": "get temporary directory path (ANSI)", "category": "win_file"},
    "GetTempPathW": {"lib": "kernel32", "purpose": "get temporary directory path (Unicode)", "category": "win_file"},
    "GetTempFileNameA": {"lib": "kernel32", "purpose": "create temporary file name (ANSI)", "category": "win_file"},
    "GetTempFileNameW": {"lib": "kernel32", "purpose": "create temporary file name (Unicode)", "category": "win_file"},
    "GetLongPathNameA": {"lib": "kernel32", "purpose": "convert short path to long (ANSI)", "category": "win_file"},
    "GetLongPathNameW": {"lib": "kernel32", "purpose": "convert short path to long (Unicode)", "category": "win_file"},

    # --- kernel32: File mapping ---
    "CreateFileMappingA": {"lib": "kernel32", "purpose": "create file mapping object (ANSI)", "category": "win_memory"},
    "CreateFileMappingW": {"lib": "kernel32", "purpose": "create file mapping object (Unicode)", "category": "win_memory"},
    "MapViewOfFile": {"lib": "kernel32", "purpose": "map view of file into address space", "category": "win_memory"},
    "MapViewOfFileEx": {"lib": "kernel32", "purpose": "map view at specified address", "category": "win_memory"},
    "UnmapViewOfFile": {"lib": "kernel32", "purpose": "unmap view of file from address space", "category": "win_memory"},
    "FlushViewOfFile": {"lib": "kernel32", "purpose": "flush dirty pages of mapped view to disk", "category": "win_memory"},

    # --- kernel32: Interlocked operations ---
    "InterlockedIncrement": {"lib": "kernel32", "purpose": "atomic increment", "category": "win_sync"},
    "InterlockedDecrement": {"lib": "kernel32", "purpose": "atomic decrement", "category": "win_sync"},
    "InterlockedExchange": {"lib": "kernel32", "purpose": "atomic exchange", "category": "win_sync"},
    "InterlockedCompareExchange": {"lib": "kernel32", "purpose": "atomic compare-and-swap", "category": "win_sync"},

    # --- kernel32: Console I/O ---
    "GetStdHandle": {"lib": "kernel32", "purpose": "get standard I/O handle (stdin/stdout/stderr)", "category": "win_io"},
    "WriteConsoleA": {"lib": "kernel32", "purpose": "write to console output buffer (ANSI)", "category": "win_io"},
    "WriteConsoleW": {"lib": "kernel32", "purpose": "write to console output buffer (Unicode)", "category": "win_io"},
    "ReadConsoleA": {"lib": "kernel32", "purpose": "read from console input buffer (ANSI)", "category": "win_io"},
    "ReadConsoleW": {"lib": "kernel32", "purpose": "read from console input buffer (Unicode)", "category": "win_io"},
    "SetConsoleTextAttribute": {"lib": "kernel32", "purpose": "set console text color/attributes", "category": "win_io"},
    "AllocConsole": {"lib": "kernel32", "purpose": "allocate new console for process", "category": "win_io"},
    "FreeConsole": {"lib": "kernel32", "purpose": "detach process from console", "category": "win_io"},

    # --- kernel32: Environment / Path ---
    "GetEnvironmentVariableA": {"lib": "kernel32", "purpose": "get environment variable (ANSI)", "category": "win_system"},
    "GetEnvironmentVariableW": {"lib": "kernel32", "purpose": "get environment variable (Unicode)", "category": "win_system"},
    "SetEnvironmentVariableA": {"lib": "kernel32", "purpose": "set environment variable (ANSI)", "category": "win_system"},
    "SetEnvironmentVariableW": {"lib": "kernel32", "purpose": "set environment variable (Unicode)", "category": "win_system"},
    "GetModuleFileNameA": {"lib": "kernel32", "purpose": "get path of loaded module (ANSI)", "category": "win_module"},
    "GetModuleFileNameW": {"lib": "kernel32", "purpose": "get path of loaded module (Unicode)", "category": "win_module"},
    "GetSystemDirectoryA": {"lib": "kernel32", "purpose": "get system directory path (ANSI)", "category": "win_system"},
    "GetSystemDirectoryW": {"lib": "kernel32", "purpose": "get system directory path (Unicode)", "category": "win_system"},
    "GetWindowsDirectoryA": {"lib": "kernel32", "purpose": "get Windows directory path (ANSI)", "category": "win_system"},
    "GetWindowsDirectoryW": {"lib": "kernel32", "purpose": "get Windows directory path (Unicode)", "category": "win_system"},
    "GetComputerNameA": {"lib": "kernel32", "purpose": "get NetBIOS computer name (ANSI)", "category": "win_system"},
    "GetComputerNameW": {"lib": "kernel32", "purpose": "get NetBIOS computer name (Unicode)", "category": "win_system"},

    # --- kernel32: Thread pool ---
    "CreateThreadpoolWork": {"lib": "kernel32", "purpose": "create thread pool work object", "category": "win_thread"},
    "SubmitThreadpoolWork": {"lib": "kernel32", "purpose": "submit work to thread pool", "category": "win_thread"},
    "CloseThreadpoolWork": {"lib": "kernel32", "purpose": "close thread pool work object", "category": "win_thread"},
    "WaitForThreadpoolWorkCallbacks": {"lib": "kernel32", "purpose": "wait for outstanding thread pool callbacks", "category": "win_thread"},
    "CreateThreadpoolTimer": {"lib": "kernel32", "purpose": "create thread pool timer", "category": "win_thread"},
    "SetThreadpoolTimer": {"lib": "kernel32", "purpose": "set thread pool timer due time", "category": "win_thread"},
    "TlsAlloc": {"lib": "kernel32", "purpose": "allocate thread-local storage index", "category": "win_thread"},
    "TlsFree": {"lib": "kernel32", "purpose": "free thread-local storage index", "category": "win_thread"},
    "TlsGetValue": {"lib": "kernel32", "purpose": "get value in TLS slot", "category": "win_thread"},
    "TlsSetValue": {"lib": "kernel32", "purpose": "set value in TLS slot", "category": "win_thread"},

    # --- kernel32: I/O Completion Ports ---
    "CreateIoCompletionPort": {"lib": "kernel32", "purpose": "create/associate I/O completion port", "category": "win_io"},
    "GetQueuedCompletionStatus": {"lib": "kernel32", "purpose": "dequeue I/O completion packet", "category": "win_io"},
    "PostQueuedCompletionStatus": {"lib": "kernel32", "purpose": "post completion packet to port", "category": "win_io"},
    "GetQueuedCompletionStatusEx": {"lib": "kernel32", "purpose": "dequeue multiple completion packets", "category": "win_io"},

    # --- kernel32: Pipes ---
    "CreatePipe": {"lib": "kernel32", "purpose": "create anonymous pipe", "category": "win_io"},
    "CreateNamedPipeA": {"lib": "kernel32", "purpose": "create named pipe instance (ANSI)", "category": "win_io"},
    "CreateNamedPipeW": {"lib": "kernel32", "purpose": "create named pipe instance (Unicode)", "category": "win_io"},
    "ConnectNamedPipe": {"lib": "kernel32", "purpose": "wait for client to connect to named pipe", "category": "win_io"},
    "DisconnectNamedPipe": {"lib": "kernel32", "purpose": "disconnect server end of named pipe", "category": "win_io"},
    "PeekNamedPipe": {"lib": "kernel32", "purpose": "peek data from named pipe without removing", "category": "win_io"},
    "TransactNamedPipe": {"lib": "kernel32", "purpose": "write then read on named pipe", "category": "win_io"},

    # --- kernel32: Fiber ---
    "ConvertThreadToFiber": {"lib": "kernel32", "purpose": "convert thread to fiber", "category": "win_thread"},
    "CreateFiber": {"lib": "kernel32", "purpose": "create fiber in current thread", "category": "win_thread"},
    "SwitchToFiber": {"lib": "kernel32", "purpose": "switch execution to specified fiber", "category": "win_thread"},
    "DeleteFiber": {"lib": "kernel32", "purpose": "delete fiber", "category": "win_thread"},

    # --- ws2_32 extended ---
    "WSASocketA": {"lib": "ws2_32", "purpose": "create socket with WSA options (ANSI)", "category": "win_network"},
    "WSASocketW": {"lib": "ws2_32", "purpose": "create socket with WSA options (Unicode)", "category": "win_network"},
    "WSAConnect": {"lib": "ws2_32", "purpose": "establish connection with WSA extensions", "category": "win_network"},
    "WSASend": {"lib": "ws2_32", "purpose": "send data using overlapped I/O", "category": "win_network"},
    "WSARecv": {"lib": "ws2_32", "purpose": "receive data using overlapped I/O", "category": "win_network"},
    "WSASendTo": {"lib": "ws2_32", "purpose": "send datagram using overlapped I/O", "category": "win_network"},
    "WSARecvFrom": {"lib": "ws2_32", "purpose": "receive datagram using overlapped I/O", "category": "win_network"},
    "WSAIoctl": {"lib": "ws2_32", "purpose": "control socket I/O mode (extended)", "category": "win_network"},
    "WSAAsyncSelect": {"lib": "ws2_32", "purpose": "request async notification for socket events", "category": "win_network"},
    "WSAEnumNetworkEvents": {"lib": "ws2_32", "purpose": "enumerate network events for socket", "category": "win_network"},
    "WSAAddressToStringA": {"lib": "ws2_32", "purpose": "convert socket address to string (ANSI)", "category": "win_network"},
    "WSAStringToAddressA": {"lib": "ws2_32", "purpose": "convert string to socket address (ANSI)", "category": "win_network"},
    "InetPtonW": {"lib": "ws2_32", "purpose": "convert IP string to binary (Unicode)", "category": "win_network"},
    "InetNtopW": {"lib": "ws2_32", "purpose": "convert binary IP to string (Unicode)", "category": "win_network"},

    # --- advapi32 extended ---
    "RegOpenKeyExW": {"lib": "advapi32", "purpose": "open registry key (Unicode)", "category": "win_registry"},
    "RegQueryValueExW": {"lib": "advapi32", "purpose": "query registry value data (Unicode)", "category": "win_registry"},
    "RegSetValueExW": {"lib": "advapi32", "purpose": "set registry value data (Unicode)", "category": "win_registry"},
    "RegDeleteValueW": {"lib": "advapi32", "purpose": "delete registry value (Unicode)", "category": "win_registry"},
    "RegDeleteKeyExA": {"lib": "advapi32", "purpose": "delete registry key (ANSI, 64-bit aware)", "category": "win_registry"},
    "RegDeleteKeyExW": {"lib": "advapi32", "purpose": "delete registry key (Unicode, 64-bit aware)", "category": "win_registry"},
    "RegCreateKeyExW": {"lib": "advapi32", "purpose": "create or open registry key (Unicode)", "category": "win_registry"},
    "RegEnumKeyExW": {"lib": "advapi32", "purpose": "enumerate registry subkeys (Unicode)", "category": "win_registry"},
    "RegEnumValueW": {"lib": "advapi32", "purpose": "enumerate registry values (Unicode)", "category": "win_registry"},
    "RegNotifyChangeKeyValue": {"lib": "advapi32", "purpose": "notify on registry key change", "category": "win_registry"},
    "RegFlushKey": {"lib": "advapi32", "purpose": "flush registry key to disk", "category": "win_registry"},
    "RegLoadKeyA": {"lib": "advapi32", "purpose": "load registry hive from file (ANSI)", "category": "win_registry"},
    "RegUnLoadKeyA": {"lib": "advapi32", "purpose": "unload registry hive (ANSI)", "category": "win_registry"},
    "RegSaveKeyA": {"lib": "advapi32", "purpose": "save registry key to file (ANSI)", "category": "win_registry"},
    "RegRestoreKeyA": {"lib": "advapi32", "purpose": "restore registry key from file (ANSI)", "category": "win_registry"},

    # --- advapi32: Security extended ---
    "OpenThreadToken": {"lib": "advapi32", "purpose": "open access token of thread", "category": "win_security"},
    "DuplicateToken": {"lib": "advapi32", "purpose": "duplicate access token", "category": "win_security"},
    "DuplicateTokenEx": {"lib": "advapi32", "purpose": "duplicate token with options", "category": "win_security"},
    "ImpersonateLoggedOnUser": {"lib": "advapi32", "purpose": "impersonate logged-on user token", "category": "win_security"},
    "RevertToSelf": {"lib": "advapi32", "purpose": "stop impersonation", "category": "win_security"},
    "LogonUserA": {"lib": "advapi32", "purpose": "logon user to obtain token (ANSI)", "category": "win_security"},
    "LogonUserW": {"lib": "advapi32", "purpose": "logon user to obtain token (Unicode)", "category": "win_security"},
    "CreateProcessAsUserA": {"lib": "advapi32", "purpose": "create process as another user (ANSI)", "category": "win_security"},
    "CreateProcessAsUserW": {"lib": "advapi32", "purpose": "create process as another user (Unicode)", "category": "win_security"},
    "CreateServiceA": {"lib": "advapi32", "purpose": "create Windows service (ANSI)", "category": "win_service"},
    "CreateServiceW": {"lib": "advapi32", "purpose": "create Windows service (Unicode)", "category": "win_service"},
    "OpenServiceA": {"lib": "advapi32", "purpose": "open existing service (ANSI)", "category": "win_service"},
    "OpenServiceW": {"lib": "advapi32", "purpose": "open existing service (Unicode)", "category": "win_service"},
    "OpenSCManagerA": {"lib": "advapi32", "purpose": "open service control manager (ANSI)", "category": "win_service"},
    "OpenSCManagerW": {"lib": "advapi32", "purpose": "open service control manager (Unicode)", "category": "win_service"},
    "StartServiceA": {"lib": "advapi32", "purpose": "start a service (ANSI)", "category": "win_service"},
    "ControlService": {"lib": "advapi32", "purpose": "send control code to service", "category": "win_service"},
    "DeleteService": {"lib": "advapi32", "purpose": "mark service for deletion", "category": "win_service"},
    "QueryServiceStatusEx": {"lib": "advapi32", "purpose": "query extended service status", "category": "win_service"},
    "ChangeServiceConfigA": {"lib": "advapi32", "purpose": "change service configuration (ANSI)", "category": "win_service"},
    "CryptEncrypt": {"lib": "advapi32", "purpose": "encrypt data (CryptoAPI)", "category": "win_crypto"},
    "CryptDecrypt": {"lib": "advapi32", "purpose": "decrypt data (CryptoAPI)", "category": "win_crypto"},
    "CryptGetHashParam": {"lib": "advapi32", "purpose": "get hash parameter value", "category": "win_crypto"},
    "CryptSignHashA": {"lib": "advapi32", "purpose": "sign hash value (ANSI)", "category": "win_crypto"},
    "CryptVerifySignatureA": {"lib": "advapi32", "purpose": "verify hash signature (ANSI)", "category": "win_crypto"},
    "CryptImportKey": {"lib": "advapi32", "purpose": "import crypto key from blob", "category": "win_crypto"},
    "CryptExportKey": {"lib": "advapi32", "purpose": "export crypto key to blob", "category": "win_crypto"},
    "CryptGenKey": {"lib": "advapi32", "purpose": "generate random crypto key", "category": "win_crypto"},
    "CryptDestroyKey": {"lib": "advapi32", "purpose": "destroy crypto key handle", "category": "win_crypto"},
    "CryptDestroyHash": {"lib": "advapi32", "purpose": "destroy hash object handle", "category": "win_crypto"},
    "CryptDeriveKey": {"lib": "advapi32", "purpose": "derive key from password hash", "category": "win_crypto"},

    # --- advapi32: Event log ---
    "OpenEventLogA": {"lib": "advapi32", "purpose": "open event log (ANSI)", "category": "win_eventlog"},
    "CloseEventLog": {"lib": "advapi32", "purpose": "close event log handle", "category": "win_eventlog"},
    "ReadEventLogA": {"lib": "advapi32", "purpose": "read event log entries (ANSI)", "category": "win_eventlog"},
    "ReportEventA": {"lib": "advapi32", "purpose": "write event log entry (ANSI)", "category": "win_eventlog"},

    # --- user32 extended ---
    "CreateWindowExW": {"lib": "user32", "purpose": "create window (Unicode)", "category": "win_gui"},
    "RegisterClassExW": {"lib": "user32", "purpose": "register window class (Unicode)", "category": "win_gui"},
    "DefWindowProcW": {"lib": "user32", "purpose": "default window procedure (Unicode)", "category": "win_gui"},
    "GetMessageW": {"lib": "user32", "purpose": "retrieve message from queue (Unicode)", "category": "win_msg"},
    "PeekMessageA": {"lib": "user32", "purpose": "peek at message without removing (ANSI)", "category": "win_msg"},
    "PeekMessageW": {"lib": "user32", "purpose": "peek at message without removing (Unicode)", "category": "win_msg"},
    "DispatchMessageW": {"lib": "user32", "purpose": "dispatch message to window procedure (Unicode)", "category": "win_msg"},
    "PostMessageW": {"lib": "user32", "purpose": "post message to thread queue (Unicode)", "category": "win_msg"},
    "SendMessageW": {"lib": "user32", "purpose": "send message to window procedure (Unicode)", "category": "win_msg"},
    "GetWindowTextA": {"lib": "user32", "purpose": "get window title bar text (ANSI)", "category": "win_gui"},
    "GetWindowTextW": {"lib": "user32", "purpose": "get window title bar text (Unicode)", "category": "win_gui"},
    "SetWindowTextA": {"lib": "user32", "purpose": "set window title bar text (ANSI)", "category": "win_gui"},
    "SetWindowTextW": {"lib": "user32", "purpose": "set window title bar text (Unicode)", "category": "win_gui"},
    "GetWindowRect": {"lib": "user32", "purpose": "get window bounding rectangle", "category": "win_gui"},
    "GetClientRect": {"lib": "user32", "purpose": "get window client area rectangle", "category": "win_gui"},
    "MoveWindow": {"lib": "user32", "purpose": "change window position and size", "category": "win_gui"},
    "SetWindowPos": {"lib": "user32", "purpose": "change size/position/Z-order", "category": "win_gui"},
    "EnumWindows": {"lib": "user32", "purpose": "enumerate all top-level windows", "category": "win_gui"},
    "FindWindowA": {"lib": "user32", "purpose": "find window by class and title (ANSI)", "category": "win_gui"},
    "FindWindowW": {"lib": "user32", "purpose": "find window by class and title (Unicode)", "category": "win_gui"},
    "GetWindowLongA": {"lib": "user32", "purpose": "get window attribute (ANSI)", "category": "win_gui"},
    "SetWindowLongA": {"lib": "user32", "purpose": "set window attribute (ANSI)", "category": "win_gui"},
    "GetClassNameA": {"lib": "user32", "purpose": "get window class name (ANSI)", "category": "win_gui"},
    "IsWindow": {"lib": "user32", "purpose": "check if handle is valid window", "category": "win_gui"},
    "IsWindowVisible": {"lib": "user32", "purpose": "check if window is visible", "category": "win_gui"},
    "EnableWindow": {"lib": "user32", "purpose": "enable or disable window input", "category": "win_gui"},

    # --- user32: Clipboard ---
    "OpenClipboard": {"lib": "user32", "purpose": "open clipboard for examination", "category": "win_clipboard"},
    "CloseClipboard": {"lib": "user32", "purpose": "close clipboard", "category": "win_clipboard"},
    "GetClipboardData": {"lib": "user32", "purpose": "retrieve clipboard data", "category": "win_clipboard"},
    "SetClipboardData": {"lib": "user32", "purpose": "place data on clipboard", "category": "win_clipboard"},
    "EmptyClipboard": {"lib": "user32", "purpose": "empty clipboard contents", "category": "win_clipboard"},

    # --- user32: Input ---
    "GetAsyncKeyState": {"lib": "user32", "purpose": "check if key is pressed (async)", "category": "win_input"},
    "GetKeyState": {"lib": "user32", "purpose": "get key state from message queue", "category": "win_input"},
    "keybd_event": {"lib": "user32", "purpose": "synthesize keyboard input (deprecated)", "category": "win_input"},
    "mouse_event": {"lib": "user32", "purpose": "synthesize mouse input (deprecated)", "category": "win_input"},
    "SendInput": {"lib": "user32", "purpose": "synthesize keyboard/mouse input", "category": "win_input"},
    "SetWindowsHookExA": {"lib": "user32", "purpose": "install hook procedure (ANSI)", "category": "win_hook"},
    "SetWindowsHookExW": {"lib": "user32", "purpose": "install hook procedure (Unicode)", "category": "win_hook"},
    "UnhookWindowsHookEx": {"lib": "user32", "purpose": "remove hook procedure", "category": "win_hook"},
    "CallNextHookEx": {"lib": "user32", "purpose": "pass hook info to next procedure", "category": "win_hook"},
    "GetCursorPos": {"lib": "user32", "purpose": "get cursor position", "category": "win_input"},
    "SetCursorPos": {"lib": "user32", "purpose": "set cursor position", "category": "win_input"},

    # --- gdi32 ---
    "CreateCompatibleDC": {"lib": "gdi32", "purpose": "create memory device context", "category": "win_gdi"},
    "CreateCompatibleBitmap": {"lib": "gdi32", "purpose": "create bitmap compatible with DC", "category": "win_gdi"},
    "SelectObject": {"lib": "gdi32", "purpose": "select GDI object into DC", "category": "win_gdi"},
    "DeleteObject": {"lib": "gdi32", "purpose": "delete GDI object", "category": "win_gdi"},
    "DeleteDC": {"lib": "gdi32", "purpose": "delete device context", "category": "win_gdi"},
    "BitBlt": {"lib": "gdi32", "purpose": "bit-block transfer between DCs", "category": "win_gdi"},
    "StretchBlt": {"lib": "gdi32", "purpose": "stretch bit-block transfer", "category": "win_gdi"},
    "CreateFontA": {"lib": "gdi32", "purpose": "create logical font (ANSI)", "category": "win_gdi"},
    "CreateFontW": {"lib": "gdi32", "purpose": "create logical font (Unicode)", "category": "win_gdi"},
    "TextOutA": {"lib": "gdi32", "purpose": "draw text string at position (ANSI)", "category": "win_gdi"},
    "TextOutW": {"lib": "gdi32", "purpose": "draw text string at position (Unicode)", "category": "win_gdi"},
    "CreatePen": {"lib": "gdi32", "purpose": "create GDI pen object", "category": "win_gdi"},
    "CreateSolidBrush": {"lib": "gdi32", "purpose": "create solid color brush", "category": "win_gdi"},
    "Rectangle": {"lib": "gdi32", "purpose": "draw rectangle", "category": "win_gdi"},
    "Ellipse": {"lib": "gdi32", "purpose": "draw ellipse", "category": "win_gdi"},
    "LineTo": {"lib": "gdi32", "purpose": "draw line from current position", "category": "win_gdi"},
    "MoveToEx": {"lib": "gdi32", "purpose": "move current position", "category": "win_gdi"},
    "SetPixel": {"lib": "gdi32", "purpose": "set pixel color at point", "category": "win_gdi"},
    "GetPixel": {"lib": "gdi32", "purpose": "get pixel color at point", "category": "win_gdi"},
    "GetDeviceCaps": {"lib": "gdi32", "purpose": "get device capability value", "category": "win_gdi"},

    # --- ntdll extended ---
    "NtOpenProcess": {"lib": "ntdll", "purpose": "native open process by PID", "category": "win_native"},
    "NtOpenThread": {"lib": "ntdll", "purpose": "native open thread by TID", "category": "win_native"},
    "NtQueryVirtualMemory": {"lib": "ntdll", "purpose": "query virtual memory region info", "category": "win_native"},
    "NtCreateSection": {"lib": "ntdll", "purpose": "create section object (file mapping)", "category": "win_native"},
    "NtMapViewOfSection": {"lib": "ntdll", "purpose": "native map section view", "category": "win_native"},
    "NtUnmapViewOfSection": {"lib": "ntdll", "purpose": "native unmap section view", "category": "win_native"},
    "NtSetInformationThread": {"lib": "ntdll", "purpose": "set thread information class", "category": "win_native"},
    "NtQueryInformationThread": {"lib": "ntdll", "purpose": "query thread information class", "category": "win_native"},
    "NtSetInformationProcess": {"lib": "ntdll", "purpose": "set process information class", "category": "win_native"},
    "NtDelayExecution": {"lib": "ntdll", "purpose": "native sleep (NtDelayExecution)", "category": "win_native"},
    "NtWaitForSingleObject": {"lib": "ntdll", "purpose": "native wait for object", "category": "win_native"},
    "NtSignalAndWaitForSingleObject": {"lib": "ntdll", "purpose": "signal object and wait atomically", "category": "win_native"},
    "NtCreateEvent": {"lib": "ntdll", "purpose": "native create event object", "category": "win_native"},
    "NtCreateMutant": {"lib": "ntdll", "purpose": "native create mutex object", "category": "win_native"},
    "NtQueryObject": {"lib": "ntdll", "purpose": "query object attributes", "category": "win_native"},
    "NtDuplicateObject": {"lib": "ntdll", "purpose": "duplicate handle between processes", "category": "win_native"},
    "NtQueryDirectoryFile": {"lib": "ntdll", "purpose": "native directory enumeration", "category": "win_native"},
    "NtDeviceIoControlFile": {"lib": "ntdll", "purpose": "native device I/O control", "category": "win_native"},
    "NtCreateKey": {"lib": "ntdll", "purpose": "native create registry key", "category": "win_native"},
    "NtOpenKey": {"lib": "ntdll", "purpose": "native open registry key", "category": "win_native"},
    "NtQueryValueKey": {"lib": "ntdll", "purpose": "native query registry value", "category": "win_native"},
    "NtSetValueKey": {"lib": "ntdll", "purpose": "native set registry value", "category": "win_native"},
    "LdrLoadDll": {"lib": "ntdll", "purpose": "native DLL loading (below LoadLibrary)", "category": "win_native"},
    "LdrGetProcedureAddress": {"lib": "ntdll", "purpose": "native export resolution (below GetProcAddress)", "category": "win_native"},
    "LdrGetDllHandle": {"lib": "ntdll", "purpose": "native get DLL base address", "category": "win_native"},
    "RtlCreateUserThread": {"lib": "ntdll", "purpose": "create thread in target process", "category": "win_native"},
    "RtlCopyMemory": {"lib": "ntdll", "purpose": "copy memory block", "category": "win_native"},
    "RtlZeroMemory": {"lib": "ntdll", "purpose": "zero memory block", "category": "win_native"},
    "RtlMoveMemory": {"lib": "ntdll", "purpose": "move memory block (overlap-safe)", "category": "win_native"},
    "RtlCompareMemory": {"lib": "ntdll", "purpose": "compare memory blocks", "category": "win_native"},
    "NtSystemDebugControl": {"lib": "ntdll", "purpose": "kernel debug control operations", "category": "win_native"},

    # --- shell32 ---
    "ShellExecuteA": {"lib": "shell32", "purpose": "open/run file or URL (ANSI)", "category": "win_shell"},
    "ShellExecuteW": {"lib": "shell32", "purpose": "open/run file or URL (Unicode)", "category": "win_shell"},
    "ShellExecuteExA": {"lib": "shell32", "purpose": "extended shell execute (ANSI)", "category": "win_shell"},
    "ShellExecuteExW": {"lib": "shell32", "purpose": "extended shell execute (Unicode)", "category": "win_shell"},
    "SHGetFolderPathA": {"lib": "shell32", "purpose": "get special folder path (ANSI)", "category": "win_shell"},
    "SHGetFolderPathW": {"lib": "shell32", "purpose": "get special folder path (Unicode)", "category": "win_shell"},
    "SHGetKnownFolderPath": {"lib": "shell32", "purpose": "get known folder path (Vista+)", "category": "win_shell"},
    "SHCreateDirectoryExA": {"lib": "shell32", "purpose": "create directory tree (ANSI)", "category": "win_shell"},
    "SHFileOperationA": {"lib": "shell32", "purpose": "copy/move/rename/delete files (ANSI)", "category": "win_shell"},
    "SHFileOperationW": {"lib": "shell32", "purpose": "copy/move/rename/delete files (Unicode)", "category": "win_shell"},
    "DragQueryFileA": {"lib": "shell32", "purpose": "get dropped file path (ANSI)", "category": "win_shell"},
    "SHBrowseForFolderA": {"lib": "shell32", "purpose": "display folder browser dialog (ANSI)", "category": "win_shell"},
    "SHGetPathFromIDListA": {"lib": "shell32", "purpose": "convert PIDL to path (ANSI)", "category": "win_shell"},

    # --- ole32 / COM ---
    "CoInitialize": {"lib": "ole32", "purpose": "initialize COM library (STA)", "category": "win_com"},
    "CoInitializeEx": {"lib": "ole32", "purpose": "initialize COM library with concurrency model", "category": "win_com"},
    "CoUninitialize": {"lib": "ole32", "purpose": "uninitialize COM library", "category": "win_com"},
    "CoCreateInstance": {"lib": "ole32", "purpose": "create COM object instance", "category": "win_com"},
    "CoGetClassObject": {"lib": "ole32", "purpose": "get COM class factory", "category": "win_com"},
    "CoTaskMemAlloc": {"lib": "ole32", "purpose": "allocate COM task memory", "category": "win_com"},
    "CoTaskMemFree": {"lib": "ole32", "purpose": "free COM task memory", "category": "win_com"},
    "CoMarshalInterThreadInterfaceInStream": {"lib": "ole32", "purpose": "marshal COM interface across threads", "category": "win_com"},
    "StringFromCLSID": {"lib": "ole32", "purpose": "convert CLSID to string", "category": "win_com"},
    "CLSIDFromString": {"lib": "ole32", "purpose": "convert string to CLSID", "category": "win_com"},
    "StringFromGUID2": {"lib": "ole32", "purpose": "convert GUID to string", "category": "win_com"},

    # --- oleaut32 ---
    "SysAllocString": {"lib": "oleaut32", "purpose": "allocate BSTR string", "category": "win_com"},
    "SysFreeString": {"lib": "oleaut32", "purpose": "free BSTR string", "category": "win_com"},
    "SysStringLen": {"lib": "oleaut32", "purpose": "get BSTR length", "category": "win_com"},
    "VariantInit": {"lib": "oleaut32", "purpose": "initialize VARIANT structure", "category": "win_com"},
    "VariantClear": {"lib": "oleaut32", "purpose": "clear VARIANT and release resources", "category": "win_com"},
    "VariantChangeType": {"lib": "oleaut32", "purpose": "convert VARIANT to different type", "category": "win_com"},
    "SafeArrayCreate": {"lib": "oleaut32", "purpose": "create OLE safe array", "category": "win_com"},
    "SafeArrayDestroy": {"lib": "oleaut32", "purpose": "destroy OLE safe array", "category": "win_com"},
    "SafeArrayAccessData": {"lib": "oleaut32", "purpose": "lock safe array and get data pointer", "category": "win_com"},
    "SafeArrayUnaccessData": {"lib": "oleaut32", "purpose": "unlock safe array", "category": "win_com"},

    # --- crypt32 ---
    "CertOpenStore": {"lib": "crypt32", "purpose": "open certificate store", "category": "win_crypto"},
    "CertCloseStore": {"lib": "crypt32", "purpose": "close certificate store", "category": "win_crypto"},
    "CertFindCertificateInStore": {"lib": "crypt32", "purpose": "find certificate in store", "category": "win_crypto"},
    "CertGetCertificateChain": {"lib": "crypt32", "purpose": "build certificate chain", "category": "win_crypto"},
    "CertVerifyCertificateChainPolicy": {"lib": "crypt32", "purpose": "verify certificate chain policy", "category": "win_crypto"},
    "CertFreeCertificateContext": {"lib": "crypt32", "purpose": "free certificate context", "category": "win_crypto"},
    "CertDuplicateCertificateContext": {"lib": "crypt32", "purpose": "duplicate certificate context", "category": "win_crypto"},
    "CryptStringToBinaryA": {"lib": "crypt32", "purpose": "decode base64/hex string to binary (ANSI)", "category": "win_crypto"},
    "CryptBinaryToStringA": {"lib": "crypt32", "purpose": "encode binary to base64/hex string (ANSI)", "category": "win_crypto"},
    "CryptDecodeObjectEx": {"lib": "crypt32", "purpose": "decode ASN.1 structure", "category": "win_crypto"},
    "CryptEncodeObjectEx": {"lib": "crypt32", "purpose": "encode to ASN.1 structure", "category": "win_crypto"},
    "CryptProtectData": {"lib": "crypt32", "purpose": "encrypt data using DPAPI", "category": "win_crypto"},
    "CryptUnprotectData": {"lib": "crypt32", "purpose": "decrypt DPAPI-protected data", "category": "win_crypto"},
    "PFXImportCertStore": {"lib": "crypt32", "purpose": "import PFX/PKCS#12 certificate", "category": "win_crypto"},
    "PFXExportCertStoreEx": {"lib": "crypt32", "purpose": "export certificate store as PFX", "category": "win_crypto"},

    # --- bcrypt (CNG - Cryptography Next Generation) ---
    "BCryptOpenAlgorithmProvider": {"lib": "bcrypt", "purpose": "open CNG algorithm provider", "category": "win_crypto"},
    "BCryptCloseAlgorithmProvider": {"lib": "bcrypt", "purpose": "close CNG algorithm provider", "category": "win_crypto"},
    "BCryptGenerateSymmetricKey": {"lib": "bcrypt", "purpose": "generate CNG symmetric key", "category": "win_crypto"},
    "BCryptEncrypt": {"lib": "bcrypt", "purpose": "CNG symmetric encryption", "category": "win_crypto"},
    "BCryptDecrypt": {"lib": "bcrypt", "purpose": "CNG symmetric decryption", "category": "win_crypto"},
    "BCryptCreateHash": {"lib": "bcrypt", "purpose": "create CNG hash object", "category": "win_crypto"},
    "BCryptHashData": {"lib": "bcrypt", "purpose": "add data to CNG hash", "category": "win_crypto"},
    "BCryptFinishHash": {"lib": "bcrypt", "purpose": "finalize CNG hash computation", "category": "win_crypto"},
    "BCryptDestroyHash": {"lib": "bcrypt", "purpose": "destroy CNG hash object", "category": "win_crypto"},
    "BCryptDestroyKey": {"lib": "bcrypt", "purpose": "destroy CNG key object", "category": "win_crypto"},
    "BCryptGenRandom": {"lib": "bcrypt", "purpose": "generate CNG random bytes", "category": "win_crypto"},
    "BCryptGenerateKeyPair": {"lib": "bcrypt", "purpose": "generate CNG asymmetric key pair", "category": "win_crypto"},
    "BCryptFinalizeKeyPair": {"lib": "bcrypt", "purpose": "finalize CNG key pair generation", "category": "win_crypto"},
    "BCryptSignHash": {"lib": "bcrypt", "purpose": "CNG digital signature creation", "category": "win_crypto"},
    "BCryptVerifySignature": {"lib": "bcrypt", "purpose": "CNG digital signature verification", "category": "win_crypto"},
    "BCryptDeriveKey": {"lib": "bcrypt", "purpose": "CNG key derivation", "category": "win_crypto"},
    "BCryptExportKey": {"lib": "bcrypt", "purpose": "export CNG key to blob", "category": "win_crypto"},
    "BCryptImportKey": {"lib": "bcrypt", "purpose": "import CNG key from blob", "category": "win_crypto"},

    # --- winhttp ---
    "WinHttpOpen": {"lib": "winhttp", "purpose": "initialize WinHTTP session", "category": "win_http"},
    "WinHttpConnect": {"lib": "winhttp", "purpose": "connect to HTTP server", "category": "win_http"},
    "WinHttpOpenRequest": {"lib": "winhttp", "purpose": "create HTTP request handle", "category": "win_http"},
    "WinHttpSendRequest": {"lib": "winhttp", "purpose": "send HTTP request", "category": "win_http"},
    "WinHttpReceiveResponse": {"lib": "winhttp", "purpose": "receive HTTP response", "category": "win_http"},
    "WinHttpReadData": {"lib": "winhttp", "purpose": "read HTTP response data", "category": "win_http"},
    "WinHttpQueryHeaders": {"lib": "winhttp", "purpose": "query HTTP response headers", "category": "win_http"},
    "WinHttpCloseHandle": {"lib": "winhttp", "purpose": "close WinHTTP handle", "category": "win_http"},
    "WinHttpSetOption": {"lib": "winhttp", "purpose": "set WinHTTP option", "category": "win_http"},
    "WinHttpQueryDataAvailable": {"lib": "winhttp", "purpose": "query amount of available data", "category": "win_http"},
    "WinHttpCrackUrl": {"lib": "winhttp", "purpose": "parse URL into components", "category": "win_http"},
    "WinHttpAddRequestHeaders": {"lib": "winhttp", "purpose": "add HTTP request headers", "category": "win_http"},

    # --- wininet ---
    "InternetOpenA": {"lib": "wininet", "purpose": "initialize WinINet session (ANSI)", "category": "win_http"},
    "InternetOpenW": {"lib": "wininet", "purpose": "initialize WinINet session (Unicode)", "category": "win_http"},
    "InternetConnectA": {"lib": "wininet", "purpose": "connect to server (ANSI)", "category": "win_http"},
    "InternetOpenUrlA": {"lib": "wininet", "purpose": "open URL (ANSI)", "category": "win_http"},
    "InternetReadFile": {"lib": "wininet", "purpose": "read data from internet handle", "category": "win_http"},
    "InternetWriteFile": {"lib": "wininet", "purpose": "write data to internet handle", "category": "win_http"},
    "InternetCloseHandle": {"lib": "wininet", "purpose": "close internet handle", "category": "win_http"},
    "HttpOpenRequestA": {"lib": "wininet", "purpose": "create HTTP request (ANSI)", "category": "win_http"},
    "HttpSendRequestA": {"lib": "wininet", "purpose": "send HTTP request (ANSI)", "category": "win_http"},
    "HttpQueryInfoA": {"lib": "wininet", "purpose": "query HTTP header info (ANSI)", "category": "win_http"},
    "InternetSetOptionA": {"lib": "wininet", "purpose": "set internet option (ANSI)", "category": "win_http"},
    "InternetQueryOptionA": {"lib": "wininet", "purpose": "query internet option (ANSI)", "category": "win_http"},

    # --- version.dll ---
    "GetFileVersionInfoA": {"lib": "version", "purpose": "get file version info (ANSI)", "category": "win_system"},
    "GetFileVersionInfoW": {"lib": "version", "purpose": "get file version info (Unicode)", "category": "win_system"},
    "GetFileVersionInfoSizeA": {"lib": "version", "purpose": "get version info buffer size (ANSI)", "category": "win_system"},
    "VerQueryValueA": {"lib": "version", "purpose": "query version info value (ANSI)", "category": "win_system"},
    "VerQueryValueW": {"lib": "version", "purpose": "query version info value (Unicode)", "category": "win_system"},

    # --- psapi ---
    "EnumProcesses": {"lib": "psapi", "purpose": "enumerate running process IDs", "category": "win_process"},
    "EnumProcessModules": {"lib": "psapi", "purpose": "enumerate modules in process", "category": "win_process"},
    "EnumProcessModulesEx": {"lib": "psapi", "purpose": "enumerate modules with filter", "category": "win_process"},
    "GetModuleBaseNameA": {"lib": "psapi", "purpose": "get module base name (ANSI)", "category": "win_process"},
    "GetModuleFileNameExA": {"lib": "psapi", "purpose": "get module file name in process (ANSI)", "category": "win_process"},
    "GetProcessMemoryInfo": {"lib": "psapi", "purpose": "get process memory usage info", "category": "win_process"},

    # --- dbghelp ---
    "SymInitialize": {"lib": "dbghelp", "purpose": "initialize symbol handler", "category": "win_debug"},
    "SymCleanup": {"lib": "dbghelp", "purpose": "cleanup symbol handler", "category": "win_debug"},
    "SymFromAddr": {"lib": "dbghelp", "purpose": "get symbol from address", "category": "win_debug"},
    "SymLoadModuleEx": {"lib": "dbghelp", "purpose": "load debug symbols for module", "category": "win_debug"},
    "StackWalk64": {"lib": "dbghelp", "purpose": "walk call stack frames", "category": "win_debug"},
    "MiniDumpWriteDump": {"lib": "dbghelp", "purpose": "write process minidump file", "category": "win_debug"},
    "UnDecorateSymbolName": {"lib": "dbghelp", "purpose": "undecorate C++ mangled name", "category": "win_debug"},

    # --- iphlpapi ---
    "GetAdaptersInfo": {"lib": "iphlpapi", "purpose": "get network adapter information", "category": "win_network"},
    "GetAdaptersAddresses": {"lib": "iphlpapi", "purpose": "get network adapter addresses", "category": "win_network"},
    "GetTcpTable": {"lib": "iphlpapi", "purpose": "get TCP connection table", "category": "win_network"},
    "GetUdpTable": {"lib": "iphlpapi", "purpose": "get UDP endpoint table", "category": "win_network"},
    "GetBestRoute": {"lib": "iphlpapi", "purpose": "get best route for destination", "category": "win_network"},
    "GetIpForwardTable": {"lib": "iphlpapi", "purpose": "get IP routing table", "category": "win_network"},

    # --- secur32 ---
    "AcquireCredentialsHandleA": {"lib": "secur32", "purpose": "acquire SSPI credentials (ANSI)", "category": "win_security"},
    "InitializeSecurityContextA": {"lib": "secur32", "purpose": "initialize SSPI security context (ANSI)", "category": "win_security"},
    "AcceptSecurityContext": {"lib": "secur32", "purpose": "accept SSPI security context", "category": "win_security"},
    "FreeCredentialsHandle": {"lib": "secur32", "purpose": "free SSPI credentials handle", "category": "win_security"},
    "DeleteSecurityContext": {"lib": "secur32", "purpose": "delete SSPI security context", "category": "win_security"},
    "EncryptMessage": {"lib": "secur32", "purpose": "SSPI encrypt message", "category": "win_security"},
    "DecryptMessage": {"lib": "secur32", "purpose": "SSPI decrypt message", "category": "win_security"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Rust Standard Library (~100 imza)
# Tokio async runtime, serde, popular crate patterns.
# ---------------------------------------------------------------------------

_RUST_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # -- Tokio async runtime --
    "__ZN5tokio7runtime": {"lib": "tokio", "purpose": "tokio::runtime (async runtime)", "category": "rust_async"},
    "__ZN5tokio2io": {"lib": "tokio", "purpose": "tokio::io async I/O", "category": "rust_async"},
    "__ZN5tokio3net": {"lib": "tokio", "purpose": "tokio::net async networking", "category": "rust_async"},
    "__ZN5tokio4sync": {"lib": "tokio", "purpose": "tokio::sync async synchronization", "category": "rust_async"},
    "__ZN5tokio4task": {"lib": "tokio", "purpose": "tokio::task task spawning", "category": "rust_async"},
    "__ZN5tokio4time": {"lib": "tokio", "purpose": "tokio::time timers and delays", "category": "rust_async"},
    "__ZN5tokio6signal": {"lib": "tokio", "purpose": "tokio::signal signal handling", "category": "rust_async"},
    "__ZN5tokio7process": {"lib": "tokio", "purpose": "tokio::process async child process", "category": "rust_async"},
    "__ZN5tokio2fs": {"lib": "tokio", "purpose": "tokio::fs async filesystem", "category": "rust_async"},

    # -- async-std --
    "__ZN9async_std": {"lib": "async-std", "purpose": "async-std runtime", "category": "rust_async"},

    # -- serde --
    "__ZN5serde2de": {"lib": "serde", "purpose": "serde::de deserialization", "category": "rust_serde"},
    "__ZN5serde3ser": {"lib": "serde", "purpose": "serde::ser serialization", "category": "rust_serde"},
    "__ZN10serde_json": {"lib": "serde_json", "purpose": "serde_json JSON serde", "category": "rust_serde"},
    "__ZN11serde_cbor": {"lib": "serde_cbor", "purpose": "serde CBOR format", "category": "rust_serde"},
    "__ZN8bincode": {"lib": "bincode", "purpose": "bincode binary serialization", "category": "rust_serde"},
    "__ZN4toml": {"lib": "toml", "purpose": "TOML format serde", "category": "rust_serde"},

    # -- hyper / reqwest HTTP --
    "__ZN5hyper": {"lib": "hyper", "purpose": "hyper HTTP client/server", "category": "rust_http"},
    "__ZN7reqwest": {"lib": "reqwest", "purpose": "reqwest HTTP client", "category": "rust_http"},
    "__ZN4actix": {"lib": "actix", "purpose": "actix web framework", "category": "rust_http"},
    "__ZN4warp": {"lib": "warp", "purpose": "warp web framework", "category": "rust_http"},
    "__ZN4axum": {"lib": "axum", "purpose": "axum web framework", "category": "rust_http"},

    # -- core / alloc extended --
    "__ZN4core4hash": {"lib": "rust-core", "purpose": "core::hash hashing infrastructure", "category": "rust_core"},
    "__ZN4core3num": {"lib": "rust-core", "purpose": "core::num numeric parsing/conversion", "category": "rust_core"},
    "__ZN4core4char": {"lib": "rust-core", "purpose": "core::char Unicode character handling", "category": "rust_core"},
    "__ZN4core6marker": {"lib": "rust-core", "purpose": "core::marker trait implementations (Send/Sync)", "category": "rust_core"},
    "__ZN4core7convert": {"lib": "rust-core", "purpose": "core::convert From/Into/TryFrom traits", "category": "rust_core"},
    "__ZN4core3cmp": {"lib": "rust-core", "purpose": "core::cmp comparison trait impls", "category": "rust_core"},
    "__ZN4core5clone": {"lib": "rust-core", "purpose": "core::clone::Clone implementations", "category": "rust_core"},
    "__ZN4core7default": {"lib": "rust-core", "purpose": "core::default::Default implementations", "category": "rust_core"},
    "__ZN4core4cell": {"lib": "rust-core", "purpose": "core::cell interior mutability (Cell/RefCell)", "category": "rust_core"},
    "__ZN4core3mem": {"lib": "rust-core", "purpose": "core::mem memory manipulation (swap, drop, etc)", "category": "rust_core"},
    "__ZN4core4sync6atomic": {"lib": "rust-core", "purpose": "core::sync::atomic operations", "category": "rust_sync"},
    "__ZN4core5alloc": {"lib": "rust-core", "purpose": "core::alloc allocator traits", "category": "rust_core"},
    "__ZN4core8intrinsics": {"lib": "rust-core", "purpose": "core::intrinsics compiler intrinsics", "category": "rust_core"},
    "__ZN4core5array": {"lib": "rust-core", "purpose": "core::array fixed-size array operations", "category": "rust_core"},
    "__ZN4core4hint": {"lib": "rust-core", "purpose": "core::hint performance hints (black_box etc)", "category": "rust_core"},
    "__ZN4core5error": {"lib": "rust-core", "purpose": "core::error Error trait", "category": "rust_core"},
    "__ZN5alloc7raw_vec": {"lib": "rust-alloc", "purpose": "alloc::raw_vec::RawVec raw vector", "category": "rust_collections"},
    "__ZN5alloc6alloc": {"lib": "rust-alloc", "purpose": "alloc::alloc global allocator", "category": "rust_collections"},
    "__ZN5alloc4borrow": {"lib": "rust-alloc", "purpose": "alloc::borrow Cow borrow type", "category": "rust_collections"},
    "__ZN5alloc3fmt": {"lib": "rust-alloc", "purpose": "alloc::fmt formatting support", "category": "rust_core"},

    # -- std extended --
    "__ZN3std7ffi": {"lib": "rust-std", "purpose": "std::ffi foreign function interface (CString etc)", "category": "rust_ffi"},
    "__ZN3std5path": {"lib": "rust-std", "purpose": "std::path Path/PathBuf operations", "category": "rust_io"},
    "__ZN3std8backtrace": {"lib": "rust-std", "purpose": "std::backtrace stack trace capture", "category": "rust_debug"},
    "__ZN3std5error": {"lib": "rust-std", "purpose": "std::error Error trait extensions", "category": "rust_core"},

    # -- log / tracing --
    "__ZN3log": {"lib": "log", "purpose": "log crate logging facade", "category": "rust_log"},
    "__ZN7tracing": {"lib": "tracing", "purpose": "tracing instrumentation framework", "category": "rust_log"},
    "__ZN14tracing_subscriber": {"lib": "tracing-subscriber", "purpose": "tracing subscriber layer", "category": "rust_log"},
    "__ZN6env_logger": {"lib": "env_logger", "purpose": "env_logger logging backend", "category": "rust_log"},

    # -- crypto / TLS crates --
    "__ZN7rustls": {"lib": "rustls", "purpose": "rustls TLS implementation", "category": "rust_crypto"},
    "__ZN5ring": {"lib": "ring", "purpose": "ring cryptography library", "category": "rust_crypto"},
    "__ZN3sha2": {"lib": "sha2", "purpose": "sha2 hash crate", "category": "rust_crypto"},
    "__ZN3aes": {"lib": "aes", "purpose": "aes cipher crate", "category": "rust_crypto"},
    "__ZN10native_tls": {"lib": "native-tls", "purpose": "native-tls platform TLS", "category": "rust_crypto"},

    # -- database crates --
    "__ZN6diesel": {"lib": "diesel", "purpose": "diesel ORM/query builder", "category": "rust_db"},
    "__ZN4sqlx": {"lib": "sqlx", "purpose": "sqlx async SQL toolkit", "category": "rust_db"},
    "__ZN8rusqlite": {"lib": "rusqlite", "purpose": "rusqlite SQLite bindings", "category": "rust_db"},

    # -- error handling --
    "__ZN6anyhow": {"lib": "anyhow", "purpose": "anyhow flexible error handling", "category": "rust_error"},
    "__ZN9thiserror": {"lib": "thiserror", "purpose": "thiserror derive macro for Error", "category": "rust_error"},

    # -- CLI / args --
    "__ZN4clap": {"lib": "clap", "purpose": "clap command-line argument parser", "category": "rust_cli"},
    "__ZN10structopt": {"lib": "structopt", "purpose": "structopt CLI derive macro", "category": "rust_cli"},

    # -- concurrency --
    "__ZN8crossbeam": {"lib": "crossbeam", "purpose": "crossbeam concurrent utilities", "category": "rust_sync"},
    "__ZN5rayon": {"lib": "rayon", "purpose": "rayon data parallelism library", "category": "rust_sync"},
    "__ZN6parking_lot": {"lib": "parking_lot", "purpose": "parking_lot efficient sync primitives", "category": "rust_sync"},

    # -- regex --
    "__ZN5regex": {"lib": "regex", "purpose": "regex regular expression engine", "category": "rust_regex"},

    # -- rand --
    "__ZN4rand": {"lib": "rand", "purpose": "rand random number generation", "category": "rust_rand"},

    # -- chrono / time --
    "__ZN6chrono": {"lib": "chrono", "purpose": "chrono date/time library", "category": "rust_time"},

    # -- Rust unwinding / panic symbols (demangled) --
    "rust_begin_unwind": {"lib": "rust-std", "purpose": "Rust panic unwinding entry", "category": "rust_panic"},
    "rust_panic": {"lib": "rust-std", "purpose": "Rust panic handler", "category": "rust_panic"},
    "rust_eh_personality": {"lib": "rust-std", "purpose": "Rust exception personality function (LSDA)", "category": "rust_panic"},
    "__rust_alloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (alloc)", "category": "rust_runtime"},
    "__rust_dealloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (dealloc)", "category": "rust_runtime"},
    "__rust_realloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (realloc)", "category": "rust_runtime"},
    "__rust_alloc_zeroed": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (alloc_zeroed)", "category": "rust_runtime"},
    "__rust_alloc_error_handler": {"lib": "rust-alloc", "purpose": "Rust allocation failure handler", "category": "rust_runtime"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Go Runtime + stdlib (~100 imza)
# Go binary'lerde gorulen ek paket fonksiyonlari.
# ---------------------------------------------------------------------------

_GO_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- runtime extended ---
    "runtime.mstart": {"lib": "go-runtime", "purpose": "OS thread start routine for Go", "category": "go_runtime"},
    "runtime.mstart0": {"lib": "go-runtime", "purpose": "initial OS thread setup", "category": "go_runtime"},
    "runtime.schedinit": {"lib": "go-runtime", "purpose": "scheduler initialization", "category": "go_runtime"},
    "runtime.schedule": {"lib": "go-runtime", "purpose": "select next goroutine to run", "category": "go_runtime"},
    "runtime.findrunnable": {"lib": "go-runtime", "purpose": "find a runnable goroutine", "category": "go_runtime"},
    "runtime.park_m": {"lib": "go-runtime", "purpose": "park current goroutine", "category": "go_runtime"},
    "runtime.gopark": {"lib": "go-runtime", "purpose": "goroutine park (suspend)", "category": "go_runtime"},
    "runtime.goready": {"lib": "go-runtime", "purpose": "goroutine ready (resume)", "category": "go_runtime"},
    "runtime.Gosched": {"lib": "go-runtime", "purpose": "yield to scheduler (cooperative)", "category": "go_runtime"},
    "runtime.GOMAXPROCS": {"lib": "go-runtime", "purpose": "set max OS threads for goroutines", "category": "go_runtime"},
    "runtime.NumGoroutine": {"lib": "go-runtime", "purpose": "get number of goroutines", "category": "go_runtime"},
    "runtime.NumCPU": {"lib": "go-runtime", "purpose": "get number of CPUs", "category": "go_runtime"},
    "runtime.GC": {"lib": "go-runtime", "purpose": "trigger garbage collection", "category": "go_gc"},
    "runtime.SetFinalizer": {"lib": "go-runtime", "purpose": "set finalizer on object", "category": "go_gc"},
    "runtime.ReadMemStats": {"lib": "go-runtime", "purpose": "read memory allocator stats", "category": "go_gc"},
    "runtime.KeepAlive": {"lib": "go-runtime", "purpose": "prevent GC from collecting object", "category": "go_gc"},
    "runtime.gcBgMarkWorker": {"lib": "go-runtime", "purpose": "background GC mark worker", "category": "go_gc"},
    "runtime.gcSweep": {"lib": "go-runtime", "purpose": "GC sweep phase", "category": "go_gc"},
    "runtime.systemstack": {"lib": "go-runtime", "purpose": "switch to system stack", "category": "go_runtime"},
    "runtime.mcall": {"lib": "go-runtime", "purpose": "call function on m stack", "category": "go_runtime"},
    "runtime.gogo": {"lib": "go-runtime", "purpose": "switch to goroutine (context switch)", "category": "go_runtime"},
    "runtime.Caller": {"lib": "go-runtime", "purpose": "get calling goroutine stack info", "category": "go_runtime"},
    "runtime.Callers": {"lib": "go-runtime", "purpose": "get stack trace of goroutine", "category": "go_runtime"},
    "runtime.Stack": {"lib": "go-runtime", "purpose": "format stack trace", "category": "go_runtime"},

    # --- runtime: map internals ---
    "runtime.mapaccess1_fast32": {"lib": "go-runtime", "purpose": "fast map lookup (int32 key)", "category": "go_map"},
    "runtime.mapaccess1_fast64": {"lib": "go-runtime", "purpose": "fast map lookup (int64 key)", "category": "go_map"},
    "runtime.mapaccess1_faststr": {"lib": "go-runtime", "purpose": "fast map lookup (string key)", "category": "go_map"},
    "runtime.mapassign_fast32": {"lib": "go-runtime", "purpose": "fast map assign (int32 key)", "category": "go_map"},
    "runtime.mapassign_fast64": {"lib": "go-runtime", "purpose": "fast map assign (int64 key)", "category": "go_map"},
    "runtime.mapassign_faststr": {"lib": "go-runtime", "purpose": "fast map assign (string key)", "category": "go_map"},
    "runtime.mapdelete_fast32": {"lib": "go-runtime", "purpose": "fast map delete (int32 key)", "category": "go_map"},
    "runtime.mapdelete_fast64": {"lib": "go-runtime", "purpose": "fast map delete (int64 key)", "category": "go_map"},
    "runtime.mapdelete_faststr": {"lib": "go-runtime", "purpose": "fast map delete (string key)", "category": "go_map"},
    "runtime.mapiterinit": {"lib": "go-runtime", "purpose": "initialize map iterator", "category": "go_map"},
    "runtime.mapiternext": {"lib": "go-runtime", "purpose": "advance map iterator", "category": "go_map"},

    # --- runtime: type assertion / interface ---
    "runtime.assertI2I": {"lib": "go-runtime", "purpose": "interface-to-interface type assertion", "category": "go_runtime"},
    "runtime.assertI2I2": {"lib": "go-runtime", "purpose": "interface-to-interface (comma-ok)", "category": "go_runtime"},
    "runtime.assertE2I": {"lib": "go-runtime", "purpose": "empty-to-interface type assertion", "category": "go_runtime"},
    "runtime.assertE2I2": {"lib": "go-runtime", "purpose": "empty-to-interface (comma-ok)", "category": "go_runtime"},
    "runtime.convI2I": {"lib": "go-runtime", "purpose": "convert between interface types", "category": "go_runtime"},

    # --- runtime: string operations ---
    "runtime.stringtoslicebyte": {"lib": "go-runtime", "purpose": "convert string to []byte", "category": "go_slice"},
    "runtime.slicebytetostringtmp": {"lib": "go-runtime", "purpose": "temporary []byte to string (no copy)", "category": "go_slice"},
    "runtime.concatstrings": {"lib": "go-runtime", "purpose": "concatenate strings", "category": "go_slice"},
    "runtime.rawstringtmp": {"lib": "go-runtime", "purpose": "create temporary raw string", "category": "go_slice"},

    # --- runtime: select ---
    "runtime.selectgo": {"lib": "go-runtime", "purpose": "Go select statement implementation", "category": "go_channel"},
    "runtime.selectnbsend": {"lib": "go-runtime", "purpose": "non-blocking channel send in select", "category": "go_channel"},
    "runtime.selectnbrecv": {"lib": "go-runtime", "purpose": "non-blocking channel receive in select", "category": "go_channel"},

    # --- runtime: defer ---
    "runtime.deferproc": {"lib": "go-runtime", "purpose": "register deferred function call", "category": "go_runtime"},
    "runtime.deferreturn": {"lib": "go-runtime", "purpose": "execute deferred function calls", "category": "go_runtime"},

    # --- runtime: memory internals ---
    "runtime.newobject": {"lib": "go-runtime", "purpose": "allocate new object on heap", "category": "go_memory"},
    "runtime.memmove": {"lib": "go-runtime", "purpose": "Go runtime memory move", "category": "go_memory"},
    "runtime.memclrNoHeapPointers": {"lib": "go-runtime", "purpose": "clear non-pointer memory", "category": "go_memory"},
    "runtime.memclrHasPointers": {"lib": "go-runtime", "purpose": "clear memory containing pointers", "category": "go_memory"},

    # --- fmt extended ---
    "fmt.Errorf": {"lib": "go-fmt", "purpose": "format error message", "category": "go_fmt"},
    "fmt.Sscanf": {"lib": "go-fmt", "purpose": "scan formatted string", "category": "go_fmt"},
    "fmt.Fprintln": {"lib": "go-fmt", "purpose": "print line to io.Writer", "category": "go_fmt"},
    "fmt.Fprint": {"lib": "go-fmt", "purpose": "print to io.Writer", "category": "go_fmt"},
    "fmt.Sprint": {"lib": "go-fmt", "purpose": "format to string", "category": "go_fmt"},
    "fmt.Sprintln": {"lib": "go-fmt", "purpose": "format line to string", "category": "go_fmt"},

    # --- os extended ---
    "os.OpenFile": {"lib": "go-os", "purpose": "open file with flags and permissions", "category": "go_os"},
    "os.Mkdir": {"lib": "go-os", "purpose": "create directory", "category": "go_os"},
    "os.MkdirAll": {"lib": "go-os", "purpose": "create directory tree", "category": "go_os"},
    "os.Remove": {"lib": "go-os", "purpose": "remove file or empty directory", "category": "go_os"},
    "os.RemoveAll": {"lib": "go-os", "purpose": "remove file/directory tree", "category": "go_os"},
    "os.Rename": {"lib": "go-os", "purpose": "rename file", "category": "go_os"},
    "os.Stat": {"lib": "go-os", "purpose": "get file info", "category": "go_os"},
    "os.Lstat": {"lib": "go-os", "purpose": "get file info (no follow symlink)", "category": "go_os"},
    "os.ReadFile": {"lib": "go-os", "purpose": "read entire file contents", "category": "go_os"},
    "os.WriteFile": {"lib": "go-os", "purpose": "write data to file", "category": "go_os"},
    "os.Executable": {"lib": "go-os", "purpose": "get path of current executable", "category": "go_os"},
    "os.Hostname": {"lib": "go-os", "purpose": "get system hostname", "category": "go_os"},
    "os.UserHomeDir": {"lib": "go-os", "purpose": "get user home directory", "category": "go_os"},
    "os.Setenv": {"lib": "go-os", "purpose": "set environment variable", "category": "go_os"},

    # --- io ---
    "io.Copy": {"lib": "go-io", "purpose": "copy from Reader to Writer", "category": "go_io"},
    "io.ReadAll": {"lib": "go-io", "purpose": "read all bytes from Reader", "category": "go_io"},
    "io.ReadFull": {"lib": "go-io", "purpose": "read exactly n bytes", "category": "go_io"},
    "io.WriteString": {"lib": "go-io", "purpose": "write string to Writer", "category": "go_io"},
    "io.Pipe": {"lib": "go-io", "purpose": "create in-memory pipe", "category": "go_io"},
    "io.NopCloser": {"lib": "go-io", "purpose": "wrap Reader with no-op Close", "category": "go_io"},

    # --- bufio ---
    "bufio.NewReader": {"lib": "go-bufio", "purpose": "create buffered Reader", "category": "go_io"},
    "bufio.NewWriter": {"lib": "go-bufio", "purpose": "create buffered Writer", "category": "go_io"},
    "bufio.NewScanner": {"lib": "go-bufio", "purpose": "create line scanner", "category": "go_io"},

    # --- strings ---
    "strings.Contains": {"lib": "go-strings", "purpose": "check if string contains substring", "category": "go_string"},
    "strings.HasPrefix": {"lib": "go-strings", "purpose": "check string prefix", "category": "go_string"},
    "strings.HasSuffix": {"lib": "go-strings", "purpose": "check string suffix", "category": "go_string"},
    "strings.Split": {"lib": "go-strings", "purpose": "split string by separator", "category": "go_string"},
    "strings.Join": {"lib": "go-strings", "purpose": "join strings with separator", "category": "go_string"},
    "strings.Replace": {"lib": "go-strings", "purpose": "replace substring occurrences", "category": "go_string"},
    "strings.TrimSpace": {"lib": "go-strings", "purpose": "trim leading/trailing whitespace", "category": "go_string"},
    "strings.ToLower": {"lib": "go-strings", "purpose": "convert string to lowercase", "category": "go_string"},
    "strings.ToUpper": {"lib": "go-strings", "purpose": "convert string to uppercase", "category": "go_string"},
    "strings.NewReader": {"lib": "go-strings", "purpose": "create Reader from string", "category": "go_string"},

    # --- strconv ---
    "strconv.Itoa": {"lib": "go-strconv", "purpose": "integer to ASCII string", "category": "go_string"},
    "strconv.Atoi": {"lib": "go-strconv", "purpose": "ASCII string to integer", "category": "go_string"},
    "strconv.FormatInt": {"lib": "go-strconv", "purpose": "format int64 to string", "category": "go_string"},
    "strconv.ParseInt": {"lib": "go-strconv", "purpose": "parse string to int64", "category": "go_string"},
    "strconv.ParseFloat": {"lib": "go-strconv", "purpose": "parse string to float", "category": "go_string"},
    "strconv.FormatFloat": {"lib": "go-strconv", "purpose": "format float to string", "category": "go_string"},

    # --- bytes ---
    "bytes.Contains": {"lib": "go-bytes", "purpose": "check if byte slice contains pattern", "category": "go_string"},
    "bytes.Equal": {"lib": "go-bytes", "purpose": "compare byte slices for equality", "category": "go_string"},
    "bytes.NewBuffer": {"lib": "go-bytes", "purpose": "create byte buffer from initial data", "category": "go_string"},
    "bytes.NewReader": {"lib": "go-bytes", "purpose": "create Reader from byte slice", "category": "go_string"},

    # --- net extended ---
    "net.DialTimeout": {"lib": "go-net", "purpose": "connect with timeout", "category": "go_net"},
    "net.LookupHost": {"lib": "go-net", "purpose": "DNS hostname lookup", "category": "go_net"},
    "net.LookupAddr": {"lib": "go-net", "purpose": "reverse DNS lookup", "category": "go_net"},
    "net.LookupIP": {"lib": "go-net", "purpose": "lookup IP addresses for host", "category": "go_net"},
    "net.JoinHostPort": {"lib": "go-net", "purpose": "join host and port strings", "category": "go_net"},
    "net.SplitHostPort": {"lib": "go-net", "purpose": "split host:port string", "category": "go_net"},
    "net.ParseCIDR": {"lib": "go-net", "purpose": "parse CIDR notation address", "category": "go_net"},
    "net.ParseIP": {"lib": "go-net", "purpose": "parse IP address string", "category": "go_net"},
    "net.(*TCPListener).Accept": {"lib": "go-net", "purpose": "accept TCP connection", "category": "go_net"},
    "net.(*UDPConn).ReadFromUDP": {"lib": "go-net", "purpose": "read UDP datagram", "category": "go_net"},
    "net.(*UDPConn).WriteToUDP": {"lib": "go-net", "purpose": "write UDP datagram", "category": "go_net"},

    # --- net/http ---
    "net/http.ListenAndServe": {"lib": "go-net-http", "purpose": "start HTTP server", "category": "go_http"},
    "net/http.ListenAndServeTLS": {"lib": "go-net-http", "purpose": "start HTTPS server", "category": "go_http"},
    "net/http.Get": {"lib": "go-net-http", "purpose": "HTTP GET request", "category": "go_http"},
    "net/http.Post": {"lib": "go-net-http", "purpose": "HTTP POST request", "category": "go_http"},
    "net/http.NewRequest": {"lib": "go-net-http", "purpose": "create HTTP request", "category": "go_http"},
    "net/http.HandleFunc": {"lib": "go-net-http", "purpose": "register HTTP handler function", "category": "go_http"},
    "net/http.Handle": {"lib": "go-net-http", "purpose": "register HTTP handler", "category": "go_http"},
    "net/http.Redirect": {"lib": "go-net-http", "purpose": "HTTP redirect response", "category": "go_http"},
    "net/http.Error": {"lib": "go-net-http", "purpose": "HTTP error response", "category": "go_http"},
    "net/http.ServeFile": {"lib": "go-net-http", "purpose": "serve file over HTTP", "category": "go_http"},

    # --- encoding/json ---
    "encoding/json.Marshal": {"lib": "go-json", "purpose": "JSON marshal (struct to bytes)", "category": "go_json"},
    "encoding/json.Unmarshal": {"lib": "go-json", "purpose": "JSON unmarshal (bytes to struct)", "category": "go_json"},
    "encoding/json.NewDecoder": {"lib": "go-json", "purpose": "create streaming JSON decoder", "category": "go_json"},
    "encoding/json.NewEncoder": {"lib": "go-json", "purpose": "create streaming JSON encoder", "category": "go_json"},

    # --- encoding/base64 ---
    "encoding/base64.StdEncoding.EncodeToString": {"lib": "go-base64", "purpose": "base64 encode to string", "category": "go_encoding"},
    "encoding/base64.StdEncoding.DecodeString": {"lib": "go-base64", "purpose": "base64 decode from string", "category": "go_encoding"},

    # --- crypto ---
    "crypto/tls.Dial": {"lib": "go-crypto", "purpose": "TLS dial connection", "category": "go_crypto"},
    "crypto/sha256.Sum256": {"lib": "go-crypto", "purpose": "SHA-256 hash computation", "category": "go_crypto"},
    "crypto/sha256.New": {"lib": "go-crypto", "purpose": "create new SHA-256 hash", "category": "go_crypto"},
    "crypto/md5.Sum": {"lib": "go-crypto", "purpose": "MD5 hash computation", "category": "go_crypto"},
    "crypto/aes.NewCipher": {"lib": "go-crypto", "purpose": "create AES cipher block", "category": "go_crypto"},
    "crypto/rand.Read": {"lib": "go-crypto", "purpose": "read cryptographic random bytes", "category": "go_crypto"},
    "crypto/rsa.GenerateKey": {"lib": "go-crypto", "purpose": "generate RSA key pair", "category": "go_crypto"},
    "crypto/rsa.EncryptPKCS1v15": {"lib": "go-crypto", "purpose": "RSA PKCS#1 v1.5 encrypt", "category": "go_crypto"},
    "crypto/rsa.DecryptPKCS1v15": {"lib": "go-crypto", "purpose": "RSA PKCS#1 v1.5 decrypt", "category": "go_crypto"},
    "crypto/x509.ParseCertificate": {"lib": "go-crypto", "purpose": "parse X.509 certificate", "category": "go_crypto"},

    # --- sync extended ---
    "sync.(*RWMutex).RLock": {"lib": "go-sync", "purpose": "acquire read lock", "category": "go_sync"},
    "sync.(*RWMutex).RUnlock": {"lib": "go-sync", "purpose": "release read lock", "category": "go_sync"},
    "sync.(*RWMutex).Lock": {"lib": "go-sync", "purpose": "acquire write lock", "category": "go_sync"},
    "sync.(*RWMutex).Unlock": {"lib": "go-sync", "purpose": "release write lock", "category": "go_sync"},
    "sync.(*WaitGroup).Done": {"lib": "go-sync", "purpose": "decrement WaitGroup counter", "category": "go_sync"},
    "sync.(*Once).Do": {"lib": "go-sync", "purpose": "execute function exactly once", "category": "go_sync"},
    "sync.(*Pool).Get": {"lib": "go-sync", "purpose": "get item from sync pool", "category": "go_sync"},
    "sync.(*Pool).Put": {"lib": "go-sync", "purpose": "return item to sync pool", "category": "go_sync"},
    "sync.(*Map).Load": {"lib": "go-sync", "purpose": "load value from concurrent map", "category": "go_sync"},
    "sync.(*Map).Store": {"lib": "go-sync", "purpose": "store value in concurrent map", "category": "go_sync"},
    "sync.(*Map).Delete": {"lib": "go-sync", "purpose": "delete from concurrent map", "category": "go_sync"},
    "sync.(*Map).Range": {"lib": "go-sync", "purpose": "iterate concurrent map", "category": "go_sync"},
    "sync.(*Cond).Wait": {"lib": "go-sync", "purpose": "wait on condition variable", "category": "go_sync"},
    "sync.(*Cond).Signal": {"lib": "go-sync", "purpose": "signal one waiter", "category": "go_sync"},
    "sync.(*Cond).Broadcast": {"lib": "go-sync", "purpose": "signal all waiters", "category": "go_sync"},

    # --- context ---
    "context.Background": {"lib": "go-context", "purpose": "root context", "category": "go_context"},
    "context.TODO": {"lib": "go-context", "purpose": "placeholder context", "category": "go_context"},
    "context.WithCancel": {"lib": "go-context", "purpose": "create cancellable context", "category": "go_context"},
    "context.WithTimeout": {"lib": "go-context", "purpose": "create context with timeout", "category": "go_context"},
    "context.WithDeadline": {"lib": "go-context", "purpose": "create context with deadline", "category": "go_context"},
    "context.WithValue": {"lib": "go-context", "purpose": "create context with value", "category": "go_context"},

    # --- errors ---
    "errors.New": {"lib": "go-errors", "purpose": "create new error value", "category": "go_error"},
    "errors.Is": {"lib": "go-errors", "purpose": "check error chain for match", "category": "go_error"},
    "errors.As": {"lib": "go-errors", "purpose": "extract typed error from chain", "category": "go_error"},
    "errors.Unwrap": {"lib": "go-errors", "purpose": "unwrap error one level", "category": "go_error"},

    # --- path/filepath ---
    "path/filepath.Join": {"lib": "go-filepath", "purpose": "join path elements", "category": "go_os"},
    "path/filepath.Dir": {"lib": "go-filepath", "purpose": "get directory component", "category": "go_os"},
    "path/filepath.Base": {"lib": "go-filepath", "purpose": "get last path element", "category": "go_os"},
    "path/filepath.Ext": {"lib": "go-filepath", "purpose": "get file extension", "category": "go_os"},
    "path/filepath.Abs": {"lib": "go-filepath", "purpose": "get absolute path", "category": "go_os"},
    "path/filepath.Walk": {"lib": "go-filepath", "purpose": "walk directory tree", "category": "go_os"},
    "path/filepath.WalkDir": {"lib": "go-filepath", "purpose": "walk directory tree (efficient)", "category": "go_os"},
    "path/filepath.Glob": {"lib": "go-filepath", "purpose": "glob pattern matching", "category": "go_os"},

    # --- regexp ---
    "regexp.Compile": {"lib": "go-regexp", "purpose": "compile regular expression", "category": "go_regex"},
    "regexp.MustCompile": {"lib": "go-regexp", "purpose": "compile regex (panic on error)", "category": "go_regex"},
    "regexp.MatchString": {"lib": "go-regexp", "purpose": "test if string matches regex", "category": "go_regex"},

    # --- sort ---
    "sort.Slice": {"lib": "go-sort", "purpose": "sort slice with less function", "category": "go_sort"},
    "sort.SliceStable": {"lib": "go-sort", "purpose": "stable sort slice", "category": "go_sort"},
    "sort.Strings": {"lib": "go-sort", "purpose": "sort string slice", "category": "go_sort"},
    "sort.Ints": {"lib": "go-sort", "purpose": "sort int slice", "category": "go_sort"},
    "sort.Search": {"lib": "go-sort", "purpose": "binary search", "category": "go_sort"},

    # --- log ---
    "log.Fatal": {"lib": "go-log", "purpose": "log + os.Exit(1)", "category": "go_log"},
    "log.Fatalf": {"lib": "go-log", "purpose": "formatted log + exit", "category": "go_log"},
    "log.Panic": {"lib": "go-log", "purpose": "log + panic", "category": "go_log"},
    "log.Printf": {"lib": "go-log", "purpose": "formatted log output", "category": "go_log"},
    "log.Println": {"lib": "go-log", "purpose": "log line output", "category": "go_log"},

    # --- time ---
    "time.Now": {"lib": "go-time", "purpose": "get current time", "category": "go_time"},
    "time.Sleep": {"lib": "go-time", "purpose": "pause goroutine for duration", "category": "go_time"},
    "time.After": {"lib": "go-time", "purpose": "channel send after duration", "category": "go_time"},
    "time.Since": {"lib": "go-time", "purpose": "time elapsed since given time", "category": "go_time"},
    "time.NewTicker": {"lib": "go-time", "purpose": "create periodic ticker", "category": "go_time"},
    "time.NewTimer": {"lib": "go-time", "purpose": "create one-shot timer", "category": "go_time"},
    "time.Parse": {"lib": "go-time", "purpose": "parse time string", "category": "go_time"},

    # --- exec ---
    "os/exec.Command": {"lib": "go-exec", "purpose": "create command for execution", "category": "go_exec"},
    "os/exec.(*Cmd).Run": {"lib": "go-exec", "purpose": "run command and wait", "category": "go_exec"},
    "os/exec.(*Cmd).Output": {"lib": "go-exec", "purpose": "run command and capture stdout", "category": "go_exec"},
    "os/exec.(*Cmd).Start": {"lib": "go-exec", "purpose": "start command asynchronously", "category": "go_exec"},
    "os/exec.(*Cmd).Wait": {"lib": "go-exec", "purpose": "wait for started command", "category": "go_exec"},
    "os/exec.(*Cmd).CombinedOutput": {"lib": "go-exec", "purpose": "run and capture stdout+stderr", "category": "go_exec"},

    # --- database/sql ---
    "database/sql.Open": {"lib": "go-sql", "purpose": "open database connection pool", "category": "go_db"},
    "database/sql.(*DB).Query": {"lib": "go-sql", "purpose": "execute query returning rows", "category": "go_db"},
    "database/sql.(*DB).QueryRow": {"lib": "go-sql", "purpose": "execute query returning one row", "category": "go_db"},
    "database/sql.(*DB).Exec": {"lib": "go-sql", "purpose": "execute non-query statement", "category": "go_db"},
    "database/sql.(*DB).Prepare": {"lib": "go-sql", "purpose": "prepare SQL statement", "category": "go_db"},
    "database/sql.(*DB).Begin": {"lib": "go-sql", "purpose": "begin database transaction", "category": "go_db"},
    "database/sql.(*Tx).Commit": {"lib": "go-sql", "purpose": "commit transaction", "category": "go_db"},
    "database/sql.(*Tx).Rollback": {"lib": "go-sql", "purpose": "rollback transaction", "category": "go_db"},
    "database/sql.(*Rows).Scan": {"lib": "go-sql", "purpose": "scan row values into variables", "category": "go_db"},
    "database/sql.(*Rows).Next": {"lib": "go-sql", "purpose": "advance to next row", "category": "go_db"},
    "database/sql.(*Rows).Close": {"lib": "go-sql", "purpose": "close row iterator", "category": "go_db"},
}


# ---------------------------------------------------------------------------
# EXTENDED: ELF/Linux libc functions (~100 imza)
# C standard library (glibc/musl), dlopen/dlsym, pthread extended
# ---------------------------------------------------------------------------

_LIBC_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Dynamic loading (extending _DYNLOAD_SIGNATURES) ---
    "dlopen": {"lib": "libdl", "purpose": "load shared library at runtime", "category": "dynload"},
    "dlsym": {"lib": "libdl", "purpose": "get symbol address from shared library", "category": "dynload"},
    "dlclose": {"lib": "libdl", "purpose": "unload shared library", "category": "dynload"},
    "dlerror": {"lib": "libdl", "purpose": "get last dynamic loading error string", "category": "dynload"},
    "dladdr": {"lib": "libdl", "purpose": "get info about address in loaded library", "category": "dynload"},
    "dlinfo": {"lib": "libdl", "purpose": "get information about shared library", "category": "dynload"},
    "dl_iterate_phdr": {"lib": "libdl", "purpose": "iterate over loaded ELF program headers", "category": "dynload"},

    # --- stdio (extending _STRING_STDLIB_SIGNATURES) ---
    "printf": {"lib": "libc", "purpose": "formatted output to stdout", "category": "string"},
    "fprintf": {"lib": "libc", "purpose": "formatted output to stream", "category": "string"},
    "sprintf": {"lib": "libc", "purpose": "formatted output to string buffer", "category": "string"},
    "snprintf": {"lib": "libc", "purpose": "formatted output with size limit", "category": "string"},
    "vprintf": {"lib": "libc", "purpose": "formatted output (va_list)", "category": "string"},
    "vfprintf": {"lib": "libc", "purpose": "formatted output to stream (va_list)", "category": "string"},
    "vsprintf": {"lib": "libc", "purpose": "formatted output to buffer (va_list)", "category": "string"},
    "vsnprintf": {"lib": "libc", "purpose": "formatted output with limit (va_list)", "category": "string"},
    "scanf": {"lib": "libc", "purpose": "formatted input from stdin", "category": "string"},
    "fscanf": {"lib": "libc", "purpose": "formatted input from stream", "category": "string"},
    "sscanf": {"lib": "libc", "purpose": "formatted input from string", "category": "string"},
    "puts": {"lib": "libc", "purpose": "write string to stdout with newline", "category": "string"},
    "fputs": {"lib": "libc", "purpose": "write string to stream", "category": "string"},
    "fgets": {"lib": "libc", "purpose": "read string from stream", "category": "string"},
    "getc": {"lib": "libc", "purpose": "read character from stream", "category": "string"},
    "fgetc": {"lib": "libc", "purpose": "read character from stream (function)", "category": "string"},
    "putc": {"lib": "libc", "purpose": "write character to stream", "category": "string"},
    "fputc": {"lib": "libc", "purpose": "write character to stream (function)", "category": "string"},
    "getchar": {"lib": "libc", "purpose": "read character from stdin", "category": "string"},
    "putchar": {"lib": "libc", "purpose": "write character to stdout", "category": "string"},
    "ungetc": {"lib": "libc", "purpose": "push character back to stream", "category": "string"},
    "perror": {"lib": "libc", "purpose": "print error message to stderr", "category": "string"},

    # --- String functions ---
    "strlen": {"lib": "libc", "purpose": "get string length", "category": "string"},
    "strnlen": {"lib": "libc", "purpose": "get string length with limit", "category": "string"},
    "strcmp": {"lib": "libc", "purpose": "compare two strings", "category": "string"},
    "strncmp": {"lib": "libc", "purpose": "compare strings with limit", "category": "string"},
    "strcasecmp": {"lib": "libc", "purpose": "case-insensitive string compare", "category": "string"},
    "strncasecmp": {"lib": "libc", "purpose": "case-insensitive compare with limit", "category": "string"},
    "strcpy": {"lib": "libc", "purpose": "copy string", "category": "string"},
    "strncpy": {"lib": "libc", "purpose": "copy string with limit", "category": "string"},
    "strlcpy": {"lib": "libc", "purpose": "copy string (safe, BSD)", "category": "string"},
    "strlcat": {"lib": "libc", "purpose": "concatenate string (safe, BSD)", "category": "string"},
    "strcat": {"lib": "libc", "purpose": "concatenate strings", "category": "string"},
    "strncat": {"lib": "libc", "purpose": "concatenate strings with limit", "category": "string"},
    "strstr": {"lib": "libc", "purpose": "find substring", "category": "string"},
    "strchr": {"lib": "libc", "purpose": "find first occurrence of character", "category": "string"},
    "strrchr": {"lib": "libc", "purpose": "find last occurrence of character", "category": "string"},
    "strpbrk": {"lib": "libc", "purpose": "find first of character set", "category": "string"},
    "strspn": {"lib": "libc", "purpose": "count chars from character set", "category": "string"},
    "strcspn": {"lib": "libc", "purpose": "count chars not in character set", "category": "string"},
    "strtok": {"lib": "libc", "purpose": "tokenize string (not thread-safe)", "category": "string"},
    "strtok_r": {"lib": "libc", "purpose": "tokenize string (reentrant)", "category": "string"},
    "strdup": {"lib": "libc", "purpose": "duplicate string (malloc + copy)", "category": "string"},
    "strndup": {"lib": "libc", "purpose": "duplicate string with limit", "category": "string"},
    "strerror": {"lib": "libc", "purpose": "get error message string", "category": "string"},
    "strerror_r": {"lib": "libc", "purpose": "get error message (reentrant)", "category": "string"},

    # --- Memory functions ---
    "malloc": {"lib": "libc", "purpose": "allocate heap memory", "category": "memory"},
    "free": {"lib": "libc", "purpose": "free heap memory", "category": "memory"},
    "calloc": {"lib": "libc", "purpose": "allocate and zero heap memory", "category": "memory"},
    "realloc": {"lib": "libc", "purpose": "resize heap memory block", "category": "memory"},
    "reallocarray": {"lib": "libc", "purpose": "resize with overflow check", "category": "memory"},
    "memcpy": {"lib": "libc", "purpose": "copy memory block", "category": "memory"},
    "memmove": {"lib": "libc", "purpose": "copy memory (overlap safe)", "category": "memory"},
    "memset": {"lib": "libc", "purpose": "fill memory with byte value", "category": "memory"},
    "memcmp": {"lib": "libc", "purpose": "compare memory blocks", "category": "memory"},
    "memchr": {"lib": "libc", "purpose": "find byte in memory", "category": "memory"},
    "memrchr": {"lib": "libc", "purpose": "find byte in memory (reverse)", "category": "memory"},
    "posix_memalign": {"lib": "libc", "purpose": "allocate aligned memory", "category": "memory"},
    "aligned_alloc": {"lib": "libc", "purpose": "allocate aligned memory (C11)", "category": "memory"},
    "memalign": {"lib": "libc", "purpose": "allocate aligned memory (deprecated)", "category": "memory"},
    "valloc": {"lib": "libc", "purpose": "allocate page-aligned memory (deprecated)", "category": "memory"},
    "pvalloc": {"lib": "libc", "purpose": "allocate pages (deprecated)", "category": "memory"},
    "malloc_usable_size": {"lib": "libc", "purpose": "get usable size of allocation", "category": "memory"},
    "explicit_bzero": {"lib": "libc", "purpose": "zero memory (not optimized out)", "category": "memory"},
    "bzero": {"lib": "libc", "purpose": "zero memory block (deprecated)", "category": "memory"},
    "bcopy": {"lib": "libc", "purpose": "copy memory (deprecated, use memcpy)", "category": "memory"},

    # --- pthread extended ---
    "pthread_create": {"lib": "libpthread", "purpose": "create new POSIX thread", "category": "thread"},
    "pthread_join": {"lib": "libpthread", "purpose": "wait for thread to terminate", "category": "thread"},
    "pthread_detach": {"lib": "libpthread", "purpose": "detach thread (auto cleanup on exit)", "category": "thread"},
    "pthread_exit": {"lib": "libpthread", "purpose": "terminate calling thread", "category": "thread"},
    "pthread_self": {"lib": "libpthread", "purpose": "get calling thread ID", "category": "thread"},
    "pthread_equal": {"lib": "libpthread", "purpose": "compare thread IDs", "category": "thread"},
    "pthread_cancel": {"lib": "libpthread", "purpose": "request thread cancellation", "category": "thread"},
    "pthread_mutex_init": {"lib": "libpthread", "purpose": "initialize mutex", "category": "thread"},
    "pthread_mutex_destroy": {"lib": "libpthread", "purpose": "destroy mutex", "category": "thread"},
    "pthread_mutex_lock": {"lib": "libpthread", "purpose": "lock mutex (blocking)", "category": "thread"},
    "pthread_mutex_trylock": {"lib": "libpthread", "purpose": "try to lock mutex (non-blocking)", "category": "thread"},
    "pthread_mutex_unlock": {"lib": "libpthread", "purpose": "unlock mutex", "category": "thread"},
    "pthread_mutex_timedlock": {"lib": "libpthread", "purpose": "lock mutex with timeout", "category": "thread"},
    "pthread_cond_init": {"lib": "libpthread", "purpose": "initialize condition variable", "category": "thread"},
    "pthread_cond_destroy": {"lib": "libpthread", "purpose": "destroy condition variable", "category": "thread"},
    "pthread_cond_wait": {"lib": "libpthread", "purpose": "wait on condition variable", "category": "thread"},
    "pthread_cond_timedwait": {"lib": "libpthread", "purpose": "wait on condition with timeout", "category": "thread"},
    "pthread_cond_signal": {"lib": "libpthread", "purpose": "signal one waiting thread", "category": "thread"},
    "pthread_cond_broadcast": {"lib": "libpthread", "purpose": "signal all waiting threads", "category": "thread"},
    "pthread_rwlock_init": {"lib": "libpthread", "purpose": "initialize read-write lock", "category": "thread"},
    "pthread_rwlock_destroy": {"lib": "libpthread", "purpose": "destroy read-write lock", "category": "thread"},
    "pthread_rwlock_rdlock": {"lib": "libpthread", "purpose": "acquire read lock", "category": "thread"},
    "pthread_rwlock_wrlock": {"lib": "libpthread", "purpose": "acquire write lock", "category": "thread"},
    "pthread_rwlock_unlock": {"lib": "libpthread", "purpose": "release read-write lock", "category": "thread"},
    "pthread_rwlock_tryrdlock": {"lib": "libpthread", "purpose": "try acquire read lock", "category": "thread"},
    "pthread_rwlock_trywrlock": {"lib": "libpthread", "purpose": "try acquire write lock", "category": "thread"},
    "pthread_spin_init": {"lib": "libpthread", "purpose": "initialize spinlock", "category": "thread"},
    "pthread_spin_destroy": {"lib": "libpthread", "purpose": "destroy spinlock", "category": "thread"},
    "pthread_spin_lock": {"lib": "libpthread", "purpose": "acquire spinlock", "category": "thread"},
    "pthread_spin_trylock": {"lib": "libpthread", "purpose": "try acquire spinlock", "category": "thread"},
    "pthread_spin_unlock": {"lib": "libpthread", "purpose": "release spinlock", "category": "thread"},
    "pthread_key_create": {"lib": "libpthread", "purpose": "create thread-specific data key", "category": "thread"},
    "pthread_key_delete": {"lib": "libpthread", "purpose": "delete thread-specific data key", "category": "thread"},
    "pthread_getspecific": {"lib": "libpthread", "purpose": "get thread-specific data value", "category": "thread"},
    "pthread_setspecific": {"lib": "libpthread", "purpose": "set thread-specific data value", "category": "thread"},
    "pthread_once": {"lib": "libpthread", "purpose": "one-time initialization", "category": "thread"},
    "pthread_barrier_init": {"lib": "libpthread", "purpose": "initialize barrier", "category": "thread"},
    "pthread_barrier_destroy": {"lib": "libpthread", "purpose": "destroy barrier", "category": "thread"},
    "pthread_barrier_wait": {"lib": "libpthread", "purpose": "wait at barrier", "category": "thread"},
    "pthread_attr_init": {"lib": "libpthread", "purpose": "initialize thread attributes", "category": "thread"},
    "pthread_attr_destroy": {"lib": "libpthread", "purpose": "destroy thread attributes", "category": "thread"},
    "pthread_attr_setdetachstate": {"lib": "libpthread", "purpose": "set thread detach state attribute", "category": "thread"},
    "pthread_attr_setstacksize": {"lib": "libpthread", "purpose": "set thread stack size attribute", "category": "thread"},

    # --- Semaphores (sem_*) ---
    "sem_init": {"lib": "libpthread", "purpose": "initialize unnamed semaphore", "category": "thread"},
    "sem_destroy": {"lib": "libpthread", "purpose": "destroy unnamed semaphore", "category": "thread"},
    "sem_wait": {"lib": "libpthread", "purpose": "decrement (lock) semaphore", "category": "thread"},
    "sem_trywait": {"lib": "libpthread", "purpose": "try decrement semaphore (non-blocking)", "category": "thread"},
    "sem_timedwait": {"lib": "libpthread", "purpose": "decrement semaphore with timeout", "category": "thread"},
    "sem_post": {"lib": "libpthread", "purpose": "increment (unlock) semaphore", "category": "thread"},
    "sem_getvalue": {"lib": "libpthread", "purpose": "get current semaphore value", "category": "thread"},
    "sem_open": {"lib": "libpthread", "purpose": "open named semaphore", "category": "thread"},
    "sem_close": {"lib": "libpthread", "purpose": "close named semaphore", "category": "thread"},
    "sem_unlink": {"lib": "libpthread", "purpose": "remove named semaphore", "category": "thread"},

    # --- Conversion / stdlib ---
    "atoi": {"lib": "libc", "purpose": "convert string to integer", "category": "string"},
    "atol": {"lib": "libc", "purpose": "convert string to long integer", "category": "string"},
    "atof": {"lib": "libc", "purpose": "convert string to double", "category": "string"},
    "strtol": {"lib": "libc", "purpose": "convert string to long with base", "category": "string"},
    "strtoul": {"lib": "libc", "purpose": "convert string to unsigned long", "category": "string"},
    "strtoll": {"lib": "libc", "purpose": "convert string to long long", "category": "string"},
    "strtoull": {"lib": "libc", "purpose": "convert string to unsigned long long", "category": "string"},
    "strtod": {"lib": "libc", "purpose": "convert string to double", "category": "string"},
    "strtof": {"lib": "libc", "purpose": "convert string to float", "category": "string"},

    # --- stdlib ---
    "abort": {"lib": "libc", "purpose": "abort process (raise SIGABRT)", "category": "process"},
    "exit": {"lib": "libc", "purpose": "normal process termination", "category": "process"},
    "atexit": {"lib": "libc", "purpose": "register function called at exit", "category": "process"},
    "system": {"lib": "libc", "purpose": "execute shell command", "category": "process"},
    "getenv": {"lib": "libc", "purpose": "get environment variable value", "category": "process"},
    "setenv": {"lib": "libc", "purpose": "set environment variable", "category": "process"},
    "unsetenv": {"lib": "libc", "purpose": "remove environment variable", "category": "process"},
    "qsort": {"lib": "libc", "purpose": "sort array (quicksort)", "category": "stdlib"},
    "bsearch": {"lib": "libc", "purpose": "binary search sorted array", "category": "stdlib"},
    "abs": {"lib": "libc", "purpose": "absolute value of integer", "category": "stdlib"},
    "labs": {"lib": "libc", "purpose": "absolute value of long", "category": "stdlib"},
    "div": {"lib": "libc", "purpose": "integer division with remainder", "category": "stdlib"},
    "rand": {"lib": "libc", "purpose": "generate pseudo-random number", "category": "stdlib"},
    "srand": {"lib": "libc", "purpose": "seed pseudo-random generator", "category": "stdlib"},
    "rand_r": {"lib": "libc", "purpose": "generate pseudo-random (reentrant)", "category": "stdlib"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Networking Libraries (~150 imza)
# OpenSSL extended, SSL/TLS, DNS, HTTP/2, QUIC patterns
# ---------------------------------------------------------------------------

_NETWORKING_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- OpenSSL / BoringSSL extended ---
    "SSL_new": {"lib": "openssl", "purpose": "create new SSL connection object", "category": "network_tls"},
    "SSL_free": {"lib": "openssl", "purpose": "free SSL connection object", "category": "network_tls"},
    "SSL_connect": {"lib": "openssl", "purpose": "initiate TLS client handshake", "category": "network_tls"},
    "SSL_accept": {"lib": "openssl", "purpose": "accept TLS server handshake", "category": "network_tls"},
    "SSL_read": {"lib": "openssl", "purpose": "read decrypted data from TLS connection", "category": "network_tls"},
    "SSL_write": {"lib": "openssl", "purpose": "write data to TLS connection", "category": "network_tls"},
    "SSL_shutdown": {"lib": "openssl", "purpose": "shut down TLS connection", "category": "network_tls"},
    "SSL_set_fd": {"lib": "openssl", "purpose": "set socket fd for SSL", "category": "network_tls"},
    "SSL_get_error": {"lib": "openssl", "purpose": "get SSL error code", "category": "network_tls"},
    "SSL_get_peer_certificate": {"lib": "openssl", "purpose": "get peer's X509 certificate", "category": "network_tls"},
    "SSL_get_verify_result": {"lib": "openssl", "purpose": "get certificate verification result", "category": "network_tls"},
    "SSL_set_tlsext_host_name": {"lib": "openssl", "purpose": "set SNI hostname for TLS", "category": "network_tls"},
    "SSL_CTX_new": {"lib": "openssl", "purpose": "create new SSL context", "category": "network_tls"},
    "SSL_CTX_free": {"lib": "openssl", "purpose": "free SSL context", "category": "network_tls"},
    "SSL_CTX_set_verify": {"lib": "openssl", "purpose": "set certificate verification mode", "category": "network_tls"},
    "SSL_CTX_use_certificate_file": {"lib": "openssl", "purpose": "load certificate from file", "category": "network_tls"},
    "SSL_CTX_use_PrivateKey_file": {"lib": "openssl", "purpose": "load private key from file", "category": "network_tls"},
    "SSL_CTX_load_verify_locations": {"lib": "openssl", "purpose": "set CA certificate locations", "category": "network_tls"},
    "SSL_CTX_set_cipher_list": {"lib": "openssl", "purpose": "set allowed cipher suites (TLS 1.2)", "category": "network_tls"},
    "SSL_CTX_set_ciphersuites": {"lib": "openssl", "purpose": "set allowed cipher suites (TLS 1.3)", "category": "network_tls"},
    "SSL_CTX_set_min_proto_version": {"lib": "openssl", "purpose": "set minimum TLS protocol version", "category": "network_tls"},
    "SSL_CTX_set_max_proto_version": {"lib": "openssl", "purpose": "set maximum TLS protocol version", "category": "network_tls"},
    "SSL_CTX_set_options": {"lib": "openssl", "purpose": "set SSL context options", "category": "network_tls"},
    "SSL_CTX_set_session_cache_mode": {"lib": "openssl", "purpose": "configure TLS session caching", "category": "network_tls"},
    "SSL_CTX_set_alpn_protos": {"lib": "openssl", "purpose": "set ALPN protocol list", "category": "network_tls"},

    # --- Networking resolution ---
    "getaddrinfo": {"lib": "libc", "purpose": "resolve hostname to socket addresses", "category": "network_dns"},
    "freeaddrinfo": {"lib": "libc", "purpose": "free addrinfo linked list", "category": "network_dns"},
    "getnameinfo": {"lib": "libc", "purpose": "reverse DNS lookup (address to name)", "category": "network_dns"},
    "gethostbyname": {"lib": "libc", "purpose": "resolve hostname (deprecated, use getaddrinfo)", "category": "network_dns"},
    "gethostbyname2": {"lib": "libc", "purpose": "resolve hostname with address family", "category": "network_dns"},
    "gethostbyaddr": {"lib": "libc", "purpose": "reverse DNS lookup (deprecated)", "category": "network_dns"},
    "inet_pton": {"lib": "libc", "purpose": "convert IP address string to binary", "category": "network_dns"},
    "inet_ntop": {"lib": "libc", "purpose": "convert binary IP address to string", "category": "network_dns"},
    "inet_addr": {"lib": "libc", "purpose": "convert IPv4 dotted-decimal to binary (deprecated)", "category": "network_dns"},
    "inet_ntoa": {"lib": "libc", "purpose": "convert binary IPv4 to dotted-decimal (deprecated)", "category": "network_dns"},
    "inet_aton": {"lib": "libc", "purpose": "convert IPv4 string to in_addr", "category": "network_dns"},
    "htons": {"lib": "libc", "purpose": "host to network byte order (16-bit)", "category": "network_util"},
    "ntohs": {"lib": "libc", "purpose": "network to host byte order (16-bit)", "category": "network_util"},
    "htonl": {"lib": "libc", "purpose": "host to network byte order (32-bit)", "category": "network_util"},
    "ntohl": {"lib": "libc", "purpose": "network to host byte order (32-bit)", "category": "network_util"},

    # --- libcurl extended ---
    "curl_easy_init": {"lib": "libcurl", "purpose": "initialize easy curl handle", "category": "network_http"},
    "curl_easy_cleanup": {"lib": "libcurl", "purpose": "cleanup easy curl handle", "category": "network_http"},
    "curl_easy_setopt": {"lib": "libcurl", "purpose": "set curl option", "category": "network_http"},
    "curl_easy_perform": {"lib": "libcurl", "purpose": "perform curl transfer", "category": "network_http"},
    "curl_easy_getinfo": {"lib": "libcurl", "purpose": "get transfer information", "category": "network_http"},
    "curl_easy_reset": {"lib": "libcurl", "purpose": "reset curl handle to defaults", "category": "network_http"},
    "curl_easy_duphandle": {"lib": "libcurl", "purpose": "duplicate curl handle", "category": "network_http"},
    "curl_easy_strerror": {"lib": "libcurl", "purpose": "get curl error string", "category": "network_http"},
    "curl_multi_init": {"lib": "libcurl", "purpose": "initialize multi curl handle", "category": "network_http"},
    "curl_multi_add_handle": {"lib": "libcurl", "purpose": "add easy handle to multi", "category": "network_http"},
    "curl_multi_remove_handle": {"lib": "libcurl", "purpose": "remove easy handle from multi", "category": "network_http"},
    "curl_multi_perform": {"lib": "libcurl", "purpose": "perform multi transfers", "category": "network_http"},
    "curl_multi_wait": {"lib": "libcurl", "purpose": "wait for multi activity", "category": "network_http"},
    "curl_multi_cleanup": {"lib": "libcurl", "purpose": "cleanup multi handle", "category": "network_http"},
    "curl_global_init": {"lib": "libcurl", "purpose": "initialize libcurl globally", "category": "network_http"},
    "curl_global_cleanup": {"lib": "libcurl", "purpose": "cleanup libcurl globally", "category": "network_http"},
    "curl_slist_append": {"lib": "libcurl", "purpose": "append to curl string list (headers)", "category": "network_http"},
    "curl_slist_free_all": {"lib": "libcurl", "purpose": "free curl string list", "category": "network_http"},
    "curl_url": {"lib": "libcurl", "purpose": "create URL object", "category": "network_http"},
    "curl_url_set": {"lib": "libcurl", "purpose": "set URL component", "category": "network_http"},
    "curl_url_get": {"lib": "libcurl", "purpose": "get URL component", "category": "network_http"},
    "curl_ws_recv": {"lib": "libcurl", "purpose": "receive WebSocket frame", "category": "network_ws"},
    "curl_ws_send": {"lib": "libcurl", "purpose": "send WebSocket frame", "category": "network_ws"},

    # --- QUIC / HTTP3 (ngtcp2, nghttp3) ---
    "ngtcp2_conn_client_new": {"lib": "ngtcp2", "purpose": "create QUIC client connection", "category": "network_quic"},
    "ngtcp2_conn_server_new": {"lib": "ngtcp2", "purpose": "create QUIC server connection", "category": "network_quic"},
    "ngtcp2_conn_read_pkt": {"lib": "ngtcp2", "purpose": "process incoming QUIC packet", "category": "network_quic"},
    "ngtcp2_conn_write_pkt": {"lib": "ngtcp2", "purpose": "generate outgoing QUIC packet", "category": "network_quic"},
    "ngtcp2_conn_open_bidi_stream": {"lib": "ngtcp2", "purpose": "open bidirectional QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_open_uni_stream": {"lib": "ngtcp2", "purpose": "open unidirectional QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_writev_stream": {"lib": "ngtcp2", "purpose": "write data to QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_del": {"lib": "ngtcp2", "purpose": "delete QUIC connection", "category": "network_quic"},
    "nghttp3_conn_client_new": {"lib": "nghttp3", "purpose": "create HTTP/3 client connection", "category": "network_h3"},
    "nghttp3_conn_server_new": {"lib": "nghttp3", "purpose": "create HTTP/3 server connection", "category": "network_h3"},
    "nghttp3_conn_submit_request": {"lib": "nghttp3", "purpose": "submit HTTP/3 request", "category": "network_h3"},
    "nghttp3_conn_read_stream": {"lib": "nghttp3", "purpose": "process HTTP/3 stream data", "category": "network_h3"},
    "nghttp3_conn_writev_stream": {"lib": "nghttp3", "purpose": "write HTTP/3 stream data", "category": "network_h3"},
    "nghttp3_conn_del": {"lib": "nghttp3", "purpose": "delete HTTP/3 connection", "category": "network_h3"},

    # --- libssh2 ---
    "libssh2_init": {"lib": "libssh2", "purpose": "initialize libssh2", "category": "network_ssh"},
    "libssh2_exit": {"lib": "libssh2", "purpose": "cleanup libssh2", "category": "network_ssh"},
    "libssh2_session_init": {"lib": "libssh2", "purpose": "create SSH session", "category": "network_ssh"},
    "libssh2_session_handshake": {"lib": "libssh2", "purpose": "perform SSH handshake", "category": "network_ssh"},
    "libssh2_session_disconnect": {"lib": "libssh2", "purpose": "disconnect SSH session", "category": "network_ssh"},
    "libssh2_session_free": {"lib": "libssh2", "purpose": "free SSH session", "category": "network_ssh"},
    "libssh2_userauth_password": {"lib": "libssh2", "purpose": "SSH password authentication", "category": "network_ssh"},
    "libssh2_userauth_publickey_fromfile": {"lib": "libssh2", "purpose": "SSH public key authentication", "category": "network_ssh"},
    "libssh2_channel_open_session": {"lib": "libssh2", "purpose": "open SSH channel", "category": "network_ssh"},
    "libssh2_channel_exec": {"lib": "libssh2", "purpose": "execute command on SSH channel", "category": "network_ssh"},
    "libssh2_channel_read": {"lib": "libssh2", "purpose": "read from SSH channel", "category": "network_ssh"},
    "libssh2_channel_write": {"lib": "libssh2", "purpose": "write to SSH channel", "category": "network_ssh"},
    "libssh2_channel_close": {"lib": "libssh2", "purpose": "close SSH channel", "category": "network_ssh"},
    "libssh2_channel_free": {"lib": "libssh2", "purpose": "free SSH channel", "category": "network_ssh"},
    "libssh2_sftp_init": {"lib": "libssh2", "purpose": "initialize SFTP session", "category": "network_ssh"},
    "libssh2_sftp_open": {"lib": "libssh2", "purpose": "open SFTP file", "category": "network_ssh"},
    "libssh2_sftp_read": {"lib": "libssh2", "purpose": "read SFTP file", "category": "network_ssh"},
    "libssh2_sftp_write": {"lib": "libssh2", "purpose": "write SFTP file", "category": "network_ssh"},
    "libssh2_sftp_close": {"lib": "libssh2", "purpose": "close SFTP file", "category": "network_ssh"},
    "libssh2_sftp_shutdown": {"lib": "libssh2", "purpose": "shutdown SFTP session", "category": "network_ssh"},
    "libssh2_scp_send64": {"lib": "libssh2", "purpose": "start SCP send", "category": "network_ssh"},
    "libssh2_scp_recv2": {"lib": "libssh2", "purpose": "start SCP receive", "category": "network_ssh"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Database Libraries (~100 imza)
# MySQL, PostgreSQL, Redis, LMDB, LevelDB, MongoDB
# ---------------------------------------------------------------------------

_DATABASE_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- MySQL (libmysqlclient / C API) ---
    "mysql_init": {"lib": "libmysqlclient", "purpose": "initialize MySQL handle", "category": "database"},
    "mysql_real_connect": {"lib": "libmysqlclient", "purpose": "connect to MySQL server", "category": "database"},
    "mysql_close": {"lib": "libmysqlclient", "purpose": "close MySQL connection", "category": "database"},
    "mysql_query": {"lib": "libmysqlclient", "purpose": "execute SQL query", "category": "database"},
    "mysql_real_query": {"lib": "libmysqlclient", "purpose": "execute query with length", "category": "database"},
    "mysql_store_result": {"lib": "libmysqlclient", "purpose": "store full result set", "category": "database"},
    "mysql_use_result": {"lib": "libmysqlclient", "purpose": "initiate row-by-row retrieval", "category": "database"},
    "mysql_fetch_row": {"lib": "libmysqlclient", "purpose": "fetch next result row", "category": "database"},
    "mysql_fetch_fields": {"lib": "libmysqlclient", "purpose": "fetch column metadata", "category": "database"},
    "mysql_num_rows": {"lib": "libmysqlclient", "purpose": "get result row count", "category": "database"},
    "mysql_num_fields": {"lib": "libmysqlclient", "purpose": "get result column count", "category": "database"},
    "mysql_free_result": {"lib": "libmysqlclient", "purpose": "free result set", "category": "database"},
    "mysql_error": {"lib": "libmysqlclient", "purpose": "get last error message", "category": "database"},
    "mysql_errno": {"lib": "libmysqlclient", "purpose": "get last error code", "category": "database"},
    "mysql_stmt_init": {"lib": "libmysqlclient", "purpose": "initialize prepared statement", "category": "database"},
    "mysql_stmt_prepare": {"lib": "libmysqlclient", "purpose": "prepare SQL statement", "category": "database"},
    "mysql_stmt_execute": {"lib": "libmysqlclient", "purpose": "execute prepared statement", "category": "database"},
    "mysql_stmt_bind_param": {"lib": "libmysqlclient", "purpose": "bind input parameters", "category": "database"},
    "mysql_stmt_bind_result": {"lib": "libmysqlclient", "purpose": "bind output columns", "category": "database"},
    "mysql_stmt_fetch": {"lib": "libmysqlclient", "purpose": "fetch prepared statement row", "category": "database"},
    "mysql_stmt_close": {"lib": "libmysqlclient", "purpose": "close prepared statement", "category": "database"},
    "mysql_autocommit": {"lib": "libmysqlclient", "purpose": "set autocommit mode", "category": "database"},
    "mysql_commit": {"lib": "libmysqlclient", "purpose": "commit transaction", "category": "database"},
    "mysql_rollback": {"lib": "libmysqlclient", "purpose": "rollback transaction", "category": "database"},
    "mysql_ping": {"lib": "libmysqlclient", "purpose": "ping server / reconnect", "category": "database"},
    "mysql_select_db": {"lib": "libmysqlclient", "purpose": "select database", "category": "database"},
    "mysql_real_escape_string": {"lib": "libmysqlclient", "purpose": "escape string for SQL", "category": "database"},
    "mysql_set_character_set": {"lib": "libmysqlclient", "purpose": "set connection character set", "category": "database"},

    # --- PostgreSQL (libpq) ---
    "PQconnectdb": {"lib": "libpq", "purpose": "connect to PostgreSQL (connection string)", "category": "database"},
    "PQconnectdbParams": {"lib": "libpq", "purpose": "connect with parameter arrays", "category": "database"},
    "PQfinish": {"lib": "libpq", "purpose": "close PostgreSQL connection", "category": "database"},
    "PQstatus": {"lib": "libpq", "purpose": "get connection status", "category": "database"},
    "PQerrorMessage": {"lib": "libpq", "purpose": "get last error message", "category": "database"},
    "PQexec": {"lib": "libpq", "purpose": "execute SQL command", "category": "database"},
    "PQexecParams": {"lib": "libpq", "purpose": "execute parameterized SQL", "category": "database"},
    "PQprepare": {"lib": "libpq", "purpose": "prepare named statement", "category": "database"},
    "PQexecPrepared": {"lib": "libpq", "purpose": "execute prepared statement", "category": "database"},
    "PQresultStatus": {"lib": "libpq", "purpose": "get command result status", "category": "database"},
    "PQntuples": {"lib": "libpq", "purpose": "get number of result rows", "category": "database"},
    "PQnfields": {"lib": "libpq", "purpose": "get number of result columns", "category": "database"},
    "PQgetvalue": {"lib": "libpq", "purpose": "get field value as string", "category": "database"},
    "PQgetisnull": {"lib": "libpq", "purpose": "check if field is NULL", "category": "database"},
    "PQfname": {"lib": "libpq", "purpose": "get column name", "category": "database"},
    "PQftype": {"lib": "libpq", "purpose": "get column type OID", "category": "database"},
    "PQclear": {"lib": "libpq", "purpose": "free result object", "category": "database"},
    "PQescapeStringConn": {"lib": "libpq", "purpose": "escape string for SQL", "category": "database"},
    "PQescapeLiteral": {"lib": "libpq", "purpose": "escape string as SQL literal", "category": "database"},
    "PQsendQuery": {"lib": "libpq", "purpose": "send async query", "category": "database"},
    "PQgetResult": {"lib": "libpq", "purpose": "get async query result", "category": "database"},
    "PQsetnonblocking": {"lib": "libpq", "purpose": "set non-blocking mode", "category": "database"},
    "PQsocket": {"lib": "libpq", "purpose": "get connection socket fd", "category": "database"},
    "PQconsumeInput": {"lib": "libpq", "purpose": "consume input from server", "category": "database"},
    "PQnotifies": {"lib": "libpq", "purpose": "get NOTIFY message", "category": "database"},

    # --- Redis (hiredis) ---
    "redisConnect": {"lib": "hiredis", "purpose": "connect to Redis server", "category": "database"},
    "redisConnectWithTimeout": {"lib": "hiredis", "purpose": "connect to Redis with timeout", "category": "database"},
    "redisFree": {"lib": "hiredis", "purpose": "free Redis connection", "category": "database"},
    "redisCommand": {"lib": "hiredis", "purpose": "execute Redis command", "category": "database"},
    "redisCommandArgv": {"lib": "hiredis", "purpose": "execute Redis command (argv)", "category": "database"},
    "redisAppendCommand": {"lib": "hiredis", "purpose": "append command to pipeline", "category": "database"},
    "redisGetReply": {"lib": "hiredis", "purpose": "get pipelined reply", "category": "database"},
    "freeReplyObject": {"lib": "hiredis", "purpose": "free Redis reply object", "category": "database"},
    "redisAsyncConnect": {"lib": "hiredis", "purpose": "async connect to Redis", "category": "database"},
    "redisAsyncCommand": {"lib": "hiredis", "purpose": "execute async Redis command", "category": "database"},
    "redisAsyncFree": {"lib": "hiredis", "purpose": "free async Redis context", "category": "database"},

    # --- LMDB (Lightning Memory-Mapped DB) ---
    "mdb_env_create": {"lib": "lmdb", "purpose": "create LMDB environment", "category": "database"},
    "mdb_env_open": {"lib": "lmdb", "purpose": "open LMDB environment", "category": "database"},
    "mdb_env_close": {"lib": "lmdb", "purpose": "close LMDB environment", "category": "database"},
    "mdb_txn_begin": {"lib": "lmdb", "purpose": "begin LMDB transaction", "category": "database"},
    "mdb_txn_commit": {"lib": "lmdb", "purpose": "commit LMDB transaction", "category": "database"},
    "mdb_txn_abort": {"lib": "lmdb", "purpose": "abort LMDB transaction", "category": "database"},
    "mdb_dbi_open": {"lib": "lmdb", "purpose": "open LMDB database", "category": "database"},
    "mdb_put": {"lib": "lmdb", "purpose": "put key-value pair", "category": "database"},
    "mdb_get": {"lib": "lmdb", "purpose": "get value by key", "category": "database"},
    "mdb_del": {"lib": "lmdb", "purpose": "delete key-value pair", "category": "database"},
    "mdb_cursor_open": {"lib": "lmdb", "purpose": "open database cursor", "category": "database"},
    "mdb_cursor_get": {"lib": "lmdb", "purpose": "get data at cursor position", "category": "database"},
    "mdb_cursor_put": {"lib": "lmdb", "purpose": "put data at cursor position", "category": "database"},
    "mdb_cursor_del": {"lib": "lmdb", "purpose": "delete at cursor position", "category": "database"},
    "mdb_cursor_close": {"lib": "lmdb", "purpose": "close database cursor", "category": "database"},

    # --- LevelDB ---
    "leveldb_open": {"lib": "leveldb", "purpose": "open LevelDB database", "category": "database"},
    "leveldb_close": {"lib": "leveldb", "purpose": "close LevelDB database", "category": "database"},
    "leveldb_put": {"lib": "leveldb", "purpose": "put key-value pair", "category": "database"},
    "leveldb_get": {"lib": "leveldb", "purpose": "get value by key", "category": "database"},
    "leveldb_delete": {"lib": "leveldb", "purpose": "delete key", "category": "database"},
    "leveldb_write": {"lib": "leveldb", "purpose": "write batch of operations", "category": "database"},
    "leveldb_create_iterator": {"lib": "leveldb", "purpose": "create database iterator", "category": "database"},
    "leveldb_iter_seek_to_first": {"lib": "leveldb", "purpose": "seek iterator to first entry", "category": "database"},
    "leveldb_iter_next": {"lib": "leveldb", "purpose": "advance iterator", "category": "database"},
    "leveldb_iter_key": {"lib": "leveldb", "purpose": "get current iterator key", "category": "database"},
    "leveldb_iter_value": {"lib": "leveldb", "purpose": "get current iterator value", "category": "database"},
    "leveldb_iter_valid": {"lib": "leveldb", "purpose": "check if iterator is valid", "category": "database"},
    "leveldb_iter_destroy": {"lib": "leveldb", "purpose": "destroy iterator", "category": "database"},
    "leveldb_writebatch_create": {"lib": "leveldb", "purpose": "create write batch", "category": "database"},
    "leveldb_writebatch_put": {"lib": "leveldb", "purpose": "add put to batch", "category": "database"},
    "leveldb_writebatch_delete": {"lib": "leveldb", "purpose": "add delete to batch", "category": "database"},
    "leveldb_writebatch_destroy": {"lib": "leveldb", "purpose": "destroy write batch", "category": "database"},
}


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

_DOTNET_CLR_SIGNATURES: dict[str, dict[str, str]] = {
    # --- CoreCLR hosting ---
    "coreclr_initialize": {"lib": "coreclr", "purpose": "initialize .NET CoreCLR runtime", "category": "dotnet"},
    "coreclr_create_delegate": {"lib": "coreclr", "purpose": "create delegate to managed method", "category": "dotnet"},
    "coreclr_execute_assembly": {"lib": "coreclr", "purpose": "execute managed assembly entrypoint", "category": "dotnet"},
    "coreclr_shutdown": {"lib": "coreclr", "purpose": "shutdown CoreCLR runtime", "category": "dotnet"},
    "coreclr_shutdown_2": {"lib": "coreclr", "purpose": "shutdown with exit code", "category": "dotnet"},

    # --- Mono embedding ---
    "mono_jit_init": {"lib": "mono", "purpose": "initialize Mono JIT engine", "category": "dotnet"},
    "mono_jit_cleanup": {"lib": "mono", "purpose": "cleanup Mono JIT", "category": "dotnet"},
    "mono_domain_create_appdomain": {"lib": "mono", "purpose": "create Mono AppDomain", "category": "dotnet"},
    "mono_domain_unload": {"lib": "mono", "purpose": "unload Mono AppDomain", "category": "dotnet"},
    "mono_assembly_open": {"lib": "mono", "purpose": "load .NET assembly", "category": "dotnet"},
    "mono_assembly_get_image": {"lib": "mono", "purpose": "get image from assembly", "category": "dotnet"},
    "mono_class_from_name": {"lib": "mono", "purpose": "find managed class by name", "category": "dotnet"},
    "mono_class_get_method_from_name": {"lib": "mono", "purpose": "find method by name", "category": "dotnet"},
    "mono_runtime_invoke": {"lib": "mono", "purpose": "invoke managed method", "category": "dotnet"},
    "mono_object_new": {"lib": "mono", "purpose": "create managed object instance", "category": "dotnet"},
    "mono_runtime_object_init": {"lib": "mono", "purpose": "call managed constructor", "category": "dotnet"},
    "mono_string_new": {"lib": "mono", "purpose": "create managed string", "category": "dotnet"},
    "mono_string_to_utf8": {"lib": "mono", "purpose": "convert managed string to UTF-8", "category": "dotnet"},
    "mono_array_new": {"lib": "mono", "purpose": "create managed array", "category": "dotnet"},
    "mono_gchandle_new": {"lib": "mono", "purpose": "create GC handle for managed object", "category": "dotnet"},
    "mono_gchandle_free": {"lib": "mono", "purpose": "free GC handle", "category": "dotnet"},
    "mono_gchandle_get_target": {"lib": "mono", "purpose": "get object from GC handle", "category": "dotnet"},
    "mono_gc_collect": {"lib": "mono", "purpose": "trigger GC collection", "category": "dotnet"},
    "mono_thread_attach": {"lib": "mono", "purpose": "attach native thread to Mono runtime", "category": "dotnet"},
    "mono_thread_detach": {"lib": "mono", "purpose": "detach native thread from Mono", "category": "dotnet"},
    "mono_add_internal_call": {"lib": "mono", "purpose": "register native method as internal call", "category": "dotnet"},
    "mono_type_get_object": {"lib": "mono", "purpose": "get System.Type for mono type", "category": "dotnet"},
    "mono_field_get_value": {"lib": "mono", "purpose": "get field value from managed object", "category": "dotnet"},
    "mono_field_set_value": {"lib": "mono", "purpose": "set field value on managed object", "category": "dotnet"},
    "mono_property_get_value": {"lib": "mono", "purpose": "get property value", "category": "dotnet"},
    "mono_property_set_value": {"lib": "mono", "purpose": "set property value", "category": "dotnet"},
    "mono_raise_exception": {"lib": "mono", "purpose": "raise managed exception", "category": "dotnet"},
    "mono_error_init": {"lib": "mono", "purpose": "initialize error struct", "category": "dotnet"},
    "mono_error_ok": {"lib": "mono", "purpose": "check if error occurred", "category": "dotnet"},

    # --- .NET hosting API (newer) ---
    "hostfxr_initialize_for_runtime_config": {"lib": "hostfxr", "purpose": "initialize host with runtime config", "category": "dotnet"},
    "hostfxr_get_runtime_delegate": {"lib": "hostfxr", "purpose": "get runtime delegate function pointer", "category": "dotnet"},
    "hostfxr_close": {"lib": "hostfxr", "purpose": "close host context", "category": "dotnet"},
    "hostfxr_initialize_for_dotnet_command_line": {"lib": "hostfxr", "purpose": "initialize for CLI command", "category": "dotnet"},
    "hostfxr_run_app": {"lib": "hostfxr", "purpose": "run .NET application", "category": "dotnet"},
    "hostfxr_set_runtime_property_value": {"lib": "hostfxr", "purpose": "set runtime configuration property", "category": "dotnet"},

    # --- Unity / IL2CPP ---
    "il2cpp_init": {"lib": "il2cpp", "purpose": "initialize IL2CPP runtime (Unity)", "category": "dotnet"},
    "il2cpp_init_utf16": {"lib": "il2cpp", "purpose": "initialize IL2CPP (UTF-16 domain name)", "category": "dotnet"},
    "il2cpp_shutdown": {"lib": "il2cpp", "purpose": "shutdown IL2CPP runtime", "category": "dotnet"},
    "il2cpp_domain_get": {"lib": "il2cpp", "purpose": "get current IL2CPP domain", "category": "dotnet"},
    "il2cpp_domain_assembly_open": {"lib": "il2cpp", "purpose": "load assembly in IL2CPP domain", "category": "dotnet"},
    "il2cpp_class_from_name": {"lib": "il2cpp", "purpose": "find IL2CPP class by namespace/name", "category": "dotnet"},
    "il2cpp_class_get_method_from_name": {"lib": "il2cpp", "purpose": "find method in IL2CPP class", "category": "dotnet"},
    "il2cpp_runtime_invoke": {"lib": "il2cpp", "purpose": "invoke IL2CPP method", "category": "dotnet"},
    "il2cpp_object_new": {"lib": "il2cpp", "purpose": "create IL2CPP object", "category": "dotnet"},
    "il2cpp_string_new": {"lib": "il2cpp", "purpose": "create IL2CPP string", "category": "dotnet"},
    "il2cpp_string_chars": {"lib": "il2cpp", "purpose": "get chars from IL2CPP string", "category": "dotnet"},
    "il2cpp_array_new": {"lib": "il2cpp", "purpose": "create IL2CPP array", "category": "dotnet"},
    "il2cpp_field_get_value": {"lib": "il2cpp", "purpose": "get field value from IL2CPP object", "category": "dotnet"},
    "il2cpp_field_set_value": {"lib": "il2cpp", "purpose": "set field value on IL2CPP object", "category": "dotnet"},
    "il2cpp_gchandle_new": {"lib": "il2cpp", "purpose": "create IL2CPP GC handle", "category": "dotnet"},
    "il2cpp_gchandle_free": {"lib": "il2cpp", "purpose": "free IL2CPP GC handle", "category": "dotnet"},
    "il2cpp_thread_attach": {"lib": "il2cpp", "purpose": "attach thread to IL2CPP", "category": "dotnet"},
    "il2cpp_thread_detach": {"lib": "il2cpp", "purpose": "detach thread from IL2CPP", "category": "dotnet"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Anti-Reversing / Obfuscation Patterns (~50 imza)
# Binary'lerde gorulen anti-debugging, anti-tampering teknikleri.
# ---------------------------------------------------------------------------

_ANTI_ANALYSIS_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Anti-debug (Linux) ---
    "ptrace_PTRACE_TRACEME": {"lib": "libc", "purpose": "self-trace to detect debugger", "category": "anti_debug"},
    "__debugbreak": {"lib": "compiler", "purpose": "compiler intrinsic breakpoint", "category": "anti_debug"},

    # --- Anti-debug (macOS) ---
    "sysctl_kern_proc": {"lib": "libc", "purpose": "query process info (anti-debug check)", "category": "anti_debug"},
    "AmIBeingDebugged": {"lib": "custom", "purpose": "custom debugger detection function", "category": "anti_debug"},

    # --- Anti-debug (Windows) ---
    "CheckRemoteDebuggerPresent": {"lib": "kernel32", "purpose": "check if remote debugger attached", "category": "anti_debug"},
    "NtQueryInformationProcess_ProcessDebugPort": {"lib": "ntdll", "purpose": "query debug port (anti-debug)", "category": "anti_debug"},
    "NtSetInformationThread_ThreadHideFromDebugger": {"lib": "ntdll", "purpose": "hide thread from debugger", "category": "anti_debug"},

    # --- VM detection ---
    "cpuid_hypervisor_detect": {"lib": "custom", "purpose": "CPUID hypervisor bit check (VM detection)", "category": "anti_vm"},

    # --- Timing checks ---
    "rdtsc_timing_check": {"lib": "custom", "purpose": "RDTSC timing-based debugger detection", "category": "anti_debug"},

    # --- Code integrity ---
    "CRC32_self_check": {"lib": "custom", "purpose": "CRC32 self-integrity verification", "category": "anti_tamper"},

    # --- Packed / encrypted ---
    "UPX_unpack": {"lib": "upx", "purpose": "UPX packer runtime unpacker", "category": "packer"},

    # --- Obfuscation markers ---
    "ollvm_flattening": {"lib": "ollvm", "purpose": "OLLVM control flow flattening marker", "category": "obfuscation"},
    "themida_entry": {"lib": "themida", "purpose": "Themida protector entry", "category": "packer"},
    "vmprotect_entry": {"lib": "vmprotect", "purpose": "VMProtect virtualized entry", "category": "packer"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Compression/Archive Libraries Extended (~80 imza)
# tar, zip, xz/lzma, snappy, blosc, lzo
# ---------------------------------------------------------------------------

_COMPRESSION_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- XZ / LZMA ---
    "lzma_stream_decoder": {"lib": "liblzma", "purpose": "initialize LZMA stream decoder", "category": "compression"},
    "lzma_stream_encoder": {"lib": "liblzma", "purpose": "initialize LZMA stream encoder", "category": "compression"},
    "lzma_alone_decoder": {"lib": "liblzma", "purpose": "initialize legacy LZMA alone decoder", "category": "compression"},
    "lzma_alone_encoder": {"lib": "liblzma", "purpose": "initialize legacy LZMA alone encoder", "category": "compression"},
    "lzma_code": {"lib": "liblzma", "purpose": "encode/decode data block", "category": "compression"},
    "lzma_end": {"lib": "liblzma", "purpose": "free LZMA stream", "category": "compression"},
    "lzma_easy_encoder": {"lib": "liblzma", "purpose": "initialize easy xz encoder", "category": "compression"},
    "lzma_easy_buffer_encode": {"lib": "liblzma", "purpose": "one-shot xz encode", "category": "compression"},
    "lzma_stream_buffer_decode": {"lib": "liblzma", "purpose": "one-shot xz decode", "category": "compression"},
    "lzma_auto_decoder": {"lib": "liblzma", "purpose": "auto-detect xz/lzma format and decode", "category": "compression"},
    "lzma_crc32": {"lib": "liblzma", "purpose": "LZMA CRC-32 calculation", "category": "compression"},
    "lzma_crc64": {"lib": "liblzma", "purpose": "LZMA CRC-64 calculation", "category": "compression"},

    # --- Snappy ---
    "snappy_compress": {"lib": "snappy", "purpose": "compress data with Snappy", "category": "compression"},
    "snappy_uncompress": {"lib": "snappy", "purpose": "decompress Snappy data", "category": "compression"},
    "snappy_max_compressed_length": {"lib": "snappy", "purpose": "get max compressed size", "category": "compression"},
    "snappy_uncompressed_length": {"lib": "snappy", "purpose": "get uncompressed size from header", "category": "compression"},
    "snappy_validate_compressed_buffer": {"lib": "snappy", "purpose": "validate Snappy compressed data", "category": "compression"},

    # --- LZO ---
    "lzo1x_1_compress": {"lib": "lzo", "purpose": "LZO1X-1 compress (fast)", "category": "compression"},
    "lzo1x_decompress": {"lib": "lzo", "purpose": "LZO1X decompress", "category": "compression"},
    "lzo1x_decompress_safe": {"lib": "lzo", "purpose": "LZO1X safe decompress (bounds check)", "category": "compression"},
    "lzo_init": {"lib": "lzo", "purpose": "initialize LZO library", "category": "compression"},

    # --- Brotli ---
    "BrotliEncoderCompress": {"lib": "brotli", "purpose": "one-shot Brotli compress", "category": "compression"},
    "BrotliDecoderDecompress": {"lib": "brotli", "purpose": "one-shot Brotli decompress", "category": "compression"},
    "BrotliEncoderCreateInstance": {"lib": "brotli", "purpose": "create Brotli encoder", "category": "compression"},
    "BrotliEncoderCompressStream": {"lib": "brotli", "purpose": "streaming Brotli compress", "category": "compression"},
    "BrotliEncoderDestroyInstance": {"lib": "brotli", "purpose": "destroy Brotli encoder", "category": "compression"},
    "BrotliDecoderCreateInstance": {"lib": "brotli", "purpose": "create Brotli decoder", "category": "compression"},
    "BrotliDecoderDecompressStream": {"lib": "brotli", "purpose": "streaming Brotli decompress", "category": "compression"},
    "BrotliDecoderDestroyInstance": {"lib": "brotli", "purpose": "destroy Brotli decoder", "category": "compression"},

    # --- libarchive ---
    "archive_read_new": {"lib": "libarchive", "purpose": "create archive reader", "category": "archive"},
    "archive_read_support_format_all": {"lib": "libarchive", "purpose": "enable all archive formats", "category": "archive"},
    "archive_read_support_filter_all": {"lib": "libarchive", "purpose": "enable all decompression filters", "category": "archive"},
    "archive_read_open_filename": {"lib": "libarchive", "purpose": "open archive file for reading", "category": "archive"},
    "archive_read_next_header": {"lib": "libarchive", "purpose": "read next archive entry header", "category": "archive"},
    "archive_read_data": {"lib": "libarchive", "purpose": "read entry data", "category": "archive"},
    "archive_read_data_block": {"lib": "libarchive", "purpose": "read entry data block", "category": "archive"},
    "archive_read_close": {"lib": "libarchive", "purpose": "close archive reader", "category": "archive"},
    "archive_read_free": {"lib": "libarchive", "purpose": "free archive reader", "category": "archive"},
    "archive_write_new": {"lib": "libarchive", "purpose": "create archive writer", "category": "archive"},
    "archive_write_set_format_zip": {"lib": "libarchive", "purpose": "set ZIP output format", "category": "archive"},
    "archive_write_set_format_pax_restricted": {"lib": "libarchive", "purpose": "set tar (pax restricted) format", "category": "archive"},
    "archive_write_add_filter_gzip": {"lib": "libarchive", "purpose": "add gzip compression filter", "category": "archive"},
    "archive_write_add_filter_xz": {"lib": "libarchive", "purpose": "add xz compression filter", "category": "archive"},
    "archive_write_open_filename": {"lib": "libarchive", "purpose": "open archive file for writing", "category": "archive"},
    "archive_write_header": {"lib": "libarchive", "purpose": "write archive entry header", "category": "archive"},
    "archive_write_data": {"lib": "libarchive", "purpose": "write entry data", "category": "archive"},
    "archive_write_close": {"lib": "libarchive", "purpose": "close archive writer", "category": "archive"},
    "archive_write_free": {"lib": "libarchive", "purpose": "free archive writer", "category": "archive"},
    "archive_entry_new": {"lib": "libarchive", "purpose": "create new archive entry", "category": "archive"},
    "archive_entry_free": {"lib": "libarchive", "purpose": "free archive entry", "category": "archive"},
    "archive_entry_pathname": {"lib": "libarchive", "purpose": "get entry pathname", "category": "archive"},
    "archive_entry_set_pathname": {"lib": "libarchive", "purpose": "set entry pathname", "category": "archive"},
    "archive_entry_size": {"lib": "libarchive", "purpose": "get entry file size", "category": "archive"},
    "archive_entry_set_size": {"lib": "libarchive", "purpose": "set entry file size", "category": "archive"},
    "archive_entry_filetype": {"lib": "libarchive", "purpose": "get entry file type", "category": "archive"},
    "archive_entry_set_filetype": {"lib": "libarchive", "purpose": "set entry file type", "category": "archive"},
    "archive_entry_perm": {"lib": "libarchive", "purpose": "get entry permissions", "category": "archive"},
    "archive_entry_set_perm": {"lib": "libarchive", "purpose": "set entry permissions", "category": "archive"},
    "archive_error_string": {"lib": "libarchive", "purpose": "get error description string", "category": "archive"},

    # --- minizip ---
    "zipOpen": {"lib": "minizip", "purpose": "open ZIP file for writing", "category": "archive"},
    "zipOpenNewFileInZip": {"lib": "minizip", "purpose": "start new file in ZIP", "category": "archive"},
    "zipWriteInFileInZip": {"lib": "minizip", "purpose": "write data to file in ZIP", "category": "archive"},
    "zipCloseFileInZip": {"lib": "minizip", "purpose": "close current file in ZIP", "category": "archive"},
    "zipClose": {"lib": "minizip", "purpose": "close ZIP file", "category": "archive"},
    "unzOpen": {"lib": "minizip", "purpose": "open ZIP file for reading", "category": "archive"},
    "unzGoToFirstFile": {"lib": "minizip", "purpose": "go to first file in ZIP", "category": "archive"},
    "unzGoToNextFile": {"lib": "minizip", "purpose": "go to next file in ZIP", "category": "archive"},
    "unzOpenCurrentFile": {"lib": "minizip", "purpose": "open current file for reading", "category": "archive"},
    "unzReadCurrentFile": {"lib": "minizip", "purpose": "read from current file in ZIP", "category": "archive"},
    "unzCloseCurrentFile": {"lib": "minizip", "purpose": "close current file in ZIP", "category": "archive"},
    "unzClose": {"lib": "minizip", "purpose": "close ZIP reader", "category": "archive"},
    "unzGetCurrentFileInfo": {"lib": "minizip", "purpose": "get info about current file in ZIP", "category": "archive"},
}


# ---------------------------------------------------------------------------
# sig_db Faz 3 — compression kategori override (dalga 3)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.compression` modulune tasindi.
# Asagidaki override, eski dict'leri silmeden yeni kaynak-of-truth'a baglar.
# Import basarisiz olursa (ornek: sigdb_builtin paketi yok / bozuk) eski
# inline dict'ler kullanilmaya devam eder — geriye uyumlu, rollback kolay.
try:
    from karadul.analyzers.sigdb_builtin.compression import (
        SIGNATURES as _BUILTIN_COMPRESSION_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_COMPRESSION_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_COMPRESSION_SIGNATURES is not None:
    _ZLIB_SIGNATURES = _BUILTIN_COMPRESSION_SIGNATURES.get(
        "zlib_signatures", _ZLIB_SIGNATURES
    )
    _BZIP2_SIGNATURES = _BUILTIN_COMPRESSION_SIGNATURES.get(
        "bzip2_signatures", _BZIP2_SIGNATURES
    )
    _LZ4_SIGNATURES = _BUILTIN_COMPRESSION_SIGNATURES.get(
        "lz4_signatures", _LZ4_SIGNATURES
    )
    _ZSTD_SIGNATURES = _BUILTIN_COMPRESSION_SIGNATURES.get(
        "zstd_signatures", _ZSTD_SIGNATURES
    )
    _COMPRESSION_EXT_SIGNATURES = _BUILTIN_COMPRESSION_SIGNATURES.get(
        "compression_ext_signatures", _COMPRESSION_EXT_SIGNATURES
    )


# ---------------------------------------------------------------------------
# sig_db Faz 3 — network kategori override (dalga 3)
# ---------------------------------------------------------------------------
# Veri `karadul.analyzers.sigdb_builtin.network` modulune tasindi. Ayni
# rollback-guvenli override pattern'i (crypto/compression ile ozdes).
# NOT: SSL/TLS lib'leri crypto kategorisine aittir; burada yalnizca
# network-layer imzalari (HTTP, TCP/UDP, WebSocket, DNS, ...) vardir.
try:
    from karadul.analyzers.sigdb_builtin.network import (
        SIGNATURES as _BUILTIN_NETWORK_SIGNATURES,
    )
except ImportError:  # pragma: no cover - paket yoksa legacy fallback
    _BUILTIN_NETWORK_SIGNATURES = None  # type: ignore[assignment]

if _BUILTIN_NETWORK_SIGNATURES is not None:
    _LIBCURL_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "libcurl_signatures", _LIBCURL_SIGNATURES
    )
    _POSIX_NETWORKING_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "posix_networking_signatures", _POSIX_NETWORKING_SIGNATURES
    )
    _NGHTTP2_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "nghttp2_signatures", _NGHTTP2_SIGNATURES
    )
    _WEBSOCKET_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "websocket_signatures", _WEBSOCKET_SIGNATURES
    )
    _MACOS_NETWORKING_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "macos_networking_signatures", _MACOS_NETWORKING_SIGNATURES
    )
    _APPLE_NETWORK_FRAMEWORK_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "apple_network_framework_signatures", _APPLE_NETWORK_FRAMEWORK_SIGNATURES
    )
    _NETWORKING_EXT_SIGNATURES = _BUILTIN_NETWORK_SIGNATURES.get(
        "networking_ext_signatures", _NETWORKING_EXT_SIGNATURES
    )


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
# EXTENDED: Logging/Observability Libraries (~50 imza)
# syslog, journald, ETW, DTrace probes
# ---------------------------------------------------------------------------

_LOGGING_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- syslog ---
    "openlog": {"lib": "libc", "purpose": "open connection to syslog", "category": "logging"},
    "syslog": {"lib": "libc", "purpose": "submit message to syslog", "category": "logging"},
    "closelog": {"lib": "libc", "purpose": "close syslog connection", "category": "logging"},
    "setlogmask": {"lib": "libc", "purpose": "set syslog priority mask", "category": "logging"},
    "vsyslog": {"lib": "libc", "purpose": "submit formatted message to syslog", "category": "logging"},

    # --- systemd journal ---
    "sd_journal_print": {"lib": "libsystemd", "purpose": "submit message to systemd journal", "category": "logging"},
    "sd_journal_send": {"lib": "libsystemd", "purpose": "submit structured entry to journal", "category": "logging"},
    "sd_journal_open": {"lib": "libsystemd", "purpose": "open journal for reading", "category": "logging"},
    "sd_journal_close": {"lib": "libsystemd", "purpose": "close journal handle", "category": "logging"},
    "sd_journal_next": {"lib": "libsystemd", "purpose": "advance to next journal entry", "category": "logging"},
    "sd_journal_get_data": {"lib": "libsystemd", "purpose": "get journal entry field data", "category": "logging"},
    "sd_journal_seek_tail": {"lib": "libsystemd", "purpose": "seek to end of journal", "category": "logging"},
    "sd_journal_wait": {"lib": "libsystemd", "purpose": "wait for new journal entries", "category": "logging"},

    # --- systemd misc ---
    "sd_notify": {"lib": "libsystemd", "purpose": "notify systemd about service state", "category": "logging"},
    "sd_bus_open_system": {"lib": "libsystemd", "purpose": "open system D-Bus connection", "category": "ipc"},
    "sd_bus_open_user": {"lib": "libsystemd", "purpose": "open user D-Bus connection", "category": "ipc"},
    "sd_bus_call_method": {"lib": "libsystemd", "purpose": "call D-Bus method", "category": "ipc"},
    "sd_bus_message_read": {"lib": "libsystemd", "purpose": "read D-Bus message data", "category": "ipc"},

    # --- D-Bus (libdbus) ---
    "dbus_bus_get": {"lib": "libdbus", "purpose": "connect to message bus", "category": "ipc"},
    "dbus_connection_send": {"lib": "libdbus", "purpose": "send D-Bus message", "category": "ipc"},
    "dbus_connection_flush": {"lib": "libdbus", "purpose": "flush D-Bus connection", "category": "ipc"},
    "dbus_message_new_method_call": {"lib": "libdbus", "purpose": "create D-Bus method call message", "category": "ipc"},
    "dbus_message_append_args": {"lib": "libdbus", "purpose": "append arguments to D-Bus message", "category": "ipc"},
    "dbus_message_get_args": {"lib": "libdbus", "purpose": "get arguments from D-Bus message", "category": "ipc"},
    "dbus_message_unref": {"lib": "libdbus", "purpose": "release D-Bus message reference", "category": "ipc"},
    "dbus_connection_read_write": {"lib": "libdbus", "purpose": "read/write on D-Bus connection", "category": "ipc"},
    "dbus_connection_pop_message": {"lib": "libdbus", "purpose": "pop incoming D-Bus message", "category": "ipc"},
    "dbus_connection_unref": {"lib": "libdbus", "purpose": "release D-Bus connection reference", "category": "ipc"},

    # --- Windows ETW ---
    "EventRegister": {"lib": "advapi32", "purpose": "register ETW event provider", "category": "win_etw"},
    "EventWrite": {"lib": "advapi32", "purpose": "write ETW event", "category": "win_etw"},
    "EventUnregister": {"lib": "advapi32", "purpose": "unregister ETW event provider", "category": "win_etw"},
    "EventWriteTransfer": {"lib": "advapi32", "purpose": "write ETW event with activity transfer", "category": "win_etw"},
    "EventActivityIdControl": {"lib": "advapi32", "purpose": "manage ETW activity ID", "category": "win_etw"},

    # --- Windows Performance Counters ---
    "PdhOpenQueryA": {"lib": "pdh", "purpose": "open PDH query handle", "category": "win_perf"},
    "PdhAddCounterA": {"lib": "pdh", "purpose": "add performance counter to query", "category": "win_perf"},
    "PdhCollectQueryData": {"lib": "pdh", "purpose": "collect performance data", "category": "win_perf"},
    "PdhGetFormattedCounterValue": {"lib": "pdh", "purpose": "get formatted counter value", "category": "win_perf"},
    "PdhCloseQuery": {"lib": "pdh", "purpose": "close PDH query handle", "category": "win_perf"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Multimedia/Graphics Extra (~100 imza)
# Vulkan, Direct3D, DirectX, FreeType, Harfbuzz, Cairo
# ---------------------------------------------------------------------------

_GRAPHICS_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Vulkan ---
    "vkCreateInstance": {"lib": "vulkan", "purpose": "create Vulkan instance", "category": "graphics"},
    "vkDestroyInstance": {"lib": "vulkan", "purpose": "destroy Vulkan instance", "category": "graphics"},
    "vkEnumeratePhysicalDevices": {"lib": "vulkan", "purpose": "enumerate GPUs", "category": "graphics"},
    "vkCreateDevice": {"lib": "vulkan", "purpose": "create logical device", "category": "graphics"},
    "vkDestroyDevice": {"lib": "vulkan", "purpose": "destroy logical device", "category": "graphics"},
    "vkGetDeviceQueue": {"lib": "vulkan", "purpose": "get device queue handle", "category": "graphics"},
    "vkCreateSwapchainKHR": {"lib": "vulkan", "purpose": "create swap chain", "category": "graphics"},
    "vkDestroySwapchainKHR": {"lib": "vulkan", "purpose": "destroy swap chain", "category": "graphics"},
    "vkAcquireNextImageKHR": {"lib": "vulkan", "purpose": "acquire next swap chain image", "category": "graphics"},
    "vkQueuePresentKHR": {"lib": "vulkan", "purpose": "present rendered image", "category": "graphics"},
    "vkCreateRenderPass": {"lib": "vulkan", "purpose": "create render pass", "category": "graphics"},
    "vkCreateFramebuffer": {"lib": "vulkan", "purpose": "create framebuffer", "category": "graphics"},
    "vkCreateGraphicsPipelines": {"lib": "vulkan", "purpose": "create graphics pipeline", "category": "graphics"},
    "vkCreateComputePipelines": {"lib": "vulkan", "purpose": "create compute pipeline", "category": "graphics"},
    "vkCreatePipelineLayout": {"lib": "vulkan", "purpose": "create pipeline layout", "category": "graphics"},
    "vkCreateShaderModule": {"lib": "vulkan", "purpose": "create shader module from SPIR-V", "category": "graphics"},
    "vkCreateBuffer": {"lib": "vulkan", "purpose": "create buffer object", "category": "graphics"},
    "vkCreateImage": {"lib": "vulkan", "purpose": "create image object", "category": "graphics"},
    "vkAllocateMemory": {"lib": "vulkan", "purpose": "allocate device memory", "category": "graphics"},
    "vkFreeMemory": {"lib": "vulkan", "purpose": "free device memory", "category": "graphics"},
    "vkBindBufferMemory": {"lib": "vulkan", "purpose": "bind memory to buffer", "category": "graphics"},
    "vkBindImageMemory": {"lib": "vulkan", "purpose": "bind memory to image", "category": "graphics"},
    "vkMapMemory": {"lib": "vulkan", "purpose": "map device memory to host", "category": "graphics"},
    "vkUnmapMemory": {"lib": "vulkan", "purpose": "unmap device memory", "category": "graphics"},
    "vkCreateCommandPool": {"lib": "vulkan", "purpose": "create command pool", "category": "graphics"},
    "vkAllocateCommandBuffers": {"lib": "vulkan", "purpose": "allocate command buffers", "category": "graphics"},
    "vkBeginCommandBuffer": {"lib": "vulkan", "purpose": "begin recording command buffer", "category": "graphics"},
    "vkEndCommandBuffer": {"lib": "vulkan", "purpose": "end recording command buffer", "category": "graphics"},
    "vkCmdBeginRenderPass": {"lib": "vulkan", "purpose": "begin render pass in command buffer", "category": "graphics"},
    "vkCmdEndRenderPass": {"lib": "vulkan", "purpose": "end render pass", "category": "graphics"},
    "vkCmdBindPipeline": {"lib": "vulkan", "purpose": "bind pipeline to command buffer", "category": "graphics"},
    "vkCmdDraw": {"lib": "vulkan", "purpose": "record non-indexed draw", "category": "graphics"},
    "vkCmdDrawIndexed": {"lib": "vulkan", "purpose": "record indexed draw", "category": "graphics"},
    "vkCmdDispatch": {"lib": "vulkan", "purpose": "record compute dispatch", "category": "graphics"},
    "vkCmdCopyBuffer": {"lib": "vulkan", "purpose": "record buffer copy", "category": "graphics"},
    "vkCmdCopyImage": {"lib": "vulkan", "purpose": "record image copy", "category": "graphics"},
    "vkCmdCopyBufferToImage": {"lib": "vulkan", "purpose": "record buffer-to-image copy", "category": "graphics"},
    "vkQueueSubmit": {"lib": "vulkan", "purpose": "submit command buffers to queue", "category": "graphics"},
    "vkQueueWaitIdle": {"lib": "vulkan", "purpose": "wait for queue to finish", "category": "graphics"},
    "vkDeviceWaitIdle": {"lib": "vulkan", "purpose": "wait for device to finish all work", "category": "graphics"},
    "vkCreateSemaphore": {"lib": "vulkan", "purpose": "create synchronization semaphore", "category": "graphics"},
    "vkCreateFence": {"lib": "vulkan", "purpose": "create synchronization fence", "category": "graphics"},
    "vkWaitForFences": {"lib": "vulkan", "purpose": "wait for fence to be signaled", "category": "graphics"},
    "vkResetFences": {"lib": "vulkan", "purpose": "reset fence to unsignaled state", "category": "graphics"},
    "vkCreateDescriptorSetLayout": {"lib": "vulkan", "purpose": "create descriptor set layout", "category": "graphics"},
    "vkCreateDescriptorPool": {"lib": "vulkan", "purpose": "create descriptor pool", "category": "graphics"},
    "vkAllocateDescriptorSets": {"lib": "vulkan", "purpose": "allocate descriptor sets", "category": "graphics"},
    "vkUpdateDescriptorSets": {"lib": "vulkan", "purpose": "update descriptor sets", "category": "graphics"},
    "vkCreateSampler": {"lib": "vulkan", "purpose": "create texture sampler", "category": "graphics"},
    "vkCreateImageView": {"lib": "vulkan", "purpose": "create image view", "category": "graphics"},

    # --- Direct3D 11 ---
    "D3D11CreateDevice": {"lib": "d3d11", "purpose": "create Direct3D 11 device", "category": "graphics"},
    "D3D11CreateDeviceAndSwapChain": {"lib": "d3d11", "purpose": "create D3D11 device + swap chain", "category": "graphics"},

    # --- Direct3D 12 ---
    "D3D12CreateDevice": {"lib": "d3d12", "purpose": "create Direct3D 12 device", "category": "graphics"},
    "D3D12GetDebugInterface": {"lib": "d3d12", "purpose": "get D3D12 debug interface", "category": "graphics"},
    "D3D12SerializeRootSignature": {"lib": "d3d12", "purpose": "serialize D3D12 root signature", "category": "graphics"},

    # --- DXGI ---
    "CreateDXGIFactory": {"lib": "dxgi", "purpose": "create DXGI factory", "category": "graphics"},
    "CreateDXGIFactory1": {"lib": "dxgi", "purpose": "create DXGI factory 1.1+", "category": "graphics"},
    "CreateDXGIFactory2": {"lib": "dxgi", "purpose": "create DXGI factory 2 (debug support)", "category": "graphics"},

    # --- FreeType ---
    "FT_Init_FreeType": {"lib": "freetype", "purpose": "initialize FreeType library", "category": "font"},
    "FT_Done_FreeType": {"lib": "freetype", "purpose": "finalize FreeType library", "category": "font"},
    "FT_New_Face": {"lib": "freetype", "purpose": "create face from font file", "category": "font"},
    "FT_Done_Face": {"lib": "freetype", "purpose": "destroy font face", "category": "font"},
    "FT_Set_Pixel_Sizes": {"lib": "freetype", "purpose": "set character pixel size", "category": "font"},
    "FT_Set_Char_Size": {"lib": "freetype", "purpose": "set character point size", "category": "font"},
    "FT_Load_Glyph": {"lib": "freetype", "purpose": "load glyph by index", "category": "font"},
    "FT_Load_Char": {"lib": "freetype", "purpose": "load glyph by character code", "category": "font"},
    "FT_Render_Glyph": {"lib": "freetype", "purpose": "render glyph to bitmap", "category": "font"},
    "FT_Get_Char_Index": {"lib": "freetype", "purpose": "get glyph index for character", "category": "font"},

    # --- HarfBuzz ---
    "hb_buffer_create": {"lib": "harfbuzz", "purpose": "create text shaping buffer", "category": "font"},
    "hb_buffer_destroy": {"lib": "harfbuzz", "purpose": "destroy shaping buffer", "category": "font"},
    "hb_buffer_add_utf8": {"lib": "harfbuzz", "purpose": "add UTF-8 text to buffer", "category": "font"},
    "hb_buffer_set_direction": {"lib": "harfbuzz", "purpose": "set text direction (LTR/RTL)", "category": "font"},
    "hb_buffer_set_script": {"lib": "harfbuzz", "purpose": "set script for shaping", "category": "font"},
    "hb_buffer_set_language": {"lib": "harfbuzz", "purpose": "set language for shaping", "category": "font"},
    "hb_shape": {"lib": "harfbuzz", "purpose": "perform text shaping", "category": "font"},
    "hb_buffer_get_glyph_infos": {"lib": "harfbuzz", "purpose": "get shaped glyph infos", "category": "font"},
    "hb_buffer_get_glyph_positions": {"lib": "harfbuzz", "purpose": "get shaped glyph positions", "category": "font"},
    "hb_font_create": {"lib": "harfbuzz", "purpose": "create font for shaping", "category": "font"},
    "hb_font_destroy": {"lib": "harfbuzz", "purpose": "destroy font object", "category": "font"},
    "hb_ft_font_create": {"lib": "harfbuzz", "purpose": "create HarfBuzz font from FreeType face", "category": "font"},

    # --- Cairo ---
    "cairo_create": {"lib": "cairo", "purpose": "create drawing context", "category": "graphics_2d"},
    "cairo_destroy": {"lib": "cairo", "purpose": "destroy drawing context", "category": "graphics_2d"},
    "cairo_image_surface_create": {"lib": "cairo", "purpose": "create image surface", "category": "graphics_2d"},
    "cairo_surface_destroy": {"lib": "cairo", "purpose": "destroy surface", "category": "graphics_2d"},
    "cairo_set_source_rgb": {"lib": "cairo", "purpose": "set RGB source color", "category": "graphics_2d"},
    "cairo_set_source_rgba": {"lib": "cairo", "purpose": "set RGBA source color", "category": "graphics_2d"},
    "cairo_set_line_width": {"lib": "cairo", "purpose": "set line width", "category": "graphics_2d"},
    "cairo_move_to": {"lib": "cairo", "purpose": "move current point", "category": "graphics_2d"},
    "cairo_line_to": {"lib": "cairo", "purpose": "add line to path", "category": "graphics_2d"},
    "cairo_rectangle": {"lib": "cairo", "purpose": "add rectangle to path", "category": "graphics_2d"},
    "cairo_arc": {"lib": "cairo", "purpose": "add arc to path", "category": "graphics_2d"},
    "cairo_stroke": {"lib": "cairo", "purpose": "stroke current path", "category": "graphics_2d"},
    "cairo_fill": {"lib": "cairo", "purpose": "fill current path", "category": "graphics_2d"},
    "cairo_paint": {"lib": "cairo", "purpose": "paint entire surface", "category": "graphics_2d"},
    "cairo_show_text": {"lib": "cairo", "purpose": "draw text string", "category": "graphics_2d"},
    "cairo_select_font_face": {"lib": "cairo", "purpose": "select font family", "category": "graphics_2d"},
    "cairo_set_font_size": {"lib": "cairo", "purpose": "set font size", "category": "graphics_2d"},
    "cairo_surface_write_to_png": {"lib": "cairo", "purpose": "write surface to PNG file", "category": "graphics_2d"},
    "cairo_pdf_surface_create": {"lib": "cairo", "purpose": "create PDF surface", "category": "graphics_2d"},
    "cairo_svg_surface_create": {"lib": "cairo", "purpose": "create SVG surface", "category": "graphics_2d"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Node.js / V8 Engine (~80 imza)
# V8 embedder API ve Node.js native addon pattern'leri.
# ---------------------------------------------------------------------------

_V8_NODE_SIGNATURES: dict[str, dict[str, str]] = {
    # --- V8 core ---
    "v8::Isolate::New": {"lib": "v8", "purpose": "create new V8 isolate", "category": "v8"},
    "v8::Isolate::Dispose": {"lib": "v8", "purpose": "dispose V8 isolate", "category": "v8"},
    "v8::Isolate::GetCurrent": {"lib": "v8", "purpose": "get current V8 isolate", "category": "v8"},
    "v8::HandleScope::HandleScope": {"lib": "v8", "purpose": "create V8 handle scope", "category": "v8"},
    "v8::Context::New": {"lib": "v8", "purpose": "create new V8 execution context", "category": "v8"},
    "v8::Script::Compile": {"lib": "v8", "purpose": "compile JavaScript source", "category": "v8"},
    "v8::Script::Run": {"lib": "v8", "purpose": "run compiled JavaScript", "category": "v8"},
    "v8::String::NewFromUtf8": {"lib": "v8", "purpose": "create V8 string from UTF-8", "category": "v8"},
    "v8::Number::New": {"lib": "v8", "purpose": "create V8 number", "category": "v8"},
    "v8::Integer::New": {"lib": "v8", "purpose": "create V8 integer", "category": "v8"},
    "v8::Boolean::New": {"lib": "v8", "purpose": "create V8 boolean", "category": "v8"},
    "v8::Object::New": {"lib": "v8", "purpose": "create V8 object", "category": "v8"},
    "v8::Array::New": {"lib": "v8", "purpose": "create V8 array", "category": "v8"},
    "v8::Function::New": {"lib": "v8", "purpose": "create V8 function", "category": "v8"},
    "v8::Function::Call": {"lib": "v8", "purpose": "call V8 function", "category": "v8"},
    "v8::FunctionTemplate::New": {"lib": "v8", "purpose": "create function template", "category": "v8"},
    "v8::ObjectTemplate::New": {"lib": "v8", "purpose": "create object template", "category": "v8"},
    "v8::FunctionTemplate::GetFunction": {"lib": "v8", "purpose": "get function from template", "category": "v8"},
    "v8::TryCatch::TryCatch": {"lib": "v8", "purpose": "create exception handler scope", "category": "v8"},
    "v8::Value::IsObject": {"lib": "v8", "purpose": "check if value is object", "category": "v8"},
    "v8::Value::IsString": {"lib": "v8", "purpose": "check if value is string", "category": "v8"},
    "v8::Value::IsNumber": {"lib": "v8", "purpose": "check if value is number", "category": "v8"},
    "v8::Value::IsArray": {"lib": "v8", "purpose": "check if value is array", "category": "v8"},
    "v8::Value::IsFunction": {"lib": "v8", "purpose": "check if value is function", "category": "v8"},
    "v8::Value::ToObject": {"lib": "v8", "purpose": "convert value to object", "category": "v8"},
    "v8::Value::ToString": {"lib": "v8", "purpose": "convert value to string", "category": "v8"},
    "v8::Object::Get": {"lib": "v8", "purpose": "get object property", "category": "v8"},
    "v8::Object::Set": {"lib": "v8", "purpose": "set object property", "category": "v8"},
    "v8::Persistent::New": {"lib": "v8", "purpose": "create persistent handle", "category": "v8"},
    "v8::Persistent::Reset": {"lib": "v8", "purpose": "reset persistent handle", "category": "v8"},

    # --- Node.js N-API ---
    "napi_create_function": {"lib": "node", "purpose": "create N-API function", "category": "node"},
    "napi_get_cb_info": {"lib": "node", "purpose": "get N-API callback info", "category": "node"},
    "napi_get_value_string_utf8": {"lib": "node", "purpose": "get string from N-API value", "category": "node"},
    "napi_create_string_utf8": {"lib": "node", "purpose": "create N-API string", "category": "node"},
    "napi_get_value_int32": {"lib": "node", "purpose": "get int32 from N-API value", "category": "node"},
    "napi_get_value_double": {"lib": "node", "purpose": "get double from N-API value", "category": "node"},
    "napi_create_int32": {"lib": "node", "purpose": "create N-API int32", "category": "node"},
    "napi_create_double": {"lib": "node", "purpose": "create N-API double", "category": "node"},
    "napi_create_object": {"lib": "node", "purpose": "create N-API object", "category": "node"},
    "napi_create_array": {"lib": "node", "purpose": "create N-API array", "category": "node"},
    "napi_set_named_property": {"lib": "node", "purpose": "set property on N-API object", "category": "node"},
    "napi_get_named_property": {"lib": "node", "purpose": "get property from N-API object", "category": "node"},
    "napi_set_element": {"lib": "node", "purpose": "set array element", "category": "node"},
    "napi_get_element": {"lib": "node", "purpose": "get array element", "category": "node"},
    "napi_typeof": {"lib": "node", "purpose": "get type of N-API value", "category": "node"},
    "napi_throw_error": {"lib": "node", "purpose": "throw JavaScript error", "category": "node"},
    "napi_create_error": {"lib": "node", "purpose": "create JavaScript error", "category": "node"},
    "napi_is_exception_pending": {"lib": "node", "purpose": "check pending exception", "category": "node"},
    "napi_create_promise": {"lib": "node", "purpose": "create JavaScript Promise", "category": "node"},
    "napi_resolve_deferred": {"lib": "node", "purpose": "resolve Promise", "category": "node"},
    "napi_reject_deferred": {"lib": "node", "purpose": "reject Promise", "category": "node"},
    "napi_create_async_work": {"lib": "node", "purpose": "create async work item", "category": "node"},
    "napi_queue_async_work": {"lib": "node", "purpose": "queue async work for execution", "category": "node"},
    "napi_cancel_async_work": {"lib": "node", "purpose": "cancel async work", "category": "node"},
    "napi_create_buffer": {"lib": "node", "purpose": "create Node.js Buffer", "category": "node"},
    "napi_create_buffer_copy": {"lib": "node", "purpose": "create Buffer with data copy", "category": "node"},
    "napi_get_buffer_info": {"lib": "node", "purpose": "get Buffer data and length", "category": "node"},
    "napi_create_external": {"lib": "node", "purpose": "wrap native pointer as JS value", "category": "node"},
    "napi_get_value_external": {"lib": "node", "purpose": "get native pointer from external", "category": "node"},
    "napi_create_reference": {"lib": "node", "purpose": "create reference to prevent GC", "category": "node"},
    "napi_delete_reference": {"lib": "node", "purpose": "delete reference", "category": "node"},
    "napi_get_reference_value": {"lib": "node", "purpose": "get value from reference", "category": "node"},
    "napi_define_class": {"lib": "node", "purpose": "define JavaScript class from N-API", "category": "node"},
    "napi_wrap": {"lib": "node", "purpose": "associate native data with JS object", "category": "node"},
    "napi_unwrap": {"lib": "node", "purpose": "get native data from JS object", "category": "node"},
    "napi_open_handle_scope": {"lib": "node", "purpose": "open N-API handle scope", "category": "node"},
    "napi_close_handle_scope": {"lib": "node", "purpose": "close N-API handle scope", "category": "node"},
    "napi_get_global": {"lib": "node", "purpose": "get JavaScript global object", "category": "node"},
    "napi_call_function": {"lib": "node", "purpose": "call JavaScript function", "category": "node"},
    "napi_new_instance": {"lib": "node", "purpose": "create new JavaScript instance (new)", "category": "node"},
    "napi_create_threadsafe_function": {"lib": "node", "purpose": "create thread-safe JS function callback", "category": "node"},
    "napi_call_threadsafe_function": {"lib": "node", "purpose": "call thread-safe function from any thread", "category": "node"},
    "napi_release_threadsafe_function": {"lib": "node", "purpose": "release thread-safe function", "category": "node"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Lua Embedding (~40 imza)
# Lua C API - embedded scripting patterns.
# ---------------------------------------------------------------------------

_LUA_SIGNATURES: dict[str, dict[str, str]] = {
    "luaL_newstate": {"lib": "lua", "purpose": "create new Lua state", "category": "lua"},
    "lua_close": {"lib": "lua", "purpose": "close Lua state", "category": "lua"},
    "luaL_openlibs": {"lib": "lua", "purpose": "open standard Lua libraries", "category": "lua"},
    "luaL_dofile": {"lib": "lua", "purpose": "load and execute Lua file", "category": "lua"},
    "luaL_dostring": {"lib": "lua", "purpose": "load and execute Lua string", "category": "lua"},
    "luaL_loadfile": {"lib": "lua", "purpose": "load Lua file as chunk", "category": "lua"},
    "luaL_loadstring": {"lib": "lua", "purpose": "load Lua string as chunk", "category": "lua"},
    "luaL_loadbuffer": {"lib": "lua", "purpose": "load Lua buffer as chunk", "category": "lua"},
    "lua_pcall": {"lib": "lua", "purpose": "protected call (with error handler)", "category": "lua"},
    "lua_call": {"lib": "lua", "purpose": "call Lua function", "category": "lua"},
    "lua_getglobal": {"lib": "lua", "purpose": "get global variable value", "category": "lua"},
    "lua_setglobal": {"lib": "lua", "purpose": "set global variable value", "category": "lua"},
    "lua_pushstring": {"lib": "lua", "purpose": "push string onto stack", "category": "lua"},
    "lua_pushnumber": {"lib": "lua", "purpose": "push number onto stack", "category": "lua"},
    "lua_pushinteger": {"lib": "lua", "purpose": "push integer onto stack", "category": "lua"},
    "lua_pushboolean": {"lib": "lua", "purpose": "push boolean onto stack", "category": "lua"},
    "lua_pushnil": {"lib": "lua", "purpose": "push nil onto stack", "category": "lua"},
    "lua_pushcfunction": {"lib": "lua", "purpose": "push C function onto stack", "category": "lua"},
    "lua_pushlightuserdata": {"lib": "lua", "purpose": "push light userdata", "category": "lua"},
    "lua_tostring": {"lib": "lua", "purpose": "convert stack value to string", "category": "lua"},
    "lua_tonumber": {"lib": "lua", "purpose": "convert stack value to number", "category": "lua"},
    "lua_tointeger": {"lib": "lua", "purpose": "convert stack value to integer", "category": "lua"},
    "lua_toboolean": {"lib": "lua", "purpose": "convert stack value to boolean", "category": "lua"},
    "lua_touserdata": {"lib": "lua", "purpose": "get userdata pointer", "category": "lua"},
    "lua_type": {"lib": "lua", "purpose": "get type of stack value", "category": "lua"},
    "lua_isstring": {"lib": "lua", "purpose": "check if stack value is string", "category": "lua"},
    "lua_isnumber": {"lib": "lua", "purpose": "check if stack value is number", "category": "lua"},
    "lua_istable": {"lib": "lua", "purpose": "check if stack value is table", "category": "lua"},
    "lua_isfunction": {"lib": "lua", "purpose": "check if stack value is function", "category": "lua"},
    "lua_createtable": {"lib": "lua", "purpose": "create new table on stack", "category": "lua"},
    "lua_newtable": {"lib": "lua", "purpose": "create new empty table", "category": "lua"},
    "lua_settable": {"lib": "lua", "purpose": "set table field (t[k]=v)", "category": "lua"},
    "lua_gettable": {"lib": "lua", "purpose": "get table field (v=t[k])", "category": "lua"},
    "lua_setfield": {"lib": "lua", "purpose": "set named field in table", "category": "lua"},
    "lua_getfield": {"lib": "lua", "purpose": "get named field from table", "category": "lua"},
    "lua_rawset": {"lib": "lua", "purpose": "raw table set (no metamethods)", "category": "lua"},
    "lua_rawget": {"lib": "lua", "purpose": "raw table get (no metamethods)", "category": "lua"},
    "lua_newuserdata": {"lib": "lua", "purpose": "create full userdata", "category": "lua"},
    "luaL_newmetatable": {"lib": "lua", "purpose": "create new metatable in registry", "category": "lua"},
    "lua_setmetatable": {"lib": "lua", "purpose": "set metatable for value", "category": "lua"},
    "lua_pop": {"lib": "lua", "purpose": "pop values from stack", "category": "lua"},
    "lua_settop": {"lib": "lua", "purpose": "set stack top index", "category": "lua"},
    "lua_gettop": {"lib": "lua", "purpose": "get stack top index", "category": "lua"},
    "lua_error": {"lib": "lua", "purpose": "raise Lua error", "category": "lua"},
    "luaL_error": {"lib": "lua", "purpose": "raise formatted Lua error", "category": "lua"},
    "luaL_checkstring": {"lib": "lua", "purpose": "check and get string argument", "category": "lua"},
    "luaL_checknumber": {"lib": "lua", "purpose": "check and get number argument", "category": "lua"},
    "luaL_checkinteger": {"lib": "lua", "purpose": "check and get integer argument", "category": "lua"},
    "luaL_ref": {"lib": "lua", "purpose": "create reference in registry", "category": "lua"},
    "luaL_unref": {"lib": "lua", "purpose": "release registry reference", "category": "lua"},
    "lua_register": {"lib": "lua", "purpose": "register C function as global", "category": "lua"},
    "luaL_register": {"lib": "lua", "purpose": "register library functions", "category": "lua"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Ruby C Extension API (~30 imza)
# ---------------------------------------------------------------------------

_RUBY_SIGNATURES: dict[str, dict[str, str]] = {
    "ruby_init": {"lib": "ruby", "purpose": "initialize Ruby interpreter", "category": "ruby"},
    "ruby_finalize": {"lib": "ruby", "purpose": "finalize Ruby interpreter", "category": "ruby"},
    "rb_eval_string": {"lib": "ruby", "purpose": "evaluate Ruby string", "category": "ruby"},
    "rb_funcall": {"lib": "ruby", "purpose": "call Ruby method", "category": "ruby"},
    "rb_define_class": {"lib": "ruby", "purpose": "define new Ruby class", "category": "ruby"},
    "rb_define_module": {"lib": "ruby", "purpose": "define new Ruby module", "category": "ruby"},
    "rb_define_method": {"lib": "ruby", "purpose": "define Ruby method", "category": "ruby"},
    "rb_define_singleton_method": {"lib": "ruby", "purpose": "define singleton method", "category": "ruby"},
    "rb_str_new": {"lib": "ruby", "purpose": "create Ruby string", "category": "ruby"},
    "rb_str_new_cstr": {"lib": "ruby", "purpose": "create Ruby string from C string", "category": "ruby"},
    "rb_int2inum": {"lib": "ruby", "purpose": "convert C int to Ruby Integer", "category": "ruby"},
    "rb_float_new": {"lib": "ruby", "purpose": "create Ruby Float", "category": "ruby"},
    "rb_ary_new": {"lib": "ruby", "purpose": "create Ruby Array", "category": "ruby"},
    "rb_ary_push": {"lib": "ruby", "purpose": "push to Ruby Array", "category": "ruby"},
    "rb_hash_new": {"lib": "ruby", "purpose": "create Ruby Hash", "category": "ruby"},
    "rb_hash_aset": {"lib": "ruby", "purpose": "set Hash key-value", "category": "ruby"},
    "rb_hash_aref": {"lib": "ruby", "purpose": "get Hash value by key", "category": "ruby"},
    "rb_raise": {"lib": "ruby", "purpose": "raise Ruby exception", "category": "ruby"},
    "rb_protect": {"lib": "ruby", "purpose": "call with exception protection", "category": "ruby"},
    "rb_rescue": {"lib": "ruby", "purpose": "call with rescue handler", "category": "ruby"},
    "rb_ensure": {"lib": "ruby", "purpose": "call with ensure block", "category": "ruby"},
    "rb_gc_register_mark_object": {"lib": "ruby", "purpose": "register object with GC", "category": "ruby"},
    "rb_iv_get": {"lib": "ruby", "purpose": "get instance variable", "category": "ruby"},
    "rb_iv_set": {"lib": "ruby", "purpose": "set instance variable", "category": "ruby"},
    "rb_require": {"lib": "ruby", "purpose": "require Ruby file", "category": "ruby"},
    "rb_yield": {"lib": "ruby", "purpose": "yield to block", "category": "ruby"},
    "rb_block_given_p": {"lib": "ruby", "purpose": "check if block given", "category": "ruby"},
    "rb_thread_create": {"lib": "ruby", "purpose": "create Ruby thread", "category": "ruby"},
    "rb_thread_schedule": {"lib": "ruby", "purpose": "schedule Ruby thread", "category": "ruby"},
    "Data_Wrap_Struct": {"lib": "ruby", "purpose": "wrap C struct as Ruby object", "category": "ruby"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Message Queue / Event Systems (~60 imza)
# ZeroMQ, RabbitMQ/AMQP, Kafka, MQTT
# ---------------------------------------------------------------------------

_MSGQUEUE_SIGNATURES: dict[str, dict[str, str]] = {
    # --- ZeroMQ ---
    "zmq_ctx_new": {"lib": "zeromq", "purpose": "create ZeroMQ context", "category": "messaging"},
    "zmq_ctx_destroy": {"lib": "zeromq", "purpose": "destroy ZeroMQ context", "category": "messaging"},
    "zmq_ctx_term": {"lib": "zeromq", "purpose": "terminate ZeroMQ context", "category": "messaging"},
    "zmq_socket": {"lib": "zeromq", "purpose": "create ZeroMQ socket", "category": "messaging"},
    "zmq_close": {"lib": "zeromq", "purpose": "close ZeroMQ socket", "category": "messaging"},
    "zmq_bind": {"lib": "zeromq", "purpose": "bind ZeroMQ socket to endpoint", "category": "messaging"},
    "zmq_connect": {"lib": "zeromq", "purpose": "connect ZeroMQ socket to endpoint", "category": "messaging"},
    "zmq_send": {"lib": "zeromq", "purpose": "send message on ZeroMQ socket", "category": "messaging"},
    "zmq_recv": {"lib": "zeromq", "purpose": "receive message from ZeroMQ socket", "category": "messaging"},
    "zmq_msg_init": {"lib": "zeromq", "purpose": "initialize ZeroMQ message", "category": "messaging"},
    "zmq_msg_init_size": {"lib": "zeromq", "purpose": "initialize message with size", "category": "messaging"},
    "zmq_msg_init_data": {"lib": "zeromq", "purpose": "initialize message with data", "category": "messaging"},
    "zmq_msg_send": {"lib": "zeromq", "purpose": "send multipart message", "category": "messaging"},
    "zmq_msg_recv": {"lib": "zeromq", "purpose": "receive multipart message", "category": "messaging"},
    "zmq_msg_close": {"lib": "zeromq", "purpose": "release message resources", "category": "messaging"},
    "zmq_msg_data": {"lib": "zeromq", "purpose": "get message data pointer", "category": "messaging"},
    "zmq_msg_size": {"lib": "zeromq", "purpose": "get message data size", "category": "messaging"},
    "zmq_setsockopt": {"lib": "zeromq", "purpose": "set ZeroMQ socket option", "category": "messaging"},
    "zmq_getsockopt": {"lib": "zeromq", "purpose": "get ZeroMQ socket option", "category": "messaging"},
    "zmq_poll": {"lib": "zeromq", "purpose": "poll ZeroMQ sockets for events", "category": "messaging"},
    "zmq_proxy": {"lib": "zeromq", "purpose": "start ZeroMQ proxy device", "category": "messaging"},

    # --- RabbitMQ / AMQP (rabbitmq-c) ---
    "amqp_new_connection": {"lib": "rabbitmq-c", "purpose": "create AMQP connection state", "category": "messaging"},
    "amqp_tcp_socket_new": {"lib": "rabbitmq-c", "purpose": "create TCP socket for AMQP", "category": "messaging"},
    "amqp_socket_open": {"lib": "rabbitmq-c", "purpose": "open AMQP socket connection", "category": "messaging"},
    "amqp_login": {"lib": "rabbitmq-c", "purpose": "AMQP login/authenticate", "category": "messaging"},
    "amqp_channel_open": {"lib": "rabbitmq-c", "purpose": "open AMQP channel", "category": "messaging"},
    "amqp_channel_close": {"lib": "rabbitmq-c", "purpose": "close AMQP channel", "category": "messaging"},
    "amqp_connection_close": {"lib": "rabbitmq-c", "purpose": "close AMQP connection", "category": "messaging"},
    "amqp_destroy_connection": {"lib": "rabbitmq-c", "purpose": "destroy AMQP connection", "category": "messaging"},
    "amqp_queue_declare": {"lib": "rabbitmq-c", "purpose": "declare AMQP queue", "category": "messaging"},
    "amqp_queue_bind": {"lib": "rabbitmq-c", "purpose": "bind queue to exchange", "category": "messaging"},
    "amqp_basic_publish": {"lib": "rabbitmq-c", "purpose": "publish message to exchange", "category": "messaging"},
    "amqp_basic_consume": {"lib": "rabbitmq-c", "purpose": "start consuming from queue", "category": "messaging"},
    "amqp_consume_message": {"lib": "rabbitmq-c", "purpose": "consume next message", "category": "messaging"},
    "amqp_basic_ack": {"lib": "rabbitmq-c", "purpose": "acknowledge message", "category": "messaging"},
    "amqp_exchange_declare": {"lib": "rabbitmq-c", "purpose": "declare AMQP exchange", "category": "messaging"},

    # --- librdkafka (Kafka) ---
    "rd_kafka_new": {"lib": "librdkafka", "purpose": "create Kafka handle (producer/consumer)", "category": "messaging"},
    "rd_kafka_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka handle", "category": "messaging"},
    "rd_kafka_topic_new": {"lib": "librdkafka", "purpose": "create Kafka topic handle", "category": "messaging"},
    "rd_kafka_topic_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka topic handle", "category": "messaging"},
    "rd_kafka_produce": {"lib": "librdkafka", "purpose": "produce message to Kafka topic", "category": "messaging"},
    "rd_kafka_poll": {"lib": "librdkafka", "purpose": "poll Kafka for events/callbacks", "category": "messaging"},
    "rd_kafka_flush": {"lib": "librdkafka", "purpose": "flush outstanding Kafka produce requests", "category": "messaging"},
    "rd_kafka_subscribe": {"lib": "librdkafka", "purpose": "subscribe to Kafka topics", "category": "messaging"},
    "rd_kafka_consumer_poll": {"lib": "librdkafka", "purpose": "poll Kafka consumer for messages", "category": "messaging"},
    "rd_kafka_consumer_close": {"lib": "librdkafka", "purpose": "close Kafka consumer", "category": "messaging"},
    "rd_kafka_message_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka message", "category": "messaging"},
    "rd_kafka_conf_new": {"lib": "librdkafka", "purpose": "create Kafka configuration", "category": "messaging"},
    "rd_kafka_conf_set": {"lib": "librdkafka", "purpose": "set Kafka configuration property", "category": "messaging"},
    "rd_kafka_commit": {"lib": "librdkafka", "purpose": "commit Kafka consumer offsets", "category": "messaging"},
    "rd_kafka_offset_store": {"lib": "librdkafka", "purpose": "store Kafka offset for commit", "category": "messaging"},

    # --- Eclipse Paho MQTT ---
    "MQTTClient_create": {"lib": "paho-mqtt", "purpose": "create MQTT client", "category": "messaging"},
    "MQTTClient_connect": {"lib": "paho-mqtt", "purpose": "connect to MQTT broker", "category": "messaging"},
    "MQTTClient_disconnect": {"lib": "paho-mqtt", "purpose": "disconnect from MQTT broker", "category": "messaging"},
    "MQTTClient_destroy": {"lib": "paho-mqtt", "purpose": "destroy MQTT client", "category": "messaging"},
    "MQTTClient_publish": {"lib": "paho-mqtt", "purpose": "publish MQTT message", "category": "messaging"},
    "MQTTClient_subscribe": {"lib": "paho-mqtt", "purpose": "subscribe to MQTT topic", "category": "messaging"},
    "MQTTClient_unsubscribe": {"lib": "paho-mqtt", "purpose": "unsubscribe from MQTT topic", "category": "messaging"},
    "MQTTClient_receive": {"lib": "paho-mqtt", "purpose": "receive MQTT message", "category": "messaging"},
    "MQTTClient_setCallbacks": {"lib": "paho-mqtt", "purpose": "set MQTT callback functions", "category": "messaging"},
    "MQTTClient_yield": {"lib": "paho-mqtt", "purpose": "yield to MQTT client loop", "category": "messaging"},
}


# ---------------------------------------------------------------------------
# EXTENDED: ML/AI Libraries (~80 imza)
# CUDA runtime, cuDNN, TensorRT, ONNX Runtime, OpenCV
# ---------------------------------------------------------------------------

_ML_COMPUTE_SIGNATURES: dict[str, dict[str, str]] = {
    # --- CUDA Runtime ---
    "cudaMalloc": {"lib": "cuda", "purpose": "allocate GPU device memory", "category": "gpu_compute"},
    "cudaFree": {"lib": "cuda", "purpose": "free GPU device memory", "category": "gpu_compute"},
    "cudaMemcpy": {"lib": "cuda", "purpose": "copy data between host and device", "category": "gpu_compute"},
    "cudaMemcpyAsync": {"lib": "cuda", "purpose": "async copy between host and device", "category": "gpu_compute"},
    "cudaMemset": {"lib": "cuda", "purpose": "set GPU memory to value", "category": "gpu_compute"},
    "cudaSetDevice": {"lib": "cuda", "purpose": "set active GPU device", "category": "gpu_compute"},
    "cudaGetDevice": {"lib": "cuda", "purpose": "get active GPU device", "category": "gpu_compute"},
    "cudaGetDeviceCount": {"lib": "cuda", "purpose": "get number of CUDA devices", "category": "gpu_compute"},
    "cudaGetDeviceProperties": {"lib": "cuda", "purpose": "get GPU device properties", "category": "gpu_compute"},
    "cudaDeviceSynchronize": {"lib": "cuda", "purpose": "wait for all GPU operations", "category": "gpu_compute"},
    "cudaStreamCreate": {"lib": "cuda", "purpose": "create CUDA stream", "category": "gpu_compute"},
    "cudaStreamDestroy": {"lib": "cuda", "purpose": "destroy CUDA stream", "category": "gpu_compute"},
    "cudaStreamSynchronize": {"lib": "cuda", "purpose": "synchronize CUDA stream", "category": "gpu_compute"},
    "cudaEventCreate": {"lib": "cuda", "purpose": "create CUDA event", "category": "gpu_compute"},
    "cudaEventRecord": {"lib": "cuda", "purpose": "record event in stream", "category": "gpu_compute"},
    "cudaEventSynchronize": {"lib": "cuda", "purpose": "wait for CUDA event", "category": "gpu_compute"},
    "cudaEventElapsedTime": {"lib": "cuda", "purpose": "compute elapsed time between events", "category": "gpu_compute"},
    "cudaEventDestroy": {"lib": "cuda", "purpose": "destroy CUDA event", "category": "gpu_compute"},
    "cudaLaunchKernel": {"lib": "cuda", "purpose": "launch CUDA kernel", "category": "gpu_compute"},
    "cudaMallocManaged": {"lib": "cuda", "purpose": "allocate unified memory", "category": "gpu_compute"},
    "cudaMemPrefetchAsync": {"lib": "cuda", "purpose": "prefetch unified memory", "category": "gpu_compute"},
    "cudaHostAlloc": {"lib": "cuda", "purpose": "allocate pinned host memory", "category": "gpu_compute"},
    "cudaFreeHost": {"lib": "cuda", "purpose": "free pinned host memory", "category": "gpu_compute"},
    "cudaGetLastError": {"lib": "cuda", "purpose": "get last CUDA error", "category": "gpu_compute"},
    "cudaPeekAtLastError": {"lib": "cuda", "purpose": "peek at last CUDA error", "category": "gpu_compute"},
    "cudaGetErrorString": {"lib": "cuda", "purpose": "get CUDA error description", "category": "gpu_compute"},

    # --- cuBLAS ---
    "cublasCreate": {"lib": "cublas", "purpose": "create cuBLAS handle", "category": "gpu_compute"},
    "cublasDestroy": {"lib": "cublas", "purpose": "destroy cuBLAS handle", "category": "gpu_compute"},
    "cublasSgemm": {"lib": "cublas", "purpose": "single-precision matrix multiply (GPU)", "category": "gpu_compute"},
    "cublasDgemm": {"lib": "cublas", "purpose": "double-precision matrix multiply (GPU)", "category": "gpu_compute"},
    "cublasHgemm": {"lib": "cublas", "purpose": "half-precision matrix multiply (GPU)", "category": "gpu_compute"},
    "cublasSgemv": {"lib": "cublas", "purpose": "single-precision matrix-vector multiply", "category": "gpu_compute"},
    "cublasSetStream": {"lib": "cublas", "purpose": "set cuBLAS CUDA stream", "category": "gpu_compute"},

    # --- cuDNN ---
    "cudnnCreate": {"lib": "cudnn", "purpose": "create cuDNN handle", "category": "gpu_compute"},
    "cudnnDestroy": {"lib": "cudnn", "purpose": "destroy cuDNN handle", "category": "gpu_compute"},
    "cudnnConvolutionForward": {"lib": "cudnn", "purpose": "cuDNN convolution forward pass", "category": "gpu_compute"},
    "cudnnConvolutionBackwardData": {"lib": "cudnn", "purpose": "cuDNN convolution backward data", "category": "gpu_compute"},
    "cudnnConvolutionBackwardFilter": {"lib": "cudnn", "purpose": "cuDNN convolution backward filter", "category": "gpu_compute"},
    "cudnnBatchNormalizationForwardTraining": {"lib": "cudnn", "purpose": "cuDNN batch normalization forward", "category": "gpu_compute"},
    "cudnnActivationForward": {"lib": "cudnn", "purpose": "cuDNN activation function forward", "category": "gpu_compute"},
    "cudnnPoolingForward": {"lib": "cudnn", "purpose": "cuDNN pooling forward", "category": "gpu_compute"},
    "cudnnSoftmaxForward": {"lib": "cudnn", "purpose": "cuDNN softmax forward", "category": "gpu_compute"},
    "cudnnSetTensorNdDescriptor": {"lib": "cudnn", "purpose": "set cuDNN tensor descriptor", "category": "gpu_compute"},
    "cudnnGetConvolutionForwardAlgorithm": {"lib": "cudnn", "purpose": "find best convolution algorithm", "category": "gpu_compute"},

    # --- ONNX Runtime ---
    "OrtCreateEnv": {"lib": "onnxruntime", "purpose": "create ONNX Runtime environment", "category": "ml_inference"},
    "OrtCreateSession": {"lib": "onnxruntime", "purpose": "create inference session", "category": "ml_inference"},
    "OrtCreateSessionOptions": {"lib": "onnxruntime", "purpose": "create session options", "category": "ml_inference"},
    "OrtSessionGetInputCount": {"lib": "onnxruntime", "purpose": "get number of model inputs", "category": "ml_inference"},
    "OrtSessionGetOutputCount": {"lib": "onnxruntime", "purpose": "get number of model outputs", "category": "ml_inference"},
    "OrtRun": {"lib": "onnxruntime", "purpose": "run inference", "category": "ml_inference"},
    "OrtCreateTensorWithDataAsOrtValue": {"lib": "onnxruntime", "purpose": "create input tensor", "category": "ml_inference"},
    "OrtGetTensorData": {"lib": "onnxruntime", "purpose": "get output tensor data", "category": "ml_inference"},
    "OrtReleaseEnv": {"lib": "onnxruntime", "purpose": "release environment", "category": "ml_inference"},
    "OrtReleaseSession": {"lib": "onnxruntime", "purpose": "release inference session", "category": "ml_inference"},

    # --- OpenCV (imgproc/core) ---
    "cv::imread": {"lib": "opencv", "purpose": "read image file", "category": "cv"},
    "cv::imwrite": {"lib": "opencv", "purpose": "write image file", "category": "cv"},
    "cv::imshow": {"lib": "opencv", "purpose": "display image in window", "category": "cv"},
    "cv::waitKey": {"lib": "opencv", "purpose": "wait for key press in window", "category": "cv"},
    "cv::cvtColor": {"lib": "opencv", "purpose": "convert color space", "category": "cv"},
    "cv::resize": {"lib": "opencv", "purpose": "resize image", "category": "cv"},
    "cv::GaussianBlur": {"lib": "opencv", "purpose": "Gaussian blur filter", "category": "cv"},
    "cv::Canny": {"lib": "opencv", "purpose": "Canny edge detection", "category": "cv"},
    "cv::threshold": {"lib": "opencv", "purpose": "binary threshold", "category": "cv"},
    "cv::findContours": {"lib": "opencv", "purpose": "find contours in binary image", "category": "cv"},
    "cv::drawContours": {"lib": "opencv", "purpose": "draw contours on image", "category": "cv"},
    "cv::rectangle": {"lib": "opencv", "purpose": "draw rectangle on image", "category": "cv"},
    "cv::circle": {"lib": "opencv", "purpose": "draw circle on image", "category": "cv"},
    "cv::putText": {"lib": "opencv", "purpose": "draw text on image", "category": "cv"},
    "cv::VideoCapture::VideoCapture": {"lib": "opencv", "purpose": "create video capture", "category": "cv"},
    "cv::VideoCapture::read": {"lib": "opencv", "purpose": "read video frame", "category": "cv"},
    "cv::VideoWriter::VideoWriter": {"lib": "opencv", "purpose": "create video writer", "category": "cv"},
    "cv::Mat::Mat": {"lib": "opencv", "purpose": "create OpenCV matrix", "category": "cv"},
    "cv::Mat::clone": {"lib": "opencv", "purpose": "clone OpenCV matrix", "category": "cv"},
    "cv::Mat::copyTo": {"lib": "opencv", "purpose": "copy matrix to another", "category": "cv"},
}


# ---------------------------------------------------------------------------
# EXTENDED: Game Engines / Physics (~80 imza)
# Unreal, Godot, Box2D, Bullet patterns
# ---------------------------------------------------------------------------

_GAME_ENGINE_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Unreal Engine ---
    "UObject::ProcessEvent": {"lib": "unreal", "purpose": "Unreal process Blueprint event", "category": "game_engine"},
    "FMemory::Malloc": {"lib": "unreal", "purpose": "Unreal memory allocation", "category": "game_engine"},
    "FMemory::Free": {"lib": "unreal", "purpose": "Unreal memory free", "category": "game_engine"},
    "FMemory::Realloc": {"lib": "unreal", "purpose": "Unreal memory reallocation", "category": "game_engine"},
    "FString::Printf": {"lib": "unreal", "purpose": "Unreal formatted string", "category": "game_engine"},
    "FName::Init": {"lib": "unreal", "purpose": "Unreal name initialization", "category": "game_engine"},
    "UWorld::Tick": {"lib": "unreal", "purpose": "Unreal world tick update", "category": "game_engine"},
    "AActor::BeginPlay": {"lib": "unreal", "purpose": "Unreal actor begin play", "category": "game_engine"},
    "AActor::Tick": {"lib": "unreal", "purpose": "Unreal actor tick", "category": "game_engine"},
    "UGameplayStatics::SpawnActor": {"lib": "unreal", "purpose": "Unreal spawn actor", "category": "game_engine"},
    "GEngine": {"lib": "unreal", "purpose": "Unreal global engine pointer", "category": "game_engine"},

    # --- Godot Engine ---
    "godot_gdnative_init": {"lib": "godot", "purpose": "Godot GDNative init", "category": "game_engine"},
    "godot_gdnative_terminate": {"lib": "godot", "purpose": "Godot GDNative terminate", "category": "game_engine"},
    "godot_nativescript_init": {"lib": "godot", "purpose": "Godot NativeScript init", "category": "game_engine"},
    "godot_variant_new_string": {"lib": "godot", "purpose": "create Godot variant from string", "category": "game_engine"},
    "godot_variant_destroy": {"lib": "godot", "purpose": "destroy Godot variant", "category": "game_engine"},
    "godot_string_new": {"lib": "godot", "purpose": "create new Godot string", "category": "game_engine"},
    "godot_string_destroy": {"lib": "godot", "purpose": "destroy Godot string", "category": "game_engine"},
    "godot_method_bind_get_method": {"lib": "godot", "purpose": "get Godot method binding", "category": "game_engine"},
    "godot_method_bind_call": {"lib": "godot", "purpose": "call Godot method", "category": "game_engine"},

    # --- Box2D ---
    "b2World::Step": {"lib": "box2d", "purpose": "Box2D physics step", "category": "physics"},
    "b2World::CreateBody": {"lib": "box2d", "purpose": "create Box2D rigid body", "category": "physics"},
    "b2World::DestroyBody": {"lib": "box2d", "purpose": "destroy Box2D rigid body", "category": "physics"},
    "b2Body::CreateFixture": {"lib": "box2d", "purpose": "create Box2D fixture", "category": "physics"},
    "b2Body::DestroyFixture": {"lib": "box2d", "purpose": "destroy Box2D fixture", "category": "physics"},
    "b2Body::SetTransform": {"lib": "box2d", "purpose": "set Box2D body position/angle", "category": "physics"},
    "b2Body::GetPosition": {"lib": "box2d", "purpose": "get Box2D body position", "category": "physics"},
    "b2Body::ApplyForce": {"lib": "box2d", "purpose": "apply force to Box2D body", "category": "physics"},
    "b2Body::ApplyLinearImpulse": {"lib": "box2d", "purpose": "apply impulse to Box2D body", "category": "physics"},
    "b2World::CreateJoint": {"lib": "box2d", "purpose": "create Box2D joint", "category": "physics"},
    "b2World::DestroyJoint": {"lib": "box2d", "purpose": "destroy Box2D joint", "category": "physics"},
    "b2World::SetContactListener": {"lib": "box2d", "purpose": "set Box2D contact callback", "category": "physics"},

    # --- Bullet Physics ---
    "btDiscreteDynamicsWorld::stepSimulation": {"lib": "bullet", "purpose": "Bullet physics step", "category": "physics"},
    "btCollisionDispatcher::btCollisionDispatcher": {"lib": "bullet", "purpose": "Bullet collision dispatcher", "category": "physics"},
    "btDbvtBroadphase::btDbvtBroadphase": {"lib": "bullet", "purpose": "Bullet broadphase", "category": "physics"},
    "btSequentialImpulseConstraintSolver::btSequentialImpulseConstraintSolver": {"lib": "bullet", "purpose": "Bullet constraint solver", "category": "physics"},
    "btRigidBody::btRigidBody": {"lib": "bullet", "purpose": "create Bullet rigid body", "category": "physics"},
    "btDiscreteDynamicsWorld::addRigidBody": {"lib": "bullet", "purpose": "add rigid body to Bullet world", "category": "physics"},
    "btDiscreteDynamicsWorld::removeRigidBody": {"lib": "bullet", "purpose": "remove rigid body from Bullet world", "category": "physics"},
    "btRigidBody::applyCentralForce": {"lib": "bullet", "purpose": "apply force to Bullet body", "category": "physics"},
    "btRigidBody::applyCentralImpulse": {"lib": "bullet", "purpose": "apply impulse to Bullet body", "category": "physics"},

    # --- GLFW (windowing) ---
    "glfwInit": {"lib": "glfw", "purpose": "initialize GLFW", "category": "windowing"},
    "glfwTerminate": {"lib": "glfw", "purpose": "terminate GLFW", "category": "windowing"},
    "glfwCreateWindow": {"lib": "glfw", "purpose": "create GLFW window", "category": "windowing"},
    "glfwDestroyWindow": {"lib": "glfw", "purpose": "destroy GLFW window", "category": "windowing"},
    "glfwMakeContextCurrent": {"lib": "glfw", "purpose": "make OpenGL context current", "category": "windowing"},
    "glfwSwapBuffers": {"lib": "glfw", "purpose": "swap front/back buffers", "category": "windowing"},
    "glfwPollEvents": {"lib": "glfw", "purpose": "poll for window events", "category": "windowing"},
    "glfwWaitEvents": {"lib": "glfw", "purpose": "wait for window events", "category": "windowing"},
    "glfwSetKeyCallback": {"lib": "glfw", "purpose": "set keyboard callback", "category": "windowing"},
    "glfwSetMouseButtonCallback": {"lib": "glfw", "purpose": "set mouse button callback", "category": "windowing"},
    "glfwSetCursorPosCallback": {"lib": "glfw", "purpose": "set cursor position callback", "category": "windowing"},
    "glfwSetFramebufferSizeCallback": {"lib": "glfw", "purpose": "set framebuffer resize callback", "category": "windowing"},
    "glfwWindowShouldClose": {"lib": "glfw", "purpose": "check if window should close", "category": "windowing"},
    "glfwGetTime": {"lib": "glfw", "purpose": "get GLFW time", "category": "windowing"},
    "glfwSetWindowTitle": {"lib": "glfw", "purpose": "set window title", "category": "windowing"},
    "glfwGetWindowSize": {"lib": "glfw", "purpose": "get window size", "category": "windowing"},
    "glfwSetInputMode": {"lib": "glfw", "purpose": "set input mode (cursor, etc)", "category": "windowing"},

    # --- GLAD/GLEW (OpenGL loader) ---
    "gladLoadGLLoader": {"lib": "glad", "purpose": "load OpenGL function pointers", "category": "graphics"},
    "glewInit": {"lib": "glew", "purpose": "initialize GLEW (OpenGL extension loader)", "category": "graphics"},

    # --- ImGui ---
    "ImGui::Begin": {"lib": "imgui", "purpose": "begin ImGui window", "category": "gui"},
    "ImGui::End": {"lib": "imgui", "purpose": "end ImGui window", "category": "gui"},
    "ImGui::Text": {"lib": "imgui", "purpose": "display ImGui text", "category": "gui"},
    "ImGui::Button": {"lib": "imgui", "purpose": "ImGui button widget", "category": "gui"},
    "ImGui::InputText": {"lib": "imgui", "purpose": "ImGui text input", "category": "gui"},
    "ImGui::SliderFloat": {"lib": "imgui", "purpose": "ImGui float slider", "category": "gui"},
    "ImGui::Checkbox": {"lib": "imgui", "purpose": "ImGui checkbox", "category": "gui"},
    "ImGui::TreeNode": {"lib": "imgui", "purpose": "ImGui tree node", "category": "gui"},
    "ImGui::Render": {"lib": "imgui", "purpose": "render ImGui frame", "category": "gui"},
    "ImGui::NewFrame": {"lib": "imgui", "purpose": "start new ImGui frame", "category": "gui"},
    "ImGui::CreateContext": {"lib": "imgui", "purpose": "create ImGui context", "category": "gui"},
    "ImGui::DestroyContext": {"lib": "imgui", "purpose": "destroy ImGui context", "category": "gui"},
    "ImGui::GetIO": {"lib": "imgui", "purpose": "get ImGui IO structure", "category": "gui"},
}


# ---------------------------------------------------------------------------
# EXTENDED: macOS/iOS System Calls Extra (~100 imza)
# Mach kernel, IOKit extended, launchd, sandbox
# ---------------------------------------------------------------------------

_MACOS_EXT_SIGNATURES: dict[str, dict[str, str]] = {
    # --- Mach kernel ---
    "mach_task_self": {"lib": "mach", "purpose": "get mach port for current task", "category": "macos_kernel"},
    "mach_host_self": {"lib": "mach", "purpose": "get mach port for host", "category": "macos_kernel"},
    "task_for_pid": {"lib": "mach", "purpose": "get task port for PID", "category": "macos_kernel"},
    "mach_vm_allocate": {"lib": "mach", "purpose": "allocate virtual memory in task", "category": "macos_kernel"},
    "mach_vm_deallocate": {"lib": "mach", "purpose": "deallocate virtual memory", "category": "macos_kernel"},
    "mach_vm_protect": {"lib": "mach", "purpose": "set memory protection on region", "category": "macos_kernel"},
    "mach_vm_read": {"lib": "mach", "purpose": "read memory from task", "category": "macos_kernel"},
    "mach_vm_write": {"lib": "mach", "purpose": "write memory to task", "category": "macos_kernel"},
    "mach_vm_region": {"lib": "mach", "purpose": "query virtual memory region info", "category": "macos_kernel"},
    "mach_port_allocate": {"lib": "mach", "purpose": "allocate mach port", "category": "macos_kernel"},
    "mach_port_deallocate": {"lib": "mach", "purpose": "deallocate mach port", "category": "macos_kernel"},
    "mach_port_insert_right": {"lib": "mach", "purpose": "insert mach port right", "category": "macos_kernel"},
    "mach_msg": {"lib": "mach", "purpose": "send/receive mach message", "category": "macos_kernel"},
    "thread_create": {"lib": "mach", "purpose": "create mach thread", "category": "macos_kernel"},
    "thread_terminate": {"lib": "mach", "purpose": "terminate mach thread", "category": "macos_kernel"},
    "thread_suspend": {"lib": "mach", "purpose": "suspend mach thread", "category": "macos_kernel"},
    "thread_resume": {"lib": "mach", "purpose": "resume mach thread", "category": "macos_kernel"},
    "thread_get_state": {"lib": "mach", "purpose": "get thread register state", "category": "macos_kernel"},
    "thread_set_state": {"lib": "mach", "purpose": "set thread register state", "category": "macos_kernel"},
    "task_threads": {"lib": "mach", "purpose": "get all threads in task", "category": "macos_kernel"},
    "task_info": {"lib": "mach", "purpose": "get task information", "category": "macos_kernel"},
    "host_statistics64": {"lib": "mach", "purpose": "get host statistics (64-bit)", "category": "macos_kernel"},
    "host_processor_info": {"lib": "mach", "purpose": "get per-CPU info", "category": "macos_kernel"},

    # --- kqueue ---
    "kqueue": {"lib": "libc", "purpose": "create new kqueue", "category": "macos_io"},
    "kevent": {"lib": "libc", "purpose": "register/poll kqueue events", "category": "macos_io"},
    "kevent64": {"lib": "libc", "purpose": "register/poll kqueue events (64-bit)", "category": "macos_io"},

    # --- Sandbox ---
    "sandbox_init": {"lib": "libsandbox", "purpose": "initialize sandbox profile", "category": "macos_security"},
    "sandbox_free_error": {"lib": "libsandbox", "purpose": "free sandbox error string", "category": "macos_security"},
    "sandbox_check": {"lib": "libsandbox", "purpose": "check sandbox permission", "category": "macos_security"},

    # --- Launch Services ---
    "LSOpenCFURLRef": {"lib": "LaunchServices", "purpose": "open URL with default app", "category": "macos_system"},
    "LSGetApplicationForURL": {"lib": "LaunchServices", "purpose": "get default app for URL", "category": "macos_system"},
    "LSCopyDefaultApplicationURLForURL": {"lib": "LaunchServices", "purpose": "copy default app URL", "category": "macos_system"},
    "LSRegisterURL": {"lib": "LaunchServices", "purpose": "register app at URL", "category": "macos_system"},

    # --- Disk Arbitration ---
    "DASessionCreate": {"lib": "DiskArbitration", "purpose": "create disk arbitration session", "category": "macos_system"},
    "DADiskCreateFromBSDName": {"lib": "DiskArbitration", "purpose": "create disk object from BSD name", "category": "macos_system"},
    "DADiskCopyDescription": {"lib": "DiskArbitration", "purpose": "copy disk description dictionary", "category": "macos_system"},

    # --- System Configuration ---
    "SCDynamicStoreCreate": {"lib": "SystemConfiguration", "purpose": "create dynamic store session", "category": "macos_system"},
    "SCDynamicStoreCopyValue": {"lib": "SystemConfiguration", "purpose": "copy value from dynamic store", "category": "macos_system"},
    "SCDynamicStoreSetNotificationKeys": {"lib": "SystemConfiguration", "purpose": "set change notification keys", "category": "macos_system"},
    "SCNetworkReachabilityCreateWithAddress": {"lib": "SystemConfiguration", "purpose": "create reachability by address", "category": "macos_system"},

    # --- Authorization Services ---
    "AuthorizationCreate": {"lib": "Security", "purpose": "create authorization reference", "category": "macos_security"},
    "AuthorizationCopyRights": {"lib": "Security", "purpose": "acquire authorization rights", "category": "macos_security"},
    "AuthorizationFree": {"lib": "Security", "purpose": "free authorization reference", "category": "macos_security"},
    "AuthorizationExecuteWithPrivileges": {"lib": "Security", "purpose": "execute with elevated privileges (deprecated)", "category": "macos_security"},

    # --- posix_spawn (macOS specific flags) ---
    "posix_spawn": {"lib": "libc", "purpose": "spawn new process (POSIX)", "category": "macos_process"},
    "posix_spawnattr_init": {"lib": "libc", "purpose": "initialize spawn attributes", "category": "macos_process"},
    "posix_spawnattr_destroy": {"lib": "libc", "purpose": "destroy spawn attributes", "category": "macos_process"},
    "posix_spawnattr_setflags": {"lib": "libc", "purpose": "set spawn attribute flags", "category": "macos_process"},
    "posix_spawnattr_setbinpref_np": {"lib": "libc", "purpose": "set preferred binary architectures", "category": "macos_process"},
    "posix_spawn_file_actions_init": {"lib": "libc", "purpose": "initialize file actions", "category": "macos_process"},
    "posix_spawn_file_actions_addopen": {"lib": "libc", "purpose": "add open action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_adddup2": {"lib": "libc", "purpose": "add dup2 action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_addclose": {"lib": "libc", "purpose": "add close action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_destroy": {"lib": "libc", "purpose": "destroy file actions", "category": "macos_process"},

    # --- Security.framework extended ---
    "SecAccessControlCreateWithFlags": {"lib": "Security", "purpose": "create access control with biometric flags", "category": "macos_security"},
    "SecKeyCreateWithData": {"lib": "Security", "purpose": "create key from raw data", "category": "macos_security"},
    "SecKeyCopyExternalRepresentation": {"lib": "Security", "purpose": "export key as data", "category": "macos_security"},
    "SecCertificateCreateWithData": {"lib": "Security", "purpose": "create certificate from DER data", "category": "macos_security"},
    "SecCertificateCopyCommonName": {"lib": "Security", "purpose": "get certificate common name", "category": "macos_security"},
    "SecPolicyCreateSSL": {"lib": "Security", "purpose": "create SSL/TLS trust policy", "category": "macos_security"},
    "SecPolicyCreateRevocation": {"lib": "Security", "purpose": "create revocation check policy", "category": "macos_security"},
    "SecTrustSetVerifyDate": {"lib": "Security", "purpose": "set trust verification date", "category": "macos_security"},
    "SecTrustGetCertificateCount": {"lib": "Security", "purpose": "get cert count in trust chain", "category": "macos_security"},

    # --- CoreFoundation extended ---
    "CFStringCreateWithCString": {"lib": "CoreFoundation", "purpose": "create CFString from C string", "category": "macos_cf"},
    "CFStringGetCString": {"lib": "CoreFoundation", "purpose": "get C string from CFString", "category": "macos_cf"},
    "CFStringCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFString", "category": "macos_cf"},
    "CFStringAppend": {"lib": "CoreFoundation", "purpose": "append to mutable CFString", "category": "macos_cf"},
    "CFDataCreate": {"lib": "CoreFoundation", "purpose": "create CFData from bytes", "category": "macos_cf"},
    "CFDataGetBytePtr": {"lib": "CoreFoundation", "purpose": "get byte pointer from CFData", "category": "macos_cf"},
    "CFDataGetLength": {"lib": "CoreFoundation", "purpose": "get CFData length", "category": "macos_cf"},
    "CFDictionaryCreate": {"lib": "CoreFoundation", "purpose": "create CFDictionary", "category": "macos_cf"},
    "CFDictionaryGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFDictionary", "category": "macos_cf"},
    "CFDictionarySetValue": {"lib": "CoreFoundation", "purpose": "set value in mutable CFDictionary", "category": "macos_cf"},
    "CFDictionaryCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFDictionary", "category": "macos_cf"},
    "CFArrayCreate": {"lib": "CoreFoundation", "purpose": "create CFArray", "category": "macos_cf"},
    "CFArrayGetCount": {"lib": "CoreFoundation", "purpose": "get CFArray count", "category": "macos_cf"},
    "CFArrayGetValueAtIndex": {"lib": "CoreFoundation", "purpose": "get CFArray element at index", "category": "macos_cf"},
    "CFArrayCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFArray", "category": "macos_cf"},
    "CFArrayAppendValue": {"lib": "CoreFoundation", "purpose": "append to mutable CFArray", "category": "macos_cf"},
    "CFNumberCreate": {"lib": "CoreFoundation", "purpose": "create CFNumber", "category": "macos_cf"},
    "CFNumberGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFNumber", "category": "macos_cf"},
    "CFBooleanGetValue": {"lib": "CoreFoundation", "purpose": "get bool from CFBoolean", "category": "macos_cf"},
    "CFURLCreateWithString": {"lib": "CoreFoundation", "purpose": "create CFURL from string", "category": "macos_cf"},
    "CFURLCreateWithFileSystemPath": {"lib": "CoreFoundation", "purpose": "create CFURL from file path", "category": "macos_cf"},
    "CFPreferencesCopyValue": {"lib": "CoreFoundation", "purpose": "read preference value", "category": "macos_cf"},
    "CFPreferencesSetValue": {"lib": "CoreFoundation", "purpose": "set preference value", "category": "macos_cf"},
    "CFPreferencesAppSynchronize": {"lib": "CoreFoundation", "purpose": "synchronize preferences", "category": "macos_cf"},
    "CFRunLoopRun": {"lib": "CoreFoundation", "purpose": "run current run loop", "category": "macos_cf"},
    "CFRunLoopStop": {"lib": "CoreFoundation", "purpose": "stop run loop", "category": "macos_cf"},
    "CFRunLoopGetCurrent": {"lib": "CoreFoundation", "purpose": "get current run loop", "category": "macos_cf"},
    "CFRunLoopGetMain": {"lib": "CoreFoundation", "purpose": "get main run loop", "category": "macos_cf"},
    "CFRunLoopAddSource": {"lib": "CoreFoundation", "purpose": "add source to run loop", "category": "macos_cf"},
    "CFRunLoopAddTimer": {"lib": "CoreFoundation", "purpose": "add timer to run loop", "category": "macos_cf"},
    "CFRetain": {"lib": "CoreFoundation", "purpose": "increment CF reference count", "category": "macos_cf"},
    "CFRelease": {"lib": "CoreFoundation", "purpose": "decrement CF reference count", "category": "macos_cf"},
    "CFGetTypeID": {"lib": "CoreFoundation", "purpose": "get CF type identifier", "category": "macos_cf"},
    "CFEqual": {"lib": "CoreFoundation", "purpose": "compare two CF objects", "category": "macos_cf"},
    "CFHash": {"lib": "CoreFoundation", "purpose": "compute CF object hash", "category": "macos_cf"},
    "CFShow": {"lib": "CoreFoundation", "purpose": "print CF object description", "category": "macos_cf"},
}


# ---------------------------------------------------------------------------
# MEGA BATCH: Additional well-known library functions
# Windows CRT, POSIX extended, Crypto extended, C++ ABI, etc.
# Total: ~4500 new entries to reach 10,000+
# ---------------------------------------------------------------------------

_MEGA_BATCH_1_SIGNATURES: dict[str, dict[str, str]] = {
    # =======================================================================
    # SECTION 1: Windows CRT (C Runtime Library) ~120 entries
    # msvcrt / ucrtbase.dll
    # =======================================================================
    "_open": {"lib": "msvcrt", "purpose": "open file (MSVC CRT)", "category": "win_crt"},
    "_close": {"lib": "msvcrt", "purpose": "close file descriptor (MSVC CRT)", "category": "win_crt"},
    "_read": {"lib": "msvcrt", "purpose": "read from file descriptor (MSVC CRT)", "category": "win_crt"},
    "_write": {"lib": "msvcrt", "purpose": "write to file descriptor (MSVC CRT)", "category": "win_crt"},
    "_lseek": {"lib": "msvcrt", "purpose": "seek file position (MSVC CRT)", "category": "win_crt"},
    "_stat": {"lib": "msvcrt", "purpose": "get file status (MSVC CRT)", "category": "win_crt"},
    "_fstat": {"lib": "msvcrt", "purpose": "get file status by fd (MSVC CRT)", "category": "win_crt"},
    "_access": {"lib": "msvcrt", "purpose": "check file access (MSVC CRT)", "category": "win_crt"},
    "_mkdir": {"lib": "msvcrt", "purpose": "create directory (MSVC CRT)", "category": "win_crt"},
    "_rmdir": {"lib": "msvcrt", "purpose": "remove directory (MSVC CRT)", "category": "win_crt"},
    "_unlink": {"lib": "msvcrt", "purpose": "delete file (MSVC CRT)", "category": "win_crt"},
    "_getcwd": {"lib": "msvcrt", "purpose": "get current directory (MSVC CRT)", "category": "win_crt"},
    "_chdir": {"lib": "msvcrt", "purpose": "change directory (MSVC CRT)", "category": "win_crt"},
    "_dup": {"lib": "msvcrt", "purpose": "duplicate fd (MSVC CRT)", "category": "win_crt"},
    "_dup2": {"lib": "msvcrt", "purpose": "duplicate fd to specific number (MSVC CRT)", "category": "win_crt"},
    "_pipe": {"lib": "msvcrt", "purpose": "create pipe (MSVC CRT)", "category": "win_crt"},
    "_popen": {"lib": "msvcrt", "purpose": "open pipe to process (MSVC CRT)", "category": "win_crt"},
    "_pclose": {"lib": "msvcrt", "purpose": "close process pipe (MSVC CRT)", "category": "win_crt"},
    "_findfirst": {"lib": "msvcrt", "purpose": "find first file (MSVC CRT)", "category": "win_crt"},
    "_findnext": {"lib": "msvcrt", "purpose": "find next file (MSVC CRT)", "category": "win_crt"},
    "_findclose": {"lib": "msvcrt", "purpose": "close find handle (MSVC CRT)", "category": "win_crt"},
    "_getpid": {"lib": "msvcrt", "purpose": "get process ID (MSVC CRT)", "category": "win_crt"},
    "_beginthreadex": {"lib": "msvcrt", "purpose": "create thread (CRT-safe)", "category": "win_crt"},
    "_endthreadex": {"lib": "msvcrt", "purpose": "terminate thread (CRT-safe)", "category": "win_crt"},
    "_beginthread": {"lib": "msvcrt", "purpose": "create thread (legacy)", "category": "win_crt"},
    "_endthread": {"lib": "msvcrt", "purpose": "end thread (legacy)", "category": "win_crt"},
    "_set_se_translator": {"lib": "msvcrt", "purpose": "set SEH to C++ exception translator", "category": "win_crt"},
    "_set_invalid_parameter_handler": {"lib": "msvcrt", "purpose": "set invalid parameter handler", "category": "win_crt"},
    "_CrtDbgReport": {"lib": "msvcrt", "purpose": "CRT debug report", "category": "win_crt"},
    "_CrtSetReportMode": {"lib": "msvcrt", "purpose": "set CRT report mode", "category": "win_crt"},
    "_CrtSetDbgFlag": {"lib": "msvcrt", "purpose": "set CRT debug flag", "category": "win_crt"},
    "_CrtDumpMemoryLeaks": {"lib": "msvcrt", "purpose": "dump memory leaks", "category": "win_crt"},
    "_msize": {"lib": "msvcrt", "purpose": "get heap allocation size", "category": "win_crt"},
    "_aligned_malloc": {"lib": "msvcrt", "purpose": "aligned memory allocation", "category": "win_crt"},
    "_aligned_free": {"lib": "msvcrt", "purpose": "free aligned allocation", "category": "win_crt"},
    "_aligned_realloc": {"lib": "msvcrt", "purpose": "reallocate aligned memory", "category": "win_crt"},
    "_malloca": {"lib": "msvcrt", "purpose": "stack or heap allocation", "category": "win_crt"},
    "_freea": {"lib": "msvcrt", "purpose": "free stack/heap allocation", "category": "win_crt"},
    "_strdup": {"lib": "msvcrt", "purpose": "duplicate string (MSVC)", "category": "win_crt"},
    "_wcsdup": {"lib": "msvcrt", "purpose": "duplicate wide string (MSVC)", "category": "win_crt"},
    "_stricmp": {"lib": "msvcrt", "purpose": "case-insensitive compare (MSVC)", "category": "win_crt"},
    "_strnicmp": {"lib": "msvcrt", "purpose": "case-insensitive compare n chars (MSVC)", "category": "win_crt"},
    "_strlwr": {"lib": "msvcrt", "purpose": "convert string to lowercase (MSVC)", "category": "win_crt"},
    "_strupr": {"lib": "msvcrt", "purpose": "convert string to uppercase (MSVC)", "category": "win_crt"},
    "_itoa": {"lib": "msvcrt", "purpose": "integer to string (MSVC)", "category": "win_crt"},
    "_ltoa": {"lib": "msvcrt", "purpose": "long to string (MSVC)", "category": "win_crt"},
    "_i64toa": {"lib": "msvcrt", "purpose": "int64 to string (MSVC)", "category": "win_crt"},
    "_atoi64": {"lib": "msvcrt", "purpose": "string to int64 (MSVC)", "category": "win_crt"},
    "_wtoi": {"lib": "msvcrt", "purpose": "wide string to int (MSVC)", "category": "win_crt"},
    "_wtof": {"lib": "msvcrt", "purpose": "wide string to float (MSVC)", "category": "win_crt"},
    "_snprintf": {"lib": "msvcrt", "purpose": "bounded sprintf (MSVC)", "category": "win_crt"},
    "_vsnprintf": {"lib": "msvcrt", "purpose": "bounded vsprintf (MSVC)", "category": "win_crt"},
    "_snwprintf": {"lib": "msvcrt", "purpose": "bounded swprintf (MSVC)", "category": "win_crt"},
    "sprintf_s": {"lib": "msvcrt", "purpose": "safe sprintf (CRT secure)", "category": "win_crt"},
    "strcpy_s": {"lib": "msvcrt", "purpose": "safe strcpy (CRT secure)", "category": "win_crt"},
    "strncpy_s": {"lib": "msvcrt", "purpose": "safe strncpy (CRT secure)", "category": "win_crt"},
    "strcat_s": {"lib": "msvcrt", "purpose": "safe strcat (CRT secure)", "category": "win_crt"},
    "wcscpy_s": {"lib": "msvcrt", "purpose": "safe wcscpy (CRT secure)", "category": "win_crt"},
    "wcscat_s": {"lib": "msvcrt", "purpose": "safe wcscat (CRT secure)", "category": "win_crt"},
    "memcpy_s": {"lib": "msvcrt", "purpose": "safe memcpy (CRT secure)", "category": "win_crt"},
    "memmove_s": {"lib": "msvcrt", "purpose": "safe memmove (CRT secure)", "category": "win_crt"},
    "_wfopen": {"lib": "msvcrt", "purpose": "open file (wide path, MSVC)", "category": "win_crt"},
    "fopen_s": {"lib": "msvcrt", "purpose": "safe fopen (CRT secure)", "category": "win_crt"},
    "_wfopen_s": {"lib": "msvcrt", "purpose": "safe fopen wide (CRT secure)", "category": "win_crt"},
    "wprintf": {"lib": "msvcrt", "purpose": "wide formatted output to stdout", "category": "win_crt"},
    "wcslen": {"lib": "msvcrt", "purpose": "wide string length", "category": "win_crt"},
    "wcscmp": {"lib": "msvcrt", "purpose": "compare wide strings", "category": "win_crt"},
    "wcsncmp": {"lib": "msvcrt", "purpose": "compare wide strings with limit", "category": "win_crt"},
    "wcscpy": {"lib": "msvcrt", "purpose": "copy wide string", "category": "win_crt"},
    "wcscat": {"lib": "msvcrt", "purpose": "concatenate wide strings", "category": "win_crt"},
    "wcsstr": {"lib": "msvcrt", "purpose": "find wide substring", "category": "win_crt"},
    "wcschr": {"lib": "msvcrt", "purpose": "find wide char in string", "category": "win_crt"},
    "wcsrchr": {"lib": "msvcrt", "purpose": "find last wide char in string", "category": "win_crt"},
    "wcstol": {"lib": "msvcrt", "purpose": "wide string to long", "category": "win_crt"},
    "wcstod": {"lib": "msvcrt", "purpose": "wide string to double", "category": "win_crt"},
    "_wcsicmp": {"lib": "msvcrt", "purpose": "case-insensitive wide compare", "category": "win_crt"},
    "_wcsnicmp": {"lib": "msvcrt", "purpose": "case-insensitive wide compare n chars", "category": "win_crt"},

    # =======================================================================
    # SECTION 2: C++ Standard Library / ABI (~150 entries)
    # Demangled names for common C++ std:: functions
    # =======================================================================
    "std::string::string": {"lib": "libc++", "purpose": "std::string constructor", "category": "cpp_stl"},
    "std::string::~string": {"lib": "libc++", "purpose": "std::string destructor", "category": "cpp_stl"},
    "std::string::append": {"lib": "libc++", "purpose": "append to string", "category": "cpp_stl"},
    "std::string::assign": {"lib": "libc++", "purpose": "assign string content", "category": "cpp_stl"},
    "std::string::c_str": {"lib": "libc++", "purpose": "get C string", "category": "cpp_stl"},
    "std::string::data": {"lib": "libc++", "purpose": "get string data", "category": "cpp_stl"},
    "std::string::size": {"lib": "libc++", "purpose": "get string size", "category": "cpp_stl"},
    "std::string::empty": {"lib": "libc++", "purpose": "check if string empty", "category": "cpp_stl"},
    "std::string::find": {"lib": "libc++", "purpose": "find substring", "category": "cpp_stl"},
    "std::string::substr": {"lib": "libc++", "purpose": "get substring", "category": "cpp_stl"},
    "std::string::compare": {"lib": "libc++", "purpose": "compare strings", "category": "cpp_stl"},
    "std::string::reserve": {"lib": "libc++", "purpose": "reserve string capacity", "category": "cpp_stl"},
    "std::string::resize": {"lib": "libc++", "purpose": "resize string", "category": "cpp_stl"},
    "std::string::clear": {"lib": "libc++", "purpose": "clear string content", "category": "cpp_stl"},
    "std::string::push_back": {"lib": "libc++", "purpose": "append character", "category": "cpp_stl"},
    "std::string::erase": {"lib": "libc++", "purpose": "erase characters", "category": "cpp_stl"},
    "std::string::insert": {"lib": "libc++", "purpose": "insert characters", "category": "cpp_stl"},
    "std::string::replace": {"lib": "libc++", "purpose": "replace portion", "category": "cpp_stl"},
    "std::vector::push_back": {"lib": "libc++", "purpose": "add element to vector end", "category": "cpp_stl"},
    "std::vector::emplace_back": {"lib": "libc++", "purpose": "construct element at vector end", "category": "cpp_stl"},
    "std::vector::pop_back": {"lib": "libc++", "purpose": "remove last vector element", "category": "cpp_stl"},
    "std::vector::reserve": {"lib": "libc++", "purpose": "reserve vector capacity", "category": "cpp_stl"},
    "std::vector::resize": {"lib": "libc++", "purpose": "resize vector", "category": "cpp_stl"},
    "std::vector::clear": {"lib": "libc++", "purpose": "clear vector", "category": "cpp_stl"},
    "std::vector::erase": {"lib": "libc++", "purpose": "erase vector elements", "category": "cpp_stl"},
    "std::vector::insert": {"lib": "libc++", "purpose": "insert vector elements", "category": "cpp_stl"},
    "std::vector::size": {"lib": "libc++", "purpose": "get vector size", "category": "cpp_stl"},
    "std::vector::empty": {"lib": "libc++", "purpose": "check if vector empty", "category": "cpp_stl"},
    "std::vector::begin": {"lib": "libc++", "purpose": "get vector begin iterator", "category": "cpp_stl"},
    "std::vector::end": {"lib": "libc++", "purpose": "get vector end iterator", "category": "cpp_stl"},
    "std::vector::data": {"lib": "libc++", "purpose": "get vector data pointer", "category": "cpp_stl"},
    "std::map::find": {"lib": "libc++", "purpose": "find element in map", "category": "cpp_stl"},
    "std::map::insert": {"lib": "libc++", "purpose": "insert into map", "category": "cpp_stl"},
    "std::map::erase": {"lib": "libc++", "purpose": "erase from map", "category": "cpp_stl"},
    "std::map::count": {"lib": "libc++", "purpose": "count map elements", "category": "cpp_stl"},
    "std::map::size": {"lib": "libc++", "purpose": "get map size", "category": "cpp_stl"},
    "std::map::empty": {"lib": "libc++", "purpose": "check if map empty", "category": "cpp_stl"},
    "std::map::begin": {"lib": "libc++", "purpose": "get map begin iterator", "category": "cpp_stl"},
    "std::map::end": {"lib": "libc++", "purpose": "get map end iterator", "category": "cpp_stl"},
    "std::map::operator[]": {"lib": "libc++", "purpose": "map subscript access", "category": "cpp_stl"},
    "std::unordered_map::find": {"lib": "libc++", "purpose": "find in unordered_map", "category": "cpp_stl"},
    "std::unordered_map::insert": {"lib": "libc++", "purpose": "insert into unordered_map", "category": "cpp_stl"},
    "std::unordered_map::erase": {"lib": "libc++", "purpose": "erase from unordered_map", "category": "cpp_stl"},
    "std::unordered_map::count": {"lib": "libc++", "purpose": "count unordered_map elements", "category": "cpp_stl"},
    "std::unordered_map::size": {"lib": "libc++", "purpose": "get unordered_map size", "category": "cpp_stl"},
    "std::unordered_map::empty": {"lib": "libc++", "purpose": "check if unordered_map empty", "category": "cpp_stl"},
    "std::unordered_map::operator[]": {"lib": "libc++", "purpose": "unordered_map subscript access", "category": "cpp_stl"},
    "std::set::insert": {"lib": "libc++", "purpose": "insert into set", "category": "cpp_stl"},
    "std::set::erase": {"lib": "libc++", "purpose": "erase from set", "category": "cpp_stl"},
    "std::set::find": {"lib": "libc++", "purpose": "find in set", "category": "cpp_stl"},
    "std::set::count": {"lib": "libc++", "purpose": "count set elements", "category": "cpp_stl"},
    "std::set::size": {"lib": "libc++", "purpose": "get set size", "category": "cpp_stl"},
    "std::unordered_set::insert": {"lib": "libc++", "purpose": "insert into unordered_set", "category": "cpp_stl"},
    "std::unordered_set::erase": {"lib": "libc++", "purpose": "erase from unordered_set", "category": "cpp_stl"},
    "std::unordered_set::find": {"lib": "libc++", "purpose": "find in unordered_set", "category": "cpp_stl"},
    "std::list::push_back": {"lib": "libc++", "purpose": "add to list end", "category": "cpp_stl"},
    "std::list::push_front": {"lib": "libc++", "purpose": "add to list front", "category": "cpp_stl"},
    "std::list::pop_back": {"lib": "libc++", "purpose": "remove from list end", "category": "cpp_stl"},
    "std::list::pop_front": {"lib": "libc++", "purpose": "remove from list front", "category": "cpp_stl"},
    "std::list::erase": {"lib": "libc++", "purpose": "erase list element", "category": "cpp_stl"},
    "std::list::insert": {"lib": "libc++", "purpose": "insert into list", "category": "cpp_stl"},
    "std::list::size": {"lib": "libc++", "purpose": "get list size", "category": "cpp_stl"},
    "std::list::empty": {"lib": "libc++", "purpose": "check if list empty", "category": "cpp_stl"},
    "std::list::sort": {"lib": "libc++", "purpose": "sort list elements", "category": "cpp_stl"},
    "std::deque::push_back": {"lib": "libc++", "purpose": "add to deque end", "category": "cpp_stl"},
    "std::deque::push_front": {"lib": "libc++", "purpose": "add to deque front", "category": "cpp_stl"},
    "std::deque::pop_back": {"lib": "libc++", "purpose": "remove from deque end", "category": "cpp_stl"},
    "std::deque::pop_front": {"lib": "libc++", "purpose": "remove from deque front", "category": "cpp_stl"},
    "std::deque::size": {"lib": "libc++", "purpose": "get deque size", "category": "cpp_stl"},
    "std::queue::push": {"lib": "libc++", "purpose": "push to queue", "category": "cpp_stl"},
    "std::queue::pop": {"lib": "libc++", "purpose": "pop from queue", "category": "cpp_stl"},
    "std::queue::front": {"lib": "libc++", "purpose": "get queue front element", "category": "cpp_stl"},
    "std::queue::empty": {"lib": "libc++", "purpose": "check if queue empty", "category": "cpp_stl"},
    "std::stack::push": {"lib": "libc++", "purpose": "push to stack", "category": "cpp_stl"},
    "std::stack::pop": {"lib": "libc++", "purpose": "pop from stack", "category": "cpp_stl"},
    "std::stack::top": {"lib": "libc++", "purpose": "get stack top element", "category": "cpp_stl"},
    "std::stack::empty": {"lib": "libc++", "purpose": "check if stack empty", "category": "cpp_stl"},
    "std::priority_queue::push": {"lib": "libc++", "purpose": "push to priority queue", "category": "cpp_stl"},
    "std::priority_queue::pop": {"lib": "libc++", "purpose": "pop from priority queue", "category": "cpp_stl"},
    "std::priority_queue::top": {"lib": "libc++", "purpose": "get priority queue top", "category": "cpp_stl"},
    "std::sort": {"lib": "libc++", "purpose": "sort range", "category": "cpp_algorithm"},
    "std::stable_sort": {"lib": "libc++", "purpose": "stable sort range", "category": "cpp_algorithm"},
    "std::partial_sort": {"lib": "libc++", "purpose": "partial sort range", "category": "cpp_algorithm"},
    "std::nth_element": {"lib": "libc++", "purpose": "nth element partition", "category": "cpp_algorithm"},
    "std::binary_search": {"lib": "libc++", "purpose": "binary search in sorted range", "category": "cpp_algorithm"},
    "std::lower_bound": {"lib": "libc++", "purpose": "lower bound in sorted range", "category": "cpp_algorithm"},
    "std::upper_bound": {"lib": "libc++", "purpose": "upper bound in sorted range", "category": "cpp_algorithm"},
    "std::find": {"lib": "libc++", "purpose": "find element in range", "category": "cpp_algorithm"},
    "std::find_if": {"lib": "libc++", "purpose": "find element by predicate", "category": "cpp_algorithm"},
    "std::count": {"lib": "libc++", "purpose": "count elements", "category": "cpp_algorithm"},
    "std::count_if": {"lib": "libc++", "purpose": "count elements by predicate", "category": "cpp_algorithm"},
    "std::copy": {"lib": "libc++", "purpose": "copy range", "category": "cpp_algorithm"},
    "std::move": {"lib": "libc++", "purpose": "move range (or cast to rvalue)", "category": "cpp_algorithm"},
    "std::fill": {"lib": "libc++", "purpose": "fill range with value", "category": "cpp_algorithm"},
    "std::transform": {"lib": "libc++", "purpose": "transform range", "category": "cpp_algorithm"},
    "std::accumulate": {"lib": "libc++", "purpose": "accumulate range", "category": "cpp_algorithm"},
    "std::for_each": {"lib": "libc++", "purpose": "apply function to range", "category": "cpp_algorithm"},
    "std::remove_if": {"lib": "libc++", "purpose": "remove elements by predicate", "category": "cpp_algorithm"},
    "std::unique": {"lib": "libc++", "purpose": "remove consecutive duplicates", "category": "cpp_algorithm"},
    "std::reverse": {"lib": "libc++", "purpose": "reverse range", "category": "cpp_algorithm"},
    "std::min_element": {"lib": "libc++", "purpose": "find minimum element", "category": "cpp_algorithm"},
    "std::max_element": {"lib": "libc++", "purpose": "find maximum element", "category": "cpp_algorithm"},
    "std::swap": {"lib": "libc++", "purpose": "swap two values", "category": "cpp_algorithm"},
    "std::make_shared": {"lib": "libc++", "purpose": "create shared_ptr", "category": "cpp_memory"},
    "std::make_unique": {"lib": "libc++", "purpose": "create unique_ptr", "category": "cpp_memory"},
    "std::shared_ptr::shared_ptr": {"lib": "libc++", "purpose": "shared_ptr constructor", "category": "cpp_memory"},
    "std::shared_ptr::reset": {"lib": "libc++", "purpose": "reset shared_ptr", "category": "cpp_memory"},
    "std::shared_ptr::get": {"lib": "libc++", "purpose": "get shared_ptr raw pointer", "category": "cpp_memory"},
    "std::shared_ptr::use_count": {"lib": "libc++", "purpose": "get shared_ptr reference count", "category": "cpp_memory"},
    "std::unique_ptr::unique_ptr": {"lib": "libc++", "purpose": "unique_ptr constructor", "category": "cpp_memory"},
    "std::unique_ptr::reset": {"lib": "libc++", "purpose": "reset unique_ptr", "category": "cpp_memory"},
    "std::unique_ptr::release": {"lib": "libc++", "purpose": "release unique_ptr ownership", "category": "cpp_memory"},
    "std::unique_ptr::get": {"lib": "libc++", "purpose": "get unique_ptr raw pointer", "category": "cpp_memory"},
    "std::weak_ptr::lock": {"lib": "libc++", "purpose": "lock weak_ptr to shared_ptr", "category": "cpp_memory"},
    "std::weak_ptr::expired": {"lib": "libc++", "purpose": "check if weak_ptr expired", "category": "cpp_memory"},
    "std::mutex::lock": {"lib": "libc++", "purpose": "lock std::mutex", "category": "cpp_thread"},
    "std::mutex::unlock": {"lib": "libc++", "purpose": "unlock std::mutex", "category": "cpp_thread"},
    "std::mutex::try_lock": {"lib": "libc++", "purpose": "try lock std::mutex", "category": "cpp_thread"},
    "std::recursive_mutex::lock": {"lib": "libc++", "purpose": "lock recursive mutex", "category": "cpp_thread"},
    "std::recursive_mutex::unlock": {"lib": "libc++", "purpose": "unlock recursive mutex", "category": "cpp_thread"},
    "std::condition_variable::wait": {"lib": "libc++", "purpose": "wait on condition variable", "category": "cpp_thread"},
    "std::condition_variable::notify_one": {"lib": "libc++", "purpose": "notify one waiter", "category": "cpp_thread"},
    "std::condition_variable::notify_all": {"lib": "libc++", "purpose": "notify all waiters", "category": "cpp_thread"},
    "std::thread::thread": {"lib": "libc++", "purpose": "std::thread constructor", "category": "cpp_thread"},
    "std::thread::join": {"lib": "libc++", "purpose": "join std::thread", "category": "cpp_thread"},
    "std::thread::detach": {"lib": "libc++", "purpose": "detach std::thread", "category": "cpp_thread"},
    "std::async": {"lib": "libc++", "purpose": "launch async task", "category": "cpp_thread"},
    "std::future::get": {"lib": "libc++", "purpose": "get future result", "category": "cpp_thread"},
    "std::future::wait": {"lib": "libc++", "purpose": "wait for future result", "category": "cpp_thread"},
    "std::promise::set_value": {"lib": "libc++", "purpose": "set promise value", "category": "cpp_thread"},
    "std::promise::set_exception": {"lib": "libc++", "purpose": "set promise exception", "category": "cpp_thread"},
    "std::fstream::open": {"lib": "libc++", "purpose": "open file stream", "category": "cpp_io"},
    "std::fstream::close": {"lib": "libc++", "purpose": "close file stream", "category": "cpp_io"},
    "std::ifstream::open": {"lib": "libc++", "purpose": "open input file stream", "category": "cpp_io"},
    "std::ofstream::open": {"lib": "libc++", "purpose": "open output file stream", "category": "cpp_io"},
    "std::stringstream::str": {"lib": "libc++", "purpose": "get/set stringstream string", "category": "cpp_io"},
    "std::getline": {"lib": "libc++", "purpose": "read line from stream", "category": "cpp_io"},
    "std::stoi": {"lib": "libc++", "purpose": "string to int", "category": "cpp_stl"},
    "std::stol": {"lib": "libc++", "purpose": "string to long", "category": "cpp_stl"},
    "std::stoll": {"lib": "libc++", "purpose": "string to long long", "category": "cpp_stl"},
    "std::stof": {"lib": "libc++", "purpose": "string to float", "category": "cpp_stl"},
    "std::stod": {"lib": "libc++", "purpose": "string to double", "category": "cpp_stl"},
    "std::to_string": {"lib": "libc++", "purpose": "number to string", "category": "cpp_stl"},
    "std::regex_search": {"lib": "libc++", "purpose": "search for regex match", "category": "cpp_stl"},
    "std::regex_match": {"lib": "libc++", "purpose": "test full regex match", "category": "cpp_stl"},
    "std::regex_replace": {"lib": "libc++", "purpose": "regex replace", "category": "cpp_stl"},
    "std::filesystem::exists": {"lib": "libc++", "purpose": "check if path exists (C++17)", "category": "cpp_fs"},
    "std::filesystem::create_directory": {"lib": "libc++", "purpose": "create directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::create_directories": {"lib": "libc++", "purpose": "create directory tree (C++17)", "category": "cpp_fs"},
    "std::filesystem::remove": {"lib": "libc++", "purpose": "remove file/directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::remove_all": {"lib": "libc++", "purpose": "remove recursively (C++17)", "category": "cpp_fs"},
    "std::filesystem::rename": {"lib": "libc++", "purpose": "rename file/directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::copy": {"lib": "libc++", "purpose": "copy file (C++17)", "category": "cpp_fs"},
    "std::filesystem::copy_file": {"lib": "libc++", "purpose": "copy regular file (C++17)", "category": "cpp_fs"},
    "std::filesystem::file_size": {"lib": "libc++", "purpose": "get file size (C++17)", "category": "cpp_fs"},
    "std::filesystem::current_path": {"lib": "libc++", "purpose": "get/set current directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::is_regular_file": {"lib": "libc++", "purpose": "check if regular file (C++17)", "category": "cpp_fs"},
    "std::filesystem::is_directory": {"lib": "libc++", "purpose": "check if directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::directory_iterator": {"lib": "libc++", "purpose": "iterate directory (C++17)", "category": "cpp_fs"},
    "std::filesystem::recursive_directory_iterator": {"lib": "libc++", "purpose": "iterate directory tree (C++17)", "category": "cpp_fs"},
    "std::filesystem::path::extension": {"lib": "libc++", "purpose": "get path extension (C++17)", "category": "cpp_fs"},
    "std::filesystem::path::stem": {"lib": "libc++", "purpose": "get path stem (C++17)", "category": "cpp_fs"},
    "std::filesystem::path::parent_path": {"lib": "libc++", "purpose": "get parent path (C++17)", "category": "cpp_fs"},
    "std::filesystem::path::filename": {"lib": "libc++", "purpose": "get filename component (C++17)", "category": "cpp_fs"},
    "std::filesystem::absolute": {"lib": "libc++", "purpose": "get absolute path (C++17)", "category": "cpp_fs"},
    "std::filesystem::canonical": {"lib": "libc++", "purpose": "get canonical path (C++17)", "category": "cpp_fs"},
    "std::filesystem::temp_directory_path": {"lib": "libc++", "purpose": "get temp directory (C++17)", "category": "cpp_fs"},
    # C++ exception handling
    "__cxa_throw": {"lib": "libc++abi", "purpose": "throw C++ exception", "category": "cpp_exception"},
    "__cxa_begin_catch": {"lib": "libc++abi", "purpose": "begin C++ catch block", "category": "cpp_exception"},
    "__cxa_end_catch": {"lib": "libc++abi", "purpose": "end C++ catch block", "category": "cpp_exception"},
    "__cxa_rethrow": {"lib": "libc++abi", "purpose": "rethrow current C++ exception", "category": "cpp_exception"},
    "__cxa_allocate_exception": {"lib": "libc++abi", "purpose": "allocate exception object", "category": "cpp_exception"},
    "__cxa_free_exception": {"lib": "libc++abi", "purpose": "free exception object", "category": "cpp_exception"},
    "__cxa_get_exception_ptr": {"lib": "libc++abi", "purpose": "get exception pointer", "category": "cpp_exception"},
    "__cxa_current_exception_type": {"lib": "libc++abi", "purpose": "get current exception type info", "category": "cpp_exception"},
    "__gxx_personality_v0": {"lib": "libc++abi", "purpose": "GCC/Clang exception personality function", "category": "cpp_exception"},
    "__cxa_guard_acquire": {"lib": "libc++abi", "purpose": "acquire static init guard", "category": "cpp_runtime"},
    "__cxa_guard_release": {"lib": "libc++abi", "purpose": "release static init guard", "category": "cpp_runtime"},
    "__cxa_guard_abort": {"lib": "libc++abi", "purpose": "abort static initialization", "category": "cpp_runtime"},
    "__cxa_atexit": {"lib": "libc++abi", "purpose": "register destructor for static/global", "category": "cpp_runtime"},
    "__cxa_finalize": {"lib": "libc++abi", "purpose": "call registered destructors at exit", "category": "cpp_runtime"},
    "__cxa_demangle": {"lib": "libc++abi", "purpose": "demangle C++ symbol name", "category": "cpp_runtime"},
    "__cxa_pure_virtual": {"lib": "libc++abi", "purpose": "pure virtual function call handler", "category": "cpp_runtime"},
    "__cxa_deleted_virtual": {"lib": "libc++abi", "purpose": "deleted virtual function call handler", "category": "cpp_runtime"},
    "operator new": {"lib": "libc++", "purpose": "C++ global operator new", "category": "cpp_memory"},
    "operator new[]": {"lib": "libc++", "purpose": "C++ global operator new[]", "category": "cpp_memory"},
    "operator delete": {"lib": "libc++", "purpose": "C++ global operator delete", "category": "cpp_memory"},
    "operator delete[]": {"lib": "libc++", "purpose": "C++ global operator delete[]", "category": "cpp_memory"},

    # =======================================================================
    # SECTION 3: Math functions (libm) (~60 entries)
    # =======================================================================
    "sin": {"lib": "libm", "purpose": "sine", "category": "math"},
    "cos": {"lib": "libm", "purpose": "cosine", "category": "math"},
    "tan": {"lib": "libm", "purpose": "tangent", "category": "math"},
    "asin": {"lib": "libm", "purpose": "arc sine", "category": "math"},
    "acos": {"lib": "libm", "purpose": "arc cosine", "category": "math"},
    "atan": {"lib": "libm", "purpose": "arc tangent", "category": "math"},
    "atan2": {"lib": "libm", "purpose": "arc tangent of y/x", "category": "math"},
    "sinh": {"lib": "libm", "purpose": "hyperbolic sine", "category": "math"},
    "cosh": {"lib": "libm", "purpose": "hyperbolic cosine", "category": "math"},
    "tanh": {"lib": "libm", "purpose": "hyperbolic tangent", "category": "math"},
    "asinh": {"lib": "libm", "purpose": "inverse hyperbolic sine", "category": "math"},
    "acosh": {"lib": "libm", "purpose": "inverse hyperbolic cosine", "category": "math"},
    "atanh": {"lib": "libm", "purpose": "inverse hyperbolic tangent", "category": "math"},
    "exp": {"lib": "libm", "purpose": "exponential (e^x)", "category": "math"},
    "exp2": {"lib": "libm", "purpose": "base-2 exponential (2^x)", "category": "math"},
    "expm1": {"lib": "libm", "purpose": "e^x - 1 (precise for small x)", "category": "math"},
    "log": {"lib": "libm", "purpose": "natural logarithm", "category": "math"},
    "log2": {"lib": "libm", "purpose": "base-2 logarithm", "category": "math"},
    "log10": {"lib": "libm", "purpose": "base-10 logarithm", "category": "math"},
    "log1p": {"lib": "libm", "purpose": "log(1+x) (precise for small x)", "category": "math"},
    "pow": {"lib": "libm", "purpose": "raise to power", "category": "math"},
    "sqrt": {"lib": "libm", "purpose": "square root", "category": "math"},
    "cbrt": {"lib": "libm", "purpose": "cube root", "category": "math"},
    "hypot": {"lib": "libm", "purpose": "hypotenuse (sqrt(x^2+y^2))", "category": "math"},
    "fabs": {"lib": "libm", "purpose": "absolute value (float)", "category": "math"},
    "fabsf": {"lib": "libm", "purpose": "absolute value (float32)", "category": "math"},
    "ceil": {"lib": "libm", "purpose": "ceiling (round up)", "category": "math"},
    "ceilf": {"lib": "libm", "purpose": "ceiling float32", "category": "math"},
    "floor": {"lib": "libm", "purpose": "floor (round down)", "category": "math"},
    "floorf": {"lib": "libm", "purpose": "floor float32", "category": "math"},
    "round": {"lib": "libm", "purpose": "round to nearest integer", "category": "math"},
    "roundf": {"lib": "libm", "purpose": "round float32", "category": "math"},
    "trunc": {"lib": "libm", "purpose": "truncate toward zero", "category": "math"},
    "truncf": {"lib": "libm", "purpose": "truncate float32", "category": "math"},
    "fmod": {"lib": "libm", "purpose": "floating-point modulo", "category": "math"},
    "fmodf": {"lib": "libm", "purpose": "floating-point modulo float32", "category": "math"},
    "remainder": {"lib": "libm", "purpose": "IEEE remainder", "category": "math"},
    "fmin": {"lib": "libm", "purpose": "minimum of two floats", "category": "math"},
    "fmax": {"lib": "libm", "purpose": "maximum of two floats", "category": "math"},
    "fminf": {"lib": "libm", "purpose": "minimum float32", "category": "math"},
    "fmaxf": {"lib": "libm", "purpose": "maximum float32", "category": "math"},
    "copysign": {"lib": "libm", "purpose": "copy sign of float", "category": "math"},
    "isnan": {"lib": "libm", "purpose": "check if NaN", "category": "math"},
    "isinf": {"lib": "libm", "purpose": "check if infinity", "category": "math"},
    "isfinite": {"lib": "libm", "purpose": "check if finite", "category": "math"},
    "nan": {"lib": "libm", "purpose": "generate quiet NaN", "category": "math"},
    "frexp": {"lib": "libm", "purpose": "extract exponent and mantissa", "category": "math"},
    "ldexp": {"lib": "libm", "purpose": "multiply by power of 2", "category": "math"},
    "modf": {"lib": "libm", "purpose": "split into integer and fractional parts", "category": "math"},
    "nextafter": {"lib": "libm", "purpose": "next representable float", "category": "math"},
    "scalbn": {"lib": "libm", "purpose": "scale by power of radix", "category": "math"},
    "lgamma": {"lib": "libm", "purpose": "log-gamma function", "category": "math"},
    "tgamma": {"lib": "libm", "purpose": "gamma function", "category": "math"},
    "erf": {"lib": "libm", "purpose": "error function", "category": "math"},
    "erfc": {"lib": "libm", "purpose": "complementary error function", "category": "math"},
    "j0": {"lib": "libm", "purpose": "Bessel function J0", "category": "math"},
    "j1": {"lib": "libm", "purpose": "Bessel function J1", "category": "math"},
    "sinf": {"lib": "libm", "purpose": "sine float32", "category": "math"},
    "cosf": {"lib": "libm", "purpose": "cosine float32", "category": "math"},
    "tanf": {"lib": "libm", "purpose": "tangent float32", "category": "math"},
    "sqrtf": {"lib": "libm", "purpose": "square root float32", "category": "math"},
    "powf": {"lib": "libm", "purpose": "power float32", "category": "math"},
    "logf": {"lib": "libm", "purpose": "natural log float32", "category": "math"},
    "expf": {"lib": "libm", "purpose": "exponential float32", "category": "math"},
}


# ---------------------------------------------------------------------------
# MEGA BATCH 2: Objective-C Runtime, Swift, Foundation, UIKit, AppKit
# macOS prefix ("_") applied where needed.
# ---------------------------------------------------------------------------

_MEGA_BATCH_2_SIGNATURES: dict[str, dict[str, str]] = {
    # =======================================================================
    # Objective-C Runtime Extended (~100)
    # =======================================================================
    "_objc_msgSend": {"lib": "libobjc", "purpose": "send ObjC message (primary dispatch)", "category": "objc_runtime"},
    "_objc_msgSendSuper": {"lib": "libobjc", "purpose": "send ObjC message to super", "category": "objc_runtime"},
    "_objc_msgSendSuper2": {"lib": "libobjc", "purpose": "send ObjC message to super (v2)", "category": "objc_runtime"},
    "_objc_msgSend_stret": {"lib": "libobjc", "purpose": "send ObjC message returning struct", "category": "objc_runtime"},
    "_objc_msgSend_fpret": {"lib": "libobjc", "purpose": "send ObjC message returning float", "category": "objc_runtime"},
    "_objc_retain": {"lib": "libobjc", "purpose": "ARC retain object", "category": "objc_runtime"},
    "_objc_release": {"lib": "libobjc", "purpose": "ARC release object", "category": "objc_runtime"},
    "_objc_autorelease": {"lib": "libobjc", "purpose": "ARC autorelease object", "category": "objc_runtime"},
    "_objc_autoreleaseReturnValue": {"lib": "libobjc", "purpose": "ARC autorelease return value", "category": "objc_runtime"},
    "_objc_retainAutoreleasedReturnValue": {"lib": "libobjc", "purpose": "ARC retain autoreleased return", "category": "objc_runtime"},
    "_objc_retainAutoreleaseReturnValue": {"lib": "libobjc", "purpose": "ARC retain+autorelease return", "category": "objc_runtime"},
    "_objc_storeStrong": {"lib": "libobjc", "purpose": "ARC store strong reference", "category": "objc_runtime"},
    "_objc_storeWeak": {"lib": "libobjc", "purpose": "ARC store weak reference", "category": "objc_runtime"},
    "_objc_loadWeakRetained": {"lib": "libobjc", "purpose": "ARC load and retain weak ref", "category": "objc_runtime"},
    "_objc_destroyWeak": {"lib": "libobjc", "purpose": "ARC destroy weak reference", "category": "objc_runtime"},
    "_objc_initWeak": {"lib": "libobjc", "purpose": "ARC initialize weak reference", "category": "objc_runtime"},
    "_objc_moveWeak": {"lib": "libobjc", "purpose": "ARC move weak reference", "category": "objc_runtime"},
    "_objc_copyWeak": {"lib": "libobjc", "purpose": "ARC copy weak reference", "category": "objc_runtime"},
    "_objc_autoreleasePoolPush": {"lib": "libobjc", "purpose": "push autorelease pool", "category": "objc_runtime"},
    "_objc_autoreleasePoolPop": {"lib": "libobjc", "purpose": "pop autorelease pool", "category": "objc_runtime"},
    "_objc_alloc": {"lib": "libobjc", "purpose": "allocate ObjC object", "category": "objc_runtime"},
    "_objc_alloc_init": {"lib": "libobjc", "purpose": "alloc + init ObjC object", "category": "objc_runtime"},
    "_objc_allocWithZone": {"lib": "libobjc", "purpose": "allocate in memory zone", "category": "objc_runtime"},
    "_objc_opt_new": {"lib": "libobjc", "purpose": "optimized +new", "category": "objc_runtime"},
    "_objc_opt_self": {"lib": "libobjc", "purpose": "optimized +self", "category": "objc_runtime"},
    "_objc_opt_class": {"lib": "libobjc", "purpose": "optimized +class", "category": "objc_runtime"},
    "_objc_opt_isKindOfClass": {"lib": "libobjc", "purpose": "optimized -isKindOfClass:", "category": "objc_runtime"},
    "_objc_opt_respondsToSelector": {"lib": "libobjc", "purpose": "optimized -respondsToSelector:", "category": "objc_runtime"},
    "_objc_getClass": {"lib": "libobjc", "purpose": "get ObjC class by name", "category": "objc_runtime"},
    "_objc_getMetaClass": {"lib": "libobjc", "purpose": "get ObjC metaclass by name", "category": "objc_runtime"},
    "_objc_lookUpClass": {"lib": "libobjc", "purpose": "lookup ObjC class (nil if not found)", "category": "objc_runtime"},
    "_class_getName": {"lib": "libobjc", "purpose": "get ObjC class name", "category": "objc_runtime"},
    "_class_getSuperclass": {"lib": "libobjc", "purpose": "get ObjC superclass", "category": "objc_runtime"},
    "_class_getInstanceMethod": {"lib": "libobjc", "purpose": "get instance method", "category": "objc_runtime"},
    "_class_getClassMethod": {"lib": "libobjc", "purpose": "get class method", "category": "objc_runtime"},
    "_class_addMethod": {"lib": "libobjc", "purpose": "add method to class", "category": "objc_runtime"},
    "_class_replaceMethod": {"lib": "libobjc", "purpose": "replace method implementation", "category": "objc_runtime"},
    "_class_getInstanceSize": {"lib": "libobjc", "purpose": "get instance size", "category": "objc_runtime"},
    "_class_getProperty": {"lib": "libobjc", "purpose": "get class property", "category": "objc_runtime"},
    "_class_copyPropertyList": {"lib": "libobjc", "purpose": "copy property list", "category": "objc_runtime"},
    "_class_copyMethodList": {"lib": "libobjc", "purpose": "copy method list", "category": "objc_runtime"},
    "_class_copyIvarList": {"lib": "libobjc", "purpose": "copy ivar list", "category": "objc_runtime"},
    "_class_conformsToProtocol": {"lib": "libobjc", "purpose": "check protocol conformance", "category": "objc_runtime"},
    "_class_isMetaClass": {"lib": "libobjc", "purpose": "check if metaclass", "category": "objc_runtime"},
    "_object_getClass": {"lib": "libobjc", "purpose": "get object's class", "category": "objc_runtime"},
    "_object_setClass": {"lib": "libobjc", "purpose": "set object's class (isa swizzle)", "category": "objc_runtime"},
    "_object_getClassName": {"lib": "libobjc", "purpose": "get object's class name", "category": "objc_runtime"},
    "_object_getIvar": {"lib": "libobjc", "purpose": "get ivar value", "category": "objc_runtime"},
    "_object_setIvar": {"lib": "libobjc", "purpose": "set ivar value", "category": "objc_runtime"},
    "_sel_getName": {"lib": "libobjc", "purpose": "get selector name string", "category": "objc_runtime"},
    "_sel_registerName": {"lib": "libobjc", "purpose": "register selector name", "category": "objc_runtime"},
    "_sel_getUid": {"lib": "libobjc", "purpose": "get selector UID", "category": "objc_runtime"},
    "_method_getName": {"lib": "libobjc", "purpose": "get method selector", "category": "objc_runtime"},
    "_method_getImplementation": {"lib": "libobjc", "purpose": "get method IMP pointer", "category": "objc_runtime"},
    "_method_setImplementation": {"lib": "libobjc", "purpose": "set method IMP (method swizzling)", "category": "objc_runtime"},
    "_method_exchangeImplementations": {"lib": "libobjc", "purpose": "swap two method IMPs", "category": "objc_runtime"},
    "_method_getTypeEncoding": {"lib": "libobjc", "purpose": "get method type encoding", "category": "objc_runtime"},
    "_ivar_getName": {"lib": "libobjc", "purpose": "get ivar name", "category": "objc_runtime"},
    "_ivar_getOffset": {"lib": "libobjc", "purpose": "get ivar offset", "category": "objc_runtime"},
    "_ivar_getTypeEncoding": {"lib": "libobjc", "purpose": "get ivar type encoding", "category": "objc_runtime"},
    "_protocol_getName": {"lib": "libobjc", "purpose": "get protocol name", "category": "objc_runtime"},
    "_protocol_conformsToProtocol": {"lib": "libobjc", "purpose": "check protocol inheritance", "category": "objc_runtime"},
    "_protocol_copyMethodDescriptionList": {"lib": "libobjc", "purpose": "copy protocol method list", "category": "objc_runtime"},
    "_objc_setAssociatedObject": {"lib": "libobjc", "purpose": "set associated object (runtime attach)", "category": "objc_runtime"},
    "_objc_getAssociatedObject": {"lib": "libobjc", "purpose": "get associated object", "category": "objc_runtime"},
    "_objc_removeAssociatedObjects": {"lib": "libobjc", "purpose": "remove all associated objects", "category": "objc_runtime"},
    "_objc_constructInstance": {"lib": "libobjc", "purpose": "construct instance at memory", "category": "objc_runtime"},
    "_objc_destructInstance": {"lib": "libobjc", "purpose": "destruct instance without free", "category": "objc_runtime"},
    "_objc_enumerationMutation": {"lib": "libobjc", "purpose": "fast enumeration mutation handler", "category": "objc_runtime"},
    "_objc_exception_throw": {"lib": "libobjc", "purpose": "throw ObjC exception", "category": "objc_runtime"},
    "_objc_exception_rethrow": {"lib": "libobjc", "purpose": "rethrow ObjC exception", "category": "objc_runtime"},
    "_objc_begin_catch": {"lib": "libobjc", "purpose": "begin ObjC catch block", "category": "objc_runtime"},
    "_objc_end_catch": {"lib": "libobjc", "purpose": "end ObjC catch block", "category": "objc_runtime"},
    "_objc_terminate": {"lib": "libobjc", "purpose": "ObjC terminate handler", "category": "objc_runtime"},
    "_objc_sync_enter": {"lib": "libobjc", "purpose": "@synchronized enter", "category": "objc_runtime"},
    "_objc_sync_exit": {"lib": "libobjc", "purpose": "@synchronized exit", "category": "objc_runtime"},

    # =======================================================================
    # NSObject / Foundation Extended (~150)
    # =======================================================================
    "_NSLog": {"lib": "Foundation", "purpose": "Foundation formatted logging", "category": "foundation"},
    "_NSLogv": {"lib": "Foundation", "purpose": "Foundation formatted logging (va_list)", "category": "foundation"},
    "_NSStringFromClass": {"lib": "Foundation", "purpose": "class name to NSString", "category": "foundation"},
    "_NSClassFromString": {"lib": "Foundation", "purpose": "NSString to class", "category": "foundation"},
    "_NSSelectorFromString": {"lib": "Foundation", "purpose": "NSString to SEL", "category": "foundation"},
    "_NSStringFromSelector": {"lib": "Foundation", "purpose": "SEL to NSString", "category": "foundation"},
    "_NSHomeDirectory": {"lib": "Foundation", "purpose": "get user home directory", "category": "foundation"},
    "_NSTemporaryDirectory": {"lib": "Foundation", "purpose": "get temp directory", "category": "foundation"},
    "_NSSearchPathForDirectoriesInDomains": {"lib": "Foundation", "purpose": "search system directories", "category": "foundation"},
    "_NSUserName": {"lib": "Foundation", "purpose": "get current user name", "category": "foundation"},
    "_NSFullUserName": {"lib": "Foundation", "purpose": "get full user name", "category": "foundation"},
    "-[NSObject init]": {"lib": "Foundation", "purpose": "NSObject init", "category": "foundation"},
    "-[NSObject dealloc]": {"lib": "Foundation", "purpose": "NSObject dealloc", "category": "foundation"},
    "-[NSObject copy]": {"lib": "Foundation", "purpose": "NSObject copy", "category": "foundation"},
    "-[NSObject mutableCopy]": {"lib": "Foundation", "purpose": "NSObject mutable copy", "category": "foundation"},
    "-[NSObject respondsToSelector:]": {"lib": "Foundation", "purpose": "check method availability", "category": "foundation"},
    "-[NSObject performSelector:]": {"lib": "Foundation", "purpose": "perform selector dynamically", "category": "foundation"},
    "-[NSObject isKindOfClass:]": {"lib": "Foundation", "purpose": "check class type", "category": "foundation"},
    "-[NSObject description]": {"lib": "Foundation", "purpose": "get object description", "category": "foundation"},
    "+[NSString stringWithFormat:]": {"lib": "Foundation", "purpose": "create formatted NSString", "category": "foundation"},
    "+[NSString stringWithUTF8String:]": {"lib": "Foundation", "purpose": "create NSString from UTF-8", "category": "foundation"},
    "+[NSString stringWithContentsOfFile:encoding:error:]": {"lib": "Foundation", "purpose": "read file to NSString", "category": "foundation"},
    "-[NSString UTF8String]": {"lib": "Foundation", "purpose": "get UTF-8 C string", "category": "foundation"},
    "-[NSString length]": {"lib": "Foundation", "purpose": "get string length", "category": "foundation"},
    "-[NSString isEqualToString:]": {"lib": "Foundation", "purpose": "compare strings", "category": "foundation"},
    "-[NSString containsString:]": {"lib": "Foundation", "purpose": "check substring", "category": "foundation"},
    "-[NSString hasPrefix:]": {"lib": "Foundation", "purpose": "check string prefix", "category": "foundation"},
    "-[NSString hasSuffix:]": {"lib": "Foundation", "purpose": "check string suffix", "category": "foundation"},
    "-[NSString stringByAppendingString:]": {"lib": "Foundation", "purpose": "append string", "category": "foundation"},
    "-[NSString stringByAppendingPathComponent:]": {"lib": "Foundation", "purpose": "append path component", "category": "foundation"},
    "-[NSString substringWithRange:]": {"lib": "Foundation", "purpose": "get substring by range", "category": "foundation"},
    "-[NSString componentsSeparatedByString:]": {"lib": "Foundation", "purpose": "split string", "category": "foundation"},
    "-[NSString lowercaseString]": {"lib": "Foundation", "purpose": "lowercase string", "category": "foundation"},
    "-[NSString uppercaseString]": {"lib": "Foundation", "purpose": "uppercase string", "category": "foundation"},
    "-[NSString dataUsingEncoding:]": {"lib": "Foundation", "purpose": "convert string to data", "category": "foundation"},
    "-[NSString writeToFile:atomically:encoding:error:]": {"lib": "Foundation", "purpose": "write string to file", "category": "foundation"},
    "+[NSMutableString stringWithCapacity:]": {"lib": "Foundation", "purpose": "create mutable string", "category": "foundation"},
    "-[NSMutableString appendString:]": {"lib": "Foundation", "purpose": "append to mutable string", "category": "foundation"},
    "-[NSMutableString appendFormat:]": {"lib": "Foundation", "purpose": "append formatted string", "category": "foundation"},
    "+[NSArray arrayWithObjects:count:]": {"lib": "Foundation", "purpose": "create array from C array", "category": "foundation"},
    "-[NSArray count]": {"lib": "Foundation", "purpose": "get array count", "category": "foundation"},
    "-[NSArray objectAtIndex:]": {"lib": "Foundation", "purpose": "get array element", "category": "foundation"},
    "-[NSArray objectAtIndexedSubscript:]": {"lib": "Foundation", "purpose": "array subscript access", "category": "foundation"},
    "-[NSArray containsObject:]": {"lib": "Foundation", "purpose": "check if array contains", "category": "foundation"},
    "-[NSArray enumerateObjectsUsingBlock:]": {"lib": "Foundation", "purpose": "enumerate array with block", "category": "foundation"},
    "-[NSArray filteredArrayUsingPredicate:]": {"lib": "Foundation", "purpose": "filter array", "category": "foundation"},
    "-[NSArray sortedArrayUsingComparator:]": {"lib": "Foundation", "purpose": "sort array", "category": "foundation"},
    "-[NSMutableArray addObject:]": {"lib": "Foundation", "purpose": "add to mutable array", "category": "foundation"},
    "-[NSMutableArray removeObjectAtIndex:]": {"lib": "Foundation", "purpose": "remove from mutable array", "category": "foundation"},
    "-[NSMutableArray insertObject:atIndex:]": {"lib": "Foundation", "purpose": "insert into mutable array", "category": "foundation"},
    "-[NSMutableArray removeAllObjects]": {"lib": "Foundation", "purpose": "clear mutable array", "category": "foundation"},
    "+[NSDictionary dictionaryWithObjects:forKeys:count:]": {"lib": "Foundation", "purpose": "create dictionary", "category": "foundation"},
    "-[NSDictionary objectForKey:]": {"lib": "Foundation", "purpose": "get dict value by key", "category": "foundation"},
    "-[NSDictionary objectForKeyedSubscript:]": {"lib": "Foundation", "purpose": "dict subscript access", "category": "foundation"},
    "-[NSDictionary count]": {"lib": "Foundation", "purpose": "get dict count", "category": "foundation"},
    "-[NSDictionary allKeys]": {"lib": "Foundation", "purpose": "get all dict keys", "category": "foundation"},
    "-[NSDictionary allValues]": {"lib": "Foundation", "purpose": "get all dict values", "category": "foundation"},
    "-[NSDictionary enumerateKeysAndObjectsUsingBlock:]": {"lib": "Foundation", "purpose": "enumerate dict", "category": "foundation"},
    "-[NSMutableDictionary setObject:forKey:]": {"lib": "Foundation", "purpose": "set dict value", "category": "foundation"},
    "-[NSMutableDictionary removeObjectForKey:]": {"lib": "Foundation", "purpose": "remove dict value", "category": "foundation"},
    "-[NSMutableDictionary removeAllObjects]": {"lib": "Foundation", "purpose": "clear dict", "category": "foundation"},
    "+[NSData dataWithBytes:length:]": {"lib": "Foundation", "purpose": "create NSData from bytes", "category": "foundation"},
    "+[NSData dataWithContentsOfFile:]": {"lib": "Foundation", "purpose": "read file to NSData", "category": "foundation"},
    "+[NSData dataWithContentsOfURL:]": {"lib": "Foundation", "purpose": "read URL to NSData", "category": "foundation"},
    "-[NSData bytes]": {"lib": "Foundation", "purpose": "get NSData byte pointer", "category": "foundation"},
    "-[NSData length]": {"lib": "Foundation", "purpose": "get NSData length", "category": "foundation"},
    "-[NSData writeToFile:atomically:]": {"lib": "Foundation", "purpose": "write NSData to file", "category": "foundation"},
    "-[NSData subdataWithRange:]": {"lib": "Foundation", "purpose": "get NSData subrange", "category": "foundation"},
    "+[NSFileManager defaultManager]": {"lib": "Foundation", "purpose": "get shared file manager", "category": "foundation"},
    "-[NSFileManager fileExistsAtPath:]": {"lib": "Foundation", "purpose": "check if file exists", "category": "foundation"},
    "-[NSFileManager createDirectoryAtPath:withIntermediateDirectories:attributes:error:]": {"lib": "Foundation", "purpose": "create directory", "category": "foundation"},
    "-[NSFileManager removeItemAtPath:error:]": {"lib": "Foundation", "purpose": "remove file/directory", "category": "foundation"},
    "-[NSFileManager copyItemAtPath:toPath:error:]": {"lib": "Foundation", "purpose": "copy file/directory", "category": "foundation"},
    "-[NSFileManager moveItemAtPath:toPath:error:]": {"lib": "Foundation", "purpose": "move file/directory", "category": "foundation"},
    "-[NSFileManager contentsOfDirectoryAtPath:error:]": {"lib": "Foundation", "purpose": "list directory", "category": "foundation"},
    "-[NSFileManager attributesOfItemAtPath:error:]": {"lib": "Foundation", "purpose": "get file attributes", "category": "foundation"},
    "+[NSJSONSerialization JSONObjectWithData:options:error:]": {"lib": "Foundation", "purpose": "parse JSON data", "category": "foundation"},
    "+[NSJSONSerialization dataWithJSONObject:options:error:]": {"lib": "Foundation", "purpose": "serialize to JSON", "category": "foundation"},
    "+[NSPropertyListSerialization propertyListWithData:options:format:error:]": {"lib": "Foundation", "purpose": "parse property list", "category": "foundation"},
    "+[NSURLSession sharedSession]": {"lib": "Foundation", "purpose": "get shared URL session", "category": "foundation"},
    "+[NSURLSession sessionWithConfiguration:]": {"lib": "Foundation", "purpose": "create URL session", "category": "foundation"},
    "-[NSURLSession dataTaskWithRequest:completionHandler:]": {"lib": "Foundation", "purpose": "create data task", "category": "foundation"},
    "-[NSURLSession downloadTaskWithRequest:completionHandler:]": {"lib": "Foundation", "purpose": "create download task", "category": "foundation"},
    "-[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]": {"lib": "Foundation", "purpose": "create upload task", "category": "foundation"},
    "+[NSURLRequest requestWithURL:]": {"lib": "Foundation", "purpose": "create URL request", "category": "foundation"},
    "+[NSNotificationCenter defaultCenter]": {"lib": "Foundation", "purpose": "get default notification center", "category": "foundation"},
    "-[NSNotificationCenter addObserver:selector:name:object:]": {"lib": "Foundation", "purpose": "add notification observer", "category": "foundation"},
    "-[NSNotificationCenter removeObserver:]": {"lib": "Foundation", "purpose": "remove notification observer", "category": "foundation"},
    "-[NSNotificationCenter postNotificationName:object:]": {"lib": "Foundation", "purpose": "post notification", "category": "foundation"},
    "-[NSUserDefaults objectForKey:]": {"lib": "Foundation", "purpose": "read user defaults value", "category": "foundation"},
    "-[NSUserDefaults setObject:forKey:]": {"lib": "Foundation", "purpose": "write user defaults value", "category": "foundation"},
    "-[NSUserDefaults synchronize]": {"lib": "Foundation", "purpose": "sync user defaults to disk", "category": "foundation"},
    "+[NSUserDefaults standardUserDefaults]": {"lib": "Foundation", "purpose": "get standard user defaults", "category": "foundation"},
    "+[NSDate date]": {"lib": "Foundation", "purpose": "create current date", "category": "foundation"},
    "+[NSDate dateWithTimeIntervalSince1970:]": {"lib": "Foundation", "purpose": "create date from epoch", "category": "foundation"},
    "-[NSDate timeIntervalSince1970]": {"lib": "Foundation", "purpose": "get epoch timestamp", "category": "foundation"},
    "-[NSDate timeIntervalSinceDate:]": {"lib": "Foundation", "purpose": "time interval between dates", "category": "foundation"},
    "+[NSDateFormatter new]": {"lib": "Foundation", "purpose": "create date formatter", "category": "foundation"},
    "+[NSUUID UUID]": {"lib": "Foundation", "purpose": "generate UUID", "category": "foundation"},
    "-[NSUUID UUIDString]": {"lib": "Foundation", "purpose": "get UUID string representation", "category": "foundation"},
    "-[NSError localizedDescription]": {"lib": "Foundation", "purpose": "get error description", "category": "foundation"},
    "-[NSError domain]": {"lib": "Foundation", "purpose": "get error domain", "category": "foundation"},
    "-[NSError code]": {"lib": "Foundation", "purpose": "get error code", "category": "foundation"},
    "+[NSError errorWithDomain:code:userInfo:]": {"lib": "Foundation", "purpose": "create NSError", "category": "foundation"},
    "+[NSBundle mainBundle]": {"lib": "Foundation", "purpose": "get main app bundle", "category": "foundation"},
    "-[NSBundle pathForResource:ofType:]": {"lib": "Foundation", "purpose": "get bundle resource path", "category": "foundation"},
    "-[NSBundle bundleIdentifier]": {"lib": "Foundation", "purpose": "get bundle ID", "category": "foundation"},
    "+[NSProcessInfo processInfo]": {"lib": "Foundation", "purpose": "get process info singleton", "category": "foundation"},
    "-[NSProcessInfo processName]": {"lib": "Foundation", "purpose": "get process name", "category": "foundation"},
    "-[NSProcessInfo arguments]": {"lib": "Foundation", "purpose": "get command line arguments", "category": "foundation"},
    "-[NSProcessInfo environment]": {"lib": "Foundation", "purpose": "get environment dict", "category": "foundation"},
    "-[NSProcessInfo operatingSystemVersion]": {"lib": "Foundation", "purpose": "get OS version", "category": "foundation"},
    "-[NSProcessInfo physicalMemory]": {"lib": "Foundation", "purpose": "get physical memory bytes", "category": "foundation"},
    "-[NSProcessInfo processorCount]": {"lib": "Foundation", "purpose": "get CPU count", "category": "foundation"},
    "+[NSThread currentThread]": {"lib": "Foundation", "purpose": "get current thread", "category": "foundation"},
    "+[NSThread isMainThread]": {"lib": "Foundation", "purpose": "check if main thread", "category": "foundation"},
    "-[NSThread start]": {"lib": "Foundation", "purpose": "start NSThread", "category": "foundation"},
    "-[NSThread cancel]": {"lib": "Foundation", "purpose": "cancel NSThread", "category": "foundation"},
    "+[NSThread sleepForTimeInterval:]": {"lib": "Foundation", "purpose": "sleep thread", "category": "foundation"},
    "-[NSLock lock]": {"lib": "Foundation", "purpose": "acquire NSLock", "category": "foundation"},
    "-[NSLock unlock]": {"lib": "Foundation", "purpose": "release NSLock", "category": "foundation"},
    "-[NSRecursiveLock lock]": {"lib": "Foundation", "purpose": "acquire recursive NSLock", "category": "foundation"},
    "-[NSRecursiveLock unlock]": {"lib": "Foundation", "purpose": "release recursive NSLock", "category": "foundation"},
    "-[NSCondition wait]": {"lib": "Foundation", "purpose": "wait on NSCondition", "category": "foundation"},
    "-[NSCondition signal]": {"lib": "Foundation", "purpose": "signal NSCondition", "category": "foundation"},
    "-[NSCondition broadcast]": {"lib": "Foundation", "purpose": "broadcast NSCondition", "category": "foundation"},
    "+[NSOperationQueue mainQueue]": {"lib": "Foundation", "purpose": "get main operation queue", "category": "foundation"},
    "-[NSOperationQueue addOperationWithBlock:]": {"lib": "Foundation", "purpose": "add block operation", "category": "foundation"},
    "-[NSOperationQueue waitUntilAllOperationsAreFinished]": {"lib": "Foundation", "purpose": "wait for all operations", "category": "foundation"},
    "-[NSTimer scheduledTimerWithTimeInterval:repeats:block:]": {"lib": "Foundation", "purpose": "schedule timer", "category": "foundation"},
    "-[NSTimer invalidate]": {"lib": "Foundation", "purpose": "invalidate timer", "category": "foundation"},
    "+[NSRegularExpression regularExpressionWithPattern:options:error:]": {"lib": "Foundation", "purpose": "create regex", "category": "foundation"},
    "-[NSRegularExpression matchesInString:options:range:]": {"lib": "Foundation", "purpose": "find regex matches", "category": "foundation"},
    "-[NSRegularExpression firstMatchInString:options:range:]": {"lib": "Foundation", "purpose": "find first regex match", "category": "foundation"},

    # =======================================================================
    # Swift Runtime (~60)
    # =======================================================================
    "_swift_allocObject": {"lib": "swift_runtime", "purpose": "allocate Swift object", "category": "swift"},
    "_swift_deallocObject": {"lib": "swift_runtime", "purpose": "deallocate Swift object", "category": "swift"},
    "_swift_retain": {"lib": "swift_runtime", "purpose": "Swift ARC retain", "category": "swift"},
    "_swift_release": {"lib": "swift_runtime", "purpose": "Swift ARC release", "category": "swift"},
    "_swift_retain_n": {"lib": "swift_runtime", "purpose": "Swift retain n times", "category": "swift"},
    "_swift_release_n": {"lib": "swift_runtime", "purpose": "Swift release n times", "category": "swift"},
    "_swift_unownedRetain": {"lib": "swift_runtime", "purpose": "Swift unowned retain", "category": "swift"},
    "_swift_unownedRelease": {"lib": "swift_runtime", "purpose": "Swift unowned release", "category": "swift"},
    "_swift_weakLoadStrong": {"lib": "swift_runtime", "purpose": "load strong ref from weak", "category": "swift"},
    "_swift_weakAssign": {"lib": "swift_runtime", "purpose": "assign weak reference", "category": "swift"},
    "_swift_weakInit": {"lib": "swift_runtime", "purpose": "initialize weak reference", "category": "swift"},
    "_swift_weakDestroy": {"lib": "swift_runtime", "purpose": "destroy weak reference", "category": "swift"},
    "_swift_isUniquelyReferenced": {"lib": "swift_runtime", "purpose": "check unique reference (COW)", "category": "swift"},
    "_swift_getTypeByMangledNameInContext": {"lib": "swift_runtime", "purpose": "resolve type by mangled name", "category": "swift"},
    "_swift_getExistentialTypeMetadata": {"lib": "swift_runtime", "purpose": "get protocol type metadata", "category": "swift"},
    "_swift_dynamicCast": {"lib": "swift_runtime", "purpose": "Swift dynamic cast (as?/as!)", "category": "swift"},
    "_swift_dynamicCastClass": {"lib": "swift_runtime", "purpose": "Swift class dynamic cast", "category": "swift"},
    "_swift_dynamicCastObjCClass": {"lib": "swift_runtime", "purpose": "Swift ObjC class dynamic cast", "category": "swift"},
    "_swift_conformsToProtocol": {"lib": "swift_runtime", "purpose": "check Swift protocol conformance", "category": "swift"},
    "_swift_allocBox": {"lib": "swift_runtime", "purpose": "allocate Swift box (heap closure capture)", "category": "swift"},
    "_swift_deallocBox": {"lib": "swift_runtime", "purpose": "deallocate Swift box", "category": "swift"},
    "_swift_makeBoxUnique": {"lib": "swift_runtime", "purpose": "make box unique (COW)", "category": "swift"},
    "_swift_projectBox": {"lib": "swift_runtime", "purpose": "project value from box", "category": "swift"},
    "_swift_bridgeObjectRetain": {"lib": "swift_runtime", "purpose": "retain bridged ObjC object", "category": "swift"},
    "_swift_bridgeObjectRelease": {"lib": "swift_runtime", "purpose": "release bridged ObjC object", "category": "swift"},
    "_swift_errorRetain": {"lib": "swift_runtime", "purpose": "retain Swift Error", "category": "swift"},
    "_swift_errorRelease": {"lib": "swift_runtime", "purpose": "release Swift Error", "category": "swift"},
    "_swift_willThrow": {"lib": "swift_runtime", "purpose": "Swift will throw error (for debugger)", "category": "swift"},
    "_swift_getObjCClassMetadata": {"lib": "swift_runtime", "purpose": "get ObjC interop metadata", "category": "swift"},
    "_swift_lookUpClassMethod": {"lib": "swift_runtime", "purpose": "look up class method vtable entry", "category": "swift"},
    "_swift_allocateGenericClassMetadata": {"lib": "swift_runtime", "purpose": "allocate generic class metadata", "category": "swift"},
    "_swift_allocateGenericValueMetadata": {"lib": "swift_runtime", "purpose": "allocate generic value metadata", "category": "swift"},
    "_swift_initClassMetadata2": {"lib": "swift_runtime", "purpose": "initialize class metadata", "category": "swift"},
    "_swift_initStructMetadata": {"lib": "swift_runtime", "purpose": "initialize struct metadata", "category": "swift"},
    "_swift_initEnumMetadataSingleCase": {"lib": "swift_runtime", "purpose": "init single-case enum metadata", "category": "swift"},
    "_swift_initEnumMetadataMultiPayload": {"lib": "swift_runtime", "purpose": "init multi-payload enum metadata", "category": "swift"},
    "_swift_getAssociatedTypeWitness": {"lib": "swift_runtime", "purpose": "get associated type from witness", "category": "swift"},
    "_swift_getWitnessTable": {"lib": "swift_runtime", "purpose": "get protocol witness table", "category": "swift"},
    "_swift_once": {"lib": "swift_runtime", "purpose": "Swift one-time initialization", "category": "swift"},
    "_swift_beginAccess": {"lib": "swift_runtime", "purpose": "begin exclusivity access check", "category": "swift"},
    "_swift_endAccess": {"lib": "swift_runtime", "purpose": "end exclusivity access check", "category": "swift"},
    "_swift_task_create": {"lib": "swift_runtime", "purpose": "create Swift concurrency task", "category": "swift_concurrency"},
    "_swift_task_switch": {"lib": "swift_runtime", "purpose": "switch Swift task (async/await)", "category": "swift_concurrency"},
    "_swift_task_future_wait": {"lib": "swift_runtime", "purpose": "await Swift task future", "category": "swift_concurrency"},
    "_swift_taskGroup_create": {"lib": "swift_runtime", "purpose": "create Swift task group", "category": "swift_concurrency"},
    "_swift_taskGroup_addPending": {"lib": "swift_runtime", "purpose": "add pending task to group", "category": "swift_concurrency"},
    "_swift_taskGroup_wait": {"lib": "swift_runtime", "purpose": "await task group completion", "category": "swift_concurrency"},
    "_swift_asyncLet_begin": {"lib": "swift_runtime", "purpose": "begin async let binding", "category": "swift_concurrency"},
    "_swift_asyncLet_end": {"lib": "swift_runtime", "purpose": "end async let binding", "category": "swift_concurrency"},
    "_swift_continuation_resume": {"lib": "swift_runtime", "purpose": "resume continuation (withCheckedContinuation)", "category": "swift_concurrency"},
}


_LIBUV_SIGNATURES: dict[str, dict[str, str]] = {
    # Event loop
    "_uv_loop_init": {"lib": "libuv", "purpose": "Initialize event loop", "category": "event_loop"},
    "_uv_loop_close": {"lib": "libuv", "purpose": "Close event loop", "category": "event_loop"},
    "_uv_run": {"lib": "libuv", "purpose": "Run the event loop", "category": "event_loop"},
    "_uv_stop": {"lib": "libuv", "purpose": "Stop the event loop", "category": "event_loop"},
    "_uv_default_loop": {"lib": "libuv", "purpose": "Get default event loop", "category": "event_loop"},
    # TCP
    "_uv_tcp_init": {"lib": "libuv", "purpose": "Initialize TCP handle", "category": "network"},
    "_uv_tcp_bind": {"lib": "libuv", "purpose": "Bind TCP handle to address", "category": "network"},
    "_uv_tcp_connect": {"lib": "libuv", "purpose": "Establish TCP connection", "category": "network"},
    "_uv_listen": {"lib": "libuv", "purpose": "Start listening for connections", "category": "network"},
    "_uv_accept": {"lib": "libuv", "purpose": "Accept incoming connection", "category": "network"},
    # UDP
    "_uv_udp_init": {"lib": "libuv", "purpose": "Initialize UDP handle", "category": "network"},
    "_uv_udp_bind": {"lib": "libuv", "purpose": "Bind UDP handle to address", "category": "network"},
    "_uv_udp_send": {"lib": "libuv", "purpose": "Send UDP datagram", "category": "network"},
    "_uv_udp_recv_start": {"lib": "libuv", "purpose": "Start receiving UDP datagrams", "category": "network"},
    "_uv_udp_recv_stop": {"lib": "libuv", "purpose": "Stop receiving UDP datagrams", "category": "network"},
    # Stream I/O
    "_uv_read_start": {"lib": "libuv", "purpose": "Start reading from stream", "category": "io"},
    "_uv_read_stop": {"lib": "libuv", "purpose": "Stop reading from stream", "category": "io"},
    "_uv_write": {"lib": "libuv", "purpose": "Write data to stream", "category": "io"},
    "_uv_shutdown": {"lib": "libuv", "purpose": "Shutdown write side of stream", "category": "io"},
    # Handle lifecycle
    "_uv_close": {"lib": "libuv", "purpose": "Close handle", "category": "event_loop"},
    "_uv_is_active": {"lib": "libuv", "purpose": "Check if handle is active", "category": "event_loop"},
    "_uv_is_closing": {"lib": "libuv", "purpose": "Check if handle is closing", "category": "event_loop"},
    "_uv_ref": {"lib": "libuv", "purpose": "Reference handle (keeps loop alive)", "category": "event_loop"},
    "_uv_unref": {"lib": "libuv", "purpose": "Unreference handle", "category": "event_loop"},
    # Timer
    "_uv_timer_init": {"lib": "libuv", "purpose": "Initialize timer handle", "category": "event_loop"},
    "_uv_timer_start": {"lib": "libuv", "purpose": "Start timer", "category": "event_loop"},
    "_uv_timer_stop": {"lib": "libuv", "purpose": "Stop timer", "category": "event_loop"},
    "_uv_timer_again": {"lib": "libuv", "purpose": "Restart timer with repeat value", "category": "event_loop"},
    # Idle
    "_uv_idle_init": {"lib": "libuv", "purpose": "Initialize idle handle", "category": "event_loop"},
    "_uv_idle_start": {"lib": "libuv", "purpose": "Start idle handle", "category": "event_loop"},
    "_uv_idle_stop": {"lib": "libuv", "purpose": "Stop idle handle", "category": "event_loop"},
    # Async
    "_uv_async_init": {"lib": "libuv", "purpose": "Initialize async handle for cross-thread signaling", "category": "threading"},
    "_uv_async_send": {"lib": "libuv", "purpose": "Send async notification", "category": "threading"},
    # Signal
    "_uv_signal_init": {"lib": "libuv", "purpose": "Initialize signal handle", "category": "event_loop"},
    "_uv_signal_start": {"lib": "libuv", "purpose": "Start watching for signal", "category": "event_loop"},
    "_uv_signal_stop": {"lib": "libuv", "purpose": "Stop watching for signal", "category": "event_loop"},
    # Filesystem
    "_uv_fs_open": {"lib": "libuv", "purpose": "Async file open", "category": "io"},
    "_uv_fs_close": {"lib": "libuv", "purpose": "Async file close", "category": "io"},
    "_uv_fs_read": {"lib": "libuv", "purpose": "Async file read", "category": "io"},
    "_uv_fs_write": {"lib": "libuv", "purpose": "Async file write", "category": "io"},
    "_uv_fs_stat": {"lib": "libuv", "purpose": "Async file stat", "category": "io"},
    "_uv_fs_unlink": {"lib": "libuv", "purpose": "Async file delete", "category": "io"},
    "_uv_fs_mkdir": {"lib": "libuv", "purpose": "Async create directory", "category": "io"},
    "_uv_fs_scandir": {"lib": "libuv", "purpose": "Async directory scan", "category": "io"},
    # Pipe
    "_uv_pipe_init": {"lib": "libuv", "purpose": "Initialize pipe handle", "category": "io"},
    "_uv_pipe_open": {"lib": "libuv", "purpose": "Open existing fd as pipe", "category": "io"},
    "_uv_pipe_bind": {"lib": "libuv", "purpose": "Bind pipe to name", "category": "io"},
    "_uv_pipe_connect": {"lib": "libuv", "purpose": "Connect pipe to name", "category": "io"},
    # Process
    "_uv_spawn": {"lib": "libuv", "purpose": "Spawn child process", "category": "process"},
    "_uv_process_kill": {"lib": "libuv", "purpose": "Send signal to child process", "category": "process"},
    # Threading
    "_uv_thread_create": {"lib": "libuv", "purpose": "Create thread", "category": "threading"},
    "_uv_thread_join": {"lib": "libuv", "purpose": "Join thread", "category": "threading"},
    "_uv_mutex_init": {"lib": "libuv", "purpose": "Initialize mutex", "category": "threading"},
    "_uv_mutex_lock": {"lib": "libuv", "purpose": "Lock mutex", "category": "threading"},
    "_uv_mutex_unlock": {"lib": "libuv", "purpose": "Unlock mutex", "category": "threading"},
    "_uv_mutex_destroy": {"lib": "libuv", "purpose": "Destroy mutex", "category": "threading"},
    "_uv_rwlock_init": {"lib": "libuv", "purpose": "Initialize read-write lock", "category": "threading"},
    "_uv_rwlock_rdlock": {"lib": "libuv", "purpose": "Acquire read lock", "category": "threading"},
    "_uv_rwlock_wrlock": {"lib": "libuv", "purpose": "Acquire write lock", "category": "threading"},
    "_uv_rwlock_rdunlock": {"lib": "libuv", "purpose": "Release read lock", "category": "threading"},
    "_uv_rwlock_wrunlock": {"lib": "libuv", "purpose": "Release write lock", "category": "threading"},
    # DNS / address
    "_uv_getaddrinfo": {"lib": "libuv", "purpose": "Async DNS resolution (getaddrinfo)", "category": "network"},
    "_uv_freeaddrinfo": {"lib": "libuv", "purpose": "Free addrinfo result", "category": "network"},
    "_uv_ip4_addr": {"lib": "libuv", "purpose": "Convert IPv4 string to sockaddr", "category": "network"},
    "_uv_ip6_addr": {"lib": "libuv", "purpose": "Convert IPv6 string to sockaddr", "category": "network"},
    # Utility
    "_uv_strerror": {"lib": "libuv", "purpose": "Get error string", "category": "event_loop"},
    "_uv_err_name": {"lib": "libuv", "purpose": "Get error name constant", "category": "event_loop"},
    "_uv_version": {"lib": "libuv", "purpose": "Get libuv version number", "category": "event_loop"},
    "_uv_version_string": {"lib": "libuv", "purpose": "Get libuv version string", "category": "event_loop"},
}


# ---------------------------------------------------------------------------
# libevent (event-driven I/O)  ~26 imza
# ---------------------------------------------------------------------------

_LIBEVENT_SIGNATURES: dict[str, dict[str, str]] = {
    "_event_base_new": {"lib": "libevent", "purpose": "Create new event base", "category": "event_loop"},
    "_event_base_free": {"lib": "libevent", "purpose": "Free event base", "category": "event_loop"},
    "_event_base_dispatch": {"lib": "libevent", "purpose": "Dispatch events (blocking)", "category": "event_loop"},
    "_event_base_loop": {"lib": "libevent", "purpose": "Run event loop with flags", "category": "event_loop"},
    "_event_base_loopbreak": {"lib": "libevent", "purpose": "Break out of event loop", "category": "event_loop"},
    "_event_base_loopexit": {"lib": "libevent", "purpose": "Schedule event loop exit", "category": "event_loop"},
    "_event_new": {"lib": "libevent", "purpose": "Create new event", "category": "event_loop"},
    "_event_free": {"lib": "libevent", "purpose": "Free event", "category": "event_loop"},
    "_event_add": {"lib": "libevent", "purpose": "Add event to pending set", "category": "event_loop"},
    "_event_del": {"lib": "libevent", "purpose": "Remove event from pending set", "category": "event_loop"},
    "_event_assign": {"lib": "libevent", "purpose": "Assign event fields (no alloc)", "category": "event_loop"},
    "_evbuffer_new": {"lib": "libevent", "purpose": "Create new evbuffer", "category": "io"},
    "_evbuffer_free": {"lib": "libevent", "purpose": "Free evbuffer", "category": "io"},
    "_evbuffer_add": {"lib": "libevent", "purpose": "Append data to evbuffer", "category": "io"},
    "_evbuffer_remove": {"lib": "libevent", "purpose": "Remove data from evbuffer", "category": "io"},
    "_evbuffer_get_length": {"lib": "libevent", "purpose": "Get evbuffer data length", "category": "io"},
    "_evbuffer_readln": {"lib": "libevent", "purpose": "Read line from evbuffer", "category": "io"},
    "_bufferevent_socket_new": {"lib": "libevent", "purpose": "Create socket-based bufferevent", "category": "network"},
    "_bufferevent_free": {"lib": "libevent", "purpose": "Free bufferevent", "category": "network"},
    "_bufferevent_setcb": {"lib": "libevent", "purpose": "Set bufferevent callbacks", "category": "network"},
    "_bufferevent_enable": {"lib": "libevent", "purpose": "Enable bufferevent reading/writing", "category": "network"},
    "_bufferevent_disable": {"lib": "libevent", "purpose": "Disable bufferevent reading/writing", "category": "network"},
    "_evconnlistener_new_bind": {"lib": "libevent", "purpose": "Create listener, bind and listen", "category": "network"},
    "_evconnlistener_free": {"lib": "libevent", "purpose": "Free connection listener", "category": "network"},
    "_evconnlistener_set_cb": {"lib": "libevent", "purpose": "Set listener accept callback", "category": "network"},
    "_evhttp_new": {"lib": "libevent", "purpose": "Create HTTP server", "category": "network"},
    "_evhttp_bind_socket": {"lib": "libevent", "purpose": "Bind HTTP server to port", "category": "network"},
    "_evhttp_set_cb": {"lib": "libevent", "purpose": "Set HTTP request handler", "category": "network"},
    "_evhttp_send_reply": {"lib": "libevent", "purpose": "Send HTTP response", "category": "network"},
}


# ---------------------------------------------------------------------------
# PCRE2 / POSIX regex / RE2  ~18 imza
# ---------------------------------------------------------------------------

_REGEX_SIGNATURES: dict[str, dict[str, str]] = {
    "_pcre2_compile_8": {"lib": "pcre2", "purpose": "Compile regex pattern (8-bit)", "category": "regex"},
    "_pcre2_match_8": {"lib": "pcre2", "purpose": "Match compiled regex (8-bit)", "category": "regex"},
    "_pcre2_match_data_create_from_pattern_8": {"lib": "pcre2", "purpose": "Create match data block from pattern", "category": "regex"},
    "_pcre2_get_ovector_pointer_8": {"lib": "pcre2", "purpose": "Get output vector pointer", "category": "regex"},
    "_pcre2_get_ovector_count_8": {"lib": "pcre2", "purpose": "Get output vector pair count", "category": "regex"},
    "_pcre2_code_free_8": {"lib": "pcre2", "purpose": "Free compiled regex", "category": "regex"},
    "_pcre2_match_data_free_8": {"lib": "pcre2", "purpose": "Free match data block", "category": "regex"},
    "_pcre2_pattern_info_8": {"lib": "pcre2", "purpose": "Query pattern information", "category": "regex"},
    "_pcre2_jit_compile_8": {"lib": "pcre2", "purpose": "JIT compile regex for speed", "category": "regex"},
    "_pcre2_jit_match_8": {"lib": "pcre2", "purpose": "Match using JIT-compiled regex", "category": "regex"},
    "_pcre2_substitute_8": {"lib": "pcre2", "purpose": "Search and replace with regex", "category": "regex"},
    "_regcomp": {"lib": "libc", "purpose": "Compile POSIX regular expression", "category": "regex"},
    "_regexec": {"lib": "libc", "purpose": "Execute POSIX regular expression", "category": "regex"},
    "_regfree": {"lib": "libc", "purpose": "Free compiled POSIX regex", "category": "regex"},
    "_regerror": {"lib": "libc", "purpose": "Get regex error message", "category": "regex"},
    "__ZN3re22RE2C1": {"lib": "re2", "purpose": "RE2 regex constructor (C++ mangled prefix)", "category": "regex"},
    "__ZN3re22RE211FullMatchN": {"lib": "re2", "purpose": "RE2::FullMatchN (C++ mangled prefix)", "category": "regex"},
    "__ZN3re22RE214PartialMatchN": {"lib": "re2", "purpose": "RE2::PartialMatchN (C++ mangled prefix)", "category": "regex"},
}


# ---------------------------------------------------------------------------
# ICU (International Components for Unicode)  ~30 imza
# ---------------------------------------------------------------------------

_ICU_SIGNATURES: dict[str, dict[str, str]] = {
    "_u_init": {"lib": "icu", "purpose": "Initialize ICU library", "category": "unicode"},
    "_u_cleanup": {"lib": "icu", "purpose": "Clean up ICU library resources", "category": "unicode"},
    "_u_errorName": {"lib": "icu", "purpose": "Get ICU error code name", "category": "unicode"},
    "_ucnv_open": {"lib": "icu", "purpose": "Open charset converter", "category": "unicode"},
    "_ucnv_close": {"lib": "icu", "purpose": "Close charset converter", "category": "unicode"},
    "_ucnv_convert": {"lib": "icu", "purpose": "Convert between charsets", "category": "unicode"},
    "_ucnv_fromUChars": {"lib": "icu", "purpose": "Convert UChars to charset", "category": "unicode"},
    "_ucnv_toUChars": {"lib": "icu", "purpose": "Convert charset to UChars", "category": "unicode"},
    "_ubrk_open": {"lib": "icu", "purpose": "Open break iterator", "category": "unicode"},
    "_ubrk_close": {"lib": "icu", "purpose": "Close break iterator", "category": "unicode"},
    "_ubrk_next": {"lib": "icu", "purpose": "Move to next boundary", "category": "unicode"},
    "_ubrk_previous": {"lib": "icu", "purpose": "Move to previous boundary", "category": "unicode"},
    "_ubrk_first": {"lib": "icu", "purpose": "Move to first boundary", "category": "unicode"},
    "_ubrk_last": {"lib": "icu", "purpose": "Move to last boundary", "category": "unicode"},
    "_ucol_open": {"lib": "icu", "purpose": "Open collator for locale", "category": "unicode"},
    "_ucol_close": {"lib": "icu", "purpose": "Close collator", "category": "unicode"},
    "_ucol_strcoll": {"lib": "icu", "purpose": "Compare strings with collation", "category": "unicode"},
    "_ucol_getSortKey": {"lib": "icu", "purpose": "Get sort key for string", "category": "unicode"},
    "_unorm2_getNFCInstance": {"lib": "icu", "purpose": "Get NFC normalizer singleton", "category": "unicode"},
    "_unorm2_getNFDInstance": {"lib": "icu", "purpose": "Get NFD normalizer singleton", "category": "unicode"},
    "_unorm2_normalize": {"lib": "icu", "purpose": "Normalize Unicode string", "category": "unicode"},
    "_unorm2_isNormalized": {"lib": "icu", "purpose": "Check if string is normalized", "category": "unicode"},
    "_uregex_open": {"lib": "icu", "purpose": "Compile ICU regex pattern", "category": "unicode"},
    "_uregex_close": {"lib": "icu", "purpose": "Close ICU regex", "category": "unicode"},
    "_uregex_find": {"lib": "icu", "purpose": "Find next regex match", "category": "unicode"},
    "_uregex_group": {"lib": "icu", "purpose": "Get regex match group", "category": "unicode"},
    "_uidna_openUTS46": {"lib": "icu", "purpose": "Open IDNA UTS#46 processor", "category": "unicode"},
    "_uidna_close": {"lib": "icu", "purpose": "Close IDNA processor", "category": "unicode"},
    "_uidna_nameToASCII": {"lib": "icu", "purpose": "Convert domain name to ASCII (punycode)", "category": "unicode"},
    "_uloc_getDefault": {"lib": "icu", "purpose": "Get default locale", "category": "unicode"},
    "_uloc_setDefault": {"lib": "icu", "purpose": "Set default locale", "category": "unicode"},
    "_uloc_getLanguage": {"lib": "icu", "purpose": "Get language from locale", "category": "unicode"},
    "_uloc_getCountry": {"lib": "icu", "purpose": "Get country from locale", "category": "unicode"},
    "_udat_open": {"lib": "icu", "purpose": "Open date/time formatter", "category": "unicode"},
    "_udat_close": {"lib": "icu", "purpose": "Close date/time formatter", "category": "unicode"},
    "_udat_format": {"lib": "icu", "purpose": "Format date/time to string", "category": "unicode"},
    "_udat_parse": {"lib": "icu", "purpose": "Parse date/time from string", "category": "unicode"},
    "_unum_open": {"lib": "icu", "purpose": "Open number formatter", "category": "unicode"},
    "_unum_close": {"lib": "icu", "purpose": "Close number formatter", "category": "unicode"},
    "_unum_formatDouble": {"lib": "icu", "purpose": "Format double to string", "category": "unicode"},
    "_unum_parseDouble": {"lib": "icu", "purpose": "Parse double from string", "category": "unicode"},
}


# ---------------------------------------------------------------------------
# Math / BLAS / LAPACK / Accelerate  ~76 imza
# ---------------------------------------------------------------------------

_MATH_SIGNATURES: dict[str, dict[str, str]] = {
    # C math (libm) - trigonometric
    "_sin": {"lib": "libm", "purpose": "Sine", "category": "math"},
    "_cos": {"lib": "libm", "purpose": "Cosine", "category": "math"},
    "_tan": {"lib": "libm", "purpose": "Tangent", "category": "math"},
    "_asin": {"lib": "libm", "purpose": "Arc sine", "category": "math"},
    "_acos": {"lib": "libm", "purpose": "Arc cosine", "category": "math"},
    "_atan": {"lib": "libm", "purpose": "Arc tangent", "category": "math"},
    "_atan2": {"lib": "libm", "purpose": "Arc tangent of y/x (two-argument)", "category": "math"},
    "_sinh": {"lib": "libm", "purpose": "Hyperbolic sine", "category": "math"},
    "_cosh": {"lib": "libm", "purpose": "Hyperbolic cosine", "category": "math"},
    "_tanh": {"lib": "libm", "purpose": "Hyperbolic tangent", "category": "math"},
    "_asinh": {"lib": "libm", "purpose": "Inverse hyperbolic sine", "category": "math"},
    "_acosh": {"lib": "libm", "purpose": "Inverse hyperbolic cosine", "category": "math"},
    "_atanh": {"lib": "libm", "purpose": "Inverse hyperbolic tangent", "category": "math"},
    "_exp": {"lib": "libm", "purpose": "Exponential (e^x)", "category": "math"},
    "_exp2": {"lib": "libm", "purpose": "Base-2 exponential (2^x)", "category": "math"},
    "_log": {"lib": "libm", "purpose": "Natural logarithm", "category": "math"},
    "_log2": {"lib": "libm", "purpose": "Base-2 logarithm", "category": "math"},
    "_log10": {"lib": "libm", "purpose": "Base-10 logarithm", "category": "math"},
    "_pow": {"lib": "libm", "purpose": "Power (x^y)", "category": "math"},
    "_sqrt": {"lib": "libm", "purpose": "Square root", "category": "math"},
    "_cbrt": {"lib": "libm", "purpose": "Cube root", "category": "math"},
    "_ceil": {"lib": "libm", "purpose": "Round up to integer", "category": "math"},
    "_floor": {"lib": "libm", "purpose": "Round down to integer", "category": "math"},
    "_round": {"lib": "libm", "purpose": "Round to nearest integer", "category": "math"},
    "_trunc": {"lib": "libm", "purpose": "Truncate toward zero", "category": "math"},
    "_fabs": {"lib": "libm", "purpose": "Absolute value (float)", "category": "math"},
    "_fmod": {"lib": "libm", "purpose": "Floating-point remainder", "category": "math"},
    "_remainder": {"lib": "libm", "purpose": "IEEE remainder", "category": "math"},
    "_fma": {"lib": "libm", "purpose": "Fused multiply-add (a*b+c)", "category": "math"},
    "_hypot": {"lib": "libm", "purpose": "Hypotenuse (sqrt(x^2+y^2))", "category": "math"},
    "_ldexp": {"lib": "libm", "purpose": "Load exponent (x * 2^n)", "category": "math"},
    "_frexp": {"lib": "libm", "purpose": "Extract significand and exponent", "category": "math"},
    "_modf": {"lib": "libm", "purpose": "Split into integer and fractional parts", "category": "math"},
    "_copysign": {"lib": "libm", "purpose": "Copy sign of number", "category": "math"},
    "_nextafter": {"lib": "libm", "purpose": "Next representable float toward y", "category": "math"},
    "_isnan": {"lib": "libm", "purpose": "Check for NaN", "category": "math"},
    "_isinf": {"lib": "libm", "purpose": "Check for infinity", "category": "math"},
    "_isfinite": {"lib": "libm", "purpose": "Check for finite value", "category": "math"},
    "_isnormal": {"lib": "libm", "purpose": "Check for normal (non-zero, non-denorm)", "category": "math"},
    # BLAS
    "_cblas_sgemm": {"lib": "blas", "purpose": "Single-precision general matrix multiply", "category": "math"},
    "_cblas_dgemm": {"lib": "blas", "purpose": "Double-precision general matrix multiply", "category": "math"},
    "_cblas_sgemv": {"lib": "blas", "purpose": "Single-precision matrix-vector multiply", "category": "math"},
    "_cblas_dgemv": {"lib": "blas", "purpose": "Double-precision matrix-vector multiply", "category": "math"},
    "_cblas_saxpy": {"lib": "blas", "purpose": "Single-precision y += a*x (AXPY)", "category": "math"},
    "_cblas_daxpy": {"lib": "blas", "purpose": "Double-precision y += a*x (AXPY)", "category": "math"},
    "_cblas_sdot": {"lib": "blas", "purpose": "Single-precision dot product", "category": "math"},
    "_cblas_ddot": {"lib": "blas", "purpose": "Double-precision dot product", "category": "math"},
    "_cblas_scopy": {"lib": "blas", "purpose": "Single-precision vector copy", "category": "math"},
    "_cblas_dcopy": {"lib": "blas", "purpose": "Double-precision vector copy", "category": "math"},
    "_cblas_sscal": {"lib": "blas", "purpose": "Single-precision vector scale", "category": "math"},
    "_cblas_dscal": {"lib": "blas", "purpose": "Double-precision vector scale", "category": "math"},
    "_cblas_snrm2": {"lib": "blas", "purpose": "Single-precision Euclidean norm", "category": "math"},
    "_cblas_dnrm2": {"lib": "blas", "purpose": "Double-precision Euclidean norm", "category": "math"},
    "_cblas_sasum": {"lib": "blas", "purpose": "Single-precision sum of absolute values", "category": "math"},
    "_cblas_dasum": {"lib": "blas", "purpose": "Double-precision sum of absolute values", "category": "math"},
    # LAPACK
    "_sgesv_": {"lib": "lapack", "purpose": "Solve linear system Ax=B (single)", "category": "math"},
    "_dgesv_": {"lib": "lapack", "purpose": "Solve linear system Ax=B (double)", "category": "math"},
    "_sgetrf_": {"lib": "lapack", "purpose": "LU factorization (single)", "category": "math"},
    "_dgetrf_": {"lib": "lapack", "purpose": "LU factorization (double)", "category": "math"},
    "_sgetri_": {"lib": "lapack", "purpose": "Matrix inverse from LU (single)", "category": "math"},
    "_dgetri_": {"lib": "lapack", "purpose": "Matrix inverse from LU (double)", "category": "math"},
    "_ssyev_": {"lib": "lapack", "purpose": "Symmetric eigenvalue decomposition (single)", "category": "math"},
    "_dsyev_": {"lib": "lapack", "purpose": "Symmetric eigenvalue decomposition (double)", "category": "math"},
    "_sgesvd_": {"lib": "lapack", "purpose": "SVD - singular value decomposition (single)", "category": "math"},
    "_dgesvd_": {"lib": "lapack", "purpose": "SVD - singular value decomposition (double)", "category": "math"},
    # Apple Accelerate / vDSP
    "_vDSP_vaddD": {"lib": "accelerate", "purpose": "Vector add (double)", "category": "math"},
    "_vDSP_vmulD": {"lib": "accelerate", "purpose": "Vector multiply (double)", "category": "math"},
    "_vDSP_fft_zripD": {"lib": "accelerate", "purpose": "In-place FFT (double, split complex)", "category": "math"},
    "_vDSP_create_fftsetupD": {"lib": "accelerate", "purpose": "Create FFT setup (double)", "category": "math"},
    "_vDSP_meanvD": {"lib": "accelerate", "purpose": "Vector mean (double)", "category": "math"},
    "_vDSP_maxvD": {"lib": "accelerate", "purpose": "Vector max (double)", "category": "math"},
    "_vDSP_minvD": {"lib": "accelerate", "purpose": "Vector min (double)", "category": "math"},
    "_vDSP_rmsqvD": {"lib": "accelerate", "purpose": "Vector root-mean-square (double)", "category": "math"},
    "_vImageConvert_ARGB8888toRGB888": {"lib": "accelerate", "purpose": "Convert ARGB8888 to RGB888 pixel format", "category": "math"},
    "_vImageScale_ARGB8888": {"lib": "accelerate", "purpose": "Scale/resize ARGB8888 image", "category": "math"},
    "_BNNSFilterCreateLayerFullyConnected": {"lib": "accelerate", "purpose": "Create BNNS fully connected neural layer", "category": "math"},
    "_BNNSFilterApply": {"lib": "accelerate", "purpose": "Apply BNNS neural network filter", "category": "math"},
}


# ---------------------------------------------------------------------------
# Qt Framework (C++ mangled names)  ~16 imza
# ---------------------------------------------------------------------------

_QT_SIGNATURES: dict[str, dict[str, str]] = {
    "__ZN7QObjectC1EPS_": {"lib": "qt", "purpose": "QObject::QObject(QObject* parent)", "category": "ui"},
    "__ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE": {"lib": "qt", "purpose": "QObject::connect (signal-slot)", "category": "ui"},
    "__ZN11QApplicationC1ERiPPci": {"lib": "qt", "purpose": "QApplication::QApplication(argc, argv)", "category": "ui"},
    "__ZN7QString8fromUtf8EPKci": {"lib": "qt", "purpose": "QString::fromUtf8(const char*, int)", "category": "ui"},
    "__ZN7QString6numberEi": {"lib": "qt", "purpose": "QString::number(int)", "category": "ui"},
    "__ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE": {"lib": "qt", "purpose": "QFile::open(OpenMode)", "category": "ui"},
    "__ZN12QTcpSocket": {"lib": "qt", "purpose": "QTcpSocket (partial mangled prefix)", "category": "network"},
    "__ZN8QProcess5startERK7QStringRK11QStringListE6QFlagsIN9QIODevice12OpenModeFlagEE": {"lib": "qt", "purpose": "QProcess::start(program, args, mode)", "category": "process"},
    "__ZN7QThread5startEN2Qt8PriorityE": {"lib": "qt", "purpose": "QThread::start(Priority)", "category": "threading"},
    "__ZN6QTimerC1EPN7QObject": {"lib": "qt", "purpose": "QTimer::QTimer(QObject* parent)", "category": "ui"},
    "__ZN8QVariantC1E": {"lib": "qt", "purpose": "QVariant constructor (partial mangled prefix)", "category": "ui"},
    "__ZN5QListI7QStringEC1Ev": {"lib": "qt", "purpose": "QList<QString>::QList()", "category": "ui"},
    "__ZN4QMapI7QString8QVariantEC1Ev": {"lib": "qt", "purpose": "QMap<QString,QVariant>::QMap()", "category": "ui"},
    "__ZN10QByteArrayC1EPKci": {"lib": "qt", "purpose": "QByteArray::QByteArray(const char*, int)", "category": "ui"},
    "__ZN5QJsonDocument8fromJsonERK10QByteArray": {"lib": "qt", "purpose": "QJsonDocument::fromJson(QByteArray) (partial)", "category": "ui"},
    "__ZN13QCoreApplication4execEv": {"lib": "qt", "purpose": "QCoreApplication::exec() - start event loop", "category": "ui"},
}




# ---------------------------------------------------------------------------
# Testing frameworks  ~9 imza
# ---------------------------------------------------------------------------

_TESTING_SIGNATURES: dict[str, dict[str, str]] = {
    "__ZN7testing4TestC1Ev": {"lib": "gtest", "purpose": "testing::Test constructor", "category": "testing"},
    "__ZN7testing8internal15AssertHelper": {"lib": "gtest", "purpose": "gtest ASSERT/EXPECT helper (partial mangled)", "category": "testing"},
    "__ZN7testing14InitGoogleTestEPiPPc": {"lib": "gtest", "purpose": "InitGoogleTest(argc, argv)", "category": "testing"},
    "__ZN5Catch10RunSession3runEv": {"lib": "catch2", "purpose": "Catch::Session::run() - run all tests", "category": "testing"},
    "_CU_initialize_registry": {"lib": "cunit", "purpose": "Initialize CUnit test registry", "category": "testing"},
    "_CU_add_suite": {"lib": "cunit", "purpose": "Add test suite to registry", "category": "testing"},
    "_CU_add_test": {"lib": "cunit", "purpose": "Add test case to suite", "category": "testing"},
    "_CU_basic_run_tests": {"lib": "cunit", "purpose": "Run all CUnit tests (basic)", "category": "testing"},
    "_CU_cleanup_registry": {"lib": "cunit", "purpose": "Clean up CUnit test registry", "category": "testing"},
}


# ---------------------------------------------------------------------------
# Misc widely-used: getopt, iconv, readline, termios, uuid, GLib  ~46 imza
# ---------------------------------------------------------------------------

_MISC_SIGNATURES: dict[str, dict[str, str]] = {
    "_getopt": {"lib": "libc", "purpose": "Parse command-line options", "category": "misc"},
    "_getopt_long": {"lib": "libc", "purpose": "Parse long command-line options", "category": "misc"},
    "_getopt_long_only": {"lib": "libc", "purpose": "Parse long options (single-dash allowed)", "category": "misc"},
    "_iconv_open": {"lib": "libc", "purpose": "Open charset conversion descriptor", "category": "misc"},
    "_iconv": {"lib": "libc", "purpose": "Convert character encoding", "category": "misc"},
    "_iconv_close": {"lib": "libc", "purpose": "Close charset conversion descriptor", "category": "misc"},
    "_readline": {"lib": "readline", "purpose": "Read line with editing/completion", "category": "misc"},
    "_add_history": {"lib": "readline", "purpose": "Add line to readline history", "category": "misc"},
    "_rl_bind_key": {"lib": "readline", "purpose": "Bind key to readline function", "category": "misc"},
    "_rl_completion_matches": {"lib": "readline", "purpose": "Generate completion matches", "category": "misc"},
    "_tcgetattr": {"lib": "libc", "purpose": "Get terminal attributes", "category": "misc"},
    "_tcsetattr": {"lib": "libc", "purpose": "Set terminal attributes", "category": "misc"},
    "_cfmakeraw": {"lib": "libc", "purpose": "Set terminal to raw mode", "category": "misc"},
    "_cfsetispeed": {"lib": "libc", "purpose": "Set terminal input baud rate", "category": "misc"},
    "_cfsetospeed": {"lib": "libc", "purpose": "Set terminal output baud rate", "category": "misc"},
    "_uuid_generate": {"lib": "libuuid", "purpose": "Generate UUID (v1 or v4)", "category": "misc"},
    "_uuid_generate_random": {"lib": "libuuid", "purpose": "Generate random UUID (v4)", "category": "misc"},
    "_uuid_generate_time": {"lib": "libuuid", "purpose": "Generate time-based UUID (v1)", "category": "misc"},
    "_uuid_parse": {"lib": "libuuid", "purpose": "Parse UUID string to binary", "category": "misc"},
    "_uuid_unparse": {"lib": "libuuid", "purpose": "Convert UUID binary to string", "category": "misc"},
    "_uuid_copy": {"lib": "libuuid", "purpose": "Copy UUID", "category": "misc"},
    "_uuid_compare": {"lib": "libuuid", "purpose": "Compare two UUIDs", "category": "misc"},
    "_uuid_clear": {"lib": "libuuid", "purpose": "Set UUID to null", "category": "misc"},
    "_g_malloc": {"lib": "glib", "purpose": "GLib memory allocate (aborts on fail)", "category": "misc"},
    "_g_free": {"lib": "glib", "purpose": "GLib memory free", "category": "misc"},
    "_g_realloc": {"lib": "glib", "purpose": "GLib memory reallocate", "category": "misc"},
    "_g_strdup": {"lib": "glib", "purpose": "GLib string duplicate", "category": "misc"},
    "_g_strsplit": {"lib": "glib", "purpose": "GLib split string by delimiter", "category": "misc"},
    "_g_strjoinv": {"lib": "glib", "purpose": "GLib join string array with separator", "category": "misc"},
    "_g_list_append": {"lib": "glib", "purpose": "Append to GList", "category": "misc"},
    "_g_list_remove": {"lib": "glib", "purpose": "Remove from GList", "category": "misc"},
    "_g_list_length": {"lib": "glib", "purpose": "Get GList length", "category": "misc"},
    "_g_list_free": {"lib": "glib", "purpose": "Free GList", "category": "misc"},
    "_g_hash_table_new": {"lib": "glib", "purpose": "Create GHashTable", "category": "misc"},
    "_g_hash_table_insert": {"lib": "glib", "purpose": "Insert into GHashTable", "category": "misc"},
    "_g_hash_table_lookup": {"lib": "glib", "purpose": "Lookup in GHashTable", "category": "misc"},
    "_g_hash_table_destroy": {"lib": "glib", "purpose": "Destroy GHashTable", "category": "misc"},
    "_g_main_loop_new": {"lib": "glib", "purpose": "Create GMainLoop", "category": "event_loop"},
    "_g_main_loop_run": {"lib": "glib", "purpose": "Run GMainLoop (blocking)", "category": "event_loop"},
    "_g_main_loop_quit": {"lib": "glib", "purpose": "Quit GMainLoop", "category": "event_loop"},
    "_g_signal_connect": {"lib": "glib", "purpose": "Connect signal to callback (GObject)", "category": "misc"},
    "_g_signal_emit": {"lib": "glib", "purpose": "Emit GObject signal", "category": "misc"},
    "_g_object_new": {"lib": "glib", "purpose": "Create new GObject instance", "category": "misc"},
    "_g_object_unref": {"lib": "glib", "purpose": "Decrement GObject reference count", "category": "misc"},
}


# ---------------------------------------------------------------------------
# Katman 2: String Reference Signatures
# ---------------------------------------------------------------------------
# frozenset(string_keywords) -> (fonksiyon_adi, kutuphane)
# Bir fonksiyon bu string'lerin HEPSINI referans olarak kullaniyorsa eslestir.

_STRING_REFERENCE_SIGNATURES: dict[frozenset[str], tuple[str, str, str]] = {
    # (matched_name, library, purpose)

    # OpenSSL string patterns
    frozenset({"BIO_new", "SSL_CTX_new"}): ("ssl_ctx_setup", "openssl", "TLS context setup"),
    frozenset({"EVP_CIPHER_CTX", "EVP_EncryptInit"}): ("evp_encrypt_setup", "openssl", "cipher encryption init"),
    frozenset({"EVP_CIPHER_CTX", "EVP_DecryptInit"}): ("evp_decrypt_setup", "openssl", "cipher decryption init"),
    frozenset({"SSL_connect", "SSL_set_fd"}): ("tls_client_connect", "openssl", "TLS client connection"),
    frozenset({"SSL_accept", "SSL_set_fd"}): ("tls_server_accept", "openssl", "TLS server accept"),
    frozenset({"X509_STORE", "X509_verify_cert"}): ("x509_cert_verify", "openssl", "certificate verification"),
    frozenset({"PEM_read_bio", "X509"}): ("pem_cert_read", "openssl", "PEM certificate reading"),
    frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}): ("sha256_hash", "openssl", "SHA-256 computation"),
    frozenset({"SHA1_Init", "SHA1_Update", "SHA1_Final"}): ("sha1_hash", "openssl", "SHA-1 computation"),
    frozenset({"MD5_Init", "MD5_Update", "MD5_Final"}): ("md5_hash", "openssl", "MD5 computation"),
    frozenset({"HMAC_Init_ex", "HMAC_Update", "HMAC_Final"}): ("hmac_compute", "openssl", "HMAC computation"),
    frozenset({"EVP_PKEY_keygen_init", "EVP_PKEY_keygen"}): ("key_generation", "openssl", "key generation"),
    frozenset({"ECDSA_sign", "EC_KEY"}): ("ecdsa_signing", "openssl", "ECDSA signing"),
    frozenset({"RSA_public_encrypt", "RSA_size"}): ("rsa_encrypt", "openssl", "RSA encryption"),
    frozenset({"RSA_private_decrypt", "RSA_size"}): ("rsa_decrypt", "openssl", "RSA decryption"),
    frozenset({"PKCS12_parse", "EVP_PKEY"}): ("pkcs12_import", "openssl", "PKCS#12 import"),
    frozenset({"RAND_bytes", "RAND_seed"}): ("crypto_random", "openssl", "cryptographic RNG"),

    # zlib string patterns
    frozenset({"inflate", "Z_STREAM_END"}): ("zlib_decompress", "zlib", "zlib decompression"),
    frozenset({"deflate", "Z_FINISH"}): ("zlib_compress", "zlib", "zlib compression"),
    frozenset({"inflateInit", "inflate", "inflateEnd"}): ("zlib_decompress_full", "zlib", "full decompression cycle"),
    frozenset({"deflateInit", "deflate", "deflateEnd"}): ("zlib_compress_full", "zlib", "full compression cycle"),
    frozenset({"gzopen", "gzread"}): ("gzip_file_read", "zlib", "gzip file reading"),
    frozenset({"gzopen", "gzwrite"}): ("gzip_file_write", "zlib", "gzip file writing"),

    # libcurl string patterns
    frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"}): ("http_request", "libcurl", "HTTP request execution"),
    frozenset({"curl_easy_setopt", "CURLOPT_URL"}): ("curl_url_setup", "libcurl", "URL configuration"),
    frozenset({"curl_easy_setopt", "CURLOPT_POSTFIELDS"}): ("http_post_request", "libcurl", "HTTP POST request"),
    frozenset({"curl_easy_setopt", "CURLOPT_WRITEFUNCTION"}): ("curl_download_setup", "libcurl", "download callback setup"),
    frozenset({"curl_multi_init", "curl_multi_add_handle"}): ("multi_transfer_setup", "libcurl", "multi-transfer setup"),
    frozenset({"curl_ws_recv", "curl_ws_send"}): ("websocket_io", "libcurl", "WebSocket I/O"),

    # SQLite string patterns
    frozenset({"sqlite3_open", "sqlite3_exec"}): ("sqlite_exec_query", "sqlite3", "database query execution"),
    frozenset({"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize"}): ("sqlite_prepared_query", "sqlite3", "prepared statement query"),
    frozenset({"sqlite3_bind_text", "sqlite3_step"}): ("sqlite_parameterized_query", "sqlite3", "parameterized query"),
    frozenset({"sqlite3_backup_init", "sqlite3_backup_step"}): ("sqlite_backup", "sqlite3", "online database backup"),
    frozenset({"sqlite3_blob_open", "sqlite3_blob_read"}): ("sqlite_blob_read", "sqlite3", "blob I/O"),
    frozenset({"sqlite3_key", "sqlite3_open"}): ("sqlite_encrypted_open", "sqlite3", "encrypted database open"),

    # CommonCrypto string patterns
    frozenset({"CCCrypt", "kCCEncrypt"}): ("cc_encrypt", "CommonCrypto", "symmetric encryption"),
    frozenset({"CCCrypt", "kCCDecrypt"}): ("cc_decrypt", "CommonCrypto", "symmetric decryption"),
    frozenset({"CCHmac", "kCCHmacAlgSHA256"}): ("cc_hmac_sha256", "CommonCrypto", "HMAC-SHA256"),
    frozenset({"CCKeyDerivationPBKDF", "kCCPBKDF2"}): ("cc_pbkdf2", "CommonCrypto", "PBKDF2 key derivation"),

    # Security.framework string patterns
    frozenset({"SecItemAdd", "kSecClass"}): ("keychain_store", "Security", "Keychain item storage"),
    frozenset({"SecItemCopyMatching", "kSecClass"}): ("keychain_lookup", "Security", "Keychain item lookup"),
    frozenset({"SecKeyCreateSignature", "SecKeyCreateRandomKey"}): ("digital_sign_with_keygen", "Security", "key generation + signing"),
    frozenset({"SecTrustCreateWithCertificates", "SecTrustEvaluateWithError"}): ("cert_trust_eval", "Security", "certificate trust evaluation"),
    frozenset({"SecCodeCheckValidity", "SecStaticCodeCreateWithPath"}): ("code_sign_verify", "Security", "code signature verification"),

    # Endpoint Security patterns
    frozenset({"es_new_client", "es_subscribe"}): ("es_client_setup", "EndpointSecurity", "ES client creation + subscription"),
    frozenset({"es_respond_auth_result", "es_subscribe"}): ("es_auth_handler", "EndpointSecurity", "ES authorization handler"),

    # Protobuf patterns
    frozenset({"SerializeToString", "ParseFromString"}): ("protobuf_serde", "protobuf", "protobuf serialize/deserialize"),
    frozenset({"CodedOutputStream", "WriteVarint"}): ("protobuf_encode", "protobuf", "protobuf encoding"),
    frozenset({"CodedInputStream", "ReadVarint"}): ("protobuf_decode", "protobuf", "protobuf decoding"),
    frozenset({"Arena", "CreateMessage"}): ("protobuf_arena_alloc", "protobuf", "arena-allocated message"),

    # bzip2 string patterns
    frozenset({"BZ2_bzCompressInit", "BZ2_bzCompress", "BZ2_bzCompressEnd"}): ("bzip2_compress_full", "bzip2", "full bzip2 compression cycle"),
    frozenset({"BZ2_bzDecompressInit", "BZ2_bzDecompress", "BZ2_bzDecompressEnd"}): ("bzip2_decompress_full", "bzip2", "full bzip2 decompression cycle"),
    frozenset({"BZ2_bzReadOpen", "BZ2_bzRead"}): ("bzip2_file_read", "bzip2", "bzip2 file reading"),
    frozenset({"BZ2_bzWriteOpen", "BZ2_bzWrite"}): ("bzip2_file_write", "bzip2", "bzip2 file writing"),

    # lz4 string patterns
    frozenset({"LZ4_compress_default", "LZ4_decompress_safe"}): ("lz4_roundtrip", "lz4", "LZ4 compress/decompress"),
    frozenset({"LZ4F_createCompressionContext", "LZ4F_compressBegin"}): ("lz4_frame_compress", "lz4", "LZ4 frame compression"),
    frozenset({"LZ4F_createDecompressionContext", "LZ4F_decompress"}): ("lz4_frame_decompress", "lz4", "LZ4 frame decompression"),

    # zstd string patterns
    frozenset({"ZSTD_compress", "ZSTD_decompress"}): ("zstd_roundtrip", "zstd", "zstd compress/decompress"),
    frozenset({"ZSTD_createCCtx", "ZSTD_compressCCtx"}): ("zstd_ctx_compress", "zstd", "zstd context compression"),
    frozenset({"ZSTD_createDCtx", "ZSTD_decompressDCtx"}): ("zstd_ctx_decompress", "zstd", "zstd context decompression"),
    frozenset({"ZSTD_createCStream", "ZSTD_compressStream", "ZSTD_endStream"}): ("zstd_streaming_compress", "zstd", "zstd streaming compression"),
    frozenset({"ZSTD_createDStream", "ZSTD_decompressStream"}): ("zstd_streaming_decompress", "zstd", "zstd streaming decompression"),

    # cJSON string patterns
    frozenset({"cJSON_Parse", "cJSON_Delete"}): ("cjson_parse", "cJSON", "cJSON parsing"),
    frozenset({"cJSON_CreateObject", "cJSON_AddItemToObject"}): ("cjson_build", "cJSON", "cJSON object building"),
    frozenset({"cJSON_Print", "cJSON_CreateObject"}): ("cjson_build_print", "cJSON", "cJSON build + serialize"),

    # yyjson string patterns
    frozenset({"yyjson_read", "yyjson_doc_free"}): ("yyjson_parse", "yyjson", "yyjson parsing"),
    frozenset({"yyjson_mut_doc_new", "yyjson_mut_write"}): ("yyjson_build", "yyjson", "yyjson mutable build + serialize"),

    # jansson string patterns
    frozenset({"json_loads", "json_decref"}): ("jansson_parse", "jansson", "jansson JSON parsing"),
    frozenset({"json_object", "json_object_set"}): ("jansson_build", "jansson", "jansson JSON object building"),
    frozenset({"json_dumps", "json_object"}): ("jansson_serialize", "jansson", "jansson JSON serialization"),

    # libxml2 string patterns
    frozenset({"xmlReadMemory", "xmlFreeDoc"}): ("libxml2_parse_mem", "libxml2", "libxml2 parse from memory"),
    frozenset({"xmlReadFile", "xmlFreeDoc"}): ("libxml2_parse_file", "libxml2", "libxml2 parse from file"),
    frozenset({"xmlXPathNewContext", "xmlXPathEvalExpression"}): ("libxml2_xpath", "libxml2", "libxml2 XPath query"),
    frozenset({"xmlNewDoc", "xmlNewNode", "xmlAddChild"}): ("libxml2_build_tree", "libxml2", "libxml2 tree building"),
    frozenset({"xmlSaveFormatFile", "xmlNewDoc"}): ("libxml2_save", "libxml2", "libxml2 save to file"),

    # expat string patterns
    frozenset({"XML_ParserCreate", "XML_Parse", "XML_ParserFree"}): ("expat_parse", "expat", "expat XML parsing"),
    frozenset({"XML_SetElementHandler", "XML_SetCharacterDataHandler"}): ("expat_handlers", "expat", "expat event handler setup"),

    # Networking patterns (generic)
    frozenset({"socket", "connect", "send", "recv"}): ("tcp_client", "libc", "TCP client connection"),
    frozenset({"socket", "bind", "listen", "accept"}): ("tcp_server", "libc", "TCP server setup"),
    frozenset({"getaddrinfo", "socket", "connect"}): ("dns_resolve_connect", "libc", "DNS resolve + connect"),
    frozenset({"sendto", "recvfrom", "SOCK_DGRAM"}): ("udp_io", "libc", "UDP I/O"),

    # File I/O patterns
    frozenset({"fopen", "fread", "fclose"}): ("file_read", "libc", "file reading"),
    frozenset({"fopen", "fwrite", "fclose"}): ("file_write", "libc", "file writing"),
    frozenset({"mmap", "munmap"}): ("memory_mapped_io", "libc", "memory-mapped file I/O"),
    frozenset({"opendir", "readdir", "closedir"}): ("directory_scan", "libc", "directory scanning"),

    # Process patterns
    frozenset({"fork", "exec", "waitpid"}): ("process_spawn", "libc", "process spawn + wait"),
    frozenset({"posix_spawn", "posix_spawnattr"}): ("posix_process_spawn", "libc", "POSIX process spawning"),
    frozenset({"pthread_create", "pthread_join"}): ("thread_spawn", "libpthread", "thread creation + join"),
    frozenset({"pthread_mutex_lock", "pthread_mutex_unlock"}): ("mutex_operation", "libpthread", "mutex lock/unlock"),
    frozenset({"pthread_cond_wait", "pthread_cond_signal"}): ("condition_variable", "libpthread", "condition variable wait/signal"),

    # ===================================================================
    # EXTENDED STRING REFERENCE SIGNATURES (v2 expansion)
    # ===================================================================

    # --- OpenSSL string patterns (extended) ---
    frozenset({"SSL_connect", "handshake"}): ("ssl_handshake", "openssl", "TLS handshake initiation"),
    frozenset({"certificate", "verify", "X509"}): ("verify_certificate", "openssl", "X.509 certificate verification"),
    frozenset({"private key", "PEM"}): ("load_private_key", "openssl", "PEM private key loading"),
    frozenset({"cipher", "encrypt"}): ("setup_cipher", "openssl", "cipher suite setup"),
    frozenset({"TLS", "version"}): ("check_tls_version", "openssl", "TLS version negotiation"),
    frozenset({"RAND_bytes", "random"}): ("generate_random", "openssl", "cryptographic random generation"),
    frozenset({"digest", "hash"}): ("compute_hash", "openssl", "message digest computation"),
    frozenset({"RSA", "key", "generate"}): ("generate_rsa_key", "openssl", "RSA key pair generation"),
    frozenset({"ECDSA", "sign"}): ("ecdsa_sign", "openssl", "ECDSA digital signature"),
    frozenset({"HMAC", "auth"}): ("hmac_authenticate", "openssl", "HMAC authentication"),
    frozenset({"DH_generate_parameters", "DH_generate_key"}): ("dh_key_exchange", "openssl", "Diffie-Hellman key exchange"),
    frozenset({"SSL_CTX_set_verify", "SSL_VERIFY_PEER"}): ("ssl_peer_verify", "openssl", "TLS peer certificate verification"),
    frozenset({"OCSP_basic_verify", "OCSP_response"}): ("ocsp_check", "openssl", "OCSP certificate status check"),
    frozenset({"CRL", "X509_CRL_verify"}): ("crl_verify", "openssl", "CRL verification"),
    frozenset({"BIO_new_ssl_connect", "BIO_do_connect"}): ("bio_ssl_connect", "openssl", "BIO-based SSL connection"),
    frozenset({"SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file"}): ("ssl_load_cert_key", "openssl", "load certificate and key for TLS"),
    frozenset({"SSL_CTX_set_cipher_list", "TLS_method"}): ("ssl_cipher_config", "openssl", "cipher list configuration"),
    frozenset({"PKCS7_sign", "PKCS7_verify"}): ("pkcs7_sign_verify", "openssl", "PKCS#7 signing/verification"),
    frozenset({"EVP_PKEY_derive_init", "EVP_PKEY_derive"}): ("pkey_derive", "openssl", "EVP key derivation"),
    frozenset({"SSL_read", "SSL_write"}): ("ssl_io", "openssl", "TLS read/write I/O"),
    frozenset({"SSL_get_error", "SSL_ERROR_WANT_READ"}): ("ssl_error_handling", "openssl", "TLS error handling"),
    frozenset({"X509_get_subject_name", "X509_get_issuer_name"}): ("x509_name_extract", "openssl", "X.509 name extraction"),
    frozenset({"X509_get_notBefore", "X509_get_notAfter"}): ("x509_validity_check", "openssl", "certificate validity period check"),
    frozenset({"PEM_write_bio_RSAPublicKey", "PEM_read_bio_RSAPublicKey"}): ("rsa_pem_io", "openssl", "RSA public key PEM I/O"),
    frozenset({"EVP_aes_256_gcm", "EVP_EncryptInit_ex"}): ("aes256_gcm_setup", "openssl", "AES-256-GCM initialization"),
    frozenset({"EVP_chacha20_poly1305", "EVP_EncryptInit_ex"}): ("chacha20_poly1305_setup", "openssl", "ChaCha20-Poly1305 initialization"),
    frozenset({"EC_KEY_new_by_curve_name", "NID_X9_62_prime256v1"}): ("ec_p256_key", "openssl", "P-256 elliptic curve key creation"),
    frozenset({"EVP_PKEY_CTX_new", "EVP_PKEY_sign"}): ("pkey_sign", "openssl", "EVP PKEY signing"),
    frozenset({"EVP_PKEY_CTX_new", "EVP_PKEY_verify"}): ("pkey_verify", "openssl", "EVP PKEY verification"),
    frozenset({"SSL_SESSION_get_id", "SSL_get_session"}): ("ssl_session_resume", "openssl", "TLS session ID retrieval/resume"),

    # --- SQLite string patterns (extended) ---
    frozenset({"CREATE TABLE", "sqlite"}): ("create_table", "sqlite3", "SQL CREATE TABLE"),
    frozenset({"SELECT", "FROM", "WHERE"}): ("execute_query", "sqlite3", "SQL SELECT query execution"),
    frozenset({"INSERT INTO"}): ("insert_record", "sqlite3", "SQL INSERT record"),
    frozenset({"UPDATE", "SET"}): ("update_record", "sqlite3", "SQL UPDATE record"),
    frozenset({"DELETE FROM"}): ("delete_record", "sqlite3", "SQL DELETE record"),
    frozenset({"BEGIN TRANSACTION"}): ("begin_transaction", "sqlite3", "SQL transaction begin"),
    frozenset({"PRAGMA"}): ("set_pragma", "sqlite3", "SQLite PRAGMA command"),
    frozenset({"database is locked"}): ("handle_db_lock", "sqlite3", "handle database lock contention"),
    frozenset({"CREATE INDEX", "sqlite3"}): ("create_index", "sqlite3", "SQL CREATE INDEX"),
    frozenset({"FOREIGN KEY", "REFERENCES"}): ("foreign_key_setup", "sqlite3", "foreign key constraint"),
    frozenset({"ALTER TABLE", "ADD COLUMN"}): ("alter_table", "sqlite3", "SQL ALTER TABLE"),
    frozenset({"VACUUM"}): ("vacuum_db", "sqlite3", "SQLite VACUUM optimization"),
    frozenset({"ATTACH DATABASE"}): ("attach_db", "sqlite3", "SQLite ATTACH DATABASE"),
    frozenset({"sqlite3_wal_checkpoint"}): ("wal_checkpoint", "sqlite3", "WAL checkpoint"),
    frozenset({"sqlite3_create_function"}): ("register_custom_func", "sqlite3", "register custom SQL function"),

    # --- Network string patterns (extended) ---
    frozenset({"HTTP/1.1", "GET"}): ("http_get_request", "http", "HTTP GET request construction"),
    frozenset({"HTTP/1.1", "POST"}): ("http_post_request", "http", "HTTP POST request construction"),
    frozenset({"Content-Type", "application/json"}): ("set_json_content", "http", "JSON content-type header"),
    frozenset({"Authorization", "Bearer"}): ("set_auth_header", "http", "Bearer token authorization"),
    frozenset({"WebSocket", "Upgrade"}): ("websocket_upgrade", "websocket", "WebSocket protocol upgrade"),
    frozenset({"Connection", "keep-alive"}): ("set_keepalive", "http", "HTTP keep-alive setting"),
    frozenset({"Host:", "User-Agent:"}): ("build_http_headers", "http", "HTTP header construction"),
    frozenset({"DNS", "resolve"}): ("dns_resolve", "dns", "DNS name resolution"),
    frozenset({"gRPC", "proto"}): ("grpc_call", "grpc", "gRPC remote procedure call"),
    frozenset({"HTTP/2", "SETTINGS"}): ("http2_setup", "http2", "HTTP/2 connection settings"),
    frozenset({"Content-Length", "Transfer-Encoding"}): ("http_body_framing", "http", "HTTP body framing"),
    frozenset({"Cookie", "Set-Cookie"}): ("http_cookie_handling", "http", "HTTP cookie management"),
    frozenset({"Proxy-Authorization", "CONNECT"}): ("http_proxy_connect", "http", "HTTP proxy CONNECT tunnel"),
    frozenset({"multipart/form-data", "boundary"}): ("multipart_upload", "http", "multipart form-data upload"),
    frozenset({"text/event-stream", "SSE"}): ("server_sent_events", "http", "Server-Sent Events stream"),
    frozenset({"SOCKS5", "\\x05"}): ("socks5_proxy", "network", "SOCKS5 proxy negotiation"),
    frozenset({"ICMP", "ping"}): ("icmp_ping", "network", "ICMP ping request"),
    frozenset({"ARP", "request"}): ("arp_request", "network", "ARP request"),
    frozenset({"MQTT", "CONNECT", "PUBLISH"}): ("mqtt_client", "mqtt", "MQTT publish/subscribe"),
    frozenset({"AMQP", "channel"}): ("amqp_channel", "amqp", "AMQP channel operation"),

    # --- Error/logging string patterns ---
    frozenset({"error", "failed", "errno"}): ("handle_error", "error_handling", "error handling with errno"),
    frozenset({"warning", "deprecated"}): ("log_warning", "logging", "deprecation warning logging"),
    frozenset({"debug", "trace"}): ("log_debug", "logging", "debug/trace logging"),
    frozenset({"out of memory", "alloc"}): ("handle_oom", "memory", "out-of-memory handler"),
    frozenset({"stack overflow"}): ("handle_stack_overflow", "error_handling", "stack overflow handler"),
    frozenset({"segmentation fault", "SIGSEGV"}): ("handle_sigsegv", "signal_handling", "SIGSEGV signal handler"),
    frozenset({"assertion failed"}): ("assertion_handler", "debug", "assertion failure handler"),
    frozenset({"abort", "SIGABRT"}): ("abort_handler", "signal_handling", "SIGABRT abort handler"),
    frozenset({"bus error", "SIGBUS"}): ("handle_sigbus", "signal_handling", "SIGBUS signal handler"),
    frozenset({"broken pipe", "SIGPIPE"}): ("handle_sigpipe", "signal_handling", "SIGPIPE signal handler"),
    frozenset({"floating point", "SIGFPE"}): ("handle_sigfpe", "signal_handling", "SIGFPE signal handler"),
    frozenset({"panic", "fatal"}): ("fatal_error", "error_handling", "fatal error/panic handler"),
    frozenset({"unhandled exception"}): ("unhandled_exception", "error_handling", "unhandled exception handler"),
    frozenset({"core dump", "signal"}): ("coredump_handler", "signal_handling", "core dump signal handler"),
    frozenset({"log_level", "LOG_ERR", "LOG_INFO"}): ("syslog_logging", "logging", "syslog-style logging"),

    # --- File format string patterns ---
    frozenset({"PNG", "IHDR"}): ("parse_png_header", "libpng", "PNG header parsing"),
    frozenset({"JFIF", "Exif"}): ("parse_jpeg_header", "libjpeg", "JPEG header parsing"),
    frozenset({"GIF89a", "GIF87a"}): ("parse_gif", "image", "GIF format parsing"),
    frozenset({"PDF", "%PDF"}): ("parse_pdf", "pdf", "PDF document parsing"),
    frozenset({"PK\\x03\\x04"}): ("parse_zip", "zip", "ZIP archive parsing"),
    frozenset({"<?xml", "encoding"}): ("parse_xml", "xml", "XML document parsing"),
    frozenset({"<!DOCTYPE html"}): ("parse_html", "html", "HTML document parsing"),
    frozenset({"ELF"}): ("parse_elf", "binary", "ELF binary parsing"),
    frozenset({"MZ"}): ("parse_pe", "binary", "PE/MZ binary parsing"),
    frozenset({"\\x89PNG\\r\\n"}): ("validate_png_magic", "libpng", "PNG magic byte validation"),
    frozenset({"\\xff\\xd8\\xff"}): ("validate_jpeg_magic", "libjpeg", "JPEG magic byte validation"),
    frozenset({"Mach-O", "LC_SEGMENT"}): ("parse_macho", "binary", "Mach-O binary parsing"),
    frozenset({"FAT_MAGIC", "fat_header"}): ("parse_fat_binary", "binary", "FAT/universal binary parsing"),
    frozenset({"dex\\n035"}): ("parse_dex", "binary", "Android DEX file parsing"),
    frozenset({"SQLite format 3"}): ("detect_sqlite_db", "sqlite3", "SQLite database file detection"),

    # --- Crypto string patterns ---
    frozenset({"AES", "key", "iv"}): ("aes_init", "crypto", "AES cipher initialization"),
    frozenset({"SHA256", "digest"}): ("sha256_digest", "crypto", "SHA-256 digest computation"),
    frozenset({"password", "hash", "salt"}): ("hash_password", "crypto", "password hashing with salt"),
    frozenset({"PBKDF2", "iterations"}): ("derive_key", "crypto", "PBKDF2 key derivation"),
    frozenset({"base64", "encode"}): ("base64_encode", "encoding", "Base64 encoding"),
    frozenset({"base64", "decode"}): ("base64_decode", "encoding", "Base64 decoding"),
    frozenset({"JWT", "token"}): ("process_jwt", "auth", "JWT token processing"),
    frozenset({"OAuth", "token"}): ("oauth_flow", "auth", "OAuth token flow"),
    frozenset({"bcrypt", "cost"}): ("bcrypt_hash", "crypto", "bcrypt password hashing"),
    frozenset({"scrypt", "memory"}): ("scrypt_derive", "crypto", "scrypt key derivation"),
    frozenset({"argon2", "password"}): ("argon2_hash", "crypto", "Argon2 password hashing"),
    frozenset({"ChaCha20", "nonce"}): ("chacha20_init", "crypto", "ChaCha20 stream cipher init"),
    frozenset({"Poly1305", "tag"}): ("poly1305_auth", "crypto", "Poly1305 MAC authentication"),
    frozenset({"X25519", "curve25519"}): ("x25519_exchange", "crypto", "X25519 key exchange"),
    frozenset({"Ed25519", "sign"}): ("ed25519_sign", "crypto", "Ed25519 digital signature"),

    # --- Config/settings string patterns ---
    frozenset({"config", "settings", "load"}): ("load_config", "config", "configuration loading"),
    frozenset({"default", "fallback"}): ("get_default_value", "config", "default/fallback value retrieval"),
    frozenset({".json", "parse"}): ("parse_json_config", "config", "JSON configuration parsing"),
    frozenset({".yaml", ".yml"}): ("parse_yaml_config", "config", "YAML configuration parsing"),
    frozenset({".plist"}): ("parse_plist", "apple", "Apple plist parsing"),
    frozenset({"environment", "env"}): ("read_env_var", "config", "environment variable reading"),
    frozenset({".ini", "section", "key"}): ("parse_ini_config", "config", "INI configuration parsing"),
    frozenset({".toml", "table"}): ("parse_toml_config", "config", "TOML configuration parsing"),
    frozenset({"registry", "HKEY_"}): ("read_registry", "winapi", "Windows registry access"),
    frozenset({"NSUserDefaults", "standardUserDefaults"}): ("read_user_defaults", "apple", "NSUserDefaults reading"),

    # --- Anti-RE / security string patterns ---
    frozenset({"ptrace", "PT_DENY_ATTACH"}): ("anti_debug_check", "anti_re", "anti-debug ptrace check"),
    frozenset({"debugger", "attached"}): ("detect_debugger", "anti_re", "debugger detection"),
    frozenset({"checksum", "integrity"}): ("integrity_check", "anti_tamper", "integrity/checksum verification"),
    frozenset({"jailbreak", "cydia"}): ("jailbreak_detect", "anti_re", "jailbreak detection"),
    frozenset({"frida", "substrate"}): ("detect_instrumentation", "anti_re", "instrumentation framework detection"),
    frozenset({"tamper", "modified"}): ("tamper_detection", "anti_tamper", "tamper detection"),
    frozenset({"SVC", "sysctl", "P_TRACED"}): ("sysctl_debug_check", "anti_re", "sysctl-based debug detection"),
    frozenset({"_dyld_get_image_name", "MobileSubstrate"}): ("detect_substrate", "anti_re", "MobileSubstrate injection detection"),
    frozenset({"getppid", "launchd"}): ("parent_process_check", "anti_re", "parent process validation"),
    frozenset({"obfuscat", "encrypt", "decrypt"}): ("string_obfuscation", "anti_re", "string obfuscation/deobfuscation"),

    # --- macOS / Apple framework string patterns ---
    frozenset({"NSTask", "launch"}): ("run_subprocess_cocoa", "Foundation", "NSTask subprocess launch"),
    frozenset({"CFRunLoop", "CFRunLoopRun"}): ("run_loop_setup", "CoreFoundation", "CFRunLoop main loop"),
    frozenset({"IOServiceGetMatchingService", "IORegistryEntryCreateCFProperty"}): ("iokit_property_read", "IOKit", "IOKit registry property read"),
    frozenset({"NSWorkspace", "openURL"}): ("open_url_cocoa", "AppKit", "open URL via NSWorkspace"),
    frozenset({"kext", "IOServiceMatching"}): ("iokit_kext_match", "IOKit", "IOKit kernel extension matching"),
    frozenset({"launchd", "SMJobBless"}): ("install_helper_tool", "ServiceManagement", "install privileged helper tool"),
    frozenset({"NSAppleScript", "executeAndReturnError"}): ("execute_applescript", "Foundation", "AppleScript execution"),
    frozenset({"MDQuery", "MDItemCopyAttribute"}): ("spotlight_query", "CoreServices", "Spotlight metadata query"),
    frozenset({"CGEventCreate", "CGEventPost"}): ("cg_event_injection", "CoreGraphics", "CoreGraphics event injection"),
    frozenset({"AXUIElementRef", "AXUIElementCopyAttributeValue"}): ("accessibility_query", "Accessibility", "Accessibility API query"),

    # --- Objective-C runtime patterns ---
    frozenset({"objc_msgSend", "sel_registerName"}): ("objc_dynamic_dispatch", "objc_runtime", "ObjC dynamic message dispatch"),
    frozenset({"class_addMethod", "class_replaceMethod"}): ("objc_method_swizzle", "objc_runtime", "ObjC method swizzling"),
    frozenset({"objc_getClass", "class_getInstanceMethod"}): ("objc_class_introspect", "objc_runtime", "ObjC class introspection"),
    frozenset({"object_getClassName", "NSStringFromClass"}): ("objc_class_name", "objc_runtime", "ObjC class name resolution"),
    frozenset({"method_exchangeImplementations"}): ("objc_imp_exchange", "objc_runtime", "ObjC implementation exchange"),

    # --- Swift runtime patterns ---
    frozenset({"swift_allocObject", "swift_release"}): ("swift_refcount", "swift_runtime", "Swift reference counting"),
    frozenset({"swift_dynamicCast", "swift_getTypeByMangledName"}): ("swift_type_cast", "swift_runtime", "Swift dynamic type casting"),

    # --- IPC / Mach patterns ---
    frozenset({"mach_msg", "mach_port_allocate"}): ("mach_ipc", "mach", "Mach IPC message passing"),
    frozenset({"bootstrap_look_up", "mach_port_t"}): ("mach_service_lookup", "mach", "Mach bootstrap service lookup"),
    frozenset({"xpc_dictionary_create", "xpc_connection_send_message"}): ("xpc_message_send", "libxpc", "XPC dictionary message send"),

    # --- Compression detection (generic) ---
    frozenset({"compress", "decompress", "level"}): ("generic_compress", "compression", "generic compression operation"),
    frozenset({"snappy_compress", "snappy_uncompress"}): ("snappy_roundtrip", "snappy", "Snappy compress/decompress"),
    frozenset({"brotli", "BrotliEncoder"}): ("brotli_compress", "brotli", "Brotli compression"),

    # --- Regex / string processing ---
    frozenset({"regcomp", "regexec", "regfree"}): ("posix_regex", "libc", "POSIX regex matching"),
    frozenset({"pcre2_compile", "pcre2_match"}): ("pcre2_regex", "pcre2", "PCRE2 regex matching"),
    frozenset({"fnmatch", "FNM_PATHNAME"}): ("glob_match", "libc", "filename glob matching"),
}


# ---------------------------------------------------------------------------
# Katman 3: Call Pattern Signatures (Structural)
# ---------------------------------------------------------------------------
# Fonksiyonun cagirdigi API'lerin sirali kombinasyonundan tanimlama.
# tuple(callee_names) -> (matched_name, library, purpose)
# NOT: Burada sira ONEMLI degil, set olarak eslestirilir.

_CALL_PATTERN_SIGNATURES: list[tuple[frozenset[str], str, str, str, float]] = [
    # (callee_set, matched_name, library, purpose, confidence)

    # TLS client setup pattern
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_set_fd", "SSL_connect"}),
     "tls_client_connect", "openssl", "complete TLS client handshake", 0.90),

    # TLS server pattern
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_set_fd", "SSL_accept"}),
     "tls_server_accept", "openssl", "complete TLS server accept", 0.90),

    # Certificate verification chain
    (frozenset({"X509_STORE_new", "X509_STORE_add_cert", "X509_STORE_CTX_new", "X509_verify_cert"}),
     "x509_chain_verify", "openssl", "X509 certificate chain verification", 0.85),

    # SHA-256 incremental hash
    (frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}),
     "sha256_hash_buffer", "openssl", "SHA-256 buffer hashing", 0.92),

    # AES-GCM encrypt pattern
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex"}),
     "aes_encrypt", "openssl", "AES encryption", 0.88),

    # AES-GCM decrypt pattern
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex"}),
     "aes_decrypt", "openssl", "AES decryption", 0.88),

    # HMAC computation
    (frozenset({"HMAC_CTX_new", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final"}),
     "hmac_compute", "openssl", "HMAC computation", 0.90),

    # RSA key generation + encryption
    (frozenset({"RSA_new", "RSA_generate_key_ex", "RSA_public_encrypt"}),
     "rsa_keygen_encrypt", "openssl", "RSA key gen + encryption", 0.85),

    # ECDH key exchange
    (frozenset({"EC_KEY_new_by_curve_name", "EC_KEY_generate_key", "ECDH_compute_key"}),
     "ecdh_key_exchange", "openssl", "ECDH key exchange", 0.88),

    # Keychain store + retrieve
    (frozenset({"SecItemAdd", "SecItemCopyMatching"}),
     "keychain_store_retrieve", "Security", "Keychain store and retrieve", 0.85),

    # Code signing verification
    (frozenset({"SecStaticCodeCreateWithPath", "SecCodeCheckValidity", "SecCodeCopySigningInformation"}),
     "codesign_verify", "Security", "code signature validation chain", 0.90),

    # Certificate trust eval
    (frozenset({"SecCertificateCreateWithData", "SecTrustCreateWithCertificates", "SecTrustEvaluateWithError"}),
     "cert_trust_evaluate", "Security", "certificate trust evaluation", 0.88),

    # CommonCrypto encrypt/decrypt
    (frozenset({"CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal", "CCCryptorRelease"}),
     "cc_incremental_crypt", "CommonCrypto", "incremental encryption/decryption", 0.88),

    # PBKDF2 key derivation + encrypt
    (frozenset({"CCKeyDerivationPBKDF", "CCCrypt"}),
     "derive_and_encrypt", "CommonCrypto", "key derivation + encryption", 0.82),

    # SQLite open + prepared statement
    (frozenset({"sqlite3_open_v2", "sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize", "sqlite3_close"}),
     "sqlite_query_lifecycle", "sqlite3", "full query lifecycle", 0.90),

    # SQLite FTS (full-text search)
    (frozenset({"sqlite3_prepare_v2", "sqlite3_bind_text", "sqlite3_step", "sqlite3_column_text"}),
     "sqlite_text_search", "sqlite3", "text search query", 0.75),

    # SQLite transaction
    (frozenset({"sqlite3_exec", "BEGIN", "COMMIT"}),
     "sqlite_transaction", "sqlite3", "database transaction", 0.70),

    # zlib compress pipeline
    (frozenset({"deflateInit2_", "deflate", "deflateEnd"}),
     "zlib_compress_pipeline", "zlib", "zlib compression pipeline", 0.90),

    # zlib decompress pipeline
    (frozenset({"inflateInit2_", "inflate", "inflateEnd"}),
     "zlib_decompress_pipeline", "zlib", "zlib decompression pipeline", 0.90),

    # bzip2 compress pipeline
    (frozenset({"BZ2_bzCompressInit", "BZ2_bzCompress", "BZ2_bzCompressEnd"}),
     "bzip2_compress_pipeline", "bzip2", "bzip2 compression pipeline", 0.90),

    # bzip2 decompress pipeline
    (frozenset({"BZ2_bzDecompressInit", "BZ2_bzDecompress", "BZ2_bzDecompressEnd"}),
     "bzip2_decompress_pipeline", "bzip2", "bzip2 decompression pipeline", 0.90),

    # lz4 frame compress pipeline
    (frozenset({"LZ4F_createCompressionContext", "LZ4F_compressBegin", "LZ4F_compressUpdate", "LZ4F_compressEnd", "LZ4F_freeCompressionContext"}),
     "lz4_frame_compress_pipeline", "lz4", "LZ4 frame compression pipeline", 0.90),

    # lz4 frame decompress pipeline
    (frozenset({"LZ4F_createDecompressionContext", "LZ4F_decompress", "LZ4F_freeDecompressionContext"}),
     "lz4_frame_decompress_pipeline", "lz4", "LZ4 frame decompression pipeline", 0.88),

    # zstd simple compress/decompress
    (frozenset({"ZSTD_compress", "ZSTD_decompress", "ZSTD_compressBound"}),
     "zstd_simple_roundtrip", "zstd", "zstd one-shot compress/decompress", 0.85),

    # zstd streaming compress pipeline
    (frozenset({"ZSTD_createCStream", "ZSTD_initCStream", "ZSTD_compressStream", "ZSTD_endStream", "ZSTD_freeCStream"}),
     "zstd_streaming_compress_pipeline", "zstd", "zstd streaming compression pipeline", 0.90),

    # zstd streaming decompress pipeline
    (frozenset({"ZSTD_createDStream", "ZSTD_initDStream", "ZSTD_decompressStream", "ZSTD_freeDStream"}),
     "zstd_streaming_decompress_pipeline", "zstd", "zstd streaming decompression pipeline", 0.90),

    # zstd context compress
    (frozenset({"ZSTD_createCCtx", "ZSTD_compressCCtx", "ZSTD_freeCCtx"}),
     "zstd_ctx_compress_pipeline", "zstd", "zstd context-based compression", 0.88),

    # cJSON parse + use + cleanup
    (frozenset({"cJSON_Parse", "cJSON_GetObjectItem", "cJSON_Delete"}),
     "cjson_parse_access", "cJSON", "cJSON parse and access", 0.88),

    # cJSON build + print + cleanup
    (frozenset({"cJSON_CreateObject", "cJSON_AddItemToObject", "cJSON_Print", "cJSON_Delete"}),
     "cjson_build_serialize", "cJSON", "cJSON build and serialize", 0.88),

    # jansson parse + use + cleanup
    (frozenset({"json_loads", "json_object_get", "json_decref"}),
     "jansson_parse_access", "jansson", "jansson parse and access", 0.85),

    # libxml2 parse + XPath + cleanup
    (frozenset({"xmlReadMemory", "xmlXPathNewContext", "xmlXPathEvalExpression", "xmlXPathFreeObject", "xmlXPathFreeContext", "xmlFreeDoc"}),
     "libxml2_xpath_query", "libxml2", "libxml2 parse + XPath query", 0.90),

    # libxml2 tree build + save
    (frozenset({"xmlNewDoc", "xmlNewNode", "xmlAddChild", "xmlSaveFormatFile", "xmlFreeDoc"}),
     "libxml2_build_save", "libxml2", "libxml2 tree build + save", 0.88),

    # expat SAX parse
    (frozenset({"XML_ParserCreate", "XML_SetElementHandler", "XML_SetCharacterDataHandler", "XML_Parse", "XML_ParserFree"}),
     "expat_sax_parse", "expat", "expat SAX-style parsing", 0.90),

    # HTTP request with curl
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform", "curl_easy_cleanup"}),
     "http_request", "libcurl", "complete HTTP request", 0.92),

    # HTTP multi transfer
    (frozenset({"curl_multi_init", "curl_multi_add_handle", "curl_multi_perform", "curl_multi_cleanup"}),
     "http_multi_transfer", "libcurl", "concurrent HTTP transfers", 0.88),

    # XPC service setup
    (frozenset({"xpc_connection_create_mach_service", "xpc_connection_set_event_handler", "xpc_connection_resume"}),
     "xpc_service_connect", "libxpc", "XPC service connection", 0.88),

    # Endpoint Security client
    (frozenset({"es_new_client", "es_subscribe", "es_respond_auth_result"}),
     "es_auth_client", "EndpointSecurity", "Endpoint Security auth client", 0.92),

    # Network Extension filter
    (frozenset({"NEFilterDataProvider", "handleNewFlow"}),
     "network_filter", "NetworkExtension", "network content filter", 0.85),

    # GCD parallel execution
    (frozenset({"dispatch_queue_create", "dispatch_async", "dispatch_group_notify"}),
     "parallel_dispatch", "libdispatch", "GCD parallel execution", 0.75),

    # Process spawn + communicate
    (frozenset({"posix_spawn", "waitpid", "pipe", "dup2"}),
     "spawn_with_pipes", "libc", "process spawn with pipe I/O", 0.82),

    # Memory-mapped file read
    (frozenset({"open", "fstat", "mmap", "munmap", "close"}),
     "mmap_file_read", "libc", "memory-mapped file reading", 0.80),

    # ===================================================================
    # EXTENDED CALL PATTERN SIGNATURES (v2 expansion)
    # ===================================================================

    # --- File operations ---
    (frozenset({"fopen", "fread", "fclose"}),
     "read_file", "libc", "file reading (stdio)", 0.85),
    (frozenset({"fopen", "fwrite", "fclose"}),
     "write_file", "libc", "file writing (stdio)", 0.85),
    (frozenset({"open", "read", "close"}),
     "read_file_posix", "libc", "file reading (POSIX)", 0.80),
    (frozenset({"open", "write", "close"}),
     "write_file_posix", "libc", "file writing (POSIX)", 0.80),
    (frozenset({"stat", "access"}),
     "check_file_exists", "libc", "file existence check", 0.75),
    (frozenset({"opendir", "readdir", "closedir"}),
     "list_directory", "libc", "directory listing", 0.85),
    (frozenset({"mkdir", "chmod"}),
     "create_directory", "libc", "directory creation with permissions", 0.80),
    (frozenset({"rename", "unlink"}),
     "move_file", "libc", "file move/rename", 0.75),
    (frozenset({"flock", "open", "close"}),
     "file_locking", "libc", "file-level advisory locking", 0.80),
    (frozenset({"realpath", "stat", "access"}),
     "resolve_path", "libc", "path resolution and validation", 0.75),

    # --- Network operations ---
    (frozenset({"socket", "connect", "send", "recv"}),
     "tcp_client", "libc", "TCP client connection", 0.90),
    (frozenset({"socket", "bind", "listen", "accept"}),
     "tcp_server", "libc", "TCP server setup", 0.90),
    (frozenset({"getaddrinfo", "socket", "connect"}),
     "connect_by_hostname", "libc", "DNS-resolved connection", 0.85),
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"}),
     "http_request_curl", "libcurl", "HTTP request via curl", 0.90),
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_connect"}),
     "tls_connect", "openssl", "TLS client connection", 0.90),
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_accept"}),
     "tls_accept", "openssl", "TLS server accept", 0.90),
    (frozenset({"socket", "sendto", "recvfrom"}),
     "udp_client", "libc", "UDP client communication", 0.85),
    (frozenset({"socket", "setsockopt", "SO_REUSEADDR", "bind"}),
     "server_socket_setup", "libc", "server socket with SO_REUSEADDR", 0.80),
    (frozenset({"select", "FD_SET", "FD_ISSET"}),
     "io_multiplexing_select", "libc", "I/O multiplexing via select()", 0.80),
    (frozenset({"epoll_create", "epoll_ctl", "epoll_wait"}),
     "io_multiplexing_epoll", "libc", "I/O multiplexing via epoll", 0.85),
    (frozenset({"kqueue", "kevent"}),
     "io_multiplexing_kqueue", "libc", "I/O multiplexing via kqueue", 0.85),
    (frozenset({"poll", "POLLIN", "POLLOUT"}),
     "io_multiplexing_poll", "libc", "I/O multiplexing via poll()", 0.80),

    # --- Process operations ---
    (frozenset({"fork", "execve"}),
     "spawn_process", "libc", "fork+exec process spawn", 0.85),
    (frozenset({"posix_spawn"}),
     "spawn_process_posix", "libc", "POSIX process spawn", 0.85),
    (frozenset({"pipe", "fork", "dup2"}),
     "create_pipe_child", "libc", "child process with pipe I/O", 0.90),
    (frozenset({"waitpid", "WEXITSTATUS"}),
     "wait_child_process", "libc", "wait for child process exit", 0.80),
    (frozenset({"kill", "getpid"}),
     "signal_self", "libc", "send signal to process", 0.70),
    (frozenset({"setuid", "setgid", "execve"}),
     "privileged_exec", "libc", "privilege change + exec", 0.85),

    # --- Memory patterns ---
    (frozenset({"malloc", "memcpy", "free"}),
     "copy_buffer", "libc", "heap buffer copy", 0.75),
    (frozenset({"mmap", "mprotect"}),
     "allocate_executable", "libc", "executable memory allocation", 0.80),
    (frozenset({"VirtualAlloc", "VirtualProtect"}),
     "allocate_executable_win", "winapi", "Windows executable memory allocation", 0.85),
    (frozenset({"calloc", "realloc", "free"}),
     "dynamic_array", "libc", "dynamic array management", 0.70),
    (frozenset({"mmap", "msync", "munmap"}),
     "mmap_shared_write", "libc", "memory-mapped shared write", 0.80),

    # --- Threading patterns ---
    (frozenset({"pthread_create", "pthread_join"}),
     "run_in_thread", "libpthread", "thread spawn + join", 0.80),
    (frozenset({"pthread_mutex_lock", "pthread_cond_wait", "pthread_mutex_unlock"}),
     "wait_on_condition", "libpthread", "condition variable wait under mutex", 0.85),
    (frozenset({"dispatch_async", "dispatch_get_global_queue"}),
     "async_dispatch", "libdispatch", "GCD async dispatch to global queue", 0.85),
    (frozenset({"dispatch_group_enter", "dispatch_group_leave", "dispatch_group_wait"}),
     "parallel_tasks", "libdispatch", "GCD parallel task group", 0.85),
    (frozenset({"pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock"}),
     "rwlock_operation", "libpthread", "read-write lock operation", 0.85),
    (frozenset({"dispatch_semaphore_create", "dispatch_semaphore_wait", "dispatch_semaphore_signal"}),
     "gcd_semaphore", "libdispatch", "GCD semaphore synchronization", 0.85),
    (frozenset({"os_unfair_lock_lock", "os_unfair_lock_unlock"}),
     "unfair_lock", "libc", "os_unfair_lock spin lock", 0.80),

    # --- Crypto patterns ---
    (frozenset({"EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex"}),
     "encrypt_data", "openssl", "EVP symmetric encryption", 0.90),
    (frozenset({"EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex"}),
     "decrypt_data", "openssl", "EVP symmetric decryption", 0.90),
    (frozenset({"EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex"}),
     "compute_digest", "openssl", "EVP message digest", 0.90),
    (frozenset({"CCCrypt"}),
     "symmetric_encrypt_decrypt", "CommonCrypto", "CommonCrypto symmetric cipher", 0.85),
    (frozenset({"SecKeyCreateSignature"}),
     "digital_sign", "Security", "Security.framework digital signing", 0.85),
    (frozenset({"SecKeyCreateRandomKey", "SecKeyCopyPublicKey"}),
     "generate_keypair", "Security", "asymmetric key pair generation", 0.85),
    (frozenset({"SecKeyCreateEncryptedData", "SecKeyCreateDecryptedData"}),
     "asymmetric_crypt", "Security", "asymmetric encrypt/decrypt", 0.85),

    # --- Database patterns ---
    (frozenset({"sqlite3_open", "sqlite3_exec", "sqlite3_close"}),
     "simple_db_query", "sqlite3", "simple database query lifecycle", 0.85),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize"}),
     "prepared_statement", "sqlite3", "prepared statement execution", 0.90),
    (frozenset({"sqlite3_bind_text", "sqlite3_step"}),
     "parameterized_query", "sqlite3", "text-parameterized query", 0.85),
    (frozenset({"sqlite3_open_v2", "sqlite3_key", "sqlite3_exec"}),
     "encrypted_db_query", "sqlite3", "encrypted database query", 0.85),
    (frozenset({"sqlite3_backup_init", "sqlite3_backup_step", "sqlite3_backup_finish"}),
     "db_backup", "sqlite3", "online database backup", 0.88),

    # --- macOS-specific patterns ---
    (frozenset({"NSTask", "setLaunchPath", "setArguments", "launch", "waitUntilExit"}),
     "nstask_run", "Foundation", "NSTask subprocess execution", 0.88),
    (frozenset({"CFNotificationCenterGetDarwinNotifyCenter", "CFNotificationCenterPostNotification"}),
     "darwin_notify", "CoreFoundation", "Darwin notification post", 0.85),
    (frozenset({"IOServiceGetMatchingServices", "IOIteratorNext", "IOObjectRelease"}),
     "iokit_iterate_services", "IOKit", "IOKit service iteration", 0.85),
    (frozenset({"SCNetworkReachabilityCreateWithName", "SCNetworkReachabilityGetFlags"}),
     "check_network_reachability", "SystemConfiguration", "network reachability check", 0.85),
    (frozenset({"CGWindowListCopyWindowInfo", "CFArrayGetCount", "CFArrayGetValueAtIndex"}),
     "enumerate_windows", "CoreGraphics", "window list enumeration", 0.80),
]


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


# sig_db Faz 2 — _FINDCRYPT_CONSTANTS override (pilot migration, ayni modul).
if _BUILTIN_CRYPTO_SIGNATURES is not None:
    _FINDCRYPT_CONSTANTS = _BUILTIN_CRYPTO_SIGNATURES.get(
        "findcrypt_constants", _FINDCRYPT_CONSTANTS
    )


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
