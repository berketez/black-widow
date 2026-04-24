"""sig_db Faz 6 — Apple runtime (Obj-C + Swift + CoreFoundation) migration
parity + coverage testleri.

Amac: ``karadul/analyzers/sigdb_builtin/apple_runtime.py`` modulune eklenen
YENI kapsama, orijinal ``karadul/analyzers/signature_db.py`` dict'leriyle
ne olcude uyumlu? Coverage hedefleri tutuyor mu?

  1. ``objc_runtime_signatures``    — YENI dict (~185 entry). Legacy
     ``_MACOS_SYSTEM_SIGNATURES`` icinde `_objc_*` mangled (underscore-prefix)
     sembolleri mevcut; bu modul UNMANGLED varyantlari ekler (cakisma yok).
  2. ``swift_runtime_signatures``   — YENI dict (~130 entry). Legacy
     ``_MACOS_SYSTEM_SIGNATURES`` icinde `_swift_*` mangled sembolleri var;
     bu modul UNMANGLED varyantlari ekler + ABI-stable stdlib mangled isimler.
  3. ``corefoundation_signatures``  — YENI dict (~195 entry). Legacy
     ``_MACOS_EXT_SIGNATURES`` (50+ CF entry'si) ile idempotent overlap
     (ayni ``lib`` / ``purpose`` / ``category="macos_cf"``).

pe_runtime + compression + network + windows_gui migration testlerinin
pattern'ini takip eder.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_apple_runtime_importable() -> None:
    """sigdb_builtin.apple_runtime import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import apple_runtime

    assert hasattr(apple_runtime, "SIGNATURES")
    assert isinstance(apple_runtime.SIGNATURES, dict)
    assert len(apple_runtime.SIGNATURES) == 3


def test_sigdb_builtin_apple_runtime_has_expected_keys() -> None:
    """SIGNATURES uc top-level anahtar icerir: objc / swift / corefoundation."""
    from karadul.analyzers.sigdb_builtin import apple_runtime

    expected = {
        "objc_runtime_signatures",
        "swift_runtime_signatures",
        "corefoundation_signatures",
    }
    assert set(apple_runtime.SIGNATURES.keys()) == expected


def test_sigdb_builtin_apple_runtime_entry_counts() -> None:
    """Her alt dict en az 80 entry icerir (Faz 6 taban hedefi)."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _OBJC_RUNTIME_SIGNATURES_DATA,
        _SWIFT_RUNTIME_SIGNATURES_DATA,
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    assert len(_OBJC_RUNTIME_SIGNATURES_DATA) >= 80, (
        f"objc_runtime min 80 entry bekleniyor; bulundu "
        f"{len(_OBJC_RUNTIME_SIGNATURES_DATA)}"
    )
    assert len(_SWIFT_RUNTIME_SIGNATURES_DATA) >= 80, (
        f"swift_runtime min 80 entry bekleniyor; bulundu "
        f"{len(_SWIFT_RUNTIME_SIGNATURES_DATA)}"
    )
    assert len(_COREFOUNDATION_SIGNATURES_DATA) >= 80, (
        f"corefoundation min 80 entry bekleniyor; bulundu "
        f"{len(_COREFOUNDATION_SIGNATURES_DATA)}"
    )

    total = (
        len(_OBJC_RUNTIME_SIGNATURES_DATA)
        + len(_SWIFT_RUNTIME_SIGNATURES_DATA)
        + len(_COREFOUNDATION_SIGNATURES_DATA)
    )
    assert total >= 300, f"Toplam apple_runtime entry sayisi en az 300 olmali; bulundu {total}"


# ---------------------------------------------------------------------------
# 2. Override aktif mi? (identity / is check)
# ---------------------------------------------------------------------------

def test_override_apple_runtime_identity() -> None:
    """signature_db.py icindeki dict'ler builtin.apple_runtime ile ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _OBJC_RUNTIME_SIGNATURES_DATA,
        _SWIFT_RUNTIME_SIGNATURES_DATA,
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    assert sdb._BUILTIN_APPLE_RUNTIME_SIGNATURES is not None
    assert sdb._APPLE_OBJC_RUNTIME_SIGNATURES is _OBJC_RUNTIME_SIGNATURES_DATA
    assert sdb._APPLE_SWIFT_RUNTIME_SIGNATURES is _SWIFT_RUNTIME_SIGNATURES_DATA
    assert sdb._APPLE_COREFOUNDATION_SIGNATURES is _COREFOUNDATION_SIGNATURES_DATA


def test_legacy_macos_attributes_still_accessible() -> None:
    """Backward compat: eski legacy macOS dict'leri hala erisilebilir, dolu."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_MACOS_SYSTEM_SIGNATURES")
    assert hasattr(sdb, "_MACOS_EXT_SIGNATURES")
    assert len(sdb._MACOS_SYSTEM_SIGNATURES) > 0
    assert len(sdb._MACOS_EXT_SIGNATURES) > 0


# ---------------------------------------------------------------------------
# 3. Schema parity — her entry'de lib + purpose + category var
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dict_name", [
    "objc_runtime_signatures",
    "swift_runtime_signatures",
    "corefoundation_signatures",
])
def test_schema_all_entries_have_required_fields(dict_name: str) -> None:
    """Her entry ``lib``, ``purpose``, ``category`` alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import SIGNATURES

    required = {"lib", "purpose", "category"}
    bad: dict[str, set[str]] = {}
    for name, info in SIGNATURES[dict_name].items():
        assert isinstance(info, dict), f"{name}: dict degil"
        missing = required - info.keys()
        if missing:
            bad[name] = missing
    assert not bad, f"{dict_name}: eksik alan(lar) {bad}"


# ---------------------------------------------------------------------------
# 4. lib / category etiket dogrulamasi
# ---------------------------------------------------------------------------

def test_objc_runtime_lib_labels_valid() -> None:
    """Obj-C runtime entry'lerinin lib etiketi ``libobjc`` veya ``Foundation``."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _OBJC_RUNTIME_SIGNATURES_DATA,
    )

    allowed = {"libobjc", "Foundation"}
    bad = {
        n: info["lib"]
        for n, info in _OBJC_RUNTIME_SIGNATURES_DATA.items()
        if info["lib"] not in allowed
    }
    assert not bad, f"Obj-C runtime beklenmeyen lib etiketleri: {bad}"


def test_objc_runtime_category_is_objc_runtime() -> None:
    """Tum Obj-C runtime entry'lerinin category'si ``objc_runtime``."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _OBJC_RUNTIME_SIGNATURES_DATA,
    )

    bad = {
        n: info["category"]
        for n, info in _OBJC_RUNTIME_SIGNATURES_DATA.items()
        if info["category"] != "objc_runtime"
    }
    assert not bad, f"Obj-C runtime beklenmeyen category: {bad}"


def test_swift_runtime_lib_is_libswiftcore() -> None:
    """Tum Swift runtime entry'lerinin lib'i ``libswiftCore``."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _SWIFT_RUNTIME_SIGNATURES_DATA,
    )

    bad = {
        n: info["lib"]
        for n, info in _SWIFT_RUNTIME_SIGNATURES_DATA.items()
        if info["lib"] != "libswiftCore"
    }
    assert not bad, f"Swift runtime beklenmeyen lib: {bad}"


def test_swift_runtime_category_is_swift_runtime() -> None:
    """Tum Swift runtime entry'lerinin category'si ``swift_runtime``."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _SWIFT_RUNTIME_SIGNATURES_DATA,
    )

    bad = {
        n: info["category"]
        for n, info in _SWIFT_RUNTIME_SIGNATURES_DATA.items()
        if info["category"] != "swift_runtime"
    }
    assert not bad, f"Swift runtime beklenmeyen category: {bad}"


def test_corefoundation_lib_is_corefoundation() -> None:
    """Tum CF entry'lerinin lib'i ``CoreFoundation``."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    bad = {
        n: info["lib"]
        for n, info in _COREFOUNDATION_SIGNATURES_DATA.items()
        if info["lib"] != "CoreFoundation"
    }
    assert not bad, f"CoreFoundation beklenmeyen lib: {bad}"


def test_corefoundation_category_is_macos_cf() -> None:
    """Tum CF entry'lerinin category'si ``macos_cf`` (legacy ile parity)."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    bad = {
        n: info["category"]
        for n, info in _COREFOUNDATION_SIGNATURES_DATA.items()
        if info["category"] != "macos_cf"
    }
    assert not bad, f"CF beklenmeyen category: {bad}"


# ---------------------------------------------------------------------------
# 5. Idempotent overlap — legacy `_MACOS_EXT_SIGNATURES` CF entry'leri ile
# ---------------------------------------------------------------------------

def test_corefoundation_macos_ext_overlap_is_idempotent() -> None:
    """Legacy _MACOS_EXT_SIGNATURES CF entry'leri ile cakisma ayni icerikle."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    overlap = set(_COREFOUNDATION_SIGNATURES_DATA) & set(sdb._MACOS_EXT_SIGNATURES)
    conflicts = {
        k: (_COREFOUNDATION_SIGNATURES_DATA[k], sdb._MACOS_EXT_SIGNATURES[k])
        for k in overlap
        if _COREFOUNDATION_SIGNATURES_DATA[k] != sdb._MACOS_EXT_SIGNATURES[k]
    }
    assert not conflicts, (
        f"Legacy _MACOS_EXT_SIGNATURES ile cakisan {len(conflicts)} CF entry "
        f"farkli icerige sahip: {list(conflicts)[:5]}"
    )
    # Overlap gercekten var olmali (CFRetain/Release/RunLoopRun vb.)
    assert len(overlap) >= 20, (
        f"Legacy _MACOS_EXT_SIGNATURES ile CF overlap cok az: {len(overlap)}"
    )


# ---------------------------------------------------------------------------
# 6. Anahtar icerik testi — beklenen sembolleri kapsamis mi?
# ---------------------------------------------------------------------------

def test_objc_runtime_core_symbols_present() -> None:
    """Obj-C runtime'in temel sembolleri icerir."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _OBJC_RUNTIME_SIGNATURES_DATA,
    )

    core = {
        "objc_msgSend", "objc_msgSendSuper", "objc_msgSend_stret",
        "objc_retain", "objc_release", "objc_autorelease",
        "objc_retainAutoreleasedReturnValue", "objc_storeStrong",
        "objc_storeWeak", "objc_loadWeakRetained", "objc_destroyWeak",
        "objc_autoreleasePoolPush", "objc_autoreleasePoolPop",
        "objc_getClass", "objc_lookUpClass",
        "objc_allocateClassPair", "objc_registerClassPair",
        "objc_setAssociatedObject", "objc_getAssociatedObject",
        "class_getName", "class_getSuperclass",
        "class_addMethod", "class_addIvar",
        "sel_registerName", "sel_getName",
        "method_getName", "method_getImplementation",
        "Block_copy", "Block_release",
        "_Block_object_assign", "_Block_object_dispose",
        "NSLog", "NSClassFromString", "NSStringFromClass",
    }
    missing = core - _OBJC_RUNTIME_SIGNATURES_DATA.keys()
    assert not missing, f"Obj-C runtime temel semboller eksik: {missing}"


def test_swift_runtime_core_symbols_present() -> None:
    """Swift runtime'in temel sembolleri icerir."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _SWIFT_RUNTIME_SIGNATURES_DATA,
    )

    core = {
        "swift_retain", "swift_release", "swift_tryRetain",
        "swift_retain_n", "swift_release_n",
        "swift_allocObject", "swift_deallocObject", "swift_deallocClassInstance",
        "swift_weakInit", "swift_weakAssign", "swift_weakLoadStrong",
        "swift_weakDestroy",
        "swift_unknownObjectRetain", "swift_unknownObjectRelease",
        "swift_bridgeObjectRetain", "swift_bridgeObjectRelease",
        "swift_conformsToProtocol",
        "swift_allocateGenericValueMetadata",
        "swift_dynamicCastClass", "swift_dynamicCastObjCClass",
        "swift_dynamicCastMetatype",
        "swift_errorRetain", "swift_errorRelease",
    }
    missing = core - _SWIFT_RUNTIME_SIGNATURES_DATA.keys()
    assert not missing, f"Swift runtime temel semboller eksik: {missing}"


def test_swift_stdlib_mangled_symbols_present() -> None:
    """Swift std lib ABI-stable mangled sembolleri (en az 10 adet)."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _SWIFT_RUNTIME_SIGNATURES_DATA,
    )

    mangled = [
        k for k in _SWIFT_RUNTIME_SIGNATURES_DATA.keys()
        if k.startswith("$s") or k.startswith("$ss")
    ]
    assert len(mangled) >= 10, (
        f"Swift stdlib mangled sembolleri ($sSS.../$ss...) en az 10 olmali; "
        f"bulundu {len(mangled)}"
    )


def test_corefoundation_core_symbols_present() -> None:
    """CoreFoundation'un temel sembolleri icerir."""
    from karadul.analyzers.sigdb_builtin.apple_runtime import (
        _COREFOUNDATION_SIGNATURES_DATA,
    )

    core = {
        "CFRetain", "CFRelease", "CFAutorelease", "CFGetRetainCount",
        "CFStringCreateWithCString", "CFStringGetCString", "CFStringGetLength",
        "CFArrayCreate", "CFArrayGetCount", "CFArrayGetValueAtIndex",
        "CFDictionaryCreate", "CFDictionaryGetValue", "CFDictionarySetValue",
        "CFDataCreate", "CFDataGetLength", "CFDataGetBytePtr",
        "CFNumberCreate", "CFNumberGetValue",
        "CFBundleGetBundleWithIdentifier", "CFBundleGetMainBundle",
        "CFRunLoopRun", "CFRunLoopStop", "CFRunLoopGetMain",
    }
    missing = core - _COREFOUNDATION_SIGNATURES_DATA.keys()
    assert not missing, f"CF temel semboller eksik: {missing}"


# ---------------------------------------------------------------------------
# 7. Platform filter testi — Mach-O-only dogrulamasi
# ---------------------------------------------------------------------------

def test_platform_filter_objc_runtime_macho_only() -> None:
    """objc_runtime kategori + libobjc lib Mach-O'ya filtrelenmeli."""
    from karadul.analyzers.signature_db import _is_platform_compatible

    # macho: izin
    assert _is_platform_compatible("libobjc", "objc_runtime", "macho") is True
    # pe: blok (lib + category ikisi de)
    assert _is_platform_compatible("libobjc", "objc_runtime", "pe") is False
    # elf: blok
    assert _is_platform_compatible("libobjc", "objc_runtime", "elf") is False


def test_platform_filter_swift_runtime_macho_only() -> None:
    """swift_runtime kategori + libswiftCore lib Mach-O'ya filtrelenmeli."""
    from karadul.analyzers.signature_db import _is_platform_compatible

    # macho: izin
    assert _is_platform_compatible("libswiftCore", "swift_runtime", "macho") is True
    # pe: blok
    assert _is_platform_compatible("libswiftCore", "swift_runtime", "pe") is False
    # elf: blok
    assert _is_platform_compatible("libswiftCore", "swift_runtime", "elf") is False


def test_platform_filter_corefoundation_macho_only() -> None:
    """CoreFoundation lib + macos_cf category Mach-O'ya filtrelenmeli."""
    from karadul.analyzers.signature_db import _is_platform_compatible

    # macho: izin
    assert _is_platform_compatible("CoreFoundation", "macos_cf", "macho") is True
    # pe: blok
    assert _is_platform_compatible("CoreFoundation", "macos_cf", "pe") is False
    # elf: blok
    assert _is_platform_compatible("CoreFoundation", "macos_cf", "elf") is False


def test_platform_filter_foundation_nslog_macho_only() -> None:
    """Foundation lib (NSLog vb.) Mach-O'ya filtrelenmeli."""
    from karadul.analyzers.signature_db import _is_platform_compatible

    # Foundation lib _MACHO_ONLY_LIBS'te oldugu icin category fark etmeksizin blok
    assert _is_platform_compatible("Foundation", "objc_runtime", "macho") is True
    assert _is_platform_compatible("Foundation", "objc_runtime", "pe") is False


def test_macho_only_category_prefixes_includes_swift_runtime() -> None:
    """_MACHO_ONLY_CATEGORY_PREFIXES tuple'inda ``swift_runtime`` olmali."""
    from karadul.analyzers.signature_db import _MACHO_ONLY_CATEGORY_PREFIXES

    assert "objc_runtime" in _MACHO_ONLY_CATEGORY_PREFIXES
    assert "swift_runtime" in _MACHO_ONLY_CATEGORY_PREFIXES


def test_macho_only_libs_includes_libswiftcore() -> None:
    """_MACHO_ONLY_LIBS frozenset'inde ``libswiftCore`` olmali."""
    from karadul.analyzers.signature_db import _MACHO_ONLY_LIBS

    assert "libswiftCore" in _MACHO_ONLY_LIBS
    assert "libobjc" in _MACHO_ONLY_LIBS
    assert "CoreFoundation" in _MACHO_ONLY_LIBS
    assert "Foundation" in _MACHO_ONLY_LIBS


# ---------------------------------------------------------------------------
# 8. SignatureDB class kullanimi — apple runtime gercekten yuklendi mi?
# ---------------------------------------------------------------------------

def _fresh_signature_db():
    """_full_cache'i temizleyip taze SignatureDB olustur."""
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    SignatureDB._full_cache.clear()
    return SignatureDB(Config())


def test_signature_db_loads_objc_runtime_symbols() -> None:
    """SignatureDB instance Obj-C runtime sembollerini icerir."""
    db = _fresh_signature_db()

    assert "objc_msgSend" in db._symbol_db
    entry = db._symbol_db["objc_msgSend"]
    assert entry["lib"] == "libobjc"
    assert entry["category"] == "objc_runtime"

    assert "objc_retain" in db._symbol_db
    assert "NSLog" in db._symbol_db
    assert db._symbol_db["NSLog"]["lib"] == "Foundation"


def test_signature_db_loads_swift_runtime_symbols() -> None:
    """SignatureDB instance Swift runtime sembollerini icerir."""
    db = _fresh_signature_db()

    assert "swift_retain" in db._symbol_db
    entry = db._symbol_db["swift_retain"]
    assert entry["lib"] == "libswiftCore"
    assert entry["category"] == "swift_runtime"

    assert "swift_allocObject" in db._symbol_db
    assert "swift_dynamicCastClass" in db._symbol_db


def test_signature_db_loads_corefoundation_symbols() -> None:
    """SignatureDB instance CoreFoundation sembollerini icerir."""
    db = _fresh_signature_db()

    assert "CFRetain" in db._symbol_db
    entry = db._symbol_db["CFRetain"]
    assert entry["lib"] == "CoreFoundation"
    assert entry["category"] == "macos_cf"

    assert "CFStringCreateWithCString" in db._symbol_db
    assert "CFBundleGetMainBundle" in db._symbol_db
    assert "CFRunLoopRun" in db._symbol_db


# ---------------------------------------------------------------------------
# 9. Regression: onceki migrasyonlar hala saglam
# ---------------------------------------------------------------------------

def test_previous_migrations_still_intact() -> None:
    """Crypto / compression / network / pe_runtime / windows_gui yuklenebilir."""
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES as comp
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES as cry
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as net
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as pe
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES as gui

    assert len(cry) == 6   # openssl, boringssl, libsodium, mbedtls, wincrypto, findcrypt
    assert len(comp) == 5  # zlib, bzip2, lz4, zstd, compression_ext
    assert len(net) == 7   # libcurl, posix_net, nghttp2, websocket, macos_net, apple_nw, net_ext
    assert len(pe) == 3    # kernel32, ntdll, msvc_crt
    assert len(gui) == 3   # user32, advapi32, gdi32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
