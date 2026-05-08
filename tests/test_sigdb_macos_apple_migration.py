"""sig_db macos_apple migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.macos_apple import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. No duplicate keys
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_MACOS_APPLE_SIGS`` referansi VAR.

NOT: ``_MACOS_NETWORKING_SIGNATURES`` ve ``_APPLE_NETWORK_FRAMEWORK_SIGNATURES``
network builtin modulu uzerinden geliyor (``_BUILTIN_NETWORK_SIGNATURES``);
diger 12 dict ise dogrudan macos_apple modulunden.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Sabitler — beklenen entry sayilari
# ---------------------------------------------------------------------------

EXPECTED_COUNTS: dict[str, int] = {
    "macos_system": 310,
    "macos_networking": 50,
    "ipc_xpc": 51,
    "apple_coredata": 16,
    "apple_webkit": 13,
    "apple_corelocation": 9,
    "apple_corebluetooth": 11,
    "apple_storekit": 10,
    "apple_usernotifications": 11,
    "apple_network_framework": 35,
    "apple_endpoint_security_ext": 14,
    "apple_systemextensions": 3,
    "apple_appkit": 77,
    "macos_ext": 99,
}

LEGACY_NAME_MAP: dict[str, str] = {
    "macos_system": "_MACOS_SYSTEM_SIGNATURES",
    "macos_networking": "_MACOS_NETWORKING_SIGNATURES",
    "ipc_xpc": "_IPC_XPC_SIGNATURES",
    "apple_coredata": "_APPLE_COREDATA_SIGNATURES",
    "apple_webkit": "_APPLE_WEBKIT_SIGNATURES",
    "apple_corelocation": "_APPLE_CORELOCATION_SIGNATURES",
    "apple_corebluetooth": "_APPLE_COREBLUETOOTH_SIGNATURES",
    "apple_storekit": "_APPLE_STOREKIT_SIGNATURES",
    "apple_usernotifications": "_APPLE_USERNOTIFICATIONS_SIGNATURES",
    "apple_network_framework": "_APPLE_NETWORK_FRAMEWORK_SIGNATURES",
    "apple_endpoint_security_ext": "_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES",
    "apple_systemextensions": "_APPLE_SYSTEMEXTENSIONS_SIGNATURES",
    "apple_appkit": "_APPLE_APPKIT_SIGNATURES",
    "macos_ext": "_MACOS_EXT_SIGNATURES",
}

# Bu iki dict signature_db.py'da network builtin modulu uzerinden geliyor;
# macos_apple builtin'inden FARKLI bir kaynaga point ediyor olabilir.
# Bu yuzden runtime identity testinde sadece esit (==) icerik dogrulamasi yapilir.
_NETWORK_PROVIDED: set[str] = {"macos_networking", "apple_network_framework"}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_macos_apple_importable() -> None:
    """sigdb_builtin.macos_apple import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import macos_apple as ma_mod

    assert hasattr(ma_mod, "SIGNATURES")
    assert isinstance(ma_mod.SIGNATURES, dict)
    assert len(ma_mod.SIGNATURES) == 14


def test_sigdb_builtin_macos_apple_has_expected_keys() -> None:
    """SIGNATURES tam 14 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import macos_apple as ma_mod

    assert set(ma_mod.SIGNATURES.keys()) == set(EXPECTED_COUNTS.keys())


# ---------------------------------------------------------------------------
# 2. Coverage — her kategori beklenen entry sayisina sahip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,expected", sorted(EXPECTED_COUNTS.items()))
def test_coverage_count_per_category(key: str, expected: int) -> None:
    """Her macos_apple kategorisi tam entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import macos_apple as ma_mod

    actual = len(ma_mod.SIGNATURES[key])
    assert actual == expected, f"{key}: expected {expected}, got {actual}"


def test_coverage_count_total() -> None:
    """Toplam entry sayisi 709."""
    from karadul.analyzers.sigdb_builtin import macos_apple as ma_mod

    total = sum(len(v) for v in ma_mod.SIGNATURES.values())
    assert total == 709, f"macos_apple total entry count: expected 709, got {total}"
    assert total == sum(EXPECTED_COUNTS.values())


# ---------------------------------------------------------------------------
# 3. Anahtar guvenligi — dict basina entry semasi tutarli
# ---------------------------------------------------------------------------

def test_no_duplicate_keys_within_each_dict() -> None:
    """Her dict icindeki entry'ler {lib, purpose, category} icerir."""
    from karadul.analyzers.sigdb_builtin import macos_apple as ma_mod

    for key, sigs in ma_mod.SIGNATURES.items():
        for name, entry in sigs.items():
            assert isinstance(name, str), f"{key}: non-str key {name!r}"
            assert isinstance(entry, dict), f"{key}/{name}: value not dict"
            assert "lib" in entry, f"{key}/{name}: 'lib' missing"
            assert "purpose" in entry, f"{key}/{name}: 'purpose' missing"
            assert "category" in entry, f"{key}/{name}: 'category' missing"


# ---------------------------------------------------------------------------
# 4. Runtime identity / equality — signature_db legacy <-> builtin
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(LEGACY_NAME_MAP.items()))
def test_runtime_parity(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin macos_apple[<key>] icerik olarak ayni.

    macos_networking/apple_network_framework dict'leri network builtin'den
    aliniyor; bu yuzden identity (`is`) yerine equality (`==`) testi yapariz.
    Diger 12 dict icin identity korunur.
    """
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    legacy = getattr(sdb, legacy_name)
    migrated = SIGNATURES[builtin_key]

    if builtin_key in _NETWORK_PROVIDED:
        assert legacy == migrated, (
            f"{legacy_name} <-> {builtin_key} icerik esitlik ihlali"
        )
    else:
        assert legacy is migrated, (
            f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
        )
    assert len(migrated) == EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 5. Dispatcher (get_category)
# ---------------------------------------------------------------------------

def test_get_category_macos_apple_returns_data() -> None:
    """sigdb_builtin.get_category('macos_apple') 14 alt-key dolu dict dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("macos_apple")
    assert isinstance(sigs, dict)
    assert len(sigs) == 14
    for key in EXPECTED_COUNTS:
        assert key in sigs, f"get_category('macos_apple') eksik key: {key}"


# ---------------------------------------------------------------------------
# 6. Bilindik Apple/macOS sembolleri
# ---------------------------------------------------------------------------

def test_known_apple_symbols_libdispatch() -> None:
    """libdispatch (GCD) temel sembolleri tasinmis."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    macos_system = SIGNATURES["macos_system"]
    assert "_dispatch_async" in macos_system
    assert "_dispatch_sync" in macos_system
    assert "_dispatch_once" in macos_system
    entry = macos_system["_dispatch_async"]
    assert entry["lib"] == "libdispatch"
    assert entry["category"] == "concurrency"


def test_known_apple_symbols_libobjc() -> None:
    """ObjC runtime temel sembolleri (objc_msgSend kritik)."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    macos_system = SIGNATURES["macos_system"]
    assert "_objc_msgSend" in macos_system
    assert "_objc_retain" in macos_system
    assert "_objc_release" in macos_system
    assert macos_system["_objc_msgSend"]["lib"] == "libobjc"


def test_known_apple_symbols_swift_runtime() -> None:
    """Swift runtime ARC ve concurrency sembolleri tasinmis."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    macos_system = SIGNATURES["macos_system"]
    assert "_swift_retain" in macos_system
    assert "_swift_release" in macos_system
    assert "_swift_task_create" in macos_system
    assert macos_system["_swift_retain"]["lib"] == "swift_runtime"
    assert macos_system["_swift_task_create"]["category"] == "concurrency"


def test_known_apple_symbols_xpc() -> None:
    """XPC + NSXPC sembolleri ipc_xpc dict'inde."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    ipc_xpc = SIGNATURES["ipc_xpc"]
    assert "_xpc_connection_create" in ipc_xpc
    assert "_xpc_dictionary_set_int64" in ipc_xpc
    assert "_OBJC_CLASS_$_NSXPCConnection" in ipc_xpc
    assert ipc_xpc["_xpc_connection_create"]["lib"] == "libxpc"
    assert ipc_xpc["_xpc_connection_create"]["category"] == "ipc"


def test_known_apple_symbols_nsurlsession_appkit() -> None:
    """NSURLSession Foundation/AppKit dict'inde + Foundation lib markasi."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    appkit = SIGNATURES["apple_appkit"]
    assert "_OBJC_CLASS_$_NSURLSession" in appkit
    assert "_OBJC_CLASS_$_NSApplication" in appkit
    assert appkit["_OBJC_CLASS_$_NSApplication"]["lib"] == "AppKit"
    assert appkit["_OBJC_CLASS_$_NSURLSession"]["lib"] == "Foundation"


def test_known_apple_symbols_webkit() -> None:
    """WKWebView ve delegate protocol'leri webkit dict'inde."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    webkit = SIGNATURES["apple_webkit"]
    assert "_OBJC_CLASS_$_WKWebView" in webkit
    assert "_OBJC_PROTOCOL_$_WKNavigationDelegate" in webkit
    assert webkit["_OBJC_CLASS_$_WKWebView"]["lib"] == "WebKit"


def test_known_apple_symbols_mach_kernel() -> None:
    """Mach kernel (mach_task_self / mach_msg / task_for_pid) macos_ext'te."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    macos_ext = SIGNATURES["macos_ext"]
    assert "mach_task_self" in macos_ext
    assert "mach_msg" in macos_ext
    assert "task_for_pid" in macos_ext
    assert macos_ext["mach_task_self"]["lib"] == "mach"
    assert macos_ext["mach_task_self"]["category"] == "macos_kernel"


def test_known_apple_symbols_endpoint_security_ext() -> None:
    """ES extended (mute, message, exec arg/env) eklenti dict'inde."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    es_ext = SIGNATURES["apple_endpoint_security_ext"]
    assert "_es_mute_path" in es_ext
    assert "_es_exec_arg" in es_ext
    assert es_ext["_es_mute_path"]["lib"] == "EndpointSecurity"
    assert es_ext["_es_mute_path"]["category"] == "security"


# ---------------------------------------------------------------------------
# 7. Negatif test
# ---------------------------------------------------------------------------

def test_swift_symbol_not_in_appkit_dict() -> None:
    """Swift runtime sembolu sadece macos_system'da, AppKit'te degil."""
    from karadul.analyzers.sigdb_builtin.macos_apple import SIGNATURES

    assert "_swift_retain" not in SIGNATURES["apple_appkit"]
    assert "_swift_retain" in SIGNATURES["macos_system"]


# ---------------------------------------------------------------------------
# 8. Post-A-DELETE: legacy literal silindi, dogrudan referans kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # En az birkac referans olmali
    assert (
        '_MACOS_SYSTEM_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_MACOS_APPLE_SIGS["macos_system"]'
    ) in text
    assert (
        '_IPC_XPC_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_MACOS_APPLE_SIGS["ipc_xpc"]'
    ) in text
    assert (
        '_APPLE_APPKIT_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_MACOS_APPLE_SIGS["apple_appkit"]'
    ) in text
    # Inline literal blok baslangici YOK
    for legacy in LEGACY_NAME_MAP.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py macos_apple SIGNATURES'i ``sigdb_builtin.macos_apple``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_MACOS_APPLE_SIGS" in text
    assert "sigdb_builtin" in text and "macos_apple" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
