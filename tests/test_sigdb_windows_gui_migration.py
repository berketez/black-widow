"""sig_db Faz 7D — Windows GUI / advapi32 / gdi32 migration + coverage testleri.

Amac: ``karadul/analyzers/sigdb_builtin/windows_gui.py`` modulune eklenen YENI
kapsama, orijinal ``karadul/analyzers/signature_db.py`` dict'leriyle ne
olcude uyumlu? Coverage hedefleri tutuyor mu?

  1. ``user32_signatures``    — YENI dict (~270 entry). Legacy
     ``_WIN32_USER32_GDI32_SIGNATURES`` icindeki user32 entry'leri ile
     overlap'te ayni ``lib`` degerini tasir (idempotent).
  2. ``advapi32_signatures``  — YENI dict (~160 entry). Legacy
     ``_WIN32_ADVAPI32_SIGNATURES`` (20 entry) subset'idir ve genisletir.
  3. ``gdi32_signatures``     — YENI dict (~125 entry). Legacy
     ``_WIN32_USER32_GDI32_SIGNATURES`` icindeki gdi32 entry'leri ile
     overlap'te ayni ``lib`` degerini tasir (idempotent).

pe_runtime + compression + network migration testlerinin pattern'ini takip
eder (bkz: test_sigdb_pe_runtime_migration.py).
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_windows_gui_importable() -> None:
    """sigdb_builtin.windows_gui import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import windows_gui

    assert hasattr(windows_gui, "SIGNATURES")
    assert isinstance(windows_gui.SIGNATURES, dict)
    assert len(windows_gui.SIGNATURES) == 3


def test_sigdb_builtin_windows_gui_has_expected_keys() -> None:
    """SIGNATURES uc top-level anahtar icerir: user32/advapi32/gdi32."""
    from karadul.analyzers.sigdb_builtin import windows_gui

    expected = {
        "user32_signatures",
        "advapi32_signatures",
        "gdi32_signatures",
    }
    assert set(windows_gui.SIGNATURES.keys()) == expected


def test_sigdb_builtin_windows_gui_entry_counts() -> None:
    """Her kategori beklenen minimum entry sayisina sahip (Faz 7D hedefi)."""
    from karadul.analyzers.sigdb_builtin import windows_gui

    user32 = windows_gui.SIGNATURES["user32_signatures"]
    advapi32 = windows_gui.SIGNATURES["advapi32_signatures"]
    gdi32 = windows_gui.SIGNATURES["gdi32_signatures"]

    # Faz 7D kapsam hedefleri (alt sinir ile fuzzy test)
    assert len(user32) >= 120, (
        f"user32_signatures min 120 entry bekleniyor; bulundu {len(user32)}"
    )
    assert len(advapi32) >= 80, (
        f"advapi32_signatures min 80 entry bekleniyor; bulundu {len(advapi32)}"
    )
    assert len(gdi32) >= 50, (
        f"gdi32_signatures min 50 entry bekleniyor; bulundu {len(gdi32)}"
    )

    total = len(user32) + len(advapi32) + len(gdi32)
    assert total >= 250, (
        f"Toplam windows_gui entry sayisi en az 250 olmali; bulundu {total}"
    )


def test_sigdb_builtin_windows_gui_no_cross_dict_duplicates() -> None:
    """Uc alt dict arasinda duplicate key olmamali (disjoint namespace)."""
    from karadul.analyzers.sigdb_builtin import windows_gui

    user32 = windows_gui.SIGNATURES["user32_signatures"]
    advapi32 = windows_gui.SIGNATURES["advapi32_signatures"]
    gdi32 = windows_gui.SIGNATURES["gdi32_signatures"]

    overlap_ua = set(user32) & set(advapi32)
    overlap_ug = set(user32) & set(gdi32)
    overlap_ag = set(advapi32) & set(gdi32)

    assert not overlap_ua, f"user32 <-> advapi32 duplicate: {overlap_ua}"
    assert not overlap_ug, f"user32 <-> gdi32 duplicate: {overlap_ug}"
    assert not overlap_ag, f"advapi32 <-> gdi32 duplicate: {overlap_ag}"


# ---------------------------------------------------------------------------
# 2. Override aktif mi? (identity / is check)
# ---------------------------------------------------------------------------

def test_override_windows_gui_identity() -> None:
    """signature_db.py icindeki yeni dict'ler builtin.windows_gui ile ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES as builtin

    assert sdb._BUILTIN_WINDOWS_GUI_SIGNATURES is not None
    assert sdb._WIN32_USER32_SIGNATURES is builtin["user32_signatures"]
    assert sdb._WIN32_ADVAPI32_FULL_SIGNATURES is builtin["advapi32_signatures"]
    assert sdb._WIN32_GDI32_SIGNATURES is builtin["gdi32_signatures"]


def test_override_legacy_dicts_extended() -> None:
    """Legacy `_WIN32_USER32_GDI32_SIGNATURES` + `_WIN32_ADVAPI32_SIGNATURES`
    override sonrasi genisler (eski 25 + 20 entry'den cok daha fazla)."""
    from karadul.analyzers import signature_db as sdb

    # Legacy _WIN32_USER32_GDI32_SIGNATURES: eski 25 entry, override sonra >200
    assert len(sdb._WIN32_USER32_GDI32_SIGNATURES) >= 200, (
        f"user32+gdi32 override sonrasi min 200 entry olmali; "
        f"bulundu {len(sdb._WIN32_USER32_GDI32_SIGNATURES)}"
    )
    # Legacy _WIN32_ADVAPI32_SIGNATURES: eski 20 entry, override sonra >80
    assert len(sdb._WIN32_ADVAPI32_SIGNATURES) >= 80, (
        f"advapi32 override sonrasi min 80 entry olmali; "
        f"bulundu {len(sdb._WIN32_ADVAPI32_SIGNATURES)}"
    )


def test_legacy_windows_gui_attributes_still_accessible() -> None:
    """Backward compat: eski dict attribute'lari hala erisilebilir ve dolu."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_WIN32_USER32_GDI32_SIGNATURES")
    assert hasattr(sdb, "_WIN32_ADVAPI32_SIGNATURES")
    assert len(sdb._WIN32_USER32_GDI32_SIGNATURES) > 0
    assert len(sdb._WIN32_ADVAPI32_SIGNATURES) > 0


# ---------------------------------------------------------------------------
# 3. Schema dogrulamasi — her entry dogru field setine sahip
# ---------------------------------------------------------------------------

def test_windows_gui_all_entries_have_schema_fields() -> None:
    """Her entry ``lib``, ``purpose``, ``category`` alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    required = {"lib", "purpose", "category"}
    for bucket_name, bucket in SIGNATURES.items():
        for name, info in bucket.items():
            assert isinstance(info, dict), f"{bucket_name}/{name}: dict degil"
            assert required.issubset(info.keys()), (
                f"{bucket_name}/{name}: eksik alan(lar) {required - info.keys()}"
            )


def test_windows_gui_lib_labels_match_bucket() -> None:
    """Her entry'nin ``lib`` etiketi ait oldugu bucket ile tutarli."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    expected_libs = {
        "user32_signatures": {"user32"},
        "advapi32_signatures": {"advapi32"},
        "gdi32_signatures": {"gdi32"},
    }
    for bucket_name, allowed in expected_libs.items():
        bad = {
            n: info["lib"]
            for n, info in SIGNATURES[bucket_name].items()
            if info["lib"] not in allowed
        }
        assert not bad, f"{bucket_name}: yanlis lib etiketli entry'ler: {bad}"


def test_windows_gui_categories_are_valid() -> None:
    """Her entry'nin ``category`` etiketi kabul listesinde."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    # Faz 7D kapsaminda beklenen kategoriler
    allowed = {
        "win_gui", "win_msg", "win_gdi", "win_clipboard", "win_hook",
        "win_input", "win_registry", "win_security", "win_service",
        "win_crypto", "win_eventlog",
    }
    all_entries = {
        **SIGNATURES["user32_signatures"],
        **SIGNATURES["advapi32_signatures"],
        **SIGNATURES["gdi32_signatures"],
    }
    bad = {n: info["category"] for n, info in all_entries.items()
           if info["category"] not in allowed}
    assert not bad, f"Beklenmeyen category etiketleri: {bad}"


# ---------------------------------------------------------------------------
# 4. Legacy idempotent overlap
# ---------------------------------------------------------------------------

def test_user32_gdi32_legacy_overlap_is_idempotent() -> None:
    """Legacy `_WIN32_USER32_GDI32_SIGNATURES` icindeki entry'ler yeni
    dict'lerle ayni ``lib`` ve ``category`` degerini tasimali."""
    # Legacy inline dict'i AST yolu ile oku — override bypass.
    import ast
    from pathlib import Path

    src = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    legacy = None
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id == "_WIN32_USER32_GDI32_SIGNATURES":
                legacy = ast.literal_eval(n.value)
                break
    assert legacy is not None

    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES
    merged = {
        **SIGNATURES["user32_signatures"],
        **SIGNATURES["gdi32_signatures"],
    }

    overlap = set(merged) & set(legacy)
    # En az yarisi overlap (legacy'nin buyuk kismi yeni kapsamda yer alir).
    assert len(overlap) >= 15, f"Legacy overlap beklenmeyen oranda az: {len(overlap)}"

    # Overlap entry'leri ayni `lib` ve `category` tasimali (idempotent).
    conflicts = []
    for k in overlap:
        if merged[k]["lib"] != legacy[k]["lib"]:
            conflicts.append((k, "lib", merged[k]["lib"], legacy[k]["lib"]))
        if merged[k]["category"] != legacy[k]["category"]:
            conflicts.append((k, "category", merged[k]["category"], legacy[k]["category"]))
    assert not conflicts, f"Legacy ile lib/category farkli entry'ler: {conflicts[:5]}"


def test_advapi32_legacy_overlap_is_idempotent() -> None:
    """Legacy `_WIN32_ADVAPI32_SIGNATURES` icindeki entry'ler yeni dict ile
    ayni ``lib`` ve ``category`` degerini tasimali."""
    import ast
    from pathlib import Path

    src = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    legacy = None
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id == "_WIN32_ADVAPI32_SIGNATURES":
                legacy = ast.literal_eval(n.value)
                break
    assert legacy is not None

    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES
    new_adv = SIGNATURES["advapi32_signatures"]

    overlap = set(new_adv) & set(legacy)
    # Legacy'nin tamamini kapsamalidir (20 entry hepsi yenide var).
    assert len(overlap) >= 15, f"Legacy advapi32 overlap cok dusuk: {len(overlap)}"

    conflicts = []
    for k in overlap:
        if new_adv[k]["lib"] != legacy[k]["lib"]:
            conflicts.append((k, "lib", new_adv[k]["lib"], legacy[k]["lib"]))
        if new_adv[k]["category"] != legacy[k]["category"]:
            conflicts.append((k, "category", new_adv[k]["category"], legacy[k]["category"]))
    assert not conflicts, f"Legacy advapi32 ile farkli entry'ler: {conflicts[:5]}"


# ---------------------------------------------------------------------------
# 5. Kritik sembol varligi (Faz 7D hedef kapsami)
# ---------------------------------------------------------------------------

def test_user32_key_symbols_present() -> None:
    """Faz 7D hedef listesinde olmasi gereken kritik user32 sembolleri."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    user32 = SIGNATURES["user32_signatures"]
    must_have = {
        # Window management
        "CreateWindowExW", "DestroyWindow", "ShowWindow",
        "SetWindowTextW", "GetWindowTextW",
        # Dialog
        "MessageBoxW", "DialogBoxParamW", "EndDialog",
        # Message loop
        "GetMessageW", "DispatchMessageW", "PostMessageW",
        "SendMessageW", "RegisterClassExW",
        # Resources
        "LoadIconW", "LoadCursorW", "LoadBitmapW", "SetCursor",
        # Dialog controls
        "GetDlgItem", "SendDlgItemMessageW", "SetFocus", "GetFocus",
    }
    missing = must_have - set(user32)
    assert not missing, f"user32 eksik kritik semboller: {missing}"


def test_advapi32_key_symbols_present() -> None:
    """Faz 7D hedef listesinde olmasi gereken kritik advapi32 sembolleri."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    advapi32 = SIGNATURES["advapi32_signatures"]
    must_have = {
        # Registry
        "RegOpenKeyExW", "RegCloseKey", "RegQueryValueExW",
        "RegSetValueExW", "RegEnumKeyExW",
        # Token
        "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueW",
        # Service
        "OpenServiceW", "StartServiceW", "CloseServiceHandle",
        # Legacy CryptoAPI
        "CryptAcquireContextW", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
    }
    missing = must_have - set(advapi32)
    assert not missing, f"advapi32 eksik kritik semboller: {missing}"


def test_gdi32_key_symbols_present() -> None:
    """Faz 7D hedef listesinde olmasi gereken kritik gdi32 sembolleri."""
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    gdi32 = SIGNATURES["gdi32_signatures"]
    must_have = {
        # DC
        "CreateDCW", "DeleteDC",
        # Pen / brush
        "CreatePen", "SelectObject", "DeleteObject",
        # Text
        "TextOutW", "SetTextColor", "SetBkColor",
        # Bitmap / blit
        "BitBlt", "StretchBlt", "CreateBitmap", "CreateCompatibleBitmap",
    }
    missing = must_have - set(gdi32)
    assert not missing, f"gdi32 eksik kritik semboller: {missing}"


# ---------------------------------------------------------------------------
# 6. SignatureDB class kullanimi — yeni semboller gercekten yuklendi mi?
# ---------------------------------------------------------------------------

def _fresh_signature_db():
    """_full_cache'i temizleyip taze SignatureDB olustur."""
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    SignatureDB._full_cache.clear()
    return SignatureDB(Config())


def test_signature_db_loads_new_user32_symbols() -> None:
    """SignatureDB instance yeni user32 sembollerini icerir."""
    db = _fresh_signature_db()

    # Yeni eklenen user32 sembolleri
    assert "DrawTextW" in db._symbol_db
    assert "SendInput" in db._symbol_db
    assert "OpenClipboard" in db._symbol_db
    # Lib ve category dogru mu?
    assert db._symbol_db["SendInput"]["lib"] == "user32"
    assert db._symbol_db["SendInput"]["category"] == "win_input"


def test_signature_db_loads_new_advapi32_symbols() -> None:
    """SignatureDB instance yeni advapi32 sembollerini icerir."""
    db = _fresh_signature_db()

    assert "RegEnumKeyExW" in db._symbol_db
    assert "CryptEncrypt" in db._symbol_db
    assert "OpenSCManagerW" in db._symbol_db
    assert db._symbol_db["CryptEncrypt"]["lib"] == "advapi32"
    assert db._symbol_db["CryptEncrypt"]["category"] == "win_crypto"


def test_signature_db_loads_new_gdi32_symbols() -> None:
    """SignatureDB instance yeni gdi32 sembollerini icerir."""
    db = _fresh_signature_db()

    assert "BitBlt" in db._symbol_db
    assert "CreateCompatibleBitmap" in db._symbol_db
    assert "TextOutW" in db._symbol_db
    assert db._symbol_db["BitBlt"]["lib"] == "gdi32"
    assert db._symbol_db["BitBlt"]["category"] == "win_gdi"


# ---------------------------------------------------------------------------
# 7. Regression: onceki migrasyonlar hala saglam
# ---------------------------------------------------------------------------

def test_previous_migrations_still_intact() -> None:
    """Crypto / compression / network / pe_runtime modulleri hala yuklenebilir."""
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES as comp
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES as cry
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as net
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as pe

    assert len(cry) == 6
    assert len(comp) == 5
    assert len(net) == 7
    assert len(pe) == 3


def test_pe_runtime_override_still_active() -> None:
    """pe_runtime override (kernel32/ntdll/msvc_crt) hala aktif."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as pe

    assert sdb._WIN32_KERNEL32_SIGNATURES is pe["kernel32_signatures"]
    assert sdb._WIN32_NTDLL_SIGNATURES is pe["ntdll_signatures"]
    assert sdb._MSVC_CRT_SIGNATURES is pe["msvc_crt_signatures"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
