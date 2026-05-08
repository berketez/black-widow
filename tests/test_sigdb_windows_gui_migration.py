"""sig_db Windows GUI / advapi32 / gdi32 migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
(crypto/compression/network/pe_runtime/logging/languages + ``_WIN32_ADVAPI32``
alias) silindi/yeniden baglandi. ``_WIN32_USER32_SIGNATURES``,
``_WIN32_ADVAPI32_FULL_SIGNATURES``, ``_WIN32_GDI32_SIGNATURES`` artik
``_BUILTIN_WINDOWS_GUI_SIGNATURES`` referansi uzerinden geliyor.

AST parse parity (eski legacy ``_WIN32_USER32_GDI32_SIGNATURES`` ve
``_WIN32_ADVAPI32_SIGNATURES`` icin ``ast.literal_eval`` overlap testleri)
artik tautolojik veya patolojik (advapi32 alias bir ``Name``,
literal_eval edilemez) hale geldi ve kaldirildi. Yerine runtime sembol
overlap testleri ve post-A-DELETE referans dogrulamasi konuldu.

Korunan parity katmanlari:
1. Runtime identity (``is`` check, user32/advapi32/gdi32)
2. Coverage count (>=120 / >=80 / >=50, toplam >=250)
3. Schema + lib + category dogrulamasi
4. Bilinen sembol kapsamasi (CreateWindowExW, RegOpenKeyExW, BitBlt, ...)
5. SignatureDB instance entegrasyon (_full_cache temizli)
6. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_WINDOWS_GUI_SIGNATURES`` referansi VAR.
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
# 4. Runtime idempotent overlap (Faz A-DELETE sonrasi)
# ---------------------------------------------------------------------------
#
# A-DELETE sonrasi `_WIN32_ADVAPI32_SIGNATURES` artik
# `_WIN32_ADVAPI32_FULL_SIGNATURES` (= builtin advapi32) alias'i; AST
# literal_eval edilemez. `_WIN32_USER32_GDI32_SIGNATURES` ise legacy 23
# entry'lik kucuk bir literal olarak `signature_db.py` icinde duruyor (Faz
# A-DELETE kapsami disinda; v1.14+ icin bekliyor). Yine de runtime degeriyle
# overlap kontrolu yaparak idempotent olduklarini dogrulariz.

def test_user32_gdi32_runtime_overlap_is_idempotent() -> None:
    """Runtime `_WIN32_USER32_GDI32_SIGNATURES` (legacy small dict) yeni
    user32/gdi32 builtin dict'leriyle ortusen entry'lerde ayni ``lib`` ve
    ``category`` tasimali (idempotent merge garantisi)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    legacy = sdb._WIN32_USER32_GDI32_SIGNATURES
    merged = {
        **SIGNATURES["user32_signatures"],
        **SIGNATURES["gdi32_signatures"],
    }

    overlap = set(merged) & set(legacy)
    assert len(overlap) >= 15, (
        f"Legacy user32_gdi32 overlap beklenmeyen oranda az: {len(overlap)}"
    )

    conflicts = []
    for k in overlap:
        if merged[k]["lib"] != legacy[k]["lib"]:
            conflicts.append((k, "lib", merged[k]["lib"], legacy[k]["lib"]))
        if merged[k]["category"] != legacy[k]["category"]:
            conflicts.append(
                (k, "category", merged[k]["category"], legacy[k]["category"])
            )
    assert not conflicts, (
        f"Legacy ile lib/category farkli entry'ler: {conflicts[:5]}"
    )


def test_advapi32_runtime_full_alias_is_idempotent() -> None:
    """A-DELETE sonrasi `_WIN32_ADVAPI32_SIGNATURES` artik full alias.

    `_WIN32_ADVAPI32_SIGNATURES is _WIN32_ADVAPI32_FULL_SIGNATURES is
    builtin["advapi32_signatures"]` olmali; bu nedenle overlap %100, conflict
    olmamali (trivially idempotent)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES

    new_adv = SIGNATURES["advapi32_signatures"]
    legacy_alias = sdb._WIN32_ADVAPI32_SIGNATURES

    # Tam alias: ayni obje
    assert legacy_alias is new_adv or legacy_alias is sdb._WIN32_ADVAPI32_FULL_SIGNATURES
    # Cakisan tum keyler ayni icerige sahip
    overlap = set(new_adv) & set(legacy_alias)
    assert len(overlap) == len(legacy_alias), (
        "Alias uzerinden overlap %100 olmali"
    )
    conflicts = [
        k for k in overlap
        if new_adv[k]["lib"] != legacy_alias[k]["lib"]
        or new_adv[k]["category"] != legacy_alias[k]["category"]
    ]
    assert not conflicts, f"Alias ile conflict olmamali: {conflicts[:5]}"


# ---------------------------------------------------------------------------
# 4b. Post-A-DELETE: legacy literal silindi, dogrudan import kullaniliyor
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da yeni windows_gui dict'lerinin inline literal'i YOK.

    A-DELETE sonrasi user32/advapi32_full/gdi32 sadece
    ``_BUILTIN_WINDOWS_GUI_SIGNATURES["..."]`` lookup'u uzerinden tutulur.
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar olmali
    assert (
        '_WIN32_USER32_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_WINDOWS_GUI_SIGNATURES["user32_signatures"]'
    ) in text
    assert (
        '_WIN32_ADVAPI32_FULL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_WINDOWS_GUI_SIGNATURES["advapi32_signatures"]'
    ) in text
    assert (
        '_WIN32_GDI32_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_WINDOWS_GUI_SIGNATURES["gdi32_signatures"]'
    ) in text
    # Yeni 3 isim icin inline literal YOK
    assert "_WIN32_USER32_SIGNATURES: dict[str, dict[str, str]] = {" not in text
    assert "_WIN32_ADVAPI32_FULL_SIGNATURES: dict[str, dict[str, str]] = {" not in text
    assert "_WIN32_GDI32_SIGNATURES: dict[str, dict[str, str]] = {" not in text


def test_post_a_delete_direct_import() -> None:
    """signature_db.py windows_gui SIGNATURES'i ``sigdb_builtin.windows_gui``'dan
    dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_WINDOWS_GUI_SIGNATURES" in text
    assert "sigdb_builtin" in text and "windows_gui" in text


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

    # v1.13 Wave 1: 7. anahtar "modern_crypto_signatures" eklendi.
    assert len(cry) == 7
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
