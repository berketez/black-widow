"""sig_db Windows API extended migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: ``signature_db.py`` icindeki ``_WIN32_*`` dict'lerin
bir kismi shadow modullere referansa donustu, kalanlar (ws2_32, user32_gdi32,
ext) ise hala literal halde duruyor (A-DELETE kapsami disinda kaldi). Eski
``_load_original_ast_values()`` + ``test_data_parity_*`` testleri tautolojik
veya literal_eval edilemez (Name AnnAssign) hale geldigi icin kaldirildi.

Korunan dogrulamalar (windows_api shadow modulu kendi kendine yeterlidir):
1. Modul yuklenebilir, 6 alt-kategori, 509 imza
2. Dispatcher ``get_category('windows_api')``
3. Dict-ici saglik: duplicate key yok, schema, lib labels
4. Bilinen sembol kapsamasi (CreateFileW, BCryptOpenAlgorithmProvider, ...)
5. Post-A-DELETE: ws2_32/user32_gdi32/ext hala legacy literal mi
   (A-DELETE kapsami disinda kalmaktan emin olmak icin), runtime icerik
   shadow modulle uyumlu mu (idempotent overlap).
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi? Iskeletten dolu modle gectik mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_windows_api_importable() -> None:
    """sigdb_builtin.windows_api import edilebilir ve dolu SIGNATURES var."""
    from karadul.analyzers.sigdb_builtin import windows_api as mod

    assert hasattr(mod, "SIGNATURES")
    assert isinstance(mod.SIGNATURES, dict)
    # Faz A4'te 6 alt-kategori bekleniyor (placeholder degil).
    assert len(mod.SIGNATURES) == 6, (
        f"Faz A4 sonrasi 6 alt-kategori bekleniyor (kernel32, ws2_32, advapi32, "
        f"user32_gdi32, ntdll, ext), mevcut: {len(mod.SIGNATURES)}"
    )


def test_sigdb_builtin_windows_api_has_expected_keys() -> None:
    """SIGNATURES tam olarak 6 beklenen anahtar icerir (typo / fazla key korumasi)."""
    from karadul.analyzers.sigdb_builtin import windows_api as mod

    expected = {
        "win32_kernel32_signatures",
        "win32_ws2_32_signatures",
        "win32_advapi32_signatures",
        "win32_user32_gdi32_signatures",
        "win32_ntdll_signatures",
        "win32_ext_signatures",
    }
    assert set(mod.SIGNATURES.keys()) == expected


def test_sigdb_builtin_windows_api_entry_counts() -> None:
    """Her alt-kategori beklenen entry sayisina sahip (regression koruma)."""
    from karadul.analyzers.sigdb_builtin import windows_api as mod

    expected_counts = {
        "win32_kernel32_signatures": 60,
        "win32_ws2_32_signatures": 19,
        "win32_advapi32_signatures": 20,
        "win32_user32_gdi32_signatures": 23,
        "win32_ntdll_signatures": 14,
        "win32_ext_signatures": 373,
    }
    for key, expected in expected_counts.items():
        actual = len(mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in mod.SIGNATURES.values())
    assert total == 509, f"Total Windows API entry count: expected 509, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher: sigdb_builtin.get_category("windows_api") calisir mi?
# ---------------------------------------------------------------------------

def test_get_category_windows_api_returns_data() -> None:
    """Dispatcher dolu Windows API kategori verisi dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("windows_api")
    assert isinstance(sigs, dict)
    assert len(sigs) == 6
    # Spot-check alt-kategoriler
    assert "win32_kernel32_signatures" in sigs
    assert "win32_ext_signatures" in sigs
    assert sum(len(v) for v in sigs.values()) == 509


# ---------------------------------------------------------------------------
# 3. Post-A-DELETE: kernel32/ntdll legacy YOK; ws2_32/user32_gdi32/ext literal
# ---------------------------------------------------------------------------

def test_post_a_delete_kernel32_ntdll_no_inline_literal() -> None:
    """A-DELETE sonrasi kernel32 + ntdll legacy literal'leri silindi.

    Ikisi de ``_BUILTIN_PE_RUNTIME_SIGNATURES`` referansi uzerinden geliyor
    (pe_runtime modulune tasindi).
    """
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_WIN32_KERNEL32_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_PE_RUNTIME_SIGNATURES["kernel32_signatures"]'
    ) in text
    assert (
        '_WIN32_NTDLL_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_PE_RUNTIME_SIGNATURES["ntdll_signatures"]'
    ) in text
    # Inline literal yok
    assert "_WIN32_KERNEL32_SIGNATURES: dict[str, dict[str, str]] = {" not in text
    assert "_WIN32_NTDLL_SIGNATURES: dict[str, dict[str, str]] = {" not in text


def test_post_a_delete_kernel32_ntdll_runtime_idempotent() -> None:
    """Runtime ``_WIN32_KERNEL32/NTDLL_SIGNATURES`` shadow modul ile birebir ayni icerik.

    pe_runtime modulu uzerinden geldikleri icin, shadow windows_api modulundeki
    karsiliklarinin da birebir ayni icerik olmasi beklenir (her iki shadow modul
    de ayni kaynak veriyi yansitiyor)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    assert sdb._WIN32_KERNEL32_SIGNATURES == SIGNATURES["win32_kernel32_signatures"]
    assert sdb._WIN32_NTDLL_SIGNATURES == SIGNATURES["win32_ntdll_signatures"]


def test_ws2_32_ext_runtime_birebir_uyumlu() -> None:
    """ws2_32 ve ext dict'leri runtime'da shadow ile birebir ayni icerikte.

    Bu iki dict A-DELETE sonrasi degismedi (shadow modul ile ayni boyutta).
    """
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    assert sdb._WIN32_WS2_32_SIGNATURES == SIGNATURES["win32_ws2_32_signatures"]
    assert sdb._WIN32_EXT_SIGNATURES == SIGNATURES["win32_ext_signatures"]


def test_user32_gdi32_runtime_subset_overlap_idempotent() -> None:
    """A-DELETE sonrasi ``_WIN32_USER32_GDI32_SIGNATURES`` runtime'da windows_gui
    user32+gdi32 ile genisletilmis durumda (~404 entry); shadow windows_api
    modulu ise eski 23 entry'lik kucuk listeyi tutuyor. Shadow'un tum keyleri
    runtime'da bulunmali ve ayni ``lib``/``category`` icerik tasimali."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    shadow_small = SIGNATURES["win32_user32_gdi32_signatures"]
    runtime_full = sdb._WIN32_USER32_GDI32_SIGNATURES

    missing = set(shadow_small) - set(runtime_full)
    assert not missing, (
        f"Shadow user32_gdi32 entry'leri runtime'da bulunmali: {missing}"
    )
    conflicts = [
        k for k in shadow_small
        if shadow_small[k]["lib"] != runtime_full[k]["lib"]
        or shadow_small[k]["category"] != runtime_full[k]["category"]
    ]
    assert not conflicts, (
        f"Shadow vs runtime user32_gdi32 conflict: {conflicts[:5]}"
    )


def test_advapi32_runtime_subset_overlap_idempotent() -> None:
    """A-DELETE sonrasi `_WIN32_ADVAPI32_SIGNATURES` artik windows_gui
    full alias'i (~162 entry); shadow windows_api modulu eski 20 entry'lik
    kucuk listeyi tutuyor. Shadow'un tum keyleri runtime full alias'inda
    bulunmali ve ayni `lib`/`category` icerik tasimali (subset idempotency)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    shadow_small = SIGNATURES["win32_advapi32_signatures"]
    runtime_full = sdb._WIN32_ADVAPI32_SIGNATURES

    # Shadow tamamen runtime full'in altkumesi olmali
    missing = set(shadow_small) - set(runtime_full)
    assert not missing, (
        f"Shadow advapi32 entry'leri runtime full'de bulunmali: {missing}"
    )

    # Cakisan keylerde lib + category birebir
    conflicts = [
        k for k in shadow_small
        if shadow_small[k]["lib"] != runtime_full[k]["lib"]
        or shadow_small[k]["category"] != runtime_full[k]["category"]
    ]
    assert not conflicts, (
        f"Shadow vs runtime advapi32 conflict: {conflicts[:5]}"
    )


def test_post_a_delete_direct_import_pe_runtime() -> None:
    """signature_db.py kernel32/ntdll'i ``sigdb_builtin.pe_runtime``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_PE_RUNTIME_SIGNATURES" in text
    assert "sigdb_builtin" in text and "pe_runtime" in text


# ---------------------------------------------------------------------------
# 4. Modul-ici saglik: key kesişmesi, lib alani, mangling pattern'leri
# ---------------------------------------------------------------------------

def test_no_duplicate_keys_across_subcategories() -> None:
    """Bir Windows API sembolu birden fazla alt-kategoride durmamali (entry leak).

    NOT: kernel32, ws2_32, advapi32, user32_gdi32, ntdll core dict'leri ayrik;
    fakat ext dict'i ayni sembolu farkli isim/imza ile genisletebilir mi?
    Bu testin amaci ayni anahtar adinin kopyalanmadigini garanti etmek (yanlis
    merge sirasinda entry'lerin sessizce ezilmesini engeller).
    """
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    seen: dict[str, str] = {}
    duplicates: list[tuple[str, str, str]] = []
    for cat, entries in SIGNATURES.items():
        for sym in entries:
            if sym in seen:
                duplicates.append((sym, seen[sym], cat))
            else:
                seen[sym] = cat
    assert not duplicates, f"Anahtar kesişimi tespit edildi: {duplicates[:5]}"


def test_known_kernel32_symbols_present() -> None:
    """Bilindik kernel32 sembolleri migration'dan sonra hala mevcut."""
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    core = SIGNATURES["win32_kernel32_signatures"]
    # Klasik Windows API esaslari
    for sym in ("CreateFileA", "CreateFileW", "VirtualAlloc", "GetProcAddress",
                "LoadLibraryA", "CreateThread", "GetLastError"):
        assert sym in core, f"{sym} kernel32 dict'inde olmali"
        assert core[sym]["lib"] == "kernel32"


def test_known_ext_symbols_with_correct_lib() -> None:
    """Ext dict'i icinde lib alani DLL adlariyla tutarli (crypt32, bcrypt, ...)."""
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    ext = SIGNATURES["win32_ext_signatures"]
    expectations = {
        "BCryptOpenAlgorithmProvider": "bcrypt",
        "CertOpenStore": "crypt32",
        "CoCreateInstance": "ole32",
        "ShellExecuteW": "shell32",
        "WinHttpOpen": "winhttp",
        "GetAdaptersInfo": "iphlpapi",
        "SymInitialize": "dbghelp",
    }
    for sym, lib in expectations.items():
        assert sym in ext, f"{sym} ext dict'inde olmali"
        assert ext[sym]["lib"] == lib, (
            f"{sym}: lib {lib} bekleniyor, {ext[sym]['lib']} bulundu"
        )


def test_all_entries_have_required_fields() -> None:
    """Her entry {lib, purpose, category} alanlarini icermeli (schema garantisi)."""
    from karadul.analyzers.sigdb_builtin.windows_api import SIGNATURES

    required = {"lib", "purpose", "category"}
    bad: list[tuple[str, str, set]] = []
    for cat, entries in SIGNATURES.items():
        for sym, data in entries.items():
            missing = required - set(data.keys())
            if missing:
                bad.append((cat, sym, missing))
    assert not bad, f"Eksik alan tespit edildi: {bad[:5]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
