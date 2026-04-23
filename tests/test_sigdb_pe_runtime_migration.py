"""sig_db Faz 6C — PE/MSVC runtime migration parity + coverage testleri.

Amac: ``karadul/analyzers/sigdb_builtin/pe_runtime.py`` modulune tasinan /
eklenen veri, orijinal ``karadul/analyzers/signature_db.py`` dict'leriyle
ne olcude uyumlu?

  1. ``kernel32_signatures`` — legacy ``_WIN32_KERNEL32_SIGNATURES`` ile
     birebir identity parity (60 entry).
  2. ``ntdll_signatures``    — legacy ``_WIN32_NTDLL_SIGNATURES`` ile birebir
     identity parity (14 entry).
  3. ``msvc_crt_signatures`` — YENI dict, legacy karsiligi YOK. Coverage
     dogrulanir: 200+ entry (MSVCRT / UCRT / VCRUNTIME140). Altkumesi legacy
     ``_MEGA_BATCH_1_SIGNATURES`` icindeki CRT sembolleriyle ortustugunde
     ayni ``lib``/``purpose`` degerini tasimalidir (idempotent).

Crypto / compression / network migration testlerinin pattern'ini takip eder
(bkz: test_sigdb_compression_migration.py).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_pe_runtime_importable() -> None:
    """sigdb_builtin.pe_runtime import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import pe_runtime

    assert hasattr(pe_runtime, "SIGNATURES")
    assert isinstance(pe_runtime.SIGNATURES, dict)
    assert len(pe_runtime.SIGNATURES) == 3


def test_sigdb_builtin_pe_runtime_has_expected_keys() -> None:
    """SIGNATURES 3 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import pe_runtime

    expected = {
        "kernel32_signatures",
        "ntdll_signatures",
        "msvc_crt_signatures",
    }
    assert set(pe_runtime.SIGNATURES.keys()) == expected


def test_sigdb_builtin_pe_runtime_entry_counts() -> None:
    """Her kategori beklenen minimum entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import pe_runtime

    # kernel32 + ntdll: birebir parity (sabit sayi)
    assert len(pe_runtime.SIGNATURES["kernel32_signatures"]) == 60
    assert len(pe_runtime.SIGNATURES["ntdll_signatures"]) == 14

    # msvc_crt: yeni coverage, alt sinir ile dogrula (fuzzy)
    msvc_crt = pe_runtime.SIGNATURES["msvc_crt_signatures"]
    assert len(msvc_crt) >= 200, (
        f"msvc_crt_signatures min 200 entry bekleniyor; bulundu {len(msvc_crt)}"
    )

    total = sum(len(v) for v in pe_runtime.SIGNATURES.values())
    assert total >= 270, f"Toplam pe_runtime entry sayisi en az 270 olmali; bulundu {total}"


# ---------------------------------------------------------------------------
# 2. Override aktif mi? (identity / is check)
# ---------------------------------------------------------------------------

def test_override_pe_runtime_identity() -> None:
    """signature_db.py icindeki dict'ler builtin.pe_runtime ile ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as builtin

    assert sdb._BUILTIN_PE_RUNTIME_SIGNATURES is not None
    assert sdb._WIN32_KERNEL32_SIGNATURES is builtin["kernel32_signatures"]
    assert sdb._WIN32_NTDLL_SIGNATURES is builtin["ntdll_signatures"]
    assert sdb._MSVC_CRT_SIGNATURES is builtin["msvc_crt_signatures"]


def test_legacy_pe_runtime_attributes_still_accessible() -> None:
    """Backward compat: eski dict attribute'lari hala erisilebilir, dolu."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_WIN32_KERNEL32_SIGNATURES")
    assert hasattr(sdb, "_WIN32_NTDLL_SIGNATURES")
    assert hasattr(sdb, "_MSVC_CRT_SIGNATURES")
    assert len(sdb._WIN32_KERNEL32_SIGNATURES) > 0
    assert len(sdb._WIN32_NTDLL_SIGNATURES) > 0
    assert len(sdb._MSVC_CRT_SIGNATURES) > 0


# ---------------------------------------------------------------------------
# 3. Data parity — orijinal inline ile birebir kopya mi? (kernel32 / ntdll)
# ---------------------------------------------------------------------------

def _load_original_ast_values() -> dict:
    """signature_db.py'nin BIRINCI ham AST parse'indan orijinal dict'leri al.

    Override'i bypass etmek icin kaynak kodu direkt AST'den okuyoruz.
    ``ast.AnnAssign`` sadece orijinal ``_X: dict[...] = {...}`` tanimini yakalar;
    override bloklarindaki ``_X = _BUILTIN_X.get(...)`` yok sayilir (bu bir
    ``ast.Assign``, annotation yok).
    """
    src_path = Path("karadul/analyzers/signature_db.py")
    src = src_path.read_text(encoding="utf-8")
    tree = ast.parse(src)

    targets = {
        "_WIN32_KERNEL32_SIGNATURES",
        "_WIN32_NTDLL_SIGNATURES",
    }
    result: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if n.target.id in targets and n.target.id not in result:
                result[n.target.id] = ast.literal_eval(n.value)
    return result


def test_data_parity_kernel32() -> None:
    """kernel32 dict: override sonrasi icerik orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES

    original = _load_original_ast_values()
    migrated = SIGNATURES["kernel32_signatures"]
    assert migrated == original["_WIN32_KERNEL32_SIGNATURES"]
    assert len(migrated) == len(original["_WIN32_KERNEL32_SIGNATURES"])


def test_data_parity_ntdll() -> None:
    """ntdll dict: override sonrasi icerik orijinal inline ile birebir ayni."""
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES

    original = _load_original_ast_values()
    assert SIGNATURES["ntdll_signatures"] == original["_WIN32_NTDLL_SIGNATURES"]


# ---------------------------------------------------------------------------
# 4. MSVC CRT yeni dict: idempotent overlap + schema dogrulamasi
# ---------------------------------------------------------------------------

def test_msvc_crt_all_entries_have_schema_fields() -> None:
    """Her MSVC CRT entry'si ``lib``, ``purpose``, ``category`` alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES

    msvc_crt = SIGNATURES["msvc_crt_signatures"]
    required = {"lib", "purpose", "category"}
    for name, info in msvc_crt.items():
        assert isinstance(info, dict), f"{name}: dict degil"
        assert required.issubset(info.keys()), (
            f"{name}: eksik alan(lar) {required - info.keys()}"
        )


def test_msvc_crt_lib_labels_are_valid() -> None:
    """Her entry'nin ``lib`` etiketi kabul listesinde (msvcrt/ucrtbase/vcruntime140)."""
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES

    msvc_crt = SIGNATURES["msvc_crt_signatures"]
    allowed = {"msvcrt", "ucrtbase", "vcruntime140"}
    bad = {n: info["lib"] for n, info in msvc_crt.items() if info["lib"] not in allowed}
    assert not bad, f"Beklenmeyen lib etiketleri: {bad}"


def test_msvc_crt_mega_batch_overlap_is_idempotent() -> None:
    """Legacy MEGA_BATCH_1 CRT entry'leri ile cakisma varsa ayni icerikte."""
    from karadul.analyzers import signature_db as sdb

    msvc_crt = sdb._MSVC_CRT_SIGNATURES
    mega = sdb._MEGA_BATCH_1_SIGNATURES

    overlap = set(msvc_crt) & set(mega)
    # Ayni isim legacy'de varsa ayni ``lib`` / ``purpose`` olmali (idempotent update).
    conflicts = {
        k: (msvc_crt[k], mega[k])
        for k in overlap
        if msvc_crt[k] != mega[k]
    }
    assert not conflicts, (
        f"Legacy MEGA_BATCH_1 ile cakisan {len(conflicts)} entry farkli degere sahip: "
        f"{list(conflicts)[:5]}"
    )
    # Overlap var olmali (legacy CRT entry'leri gercekten tekrarlaniyor)
    assert len(overlap) > 20, f"Legacy overlap cok az; bulundu {len(overlap)}"


def test_msvc_crt_key_categories_present() -> None:
    """Beklenen MSVC CRT alt kategorileri (UCRT startup + vcruntime EH) kapsandi mi?"""
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES

    msvc_crt = SIGNATURES["msvc_crt_signatures"]

    # UCRT startup sembolleri (sadece v1.12.0 Faz 6C'de eklendi)
    ucrt_startup = {"__p___argc", "__p___argv", "_initterm", "_cexit",
                    "__getmainargs", "_set_app_type"}
    assert ucrt_startup.issubset(msvc_crt.keys()), (
        f"UCRT startup eksik: {ucrt_startup - msvc_crt.keys()}"
    )

    # VCRUNTIME EH / RTTI sembolleri
    vcrt_eh = {"__CxxFrameHandler3", "__CxxThrowException", "__RTDynamicCast",
               "__GSHandlerCheck", "__security_check_cookie"}
    assert vcrt_eh.issubset(msvc_crt.keys()), (
        f"VCRUNTIME EH eksik: {vcrt_eh - msvc_crt.keys()}"
    )

    # Lib etiketlerinin dogru dagilmis oldugunu kontrol et
    assert msvc_crt["__CxxFrameHandler3"]["lib"] == "vcruntime140"
    assert msvc_crt["_initterm"]["lib"] == "ucrtbase"
    assert msvc_crt["_open"]["lib"] == "msvcrt"


# ---------------------------------------------------------------------------
# 5. SignatureDB class kullanimi — MSVC CRT gercekten yuklendi mi?
# ---------------------------------------------------------------------------

def _fresh_signature_db():
    """_full_cache'i temizleyip taze SignatureDB olustur."""
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    # Class-level cache'i temizle ki yeni _MSVC_CRT eklenen tuple yeniden yuklenin.
    SignatureDB._full_cache.clear()
    return SignatureDB(Config())


def test_signature_db_loads_msvc_crt_symbols() -> None:
    """SignatureDB instance _symbol_db'si MSVC CRT entry'lerini icerir."""
    db = _fresh_signature_db()

    # Yaygin VCRUNTIME sembolleri gerçekten _symbol_db'ye akmis
    assert "__CxxFrameHandler3" in db._symbol_db
    entry = db._symbol_db["__CxxFrameHandler3"]
    assert entry["lib"] == "vcruntime140"
    assert entry["category"] == "win_cxx_eh"

    # UCRT startup
    assert "__p___argv" in db._symbol_db
    assert db._symbol_db["__p___argv"]["lib"] == "ucrtbase"

    # MSVCRT secure CRT
    assert "strcpy_s" in db._symbol_db
    assert db._symbol_db["strcpy_s"]["lib"] == "msvcrt"


def test_signature_db_kernel32_symbol_lookup() -> None:
    """Override sonrasi kernel32 sembolleri hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    assert "CreateFileW" in sdb._WIN32_KERNEL32_SIGNATURES
    entry = sdb._WIN32_KERNEL32_SIGNATURES["CreateFileW"]
    assert entry["lib"] == "kernel32"
    assert entry["category"] == "win_file"


def test_signature_db_ntdll_symbol_lookup() -> None:
    """Override sonrasi ntdll Nt/Rtl sembolleri hala bulunabilir."""
    from karadul.analyzers import signature_db as sdb

    assert "NtCreateFile" in sdb._WIN32_NTDLL_SIGNATURES
    assert "RtlInitUnicodeString" in sdb._WIN32_NTDLL_SIGNATURES
    assert sdb._WIN32_NTDLL_SIGNATURES["NtCreateFile"]["lib"] == "ntdll"


# ---------------------------------------------------------------------------
# 6. Regression: onceki migrasyonlar hala saglam
# ---------------------------------------------------------------------------

def test_previous_migrations_still_intact() -> None:
    """Crypto / compression / network modulleri hala yuklenebilir."""
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES as comp
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES as cry
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as net

    assert len(cry) == 6   # openssl, boringssl, libsodium, mbedtls, wincrypto, findcrypt
    assert len(comp) == 5  # zlib, bzip2, lz4, zstd, compression_ext
    assert len(net) == 7   # libcurl, posix_net, nghttp2, websocket, macos_net, apple_nw, net_ext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
