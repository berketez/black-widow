"""sig_db Runtimes (Rust/Go/Python/Java/.NET) migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi (Rust/Go/.NET icin), signature_db.py artik
``from sigdb_builtin.runtimes import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale
geldigi icin kaldirildi.

DİKKAT: ``_PYTHON_CAPI_SIGNATURES`` ve ``_JAVA_JNI_SIGNATURES`` hala inline
literal olarak signature_db.py icinde (vm_runtime override layer'i farkli
bir mekanizma kullaniyor). Bu iki dict A-DELETE kapsami DISINDA kaldi —
post-A-DELETE testleri bu istisnayi belgeler.

Korunan parity katmanlari:
1. Modul yuklenebilirlik
2. Coverage count
3. Cross-key kesişme yok
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da Rust/Go/.NET inline YOK + dogrudan
   ``_BUILTIN_RUNTIMES_SIGS`` referansi VAR.

Kapsam:
  - rust_stdlib_signatures   (47 entry)
  - rust_ext_signatures      (75 entry)
  - go_runtime_signatures    (53 entry)
  - go_ext_signatures        (209 entry)
  - python_capi_signatures   (76 entry)   [hala inline literal — vm_runtime layer]
  - java_jni_signatures      (50 entry)   [hala inline literal — vm_runtime layer]
  - dotnet_clr_signatures    (58 entry)

Toplam: 568 imza.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilirlik
# ---------------------------------------------------------------------------

def test_sigdb_builtin_runtimes_importable() -> None:
    """sigdb_builtin.runtimes import edilebilir ve dolu SIGNATURES var."""
    from karadul.analyzers.sigdb_builtin import runtimes as mod

    assert hasattr(mod, "SIGNATURES")
    assert isinstance(mod.SIGNATURES, dict)
    assert len(mod.SIGNATURES) == 7


def test_sigdb_builtin_runtimes_has_expected_keys() -> None:
    """SIGNATURES tam olarak 7 beklenen anahtari icerir."""
    from karadul.analyzers.sigdb_builtin import runtimes as mod

    expected = {
        "rust_stdlib_signatures",
        "rust_ext_signatures",
        "go_runtime_signatures",
        "go_ext_signatures",
        "python_capi_signatures",
        "java_jni_signatures",
        "dotnet_clr_signatures",
    }
    assert set(mod.SIGNATURES.keys()) == expected


def test_sigdb_builtin_runtimes_entry_counts() -> None:
    """Her alt-kategori beklenen entry sayisina sahip."""
    from karadul.analyzers.sigdb_builtin import runtimes as mod

    expected_counts = {
        "rust_stdlib_signatures": 47,
        "rust_ext_signatures": 75,
        "go_runtime_signatures": 53,
        "go_ext_signatures": 209,
        "python_capi_signatures": 76,
        "java_jni_signatures": 50,
        "dotnet_clr_signatures": 58,
    }
    for key, expected in expected_counts.items():
        actual = len(mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in mod.SIGNATURES.values())
    assert total == 568, f"Total runtimes entry count: expected 568, got {total}"


# ---------------------------------------------------------------------------
# 2. Dispatcher
# ---------------------------------------------------------------------------

def test_get_category_runtimes_returns_data() -> None:
    """Dispatcher dolu runtimes kategori verisi dondurur."""
    from karadul.analyzers.sigdb_builtin import get_category

    sigs = get_category("runtimes")
    assert isinstance(sigs, dict)
    assert len(sigs) == 7
    assert "go_ext_signatures" in sigs
    assert "python_capi_signatures" in sigs
    assert sum(len(v) for v in sigs.values()) == 568


# ---------------------------------------------------------------------------
# 3. Runtime identity — A-DELETE kapsamindaki dict'ler
# ---------------------------------------------------------------------------

# Sadece A-DELETE uygulanmis dict'ler icin identity gecerli.
_A_DELETE_KEYS_TO_LEGACY: dict[str, str] = {
    "rust_stdlib_signatures": "_RUST_STDLIB_SIGNATURES",
    "rust_ext_signatures": "_RUST_EXT_SIGNATURES",
    "go_runtime_signatures": "_GO_RUNTIME_SIGNATURES",
    "go_ext_signatures": "_GO_EXT_SIGNATURES",
    "dotnet_clr_signatures": "_DOTNET_CLR_SIGNATURES",
}


@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_A_DELETE_KEYS_TO_LEGACY.items()))
def test_runtime_identity_a_delete_dicts(builtin_key: str, legacy_name: str) -> None:
    """A-DELETE uygulanmis runtime dict'leri: legacy is migrated."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    legacy = getattr(sdb, legacy_name)
    migrated = SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )


def test_python_capi_java_jni_runtime_equality() -> None:
    """PYTHON_CAPI ve JAVA_JNI dict'leri A-DELETE DISINDA, ancak runtime
    icerikleri sigdb_builtin.runtimes ile esit (vm_runtime override
    bypass edildiginde). Bu test minimum coverage'in bozulmadigini
    dogrular — identity GARANTILI DEGIL, sadece icerik uyusur."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    # Coverage parity (tam icerik karsilastirmasi degil — vm_runtime
    # override sonucu signature_db tarafinda farkli iceriksel olabilir).
    assert len(sdb._PYTHON_CAPI_SIGNATURES) >= 76
    assert len(sdb._JAVA_JNI_SIGNATURES) >= 50
    assert len(SIGNATURES["python_capi_signatures"]) == 76
    assert len(SIGNATURES["java_jni_signatures"]) == 50


# ---------------------------------------------------------------------------
# 4. Modul-ici saglik
# ---------------------------------------------------------------------------

def test_no_duplicate_keys_across_subcategories() -> None:
    """Bir runtime sembolu birden fazla alt-kategoride durmamali."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    seen: dict[str, str] = {}
    duplicates: list[tuple[str, str, str]] = []
    for cat, entries in SIGNATURES.items():
        for sym in entries:
            if sym in seen:
                duplicates.append((sym, seen[sym], cat))
            else:
                seen[sym] = cat
    assert not duplicates, f"Anahtar kesişimi tespit edildi: {duplicates[:5]}"


def test_rust_v0_mangling_prefix_present() -> None:
    """Rust v0 mangling marker `_RNvNtCs...` Rust stdlib dict'inde mevcut."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    rust_std = SIGNATURES["rust_stdlib_signatures"]
    assert "_RNvNtCs" in rust_std
    assert rust_std["_RNvNtCs"]["category"] == "rust"


def test_go_runtime_core_symbols_present() -> None:
    """Go runtime esas sembolleri."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    go_rt = SIGNATURES["go_runtime_signatures"]
    for sym in ("runtime.main", "runtime.newproc", "runtime.mallocgc",
                "runtime.chansend", "runtime.gopanic"):
        assert sym in go_rt, f"{sym} go_runtime dict'inde olmali"
        assert go_rt[sym]["lib"].startswith("go-"), (
            f"{sym}: lib 'go-*' bekleniyor, {go_rt[sym]['lib']} bulundu"
        )


def test_python_capi_known_symbols() -> None:
    """CPython API klasik sembolleri."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    py = SIGNATURES["python_capi_signatures"]
    for sym in ("Py_Initialize", "Py_Finalize", "PyObject_CallObject",
                "PyDict_New", "PyErr_SetString", "PyGILState_Ensure"):
        assert sym in py, f"{sym} python_capi dict'inde olmali"
        assert py[sym]["lib"] == "python"
        assert py[sym]["category"] == "python"


def test_jni_known_symbols() -> None:
    """JNI bilindik fonksiyonlari."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    jni = SIGNATURES["java_jni_signatures"]
    for sym in ("JNI_CreateJavaVM", "JNI_OnLoad", "FindClass", "GetMethodID",
                "RegisterNatives", "AttachCurrentThread"):
        assert sym in jni, f"{sym} java_jni dict'inde olmali"
        assert jni[sym]["lib"] == "jni"
        assert jni[sym]["category"] == "java"


def test_dotnet_runtime_libs_distinct() -> None:
    """CLR dict'i 4 farkli runtime'i (coreclr, mono, hostfxr, il2cpp) icerir."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    clr = SIGNATURES["dotnet_clr_signatures"]
    libs = {entry["lib"] for entry in clr.values()}
    assert {"coreclr", "mono", "hostfxr", "il2cpp"}.issubset(libs), (
        f"4 .NET runtime'i da temsil edilmeli, mevcut: {libs}"
    )
    cats = {entry["category"] for entry in clr.values()}
    assert cats == {"dotnet"}, f"dotnet_clr category homojen olmali: {cats}"


def test_all_entries_have_required_fields() -> None:
    """Her entry {lib, purpose, category} icermeli."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    required = {"lib", "purpose", "category"}
    bad: list[tuple[str, str, set]] = []
    for cat, entries in SIGNATURES.items():
        for sym, data in entries.items():
            missing = required - set(data.keys())
            if missing:
                bad.append((cat, sym, missing))
    assert not bad, f"Eksik alan tespit edildi: {bad[:5]}"


# ---------------------------------------------------------------------------
# 5. Post-A-DELETE: A-DELETE kapsamindaki dict'ler icin literal silindi
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal_rust_go_dotnet() -> None:
    """signature_db.py'da Rust/Go/.NET legacy literal'leri YOK; referans VAR."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Reference assignment'lar
    assert (
        '_RUST_STDLIB_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_RUNTIMES_SIGS["rust_stdlib_signatures"]'
    ) in text
    assert (
        '_GO_RUNTIME_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_RUNTIMES_SIGS["go_runtime_signatures"]'
    ) in text
    assert (
        '_DOTNET_CLR_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_RUNTIMES_SIGS["dotnet_clr_signatures"]'
    ) in text
    # Inline literal blok baslangici YOK (A-DELETE kapsamindaki 5 dict)
    # ``\n`` ile sabitleyerek `_MODERN_GO_RUNTIME_SIGNATURES = {}` gibi
    # alakasiz baska dict tanimlarinin substring olarak yakalanmamasini garantile.
    for legacy in _A_DELETE_KEYS_TO_LEGACY.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py runtimes'i ``sigdb_builtin.runtimes``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_RUNTIMES_SIGS" in text
    assert "sigdb_builtin" in text and "runtimes" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
