"""sig_db Runtimes (Rust/Go/Python/Java/.NET) migration testleri (v1.14 D0 sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi (Rust/Go/.NET icin), signature_db.py artik
``from sigdb_builtin.runtimes import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale
geldigi icin kaldirildi.

v1.14 Dalga 0 cleanup: ``_PYTHON_CAPI_SIGNATURES`` (76 inline) ve
``_JAVA_JNI_SIGNATURES`` (50 inline) literal'leri SILINDI. Veri sahibi
``sigdb_builtin.vm_runtime`` modulundeki kanonik (genisletilmis) dict'lere
referans yapiliyor:
  - python_capi_signatures   76 -> 259 (kanonik: lib in {python, libpython},
                                         category=python_c_api)
  - java_jni_signatures      50 -> 158 (kanonik: lib in {jvm, libjvm},
                                         category=jni)
``runtimes`` modulu sadece public kategori yuzeyi olarak alias yapar; tek
veri sahibi vm_runtime modulu.

Korunan parity katmanlari:
1. Modul yuklenebilirlik
2. Coverage count (genis kapsam)
3. Cross-key kesişme yok
4. Bilinen sembol lookup (kanonik etiket)
5. Post-D0: signature_db.py'da Python/JNI inline YOK + dogrudan
   ``_BUILTIN_RUNTIMES_SIGS`` referansi VAR.
6. Identity zinciri: signature_db -> runtimes -> vm_runtime (ayni dict objesi).

Kapsam:
  - rust_stdlib_signatures   (47 entry)
  - rust_ext_signatures      (75 entry)
  - go_runtime_signatures    (53 entry)
  - go_ext_signatures        (209 entry)
  - python_capi_signatures   (259 entry)  [vm_runtime alias]
  - java_jni_signatures      (158 entry)  [vm_runtime alias]
  - dotnet_clr_signatures    (58 entry)

Toplam: 864 imza.
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
        "python_capi_signatures": 259,
        "java_jni_signatures": 158,
        "dotnet_clr_signatures": 58,
    }
    for key, expected in expected_counts.items():
        actual = len(mod.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in mod.SIGNATURES.values())
    assert total == 859, f"Total runtimes entry count: expected 859, got {total}"


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
    assert sum(len(v) for v in sigs.values()) == 859


# ---------------------------------------------------------------------------
# 3. Runtime identity — v1.14 D0 sonrasi tum runtime dict'leri migrated
# ---------------------------------------------------------------------------

# v1.14 D0 cleanup: 7 runtime kategori'sinin TUMU artik signature_db.py'da
# inline literal degil; ``_BUILTIN_RUNTIMES_SIGS`` (= sigdb_builtin.runtimes
# SIGNATURES) uzerinden bind ediliyor. Python/JNI ayrica vm_runtime modulune
# alias yapildigi icin identity zinciri 3 katmanli:
#   sdb._XXX_SIGNATURES is runtimes.SIGNATURES[key] is vm_runtime.SIGNATURES[vm_key]
_MIGRATED_KEYS_TO_LEGACY: dict[str, str] = {
    "rust_stdlib_signatures": "_RUST_STDLIB_SIGNATURES",
    "rust_ext_signatures": "_RUST_EXT_SIGNATURES",
    "go_runtime_signatures": "_GO_RUNTIME_SIGNATURES",
    "go_ext_signatures": "_GO_EXT_SIGNATURES",
    "dotnet_clr_signatures": "_DOTNET_CLR_SIGNATURES",
    "python_capi_signatures": "_PYTHON_CAPI_SIGNATURES",
    "java_jni_signatures": "_JAVA_JNI_SIGNATURES",
}

# Backward-compat alias (eski testler bu ismi referans alabilir).
_A_DELETE_KEYS_TO_LEGACY = _MIGRATED_KEYS_TO_LEGACY


@pytest.mark.parametrize(
    "builtin_key,legacy_name", sorted(_MIGRATED_KEYS_TO_LEGACY.items())
)
def test_runtime_identity_a_delete_dicts(builtin_key: str, legacy_name: str) -> None:
    """v1.14 D0 sonrasi tum runtime dict'leri identity zinciri korur."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    legacy = getattr(sdb, legacy_name)
    migrated = SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )


def test_python_capi_java_jni_vm_runtime_chain() -> None:
    """v1.14 D0: signature_db -> runtimes -> vm_runtime identity zinciri."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES as RT
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES as VM

    # Python C API: 3 katman ayni objeye isaret etmeli.
    assert sdb._PYTHON_CAPI_SIGNATURES is RT["python_capi_signatures"]
    assert RT["python_capi_signatures"] is VM["python_c_api_signatures"]
    assert len(sdb._PYTHON_CAPI_SIGNATURES) == 259

    # JNI: 3 katman ayni objeye isaret etmeli.
    assert sdb._JAVA_JNI_SIGNATURES is RT["java_jni_signatures"]
    assert RT["java_jni_signatures"] is VM["jni_signatures"]
    assert len(sdb._JAVA_JNI_SIGNATURES) == 158


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
    """CPython API klasik sembolleri (v1.14 D0 kanonik etiket)."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    py = SIGNATURES["python_capi_signatures"]
    for sym in ("Py_Initialize", "Py_Finalize", "PyObject_CallObject",
                "PyDict_New", "PyErr_SetString", "PyGILState_Ensure"):
        assert sym in py, f"{sym} python_capi dict'inde olmali"
        assert py[sym]["lib"] in {"python", "libpython"}, (
            f"{sym}: lib in {{python, libpython}} bekleniyor, {py[sym]['lib']}"
        )
        assert py[sym]["category"] == "python_c_api", (
            f"{sym}: kanonik category=python_c_api bekleniyor"
        )


def test_python_capi_extended_symbols_present() -> None:
    """v1.14 D0 sonrasi 259 entry kapsamindan secili yeni semboller."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    py = SIGNATURES["python_capi_signatures"]
    # Py2 legacy + Py3 + Capsule + buffer protocol kanitlari (vm_runtime kapsama).
    extended = (
        "Py_InitModule", "Py_InitModule3", "Py_InitModule4",  # Py2
        "PyModule_Create", "PyModule_Create2",                # Py3
        "PyCapsule_New", "PyCapsule_GetPointer",              # Capsule API
        "PyUnicode_DecodeUTF8", "PyUnicode_AsUTF8String",     # Unicode
        "PyString_FromString", "PyString_AsString",           # Py2 str
        "Py_INCREF", "Py_DECREF", "Py_CLEAR",                 # refcount macros
        "PyEval_AcquireLock", "PyEval_ReleaseLock",           # eski GIL
    )
    missing = [s for s in extended if s not in py]
    assert not missing, f"Genisletilmis Python C API semboller eksik: {missing}"


def test_jni_known_symbols() -> None:
    """JNI bilindik fonksiyonlari (v1.14 D0 kanonik etiket)."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    jni = SIGNATURES["java_jni_signatures"]
    for sym in ("JNI_CreateJavaVM", "JNI_OnLoad", "FindClass", "GetMethodID",
                "RegisterNatives", "AttachCurrentThread"):
        assert sym in jni, f"{sym} java_jni dict'inde olmali"
        assert jni[sym]["lib"] in {"jvm", "libjvm"}, (
            f"{sym}: lib in {{jvm, libjvm}} bekleniyor, {jni[sym]['lib']}"
        )
        assert jni[sym]["category"] == "jni", (
            f"{sym}: kanonik category=jni bekleniyor"
        )


def test_jni_extended_symbols_present() -> None:
    """v1.14 D0 sonrasi 158 entry kapsamindan secili yeni semboller."""
    from karadul.analyzers.sigdb_builtin.runtimes import SIGNATURES

    jni = SIGNATURES["java_jni_signatures"]
    extended = (
        # Class hierarchy + reflection
        "GetSuperclass", "IsAssignableFrom", "IsSameObject",
        "FromReflectedMethod", "ToReflectedMethod",
        # Critical / pinned access
        "GetStringCritical", "ReleaseStringCritical",
        "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
        # Direct buffer
        "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
        # Local frame
        "PushLocalFrame", "PopLocalFrame",
        # Invocation API
        "DestroyJavaVM", "AttachCurrentThreadAsDaemon",
        # Exception handling
        "Throw", "ExceptionOccurred",
    )
    missing = [s for s in extended if s not in jni]
    assert not missing, f"Genisletilmis JNI semboller eksik: {missing}"


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
    """signature_db.py'da Rust/Go/.NET/Python/JNI legacy literal'leri YOK; referans VAR."""
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
    # v1.14 D0: Python C API ve JNI de artik dogrudan bind ediliyor.
    assert '_BUILTIN_RUNTIMES_SIGS["python_capi_signatures"]' in text, (
        "_PYTHON_CAPI_SIGNATURES dogrudan bind edilmiyor"
    )
    assert '_BUILTIN_RUNTIMES_SIGS["java_jni_signatures"]' in text, (
        "_JAVA_JNI_SIGNATURES dogrudan bind edilmiyor"
    )
    # Inline literal blok baslangici YOK (D0 sonrasi tum 7 dict)
    # ``\n`` ile sabitleyerek `_MODERN_GO_RUNTIME_SIGNATURES = {}` gibi
    # alakasiz baska dict tanimlarinin substring olarak yakalanmamasini garantile.
    for legacy in _MIGRATED_KEYS_TO_LEGACY.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_v1_14_d0_no_vm_runtime_override_layer() -> None:
    """v1.14 D0: signature_db.py icindeki vm_runtime override try/except blogu silindi."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    # Eski override deseni: ``_BUILTIN_VM_RUNTIME_SIGNATURES.get("...", _XXX)``
    # artik olmamali (legacy dict yok ki override edilsin).
    assert "_BUILTIN_VM_RUNTIME_SIGNATURES.get" not in text, (
        "VM runtime override layer hala kodda; v1.14 D0 cleanup eksik"
    )
    # Eski override if-blogu da olmamali.
    assert "if _BUILTIN_VM_RUNTIME_SIGNATURES is not None:" not in text, (
        "VM runtime override if-blogu hala kodda"
    )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py runtimes'i ``sigdb_builtin.runtimes``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_RUNTIMES_SIGS" in text
    assert "sigdb_builtin" in text and "runtimes" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
