"""sig_db Faz 8 — VM runtime (JNI + Python C API) migration + coverage testleri.

Amac: ``karadul/analyzers/sigdb_builtin/vm_runtime.py`` modulune eklenen YENI
kapsama, orijinal ``karadul/analyzers/signature_db.py`` dict'leriyle ne
olcude uyumlu? Coverage hedefleri tutuyor mu?

  1. ``jni_signatures``             — YENI dict (~100+ entry). Legacy
     ``_JAVA_JNI_SIGNATURES`` (~50 entry) override edilir. Kanonik
     etiketleme: lib=jvm/libjvm, category=jni.
  2. ``python_c_api_signatures``    — YENI dict (~160+ entry). Legacy
     ``_PYTHON_CAPI_SIGNATURES`` (~80 entry) override edilir. Kanonik
     etiketleme: lib=python/libpython, category=python_c_api.

pe_runtime + windows_gui migration testlerinin pattern'ini takip eder
(bkz: test_sigdb_windows_gui_migration.py).
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_vm_runtime_importable() -> None:
    """sigdb_builtin.vm_runtime import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import vm_runtime

    assert hasattr(vm_runtime, "SIGNATURES")
    assert isinstance(vm_runtime.SIGNATURES, dict)
    assert len(vm_runtime.SIGNATURES) == 2


def test_sigdb_builtin_vm_runtime_has_expected_keys() -> None:
    """SIGNATURES iki top-level anahtar icerir: jni / python_c_api."""
    from karadul.analyzers.sigdb_builtin import vm_runtime

    expected = {
        "jni_signatures",
        "python_c_api_signatures",
    }
    assert set(vm_runtime.SIGNATURES.keys()) == expected


def test_sigdb_builtin_vm_runtime_entry_counts() -> None:
    """Her kategori beklenen minimum entry sayisina sahip (Faz 8 hedefi)."""
    from karadul.analyzers.sigdb_builtin import vm_runtime

    jni = vm_runtime.SIGNATURES["jni_signatures"]
    py = vm_runtime.SIGNATURES["python_c_api_signatures"]

    # Faz 8 kapsam hedefleri (alt sinir)
    assert len(jni) >= 80, (
        f"jni_signatures min 80 entry bekleniyor; bulundu {len(jni)}"
    )
    assert len(py) >= 120, (
        f"python_c_api_signatures min 120 entry bekleniyor; bulundu {len(py)}"
    )

    total = len(jni) + len(py)
    assert total >= 200, (
        f"Toplam vm_runtime entry sayisi en az 200 olmali; bulundu {total}"
    )


def test_sigdb_builtin_vm_runtime_no_cross_dict_duplicates() -> None:
    """Iki alt dict arasinda duplicate key olmamali (disjoint namespace)."""
    from karadul.analyzers.sigdb_builtin import vm_runtime

    jni = vm_runtime.SIGNATURES["jni_signatures"]
    py = vm_runtime.SIGNATURES["python_c_api_signatures"]

    overlap = set(jni) & set(py)
    assert not overlap, f"jni <-> python_c_api duplicate: {overlap}"


# ---------------------------------------------------------------------------
# 2. Override aktif mi? (identity / is check)
# ---------------------------------------------------------------------------

def test_override_vm_runtime_identity() -> None:
    """signature_db.py icindeki dict'ler builtin.vm_runtime ile ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES as builtin

    assert sdb._BUILTIN_VM_RUNTIME_SIGNATURES is not None
    assert sdb._JAVA_JNI_SIGNATURES is builtin["jni_signatures"]
    assert sdb._PYTHON_CAPI_SIGNATURES is builtin["python_c_api_signatures"]


def test_override_legacy_dicts_extended() -> None:
    """Legacy `_JAVA_JNI_SIGNATURES` + `_PYTHON_CAPI_SIGNATURES` override
    sonrasi genisler (eski 50 + 80 entry'den cok daha fazla)."""
    from karadul.analyzers import signature_db as sdb

    # Legacy _JAVA_JNI_SIGNATURES: eski ~50 entry, override sonra >= 80
    assert len(sdb._JAVA_JNI_SIGNATURES) >= 80, (
        f"JNI override sonrasi min 80 entry olmali; "
        f"bulundu {len(sdb._JAVA_JNI_SIGNATURES)}"
    )
    # Legacy _PYTHON_CAPI_SIGNATURES: eski ~80 entry, override sonra >= 120
    assert len(sdb._PYTHON_CAPI_SIGNATURES) >= 120, (
        f"Python C API override sonrasi min 120 entry olmali; "
        f"bulundu {len(sdb._PYTHON_CAPI_SIGNATURES)}"
    )


def test_legacy_vm_runtime_attributes_still_accessible() -> None:
    """Backward compat: eski dict attribute'lari hala erisilebilir ve dolu."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_JAVA_JNI_SIGNATURES")
    assert hasattr(sdb, "_PYTHON_CAPI_SIGNATURES")
    assert len(sdb._JAVA_JNI_SIGNATURES) > 0
    assert len(sdb._PYTHON_CAPI_SIGNATURES) > 0


# ---------------------------------------------------------------------------
# 3. Schema dogrulamasi — her entry dogru field setine sahip
# ---------------------------------------------------------------------------

def test_vm_runtime_all_entries_have_schema_fields() -> None:
    """Her entry ``lib``, ``purpose``, ``category`` alanlarina sahip."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    required = {"lib", "purpose", "category"}
    for bucket_name, bucket in SIGNATURES.items():
        for name, info in bucket.items():
            assert isinstance(info, dict), f"{bucket_name}/{name}: dict degil"
            assert required.issubset(info.keys()), (
                f"{bucket_name}/{name}: eksik alan(lar) {required - info.keys()}"
            )


def test_jni_lib_labels_valid() -> None:
    """Her JNI entry'nin ``lib`` etiketi jvm / libjvm setinden."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    allowed_libs = {"jvm", "libjvm"}
    bad = {
        n: info["lib"]
        for n, info in SIGNATURES["jni_signatures"].items()
        if info["lib"] not in allowed_libs
    }
    assert not bad, f"jni_signatures: yanlis lib etiketli entry'ler: {bad}"


def test_python_c_api_lib_labels_valid() -> None:
    """Her Python C API entry'nin ``lib`` etiketi python / libpython setinden."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    allowed_libs = {"python", "libpython"}
    bad = {
        n: info["lib"]
        for n, info in SIGNATURES["python_c_api_signatures"].items()
        if info["lib"] not in allowed_libs
    }
    assert not bad, f"python_c_api_signatures: yanlis lib etiketli entry'ler: {bad}"


def test_jni_category_is_canonical() -> None:
    """Tum JNI entry'leri ``category='jni'`` kullanmali."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    bad = {
        n: info["category"]
        for n, info in SIGNATURES["jni_signatures"].items()
        if info["category"] != "jni"
    }
    assert not bad, f"jni_signatures: beklenmeyen category'ler: {bad}"


def test_python_c_api_category_is_canonical() -> None:
    """Tum Python C API entry'leri ``category='python_c_api'`` kullanmali."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    bad = {
        n: info["category"]
        for n, info in SIGNATURES["python_c_api_signatures"].items()
        if info["category"] != "python_c_api"
    }
    assert not bad, f"python_c_api_signatures: beklenmeyen category'ler: {bad}"


# ---------------------------------------------------------------------------
# 4. Kritik sembol varligi (Faz 8 hedef kapsami)
# ---------------------------------------------------------------------------

def test_jni_entry_symbols_present() -> None:
    """JVM entry API sembolleri mevcut (JNI_* prefix)."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    jni = SIGNATURES["jni_signatures"]
    must_have = {
        "JNI_OnLoad", "JNI_OnUnload",
        "JNI_CreateJavaVM", "JNI_GetCreatedJavaVMs",
        "JNI_GetDefaultJavaVMInitArgs",
    }
    missing = must_have - set(jni)
    assert not missing, f"JNI entry API eksik semboller: {missing}"


def test_jni_common_method_chain_present() -> None:
    """Yaygin JNI method chain (FindClass -> GetMethodID -> CallObjectMethod)."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    jni = SIGNATURES["jni_signatures"]
    chain = {
        # Class lookup
        "FindClass", "GetObjectClass", "GetSuperclass",
        # Method resolution
        "GetMethodID", "GetStaticMethodID",
        "GetFieldID", "GetStaticFieldID",
        # Invocation (common return types)
        "CallObjectMethod", "CallIntMethod", "CallVoidMethod", "CallBooleanMethod",
        "CallStaticObjectMethod", "CallStaticVoidMethod", "CallStaticIntMethod",
        # Object creation
        "NewObject", "AllocObject",
        # String marshalling
        "NewStringUTF", "GetStringUTFChars", "ReleaseStringUTFChars",
        # Array marshalling
        "GetArrayLength", "GetByteArrayElements", "ReleaseByteArrayElements",
        "GetByteArrayRegion", "SetByteArrayRegion",
        # References
        "NewGlobalRef", "DeleteGlobalRef", "NewLocalRef", "DeleteLocalRef",
        # Exceptions
        "ExceptionCheck", "ExceptionClear", "Throw", "ThrowNew",
        # Monitor
        "MonitorEnter", "MonitorExit",
        # Native registration
        "RegisterNatives", "UnregisterNatives",
    }
    missing = chain - set(jni)
    assert not missing, f"JNI yaygin method chain eksik semboller: {missing}"


def test_jni_invocation_api_present() -> None:
    """JavaVM invocation API sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    jni = SIGNATURES["jni_signatures"]
    must_have = {
        "GetEnv", "AttachCurrentThread", "DetachCurrentThread",
        "AttachCurrentThreadAsDaemon", "DestroyJavaVM", "GetJavaVM",
    }
    missing = must_have - set(jni)
    assert not missing, f"JNI invocation API eksik semboller: {missing}"


def test_python_c_api_interpreter_lifecycle_present() -> None:
    """Python interpreter lifecycle sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    must_have = {
        "Py_Initialize", "Py_Finalize", "Py_IsInitialized",
        "PyRun_SimpleString", "PyRun_SimpleFile",
        "PyRun_String", "PyRun_File",
    }
    missing = must_have - set(py)
    assert not missing, f"Python C API interpreter lifecycle eksik: {missing}"


def test_python_c_api_module_init_present() -> None:
    """Extension module init fonksiyonlari (Py2 + Py3) mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    must_have = {
        # Python 3
        "PyModule_Create", "PyModule_Create2", "PyModule_AddObject",
        "PyModule_AddIntConstant", "PyModule_AddStringConstant",
        # Python 2 legacy
        "Py_InitModule", "Py_InitModule3", "Py_InitModule4",
        # Import
        "PyImport_ImportModule", "PyImport_Import", "PyImport_AddModule",
    }
    missing = must_have - set(py)
    assert not missing, f"Python C API module init eksik: {missing}"


def test_python_c_api_gil_family_present() -> None:
    """PyGILState_* + PyEval_*Thread aile sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    gil_family = {
        "PyGILState_Ensure", "PyGILState_Release",
        "PyGILState_GetThisThreadState",
        "PyEval_InitThreads", "PyEval_AcquireLock", "PyEval_ReleaseLock",
        "PyEval_SaveThread", "PyEval_RestoreThread",
    }
    missing = gil_family - set(py)
    assert not missing, f"Python C API GIL family eksik semboller: {missing}"


def test_python_c_api_unicode_py2_py3_both_present() -> None:
    """Python 2 PyString ve Python 3 PyUnicode her ikisi de mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    # Python 3 Unicode family
    py3 = {
        "PyUnicode_FromString", "PyUnicode_AsUTF8", "PyUnicode_AsUTF8String",
        "PyUnicode_DecodeUTF8",
    }
    # Python 2 legacy
    py2 = {
        "PyString_FromString", "PyString_AsString",
    }
    missing_py3 = py3 - set(py)
    missing_py2 = py2 - set(py)
    assert not missing_py3, f"Python 3 Unicode API eksik: {missing_py3}"
    assert not missing_py2, f"Python 2 PyString API eksik: {missing_py2}"


def test_python_c_api_refcount_macros_present() -> None:
    """Py_INCREF / Py_DECREF aile sembolleri signature tablosunda mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    refcount = {
        "Py_IncRef", "Py_DecRef",
        "Py_INCREF", "Py_DECREF",
        "Py_XINCREF", "Py_XDECREF", "Py_CLEAR",
    }
    missing = refcount - set(py)
    assert not missing, f"Python C API refcount macros eksik: {missing}"


def test_python_c_api_arg_parsing_present() -> None:
    """PyArg_* ve Py_BuildValue aile sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    py = SIGNATURES["python_c_api_signatures"]
    must_have = {
        "PyArg_Parse", "PyArg_ParseTuple", "PyArg_ParseTupleAndKeywords",
        "Py_BuildValue",
    }
    missing = must_have - set(py)
    assert not missing, f"Python C API arg parsing eksik: {missing}"


# ---------------------------------------------------------------------------
# 5. Cross-platform dogrulamasi (platform-specific etiket yok)
# ---------------------------------------------------------------------------

def test_vm_runtime_no_platform_specific_category() -> None:
    """JNI ve Python C API cross-platform'dur; platform-specific kategori olmamali."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    forbidden_categories = {
        "win_file", "win_process", "win_memory", "win_gui",
        "linux_io", "linux_system",
        "macos_apple", "macos_system",
    }
    for bucket_name, bucket in SIGNATURES.items():
        bad = {
            n: info["category"]
            for n, info in bucket.items()
            if info["category"] in forbidden_categories
        }
        assert not bad, (
            f"{bucket_name}: platform-specific category bulundu: {bad}"
        )


def test_vm_runtime_no_android_art_specific() -> None:
    """Android ART runtime'a ozel semboller bu modulde olmamali (v1.13 mobile-lite)."""
    from karadul.analyzers.sigdb_builtin.vm_runtime import SIGNATURES

    jni = SIGNATURES["jni_signatures"]
    # ART-specific semboller hariclanmalidir
    art_specific = {
        "ArtMethod_Invoke",
        "art_quick_generic_jni_trampoline",
        "android_dlopen_ext",
    }
    found = art_specific & set(jni)
    assert not found, f"Android ART-specific semboller bulundu (hariclanmali): {found}"


# ---------------------------------------------------------------------------
# 6. SignatureDB class kullanimi — yeni semboller gercekten yuklendi mi?
# ---------------------------------------------------------------------------

def _fresh_signature_db():
    """_full_cache'i temizleyip taze SignatureDB olustur."""
    from karadul.analyzers.signature_db import SignatureDB
    from karadul.config import Config

    SignatureDB._full_cache.clear()
    return SignatureDB(Config())


def test_signature_db_loads_new_jni_symbols() -> None:
    """SignatureDB instance yeni JNI sembollerini icerir + kanonik etiket."""
    db = _fresh_signature_db()

    # Yeni eklenen JNI sembolleri (eski dict'te yoktu)
    assert "GetStringCritical" in db._symbol_db
    assert "NewDirectByteBuffer" in db._symbol_db
    assert "GetDirectBufferAddress" in db._symbol_db
    assert "PushLocalFrame" in db._symbol_db

    # Kanonik etiketler
    assert db._symbol_db["FindClass"]["lib"] == "libjvm"
    assert db._symbol_db["FindClass"]["category"] == "jni"
    assert db._symbol_db["JNI_OnLoad"]["lib"] == "jvm"
    assert db._symbol_db["JNI_OnLoad"]["category"] == "jni"


def test_signature_db_loads_new_python_c_api_symbols() -> None:
    """SignatureDB instance yeni Python C API sembollerini icerir + kanonik etiket."""
    db = _fresh_signature_db()

    # Yeni eklenen Python C API sembolleri
    assert "PyCapsule_New" in db._symbol_db
    assert "PyUnicode_DecodeUTF8" in db._symbol_db
    assert "Py_InitModule" in db._symbol_db  # Py2 legacy
    assert "PyModule_Create" in db._symbol_db  # Py3

    # Kanonik etiketler
    assert db._symbol_db["PyGILState_Ensure"]["lib"] == "python"
    assert db._symbol_db["PyGILState_Ensure"]["category"] == "python_c_api"
    assert db._symbol_db["Py_Initialize"]["category"] == "python_c_api"


# ---------------------------------------------------------------------------
# 7. Regression: onceki migrasyonlar hala saglam
# ---------------------------------------------------------------------------

def test_previous_migrations_still_intact() -> None:
    """Crypto / compression / network / pe_runtime / windows_gui hala yuklenebilir."""
    from karadul.analyzers.sigdb_builtin.compression import SIGNATURES as comp
    from karadul.analyzers.sigdb_builtin.crypto import SIGNATURES as cry
    from karadul.analyzers.sigdb_builtin.network import SIGNATURES as net
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as pe
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES as gui

    assert len(cry) == 6
    assert len(comp) == 5
    assert len(net) == 7
    assert len(pe) == 3
    assert len(gui) == 3


def test_pe_runtime_override_still_active() -> None:
    """pe_runtime override (kernel32/ntdll/msvc_crt) hala aktif."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.pe_runtime import SIGNATURES as pe

    assert sdb._WIN32_KERNEL32_SIGNATURES is pe["kernel32_signatures"]
    assert sdb._WIN32_NTDLL_SIGNATURES is pe["ntdll_signatures"]
    assert sdb._MSVC_CRT_SIGNATURES is pe["msvc_crt_signatures"]


def test_windows_gui_override_still_active() -> None:
    """windows_gui override (user32/advapi32/gdi32) hala aktif."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.windows_gui import SIGNATURES as gui

    assert sdb._WIN32_USER32_SIGNATURES is gui["user32_signatures"]
    assert sdb._WIN32_ADVAPI32_FULL_SIGNATURES is gui["advapi32_signatures"]
    assert sdb._WIN32_GDI32_SIGNATURES is gui["gdi32_signatures"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
