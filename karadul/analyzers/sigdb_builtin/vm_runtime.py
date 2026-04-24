"""VM runtime / hybrid binary category signatures — sig_db Faz 8 dalgasi.

Bu modul hybrid (native + managed) binary analizi icin iki ayri runtime
surface icin YENI kapsama saglar:

  1. ``jni_signatures``            — Java Native Interface (JNI) API.
                                     Hedef: libjvm.so / jvm.dll export'lari +
                                     JNIEnv / JavaVM struct fonksiyon pointer
                                     tablosu isimleri.
                                     Kapsama hedefi: ~80-120 entry.
  2. ``python_c_api_signatures``   — CPython C API. Embed + C extension
                                     modul (Py_InitModule / PyModule_Create)
                                     analizi icin. Python 2 + Python 3 API
                                     esit sekilde dahil.
                                     Kapsama hedefi: ~120-180 entry.

Toplam hedef: ~200-300 entry. YENI coverage — legacy'de kucuk bir alt
kume (JNI ~50, Python C API ~80) mevcuttu; bu modul onlari override EDER
ve kanonik isimlendirmeye (category="jni" / "python_c_api") tasir.

Platform: Her iki runtime cross-platform'dur (Windows / Linux / macOS).
Android ART runtime'a ozel sembolleri (``ArtMethod_Invoke`` vb.) burada
HARIC tutulmustur; mobile-lite dalgasinda (v1.13) ayri modulde islenir.

Online fetch YAPILMAMISTIR. Bilgi kaynagi: Oracle JDK 21 JNI specification
(jni.h) ve CPython 3.12 stable ABI (PEP 384 / 523). Python 2 sembolleri
(``Py_InitModule*``) eski binary'ler icin dahil edilmistir.

Legacy ``_JAVA_JNI_SIGNATURES`` ve ``_PYTHON_CAPI_SIGNATURES``
(signature_db.py satir 6033-6187) SILINMEDI; rollback icin override
yontemi kullanilir. Overlap entry'ler ayni sembol isimlerini tasir ama
kanonik ``lib`` / ``category`` etiketleriyle normalize edilir
(ornegin: legacy "jni"/"java" -> "jvm"/"jni").
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# JNI (~100 entry) — Java Native Interface
# Kaynak: Oracle JDK 21 JNI specification, jni.h.
#
# JNI entry'leri iki gruba ayrilir:
#   a) JVM library exports (``JNI_*`` prefix): binary'de global export
#      sembolleri. libjvm.so / jvm.dll'den resolve edilir.
#   b) JNIEnv / JavaVM function pointer table: struct uzerinden cagrilir,
#      sembolleri dogrudan export edilmez ama decompiled kodda isim olarak
#      bulunur (offset + pattern match). Binary analizinde isim eslesmesi
#      icin signature DB'sinde tutmak degerlidir.
# Kategori: ``jni``. lib etiketi: ``jvm`` (JNI_*) veya ``libjvm``
# (function pointer table isimleri).
# ---------------------------------------------------------------------------
_JNI_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # ---- JVM library exports (JNI_* prefix) ----
    "JNI_OnLoad": {"lib": "jvm", "purpose": "native library loaded by JVM (entry)", "category": "jni"},
    "JNI_OnUnload": {"lib": "jvm", "purpose": "native library unloaded by JVM", "category": "jni"},
    "JNI_CreateJavaVM": {"lib": "jvm", "purpose": "create Java Virtual Machine instance", "category": "jni"},
    "JNI_GetCreatedJavaVMs": {"lib": "jvm", "purpose": "get list of created JVMs in process", "category": "jni"},
    "JNI_GetDefaultJavaVMInitArgs": {"lib": "jvm", "purpose": "get default JVM init args structure", "category": "jni"},

    # ---- JavaVM interface (invocation API) ----
    "GetEnv": {"lib": "libjvm", "purpose": "get JNIEnv for current thread", "category": "jni"},
    "AttachCurrentThread": {"lib": "libjvm", "purpose": "attach native thread to JVM", "category": "jni"},
    "AttachCurrentThreadAsDaemon": {"lib": "libjvm", "purpose": "attach native thread as daemon", "category": "jni"},
    "DetachCurrentThread": {"lib": "libjvm", "purpose": "detach native thread from JVM", "category": "jni"},
    "DestroyJavaVM": {"lib": "libjvm", "purpose": "destroy Java Virtual Machine", "category": "jni"},
    "GetJavaVM": {"lib": "libjvm", "purpose": "get JavaVM pointer from JNIEnv", "category": "jni"},

    # ---- Version / capabilities ----
    "GetVersion": {"lib": "libjvm", "purpose": "get JNI interface version number", "category": "jni"},

    # ---- Class operations ----
    "DefineClass": {"lib": "libjvm", "purpose": "define class from byte array", "category": "jni"},
    "FindClass": {"lib": "libjvm", "purpose": "find Java class by name descriptor", "category": "jni"},
    "GetObjectClass": {"lib": "libjvm", "purpose": "get class of Java object instance", "category": "jni"},
    "GetSuperclass": {"lib": "libjvm", "purpose": "get superclass of given class", "category": "jni"},
    "IsAssignableFrom": {"lib": "libjvm", "purpose": "check class assignment compatibility", "category": "jni"},
    "IsInstanceOf": {"lib": "libjvm", "purpose": "check Java instanceof relation", "category": "jni"},
    "IsSameObject": {"lib": "libjvm", "purpose": "check if two refs point to same object", "category": "jni"},

    # ---- Method / field IDs ----
    "GetMethodID": {"lib": "libjvm", "purpose": "get Java instance method ID", "category": "jni"},
    "GetStaticMethodID": {"lib": "libjvm", "purpose": "get Java static method ID", "category": "jni"},
    "GetFieldID": {"lib": "libjvm", "purpose": "get Java instance field ID", "category": "jni"},
    "GetStaticFieldID": {"lib": "libjvm", "purpose": "get Java static field ID", "category": "jni"},
    "FromReflectedMethod": {"lib": "libjvm", "purpose": "convert reflected method to jmethodID", "category": "jni"},
    "FromReflectedField": {"lib": "libjvm", "purpose": "convert reflected field to jfieldID", "category": "jni"},
    "ToReflectedMethod": {"lib": "libjvm", "purpose": "convert jmethodID to reflected method", "category": "jni"},
    "ToReflectedField": {"lib": "libjvm", "purpose": "convert jfieldID to reflected field", "category": "jni"},

    # ---- Object creation ----
    "AllocObject": {"lib": "libjvm", "purpose": "allocate object without calling constructor", "category": "jni"},
    "NewObject": {"lib": "libjvm", "purpose": "construct new Java object (varargs)", "category": "jni"},
    "NewObjectA": {"lib": "libjvm", "purpose": "construct new Java object (jvalue array)", "category": "jni"},
    "NewObjectV": {"lib": "libjvm", "purpose": "construct new Java object (va_list)", "category": "jni"},

    # ---- Instance method invocation ----
    "CallObjectMethod": {"lib": "libjvm", "purpose": "call Java object method returning Object", "category": "jni"},
    "CallObjectMethodA": {"lib": "libjvm", "purpose": "call Java method (jvalue array args)", "category": "jni"},
    "CallObjectMethodV": {"lib": "libjvm", "purpose": "call Java method (va_list args)", "category": "jni"},
    "CallBooleanMethod": {"lib": "libjvm", "purpose": "call Java method returning boolean", "category": "jni"},
    "CallByteMethod": {"lib": "libjvm", "purpose": "call Java method returning byte", "category": "jni"},
    "CallCharMethod": {"lib": "libjvm", "purpose": "call Java method returning char", "category": "jni"},
    "CallShortMethod": {"lib": "libjvm", "purpose": "call Java method returning short", "category": "jni"},
    "CallIntMethod": {"lib": "libjvm", "purpose": "call Java method returning int", "category": "jni"},
    "CallLongMethod": {"lib": "libjvm", "purpose": "call Java method returning long", "category": "jni"},
    "CallFloatMethod": {"lib": "libjvm", "purpose": "call Java method returning float", "category": "jni"},
    "CallDoubleMethod": {"lib": "libjvm", "purpose": "call Java method returning double", "category": "jni"},
    "CallVoidMethod": {"lib": "libjvm", "purpose": "call Java method returning void", "category": "jni"},
    "CallNonvirtualObjectMethod": {"lib": "libjvm", "purpose": "nonvirtual call returning Object", "category": "jni"},
    "CallNonvirtualVoidMethod": {"lib": "libjvm", "purpose": "nonvirtual call returning void", "category": "jni"},

    # ---- Static method invocation ----
    "CallStaticObjectMethod": {"lib": "libjvm", "purpose": "call static method returning Object", "category": "jni"},
    "CallStaticBooleanMethod": {"lib": "libjvm", "purpose": "call static method returning boolean", "category": "jni"},
    "CallStaticByteMethod": {"lib": "libjvm", "purpose": "call static method returning byte", "category": "jni"},
    "CallStaticCharMethod": {"lib": "libjvm", "purpose": "call static method returning char", "category": "jni"},
    "CallStaticShortMethod": {"lib": "libjvm", "purpose": "call static method returning short", "category": "jni"},
    "CallStaticIntMethod": {"lib": "libjvm", "purpose": "call static method returning int", "category": "jni"},
    "CallStaticLongMethod": {"lib": "libjvm", "purpose": "call static method returning long", "category": "jni"},
    "CallStaticFloatMethod": {"lib": "libjvm", "purpose": "call static method returning float", "category": "jni"},
    "CallStaticDoubleMethod": {"lib": "libjvm", "purpose": "call static method returning double", "category": "jni"},
    "CallStaticVoidMethod": {"lib": "libjvm", "purpose": "call static method returning void", "category": "jni"},

    # ---- Instance field access ----
    "GetObjectField": {"lib": "libjvm", "purpose": "get Object field value", "category": "jni"},
    "GetBooleanField": {"lib": "libjvm", "purpose": "get boolean field value", "category": "jni"},
    "GetByteField": {"lib": "libjvm", "purpose": "get byte field value", "category": "jni"},
    "GetCharField": {"lib": "libjvm", "purpose": "get char field value", "category": "jni"},
    "GetShortField": {"lib": "libjvm", "purpose": "get short field value", "category": "jni"},
    "GetIntField": {"lib": "libjvm", "purpose": "get int field value", "category": "jni"},
    "GetLongField": {"lib": "libjvm", "purpose": "get long field value", "category": "jni"},
    "GetFloatField": {"lib": "libjvm", "purpose": "get float field value", "category": "jni"},
    "GetDoubleField": {"lib": "libjvm", "purpose": "get double field value", "category": "jni"},
    "SetObjectField": {"lib": "libjvm", "purpose": "set Object field value", "category": "jni"},
    "SetBooleanField": {"lib": "libjvm", "purpose": "set boolean field value", "category": "jni"},
    "SetByteField": {"lib": "libjvm", "purpose": "set byte field value", "category": "jni"},
    "SetCharField": {"lib": "libjvm", "purpose": "set char field value", "category": "jni"},
    "SetShortField": {"lib": "libjvm", "purpose": "set short field value", "category": "jni"},
    "SetIntField": {"lib": "libjvm", "purpose": "set int field value", "category": "jni"},
    "SetLongField": {"lib": "libjvm", "purpose": "set long field value", "category": "jni"},
    "SetFloatField": {"lib": "libjvm", "purpose": "set float field value", "category": "jni"},
    "SetDoubleField": {"lib": "libjvm", "purpose": "set double field value", "category": "jni"},

    # ---- Static field access ----
    "GetStaticObjectField": {"lib": "libjvm", "purpose": "get static Object field value", "category": "jni"},
    "GetStaticBooleanField": {"lib": "libjvm", "purpose": "get static boolean field value", "category": "jni"},
    "GetStaticIntField": {"lib": "libjvm", "purpose": "get static int field value", "category": "jni"},
    "GetStaticLongField": {"lib": "libjvm", "purpose": "get static long field value", "category": "jni"},
    "GetStaticFloatField": {"lib": "libjvm", "purpose": "get static float field value", "category": "jni"},
    "GetStaticDoubleField": {"lib": "libjvm", "purpose": "get static double field value", "category": "jni"},
    "SetStaticObjectField": {"lib": "libjvm", "purpose": "set static Object field value", "category": "jni"},
    "SetStaticIntField": {"lib": "libjvm", "purpose": "set static int field value", "category": "jni"},
    "SetStaticLongField": {"lib": "libjvm", "purpose": "set static long field value", "category": "jni"},

    # ---- String operations ----
    "NewString": {"lib": "libjvm", "purpose": "create Java string from Unicode buffer", "category": "jni"},
    "GetStringLength": {"lib": "libjvm", "purpose": "get Unicode length of Java string", "category": "jni"},
    "GetStringChars": {"lib": "libjvm", "purpose": "get Unicode chars from Java string", "category": "jni"},
    "ReleaseStringChars": {"lib": "libjvm", "purpose": "release Unicode chars from GetStringChars", "category": "jni"},
    "NewStringUTF": {"lib": "libjvm", "purpose": "create Java string from UTF-8 C string", "category": "jni"},
    "GetStringUTFLength": {"lib": "libjvm", "purpose": "get UTF-8 byte length of Java string", "category": "jni"},
    "GetStringUTFChars": {"lib": "libjvm", "purpose": "get UTF-8 chars from Java string", "category": "jni"},
    "ReleaseStringUTFChars": {"lib": "libjvm", "purpose": "release UTF-8 chars from GetStringUTFChars", "category": "jni"},
    "GetStringRegion": {"lib": "libjvm", "purpose": "copy Unicode chars region into buffer", "category": "jni"},
    "GetStringUTFRegion": {"lib": "libjvm", "purpose": "copy UTF-8 chars region into buffer", "category": "jni"},
    "GetStringCritical": {"lib": "libjvm", "purpose": "get direct pointer to string chars (critical)", "category": "jni"},
    "ReleaseStringCritical": {"lib": "libjvm", "purpose": "release string chars (critical)", "category": "jni"},

    # ---- Array operations ----
    "GetArrayLength": {"lib": "libjvm", "purpose": "get length of Java array", "category": "jni"},
    "NewObjectArray": {"lib": "libjvm", "purpose": "create new Object array", "category": "jni"},
    "GetObjectArrayElement": {"lib": "libjvm", "purpose": "get element of Object array", "category": "jni"},
    "SetObjectArrayElement": {"lib": "libjvm", "purpose": "set element of Object array", "category": "jni"},
    "NewBooleanArray": {"lib": "libjvm", "purpose": "create new boolean array", "category": "jni"},
    "NewByteArray": {"lib": "libjvm", "purpose": "create new byte array", "category": "jni"},
    "NewCharArray": {"lib": "libjvm", "purpose": "create new char array", "category": "jni"},
    "NewShortArray": {"lib": "libjvm", "purpose": "create new short array", "category": "jni"},
    "NewIntArray": {"lib": "libjvm", "purpose": "create new int array", "category": "jni"},
    "NewLongArray": {"lib": "libjvm", "purpose": "create new long array", "category": "jni"},
    "NewFloatArray": {"lib": "libjvm", "purpose": "create new float array", "category": "jni"},
    "NewDoubleArray": {"lib": "libjvm", "purpose": "create new double array", "category": "jni"},

    # ---- Primitive array element access ----
    "GetBooleanArrayElements": {"lib": "libjvm", "purpose": "get pointer to boolean array elements", "category": "jni"},
    "GetByteArrayElements": {"lib": "libjvm", "purpose": "get pointer to byte array elements", "category": "jni"},
    "GetCharArrayElements": {"lib": "libjvm", "purpose": "get pointer to char array elements", "category": "jni"},
    "GetShortArrayElements": {"lib": "libjvm", "purpose": "get pointer to short array elements", "category": "jni"},
    "GetIntArrayElements": {"lib": "libjvm", "purpose": "get pointer to int array elements", "category": "jni"},
    "GetLongArrayElements": {"lib": "libjvm", "purpose": "get pointer to long array elements", "category": "jni"},
    "GetFloatArrayElements": {"lib": "libjvm", "purpose": "get pointer to float array elements", "category": "jni"},
    "GetDoubleArrayElements": {"lib": "libjvm", "purpose": "get pointer to double array elements", "category": "jni"},
    "ReleaseBooleanArrayElements": {"lib": "libjvm", "purpose": "release boolean array elements", "category": "jni"},
    "ReleaseByteArrayElements": {"lib": "libjvm", "purpose": "release byte array elements", "category": "jni"},
    "ReleaseCharArrayElements": {"lib": "libjvm", "purpose": "release char array elements", "category": "jni"},
    "ReleaseShortArrayElements": {"lib": "libjvm", "purpose": "release short array elements", "category": "jni"},
    "ReleaseIntArrayElements": {"lib": "libjvm", "purpose": "release int array elements", "category": "jni"},
    "ReleaseLongArrayElements": {"lib": "libjvm", "purpose": "release long array elements", "category": "jni"},
    "ReleaseFloatArrayElements": {"lib": "libjvm", "purpose": "release float array elements", "category": "jni"},
    "ReleaseDoubleArrayElements": {"lib": "libjvm", "purpose": "release double array elements", "category": "jni"},

    # ---- Primitive array region copy ----
    "GetByteArrayRegion": {"lib": "libjvm", "purpose": "copy byte array region to buffer", "category": "jni"},
    "GetIntArrayRegion": {"lib": "libjvm", "purpose": "copy int array region to buffer", "category": "jni"},
    "GetLongArrayRegion": {"lib": "libjvm", "purpose": "copy long array region to buffer", "category": "jni"},
    "GetFloatArrayRegion": {"lib": "libjvm", "purpose": "copy float array region to buffer", "category": "jni"},
    "GetDoubleArrayRegion": {"lib": "libjvm", "purpose": "copy double array region to buffer", "category": "jni"},
    "SetByteArrayRegion": {"lib": "libjvm", "purpose": "copy byte buffer into array region", "category": "jni"},
    "SetIntArrayRegion": {"lib": "libjvm", "purpose": "copy int buffer into array region", "category": "jni"},
    "SetLongArrayRegion": {"lib": "libjvm", "purpose": "copy long buffer into array region", "category": "jni"},
    "SetFloatArrayRegion": {"lib": "libjvm", "purpose": "copy float buffer into array region", "category": "jni"},
    "SetDoubleArrayRegion": {"lib": "libjvm", "purpose": "copy double buffer into array region", "category": "jni"},
    "GetPrimitiveArrayCritical": {"lib": "libjvm", "purpose": "get direct pointer to array (critical)", "category": "jni"},
    "ReleasePrimitiveArrayCritical": {"lib": "libjvm", "purpose": "release direct array pointer (critical)", "category": "jni"},

    # ---- References ----
    "NewGlobalRef": {"lib": "libjvm", "purpose": "create global JNI reference", "category": "jni"},
    "DeleteGlobalRef": {"lib": "libjvm", "purpose": "delete global JNI reference", "category": "jni"},
    "NewLocalRef": {"lib": "libjvm", "purpose": "create local JNI reference", "category": "jni"},
    "DeleteLocalRef": {"lib": "libjvm", "purpose": "delete local JNI reference", "category": "jni"},
    "NewWeakGlobalRef": {"lib": "libjvm", "purpose": "create weak global JNI reference", "category": "jni"},
    "DeleteWeakGlobalRef": {"lib": "libjvm", "purpose": "delete weak global JNI reference", "category": "jni"},
    "EnsureLocalCapacity": {"lib": "libjvm", "purpose": "ensure local ref frame capacity", "category": "jni"},
    "PushLocalFrame": {"lib": "libjvm", "purpose": "push new local reference frame", "category": "jni"},
    "PopLocalFrame": {"lib": "libjvm", "purpose": "pop local reference frame", "category": "jni"},
    "GetObjectRefType": {"lib": "libjvm", "purpose": "classify reference as local/global/weak", "category": "jni"},

    # ---- Exceptions ----
    "Throw": {"lib": "libjvm", "purpose": "throw existing Throwable object", "category": "jni"},
    "ThrowNew": {"lib": "libjvm", "purpose": "construct and throw new Throwable", "category": "jni"},
    "ExceptionOccurred": {"lib": "libjvm", "purpose": "get pending Throwable reference", "category": "jni"},
    "ExceptionCheck": {"lib": "libjvm", "purpose": "check if exception is pending", "category": "jni"},
    "ExceptionClear": {"lib": "libjvm", "purpose": "clear pending Java exception", "category": "jni"},
    "ExceptionDescribe": {"lib": "libjvm", "purpose": "print Java exception to stderr", "category": "jni"},
    "FatalError": {"lib": "libjvm", "purpose": "raise fatal JVM error (aborts VM)", "category": "jni"},

    # ---- Monitor / synchronization ----
    "MonitorEnter": {"lib": "libjvm", "purpose": "acquire Java object monitor", "category": "jni"},
    "MonitorExit": {"lib": "libjvm", "purpose": "release Java object monitor", "category": "jni"},

    # ---- Native method registration ----
    "RegisterNatives": {"lib": "libjvm", "purpose": "register native methods with class", "category": "jni"},
    "UnregisterNatives": {"lib": "libjvm", "purpose": "unregister native methods of class", "category": "jni"},

    # ---- Direct byte buffers (NIO) ----
    "NewDirectByteBuffer": {"lib": "libjvm", "purpose": "create direct NIO ByteBuffer", "category": "jni"},
    "GetDirectBufferAddress": {"lib": "libjvm", "purpose": "get native address of direct buffer", "category": "jni"},
    "GetDirectBufferCapacity": {"lib": "libjvm", "purpose": "get capacity of direct buffer", "category": "jni"},
}


# ---------------------------------------------------------------------------
# Python C API (~160 entry) — CPython embed + extension module
# Kaynak: CPython 3.12 stable ABI (PEP 384 / 523) + Python 2.7 legacy.
# Kategori: ``python_c_api``. lib: ``python`` (generic) veya ``libpython``.
#
# Kapsama:
#   - Interpreter lifecycle (Initialize, Finalize, Run*)
#   - Module / import (PyModule_*, PyImport_*, Py_InitModule*)
#   - Object protocol (PyObject_*)
#   - Reference counting macros (Py_INCREF/DECREF)
#   - Type system (PyType_*)
#   - Numeric types (PyLong, PyFloat)
#   - Sequence types (PyTuple, PyList)
#   - Mapping (PyDict, PySet)
#   - String / bytes (PyUnicode, PyBytes, legacy PyString)
#   - Error handling (PyErr_*)
#   - GIL / threading (PyGILState_*, PyEval_*)
#   - Argument parsing (PyArg_*, Py_BuildValue)
#   - Callable / method (PyCFunction_*, PyMethod_*)
#   - Capsule (PyCapsule_*)
# ---------------------------------------------------------------------------
_PYTHON_C_API_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # ---- Interpreter lifecycle ----
    "Py_Initialize": {"lib": "python", "purpose": "initialize Python interpreter", "category": "python_c_api"},
    "Py_InitializeEx": {"lib": "python", "purpose": "initialize with signal config", "category": "python_c_api"},
    "Py_Finalize": {"lib": "python", "purpose": "finalize Python interpreter", "category": "python_c_api"},
    "Py_FinalizeEx": {"lib": "python", "purpose": "finalize with status return", "category": "python_c_api"},
    "Py_IsInitialized": {"lib": "python", "purpose": "check if interpreter initialized", "category": "python_c_api"},
    "Py_Main": {"lib": "python", "purpose": "run Python main with argv", "category": "python_c_api"},
    "Py_SetProgramName": {"lib": "python", "purpose": "set program name before init", "category": "python_c_api"},
    "Py_SetPythonHome": {"lib": "python", "purpose": "set Python home directory", "category": "python_c_api"},
    "Py_GetVersion": {"lib": "python", "purpose": "get Python version string", "category": "python_c_api"},
    "Py_GetPlatform": {"lib": "python", "purpose": "get platform identifier", "category": "python_c_api"},
    "Py_Exit": {"lib": "python", "purpose": "finalize and exit process", "category": "python_c_api"},
    "Py_AtExit": {"lib": "python", "purpose": "register finalize cleanup hook", "category": "python_c_api"},

    # ---- Code execution (high-level) ----
    "PyRun_SimpleString": {"lib": "python", "purpose": "execute Python string (simple)", "category": "python_c_api"},
    "PyRun_SimpleStringFlags": {"lib": "python", "purpose": "execute Python string with flags", "category": "python_c_api"},
    "PyRun_SimpleFile": {"lib": "python", "purpose": "execute Python file (simple)", "category": "python_c_api"},
    "PyRun_SimpleFileEx": {"lib": "python", "purpose": "execute Python file with close flag", "category": "python_c_api"},
    "PyRun_String": {"lib": "python", "purpose": "execute string and return result", "category": "python_c_api"},
    "PyRun_StringFlags": {"lib": "python", "purpose": "execute string with compiler flags", "category": "python_c_api"},
    "PyRun_File": {"lib": "python", "purpose": "execute file and return result", "category": "python_c_api"},
    "PyRun_FileEx": {"lib": "python", "purpose": "execute file with close flag", "category": "python_c_api"},
    "Py_CompileString": {"lib": "python", "purpose": "compile source to code object", "category": "python_c_api"},
    "Py_CompileStringFlags": {"lib": "python", "purpose": "compile source with flags", "category": "python_c_api"},
    "PyEval_EvalCode": {"lib": "python", "purpose": "evaluate compiled code object", "category": "python_c_api"},
    "PyEval_EvalCodeEx": {"lib": "python", "purpose": "evaluate code with extended args", "category": "python_c_api"},

    # ---- Module / import ----
    "PyImport_ImportModule": {"lib": "python", "purpose": "import Python module by name", "category": "python_c_api"},
    "PyImport_ImportModuleLevel": {"lib": "python", "purpose": "import with relative level", "category": "python_c_api"},
    "PyImport_Import": {"lib": "python", "purpose": "high-level import (uses __import__)", "category": "python_c_api"},
    "PyImport_ImportModuleEx": {"lib": "python", "purpose": "import with globals/locals/fromlist", "category": "python_c_api"},
    "PyImport_AddModule": {"lib": "python", "purpose": "get or create module by name", "category": "python_c_api"},
    "PyImport_GetModuleDict": {"lib": "python", "purpose": "get sys.modules dict", "category": "python_c_api"},
    "PyImport_ReloadModule": {"lib": "python", "purpose": "reload Python module", "category": "python_c_api"},
    "PyModule_Create": {"lib": "python", "purpose": "create extension module (Py3)", "category": "python_c_api"},
    "PyModule_Create2": {"lib": "python", "purpose": "create extension module with ABI", "category": "python_c_api"},
    "PyModule_AddObject": {"lib": "python", "purpose": "add object to module namespace", "category": "python_c_api"},
    "PyModule_AddIntConstant": {"lib": "python", "purpose": "add int constant to module", "category": "python_c_api"},
    "PyModule_AddStringConstant": {"lib": "python", "purpose": "add string constant to module", "category": "python_c_api"},
    "PyModule_AddType": {"lib": "python", "purpose": "add type to module namespace", "category": "python_c_api"},
    "PyModule_GetDict": {"lib": "python", "purpose": "get module's __dict__", "category": "python_c_api"},
    "PyModule_GetName": {"lib": "python", "purpose": "get module __name__ attribute", "category": "python_c_api"},
    "PyModule_GetFilename": {"lib": "python", "purpose": "get module __file__ attribute", "category": "python_c_api"},
    "PyModule_GetState": {"lib": "python", "purpose": "get module state pointer", "category": "python_c_api"},
    # Python 2 legacy extension init
    "Py_InitModule": {"lib": "python", "purpose": "init Py2 extension module", "category": "python_c_api"},
    "Py_InitModule3": {"lib": "python", "purpose": "init Py2 extension module (docstring)", "category": "python_c_api"},
    "Py_InitModule4": {"lib": "python", "purpose": "init Py2 extension module (ABI check)", "category": "python_c_api"},

    # ---- Object protocol ----
    "PyObject_GetAttr": {"lib": "python", "purpose": "get attribute by name object", "category": "python_c_api"},
    "PyObject_SetAttr": {"lib": "python", "purpose": "set attribute by name object", "category": "python_c_api"},
    "PyObject_HasAttr": {"lib": "python", "purpose": "check attribute exists by name object", "category": "python_c_api"},
    "PyObject_DelAttr": {"lib": "python", "purpose": "delete attribute by name object", "category": "python_c_api"},
    "PyObject_GetAttrString": {"lib": "python", "purpose": "get attribute by C string name", "category": "python_c_api"},
    "PyObject_SetAttrString": {"lib": "python", "purpose": "set attribute by C string name", "category": "python_c_api"},
    "PyObject_HasAttrString": {"lib": "python", "purpose": "check attribute by C string name", "category": "python_c_api"},
    "PyObject_DelAttrString": {"lib": "python", "purpose": "delete attribute by C string name", "category": "python_c_api"},
    "PyObject_Call": {"lib": "python", "purpose": "call callable with args and kwargs", "category": "python_c_api"},
    "PyObject_CallObject": {"lib": "python", "purpose": "call callable with args tuple", "category": "python_c_api"},
    "PyObject_CallFunction": {"lib": "python", "purpose": "call callable with format args", "category": "python_c_api"},
    "PyObject_CallFunctionObjArgs": {"lib": "python", "purpose": "call callable with variadic objs", "category": "python_c_api"},
    "PyObject_CallMethod": {"lib": "python", "purpose": "call method by name with format args", "category": "python_c_api"},
    "PyObject_CallMethodObjArgs": {"lib": "python", "purpose": "call method with variadic objs", "category": "python_c_api"},
    "PyObject_CallNoArgs": {"lib": "python", "purpose": "call callable with no arguments", "category": "python_c_api"},
    "PyObject_CallOneArg": {"lib": "python", "purpose": "call callable with single argument", "category": "python_c_api"},
    "PyObject_Str": {"lib": "python", "purpose": "str() on Python object", "category": "python_c_api"},
    "PyObject_Repr": {"lib": "python", "purpose": "repr() on Python object", "category": "python_c_api"},
    "PyObject_Bytes": {"lib": "python", "purpose": "bytes() on Python object", "category": "python_c_api"},
    "PyObject_IsTrue": {"lib": "python", "purpose": "bool() on Python object", "category": "python_c_api"},
    "PyObject_Not": {"lib": "python", "purpose": "not operator on Python object", "category": "python_c_api"},
    "PyObject_IsInstance": {"lib": "python", "purpose": "isinstance() check", "category": "python_c_api"},
    "PyObject_IsSubclass": {"lib": "python", "purpose": "issubclass() check", "category": "python_c_api"},
    "PyObject_Type": {"lib": "python", "purpose": "type() of Python object", "category": "python_c_api"},
    "PyObject_Length": {"lib": "python", "purpose": "len() of Python object", "category": "python_c_api"},
    "PyObject_Size": {"lib": "python", "purpose": "len() of Python object (alias)", "category": "python_c_api"},
    "PyObject_Hash": {"lib": "python", "purpose": "hash() of Python object", "category": "python_c_api"},
    "PyObject_RichCompare": {"lib": "python", "purpose": "rich comparison (==, <, > etc)", "category": "python_c_api"},
    "PyObject_RichCompareBool": {"lib": "python", "purpose": "rich compare returning C int", "category": "python_c_api"},
    "PyObject_GetItem": {"lib": "python", "purpose": "subscript operator obj[key]", "category": "python_c_api"},
    "PyObject_SetItem": {"lib": "python", "purpose": "subscript assignment obj[key]=val", "category": "python_c_api"},
    "PyObject_DelItem": {"lib": "python", "purpose": "subscript delete del obj[key]", "category": "python_c_api"},
    "PyObject_GetIter": {"lib": "python", "purpose": "iter() of Python object", "category": "python_c_api"},
    "PyObject_Dir": {"lib": "python", "purpose": "dir() of Python object", "category": "python_c_api"},

    # ---- Reference counting (some are macros but symbol-resolvable in Py3.9+) ----
    "Py_IncRef": {"lib": "python", "purpose": "increment reference count (function)", "category": "python_c_api"},
    "Py_DecRef": {"lib": "python", "purpose": "decrement reference count (function)", "category": "python_c_api"},
    "Py_INCREF": {"lib": "python", "purpose": "increment refcount (macro alias)", "category": "python_c_api"},
    "Py_DECREF": {"lib": "python", "purpose": "decrement refcount (macro alias)", "category": "python_c_api"},
    "Py_XINCREF": {"lib": "python", "purpose": "increment refcount (NULL-safe)", "category": "python_c_api"},
    "Py_XDECREF": {"lib": "python", "purpose": "decrement refcount (NULL-safe)", "category": "python_c_api"},
    "Py_CLEAR": {"lib": "python", "purpose": "clear ref and decref (NULL-safe)", "category": "python_c_api"},

    # ---- Type system ----
    "PyType_Ready": {"lib": "python", "purpose": "finalize type object for use", "category": "python_c_api"},
    "PyType_IsSubtype": {"lib": "python", "purpose": "check subtype relation", "category": "python_c_api"},
    "PyType_GenericAlloc": {"lib": "python", "purpose": "generic type instance allocator", "category": "python_c_api"},
    "PyType_GenericNew": {"lib": "python", "purpose": "generic type __new__", "category": "python_c_api"},
    "PyType_FromSpec": {"lib": "python", "purpose": "create heap type from spec", "category": "python_c_api"},
    "PyType_FromSpecWithBases": {"lib": "python", "purpose": "create heap type with bases", "category": "python_c_api"},
    "PyType_GetSlot": {"lib": "python", "purpose": "get type slot implementation", "category": "python_c_api"},

    # ---- Numeric types ----
    "PyLong_FromLong": {"lib": "python", "purpose": "create Python int from C long", "category": "python_c_api"},
    "PyLong_FromUnsignedLong": {"lib": "python", "purpose": "create int from C unsigned long", "category": "python_c_api"},
    "PyLong_FromLongLong": {"lib": "python", "purpose": "create int from C long long", "category": "python_c_api"},
    "PyLong_FromUnsignedLongLong": {"lib": "python", "purpose": "create int from C ull", "category": "python_c_api"},
    "PyLong_FromSsize_t": {"lib": "python", "purpose": "create int from Py_ssize_t", "category": "python_c_api"},
    "PyLong_FromSize_t": {"lib": "python", "purpose": "create int from size_t", "category": "python_c_api"},
    "PyLong_FromDouble": {"lib": "python", "purpose": "create int from C double (truncated)", "category": "python_c_api"},
    "PyLong_FromString": {"lib": "python", "purpose": "create int from C string in base", "category": "python_c_api"},
    "PyLong_AsLong": {"lib": "python", "purpose": "convert int to C long", "category": "python_c_api"},
    "PyLong_AsUnsignedLong": {"lib": "python", "purpose": "convert int to C unsigned long", "category": "python_c_api"},
    "PyLong_AsLongLong": {"lib": "python", "purpose": "convert int to C long long", "category": "python_c_api"},
    "PyLong_AsUnsignedLongLong": {"lib": "python", "purpose": "convert int to C ull", "category": "python_c_api"},
    "PyLong_AsSsize_t": {"lib": "python", "purpose": "convert int to Py_ssize_t", "category": "python_c_api"},
    "PyLong_AsDouble": {"lib": "python", "purpose": "convert int to C double", "category": "python_c_api"},
    "PyFloat_FromDouble": {"lib": "python", "purpose": "create Python float from C double", "category": "python_c_api"},
    "PyFloat_FromString": {"lib": "python", "purpose": "create float from Python string", "category": "python_c_api"},
    "PyFloat_AsDouble": {"lib": "python", "purpose": "convert Python float to C double", "category": "python_c_api"},
    "PyBool_FromLong": {"lib": "python", "purpose": "create Python bool from C long", "category": "python_c_api"},
    "PyComplex_FromDoubles": {"lib": "python", "purpose": "create Python complex from reals", "category": "python_c_api"},

    # ---- Sequence / tuple ----
    "PyTuple_New": {"lib": "python", "purpose": "create new Python tuple", "category": "python_c_api"},
    "PyTuple_Pack": {"lib": "python", "purpose": "create tuple from variadic objects", "category": "python_c_api"},
    "PyTuple_SetItem": {"lib": "python", "purpose": "set tuple item (steals ref)", "category": "python_c_api"},
    "PyTuple_GetItem": {"lib": "python", "purpose": "get tuple item (borrowed ref)", "category": "python_c_api"},
    "PyTuple_GetSlice": {"lib": "python", "purpose": "get slice of tuple", "category": "python_c_api"},
    "PyTuple_Size": {"lib": "python", "purpose": "get tuple length", "category": "python_c_api"},

    # ---- List ----
    "PyList_New": {"lib": "python", "purpose": "create new Python list", "category": "python_c_api"},
    "PyList_Append": {"lib": "python", "purpose": "append item to Python list", "category": "python_c_api"},
    "PyList_Insert": {"lib": "python", "purpose": "insert item into Python list", "category": "python_c_api"},
    "PyList_GetItem": {"lib": "python", "purpose": "get list item (borrowed ref)", "category": "python_c_api"},
    "PyList_SetItem": {"lib": "python", "purpose": "set list item (steals ref)", "category": "python_c_api"},
    "PyList_GetSlice": {"lib": "python", "purpose": "get slice of list", "category": "python_c_api"},
    "PyList_SetSlice": {"lib": "python", "purpose": "set slice of list", "category": "python_c_api"},
    "PyList_Size": {"lib": "python", "purpose": "get list length", "category": "python_c_api"},
    "PyList_Sort": {"lib": "python", "purpose": "sort Python list in place", "category": "python_c_api"},
    "PyList_Reverse": {"lib": "python", "purpose": "reverse Python list in place", "category": "python_c_api"},
    "PyList_AsTuple": {"lib": "python", "purpose": "convert list to tuple", "category": "python_c_api"},

    # ---- Dict ----
    "PyDict_New": {"lib": "python", "purpose": "create new Python dict", "category": "python_c_api"},
    "PyDict_SetItem": {"lib": "python", "purpose": "set dict item by object key", "category": "python_c_api"},
    "PyDict_SetItemString": {"lib": "python", "purpose": "set dict item by C string key", "category": "python_c_api"},
    "PyDict_GetItem": {"lib": "python", "purpose": "get dict item by object key (borrowed)", "category": "python_c_api"},
    "PyDict_GetItemString": {"lib": "python", "purpose": "get dict item by C string (borrowed)", "category": "python_c_api"},
    "PyDict_GetItemWithError": {"lib": "python", "purpose": "get dict item raising on error", "category": "python_c_api"},
    "PyDict_DelItem": {"lib": "python", "purpose": "delete dict item by object key", "category": "python_c_api"},
    "PyDict_DelItemString": {"lib": "python", "purpose": "delete dict item by C string key", "category": "python_c_api"},
    "PyDict_Contains": {"lib": "python", "purpose": "check dict contains key", "category": "python_c_api"},
    "PyDict_Clear": {"lib": "python", "purpose": "empty Python dict", "category": "python_c_api"},
    "PyDict_Copy": {"lib": "python", "purpose": "shallow copy of Python dict", "category": "python_c_api"},
    "PyDict_Merge": {"lib": "python", "purpose": "merge mapping into dict", "category": "python_c_api"},
    "PyDict_Update": {"lib": "python", "purpose": "update dict from another mapping", "category": "python_c_api"},
    "PyDict_Keys": {"lib": "python", "purpose": "get list of dict keys", "category": "python_c_api"},
    "PyDict_Values": {"lib": "python", "purpose": "get list of dict values", "category": "python_c_api"},
    "PyDict_Items": {"lib": "python", "purpose": "get list of dict items", "category": "python_c_api"},
    "PyDict_Size": {"lib": "python", "purpose": "get dict length", "category": "python_c_api"},
    "PyDict_Next": {"lib": "python", "purpose": "iterate dict items (C-level)", "category": "python_c_api"},

    # ---- Set ----
    "PySet_New": {"lib": "python", "purpose": "create new Python set", "category": "python_c_api"},
    "PyFrozenSet_New": {"lib": "python", "purpose": "create new Python frozenset", "category": "python_c_api"},
    "PySet_Add": {"lib": "python", "purpose": "add item to Python set", "category": "python_c_api"},
    "PySet_Discard": {"lib": "python", "purpose": "remove item from set if present", "category": "python_c_api"},
    "PySet_Contains": {"lib": "python", "purpose": "check set membership", "category": "python_c_api"},
    "PySet_Size": {"lib": "python", "purpose": "get set length", "category": "python_c_api"},
    "PySet_Pop": {"lib": "python", "purpose": "remove and return arbitrary element", "category": "python_c_api"},

    # ---- Bytes ----
    "PyBytes_FromString": {"lib": "python", "purpose": "create bytes from C string", "category": "python_c_api"},
    "PyBytes_FromStringAndSize": {"lib": "python", "purpose": "create bytes with size", "category": "python_c_api"},
    "PyBytes_FromFormat": {"lib": "python", "purpose": "create bytes from format string", "category": "python_c_api"},
    "PyBytes_AsString": {"lib": "python", "purpose": "get C char* from bytes", "category": "python_c_api"},
    "PyBytes_AsStringAndSize": {"lib": "python", "purpose": "get char* and size from bytes", "category": "python_c_api"},
    "PyBytes_Size": {"lib": "python", "purpose": "get bytes length", "category": "python_c_api"},
    "PyBytes_Concat": {"lib": "python", "purpose": "concatenate bytes in place", "category": "python_c_api"},
    "PyBytes_ConcatAndDel": {"lib": "python", "purpose": "concat bytes and decref right", "category": "python_c_api"},
    "PyByteArray_FromStringAndSize": {"lib": "python", "purpose": "create bytearray with size", "category": "python_c_api"},
    "PyByteArray_AsString": {"lib": "python", "purpose": "get char* from bytearray", "category": "python_c_api"},
    "PyByteArray_Size": {"lib": "python", "purpose": "get bytearray length", "category": "python_c_api"},

    # ---- Unicode / string ----
    "PyUnicode_FromString": {"lib": "python", "purpose": "create str from UTF-8 C string", "category": "python_c_api"},
    "PyUnicode_FromStringAndSize": {"lib": "python", "purpose": "create str from UTF-8 with size", "category": "python_c_api"},
    "PyUnicode_FromFormat": {"lib": "python", "purpose": "create str from format string", "category": "python_c_api"},
    "PyUnicode_FromFormatV": {"lib": "python", "purpose": "create str from format va_list", "category": "python_c_api"},
    "PyUnicode_FromWideChar": {"lib": "python", "purpose": "create str from wchar_t buffer", "category": "python_c_api"},
    "PyUnicode_AsUTF8": {"lib": "python", "purpose": "get UTF-8 C string from str", "category": "python_c_api"},
    "PyUnicode_AsUTF8AndSize": {"lib": "python", "purpose": "get UTF-8 C string with size", "category": "python_c_api"},
    "PyUnicode_AsUTF8String": {"lib": "python", "purpose": "encode str as UTF-8 bytes", "category": "python_c_api"},
    "PyUnicode_AsEncodedString": {"lib": "python", "purpose": "encode str with named encoding", "category": "python_c_api"},
    "PyUnicode_AsWideChar": {"lib": "python", "purpose": "copy str to wchar_t buffer", "category": "python_c_api"},
    "PyUnicode_AsWideCharString": {"lib": "python", "purpose": "encode str to new wchar_t buffer", "category": "python_c_api"},
    "PyUnicode_DecodeUTF8": {"lib": "python", "purpose": "decode UTF-8 bytes to str", "category": "python_c_api"},
    "PyUnicode_DecodeUTF16": {"lib": "python", "purpose": "decode UTF-16 bytes to str", "category": "python_c_api"},
    "PyUnicode_DecodeUTF32": {"lib": "python", "purpose": "decode UTF-32 bytes to str", "category": "python_c_api"},
    "PyUnicode_DecodeLatin1": {"lib": "python", "purpose": "decode Latin-1 bytes to str", "category": "python_c_api"},
    "PyUnicode_DecodeASCII": {"lib": "python", "purpose": "decode ASCII bytes to str", "category": "python_c_api"},
    "PyUnicode_GetLength": {"lib": "python", "purpose": "get str length in code points", "category": "python_c_api"},
    "PyUnicode_Compare": {"lib": "python", "purpose": "compare two str objects", "category": "python_c_api"},
    "PyUnicode_Concat": {"lib": "python", "purpose": "concatenate two str objects", "category": "python_c_api"},
    "PyUnicode_Split": {"lib": "python", "purpose": "split str into list", "category": "python_c_api"},
    "PyUnicode_Join": {"lib": "python", "purpose": "join iterable with separator str", "category": "python_c_api"},
    # Python 2 legacy PyString
    "PyString_FromString": {"lib": "python", "purpose": "create Py2 str from C string (legacy)", "category": "python_c_api"},
    "PyString_FromStringAndSize": {"lib": "python", "purpose": "create Py2 str with size (legacy)", "category": "python_c_api"},
    "PyString_AsString": {"lib": "python", "purpose": "get C char* from Py2 str (legacy)", "category": "python_c_api"},
    "PyString_Size": {"lib": "python", "purpose": "get Py2 str length (legacy)", "category": "python_c_api"},

    # ---- Error handling ----
    "PyErr_SetString": {"lib": "python", "purpose": "set exception with C string message", "category": "python_c_api"},
    "PyErr_SetObject": {"lib": "python", "purpose": "set exception with object value", "category": "python_c_api"},
    "PyErr_SetNone": {"lib": "python", "purpose": "set exception with no value", "category": "python_c_api"},
    "PyErr_Format": {"lib": "python", "purpose": "set exception with formatted message", "category": "python_c_api"},
    "PyErr_FormatV": {"lib": "python", "purpose": "set exception with format va_list", "category": "python_c_api"},
    "PyErr_Occurred": {"lib": "python", "purpose": "get pending exception type (borrowed)", "category": "python_c_api"},
    "PyErr_Clear": {"lib": "python", "purpose": "clear current exception state", "category": "python_c_api"},
    "PyErr_Print": {"lib": "python", "purpose": "print exception and traceback to stderr", "category": "python_c_api"},
    "PyErr_PrintEx": {"lib": "python", "purpose": "print exception with sys.last hook", "category": "python_c_api"},
    "PyErr_Fetch": {"lib": "python", "purpose": "fetch and clear exception triple", "category": "python_c_api"},
    "PyErr_Restore": {"lib": "python", "purpose": "restore exception triple", "category": "python_c_api"},
    "PyErr_NormalizeException": {"lib": "python", "purpose": "normalize exception triple", "category": "python_c_api"},
    "PyErr_NoMemory": {"lib": "python", "purpose": "set MemoryError exception", "category": "python_c_api"},
    "PyErr_BadArgument": {"lib": "python", "purpose": "set TypeError for bad argument", "category": "python_c_api"},
    "PyErr_BadInternalCall": {"lib": "python", "purpose": "set SystemError for bad internal call", "category": "python_c_api"},
    "PyErr_ExceptionMatches": {"lib": "python", "purpose": "check exception class match", "category": "python_c_api"},
    "PyErr_GivenExceptionMatches": {"lib": "python", "purpose": "check given exception class match", "category": "python_c_api"},
    "PyErr_WarnEx": {"lib": "python", "purpose": "issue Python warning", "category": "python_c_api"},
    "PyErr_WriteUnraisable": {"lib": "python", "purpose": "write unraisable exception to stderr", "category": "python_c_api"},
    "PyErr_SetFromErrno": {"lib": "python", "purpose": "set OSError from C errno", "category": "python_c_api"},
    "PyErr_SetFromErrnoWithFilename": {"lib": "python", "purpose": "set OSError from errno with filename", "category": "python_c_api"},
    "PyErr_CheckSignals": {"lib": "python", "purpose": "check and run pending signal handlers", "category": "python_c_api"},

    # ---- GIL / threading ----
    "PyGILState_Ensure": {"lib": "python", "purpose": "acquire GIL and return state", "category": "python_c_api"},
    "PyGILState_Release": {"lib": "python", "purpose": "release GIL and restore state", "category": "python_c_api"},
    "PyGILState_GetThisThreadState": {"lib": "python", "purpose": "get current thread state", "category": "python_c_api"},
    "PyGILState_Check": {"lib": "python", "purpose": "check if current thread holds GIL", "category": "python_c_api"},
    "PyEval_InitThreads": {"lib": "python", "purpose": "initialize thread support (legacy)", "category": "python_c_api"},
    "PyEval_AcquireLock": {"lib": "python", "purpose": "acquire global interpreter lock (legacy)", "category": "python_c_api"},
    "PyEval_ReleaseLock": {"lib": "python", "purpose": "release global interpreter lock (legacy)", "category": "python_c_api"},
    "PyEval_AcquireThread": {"lib": "python", "purpose": "acquire GIL with thread state", "category": "python_c_api"},
    "PyEval_ReleaseThread": {"lib": "python", "purpose": "release GIL with thread state", "category": "python_c_api"},
    "PyEval_SaveThread": {"lib": "python", "purpose": "release GIL (Py_BEGIN_ALLOW_THREADS)", "category": "python_c_api"},
    "PyEval_RestoreThread": {"lib": "python", "purpose": "acquire GIL (Py_END_ALLOW_THREADS)", "category": "python_c_api"},
    "PyThreadState_New": {"lib": "python", "purpose": "create new thread state", "category": "python_c_api"},
    "PyThreadState_Clear": {"lib": "python", "purpose": "clear thread state", "category": "python_c_api"},
    "PyThreadState_Delete": {"lib": "python", "purpose": "delete thread state", "category": "python_c_api"},
    "PyThreadState_Get": {"lib": "python", "purpose": "get current thread state", "category": "python_c_api"},
    "PyThreadState_Swap": {"lib": "python", "purpose": "swap active thread state", "category": "python_c_api"},
    "PyInterpreterState_New": {"lib": "python", "purpose": "create new interpreter state", "category": "python_c_api"},
    "PyInterpreterState_Clear": {"lib": "python", "purpose": "clear interpreter state", "category": "python_c_api"},
    "PyInterpreterState_Delete": {"lib": "python", "purpose": "delete interpreter state", "category": "python_c_api"},

    # ---- Callable / method / function ----
    "PyCFunction_New": {"lib": "python", "purpose": "create C function object", "category": "python_c_api"},
    "PyCFunction_NewEx": {"lib": "python", "purpose": "create C function with module", "category": "python_c_api"},
    "PyMethod_New": {"lib": "python", "purpose": "create bound method object", "category": "python_c_api"},
    "PyFunction_New": {"lib": "python", "purpose": "create Python function object", "category": "python_c_api"},
    "PyFunction_NewWithQualName": {"lib": "python", "purpose": "create function with qualname", "category": "python_c_api"},
    "PyStaticMethod_New": {"lib": "python", "purpose": "create staticmethod descriptor", "category": "python_c_api"},
    "PyClassMethod_New": {"lib": "python", "purpose": "create classmethod descriptor", "category": "python_c_api"},

    # ---- Argument parsing / value building ----
    "PyArg_Parse": {"lib": "python", "purpose": "parse single argument", "category": "python_c_api"},
    "PyArg_ParseTuple": {"lib": "python", "purpose": "parse positional args tuple", "category": "python_c_api"},
    "PyArg_ParseTupleAndKeywords": {"lib": "python", "purpose": "parse args and kwargs", "category": "python_c_api"},
    "PyArg_VaParse": {"lib": "python", "purpose": "parse args with va_list", "category": "python_c_api"},
    "PyArg_VaParseTupleAndKeywords": {"lib": "python", "purpose": "parse args+kwargs with va_list", "category": "python_c_api"},
    "PyArg_UnpackTuple": {"lib": "python", "purpose": "unpack tuple into C pointers", "category": "python_c_api"},
    "Py_BuildValue": {"lib": "python", "purpose": "build Python value from format", "category": "python_c_api"},
    "Py_VaBuildValue": {"lib": "python", "purpose": "build Python value from va_list", "category": "python_c_api"},

    # ---- Capsule (opaque pointer wrapper) ----
    "PyCapsule_New": {"lib": "python", "purpose": "create capsule for C pointer", "category": "python_c_api"},
    "PyCapsule_GetPointer": {"lib": "python", "purpose": "get C pointer from capsule", "category": "python_c_api"},
    "PyCapsule_GetName": {"lib": "python", "purpose": "get capsule name string", "category": "python_c_api"},
    "PyCapsule_GetDestructor": {"lib": "python", "purpose": "get capsule destructor callback", "category": "python_c_api"},
    "PyCapsule_GetContext": {"lib": "python", "purpose": "get capsule context pointer", "category": "python_c_api"},
    "PyCapsule_SetPointer": {"lib": "python", "purpose": "set capsule C pointer", "category": "python_c_api"},
    "PyCapsule_SetName": {"lib": "python", "purpose": "set capsule name string", "category": "python_c_api"},
    "PyCapsule_IsValid": {"lib": "python", "purpose": "check capsule validity by name", "category": "python_c_api"},

    # ---- Memory allocation (CPython allocators) ----
    "PyMem_Malloc": {"lib": "python", "purpose": "allocate memory (CPython heap)", "category": "python_c_api"},
    "PyMem_Calloc": {"lib": "python", "purpose": "allocate zero-init memory", "category": "python_c_api"},
    "PyMem_Realloc": {"lib": "python", "purpose": "reallocate memory", "category": "python_c_api"},
    "PyMem_Free": {"lib": "python", "purpose": "free memory from CPython heap", "category": "python_c_api"},
    "PyObject_Malloc": {"lib": "python", "purpose": "allocate object-sized memory", "category": "python_c_api"},
    "PyObject_Free": {"lib": "python", "purpose": "free object-sized memory", "category": "python_c_api"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — signature_db.py dogrudan SIGNATURES dict'ini import eder.
# Anahtar isimleri signature_db.py'deki dict adlariyla uyumludur:
#   "jni_signatures"           <-> _JAVA_JNI_SIGNATURES (override)
#   "python_c_api_signatures"  <-> _PYTHON_CAPI_SIGNATURES (override)
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "jni_signatures": _JNI_SIGNATURES_DATA,
    "python_c_api_signatures": _PYTHON_C_API_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
