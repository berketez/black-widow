"""Apple runtime kategori imzalari — sig_db Faz 6 dalgasi.

Bu modul macOS/iOS (Mach-O) binary analizinde kritik olan uc alt veri
kumesini barindirir:

  1. ``objc_runtime_signatures``   — Obj-C runtime API (libobjc). ARC
                                      retain/release, weak reference,
                                      message dispatch (objc_msgSend*),
                                      class/selector/method/protocol
                                      introspection, block runtime, temel
                                      Foundation logging (NSLog).
                                      Hedef kapsama: 120-180 entry.
  2. ``swift_runtime_signatures``  — Swift runtime API (libswiftCore).
                                      ARC (swift_retain/release/tryRetain),
                                      weak reference, object allocation,
                                      dynamic cast, protocol conformance,
                                      error handling, bridging, mangled
                                      Swift standart kutuphane sembolleri
                                      ($sSS... Swift.String, Array,
                                      Dictionary, Optional, Result).
                                      Hedef kapsama: 80-120 entry.
  3. ``corefoundation_signatures`` — CoreFoundation C API. CFRetain/Release,
                                      CFString, CFArray, CFDictionary,
                                      CFData, CFNumber, CFBundle, CFRunLoop.
                                      Obj-C altyapisi (toll-free bridging).
                                      Hedef kapsama: 80-120 entry.

Toplam: ~280-400 entry (tekrarsiz).

Kategori etiketleri:
  - ``objc_runtime``  — libobjc ARC/dispatch; ``_MACHO_ONLY_CATEGORY_PREFIXES``
                        listesindeki ``"objc_runtime"`` prefix'i ile Mach-O
                        platformuna filtrelenir.
  - ``swift_runtime`` — libswiftCore ARC/dispatch; YENI prefix. Filtrenin
                        aktif olmasi icin ``_MACHO_ONLY_CATEGORY_PREFIXES``
                        tuple'ina ``"swift_runtime"`` eklenir.
  - ``macos_cf``      — CoreFoundation; legacy ``_MACOS_EXT_SIGNATURES``
                        icindeki CF entry'leri ile idempotent parity.
                        ``"macos_"`` prefix'i ile zaten filtrelenir.

Kutuphane (``lib``) etiketleri ``_MACHO_ONLY_LIBS`` frozenset'inde mevcut
olmalidir: ``libobjc``, ``Foundation``, ``libswiftCore`` (YENI — aşağıda
signature_db.py'ye eklendi), ``CoreFoundation``.

Legacy ``_MACOS_EXT_SIGNATURES`` (~50 CF entry'si) SILINMEDI; bu modulun CF
alt kumesi legacy ile CAKISIR (ayni ``lib``/``purpose``/``category``) —
``dict.update`` sirasinda idempotent kalir.

Legacy ``_MACOS_SYSTEM_SIGNATURES`` (~60 ``_objc_*`` + ``_swift_*`` entry'si)
SILINMEDI. Mangled Mach-O sembolleri (leading underscore) legacy icinde
``category="runtime"`` ile kalir; bu modulun unmangled varyantlari
(``objc_msgSend`` vs ``_objc_msgSend``) AYRI anahtardir, cakisma olmaz.

Kanonik liste kaynaklari (offline hatirlama):
  - libobjc: Apple open source objc4 runtime (NSObject.mm, objc-class.mm)
  - libswiftCore: Apple swift-project swift/docs/ABI/RuntimeFunctions.rst
  - CoreFoundation: Apple CFLite open source (CF*.h public headers)
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Obj-C runtime (libobjc / Foundation) — ARC + dispatch + introspection.
# ---------------------------------------------------------------------------
_OBJC_RUNTIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Dynamic message dispatch (objc_msgSend family) ---
    "objc_msgSend": {"lib": "libobjc", "purpose": "ObjC dynamic message dispatch", "category": "objc_runtime"},
    "objc_msgSendSuper": {"lib": "libobjc", "purpose": "ObjC super message dispatch", "category": "objc_runtime"},
    "objc_msgSendSuper2": {"lib": "libobjc", "purpose": "ObjC super2 message dispatch", "category": "objc_runtime"},
    "objc_msgSend_stret": {"lib": "libobjc", "purpose": "ObjC dispatch with struct return", "category": "objc_runtime"},
    "objc_msgSendSuper_stret": {"lib": "libobjc", "purpose": "ObjC super dispatch with struct return", "category": "objc_runtime"},
    "objc_msgSendSuper2_stret": {"lib": "libobjc", "purpose": "ObjC super2 dispatch with struct return", "category": "objc_runtime"},
    "objc_msgSend_fpret": {"lib": "libobjc", "purpose": "ObjC dispatch with floating-point return", "category": "objc_runtime"},
    "objc_msgSend_fp2ret": {"lib": "libobjc", "purpose": "ObjC dispatch with complex fp return", "category": "objc_runtime"},
    "objc_msgLookup": {"lib": "libobjc", "purpose": "ObjC IMP lookup for selector", "category": "objc_runtime"},
    "objc_msgLookupSuper2": {"lib": "libobjc", "purpose": "ObjC super IMP lookup", "category": "objc_runtime"},
    "method_invoke": {"lib": "libobjc", "purpose": "invoke method via Method pointer", "category": "objc_runtime"},
    "method_invoke_stret": {"lib": "libobjc", "purpose": "invoke method with struct return", "category": "objc_runtime"},

    # --- ARC retain/release ---
    "objc_retain": {"lib": "libobjc", "purpose": "ObjC ARC retain", "category": "objc_runtime"},
    "objc_release": {"lib": "libobjc", "purpose": "ObjC ARC release", "category": "objc_runtime"},
    "objc_autorelease": {"lib": "libobjc", "purpose": "ObjC ARC autorelease", "category": "objc_runtime"},
    "objc_autoreleaseReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC autorelease return value", "category": "objc_runtime"},
    "objc_retainAutorelease": {"lib": "libobjc", "purpose": "ObjC ARC retain+autorelease", "category": "objc_runtime"},
    "objc_retainAutoreleaseReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC retain+autorelease return", "category": "objc_runtime"},
    "objc_retainAutoreleasedReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC retain autoreleased return", "category": "objc_runtime"},
    "objc_unsafeClaimAutoreleasedReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC unsafe claim autoreleased return", "category": "objc_runtime"},
    "objc_retainBlock": {"lib": "libobjc", "purpose": "ObjC ARC retain block object", "category": "objc_runtime"},
    "objc_retain_autorelease": {"lib": "libobjc", "purpose": "ObjC ARC alias retain+autorelease", "category": "objc_runtime"},
    "objc_autoreleasePoolPush": {"lib": "libobjc", "purpose": "ObjC autorelease pool push", "category": "objc_runtime"},
    "objc_autoreleasePoolPop": {"lib": "libobjc", "purpose": "ObjC autorelease pool pop", "category": "objc_runtime"},
    "objc_storeStrong": {"lib": "libobjc", "purpose": "ObjC ARC strong store", "category": "objc_runtime"},

    # --- ARC weak references ---
    "objc_initWeak": {"lib": "libobjc", "purpose": "ObjC ARC initialize weak reference", "category": "objc_runtime"},
    "objc_initWeakOrNil": {"lib": "libobjc", "purpose": "ObjC ARC init weak (may be nil)", "category": "objc_runtime"},
    "objc_storeWeak": {"lib": "libobjc", "purpose": "ObjC ARC store weak reference", "category": "objc_runtime"},
    "objc_storeWeakOrNil": {"lib": "libobjc", "purpose": "ObjC ARC store weak or nil", "category": "objc_runtime"},
    "objc_loadWeak": {"lib": "libobjc", "purpose": "ObjC ARC load weak reference (autorelease)", "category": "objc_runtime"},
    "objc_loadWeakRetained": {"lib": "libobjc", "purpose": "ObjC ARC load weak (retained)", "category": "objc_runtime"},
    "objc_copyWeak": {"lib": "libobjc", "purpose": "ObjC ARC copy weak reference", "category": "objc_runtime"},
    "objc_moveWeak": {"lib": "libobjc", "purpose": "ObjC ARC move weak reference", "category": "objc_runtime"},
    "objc_destroyWeak": {"lib": "libobjc", "purpose": "ObjC ARC destroy weak reference", "category": "objc_runtime"},

    # --- Allocation / init ---
    "objc_alloc": {"lib": "libobjc", "purpose": "ObjC +alloc fast path", "category": "objc_runtime"},
    "objc_alloc_init": {"lib": "libobjc", "purpose": "ObjC +alloc+init fast path", "category": "objc_runtime"},
    "objc_allocWithZone": {"lib": "libobjc", "purpose": "ObjC +allocWithZone: fast path", "category": "objc_runtime"},
    "objc_opt_new": {"lib": "libobjc", "purpose": "ObjC +new fast path", "category": "objc_runtime"},
    "objc_opt_self": {"lib": "libobjc", "purpose": "ObjC -self fast path", "category": "objc_runtime"},
    "objc_opt_class": {"lib": "libobjc", "purpose": "ObjC -class fast path", "category": "objc_runtime"},
    "objc_opt_isKindOfClass": {"lib": "libobjc", "purpose": "ObjC isKindOfClass fast path", "category": "objc_runtime"},
    "objc_opt_respondsToSelector": {"lib": "libobjc", "purpose": "ObjC respondsToSelector fast path", "category": "objc_runtime"},
    "_objc_rootAlloc": {"lib": "libobjc", "purpose": "ObjC NSObject root alloc impl", "category": "objc_runtime"},
    "_objc_rootAllocWithZone": {"lib": "libobjc", "purpose": "ObjC NSObject root allocWithZone impl", "category": "objc_runtime"},
    "_objc_rootInit": {"lib": "libobjc", "purpose": "ObjC NSObject root init impl", "category": "objc_runtime"},
    "_objc_rootDealloc": {"lib": "libobjc", "purpose": "ObjC NSObject root dealloc impl", "category": "objc_runtime"},

    # --- Class lookup / registration ---
    "objc_getClass": {"lib": "libobjc", "purpose": "ObjC class lookup by name (abort if missing)", "category": "objc_runtime"},
    "objc_getRequiredClass": {"lib": "libobjc", "purpose": "ObjC required class lookup", "category": "objc_runtime"},
    "objc_getMetaClass": {"lib": "libobjc", "purpose": "ObjC metaclass lookup", "category": "objc_runtime"},
    "objc_lookUpClass": {"lib": "libobjc", "purpose": "ObjC optional class lookup (nil if missing)", "category": "objc_runtime"},
    "objc_getClassList": {"lib": "libobjc", "purpose": "enumerate all registered classes", "category": "objc_runtime"},
    "objc_copyClassList": {"lib": "libobjc", "purpose": "copy list of all registered classes", "category": "objc_runtime"},
    "objc_allocateClassPair": {"lib": "libobjc", "purpose": "allocate dynamic class pair", "category": "objc_runtime"},
    "objc_registerClassPair": {"lib": "libobjc", "purpose": "register dynamic class pair", "category": "objc_runtime"},
    "objc_disposeClassPair": {"lib": "libobjc", "purpose": "dispose unregistered dynamic class", "category": "objc_runtime"},
    "objc_duplicateClass": {"lib": "libobjc", "purpose": "duplicate class (used by KVO)", "category": "objc_runtime"},

    # --- Selector / SEL ---
    "sel_registerName": {"lib": "libobjc", "purpose": "register selector by name", "category": "objc_runtime"},
    "sel_getName": {"lib": "libobjc", "purpose": "get selector name string", "category": "objc_runtime"},
    "sel_getUid": {"lib": "libobjc", "purpose": "get UID for selector name (legacy)", "category": "objc_runtime"},
    "sel_isEqual": {"lib": "libobjc", "purpose": "compare selectors", "category": "objc_runtime"},

    # --- Class introspection ---
    "class_getName": {"lib": "libobjc", "purpose": "get class name", "category": "objc_runtime"},
    "class_getSuperclass": {"lib": "libobjc", "purpose": "get superclass", "category": "objc_runtime"},
    "class_isMetaClass": {"lib": "libobjc", "purpose": "check if class is metaclass", "category": "objc_runtime"},
    "class_getInstanceSize": {"lib": "libobjc", "purpose": "get instance size in bytes", "category": "objc_runtime"},
    "class_getInstanceVariable": {"lib": "libobjc", "purpose": "get instance variable by name", "category": "objc_runtime"},
    "class_getClassVariable": {"lib": "libobjc", "purpose": "get class variable by name", "category": "objc_runtime"},
    "class_copyIvarList": {"lib": "libobjc", "purpose": "copy list of instance variables", "category": "objc_runtime"},
    "class_getInstanceMethod": {"lib": "libobjc", "purpose": "get instance method by selector", "category": "objc_runtime"},
    "class_getClassMethod": {"lib": "libobjc", "purpose": "get class method by selector", "category": "objc_runtime"},
    "class_getMethodImplementation": {"lib": "libobjc", "purpose": "get IMP for selector", "category": "objc_runtime"},
    "class_getMethodImplementation_stret": {"lib": "libobjc", "purpose": "get IMP for struct-return selector", "category": "objc_runtime"},
    "class_respondsToSelector": {"lib": "libobjc", "purpose": "check if class responds to selector", "category": "objc_runtime"},
    "class_copyMethodList": {"lib": "libobjc", "purpose": "copy list of class methods", "category": "objc_runtime"},
    "class_conformsToProtocol": {"lib": "libobjc", "purpose": "check class protocol conformance", "category": "objc_runtime"},
    "class_copyProtocolList": {"lib": "libobjc", "purpose": "copy list of adopted protocols", "category": "objc_runtime"},
    "class_getProperty": {"lib": "libobjc", "purpose": "get property by name", "category": "objc_runtime"},
    "class_copyPropertyList": {"lib": "libobjc", "purpose": "copy list of class properties", "category": "objc_runtime"},
    "class_getIvarLayout": {"lib": "libobjc", "purpose": "get ivar strong layout", "category": "objc_runtime"},
    "class_getWeakIvarLayout": {"lib": "libobjc", "purpose": "get ivar weak layout", "category": "objc_runtime"},
    "class_setIvarLayout": {"lib": "libobjc", "purpose": "set ivar strong layout", "category": "objc_runtime"},
    "class_setWeakIvarLayout": {"lib": "libobjc", "purpose": "set ivar weak layout", "category": "objc_runtime"},
    "class_addMethod": {"lib": "libobjc", "purpose": "dynamically add method", "category": "objc_runtime"},
    "class_replaceMethod": {"lib": "libobjc", "purpose": "replace method (swizzle)", "category": "objc_runtime"},
    "class_addIvar": {"lib": "libobjc", "purpose": "dynamically add instance variable", "category": "objc_runtime"},
    "class_addProtocol": {"lib": "libobjc", "purpose": "add protocol conformance to class", "category": "objc_runtime"},
    "class_addProperty": {"lib": "libobjc", "purpose": "dynamically add property", "category": "objc_runtime"},
    "class_replaceProperty": {"lib": "libobjc", "purpose": "replace property definition", "category": "objc_runtime"},
    "class_setSuperclass": {"lib": "libobjc", "purpose": "change superclass (deprecated)", "category": "objc_runtime"},
    "class_getVersion": {"lib": "libobjc", "purpose": "get class version number", "category": "objc_runtime"},
    "class_setVersion": {"lib": "libobjc", "purpose": "set class version number", "category": "objc_runtime"},
    "class_createInstance": {"lib": "libobjc", "purpose": "create instance from class", "category": "objc_runtime"},

    # --- Object introspection ---
    "object_getClass": {"lib": "libobjc", "purpose": "get class of object", "category": "objc_runtime"},
    "object_setClass": {"lib": "libobjc", "purpose": "set class of object", "category": "objc_runtime"},
    "object_getClassName": {"lib": "libobjc", "purpose": "get class name of object", "category": "objc_runtime"},
    "object_isClass": {"lib": "libobjc", "purpose": "check if object is a class", "category": "objc_runtime"},
    "object_getIndexedIvars": {"lib": "libobjc", "purpose": "get pointer to extra bytes", "category": "objc_runtime"},
    "object_getIvar": {"lib": "libobjc", "purpose": "read ivar value", "category": "objc_runtime"},
    "object_setIvar": {"lib": "libobjc", "purpose": "write ivar value", "category": "objc_runtime"},
    "object_setIvarWithStrongDefault": {"lib": "libobjc", "purpose": "write ivar (strong default)", "category": "objc_runtime"},
    "object_copy": {"lib": "libobjc", "purpose": "copy object instance", "category": "objc_runtime"},
    "object_dispose": {"lib": "libobjc", "purpose": "dispose object instance", "category": "objc_runtime"},

    # --- Method introspection / swizzle ---
    "method_getName": {"lib": "libobjc", "purpose": "get method selector", "category": "objc_runtime"},
    "method_getImplementation": {"lib": "libobjc", "purpose": "get method IMP", "category": "objc_runtime"},
    "method_setImplementation": {"lib": "libobjc", "purpose": "set method IMP", "category": "objc_runtime"},
    "method_getTypeEncoding": {"lib": "libobjc", "purpose": "get method type encoding string", "category": "objc_runtime"},
    "method_getNumberOfArguments": {"lib": "libobjc", "purpose": "get method argument count", "category": "objc_runtime"},
    "method_copyReturnType": {"lib": "libobjc", "purpose": "copy method return type encoding", "category": "objc_runtime"},
    "method_copyArgumentType": {"lib": "libobjc", "purpose": "copy method argument type encoding", "category": "objc_runtime"},
    "method_getReturnType": {"lib": "libobjc", "purpose": "get method return type encoding", "category": "objc_runtime"},
    "method_getArgumentType": {"lib": "libobjc", "purpose": "get method argument type encoding", "category": "objc_runtime"},
    "method_exchangeImplementations": {"lib": "libobjc", "purpose": "exchange method IMPs (swizzle)", "category": "objc_runtime"},

    # --- Ivar introspection ---
    "ivar_getName": {"lib": "libobjc", "purpose": "get ivar name", "category": "objc_runtime"},
    "ivar_getTypeEncoding": {"lib": "libobjc", "purpose": "get ivar type encoding", "category": "objc_runtime"},
    "ivar_getOffset": {"lib": "libobjc", "purpose": "get ivar byte offset", "category": "objc_runtime"},

    # --- Protocol introspection ---
    "objc_getProtocol": {"lib": "libobjc", "purpose": "lookup protocol by name", "category": "objc_runtime"},
    "objc_copyProtocolList": {"lib": "libobjc", "purpose": "copy list of all protocols", "category": "objc_runtime"},
    "objc_allocateProtocol": {"lib": "libobjc", "purpose": "allocate new protocol", "category": "objc_runtime"},
    "objc_registerProtocol": {"lib": "libobjc", "purpose": "register protocol", "category": "objc_runtime"},
    "protocol_getName": {"lib": "libobjc", "purpose": "get protocol name", "category": "objc_runtime"},
    "protocol_isEqual": {"lib": "libobjc", "purpose": "compare protocols", "category": "objc_runtime"},
    "protocol_conformsToProtocol": {"lib": "libobjc", "purpose": "check protocol conformance chain", "category": "objc_runtime"},
    "protocol_copyMethodDescriptionList": {"lib": "libobjc", "purpose": "copy protocol method descriptions", "category": "objc_runtime"},
    "protocol_getMethodDescription": {"lib": "libobjc", "purpose": "get protocol method description", "category": "objc_runtime"},
    "protocol_copyPropertyList": {"lib": "libobjc", "purpose": "copy protocol properties", "category": "objc_runtime"},
    "protocol_getProperty": {"lib": "libobjc", "purpose": "get protocol property", "category": "objc_runtime"},
    "protocol_copyProtocolList": {"lib": "libobjc", "purpose": "copy list of inherited protocols", "category": "objc_runtime"},
    "protocol_addProtocol": {"lib": "libobjc", "purpose": "add inherited protocol", "category": "objc_runtime"},
    "protocol_addMethodDescription": {"lib": "libobjc", "purpose": "add method description to protocol", "category": "objc_runtime"},
    "protocol_addProperty": {"lib": "libobjc", "purpose": "add property to protocol", "category": "objc_runtime"},

    # --- Property introspection ---
    "property_getName": {"lib": "libobjc", "purpose": "get property name", "category": "objc_runtime"},
    "property_getAttributes": {"lib": "libobjc", "purpose": "get property attribute string", "category": "objc_runtime"},
    "property_copyAttributeList": {"lib": "libobjc", "purpose": "copy property attributes", "category": "objc_runtime"},
    "property_copyAttributeValue": {"lib": "libobjc", "purpose": "copy named attribute value", "category": "objc_runtime"},

    # --- Associated objects ---
    "objc_setAssociatedObject": {"lib": "libobjc", "purpose": "set associated object on instance", "category": "objc_runtime"},
    "objc_getAssociatedObject": {"lib": "libobjc", "purpose": "get associated object from instance", "category": "objc_runtime"},
    "objc_removeAssociatedObjects": {"lib": "libobjc", "purpose": "remove all associated objects", "category": "objc_runtime"},

    # --- Exception / sync ---
    "objc_exception_throw": {"lib": "libobjc", "purpose": "throw ObjC exception", "category": "objc_runtime"},
    "objc_exception_rethrow": {"lib": "libobjc", "purpose": "rethrow caught exception", "category": "objc_runtime"},
    "objc_begin_catch": {"lib": "libobjc", "purpose": "begin catch block (Itanium ABI)", "category": "objc_runtime"},
    "objc_end_catch": {"lib": "libobjc", "purpose": "end catch block (Itanium ABI)", "category": "objc_runtime"},
    "objc_exception_try_enter": {"lib": "libobjc", "purpose": "enter @try scope (legacy)", "category": "objc_runtime"},
    "objc_exception_try_exit": {"lib": "libobjc", "purpose": "exit @try scope (legacy)", "category": "objc_runtime"},
    "objc_exception_extract": {"lib": "libobjc", "purpose": "extract exception (legacy)", "category": "objc_runtime"},
    "objc_exception_match": {"lib": "libobjc", "purpose": "match exception class (legacy)", "category": "objc_runtime"},
    "objc_sync_enter": {"lib": "libobjc", "purpose": "@synchronized enter (recursive mutex)", "category": "objc_runtime"},
    "objc_sync_exit": {"lib": "libobjc", "purpose": "@synchronized exit", "category": "objc_runtime"},
    "objc_terminate": {"lib": "libobjc", "purpose": "terminate from uncaught exception", "category": "objc_runtime"},

    # --- Enumeration / fast enumeration ---
    "objc_enumerationMutation": {"lib": "libobjc", "purpose": "enumeration mutation guard", "category": "objc_runtime"},
    "objc_setEnumerationMutationHandler": {"lib": "libobjc", "purpose": "install mutation handler", "category": "objc_runtime"},

    # --- Block runtime ---
    "_Block_copy": {"lib": "libobjc", "purpose": "copy block (move to heap)", "category": "objc_runtime"},
    "_Block_release": {"lib": "libobjc", "purpose": "release block reference", "category": "objc_runtime"},
    "Block_copy": {"lib": "libobjc", "purpose": "public macro for _Block_copy", "category": "objc_runtime"},
    "Block_release": {"lib": "libobjc", "purpose": "public macro for _Block_release", "category": "objc_runtime"},
    "_Block_object_assign": {"lib": "libobjc", "purpose": "block byref assign helper", "category": "objc_runtime"},
    "_Block_object_dispose": {"lib": "libobjc", "purpose": "block byref dispose helper", "category": "objc_runtime"},
    "_Block_use_RR": {"lib": "libobjc", "purpose": "install block runtime retain/release", "category": "objc_runtime"},
    "_NSConcreteGlobalBlock": {"lib": "libobjc", "purpose": "ISA for global (compile-time) blocks", "category": "objc_runtime"},
    "_NSConcreteStackBlock": {"lib": "libobjc", "purpose": "ISA for stack blocks", "category": "objc_runtime"},
    "_NSConcreteMallocBlock": {"lib": "libobjc", "purpose": "ISA for heap blocks", "category": "objc_runtime"},
    "_NSConcreteAutoBlock": {"lib": "libobjc", "purpose": "ISA for GC auto blocks (legacy)", "category": "objc_runtime"},
    "_NSConcreteFinalizingBlock": {"lib": "libobjc", "purpose": "ISA for GC finalizing blocks (legacy)", "category": "objc_runtime"},
    "_NSConcreteWeakBlockVariable": {"lib": "libobjc", "purpose": "ISA for weak block byref", "category": "objc_runtime"},

    # --- Foundation logging / introspection (NS*) ---
    "NSLog": {"lib": "Foundation", "purpose": "ObjC console logging", "category": "objc_runtime"},
    "NSLogv": {"lib": "Foundation", "purpose": "ObjC console logging (va_list)", "category": "objc_runtime"},
    "NSClassFromString": {"lib": "Foundation", "purpose": "lookup class by NSString name", "category": "objc_runtime"},
    "NSStringFromClass": {"lib": "Foundation", "purpose": "get NSString name of class", "category": "objc_runtime"},
    "NSStringFromSelector": {"lib": "Foundation", "purpose": "get NSString from selector", "category": "objc_runtime"},
    "NSSelectorFromString": {"lib": "Foundation", "purpose": "lookup selector by NSString", "category": "objc_runtime"},
    "NSStringFromProtocol": {"lib": "Foundation", "purpose": "get NSString name of protocol", "category": "objc_runtime"},
    "NSProtocolFromString": {"lib": "Foundation", "purpose": "lookup protocol by NSString", "category": "objc_runtime"},
    "NSGetSizeAndAlignment": {"lib": "Foundation", "purpose": "parse ObjC type encoding", "category": "objc_runtime"},
    "NSStringFromRange": {"lib": "Foundation", "purpose": "format NSRange as string", "category": "objc_runtime"},
    "NSRangeFromString": {"lib": "Foundation", "purpose": "parse NSRange from string", "category": "objc_runtime"},

    # --- Runtime misc / load ---
    "objc_loadClassref": {"lib": "libobjc", "purpose": "load classref indirection", "category": "objc_runtime"},
    "objc_opt_class": {"lib": "libobjc", "purpose": "optimized class getter", "category": "objc_runtime"},
    "objc_copyImageNames": {"lib": "libobjc", "purpose": "copy names of loaded Mach-O images", "category": "objc_runtime"},
    "objc_copyClassNamesForImage": {"lib": "libobjc", "purpose": "copy class names in Mach-O image", "category": "objc_runtime"},
    "objc_setForwardHandler": {"lib": "libobjc", "purpose": "install forward invocation handler", "category": "objc_runtime"},
    "objc_setHook_getClass": {"lib": "libobjc", "purpose": "install class lookup hook", "category": "objc_runtime"},
    "objc_setUncaughtExceptionHandler": {"lib": "libobjc", "purpose": "install uncaught exception handler", "category": "objc_runtime"},
    "objc_getUncaughtExceptionHandler": {"lib": "libobjc", "purpose": "get uncaught exception handler", "category": "objc_runtime"},
    "_objc_msgForward": {"lib": "libobjc", "purpose": "forwarding trampoline (default IMP)", "category": "objc_runtime"},
    "_objc_msgForward_stret": {"lib": "libobjc", "purpose": "forwarding trampoline (struct return)", "category": "objc_runtime"},
    "objc_readClassPair": {"lib": "libobjc", "purpose": "register class pair from image", "category": "objc_runtime"},
    "objc_destructInstance": {"lib": "libobjc", "purpose": "destruct instance without freeing", "category": "objc_runtime"},
    "objc_constructInstance": {"lib": "libobjc", "purpose": "construct instance from bytes", "category": "objc_runtime"},
}


# ---------------------------------------------------------------------------
# Swift runtime (libswiftCore) — ARC + dispatch + metadata + stdlib demangled.
# ---------------------------------------------------------------------------
_SWIFT_RUNTIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- ARC retain/release (native Swift objects) ---
    "swift_retain": {"lib": "libswiftCore", "purpose": "Swift ARC retain", "category": "swift_runtime"},
    "swift_retain_n": {"lib": "libswiftCore", "purpose": "Swift ARC retain by N", "category": "swift_runtime"},
    "swift_release": {"lib": "libswiftCore", "purpose": "Swift ARC release", "category": "swift_runtime"},
    "swift_release_n": {"lib": "libswiftCore", "purpose": "Swift ARC release by N", "category": "swift_runtime"},
    "swift_tryRetain": {"lib": "libswiftCore", "purpose": "Swift ARC try retain (may fail)", "category": "swift_runtime"},
    "swift_nonatomic_retain": {"lib": "libswiftCore", "purpose": "Swift ARC non-atomic retain", "category": "swift_runtime"},
    "swift_nonatomic_retain_n": {"lib": "libswiftCore", "purpose": "Swift ARC non-atomic retain by N", "category": "swift_runtime"},
    "swift_nonatomic_release": {"lib": "libswiftCore", "purpose": "Swift ARC non-atomic release", "category": "swift_runtime"},
    "swift_nonatomic_release_n": {"lib": "libswiftCore", "purpose": "Swift ARC non-atomic release by N", "category": "swift_runtime"},
    "swift_isUniquelyReferenced_native": {"lib": "libswiftCore", "purpose": "Swift COW uniqueness check", "category": "swift_runtime"},
    "swift_isUniquelyReferenced_nonNull_native": {"lib": "libswiftCore", "purpose": "Swift COW uniqueness (non-null)", "category": "swift_runtime"},
    "swift_isUniquelyReferencedOrPinned_native": {"lib": "libswiftCore", "purpose": "Swift COW uniqueness or pinned", "category": "swift_runtime"},
    "swift_retainCount": {"lib": "libswiftCore", "purpose": "Swift retain count (debug)", "category": "swift_runtime"},

    # --- Weak references ---
    "swift_weakInit": {"lib": "libswiftCore", "purpose": "Swift weak reference init", "category": "swift_runtime"},
    "swift_weakAssign": {"lib": "libswiftCore", "purpose": "Swift weak reference assign", "category": "swift_runtime"},
    "swift_weakLoadStrong": {"lib": "libswiftCore", "purpose": "Swift weak -> strong load", "category": "swift_runtime"},
    "swift_weakTakeStrong": {"lib": "libswiftCore", "purpose": "Swift weak -> strong take", "category": "swift_runtime"},
    "swift_weakDestroy": {"lib": "libswiftCore", "purpose": "Swift weak reference destroy", "category": "swift_runtime"},
    "swift_weakCopyInit": {"lib": "libswiftCore", "purpose": "Swift weak copy init", "category": "swift_runtime"},
    "swift_weakCopyAssign": {"lib": "libswiftCore", "purpose": "Swift weak copy assign", "category": "swift_runtime"},
    "swift_weakTakeInit": {"lib": "libswiftCore", "purpose": "Swift weak take init", "category": "swift_runtime"},
    "swift_weakTakeAssign": {"lib": "libswiftCore", "purpose": "Swift weak take assign", "category": "swift_runtime"},

    # --- Unknown object (Obj-C bridging aware) ---
    "swift_unknownObjectRetain": {"lib": "libswiftCore", "purpose": "Swift unknown object retain (bridged)", "category": "swift_runtime"},
    "swift_unknownObjectRelease": {"lib": "libswiftCore", "purpose": "Swift unknown object release (bridged)", "category": "swift_runtime"},
    "swift_unknownObjectRetain_n": {"lib": "libswiftCore", "purpose": "Swift unknown object retain by N", "category": "swift_runtime"},
    "swift_unknownObjectRelease_n": {"lib": "libswiftCore", "purpose": "Swift unknown object release by N", "category": "swift_runtime"},
    "swift_unknownObjectWeakInit": {"lib": "libswiftCore", "purpose": "Swift unknown weak init (bridged)", "category": "swift_runtime"},
    "swift_unknownObjectWeakAssign": {"lib": "libswiftCore", "purpose": "Swift unknown weak assign (bridged)", "category": "swift_runtime"},
    "swift_unknownObjectWeakLoadStrong": {"lib": "libswiftCore", "purpose": "Swift unknown weak -> strong load", "category": "swift_runtime"},
    "swift_unknownObjectWeakTakeStrong": {"lib": "libswiftCore", "purpose": "Swift unknown weak -> strong take", "category": "swift_runtime"},
    "swift_unknownObjectWeakDestroy": {"lib": "libswiftCore", "purpose": "Swift unknown weak destroy", "category": "swift_runtime"},
    "swift_unknownObjectWeakCopyInit": {"lib": "libswiftCore", "purpose": "Swift unknown weak copy init", "category": "swift_runtime"},
    "swift_unknownObjectWeakCopyAssign": {"lib": "libswiftCore", "purpose": "Swift unknown weak copy assign", "category": "swift_runtime"},
    "swift_unknownObjectWeakTakeInit": {"lib": "libswiftCore", "purpose": "Swift unknown weak take init", "category": "swift_runtime"},
    "swift_unknownObjectWeakTakeAssign": {"lib": "libswiftCore", "purpose": "Swift unknown weak take assign", "category": "swift_runtime"},

    # --- Bridge object (tagged bridged NS-types) ---
    "swift_bridgeObjectRetain": {"lib": "libswiftCore", "purpose": "Swift bridge object retain (tagged)", "category": "swift_runtime"},
    "swift_bridgeObjectRetain_n": {"lib": "libswiftCore", "purpose": "Swift bridge object retain by N", "category": "swift_runtime"},
    "swift_bridgeObjectRelease": {"lib": "libswiftCore", "purpose": "Swift bridge object release (tagged)", "category": "swift_runtime"},
    "swift_bridgeObjectRelease_n": {"lib": "libswiftCore", "purpose": "Swift bridge object release by N", "category": "swift_runtime"},

    # --- Object allocation / deallocation ---
    "swift_allocObject": {"lib": "libswiftCore", "purpose": "Swift allocate heap object", "category": "swift_runtime"},
    "swift_initStackObject": {"lib": "libswiftCore", "purpose": "Swift init stack-promoted object", "category": "swift_runtime"},
    "swift_initStaticObject": {"lib": "libswiftCore", "purpose": "Swift init static object", "category": "swift_runtime"},
    "swift_deallocObject": {"lib": "libswiftCore", "purpose": "Swift deallocate object", "category": "swift_runtime"},
    "swift_deallocClassInstance": {"lib": "libswiftCore", "purpose": "Swift deallocate class instance", "category": "swift_runtime"},
    "swift_deallocPartialClassInstance": {"lib": "libswiftCore", "purpose": "Swift deallocate partial (ctor failure)", "category": "swift_runtime"},
    "swift_deallocUninitializedObject": {"lib": "libswiftCore", "purpose": "Swift deallocate uninitialized object", "category": "swift_runtime"},
    "swift_allocBox": {"lib": "libswiftCore", "purpose": "Swift allocate boxed value", "category": "swift_runtime"},
    "swift_deallocBox": {"lib": "libswiftCore", "purpose": "Swift deallocate boxed value", "category": "swift_runtime"},
    "swift_projectBox": {"lib": "libswiftCore", "purpose": "Swift project box to value pointer", "category": "swift_runtime"},
    "swift_makeBoxUnique": {"lib": "libswiftCore", "purpose": "Swift make box uniquely referenced", "category": "swift_runtime"},

    # --- Dynamic cast ---
    "swift_dynamicCast": {"lib": "libswiftCore", "purpose": "Swift dynamic cast (as?)", "category": "swift_runtime"},
    "swift_dynamicCastClass": {"lib": "libswiftCore", "purpose": "Swift dynamic class cast", "category": "swift_runtime"},
    "swift_dynamicCastClassUnconditional": {"lib": "libswiftCore", "purpose": "Swift forced class cast (as!)", "category": "swift_runtime"},
    "swift_dynamicCastObjCClass": {"lib": "libswiftCore", "purpose": "Swift -> Obj-C class cast", "category": "swift_runtime"},
    "swift_dynamicCastObjCClassUnconditional": {"lib": "libswiftCore", "purpose": "Swift -> Obj-C forced class cast", "category": "swift_runtime"},
    "swift_dynamicCastForeignClass": {"lib": "libswiftCore", "purpose": "Swift foreign class cast", "category": "swift_runtime"},
    "swift_dynamicCastForeignClassUnconditional": {"lib": "libswiftCore", "purpose": "Swift foreign class forced cast", "category": "swift_runtime"},
    "swift_dynamicCastUnknownClass": {"lib": "libswiftCore", "purpose": "Swift unknown class cast", "category": "swift_runtime"},
    "swift_dynamicCastUnknownClassUnconditional": {"lib": "libswiftCore", "purpose": "Swift unknown class forced cast", "category": "swift_runtime"},
    "swift_dynamicCastMetatype": {"lib": "libswiftCore", "purpose": "Swift metatype cast", "category": "swift_runtime"},
    "swift_dynamicCastMetatypeUnconditional": {"lib": "libswiftCore", "purpose": "Swift metatype forced cast", "category": "swift_runtime"},
    "swift_dynamicCastMetatypeToObjectConditional": {"lib": "libswiftCore", "purpose": "metatype -> object conditional", "category": "swift_runtime"},
    "swift_dynamicCastMetatypeToObjectUnconditional": {"lib": "libswiftCore", "purpose": "metatype -> object forced", "category": "swift_runtime"},

    # --- Type metadata ---
    "swift_getObjectType": {"lib": "libswiftCore", "purpose": "Swift get runtime type metadata", "category": "swift_runtime"},
    "swift_getTypeName": {"lib": "libswiftCore", "purpose": "Swift get type name (demangled)", "category": "swift_runtime"},
    "swift_getTypeByMangledNameInContext": {"lib": "libswiftCore", "purpose": "Swift lookup type by mangled name", "category": "swift_runtime"},
    "swift_getTypeByMangledNameInContextInMetadataState": {"lib": "libswiftCore", "purpose": "Swift lookup type with metadata state", "category": "swift_runtime"},
    "swift_getTypeContextDescriptor": {"lib": "libswiftCore", "purpose": "Swift get type descriptor", "category": "swift_runtime"},
    "swift_getGenericMetadata": {"lib": "libswiftCore", "purpose": "Swift instantiate generic metadata", "category": "swift_runtime"},
    "swift_allocateGenericClassMetadata": {"lib": "libswiftCore", "purpose": "Swift allocate generic class metadata", "category": "swift_runtime"},
    "swift_allocateGenericValueMetadata": {"lib": "libswiftCore", "purpose": "Swift allocate generic value metadata", "category": "swift_runtime"},
    "swift_getTupleTypeMetadata": {"lib": "libswiftCore", "purpose": "Swift get tuple metadata", "category": "swift_runtime"},
    "swift_getFunctionTypeMetadata": {"lib": "libswiftCore", "purpose": "Swift get function type metadata", "category": "swift_runtime"},
    "swift_getExistentialTypeMetadata": {"lib": "libswiftCore", "purpose": "Swift get existential metadata", "category": "swift_runtime"},
    "swift_getMetatypeMetadata": {"lib": "libswiftCore", "purpose": "Swift get metatype metadata", "category": "swift_runtime"},
    "swift_getObjCClassMetadata": {"lib": "libswiftCore", "purpose": "Swift get Obj-C class as metadata", "category": "swift_runtime"},
    "swift_getExistentialMetatypeMetadata": {"lib": "libswiftCore", "purpose": "Swift existential metatype metadata", "category": "swift_runtime"},
    "swift_getForeignTypeMetadata": {"lib": "libswiftCore", "purpose": "Swift get foreign type metadata", "category": "swift_runtime"},

    # --- Protocol conformance / witness tables ---
    "swift_conformsToProtocol": {"lib": "libswiftCore", "purpose": "Swift protocol conformance check", "category": "swift_runtime"},
    "swift_conformsToProtocols": {"lib": "libswiftCore", "purpose": "Swift multi-protocol conformance", "category": "swift_runtime"},
    "swift_getWitnessTable": {"lib": "libswiftCore", "purpose": "Swift witness table lookup", "category": "swift_runtime"},
    "swift_getAssociatedTypeWitness": {"lib": "libswiftCore", "purpose": "Swift associated type witness", "category": "swift_runtime"},
    "swift_getAssociatedConformanceWitness": {"lib": "libswiftCore", "purpose": "Swift associated conformance witness", "category": "swift_runtime"},

    # --- Error handling ---
    "swift_allocError": {"lib": "libswiftCore", "purpose": "Swift allocate Error existential box", "category": "swift_runtime"},
    "swift_deallocError": {"lib": "libswiftCore", "purpose": "Swift deallocate Error box", "category": "swift_runtime"},
    "swift_errorRetain": {"lib": "libswiftCore", "purpose": "Swift Error retain", "category": "swift_runtime"},
    "swift_errorRelease": {"lib": "libswiftCore", "purpose": "Swift Error release", "category": "swift_runtime"},
    "swift_willThrow": {"lib": "libswiftCore", "purpose": "Swift will-throw hook (debug)", "category": "swift_runtime"},
    "swift_unexpectedError": {"lib": "libswiftCore", "purpose": "Swift unexpected error trap", "category": "swift_runtime"},

    # --- Once / synchronization / misc ---
    "swift_once": {"lib": "libswiftCore", "purpose": "Swift one-time initialization", "category": "swift_runtime"},
    "swift_beginAccess": {"lib": "libswiftCore", "purpose": "Swift exclusivity access begin", "category": "swift_runtime"},
    "swift_endAccess": {"lib": "libswiftCore", "purpose": "Swift exclusivity access end", "category": "swift_runtime"},

    # --- Value witness / opaque ops ---
    "swift_copyPOD": {"lib": "libswiftCore", "purpose": "Swift copy plain-old-data value", "category": "swift_runtime"},
    "swift_initEnumMetadataSingleCase": {"lib": "libswiftCore", "purpose": "Swift init single-case enum metadata", "category": "swift_runtime"},
    "swift_initEnumMetadataMultiPayload": {"lib": "libswiftCore", "purpose": "Swift init multi-payload enum metadata", "category": "swift_runtime"},
    "swift_getEnumCaseMultiPayload": {"lib": "libswiftCore", "purpose": "Swift get enum case index", "category": "swift_runtime"},
    "swift_storeEnumTagMultiPayload": {"lib": "libswiftCore", "purpose": "Swift store enum tag (multi-payload)", "category": "swift_runtime"},

    # --- Swift <-> Obj-C bridging ---
    "swift_bridgeNonVerbatimFromObjectiveC": {"lib": "libswiftCore", "purpose": "bridge from Obj-C to Swift value", "category": "swift_runtime"},
    "swift_bridgeNonVerbatimToObjectiveC": {"lib": "libswiftCore", "purpose": "bridge from Swift value to Obj-C", "category": "swift_runtime"},
    "swift_unboxFromSwiftValueWithType": {"lib": "libswiftCore", "purpose": "unbox Swift value from _SwiftValue", "category": "swift_runtime"},

    # --- Swift standard library mangled symbols ($sSS..., $ss..., $sSa...) ---
    # Canonical prefix reference:
    #   $sSS  -> Swift.String
    #   $sSa  -> Swift.Array
    #   $sSD  -> Swift.Dictionary
    #   $sSS5index..   -> String.index(...)
    # The symbols listed below are high-frequency runtime helpers/initializers
    # emitted by the Swift compiler for the stdlib ABI-stable interface.
    "$sSSN": {"lib": "libswiftCore", "purpose": "Swift.String type metadata", "category": "swift_runtime"},
    "$sSSMa": {"lib": "libswiftCore", "purpose": "Swift.String metadata access function", "category": "swift_runtime"},
    "$sSS7cStringSSSPys4Int8VG_tcfC": {"lib": "libswiftCore", "purpose": "String.init(cString:) from Int8 ptr", "category": "swift_runtime"},
    "$sSS8UTF8ViewV": {"lib": "libswiftCore", "purpose": "Swift.String.UTF8View", "category": "swift_runtime"},
    "$sSS9UnicodeV8ScalarVN": {"lib": "libswiftCore", "purpose": "Swift.Unicode.Scalar metadata", "category": "swift_runtime"},
    "$sSaMa": {"lib": "libswiftCore", "purpose": "Swift.Array metadata access function", "category": "swift_runtime"},
    "$sSayxGMa": {"lib": "libswiftCore", "purpose": "Swift.Array generic metadata access", "category": "swift_runtime"},
    "$sSa9_getCount33_8": {"lib": "libswiftCore", "purpose": "Swift.Array internal count getter", "category": "swift_runtime"},
    "$sSa5countSivg": {"lib": "libswiftCore", "purpose": "Swift.Array.count getter", "category": "swift_runtime"},
    "$sSa8capacitySivg": {"lib": "libswiftCore", "purpose": "Swift.Array.capacity getter", "category": "swift_runtime"},
    "$sSaxSicig": {"lib": "libswiftCore", "purpose": "Swift.Array subscript getter", "category": "swift_runtime"},
    "$sSaxSicis": {"lib": "libswiftCore", "purpose": "Swift.Array subscript setter", "category": "swift_runtime"},
    "$sSaMn": {"lib": "libswiftCore", "purpose": "Swift.Array type descriptor", "category": "swift_runtime"},
    "$sSDMa": {"lib": "libswiftCore", "purpose": "Swift.Dictionary metadata access", "category": "swift_runtime"},
    "$sSDyq_Sgxcig": {"lib": "libswiftCore", "purpose": "Swift.Dictionary subscript getter", "category": "swift_runtime"},
    "$sSDyq_Sgxcis": {"lib": "libswiftCore", "purpose": "Swift.Dictionary subscript setter", "category": "swift_runtime"},
    "$sSDMn": {"lib": "libswiftCore", "purpose": "Swift.Dictionary type descriptor", "category": "swift_runtime"},
    "$ss10DictionaryV5countSivg": {"lib": "libswiftCore", "purpose": "Dictionary.count getter", "category": "swift_runtime"},
    "$sSqMa": {"lib": "libswiftCore", "purpose": "Swift.Optional metadata access", "category": "swift_runtime"},
    "$sSqMn": {"lib": "libswiftCore", "purpose": "Swift.Optional type descriptor", "category": "swift_runtime"},
    "$sSqxSgWOb": {"lib": "libswiftCore", "purpose": "Swift.Optional value witness", "category": "swift_runtime"},
    "$ss5ErrorPMp": {"lib": "libswiftCore", "purpose": "Swift.Error protocol descriptor", "category": "swift_runtime"},
    "$ss5ResultOMa": {"lib": "libswiftCore", "purpose": "Swift.Result metadata access", "category": "swift_runtime"},
    "$ss5ResultOMn": {"lib": "libswiftCore", "purpose": "Swift.Result type descriptor", "category": "swift_runtime"},
    "$ss8_abstractys5NeverOyXlSg_s12StaticStringV4fileSutF": {"lib": "libswiftCore", "purpose": "Swift._abstract abstract-method trap", "category": "swift_runtime"},
    "$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_SSAHSus6UInt32VtF": {"lib": "libswiftCore", "purpose": "Swift assertion failure trap", "category": "swift_runtime"},
    "$ss27_allocateUninitializedArrayySayxG_BptBwlF": {"lib": "libswiftCore", "purpose": "Swift allocate uninitialized Array", "category": "swift_runtime"},
    "$ss27_finalizeUninitializedArrayySayxGABnlF": {"lib": "libswiftCore", "purpose": "Swift finalize uninitialized Array", "category": "swift_runtime"},
    "$sS2SycfC": {"lib": "libswiftCore", "purpose": "Swift.String.init() default", "category": "swift_runtime"},
    "$sSS5countSivg": {"lib": "libswiftCore", "purpose": "Swift.String.count getter", "category": "swift_runtime"},
    "$sSS5countSivgTj": {"lib": "libswiftCore", "purpose": "Swift.String.count dispatch thunk", "category": "swift_runtime"},
    "$sSS8appendedySSSSF": {"lib": "libswiftCore", "purpose": "Swift.String.appended(_:)", "category": "swift_runtime"},
    "$sSS6appendyySSF": {"lib": "libswiftCore", "purpose": "Swift.String.append(_:)", "category": "swift_runtime"},
    "$sSS7unicodeSS15UnicodeScalarsVvg": {"lib": "libswiftCore", "purpose": "Swift.String.unicodeScalars getter", "category": "swift_runtime"},
}


# ---------------------------------------------------------------------------
# CoreFoundation (CFLite) — C API, toll-free bridged with Foundation.
# Category "macos_cf" ile ``_MACOS_EXT_SIGNATURES`` ile idempotent parity.
# ---------------------------------------------------------------------------
_COREFOUNDATION_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Reference counting ---
    "CFRetain": {"lib": "CoreFoundation", "purpose": "increment CF reference count", "category": "macos_cf"},
    "CFRelease": {"lib": "CoreFoundation", "purpose": "decrement CF reference count", "category": "macos_cf"},
    "CFAutorelease": {"lib": "CoreFoundation", "purpose": "add CF object to autorelease pool", "category": "macos_cf"},
    "CFGetRetainCount": {"lib": "CoreFoundation", "purpose": "get CF retain count (debug)", "category": "macos_cf"},
    "CFMakeCollectable": {"lib": "CoreFoundation", "purpose": "mark CF object as collectable (legacy GC)", "category": "macos_cf"},
    "CFGetTypeID": {"lib": "CoreFoundation", "purpose": "get CF type identifier", "category": "macos_cf"},
    "CFCopyTypeIDDescription": {"lib": "CoreFoundation", "purpose": "copy CFType description string", "category": "macos_cf"},
    "CFCopyDescription": {"lib": "CoreFoundation", "purpose": "copy CF object description", "category": "macos_cf"},
    "CFEqual": {"lib": "CoreFoundation", "purpose": "compare two CF objects", "category": "macos_cf"},
    "CFHash": {"lib": "CoreFoundation", "purpose": "compute CF object hash", "category": "macos_cf"},
    "CFShow": {"lib": "CoreFoundation", "purpose": "print CF object description", "category": "macos_cf"},
    "CFGetAllocator": {"lib": "CoreFoundation", "purpose": "get allocator of CF object", "category": "macos_cf"},

    # --- Allocator ---
    "CFAllocatorCreate": {"lib": "CoreFoundation", "purpose": "create custom CF allocator", "category": "macos_cf"},
    "CFAllocatorAllocate": {"lib": "CoreFoundation", "purpose": "allocate via CF allocator", "category": "macos_cf"},
    "CFAllocatorReallocate": {"lib": "CoreFoundation", "purpose": "reallocate via CF allocator", "category": "macos_cf"},
    "CFAllocatorDeallocate": {"lib": "CoreFoundation", "purpose": "deallocate via CF allocator", "category": "macos_cf"},
    "CFAllocatorGetDefault": {"lib": "CoreFoundation", "purpose": "get default CF allocator", "category": "macos_cf"},
    "CFAllocatorSetDefault": {"lib": "CoreFoundation", "purpose": "set default CF allocator", "category": "macos_cf"},

    # --- CFString ---
    "CFStringCreateWithCString": {"lib": "CoreFoundation", "purpose": "create CFString from C string", "category": "macos_cf"},
    "CFStringCreateWithCStringNoCopy": {"lib": "CoreFoundation", "purpose": "create CFString wrapping C string", "category": "macos_cf"},
    "CFStringCreateWithBytes": {"lib": "CoreFoundation", "purpose": "create CFString from byte buffer", "category": "macos_cf"},
    "CFStringCreateWithBytesNoCopy": {"lib": "CoreFoundation", "purpose": "create CFString wrapping byte buffer", "category": "macos_cf"},
    "CFStringCreateWithFormat": {"lib": "CoreFoundation", "purpose": "create CFString from format + args", "category": "macos_cf"},
    "CFStringCreateWithFormatAndArguments": {"lib": "CoreFoundation", "purpose": "create CFString from format + va_list", "category": "macos_cf"},
    "CFStringCreateCopy": {"lib": "CoreFoundation", "purpose": "copy immutable CFString", "category": "macos_cf"},
    "CFStringCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFString", "category": "macos_cf"},
    "CFStringCreateMutableCopy": {"lib": "CoreFoundation", "purpose": "create mutable copy of CFString", "category": "macos_cf"},
    "CFStringGetCString": {"lib": "CoreFoundation", "purpose": "get C string from CFString", "category": "macos_cf"},
    "CFStringGetCStringPtr": {"lib": "CoreFoundation", "purpose": "fast access to backing C string", "category": "macos_cf"},
    "CFStringGetLength": {"lib": "CoreFoundation", "purpose": "get CFString UTF-16 length", "category": "macos_cf"},
    "CFStringGetCharacters": {"lib": "CoreFoundation", "purpose": "extract UTF-16 characters", "category": "macos_cf"},
    "CFStringGetCharacterAtIndex": {"lib": "CoreFoundation", "purpose": "get UTF-16 unit at index", "category": "macos_cf"},
    "CFStringAppend": {"lib": "CoreFoundation", "purpose": "append to mutable CFString", "category": "macos_cf"},
    "CFStringAppendCString": {"lib": "CoreFoundation", "purpose": "append C string to CFString", "category": "macos_cf"},
    "CFStringAppendFormat": {"lib": "CoreFoundation", "purpose": "append formatted string", "category": "macos_cf"},
    "CFStringCompare": {"lib": "CoreFoundation", "purpose": "compare two CFStrings", "category": "macos_cf"},
    "CFStringFind": {"lib": "CoreFoundation", "purpose": "find substring in CFString", "category": "macos_cf"},
    "CFStringHasPrefix": {"lib": "CoreFoundation", "purpose": "test prefix of CFString", "category": "macos_cf"},
    "CFStringHasSuffix": {"lib": "CoreFoundation", "purpose": "test suffix of CFString", "category": "macos_cf"},
    "CFStringGetMaximumSizeForEncoding": {"lib": "CoreFoundation", "purpose": "max byte count for encoding", "category": "macos_cf"},

    # --- CFData ---
    "CFDataCreate": {"lib": "CoreFoundation", "purpose": "create CFData from bytes", "category": "macos_cf"},
    "CFDataCreateWithBytesNoCopy": {"lib": "CoreFoundation", "purpose": "create CFData wrapping bytes", "category": "macos_cf"},
    "CFDataCreateCopy": {"lib": "CoreFoundation", "purpose": "copy CFData", "category": "macos_cf"},
    "CFDataCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFData", "category": "macos_cf"},
    "CFDataCreateMutableCopy": {"lib": "CoreFoundation", "purpose": "create mutable CFData copy", "category": "macos_cf"},
    "CFDataGetLength": {"lib": "CoreFoundation", "purpose": "get CFData length", "category": "macos_cf"},
    "CFDataGetBytePtr": {"lib": "CoreFoundation", "purpose": "get byte pointer from CFData", "category": "macos_cf"},
    "CFDataGetMutableBytePtr": {"lib": "CoreFoundation", "purpose": "get mutable byte pointer", "category": "macos_cf"},
    "CFDataGetBytes": {"lib": "CoreFoundation", "purpose": "copy bytes into external buffer", "category": "macos_cf"},
    "CFDataAppendBytes": {"lib": "CoreFoundation", "purpose": "append bytes to mutable CFData", "category": "macos_cf"},
    "CFDataSetLength": {"lib": "CoreFoundation", "purpose": "set mutable CFData length", "category": "macos_cf"},
    "CFDataReplaceBytes": {"lib": "CoreFoundation", "purpose": "replace byte range in mutable CFData", "category": "macos_cf"},

    # --- CFArray ---
    "CFArrayCreate": {"lib": "CoreFoundation", "purpose": "create CFArray", "category": "macos_cf"},
    "CFArrayCreateCopy": {"lib": "CoreFoundation", "purpose": "copy CFArray", "category": "macos_cf"},
    "CFArrayCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFArray", "category": "macos_cf"},
    "CFArrayCreateMutableCopy": {"lib": "CoreFoundation", "purpose": "create mutable CFArray copy", "category": "macos_cf"},
    "CFArrayGetCount": {"lib": "CoreFoundation", "purpose": "get CFArray count", "category": "macos_cf"},
    "CFArrayGetValueAtIndex": {"lib": "CoreFoundation", "purpose": "get CFArray element at index", "category": "macos_cf"},
    "CFArrayAppendValue": {"lib": "CoreFoundation", "purpose": "append to mutable CFArray", "category": "macos_cf"},
    "CFArrayInsertValueAtIndex": {"lib": "CoreFoundation", "purpose": "insert into mutable CFArray", "category": "macos_cf"},
    "CFArraySetValueAtIndex": {"lib": "CoreFoundation", "purpose": "replace element in mutable CFArray", "category": "macos_cf"},
    "CFArrayRemoveValueAtIndex": {"lib": "CoreFoundation", "purpose": "remove element from CFArray", "category": "macos_cf"},
    "CFArrayRemoveAllValues": {"lib": "CoreFoundation", "purpose": "clear mutable CFArray", "category": "macos_cf"},
    "CFArrayContainsValue": {"lib": "CoreFoundation", "purpose": "test membership in CFArray", "category": "macos_cf"},
    "CFArrayGetFirstIndexOfValue": {"lib": "CoreFoundation", "purpose": "find first index of value", "category": "macos_cf"},
    "CFArrayApplyFunction": {"lib": "CoreFoundation", "purpose": "apply function to each element", "category": "macos_cf"},

    # --- CFDictionary ---
    "CFDictionaryCreate": {"lib": "CoreFoundation", "purpose": "create CFDictionary", "category": "macos_cf"},
    "CFDictionaryCreateCopy": {"lib": "CoreFoundation", "purpose": "copy CFDictionary", "category": "macos_cf"},
    "CFDictionaryCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFDictionary", "category": "macos_cf"},
    "CFDictionaryCreateMutableCopy": {"lib": "CoreFoundation", "purpose": "create mutable dict copy", "category": "macos_cf"},
    "CFDictionaryGetCount": {"lib": "CoreFoundation", "purpose": "get CFDictionary count", "category": "macos_cf"},
    "CFDictionaryGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFDictionary", "category": "macos_cf"},
    "CFDictionaryGetValueIfPresent": {"lib": "CoreFoundation", "purpose": "safe get from CFDictionary", "category": "macos_cf"},
    "CFDictionaryContainsKey": {"lib": "CoreFoundation", "purpose": "test key membership", "category": "macos_cf"},
    "CFDictionaryContainsValue": {"lib": "CoreFoundation", "purpose": "test value membership", "category": "macos_cf"},
    "CFDictionarySetValue": {"lib": "CoreFoundation", "purpose": "set value in mutable CFDictionary", "category": "macos_cf"},
    "CFDictionaryAddValue": {"lib": "CoreFoundation", "purpose": "add value (only if key absent)", "category": "macos_cf"},
    "CFDictionaryReplaceValue": {"lib": "CoreFoundation", "purpose": "replace value (only if key present)", "category": "macos_cf"},
    "CFDictionaryRemoveValue": {"lib": "CoreFoundation", "purpose": "remove key from CFDictionary", "category": "macos_cf"},
    "CFDictionaryRemoveAllValues": {"lib": "CoreFoundation", "purpose": "clear mutable CFDictionary", "category": "macos_cf"},
    "CFDictionaryGetKeysAndValues": {"lib": "CoreFoundation", "purpose": "get all keys and values", "category": "macos_cf"},
    "CFDictionaryApplyFunction": {"lib": "CoreFoundation", "purpose": "apply function to each pair", "category": "macos_cf"},

    # --- CFSet ---
    "CFSetCreate": {"lib": "CoreFoundation", "purpose": "create CFSet", "category": "macos_cf"},
    "CFSetCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFSet", "category": "macos_cf"},
    "CFSetGetCount": {"lib": "CoreFoundation", "purpose": "get CFSet count", "category": "macos_cf"},
    "CFSetContainsValue": {"lib": "CoreFoundation", "purpose": "test membership in CFSet", "category": "macos_cf"},
    "CFSetAddValue": {"lib": "CoreFoundation", "purpose": "add value to mutable CFSet", "category": "macos_cf"},
    "CFSetRemoveValue": {"lib": "CoreFoundation", "purpose": "remove value from mutable CFSet", "category": "macos_cf"},
    "CFSetGetValues": {"lib": "CoreFoundation", "purpose": "get all values of CFSet", "category": "macos_cf"},

    # --- CFNumber / CFBoolean ---
    "CFNumberCreate": {"lib": "CoreFoundation", "purpose": "create CFNumber", "category": "macos_cf"},
    "CFNumberGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFNumber", "category": "macos_cf"},
    "CFNumberGetType": {"lib": "CoreFoundation", "purpose": "get CFNumber numeric type", "category": "macos_cf"},
    "CFNumberGetByteSize": {"lib": "CoreFoundation", "purpose": "get CFNumber byte size", "category": "macos_cf"},
    "CFNumberCompare": {"lib": "CoreFoundation", "purpose": "compare CFNumber values", "category": "macos_cf"},
    "CFBooleanGetValue": {"lib": "CoreFoundation", "purpose": "get bool from CFBoolean", "category": "macos_cf"},

    # --- CFDate / CFTimeZone ---
    "CFDateCreate": {"lib": "CoreFoundation", "purpose": "create CFDate", "category": "macos_cf"},
    "CFDateGetAbsoluteTime": {"lib": "CoreFoundation", "purpose": "get CFDate absolute time", "category": "macos_cf"},
    "CFDateGetTimeIntervalSinceDate": {"lib": "CoreFoundation", "purpose": "interval between CFDates", "category": "macos_cf"},
    "CFAbsoluteTimeGetCurrent": {"lib": "CoreFoundation", "purpose": "get current absolute time", "category": "macos_cf"},
    "CFTimeZoneCreateWithName": {"lib": "CoreFoundation", "purpose": "create CFTimeZone by name", "category": "macos_cf"},
    "CFTimeZoneGetName": {"lib": "CoreFoundation", "purpose": "get CFTimeZone name", "category": "macos_cf"},
    "CFTimeZoneCopySystem": {"lib": "CoreFoundation", "purpose": "copy system time zone", "category": "macos_cf"},
    "CFTimeZoneCopyDefault": {"lib": "CoreFoundation", "purpose": "copy default time zone", "category": "macos_cf"},

    # --- CFURL ---
    "CFURLCreateWithString": {"lib": "CoreFoundation", "purpose": "create CFURL from string", "category": "macos_cf"},
    "CFURLCreateWithBytes": {"lib": "CoreFoundation", "purpose": "create CFURL from byte buffer", "category": "macos_cf"},
    "CFURLCreateWithFileSystemPath": {"lib": "CoreFoundation", "purpose": "create CFURL from file path", "category": "macos_cf"},
    "CFURLCreateFromFileSystemRepresentation": {"lib": "CoreFoundation", "purpose": "create CFURL from POSIX path", "category": "macos_cf"},
    "CFURLCopyPath": {"lib": "CoreFoundation", "purpose": "copy CFURL path component", "category": "macos_cf"},
    "CFURLCopyHostName": {"lib": "CoreFoundation", "purpose": "copy CFURL host component", "category": "macos_cf"},
    "CFURLCopyScheme": {"lib": "CoreFoundation", "purpose": "copy CFURL scheme component", "category": "macos_cf"},
    "CFURLGetString": {"lib": "CoreFoundation", "purpose": "get CFURL as CFString", "category": "macos_cf"},
    "CFURLCreateCopyAppendingPathComponent": {"lib": "CoreFoundation", "purpose": "append path component to URL", "category": "macos_cf"},
    "CFURLCreateCopyDeletingLastPathComponent": {"lib": "CoreFoundation", "purpose": "drop last path component", "category": "macos_cf"},

    # --- CFBundle ---
    "CFBundleGetMainBundle": {"lib": "CoreFoundation", "purpose": "get main bundle", "category": "macos_cf"},
    "CFBundleGetBundleWithIdentifier": {"lib": "CoreFoundation", "purpose": "get bundle by identifier", "category": "macos_cf"},
    "CFBundleCreate": {"lib": "CoreFoundation", "purpose": "create bundle from URL", "category": "macos_cf"},
    "CFBundleGetIdentifier": {"lib": "CoreFoundation", "purpose": "get bundle identifier", "category": "macos_cf"},
    "CFBundleGetInfoDictionary": {"lib": "CoreFoundation", "purpose": "get bundle Info.plist dict", "category": "macos_cf"},
    "CFBundleGetValueForInfoDictionaryKey": {"lib": "CoreFoundation", "purpose": "read Info.plist key", "category": "macos_cf"},
    "CFBundleCopyBundleURL": {"lib": "CoreFoundation", "purpose": "copy bundle URL", "category": "macos_cf"},
    "CFBundleCopyExecutableURL": {"lib": "CoreFoundation", "purpose": "copy bundle executable URL", "category": "macos_cf"},
    "CFBundleCopyResourceURL": {"lib": "CoreFoundation", "purpose": "copy URL for bundle resource", "category": "macos_cf"},
    "CFBundleLoadExecutable": {"lib": "CoreFoundation", "purpose": "load bundle executable code", "category": "macos_cf"},
    "CFBundleGetFunctionPointerForName": {"lib": "CoreFoundation", "purpose": "lookup function pointer by name", "category": "macos_cf"},
    "CFBundleGetDataPointerForName": {"lib": "CoreFoundation", "purpose": "lookup data pointer by name", "category": "macos_cf"},

    # --- CFRunLoop ---
    "CFRunLoopRun": {"lib": "CoreFoundation", "purpose": "run current run loop", "category": "macos_cf"},
    "CFRunLoopRunInMode": {"lib": "CoreFoundation", "purpose": "run run loop in specific mode", "category": "macos_cf"},
    "CFRunLoopStop": {"lib": "CoreFoundation", "purpose": "stop run loop", "category": "macos_cf"},
    "CFRunLoopWakeUp": {"lib": "CoreFoundation", "purpose": "wake up blocked run loop", "category": "macos_cf"},
    "CFRunLoopGetCurrent": {"lib": "CoreFoundation", "purpose": "get current run loop", "category": "macos_cf"},
    "CFRunLoopGetMain": {"lib": "CoreFoundation", "purpose": "get main run loop", "category": "macos_cf"},
    "CFRunLoopAddSource": {"lib": "CoreFoundation", "purpose": "add source to run loop", "category": "macos_cf"},
    "CFRunLoopRemoveSource": {"lib": "CoreFoundation", "purpose": "remove source from run loop", "category": "macos_cf"},
    "CFRunLoopAddTimer": {"lib": "CoreFoundation", "purpose": "add timer to run loop", "category": "macos_cf"},
    "CFRunLoopRemoveTimer": {"lib": "CoreFoundation", "purpose": "remove timer from run loop", "category": "macos_cf"},
    "CFRunLoopAddObserver": {"lib": "CoreFoundation", "purpose": "add observer to run loop", "category": "macos_cf"},
    "CFRunLoopRemoveObserver": {"lib": "CoreFoundation", "purpose": "remove observer from run loop", "category": "macos_cf"},
    "CFRunLoopContainsSource": {"lib": "CoreFoundation", "purpose": "test source membership", "category": "macos_cf"},
    "CFRunLoopPerformBlock": {"lib": "CoreFoundation", "purpose": "schedule block on run loop", "category": "macos_cf"},
    "CFRunLoopSourceCreate": {"lib": "CoreFoundation", "purpose": "create run loop source (v0/v1)", "category": "macos_cf"},
    "CFRunLoopSourceInvalidate": {"lib": "CoreFoundation", "purpose": "invalidate run loop source", "category": "macos_cf"},
    "CFRunLoopSourceIsValid": {"lib": "CoreFoundation", "purpose": "test source validity", "category": "macos_cf"},
    "CFRunLoopTimerCreate": {"lib": "CoreFoundation", "purpose": "create run loop timer", "category": "macos_cf"},
    "CFRunLoopTimerInvalidate": {"lib": "CoreFoundation", "purpose": "invalidate run loop timer", "category": "macos_cf"},

    # --- CFPreferences ---
    "CFPreferencesCopyValue": {"lib": "CoreFoundation", "purpose": "read preference value", "category": "macos_cf"},
    "CFPreferencesSetValue": {"lib": "CoreFoundation", "purpose": "set preference value", "category": "macos_cf"},
    "CFPreferencesCopyAppValue": {"lib": "CoreFoundation", "purpose": "copy app preference value", "category": "macos_cf"},
    "CFPreferencesSetAppValue": {"lib": "CoreFoundation", "purpose": "set app preference value", "category": "macos_cf"},
    "CFPreferencesAppSynchronize": {"lib": "CoreFoundation", "purpose": "synchronize preferences", "category": "macos_cf"},
    "CFPreferencesCopyKeyList": {"lib": "CoreFoundation", "purpose": "list preference keys", "category": "macos_cf"},

    # --- CFNotificationCenter ---
    "CFNotificationCenterGetLocalCenter": {"lib": "CoreFoundation", "purpose": "get local notification center", "category": "macos_cf"},
    "CFNotificationCenterGetDarwinNotifyCenter": {"lib": "CoreFoundation", "purpose": "get Darwin notify center", "category": "macos_cf"},
    "CFNotificationCenterGetDistributedCenter": {"lib": "CoreFoundation", "purpose": "get distributed notify center", "category": "macos_cf"},
    "CFNotificationCenterAddObserver": {"lib": "CoreFoundation", "purpose": "add notification observer", "category": "macos_cf"},
    "CFNotificationCenterRemoveObserver": {"lib": "CoreFoundation", "purpose": "remove notification observer", "category": "macos_cf"},
    "CFNotificationCenterPostNotification": {"lib": "CoreFoundation", "purpose": "post CF notification", "category": "macos_cf"},
    "CFNotificationCenterPostNotificationWithOptions": {"lib": "CoreFoundation", "purpose": "post CF notification with options", "category": "macos_cf"},

    # --- CFStream ---
    "CFReadStreamCreateWithBytesNoCopy": {"lib": "CoreFoundation", "purpose": "create read stream over bytes", "category": "macos_cf"},
    "CFReadStreamCreateWithFile": {"lib": "CoreFoundation", "purpose": "create read stream from file", "category": "macos_cf"},
    "CFReadStreamOpen": {"lib": "CoreFoundation", "purpose": "open read stream", "category": "macos_cf"},
    "CFReadStreamClose": {"lib": "CoreFoundation", "purpose": "close read stream", "category": "macos_cf"},
    "CFReadStreamRead": {"lib": "CoreFoundation", "purpose": "read from stream", "category": "macos_cf"},
    "CFReadStreamHasBytesAvailable": {"lib": "CoreFoundation", "purpose": "test available bytes", "category": "macos_cf"},
    "CFWriteStreamCreateWithFile": {"lib": "CoreFoundation", "purpose": "create write stream to file", "category": "macos_cf"},
    "CFWriteStreamOpen": {"lib": "CoreFoundation", "purpose": "open write stream", "category": "macos_cf"},
    "CFWriteStreamClose": {"lib": "CoreFoundation", "purpose": "close write stream", "category": "macos_cf"},
    "CFWriteStreamWrite": {"lib": "CoreFoundation", "purpose": "write to stream", "category": "macos_cf"},

    # --- CFUUID ---
    "CFUUIDCreate": {"lib": "CoreFoundation", "purpose": "create random CFUUID", "category": "macos_cf"},
    "CFUUIDCreateFromString": {"lib": "CoreFoundation", "purpose": "parse CFUUID from string", "category": "macos_cf"},
    "CFUUIDCreateString": {"lib": "CoreFoundation", "purpose": "format CFUUID as string", "category": "macos_cf"},
    "CFUUIDGetUUIDBytes": {"lib": "CoreFoundation", "purpose": "get raw UUID bytes", "category": "macos_cf"},

    # --- CFPropertyList / CFXML ---
    "CFPropertyListCreateWithData": {"lib": "CoreFoundation", "purpose": "decode plist from data", "category": "macos_cf"},
    "CFPropertyListCreateData": {"lib": "CoreFoundation", "purpose": "encode plist to data", "category": "macos_cf"},
    "CFPropertyListCreateDeepCopy": {"lib": "CoreFoundation", "purpose": "deep copy plist", "category": "macos_cf"},

    # --- CFError ---
    "CFErrorCreate": {"lib": "CoreFoundation", "purpose": "create CFError", "category": "macos_cf"},
    "CFErrorGetDomain": {"lib": "CoreFoundation", "purpose": "get CFError domain", "category": "macos_cf"},
    "CFErrorGetCode": {"lib": "CoreFoundation", "purpose": "get CFError code", "category": "macos_cf"},
    "CFErrorCopyDescription": {"lib": "CoreFoundation", "purpose": "copy CFError description", "category": "macos_cf"},
    "CFErrorCopyFailureReason": {"lib": "CoreFoundation", "purpose": "copy CFError failure reason", "category": "macos_cf"},
    "CFErrorCopyRecoverySuggestion": {"lib": "CoreFoundation", "purpose": "copy CFError recovery suggestion", "category": "macos_cf"},
    "CFErrorCopyUserInfo": {"lib": "CoreFoundation", "purpose": "copy CFError user info dict", "category": "macos_cf"},

    # --- CFLocale / CFCalendar ---
    "CFLocaleCopyCurrent": {"lib": "CoreFoundation", "purpose": "copy current locale", "category": "macos_cf"},
    "CFLocaleCreate": {"lib": "CoreFoundation", "purpose": "create locale by identifier", "category": "macos_cf"},
    "CFLocaleGetIdentifier": {"lib": "CoreFoundation", "purpose": "get locale identifier", "category": "macos_cf"},
    "CFLocaleCopyAvailableLocaleIdentifiers": {"lib": "CoreFoundation", "purpose": "list available locales", "category": "macos_cf"},
    "CFCalendarCopyCurrent": {"lib": "CoreFoundation", "purpose": "copy current calendar", "category": "macos_cf"},
    "CFCalendarCreateWithIdentifier": {"lib": "CoreFoundation", "purpose": "create calendar by ID", "category": "macos_cf"},

    # --- CFFileDescriptor ---
    "CFFileDescriptorCreate": {"lib": "CoreFoundation", "purpose": "create CFFileDescriptor", "category": "macos_cf"},
    "CFFileDescriptorGetNativeDescriptor": {"lib": "CoreFoundation", "purpose": "get underlying fd", "category": "macos_cf"},
    "CFFileDescriptorEnableCallBacks": {"lib": "CoreFoundation", "purpose": "enable fd callbacks", "category": "macos_cf"},
    "CFFileDescriptorCreateRunLoopSource": {"lib": "CoreFoundation", "purpose": "wrap fd as run loop source", "category": "macos_cf"},

    # --- Machport / Mach source ---
    "CFMachPortCreate": {"lib": "CoreFoundation", "purpose": "create CFMachPort", "category": "macos_cf"},
    "CFMachPortGetPort": {"lib": "CoreFoundation", "purpose": "get underlying mach port", "category": "macos_cf"},
    "CFMachPortInvalidate": {"lib": "CoreFoundation", "purpose": "invalidate mach port", "category": "macos_cf"},
    "CFMachPortCreateRunLoopSource": {"lib": "CoreFoundation", "purpose": "wrap mach port as run loop source", "category": "macos_cf"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — signature_db.py uc alt dict'i isme gore import eder.
# Ayni kalip pe_runtime.SIGNATURES ile ozdes (dict-of-dicts yapisi).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "objc_runtime_signatures": _OBJC_RUNTIME_SIGNATURES_DATA,
    "swift_runtime_signatures": _SWIFT_RUNTIME_SIGNATURES_DATA,
    "corefoundation_signatures": _COREFOUNDATION_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
