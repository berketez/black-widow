"""macOS / Apple ailesi signature'lari — sig_db v1.13 Dalga 2 migrasyonu (ADR 0007 A3).

Kaynak: karadul/analyzers/signature_db.py
  - _MACOS_SYSTEM_SIGNATURES                (~280 entry, satir 299-657)
  - _MACOS_NETWORKING_SIGNATURES            (~51 entry,  satir 2655-2706)
  - _IPC_XPC_SIGNATURES                     (~52 entry,  satir 2713-2765)
  - _APPLE_COREDATA_SIGNATURES              (~16 entry,  satir 3345-3362)
  - _APPLE_WEBKIT_SIGNATURES                (~14 entry,  satir 3369-3383)
  - _APPLE_CORELOCATION_SIGNATURES          (~9  entry,  satir 3390-3400)
  - _APPLE_COREBLUETOOTH_SIGNATURES         (~11 entry,  satir 3407-3419)
  - _APPLE_STOREKIT_SIGNATURES              (~10 entry,  satir 3426-3437)
  - _APPLE_USERNOTIFICATIONS_SIGNATURES     (~11 entry,  satir 3444-3456)
  - _APPLE_NETWORK_FRAMEWORK_SIGNATURES     (~38 entry,  satir 3463-3503)
  - _APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES (~14 entry,  satir 3510-3525)
  - _APPLE_SYSTEMEXTENSIONS_SIGNATURES      (~3  entry,  satir 3532-3536)
  - _APPLE_APPKIT_SIGNATURES                (~84 entry,  satir 3543-3629)
  - _MACOS_EXT_SIGNATURES                   (~117 entry, satir 7302-7421)

Toplam: ~610 signature (en buyuk taşinacak kategori).

ADR 0007 A3 / ADR 0008 — Grup "macos_apple". Tip A yumusak override pattern'i
(crypto / compression / network / vm_runtime / logging / languages ile ozdes):
signature_db.py'de orijinal dict gövdeleri SILINMEDI; runtime'da bu modulden
gelen veriyle yeniden baglanir. Rollback icin override blogu silinince
(try/except ImportError) eski inline veri otomatik geri devreye girer.
Faz A-DELETE v1.14'te legacy dict'leri kaldiracaktir.

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``macos_system``                <-> ``_MACOS_SYSTEM_SIGNATURES``
  ``macos_networking``            <-> ``_MACOS_NETWORKING_SIGNATURES``
  ``ipc_xpc``                     <-> ``_IPC_XPC_SIGNATURES``
  ``apple_coredata``              <-> ``_APPLE_COREDATA_SIGNATURES``
  ``apple_webkit``                <-> ``_APPLE_WEBKIT_SIGNATURES``
  ``apple_corelocation``          <-> ``_APPLE_CORELOCATION_SIGNATURES``
  ``apple_corebluetooth``         <-> ``_APPLE_COREBLUETOOTH_SIGNATURES``
  ``apple_storekit``              <-> ``_APPLE_STOREKIT_SIGNATURES``
  ``apple_usernotifications``     <-> ``_APPLE_USERNOTIFICATIONS_SIGNATURES``
  ``apple_network_framework``     <-> ``_APPLE_NETWORK_FRAMEWORK_SIGNATURES``
  ``apple_endpoint_security_ext`` <-> ``_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES``
  ``apple_systemextensions``      <-> ``_APPLE_SYSTEMEXTENSIONS_SIGNATURES``
  ``apple_appkit``                <-> ``_APPLE_APPKIT_SIGNATURES``
  ``macos_ext``                   <-> ``_MACOS_EXT_SIGNATURES``

Bilgi: Tarihsel olarak _MACOS_SYSTEM_SIGNATURES; libdispatch (concurrency),
libobjc (runtime), Swift runtime, CommonCrypto (crypto), Security.framework,
EndpointSecurity, NetworkExtension (network), libxpc (ipc), IOKit (hardware)
ve CoreFoundation (foundation) entry'lerini ortak sepette tutar — Tip A
migrasyon kapsami sadece tasimadir; alt kategori ayirimi sonraki rafinaj
fazlarinda ele alinabilir. Ayni sekilde _APPLE_NETWORK_FRAMEWORK ile
_MACOS_NETWORKING kismen ortusen ``_nw_*`` entry'lerine sahiptir; iki
dict ayri tutuldu (orijinal yapiyi koruma kurali).
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# macos_system (~280 entry) — libdispatch + libobjc + Swift runtime +
# CommonCrypto + Security.framework + EndpointSecurity + NetworkExtension +
# libxpc + IOKit + CoreFoundation. Kaynak: signature_db.py satir 299-657.
# ---------------------------------------------------------------------------
_MACOS_SYSTEM_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # libdispatch (Grand Central Dispatch)
    "_dispatch_once_f": {"lib": "libdispatch", "purpose": "thread-safe lazy init", "category": "concurrency"},
    "_dispatch_once": {"lib": "libdispatch", "purpose": "thread-safe lazy init", "category": "concurrency"},
    "_dispatch_async": {"lib": "libdispatch", "purpose": "async task dispatch", "category": "concurrency"},
    "_dispatch_sync": {"lib": "libdispatch", "purpose": "sync task dispatch", "category": "concurrency"},
    "_dispatch_group_create": {"lib": "libdispatch", "purpose": "dispatch group creation", "category": "concurrency"},
    "_dispatch_group_enter": {"lib": "libdispatch", "purpose": "dispatch group enter", "category": "concurrency"},
    "_dispatch_group_leave": {"lib": "libdispatch", "purpose": "dispatch group leave", "category": "concurrency"},
    "_dispatch_group_notify": {"lib": "libdispatch", "purpose": "dispatch group completion", "category": "concurrency"},
    "_dispatch_group_wait": {"lib": "libdispatch", "purpose": "dispatch group wait", "category": "concurrency"},
    "_dispatch_queue_create": {"lib": "libdispatch", "purpose": "dispatch queue creation", "category": "concurrency"},
    "_dispatch_semaphore_create": {"lib": "libdispatch", "purpose": "semaphore creation", "category": "concurrency"},
    "_dispatch_semaphore_signal": {"lib": "libdispatch", "purpose": "semaphore signal", "category": "concurrency"},
    "_dispatch_semaphore_wait": {"lib": "libdispatch", "purpose": "semaphore wait", "category": "concurrency"},
    "_dispatch_barrier_async": {"lib": "libdispatch", "purpose": "barrier async dispatch", "category": "concurrency"},
    "_dispatch_barrier_sync": {"lib": "libdispatch", "purpose": "barrier sync dispatch", "category": "concurrency"},
    "_dispatch_after": {"lib": "libdispatch", "purpose": "delayed execution", "category": "concurrency"},
    "_dispatch_apply": {"lib": "libdispatch", "purpose": "parallel for loop", "category": "concurrency"},
    "_dispatch_source_create": {"lib": "libdispatch", "purpose": "event source creation", "category": "concurrency"},
    "_dispatch_data_create": {"lib": "libdispatch", "purpose": "dispatch data creation", "category": "concurrency"},
    "_dispatch_io_create": {"lib": "libdispatch", "purpose": "dispatch I/O channel", "category": "concurrency"},
    "_dispatch_get_global_queue": {"lib": "libdispatch", "purpose": "global queue access", "category": "concurrency"},
    "_dispatch_get_main_queue": {"lib": "libdispatch", "purpose": "main queue access", "category": "concurrency"},
    "_dispatch_main": {"lib": "libdispatch", "purpose": "run main dispatch loop", "category": "concurrency"},
    "_dispatch_time": {"lib": "libdispatch", "purpose": "dispatch time calculation", "category": "concurrency"},
    "_dispatch_walltime": {"lib": "libdispatch", "purpose": "dispatch wall time", "category": "concurrency"},
    "_dispatch_block_create": {"lib": "libdispatch", "purpose": "dispatch block creation", "category": "concurrency"},
    "_dispatch_block_cancel": {"lib": "libdispatch", "purpose": "dispatch block cancel", "category": "concurrency"},
    "_dispatch_block_wait": {"lib": "libdispatch", "purpose": "dispatch block wait", "category": "concurrency"},
    "_dispatch_release": {"lib": "libdispatch", "purpose": "dispatch object release", "category": "concurrency"},
    "_dispatch_retain": {"lib": "libdispatch", "purpose": "dispatch object retain", "category": "concurrency"},

    # libobjc (Objective-C runtime)
    "_objc_msgSend": {"lib": "libobjc", "purpose": "ObjC message dispatch", "category": "runtime"},
    "_objc_msgSendSuper": {"lib": "libobjc", "purpose": "ObjC super dispatch", "category": "runtime"},
    "_objc_msgSendSuper2": {"lib": "libobjc", "purpose": "ObjC super2 dispatch", "category": "runtime"},
    "_objc_msgSend_stret": {"lib": "libobjc", "purpose": "ObjC struct return dispatch", "category": "runtime"},
    "_objc_release": {"lib": "libobjc", "purpose": "ObjC ARC release", "category": "runtime"},
    "_objc_retain": {"lib": "libobjc", "purpose": "ObjC ARC retain", "category": "runtime"},
    "_objc_retainAutoreleasedReturnValue": {"lib": "libobjc", "purpose": "ObjC ARC autorelease opt", "category": "runtime"},
    "_objc_autoreleaseReturnValue": {"lib": "libobjc", "purpose": "ObjC autorelease return", "category": "runtime"},
    "_objc_autorelease": {"lib": "libobjc", "purpose": "ObjC autorelease", "category": "runtime"},
    "_objc_alloc": {"lib": "libobjc", "purpose": "ObjC alloc", "category": "runtime"},
    "_objc_alloc_init": {"lib": "libobjc", "purpose": "ObjC alloc+init", "category": "runtime"},
    "_objc_allocWithZone": {"lib": "libobjc", "purpose": "ObjC zoned alloc", "category": "runtime"},
    "_objc_getClass": {"lib": "libobjc", "purpose": "ObjC class lookup by name", "category": "runtime"},
    "_objc_getMetaClass": {"lib": "libobjc", "purpose": "ObjC metaclass lookup", "category": "runtime"},
    "_objc_lookUpClass": {"lib": "libobjc", "purpose": "ObjC optional class lookup", "category": "runtime"},
    "_objc_enumerationMutation": {"lib": "libobjc", "purpose": "ObjC mutation during enumeration", "category": "runtime"},
    "_objc_opt_class": {"lib": "libobjc", "purpose": "ObjC optimized class", "category": "runtime"},
    "_objc_opt_isKindOfClass": {"lib": "libobjc", "purpose": "ObjC optimized isKindOfClass", "category": "runtime"},
    "_objc_opt_respondsToSelector": {"lib": "libobjc", "purpose": "ObjC optimized respondsToSelector", "category": "runtime"},
    "_objc_storeStrong": {"lib": "libobjc", "purpose": "ObjC ARC strong store", "category": "runtime"},
    "_objc_storeWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak store", "category": "runtime"},
    "_objc_loadWeakRetained": {"lib": "libobjc", "purpose": "ObjC ARC weak load", "category": "runtime"},
    "_objc_destroyWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak destroy", "category": "runtime"},
    "_objc_copyWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak copy", "category": "runtime"},
    "_objc_moveWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak move", "category": "runtime"},
    "_objc_initWeak": {"lib": "libobjc", "purpose": "ObjC ARC weak init", "category": "runtime"},
    "_objc_autoreleasePoolPush": {"lib": "libobjc", "purpose": "ObjC autorelease pool push", "category": "runtime"},
    "_objc_autoreleasePoolPop": {"lib": "libobjc", "purpose": "ObjC autorelease pool pop", "category": "runtime"},
    "_sel_registerName": {"lib": "libobjc", "purpose": "ObjC selector registration", "category": "runtime"},
    "_sel_getName": {"lib": "libobjc", "purpose": "ObjC selector name lookup", "category": "runtime"},
    "_class_getName": {"lib": "libobjc", "purpose": "ObjC class name lookup", "category": "runtime"},
    "_class_getSuperclass": {"lib": "libobjc", "purpose": "ObjC superclass lookup", "category": "runtime"},
    "_class_getInstanceMethod": {"lib": "libobjc", "purpose": "ObjC instance method lookup", "category": "runtime"},
    "_class_getClassMethod": {"lib": "libobjc", "purpose": "ObjC class method lookup", "category": "runtime"},
    "_class_addMethod": {"lib": "libobjc", "purpose": "ObjC dynamic method add", "category": "runtime"},
    "_class_replaceMethod": {"lib": "libobjc", "purpose": "ObjC method swizzle", "category": "runtime"},
    "_method_exchangeImplementations": {"lib": "libobjc", "purpose": "ObjC method exchange (swizzle)", "category": "runtime"},
    "_protocol_conformsToProtocol": {"lib": "libobjc", "purpose": "ObjC protocol conformance check", "category": "runtime"},
    "_object_getClass": {"lib": "libobjc", "purpose": "ObjC get object class", "category": "runtime"},
    "_NSLog": {"lib": "Foundation", "purpose": "ObjC console logging", "category": "runtime"},

    # Swift runtime
    "_swift_retain": {"lib": "swift_runtime", "purpose": "Swift ARC retain", "category": "runtime"},
    "_swift_release": {"lib": "swift_runtime", "purpose": "Swift ARC release", "category": "runtime"},
    "_swift_allocObject": {"lib": "swift_runtime", "purpose": "Swift object allocation", "category": "runtime"},
    "_swift_deallocObject": {"lib": "swift_runtime", "purpose": "Swift object deallocation", "category": "runtime"},
    "_swift_initStackObject": {"lib": "swift_runtime", "purpose": "Swift stack object init", "category": "runtime"},
    "_swift_bridgeObjectRetain": {"lib": "swift_runtime", "purpose": "Swift bridge object retain", "category": "runtime"},
    "_swift_bridgeObjectRelease": {"lib": "swift_runtime", "purpose": "Swift bridge object release", "category": "runtime"},
    "_swift_unknownObjectRetain": {"lib": "swift_runtime", "purpose": "Swift unknown object retain", "category": "runtime"},
    "_swift_unknownObjectRelease": {"lib": "swift_runtime", "purpose": "Swift unknown object release", "category": "runtime"},
    "_swift_isUniquelyReferenced_nonNull_native": {"lib": "swift_runtime", "purpose": "Swift COW uniqueness check", "category": "runtime"},
    "_swift_getObjectType": {"lib": "swift_runtime", "purpose": "Swift type metadata lookup", "category": "runtime"},
    "_swift_getTypeByMangledNameInContext": {"lib": "swift_runtime", "purpose": "Swift demangled type lookup", "category": "runtime"},
    "_swift_dynamicCast": {"lib": "swift_runtime", "purpose": "Swift dynamic cast (as?/as!)", "category": "runtime"},
    "_swift_conformsToProtocol": {"lib": "swift_runtime", "purpose": "Swift protocol conformance check", "category": "runtime"},
    "_swift_getWitnessTable": {"lib": "swift_runtime", "purpose": "Swift witness table lookup", "category": "runtime"},
    "_swift_getAssociatedTypeWitness": {"lib": "swift_runtime", "purpose": "Swift associated type witness", "category": "runtime"},
    "_swift_getTypeContextDescriptor": {"lib": "swift_runtime", "purpose": "Swift type descriptor lookup", "category": "runtime"},
    "_swift_once": {"lib": "swift_runtime", "purpose": "Swift one-time initialization", "category": "runtime"},
    "_swift_beginAccess": {"lib": "swift_runtime", "purpose": "Swift exclusivity access begin", "category": "runtime"},
    "_swift_endAccess": {"lib": "swift_runtime", "purpose": "Swift exclusivity access end", "category": "runtime"},
    "_swift_makeBoxUnique": {"lib": "swift_runtime", "purpose": "Swift box uniqueness", "category": "runtime"},
    "_swift_allocBox": {"lib": "swift_runtime", "purpose": "Swift box allocation", "category": "runtime"},
    "_swift_projectBox": {"lib": "swift_runtime", "purpose": "Swift box projection", "category": "runtime"},
    "_swift_deallocBox": {"lib": "swift_runtime", "purpose": "Swift box deallocation", "category": "runtime"},
    "_swift_getInitializedObjCClass": {"lib": "swift_runtime", "purpose": "Swift ObjC class init bridge", "category": "runtime"},
    "_swift_getObjCClassMetadata": {"lib": "swift_runtime", "purpose": "Swift ObjC metadata bridge", "category": "runtime"},
    "_swift_slowAlloc": {"lib": "swift_runtime", "purpose": "Swift slow-path alloc", "category": "runtime"},
    "_swift_slowDealloc": {"lib": "swift_runtime", "purpose": "Swift slow-path dealloc", "category": "runtime"},
    "_swift_task_create": {"lib": "swift_runtime", "purpose": "Swift async task creation", "category": "concurrency"},
    "_swift_task_switch": {"lib": "swift_runtime", "purpose": "Swift async task switch", "category": "concurrency"},
    "_swift_task_future_wait": {"lib": "swift_runtime", "purpose": "Swift async await", "category": "concurrency"},
    "_swift_asyncLet_begin": {"lib": "swift_runtime", "purpose": "Swift async let begin", "category": "concurrency"},
    "_swift_asyncLet_end": {"lib": "swift_runtime", "purpose": "Swift async let end", "category": "concurrency"},
    "_swift_task_group_create": {"lib": "swift_runtime", "purpose": "Swift task group creation", "category": "concurrency"},
    "_swift_task_group_addPending": {"lib": "swift_runtime", "purpose": "Swift task group add", "category": "concurrency"},
    "_swift_task_cancel": {"lib": "swift_runtime", "purpose": "Swift task cancellation", "category": "concurrency"},
    "_swift_task_isCancelled": {"lib": "swift_runtime", "purpose": "Swift task cancel check", "category": "concurrency"},
    "_swift_continuation_resume": {"lib": "swift_runtime", "purpose": "Swift continuation resume", "category": "concurrency"},
    "$ss17_assertionFailure": {"lib": "swift_runtime", "purpose": "Swift assertion failure", "category": "runtime"},
    "$ss18_fatalErrorMessage": {"lib": "swift_runtime", "purpose": "Swift fatal error", "category": "runtime"},
    "$ss27_allocateUninitializedArray": {"lib": "swift_runtime", "purpose": "Swift array allocation", "category": "runtime"},
    "$ss22_deallocateUninitializedArray": {"lib": "swift_runtime", "purpose": "Swift array deallocation", "category": "runtime"},
    "$sSS21_builtinStringLiteral": {"lib": "swift_runtime", "purpose": "Swift string literal", "category": "runtime"},
    "$sSa6appendyyxnF": {"lib": "swift_runtime", "purpose": "Swift Array.append", "category": "runtime"},
    "$sSa12reserveCapacityyySiF": {"lib": "swift_runtime", "purpose": "Swift Array.reserveCapacity", "category": "runtime"},
    "$sSD17dictionaryLiteral": {"lib": "swift_runtime", "purpose": "Swift Dictionary literal", "category": "runtime"},
    "$sSh13_rawHashValue": {"lib": "swift_runtime", "purpose": "Swift Hashable._rawHashValue", "category": "runtime"},

    # CommonCrypto
    "_CCCrypt": {"lib": "CommonCrypto", "purpose": "symmetric encryption (AES/DES/3DES)", "category": "crypto"},
    "_CCCryptorCreate": {"lib": "CommonCrypto", "purpose": "crypto context creation", "category": "crypto"},
    "_CCCryptorCreateFromData": {"lib": "CommonCrypto", "purpose": "crypto context from data", "category": "crypto"},
    "_CCCryptorUpdate": {"lib": "CommonCrypto", "purpose": "incremental encrypt/decrypt", "category": "crypto"},
    "_CCCryptorFinal": {"lib": "CommonCrypto", "purpose": "finalize encrypt/decrypt", "category": "crypto"},
    "_CCCryptorRelease": {"lib": "CommonCrypto", "purpose": "crypto context release", "category": "crypto"},
    "_CCHmac": {"lib": "CommonCrypto", "purpose": "HMAC computation", "category": "crypto"},
    "_CCHmacInit": {"lib": "CommonCrypto", "purpose": "HMAC context init", "category": "crypto"},
    "_CCHmacUpdate": {"lib": "CommonCrypto", "purpose": "HMAC incremental update", "category": "crypto"},
    "_CCHmacFinal": {"lib": "CommonCrypto", "purpose": "HMAC finalize", "category": "crypto"},
    "_CC_SHA1": {"lib": "CommonCrypto", "purpose": "SHA-1 hash (one-shot)", "category": "crypto"},
    "_CC_SHA1_Init": {"lib": "CommonCrypto", "purpose": "SHA-1 context init", "category": "crypto"},
    "_CC_SHA1_Update": {"lib": "CommonCrypto", "purpose": "SHA-1 incremental update", "category": "crypto"},
    "_CC_SHA1_Final": {"lib": "CommonCrypto", "purpose": "SHA-1 finalize", "category": "crypto"},
    "_CC_SHA256": {"lib": "CommonCrypto", "purpose": "SHA-256 hash (one-shot)", "category": "crypto"},
    "_CC_SHA256_Init": {"lib": "CommonCrypto", "purpose": "SHA-256 context init", "category": "crypto"},
    "_CC_SHA256_Update": {"lib": "CommonCrypto", "purpose": "SHA-256 incremental update", "category": "crypto"},
    "_CC_SHA256_Final": {"lib": "CommonCrypto", "purpose": "SHA-256 finalize", "category": "crypto"},
    "_CC_SHA384": {"lib": "CommonCrypto", "purpose": "SHA-384 hash (one-shot)", "category": "crypto"},
    "_CC_SHA512": {"lib": "CommonCrypto", "purpose": "SHA-512 hash (one-shot)", "category": "crypto"},
    "_CC_MD5": {"lib": "CommonCrypto", "purpose": "MD5 hash (one-shot, insecure)", "category": "crypto"},
    "_CC_MD5_Init": {"lib": "CommonCrypto", "purpose": "MD5 context init", "category": "crypto"},
    "_CC_MD5_Update": {"lib": "CommonCrypto", "purpose": "MD5 incremental update", "category": "crypto"},
    "_CC_MD5_Final": {"lib": "CommonCrypto", "purpose": "MD5 finalize", "category": "crypto"},
    "_CCKeyDerivationPBKDF": {"lib": "CommonCrypto", "purpose": "PBKDF2 key derivation", "category": "crypto"},
    "_CCRandomGenerateBytes": {"lib": "CommonCrypto", "purpose": "cryptographic RNG", "category": "crypto"},

    # Security.framework
    "_SecItemAdd": {"lib": "Security", "purpose": "Keychain item storage", "category": "security"},
    "_SecItemCopyMatching": {"lib": "Security", "purpose": "Keychain item lookup", "category": "security"},
    "_SecItemUpdate": {"lib": "Security", "purpose": "Keychain item update", "category": "security"},
    "_SecItemDelete": {"lib": "Security", "purpose": "Keychain item deletion", "category": "security"},
    "_SecKeyCreateRandomKey": {"lib": "Security", "purpose": "random key generation", "category": "security"},
    "_SecKeyCreateSignature": {"lib": "Security", "purpose": "digital signature creation", "category": "security"},
    "_SecKeyVerifySignature": {"lib": "Security", "purpose": "digital signature verification", "category": "security"},
    "_SecKeyCreateEncryptedData": {"lib": "Security", "purpose": "public-key encryption", "category": "security"},
    "_SecKeyCreateDecryptedData": {"lib": "Security", "purpose": "public-key decryption", "category": "security"},
    "_SecKeyCopyPublicKey": {"lib": "Security", "purpose": "extract public key", "category": "security"},
    "_SecKeyCopyExternalRepresentation": {"lib": "Security", "purpose": "export key data", "category": "security"},
    "_SecKeyCreateWithData": {"lib": "Security", "purpose": "import key data", "category": "security"},
    "_SecCertificateCreateWithData": {"lib": "Security", "purpose": "certificate from DER data", "category": "security"},
    "_SecCertificateCopySubjectSummary": {"lib": "Security", "purpose": "certificate subject", "category": "security"},
    "_SecTrustCreateWithCertificates": {"lib": "Security", "purpose": "trust evaluation setup", "category": "security"},
    "_SecTrustEvaluateWithError": {"lib": "Security", "purpose": "certificate trust evaluation", "category": "security"},
    "_SecTrustSetPolicies": {"lib": "Security", "purpose": "set trust policies", "category": "security"},
    "_SecPolicyCreateSSL": {"lib": "Security", "purpose": "SSL trust policy", "category": "security"},
    "_SecCodeCheckValidity": {"lib": "Security", "purpose": "code signature validation", "category": "security"},
    "_SecCodeCopySigningInformation": {"lib": "Security", "purpose": "code signing info", "category": "security"},
    "_SecStaticCodeCreateWithPath": {"lib": "Security", "purpose": "static code ref from path", "category": "security"},
    "_SecAccessControlCreateWithFlags": {"lib": "Security", "purpose": "access control creation (biometric)", "category": "security"},

    # Endpoint Security (macOS antivirus/EDR)
    "_es_new_client": {"lib": "EndpointSecurity", "purpose": "ES client creation", "category": "security"},
    "_es_subscribe": {"lib": "EndpointSecurity", "purpose": "ES event subscription", "category": "security"},
    "_es_unsubscribe": {"lib": "EndpointSecurity", "purpose": "ES event unsubscription", "category": "security"},
    "_es_respond_auth_result": {"lib": "EndpointSecurity", "purpose": "ES auth response", "category": "security"},
    "_es_respond_flags_result": {"lib": "EndpointSecurity", "purpose": "ES flags response", "category": "security"},
    "_es_delete_client": {"lib": "EndpointSecurity", "purpose": "ES client teardown", "category": "security"},
    "_es_mute_process": {"lib": "EndpointSecurity", "purpose": "ES process muting", "category": "security"},
    "_es_clear_cache": {"lib": "EndpointSecurity", "purpose": "ES cache clear", "category": "security"},

    # Network Extension
    "_NEFilterDataProvider": {"lib": "NetworkExtension", "purpose": "network content filter", "category": "network"},
    "_NEDNSProxyProvider": {"lib": "NetworkExtension", "purpose": "DNS proxy provider", "category": "network"},
    "_NETunnelProviderManager": {"lib": "NetworkExtension", "purpose": "VPN tunnel manager", "category": "network"},
    "_NEVPNManager": {"lib": "NetworkExtension", "purpose": "VPN configuration manager", "category": "network"},

    # XPC
    "_xpc_connection_create_mach_service": {"lib": "libxpc", "purpose": "XPC Mach service connection", "category": "ipc"},
    "_xpc_connection_send_message": {"lib": "libxpc", "purpose": "XPC message send", "category": "ipc"},
    "_xpc_connection_send_message_with_reply": {"lib": "libxpc", "purpose": "XPC message send+reply", "category": "ipc"},
    "_xpc_connection_set_event_handler": {"lib": "libxpc", "purpose": "XPC event handler", "category": "ipc"},
    "_xpc_connection_resume": {"lib": "libxpc", "purpose": "XPC connection resume", "category": "ipc"},
    "_xpc_connection_cancel": {"lib": "libxpc", "purpose": "XPC connection cancel", "category": "ipc"},
    "_xpc_dictionary_create": {"lib": "libxpc", "purpose": "XPC dict creation", "category": "ipc"},
    "_xpc_dictionary_set_string": {"lib": "libxpc", "purpose": "XPC dict set string", "category": "ipc"},
    "_xpc_dictionary_get_string": {"lib": "libxpc", "purpose": "XPC dict get string", "category": "ipc"},
    "_xpc_dictionary_set_data": {"lib": "libxpc", "purpose": "XPC dict set data", "category": "ipc"},
    "_xpc_dictionary_get_data": {"lib": "libxpc", "purpose": "XPC dict get data", "category": "ipc"},

    # IOKit
    "_IOServiceGetMatchingServices": {"lib": "IOKit", "purpose": "IOKit service matching", "category": "hardware"},
    "_IOServiceMatching": {"lib": "IOKit", "purpose": "IOKit matching dict", "category": "hardware"},
    "_IORegistryEntryCreateCFProperty": {"lib": "IOKit", "purpose": "IOKit registry property", "category": "hardware"},
    "_IOObjectRelease": {"lib": "IOKit", "purpose": "IOKit object release", "category": "hardware"},
    "_IOServiceOpen": {"lib": "IOKit", "purpose": "IOKit service open", "category": "hardware"},
    "_IOServiceClose": {"lib": "IOKit", "purpose": "IOKit service close", "category": "hardware"},
    "_IOServiceGetMatchingService": {"lib": "IOKit", "purpose": "IOKit single service match", "category": "hardware"},
    "_IORegistryEntryCreateCFProperties": {"lib": "IOKit", "purpose": "IOKit all registry properties", "category": "hardware"},
    "_IOIteratorNext": {"lib": "IOKit", "purpose": "IOKit iterator advance", "category": "hardware"},
    "_IOIteratorReset": {"lib": "IOKit", "purpose": "IOKit iterator reset", "category": "hardware"},
    "_IOConnectCallMethod": {"lib": "IOKit", "purpose": "IOKit user client method call", "category": "hardware"},
    "_IOPMAssertionCreateWithName": {"lib": "IOKit", "purpose": "power management assertion create", "category": "hardware"},
    "_IOPMAssertionRelease": {"lib": "IOKit", "purpose": "power management assertion release", "category": "hardware"},

    # CoreFoundation -- String
    "_CFStringCreateWithCString": {"lib": "CoreFoundation", "purpose": "create CFString from C string", "category": "foundation"},
    "_CFStringGetCString": {"lib": "CoreFoundation", "purpose": "extract C string from CFString", "category": "foundation"},
    "_CFStringGetLength": {"lib": "CoreFoundation", "purpose": "get CFString length", "category": "foundation"},
    "_CFStringCreateCopy": {"lib": "CoreFoundation", "purpose": "copy immutable CFString", "category": "foundation"},
    "_CFStringCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFString", "category": "foundation"},
    "_CFStringAppend": {"lib": "CoreFoundation", "purpose": "append to mutable CFString", "category": "foundation"},
    "_CFStringCompare": {"lib": "CoreFoundation", "purpose": "compare two CFStrings", "category": "foundation"},

    # CoreFoundation -- Array
    "_CFArrayCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFArray", "category": "foundation"},
    "_CFArrayCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFArray", "category": "foundation"},
    "_CFArrayGetCount": {"lib": "CoreFoundation", "purpose": "get CFArray element count", "category": "foundation"},
    "_CFArrayGetValueAtIndex": {"lib": "CoreFoundation", "purpose": "get CFArray element at index", "category": "foundation"},
    "_CFArrayAppendValue": {"lib": "CoreFoundation", "purpose": "append to mutable CFArray", "category": "foundation"},
    "_CFArrayContainsValue": {"lib": "CoreFoundation", "purpose": "check CFArray membership", "category": "foundation"},

    # CoreFoundation -- Dictionary
    "_CFDictionaryCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFDictionary", "category": "foundation"},
    "_CFDictionaryCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFDictionary", "category": "foundation"},
    "_CFDictionaryGetValue": {"lib": "CoreFoundation", "purpose": "get CFDictionary value for key", "category": "foundation"},
    "_CFDictionarySetValue": {"lib": "CoreFoundation", "purpose": "set CFDictionary key-value pair", "category": "foundation"},
    "_CFDictionaryGetCount": {"lib": "CoreFoundation", "purpose": "get CFDictionary entry count", "category": "foundation"},
    "_CFDictionaryContainsKey": {"lib": "CoreFoundation", "purpose": "check CFDictionary key presence", "category": "foundation"},

    # CoreFoundation -- Data
    "_CFDataCreate": {"lib": "CoreFoundation", "purpose": "create immutable CFData", "category": "foundation"},
    "_CFDataCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFData", "category": "foundation"},
    "_CFDataGetBytePtr": {"lib": "CoreFoundation", "purpose": "get CFData byte pointer", "category": "foundation"},
    "_CFDataGetLength": {"lib": "CoreFoundation", "purpose": "get CFData length", "category": "foundation"},
    "_CFDataAppendBytes": {"lib": "CoreFoundation", "purpose": "append bytes to mutable CFData", "category": "foundation"},

    # CoreFoundation -- Number / Boolean
    "_CFNumberCreate": {"lib": "CoreFoundation", "purpose": "create CFNumber from value", "category": "foundation"},
    "_CFNumberGetValue": {"lib": "CoreFoundation", "purpose": "extract value from CFNumber", "category": "foundation"},
    "_CFBooleanGetValue": {"lib": "CoreFoundation", "purpose": "extract bool from CFBoolean", "category": "foundation"},

    # CoreFoundation -- URL
    "_CFURLCreateWithString": {"lib": "CoreFoundation", "purpose": "create CFURL from string", "category": "foundation"},
    "_CFURLCreateWithFileSystemPath": {"lib": "CoreFoundation", "purpose": "create CFURL from file path", "category": "foundation"},
    "_CFURLGetString": {"lib": "CoreFoundation", "purpose": "get string from CFURL", "category": "foundation"},

    # CoreFoundation -- Preferences
    "_CFPreferencesCopyValue": {"lib": "CoreFoundation", "purpose": "read preference value", "category": "foundation"},
    "_CFPreferencesSetValue": {"lib": "CoreFoundation", "purpose": "write preference value", "category": "foundation"},
    "_CFPreferencesSynchronize": {"lib": "CoreFoundation", "purpose": "sync preferences to disk", "category": "foundation"},

    # CoreFoundation -- Notification Center
    "_CFNotificationCenterGetDistributedCenter": {"lib": "CoreFoundation", "purpose": "get distributed notification center", "category": "foundation"},
    "_CFNotificationCenterAddObserver": {"lib": "CoreFoundation", "purpose": "register notification observer", "category": "foundation"},
    "_CFNotificationCenterPostNotification": {"lib": "CoreFoundation", "purpose": "post notification", "category": "foundation"},

    # CoreFoundation -- RunLoop
    "_CFRunLoopGetCurrent": {"lib": "CoreFoundation", "purpose": "get current run loop", "category": "foundation"},
    "_CFRunLoopGetMain": {"lib": "CoreFoundation", "purpose": "get main run loop", "category": "foundation"},
    "_CFRunLoopRun": {"lib": "CoreFoundation", "purpose": "run the current run loop", "category": "foundation"},
    "_CFRunLoopStop": {"lib": "CoreFoundation", "purpose": "stop a run loop", "category": "foundation"},
    "_CFRunLoopAddSource": {"lib": "CoreFoundation", "purpose": "add source to run loop", "category": "foundation"},
    "_CFRunLoopAddTimer": {"lib": "CoreFoundation", "purpose": "add timer to run loop", "category": "foundation"},

    # CoreFoundation -- Bundle
    "_CFBundleGetMainBundle": {"lib": "CoreFoundation", "purpose": "get main application bundle", "category": "foundation"},
    "_CFBundleCopyResourceURL": {"lib": "CoreFoundation", "purpose": "get bundle resource URL", "category": "foundation"},
    "_CFBundleGetIdentifier": {"lib": "CoreFoundation", "purpose": "get bundle identifier", "category": "foundation"},
    "_CFBundleCopyBundleURL": {"lib": "CoreFoundation", "purpose": "get bundle URL", "category": "foundation"},

    # CoreFoundation -- Memory / Utility
    "_CFRelease": {"lib": "CoreFoundation", "purpose": "release CF object", "category": "foundation"},
    "_CFRetain": {"lib": "CoreFoundation", "purpose": "retain CF object", "category": "foundation"},
    "_CFGetRetainCount": {"lib": "CoreFoundation", "purpose": "get CF object retain count", "category": "foundation"},
    "_CFEqual": {"lib": "CoreFoundation", "purpose": "compare CF objects for equality", "category": "foundation"},
    "_CFHash": {"lib": "CoreFoundation", "purpose": "compute CF object hash", "category": "foundation"},
    "_CFCopyDescription": {"lib": "CoreFoundation", "purpose": "CF object description string", "category": "foundation"},
    "_CFShow": {"lib": "CoreFoundation", "purpose": "print CF object to stderr", "category": "foundation"},
    "_CFAllocatorAllocate": {"lib": "CoreFoundation", "purpose": "CF allocator allocate", "category": "foundation"},
    "_CFAllocatorDeallocate": {"lib": "CoreFoundation", "purpose": "CF allocator deallocate", "category": "foundation"},
    "_kCFBooleanTrue": {"lib": "CoreFoundation", "purpose": "CFBoolean true constant", "category": "foundation"},
    "_kCFBooleanFalse": {"lib": "CoreFoundation", "purpose": "CFBoolean false constant", "category": "foundation"},
    "_kCFAllocatorDefault": {"lib": "CoreFoundation", "purpose": "default CF allocator", "category": "foundation"},

    # Foundation / ObjC runtime -- eksik olanlar
    "_objc_exception_throw": {"lib": "libobjc", "purpose": "ObjC exception throw", "category": "runtime"},
    "_objc_setAssociatedObject": {"lib": "libobjc", "purpose": "ObjC associated object set", "category": "runtime"},
    "_objc_getAssociatedObject": {"lib": "libobjc", "purpose": "ObjC associated object get", "category": "runtime"},
    "_objc_removeAssociatedObjects": {"lib": "libobjc", "purpose": "ObjC remove all associated objects", "category": "runtime"},
    "_objc_sync_enter": {"lib": "libobjc", "purpose": "ObjC @synchronized enter", "category": "runtime"},
    "_objc_sync_exit": {"lib": "libobjc", "purpose": "ObjC @synchronized exit", "category": "runtime"},
    "_class_getInstanceVariable": {"lib": "libobjc", "purpose": "ObjC instance variable lookup", "category": "runtime"},
    "_method_getImplementation": {"lib": "libobjc", "purpose": "ObjC get method IMP pointer", "category": "runtime"},
    "_method_setImplementation": {"lib": "libobjc", "purpose": "ObjC set method IMP pointer", "category": "runtime"},
    "_sel_getUid": {"lib": "libobjc", "purpose": "ObjC selector UID lookup", "category": "runtime"},
    "_object_setClass": {"lib": "libobjc", "purpose": "ObjC change object isa class", "category": "runtime"},
    "_object_getInstanceVariable": {"lib": "libobjc", "purpose": "ObjC get instance variable value", "category": "runtime"},
    "_protocol_getMethodDescription": {"lib": "libobjc", "purpose": "ObjC protocol method description", "category": "runtime"},
    "_class_conformsToProtocol": {"lib": "libobjc", "purpose": "ObjC class protocol conformance", "category": "runtime"},
    "_property_getName": {"lib": "libobjc", "purpose": "ObjC property name", "category": "runtime"},
    "_property_getAttributes": {"lib": "libobjc", "purpose": "ObjC property attributes string", "category": "runtime"},
    "_class_copyPropertyList": {"lib": "libobjc", "purpose": "ObjC copy all class properties", "category": "runtime"},
    "_ivar_getName": {"lib": "libobjc", "purpose": "ObjC ivar name", "category": "runtime"},
    "_ivar_getOffset": {"lib": "libobjc", "purpose": "ObjC ivar memory offset", "category": "runtime"},
    "_class_copyIvarList": {"lib": "libobjc", "purpose": "ObjC copy all class ivars", "category": "runtime"},
    "_NSLogv": {"lib": "Foundation", "purpose": "ObjC variadic console logging", "category": "runtime"},

    # Swift runtime -- eksik olanlar
    "_swift_isUniquelyReferenced": {"lib": "swift_runtime", "purpose": "Swift COW uniqueness check", "category": "runtime"},
    "_swift_allocError": {"lib": "swift_runtime", "purpose": "Swift error box allocation", "category": "runtime"},
    "_swift_deallocError": {"lib": "swift_runtime", "purpose": "Swift error box deallocation", "category": "runtime"},
    "_swift_dynamicCastClass": {"lib": "swift_runtime", "purpose": "Swift class-only dynamic cast", "category": "runtime"},
    "_swift_task_escalate": {"lib": "swift_runtime", "purpose": "Swift task priority escalation", "category": "concurrency"},
    "_swift_job_run": {"lib": "swift_runtime", "purpose": "Swift concurrency job run", "category": "concurrency"},
    "_swift_task_enqueueGlobal": {"lib": "swift_runtime", "purpose": "Swift enqueue task to global executor", "category": "concurrency"},
    "$sSS": {"lib": "swift_runtime", "purpose": "Swift String type (mangled prefix)", "category": "runtime"},
    "$sSa": {"lib": "swift_runtime", "purpose": "Swift Array type (mangled prefix)", "category": "runtime"},
    "$sSD": {"lib": "swift_runtime", "purpose": "Swift Dictionary type (mangled prefix)", "category": "runtime"},

    # Grand Central Dispatch -- eksik olanlar
    "_dispatch_source_set_event_handler": {"lib": "libdispatch", "purpose": "set dispatch source event handler", "category": "concurrency"},
    "_dispatch_source_set_cancel_handler": {"lib": "libdispatch", "purpose": "set dispatch source cancel handler", "category": "concurrency"},
    "_dispatch_source_cancel": {"lib": "libdispatch", "purpose": "cancel dispatch source", "category": "concurrency"},
    "_dispatch_resume": {"lib": "libdispatch", "purpose": "resume dispatch object", "category": "concurrency"},
    "_dispatch_data_get_size": {"lib": "libdispatch", "purpose": "get dispatch data size", "category": "concurrency"},
    "_dispatch_data_apply": {"lib": "libdispatch", "purpose": "iterate dispatch data regions", "category": "concurrency"},
    "_dispatch_io_read": {"lib": "libdispatch", "purpose": "dispatch I/O read", "category": "concurrency"},
    "_dispatch_io_write": {"lib": "libdispatch", "purpose": "dispatch I/O write", "category": "concurrency"},
    "_dispatch_io_close": {"lib": "libdispatch", "purpose": "dispatch I/O channel close", "category": "concurrency"},

    # Security.framework -- eksik olanlar
    "_SecKeyGetBlockSize": {"lib": "Security", "purpose": "get key block size", "category": "security"},
    "_SecCertificateCopyData": {"lib": "Security", "purpose": "get certificate DER data", "category": "security"},
    "_SecTrustGetCertificateCount": {"lib": "Security", "purpose": "get trust chain cert count", "category": "security"},
    "_SecTrustGetCertificateAtIndex": {"lib": "Security", "purpose": "get cert from trust chain by index", "category": "security"},
    "_SecRandomCopyBytes": {"lib": "Security", "purpose": "generate secure random bytes", "category": "security"},
    "_SSLCreateContext": {"lib": "Security", "purpose": "create SSL/TLS context (deprecated)", "category": "security"},
    "_SSLSetIOFuncs": {"lib": "Security", "purpose": "set SSL I/O callbacks", "category": "security"},
    "_SSLHandshake": {"lib": "Security", "purpose": "perform SSL/TLS handshake", "category": "security"},
    "_SSLRead": {"lib": "Security", "purpose": "read from SSL connection", "category": "security"},
    "_SSLWrite": {"lib": "Security", "purpose": "write to SSL connection", "category": "security"},
    "_SSLClose": {"lib": "Security", "purpose": "close SSL connection", "category": "security"},
}


# ---------------------------------------------------------------------------
# macos_networking (~51 entry) — CFNetwork (CFSocket/CFStream/CFHTTPMessage)
# + Network.framework (nw_*). Kaynak: signature_db.py satir 2655-2706.
# ---------------------------------------------------------------------------
_MACOS_NETWORKING_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_CFSocketCreate": {"lib": "CFNetwork", "purpose": "create CFSocket", "category": "network"},
    "_CFSocketCreateWithNative": {"lib": "CFNetwork", "purpose": "CFSocket from native fd", "category": "network"},
    "_CFSocketGetNative": {"lib": "CFNetwork", "purpose": "get native fd from CFSocket", "category": "network"},
    "_CFSocketInvalidate": {"lib": "CFNetwork", "purpose": "invalidate CFSocket", "category": "network"},
    "_CFSocketSetAddress": {"lib": "CFNetwork", "purpose": "set CFSocket address", "category": "network"},
    "_CFSocketCopyAddress": {"lib": "CFNetwork", "purpose": "copy CFSocket address", "category": "network"},
    "_CFSocketCreateRunLoopSource": {"lib": "CFNetwork", "purpose": "CFSocket run loop source", "category": "network"},
    "_CFStreamCreatePairWithSocketToHost": {"lib": "CFNetwork", "purpose": "create stream pair to host", "category": "network"},
    "_CFReadStreamOpen": {"lib": "CFNetwork", "purpose": "open CFReadStream", "category": "network"},
    "_CFReadStreamClose": {"lib": "CFNetwork", "purpose": "close CFReadStream", "category": "network"},
    "_CFReadStreamRead": {"lib": "CFNetwork", "purpose": "read from CFReadStream", "category": "network"},
    "_CFReadStreamHasBytesAvailable": {"lib": "CFNetwork", "purpose": "check CFReadStream bytes", "category": "network"},
    "_CFWriteStreamOpen": {"lib": "CFNetwork", "purpose": "open CFWriteStream", "category": "network"},
    "_CFWriteStreamClose": {"lib": "CFNetwork", "purpose": "close CFWriteStream", "category": "network"},
    "_CFWriteStreamWrite": {"lib": "CFNetwork", "purpose": "write to CFWriteStream", "category": "network"},
    "_CFWriteStreamCanAcceptBytes": {"lib": "CFNetwork", "purpose": "check CFWriteStream capacity", "category": "network"},
    "_CFHTTPMessageCreateRequest": {"lib": "CFNetwork", "purpose": "create HTTP request message", "category": "network"},
    "_CFHTTPMessageCreateResponse": {"lib": "CFNetwork", "purpose": "create HTTP response message", "category": "network"},
    "_CFHTTPMessageSetBody": {"lib": "CFNetwork", "purpose": "set HTTP message body", "category": "network"},
    "_CFHTTPMessageSetHeaderFieldValue": {"lib": "CFNetwork", "purpose": "set HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyHeaderFieldValue": {"lib": "CFNetwork", "purpose": "get HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyAllHeaderFields": {"lib": "CFNetwork", "purpose": "get all HTTP headers", "category": "network"},
    "_CFHTTPMessageGetResponseStatusCode": {"lib": "CFNetwork", "purpose": "get HTTP status code", "category": "network"},
    "_CFHTTPMessageCopyBody": {"lib": "CFNetwork", "purpose": "get HTTP message body", "category": "network"},
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data from connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "connection state handler", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "listener state handler", "category": "network"},
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP params", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP params", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint", "category": "network"},
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel path monitor", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
}


# ---------------------------------------------------------------------------
# ipc_xpc (~52 entry) — XPC connection/dictionary/array primitives + NSXPC
# Foundation class refs. Kaynak: signature_db.py satir 2713-2765.
# ---------------------------------------------------------------------------
_IPC_XPC_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_xpc_connection_create": {"lib": "libxpc", "purpose": "create XPC connection", "category": "ipc"},
    "_xpc_connection_suspend": {"lib": "libxpc", "purpose": "suspend XPC connection", "category": "ipc"},
    "_xpc_connection_send_message_with_reply_sync": {"lib": "libxpc", "purpose": "XPC send + sync reply", "category": "ipc"},
    "_xpc_connection_set_target_queue": {"lib": "libxpc", "purpose": "XPC set target queue", "category": "ipc"},
    "_xpc_connection_get_pid": {"lib": "libxpc", "purpose": "XPC get peer PID", "category": "ipc"},
    "_xpc_connection_get_euid": {"lib": "libxpc", "purpose": "XPC get peer EUID", "category": "ipc"},
    "_xpc_connection_get_egid": {"lib": "libxpc", "purpose": "XPC get peer EGID", "category": "ipc"},
    "_xpc_dictionary_create_reply": {"lib": "libxpc", "purpose": "create XPC reply dict", "category": "ipc"},
    "_xpc_dictionary_set_int64": {"lib": "libxpc", "purpose": "XPC dict set int64", "category": "ipc"},
    "_xpc_dictionary_set_uint64": {"lib": "libxpc", "purpose": "XPC dict set uint64", "category": "ipc"},
    "_xpc_dictionary_set_bool": {"lib": "libxpc", "purpose": "XPC dict set bool", "category": "ipc"},
    "_xpc_dictionary_set_double": {"lib": "libxpc", "purpose": "XPC dict set double", "category": "ipc"},
    "_xpc_dictionary_set_value": {"lib": "libxpc", "purpose": "XPC dict set value", "category": "ipc"},
    "_xpc_dictionary_get_int64": {"lib": "libxpc", "purpose": "XPC dict get int64", "category": "ipc"},
    "_xpc_dictionary_get_uint64": {"lib": "libxpc", "purpose": "XPC dict get uint64", "category": "ipc"},
    "_xpc_dictionary_get_bool": {"lib": "libxpc", "purpose": "XPC dict get bool", "category": "ipc"},
    "_xpc_dictionary_get_double": {"lib": "libxpc", "purpose": "XPC dict get double", "category": "ipc"},
    "_xpc_dictionary_get_value": {"lib": "libxpc", "purpose": "XPC dict get value", "category": "ipc"},
    "_xpc_dictionary_get_count": {"lib": "libxpc", "purpose": "XPC dict entry count", "category": "ipc"},
    "_xpc_dictionary_apply": {"lib": "libxpc", "purpose": "XPC dict iterate", "category": "ipc"},
    "_xpc_array_create": {"lib": "libxpc", "purpose": "create XPC array", "category": "ipc"},
    "_xpc_array_append_value": {"lib": "libxpc", "purpose": "XPC array append", "category": "ipc"},
    "_xpc_array_get_count": {"lib": "libxpc", "purpose": "XPC array count", "category": "ipc"},
    "_xpc_array_get_value": {"lib": "libxpc", "purpose": "XPC array get value", "category": "ipc"},
    "_xpc_array_apply": {"lib": "libxpc", "purpose": "XPC array iterate", "category": "ipc"},
    "_xpc_string_create": {"lib": "libxpc", "purpose": "create XPC string", "category": "ipc"},
    "_xpc_string_get_string_ptr": {"lib": "libxpc", "purpose": "get XPC string ptr", "category": "ipc"},
    "_xpc_string_get_length": {"lib": "libxpc", "purpose": "get XPC string length", "category": "ipc"},
    "_xpc_int64_create": {"lib": "libxpc", "purpose": "create XPC int64", "category": "ipc"},
    "_xpc_int64_get_value": {"lib": "libxpc", "purpose": "get XPC int64 value", "category": "ipc"},
    "_xpc_uint64_create": {"lib": "libxpc", "purpose": "create XPC uint64", "category": "ipc"},
    "_xpc_uint64_get_value": {"lib": "libxpc", "purpose": "get XPC uint64 value", "category": "ipc"},
    "_xpc_bool_create": {"lib": "libxpc", "purpose": "create XPC bool", "category": "ipc"},
    "_xpc_bool_get_value": {"lib": "libxpc", "purpose": "get XPC bool value", "category": "ipc"},
    "_xpc_data_create": {"lib": "libxpc", "purpose": "create XPC data", "category": "ipc"},
    "_xpc_data_get_bytes_ptr": {"lib": "libxpc", "purpose": "get XPC data bytes", "category": "ipc"},
    "_xpc_data_get_length": {"lib": "libxpc", "purpose": "get XPC data length", "category": "ipc"},
    "_xpc_double_create": {"lib": "libxpc", "purpose": "create XPC double", "category": "ipc"},
    "_xpc_double_get_value": {"lib": "libxpc", "purpose": "get XPC double value", "category": "ipc"},
    "_xpc_date_create": {"lib": "libxpc", "purpose": "create XPC date", "category": "ipc"},
    "_xpc_date_get_value": {"lib": "libxpc", "purpose": "get XPC date value", "category": "ipc"},
    "_xpc_release": {"lib": "libxpc", "purpose": "release XPC object", "category": "ipc"},
    "_xpc_retain": {"lib": "libxpc", "purpose": "retain XPC object", "category": "ipc"},
    "_xpc_copy_description": {"lib": "libxpc", "purpose": "XPC object description", "category": "ipc"},
    "_xpc_get_type": {"lib": "libxpc", "purpose": "get XPC object type", "category": "ipc"},
    "_xpc_equal": {"lib": "libxpc", "purpose": "compare XPC objects", "category": "ipc"},
    "_xpc_hash": {"lib": "libxpc", "purpose": "XPC object hash", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCConnection": {"lib": "Foundation", "purpose": "NSXPCConnection class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCInterface": {"lib": "Foundation", "purpose": "NSXPCInterface class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCListener": {"lib": "Foundation", "purpose": "NSXPCListener class ref", "category": "ipc"},
    "_OBJC_CLASS_$_NSXPCListenerEndpoint": {"lib": "Foundation", "purpose": "NSXPCListenerEndpoint class ref", "category": "ipc"},
}


# ---------------------------------------------------------------------------
# apple_coredata (~16 entry) — CoreData persistence stack (managed object,
# fetch request, persistent container). Kaynak: signature_db.py 3345-3362.
# ---------------------------------------------------------------------------
_APPLE_COREDATA_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_NSManagedObjectContext": {"lib": "CoreData", "purpose": "managed object context class", "category": "persistence"},
    "_OBJC_CLASS_$_NSManagedObjectModel": {"lib": "CoreData", "purpose": "managed object model class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentStoreCoordinator": {"lib": "CoreData", "purpose": "persistent store coordinator class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentContainer": {"lib": "CoreData", "purpose": "persistent container class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPersistentCloudKitContainer": {"lib": "CoreData", "purpose": "CloudKit persistent container class", "category": "persistence"},
    "_OBJC_CLASS_$_NSFetchRequest": {"lib": "CoreData", "purpose": "fetch request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSEntityDescription": {"lib": "CoreData", "purpose": "entity description class", "category": "persistence"},
    "_OBJC_CLASS_$_NSPredicate": {"lib": "Foundation", "purpose": "query predicate class", "category": "persistence"},
    "_OBJC_CLASS_$_NSSortDescriptor": {"lib": "Foundation", "purpose": "sort descriptor class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchDeleteRequest": {"lib": "CoreData", "purpose": "batch delete request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchInsertRequest": {"lib": "CoreData", "purpose": "batch insert request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSBatchUpdateRequest": {"lib": "CoreData", "purpose": "batch update request class", "category": "persistence"},
    "_OBJC_CLASS_$_NSFetchedResultsController": {"lib": "CoreData", "purpose": "fetched results controller class", "category": "persistence"},
    "_OBJC_CLASS_$_NSManagedObject": {"lib": "CoreData", "purpose": "managed object base class", "category": "persistence"},
    "_OBJC_CLASS_$_NSMigrationManager": {"lib": "CoreData", "purpose": "model migration manager class", "category": "persistence"},
    "_OBJC_CLASS_$_NSMappingModel": {"lib": "CoreData", "purpose": "model mapping class", "category": "persistence"},
}


# ---------------------------------------------------------------------------
# apple_webkit (~13 entry) — WKWebView modern web view + delegate protocols.
# Kaynak: signature_db.py satir 3369-3383.
# ---------------------------------------------------------------------------
_APPLE_WEBKIT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_WKWebView": {"lib": "WebKit", "purpose": "modern web view class", "category": "ui"},
    "_OBJC_CLASS_$_WKWebViewConfiguration": {"lib": "WebKit", "purpose": "web view configuration class", "category": "ui"},
    "_OBJC_CLASS_$_WKUserContentController": {"lib": "WebKit", "purpose": "user content controller class", "category": "ui"},
    "_OBJC_CLASS_$_WKUserScript": {"lib": "WebKit", "purpose": "injected user script class", "category": "ui"},
    "_OBJC_CLASS_$_WKScriptMessage": {"lib": "WebKit", "purpose": "JS-to-native message class", "category": "ui"},
    "_OBJC_CLASS_$_WKPreferences": {"lib": "WebKit", "purpose": "web view preferences class", "category": "ui"},
    "_OBJC_CLASS_$_WKProcessPool": {"lib": "WebKit", "purpose": "web process pool class", "category": "ui"},
    "_OBJC_CLASS_$_WKWebsiteDataStore": {"lib": "WebKit", "purpose": "website data store class", "category": "ui"},
    "_OBJC_CLASS_$_WKHTTPCookieStore": {"lib": "WebKit", "purpose": "HTTP cookie store class", "category": "ui"},
    "_OBJC_CLASS_$_WKContentRuleListStore": {"lib": "WebKit", "purpose": "content blocker rule list store", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKNavigationDelegate": {"lib": "WebKit", "purpose": "navigation delegate protocol", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKUIDelegate": {"lib": "WebKit", "purpose": "UI delegate protocol", "category": "ui"},
    "_OBJC_PROTOCOL_$_WKScriptMessageHandler": {"lib": "WebKit", "purpose": "script message handler protocol", "category": "ui"},
}


# ---------------------------------------------------------------------------
# apple_corelocation (~9 entry) — CoreLocation manager + delegate.
# Kaynak: signature_db.py satir 3390-3400.
# ---------------------------------------------------------------------------
_APPLE_CORELOCATION_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_CLLocationManager": {"lib": "CoreLocation", "purpose": "location manager class", "category": "location"},
    "_OBJC_CLASS_$_CLLocation": {"lib": "CoreLocation", "purpose": "location data class", "category": "location"},
    "_OBJC_CLASS_$_CLGeocoder": {"lib": "CoreLocation", "purpose": "geocoder class", "category": "location"},
    "_OBJC_CLASS_$_CLPlacemark": {"lib": "CoreLocation", "purpose": "placemark class", "category": "location"},
    "_OBJC_CLASS_$_CLCircularRegion": {"lib": "CoreLocation", "purpose": "circular geofence region class", "category": "location"},
    "_OBJC_CLASS_$_CLBeaconRegion": {"lib": "CoreLocation", "purpose": "iBeacon region class", "category": "location"},
    "_OBJC_CLASS_$_CLVisit": {"lib": "CoreLocation", "purpose": "visit monitoring class", "category": "location"},
    "_CLLocationCoordinate2DMake": {"lib": "CoreLocation", "purpose": "create CLLocationCoordinate2D", "category": "location"},
    "_OBJC_PROTOCOL_$_CLLocationManagerDelegate": {"lib": "CoreLocation", "purpose": "location manager delegate protocol", "category": "location"},
}


# ---------------------------------------------------------------------------
# apple_corebluetooth (~11 entry) — BLE central/peripheral + delegates.
# Kaynak: signature_db.py satir 3407-3419.
# ---------------------------------------------------------------------------
_APPLE_COREBLUETOOTH_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_CBCentralManager": {"lib": "CoreBluetooth", "purpose": "BLE central manager class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBPeripheral": {"lib": "CoreBluetooth", "purpose": "BLE peripheral class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBCharacteristic": {"lib": "CoreBluetooth", "purpose": "BLE characteristic class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBService": {"lib": "CoreBluetooth", "purpose": "BLE service class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBPeripheralManager": {"lib": "CoreBluetooth", "purpose": "BLE peripheral manager class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBDescriptor": {"lib": "CoreBluetooth", "purpose": "BLE descriptor class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBUUID": {"lib": "CoreBluetooth", "purpose": "BLE UUID class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBMutableCharacteristic": {"lib": "CoreBluetooth", "purpose": "BLE mutable characteristic class", "category": "bluetooth"},
    "_OBJC_CLASS_$_CBMutableService": {"lib": "CoreBluetooth", "purpose": "BLE mutable service class", "category": "bluetooth"},
    "_OBJC_PROTOCOL_$_CBCentralManagerDelegate": {"lib": "CoreBluetooth", "purpose": "BLE central delegate protocol", "category": "bluetooth"},
    "_OBJC_PROTOCOL_$_CBPeripheralDelegate": {"lib": "CoreBluetooth", "purpose": "BLE peripheral delegate protocol", "category": "bluetooth"},
}


# ---------------------------------------------------------------------------
# apple_storekit (~10 entry) — In-app purchase products/payments + Apple Music
# cloud service + delegates. Kaynak: signature_db.py satir 3426-3437.
# ---------------------------------------------------------------------------
_APPLE_STOREKIT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_SKProductsRequest": {"lib": "StoreKit", "purpose": "IAP products request class", "category": "iap"},
    "_OBJC_CLASS_$_SKPaymentQueue": {"lib": "StoreKit", "purpose": "IAP payment queue class", "category": "iap"},
    "_OBJC_CLASS_$_SKPayment": {"lib": "StoreKit", "purpose": "IAP payment class", "category": "iap"},
    "_OBJC_CLASS_$_SKProduct": {"lib": "StoreKit", "purpose": "IAP product class", "category": "iap"},
    "_OBJC_CLASS_$_SKReceiptRefreshRequest": {"lib": "StoreKit", "purpose": "IAP receipt refresh request class", "category": "iap"},
    "_OBJC_CLASS_$_SKPaymentTransaction": {"lib": "StoreKit", "purpose": "IAP payment transaction class", "category": "iap"},
    "_OBJC_CLASS_$_SKStoreProductViewController": {"lib": "StoreKit", "purpose": "App Store product view controller", "category": "iap"},
    "_OBJC_CLASS_$_SKCloudServiceController": {"lib": "StoreKit", "purpose": "Apple Music cloud service controller", "category": "iap"},
    "_OBJC_PROTOCOL_$_SKProductsRequestDelegate": {"lib": "StoreKit", "purpose": "products request delegate protocol", "category": "iap"},
    "_OBJC_PROTOCOL_$_SKPaymentTransactionObserver": {"lib": "StoreKit", "purpose": "payment transaction observer protocol", "category": "iap"},
}


# ---------------------------------------------------------------------------
# apple_usernotifications (~11 entry) — UNUserNotificationCenter + triggers
# + delegate. Kaynak: signature_db.py satir 3444-3456.
# ---------------------------------------------------------------------------
_APPLE_USERNOTIFICATIONS_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_UNUserNotificationCenter": {"lib": "UserNotifications", "purpose": "notification center class", "category": "notification"},
    "_OBJC_CLASS_$_UNMutableNotificationContent": {"lib": "UserNotifications", "purpose": "mutable notification content class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationRequest": {"lib": "UserNotifications", "purpose": "notification request class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationAction": {"lib": "UserNotifications", "purpose": "notification action class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationCategory": {"lib": "UserNotifications", "purpose": "notification category class", "category": "notification"},
    "_OBJC_CLASS_$_UNTimeIntervalNotificationTrigger": {"lib": "UserNotifications", "purpose": "time interval trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNCalendarNotificationTrigger": {"lib": "UserNotifications", "purpose": "calendar trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNLocationNotificationTrigger": {"lib": "UserNotifications", "purpose": "location trigger class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationSound": {"lib": "UserNotifications", "purpose": "notification sound class", "category": "notification"},
    "_OBJC_CLASS_$_UNNotificationAttachment": {"lib": "UserNotifications", "purpose": "notification attachment class", "category": "notification"},
    "_OBJC_PROTOCOL_$_UNUserNotificationCenterDelegate": {"lib": "UserNotifications", "purpose": "notification center delegate protocol", "category": "notification"},
}


# ---------------------------------------------------------------------------
# apple_network_framework (~38 entry) — modern Network.framework C API
# (nw_connection / nw_listener / nw_endpoint / nw_path_monitor). Tarihsel
# olarak _MACOS_NETWORKING ile bir kisim entry'ler ortusur; ayri tutuldu.
# Kaynak: signature_db.py satir 3463-3503.
# ---------------------------------------------------------------------------
_APPLE_NETWORK_FRAMEWORK_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Connection lifecycle
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data on connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message on connection", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "set connection state handler", "category": "network"},
    "_nw_connection_copy_endpoint": {"lib": "Network", "purpose": "copy connection endpoint", "category": "network"},
    "_nw_connection_copy_current_path": {"lib": "Network", "purpose": "copy current network path", "category": "network"},
    "_nw_connection_restart": {"lib": "Network", "purpose": "restart network connection", "category": "network"},
    # Listener
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "set listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "set listener state handler", "category": "network"},
    # Endpoint & parameters
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_create_bonjour_service": {"lib": "Network", "purpose": "create Bonjour endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP parameters", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP parameters", "category": "network"},
    "_nw_parameters_create": {"lib": "Network", "purpose": "create custom network parameters", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint on parameters", "category": "network"},
    # Path monitor
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create network path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start network path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel network path monitor", "category": "network"},
    "_nw_path_monitor_set_queue": {"lib": "Network", "purpose": "set path monitor dispatch queue", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "set path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
    "_nw_path_uses_interface_type": {"lib": "Network", "purpose": "check if path uses interface type", "category": "network"},
    "_nw_path_is_expensive": {"lib": "Network", "purpose": "check if path is expensive (cellular)", "category": "network"},
    "_nw_path_is_constrained": {"lib": "Network", "purpose": "check if path is constrained (low data)", "category": "network"},
}


# ---------------------------------------------------------------------------
# apple_endpoint_security_ext (~14 entry) — EndpointSecurity extended
# (path/process muting, message handling, exec arg/env extraction).
# Kaynak: signature_db.py satir 3510-3525.
# ---------------------------------------------------------------------------
_APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_es_mute_path": {"lib": "EndpointSecurity", "purpose": "ES path muting", "category": "security"},
    "_es_mute_path_prefix": {"lib": "EndpointSecurity", "purpose": "ES path prefix muting", "category": "security"},
    "_es_unmute_all_paths": {"lib": "EndpointSecurity", "purpose": "ES unmute all paths", "category": "security"},
    "_es_unmute_all_target_paths": {"lib": "EndpointSecurity", "purpose": "ES unmute all target paths", "category": "security"},
    "_es_mute_process_events": {"lib": "EndpointSecurity", "purpose": "ES mute specific process events", "category": "security"},
    "_es_respond_result": {"lib": "EndpointSecurity", "purpose": "ES respond with result", "category": "security"},
    "_es_message_size": {"lib": "EndpointSecurity", "purpose": "ES get message size", "category": "security"},
    "_es_retain_message": {"lib": "EndpointSecurity", "purpose": "ES retain message", "category": "security"},
    "_es_release_message": {"lib": "EndpointSecurity", "purpose": "ES release message", "category": "security"},
    "_es_copy_message": {"lib": "EndpointSecurity", "purpose": "ES copy message", "category": "security"},
    "_es_exec_arg_count": {"lib": "EndpointSecurity", "purpose": "ES get exec argument count", "category": "security"},
    "_es_exec_arg": {"lib": "EndpointSecurity", "purpose": "ES get exec argument", "category": "security"},
    "_es_exec_env_count": {"lib": "EndpointSecurity", "purpose": "ES get exec env count", "category": "security"},
    "_es_exec_env": {"lib": "EndpointSecurity", "purpose": "ES get exec environment variable", "category": "security"},
}


# ---------------------------------------------------------------------------
# apple_systemextensions (~3 entry) — OSSystemExtension request/manager.
# Kaynak: signature_db.py satir 3532-3536.
# ---------------------------------------------------------------------------
_APPLE_SYSTEMEXTENSIONS_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_OBJC_CLASS_$_OSSystemExtensionRequest": {"lib": "SystemExtensions", "purpose": "system extension request class", "category": "security"},
    "_OBJC_CLASS_$_OSSystemExtensionManager": {"lib": "SystemExtensions", "purpose": "system extension manager class", "category": "security"},
    "_OBJC_PROTOCOL_$_OSSystemExtensionRequestDelegate": {"lib": "SystemExtensions", "purpose": "system extension delegate protocol", "category": "security"},
}


# ---------------------------------------------------------------------------
# apple_appkit (~84 entry) — AppKit (macOS UI) classes + ortak Foundation
# class refs. Kaynak: signature_db.py satir 3543-3629.
# ---------------------------------------------------------------------------
_APPLE_APPKIT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Application & Window
    "_OBJC_CLASS_$_NSApplication": {"lib": "AppKit", "purpose": "application singleton class", "category": "ui"},
    "_OBJC_CLASS_$_NSWindow": {"lib": "AppKit", "purpose": "window class", "category": "ui"},
    "_OBJC_CLASS_$_NSView": {"lib": "AppKit", "purpose": "base view class", "category": "ui"},
    "_OBJC_CLASS_$_NSViewController": {"lib": "AppKit", "purpose": "view controller class", "category": "ui"},
    "_OBJC_CLASS_$_NSWindowController": {"lib": "AppKit", "purpose": "window controller class", "category": "ui"},
    # Controls
    "_OBJC_CLASS_$_NSButton": {"lib": "AppKit", "purpose": "button control class", "category": "ui"},
    "_OBJC_CLASS_$_NSTextField": {"lib": "AppKit", "purpose": "text field class", "category": "ui"},
    "_OBJC_CLASS_$_NSTextView": {"lib": "AppKit", "purpose": "rich text view class", "category": "ui"},
    "_OBJC_CLASS_$_NSSearchField": {"lib": "AppKit", "purpose": "search field class", "category": "ui"},
    "_OBJC_CLASS_$_NSComboBox": {"lib": "AppKit", "purpose": "combo box class", "category": "ui"},
    "_OBJC_CLASS_$_NSPopUpButton": {"lib": "AppKit", "purpose": "popup button class", "category": "ui"},
    "_OBJC_CLASS_$_NSSlider": {"lib": "AppKit", "purpose": "slider class", "category": "ui"},
    "_OBJC_CLASS_$_NSProgressIndicator": {"lib": "AppKit", "purpose": "progress indicator class", "category": "ui"},
    "_OBJC_CLASS_$_NSSegmentedControl": {"lib": "AppKit", "purpose": "segmented control class", "category": "ui"},
    "_OBJC_CLASS_$_NSSwitch": {"lib": "AppKit", "purpose": "switch control class", "category": "ui"},
    # Dialogs & Panels
    "_OBJC_CLASS_$_NSAlert": {"lib": "AppKit", "purpose": "alert dialog class", "category": "ui"},
    "_OBJC_CLASS_$_NSOpenPanel": {"lib": "AppKit", "purpose": "file open panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSSavePanel": {"lib": "AppKit", "purpose": "file save panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSColorPanel": {"lib": "AppKit", "purpose": "color picker panel class", "category": "ui"},
    "_OBJC_CLASS_$_NSFontPanel": {"lib": "AppKit", "purpose": "font picker panel class", "category": "ui"},
    # Menus & Toolbar
    "_OBJC_CLASS_$_NSMenu": {"lib": "AppKit", "purpose": "menu class", "category": "ui"},
    "_OBJC_CLASS_$_NSMenuItem": {"lib": "AppKit", "purpose": "menu item class", "category": "ui"},
    "_OBJC_CLASS_$_NSToolbar": {"lib": "AppKit", "purpose": "toolbar class", "category": "ui"},
    "_OBJC_CLASS_$_NSToolbarItem": {"lib": "AppKit", "purpose": "toolbar item class", "category": "ui"},
    "_OBJC_CLASS_$_NSTouchBar": {"lib": "AppKit", "purpose": "Touch Bar class", "category": "ui"},
    # Layout
    "_OBJC_CLASS_$_NSSplitView": {"lib": "AppKit", "purpose": "split view class", "category": "ui"},
    "_OBJC_CLASS_$_NSSplitViewController": {"lib": "AppKit", "purpose": "split view controller class", "category": "ui"},
    "_OBJC_CLASS_$_NSStackView": {"lib": "AppKit", "purpose": "stack view class", "category": "ui"},
    "_OBJC_CLASS_$_NSScrollView": {"lib": "AppKit", "purpose": "scroll view class", "category": "ui"},
    "_OBJC_CLASS_$_NSTabView": {"lib": "AppKit", "purpose": "tab view class", "category": "ui"},
    # Table & Collection
    "_OBJC_CLASS_$_NSTableView": {"lib": "AppKit", "purpose": "table view class", "category": "ui"},
    "_OBJC_CLASS_$_NSOutlineView": {"lib": "AppKit", "purpose": "outline (tree) view class", "category": "ui"},
    "_OBJC_CLASS_$_NSCollectionView": {"lib": "AppKit", "purpose": "collection view class", "category": "ui"},
    "_OBJC_CLASS_$_NSTableColumn": {"lib": "AppKit", "purpose": "table column class", "category": "ui"},
    # Drawing
    "_OBJC_CLASS_$_NSColor": {"lib": "AppKit", "purpose": "color class", "category": "ui"},
    "_OBJC_CLASS_$_NSFont": {"lib": "AppKit", "purpose": "font class", "category": "ui"},
    "_OBJC_CLASS_$_NSImage": {"lib": "AppKit", "purpose": "image class", "category": "ui"},
    "_OBJC_CLASS_$_NSBezierPath": {"lib": "AppKit", "purpose": "bezier path class", "category": "ui"},
    "_OBJC_CLASS_$_NSGradient": {"lib": "AppKit", "purpose": "gradient class", "category": "ui"},
    "_OBJC_CLASS_$_NSShadow": {"lib": "AppKit", "purpose": "shadow class", "category": "ui"},
    # Foundation-level (often used with AppKit)
    "_OBJC_CLASS_$_NSRunLoop": {"lib": "Foundation", "purpose": "run loop class", "category": "foundation"},
    "_OBJC_CLASS_$_NSTimer": {"lib": "Foundation", "purpose": "timer class", "category": "foundation"},
    "_OBJC_CLASS_$_NSThread": {"lib": "Foundation", "purpose": "thread class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSOperationQueue": {"lib": "Foundation", "purpose": "operation queue class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSBlockOperation": {"lib": "Foundation", "purpose": "block operation class", "category": "concurrency"},
    "_OBJC_CLASS_$_NSNotificationCenter": {"lib": "Foundation", "purpose": "notification center class", "category": "foundation"},
    "_OBJC_CLASS_$_NSDistributedNotificationCenter": {"lib": "Foundation", "purpose": "distributed notification center class", "category": "foundation"},
    "_OBJC_CLASS_$_NSFileManager": {"lib": "Foundation", "purpose": "file manager class", "category": "filesystem"},
    "_OBJC_CLASS_$_NSBundle": {"lib": "Foundation", "purpose": "bundle class", "category": "foundation"},
    "_OBJC_CLASS_$_NSProcessInfo": {"lib": "Foundation", "purpose": "process info class", "category": "foundation"},
    "_OBJC_CLASS_$_NSUserDefaults": {"lib": "Foundation", "purpose": "user defaults class", "category": "persistence"},
    "_OBJC_CLASS_$_NSData": {"lib": "Foundation", "purpose": "data class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableData": {"lib": "Foundation", "purpose": "mutable data class", "category": "foundation"},
    "_OBJC_CLASS_$_NSString": {"lib": "Foundation", "purpose": "string class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableString": {"lib": "Foundation", "purpose": "mutable string class", "category": "foundation"},
    "_OBJC_CLASS_$_NSArray": {"lib": "Foundation", "purpose": "array class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableArray": {"lib": "Foundation", "purpose": "mutable array class", "category": "foundation"},
    "_OBJC_CLASS_$_NSDictionary": {"lib": "Foundation", "purpose": "dictionary class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableDictionary": {"lib": "Foundation", "purpose": "mutable dictionary class", "category": "foundation"},
    "_OBJC_CLASS_$_NSSet": {"lib": "Foundation", "purpose": "set class", "category": "foundation"},
    "_OBJC_CLASS_$_NSMutableSet": {"lib": "Foundation", "purpose": "mutable set class", "category": "foundation"},
    "_OBJC_CLASS_$_NSURLSession": {"lib": "Foundation", "purpose": "URL session class", "category": "network"},
    "_OBJC_CLASS_$_NSURLRequest": {"lib": "Foundation", "purpose": "URL request class", "category": "network"},
    "_OBJC_CLASS_$_NSMutableURLRequest": {"lib": "Foundation", "purpose": "mutable URL request class", "category": "network"},
    "_OBJC_CLASS_$_NSURLSessionConfiguration": {"lib": "Foundation", "purpose": "URL session configuration class", "category": "network"},
    "_OBJC_CLASS_$_NSJSONSerialization": {"lib": "Foundation", "purpose": "JSON serialization class", "category": "foundation"},
    "_OBJC_CLASS_$_NSPropertyListSerialization": {"lib": "Foundation", "purpose": "plist serialization class", "category": "foundation"},
    "_OBJC_CLASS_$_NSKeyedArchiver": {"lib": "Foundation", "purpose": "keyed archiver class", "category": "persistence"},
    "_OBJC_CLASS_$_NSKeyedUnarchiver": {"lib": "Foundation", "purpose": "keyed unarchiver class", "category": "persistence"},
    "_OBJC_CLASS_$_NSTask": {"lib": "Foundation", "purpose": "subprocess task class", "category": "process"},
    "_OBJC_CLASS_$_NSPipe": {"lib": "Foundation", "purpose": "pipe class for IPC", "category": "process"},
    "_OBJC_CLASS_$_NSPasteboard": {"lib": "AppKit", "purpose": "pasteboard (clipboard) class", "category": "ui"},
    "_OBJC_CLASS_$_NSStatusBar": {"lib": "AppKit", "purpose": "status bar class", "category": "ui"},
    "_OBJC_CLASS_$_NSStatusItem": {"lib": "AppKit", "purpose": "status bar item class", "category": "ui"},
    "_OBJC_CLASS_$_NSDraggingItem": {"lib": "AppKit", "purpose": "dragging item class", "category": "ui"},
    "_OBJC_CLASS_$_NSWorkspace": {"lib": "AppKit", "purpose": "workspace class (open URLs, apps)", "category": "ui"},
    "_OBJC_CLASS_$_NSAppearance": {"lib": "AppKit", "purpose": "appearance class (dark/light mode)", "category": "ui"},
}


# ---------------------------------------------------------------------------
# macos_ext (~117 entry) — Mach kernel + kqueue + sandbox + LaunchServices
# + DiskArbitration + SystemConfiguration + Authorization + posix_spawn
# + Security extended + CoreFoundation extended.
# Kaynak: signature_db.py satir 7302-7421.
# ---------------------------------------------------------------------------
_MACOS_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Mach kernel ---
    "mach_task_self": {"lib": "mach", "purpose": "get mach port for current task", "category": "macos_kernel"},
    "mach_host_self": {"lib": "mach", "purpose": "get mach port for host", "category": "macos_kernel"},
    "task_for_pid": {"lib": "mach", "purpose": "get task port for PID", "category": "macos_kernel"},
    "mach_vm_allocate": {"lib": "mach", "purpose": "allocate virtual memory in task", "category": "macos_kernel"},
    "mach_vm_deallocate": {"lib": "mach", "purpose": "deallocate virtual memory", "category": "macos_kernel"},
    "mach_vm_protect": {"lib": "mach", "purpose": "set memory protection on region", "category": "macos_kernel"},
    "mach_vm_read": {"lib": "mach", "purpose": "read memory from task", "category": "macos_kernel"},
    "mach_vm_write": {"lib": "mach", "purpose": "write memory to task", "category": "macos_kernel"},
    "mach_vm_region": {"lib": "mach", "purpose": "query virtual memory region info", "category": "macos_kernel"},
    "mach_port_allocate": {"lib": "mach", "purpose": "allocate mach port", "category": "macos_kernel"},
    "mach_port_deallocate": {"lib": "mach", "purpose": "deallocate mach port", "category": "macos_kernel"},
    "mach_port_insert_right": {"lib": "mach", "purpose": "insert mach port right", "category": "macos_kernel"},
    "mach_msg": {"lib": "mach", "purpose": "send/receive mach message", "category": "macos_kernel"},
    "thread_create": {"lib": "mach", "purpose": "create mach thread", "category": "macos_kernel"},
    "thread_terminate": {"lib": "mach", "purpose": "terminate mach thread", "category": "macos_kernel"},
    "thread_suspend": {"lib": "mach", "purpose": "suspend mach thread", "category": "macos_kernel"},
    "thread_resume": {"lib": "mach", "purpose": "resume mach thread", "category": "macos_kernel"},
    "thread_get_state": {"lib": "mach", "purpose": "get thread register state", "category": "macos_kernel"},
    "thread_set_state": {"lib": "mach", "purpose": "set thread register state", "category": "macos_kernel"},
    "task_threads": {"lib": "mach", "purpose": "get all threads in task", "category": "macos_kernel"},
    "task_info": {"lib": "mach", "purpose": "get task information", "category": "macos_kernel"},
    "host_statistics64": {"lib": "mach", "purpose": "get host statistics (64-bit)", "category": "macos_kernel"},
    "host_processor_info": {"lib": "mach", "purpose": "get per-CPU info", "category": "macos_kernel"},

    # --- kqueue ---
    "kqueue": {"lib": "libc", "purpose": "create new kqueue", "category": "macos_io"},
    "kevent": {"lib": "libc", "purpose": "register/poll kqueue events", "category": "macos_io"},
    "kevent64": {"lib": "libc", "purpose": "register/poll kqueue events (64-bit)", "category": "macos_io"},

    # --- Sandbox ---
    "sandbox_init": {"lib": "libsandbox", "purpose": "initialize sandbox profile", "category": "macos_security"},
    "sandbox_free_error": {"lib": "libsandbox", "purpose": "free sandbox error string", "category": "macos_security"},
    "sandbox_check": {"lib": "libsandbox", "purpose": "check sandbox permission", "category": "macos_security"},

    # --- Launch Services ---
    "LSOpenCFURLRef": {"lib": "LaunchServices", "purpose": "open URL with default app", "category": "macos_system"},
    "LSGetApplicationForURL": {"lib": "LaunchServices", "purpose": "get default app for URL", "category": "macos_system"},
    "LSCopyDefaultApplicationURLForURL": {"lib": "LaunchServices", "purpose": "copy default app URL", "category": "macos_system"},
    "LSRegisterURL": {"lib": "LaunchServices", "purpose": "register app at URL", "category": "macos_system"},

    # --- Disk Arbitration ---
    "DASessionCreate": {"lib": "DiskArbitration", "purpose": "create disk arbitration session", "category": "macos_system"},
    "DADiskCreateFromBSDName": {"lib": "DiskArbitration", "purpose": "create disk object from BSD name", "category": "macos_system"},
    "DADiskCopyDescription": {"lib": "DiskArbitration", "purpose": "copy disk description dictionary", "category": "macos_system"},

    # --- System Configuration ---
    "SCDynamicStoreCreate": {"lib": "SystemConfiguration", "purpose": "create dynamic store session", "category": "macos_system"},
    "SCDynamicStoreCopyValue": {"lib": "SystemConfiguration", "purpose": "copy value from dynamic store", "category": "macos_system"},
    "SCDynamicStoreSetNotificationKeys": {"lib": "SystemConfiguration", "purpose": "set change notification keys", "category": "macos_system"},
    "SCNetworkReachabilityCreateWithAddress": {"lib": "SystemConfiguration", "purpose": "create reachability by address", "category": "macos_system"},

    # --- Authorization Services ---
    "AuthorizationCreate": {"lib": "Security", "purpose": "create authorization reference", "category": "macos_security"},
    "AuthorizationCopyRights": {"lib": "Security", "purpose": "acquire authorization rights", "category": "macos_security"},
    "AuthorizationFree": {"lib": "Security", "purpose": "free authorization reference", "category": "macos_security"},
    "AuthorizationExecuteWithPrivileges": {"lib": "Security", "purpose": "execute with elevated privileges (deprecated)", "category": "macos_security"},

    # --- posix_spawn (macOS specific flags) ---
    "posix_spawn": {"lib": "libc", "purpose": "spawn new process (POSIX)", "category": "macos_process"},
    "posix_spawnattr_init": {"lib": "libc", "purpose": "initialize spawn attributes", "category": "macos_process"},
    "posix_spawnattr_destroy": {"lib": "libc", "purpose": "destroy spawn attributes", "category": "macos_process"},
    "posix_spawnattr_setflags": {"lib": "libc", "purpose": "set spawn attribute flags", "category": "macos_process"},
    "posix_spawnattr_setbinpref_np": {"lib": "libc", "purpose": "set preferred binary architectures", "category": "macos_process"},
    "posix_spawn_file_actions_init": {"lib": "libc", "purpose": "initialize file actions", "category": "macos_process"},
    "posix_spawn_file_actions_addopen": {"lib": "libc", "purpose": "add open action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_adddup2": {"lib": "libc", "purpose": "add dup2 action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_addclose": {"lib": "libc", "purpose": "add close action to spawn", "category": "macos_process"},
    "posix_spawn_file_actions_destroy": {"lib": "libc", "purpose": "destroy file actions", "category": "macos_process"},

    # --- Security.framework extended ---
    "SecAccessControlCreateWithFlags": {"lib": "Security", "purpose": "create access control with biometric flags", "category": "macos_security"},
    "SecKeyCreateWithData": {"lib": "Security", "purpose": "create key from raw data", "category": "macos_security"},
    "SecKeyCopyExternalRepresentation": {"lib": "Security", "purpose": "export key as data", "category": "macos_security"},
    "SecCertificateCreateWithData": {"lib": "Security", "purpose": "create certificate from DER data", "category": "macos_security"},
    "SecCertificateCopyCommonName": {"lib": "Security", "purpose": "get certificate common name", "category": "macos_security"},
    "SecPolicyCreateSSL": {"lib": "Security", "purpose": "create SSL/TLS trust policy", "category": "macos_security"},
    "SecPolicyCreateRevocation": {"lib": "Security", "purpose": "create revocation check policy", "category": "macos_security"},
    "SecTrustSetVerifyDate": {"lib": "Security", "purpose": "set trust verification date", "category": "macos_security"},
    "SecTrustGetCertificateCount": {"lib": "Security", "purpose": "get cert count in trust chain", "category": "macos_security"},

    # --- CoreFoundation extended ---
    "CFStringCreateWithCString": {"lib": "CoreFoundation", "purpose": "create CFString from C string", "category": "macos_cf"},
    "CFStringGetCString": {"lib": "CoreFoundation", "purpose": "get C string from CFString", "category": "macos_cf"},
    "CFStringCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFString", "category": "macos_cf"},
    "CFStringAppend": {"lib": "CoreFoundation", "purpose": "append to mutable CFString", "category": "macos_cf"},
    "CFDataCreate": {"lib": "CoreFoundation", "purpose": "create CFData from bytes", "category": "macos_cf"},
    "CFDataGetBytePtr": {"lib": "CoreFoundation", "purpose": "get byte pointer from CFData", "category": "macos_cf"},
    "CFDataGetLength": {"lib": "CoreFoundation", "purpose": "get CFData length", "category": "macos_cf"},
    "CFDictionaryCreate": {"lib": "CoreFoundation", "purpose": "create CFDictionary", "category": "macos_cf"},
    "CFDictionaryGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFDictionary", "category": "macos_cf"},
    "CFDictionarySetValue": {"lib": "CoreFoundation", "purpose": "set value in mutable CFDictionary", "category": "macos_cf"},
    "CFDictionaryCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFDictionary", "category": "macos_cf"},
    "CFArrayCreate": {"lib": "CoreFoundation", "purpose": "create CFArray", "category": "macos_cf"},
    "CFArrayGetCount": {"lib": "CoreFoundation", "purpose": "get CFArray count", "category": "macos_cf"},
    "CFArrayGetValueAtIndex": {"lib": "CoreFoundation", "purpose": "get CFArray element at index", "category": "macos_cf"},
    "CFArrayCreateMutable": {"lib": "CoreFoundation", "purpose": "create mutable CFArray", "category": "macos_cf"},
    "CFArrayAppendValue": {"lib": "CoreFoundation", "purpose": "append to mutable CFArray", "category": "macos_cf"},
    "CFNumberCreate": {"lib": "CoreFoundation", "purpose": "create CFNumber", "category": "macos_cf"},
    "CFNumberGetValue": {"lib": "CoreFoundation", "purpose": "get value from CFNumber", "category": "macos_cf"},
    "CFBooleanGetValue": {"lib": "CoreFoundation", "purpose": "get bool from CFBoolean", "category": "macos_cf"},
    "CFURLCreateWithString": {"lib": "CoreFoundation", "purpose": "create CFURL from string", "category": "macos_cf"},
    "CFURLCreateWithFileSystemPath": {"lib": "CoreFoundation", "purpose": "create CFURL from file path", "category": "macos_cf"},
    "CFPreferencesCopyValue": {"lib": "CoreFoundation", "purpose": "read preference value", "category": "macos_cf"},
    "CFPreferencesSetValue": {"lib": "CoreFoundation", "purpose": "set preference value", "category": "macos_cf"},
    "CFPreferencesAppSynchronize": {"lib": "CoreFoundation", "purpose": "synchronize preferences", "category": "macos_cf"},
    "CFRunLoopRun": {"lib": "CoreFoundation", "purpose": "run current run loop", "category": "macos_cf"},
    "CFRunLoopStop": {"lib": "CoreFoundation", "purpose": "stop run loop", "category": "macos_cf"},
    "CFRunLoopGetCurrent": {"lib": "CoreFoundation", "purpose": "get current run loop", "category": "macos_cf"},
    "CFRunLoopGetMain": {"lib": "CoreFoundation", "purpose": "get main run loop", "category": "macos_cf"},
    "CFRunLoopAddSource": {"lib": "CoreFoundation", "purpose": "add source to run loop", "category": "macos_cf"},
    "CFRunLoopAddTimer": {"lib": "CoreFoundation", "purpose": "add timer to run loop", "category": "macos_cf"},
    "CFRetain": {"lib": "CoreFoundation", "purpose": "increment CF reference count", "category": "macos_cf"},
    "CFRelease": {"lib": "CoreFoundation", "purpose": "decrement CF reference count", "category": "macos_cf"},
    "CFGetTypeID": {"lib": "CoreFoundation", "purpose": "get CF type identifier", "category": "macos_cf"},
    "CFEqual": {"lib": "CoreFoundation", "purpose": "compare two CF objects", "category": "macos_cf"},
    "CFHash": {"lib": "CoreFoundation", "purpose": "compute CF object hash", "category": "macos_cf"},
    "CFShow": {"lib": "CoreFoundation", "purpose": "print CF object description", "category": "macos_cf"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("macos_apple") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur
# (ornek: "macos_system" <-> _MACOS_SYSTEM_SIGNATURES).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "macos_system": _MACOS_SYSTEM_SIGNATURES_DATA,
    "macos_networking": _MACOS_NETWORKING_SIGNATURES_DATA,
    "ipc_xpc": _IPC_XPC_SIGNATURES_DATA,
    "apple_coredata": _APPLE_COREDATA_SIGNATURES_DATA,
    "apple_webkit": _APPLE_WEBKIT_SIGNATURES_DATA,
    "apple_corelocation": _APPLE_CORELOCATION_SIGNATURES_DATA,
    "apple_corebluetooth": _APPLE_COREBLUETOOTH_SIGNATURES_DATA,
    "apple_storekit": _APPLE_STOREKIT_SIGNATURES_DATA,
    "apple_usernotifications": _APPLE_USERNOTIFICATIONS_SIGNATURES_DATA,
    "apple_network_framework": _APPLE_NETWORK_FRAMEWORK_SIGNATURES_DATA,
    "apple_endpoint_security_ext": _APPLE_ENDPOINT_SECURITY_EXT_SIGNATURES_DATA,
    "apple_systemextensions": _APPLE_SYSTEMEXTENSIONS_SIGNATURES_DATA,
    "apple_appkit": _APPLE_APPKIT_SIGNATURES_DATA,
    "macos_ext": _MACOS_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
