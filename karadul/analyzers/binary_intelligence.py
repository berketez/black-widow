"""Binary Intelligence Module -- string'lerden mimari cikarim, algoritma tespiti, guvenlik analizi.

Binary dosyalardan elde edilen string'ler, symbol'ler ve dynamic library
listelerini analiz ederek uygulamanin:
- Alt sistemlerini (Scanning Engine, Web Shield, Update System vb.)
- Kullanilan algoritmalari (SHA-256, AES, YARA vb.)
- Guvenlik mekanizmalarini (Endpoint Security, Code Signing vb.)
- Iletisim protokollerini (HTTPS, XPC, gRPC vb.)
tespit eder ve mimari harita olusturur.

Pattern matching case-insensitive yapilir. Her tespit icin evidence
(hangi string'ler eslesti) ve confidence skoru verilir.
"""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from karadul.config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Subsystem:
    """Tespit edilen alt sistem."""
    name: str               # "Scanning Engine", "File Shield", "Web Shield"
    description: str         # ne yapiyor
    evidence: list[str]      # bu cikarimi destekleyen string'ler
    confidence: float        # 0.0 - 1.0
    category: str            # "core", "network", "ui", "update", "security"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Algorithm:
    """Tespit edilen algoritma."""
    name: str               # "SHA-256", "AES-256-CBC", "YARA Rules"
    category: str            # "hash", "encryption", "pattern_matching", "compression"
    evidence: list[str]
    usage_hint: str          # "virus signature verification", "config encryption"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityMechanism:
    """Tespit edilen guvenlik mekanizmasi."""
    name: str               # "Endpoint Security API", "Kernel Extension", "Code Signing"
    description: str
    risk_level: str          # "standard", "elevated", "kernel"
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Protocol:
    """Tespit edilen iletisim protokolu."""
    name: str               # "HTTPS", "Protobuf", "gRPC", "XPC", "WebSocket"
    usage: str              # "update server communication", "inter-process communication"
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionAnalysis:
    """Ghidra decompile ciktisi fonksiyon analizi."""
    name: str
    purpose: str
    algorithms: list[str]
    system_calls: list[str]
    vulnerabilities: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ArchitectureMap:
    """Uygulamanin mimari haritasi."""
    app_name: str
    app_type: str            # "antivirus", "ide", "terminal", "browser", "generic"
    subsystems: list[Subsystem] = field(default_factory=list)
    algorithms: list[Algorithm] = field(default_factory=list)
    security: list[SecurityMechanism] = field(default_factory=list)
    protocols: list[Protocol] = field(default_factory=list)
    function_analyses: list[FunctionAnalysis] = field(default_factory=list)
    architecture_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_name": self.app_name,
            "app_type": self.app_type,
            "subsystems": [s.to_dict() for s in self.subsystems],
            "algorithms": [a.to_dict() for a in self.algorithms],
            "security": [s.to_dict() for s in self.security],
            "protocols": [p.to_dict() for p in self.protocols],
            "function_analyses": [f.to_dict() for f in self.function_analyses],
            "architecture_summary": self.architecture_summary,
        }


@dataclass
class IntelligenceReport:
    """BinaryIntelligence analiz raporu."""
    architecture: ArchitectureMap
    raw_cluster_counts: dict[str, int] = field(default_factory=dict)
    total_strings_analyzed: int = 0
    total_symbols_analyzed: int = 0
    total_dylibs_analyzed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture.to_dict(),
            "raw_cluster_counts": self.raw_cluster_counts,
            "total_strings_analyzed": self.total_strings_analyzed,
            "total_symbols_analyzed": self.total_symbols_analyzed,
            "total_dylibs_analyzed": self.total_dylibs_analyzed,
        }


# ---------------------------------------------------------------------------
# String pattern kurallari -- 500+ pattern
# ---------------------------------------------------------------------------

# Her kural grubu:
#   "patterns": case-insensitive aranacak regex/string listesi
#   "subsystem": tespit edilecek alt sistem adi
#   "description": alt sistem aciklamasi
#   "category": alt sistem kategorisi
#   "app_types": bu pattern'ler hangi uygulama tiplerini isaret eder (opsiyonel)

STRING_PATTERNS: dict[str, dict[str, Any]] = {
    # === ANTIVIIRUS / GUVENLIK YAZILIMI ===
    "scanning": {
        "patterns": [
            r"virus", r"malware", r"trojan", r"worm",
            r"ransomware", r"spyware", r"adware", r"rootkit",
            r"infected", r"quarantine", r"disinfect",
            r"heuristic", r"yara", r"clamav", r"eicar",
            r"botnet", r"backdoor", r"keylogger",
            r"crypto.?miner", r"pup", r"potentially.unwanted",
            r"file.?shield", r"behavior.?shield", r"mail.?shield",
            r"antivirus", r"anti.?malware", r"threat.?detect",
            r"scan.?engine", r"virus.?def", r"malware.?sig",
        ],
        "subsystem": "Scanning Engine",
        "description": "Malware tarama ve tespit motoru",
        "category": "core",
        "app_types": ["antivirus"],
    },
    "realtime_protection": {
        "patterns": [
            r"real.?time", r"on.?access", r"file.?shield",
            r"behavior.?monitor", r"endpoint.?security",
            r"es_client", r"es_new_client", r"kext",
            r"kernel.?extension", r"system.?extension",
            r"network.?extension", r"content.?filter",
            r"endpoint_security_t", r"es_event_type_t",
            r"es_message_t", r"es_auth_result_t",
            r"dns.?filter", r"packet.?filter",
        ],
        "subsystem": "Real-time Protection",
        "description": "Gercek zamanli dosya/sistem izleme",
        "category": "security",
        "app_types": ["antivirus"],
    },
    "web_protection": {
        "patterns": [
            r"web.?shield", r"https.?scan", r"ssl.?intercept",
            r"mitm", r"proxy", r"certificate",
            r"url.?filter", r"phishing", r"safe.?browsing",
            r"block.?list", r"blacklist", r"whitelist",
            r"web.?filter", r"content.?filter",
            r"http.?intercept", r"ssl.?bump", r"ssl.?strip",
            r"transparent.?proxy", r"dns.?over.?https",
        ],
        "subsystem": "Web Protection",
        "description": "Web trafigi filtreleme ve koruma",
        "category": "network",
        "app_types": ["antivirus", "browser"],
    },
    "firewall": {
        "patterns": [
            r"firewall", r"packet.?filter", r"ip.?filter",
            r"port.?block", r"rule.?engine", r"network.?monitor",
            r"traffic.?monitor", r"intrusion",
            r"ips", r"ids", r"deep.?packet",
            r"stateful.?inspect",
        ],
        "subsystem": "Firewall",
        "description": "Ag trafigi filtreleme ve izleme",
        "category": "network",
        "app_types": ["antivirus"],
    },
    "update_system": {
        "patterns": [
            r"update", r"vps", r"definition.?update",
            r"signature.?update", r"auto.?update",
            r"download.?update", r"check.?update",
            r"update.?manager", r"update.?service",
            r"patch", r"upgrade", r"release.?note",
            r"changelog", r"manifest", r"delta.?update",
        ],
        "subsystem": "Update System",
        "description": "Otomatik guncelleme ve tanimlar",
        "category": "update",
    },
    "vpn": {
        "patterns": [
            r"vpn", r"tunnel", r"wireguard", r"openvpn",
            r"ipsec", r"ikev2", r"l2tp", r"pptp",
            r"vpn.?connect", r"vpn.?server", r"vpn.?client",
            r"tun.?interface", r"tap.?interface",
            r"virtual.?network", r"secure.?tunnel",
        ],
        "subsystem": "VPN Client",
        "description": "VPN baglanti yonetimi",
        "category": "network",
    },
    "password_manager": {
        "patterns": [
            r"password.?manager", r"vault", r"master.?password",
            r"password.?generator", r"credential",
            r"autofill", r"form.?fill", r"key.?chain",
            r"secret.?storage", r"password.?strength",
        ],
        "subsystem": "Password Manager",
        "description": "Parola yonetimi ve guvenligi",
        "category": "security",
    },

    # === KRIPTOGRAFI ===
    "hashing": {
        "patterns": [
            r"sha.?256", r"sha.?512", r"sha.?384", r"sha.?1",
            r"md5", r"blake2", r"xxhash", r"crc32",
            r"murmurhash", r"siphash", r"fnv", r"sha.?3",
            r"keccak", r"ripemd", r"whirlpool",
            r"hmac", r"pbkdf2", r"bcrypt", r"scrypt",
            r"argon2", r"hash.?digest", r"message.?digest",
            r"CC_SHA", r"CC_MD5", r"CommonDigest",
        ],
        "subsystem": "Cryptographic Hashing",
        "description": "Hash ve ozet fonksiyonlari",
        "category": "crypto",
    },
    "encryption": {
        "patterns": [
            r"aes", r"chacha20", r"rsa", r"ecdsa", r"ed25519",
            r"curve25519", r"tls", r"x509", r"pkcs",
            r"pem", r"der", r"encrypt", r"decrypt",
            r"cipher", r"gcm", r"cbc", r"ctr", r"ecb",
            r"blowfish", r"twofish", r"camellia",
            r"poly1305", r"nacl", r"libsodium",
            r"openssl", r"boringssl", r"libressl",
            r"SecKey", r"SecEncrypt", r"CCCrypt",
            r"kSecKey", r"CommonCrypto",
            r"key.?exchange", r"diffie.?hellman", r"ecdh",
            r"key.?derivation", r"key.?wrap",
            r"initialization.?vector", r"\biv\b",
            r"nonce", r"salt", r"padding",
        ],
        "subsystem": "Encryption",
        "description": "Sifreleme ve anahtar yonetimi",
        "category": "crypto",
    },
    "digital_signature": {
        "patterns": [
            r"sign", r"verify", r"signature",
            r"code.?sign", r"notarize", r"certificate",
            r"chain.?of.?trust", r"root.?ca",
            r"intermediate.?ca", r"self.?signed",
            r"cms", r"pkcs7", r"timestamping",
        ],
        "subsystem": "Digital Signatures",
        "description": "Dijital imza ve dogrulama",
        "category": "crypto",
    },

    # === AG / PROTOKOLLER ===
    "http_client": {
        "patterns": [
            r"http", r"https", r"curl", r"fetch",
            r"request", r"response", r"content.?type",
            r"user.?agent", r"authorization", r"bearer",
            r"accept.?encoding", r"transfer.?encoding",
            r"NSURLSession", r"URLSession", r"CFNetwork",
            r"AFNetworking", r"Alamofire",
            r"keep.?alive", r"connection.?pool",
            r"retry", r"redirect", r"cookie",
            r"cache.?control", r"etag", r"if.?none.?match",
        ],
        "subsystem": "HTTP Client",
        "description": "HTTP/HTTPS istemci islemleri",
        "category": "network",
    },
    "websocket": {
        "patterns": [
            r"websocket", r"ws://", r"wss://",
            r"socket.?io", r"signalr",
            r"web.?socket.?frame", r"ping.?pong",
            r"upgrade.*websocket",
        ],
        "subsystem": "WebSocket",
        "description": "WebSocket gercek zamanli iletisim",
        "category": "network",
    },
    "dns": {
        "patterns": [
            r"dns.?resolve", r"dns.?query", r"dns.?lookup",
            r"getaddrinfo", r"gethostbyname",
            r"dns.?cache", r"dns.?over.?https",
            r"dns.?over.?tls", r"doh", r"dot",
            r"nslookup", r"dig",
        ],
        "subsystem": "DNS Resolution",
        "description": "DNS cozumleme",
        "category": "network",
    },
    "ipc": {
        "patterns": [
            r"xpc", r"mach.?port", r"\bipc\b",
            r"protobuf", r"grpc", r"dbus",
            r"named.?pipe", r"unix.?socket",
            r"shared.?memory", r"mmap",
            r"NSXPCConnection", r"xpc_connection",
            r"dispatch_mach", r"mach_msg",
            r"bootstrap_look_up",
            r"launchd", r"xpc_service",
        ],
        "subsystem": "Inter-Process Communication",
        "description": "Sureclerin arasi iletisim",
        "category": "ipc",
    },
    "serialization": {
        "patterns": [
            r"json.?parse", r"json.?stringify",
            r"msgpack", r"flatbuf", r"capnproto",
            r"thrift", r"avro", r"bson",
            r"NSCoding", r"NSKeyedArchiver",
            r"Codable", r"JSONDecoder", r"JSONEncoder",
            r"plist", r"PropertyList",
            r"NSJSONSerialization",
        ],
        "subsystem": "Serialization",
        "description": "Veri serializasyonu ve deserialization",
        "category": "data",
    },

    # === VERITABANI ===
    "database": {
        "patterns": [
            r"sqlite", r"leveldb", r"rocksdb", r"lmdb",
            r"berkeley", r"select.*from", r"insert.*into",
            r"create.*table", r"alter.*table",
            r"drop.*table", r"index.*on",
            r"pragma", r"vacuum", r"wal_mode",
            r"core.?data", r"NSManagedObject",
            r"NSPersistentStore", r"CloudKit",
            r"realm", r"fmdb",
        ],
        "subsystem": "Local Database",
        "description": "Yerel veritabani islemleri",
        "category": "storage",
    },
    "file_system": {
        "patterns": [
            r"NSFileManager", r"FileManager",
            r"readdir", r"opendir", r"stat\(",
            r"fopen", r"fclose", r"fwrite", r"fread",
            r"fsync", r"ftruncate",
            r"file.?watcher", r"fs.?event",
            r"kqueue", r"inotify", r"FSEvents",
            r"dispatch_source.*VNODE",
        ],
        "subsystem": "File System Operations",
        "description": "Dosya sistemi islemleri ve izleme",
        "category": "storage",
    },
    "keyvalue_store": {
        "patterns": [
            r"UserDefaults", r"NSUserDefaults",
            r"keychain", r"SecItem",
            r"kSecClass", r"kSecAttr",
            r"kSecValue", r"kSecReturn",
            r"SecItemAdd", r"SecItemCopyMatching",
            r"SecItemUpdate", r"SecItemDelete",
        ],
        "subsystem": "Key-Value Store",
        "description": "Anahtar-deger depolama (UserDefaults, Keychain)",
        "category": "storage",
    },

    # === macOS SiSTEM API ===
    "macos_security": {
        "patterns": [
            r"SecKey", r"SecCertificate", r"SecTrust",
            r"Keychain", r"Security\.framework",
            r"code.?sign", r"notarize",
            r"sandbox", r"entitlement", r"app.?sandbox",
            r"SecAccessControl", r"SecPolicy",
            r"SecKeychain", r"SecIdentity",
            r"kSecAttrAccessible", r"LAContext",
            r"TouchID", r"FaceID", r"biometric",
            r"LocalAuthentication",
            r"kSecAttrTokenID",
        ],
        "subsystem": "macOS Security Framework",
        "description": "Apple Security framework entegrasyonu",
        "category": "security",
    },
    "macos_system": {
        "patterns": [
            r"NSApplication", r"NSWindow", r"NSView",
            r"AppKit", r"IOKit", r"CoreFoundation",
            r"Foundation", r"dispatch_queue",
            r"NSFileManager", r"NSProcessInfo",
            r"NSWorkspace", r"NSRunningApplication",
            r"NSTask", r"NSPipe",
            r"NSNotification", r"NSDistributed",
            r"CFRunLoop", r"NSRunLoop",
            r"GCD", r"dispatch_async",
            r"OperationQueue", r"NSOperation",
        ],
        "subsystem": "macOS System Integration",
        "description": "macOS sistem framework'leri ile entegrasyon",
        "category": "system",
    },
    "macos_ui": {
        "patterns": [
            r"NSMenu", r"NSMenuItem", r"NSStatusBar",
            r"NSStatusItem", r"NSPopover",
            r"NSAlert", r"NSPanel", r"NSSheet",
            r"NSTableView", r"NSOutlineView",
            r"NSCollectionView", r"NSStackView",
            r"SwiftUI", r"UIHostingController",
            r"NSStoryboard", r"NSViewController",
            r"NSToolbar", r"NSTouchBar",
            r"NSUserNotification", r"UNUserNotification",
        ],
        "subsystem": "User Interface",
        "description": "Kullanici arayuzu bileseneri",
        "category": "ui",
    },
    "accessibility": {
        "patterns": [
            r"accessibility", r"VoiceOver",
            r"AXUIElement", r"NSAccessibility",
            r"AXValue", r"AXRole", r"AXTitle",
            r"isAccessibilityElement",
        ],
        "subsystem": "Accessibility",
        "description": "Erisilebilirlik destegi",
        "category": "ui",
    },

    # === AI / ML ===
    "machine_learning": {
        "patterns": [
            r"tensorflow", r"pytorch", r"onnx",
            r"coreml", r"MLModel", r"CreateML",
            r"inference", r"predict", r"neural",
            r"embedding", r"transformer", r"tokenizer",
            r"huggingface", r"\bllm\b", r"\bgpt\b",
            r"claude", r"anthropic", r"openai",
            r"vision.?framework", r"NaturalLanguage",
            r"SoundAnalysis", r"SpeechRecognizer",
            r"VNRequest", r"VNCoreML",
            r"batch.?normalization", r"convolution",
            r"attention.?layer", r"softmax",
        ],
        "subsystem": "Machine Learning",
        "description": "Makine ogrenmesi ve AI entegrasyonu",
        "category": "ai",
    },

    # === IDE / KOD EDITORU ===
    "code_editor": {
        "patterns": [
            r"syntax.?highlight", r"auto.?complete",
            r"code.?action", r"diagnostic",
            r"linter", r"formatter", r"language.?server",
            r"\blsp\b", r"tree.?sitter", r"textmate",
            r"monaco", r"codemirror",
            r"code.?fold", r"bracket.?match",
            r"indent", r"snippet", r"intellisense",
            r"go.?to.?definition", r"find.?references",
            r"rename.?symbol", r"code.?lens",
        ],
        "subsystem": "Code Editor",
        "description": "Kod editoru ve IDE bileseleri",
        "category": "editor",
    },
    "version_control": {
        "patterns": [
            r"\bgit\b", r"commit", r"branch",
            r"merge", r"rebase", r"diff",
            r"blame", r"stash", r"checkout",
            r"pull", r"push", r"fetch",
            r"repository", r"remote",
            r"submodule", r"worktree",
            r"cherry.?pick", r"bisect",
            r"libgit2", r"git2",
        ],
        "subsystem": "Version Control",
        "description": "Versiyon kontrol sistemi (Git)",
        "category": "vcs",
    },
    "debugger": {
        "patterns": [
            r"breakpoint", r"debugger",
            r"step.?over", r"step.?into", r"step.?out",
            r"call.?stack", r"stack.?trace",
            r"watch.?expression", r"lldb",
            r"gdb", r"debug.?adapter",
            r"debug.?protocol",
        ],
        "subsystem": "Debugger",
        "description": "Debug ve hata ayiklama araclari",
        "category": "editor",
    },

    # === TERMiNAL ===
    "terminal_emulator": {
        "patterns": [
            r"\bpty\b", r"pseudo.?terminal",
            r"vt100", r"xterm", r"\bansi\b",
            r"escape.?sequence", r"cursor.?position",
            r"terminal.?size", r"shell",
            r"\bbash\b", r"\bzsh\b", r"\bfish\b",
            r"tty", r"termios", r"tcgetattr",
            r"tcsetattr", r"winsize", r"TIOCGWINSZ",
            r"forkpty", r"openpty", r"posix_spawn",
        ],
        "subsystem": "Terminal Emulator",
        "description": "Terminal emulasyonu",
        "category": "terminal",
    },
    "shell_integration": {
        "patterns": [
            r"shell.?integration", r"command.?palette",
            r"tab.?completion", r"history",
            r"prompt", r"PS1", r"PROMPT_COMMAND",
            r"readline", r"editline",
            r"autocomplete", r"fuzzy.?find",
        ],
        "subsystem": "Shell Integration",
        "description": "Shell entegrasyonu ve komut tamamlama",
        "category": "terminal",
    },

    # === GOZLEMLENEBILIRLIK ===
    "logging": {
        "patterns": [
            r"log.?debug", r"log.?info",
            r"log.?warn", r"log.?error",
            r"sentry", r"crashlytics", r"bugsnag",
            r"datadog", r"telemetry", r"analytics",
            r"metrics", r"os_log", r"unified.?logging",
            r"NSLog", r"os_signpost",
            r"os_activity", r"dtrace",
            r"instrument", r"tracing",
        ],
        "subsystem": "Logging & Telemetry",
        "description": "Gunlukleme, hata izleme ve telemetri",
        "category": "observability",
    },
    "crash_reporting": {
        "patterns": [
            r"crash.?report", r"exception.?handler",
            r"uncaught.?exception", r"signal.?handler",
            r"SIGABRT", r"SIGSEGV", r"SIGBUS",
            r"NSException", r"mach_exception",
            r"backtrace", r"symbolicate",
            r"crash.?log", r"minidump",
        ],
        "subsystem": "Crash Reporting",
        "description": "Cokme raporlama ve hata yakalama",
        "category": "observability",
    },

    # === KONFiGURASYON ===
    "config": {
        "patterns": [
            r"config.?file", r"settings.?panel",
            r"preferences.?window", r"user.?defaults",
            r"\bplist\b", r"json.?config", r"yaml.?config",
            r"\btoml\b", r"dotenv", r"env.?file",
            r"feature.?flag", r"remote.?config",
            r"NSPreferences", r"PreferencePane",
        ],
        "subsystem": "Configuration",
        "description": "Uygulama konfigurasyonu ve tercihler",
        "category": "config",
    },
    "localization": {
        "patterns": [
            r"NSLocalized", r"Localizable\.strings",
            r"i18n", r"l10n", r"locale",
            r"NSBundle.*localized",
            r"language.?pack", r"translation",
            r"gettext", r"ngettext",
        ],
        "subsystem": "Localization",
        "description": "Coklu dil ve yerellesirme destegi",
        "category": "config",
    },

    # === MEDYA ===
    "image_processing": {
        "patterns": [
            r"CGImage", r"CIImage", r"NSImage",
            r"UIImage", r"CoreImage",
            r"ImageIO", r"vImage",
            r"image.?processing", r"image.?codec",
            r"thumbnail.?generate", r"image.?resize",
            r"CIFilter", r"image.?blur",
        ],
        "subsystem": "Image Processing",
        "description": "Goruntu isleme ve donusturme",
        "category": "media",
    },
    "audio_video": {
        "patterns": [
            r"AVFoundation", r"AVPlayer",
            r"AVAudioSession", r"AVAudioEngine",
            r"CoreAudio", r"AudioToolbox",
            r"CoreMedia", r"CMSampleBuffer",
            r"VideoToolbox", r"VTCompress",
            r"codec", r"h264", r"h265", r"hevc",
            r"aac", r"opus", r"vorbis",
        ],
        "subsystem": "Audio/Video",
        "description": "Ses ve video isleme",
        "category": "media",
    },

    # === COMPRESSION ===
    "compression": {
        "patterns": [
            r"\bzlib\b", r"\bgzip\b", r"\bdeflate\b",
            r"\blz4\b", r"\blzma\b", r"\blzfse\b",
            r"\bbrotli\b", r"\bzstd\b", r"\bsnappy\b",
            r"compress.?stream", r"decompress.?data",
            r"\bunzip\b", r"\bbz2\b", r"\bxz\b",
        ],
        "subsystem": "Compression",
        "description": "Veri sikistrima ve arsivleme",
        "category": "data",
    },

    # === MULTI-THREADING ===
    "concurrency": {
        "patterns": [
            r"pthread", r"mutex", r"semaphore",
            r"rwlock", r"condition.?variable",
            r"dispatch_semaphore", r"os_unfair_lock",
            r"NSLock", r"NSRecursiveLock",
            r"NSCondition", r"NSConditionLock",
            r"actor", r"async.?await",
            r"Task\{", r"TaskGroup",
            r"thread.?pool", r"work.?queue",
        ],
        "subsystem": "Concurrency",
        "description": "Coklu is parcacigi ve esraman islem yonetimi",
        "category": "system",
    },

    # === MEMORY MANAGEMENT ===
    "memory_management": {
        "patterns": [
            r"malloc", r"calloc", r"realloc",
            r"free\(", r"mmap", r"munmap",
            r"vm_allocate", r"vm_deallocate",
            r"autorelease", r"retain", r"release",
            r"ARC", r"weak.?reference",
            r"memory.?pool", r"arena",
            r"jemalloc", r"mimalloc",
        ],
        "subsystem": "Memory Management",
        "description": "Bellek yonetimi",
        "category": "system",
    },

    # === BROWSER ===
    "browser_engine": {
        "patterns": [
            r"WebKit", r"WKWebView",
            r"JSContext", r"JavaScriptCore",
            r"Chromium", r"Blink", r"V8",
            r"CEF", r"Electron",
            r"DOM", r"HTML.?parser",
            r"CSS.?engine", r"layout.?engine",
            r"render.?tree", r"paint",
        ],
        "subsystem": "Browser Engine",
        "description": "Web tarayici motoru",
        "category": "browser",
        "app_types": ["browser"],
    },
    "extension_system": {
        "patterns": [
            r"extension", r"plugin",
            r"add.?on", r"module.?system",
            r"hook.?system", r"event.?bus",
            r"middleware", r"interceptor",
            r"extension.?point", r"extension.?host",
        ],
        "subsystem": "Extension System",
        "description": "Eklenti/plugin sistemi",
        "category": "extensibility",
    },

    # === NETWORKING ADVANCED ===
    "tcp_udp": {
        "patterns": [
            r"tcp", r"udp", r"socket\(",
            r"bind\(", r"listen\(", r"accept\(",
            r"connect\(", r"send\(", r"recv\(",
            r"NWConnection", r"NWListener",
            r"NWEndpoint", r"Network\.framework",
            r"CFSocket", r"GCDAsyncSocket",
            r"Bonjour", r"NSNetService",
            r"multicast", r"broadcast",
        ],
        "subsystem": "TCP/UDP Networking",
        "description": "Dusuk seviyeli ag islemleri",
        "category": "network",
    },
    "bluetooth": {
        "patterns": [
            r"bluetooth", r"CoreBluetooth",
            r"CBCentralManager", r"CBPeripheral",
            r"BLE", r"GATT", r"HID",
        ],
        "subsystem": "Bluetooth",
        "description": "Bluetooth iletisimi",
        "category": "hardware",
    },
    "usb": {
        "patterns": [
            r"IOUSBHost", r"USBDevice",
            r"IOKit.*USB", r"libusb",
            r"bulk.?transfer", r"endpoint",
        ],
        "subsystem": "USB",
        "description": "USB cihaz iletisimi",
        "category": "hardware",
    },

    # === CLOUD & SYNC ===
    "cloud_sync": {
        "patterns": [
            r"iCloud", r"CloudKit",
            r"NSUbiquitous", r"cloud.?sync",
            r"sync.?engine", r"conflict.?resolution",
            r"dropbox", r"google.?drive", r"onedrive",
            r"s3", r"aws", r"azure",
            r"firebase", r"supabase",
        ],
        "subsystem": "Cloud Sync",
        "description": "Bulut senkronizasyonu",
        "category": "cloud",
    },
    "push_notification": {
        "patterns": [
            r"push.?notification", r"APNS",
            r"remote.?notification",
            r"UNNotification", r"NSUserNotification",
            r"notification.?center",
            r"notification.?service",
        ],
        "subsystem": "Push Notifications",
        "description": "Uzak bildirimler",
        "category": "cloud",
    },

    # === LICENSING ===
    "licensing": {
        "patterns": [
            r"license", r"licence", r"activation",
            r"trial", r"subscription", r"purchase",
            r"in.?app.?purchase", r"StoreKit",
            r"receipt", r"entitlement",
            r"serial.?number", r"product.?key",
            r"license.?check", r"drm",
        ],
        "subsystem": "Licensing",
        "description": "Lisans yonetimi ve aktivasyon",
        "category": "business",
    },

    # === PROCESS MANAGEMENT ===
    "process_management": {
        "patterns": [
            r"fork\(", r"exec", r"spawn",
            r"waitpid", r"posix_spawn",
            r"NSTask", r"Process\(",
            r"launchctl", r"launchd",
            r"daemon", r"agent",
            r"service.?management",
            r"SMAppService", r"SMLoginItem",
        ],
        "subsystem": "Process Management",
        "description": "Surec yonetimi ve servis kontrolu",
        "category": "system",
    },

    # === CLIPBOARD ===
    "clipboard": {
        "patterns": [
            r"NSPasteboard", r"UIPasteboard",
            r"clipboard", r"copy", r"paste",
            r"drag.?drop", r"NSDragging",
        ],
        "subsystem": "Clipboard",
        "description": "Pano islemleri ve surukleme-birakma",
        "category": "ui",
    },

    # === PRINTING ===
    "printing": {
        "patterns": [
            r"NSPrint", r"print.?operation",
            r"PDFKit", r"PDFDocument",
            r"CoreGraphics", r"CGContext",
            r"QuartzCore",
        ],
        "subsystem": "Printing & PDF",
        "description": "Yazdirma ve PDF islemleri",
        "category": "output",
    },

    # === SWIFT / RUST RUNTIME ===
    "swift_runtime": {
        "patterns": [
            r"swift_", r"Swift\.", r"_swift_",
            r"SwiftObject", r"swift_allocObject",
            r"swift_retain", r"swift_release",
            r"protocol.?witness", r"type.?metadata",
            r"Combine", r"Publisher", r"Subscriber",
        ],
        "subsystem": "Swift Runtime",
        "description": "Swift runtime ve standart kutuphane",
        "category": "runtime",
    },
    "rust_runtime": {
        "patterns": [
            r"rust_begin_unwind", r"rust_panic",
            r"__rust_alloc", r"core::panicking",
            r"std::io", r"std::thread",
            r"tokio", r"async_std",
            r"serde", r"reqwest",
        ],
        "subsystem": "Rust Runtime",
        "description": "Rust runtime ve ekosistemi",
        "category": "runtime",
    },
    "objc_runtime": {
        "patterns": [
            r"objc_msgSend", r"objc_retain",
            r"objc_release", r"objc_autoreleasePool",
            r"class_getName", r"sel_getName",
            r"method_getImplementation",
            r"objc_getClass", r"protocol_getName",
            r"NSObject", r"@objc",
        ],
        "subsystem": "Objective-C Runtime",
        "description": "Objective-C runtime",
        "category": "runtime",
    },

    # === TESTING ===
    "testing": {
        "patterns": [
            r"XCTest", r"unittest",
            r"test.?case", r"test.?suite",
            r"assert", r"expect",
            r"mock", r"stub", r"spy",
            r"XCTAssert", r"XCTExpect",
        ],
        "subsystem": "Testing Framework",
        "description": "Test framework'u",
        "category": "development",
    },

    # === SPREADSHEET / OFFICE ===
    "spreadsheet": {
        "patterns": [
            r"spreadsheet", r"worksheet", r"workbook",
            r"cell.?value", r"formula.?bar", r"pivot.?table",
            r"xlsx", r"xls\b",
            r"spreadsheet.?view", r"cell.?editor",
            r"row.?height", r"column.?width",
            r"cell.?range", r"cell.?ref",
            r"excel", r"libre.?calc",
            r"number.?format",
        ],
        "subsystem": "Spreadsheet Engine",
        "description": "Tablo ve veri islemleri",
        "category": "office",
        "app_types": ["office"],
    },
    "document_processing": {
        "patterns": [
            r"paragraph.?style", r"rich.?text.?editor",
            r"attributed.?string",
            r"NSAttributedString",
            r"docx", r"rtf\b", r"odt\b",
            r"word.?processor", r"page.?layout",
            r"text.?formatting", r"footnote",
        ],
        "subsystem": "Document Processing",
        "description": "Belge isleme",
        "category": "office",
    },
}


# ---------------------------------------------------------------------------
# Algoritma pattern'leri -- belirli algoritmalari tespit icin
# ---------------------------------------------------------------------------

ALGORITHM_PATTERNS: dict[str, dict[str, str]] = {
    # Hash algorithmalari
    "SHA-256": {"pattern": r"sha.?256|SHA256|CC_SHA256", "category": "hash", "usage": "data integrity, signature verification"},
    "SHA-512": {"pattern": r"sha.?512|SHA512|CC_SHA512", "category": "hash", "usage": "extended hash operations"},
    "SHA-1": {"pattern": r"sha.?1\b|SHA1|CC_SHA1", "category": "hash", "usage": "legacy hash (deprecated for security)"},
    "MD5": {"pattern": r"\bmd5\b|MD5|CC_MD5", "category": "hash", "usage": "legacy checksum (not for security)"},
    "BLAKE2": {"pattern": r"blake2|BLAKE2", "category": "hash", "usage": "fast modern hash"},
    "xxHash": {"pattern": r"xxhash|XXH32|XXH64", "category": "hash", "usage": "non-cryptographic fast hash"},
    "CRC32": {"pattern": r"crc32|CRC32", "category": "hash", "usage": "checksum for data integrity"},
    "MurmurHash": {"pattern": r"murmurhash|MurmurHash", "category": "hash", "usage": "hash table lookups"},
    "HMAC": {"pattern": r"\bhmac\b|HMAC|CCHmac", "category": "hash", "usage": "message authentication"},
    "PBKDF2": {"pattern": r"pbkdf2|PBKDF2|CCKeyDerivationPBKDF", "category": "kdf", "usage": "password-based key derivation"},
    "bcrypt": {"pattern": r"\bbcrypt\b", "category": "kdf", "usage": "password hashing"},
    "Argon2": {"pattern": r"argon2|Argon2", "category": "kdf", "usage": "modern password hashing"},

    # Simetrik sifreleme
    "AES": {"pattern": r"\bAES[_\b]|kCCAlgorithmAES|[Aa][Ee][Ss]_[Ee]ncrypt|[Aa][Ee][Ss]_[Dd]ecrypt|AES_set_encrypt_key|EVP_aes_", "category": "encryption", "usage": "symmetric block cipher", "case_sensitive": True},
    "AES-GCM": {"pattern": r"aes.?gcm|AES.?GCM", "category": "encryption", "usage": "authenticated encryption"},
    "AES-CBC": {"pattern": r"aes.?cbc|AES.?CBC|kCCModeCBC", "category": "encryption", "usage": "block cipher mode"},
    "ChaCha20": {"pattern": r"chacha20|ChaCha20", "category": "encryption", "usage": "stream cipher"},
    "ChaCha20-Poly1305": {"pattern": r"chacha20.?poly1305", "category": "encryption", "usage": "authenticated stream cipher"},
    "Blowfish": {"pattern": r"blowfish|Blowfish", "category": "encryption", "usage": "legacy block cipher"},
    "3DES": {"pattern": r"3des|triple.?des|kCCAlgorithm3DES", "category": "encryption", "usage": "legacy encryption (deprecated)"},

    # Asimetrik sifreleme
    "RSA": {"pattern": r"\bRSA\b|RSA_sign|RSA_verify|kSecKeyAlgorithmRSA|rsa_oaep|rsa_pkcs1", "category": "asymmetric", "usage": "public-key cryptography", "case_sensitive": True},
    "ECDSA": {"pattern": r"ecdsa|ECDSA", "category": "asymmetric", "usage": "elliptic curve signatures"},
    "Ed25519": {"pattern": r"ed25519|Ed25519", "category": "asymmetric", "usage": "modern digital signatures"},
    "Curve25519": {"pattern": r"curve25519|Curve25519|X25519", "category": "asymmetric", "usage": "key exchange"},
    "ECDH": {"pattern": r"\becdh\b|ECDH", "category": "asymmetric", "usage": "elliptic curve key exchange"},
    "Diffie-Hellman": {"pattern": r"diffie.?hellman|DH.?key", "category": "asymmetric", "usage": "key exchange protocol"},

    # TLS/SSL
    "TLS 1.2": {"pattern": r"tls.?1\.?2|TLSv1_2", "category": "protocol", "usage": "transport layer security"},
    "TLS 1.3": {"pattern": r"tls.?1\.?3|TLSv1_3", "category": "protocol", "usage": "modern transport layer security"},

    # Compression
    "zlib": {"pattern": r"\bzlib\b|zlib_compress|inflate|deflate", "category": "compression", "usage": "general compression"},
    "LZ4": {"pattern": r"\blz4\b|LZ4", "category": "compression", "usage": "fast compression"},
    "LZMA": {"pattern": r"\blzma\b|LZMA", "category": "compression", "usage": "high-ratio compression"},
    "LZFSE": {"pattern": r"lzfse|LZFSE", "category": "compression", "usage": "Apple fast compression"},
    "Zstandard": {"pattern": r"zstd|zstandard", "category": "compression", "usage": "modern general compression"},
    "Brotli": {"pattern": r"brotli|Brotli", "category": "compression", "usage": "web compression"},

    # Pattern matching / Antivirus
    "YARA Rules": {"pattern": r"yara|YARA", "category": "pattern_matching", "usage": "malware signature matching"},
    "Regular Expressions": {"pattern": r"regex|regexp|NSRegularExpression|ICU.?regex", "category": "pattern_matching", "usage": "text pattern matching"},
    "Aho-Corasick": {"pattern": r"aho.?corasick", "category": "pattern_matching", "usage": "multi-pattern string matching"},
    "Bloom Filter": {"pattern": r"bloom.?filter", "category": "data_structure", "usage": "probabilistic set membership"},

    # ML
    "Core ML": {"pattern": r"coreml|CoreML|MLModel", "category": "ml", "usage": "on-device machine learning"},
    "TensorFlow": {"pattern": r"tensorflow|TensorFlow", "category": "ml", "usage": "machine learning framework"},
    "ONNX": {"pattern": r"\bonnx\b|ONNX", "category": "ml", "usage": "ML model interchange"},

    # -----------------------------------------------------------------------
    # Domain 1: Linear Algebra - BLAS
    # -----------------------------------------------------------------------
    "BLAS Level 1 (vector-vector)": {"pattern": r"\b[sdcz](axpy|dot|scal|copy|swap|rot|nrm2|asum)_", "category": "linear_algebra", "usage": "vector-vector operations (dot, axpy, scale, norm)"},
    "BLAS Level 2 (matrix-vector)": {"pattern": r"\b[sdcz](gemv|symv|spmv|trsv|trmv|ger|syr|spr)_", "category": "linear_algebra", "usage": "matrix-vector operations (gemv, symv, triangular solve)"},
    "BLAS Level 3 (matrix-matrix)": {"pattern": r"\b[sdcz](gemm|symm|trsm|syrk|syr2k|trmm)_", "category": "linear_algebra", "usage": "matrix-matrix operations (gemm, symm, trsm)"},

    # -----------------------------------------------------------------------
    # Domain 2: Linear Algebra - LAPACK
    # -----------------------------------------------------------------------
    "LAPACK Linear Solve": {"pattern": r"\b[sdcz](gesv|posv|sysv|gbsv)_", "category": "linear_algebra", "usage": "linear system solve (Ax=b)"},
    "LAPACK Factorization": {"pattern": r"\b[sdcz](getrf|potrf|sptrf|sytrf|pbtrf)_", "category": "linear_algebra", "usage": "matrix factorization (LU, Cholesky)"},
    "LAPACK Eigenvalue": {"pattern": r"\b[sdcz](syev|heev|geev|stev|syevd)_", "category": "linear_algebra", "usage": "eigenvalue computation"},
    "LAPACK SVD": {"pattern": r"\b[sdcz](gesvd|gesdd)_", "category": "linear_algebra", "usage": "singular value decomposition"},
    "LAPACK QR": {"pattern": r"\b[sdcz](geqrf|orgqr|ungqr|geqp3)_", "category": "linear_algebra", "usage": "QR factorization"},
    "LAPACK Triangular": {"pattern": r"\b[sdcz](getrs|getri|potrs|potri|trtrs)_", "category": "linear_algebra", "usage": "triangular solve and inverse"},

    # -----------------------------------------------------------------------
    # Domain 3: Sparse Solvers
    # -----------------------------------------------------------------------
    "SPOOLES": {"pattern": r"FrontMtx|InpMtx|ETree_\w+|SubMtx|Chv_\w+|DenseMtx|SPOOLES", "category": "sparse_solver", "usage": "SPOOLES sparse direct solver", "case_sensitive": True},
    "UMFPACK": {"pattern": r"umfpack|UMFPACK|umf_dl_|umf_di_", "category": "sparse_solver", "usage": "unsymmetric multifrontal LU factorization"},
    "PETSc": {"pattern": r"KSPSolve|MatCreate|VecCreate|SNESSolve|TSCreate|PetscInitialize", "category": "sparse_solver", "usage": "PETSc parallel toolkit for scientific computation"},
    "MUMPS": {"pattern": r"\bmumps\b|dmumps_c|zmumps_c|MUMPS", "category": "sparse_solver", "usage": "multifrontal massively parallel sparse direct solver"},
    "SuperLU": {"pattern": r"superlu|dgssv|dgstrf|SuperLU", "category": "sparse_solver", "usage": "supernodal LU factorization"},
    "SuiteSparse": {"pattern": r"cholmod|CHOLMOD|SuiteSparse|cs_lusol|cs_qrsol", "category": "sparse_solver", "usage": "sparse matrix suite (CHOLMOD, CSparse)"},
    "PARDISO": {"pattern": r"pardiso|PARDISO|mkl_pardiso", "category": "sparse_solver", "usage": "Intel MKL parallel direct sparse solver"},
    "HSL": {"pattern": r"\bma57\b|\bma87\b|\bmc64\b|HSL_MA", "category": "sparse_solver", "usage": "Harwell Subroutine Library sparse solvers"},

    # -----------------------------------------------------------------------
    # Domain 4: Eigenvalue Solvers
    # -----------------------------------------------------------------------
    "ARPACK Symmetric": {"pattern": r"\b[sdcz]saupd_|\b[sdcz]seupd_", "category": "eigenvalue", "usage": "symmetric eigenvalue via Lanczos iteration"},
    "ARPACK Non-Symmetric": {"pattern": r"\b[sdcz]naupd_|\b[sdcz]neupd_", "category": "eigenvalue", "usage": "non-symmetric eigenvalue via Arnoldi iteration"},
    "SLEPc": {"pattern": r"EPSSolve|EPSCreate|EPSSetOperators|slepc|SLEPc", "category": "eigenvalue", "usage": "Scalable Library for Eigenvalue Problem Computations"},
    "FEAST": {"pattern": r"FEAST_\w+|feastinit|[sdcz]feast_\w+", "category": "eigenvalue", "usage": "FEAST contour integral eigenvalue solver"},

    # -----------------------------------------------------------------------
    # Domain 5: Fortran Runtime
    # -----------------------------------------------------------------------
    "gfortran I/O": {"pattern": r"_gfortran_st_(read|write|open|close|rewind|inquire)", "category": "fortran_runtime", "usage": "Fortran I/O operations"},
    "gfortran Transfer": {"pattern": r"_gfortran_transfer_(real|integer|character|complex|array)", "category": "fortran_runtime", "usage": "Fortran data transfer primitives"},
    "gfortran Runtime": {"pattern": r"_gfortran_runtime_error|_gfortran_stop_string|_gfortran_exit_i[48]", "category": "fortran_runtime", "usage": "Fortran runtime error handling"},
    "gfortran String": {"pattern": r"_gfortran_compare_string|_gfortran_concat_string|_gfortran_string_len_trim", "category": "fortran_runtime", "usage": "Fortran string operations"},
    "gfortran Math": {"pattern": r"_gfortran_matmul|_gfortran_pow_|_gfortran_random_r[48]", "category": "fortran_runtime", "usage": "Fortran math intrinsics (matmul, pow, random)"},
    "Intel Fortran Runtime": {"pattern": r"\bfor_write_seq_lis\b|\bfor_read_seq_lis\b|_intel_fast_mem", "category": "fortran_runtime", "usage": "Intel Fortran runtime (ifort)"},
    "LLVM Flang Runtime": {"pattern": r"_FortranA|_Fortran\w+io|flangrti", "category": "fortran_runtime", "usage": "LLVM Flang Fortran runtime"},

    # -----------------------------------------------------------------------
    # Domain 6: Parallel Computing
    # -----------------------------------------------------------------------
    "OpenMP (GOMP)": {"pattern": r"GOMP_\w+|omp_get_\w+|omp_set_\w+|omp_in_parallel", "category": "parallel", "usage": "GNU OpenMP parallel runtime"},
    "OpenMP (KMP)": {"pattern": r"__kmpc_\w+|__kmp_\w+", "category": "parallel", "usage": "Intel/LLVM OpenMP parallel runtime"},
    "OpenCL": {"pattern": r"clCreateContext|clBuildProgram|clEnqueueNDRange|clCreateBuffer", "category": "parallel", "usage": "GPU compute via OpenCL"},
    "CUDA Runtime": {"pattern": r"cudaMalloc|cudaMemcpy|cudaFree|cudaDeviceSynchronize|cublas|cusparse", "category": "parallel", "usage": "NVIDIA CUDA GPU computing"},
    "MPI": {"pattern": r"MPI_Init|MPI_Comm_rank|MPI_Send|MPI_Recv|MPI_Bcast|MPI_Reduce|MPI_Finalize", "category": "parallel", "usage": "Message Passing Interface distributed computing"},
    "Intel TBB": {"pattern": r"tbb::|oneapi::tbb|tbb_malloc|tbb::parallel_for", "category": "parallel", "usage": "Threading Building Blocks task parallelism"},

    # -----------------------------------------------------------------------
    # Domain 7: Numerical Methods
    # -----------------------------------------------------------------------
    "SUNDIALS": {"pattern": r"CVodeCreate|CVodeSolve|IDACreate|KINSol|SUNLinSol|sundials", "category": "numerical", "usage": "ODE/DAE solver suite (CVODE, IDA, KINSOL)"},
    "ODEPACK": {"pattern": r"\bdlsod[ae]_|\blsode\b|\bdlsodi_", "category": "numerical", "usage": "legacy ODE solvers (LSODE, LSODA)"},
    "GMRES": {"pattern": r"\bdgmres_|\bfgmres\b|GMRES|gmres_solve", "category": "numerical", "usage": "GMRES iterative Krylov solver"},
    "Gauss Quadrature": {"pattern": r"\bdqag[es]?_|gauss.?quad|gauss.?legendre", "category": "numerical", "usage": "numerical integration (Gauss quadrature)"},
    "Newton-Raphson": {"pattern": r"newton.?raphson|newtonmethod|nonlinear.?solve", "category": "numerical", "usage": "nonlinear root-finding solver"},
    "Conjugate Gradient": {"pattern": r"conjugate.?gradient|PCG_solve|preconditioned.?cg", "category": "numerical", "usage": "iterative linear solver (CG/PCG)"},
    "Runge-Kutta": {"pattern": r"runge.?kutta|dormand.?prince|\brk4[58]?\b", "category": "numerical", "usage": "explicit ODE integrator (RK4, Dormand-Prince)"},

    # -----------------------------------------------------------------------
    # Domain 8: FFT / Signal Processing
    # -----------------------------------------------------------------------
    "FFTW": {"pattern": r"fftw_plan|fftw_execute|fftw_malloc|fftwf_plan", "category": "signal_processing", "usage": "FFTW fast Fourier transform library"},
    "FFT Generic": {"pattern": r"\brfft[fi]?\b|\bcfft[fi]?\b|\bdrfft", "category": "signal_processing", "usage": "generic FFT routines"},
    "Apple vDSP": {"pattern": r"vDSP_fft|vDSP_DFT|vDSP_DCT|vDSP_conv", "category": "signal_processing", "usage": "Apple Accelerate DSP framework"},
    "GSL": {"pattern": r"\bgsl_\w+|gsl_integration|gsl_linalg|gsl_matrix|gsl_vector", "category": "numerical", "usage": "GNU Scientific Library"},
    "NAG": {"pattern": r"\bnag_\w+|\bnagf_\w+", "category": "numerical", "usage": "NAG numerical library"},

    # -----------------------------------------------------------------------
    # Domain 9: FEA-Specific
    # -----------------------------------------------------------------------
    "FEA Elements": {"pattern": r"\be_c3d\b|\bC3D\d+R?\b|\bCPS\d+R?\b|\bCAX\d+\b|\bCPE\d+R?\b|\bS[3-8]R\b|\bB[23]\d\b", "category": "fea", "usage": "finite element types (hex, tet, quad, shell, beam -- CalculiX/Abaqus)"},
    "Material Models": {"pattern": r"\bumat_\w+|umatht|materialdata_|creep_|plastic_", "category": "fea", "usage": "user material subroutines (UMAT)"},
    "Contact Mechanics": {"pattern": r"contactmortar|contactpair|frictioncoeff|contactdamp|slavface", "category": "fea", "usage": "contact analysis (mortar, friction, damping)"},
    "Mesh Operations": {"pattern": r"refinemesh|meshquality|triangulate|tetrahedral|remesh", "category": "fea", "usage": "mesh generation and refinement"},
    "Thermal FEA": {"pattern": r"heattransfer|jouleheating|radiate_|convect_|specificheats", "category": "fea", "usage": "thermal analysis (conduction, convection, radiation)"},
    "Boundary Conditions": {"pattern": r"boundarycondi|constraint.*MPC|multipoint|tiedcontact|cload", "category": "fea", "usage": "boundary condition and constraint handling"},

    # -----------------------------------------------------------------------
    # Domain 10: Graphics
    # -----------------------------------------------------------------------
    "OpenGL": {"pattern": r"\bgl[A-Z]\w+|glBegin|glEnd|glShader|glCreate\w+|GLEW_", "category": "graphics", "usage": "OpenGL rendering API"},
    "Vulkan": {"pattern": r"\bvk[A-Z]\w+|VkInstance|VkDevice|VkCommandBuffer|VkPipeline", "category": "graphics", "usage": "Vulkan low-level GPU rendering"},
    "Metal": {"pattern": r"MTLDevice|MTLCommandQueue|MTLRenderPipeline|MTKView|MetalKit", "category": "graphics", "usage": "Apple Metal GPU framework"},
    "DirectX": {"pattern": r"ID3D1[12]\w+|DXGI|Direct3D|D3D1[12]_", "category": "graphics", "usage": "DirectX rendering API"},
    "SDL": {"pattern": r"SDL_Init|SDL_CreateWindow|SDL_CreateRenderer|SDL_PollEvent", "category": "graphics", "usage": "Simple DirectMedia Layer"},

    # -----------------------------------------------------------------------
    # Domain 11: GUI Frameworks
    # -----------------------------------------------------------------------
    "Qt": {"pattern": r"QApplication|QWidget|QMainWindow|QObject|QPushButton|QLayout", "category": "gui", "usage": "Qt cross-platform GUI framework"},
    "GTK": {"pattern": r"gtk_init|gtk_widget_|gtk_window_|g_signal_connect|GtkWidget", "category": "gui", "usage": "GTK toolkit"},
    "Cocoa/AppKit": {"pattern": r"NSApplication|NSWindow|NSView|NSViewController|NSButton", "category": "gui", "usage": "macOS native UI (AppKit)"},
    "SwiftUI": {"pattern": r"SwiftUI|@Observable|@State|@Binding|ViewBuilder", "category": "gui", "usage": "Apple SwiftUI declarative UI"},
    "wxWidgets": {"pattern": r"wxApp|wxFrame|wxPanel|wxButton|wxTextCtrl", "category": "gui", "usage": "wxWidgets cross-platform GUI"},
    "Electron": {"pattern": r"BrowserWindow|ipcMain|ipcRenderer|electron\.app", "category": "gui", "usage": "Electron desktop framework"},

    # -----------------------------------------------------------------------
    # Domain 12: Database
    # -----------------------------------------------------------------------
    "SQLite": {"pattern": r"sqlite3_open|sqlite3_exec|sqlite3_prepare|sqlite3_step|sqlite3_close", "category": "database", "usage": "embedded SQL database"},
    "PostgreSQL Client": {"pattern": r"PQconnectdb|PQexec|PQgetvalue|PQclear|PQfinish", "category": "database", "usage": "PostgreSQL libpq client"},
    "MySQL Client": {"pattern": r"mysql_real_connect|mysql_query|mysql_fetch_row|mysql_close", "category": "database", "usage": "MySQL C client library"},
    "LMDB": {"pattern": r"mdb_env_create|mdb_txn_begin|mdb_put|mdb_get|mdb_cursor", "category": "database", "usage": "Lightning Memory-Mapped Database"},
    "LevelDB": {"pattern": r"leveldb_open|leveldb_put|leveldb_get|leveldb_close", "category": "database", "usage": "LevelDB key-value store"},
    "Redis Client": {"pattern": r"redisConnect|redisCommand|redisAppendCommand|redisFree", "category": "database", "usage": "Redis C client (hiredis)"},
    "Core Data": {"pattern": r"NSManagedObject|NSPersistentContainer|NSFetchRequest|NSEntityDescription", "category": "database", "usage": "Apple Core Data persistence"},

    # -----------------------------------------------------------------------
    # Domain 13: Network Libraries
    # -----------------------------------------------------------------------
    "libcurl": {"pattern": r"curl_easy_init|curl_easy_perform|curl_easy_setopt|curl_global_init", "category": "network_lib", "usage": "HTTP client via libcurl"},
    "OpenSSL API": {"pattern": r"SSL_CTX_new|SSL_new|SSL_connect|SSL_read|SSL_write|EVP_\w+", "category": "network_lib", "usage": "OpenSSL cryptographic library"},
    "BoringSSL": {"pattern": r"BSSL_|boringssl|BoringSSL", "category": "network_lib", "usage": "Google BoringSSL fork"},
    "mbedTLS": {"pattern": r"mbedtls_ssl_|mbedtls_entropy_|mbedtls_ctr_drbg_", "category": "network_lib", "usage": "lightweight embedded TLS"},
    "libssh2": {"pattern": r"libssh2_session_|libssh2_channel_|libssh2_sftp_", "category": "network_lib", "usage": "SSH client library"},
    "libuv": {"pattern": r"\buv_loop_|uv_tcp_|uv_async_|uv_timer_|uv_fs_", "category": "network_lib", "usage": "async I/O event loop (libuv)"},
    "ZeroMQ": {"pattern": r"zmq_socket|zmq_bind|zmq_connect|zmq_send|zmq_recv", "category": "network_lib", "usage": "ZeroMQ message queue"},
    "gRPC C": {"pattern": r"grpc_init|grpc_channel_create|grpc_call_|grpc_server_", "category": "network_lib", "usage": "gRPC C-core framework"},

    # -----------------------------------------------------------------------
    # Domain 14: Serialization
    # -----------------------------------------------------------------------
    "Protobuf": {"pattern": r"protobuf|google::protobuf|SerializeToString|ParseFromString", "category": "serialization", "usage": "Protocol Buffers serialization"},
    "JSON C Libraries": {"pattern": r"cJSON_Parse|cJSON_Print|yyjson_read|yyjson_write|rapidjson|jansson", "category": "serialization", "usage": "C/C++ JSON parsing libraries"},
    "XML Parsing": {"pattern": r"xmlParseFile|xmlReadFile|XML_ParserCreate|expat|xmlSAXHandler", "category": "serialization", "usage": "XML parsing (libxml2, expat)"},
    "MessagePack": {"pattern": r"msgpack_pack|msgpack_unpack|msgpack_sbuffer", "category": "serialization", "usage": "MessagePack binary serialization"},
    "FlatBuffers": {"pattern": r"flatbuffers|flatcc_|FlatBufferBuilder", "category": "serialization", "usage": "FlatBuffers zero-copy serialization"},
    "YAML Parsing": {"pattern": r"yaml_parser_|yaml_emitter_|yaml_document_", "category": "serialization", "usage": "YAML parsing (libyaml)"},
    "HDF5": {"pattern": r"H5Fcreate|H5Fopen|H5Dwrite|H5Dread|H5Gopen|H5Acreate", "category": "serialization", "usage": "HDF5 hierarchical data format"},
    "NetCDF": {"pattern": r"nc_open|nc_create|nc_get_var|nc_put_var|nc_def_dim", "category": "serialization", "usage": "NetCDF scientific data format"},
    "Apache Arrow": {"pattern": r"arrow::|ArrowArray|arrow_schema|garrow_", "category": "serialization", "usage": "Apache Arrow columnar in-memory format"},
}


# ---------------------------------------------------------------------------
# Guvenlik mekanizmasi pattern'leri
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: dict[str, dict[str, str]] = {
    "Endpoint Security API": {
        "pattern": r"endpoint.?security|es_client|es_new_client|es_event_type",
        "description": "Apple Endpoint Security framework -- kernel seviyesi olay izleme",
        "risk_level": "kernel",
    },
    "System Extension": {
        "pattern": r"system.?extension|OSSystemExtension|NEProvider",
        "description": "macOS system extension (kext yerine)",
        "risk_level": "elevated",
    },
    "Kernel Extension": {
        "pattern": r"kext|kernel.?extension|IOKit.?driver|kmod",
        "description": "Kernel extension (cekirdek modulu)",
        "risk_level": "kernel",
    },
    "Network Extension": {
        "pattern": r"network.?extension|NEFilterProvider|NEDNSProxy|NEAppProxy|NETunnel",
        "description": "Ag trafigi filtreleme ve VPN tünelleme",
        "risk_level": "elevated",
    },
    "Code Signing": {
        "pattern": r"code.?sign|SecCode|SecStatic|SecRequirement|csreq|codesign",
        "description": "Kod imzalama ve dogrulama",
        "risk_level": "standard",
    },
    "App Sandbox": {
        "pattern": r"app.?sandbox|sandbox.?container|com\.apple\.security\.app-sandbox",
        "description": "macOS uygulama sandbox'i",
        "risk_level": "standard",
    },
    "Hardened Runtime": {
        "pattern": r"hardened.?runtime|com\.apple\.security\.cs\.disable|runtime.?exception",
        "description": "Guclendirilmis runtime korumalari",
        "risk_level": "standard",
    },
    "Notarization": {
        "pattern": r"notarize|notarization|staple|Developer.?ID",
        "description": "Apple notarization -- guvenlik taramasi",
        "risk_level": "standard",
    },
    "Gatekeeper": {
        "pattern": r"gatekeeper|quarantine|com\.apple\.quarantine|LSQuarantine",
        "description": "macOS Gatekeeper korumasi",
        "risk_level": "standard",
    },
    "SIP (System Integrity)": {
        "pattern": r"system.?integrity|SIP|csrutil|rootless",
        "description": "System Integrity Protection",
        "risk_level": "kernel",
    },
    "Keychain Access": {
        "pattern": r"keychain|SecKeychain|SecItem|kSecClass",
        "description": "macOS Keychain erisimi",
        "risk_level": "standard",
    },
    "Biometric Auth": {
        "pattern": r"TouchID|FaceID|LAContext|biometric|LocalAuthentication",
        "description": "Biyometrik dogrulama (Touch ID / Face ID)",
        "risk_level": "standard",
    },
    "TCC (Privacy)": {
        "pattern": r"tcc|privacy.?preference|kTCC|com\.apple\.tcc",
        "description": "Transparency, Consent, and Control -- gizlilik izinleri",
        "risk_level": "standard",
    },
    "File Quarantine": {
        "pattern": r"quarantine|xattr.*quarantine|LSQuarantine",
        "description": "Indirilen dosya karantina sistemi",
        "risk_level": "standard",
    },
    "Anti-Debugging": {
        "pattern": r"ptrace|PT_DENY_ATTACH|sysctl.*P_TRACED|anti.?debug",
        "description": "Debug onleme teknikleri",
        "risk_level": "elevated",
    },
    "Anti-Tampering": {
        "pattern": r"integrity.?check|checksum.?verify|tamper|anti.?tamper",
        "description": "Kurcalama onleme",
        "risk_level": "elevated",
    },
    "ASLR": {
        "pattern": r"aslr|pie|position.?independent|MH_PIE",
        "description": "Address Space Layout Randomization",
        "risk_level": "standard",
    },
    "Stack Protection": {
        "pattern": r"stack.?canary|__stack_chk|stack.?guard|stack.?protect",
        "description": "Stack buffer overflow korumalari",
        "risk_level": "standard",
    },
}


# ---------------------------------------------------------------------------
# Protokol pattern'leri
# ---------------------------------------------------------------------------

PROTOCOL_PATTERNS: dict[str, dict[str, str]] = {
    "HTTPS": {"pattern": r"https://|NSURLSession|URLSession|CFNetwork", "usage": "secure web communication"},
    "HTTP/2": {"pattern": r"http/2|h2c|ALPN|nghttp2", "usage": "modern HTTP protocol"},
    "HTTP/3": {"pattern": r"http/3|QUIC|quic", "usage": "next-gen HTTP over QUIC"},
    "WebSocket": {"pattern": r"websocket|ws://|wss://", "usage": "bidirectional real-time communication"},
    "gRPC": {"pattern": r"\bgrpc\b|gRPC|protobuf", "usage": "RPC framework with protobuf"},
    "XPC": {"pattern": r"\bxpc\b|NSXPCConnection|xpc_connection", "usage": "macOS inter-process communication"},
    "Mach IPC": {"pattern": r"mach_msg|mach_port|mach.?ipc", "usage": "low-level macOS IPC"},
    "Bonjour/mDNS": {"pattern": r"bonjour|mdns|NSNetService|NWBrowser", "usage": "local network service discovery"},
    "MQTT": {"pattern": r"\bmqtt\b|MQTT", "usage": "IoT messaging protocol"},
    "AMQP": {"pattern": r"\bamqp\b|AMQP|RabbitMQ", "usage": "message queue protocol"},
    "SSH": {"pattern": r"\bssh\b|libssh|openssh", "usage": "secure shell communication"},
    "SFTP": {"pattern": r"\bsftp\b|SFTP", "usage": "secure file transfer"},
    "FTP": {"pattern": r"\bftp\b|FTP|CFFTPStream", "usage": "file transfer protocol"},
    "SMTP": {"pattern": r"\bsmtp\b|SMTP|mail.?server", "usage": "email sending"},
    "IMAP": {"pattern": r"\bimap\b|IMAP", "usage": "email retrieval"},
    "DNS": {"pattern": r"\bdns\b|DNS|getaddrinfo|nslookup", "usage": "domain name resolution"},
    "NTP": {"pattern": r"\bntp\b|NTP|time.?sync|sntp", "usage": "time synchronization"},
    "SOCKS": {"pattern": r"socks|SOCKS|socks5", "usage": "proxy protocol"},
    "IPsec": {"pattern": r"ipsec|IPSec|IKE|ikev2", "usage": "VPN tunnel encryption"},
    "WireGuard": {"pattern": r"wireguard|WireGuard", "usage": "modern VPN protocol"},
}


# ---------------------------------------------------------------------------
# Uygulama tipi cikarim kurallari
# ---------------------------------------------------------------------------

APP_TYPE_RULES: dict[str, dict[str, Any]] = {
    "antivirus": {
        "required_subsystems": ["Scanning Engine"],
        "bonus_subsystems": ["Real-time Protection", "Web Protection", "Firewall", "Update System", "VPN Client"],
        "min_score": 1.5,
    },
    "ide": {
        "required_subsystems": ["Code Editor"],
        "bonus_subsystems": ["Version Control", "Debugger", "Terminal Emulator", "Extension System"],
        "min_score": 1.0,
    },
    "terminal": {
        "required_subsystems": ["Terminal Emulator"],
        "bonus_subsystems": ["Shell Integration", "Clipboard"],
        "min_score": 1.0,
    },
    "browser": {
        "required_subsystems": ["Browser Engine"],
        "bonus_subsystems": ["Web Protection", "Extension System", "HTTP Client"],
        "min_score": 1.0,
    },
    "office": {
        "required_subsystems": ["Spreadsheet Engine"],
        "bonus_subsystems": ["Document Processing", "Printing & PDF", "Image Processing"],
        "min_score": 1.0,
    },
    "vpn_client": {
        "required_subsystems": ["VPN Client"],
        "bonus_subsystems": ["Network Extension", "Firewall"],
        "min_score": 1.0,
    },
}


# ---------------------------------------------------------------------------
# Ghidra decompile analiz yardimcilari
# ---------------------------------------------------------------------------

# API cagirilari ve amaclari
_SYSTEM_CALL_MAP: dict[str, str] = {
    "malloc": "memory allocation",
    "calloc": "zeroed memory allocation",
    "realloc": "memory reallocation",
    "free": "memory deallocation",
    "memcpy": "memory copy",
    "memset": "memory initialization",
    "memmove": "safe memory move",
    "strcmp": "string comparison",
    "strncmp": "bounded string comparison",
    "strcpy": "string copy (unsafe)",
    "strncpy": "bounded string copy",
    "strlen": "string length",
    "printf": "formatted output",
    "sprintf": "formatted string (unsafe)",
    "snprintf": "bounded formatted string",
    "fprintf": "file formatted output",
    "fopen": "file open",
    "fclose": "file close",
    "fread": "file read",
    "fwrite": "file write",
    "open": "low-level file open",
    "close": "low-level file close",
    "read": "low-level file read",
    "write": "low-level file write",
    "socket": "socket creation",
    "connect": "socket connection",
    "bind": "socket binding",
    "listen": "socket listen",
    "accept": "socket accept",
    "send": "socket send",
    "recv": "socket receive",
    "fork": "process forking",
    "exec": "process execution",
    "pthread_create": "thread creation",
    "pthread_mutex_lock": "mutex lock",
    "dispatch_async": "GCD async dispatch",
    "objc_msgSend": "Objective-C message send",
    "mmap": "memory-mapped file I/O",
    "munmap": "unmap memory region",
    "mprotect": "memory protection change",
    "ioctl": "device I/O control",
    "select": "I/O multiplexing (select)",
    "poll": "I/O multiplexing (poll)",
    "kqueue": "I/O multiplexing (kqueue/BSD)",
    "signal": "signal handling",
    "sigaction": "signal action setup",
    "getenv": "environment variable read",
    "dlopen": "dynamic library loading",
    "dlsym": "dynamic symbol lookup",
    "stat": "file status query",
    "posix_spawn": "process creation (posix_spawn)",
    "pipe": "inter-process pipe creation",
}

# Guvenlik acigi pattern'leri decompiled kodda
_VULNERABILITY_PATTERNS: list[tuple[str, str, str]] = [
    (r"strcpy\s*\(", "Buffer Overflow", "strcpy kullanimi -- strncpy ile degistirilmeli"),
    (r"sprintf\s*\(", "Format String", "sprintf kullanimi -- snprintf ile degistirilmeli"),
    (r"gets\s*\(", "Buffer Overflow", "gets kullanimi -- fgets ile degistirilmeli"),
    (r"system\s*\(", "Command Injection", "system() komutu -- path dogrulanmali"),
    (r"exec[lv]?p?\s*\(", "Command Injection", "exec fonksiyonu -- girdi dogrulanmali"),
    (r"mktemp\s*\(", "Race Condition", "mktemp kullanimi -- mkstemp ile degistirilmeli"),
    (r"alloca\s*\(", "Stack Overflow", "alloca kullanimi -- heap allocation tercih edilmeli"),
    (r"scanf\s*\(.*%s", "Buffer Overflow", "scanf %s limitsiz -- buffer boyutu belirtilmeli"),
    (r"rand\s*\(\s*\)", "Weak Randomness", "rand() zayif -- arc4random veya SecRandomCopyBytes kullanilmali"),
]


# ---------------------------------------------------------------------------
# v1.10.0 Batch 3D: Fortran binary-type gate.
# _gfortran_* pattern'leri Fortran olmayan binary'lerde false positive
# uretiyordu (ornegin "exit_i4" yerine basit "exit" tokeni). Gate, en az
# 2 ayirici Fortran runtime marker aramadan Fortran algoritmalarini
# raporlamaz.
# ---------------------------------------------------------------------------
FORTRAN_RUNTIME_MARKERS: tuple[str, ...] = (
    "_gfortran_main",
    "_gfortran_runtime_error",
    "_gfortran_stop",
    "_gfortran_st_",
    "_gfortran_transfer_",
    "__fortran_",
    "for_write_seq_lis",
    "for_read_seq_lis",
    "_FortranA",
    "flangrti",
)

_FORTRAN_MIN_MARKERS = 2


def _is_fortran_binary(symbols_or_strings) -> bool:
    """Binary gercekten Fortran kodu mu iceriyor? False positive gate.

    En az _FORTRAN_MIN_MARKERS tane ayri Fortran runtime marker
    gorulmelidir. Tek basina "_gfortran_xyz" gecen bir sabit string
    (ornegin hata mesaji) tek basina yeter sayilmaz.

    Args:
        symbols_or_strings: Binary sembolleri ve/veya string havuzu.

    Returns:
        True: guvenle Fortran binary'si. False: gate kapali, Fortran
        category algoritmalari bastirilmali.
    """
    hit_markers: set[str] = set()
    for entry in symbols_or_strings:
        if not entry:
            continue
        for marker in FORTRAN_RUNTIME_MARKERS:
            if marker in entry:
                hit_markers.add(marker)
                if len(hit_markers) >= _FORTRAN_MIN_MARKERS:
                    return True
    return False


# ---------------------------------------------------------------------------
# Pre-compiled patterns (module-level, bir kez derlenir)
# ---------------------------------------------------------------------------

# Algo patterns: {name: (compiled_re, pre_filter_keywords)}
_COMPILED_ALGO: list[tuple[str, re.Pattern, list[str]]] = []
for _name, _data in ALGORITHM_PATTERNS.items():
    _flags = 0 if _data.get("case_sensitive") else re.IGNORECASE
    _pat = re.compile(_data["pattern"], _flags)
    # Pattern'den basit keyword'ler cikar (pre-filter icin)
    _raw = re.sub(r'\\[bBdDwWsS]', ' ', _data["pattern"])
    _keywords = [k.lower() for k in re.split(r'[|.?()[\]^$+*{}\\ ]', _raw) if len(k) >= 3]
    _COMPILED_ALGO.append((_name, _pat, _keywords))

# Syscall patterns: {api: (compiled_re, description)}
_COMPILED_SYSCALL: list[tuple[str, re.Pattern, str]] = [
    (api, re.compile(rf"\b{re.escape(api)}\s*\("), desc)
    for api, desc in _SYSTEM_CALL_MAP.items()
]

# Vulnerability patterns: (compiled_re, vuln_type, description, pre_filter_keyword)
_COMPILED_VULN: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(pat), vtype, desc, re.split(r'[\\()\s*]', pat)[0])
    for pat, vtype, desc in _VULNERABILITY_PATTERNS
]

# _infer_purpose keyword set (lowercase)
_PURPOSE_KEYWORDS: frozenset[str] = frozenset({
    "error", "fail", "success", "init", "open", "close",
    "read", "write", "send", "recv", "connect", "alloc",
    "free", "create", "destroy", "start", "stop",
})


def _analyze_single_file(args: tuple[str, str]) -> dict | None:
    """Tek bir decompiled .c dosyasini analiz et (worker fonksiyonu).

    Module-level fonksiyon -- ProcessPoolExecutor pickle uyumlulugu icin.
    Hicbir instance state kullanmaz, sadece pre-compiled module-level pattern'ler.
    """
    file_stem, code = args

    if len(code) < 50:
        return None

    code_lower = code.lower()

    # --- Algorithms (pre-filter + compiled regex) ---
    algorithms: list[str] = []
    for algo_name, compiled_pat, keywords in _COMPILED_ALGO:
        # Ucuz pre-filter: keyword'lerden en az biri varsa regex calistir
        if keywords and not any(kw in code_lower for kw in keywords):
            continue
        if compiled_pat.search(code):
            algorithms.append(algo_name)

    # --- System calls (tek tarama, iki sonuc: purpose + syscall listesi) ---
    found_syscalls: list[str] = []
    purpose_apis: list[str] = []
    for api, compiled_pat, desc in _COMPILED_SYSCALL:
        if api not in code:  # ucuz pre-filter
            continue
        if compiled_pat.search(code):
            found_syscalls.append(api)
            purpose_apis.append(desc)

    # --- Purpose (string literals + syscall sonuclari) ---
    purposes: list[str] = []
    string_literals = re.findall(r'"([^"]{4,80})"', code)
    if string_literals:
        informative = [
            s for s in string_literals
            if any(kw in s.lower() for kw in _PURPOSE_KEYWORDS)
        ]
        if informative:
            purposes.append(f"Based on strings: {', '.join(informative[:3])}")
    if purpose_apis:
        purposes.extend(purpose_apis[:5])
    if not purposes:
        if "void" in code[:100]:
            purposes.append("void function (side effects)")
        if "return" in code:
            purposes.append("returns a value")
    purpose = "; ".join(purposes[:5]) if purposes else "unknown purpose"

    # --- Vulnerabilities (pre-filter + compiled regex) ---
    vulnerabilities: list[str] = []
    for compiled_pat, vuln_type, description, pre_kw in _COMPILED_VULN:
        if pre_kw and pre_kw not in code:
            continue
        if compiled_pat.search(code):
            vulnerabilities.append(f"{vuln_type}: {description}")

    return {
        "name": file_stem,
        "purpose": purpose,
        "algorithms": algorithms,
        "system_calls": found_syscalls,
        "vulnerabilities": vulnerabilities,
    }


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class BinaryIntelligence:
    """Binary'den mimari ve algoritma cikarimi -- string clustering + pattern matching.

    Kullanim:
        bi = BinaryIntelligence(config)
        report = bi.analyze(strings, symbols, dylibs, target)
        # report.architecture icinde tum sonuclar
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        # Pre-compile pattern'leri (performans icin)
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._compile_all_patterns()

    def _compile_all_patterns(self) -> None:
        """Tum regex pattern'lerini bir kez compile et."""
        for group_name, group_data in STRING_PATTERNS.items():
            self._compiled_patterns[group_name] = [
                re.compile(p, re.IGNORECASE) for p in group_data["patterns"]
            ]

    def analyze(
        self,
        strings: list[str],
        symbols: list[str],
        dylibs: list[str],
        target_name: str = "unknown",
    ) -> IntelligenceReport:
        """Tam analiz: string clustering -> subsystem tespit -> algoritma -> guvenlik -> mimari.

        Args:
            strings: Binary'den cikarilan string listesi.
            symbols: Binary symbol tablosu (fonksiyon isimleri).
            dylibs: Dynamic library yollari.
            target_name: Hedef uygulama adi.

        Returns:
            IntelligenceReport: Tam analiz raporu.
        """
        # 1. String'leri kategorize et
        clusters = self._cluster_strings(strings)

        # Symbol'leri de string havuzuna ekle (ayri clusterla)
        symbol_clusters = self._cluster_strings(symbols)
        # Merge: symbol cluster'larini ana cluster'lara ekle
        for group_name, items in symbol_clusters.items():
            if group_name in clusters:
                clusters[group_name].extend(items)
            else:
                clusters[group_name] = items

        # 2. Alt sistemleri tespit et
        subsystems = self._detect_subsystems(clusters, dylibs)

        # 3. Algoritmalari bul
        all_text = strings + symbols
        algorithms = self._detect_algorithms(all_text)

        # 4. Guvenlik mekanizmalarini belirle
        security = self._detect_security(all_text, dylibs)

        # 5. Protokolleri tespit et
        protocols = self._detect_protocols(all_text)

        # 6. Mimari harita olustur
        architecture = self._build_architecture(
            target_name, subsystems, algorithms, security, protocols,
        )

        # Cluster sayilarini raporla
        cluster_counts = {k: len(v) for k, v in clusters.items()}

        return IntelligenceReport(
            architecture=architecture,
            raw_cluster_counts=cluster_counts,
            total_strings_analyzed=len(strings),
            total_symbols_analyzed=len(symbols),
            total_dylibs_analyzed=len(dylibs),
        )

    def analyze_decompiled(self, decompiled_dir: Path) -> list[FunctionAnalysis]:
        """Ghidra decompile ciktisini yorumla (paralel).

        10 worker ile ProcessPoolExecutor kullanir. Her dosya bagimsiz
        analiz edilir -- shared mutable state yok.

        Args:
            decompiled_dir: Decompiled C dosyalarinin bulundugu dizin.

        Returns:
            Fonksiyon analiz listesi.
        """
        results: list[FunctionAnalysis] = []

        if not decompiled_dir.exists():
            logger.warning("Decompiled dizini bulunamadi: %s", decompiled_dir)
            return results

        c_files = sorted(decompiled_dir.glob("*.c"))
        if not c_files:
            logger.info("Decompiled dizininde .c dosyasi yok: %s", decompiled_dir)
            return results

        n_files = len(c_files)
        logger.info("Decompiled analiz: %d fonksiyon dosyasi (paralel)", n_files)

        # Dosyalari oku ve (stem, code) tuple'lari hazirla
        work_items: list[tuple[str, str]] = []
        for c_file in c_files:
            try:
                code = c_file.read_text(encoding="utf-8", errors="replace")
                work_items.append((c_file.stem, code))
            except Exception as exc:
                logger.warning("Dosya okunamadi %s: %s", c_file.name, exc)

        if not work_items:
            return results

        # Paralel analiz -- max 10 worker, chunksize=50
        max_workers = min(10, len(work_items))
        chunksize = max(1, len(work_items) // (max_workers * 4))

        import time as _time
        t0 = _time.monotonic()

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            for result_dict in executor.map(
                _analyze_single_file, work_items, chunksize=chunksize,
            ):
                if result_dict is not None:
                    results.append(FunctionAnalysis(
                        name=result_dict["name"],
                        purpose=result_dict["purpose"],
                        algorithms=result_dict["algorithms"],
                        system_calls=result_dict["system_calls"],
                        vulnerabilities=result_dict["vulnerabilities"],
                    ))

        elapsed = _time.monotonic() - t0
        logger.info(
            "Decompiled analiz tamamlandi: %d/%d fonksiyon, %.1fs (%d worker)",
            len(results), n_files, elapsed, max_workers,
        )
        return results

    # ------------------------------------------------------------------
    # Private: String clustering
    # ------------------------------------------------------------------

    def _cluster_strings(self, strings: list[str]) -> dict[str, list[str]]:
        """String'leri pattern gruplarina ayir.

        Her string birden fazla gruba girebilir. Case-insensitive esleme.
        Evidence olarak gercek eslesen string'ler saklanir.
        Her gruptaki evidence max 50 ile sinirlidir (rapor sismemesi icin).
        """
        clusters: dict[str, list[str]] = {}

        for s in strings:
            if len(s) < 3:
                continue
            for group_name, compiled_list in self._compiled_patterns.items():
                for pattern in compiled_list:
                    if pattern.search(s):
                        if group_name not in clusters:
                            clusters[group_name] = []
                        if len(clusters[group_name]) < 50:
                            clusters[group_name].append(s[:200])  # truncate long strings
                        break  # bu gruptaki ilk eslesme yeterli

        return clusters

    # ------------------------------------------------------------------
    # Private: Subsystem detection
    # ------------------------------------------------------------------

    def _detect_subsystems(
        self, clusters: dict[str, list[str]], dylibs: list[str],
    ) -> list[Subsystem]:
        """Cluster'lardan alt sistemleri tespit et.

        Confidence hesabi:
        - matched_patterns / total_patterns * 0.7 (string esleme agirligi)
        - dylib bonusu: +0.15 (ilgili framework bulunursa)
        - evidence sayisi bonusu: +0.15 (5+ evidence varsa)
        """
        subsystems: list[Subsystem] = []
        dylibs_lower = " ".join(dylibs).lower()

        for group_name, group_data in STRING_PATTERNS.items():
            if group_name not in clusters:
                continue

            evidence = clusters[group_name]
            total_patterns = len(group_data["patterns"])
            # Kac farkli pattern eslesti
            matched_count = 0
            for compiled_pat in self._compiled_patterns[group_name]:
                for e in evidence:
                    if compiled_pat.search(e):
                        matched_count += 1
                        break

            # Confidence hesapla
            pattern_ratio = matched_count / max(total_patterns, 1)
            confidence = pattern_ratio * 0.7

            # Dylib bonusu
            subsystem_name = group_data["subsystem"].lower().replace(" ", "")
            category = group_data["category"].lower()
            if any(
                kw in dylibs_lower
                for kw in [category, subsystem_name, group_name]
            ):
                confidence += 0.15

            # Evidence sayisi bonusu
            if len(evidence) >= 5:
                confidence += 0.15
            elif len(evidence) >= 2:
                confidence += 0.08

            confidence = min(confidence, 1.0)

            # Minimum esik: en az 2 evidence ve 0.1 confidence
            if len(evidence) < 2 and confidence < 0.1:
                continue

            subsystems.append(Subsystem(
                name=group_data["subsystem"],
                description=group_data["description"],
                evidence=evidence[:20],  # en fazla 20 evidence
                confidence=round(confidence, 3),
                category=group_data["category"],
            ))

        # Confidence'a gore sirala (yuksekten dusuge)
        subsystems.sort(key=lambda s: s.confidence, reverse=True)
        return subsystems

    # ------------------------------------------------------------------
    # Private: Algorithm detection
    # ------------------------------------------------------------------

    def _detect_algorithms(self, all_text: list[str]) -> list[Algorithm]:
        """String ve symbol havuzundan algoritmalar tespit et."""
        algorithms: list[Algorithm] = []
        combined_text = "\n".join(all_text)
        # v1.10.0 Batch 3D: Fortran binary-type gate -- fortran_runtime
        # kategorisi false positive'lerini onle.
        fortran_gate_open = _is_fortran_binary(all_text)

        for algo_name, algo_data in ALGORITHM_PATTERNS.items():
            # Fortran kategorisini sadece gercekten Fortran binary'lerinde rapor et.
            if (
                algo_data.get("category") == "fortran_runtime"
                and not fortran_gate_open
            ):
                continue
            pattern = re.compile(algo_data["pattern"], re.IGNORECASE)
            matches = pattern.findall(combined_text)
            if matches:
                # Gercek eslesen string'leri evidence olarak topla
                evidence: list[str] = []
                for s in all_text:
                    if pattern.search(s) and len(evidence) < 10:
                        evidence.append(s[:200])

                algorithms.append(Algorithm(
                    name=algo_name,
                    category=algo_data["category"],
                    evidence=evidence,
                    usage_hint=algo_data["usage"],
                ))

        return algorithms

    # ------------------------------------------------------------------
    # Private: Security mechanism detection
    # ------------------------------------------------------------------

    def _detect_security(
        self, all_text: list[str], dylibs: list[str],
    ) -> list[SecurityMechanism]:
        """Guvenlik mekanizmalarini tespit et."""
        mechanisms: list[SecurityMechanism] = []
        combined = "\n".join(all_text + dylibs)

        for mech_name, mech_data in SECURITY_PATTERNS.items():
            pattern = re.compile(mech_data["pattern"], re.IGNORECASE)
            if pattern.search(combined):
                evidence: list[str] = []
                for s in all_text:
                    if pattern.search(s) and len(evidence) < 10:
                        evidence.append(s[:200])
                for lib in dylibs:
                    if pattern.search(lib) and len(evidence) < 10:
                        evidence.append(lib)

                mechanisms.append(SecurityMechanism(
                    name=mech_name,
                    description=mech_data["description"],
                    risk_level=mech_data["risk_level"],
                    evidence=evidence,
                ))

        return mechanisms

    # ------------------------------------------------------------------
    # Private: Protocol detection
    # ------------------------------------------------------------------

    def _detect_protocols(self, all_text: list[str]) -> list[Protocol]:
        """Iletisim protokollerini tespit et."""
        protocols: list[Protocol] = []
        combined = "\n".join(all_text)

        for proto_name, proto_data in PROTOCOL_PATTERNS.items():
            pattern = re.compile(proto_data["pattern"], re.IGNORECASE)
            if pattern.search(combined):
                evidence: list[str] = []
                for s in all_text:
                    if pattern.search(s) and len(evidence) < 10:
                        evidence.append(s[:200])

                protocols.append(Protocol(
                    name=proto_name,
                    usage=proto_data["usage"],
                    evidence=evidence,
                ))

        return protocols

    # ------------------------------------------------------------------
    # Private: Architecture map
    # ------------------------------------------------------------------

    def _build_architecture(
        self,
        app_name: str,
        subsystems: list[Subsystem],
        algorithms: list[Algorithm],
        security: list[SecurityMechanism],
        protocols: list[Protocol],
    ) -> ArchitectureMap:
        """Mimari harita olustur ve uygulama tipini cikar."""

        # Uygulama tipini belirle
        app_type = self._infer_app_type(subsystems)

        # Mimari ozet olustur
        summary = self._generate_summary(
            app_name, app_type, subsystems, algorithms, security, protocols,
        )

        return ArchitectureMap(
            app_name=app_name,
            app_type=app_type,
            subsystems=subsystems,
            algorithms=algorithms,
            security=security,
            protocols=protocols,
            architecture_summary=summary,
        )

    def _infer_app_type(self, subsystems: list[Subsystem]) -> str:
        """Alt sistemlerden uygulama tipini cikar.

        Sadece subsystem ismine degil, confidence degerine de bakar.
        Required subsystem'lerin confidence'i en az 0.3 olmali.
        """
        # {name: confidence} eslesmesi
        subsystem_map = {s.name: s.confidence for s in subsystems}

        best_type = "generic"
        best_score = 0

        for app_type, rules in APP_TYPE_RULES.items():
            # Zorunlu alt sistem kontrolu -- hem var olmali hem de yeterli confidence
            required = rules["required_subsystems"]
            min_conf = 0.3  # required subsystem'ler icin minimum confidence
            all_required = True
            for req in required:
                if req not in subsystem_map or subsystem_map[req] < min_conf:
                    all_required = False
                    break
            if not all_required:
                continue

            # Required subsystem confidence'larini skora ekle
            score = sum(subsystem_map.get(r, 0) * 3 for r in required)
            for bonus in rules["bonus_subsystems"]:
                if bonus in subsystem_map and subsystem_map[bonus] >= 0.15:
                    score += subsystem_map[bonus]

            if score >= rules["min_score"] and score > best_score:
                best_score = score
                best_type = app_type

        return best_type

    def _generate_summary(
        self,
        app_name: str,
        app_type: str,
        subsystems: list[Subsystem],
        algorithms: list[Algorithm],
        security: list[SecurityMechanism],
        protocols: list[Protocol],
    ) -> str:
        """Insan-okunabilir mimari ozet."""
        lines: list[str] = []

        lines.append(f"{app_name} -- Detected as: {app_type.upper()}")
        lines.append("")

        if subsystems:
            lines.append(f"Subsystems ({len(subsystems)}):")
            # Sadece yuksek confidence olanlari listele
            high_conf = [s for s in subsystems if s.confidence >= 0.2]
            for s in high_conf[:15]:
                lines.append(
                    f"  [{s.category}] {s.name} (confidence: {s.confidence:.0%}) -- {s.description}"
                )

        if algorithms:
            lines.append(f"\nAlgorithms ({len(algorithms)}):")
            for a in algorithms[:15]:
                lines.append(f"  [{a.category}] {a.name} -- {a.usage_hint}")

        if security:
            lines.append(f"\nSecurity Mechanisms ({len(security)}):")
            kernel = [s for s in security if s.risk_level == "kernel"]
            elevated = [s for s in security if s.risk_level == "elevated"]
            standard = [s for s in security if s.risk_level == "standard"]
            if kernel:
                lines.append("  KERNEL level:")
                for s in kernel:
                    lines.append(f"    {s.name} -- {s.description}")
            if elevated:
                lines.append("  ELEVATED level:")
                for s in elevated:
                    lines.append(f"    {s.name} -- {s.description}")
            if standard:
                lines.append(f"  STANDARD level: ({len(standard)} mechanisms)")
                for s in standard[:5]:
                    lines.append(f"    {s.name}")

        if protocols:
            lines.append(f"\nProtocols ({len(protocols)}):")
            for p in protocols[:10]:
                lines.append(f"  {p.name} -- {p.usage}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private: Ghidra decompiled analiz yardimcilari
    # ------------------------------------------------------------------

    def _infer_purpose(self, code: str) -> str:
        """Fonksiyonun ne yaptigini string'lerden ve API cagrilarindan cikar."""
        purposes: list[str] = []

        # String literallerinden amaç cikar
        string_literals = re.findall(r'"([^"]{4,80})"', code)
        if string_literals:
            # En bilgilendirici string'leri sec (error mesajlari, log mesajlari)
            informative = [
                s for s in string_literals
                if any(kw in s.lower() for kw in [
                    "error", "fail", "success", "init", "open", "close",
                    "read", "write", "send", "recv", "connect", "alloc",
                    "free", "create", "destroy", "start", "stop",
                ])
            ]
            if informative:
                purposes.append(f"Based on strings: {', '.join(informative[:3])}")

        # API cagrilarindan amac cikar
        for api, desc in _SYSTEM_CALL_MAP.items():
            if re.search(rf"\b{re.escape(api)}\s*\(", code):
                purposes.append(desc)

        if not purposes:
            # Genel cikarim: return tipi, parametre sayisi
            if "void" in code[:100]:
                purposes.append("void function (side effects)")
            if "return" in code:
                purposes.append("returns a value")

        return "; ".join(purposes[:5]) if purposes else "unknown purpose"

    def _find_algorithms_in_code(self, code: str) -> list[str]:
        """Decompiled kodda kullanilan algoritmalari bul."""
        found: list[str] = []
        # v1.10.0 Batch 3D: Fortran binary-type gate (tek fonksiyon scope'unda).
        fortran_gate_open = _is_fortran_binary([code])
        for algo_name, algo_data in ALGORITHM_PATTERNS.items():
            if (
                algo_data.get("category") == "fortran_runtime"
                and not fortran_gate_open
            ):
                continue
            pattern = re.compile(algo_data["pattern"], re.IGNORECASE)
            if pattern.search(code):
                found.append(algo_name)
        return found

    def _find_system_calls(self, code: str) -> list[str]:
        """Decompiled kodda cagirilan sistem fonksiyonlarini bul."""
        found: list[str] = []
        for api in _SYSTEM_CALL_MAP:
            if re.search(rf"\b{re.escape(api)}\s*\(", code):
                found.append(api)
        return found

    def _find_vulnerabilities(self, code: str) -> list[str]:
        """Decompiled kodda potansiyel guvenlik aciklari bul."""
        found: list[str] = []
        for pattern_str, vuln_type, description in _VULNERABILITY_PATTERNS:
            if re.search(pattern_str, code):
                found.append(f"{vuln_type}: {description}")
        return found
