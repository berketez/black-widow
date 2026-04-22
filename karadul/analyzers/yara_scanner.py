"""YARA rule engine entegrasyonu.

YARA, binary/dosya pattern tarama icin endustri standardi.
Binlerce hazir kural (malware, packer, crypto, compiler) mevcut.

Karadul'da kullanim:
1. Binary'deki bilinen kutuphaneleri tespit (crypto, compression)
2. Packer/protector tespiti (UPX, VMProtect, Themida)
3. Compiler tespiti (GCC, MSVC, Clang, Rust, Go)
4. Anti-debug/anti-analysis tespiti

YARA kurulu degilse graceful fallback: regex-based scanning.

Kullanim:
    scanner = YaraScanner()
    scanner.load_builtin_rules()
    matches = scanner.scan_file("/path/to/binary")
    # matches.matches: [YaraMatch(rule="OpenSSL_1_1", tags=["crypto"], ...)]
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """Tek bir YARA kural eslesmesi."""
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(default_factory=list)
    namespace: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict."""
        return {
            "rule": self.rule,
            "tags": self.tags,
            "meta": self.meta,
            "strings": [
                {"offset": off, "identifier": ident, "data": data.hex()}
                for off, ident, data in self.strings
            ],
            "namespace": self.namespace,
        }


@dataclass
class ScanResult:
    """Tarama sonucu."""
    total_rules: int = 0
    matches: list[YaraMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
    backend: str = ""  # "yara-python" veya "regex-fallback"

    @property
    def matched_rules(self) -> list[str]:
        """Eslesen kural isimlerini dondur."""
        return [m.rule for m in self.matches]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "matches": [m.to_dict() for m in self.matches],
            "scan_time_ms": round(self.scan_time_ms, 3),
            "errors": self.errors,
            "backend": self.backend,
        }


# ---------------------------------------------------------------------------
# Dahili kural tanimi
# ---------------------------------------------------------------------------

@dataclass
class BuiltinRule:
    """Python tarafinda tanimlanan dahili kural.

    YARA kurulu ise yara.compile() icin kaynak uretilebilir.
    Degilse regex/byte-pattern fallback icin kullanilir.

    Her kuralda ya ``byte_patterns`` (hex string listesi)
    ya da ``string_patterns`` (text regex listesi) bulunur.
    """
    name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    byte_patterns: list[bytes] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    condition: str = "any"  # "any" = herhangi biri, "all" = hepsi


def _hex(s: str) -> bytes:
    """Hex string'i bytes'a cevir. Bosluklar ignore edilir."""
    return bytes.fromhex(s.replace(" ", ""))


def _builtin_rules() -> list[BuiltinRule]:
    """Karadul dahili YARA kurallarini dondurur (~40 kural)."""
    rules: list[BuiltinRule] = []

    # ===================================================================
    # CRYPTO KUTUPHANE TESPITI (8 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="AES_SBox",
        tags=["crypto", "aes"],
        meta={"description": "AES S-Box lookup table", "severity": "info"},
        byte_patterns=[
            # AES S-box ilk 16 byte
            _hex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"),
        ],
    ))

    rules.append(BuiltinRule(
        name="SHA256_Init_Constants",
        tags=["crypto", "sha256"],
        meta={"description": "SHA-256 initialization hash values (H0..H3)", "severity": "info"},
        byte_patterns=[
            # SHA-256 H0..H3 (big-endian): 6a09e667 bb67ae85 3c6ef372 a54ff53a
            _hex("6A09E667 BB67AE85 3C6EF372 A54FF53A"),
        ],
    ))

    rules.append(BuiltinRule(
        name="SHA256_Round_Constants",
        tags=["crypto", "sha256"],
        meta={"description": "SHA-256 round constants (K[0..3])", "severity": "info"},
        byte_patterns=[
            # K[0..3]: 428a2f98 71374491 b5c0fbcf e9b5dba5
            _hex("428A2F98 71374491 B5C0FBCF E9B5DBA5"),
        ],
    ))

    rules.append(BuiltinRule(
        name="OpenSSL_Library",
        tags=["crypto", "openssl"],
        meta={"description": "OpenSSL library strings", "severity": "info"},
        string_patterns=[
            r"OpenSSL\s+\d+\.\d+",
            r"SSLeay",
            r"libssl",
        ],
    ))

    rules.append(BuiltinRule(
        name="wolfSSL_Library",
        tags=["crypto", "wolfssl"],
        meta={"description": "wolfSSL embedded TLS library", "severity": "info"},
        string_patterns=[
            r"wolfSSL",
            r"CyaSSL",
            r"wolfCrypt",
        ],
    ))

    rules.append(BuiltinRule(
        name="mbedTLS_Library",
        tags=["crypto", "mbedtls"],
        meta={"description": "Mbed TLS (formerly PolarSSL) library", "severity": "info"},
        string_patterns=[
            r"mbedTLS",
            r"mbed TLS",
            r"PolarSSL",
            r"mbedtls_ssl_",
        ],
    ))

    rules.append(BuiltinRule(
        name="libsodium_Library",
        tags=["crypto", "libsodium"],
        meta={"description": "libsodium (NaCl) crypto library", "severity": "info"},
        string_patterns=[
            r"sodium_init",
            r"crypto_secretbox",
            r"crypto_box_seal",
            r"crypto_aead_",
        ],
    ))

    rules.append(BuiltinRule(
        name="RSA_Public_Key_Constants",
        tags=["crypto", "rsa"],
        meta={"description": "RSA ASN.1 OID or common public exponent", "severity": "info"},
        byte_patterns=[
            # RSA OID: 1.2.840.113549.1.1.1 (DER encoded)
            _hex("06 09 2A 86 48 86 F7 0D 01 01 01"),
        ],
    ))

    # ===================================================================
    # PACKER / PROTECTOR TESPITI (7 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="UPX_Packed",
        tags=["packer", "upx"],
        meta={"description": "UPX packed binary", "severity": "warning"},
        byte_patterns=[
            # UPX magic: "UPX!" header
            b"UPX!",
        ],
        string_patterns=[
            r"UPX\d",          # UPX0, UPX1, UPX2 section names
            r"\$Info: This file is packed with the UPX",
        ],
    ))

    rules.append(BuiltinRule(
        name="VMProtect_Packed",
        tags=["packer", "vmprotect"],
        meta={"description": "VMProtect protected binary", "severity": "warning"},
        string_patterns=[
            r"\.vmp\d",         # .vmp0, .vmp1 section names
            r"VMProtect",
            r"VMProtect begin",
            r"VMProtect end",
        ],
    ))

    rules.append(BuiltinRule(
        name="Themida_Packed",
        tags=["packer", "themida"],
        meta={"description": "Themida/WinLicense protected binary", "severity": "warning"},
        string_patterns=[
            r"Themida",
            r"WinLicense",
            r"\.themida",
            r"\.winlice",
        ],
    ))

    rules.append(BuiltinRule(
        name="ASPack_Packed",
        tags=["packer", "aspack"],
        meta={"description": "ASPack packed binary", "severity": "warning"},
        string_patterns=[
            r"\.aspack",
            r"\.adata",
        ],
        byte_patterns=[
            # ASPack typical entry: pushad (0x60)
            _hex("60 E8 00 00 00 00"),
        ],
    ))

    rules.append(BuiltinRule(
        name="PECompact_Packed",
        tags=["packer", "pecompact"],
        meta={"description": "PECompact packed binary", "severity": "warning"},
        string_patterns=[
            r"PECompact2",
            r"PEC2",
        ],
    ))

    rules.append(BuiltinRule(
        name="MPRESS_Packed",
        tags=["packer", "mpress"],
        meta={"description": "MPRESS packed binary", "severity": "warning"},
        string_patterns=[
            r"\.MPRESS1",
            r"\.MPRESS2",
            r"MPRESS",
        ],
    ))

    rules.append(BuiltinRule(
        name="Enigma_Protector",
        tags=["packer", "enigma"],
        meta={"description": "Enigma Protector", "severity": "warning"},
        string_patterns=[
            r"Enigma protector",
            r"enigma\d",
            r"\.enigma\d",
        ],
    ))

    # ===================================================================
    # COMPILER TESPITI (8 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="GCC_Compiler",
        tags=["compiler", "gcc"],
        meta={"description": "GCC compiled binary", "severity": "info"},
        string_patterns=[
            r"GCC:\s*\(",                     # "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
            r"gcc[\s_\-]version",
            r"GNU C\d+",
            r"compiled by GNU C",
        ],
    ))

    rules.append(BuiltinRule(
        name="MSVC_Compiler",
        tags=["compiler", "msvc"],
        meta={"description": "MSVC compiled binary", "severity": "info"},
        string_patterns=[
            r"Microsoft \(R\) Optimizing Compiler",
            r"MSVC",
            r"Visual C\+\+",
            r"Microsoft Visual",
            r"_MSC_VER",
        ],
        byte_patterns=[
            # Rich header signature: "Rich"
            b"Rich",
        ],
    ))

    rules.append(BuiltinRule(
        name="Clang_Compiler",
        tags=["compiler", "clang"],
        meta={"description": "Clang/LLVM compiled binary", "severity": "info"},
        string_patterns=[
            r"clang version \d+",
            r"Apple LLVM",
            r"Apple clang",
            r"Linker: LLD",
        ],
    ))

    rules.append(BuiltinRule(
        name="Rust_Compiler",
        tags=["compiler", "rust"],
        meta={"description": "Rust compiled binary", "severity": "info"},
        string_patterns=[
            r"rustc/\d+\.\d+",               # "rustc/1.74.0"
            r"rust_begin_unwind",
            r"rust_panic",
            r"core::panicking",
            r"std::rt::lang_start",
        ],
    ))

    rules.append(BuiltinRule(
        name="Go_Compiler",
        tags=["compiler", "go"],
        meta={"description": "Go compiled binary", "severity": "info"},
        string_patterns=[
            r"go\d+\.\d+(\.\d+)?",           # go1.21.0 gibi
            r"Go build ID:",
            r"runtime\.gopanic",
            r"runtime\.goexit",
            r"runtime/internal/",
        ],
    ))

    rules.append(BuiltinRule(
        name="Swift_Compiler",
        tags=["compiler", "swift"],
        meta={"description": "Swift compiled binary", "severity": "info"},
        string_patterns=[
            r"swift_release",
            r"swift_retain",
            r"Swift runtime",
            r"_swift_allocObject",
            r"swiftCore",
        ],
    ))

    rules.append(BuiltinRule(
        name="Delphi_Compiler",
        tags=["compiler", "delphi"],
        meta={"description": "Delphi/Object Pascal compiled binary", "severity": "info"},
        string_patterns=[
            r"Embarcadero Delphi",
            r"Borland Delphi",
            r"TObject",
            r"System\.SysUtils",
        ],
    ))

    rules.append(BuiltinRule(
        name="Nim_Compiler",
        tags=["compiler", "nim"],
        meta={"description": "Nim compiled binary", "severity": "info"},
        string_patterns=[
            r"Nim/\d+\.\d+",
            r"nimMain",
            r"NimMain",
            r"nimGC_",
        ],
    ))

    # ===================================================================
    # ANTI-DEBUG / ANTI-ANALYSIS (7 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="AntiDebug_Ptrace",
        tags=["antidebug", "linux", "macos"],
        meta={"description": "ptrace-based anti-debugging (PTRACE_DENY_ATTACH)", "severity": "high"},
        string_patterns=[
            r"PTRACE_DENY_ATTACH",
            r"PT_DENY_ATTACH",
        ],
        byte_patterns=[
            # ptrace(PT_DENY_ATTACH, 0, 0, 0)
            # syscall number 0x1a (26) on macOS x86_64
            _hex("B8 1A 00 00 02"),     # mov eax, 0x200001a (macOS ptrace syscall)
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_IsDebuggerPresent",
        tags=["antidebug", "windows"],
        meta={"description": "Windows IsDebuggerPresent API call", "severity": "high"},
        string_patterns=[
            r"IsDebuggerPresent",
            r"CheckRemoteDebuggerPresent",
            r"NtQueryInformationProcess",
            r"OutputDebugString",
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_Timing",
        tags=["antidebug", "timing"],
        meta={"description": "Timing-based anti-debug checks", "severity": "medium"},
        string_patterns=[
            r"rdtsc",
            r"QueryPerformanceCounter",
            r"GetTickCount",
            r"clock_gettime",
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_SysctlCheck",
        tags=["antidebug", "macos"],
        meta={"description": "macOS sysctl-based debugger detection", "severity": "high"},
        string_patterns=[
            r"kern\.proc\.pid",
            r"CTL_KERN.*KERN_PROC",
            r"P_TRACED",
            r"sysctl\b",
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiVM_Detection",
        tags=["antidebug", "antivm"],
        meta={"description": "Virtual machine detection patterns", "severity": "high"},
        string_patterns=[
            r"VMware",
            r"VirtualBox",
            r"QEMU",
            r"Hyper-V",
            r"vboxguest",
            r"vmtoolsd",
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_ProcessEnum",
        tags=["antidebug"],
        meta={"description": "Process enumeration for debugger/sandbox detection", "severity": "medium"},
        string_patterns=[
            r"CreateToolhelp32Snapshot",
            r"Process32First",
            r"Process32Next",
            r"EnumProcesses",
        ],
    ))

    rules.append(BuiltinRule(
        name="AntiDebug_ExceptionTricks",
        tags=["antidebug"],
        meta={"description": "SEH/exception-based anti-debug tricks", "severity": "medium"},
        string_patterns=[
            r"UnhandledExceptionFilter",
            r"SetUnhandledExceptionFilter",
            r"RaiseException",
            r"__try",
        ],
    ))

    # ===================================================================
    # OBFUSCATION TESPITI (5 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="String_Encryption_XOR",
        tags=["obfuscation", "xor"],
        meta={"description": "XOR-based string encryption pattern", "severity": "medium"},
        byte_patterns=[
            # xor byte ptr [ecx+edx], al ; inc edx ; cmp edx, SIZE ; jl loop
            # Genel XOR decode loop'u: xor [reg+reg], reg; inc; cmp; jl
            _hex("30 04 11 42"),           # xor [ecx+edx], al; inc edx (32-bit)
            _hex("30 04 0A FF C2"),        # xor [rdx+rcx], al; inc edx (64-bit variant)
        ],
        string_patterns=[
            r"xor_decode",
            r"decrypt_string",
            r"string_decrypt",
        ],
    ))

    rules.append(BuiltinRule(
        name="String_Encryption_RC4",
        tags=["obfuscation", "rc4"],
        meta={"description": "RC4-based string decryption", "severity": "medium"},
        string_patterns=[
            r"rc4_crypt",
            r"RC4_set_key",
            r"arcfour",
        ],
    ))

    rules.append(BuiltinRule(
        name="Control_Flow_Flattening",
        tags=["obfuscation", "cff"],
        meta={"description": "Control flow flattening markers", "severity": "medium"},
        string_patterns=[
            r"__ollvm_",
            r"OLLVM",
            r"obfuscator-llvm",
            r"bogus\s+control\s+flow",
        ],
    ))

    rules.append(BuiltinRule(
        name="Opaque_Predicates",
        tags=["obfuscation"],
        meta={"description": "Opaque predicate patterns (junk code)", "severity": "low"},
        byte_patterns=[
            # Tipik opaque predicate: xor eax,eax; jz always_taken
            _hex("33 C0 74"),               # xor eax,eax; jz (short)
            _hex("31 C0 74"),               # xor eax,eax; jz (short) - AT&T
        ],
    ))

    rules.append(BuiltinRule(
        name="Stack_String_Construction",
        tags=["obfuscation", "stackstrings"],
        meta={"description": "Stack-based string construction (anti-static analysis)", "severity": "medium"},
        string_patterns=[
            r"stack_string",
            r"stackStrings",
        ],
        byte_patterns=[
            # mov byte [rbp-X], imm8 -- ardisik karakter yukleme (x86-64)
            # C6 45 XX YY (mov byte ptr [rbp+disp8], imm8) tekrarlayan
            _hex("C6 45"),
        ],
    ))

    # ===================================================================
    # COMPRESSION TESPITI (3 kural)
    # ===================================================================

    rules.append(BuiltinRule(
        name="Zlib_Library",
        tags=["compression", "zlib"],
        meta={"description": "zlib compression library", "severity": "info"},
        string_patterns=[
            r"deflate \d+\.\d+",
            r"inflate \d+\.\d+",
            r"zlib/\d+",
        ],
        byte_patterns=[
            # zlib magic header: 78 01 (low compression), 78 9C (default), 78 DA (best)
            _hex("78 9C"),
        ],
    ))

    rules.append(BuiltinRule(
        name="LZ4_Library",
        tags=["compression", "lz4"],
        meta={"description": "LZ4 compression library", "severity": "info"},
        string_patterns=[
            r"LZ4_compress",
            r"LZ4_decompress",
            r"lz4/\d+",
        ],
        byte_patterns=[
            # LZ4 frame magic: 04 22 4D 18
            _hex("04 22 4D 18"),
        ],
    ))

    rules.append(BuiltinRule(
        name="Zstd_Library",
        tags=["compression", "zstd"],
        meta={"description": "Zstandard compression library", "severity": "info"},
        string_patterns=[
            r"ZSTD_compress",
            r"ZSTD_decompress",
            r"zstd/\d+",
        ],
        byte_patterns=[
            # Zstandard frame magic: 28 B5 2F FD
            _hex("28 B5 2F FD"),
        ],
    ))

    return rules


# ---------------------------------------------------------------------------
# YARA kural kaynak kodu uretimi
# ---------------------------------------------------------------------------

# YARA identifier syntax: [A-Za-z_][A-Za-z0-9_]* (en fazla 128 karakter)
_YARA_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _validate_yara_identifier(name: str, kind: str = "identifier") -> str:
    """v1.10.0 Fix Sprint MED-2: YARA rule name / tag identifier dogrulama.

    Identifier YARA syntax'ine uygun olmali; uygun degilse rule injection
    onlemek icin ValueError atar. _rule_to_yara_source icinde cagrildigi
    yer: rule.name ve rule.tags. add_rule kullanan kodun bu kisiti bilmesi
    gerekir.
    """
    if not isinstance(name, str) or not _YARA_IDENT_RE.match(name):
        raise ValueError(
            f"Gecersiz YARA {kind}: {name!r} "
            f"(izinli: ^[A-Za-z_][A-Za-z0-9_]{{0,127}}$)"
        )
    return name


def _escape_yara_meta(value: str) -> str:
    """v1.10.0 Fix Sprint MED-2: YARA meta string value escape.

    YARA meta stringleri double-quote ile delimit edilir. Kotu niyetli
    girdiler (rule injection) backslash ve double-quote kullanarak meta
    bloklarini kirip yeni rule/condition enjekte edebilir. Ayrica control
    karakterler (0x00-0x1F) YARA syntax'i bozabilir.

    Args:
        value: Escape edilecek string.

    Returns:
        Guvenli escape edilmis string.

    Raises:
        ValueError: value icinde control karakter (0x00-0x1F) varsa.
    """
    if not isinstance(value, str):
        value = str(value)
    for c in value:
        if ord(c) < 0x20:
            raise ValueError(
                f"YARA meta icinde control character yasak: 0x{ord(c):02x}"
            )
    # Sirasi onemli: once backslash, sonra double-quote
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _rule_to_yara_source(rule: BuiltinRule) -> str:
    """BuiltinRule'dan YARA kaynak kodu uret (yara-python compile icin).

    Uretilen kural formati:
        rule RuleName : tag1 tag2 {
            meta:
                description = "..."
            strings:
                $s0 = { HEX }
                $s1 = /regex/ nocase
            condition:
                any of them
        }
    """
    parts = []

    # v1.10.0 Fix Sprint MED-2: Rule name ve tag identifier validasyonu
    # (kullanici add_rule ile enjekte edilmis ise rule injection riskine karsi).
    safe_name = _validate_yara_identifier(rule.name, kind="rule name")
    safe_tags = [_validate_yara_identifier(t, kind="tag") for t in (rule.tags or [])]

    # Rule header
    tag_str = " ".join(safe_tags)
    if tag_str:
        parts.append(f"rule {safe_name} : {tag_str} {{")
    else:
        parts.append(f"rule {safe_name} {{")

    # Meta
    if rule.meta:
        parts.append("    meta:")
        for k, v in rule.meta.items():
            if isinstance(v, str):
                # v1.10.0 Fix Sprint MED-2: YARA meta value icinde backslash/
                # double-quote escape, control char (0x00-0x1F) reddet.
                escaped = _escape_yara_meta(v)
                parts.append(f'        {k} = "{escaped}"')
            elif isinstance(v, bool):
                val = "true" if v else "false"
                parts.append(f"        {k} = {val}")
            elif isinstance(v, (int, float)):
                # sayisal degerleri dogrudan emit et (tip guvenligi)
                parts.append(f"        {k} = {v}")
            else:
                # Bilinmeyen tip (obje vb.) str'e cast ederken escape et
                escaped = _escape_yara_meta(str(v))
                parts.append(f'        {k} = "{escaped}"')

    # Strings
    string_defs = []
    idx = 0
    for bp in rule.byte_patterns:
        hex_str = " ".join(f"{b:02X}" for b in bp)
        string_defs.append(f"        $b{idx} = {{ {hex_str} }}")
        idx += 1
    for sp in rule.string_patterns:
        escaped_sp = sp.replace("/", "\\/")  # v1.9.1: YARA regex delimiter escape
        string_defs.append(f"        $s{idx} = /{escaped_sp}/ nocase")
        idx += 1

    if string_defs:
        parts.append("    strings:")
        parts.extend(string_defs)

    # Condition
    if rule.condition == "all":
        parts.append("    condition:")
        parts.append("        all of them")
    else:
        parts.append("    condition:")
        parts.append("        any of them")

    parts.append("}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Ana scanner sinifi
# ---------------------------------------------------------------------------

class YaraScanner:
    """YARA rule scanner -- binary pattern matching.

    yara-python kurulu ise native YARA kullanir.
    Kurulu degilse regex-based fallback kullanir.

    Attributes:
        yara_available: yara-python kurulu mu?
    """

    def __init__(self) -> None:
        self._yara_available = False
        self._yara = None           # yara module reference
        self._compiled_rules = None  # yara.Rules nesnesi
        self._builtin_rules: list[BuiltinRule] = []
        self._external_rule_paths: list[Path] = []
        self._rules_compiled = False

        try:
            import yara
            self._yara = yara
            self._yara_available = True
            logger.debug("yara-python mevcut, native backend kullanilacak")
        except ImportError:
            logger.debug("yara-python bulunamadi, regex fallback kullanilacak")

    @property
    def yara_available(self) -> bool:
        """yara-python kurulu mu?"""
        return self._yara_available

    @property
    def rule_count(self) -> int:
        """Yuklenmis toplam kural sayisi."""
        return len(self._builtin_rules)

    # ------------------------------------------------------------------
    # Kural yukleme
    # ------------------------------------------------------------------

    def load_builtin_rules(self) -> int:
        """Karadul'un dahili YARA kurallarini yukle.

        Dahili kurallar:
        - Crypto kutuphane tespiti (OpenSSL, libsodium, wolfSSL, mbedTLS)
        - Packer tespiti (UPX, VMProtect, Themida, ASPack, PECompact, MPRESS)
        - Compiler tespiti (GCC, MSVC, Clang, Rust, Go, Swift, Delphi, Nim)
        - Anti-debug pattern'leri (ptrace, IsDebuggerPresent, timing, VM)
        - String obfuscation tespiti (XOR, RC4, CFF, opaque predicates)
        - Compression (zlib, LZ4, Zstandard)

        Returns:
            Yuklenen kural sayisi.
        """
        self._builtin_rules = _builtin_rules()
        self._rules_compiled = False  # Yeniden compile gerekecek
        count = len(self._builtin_rules)
        logger.info("Dahili YARA kurallari yuklendi: %d kural", count)
        return count

    def load_rules(self, rules_path: Path) -> int:
        """YARA kural dosyalarini yukle (.yar, .yara).

        Sadece yara-python kuruluysa calisir. Kurulu degilse 0 dondurur ve
        uyari loglar.

        Args:
            rules_path: Tek dosya veya dizin. Dizin ise recursive tarar.

        Returns:
            Yuklenen dosya sayisi.
        """
        rules_path = Path(rules_path)

        if not self._yara_available:
            logger.warning(
                "yara-python kurulu degil, harici .yar dosyalari yuklenemez. "
                "Dahili kurallar (load_builtin_rules) regex fallback ile calisir."
            )
            return 0

        if not rules_path.exists():
            logger.error("YARA kural yolu bulunamadi: %s", rules_path)
            return 0

        paths: list[Path] = []
        if rules_path.is_file():
            paths.append(rules_path)
        else:
            for ext in ("*.yar", "*.yara"):
                paths.extend(sorted(rules_path.rglob(ext)))

        self._external_rule_paths.extend(paths)
        self._rules_compiled = False
        logger.info("Harici YARA dosyalari yuklendi: %d dosya", len(paths))
        return len(paths)

    def add_rule(self, rule: BuiltinRule) -> None:
        """Tek bir dahili kural ekle."""
        self._builtin_rules.append(rule)
        self._rules_compiled = False

    # ------------------------------------------------------------------
    # Tarama
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScanResult:
        """Dosyayi YARA kurallariyla tara.

        Args:
            file_path: Taranacak dosya.

        Returns:
            ScanResult: Eslesmeler, sure, hatalar.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return ScanResult(errors=[f"Dosya bulunamadi: {file_path}"])
        if not file_path.is_file():
            return ScanResult(errors=[f"Dosya degil: {file_path}"])

        try:
            data = file_path.read_bytes()
        except (OSError, PermissionError) as exc:
            return ScanResult(errors=[f"Dosya okunamadi: {exc}"])

        return self.scan_bytes(data)

    def scan_bytes(self, data: bytes) -> ScanResult:
        """Ham byte verisi tara.

        YARA kuruluysa native engine kullanir, yoksa regex fallback.

        Args:
            data: Taranacak byte verisi.

        Returns:
            ScanResult
        """
        if not self._builtin_rules and not self._external_rule_paths:
            return ScanResult(errors=["Kural yuklenmemis. Once load_builtin_rules() cagiriniz."])

        start = time.perf_counter()

        if self._yara_available:
            matches, errors = self._scan_with_yara(data)
            backend = "yara-python"
        else:
            matches, errors = self._scan_with_fallback(data)
            backend = "regex-fallback"

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ScanResult(
            total_rules=self.rule_count,
            matches=matches,
            scan_time_ms=elapsed_ms,
            errors=errors,
            backend=backend,
        )

    # ------------------------------------------------------------------
    # Native YARA backend
    # ------------------------------------------------------------------

    def _compile_yara(self) -> None:
        """Tum kurallari yara-python ile compile et."""
        if self._rules_compiled and self._compiled_rules is not None:
            return

        yara = self._yara
        sources: dict[str, str] = {}

        # Dahili kurallar -> YARA kaynak koduna cevir
        if self._builtin_rules:
            builtin_src = "\n\n".join(
                _rule_to_yara_source(r) for r in self._builtin_rules
            )
            sources["builtin"] = builtin_src

        try:
            if self._external_rule_paths:
                # Harici .yar dosyalari
                filepaths = {
                    f"ext_{i}": str(p)
                    for i, p in enumerate(self._external_rule_paths)
                }
                if sources:
                    # Hem source hem filepath varsa — ayri compile edip merge
                    self._compiled_rules = yara.compile(sources=sources)
                    # Not: yara-python tek compile() cagrisinda
                    # sources + filepaths birlestirilemiyor.
                    # Dahili kurallari once compile edip, harici dosyalari
                    # ayrica compile ederiz.
                    ext_rules = yara.compile(filepaths=filepaths)
                    # Ikisini birlestirmek icin her ikisini de tutariz
                    self._compiled_rules = (self._compiled_rules, ext_rules)
                else:
                    self._compiled_rules = yara.compile(filepaths=filepaths)
            elif sources:
                self._compiled_rules = yara.compile(sources=sources)
            else:
                self._compiled_rules = None

            self._rules_compiled = True
        except Exception as exc:
            logger.error("YARA compile hatasi: %s", exc)
            self._compiled_rules = None
            self._rules_compiled = False

    def _scan_with_yara(self, data: bytes) -> tuple[list[YaraMatch], list[str]]:
        """Native YARA ile tara.

        Returns:
            (matches, errors)
        """
        errors: list[str] = []
        matches: list[YaraMatch] = []

        try:
            self._compile_yara()
        except Exception as exc:
            errors.append(f"YARA compile hatasi: {exc}")
            # Fallback'e dus
            return self._scan_with_fallback(data)

        if self._compiled_rules is None:
            errors.append("YARA kurallari compile edilemedi")
            return self._scan_with_fallback(data)

        def _process_yara_matches(yara_matches: list) -> None:
            for m in yara_matches:
                strings_data = []
                if hasattr(m, "strings"):
                    for s in m.strings:
                        if hasattr(s, "instances"):
                            # yara-python >= 4.3
                            for inst in s.instances:
                                strings_data.append((
                                    inst.offset,
                                    s.identifier,
                                    bytes(inst.matched_data),
                                ))
                        else:
                            # yara-python < 4.3: (offset, identifier, data) tuple
                            strings_data.append((s[0], s[1], s[2]))

                matches.append(YaraMatch(
                    rule=m.rule,
                    tags=list(m.tags) if hasattr(m, "tags") else [],
                    meta=dict(m.meta) if hasattr(m, "meta") else {},
                    strings=strings_data,
                    namespace=m.namespace if hasattr(m, "namespace") else "",
                ))

        try:
            if isinstance(self._compiled_rules, tuple):
                # Birden fazla compiled rules (dahili + harici)
                for rules_obj in self._compiled_rules:
                    yara_matches = rules_obj.match(data=data)
                    _process_yara_matches(yara_matches)
            else:
                yara_matches = self._compiled_rules.match(data=data)
                _process_yara_matches(yara_matches)
        except Exception as exc:
            errors.append(f"YARA scan hatasi: {exc}")
            # Fallback'e dus
            fb_matches, fb_errors = self._scan_with_fallback(data)
            return fb_matches, errors + fb_errors

        return matches, errors

    # ------------------------------------------------------------------
    # Regex fallback backend
    # ------------------------------------------------------------------

    def _scan_with_fallback(self, data: bytes) -> tuple[list[YaraMatch], list[str]]:
        """YARA yoksa regex-based fallback.

        Byte pattern'ler icin basit ``in`` (subsequence) araması,
        string pattern'ler icin regex araması yapar.

        PERF/MEM (v1.10.0 C5): Eskiden `data.decode("latin-1")` ile tum
        binary ikinci kez (str kopyasi) RAM'e aliniyordu. 200 MB binary
        icin +200-400 MB (Python 3 str overhead) OOM riski. Yeni versiyon:
        regex'i dogrudan bytes uzerinde calistirir (`re.finditer(b"...", data)`).

        Returns:
            (matches, errors)
        """
        errors: list[str] = []
        matches: list[YaraMatch] = []

        for rule in self._builtin_rules:
            found_strings: list[tuple[int, str, bytes]] = []

            # Byte pattern eslestirme
            for i, bp in enumerate(rule.byte_patterns):
                offset = data.find(bp)
                if offset >= 0:
                    found_strings.append((offset, f"$b{i}", bp))

            # String/regex pattern eslestirme -- bytes uzerinde
            for i, sp in enumerate(rule.string_patterns):
                sp_bytes = sp.encode("latin-1") if isinstance(sp, str) else sp
                # Once bytes regex dene
                try:
                    for m in re.finditer(sp_bytes, data, re.IGNORECASE):
                        found_strings.append((
                            m.start(),
                            f"$s{i}",
                            m.group(),
                        ))
                        break  # Kural basina ilk eslesme yeterli
                    continue
                except re.error:
                    logger.debug(
                        "YARA fallback: bytes regex derleme basarisiz, literal fallback",
                        exc_info=True,
                    )
                # Fallback: pattern regex olarak gecerli degil -> literal arama
                # (re.escape ile literal match; case-insensitive icin re.IGNORECASE.)
                try:
                    escaped = re.escape(sp_bytes)
                    m2 = re.search(escaped, data, re.IGNORECASE)
                    if m2 is not None:
                        found_strings.append((
                            m2.start(),
                            f"$s{i}",
                            m2.group(),
                        ))
                except Exception:
                    logger.debug(
                        "YARA fallback: literal arama basarisiz, atlaniyor",
                        exc_info=True,
                    )

            # Condition kontrolu
            matched = False
            if rule.condition == "all":
                # Tum pattern'ler eslesmeliydi
                total = len(rule.byte_patterns) + len(rule.string_patterns)
                if total > 0 and len(found_strings) >= total:
                    matched = True
            else:
                # Herhangi biri yeterli
                if found_strings:
                    matched = True

            if matched:
                matches.append(YaraMatch(
                    rule=rule.name,
                    tags=list(rule.tags),
                    meta=dict(rule.meta),
                    strings=found_strings,
                    namespace="builtin",
                ))

        return matches, errors

    # ------------------------------------------------------------------
    # Yardimci
    # ------------------------------------------------------------------

    def get_rules_by_tag(self, tag: str) -> list[BuiltinRule]:
        """Belirli bir tag'a sahip dahili kurallari getir."""
        return [r for r in self._builtin_rules if tag in r.tags]

    def get_rule_names(self) -> list[str]:
        """Tum dahili kural isimlerini dondur."""
        return [r.name for r in self._builtin_rules]

    def get_stats(self) -> dict[str, Any]:
        """Scanner istatistikleri."""
        tag_counts: dict[str, int] = {}
        for rule in self._builtin_rules:
            for tag in rule.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "backend": "yara-python" if self._yara_available else "regex-fallback",
            "builtin_rules": len(self._builtin_rules),
            "external_files": len(self._external_rule_paths),
            "compiled": self._rules_compiled,
            "tag_distribution": tag_counts,
        }

    def __repr__(self) -> str:
        backend = "yara" if self._yara_available else "fallback"
        return f"<YaraScanner backend={backend} rules={self.rule_count}>"
