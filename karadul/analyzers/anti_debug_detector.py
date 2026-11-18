"""Anti-debug detection modulu (v1.13 Dalga 1 Wave 2).

Malware ve protected binary'lerin debugger varligini tespit etmek icin
kullandigi anti-debug tekniklerini saf algoritmik / pattern-based
yontemlerle tespit eder. LLM kullanmaz.

Tespit katmanlari:
  1. Import-based  : PE imports / ELF dynsym / Mach-O imported_functions
                     icinden bilinen anti-debug API'larini taramak.
                     (En guvenilir, low-FP)
  2. String-based  : Binary string'leri icinde "OLLYDBG", "TracerPid:",
                     "/proc/self/status", debugger isimleri vb.
                     (Orta-yuksek confidence)
  3. Bytes-based   : PEB offset patterns (FS:[30h], GS:[60h]+0x02 / 0x68 /
                     0xBC), RDTSC opcode (0F 31), INT 3 cluster.
                     (Heuristic, dusuk confidence)
                     Yalniz x86 / x86-64 hedefte, yalniz yurutulebilir kod
                     bolgelerinde; komut sinirlari capstone ile (IMZA-02).

Confidence skorlama:
  - Tek bir kategori tek bir bulgu  : 0.30 - 0.65 (kategoriye gore)
  - Ayni teknik birden fazla katmanda tetiklenmis -> +0.20 boost
  - Onemli API (NtQueryInformationProcess, ptrace) +0.10 boost

Pipeline entegrasyonu (W2 sequential turunda eklenecek):
    from karadul.analyzers.anti_debug_detector import AntiDebugDetector
    detector = AntiDebugDetector(target=target_info, binary_path=path)
    findings = detector.detect()
    summary = detector.summary(findings)

Bagimliliklar:
    - karadul.core.target.TargetInfo
    - lief (opsiyonel; yoksa string + bytes katmanlari calisir)
    - subprocess (`strings`, `nm`, `objdump` opsiyonel)

Yazar: Karadul v1.13 Dalga 1 Wave 2
"""

from __future__ import annotations

import logging
import re
import struct
import subprocess
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from karadul.analyzers.packer_fingerprint import parse_pe_layout
# B21: cikplak subprocess.run yerine safe_run + resolve_tool (LD_PRELOAD/DYLD koruma).
from karadul.core.safe_subprocess import resolve_tool, safe_run

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler -- platform bazli anti-debug imza kataloglari
# ---------------------------------------------------------------------------

# Windows API'lari (kategori -> {api_adi: (technique, description, weight)})
# weight: o api'nin "ne kadar guclu sinyal" oldugunu belirler (0.3-0.7)
_WINDOWS_APIS: dict[str, tuple[str, str, float]] = {
    # kernel32
    "IsDebuggerPresent": (
        "IsDebuggerPresent",
        "Process icin BeingDebugged flag'ini sorgular (PEB+0x02)",
        0.55,
    ),
    "CheckRemoteDebuggerPresent": (
        "CheckRemoteDebuggerPresent",
        "Uzak debugger varligini kontrol eder",
        0.60,
    ),
    # OutputDebugString + GetLastError hilesi yalniz Vista oncesi Windows'ta
    # calisir; ithal olagan gunluk API'sidir (masum fastlist, Ghidra lzfse).
    # Tek ve ayirt edici olmayan kanit: zayif (IMZA-03).
    "OutputDebugStringA": (
        "OutputDebugString",
        "Exception trick ile debugger varligini tespit eder (zayif: olagan gunluk API'si)",
        0.30,
    ),
    "OutputDebugStringW": (
        "OutputDebugString",
        "Exception trick ile debugger varligini tespit eder (zayif: olagan gunluk API'si)",
        0.30,
    ),
    "GetTickCount": (
        "GetTickCount",
        "Timing-based anti-debug (yalniz baska sinyal varsa anlamli)",
        0.20,
    ),
    "GetTickCount64": (
        "GetTickCount",
        "Timing-based anti-debug",
        0.20,
    ),
    "QueryPerformanceCounter": (
        "QueryPerformanceCounter",
        "Yuksek cozunurlukte timing olcumu",
        0.25,
    ),
    "FindWindowA": (
        "FindWindow",
        "Debugger window class arama (OllyDbg, x64dbg)",
        0.35,
    ),
    "FindWindowW": (
        "FindWindow",
        "Debugger window class arama",
        0.35,
    ),
    "EnumProcesses": (
        "EnumProcesses",
        "Process listesi tarayarak debugger arama",
        0.30,
    ),
    "Process32First": (
        "Process32First",
        "Toolhelp32 ile process enumeration",
        0.30,
    ),
    "Process32FirstW": (
        "Process32First",
        "Toolhelp32 ile process enumeration",
        0.30,
    ),
    "Process32Next": (
        "Process32Next",
        "Toolhelp32 ile process enumeration",
        0.30,
    ),
    "CreateToolhelp32Snapshot": (
        "CreateToolhelp32Snapshot",
        "Process snapshot - debugger arama",
        0.30,
    ),
    "DebugActiveProcessStop": (
        "DebugActiveProcessStop",
        "Self-debugging trick (kendi kendini debug edip block etme)",
        0.45,
    ),
    "DebugActiveProcess": (
        "DebugActiveProcess",
        "Self-debugging trick",
        0.45,
    ),
    # ntdll (yuksek-onem)
    "NtQueryInformationProcess": (
        "NtQueryInformationProcess",
        "ProcessDebugPort / DebugFlags / DebugObjectHandle sorgular",
        0.65,
    ),
    "ZwQueryInformationProcess": (
        "NtQueryInformationProcess",
        "Nt* aynisi - syscall thunk",
        0.65,
    ),
    "NtSetInformationThread": (
        "NtSetInformationThread",
        "ThreadHideFromDebugger=0x11 ile thread'i debugger'dan gizler",
        0.65,
    ),
    "ZwSetInformationThread": (
        "NtSetInformationThread",
        "Nt* aynisi - syscall thunk",
        0.65,
    ),
    "NtQuerySystemInformation": (
        "NtQuerySystemInformation",
        "SystemKernelDebuggerInformation=0x23 sorgular",
        0.55,
    ),
    "ZwQuerySystemInformation": (
        "NtQuerySystemInformation",
        "Nt* aynisi - syscall thunk",
        0.55,
    ),
    "NtClose": (
        "NtClose_InvalidHandle",
        "Invalid handle ile NtClose -> debugger varsa STATUS_INVALID_HANDLE",
        0.30,
    ),
    "NtSetDebugFilterState": (
        "NtSetDebugFilterState",
        "Kernel debugger ile etkilesim",
        0.50,
    ),
}

# --- Derleyici calisma zamani (MSVC CRT) ithal kumesi (IMZA-03) ---
# MSVC ile derlenen hemen her PE, CRT'nin __security_init_cookie yolu icin
# QueryPerformanceCounter + GetCurrentProcessId + GetCurrentThreadId + bir zaman
# API'sini, __report_gsfailure / __scrt_fastfail yolu icin IsDebuggerPresent +
# UnhandledExceptionFilter'i ithal eder. Kume birlikte goruldugunde bu ithaller
# anti-debug kaniti degildir: "compiler_runtime" kategorisinde bilgi olarak
# kalir, puana girmez. (Olcum: 39 masum PE'nin 25'inde kume tam; eski CRT'lerde
# zaman API'si GetTickCount, yenilerde GetSystemTimeAsFileTime.)
_CRT_COOKIE_CORE = frozenset({
    "QueryPerformanceCounter", "GetCurrentProcessId", "GetCurrentThreadId",
})
_CRT_COOKIE_TIME = frozenset({
    "GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime",
    "GetTickCount", "GetTickCount64",
})
_CRT_COOKIE_EXPLAINED = frozenset({
    "QueryPerformanceCounter", "GetTickCount", "GetTickCount64",
})
_CRT_FASTFAIL_PAIR = "UnhandledExceptionFilter"
_CRT_FASTFAIL_EXPLAINED = frozenset({"IsDebuggerPresent"})
_CRT_CONFIDENCE = 0.10

# Linux libc API'lari (ptrace + /proc tabanli)
_LINUX_APIS: dict[str, tuple[str, str, float]] = {
    "ptrace": (
        "ptrace_traceme",
        "ptrace(PTRACE_TRACEME, ...) self-trace lock",
        0.65,
    ),
    "__ptrace": (
        "ptrace_traceme",
        "ptrace alias",
        0.65,
    ),
    # prctl cok amacli bir cagri (ad koyma, seccomp, PDEATHSIG ...); anti-debug
    # anlami yalniz PR_SET_DUMPABLE=0 argumaniyla. Argumani gormeden bilgi duzeyi.
    "prctl": (
        "prctl_import",
        "prctl ithali: prctl(PR_SET_DUMPABLE, 0) ile cekirdek dokumu / ptrace "
        "baglanmasi engellenebilir; argumani dogrulanmadi, tek basina hukum degil",
        0.15,
    ),
    "personality": (
        "personality_anti_debug",
        "personality(ADDR_NO_RANDOMIZE) ASLR off (debug counter)",
        0.20,
    ),
}

# macOS API'lari
_MACOS_APIS: dict[str, tuple[str, str, float]] = {
    "_ptrace": (
        "ptrace_pt_deny_attach",
        "ptrace(PT_DENY_ATTACH, ...) macOS deny-attach",
        0.70,
    ),
    "ptrace": (
        "ptrace_pt_deny_attach",
        "ptrace(PT_DENY_ATTACH, ...) macOS deny-attach",
        0.70,
    ),
    # sysctl surec listeleyen her aracta (top, htop, ps) ithal edilir; anti-debug
    # anlami yalniz KERN_PROC + P_TRACED denetimiyle. Argumani gormeden bilgi duzeyi.
    "_sysctl": (
        "sysctl_import",
        "sysctl ithali: sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID) + P_TRACED "
        "denetimi olabilir; argumani dogrulanmadi, tek basina hukum degil",
        0.15,
    ),
    "sysctl": (
        "sysctl_import",
        "sysctl ithali: KERN_PROC + P_TRACED denetimi olabilir; argumani "
        "dogrulanmadi, tek basina hukum degil",
        0.15,
    ),
    "_task_get_exception_ports": (
        "task_get_exception_ports",
        "Exception handler hijack tespiti",
        0.45,
    ),
    "task_get_exception_ports": (
        "task_get_exception_ports",
        "Exception handler hijack tespiti",
        0.45,
    ),
}

# Argumani bir sabite bagli olan, ama burada yalniz ithal tablosundan gorulen
# teknikler: hukum yok, bilgi duzeyi (IMZA-02). Argumani dogrulayan bir katman
# (Ghidra cagri yeri) gelene kadar guvenleri bilgi esiginin altinda kalir.
_ARG_UNVERIFIED_TECHNIQUES = frozenset({"prctl_import", "sysctl_import"})

# String pattern'leri (regex/literal -> (technique, kategori_yardimci, weight))
# (case-sensitive ascii ve UTF-16 LE her ikisini de tarariz)
_STRING_PATTERNS: list[tuple[re.Pattern[bytes], str, str, float]] = [
    # Debugger isimleri
    (re.compile(rb"(?i)OLLYDBG"), "DebuggerName_OllyDbg", "string", 0.45),
    (re.compile(rb"(?i)x64dbg"), "DebuggerName_x64dbg", "string", 0.45),
    (re.compile(rb"(?i)x32dbg"), "DebuggerName_x64dbg", "string", 0.45),
    (re.compile(rb"(?i)WinDbg"), "DebuggerName_WinDbg", "string", 0.45),
    (re.compile(rb"(?i)IDA[ _]?Pro"), "DebuggerName_IDA", "string", 0.40),
    (re.compile(rb"(?i)idaq(64)?\.exe"), "DebuggerName_IDA", "string", 0.50),
    (re.compile(rb"(?i)ImmunityDebugger"), "DebuggerName_Immunity", "string", 0.45),
    (re.compile(rb"(?i)RadareOrg|radare2|r2pipe"), "DebuggerName_Radare", "string", 0.40),
    (re.compile(rb"(?i)dnSpy"), "DebuggerName_dnSpy", "string", 0.40),
    (re.compile(rb"(?i)ScyllaHide"), "AntiDebug_ScyllaHide", "string", 0.55),
    # /proc tabanli
    (re.compile(rb"/proc/self/status"), "Linux_ProcStatus", "string", 0.50),
    (re.compile(rb"/proc/[0-9]+/status"), "Linux_ProcStatus", "string", 0.45),
    (re.compile(rb"TracerPid:"), "Linux_TracerPid", "string", 0.65),
    (re.compile(rb"/proc/self/maps"), "Linux_ProcMaps", "string", 0.30),
    # VM/sandbox isimleri (anti-VM, anti-debug ile beraber gelir)
    (re.compile(rb"(?i)VBoxService|VBoxTray"), "AntiVM_VirtualBox", "string", 0.30),
    (re.compile(rb"(?i)vmtoolsd|vmware"), "AntiVM_VMware", "string", 0.30),
    (re.compile(rb"(?i)qemu-ga|QEMU"), "AntiVM_QEMU", "string", 0.30),
    # Windows class names
    (re.compile(rb"OLLYDBG"), "WindowClass_OllyDbg", "string", 0.50),
    (re.compile(rb"WinDbgFrameClass"), "WindowClass_WinDbg", "string", 0.55),
]

# Byte pattern'leri (technique, kategori_yardimci, weight)
# Her pattern (description, byte_pattern, weight)
# byte_pattern: bytes (mask yok; tam eslesme)
#
# NOT (IMZA-02): Bu tablo yalniz capstone YOKKEN (bayt taramasi yedegi) kullanilir
# ve orada yalniz "PEB okumasi" (bilgi duzeyi) uretir. MSVC'nin statik UCRT'si
# de PEB'i okur (NtGlobalFlag & 0x100, ProcessParameters); PEB'e erismek tek
# basina anti-debug degildir. Hukum icin BeingDebugged (PEB+2) ya da
# NtGlobalFlag & 0x70 denetimi gerekir; o da komut duzeyinde (capstone) aranir.

# x86 PEB ve TEB tabanli pattern'ler
_BYTE_PATTERNS: list[tuple[bytes, str, str, float, str]] = [
    # FS:[30h] -> PEB pointer (mov eax, fs:[30h]) -- 32-bit
    # 64-A1 30 00 00 00 = mov eax, fs:[30h]
    (b"\x64\xa1\x30\x00\x00\x00", "PEB_FS30_x86", "peb", 0.55,
     "FS:[30h] PEB ptr (32-bit)"),
    # 64 8B  ?? 30 00 00 00 -> mov reg, fs:[30h] (genel)
    # GS:[60h] -> PEB pointer (64-bit)
    # 65 48 8B 04 25 60 00 00 00 = mov rax, gs:[60h]
    (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "PEB_GS60_x64", "peb", 0.55,
     "GS:[60h] PEB ptr (64-bit)"),
    # 65 48 8B  ?? 25 60 00 00 00 -> mov reg64, gs:[60h] (varyant)
    (b"\x65\x48\x8b\x0c\x25\x60\x00\x00\x00", "PEB_GS60_x64", "peb", 0.55,
     "GS:[60h] PEB ptr (mov rcx, gs:[60h])"),
    (b"\x65\x48\x8b\x14\x25\x60\x00\x00\x00", "PEB_GS60_x64", "peb", 0.55,
     "GS:[60h] PEB ptr (mov rdx, gs:[60h])"),
    (b"\x65\x48\x8b\x1c\x25\x60\x00\x00\x00", "PEB_GS60_x64", "peb", 0.55,
     "GS:[60h] PEB ptr (mov rbx, gs:[60h])"),
]

# PEB desenlerinin anlamli oldugu mimari: FS:[30h] yalniz 32-bit x86 PE'de,
# GS:[60h] yalniz x86-64 PE'de PEB'i gosterir (IMZA-02).
_PEB_PATTERN_ARCH: dict[str, str] = {
    "PEB_FS30_x86": "x86",
    "PEB_GS60_x64": "x86_64",
}

# Tek tek opcode pattern'leri (PEB offset olmadan)
# Bunlar yuksek FP riskli - sayim yapip esige gore karar veriyoruz
_RDTSC_BYTES = b"\x0f\x31"           # rdtsc
_RDTSCP_BYTES = b"\x0f\x01\xf9"      # rdtscp
_INT3 = b"\xcc"                       # int3
_SIDT_BYTES = b"\x0f\x01"             # sidt/sgdt prefix (red pill icin)

# x86 islem kodu taramasinin yapildigi mimariler (IMZA-02): AArch64 / ARM
# ikilide "0F 31" bir komut degil, rastgele veridir.
_X86_ARCHES = frozenset({"x86", "x86_64"})

# Guven duzeyleri. Rapor esikleri: >= 0,4 MED, >= 0,7 HIGH, altı INFO.
# Zayif kanit (<= _WEAK_MAX_CONFIDENCE) tek basina ya da toplanarak hukme
# donusmez (IMZA-03); bilgi duzeyi bulgular yalniz analiste ipucudur.
_WEAK_MAX_CONFIDENCE = 0.30
_INFO_CONFIDENCE = 0.15
_PEB_CHECK_CONFIDENCE = 0.55
_RDTSC_SINGLE_CONFIDENCE = 0.20
_RDTSC_MULTI_CONFIDENCE = 0.30   # zayif ust sinir: sayi artsa da yukselmez

# PEB'e komut duzeyinde erisim (capstone). x86-64: mov reg, qword ptr gs:[0x60];
# x86: mov reg, dword ptr fs:[0x30]. Ardindan _PEB_LOOKAHEAD komut icinde
# BeingDebugged (byte [reg+2]) ya da NtGlobalFlag ([reg+0xBC] / [reg+0x68])
# & 0x70 denetimi gorulurse hukum; gorulmezse yalniz "PEB okumasi" (bilgi).
_PEB_LOAD_RE: dict[str, re.Pattern[str]] = {
    "x86_64": re.compile(r"^(\w+), qword ptr gs:\[0x60\]$"),
    "x86": re.compile(r"^(\w+), dword ptr fs:\[0x30\]$"),
}
_PEB_TECHNIQUE: dict[str, str] = {"x86_64": "PEB_GS60_x64", "x86": "PEB_FS30_x86"}
_PEB_BEING_DEBUGGED_DISP = 0x2
_PEB_NTGLOBALFLAG_DISP: dict[str, int] = {"x86_64": 0xBC, "x86": 0x68}
# FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS:
# hata ayiklayici altinda baslatilan surecte NtGlobalFlag'e bu bitler yazilir.
_NTGLOBALFLAG_DEBUG_MASK = 0x70
_PEB_LOOKAHEAD = 4

# Fonksiyonlar arasi hizalama: derleyiciler (MSVC, clang-cl) bir sonraki
# fonksiyonu bu sinira hizalar ve araya 0xCC doldurur (IMZA-03).
_FUNC_ALIGN = 16
_INT3_MIN_RUN = 8
# Hizalama icin kullanilan x86 NOP kodlamalari (Intel SDM onerilen cok baytli
# NOP'lar + 66 onekleri): MSVC'nin el yazmasi rutinleri "CC... + NOP" ile hizalar.
_X86_NOP_RUN_RE = re.compile(
    rb"(?:\x90|\x66*\x0f\x1f(?:\x00|\x40\x00|\x44\x00\x00|\x80\x00\x00\x00\x00"
    rb"|\x84\x00\x00\x00\x00\x00))*"
)

# --- ELF / Mach-O sabitleri (yalniz kod bolgesi + mimari icin) ---
_ELF_MACHINE_ARCH: dict[int, str] = {
    3: "x86",        # EM_386
    62: "x86_64",    # EM_X86_64
    183: "arm64",    # EM_AARCH64
    40: "arm",       # EM_ARM
}
_ELF_SHF_EXECINSTR = 0x4
_ELF_SHT_NOBITS = 8
_ELF_PT_LOAD = 1
_ELF_PF_X = 0x1

_MACHO_CPU_ARCH: dict[int, str] = {
    7: "x86",              # CPU_TYPE_X86
    0x01000007: "x86_64",  # CPU_TYPE_X86_64
    12: "arm",             # CPU_TYPE_ARM
    0x0100000C: "arm64",   # CPU_TYPE_ARM64
    0x0200000C: "arm64",   # CPU_TYPE_ARM64_32
}
_MACHO_LC_SEGMENT = 0x1
_MACHO_LC_SEGMENT_64 = 0x19
# S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS: bolum makine kodu icerir
# (__TEXT,__text, __stubs, __stub_helper ...).
_MACHO_S_ATTR_INSTRUCTIONS = 0x80000000 | 0x00000400
_MACHO_S_ZEROFILL = 0x1
_MACHO_SECTION_TYPE_MASK = 0xFF
# Evrensel ikilide x86 islem kodu taramasi icin dilim tercihi.
_FAT_SLICE_PREFERENCE = ("x86_64", "x86")
# Java .class dosyasi da CAFEBABE ile baslar; evrensel Mach-O'da dilim sayisi kucuktur.
_FAT_MAX_ARCHS = 32

# Confidence boost'lari
_BOOST_NT_API = 0.10
_BOOST_MULTI_LAYER = 0.20
_MAX_CONFIDENCE = 0.99


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AntiDebugFinding:
    """Tek bir anti-debug bulgusu.

    Attributes:
        technique: Teknik adi (ornek: "IsDebuggerPresent",
            "PEB.BeingDebugged", "ptrace_traceme").
        category: Tespit kategorisi -- "windows_api" / "peb" /
            "ptrace" / "timing" / "macos" / "string".
        confidence: 0.0 - 1.0 arasi guven.
        evidence: Bulgunun kanitini iceren kisa metin (sembol, string
            ya da offset).
        platform: "windows" / "linux" / "macos" / "any".
        description: Kisa Turkce aciklama.
    """

    technique: str
    category: str
    confidence: float
    evidence: str
    platform: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Kod yerlesimi: bicim, mimari, yurutulebilir kod araliklari (IMZA-02)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeRegion:
    """Yurutulebilir kodun dosyadaki [start, end) araligi ve bellek adresi."""
    name: str
    start: int
    end: int
    vaddr: int


@dataclass(frozen=True)
class CodeLayout:
    """Ikilinin bicimi, mimarisi ve yurutulebilir kod bolgeleri.

    fmt: "pe" | "elf" | "macho" | "unknown"
    arch: "x86" | "x86_64" | "arm64" | "arm" | "other" | "unknown"
    note: insan icin kisa aciklama (or. evrensel Mach-O'da secilen dilim).
    """
    fmt: str
    arch: str
    regions: tuple[CodeRegion, ...] = ()
    note: str = ""


_UNKNOWN_LAYOUT = CodeLayout("unknown", "unknown")


def _elf_layout(data: bytes) -> CodeLayout:
    """ELF: e_machine + SHF_EXECINSTR bolumleri (yoksa PF_X PT_LOAD)."""
    if len(data) < 52:
        return CodeLayout("elf", "unknown")
    ei_class, ei_data = data[4], data[5]
    end = "<" if ei_data == 1 else ">"
    machine = struct.unpack_from(end + "H", data, 18)[0]
    arch = _ELF_MACHINE_ARCH.get(machine, "other")
    regions: list[CodeRegion] = []
    size = len(data)
    if ei_class == 2:
        if len(data) < 64:
            return CodeLayout("elf", arch)
        phoff, shoff = struct.unpack_from(end + "QQ", data, 32)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", data, 54)
    elif ei_class == 1:
        phoff, shoff = struct.unpack_from(end + "II", data, 28)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", data, 42)
    else:
        return CodeLayout("elf", arch)

    # 1) Bolum tablosu: SHF_EXECINSTR ve dosyada verisi olan bolumler.
    if shoff and shnum and shentsize >= (64 if ei_class == 2 else 40):
        for i in range(min(shnum, 4096)):
            off = shoff + i * shentsize
            if off + shentsize > size:
                break
            if ei_class == 2:
                sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                    end + "IQQQQ", data, off + 4)
            else:
                sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                    end + "IIIII", data, off + 4)
            if not (sh_flags & _ELF_SHF_EXECINSTR) or sh_type == _ELF_SHT_NOBITS:
                continue
            if sh_size == 0 or sh_offset >= size:
                continue
            regions.append(CodeRegion(f"shdr#{i}", sh_offset,
                                      min(sh_offset + sh_size, size), sh_addr))
    # 2) Bolum tablosu yoksa (sh tablosu silinmis): yurutulebilir PT_LOAD.
    if not regions and phoff and phnum and phentsize >= (56 if ei_class == 2 else 32):
        for i in range(min(phnum, 4096)):
            off = phoff + i * phentsize
            if off + phentsize > size:
                break
            if ei_class == 2:
                p_type, p_flags, p_offset, p_vaddr = struct.unpack_from(end + "IIQQ", data, off)
                p_filesz = struct.unpack_from(end + "Q", data, off + 32)[0]
            else:
                p_type, p_offset, p_vaddr = struct.unpack_from(end + "III", data, off)
                p_filesz = struct.unpack_from(end + "I", data, off + 16)[0]
                p_flags = struct.unpack_from(end + "I", data, off + 24)[0]
            if p_type != _ELF_PT_LOAD or not (p_flags & _ELF_PF_X) or p_filesz == 0:
                continue
            if p_offset >= size:
                continue
            regions.append(CodeRegion(f"phdr#{i}", p_offset,
                                      min(p_offset + p_filesz, size), p_vaddr))
    return CodeLayout("elf", arch, tuple(regions))


def _macho_thin_layout(data: bytes, base: int = 0, limit: Optional[int] = None) -> CodeLayout:
    """Tek mimarili Mach-O (``base`` ofsetinde): cputype + komut iceren bolumler."""
    size = len(data) if limit is None else min(len(data), limit)
    if base + 28 > size:
        return CodeLayout("macho", "unknown")
    magic = data[base:base + 4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        end = "<"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        end = ">"
    else:
        return CodeLayout("macho", "unknown")
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    cputype, _sub, _ftype, ncmds = struct.unpack_from(end + "iIII", data, base + 4)
    arch = _MACHO_CPU_ARCH.get(cputype & 0xFFFFFFFF, "other")
    off = base + (32 if is64 else 28)
    regions: list[CodeRegion] = []
    for _ in range(min(ncmds, 4096)):
        if off + 8 > size:
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, off)
        if cmdsize < 8 or off + cmdsize > size:
            break
        if cmd in (_MACHO_LC_SEGMENT, _MACHO_LC_SEGMENT_64):
            seg64 = cmd == _MACHO_LC_SEGMENT_64
            hdr = 72 if seg64 else 56
            sect_size = 80 if seg64 else 68
            nsects = struct.unpack_from(end + "I", data, off + (64 if seg64 else 48))[0]
            s = off + hdr
            for _j in range(min(nsects, (cmdsize - hdr) // sect_size)):
                sectname = data[s:s + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
                segname = data[s + 16:s + 32].split(b"\x00", 1)[0].decode("ascii", "replace")
                if seg64:
                    addr, ssize = struct.unpack_from(end + "QQ", data, s + 32)
                    soff = struct.unpack_from(end + "I", data, s + 48)[0]
                    flags = struct.unpack_from(end + "I", data, s + 64)[0]
                else:
                    addr, ssize, soff = struct.unpack_from(end + "III", data, s + 32)
                    flags = struct.unpack_from(end + "I", data, s + 56)[0]
                s += sect_size
                if not (flags & _MACHO_S_ATTR_INSTRUCTIONS):
                    continue
                if (flags & _MACHO_SECTION_TYPE_MASK) == _MACHO_S_ZEROFILL:
                    continue
                if soff == 0 or ssize == 0:
                    continue
                start = base + soff
                if start >= size:
                    continue
                regions.append(CodeRegion(f"{segname},{sectname}", start,
                                          min(start + ssize, size), addr))
        off += cmdsize
    return CodeLayout("macho", arch, tuple(regions))


def _macho_fat_layout(data: bytes) -> CodeLayout:
    """Evrensel Mach-O: x86 islem kodu icin x86-64 (yoksa i386) dilimi secilir."""
    magic = data[:4]
    is64 = magic == b"\xca\xfe\xba\xbf"
    nfat = struct.unpack_from(">I", data, 4)[0]
    if nfat == 0 or nfat > _FAT_MAX_ARCHS:
        return _UNKNOWN_LAYOUT  # buyuk olasilikla Java .class
    slices: list[tuple[str, int, int]] = []
    ent = 32 if is64 else 20
    for i in range(nfat):
        off = 8 + i * ent
        if off + ent > len(data):
            break
        if is64:
            cputype, _sub, s_off, s_size = struct.unpack_from(">iIQQ", data, off)
        else:
            cputype, _sub, s_off, s_size = struct.unpack_from(">iIII", data, off)
        slices.append((_MACHO_CPU_ARCH.get(cputype & 0xFFFFFFFF, "other"), s_off, s_size))
    if not slices:
        return CodeLayout("macho", "unknown")
    chosen = slices[0]
    for want in _FAT_SLICE_PREFERENCE:
        hit = next((s for s in slices if s[0] == want), None)
        if hit is not None:
            chosen = hit
            break
    arch_name, s_off, s_size = chosen
    thin = _macho_thin_layout(data, base=s_off, limit=s_off + s_size)
    archs = ",".join(s[0] for s in slices)
    return CodeLayout("macho", thin.arch, thin.regions,
                      note=f"evrensel Mach-O ({archs}); {arch_name} dilimi @0x{s_off:x}")


def _pe_layout(data: bytes) -> CodeLayout:
    """PE: COFF makine turu + IMAGE_SCN_MEM_EXECUTE bolumleri."""
    pe = parse_pe_layout(data)
    if pe is None:
        return CodeLayout("pe", "unknown")
    regions: list[CodeRegion] = []
    for sec in pe.sections:
        if not sec.executable:
            continue
        rng = sec.file_range(len(data))
        if rng is None:
            continue
        regions.append(CodeRegion(sec.name, rng[0], rng[1], sec.virtual_address))
    return CodeLayout("pe", pe.arch, tuple(regions))


def code_layout(data: bytes) -> CodeLayout:
    """Ham ikiliden bicim, mimari ve yurutulebilir kod araliklarini cikar.

    Taninmayan bicimde ``fmt="unknown"`` doner; cagiran x86 islem kodu
    taramasini o durumda YAPMAZ (mimari bilinmeden "0F 31" rdtsc degildir).
    """
    try:
        if data[:2] == b"MZ":
            return _pe_layout(data)
        if data[:4] == b"\x7fELF":
            return _elf_layout(data)
        if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            return _macho_thin_layout(data)
        if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(data) >= 8:
            return _macho_fat_layout(data)
    except (struct.error, IndexError) as exc:
        logger.debug("kod yerlesimi cozumlenemedi: %s", exc)
    return _UNKNOWN_LAYOUT


@dataclass
class X86CodeScan:
    """x86 kod bolgelerinin komut duzeyindeki tarama sonucu."""
    decoder: str                                   # "capstone" | "bayt taramasi"
    rdtsc: int = 0
    rdtscp: int = 0
    peb_checks: list[tuple[int, str]] = field(default_factory=list)  # (ofset, ne)
    peb_reads: list[int] = field(default_factory=list)               # ofsetler


_DISP_RE_CACHE: dict[str, re.Pattern[str]] = {}
# capstone son islenen anlik deger: kucukler ondalik ("1"), buyukler onaltilik ("0x70")
_IMM_TAIL_RE = re.compile(r", (0x[0-9a-f]+|\d+)$")


def _mem_disp(reg: str, op_str: str) -> Optional[int]:
    """``op_str`` icinde ``[reg + disp]`` bellek islenenindeki ``disp`` (yoksa None)."""
    pat = _DISP_RE_CACHE.get(reg)
    if pat is None:
        pat = re.compile(r"\[" + re.escape(reg) + r" \+ (0x[0-9a-f]+|\d+)\]")
        _DISP_RE_CACHE[reg] = pat
    m = pat.search(op_str)
    return int(m.group(1), 0) if m else None


def _peb_follow(pending: list, mnem: str, op_str: str, arch: str) -> Optional[str]:
    """PEB yuklemesinden sonraki bir komut; denetim gorulurse aciklamasini doner.

    ``pending`` = [ofset, kayit, kalan_komut, ntglobalflag_okundu]
    """
    reg = pending[1]
    disp = _mem_disp(reg, op_str)
    if disp == _PEB_BEING_DEBUGGED_DISP and "byte ptr" in op_str:
        return f"PEB.BeingDebugged (byte [{reg}+2])"
    if disp == _PEB_NTGLOBALFLAG_DISP[arch]:
        pending[3] = True
        return None
    if pending[3] and mnem in ("and", "test"):
        imm = _IMM_TAIL_RE.search(op_str)
        if imm and int(imm.group(1), 0) == _NTGLOBALFLAG_DEBUG_MASK:
            return f"PEB.NtGlobalFlag & {_NTGLOBALFLAG_DEBUG_MASK:#x}"
    return None


def _scan_x86_capstone(capstone: Any, data: bytes, layout: CodeLayout) -> X86CodeScan:
    """capstone ile kod bolgelerini dogrusal tara (komut sinirlarina uyarak)."""
    mode = capstone.CS_MODE_64 if layout.arch == "x86_64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.skipdata = True  # cozulemeyen bayt taramayi durdurmasin
    scan = X86CodeScan(decoder="capstone")
    load_re = _PEB_LOAD_RE[layout.arch] if layout.fmt == "pe" else None
    for region in layout.regions:
        pending: list[list] = []
        for addr, _size, mnem, op_str in md.disasm_lite(
                data[region.start:region.end], 0):
            if mnem == "rdtsc":
                scan.rdtsc += 1
            elif mnem == "rdtscp":
                scan.rdtscp += 1
            if load_re is None:
                continue
            if pending:
                still: list[list] = []
                for p in pending:
                    what = _peb_follow(p, mnem, op_str, layout.arch)
                    if what is not None:
                        scan.peb_checks.append((p[0], what))
                        continue
                    p[2] -= 1
                    if p[2] > 0:
                        still.append(p)
                    else:
                        scan.peb_reads.append(p[0])
                pending = still
            if mnem == "mov":
                m = load_re.match(op_str)
                if m:
                    pending.append([region.start + addr, m.group(1), _PEB_LOOKAHEAD, False])
        scan.peb_reads.extend(p[0] for p in pending)
    return scan


def _scan_x86_bytes(data: bytes, layout: CodeLayout) -> X86CodeScan:
    """capstone yoksa: kod bolgelerinde bayt taramasi (komut siniri dogrulanmaz)."""
    scan = X86CodeScan(decoder="bayt taramasi")
    for r in layout.regions:
        seg = data[r.start:r.end]
        scan.rdtsc += AntiDebugDetector._count_nonoverlapping(seg, _RDTSC_BYTES)
        scan.rdtscp += AntiDebugDetector._count_nonoverlapping(seg, _RDTSCP_BYTES)
    if layout.fmt == "pe":
        for byte_pat, technique, _cat, _w, _desc in _BYTE_PATTERNS:
            if _PEB_PATTERN_ARCH.get(technique) != layout.arch:
                continue
            for r in layout.regions:
                idx = data.find(byte_pat, r.start, r.end)
                while idx >= 0:
                    scan.peb_reads.append(idx)
                    idx = data.find(byte_pat, idx + 1, r.end)
        scan.peb_reads.sort()
    return scan


def _scan_x86_code(data: bytes, layout: CodeLayout) -> X86CodeScan:
    """x86 kod bolgelerini tara: capstone varsa komut duzeyinde, yoksa bayt."""
    try:
        import capstone
    except ImportError:
        capstone = None
    if capstone is not None:
        try:
            return _scan_x86_capstone(capstone, data, layout)
        except Exception as exc:  # capstone surum/ABI sorunu: bayta dus
            logger.debug("capstone taramasi basarisiz, bayt taramasina dusuluyor: %s", exc)
    return _scan_x86_bytes(data, layout)


# ---------------------------------------------------------------------------
# AntiDebugDetector
# ---------------------------------------------------------------------------

class AntiDebugDetector:
    """Binary uzerinde anti-debug teknik tespiti yapar.

    3 katman halinde calisir: import-based, string-based, bytes-based.
    Sonuclar AntiDebugFinding listesi olarak donerilir; ayni teknik
    birden fazla katmanda tetiklenmisse `summary()` ve `detect()`
    confidence'i +0.20 yukseltir.

    Cagrim:
        detector = AntiDebugDetector(target_info, binary_path)
        findings = detector.detect()
        summary = detector.summary(findings)
    """

    def __init__(
        self,
        target: Optional[Any] = None,
        binary_path: Optional[Path] = None,
        max_bytes_scan: int = 50 * 1024 * 1024,  # 50 MB
    ) -> None:
        """Detector'u baslat.

        Args:
            target: Opsiyonel TargetInfo benzeri obje. `target.path`
                ve `target.target_type` okunur.
            binary_path: Binary dosya yolu. target verilmediginde
                zorunlu.
            max_bytes_scan: String + byte tarama icin maksimum dosya
                boyutu (default 50 MB).
        """
        self._target = target
        if binary_path is None and target is not None:
            tgt_path = getattr(target, "path", None)
            if tgt_path is not None:
                binary_path = Path(tgt_path)
        if binary_path is None:
            raise ValueError("binary_path veya target.path verilmeli")
        self.binary_path = Path(binary_path)
        self.max_bytes_scan = max_bytes_scan

        # Lazy yuklenen veriler
        self._raw_bytes: Optional[bytes] = None
        self._imports: Optional[list[str]] = None
        self._format: Optional[str] = None  # "PE" / "ELF" / "MACHO" / "UNKNOWN"
        self._layout: Optional[CodeLayout] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self) -> list[AntiDebugFinding]:
        """Tum katmanlari calistir, multi-layer boost uygula, donder.

        Returns:
            AntiDebugFinding listesi (confidence azalan sirayla).
        """
        all_findings: list[AntiDebugFinding] = []

        try:
            all_findings.extend(self.detect_by_imports())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("import-based detect hatasi: %s", exc)

        try:
            all_findings.extend(self.detect_by_strings())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("string-based detect hatasi: %s", exc)

        try:
            all_findings.extend(self.detect_by_bytes())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("bytes-based detect hatasi: %s", exc)

        # Multi-layer boost: ayni technique birden fazla kategoride varsa
        boosted = self._apply_multilayer_boost(all_findings)

        # Confidence azalan sirada
        boosted.sort(key=lambda f: (-f.confidence, f.technique))
        return boosted

    def summary(
        self, findings: list[AntiDebugFinding],
    ) -> dict[str, Any]:
        """Bulgular icin agregat istatistik dondurur.

        Returns:
            {
              "total": int,
              "by_category": {"windows_api": N, ...},
              "by_platform": {"windows": N, ...},
              "high_confidence": [findings >= 0.7],
              "techniques": [unique technique names],
              "max_confidence": float,
              "anti_debug_score": float,   # 0.0 - 1.0 toplam skor
            }
        """
        by_category: dict[str, int] = defaultdict(int)
        by_platform: dict[str, int] = defaultdict(int)
        techniques: set[str] = set()
        high_conf: list[AntiDebugFinding] = []
        max_conf = 0.0

        for f in findings:
            by_category[f.category] += 1
            by_platform[f.platform] += 1
            techniques.add(f.technique)
            if f.confidence >= 0.7:
                high_conf.append(f)
            if f.confidence > max_conf:
                max_conf = f.confidence

        # Toplam anti-debug skoru (IMZA-03): yalniz zayif ustu (> 0,30) ve
        # derleyici calisma zamanina ait olmayan bulgular hukme girer:
        #   max(guclu) + 0.05 * (guclu teknik sayisi - 1), 1.0 ile sinirli.
        # Zayif / bilgi bulgulari toplanarak yukseltilmez; yalniz onlar varsa
        # puan en guclusunun guvenidir (<= 0,30 -> rapor INFO).
        strong = [
            f for f in findings
            if f.confidence > _WEAK_MAX_CONFIDENCE and f.category != "compiler_runtime"
        ]
        if strong:
            strong_techniques = {f.technique for f in strong}
            score = min(
                1.0,
                max(f.confidence for f in strong)
                + 0.05 * max(0, len(strong_techniques) - 1),
            )
        elif findings:
            score = max_conf
        else:
            score = 0.0

        return {
            "total": len(findings),
            "by_category": dict(by_category),
            "by_platform": dict(by_platform),
            "high_confidence": [f.to_dict() for f in high_conf],
            "techniques": sorted(techniques),
            "max_confidence": max_conf,
            "anti_debug_score": round(score, 3),
        }

    # ------------------------------------------------------------------
    # Layer 1: Imports (PE / ELF / Mach-O)
    # ------------------------------------------------------------------

    def detect_by_imports(self) -> list[AntiDebugFinding]:
        """Imported function isimlerinden anti-debug API tespiti.

        Katalog bicime baglidir (IMZA-02): PE'de yalniz Windows, ELF'te yalniz
        Linux, Mach-O'da yalniz macOS API'lari aranir; bicim taninmazsa ucu de.
        Argumani sabite bagli teknikler (``sysctl`` -> KERN_PROC + P_TRACED,
        ``prctl`` -> PR_SET_DUMPABLE) yalniz ithal edildiyse hukum degil bilgi
        duzeyinde raporlanir: argumani gormeden olagan kullanimdan ayrilamaz.
        """
        imports = self._load_imports()
        if not imports:
            return []

        fmt = self._code_layout().fmt
        use_windows = fmt in ("pe", "unknown")
        use_linux = fmt in ("elf", "unknown")
        use_macos = fmt in ("macho", "unknown")

        findings: list[AntiDebugFinding] = []
        seen_techniques: set[tuple[str, str]] = set()
        crt_explained, crt_note = (
            self._crt_explained_imports(imports) if fmt == "pe" else (frozenset(), ""))

        # Hepsini tek normalleskmis stringe coevir
        for sym in imports:
            sym_clean = sym.strip()
            if not sym_clean:
                continue
            # Mach-O sembolleri "_" ile baslar — hem ham hem strip edilmis kontrol
            sym_no_leading = sym_clean.lstrip("_") if sym_clean.startswith("_") else sym_clean

            # Windows API
            for api_name, (technique, desc, weight) in (
                    _WINDOWS_APIS.items() if use_windows else ()):
                if sym_clean == api_name or sym_no_leading == api_name:
                    if api_name in crt_explained:
                        # Derleyici calisma zamaninin olagan ithali (IMZA-03)
                        key = (technique, "compiler_runtime")
                        if key not in seen_techniques:
                            seen_techniques.add(key)
                            findings.append(AntiDebugFinding(
                                technique=technique,
                                category="compiler_runtime",
                                confidence=_CRT_CONFIDENCE,
                                evidence=f"import: {sym_clean} ({crt_note})",
                                platform="windows",
                                description=(
                                    "MSVC CRT'nin olagan ithali; cagri yeri "
                                    "dogrulanmadi, anti-debug sayilmadi"
                                ),
                            ))
                        break
                    key = (technique, "windows_api")
                    if key in seen_techniques:
                        break
                    seen_techniques.add(key)
                    conf = weight
                    if (technique.startswith("Nt")
                            or technique == "NtQueryInformationProcess"):
                        conf = min(_MAX_CONFIDENCE, conf + _BOOST_NT_API)
                    findings.append(AntiDebugFinding(
                        technique=technique,
                        category="windows_api",
                        confidence=round(conf, 3),
                        evidence=f"import: {sym_clean}",
                        platform="windows",
                        description=desc,
                    ))
                    break

            # Linux API
            for api_name, (technique, desc, weight) in (
                    _LINUX_APIS.items() if use_linux else ()):
                if sym_clean == api_name or sym_no_leading == api_name:
                    key = (technique, "ptrace")
                    if key in seen_techniques:
                        break
                    seen_techniques.add(key)
                    findings.append(AntiDebugFinding(
                        technique=technique,
                        category="ptrace",
                        confidence=round(weight, 3),
                        evidence=self._import_evidence(sym_clean, technique),
                        platform="linux",
                        description=desc,
                    ))
                    break

            # macOS API
            for api_name, (technique, desc, weight) in (
                    _MACOS_APIS.items() if use_macos else ()):
                if sym_clean == api_name or sym_no_leading == api_name:
                    key = (technique, "macos")
                    if key in seen_techniques:
                        break
                    seen_techniques.add(key)
                    findings.append(AntiDebugFinding(
                        technique=technique,
                        category="macos",
                        confidence=round(weight, 3),
                        evidence=self._import_evidence(sym_clean, technique),
                        platform="macos",
                        description=desc,
                    ))
                    break

        return findings

    @staticmethod
    def _crt_explained_imports(imports: list[str]) -> tuple[frozenset[str], str]:
        """MSVC CRT ithal kumesi gorulduyse onun acikladigi API adlari + not.

        Kume: __security_init_cookie (QPC + GetCurrentProcessId +
        GetCurrentThreadId + bir zaman API'si); IsDebuggerPresent icin ayrica
        __report_gsfailure / __scrt_fastfail esi UnhandledExceptionFilter.
        """
        names = {s.strip() for s in imports}
        if not (_CRT_COOKIE_CORE <= names and names & _CRT_COOKIE_TIME):
            return frozenset(), ""
        explained = set(_CRT_COOKIE_EXPLAINED)
        parts = ["__security_init_cookie: QPC + GetCurrentProcessId + GetCurrentThreadId + "
                 + "/".join(sorted(names & _CRT_COOKIE_TIME))]
        if _CRT_FASTFAIL_PAIR in names:
            explained |= _CRT_FASTFAIL_EXPLAINED
            parts.append(f"__report_gsfailure: IsDebuggerPresent + {_CRT_FASTFAIL_PAIR}")
        return frozenset(explained), "MSVC CRT ithal kumesi; " + "; ".join(parts)

    @staticmethod
    def _import_evidence(symbol: str, technique: str) -> str:
        """Ithal kaniti; argumani dogrulanmamis tekniklerde bunu acikca yazar."""
        if technique in _ARG_UNVERIFIED_TECHNIQUES:
            return f"import: {symbol} (yalniz ithal; argumani dogrulanmadi)"
        return f"import: {symbol}"

    # ------------------------------------------------------------------
    # Layer 2: Strings
    # ------------------------------------------------------------------

    def detect_by_strings(self) -> list[AntiDebugFinding]:
        """Binary string'lerinde anti-debug pattern arama."""
        data = self._load_bytes()
        if not data:
            return []

        findings: list[AntiDebugFinding] = []
        seen: set[str] = set()

        for pattern, technique, _hint, weight in _STRING_PATTERNS:
            match = pattern.search(data)
            if match is None:
                continue
            if technique in seen:
                continue
            seen.add(technique)

            evidence_text = match.group(0).decode("ascii", errors="replace")
            # Cok uzun gosterme
            if len(evidence_text) > 80:
                evidence_text = evidence_text[:77] + "..."

            # Platform tahmini (technique adina gore)
            platform = self._guess_platform(technique)

            findings.append(AntiDebugFinding(
                technique=technique,
                category="string",
                confidence=round(weight, 3),
                evidence=f"string: '{evidence_text}' @0x{match.start():x}",
                platform=platform,
                description=self._describe_string(technique),
            ))

        # UTF-16 LE icin sadece debugger isimleri (Windows yaygin)
        # "OLLYDBG" -> "O\x00L\x00L\x00..." vb.
        utf16_targets = [
            (b"O\x00L\x00L\x00Y\x00D\x00B\x00G\x00", "DebuggerName_OllyDbg",
             "windows", 0.50),
            (b"x\x006\x004\x00d\x00b\x00g\x00", "DebuggerName_x64dbg",
             "windows", 0.50),
            (b"W\x00i\x00n\x00D\x00b\x00g\x00", "DebuggerName_WinDbg",
             "windows", 0.50),
        ]
        for needle, technique, platform, weight in utf16_targets:
            if needle in data and technique not in seen:
                seen.add(technique)
                offset = data.find(needle)
                findings.append(AntiDebugFinding(
                    technique=technique,
                    category="string",
                    confidence=round(weight, 3),
                    evidence=f"utf16 string @0x{offset:x}",
                    platform=platform,
                    description=self._describe_string(technique),
                ))

        return findings

    # ------------------------------------------------------------------
    # Layer 3: Bytes (PEB offsets, RDTSC, INT3 cluster)
    # ------------------------------------------------------------------

    def detect_by_bytes(self) -> list[AntiDebugFinding]:
        """PEB offset/RDTSC/INT3 byte pattern tespiti.

        Yalniz x86 / x86-64 hedefte ve yalniz yurutulebilir kod bolgelerinde
        (ELF SHF_EXECINSTR / PF_X, Mach-O komut iceren bolumler, PE
        IMAGE_SCN_MEM_EXECUTE) aranir (IMZA-02). Evrensel Mach-O'da x86-64
        dilimi taranir. AArch64 / ARM ikilide ya da bicimi taninmayan dosyada
        bu katman bulgu uretmez: oralarda "0F 31" bir komut degildir.
        PEB desenleri yalniz PE'de ve yalniz ait olduklari mimaride aranir.

        Komut sinirlari capstone ile (dogrusal tarama) bulunur: kod icinde de
        "0F 31" baska bir komutun parcasi olabilir (macOS vim'in x86-64
        diliminde 43 bayt eslesmesinin 0'i gercek rdtsc). capstone yoksa bayt
        taramasina dusulur ve bulgular bilgi / zayif duzeyde kalir.

        Heuristic — yuksek FP riski var, dusuk confidence ataniyor.
        """
        data = self._load_bytes()
        if not data:
            return []
        layout = self._code_layout()
        if layout.arch not in _X86_ARCHES or not layout.regions:
            return []
        regions = layout.regions
        scan = _scan_x86_code(data, layout)
        where = f"{layout.arch} kod, {scan.decoder}" + (
            f"; {layout.note}" if layout.note else "")

        findings: list[AntiDebugFinding] = []

        # PEB: denetim (BeingDebugged / NtGlobalFlag & 0x70) -> hukum;
        # yalniz okuma -> bilgi.
        if scan.peb_checks:
            off, what = scan.peb_checks[0]
            findings.append(AntiDebugFinding(
                technique=_PEB_TECHNIQUE[layout.arch],
                category="peb",
                confidence=_PEB_CHECK_CONFIDENCE,
                evidence=f"{what} x{len(scan.peb_checks)}, ilk @0x{off:x} ({where})",
                platform="windows",
                description=(
                    "PEB okunup BeingDebugged / NtGlobalFlag hata ayiklayici "
                    "bitleri denetleniyor"
                ),
            ))
        elif scan.peb_reads:
            findings.append(AntiDebugFinding(
                technique="PEB_Read",
                category="peb",
                confidence=_INFO_CONFIDENCE,
                evidence=(
                    f"PEB okumasi x{len(scan.peb_reads)}, ilk @0x{scan.peb_reads[0]:x}; "
                    f"BeingDebugged / NtGlobalFlag&0x70 denetimi gorulmedi ({where})"
                ),
                platform="windows",
                description=(
                    "PEB'e erisim (derleyici calisma zamani da yapar); tek basina "
                    "anti-debug degil — bilgi"
                ),
            ))

        # RDTSC: zayif kanit; sayi artsa da zayif ust sinirin ustune cikmaz.
        total_rdtsc = scan.rdtsc + scan.rdtscp
        if total_rdtsc >= 1:
            if scan.decoder != "capstone" or total_rdtsc == 1:
                conf = _RDTSC_SINGLE_CONFIDENCE
            else:
                conf = _RDTSC_MULTI_CONFIDENCE
            findings.append(AntiDebugFinding(
                technique="RDTSC_Timing",
                category="timing",
                confidence=round(conf, 3),
                evidence=(
                    f"rdtsc x{scan.rdtsc}, rdtscp x{scan.rdtscp} ({where})"
                ),
                platform="any",
                description=(
                    "RDTSC komutu — zamanlama tabanli anti-debug olabilir; "
                    "olagan zaman olcumunden ayirt edilmedi (zayif kanit)"
                ),
            ))

        # INT3 cluster: 8+ ardisik 0xCC byte (yalniz kod bolgelerinde).
        # Fonksiyonlar arasi dolgu sayilmaz (IMZA-03): kosu bir sonraki
        # fonksiyonun hizali baslangicinda (adres % 16 == 0) ya da kod
        # bolgesinin sonunda biter, ya da onceki fonksiyonun kosulsuz donus /
        # atlama komutundan hemen sonra baslar (oraya akis yok; ornek: CRT'nin
        # el yazmasi rutinlerinde "CC... + cok baytli NOP" hizalamasi, artimli
        # baglamada "ret; CC...; jmp [thunk]").
        int3_cluster = None
        padding_runs = 0
        for r in regions:
            seg = data[r.start:r.end]
            for rel, run_len in self._int3_runs(seg, _INT3_MIN_RUN):
                end_rel = rel + run_len
                # CC'den sonra gelen cok baytli NOP'lar da dolgunun parcasidir
                nop = _X86_NOP_RUN_RE.match(seg, end_rel)
                aligned_end = r.vaddr + (nop.end() if nop else end_rel)
                if (aligned_end % _FUNC_ALIGN == 0 or r.start + end_rel >= r.end
                        or self._after_function_end(seg, rel)):
                    padding_runs += 1
                    continue
                if int3_cluster is None or run_len > int3_cluster[1]:
                    int3_cluster = (r.start + rel, run_len)
        if int3_cluster is not None:
            offset, run_len = int3_cluster
            findings.append(AntiDebugFinding(
                technique="INT3_Cluster",
                category="timing",
                confidence=0.25,
                evidence=(f"INT3 (0xCC) x{run_len} @0x{offset:x}; hizalama "
                          f"dolgusu sayilmadi: {padding_runs} kosu"),
                platform="any",
                description=(
                    "Ardisik INT 3 (0xCC) byte cluster'i — debugger "
                    "trap veya alignment padding olabilir; FP riski "
                    "yuksek"
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # Helper'lar
    # ------------------------------------------------------------------

    def _apply_multilayer_boost(
        self, findings: list[AntiDebugFinding],
    ) -> list[AntiDebugFinding]:
        """Ayni technique birden fazla kategoride varsa +0.20.

        Yalniz zayif ustu (> 0,30) kanitlar sayilir (IMZA-03): iki zayif
        kanit birlikte hukme donusmez; derleyici calisma zamani hic sayilmaz.
        """
        # technique -> kategoriler (yalniz guclu kanitlar)
        tech_categories: dict[str, set[str]] = defaultdict(set)
        for f in findings:
            if f.confidence > _WEAK_MAX_CONFIDENCE and f.category != "compiler_runtime":
                tech_categories[f.technique].add(f.category)

        boosted: list[AntiDebugFinding] = []
        for f in findings:
            if len(tech_categories[f.technique]) >= 2:
                new_conf = min(_MAX_CONFIDENCE, f.confidence + _BOOST_MULTI_LAYER)
                f = AntiDebugFinding(
                    technique=f.technique,
                    category=f.category,
                    confidence=round(new_conf, 3),
                    evidence=f.evidence + " [multi-layer]",
                    platform=f.platform,
                    description=f.description,
                )
            boosted.append(f)
        return boosted

    def _load_bytes(self) -> bytes:
        """Binary'yi RAM'e oku (cache'li)."""
        if self._raw_bytes is not None:
            return self._raw_bytes
        try:
            size = self.binary_path.stat().st_size
            if size > self.max_bytes_scan:
                logger.info(
                    "binary cok buyuk (%d byte), %d MB ile sinirli okunuyor",
                    size, self.max_bytes_scan // (1024 * 1024),
                )
                with self.binary_path.open("rb") as fh:
                    self._raw_bytes = fh.read(self.max_bytes_scan)
            else:
                self._raw_bytes = self.binary_path.read_bytes()
        except OSError as exc:
            logger.warning("binary okunamadi: %s", exc)
            self._raw_bytes = b""
        return self._raw_bytes

    def _code_layout(self) -> CodeLayout:
        """Bicim / mimari / kod bolgeleri (cache'li)."""
        if self._layout is None:
            self._layout = code_layout(self._load_bytes())
        return self._layout

    def _load_imports(self) -> list[str]:
        """Imported function adlarini cikar (PE / ELF / Mach-O)."""
        if self._imports is not None:
            return self._imports

        # 1. lief denenir
        lief_imports = self._extract_imports_lief()
        if lief_imports is not None:
            self._imports = lief_imports
            return self._imports

        # 2. fallback: nm / strings tabanli (sadece sembol adi cikarir)
        fallback = self._extract_imports_fallback()
        self._imports = fallback or []
        return self._imports

    def _extract_imports_lief(self) -> Optional[list[str]]:
        """lief ile imported function adlarini cikar."""
        try:
            import lief
        except ImportError:
            logger.debug("lief kurulu degil, fallback kullanilacak")
            return None

        try:
            binary = lief.parse(str(self.binary_path))
        except Exception as exc:
            logger.debug("lief parse basarisiz: %s", exc)
            return None
        if binary is None:
            return None

        imports: list[str] = []
        fmt = getattr(binary, "format", None)
        fmt_str = str(fmt) if fmt is not None else ""

        try:
            # PE imports
            if "PE" in fmt_str.upper() or hasattr(binary, "imports"):
                self._format = "PE"
                imports_attr = getattr(binary, "imports", None)
                if imports_attr is not None:
                    for imp_lib in imports_attr:
                        entries = getattr(imp_lib, "entries", [])
                        for entry in entries:
                            name = getattr(entry, "name", None)
                            if name:
                                imports.append(str(name))
            # ELF dynsym
            if "ELF" in fmt_str.upper() or hasattr(binary, "dynamic_symbols"):
                self._format = self._format or "ELF"
                dynsyms = getattr(binary, "dynamic_symbols", None) or []
                for sym in dynsyms:
                    name = getattr(sym, "name", None)
                    if name and not getattr(sym, "is_function", True):
                        # sadece fonksiyon olanlari al
                        continue
                    if name:
                        imports.append(str(name))
                # Imported symbols ELF
                imp_syms = getattr(binary, "imported_symbols", None) or []
                for sym in imp_syms:
                    name = getattr(sym, "name", None)
                    if name:
                        imports.append(str(name))
            # Mach-O
            if "MACHO" in fmt_str.upper() or hasattr(binary, "imported_functions"):
                self._format = self._format or "MACHO"
                imp_fns = getattr(binary, "imported_functions", None) or []
                for fn in imp_fns:
                    name = getattr(fn, "name", None) if hasattr(fn, "name") else fn
                    if isinstance(name, str):
                        imports.append(name)
                    elif name is not None:
                        imports.append(str(name))
        except Exception as exc:
            logger.debug("lief import enumeration hatasi: %s", exc)

        # Tekrar etmeyenleri don
        return list(dict.fromkeys(imports))

    def _extract_imports_fallback(self) -> list[str]:
        """nm / objdump ile import sembollerini cikar (lief yoksa).

        Eslesme katmaninin caligar olmasi icin sembol adlarini bytes
        icinden de tarariz (dlsym/import name strings).
        """
        results: list[str] = []
        # `nm -D` ELF dynamic syms; macOS'ta `nm -gU`; Windows .exe icin
        # mingw `nm` sembolleri import descriptor'dan goremeyebilir.
        # B21: resolve_tool whitelist + safe_run (LD_PRELOAD koruma).
        nm_path = resolve_tool("nm")
        if nm_path is None:
            logger.debug("nm whitelist path'te bulunamadi; import fallback atlandi")
            candidates = []
        else:
            candidates = [
                [nm_path, "-D", "--defined-only", str(self.binary_path)],
                [nm_path, str(self.binary_path)],
            ]
        for cmd in candidates:
            try:
                proc = safe_run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=15.0, check=False, text=False,
                )
                if proc.returncode != 0:
                    continue
                for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
                    parts = line.strip().split()
                    if not parts:
                        continue
                    sym = parts[-1]
                    if sym and sym.replace("_", "").isalnum():
                        results.append(sym)
                if results:
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # Ek olarak: ham binary icinde API isimlerini text olarak da tara
        # (PE'lerde Import Directory'de zaten string olarak gecer)
        data = self._load_bytes()
        if data:
            for api_dict in (_WINDOWS_APIS, _LINUX_APIS, _MACOS_APIS):
                for api_name in api_dict.keys():
                    api_clean = api_name.lstrip("_")
                    if not api_clean:
                        continue
                    needle = api_clean.encode("ascii")
                    if needle in data and api_clean not in results:
                        results.append(api_clean)

        return results

    @staticmethod
    def _count_nonoverlapping(data: bytes, needle: bytes) -> int:
        """Ortusmeyen olarak `needle` sayisi."""
        if not needle:
            return 0
        count = 0
        idx = 0
        while True:
            found = data.find(needle, idx)
            if found < 0:
                return count
            count += 1
            idx = found + len(needle)

    @staticmethod
    def _after_function_end(seg: bytes, pos: int) -> bool:
        """``pos``'tan hemen once kosulsuz akis sonu komutu var mi (bayt duzeyinde).

        ret (C3), ret imm16 (C2 iw), jmp rel8 (EB ib), jmp rel32 (E9 id),
        jmp [mem] (FF 25 id). Bayt duzeyinde yaklasiktir; yalniz dolguyu
        DISLAMAK icin kullanilir (yanilirsa zayif INT3 bulgusu kaybolur).
        """
        return ((pos >= 1 and seg[pos - 1] == 0xC3)
                or (pos >= 3 and seg[pos - 3] == 0xC2)
                or (pos >= 2 and seg[pos - 2] == 0xEB)
                or (pos >= 5 and seg[pos - 5] == 0xE9)
                or (pos >= 6 and seg[pos - 6:pos - 4] == b"\xff\x25"))

    @staticmethod
    def _int3_runs(data: bytes, min_run: int) -> list[tuple[int, int]]:
        """``min_run`` ve uzeri ardisik 0xCC kosulari: [(ofset, uzunluk)]."""
        return [(m.start(), m.end() - m.start())
                for m in re.finditer(b"\xcc{%d,}" % min_run, data)]

    @staticmethod
    def _find_int3_cluster(
        data: bytes, min_run: int = 8,
    ) -> Optional[tuple[int, int]]:
        """En uzun INT3 (0xCC) ardisik cluster'i (>= min_run)."""
        run_start: Optional[int] = None
        run_len = 0
        best: Optional[tuple[int, int]] = None
        for idx, byte in enumerate(data):
            if byte == 0xCC:
                if run_start is None:
                    run_start = idx
                run_len += 1
            else:
                if run_start is not None and run_len >= min_run:
                    if best is None or run_len > best[1]:
                        best = (run_start, run_len)
                run_start = None
                run_len = 0
        # Son run
        if run_start is not None and run_len >= min_run:
            if best is None or run_len > best[1]:
                best = (run_start, run_len)
        return best

    @staticmethod
    def _guess_platform(technique: str) -> str:
        """String teknigine gore platform tahmini."""
        t = technique.lower()
        if "linux" in t or "tracerpid" in t or "procstatus" in t or "procmaps" in t:
            return "linux"
        if "windbg" in t or "ollydbg" in t or "x64dbg" in t or "scyllahide" in t:
            return "windows"
        if "ida" in t or "radare" in t or "dnspy" in t or "immunity" in t:
            return "any"
        if "antivm" in t:
            return "any"
        return "any"

    @staticmethod
    def _describe_string(technique: str) -> str:
        """String teknigi icin Turkce aciklama."""
        descriptions = {
            "DebuggerName_OllyDbg": "OllyDbg debugger ismine string referans",
            "DebuggerName_x64dbg": "x64dbg debugger ismine string referans",
            "DebuggerName_WinDbg": "WinDbg debugger ismine string referans",
            "DebuggerName_IDA": "IDA Pro disassembler ismine referans",
            "DebuggerName_Immunity": "Immunity Debugger ismine referans",
            "DebuggerName_Radare": "Radare2 debugger ismine referans",
            "DebuggerName_dnSpy": "dnSpy .NET debugger ismine referans",
            "AntiDebug_ScyllaHide": "ScyllaHide anti-anti-debug aracina referans",
            "Linux_ProcStatus": "/proc/self/status dosyasi okuma (TracerPid kontrolu)",
            "Linux_TracerPid": "TracerPid: alani parse — debugger PID kontrolu",
            "Linux_ProcMaps": "/proc/self/maps okuma (memory layout analizi)",
            "AntiVM_VirtualBox": "VirtualBox VM tespit string'i",
            "AntiVM_VMware": "VMware VM tespit string'i",
            "AntiVM_QEMU": "QEMU VM tespit string'i",
            "WindowClass_OllyDbg": "OllyDbg window class adi (FindWindow icin)",
            "WindowClass_WinDbg": "WinDbg window class adi (FindWindow icin)",
        }
        return descriptions.get(technique, "Anti-debug string referansi")
