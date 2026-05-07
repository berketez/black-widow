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
import subprocess
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

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
    "OutputDebugStringA": (
        "OutputDebugString",
        "Exception trick ile debugger varligini tespit eder",
        0.40,
    ),
    "OutputDebugStringW": (
        "OutputDebugString",
        "Exception trick ile debugger varligini tespit eder",
        0.40,
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
    "prctl": (
        "prctl_set_dumpable",
        "prctl(PR_SET_DUMPABLE, 0) - core dump engelleme",
        0.30,
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
    "_sysctl": (
        "sysctl_kinfo_proc",
        "sysctl(CTL_KERN, KERN_PROC, ...) P_TRACED flag kontrolu",
        0.55,
    ),
    "sysctl": (
        "sysctl_kinfo_proc",
        "sysctl P_TRACED flag kontrolu",
        0.55,
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

# Tek tek opcode pattern'leri (PEB offset olmadan)
# Bunlar yuksek FP riskli - sayim yapip esige gore karar veriyoruz
_RDTSC_BYTES = b"\x0f\x31"           # rdtsc
_RDTSCP_BYTES = b"\x0f\x01\xf9"      # rdtscp
_INT3 = b"\xcc"                       # int3
_SIDT_BYTES = b"\x0f\x01"             # sidt/sgdt prefix (red pill icin)

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

        # Toplam anti-debug skoru: max_conf + 0.05 * (technique sayisi - 1)
        # 1.0 ile sinirla
        if findings:
            score = min(
                1.0,
                max_conf + 0.05 * max(0, len(techniques) - 1),
            )
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
        """Imported function isimlerinden anti-debug API tespiti."""
        imports = self._load_imports()
        if not imports:
            return []

        findings: list[AntiDebugFinding] = []
        seen_techniques: set[tuple[str, str]] = set()

        # Hepsini tek normalleskmis stringe coevir
        for sym in imports:
            sym_clean = sym.strip()
            if not sym_clean:
                continue
            # Mach-O sembolleri "_" ile baslar — hem ham hem strip edilmis kontrol
            sym_no_leading = sym_clean.lstrip("_") if sym_clean.startswith("_") else sym_clean

            # Windows API
            for api_name, (technique, desc, weight) in _WINDOWS_APIS.items():
                if sym_clean == api_name or sym_no_leading == api_name:
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
            for api_name, (technique, desc, weight) in _LINUX_APIS.items():
                if sym_clean == api_name or sym_no_leading == api_name:
                    key = (technique, "ptrace")
                    if key in seen_techniques:
                        break
                    seen_techniques.add(key)
                    findings.append(AntiDebugFinding(
                        technique=technique,
                        category="ptrace",
                        confidence=round(weight, 3),
                        evidence=f"import: {sym_clean}",
                        platform="linux",
                        description=desc,
                    ))
                    break

            # macOS API
            for api_name, (technique, desc, weight) in _MACOS_APIS.items():
                if sym_clean == api_name or sym_no_leading == api_name:
                    key = (technique, "macos")
                    if key in seen_techniques:
                        break
                    seen_techniques.add(key)
                    findings.append(AntiDebugFinding(
                        technique=technique,
                        category="macos",
                        confidence=round(weight, 3),
                        evidence=f"import: {sym_clean}",
                        platform="macos",
                        description=desc,
                    ))
                    break

        return findings

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

        Heuristic — yuksek FP riski var, dusuk confidence ataniyor.
        """
        data = self._load_bytes()
        if not data:
            return []

        findings: list[AntiDebugFinding] = []
        seen: set[str] = set()

        # PEB pattern'leri
        for byte_pat, technique, category, weight, desc in _BYTE_PATTERNS:
            offset = data.find(byte_pat)
            if offset < 0:
                continue
            if technique in seen:
                continue
            seen.add(technique)
            findings.append(AntiDebugFinding(
                technique=technique,
                category=category,
                confidence=round(weight, 3),
                evidence=f"bytes @0x{offset:x}: {byte_pat.hex()}",
                platform="windows",
                description=desc,
            ))

        # RDTSC sayimi: 1 tane = 0.20, 5+ tane = 0.45
        rdtsc_count = self._count_nonoverlapping(data, _RDTSC_BYTES)
        rdtscp_count = self._count_nonoverlapping(data, _RDTSCP_BYTES)
        total_rdtsc = rdtsc_count + rdtscp_count
        if total_rdtsc >= 1:
            if total_rdtsc >= 5:
                conf = 0.45
            elif total_rdtsc >= 2:
                conf = 0.30
            else:
                conf = 0.20
            findings.append(AntiDebugFinding(
                technique="RDTSC_Timing",
                category="timing",
                confidence=round(conf, 3),
                evidence=(
                    f"rdtsc x{rdtsc_count}, rdtscp x{rdtscp_count}"
                ),
                platform="any",
                description=(
                    "RDTSC opcode kullanimi — timing-based anti-debug "
                    "(yuksek sayi -> daha guvenilir, FP riski mevcut)"
                ),
            ))

        # INT3 cluster: 8+ ardisik 0xCC byte
        int3_cluster = self._find_int3_cluster(data, min_run=8)
        if int3_cluster is not None:
            offset, run_len = int3_cluster
            findings.append(AntiDebugFinding(
                technique="INT3_Cluster",
                category="timing",
                confidence=0.25,
                evidence=f"INT3 (0xCC) x{run_len} @0x{offset:x}",
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
        """Ayni technique birden fazla kategoride varsa +0.20."""
        # technique -> kategoriler
        tech_categories: dict[str, set[str]] = defaultdict(set)
        for f in findings:
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
        candidates = [
            ["nm", "-D", "--defined-only", str(self.binary_path)],
            ["nm", str(self.binary_path)],
        ]
        for cmd in candidates:
            try:
                proc = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=15, check=False,
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
