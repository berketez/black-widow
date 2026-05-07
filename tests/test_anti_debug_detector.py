"""AntiDebugDetector testleri.

Anti-debug tespit modulu icin testler:
- Layer 1 (imports): PE/ELF/Mach-O imported symbols
- Layer 2 (strings): debugger isimleri, /proc/self/status, TracerPid
- Layer 3 (bytes): PEB FS:[30h] / GS:[60h] patterns, RDTSC, INT3 cluster
- Multi-layer boost: ayni technique 2+ katmanda -> +0.20
- Negatif test: temiz binary -> 0 finding (FP kontrolu)
- summary() agregasyon kontrolu
- max_bytes_scan limiti
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from karadul.analyzers.anti_debug_detector import (
    AntiDebugDetector,
    AntiDebugFinding,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_binary(tmp_path):
    """Anti-debug iz icermeyen, ASCII text + birkac NUL temiz dosya."""
    p = tmp_path / "clean.bin"
    # Sadece "Hello world" gibi text + biraz random ascii
    data = b"Hello, World!\n" * 200 + b"normal program data\n" * 50
    p.write_bytes(data)
    return p


@pytest.fixture
def windows_string_binary(tmp_path):
    """Icinde IsDebuggerPresent ve OLLYDBG string'leri olan dosya."""
    p = tmp_path / "win_strings.bin"
    data = (
        b"PADDING" * 50
        + b"IsDebuggerPresent\x00"
        + b"PADDING" * 50
        + b"OLLYDBG\x00"
        + b"PADDING" * 50
    )
    p.write_bytes(data)
    return p


@pytest.fixture
def linux_string_binary(tmp_path):
    """/proc/self/status + TracerPid: + ptrace string'i."""
    p = tmp_path / "linux_strings.bin"
    data = (
        b"\x7fELF" + b"\x00" * 100   # sahte ELF magic
        + b"/proc/self/status\x00"
        + b"PADDING" * 50
        + b"TracerPid:\x00"
        + b"PADDING" * 50
        + b"ptrace\x00"
    )
    p.write_bytes(data)
    return p


@pytest.fixture
def macos_string_binary(tmp_path):
    """sysctl + _ptrace string'i."""
    p = tmp_path / "macos.bin"
    # Mach-O 64 magic FE ED FA CF (LE: CF FA ED FE)
    data = (
        b"\xcf\xfa\xed\xfe" + b"\x00" * 200
        + b"_ptrace\x00"
        + b"PADDING" * 30
        + b"_sysctl\x00"
    )
    p.write_bytes(data)
    return p


@pytest.fixture
def peb_byte_binary(tmp_path):
    """GS:[60h] PEB pattern iceren binary."""
    p = tmp_path / "peb.bin"
    # 65 48 8B 04 25 60 00 00 00  = mov rax, gs:[60h]
    data = (
        b"\x90" * 1000
        + b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
        + b"\x90" * 1000
    )
    p.write_bytes(data)
    return p


@pytest.fixture
def fs30_byte_binary(tmp_path):
    """FS:[30h] PEB pattern (32-bit)."""
    p = tmp_path / "fs30.bin"
    # 64 A1 30 00 00 00 = mov eax, fs:[30h]
    data = b"\x90" * 500 + b"\x64\xa1\x30\x00\x00\x00" + b"\x90" * 500
    p.write_bytes(data)
    return p


@pytest.fixture
def rdtsc_binary(tmp_path):
    """Cok sayida RDTSC opcode (timing-based)."""
    p = tmp_path / "rdtsc.bin"
    # 5+ rdtsc ortusmeyen
    data = b"\x90" * 100
    for _ in range(6):
        data += b"\x0f\x31" + b"\x90" * 50
    p.write_bytes(data)
    return p


@pytest.fixture
def int3_cluster_binary(tmp_path):
    """20 ardisik 0xCC INT3 byte."""
    p = tmp_path / "int3.bin"
    data = b"\x90" * 200 + b"\xcc" * 20 + b"\x90" * 200
    p.write_bytes(data)
    return p


# ---------------------------------------------------------------------------
# Layer 1: Imports
# ---------------------------------------------------------------------------

def test_imports_windows_api_via_lief_mock(tmp_path):
    """lief mock'lanir; PE imports'da IsDebuggerPresent + Nt API var."""
    p = tmp_path / "fake.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)

    fake_entry1 = mock.MagicMock()
    fake_entry1.name = "IsDebuggerPresent"
    fake_entry2 = mock.MagicMock()
    fake_entry2.name = "NtQueryInformationProcess"

    fake_imp_lib = mock.MagicMock()
    fake_imp_lib.entries = [fake_entry1, fake_entry2]

    fake_binary = mock.MagicMock()
    fake_binary.format = "PE"
    fake_binary.imports = [fake_imp_lib]
    fake_binary.dynamic_symbols = []
    fake_binary.imported_symbols = []
    fake_binary.imported_functions = []

    fake_lief = mock.MagicMock()
    fake_lief.parse.return_value = fake_binary

    with mock.patch.dict("sys.modules", {"lief": fake_lief}):
        det = AntiDebugDetector(binary_path=p)
        findings = det.detect_by_imports()

    techniques = {f.technique for f in findings}
    assert "IsDebuggerPresent" in techniques
    assert "NtQueryInformationProcess" in techniques

    # NtQueryInformationProcess'a +0.10 boost var, en azindan 0.7 olmali
    nt = next(f for f in findings if f.technique == "NtQueryInformationProcess")
    assert nt.confidence >= 0.70
    assert nt.platform == "windows"
    assert nt.category == "windows_api"


def test_imports_linux_ptrace_via_lief_mock(tmp_path):
    """ELF dynsym mock'unda ptrace var."""
    p = tmp_path / "fake.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)

    fake_sym = mock.MagicMock()
    fake_sym.name = "ptrace"
    fake_sym.is_function = True

    fake_binary = mock.MagicMock()
    fake_binary.format = "ELF"
    fake_binary.imports = []
    fake_binary.dynamic_symbols = [fake_sym]
    fake_binary.imported_symbols = []
    fake_binary.imported_functions = []

    fake_lief = mock.MagicMock()
    fake_lief.parse.return_value = fake_binary

    with mock.patch.dict("sys.modules", {"lief": fake_lief}):
        det = AntiDebugDetector(binary_path=p)
        findings = det.detect_by_imports()

    techniques = {f.technique for f in findings}
    assert "ptrace_traceme" in techniques

    f = next(f for f in findings if f.technique == "ptrace_traceme")
    assert f.platform == "linux"
    assert f.category == "ptrace"


def test_imports_macos_ptrace_underscore(tmp_path):
    """Mach-O sembolleri "_" prefix ile gelir."""
    p = tmp_path / "fake.macho"
    p.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

    fake_fn = mock.MagicMock()
    fake_fn.name = "_ptrace"

    fake_binary = mock.MagicMock()
    fake_binary.format = "MACHO"
    fake_binary.imports = []
    fake_binary.dynamic_symbols = []
    fake_binary.imported_symbols = []
    fake_binary.imported_functions = [fake_fn]

    fake_lief = mock.MagicMock()
    fake_lief.parse.return_value = fake_binary

    with mock.patch.dict("sys.modules", {"lief": fake_lief}):
        det = AntiDebugDetector(binary_path=p)
        findings = det.detect_by_imports()

    techniques = {f.technique for f in findings}
    assert "ptrace_pt_deny_attach" in techniques

    f = next(f for f in findings if f.technique == "ptrace_pt_deny_attach")
    assert f.platform == "macos"
    assert f.category == "macos"
    # weight 0.70
    assert f.confidence >= 0.7


def test_imports_fallback_when_lief_missing(tmp_path):
    """lief yoksa fallback: binary icindeki API isim string'leri."""
    p = tmp_path / "fake.bin"
    # Binary icinde API isimleri text olarak gomulu olsun
    p.write_bytes(
        b"PADDING" * 30
        + b"\x00IsDebuggerPresent\x00"
        + b"PADDING" * 30
        + b"\x00ptrace\x00"
    )
    det = AntiDebugDetector(binary_path=p)
    # _imports'i temizle - lief import'u patch'le
    with mock.patch.object(
        det, "_extract_imports_lief", return_value=None,
    ):
        # nm subprocess'i de basarisiz olsun -> sadece text fallback
        with mock.patch(
            "karadul.analyzers.anti_debug_detector.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            findings = det.detect_by_imports()

    techniques = {f.technique for f in findings}
    # Hem windows hem linux teknigi olmali
    assert "IsDebuggerPresent" in techniques
    # ptrace_traceme ya da ptrace_pt_deny_attach (linux veya macos)
    has_ptrace = any(
        t in techniques
        for t in ("ptrace_traceme", "ptrace_pt_deny_attach")
    )
    assert has_ptrace


# ---------------------------------------------------------------------------
# Layer 2: Strings
# ---------------------------------------------------------------------------

def test_string_layer_olydbg(windows_string_binary):
    """OLLYDBG string -> WindowClass_OllyDbg + DebuggerName_OllyDbg."""
    det = AntiDebugDetector(binary_path=windows_string_binary)
    findings = det.detect_by_strings()
    techniques = {f.technique for f in findings}
    # En azindan biri tetiklenmeli
    assert "WindowClass_OllyDbg" in techniques or "DebuggerName_OllyDbg" in techniques


def test_string_layer_tracerpid(linux_string_binary):
    """TracerPid: + /proc/self/status -> Linux_TracerPid yuksek conf."""
    det = AntiDebugDetector(binary_path=linux_string_binary)
    findings = det.detect_by_strings()
    techniques = {f.technique for f in findings}
    assert "Linux_TracerPid" in techniques
    assert "Linux_ProcStatus" in techniques

    f = next(f for f in findings if f.technique == "Linux_TracerPid")
    assert f.platform == "linux"
    assert f.confidence >= 0.6
    assert f.category == "string"


def test_string_layer_utf16_ollydbg(tmp_path):
    """UTF-16 LE encoded OLLYDBG."""
    p = tmp_path / "utf16.bin"
    data = (
        b"PADDING" * 50
        + b"O\x00L\x00L\x00Y\x00D\x00B\x00G\x00"
        + b"PADDING" * 50
    )
    p.write_bytes(data)
    det = AntiDebugDetector(binary_path=p)
    findings = det.detect_by_strings()
    techniques = {f.technique for f in findings}
    assert "DebuggerName_OllyDbg" in techniques


def test_string_layer_clean(clean_binary):
    """Temiz binary string layer'da hicbir bulgu vermemeli."""
    det = AntiDebugDetector(binary_path=clean_binary)
    findings = det.detect_by_strings()
    assert findings == []


# ---------------------------------------------------------------------------
# Layer 3: Bytes (PEB / RDTSC / INT3)
# ---------------------------------------------------------------------------

def test_bytes_layer_peb_gs60(peb_byte_binary):
    """GS:[60h] pattern -> PEB_GS60_x64."""
    det = AntiDebugDetector(binary_path=peb_byte_binary)
    findings = det.detect_by_bytes()
    techniques = {f.technique for f in findings}
    assert "PEB_GS60_x64" in techniques

    f = next(f for f in findings if f.technique == "PEB_GS60_x64")
    assert f.category == "peb"
    assert f.platform == "windows"


def test_bytes_layer_fs30(fs30_byte_binary):
    """FS:[30h] -> PEB_FS30_x86."""
    det = AntiDebugDetector(binary_path=fs30_byte_binary)
    findings = det.detect_by_bytes()
    techniques = {f.technique for f in findings}
    assert "PEB_FS30_x86" in techniques


def test_bytes_layer_rdtsc(rdtsc_binary):
    """6 RDTSC -> 0.45 confidence."""
    det = AntiDebugDetector(binary_path=rdtsc_binary)
    findings = det.detect_by_bytes()
    techniques = {f.technique for f in findings}
    assert "RDTSC_Timing" in techniques

    f = next(f for f in findings if f.technique == "RDTSC_Timing")
    assert f.confidence >= 0.4
    assert f.category == "timing"


def test_bytes_layer_int3_cluster(int3_cluster_binary):
    """20 ardisik 0xCC -> INT3_Cluster."""
    det = AntiDebugDetector(binary_path=int3_cluster_binary)
    findings = det.detect_by_bytes()
    techniques = {f.technique for f in findings}
    assert "INT3_Cluster" in techniques


def test_bytes_layer_clean(clean_binary):
    """Temiz binary bytes layer'da hicbir bulgu vermemeli."""
    det = AntiDebugDetector(binary_path=clean_binary)
    findings = det.detect_by_bytes()
    assert findings == []


# ---------------------------------------------------------------------------
# Multi-layer boost
# ---------------------------------------------------------------------------

def test_multilayer_boost_ollydbg(tmp_path):
    """OLLYDBG hem string'de (WindowClass + DebuggerName) gorunur.

    Ayni technique adi (DebuggerName_OllyDbg) yalniz string layer'da
    cikar — boost sart degil. Multi-layer boost icin _technique adinin_
    iki kategoride bulunmasi gerekir.
    """
    # Bir senaryoda ayni technique hem string hem (henuz yok ama)
    # Bu yuzden boost mantigini AntiDebugFinding listesi uzerinde test
    # ediyoruz: el ile findings olustur, _apply_multilayer_boost cagir.
    det = AntiDebugDetector(binary_path=tmp_path / "x.bin", )
    # binary_path kontrolunden gecmesi icin dosya olusturalim:
    (tmp_path / "x.bin").write_bytes(b"")

    findings = [
        AntiDebugFinding(
            technique="IsDebuggerPresent",
            category="windows_api",
            confidence=0.55,
            evidence="import: IsDebuggerPresent",
            platform="windows",
            description="x",
        ),
        AntiDebugFinding(
            technique="IsDebuggerPresent",
            category="string",
            confidence=0.40,
            evidence="string: IsDebuggerPresent",
            platform="windows",
            description="x",
        ),
    ]
    boosted = det._apply_multilayer_boost(findings)
    # Her ikisi de boost almali
    for b in boosted:
        assert b.confidence >= 0.55  # 0.55 + 0.20 / 0.40 + 0.20
        assert "[multi-layer]" in b.evidence


def test_multilayer_no_boost_single_category(tmp_path):
    """Tek kategoride tek bulgu boost almamali."""
    (tmp_path / "x.bin").write_bytes(b"")
    det = AntiDebugDetector(binary_path=tmp_path / "x.bin")
    findings = [
        AntiDebugFinding(
            technique="OnlyInString",
            category="string",
            confidence=0.50,
            evidence="string: x",
            platform="any",
            description="y",
        ),
    ]
    boosted = det._apply_multilayer_boost(findings)
    assert boosted[0].confidence == 0.50
    assert "[multi-layer]" not in boosted[0].evidence


# ---------------------------------------------------------------------------
# detect() ve summary()
# ---------------------------------------------------------------------------

def test_detect_full_pipeline_clean(clean_binary):
    """Temiz binary -> 0 finding (ana FP testi)."""
    det = AntiDebugDetector(binary_path=clean_binary)
    findings = det.detect()
    # nm fallback ile ham binary'de ascii API string'i araniyor —
    # clean dosyada yok
    techniques = {f.technique for f in findings}
    # Hicbir bilinen anti-debug technique cikmamali
    forbidden = {
        "IsDebuggerPresent", "ptrace_traceme", "ptrace_pt_deny_attach",
        "NtQueryInformationProcess", "Linux_TracerPid",
        "PEB_GS60_x64", "PEB_FS30_x86",
    }
    assert techniques.isdisjoint(forbidden)


def test_summary_aggregation(linux_string_binary):
    """summary() istatistikleri dogru hesaplanmali."""
    det = AntiDebugDetector(binary_path=linux_string_binary)
    findings = det.detect()
    s = det.summary(findings)

    assert s["total"] == len(findings)
    assert "by_category" in s
    assert "by_platform" in s
    assert "anti_debug_score" in s
    assert 0.0 <= s["anti_debug_score"] <= 1.0
    assert s["max_confidence"] <= 1.0
    # Linux fixture'da Linux_TracerPid (0.65) olmali
    assert s["max_confidence"] >= 0.6


def test_summary_empty():
    """Bos finding listesi -> score 0."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"x")
        path = f.name
    try:
        det = AntiDebugDetector(binary_path=path)
        s = det.summary([])
        assert s["total"] == 0
        assert s["anti_debug_score"] == 0.0
        assert s["techniques"] == []
        assert s["max_confidence"] == 0.0
    finally:
        Path(path).unlink()


# ---------------------------------------------------------------------------
# Diger
# ---------------------------------------------------------------------------

def test_max_bytes_scan_limit(tmp_path):
    """max_bytes_scan asilirsa truncate yapilmali."""
    p = tmp_path / "big.bin"
    # 200 KB sahte binary
    p.write_bytes(b"\x90" * (200 * 1024))
    det = AntiDebugDetector(binary_path=p, max_bytes_scan=1024)
    data = det._load_bytes()
    assert len(data) == 1024


def test_init_requires_path():
    """Ne target ne binary_path verilmezse hata."""
    with pytest.raises(ValueError):
        AntiDebugDetector()


def test_init_via_target_object(tmp_path):
    """target.path uzerinden init."""
    p = tmp_path / "x.bin"
    p.write_bytes(b"x")

    class FakeTarget:
        path = p
        target_type = "pe_binary"

    det = AntiDebugDetector(target=FakeTarget())
    assert det.binary_path == p


def test_count_nonoverlapping():
    """Helper testi: ortusmeyen sayma."""
    data = b"\x0f\x31\x0f\x31\x0f\x31"
    assert AntiDebugDetector._count_nonoverlapping(data, b"\x0f\x31") == 3
    # Bos needle
    assert AntiDebugDetector._count_nonoverlapping(data, b"") == 0


def test_int3_cluster_finder():
    """Helper testi: en uzun INT3 cluster."""
    data = b"\x90" * 10 + b"\xcc" * 12 + b"\x90" * 5 + b"\xcc" * 20 + b"\x90"
    result = AntiDebugDetector._find_int3_cluster(data, min_run=8)
    assert result is not None
    offset, run_len = result
    # En uzun olan 20 olmali
    assert run_len == 20

    # Esige takilmayan
    short = b"\xcc" * 4
    assert AntiDebugDetector._find_int3_cluster(short, min_run=8) is None


def test_anti_debug_finding_to_dict():
    """AntiDebugFinding.to_dict() asdict ile uyumlu."""
    f = AntiDebugFinding(
        technique="IsDebuggerPresent",
        category="windows_api",
        confidence=0.55,
        evidence="import: IsDebuggerPresent",
        platform="windows",
        description="x",
    )
    d = f.to_dict()
    assert d["technique"] == "IsDebuggerPresent"
    assert d["confidence"] == 0.55
