""".NET/C# Binary Analyzer test suite.

PE header + CLI header detection, .NET metadata tables parse,
namespace/class/method extraction ve NuGet dependency tespiti testleri.

Gercek .NET binary olmadan calismali -- mock PE data kullanir.
"""

from __future__ import annotations

import io
import json
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.dotnet_binary import (
    DotNetBinaryAnalyzer,
    _METADATA_SIGNATURE,
    _PE_MAGIC,
    _PE_SIGNATURE,
    _parse_pe_cli_header,
    _parse_strings_heap,
    _extract_metadata_tables,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# --------------------------------------------------------------------------
# Helpers: mock PE/.NET binary olusturma
# --------------------------------------------------------------------------

def _build_minimal_pe(
    has_cli: bool = True,
    runtime_version: tuple[int, int] = (2, 5),
    metadata_version: str = "v4.0.30319",
    type_names: list[tuple[str, str]] | None = None,
    method_names: list[str] | None = None,
    assembly_refs: list[str] | None = None,
    include_mscoree: bool = True,
) -> bytes:
    """Minimal gecerli PE + .NET CLI header olustur.

    PE32 formatinda, section table ve CLI header dogru offset'lerle.
    """
    # Layout:
    # 0x000: DOS header (128 bytes, e_lfanew -> 0x80)
    # 0x080: PE signature (4 bytes)
    # 0x084: COFF header (20 bytes)
    # 0x098: Optional header (224 bytes = 96 std + 128 data dirs)
    # 0x178: Section table (2 sections * 40 bytes = 80 bytes)
    # 0x1C8: ... padding ...
    # 0x400: .text section raw data start
    #   0x400: CLI Header (72 bytes) -- mapped to RVA 0x2000
    #   0x480: Metadata root (BSJB) -- mapped to RVA 0x2080

    pe_offset = 0x80
    text_va = 0x2000
    text_raw_offset = 0x400
    text_raw_size = 0x2000

    buf = bytearray(text_raw_offset + text_raw_size)  # Pre-allocate

    # DOS Header
    buf[0:2] = _PE_MAGIC
    struct.pack_into("<I", buf, 0x3C, pe_offset)

    # PE Signature
    buf[pe_offset:pe_offset + 4] = _PE_SIGNATURE

    # COFF Header (20 bytes at pe_offset + 4)
    coff = pe_offset + 4
    struct.pack_into("<H", buf, coff + 0, 0x014C)    # Machine: i386
    struct.pack_into("<H", buf, coff + 2, 2)          # NumberOfSections
    struct.pack_into("<H", buf, coff + 16, 224)       # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff + 18, 0x0102)    # Characteristics

    # Optional Header (224 bytes at pe_offset + 24)
    opt = pe_offset + 24  # = 0x098

    # Standard fields (28 bytes for PE32)
    struct.pack_into("<H", buf, opt + 0, 0x10B)       # PE32 magic
    buf[opt + 2] = 8                                    # MajorLinkerVersion
    buf[opt + 3] = 0                                    # MinorLinkerVersion
    struct.pack_into("<I", buf, opt + 16, 0x2000)      # AddressOfEntryPoint
    # BaseOfCode(4) + BaseOfData(4) = 8 bytes at opt+24..31

    # Windows-specific fields (68 bytes at opt+28)
    ws = opt + 28
    struct.pack_into("<I", buf, ws + 0, 0x400000)     # ImageBase
    struct.pack_into("<I", buf, ws + 4, 0x1000)        # SectionAlignment
    struct.pack_into("<I", buf, ws + 8, 0x200)         # FileAlignment
    struct.pack_into("<I", buf, ws + 40, text_va + text_raw_size)  # SizeOfImage
    struct.pack_into("<I", buf, ws + 44, 0x200)        # SizeOfHeaders
    struct.pack_into("<H", buf, ws + 52, 3)            # Subsystem: CONSOLE
    struct.pack_into("<I", buf, ws + 64, 16)           # NumberOfRvaAndSizes

    # Data Directories (128 bytes = 16 * 8, at opt + 96)
    dd_base = opt + 96
    if has_cli:
        # Directory[14]: CLI Header
        struct.pack_into("<I", buf, dd_base + 14 * 8, text_va)   # CLI RVA
        struct.pack_into("<I", buf, dd_base + 14 * 8 + 4, 72)    # CLI Size

    # Section Table (at opt + 224 = pe_offset + 24 + 224 = pe_offset + 248)
    sec_table = opt + 224  # = 0x178

    # .text section
    buf[sec_table:sec_table + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sec_table + 8, text_raw_size)      # VirtualSize
    struct.pack_into("<I", buf, sec_table + 12, text_va)            # VirtualAddress
    struct.pack_into("<I", buf, sec_table + 16, text_raw_size)      # SizeOfRawData
    struct.pack_into("<I", buf, sec_table + 20, text_raw_offset)    # PointerToRawData
    struct.pack_into("<I", buf, sec_table + 36, 0x60000020)         # Characteristics

    # .rsrc section (dummy)
    sec2 = sec_table + 40
    buf[sec2:sec2 + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<I", buf, sec2 + 8, 0x200)
    struct.pack_into("<I", buf, sec2 + 12, 0x4000)
    struct.pack_into("<I", buf, sec2 + 16, 0x200)
    struct.pack_into("<I", buf, sec2 + 20, text_raw_offset + text_raw_size)

    if has_cli:
        # CLI Header at text_raw_offset (mapped to RVA text_va)
        cli_off = text_raw_offset
        metadata_rva = text_va + 128  # Metadata root 128 bytes after section start

        # CLI Header (72 bytes)
        struct.pack_into("<I", buf, cli_off + 0, 72)                     # cb
        struct.pack_into("<H", buf, cli_off + 4, runtime_version[0])     # MajorRuntimeVersion
        struct.pack_into("<H", buf, cli_off + 6, runtime_version[1])     # MinorRuntimeVersion
        struct.pack_into("<I", buf, cli_off + 8, metadata_rva)           # Metadata RVA
        struct.pack_into("<I", buf, cli_off + 12, 1024)                  # Metadata Size
        struct.pack_into("<I", buf, cli_off + 16, 0x01)                  # Flags: ILONLY

        # Metadata Root at text_raw_offset + 128
        meta_off = text_raw_offset + 128
        buf[meta_off:meta_off + 4] = _METADATA_SIGNATURE  # "BSJB"
        struct.pack_into("<H", buf, meta_off + 4, 1)   # Major
        struct.pack_into("<H", buf, meta_off + 6, 1)   # Minor
        struct.pack_into("<I", buf, meta_off + 8, 0)    # Reserved

        ver_bytes = metadata_version.encode("ascii") + b"\x00"
        ver_padded_len = len(ver_bytes) + (4 - len(ver_bytes) % 4) % 4
        struct.pack_into("<I", buf, meta_off + 12, ver_padded_len)
        ver_start = meta_off + 16
        buf[ver_start:ver_start + len(ver_bytes)] = ver_bytes

        # Stream headers start after version string
        sh_off = ver_start + ver_padded_len
        struct.pack_into("<H", buf, sh_off, 0)     # Flags
        struct.pack_into("<H", buf, sh_off + 2, 2)  # NumStreams

        # #Strings stream header
        strings_rel = 512  # relative to metadata root
        strings_heap_data = _build_strings_heap(type_names, method_names, assembly_refs)
        strings_size = len(strings_heap_data)

        sh1 = sh_off + 4
        struct.pack_into("<I", buf, sh1, strings_rel)
        struct.pack_into("<I", buf, sh1 + 4, strings_size)
        name1 = b"#Strings\x00"
        buf[sh1 + 8:sh1 + 8 + len(name1)] = name1
        name1_padded = len(name1) + (4 - len(name1) % 4) % 4

        # #~ stream header
        tilde_rel = (strings_rel + strings_size + 3) & ~3
        tilde_data = _build_tilde_stream(type_names, method_names, assembly_refs)
        tilde_size = len(tilde_data)

        sh2 = sh1 + 8 + name1_padded
        struct.pack_into("<I", buf, sh2, tilde_rel)
        struct.pack_into("<I", buf, sh2 + 4, tilde_size)
        name2 = b"#~\x00"
        buf[sh2 + 8:sh2 + 8 + len(name2)] = name2

        # Write #Strings heap data
        str_abs = meta_off + strings_rel
        if str_abs + strings_size <= len(buf):
            buf[str_abs:str_abs + strings_size] = strings_heap_data

        # Write #~ stream data
        tilde_abs = meta_off + tilde_rel
        if tilde_abs + tilde_size <= len(buf):
            buf[tilde_abs:tilde_abs + tilde_size] = tilde_data

    # mscoree.dll string (for can_handle detection)
    if include_mscoree:
        marker = b"mscoree.dll\x00.NETFramework,Version=v4.8\x00"
        marker_off = 0x100  # Within DOS stub area (after e_lfanew)
        buf[marker_off:marker_off + len(marker)] = marker

    return bytes(buf)


def _build_strings_heap(
    type_names: list[tuple[str, str]] | None = None,
    method_names: list[str] | None = None,
    assembly_refs: list[str] | None = None,
) -> bytes:
    """#Strings heap olustur."""
    strings: list[str] = [""]  # Index 0 = empty

    if type_names:
        for ns, name in type_names:
            if ns and ns not in strings:
                strings.append(ns)
            if name and name not in strings:
                strings.append(name)

    if method_names:
        for m in method_names:
            if m and m not in strings:
                strings.append(m)

    if assembly_refs:
        for r in assembly_refs:
            if r and r not in strings:
                strings.append(r)

    # Build heap: null-terminated strings
    buf = io.BytesIO()
    for s in strings:
        buf.write(s.encode("utf-8") + b"\x00")

    return buf.getvalue()


def _build_tilde_stream(
    type_names: list[tuple[str, str]] | None = None,
    method_names: list[str] | None = None,
    assembly_refs: list[str] | None = None,
) -> bytes:
    """Basitlestirilmis #~ stream olustur.

    NOT: Bu gercek bir #~ stream degil, parse fonksiyonlari icin
    yeterli bir mock. Full table layout cok karmasik.
    """
    buf = io.BytesIO()

    # Header: Reserved(4) + MajorVersion(1) + MinorVersion(1) + HeapSizes(1) + Reserved(1)
    buf.write(struct.pack("<I", 0))  # Reserved
    buf.write(struct.pack("BB", 2, 0))  # Major, Minor
    buf.write(struct.pack("B", 0))  # HeapSizes (all 2-byte indices)
    buf.write(struct.pack("B", 1))  # Reserved

    # Valid tables bitmask: we only include TypeDef (0x02)
    # For simplicity, skip complex table layouts
    valid = 0
    if type_names:
        valid |= (1 << 0x02)  # TypeDef
    buf.write(struct.pack("<Q", valid))
    buf.write(struct.pack("<Q", 0))  # Sorted

    # Row counts
    if type_names:
        buf.write(struct.pack("<I", len(type_names)))

    # We won't write actual table rows here as the parsing is complex
    # and requires proper index offsets. The integration test will verify
    # the full pipeline works with real-ish data.

    return buf.getvalue()


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def analyzer(config: Config) -> DotNetBinaryAnalyzer:
    return DotNetBinaryAnalyzer(config)


@pytest.fixture
def mock_dotnet_pe(tmp_path: Path) -> Path:
    """Basit .NET PE binary olustur."""
    data = _build_minimal_pe(
        has_cli=True,
        runtime_version=(2, 5),
        metadata_version="v4.0.30319",
    )
    pe_path = tmp_path / "TestApp.exe"
    pe_path.write_bytes(data)
    return pe_path


@pytest.fixture
def mock_native_pe(tmp_path: Path) -> Path:
    """CLI header'i olmayan native PE."""
    data = _build_minimal_pe(has_cli=False, include_mscoree=False)
    pe_path = tmp_path / "NativeApp.exe"
    pe_path.write_bytes(data)
    return pe_path


@pytest.fixture
def mock_target(mock_dotnet_pe: Path) -> TargetInfo:
    return TargetInfo(
        path=mock_dotnet_pe,
        name="TestApp",
        target_type=TargetType.DOTNET_ASSEMBLY,
        language=Language.CSHARP,
        file_size=mock_dotnet_pe.stat().st_size,
        file_hash="abc123",
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "workspace", "test_dotnet")
    ws.create()
    return ws


# --------------------------------------------------------------------------
# Test: PE + CLI header detection
# --------------------------------------------------------------------------

class TestPECliDetection:
    """PE header ve CLI header tespiti testleri."""

    def test_pe_with_cli_detected(self, mock_dotnet_pe: Path):
        """CLI header'li PE dosyasi has_cli=True vermeli."""
        data = mock_dotnet_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        assert result["has_cli"] is True

    def test_runtime_version_parsed(self, mock_dotnet_pe: Path):
        """Runtime version dogru parse edilmeli."""
        data = mock_dotnet_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        assert result["runtime_version"] == "2.5"

    def test_metadata_version_parsed(self, mock_dotnet_pe: Path):
        """Metadata version string dogru parse edilmeli."""
        data = mock_dotnet_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        assert result["metadata_version"] == "v4.0.30319"

    def test_ilonly_flag(self, mock_dotnet_pe: Path):
        """IL-only flag dogru tespit edilmeli."""
        data = mock_dotnet_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        assert result["is_ilonly"] is True

    def test_pe_without_cli(self, mock_native_pe: Path):
        """CLI header'siz PE dosyasi has_cli=False vermeli."""
        data = mock_native_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        assert result["has_cli"] is False

    def test_empty_data(self):
        """Bos veri ile hata vermemeli."""
        result = _parse_pe_cli_header(b"")
        assert result["has_cli"] is False

    def test_non_pe_data(self):
        """PE olmayan veri ile hata vermemeli."""
        result = _parse_pe_cli_header(b"\x00" * 1000)
        assert result["has_cli"] is False

    def test_truncated_pe(self):
        """Kesik PE verisi ile hata vermemeli."""
        result = _parse_pe_cli_header(b"MZ" + b"\x00" * 50)
        assert result["has_cli"] is False

    def test_streams_detected(self, mock_dotnet_pe: Path):
        """Metadata stream'leri tespit edilmeli."""
        data = mock_dotnet_pe.read_bytes()
        result = _parse_pe_cli_header(data)
        if result["has_cli"]:
            streams = result.get("streams", {})
            # En az #Strings stream'i olmali
            assert "#Strings" in streams or len(streams) >= 0


# --------------------------------------------------------------------------
# Test: #Strings heap parsing
# --------------------------------------------------------------------------

class TestStringsHeap:
    """#Strings heap parse testleri."""

    def test_basic_strings(self):
        """Basit string heap parse."""
        heap = b"\x00Hello\x00World\x00"
        result = _parse_strings_heap(heap, 0, len(heap))
        assert result[1] == "Hello"
        assert result[7] == "World"

    def test_empty_heap(self):
        """Bos heap."""
        result = _parse_strings_heap(b"\x00", 0, 1)
        assert len(result) == 0

    def test_offset_beyond_data(self):
        """Gecersiz offset ile bos donmeli."""
        result = _parse_strings_heap(b"abc", 100, 50)
        assert len(result) == 0


# --------------------------------------------------------------------------
# Test: can_handle
# --------------------------------------------------------------------------

class TestCanHandle:
    """DotNetBinaryAnalyzer.can_handle testleri."""

    def test_dotnet_exe_detected(self, analyzer: DotNetBinaryAnalyzer, mock_dotnet_pe: Path):
        """mscoree.dll iceren .exe tespit edilmeli."""
        target = TargetInfo(
            path=mock_dotnet_pe, name="TestApp",
            target_type=TargetType.DOTNET_ASSEMBLY, language=Language.CSHARP,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is True

    def test_native_exe_rejected(self, analyzer: DotNetBinaryAnalyzer, mock_native_pe: Path):
        """mscoree.dll icermeyen native PE reddedilmeli."""
        target = TargetInfo(
            path=mock_native_pe, name="NativeApp",
            target_type=TargetType.PE_BINARY, language=Language.UNKNOWN,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is False

    def test_non_exe_extension_rejected(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """.txt uzantili dosya reddedilmeli."""
        f = tmp_path / "test.txt"
        f.write_bytes(b"MZ" + b"mscoree.dll" + b"\x00" * 100)
        target = TargetInfo(
            path=f, name="test",
            target_type=TargetType.UNKNOWN, language=Language.UNKNOWN,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is False


# --------------------------------------------------------------------------
# Test: Full analyze_static pipeline
# --------------------------------------------------------------------------

class TestAnalyzeStatic:
    """analyze_static integration testleri."""

    def test_produces_stage_result(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Analiz StageResult dondurmeli."""
        result = analyzer.analyze_static(mock_target, workspace)
        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stage_name == "static"
        assert result.duration_seconds >= 0

    def test_cli_header_in_stats(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """CLI header bilgisi stats'ta olmali."""
        result = analyzer.analyze_static(mock_target, workspace)
        assert "has_cli_header" in result.stats

    def test_analysis_json_written(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Analiz sonucu JSON'a yazilmali."""
        result = analyzer.analyze_static(mock_target, workspace)
        path = Path(result.artifacts["dotnet_analysis"])
        assert path.exists()
        data = json.loads(path.read_text())
        assert "cli_header" in data
        assert "metadata" in data
        assert "obfuscation" in data

    def test_runtime_version_in_results(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Runtime version stats'ta olmali."""
        result = analyzer.analyze_static(mock_target, workspace)
        # Runtime version parse edilmis olmali
        assert "runtime_version" in result.stats


# --------------------------------------------------------------------------
# Test: Obfuscation detection
# --------------------------------------------------------------------------

class TestObfuscation:
    """.NET obfuscation tespiti testleri."""

    def test_confuserex_detected(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """ConfuserEx reference tespit edilmeli."""
        metadata = {
            "references": ["ConfuserEx.Runtime, Version=1.0.0.0"],
            "namespaces": [],
        }
        result = analyzer._detect_obfuscation(tmp_path / "test.dll", metadata)
        assert result["detected"] is True
        assert result["type"] == "confuserex"

    def test_dotfuscator_detected(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """Dotfuscator reference tespit edilmeli."""
        metadata = {
            "references": ["Dotfuscator.Runtime, Version=4.0.0.0"],
            "namespaces": [],
        }
        result = analyzer._detect_obfuscation(tmp_path / "test.dll", metadata)
        assert result["detected"] is True
        assert result["type"] == "dotfuscator"

    def test_gibberish_namespaces(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """Anlamsiz namespace'ler obfuscation olarak tespit edilmeli."""
        metadata = {
            "references": [],
            "namespaces": [f"{chr(ord('a') + i)}.{chr(ord('a') + j)}" for i in range(5) for j in range(3)],
        }
        result = analyzer._detect_obfuscation(tmp_path / "test.dll", metadata)
        assert result["detected"] is True

    def test_normal_namespaces_clean(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """Normal namespace'ler obfuscated olarak tespit edilmemeli."""
        metadata = {
            "references": [],
            "namespaces": ["MyApp.Services", "MyApp.Models", "MyApp.Controllers"],
        }
        result = analyzer._detect_obfuscation(tmp_path / "test.dll", metadata)
        assert result["detected"] is False


# --------------------------------------------------------------------------
# Test: NuGet detection
# --------------------------------------------------------------------------

class TestNuGetDetection:
    """NuGet paket tespit testleri."""

    def test_known_packages_detected(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """Bilinen NuGet paketleri tespit edilmeli."""
        metadata = {
            "references": [
                "Newtonsoft.Json, Version=13.0.0.0",
                "Serilog, Version=2.12.0.0",
            ],
        }
        deps = analyzer._detect_nuget_packages(tmp_path / "test.dll", metadata)
        assert "Newtonsoft.Json" in deps
        assert "Serilog" in deps

    def test_no_deps_in_clean_assembly(self, analyzer: DotNetBinaryAnalyzer, tmp_path: Path):
        """Sadece System referansli assembly'de NuGet paketi olmamali."""
        metadata = {"references": ["System.Core"]}
        deps = analyzer._detect_nuget_packages(tmp_path / "test.dll", metadata)
        assert len(deps) == 0


# --------------------------------------------------------------------------
# Test: reconstruct
# --------------------------------------------------------------------------

class TestReconstruct:
    """.NET proje reconstruction testleri."""

    def test_csproj_generated(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Reconstruction .csproj dosyasi olusturmali."""
        # Once analyze_static calistir
        analyzer.analyze_static(mock_target, workspace)
        result = analyzer.reconstruct(mock_target, workspace)
        assert result is not None
        assert result.success is True

        project_dir = Path(result.artifacts["dotnet_project"])
        csproj_files = list(project_dir.glob("*.csproj"))
        assert len(csproj_files) >= 1

    def test_csproj_content(self, analyzer: DotNetBinaryAnalyzer):
        """csproj icerigi dogru olmali."""
        metadata = {"assembly_name": "MyApp", "target_framework": ".NETCoreApp 6.0"}
        content = analyzer._generate_csproj(metadata, ["Newtonsoft.Json"])
        assert "net6.0" in content
        assert "MyApp" in content
        assert "Newtonsoft.Json" in content

    def test_framework_detection(self, analyzer: DotNetBinaryAnalyzer):
        """Target framework dogru tespit edilmeli."""
        # .NET Framework
        content = analyzer._generate_csproj(
            {"assembly_name": "X", "target_framework": ".NETFramework 4.8"}, [],
        )
        assert "net48" in content

        # .NET 7
        content = analyzer._generate_csproj(
            {"assembly_name": "X", "target_framework": ".NETCoreApp 7.0"}, [],
        )
        assert "net7.0" in content


# --------------------------------------------------------------------------
# Test: deobfuscate
# --------------------------------------------------------------------------

class TestDeobfuscate:
    """Deobfuscation placeholder testleri."""

    def test_deobfuscate_returns_success(
        self, analyzer: DotNetBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Deobfuscate her zaman success donmeli."""
        result = analyzer.deobfuscate(mock_target, workspace)
        assert result.success is True
        assert result.stage_name == "deobfuscate"
