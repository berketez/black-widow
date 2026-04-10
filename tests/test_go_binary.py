"""Go Binary Analyzer test suite.

Go binary tespiti, GOPCLNTAB parse, BUILDINFO parse,
type descriptor extraction ve proje reconstruction testleri.

Gercek Go binary olmadan calismali — mock data kullanir.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.go_binary import (
    GoBinaryAnalyzer,
    _GO_RUNTIME_SIGNATURES,
    _GOPCLNTAB_MAGICS,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.reconstruction.go_reconstructor import GoReconstructor


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config."""
    return Config()


@pytest.fixture
def go_analyzer(config: Config) -> GoBinaryAnalyzer:
    """GoBinaryAnalyzer instance."""
    return GoBinaryAnalyzer(config)


@pytest.fixture
def mock_go_binary(tmp_path: Path) -> Path:
    """Sahte Go binary olustur — Go runtime string'leri iceren."""
    binary_path = tmp_path / "test_go_binary"

    # Go runtime string'leri iceren sahte binary
    content = b"\x00" * 64  # padding
    content += b"runtime.gopanic\x00"
    content += b"runtime.goexit\x00"
    content += b"runtime.main\x00"
    content += b"runtime.newproc\x00"
    content += b"runtime/internal\x00"
    content += b"go.buildid\x00"
    content += b"go1.21.5\x00"
    content += b"main.handleRequest\x00"
    content += b"main.(*Server).Start\x00"
    content += b"github.com/user/project/pkg.NewClient\x00"
    content += b"github.com/user/project/pkg.(*Client).Do\x00"
    content += b"main.func1\x00"
    content += b"/Users/user/project/main.go\x00"
    content += b"/Users/user/project/pkg/client.go\x00"
    content += b"\x00" * 64  # padding

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def mock_go_target(mock_go_binary: Path) -> TargetInfo:
    """TargetInfo instance for Go binary."""
    return TargetInfo(
        path=mock_go_binary,
        name="test_go_binary",
        target_type=TargetType.GO_BINARY,
        language=Language.GO,
        file_size=mock_go_binary.stat().st_size,
        file_hash="abc123",
        metadata={"magic": "0x00000000"},
    )


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Workspace:
    """Gecici workspace."""
    ws = Workspace(tmp_path / "workspaces", "test_go")
    ws.create()
    return ws


@pytest.fixture
def sample_gopclntab() -> dict[str, Any]:
    """Ornek GOPCLNTAB verisi."""
    return {
        "total_functions": 5,
        "functions": [
            {
                "name": "main.main",
                "source_file": "/Users/user/project/main.go",
                "lines": [10, 25],
                "package": "main",
            },
            {
                "name": "main.handleRequest",
                "source_file": "/Users/user/project/main.go",
                "lines": [30, 55],
                "package": "main",
            },
            {
                "name": "main.(*Server).Start",
                "source_file": "/Users/user/project/server.go",
                "lines": [10, 80],
                "package": "main",
            },
            {
                "name": "github.com/user/project/pkg.NewClient",
                "source_file": "/Users/user/project/pkg/client.go",
                "lines": [5, 20],
                "package": "github.com/user/project/pkg",
            },
            {
                "name": "main.func1",
                "source_file": "/Users/user/project/main.go",
                "lines": [60, 65],
                "package": "main",
            },
        ],
        "source_files": [
            "/Users/user/project/main.go",
            "/Users/user/project/pkg/client.go",
            "/Users/user/project/server.go",
        ],
        "extraction_method": "test_mock",
    }


@pytest.fixture
def sample_buildinfo() -> dict[str, Any]:
    """Ornek BUILDINFO verisi."""
    return {
        "go_version": "go1.21.5",
        "module_path": "github.com/user/project",
        "module_version": "(devel)",
        "dependencies": [
            {"path": "github.com/pkg/errors", "version": "v0.9.1"},
            {"path": "golang.org/x/sync", "version": "v0.5.0"},
            {"path": "github.com/gorilla/mux", "version": "v1.8.1"},
        ],
        "build_settings": {
            "-compiler": "gc",
            "CGO_ENABLED": "1",
            "GOARCH": "arm64",
            "GOOS": "darwin",
        },
    }


@pytest.fixture
def sample_types() -> dict[str, Any]:
    """Ornek type descriptor verisi."""
    return {
        "structs": [
            {"name": "Server", "package": "main", "full_name": "main.Server"},
            {"name": "Client", "package": "github.com/user/project/pkg", "full_name": "github.com/user/project/pkg.Client"},
        ],
        "interfaces": [
            {"name": "Handler", "package": "main", "full_name": "main.Handler"},
        ],
        "methods": [
            {"full_name": "main.(*Server).Start", "receiver_type": "Server", "method_name": "Start"},
            {"full_name": "main.(*Server).Stop", "receiver_type": "Server", "method_name": "Stop"},
        ],
        "total_types": 3,
        "total_methods": 2,
    }


# --------------------------------------------------------------------------
# Go Binary Detection Tests
# --------------------------------------------------------------------------

class TestGoBinaryDetection:
    """Go binary tespiti testleri."""

    def test_can_handle_with_go_signatures(self, mock_go_target: TargetInfo):
        """Go runtime string'leri olan binary tanilanmali."""
        assert GoBinaryAnalyzer.can_handle(mock_go_target) is True

    def test_can_handle_non_go_binary(self, tmp_path: Path):
        """Go olmayan binary tanilanmamali."""
        non_go = tmp_path / "not_go"
        non_go.write_bytes(b"\x00" * 256 + b"some random content" + b"\x00" * 256)

        target = TargetInfo(
            path=non_go,
            name="not_go",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=non_go.stat().st_size,
            file_hash="xyz",
        )
        assert GoBinaryAnalyzer.can_handle(target) is False

    def test_can_handle_gopclntab_magic(self, tmp_path: Path):
        """GOPCLNTAB magic bytes ile tespit edilmeli."""
        binary = tmp_path / "go_with_magic"
        # Go 1.20 GOPCLNTAB magic iceren binary
        content = b"\x00" * 128 + _GOPCLNTAB_MAGICS[0] + b"\x00" * 128
        binary.write_bytes(content)

        target = TargetInfo(
            path=binary,
            name="go_with_magic",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=binary.stat().st_size,
            file_hash="pqr",
        )
        assert GoBinaryAnalyzer.can_handle(target) is True

    def test_can_handle_nonexistent_file(self, tmp_path: Path):
        """Mevcut olmayan dosya False dondurmeli."""
        target = TargetInfo(
            path=tmp_path / "nonexistent",
            name="nonexistent",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=0,
            file_hash="",
        )
        assert GoBinaryAnalyzer.can_handle(target) is False


# --------------------------------------------------------------------------
# GOPCLNTAB Extraction Tests
# --------------------------------------------------------------------------

class TestGopclntabExtraction:
    """GOPCLNTAB parse testleri."""

    def test_gopclntab_via_strings_basic(self, go_analyzer: GoBinaryAnalyzer, mock_go_binary: Path):
        """strings fallback ile Go fonksiyon isimleri cikarilmali."""
        result = go_analyzer._gopclntab_via_strings(mock_go_binary)

        assert result is not None
        assert result["total_functions"] > 0

        # Bilinen Go fonksiyon isimleri bulunmali
        func_names = [f["name"] for f in result["functions"]]
        assert any("main.handleRequest" in n for n in func_names)

    def test_gopclntab_via_strings_source_files(self, go_analyzer: GoBinaryAnalyzer, mock_go_binary: Path):
        """strings fallback ile .go dosya yollari bulunmali."""
        result = go_analyzer._gopclntab_via_strings(mock_go_binary)

        assert result is not None
        source_files = result.get("source_files", [])
        assert any(f.endswith(".go") for f in source_files)

    def test_gopclntab_via_objdump_mock(self, go_analyzer: GoBinaryAnalyzer, tmp_path: Path):
        """go tool objdump ciktisi dogru parse edilmeli (mock)."""
        mock_output = textwrap.dedent("""\
            TEXT main.main(SB) /Users/user/project/main.go
              main.go:10	0x1001000	MOVQ AX, BX
              main.go:11	0x1001004	CALL runtime.gopanic
            TEXT main.handleRequest(SB) /Users/user/project/main.go
              main.go:30	0x1002000	SUBQ $0x18, SP
            TEXT github.com/user/pkg.NewClient(SB) /Users/user/project/pkg/client.go
              client.go:5	0x1003000	MOVQ AX, CX
        """)

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch.object(go_analyzer.runner, "run_command", return_value=mock_result):
            go_analyzer._go_available = True
            result = go_analyzer._gopclntab_via_objdump(tmp_path / "fake_binary")

        assert result is not None
        assert result["total_functions"] == 3

        func_names = [f["name"] for f in result["functions"]]
        assert "main.main" in func_names
        assert "main.handleRequest" in func_names
        assert "github.com/user/pkg.NewClient" in func_names

        # Kaynak dosyalar
        assert "/Users/user/project/main.go" in result["source_files"]
        assert "/Users/user/project/pkg/client.go" in result["source_files"]

    def test_gopclntab_via_nm_mock(self, go_analyzer: GoBinaryAnalyzer, tmp_path: Path):
        """nm ciktisi dogru parse edilmeli (mock)."""
        mock_output = textwrap.dedent("""\
            0000000100001000 T main.main
            0000000100002000 T main.handleRequest
            0000000100003000 T main.(*Server).Start
            0000000100004000 T github.com/user/project/pkg.NewClient
                             U _runtime.gopanic
        """)

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = mock_output
        mock_result.stderr = ""

        with patch.object(go_analyzer.runner, "run_command", return_value=mock_result):
            result = go_analyzer._gopclntab_via_nm(tmp_path / "fake_binary")

        assert result is not None
        assert result["total_functions"] >= 3

        func_names = [f["name"] for f in result["functions"]]
        assert "main.main" in func_names
        assert "main.handleRequest" in func_names

    def test_gopclntab_empty_binary(self, go_analyzer: GoBinaryAnalyzer, tmp_path: Path):
        """Bos binary icin None donmeli."""
        empty = tmp_path / "empty"
        empty.write_bytes(b"\x00" * 64)

        result = go_analyzer._gopclntab_via_strings(empty)
        # Bos veya None donebilir
        if result is not None:
            assert result["total_functions"] == 0


# --------------------------------------------------------------------------
# BUILDINFO Tests
# --------------------------------------------------------------------------

class TestBuildInfoExtraction:
    """BUILDINFO parse testleri."""

    def test_parse_go_version_output(self, go_analyzer: GoBinaryAnalyzer):
        """go version -m ciktisi dogru parse edilmeli."""
        output = textwrap.dedent("""\
            /path/to/binary: go1.21.5
            \tpath\tgithub.com/user/project
            \tmod\tgithub.com/user/project\t(devel)
            \tdep\tgithub.com/pkg/errors\tv0.9.1\th1:FEBLx...
            \tdep\tgolang.org/x/sync\tv0.5.0\th1:abc...
            \tbuild\t-compiler=gc
            \tbuild\tCGO_ENABLED=1
            \tbuild\tGOARCH=arm64
            \tbuild\tGOOS=darwin
        """)

        result = go_analyzer._parse_go_version_output(output)

        assert result is not None
        assert result["go_version"] == "go1.21.5"
        assert result["module_path"] == "github.com/user/project"
        assert len(result["dependencies"]) == 2
        assert result["dependencies"][0]["path"] == "github.com/pkg/errors"
        assert result["dependencies"][0]["version"] == "v0.9.1"
        assert result["build_settings"]["-compiler"] == "gc"
        assert result["build_settings"]["CGO_ENABLED"] == "1"

    def test_parse_go_version_output_minimal(self, go_analyzer: GoBinaryAnalyzer):
        """Minimal go version ciktisi (sadece versiyon)."""
        output = "/path/to/binary: go1.20\n"
        result = go_analyzer._parse_go_version_output(output)

        assert result is not None
        assert result["go_version"] == "go1.20"

    def test_parse_go_version_output_empty(self, go_analyzer: GoBinaryAnalyzer):
        """Bos cikti icin None."""
        result = go_analyzer._parse_go_version_output("")
        assert result is None

    def test_buildinfo_via_strings(self, go_analyzer: GoBinaryAnalyzer, mock_go_binary: Path):
        """strings fallback ile buildinfo cikarilmali."""
        result = go_analyzer._buildinfo_via_strings(mock_go_binary)

        # Mock binary'de go1.21.5 var
        assert result is not None
        assert "go1.21" in result.get("go_version", "")


# --------------------------------------------------------------------------
# Type Descriptor Tests
# --------------------------------------------------------------------------

class TestTypeDescriptorExtraction:
    """Type descriptor extraction testleri."""

    def test_extract_types_basic(self, go_analyzer: GoBinaryAnalyzer, mock_go_binary: Path):
        """Binary'den type isimleri cikarilmali."""
        result = go_analyzer._extract_type_descriptors(mock_go_binary)

        # Mock binary'de main.(*Server).Start var
        # Bu Server tipini tanimlar
        if result is not None:
            assert "structs" in result
            assert "methods" in result

    def test_extract_types_empty_binary(self, go_analyzer: GoBinaryAnalyzer, tmp_path: Path):
        """Bos binary icin None donmeli."""
        empty = tmp_path / "empty"
        empty.write_bytes(b"\x00" * 64)

        result = go_analyzer._extract_type_descriptors(empty)
        assert result is None


# --------------------------------------------------------------------------
# Goroutine Detection Tests
# --------------------------------------------------------------------------

class TestGoroutineDetection:
    """Goroutine entry point tespiti testleri."""

    def test_detect_anonymous_goroutine(self, go_analyzer: GoBinaryAnalyzer):
        """Anonymous closure goroutine tespiti."""
        functions = [
            {"name": "main.func1", "package": "main"},
            {"name": "main.handleRequest.func2", "package": "main"},
            {"name": "main.handleRequest", "package": "main"},
        ]

        goroutines = go_analyzer._detect_goroutines(functions)

        assert len(goroutines) >= 1
        closure_names = [g["name"] for g in goroutines if g["type"] == "anonymous_closure"]
        assert "main.func1" in closure_names

    def test_detect_runtime_goroutine_mgmt(self, go_analyzer: GoBinaryAnalyzer):
        """Runtime goroutine yonetim fonksiyonlari tespiti."""
        functions = [
            {"name": "runtime.goexit", "package": "runtime"},
            {"name": "runtime.newproc", "package": "runtime"},
            {"name": "runtime.gopark", "package": "runtime"},
            {"name": "runtime.main", "package": "runtime"},
        ]

        goroutines = go_analyzer._detect_goroutines(functions)

        runtime_names = [g["name"] for g in goroutines if g["type"] == "runtime_goroutine_mgmt"]
        assert "runtime.goexit" in runtime_names
        assert "runtime.newproc" in runtime_names
        assert "runtime.gopark" in runtime_names
        # runtime.main goroutine yonetimi degil
        assert "runtime.main" not in runtime_names

    def test_detect_no_goroutines(self, go_analyzer: GoBinaryAnalyzer):
        """Goroutine yoksa bos liste donmeli."""
        functions = [
            {"name": "main.handleRequest", "package": "main"},
            {"name": "main.init", "package": "main"},
        ]

        goroutines = go_analyzer._detect_goroutines(functions)
        assert goroutines == []


# --------------------------------------------------------------------------
# Package Analysis Tests
# --------------------------------------------------------------------------

class TestPackageAnalysis:
    """Paket yapisi analizi testleri."""

    def test_extract_packages(self, go_analyzer: GoBinaryAnalyzer):
        """Fonksiyonlardan paket yapisi cikarilmali."""
        functions = [
            {"name": "main.main", "package": "main"},
            {"name": "main.handleRequest", "package": "main"},
            {"name": "github.com/user/pkg.NewClient", "package": "github.com/user/pkg"},
            {"name": "runtime.gopanic", "package": "runtime"},
        ]

        result = go_analyzer._extract_packages(functions)

        assert result is not None
        assert result["total"] >= 3

        pkg_names = [p["name"] for p in result["packages"]]
        assert "main" in pkg_names
        assert "github.com/user/pkg" in pkg_names

        # Stdlib vs user ayrimi
        assert result["user_packages"] >= 1
        assert result["stdlib_packages"] >= 1

    def test_is_go_stdlib(self, go_analyzer: GoBinaryAnalyzer):
        """Stdlib tespiti dogru calismali."""
        assert go_analyzer._is_go_stdlib("runtime") is True
        assert go_analyzer._is_go_stdlib("runtime/internal") is True
        assert go_analyzer._is_go_stdlib("fmt") is True
        assert go_analyzer._is_go_stdlib("net/http") is True
        assert go_analyzer._is_go_stdlib("encoding/json") is True

        assert go_analyzer._is_go_stdlib("main") is False
        assert go_analyzer._is_go_stdlib("github.com/user/project") is False
        assert go_analyzer._is_go_stdlib("mypackage") is False


# --------------------------------------------------------------------------
# Full Static Analysis Test (Integration)
# --------------------------------------------------------------------------

class TestStaticAnalysis:
    """Tam statik analiz testi (mock subprocess ile)."""

    def test_analyze_static_with_strings_fallback(
        self,
        go_analyzer: GoBinaryAnalyzer,
        mock_go_target: TargetInfo,
        mock_workspace: Workspace,
    ):
        """Go kurulu olmasa bile strings fallback calismali."""
        # Go mevcut degil
        go_analyzer._go_available = False

        # nm basarisiz (stripped binary)
        mock_nm_result = MagicMock()
        mock_nm_result.success = False
        mock_nm_result.stderr = "no symbols"
        mock_nm_result.stdout = ""

        def mock_run_command(cmd, timeout=None):
            if cmd[0] == "go":
                r = MagicMock()
                r.success = False
                return r
            if cmd[0] == str(go_analyzer.config.tools.nm):
                return mock_nm_result
            # strings komutu
            r = MagicMock()
            r.success = True
            r.stdout = "runtime.gopanic\nruntime.goexit\nmain.handleRequest\nmain.(*Server).Start\ngo1.21.5\n/Users/user/project/main.go\n"
            return r

        with patch.object(go_analyzer.runner, "run_command", side_effect=mock_run_command):
            with patch.object(go_analyzer.runner, "run_strings", return_value=[
                "runtime.gopanic",
                "runtime.goexit",
                "runtime.main",
                "main.handleRequest",
                "main.(*Server).Start",
                "github.com/user/project/pkg.NewClient",
                "go1.21.5",
                "/Users/user/project/main.go",
                "/Users/user/project/pkg/client.go",
            ]):
                result = go_analyzer.analyze_static(mock_go_target, mock_workspace)

        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stats.get("analyzer") == "go_binary"
        assert result.stats.get("gopclntab_function_count", 0) > 0


# --------------------------------------------------------------------------
# GoReconstructor Tests
# --------------------------------------------------------------------------

class TestGoReconstructor:
    """Go proje reconstruction testleri."""

    def test_basic_reconstruction(
        self,
        tmp_path: Path,
        sample_gopclntab: dict,
        sample_buildinfo: dict,
        sample_types: dict,
    ):
        """Temel proje yapisi olusturulmali."""
        output_dir = tmp_path / "reconstructed"

        reconstructor = GoReconstructor()
        result = reconstructor.reconstruct(
            analysis_results={
                "gopclntab": sample_gopclntab,
                "buildinfo": sample_buildinfo,
                "types": sample_types,
                "packages": {},
            },
            output_dir=output_dir,
        )

        assert result is not None
        assert result["total_files"] > 0
        assert result["packages_created"] >= 1
        assert result["functions_placed"] > 0

    def test_go_mod_creation(
        self,
        tmp_path: Path,
        sample_buildinfo: dict,
    ):
        """go.mod dosyasi dogru olusturulmali."""
        output_dir = tmp_path / "project"
        output_dir.mkdir()

        reconstructor = GoReconstructor()
        go_mod = reconstructor._create_go_mod(sample_buildinfo, output_dir)

        assert go_mod is not None
        assert go_mod.exists()

        content = go_mod.read_text()
        assert "module github.com/user/project" in content
        assert "go 1.21.5" in content
        assert "github.com/pkg/errors" in content
        assert "v0.9.1" in content

    def test_go_mod_without_buildinfo(self, tmp_path: Path):
        """BUILDINFO olmasa bile varsayilan go.mod olusturulmali."""
        output_dir = tmp_path / "project"
        output_dir.mkdir()

        reconstructor = GoReconstructor()
        go_mod = reconstructor._create_go_mod({}, output_dir)

        assert go_mod is not None
        content = go_mod.read_text()
        assert "module reconstructed/module" in content
        assert "go 1.21" in content

    def test_package_organization(self, sample_gopclntab: dict, sample_buildinfo: dict):
        """Fonksiyonlar dogru paketlere gruplanmali."""
        reconstructor = GoReconstructor()
        packages = reconstructor._organize_by_package(
            sample_gopclntab["functions"],
            sample_buildinfo,
        )

        assert "main" in packages
        assert len(packages["main"]) >= 3  # main.main, handleRequest, Server.Start, func1

        # User paketi
        assert "github.com/user/project/pkg" in packages
        assert len(packages["github.com/user/project/pkg"]) >= 1

    def test_stdlib_not_reconstructed(self, tmp_path: Path, sample_buildinfo: dict):
        """Stdlib paketleri icin dizin olusturulmamali."""
        output_dir = tmp_path / "project"
        output_dir.mkdir()

        reconstructor = GoReconstructor()

        # Stdlib paketi
        result = reconstructor._create_package_dir(
            "runtime", sample_buildinfo["module_path"], output_dir,
        )
        assert result is None

        result = reconstructor._create_package_dir(
            "fmt", sample_buildinfo["module_path"], output_dir,
        )
        assert result is None

        # User paketi
        result = reconstructor._create_package_dir(
            "main", sample_buildinfo["module_path"], output_dir,
        )
        assert result is not None
        assert result.exists()

    def test_go_file_content(self, tmp_path: Path, sample_types: dict):
        """Olusturulan .go dosyasi dogru icerige sahip olmali."""
        pkg_dir = tmp_path / "main_pkg"
        pkg_dir.mkdir()

        functions = [
            {
                "name": "main.handleRequest",
                "source_file": "/Users/user/project/main.go",
                "lines": [30, 55],
            },
            {
                "name": "main.(*Server).Start",
                "source_file": "/Users/user/project/server.go",
                "lines": [10, 80],
            },
        ]

        reconstructor = GoReconstructor()
        go_file = reconstructor._create_go_file(
            pkg_name="main",
            pkg_dir=pkg_dir,
            functions=functions,
            types=sample_types,
        )

        assert go_file is not None
        assert go_file.exists()

        content = go_file.read_text()
        assert "package main" in content
        assert "func handleRequest()" in content
        assert "func (r *Server) Start()" in content
        assert "type Server struct" in content
        assert "type Handler interface" in content
        assert "Karadul Go Binary Analyzer" in content

    def test_func_short_name_extraction(self):
        """Fonksiyon kisa adi dogru cikarilmali."""
        reconstructor = GoReconstructor()

        assert reconstructor._extract_func_short_name("main.handleRequest") == "handleRequest"
        assert reconstructor._extract_func_short_name("main.(*Server).Start") == "Start"
        assert reconstructor._extract_func_short_name("github.com/user/pkg.NewClient") == "NewClient"
        assert reconstructor._extract_func_short_name("runtime.gopanic") == "gopanic"

        # Anonymous closure atlanmali
        assert reconstructor._extract_func_short_name("main.func1") is None

        # Bos
        assert reconstructor._extract_func_short_name("") is None

    def test_reconstruction_with_minimal_data(self, tmp_path: Path):
        """Minimum veriyle bile proje olusturulmali."""
        output_dir = tmp_path / "minimal"

        reconstructor = GoReconstructor()
        result = reconstructor.reconstruct(
            analysis_results={
                "gopclntab": {
                    "functions": [
                        {"name": "main.main", "package": "main"},
                    ],
                    "source_files": [],
                },
                "buildinfo": {},
                "types": {},
                "packages": {},
            },
            output_dir=output_dir,
        )

        assert result is not None
        assert result["total_files"] >= 1  # en az go.mod + main.go
        assert (output_dir / "go.mod").exists()
        assert (output_dir / "main.go").exists()


# --------------------------------------------------------------------------
# Analyzer Registry Test
# --------------------------------------------------------------------------

class TestAnalyzerRegistry:
    """Analyzer registry'ye kayit testi."""

    def test_go_binary_registered(self):
        """GoBinaryAnalyzer registry'de olmali."""
        from karadul.analyzers import get_analyzer
        analyzer_cls = get_analyzer(TargetType.GO_BINARY)
        assert analyzer_cls is GoBinaryAnalyzer

    def test_go_binary_in_list(self):
        """list_analyzers() Go binary'yi icermeli."""
        from karadul.analyzers import list_analyzers
        analyzers = list_analyzers()
        assert TargetType.GO_BINARY in analyzers


# --------------------------------------------------------------------------
# Enum Tests
# --------------------------------------------------------------------------

class TestEnumValues:
    """TargetType ve Language enum'larinda Go degerlerinin varligini kontrol."""

    def test_target_type_go_binary(self):
        """TargetType.GO_BINARY mevcut olmali."""
        assert TargetType.GO_BINARY.value == "go_binary"

    def test_language_go(self):
        """Language.GO mevcut olmali."""
        assert Language.GO.value == "go"


# --------------------------------------------------------------------------
# Go Tool Availability Test
# --------------------------------------------------------------------------

class TestGoToolAvailability:
    """Go toolchain kontrol testi."""

    def test_check_go_available_cached(self, go_analyzer: GoBinaryAnalyzer):
        """Go mevcut kontrolu cache'lenmeli."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = "go version go1.21.5 darwin/arm64"

        with patch.object(go_analyzer.runner, "run_command", return_value=mock_result) as mock_run:
            assert go_analyzer._check_go_available() is True
            assert go_analyzer._check_go_available() is True
            # Sadece 1 kez cagirilmali (cache)
            assert mock_run.call_count == 1

    def test_check_go_not_available(self, go_analyzer: GoBinaryAnalyzer):
        """Go kurulu degilse False donmeli."""
        mock_result = MagicMock()
        mock_result.success = False

        with patch.object(go_analyzer.runner, "run_command", return_value=mock_result):
            assert go_analyzer._check_go_available() is False
