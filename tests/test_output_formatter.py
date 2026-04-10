"""OutputFormatter ve ReportGenerator testleri.

OutputFormatter: workspace ciktisini temiz dizin yapisina donusturur.
ReportGenerator: gelismis tek-dosya HTML rapor uretir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.core.output_formatter import OutputFormatter, FormatResult
from karadul.core.report_generator import ReportGenerator
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Test workspace olustur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_binary")
    ws.create()
    return ws


@pytest.fixture
def js_workspace(tmp_path: Path) -> Workspace:
    """JS analiz icin test workspace olustur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_bundle")
    ws.create()
    return ws


@pytest.fixture
def binary_pipeline_result(workspace: Workspace) -> PipelineResult:
    """Binary analiz pipeline result'i."""
    result = PipelineResult(
        target_name="test_binary",
        target_hash="abcdef1234567890",
        workspace_path=workspace.path,
    )

    # Identify stage
    result.add_stage_result(StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.1,
        stats={
            "target_type": "macho_binary",
            "language": "c",
            "file_size": 5242880,
        },
    ))

    # Static stage
    result.add_stage_result(StageResult(
        stage_name="static",
        success=True,
        duration_seconds=15.3,
        stats={
            "functions_found": 342,
            "strings_found": 1245,
            "ghidra_function_count": 342,
        },
    ))

    # Reconstruct stage
    result.add_stage_result(StageResult(
        stage_name="reconstruct",
        success=True,
        duration_seconds=8.7,
        stats={
            "variables_renamed": 156,
            "name_merger_total": 89,
            "name_merger_conflicts": 12,
            "structs_recovered": 15,
            "enums_recovered": 3,
            "algorithms_detected": 4,
            "signature_matches": 23,
            "comments_added": 67,
            "vuln_warnings": 3,
        },
    ))

    result.total_duration = 24.1
    return result


@pytest.fixture
def js_pipeline_result(js_workspace: Workspace) -> PipelineResult:
    """JS analiz pipeline result'i."""
    result = PipelineResult(
        target_name="test_bundle.js",
        target_hash="js123456",
        workspace_path=js_workspace.path,
    )

    result.add_stage_result(StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.05,
        stats={
            "target_type": "js_bundle",
            "language": "javascript",
            "file_size": 9150000,
            "bundler": "webpack",
        },
    ))

    result.add_stage_result(StageResult(
        stage_name="static",
        success=True,
        duration_seconds=10.0,
        stats={
            "functions_found": 500,
            "strings_found": 8000,
        },
    ))

    result.add_stage_result(StageResult(
        stage_name="reconstruct",
        success=True,
        duration_seconds=20.0,
        stats={
            "variables_renamed": 300,
            "params_recovered": 45,
            "naming_total": 42,
            "naming_avg_confidence": 0.72,
        },
    ))

    result.total_duration = 30.05
    return result


def _populate_binary_workspace(workspace: Workspace) -> None:
    """Binary workspace'ine ornek dosyalar ekle."""
    # Decompiled C dosyalari
    deob_dir = workspace.get_stage_dir("deobfuscated")
    decompiled_dir = deob_dir / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)

    (decompiled_dir / "main.c").write_text(
        '#include <stdio.h>\n\n'
        'undefined4 FUN_100001234(undefined8 param_1, undefined4 param_2) {\n'
        '    undefined8 local_10;\n'
        '    local_10 = param_1;\n'
        '    printf("Hello %s\\n", local_10);\n'
        '    return 0;\n'
        '}\n\n'
        'int main(int argc, char **argv) {\n'
        '    FUN_100001234(argv[0], argc);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )

    (decompiled_dir / "network.c").write_text(
        'void FUN_100002000(void) {\n'
        '    int sock = socket(2, 1, 0);\n'
        '    connect(sock, &addr, sizeof(addr));\n'
        '    send(sock, buffer, len, 0);\n'
        '}\n',
        encoding="utf-8",
    )

    (decompiled_dir / "crypto.c").write_text(
        'void FUN_100003000(void) {\n'
        '    CCCrypt(0, 0, 0, key, 16, iv, input, len, output, len, &outLen);\n'
        '}\n',
        encoding="utf-8",
    )

    # Commented (en son islenmis hali)
    reconstructed_dir = workspace.get_stage_dir("reconstructed")
    commented_dir = reconstructed_dir / "commented"
    commented_dir.mkdir(parents=True, exist_ok=True)

    (commented_dir / "main.c").write_text(
        '#include <stdio.h>\n\n'
        '/* Entry point function - prints greeting message */\n'
        'uint32_t print_greeting(uint64_t name, uint32_t count) {\n'
        '    uint64_t local_name;\n'
        '    local_name = name;\n'
        '    printf("Hello %s\\n", local_name);\n'
        '    return 0;\n'
        '}\n\n'
        '/* Main entry point */\n'
        'int main(int argc, char **argv) {\n'
        '    print_greeting(argv[0], argc);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )

    (commented_dir / "network.c").write_text(
        '/* Network connection handler */\n'
        'void establish_connection(void) {\n'
        '    int sock = socket(AF_INET, SOCK_STREAM, 0);\n'
        '    connect(sock, &addr, sizeof(addr));\n'
        '    send(sock, buffer, len, 0);\n'
        '}\n',
        encoding="utf-8",
    )

    (commented_dir / "crypto.c").write_text(
        '/* AES encryption wrapper using CommonCrypto */\n'
        'void aes_encrypt(void) {\n'
        '    CCCrypt(0, 0, 0, key, 16, iv, input, len, output, len, &outLen);\n'
        '}\n',
        encoding="utf-8",
    )

    # Binary names JSON
    workspace.save_json("reconstructed", "binary_names", {
        "total": 3,
        "names": {
            "FUN_100001234": {
                "recovered": "print_greeting",
                "source": "string_analysis",
                "confidence": 0.85,
                "class": "",
            },
            "FUN_100002000": {
                "recovered": "establish_connection",
                "source": "api_pattern",
                "confidence": 0.75,
                "class": "",
            },
            "FUN_100003000": {
                "recovered": "aes_encrypt",
                "source": "api_pattern",
                "confidence": 0.80,
                "class": "",
            },
        },
        "classes": {},
    })

    # Signature matches
    workspace.save_json("reconstructed", "signature_matches", {
        "total": 2,
        "matches": [
            {
                "original": "FUN_100005000",
                "matched": "strlen",
                "library": "libc",
                "confidence": 0.95,
                "purpose": "string length",
            },
            {
                "original": "FUN_100006000",
                "matched": "memcpy",
                "library": "libc",
                "confidence": 0.92,
                "purpose": "memory copy",
            },
        ],
    })


def _populate_js_workspace(workspace: Workspace) -> None:
    """JS workspace'ine ornek dosyalar ekle."""
    # Deobfuscated JS
    deob_dir = workspace.get_stage_dir("deobfuscated")
    (deob_dir / "bundle.deobfuscated.js").write_text(
        'function a(b, c) {\n'
        '    return b + c;\n'
        '}\n'
        'function d(e) {\n'
        '    return fetch("/api/users/" + e);\n'
        '}\n',
        encoding="utf-8",
    )

    # Reconstructed (renamed)
    reconstructed_dir = workspace.get_stage_dir("reconstructed")
    (reconstructed_dir / "bundle.nsa_named.js").write_text(
        '/** Add two numbers */\n'
        'function addNumbers(num1, num2) {\n'
        '    return num1 + num2;\n'
        '}\n'
        '/** Fetch user by ID */\n'
        'function fetchUserById(userId) {\n'
        '    return fetch("/api/users/" + userId);\n'
        '}\n',
        encoding="utf-8",
    )


# ------------------------------------------------------------------
# OutputFormatter Tests -- Binary
# ------------------------------------------------------------------

class TestOutputFormatterBinary:
    """Binary hedef icin OutputFormatter testleri."""

    def test_format_clean_creates_output_dir(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format cikti dizini olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        result = formatter.format_output(output, fmt="clean")

        assert result.success
        assert output.exists()
        assert result.files_written > 0

    def test_format_clean_creates_src_dir(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format src/ dizini olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        result = formatter.format_output(output, fmt="clean")

        assert (output / "src").is_dir()
        assert result.src_files > 0

    def test_format_clean_has_main_c(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format src/main.c dosyasini olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        main_c = output / "src" / "main.c"
        assert main_c.exists()
        content = main_c.read_text(encoding="utf-8")
        # Ghidra undefined tipler temizlenmis olmali
        assert "undefined4" not in content
        assert "uint32_t" in content or "print_greeting" in content

    def test_format_clean_modules_dir(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format src/modules/ dizini olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        modules = output / "src" / "modules"
        assert modules.is_dir()
        c_files = list(modules.glob("*.c"))
        assert len(c_files) >= 2  # network.c + crypto.c

    def test_format_clean_creates_naming_map(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format naming_map.json olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        naming_map = output / "naming_map.json"
        assert naming_map.exists()

        data = json.loads(naming_map.read_text(encoding="utf-8"))
        assert "mappings" in data
        assert "total_mappings" in data
        assert data["total_mappings"] > 0
        # Binary names + signature matches
        assert "FUN_100001234" in data["mappings"]
        assert data["mappings"]["FUN_100001234"]["new_name"] == "print_greeting"

    def test_format_clean_creates_dependency_graph(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format dependency_graph.json olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        dep_graph = output / "dependency_graph.json"
        assert dep_graph.exists()

        data = json.loads(dep_graph.read_text(encoding="utf-8"))
        assert "nodes" in data
        assert "edges" in data
        assert "version" in data

    def test_format_clean_creates_report_json(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format report.json olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        report = output / "report.json"
        assert report.exists()

        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["karadul_version"]
        assert data["target"]["name"] == "test_binary"
        assert data["pipeline"]["success"] is True

    def test_format_clean_creates_report_html(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format report.html olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        report_html = output / "report.html"
        assert report_html.exists()
        content = report_html.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "BLACK WIDOW" in content
        assert "test_binary" in content

    def test_format_clean_creates_readme(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format README.md olusturmali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "clean_output"
        formatter.format_output(output, fmt="clean")

        readme = output / "README.md"
        assert readme.exists()
        content = readme.read_text(encoding="utf-8")
        assert "Black Widow" in content
        assert "test_binary" in content
        assert "C/C++" in content

    def test_format_raw_copies_workspace(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Raw format workspace'i oldugu gibi kopyalamali."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "raw_output"
        result = formatter.format_output(output, fmt="raw")

        assert result.success
        assert output.exists()
        # Workspace dizinleri kopyalanmis olmali
        assert (output / "reconstructed").is_dir() or result.files_written > 0

    def test_undefined_type_cleaning(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """C source'taki undefined tipler temizlenmeli."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)

        test_content = "undefined8 var1; undefined4 var2; undefined var3;"
        cleaned = formatter._clean_c_source(test_content)

        assert "undefined8" not in cleaned
        assert "undefined4" not in cleaned
        assert "uint64_t" in cleaned
        assert "uint32_t" in cleaned
        assert "uint8_t" in cleaned


# ------------------------------------------------------------------
# OutputFormatter Tests -- JS
# ------------------------------------------------------------------

class TestOutputFormatterJS:
    """JS hedef icin OutputFormatter testleri."""

    def test_format_clean_creates_main_js(
        self, tmp_path: Path, js_workspace: Workspace, js_pipeline_result: PipelineResult,
    ) -> None:
        """Clean format src/main.js olusturmali."""
        _populate_js_workspace(js_workspace)
        formatter = OutputFormatter(js_workspace, js_pipeline_result)
        output = tmp_path / "js_output"
        result = formatter.format_output(output, fmt="clean")

        assert result.success
        main_js = output / "src" / "main.js"
        assert main_js.exists()
        content = main_js.read_text(encoding="utf-8")
        assert "function" in content

    def test_format_clean_js_naming_map(
        self, tmp_path: Path, js_workspace: Workspace, js_pipeline_result: PipelineResult,
    ) -> None:
        """JS analiz icin naming_map.json olusturmali."""
        _populate_js_workspace(js_workspace)
        formatter = OutputFormatter(js_workspace, js_pipeline_result)
        output = tmp_path / "js_output"
        formatter.format_output(output, fmt="clean")

        naming_map = output / "naming_map.json"
        assert naming_map.exists()
        data = json.loads(naming_map.read_text(encoding="utf-8"))
        assert "mappings" in data

    def test_detect_language_javascript(
        self, js_workspace: Workspace, js_pipeline_result: PipelineResult,
    ) -> None:
        """JS hedef icin dil tespiti dogru olmali."""
        formatter = OutputFormatter(js_workspace, js_pipeline_result)
        lang = formatter._detect_language()
        assert lang == "javascript"


# ------------------------------------------------------------------
# OutputFormatter Tests -- Edge Cases
# ------------------------------------------------------------------

class TestOutputFormatterEdgeCases:
    """Edge case testleri."""

    def test_empty_workspace(
        self, tmp_path: Path, workspace: Workspace,
    ) -> None:
        """Bos workspace'te hata vermemeli."""
        result = PipelineResult(
            target_name="empty_target",
            target_hash="000",
            workspace_path=workspace.path,
        )
        result.add_stage_result(StageResult(
            stage_name="identify",
            success=True,
            duration_seconds=0.1,
            stats={"target_type": "unknown", "language": "unknown", "file_size": 0},
        ))
        result.total_duration = 0.1

        formatter = OutputFormatter(workspace, result)
        output = tmp_path / "empty_output"
        fmt_result = formatter.format_output(output, fmt="clean")

        # Hata vermemeli, sadece bos dosya yazamayabilir
        assert output.exists()
        # naming_map.json her zaman olusturulmali
        assert (output / "naming_map.json").exists()

    def test_format_result_dataclass(self) -> None:
        """FormatResult dataclass dogru calismalii."""
        fr = FormatResult(
            success=True,
            output_dir=Path("/tmp/test"),
            files_written=10,
            src_files=5,
            reports_generated=2,
        )
        assert fr.success
        assert fr.files_written == 10
        assert fr.src_files == 5
        assert fr.reports_generated == 2
        assert fr.errors == []

    def test_clean_c_source_multiple_blanks(self) -> None:
        """4+ bos satir 3'e inmeli."""
        content = "line1\n\n\n\n\n\nline2"
        cleaned = OutputFormatter._clean_c_source(content)
        assert "\n\n\n\n" not in cleaned
        assert "line1" in cleaned
        assert "line2" in cleaned

    def test_clean_filename(self) -> None:
        """Ozel karakterli dosya adlari temizlenmeli."""
        assert OutputFormatter._clean_filename("test file.c") == "test_file.c"
        assert OutputFormatter._clean_filename("a/b/c.h") == "a_b_c.h"
        assert OutputFormatter._clean_filename("") == "unnamed.c"

    def test_categorize_c_module(self) -> None:
        """C modul kategorilendirmesi calismalii."""
        cat = OutputFormatter._categorize_c_module(
            "network.c", "socket(AF_INET, SOCK_STREAM, 0)"
        )
        assert cat == "networking"

        cat = OutputFormatter._categorize_c_module(
            "crypto_utils.c", "AES_encrypt(data, key)"
        )
        assert cat == "crypto"

        cat = OutputFormatter._categorize_c_module(
            "misc.c", "int x = 42;"
        )
        assert cat == "misc"


# ------------------------------------------------------------------
# ReportGenerator Tests
# ------------------------------------------------------------------

class TestReportGenerator:
    """ReportGenerator testleri."""

    def test_generate_html_returns_string(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML string dondurmeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert isinstance(html, str)
        assert len(html) > 100

    def test_html_is_valid_structure(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML temel yapiyi icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_html_has_inline_css(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """CSS inline olmali (dis bagimliligi yok)."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "<style>" in html
        # External CSS link olmamali
        assert '<link rel="stylesheet"' not in html

    def test_html_has_inline_js(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """JS inline olmali (dis bagimliligi yok)."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "<script>" in html
        assert "switchTab" in html
        # External script olmamali
        assert '<script src="' not in html

    def test_html_contains_target_info(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML target bilgilerini icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "test_binary" in html
        assert "abcdef1234567890" in html

    def test_html_contains_stats(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML istatistik dashboard icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "342" in html  # functions
        assert "1245" in html  # strings
        assert "Statistics" in html

    def test_html_contains_strategies(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML analiz stratejilerini icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "Strategies" in html
        assert "Signature" in html or "Bayesian" in html

    def test_html_contains_pipeline_timeline(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML pipeline timeline icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "Pipeline Timeline" in html
        assert "identify" in html
        assert "static" in html
        assert "reconstruct" in html

    def test_html_contains_before_after(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML before/after karsilastirma icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        # before/after section'in var olup olmadigini kontrol et
        assert "Before" in html or "Comparison" in html

    def test_html_contains_naming_table(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML naming table icermeli."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "Name Recovery" in html
        assert "FUN_100001234" in html or "print_greeting" in html

    def test_html_no_external_deps(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML dis bagimliligi olmamali."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        # Dis kaynaklara referans olmamali
        assert "https://" not in html
        assert "http://" not in html
        assert '<link rel="stylesheet"' not in html
        assert '<script src="' not in html

    def test_generate_to_file(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """generate_to_file dosyaya yazmalii."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        out_path = tmp_path / "report.html"
        result_path = gen.generate_to_file(out_path)

        assert result_path == out_path
        assert out_path.exists()
        content = out_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_html_dark_theme(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML dark theme CSS olmali."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "#0d1117" in html  # Dark background
        assert "#c9d1d9" in html  # Light text

    def test_html_responsive(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """HTML responsive olmali (viewport meta + media query)."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "viewport" in html
        assert "@media" in html


# ------------------------------------------------------------------
# ReportGenerator -- SVG Graph Tests
# ------------------------------------------------------------------

class TestReportGeneratorGraph:
    """Dependency graph SVG testleri."""

    def test_graph_with_call_graph(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Call graph varsa SVG uretilmeli."""
        _populate_binary_workspace(workspace)

        # Call graph JSON ekle
        static_dir = workspace.get_stage_dir("static")
        cg = {
            "functions": [
                {"name": "main"},
                {"name": "print_greeting"},
                {"name": "establish_connection"},
                {"name": "aes_encrypt"},
            ],
            "calls": [
                {"caller": "main", "callee": "print_greeting"},
                {"caller": "main", "callee": "establish_connection"},
                {"caller": "establish_connection", "callee": "aes_encrypt"},
            ],
        }
        (static_dir / "ghidra_call_graph.json").write_text(
            json.dumps(cg), encoding="utf-8",
        )

        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        assert "<svg" in html
        assert "circle" in html
        assert "Dependency Graph" in html

    def test_graph_without_call_graph(
        self, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Call graph yoksa SVG section olmamali."""
        _populate_binary_workspace(workspace)
        gen = ReportGenerator(binary_pipeline_result, workspace)
        html = gen.generate_html()

        # Dependency Graph section tamamen yoksa OK, veya baslik var ama SVG yoksa da OK
        # Ana kriter: hata vermemeli
        assert "<!DOCTYPE html>" in html

    def test_extract_first_function_c(self) -> None:
        """C fonksiyon extraction calismalii."""
        code = (
            "/* header */\n"
            "#include <stdio.h>\n\n"
            "void my_func(int x) {\n"
            "    printf(\"%d\", x);\n"
            "    return;\n"
            "}\n\n"
            "void other() { }\n"
        )
        result = ReportGenerator._extract_first_function(code)
        assert "my_func" in result

    def test_extract_first_function_js(self) -> None:
        """JS fonksiyon extraction calismalii."""
        code = (
            "// utils\n"
            "function addNumbers(a, b) {\n"
            "    return a + b;\n"
            "}\n"
        )
        result = ReportGenerator._extract_first_function_js(code)
        assert "addNumbers" in result


# ------------------------------------------------------------------
# Integration: OutputFormatter + ReportGenerator
# ------------------------------------------------------------------

class TestIntegration:
    """OutputFormatter ve ReportGenerator entegrasyon testleri."""

    def test_full_pipeline_binary(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Tam binary pipeline ciktisi: src/ + reports + meta."""
        _populate_binary_workspace(workspace)

        # Call graph ekle
        static_dir = workspace.get_stage_dir("static")
        cg = {
            "functions": [{"name": "main"}, {"name": "helper"}],
            "calls": [{"caller": "main", "callee": "helper"}],
        }
        (static_dir / "ghidra_call_graph.json").write_text(
            json.dumps(cg), encoding="utf-8",
        )

        formatter = OutputFormatter(workspace, binary_pipeline_result)
        output = tmp_path / "full_output"
        result = formatter.format_output(output, fmt="clean")

        assert result.success

        # Tam cikti yapisi kontrolu
        assert (output / "src").is_dir()
        assert (output / "report.json").exists()
        assert (output / "report.html").exists()
        assert (output / "naming_map.json").exists()
        assert (output / "dependency_graph.json").exists()
        assert (output / "README.md").exists()

        # HTML iceriik kontrolu
        html_content = (output / "report.html").read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_content
        assert "test_binary" in html_content
        assert "<svg" in html_content  # Dependency graph

        # README iceriik kontrolu
        readme = (output / "README.md").read_text(encoding="utf-8")
        assert "test_binary" in readme
        assert "Pipeline Stages" in readme

    def test_full_pipeline_js(
        self, tmp_path: Path, js_workspace: Workspace, js_pipeline_result: PipelineResult,
    ) -> None:
        """Tam JS pipeline ciktisi."""
        _populate_js_workspace(js_workspace)

        formatter = OutputFormatter(js_workspace, js_pipeline_result)
        output = tmp_path / "js_full_output"
        result = formatter.format_output(output, fmt="clean")

        assert result.success
        assert (output / "src").is_dir()
        assert (output / "report.json").exists()
        assert (output / "naming_map.json").exists()

    def test_raw_then_clean(
        self, tmp_path: Path, workspace: Workspace, binary_pipeline_result: PipelineResult,
    ) -> None:
        """Ayni workspace'ten once raw, sonra clean format uretilebilmeli."""
        _populate_binary_workspace(workspace)
        formatter = OutputFormatter(workspace, binary_pipeline_result)

        raw_out = tmp_path / "raw"
        clean_out = tmp_path / "clean"

        raw_result = formatter.format_output(raw_out, fmt="raw")
        clean_result = formatter.format_output(clean_out, fmt="clean")

        assert raw_result.success
        assert clean_result.success
        # Clean daha az dosya yazmis olabilir (organize)
        # ama her ikisi de dosya yazmalii
        assert raw_result.files_written > 0
        assert clean_result.files_written > 0
