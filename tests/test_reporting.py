"""Reporter testleri -- JSON, Markdown, HTML rapor uretim testleri."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.reporting.json_report import JSONReporter
from karadul.reporting.markdown_report import MarkdownReporter
from karadul.reporting.html_report import HTMLReporter


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Test workspace olustur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_target")
    ws.create()
    return ws


@pytest.fixture
def pipeline_result(workspace: Workspace) -> PipelineResult:
    """Ornek PipelineResult olustur."""
    result = PipelineResult(
        target_name="test_bundle.js",
        target_hash="abc123def456",
        workspace_path=workspace.path,
    )

    # Identify stage
    identify_result = StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.15,
        stats={
            "target_type": "js_bundle",
            "language": "javascript",
            "file_size": 9150000,
            "bundler": "webpack",
        },
    )
    result.add_stage_result(identify_result)

    # Static stage
    static_result = StageResult(
        stage_name="static",
        success=True,
        duration_seconds=12.4,
        artifacts={"analysis": workspace.path / "static" / "analysis.json"},
        stats={
            "functions_found": 847,
            "strings_found": 12340,
            "imports_found": 156,
            "webpack_modules": 42,
        },
    )
    result.add_stage_result(static_result)

    # Deobfuscate stage
    deob_result = StageResult(
        stage_name="deobfuscate",
        success=True,
        duration_seconds=45.2,
        stats={
            "steps_completed": 3,
            "chain": ["beautify", "synchrony", "babel_transforms"],
            "size_before": 9150000,
            "size_after": 11200000,
        },
    )
    result.add_stage_result(deob_result)

    result.total_duration = 57.75
    return result


class TestJSONReporter:
    """JSONReporter testleri."""

    def test_generates_valid_json(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor gecerli JSON olmali."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert path.exists()
        assert path.name == "report.json"

        content = path.read_text(encoding="utf-8")
        data = json.loads(content)  # JSON parse hatasi olmamalii
        assert isinstance(data, dict)

    def test_contains_karadul_version(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor karadul_version icermeli."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert "karadul_version" in data
        from karadul import __version__
        assert data["karadul_version"] == __version__

    def test_contains_target_info(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor target bilgilerini icermeli."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert "target" in data
        assert data["target"]["name"] == "test_bundle.js"
        assert data["target"]["hash"] == "abc123def456"

    def test_contains_pipeline_stages(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor pipeline stage'lerini icermeli."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert "pipeline" in data
        assert "stages" in data["pipeline"]
        assert "identify" in data["pipeline"]["stages"]
        assert "static" in data["pipeline"]["stages"]
        assert "deobfuscate" in data["pipeline"]["stages"]

    def test_contains_summary(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor summary icermeli."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert "summary" in data
        assert data["summary"]["total_functions"] == 847
        assert data["summary"]["total_strings"] == 12340

    def test_saved_to_reports_dir(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """JSON rapor workspace/reports/ altina kaydedilmeli."""
        reporter = JSONReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert "reports" in str(path)
        assert path.parent == workspace.get_stage_dir("reports")


class TestMarkdownReporter:
    """MarkdownReporter testleri."""

    def test_generates_markdown(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor dosya olusturmali."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert path.exists()
        assert path.name == "report.md"

    def test_contains_title(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor baslik icermeli."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "# Black Widow Analysis Report" in content
        assert "test_bundle.js" in content

    def test_contains_table_format(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor tablo formati icermeli."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "| Field | Value |" in content
        assert "|-------|-------|" in content

    def test_contains_pipeline_summary(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor pipeline summary icermeli."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "## Pipeline Summary" in content
        assert "identify" in content
        assert "static" in content

    def test_contains_footer(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor footer icermeli."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "Generated by Black Widow" in content

    def test_saved_to_reports_dir(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Markdown rapor workspace/reports/ altina kaydedilmeli."""
        reporter = MarkdownReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert path.parent == workspace.get_stage_dir("reports")


class TestHTMLReporter:
    """HTMLReporter testleri."""

    def test_generates_html(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor dosya olusturmali."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert path.exists()
        assert path.name == "report.html"

    def test_contains_html_tags(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor gecerli HTML tag'leri icermeli."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "<html" in content
        assert "</html>" in content
        assert "<head>" in content
        assert "</head>" in content
        assert "<body>" in content
        assert "</body>" in content

    def test_inline_css(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor inline CSS icermeli -- harici link olmamali."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "<style>" in content
        assert "background:" in content
        # Harici CSS link'i olmamali
        assert '<link rel="stylesheet"' not in content

    def test_contains_target_name(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor target adini icermeli."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "test_bundle.js" in content

    def test_contains_footer(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor footer icermeli."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "Generated by Black Widow" in content

    def test_dark_theme(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor dark theme kullanmali."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        content = path.read_text(encoding="utf-8")
        assert "#0d1117" in content  # dark background color

    def test_saved_to_reports_dir(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """HTML rapor workspace/reports/ altina kaydedilmeli."""
        reporter = HTMLReporter()
        path = reporter.generate(pipeline_result, workspace)

        assert path.parent == workspace.get_stage_dir("reports")


class TestAllReportersSameWorkspace:
    """Tum reporter'lar ayni workspace'e yaziyor mu?"""

    def test_all_reports_in_same_directory(self, pipeline_result: PipelineResult, workspace: Workspace) -> None:
        """Uc rapor da ayni reports/ dizininde olmali."""
        json_path = JSONReporter().generate(pipeline_result, workspace)
        md_path = MarkdownReporter().generate(pipeline_result, workspace)
        html_path = HTMLReporter().generate(pipeline_result, workspace)

        assert json_path.parent == md_path.parent == html_path.parent
        assert json_path.parent == workspace.get_stage_dir("reports")

        # Uc dosya da mevcut olmali
        assert json_path.exists()
        assert md_path.exists()
        assert html_path.exists()
