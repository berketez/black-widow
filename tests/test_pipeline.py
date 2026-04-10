"""End-to-end pipeline testleri.

Pipeline'in stage kaydini, calistirmayi, sonuc uretimini ve
rapor olusturmayi test eder. sample_minified.js uzerinde
gercek stage'lerle calisir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import Pipeline
from karadul.core.result import PipelineResult, StageResult
from karadul.stages import (
    IdentifyStage,
    StaticAnalysisStage,
    DeobfuscationStage,
    ReportStage,
)


@pytest.fixture
def sample_js_path() -> Path:
    """Test fixture JS dosyasinin yolu."""
    path = Path(__file__).parent / "fixtures" / "sample_minified.js"
    assert path.exists(), f"Test fixture bulunamadi: {path}"
    return path


@pytest.fixture
def pipeline_config(tmp_path: Path) -> Config:
    """Gecici workspace ile Config olustur."""
    cfg = Config()
    cfg.project_root = tmp_path
    # Retry'lari devre disi birak (testlerde hiz icin)
    cfg.retry.max_retries = 0
    cfg.retry.base_delay = 0.0
    return cfg


class TestPipelineRegistration:
    """Pipeline stage kayit testleri."""

    def test_register_stages(self, pipeline_config: Config) -> None:
        """Stage'ler pipeline'a kaydedilebilmeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())

        assert "identify" in pipeline.registered_stages
        assert "static" in pipeline.registered_stages

    def test_register_all_stages(self, pipeline_config: Config) -> None:
        """Tum mevcut stage'ler kaydedilebilmeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage())
        pipeline.register_stage(ReportStage())

        assert len(pipeline.registered_stages) == 4
        assert "report" in pipeline.registered_stages

    def test_duplicate_stage_raises(self, pipeline_config: Config) -> None:
        """Ayni isimde iki stage kaydetmek hata vermeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())

        with pytest.raises(ValueError, match="zaten kayitli"):
            pipeline.register_stage(IdentifyStage())

    def test_report_stage_exists(self) -> None:
        """ReportStage import edilebilmeli ve dogru ayarlara sahip olmali."""
        stage = ReportStage()
        assert stage.name == "report"
        assert "identify" in stage.requires


class TestPipelineExecution:
    """Pipeline calistirma testleri (sample_minified.js uzerinde)."""

    def test_identify_only(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Sadece identify stage'i calistirilabilmeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())

        result = pipeline.run(sample_js_path)

        assert isinstance(result, PipelineResult)
        assert "identify" in result.stages
        assert result.stages["identify"].success

    def test_identify_and_static(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Identify + Static stage'leri birlikte calisabilmeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())

        result = pipeline.run(sample_js_path)

        assert "identify" in result.stages
        assert "static" in result.stages
        assert result.stages["identify"].success
        assert result.stages["static"].success

    def test_full_pipeline_with_report(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Identify + Static + Deobfuscate + Report calisabilmeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)

        assert "identify" in result.stages
        assert "static" in result.stages
        assert result.stages["identify"].success

        # Report stage her zaman calismali (identify basarili oldugu surece)
        assert "report" in result.stages
        report_sr = result.stages["report"]
        assert report_sr.success

    def test_pipeline_result_has_target_name(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """PipelineResult hedef adini icermeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())

        result = pipeline.run(sample_js_path)
        assert result.target_name == "sample_minified"

    def test_pipeline_result_has_duration(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """PipelineResult toplam sureyi icermeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())

        result = pipeline.run(sample_js_path)
        assert result.total_duration > 0

    def test_stage_results_have_correct_names(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Her StageResult dogru stage adini tasimaali."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())

        result = pipeline.run(sample_js_path)

        for name, sr in result.stages.items():
            assert sr.stage_name == name


class TestReportGeneration:
    """Rapor uretim testleri (end-to-end)."""

    def test_json_report_valid(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Pipeline sonunda uretilen JSON rapor gecerli JSON olmali."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)
        report_sr = result.stages["report"]

        assert report_sr.success
        assert "report_json" in report_sr.artifacts

        json_path = report_sr.artifacts["report_json"]
        assert json_path.exists()

        data = json.loads(json_path.read_text(encoding="utf-8"))
        from karadul import __version__
        assert data["karadul_version"] == __version__
        assert "pipeline" in data
        assert "summary" in data

    def test_html_report_valid(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Pipeline sonunda uretilen HTML rapor gecerli olmali."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)
        report_sr = result.stages["report"]

        assert "report_html" in report_sr.artifacts
        html_path = report_sr.artifacts["report_html"]
        assert html_path.exists()

        content = html_path.read_text(encoding="utf-8")
        assert "<html" in content
        assert "</html>" in content

    def test_markdown_report_has_title(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Pipeline sonunda uretilen Markdown rapor baslik icermeli."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)
        report_sr = result.stages["report"]

        assert "report_md" in report_sr.artifacts
        md_path = report_sr.artifacts["report_md"]
        assert md_path.exists()

        content = md_path.read_text(encoding="utf-8")
        assert "# Black Widow Analysis Report" in content

    def test_workspace_directories_created(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """Pipeline calistiktan sonra workspace dizinleri olusmus olmali."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)

        ws_path = result.workspace_path
        assert ws_path.exists()

        # reports/ dizini olmali
        reports_dir = ws_path / "reports"
        assert reports_dir.exists()

        # reports/ icinde rapor dosyalari olmali
        report_files = list(reports_dir.iterdir())
        assert len(report_files) >= 3  # report.json, report.md, report.html

    def test_report_formats(self, pipeline_config: Config, sample_js_path: Path) -> None:
        """ReportStage rapor formatlari uretmeli (JSON, MD, HTML, SARIF)."""
        pipeline = Pipeline(pipeline_config)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(ReportStage())

        result = pipeline.run(sample_js_path)
        report_sr = result.stages["report"]

        assert report_sr.stats["reports_generated"] >= 3
        assert "report_json" in report_sr.stats["formats"]
        assert "report_md" in report_sr.stats["formats"]
        assert "report_html" in report_sr.stats["formats"]
