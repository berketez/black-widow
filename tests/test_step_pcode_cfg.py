"""v1.10.0 M1 T3.2 — PcodeCfgAnalysisStep testleri.

stages.py L1453-1557'den tasindi. Test kapsamlari:
- P-Code JSON yoksa None donus, timing stats yazilir
- stats_only mode header sadece stats cikarir
- CFGAnalyzer ImportError yakalanir
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.pcode_cfg_analysis import PcodeCfgAnalysisStep


@pytest.fixture
def base_ctx(tmp_path: Path):
    pc = MagicMock()
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        "pcode_json_path": tmp_path / "pcode.json",
        "cfg_json_path": tmp_path / "cfg.json",
    })
    return ctx


class TestPcodeRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("pcode_cfg_analysis")
        assert "pcode_json_path" in spec.requires
        assert "cfg_json_path" in spec.requires
        assert "pcode_result" in spec.produces
        assert "cfg_result" in spec.produces


class TestMissingFiles:
    def test_both_missing_returns_none(self, base_ctx) -> None:
        out = PcodeCfgAnalysisStep().run(base_ctx)
        assert out["pcode_result"] is None
        assert out["cfg_result"] is None
        assert out["pcode_naming_candidates"] == []
        assert "timing_pcode" in base_ctx.stats
        assert "timing_cfg" in base_ctx.stats


class TestPcodeModes:
    def test_stats_only_header(self, base_ctx, tmp_path) -> None:
        """stats_only header icin analyzer yuklenmemeli, dogrudan stats alinmali."""
        pcode_json = tmp_path / "pcode.json"
        pcode_json.write_text(json.dumps({
            "mode": "stats_only",
            "total_functions": 42,
            "total_pcode_ops": 12345,
        }))
        out = PcodeCfgAnalysisStep().run(base_ctx)
        assert out["pcode_result"] is None
        assert base_ctx.stats["pcode_functions_analyzed"] == 42
        assert base_ctx.stats["pcode_total_ops"] == 12345

    def test_jsonl_missing_jsonl_file(self, base_ctx, tmp_path) -> None:
        """JSONL mode ama jsonl dosyasi yoksa — stats'a duser, crash etmez."""
        pcode_json = tmp_path / "pcode.json"
        pcode_json.write_text(json.dumps({
            "mode": "jsonl",
            "total_functions": 7,
            "total_pcode_ops": 99,
        }))
        with patch(
            "karadul.analyzers.pcode_analyzer.PcodeAnalyzer",
            MagicMock(),
        ):
            out = PcodeCfgAnalysisStep().run(base_ctx)
        assert out["pcode_result"] is None
        assert base_ctx.stats["pcode_functions_analyzed"] == 7
        assert base_ctx.stats["pcode_total_ops"] == 99


class TestCfgAnalyzer:
    def test_cfg_import_error_swallowed(self, base_ctx, tmp_path) -> None:
        """CFGAnalyzer import edilemezse None doner, crash etmez."""
        (tmp_path / "cfg.json").write_text("{}")
        with patch(
            "karadul.analyzers.cfg_analyzer.CFGAnalyzer",
            side_effect=ImportError,
        ):
            out = PcodeCfgAnalysisStep().run(base_ctx)
        assert out["cfg_result"] is None

    def test_cfg_happy_path(self, base_ctx, tmp_path) -> None:
        (tmp_path / "cfg.json").write_text("{}")
        fake_cfg_result = MagicMock()
        fake_cfg_result.total_functions = 10
        fake_cfg_result.total_blocks = 100
        fake_cfg_result.total_edges = 200

        fake_cfg = MagicMock()
        fake_cfg.return_value.analyze.return_value = fake_cfg_result
        fake_cfg.return_value.get_summary.return_value = {
            "classification_distribution": {"loop": 5},
        }
        with patch(
            "karadul.analyzers.cfg_analyzer.CFGAnalyzer", fake_cfg,
        ):
            out = PcodeCfgAnalysisStep().run(base_ctx)
        assert out["cfg_result"] is fake_cfg_result
        assert base_ctx.stats["cfg_functions_analyzed"] == 10
        assert base_ctx.stats["cfg_total_blocks"] == 100
        assert base_ctx.stats["cfg_classification"] == {"loop": 5}
