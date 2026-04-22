"""v1.10.0 M1 T3.5 — EngineeringAnalysisStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.engineering_analysis import EngineeringAnalysisStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    static = tmp_path / "static"
    static.mkdir()
    pc.workspace.get_stage_dir = lambda name: {
        "reconstructed": reconstructed,
        "static": static,
    }[name]
    pc.workspace.save_json = MagicMock(return_value=reconstructed / "ea.json")
    pc.metadata = {}
    pc.config.binary_reconstruction.enable_engineering_analysis = True
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "project_dir": tmp_path / "project",
        "functions_data": ["main", "foo"],
        "eng_result": None,
        "algo_result": None,
        "computation_result": None,
        "strings_data": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("engineering_analysis")
        assert "project_dir" in spec.requires
        assert "engineering_analysis_result" in spec.produces


class TestDisabled:
    def test_config_disabled_skips(self, base_ctx, fake_pc) -> None:
        fake_pc.config.binary_reconstruction.enable_engineering_analysis = False
        out = EngineeringAnalysisStep().run(base_ctx)
        assert out["engineering_analysis_result"] is None


class TestNoAlgorithms:
    def test_no_algo_or_eng_skips(self, base_ctx) -> None:
        """algo_result ve eng_result yoksa analiz calistirilmaz."""
        out = EngineeringAnalysisStep().run(base_ctx)
        assert out["engineering_analysis_result"] is None


class TestHappyPath:
    def test_with_algorithms_produces_payload(self, base_ctx, tmp_path) -> None:
        algo = MagicMock(success=True, algorithms=[MagicMock()])
        base_ctx._write_artifacts({"algo_result": algo})

        domain_rep = MagicMock()
        domain_rep.to_dict.return_value = {"x": 1}
        domain_rep.domain_summary = {"ml": 5}

        fake_domain_cls = MagicMock()
        fake_domain_cls.return_value.classify.return_value = domain_rep
        fake_formula_cls = MagicMock()
        fake_formula_cls.return_value.reconstruct.return_value = []
        fake_formula_cls.return_value.generate_report.return_value = "## md"

        with patch(
            "karadul.reconstruction.engineering.DomainClassifier", fake_domain_cls,
        ), patch(
            "karadul.reconstruction.engineering.FormulaReconstructor", fake_formula_cls,
        ):
            out = EngineeringAnalysisStep().run(base_ctx)

        assert out["engineering_analysis_result"] is not None
        assert base_ctx.stats["engineering_domains"] == 1
        assert base_ctx.stats["engineering_formulas"] == 0
