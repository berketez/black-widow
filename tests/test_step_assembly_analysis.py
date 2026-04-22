"""v1.10.0 M1 T3.5 — AssemblyAnalysisStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.assembly_analysis import AssemblyAnalysisStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "asm.json")
    pc.metadata = {}
    pc.target = MagicMock()
    pc.target.target_type = "mock_type"  # MACHO_BINARY olmayan
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    fjson = tmp_path / "functions.json"
    fjson.write_text("{}", encoding="utf-8")
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "functions_json_path": fjson,
        "functions_data": {"main": {}},
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("assembly_analysis")
        assert "functions_json_path" in spec.requires
        assert "asm_results" in spec.produces
        assert "timing_assembly_analysis" in spec.produces


class TestNoAnalyzer:
    def test_import_error_swallowed(self, base_ctx) -> None:
        """AssemblyAnalyzer yoksa sessizce geçer ve bos dict doner."""
        with patch(
            "karadul.analyzers.assembly_analyzer.AssemblyAnalyzer",
            side_effect=ImportError,
        ):
            out = AssemblyAnalysisStep().run(base_ctx)
        assert out["asm_results"] == {}
        assert "timing_assembly_analysis" in out
        assert "timing_assembly_analysis" in base_ctx.stats


class TestProducesContract:
    def test_produces_subset_of_declared(self, base_ctx) -> None:
        """Run'in dondurdugu key'ler produces icinde olmali."""
        spec = get_step("assembly_analysis")
        with patch(
            "karadul.analyzers.assembly_analyzer.AssemblyAnalyzer",
            side_effect=ImportError,
        ):
            out = AssemblyAnalysisStep().run(base_ctx)
        for k in out:
            assert k in spec.produces, f"{k} not in produces"


class TestArchDetection:
    def test_detect_arch_default_x86_64(self, base_ctx) -> None:
        from karadul.pipeline.steps.assembly_analysis import AssemblyAnalysisStep as S
        target = MagicMock()
        target.target_type = "x86_64"  # MACHO_BINARY degil
        arch = S._detect_arch(target, {"metadata": {}}, base_ctx.artifacts["functions_json_path"])
        assert arch == "x86_64"

    def test_detect_arch_macho_arm(self, base_ctx, tmp_path: Path) -> None:
        from karadul.pipeline.steps.assembly_analysis import AssemblyAnalysisStep as S
        from karadul.core.target import TargetType
        target = MagicMock()
        target.target_type = TargetType.MACHO_BINARY
        arch = S._detect_arch(
            target,
            {"metadata": {"processor": "AArch64"}},
            base_ctx.artifacts["functions_json_path"],
        )
        assert arch == "aarch64"
