"""v1.10.0 M1 T3.5 — FlowSimplifyStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.flow_simplify import FlowSimplifyStep


@pytest.fixture
def fake_pc():
    pc = MagicMock()
    pc.metadata = {}
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "semantic_naming_decompiled_dir": tmp_path / "decompiled",
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("flow_simplify")
        assert "semantic_naming_decompiled_dir" in spec.requires
        assert "flow_simplify_decompiled_dir" in spec.produces
        assert "timing_flow_simplify" in spec.produces


class TestHappyPath:
    def test_simplifier_stats_propagated(self, base_ctx, tmp_path: Path) -> None:
        fake_result = MagicMock(
            gotos_eliminated=5,
            labels_renamed=3,
            labels_inlined=2,
            early_returns=1,
            breaks_continues=4,
            ifelse_restructured=0,
            cascading_collapsed=6,
            multi_target_inlined=1,
        )
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.return_value = fake_result

        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            out = FlowSimplifyStep().run(base_ctx)

        assert out["flow_simplify_decompiled_dir"] == tmp_path / "decompiled"
        assert base_ctx.stats["flow_gotos_eliminated"] == 5
        assert base_ctx.stats["flow_cascading_collapsed"] == 6


class TestException:
    def test_simplifier_exception_swallowed(self, base_ctx) -> None:
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.side_effect = RuntimeError("boom")
        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            out = FlowSimplifyStep().run(base_ctx)
        # Hata sessizce yutuluyor, timing yine yazilmali
        assert "timing_flow_simplify" in out
