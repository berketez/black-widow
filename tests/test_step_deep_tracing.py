"""v1.10.0 M1 T3.5 — DeepTracingStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.deep_tracing import DeepTracingStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=reconstructed)
    pc.workspace.save_json = MagicMock()
    pc.metadata = {}
    # Engineering analysis kapali — step calismaz ama timing yazilir
    pc.config.binary_reconstruction.enable_engineering_analysis = False
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    xrefs = tmp_path / "xrefs.json"
    xrefs.write_text("{}", encoding="utf-8")
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "engineering_annotation_decompiled_dir": tmp_path / "annotated",
        "functions_json_path": tmp_path / "f.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "strings_json_path": tmp_path / "s.json",
        "xrefs_json_path": xrefs,
        "call_graph_data": {},
        "sig_matches": None,
        "eng_result": None,
        "algo_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("deep_tracing")
        assert "deep_tracing_result" in spec.produces
        assert "engineering_annotation_decompiled_dir" in spec.requires


class TestDisabledEngAnalysis:
    def test_config_disabled_empty_result(self, base_ctx) -> None:
        """enable_engineering_analysis=False ise alt-adimlar calismaz."""
        out = DeepTracingStep().run(base_ctx)
        r = out["deep_tracing_result"]
        assert r["dispatch_result"] is None
        assert r["data_flow_result"] is None
        assert r["augmented_cg_json"] is None


class TestCollectHelper:
    def test_collect_algorithms(self) -> None:
        a = MagicMock(success=True, algorithms=["x"])
        e = MagicMock(success=True, algorithms=["y", "z"])
        out = DeepTracingStep._collect_all_algorithms(a, e)
        assert out == ["x", "y", "z"]

    def test_collect_handles_none(self) -> None:
        assert DeepTracingStep._collect_all_algorithms(None, None) == []


class TestPublishArtifact:
    def test_publish_to_pending(self, fake_pc) -> None:
        """v1.11.0 Phase 1C: _make_publish_artifact(ctx) -> ctx.produce_artifact."""
        ctx = StepContext(pipeline_context=fake_pc)
        publisher = DeepTracingStep._make_publish_artifact(ctx)
        publisher("foo", "bar")
        # Yeni kanal: ctx.stage_artifacts
        assert ctx.stage_artifacts["foo"] == "bar"
        # Geriye uyumluluk mirror'i: pc.metadata
        assert fake_pc.metadata["artifacts_pending"]["foo"] == "bar"
