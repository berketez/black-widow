"""v1.10.0 M1 T3.5 — FinalizeStep testleri."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.finalize import FinalizeStep


@pytest.fixture
def fake_pc():
    pc = MagicMock()
    pc.metadata = {}
    return pc


@pytest.fixture
def base_ctx(fake_pc):
    ctx = StepContext(pipeline_context=fake_pc)
    # v1.14.0 Dalga 0: artifact'lar produce_artifact ile yeni kanala yazilir
    ctx.produce_artifact("x", "path_x")
    # P-S1 / BORU-05: basari = proje kuruldu (project_dir yapiti) VE C adlandirma hatasiz
    ctx.produce_artifact("project_dir", Path("/tmp/project"))
    ctx._write_artifacts({
        "deep_tracing_result": {},
        "engineering_analysis_result": None,
        "project_dir": Path("/tmp/project"),
        "naming_result": MagicMock(success=True, errors=[]),
        "__stage_name": "binary_reconstruction",
        "__pipeline_start": time.monotonic() - 2.0,
    })
    ctx.stats["timing_foo"] = 1.5
    ctx.errors.append("onceki hata")
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("finalize")
        assert "stage_result" in spec.produces
        assert "deep_tracing_result" in spec.requires


class TestBasicRun:
    def test_build_stage_result(self, base_ctx) -> None:
        out = FinalizeStep().run(base_ctx)
        sr = out["stage_result"]
        assert sr.stage_name == "binary_reconstruction"
        assert "x" in sr.artifacts
        assert sr.success is True
        assert "onceki hata" in sr.errors
        # Basarili ama bir adim hata bildirdi -> kismi (P-S1 / BORU-05)
        assert sr.stats["partial"] is True
        assert sr.stats["partial_reasons"] == ["onceki hata"]
        assert sr.stats["reconstruct_status"] == "kismi"


class TestEmptyArtifacts:
    def test_no_artifacts_success_false(self, fake_pc) -> None:
        # v1.14.0 Dalga 0: stage_artifacts bos olmali; legacy mirror yok
        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": None,
        })
        out = FinalizeStep().run(ctx)
        assert out["stage_result"].success is False


class TestDurationMeasurement:
    def test_duration_positive(self, base_ctx) -> None:
        out = FinalizeStep().run(base_ctx)
        assert out["stage_result"].duration_seconds > 0
