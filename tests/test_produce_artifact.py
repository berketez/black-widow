"""v1.11.0 Phase 1C — StepContext.produce_artifact() testleri.

artifacts_pending shim'inden produce_artifact API'sine gecis.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import StepSpec
from karadul.pipeline.steps.finalize import FinalizeStep


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_pc():
    pc = MagicMock()
    pc.metadata = {}
    return pc


@pytest.fixture
def ctx(fake_pc):
    return StepContext(pipeline_context=fake_pc)


# ---------------------------------------------------------------------------
# 1. Temel davranis
# ---------------------------------------------------------------------------


class TestBasicProduce:
    def test_writes_to_stage_artifacts(self, ctx) -> None:
        ctx.produce_artifact("foo", "value_foo")
        assert ctx.stage_artifacts["foo"] == "value_foo"

    def test_mirrors_to_metadata(self, ctx, fake_pc) -> None:
        """Geriye uyumluluk: pc.metadata['artifacts_pending']'e de yazar."""
        ctx.produce_artifact("bar", Path("/tmp/bar.json"))
        assert "artifacts_pending" in fake_pc.metadata
        assert fake_pc.metadata["artifacts_pending"]["bar"] == Path("/tmp/bar.json")

    def test_none_metadata_initialized(self) -> None:
        pc = MagicMock()
        pc.metadata = None
        ctx = StepContext(pipeline_context=pc)
        ctx.produce_artifact("x", 42)
        assert pc.metadata["artifacts_pending"]["x"] == 42

    def test_multiple_artifacts(self, ctx) -> None:
        ctx.produce_artifact("a", 1)
        ctx.produce_artifact("b", 2)
        ctx.produce_artifact("c", 3)
        assert dict(ctx.stage_artifacts) == {"a": 1, "b": 2, "c": 3}


# ---------------------------------------------------------------------------
# 2. Overwrite davranisi
# ---------------------------------------------------------------------------


class TestOverwrite:
    def test_overwrite_logs_warning(self, ctx, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="karadul.pipeline.context"):
            ctx.produce_artifact("k", "v1")
            ctx.produce_artifact("k", "v2")
        assert any(
            "uzerine yaziliyor" in r.message or "zaten" in r.message
            for r in caplog.records
        )
        # Overwrite gerceklesmis olmali
        assert ctx.stage_artifacts["k"] == "v2"


# ---------------------------------------------------------------------------
# 3. Registry validation (soft)
# ---------------------------------------------------------------------------


class TestRegistryValidation:
    def test_no_step_meta_passes(self, ctx) -> None:
        """_current_step_meta None ise produce_artifact sorunsuz calisir."""
        ctx.produce_artifact("freely_named_artifact", 123)
        assert ctx.stage_artifacts["freely_named_artifact"] == 123

    def test_key_not_in_produces_debug_only(self, ctx, caplog) -> None:
        """produces listesinde olmayan key icin sadece debug log, hata YOK."""
        fake_meta = MagicMock(spec=StepSpec)
        fake_meta.name = "test_step"
        fake_meta.produces = ("expected_key",)
        ctx._current_step_meta = fake_meta

        # Hata atmamali
        ctx.produce_artifact("unexpected_key", "value")
        assert ctx.stage_artifacts["unexpected_key"] == "value"


# ---------------------------------------------------------------------------
# 4. Read-only view kurallari
# ---------------------------------------------------------------------------


class TestReadOnly:
    def test_stage_artifacts_is_immutable_view(self, ctx) -> None:
        ctx.produce_artifact("readonly_test", "v")
        view = ctx.stage_artifacts
        with pytest.raises(TypeError):
            view["readonly_test"] = "mutated"  # type: ignore[index]


# ---------------------------------------------------------------------------
# 5. Finalize step'inin yeni kanali okuyabilmesi
# ---------------------------------------------------------------------------


class TestFinalizeReadsStageArtifacts:
    def test_finalize_reads_from_stage_artifacts(self, fake_pc) -> None:
        """produce_artifact ile yazilan artifact'lar finalize'da StageResult'a."""
        ctx = StepContext(pipeline_context=fake_pc)
        ctx.produce_artifact("my_output", Path("/tmp/output.json"))
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": Path("/tmp/proj"),
            "__stage_name": "binary_reconstruction",
            "__pipeline_start": time.monotonic() - 1.0,
        })

        out = FinalizeStep().run(ctx)
        sr = out["stage_result"]
        assert sr.success is True
        assert sr.artifacts["my_output"] == Path("/tmp/output.json")

    def test_finalize_legacy_fallback_still_works(self, fake_pc) -> None:
        """Eski shim: sadece pc.metadata'dan gelse bile finalize okur."""
        fake_pc.metadata = {"artifacts_pending": {"legacy_key": "legacy_val"}}
        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": None,
            "__stage_name": "binary_reconstruction",
            "__pipeline_start": time.monotonic() - 0.5,
        })

        out = FinalizeStep().run(ctx)
        assert out["stage_result"].artifacts["legacy_key"] == "legacy_val"

    def test_finalize_new_channel_wins_on_conflict(self, fake_pc) -> None:
        """Ayni key hem stage_artifacts hem legacy'de varsa yeni kanal kazanir."""
        fake_pc.metadata = {"artifacts_pending": {"k": "old_value"}}
        ctx = StepContext(pipeline_context=fake_pc)
        # produce_artifact mirror yazdigi icin "old_value" uzerine "new_value" yazar
        ctx.produce_artifact("k", "new_value")
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": Path("/tmp/proj"),
            "__stage_name": "binary_reconstruction",
            "__pipeline_start": time.monotonic() - 0.5,
        })

        out = FinalizeStep().run(ctx)
        assert out["stage_result"].artifacts["k"] == "new_value"


# ---------------------------------------------------------------------------
# 6. Runner enjeksiyonu (integration smoke)
# ---------------------------------------------------------------------------


class TestRunnerInjection:
    """Runner calisirken _current_step_meta'yi spec ile set eder, sonra temizler."""

    def test_step_meta_cleared_after_run(self) -> None:
        from karadul.core.pipeline import PipelineContext
        from karadul.pipeline.registry import (
            Step, _clear_registry_for_tests, register_step,
        )
        from karadul.pipeline.runner import PipelineRunner

        _clear_registry_for_tests()

        captured: dict = {}

        @register_step(
            name="test_injection_step",
            requires=[],
            produces=["result_key"],
        )
        class TestStep(Step):
            def run(self, ctx: StepContext) -> dict:
                captured["meta_during_run"] = ctx._current_step_meta
                return {"result_key": "ok"}

        try:
            pc = MagicMock(spec=PipelineContext)
            pc.metadata = {}
            runner = PipelineRunner(steps=["test_injection_step"])
            out_ctx = runner.run(pc)
            # Calisirken spec set edilmisti
            assert captured["meta_during_run"] is not None
            assert captured["meta_during_run"].name == "test_injection_step"
            # Step bitince geri temizlenmis olmali
            assert out_ctx._current_step_meta is None
        finally:
            _clear_registry_for_tests()
