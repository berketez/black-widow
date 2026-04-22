"""v1.10.0 M1 T3.5 — InlineDetectionStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.inline_detection import InlineDetectionStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.metadata = {}
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    (decompiled / "a.c").write_text("int foo() { return abs(-1); }")
    (decompiled / "b.c").write_text("void bar(char *s) { strlen(s); }")
    file_cache = {
        "a.c": (decompiled / "a.c").read_text(),
        "b.c": (decompiled / "b.c").read_text(),
    }
    ctx = StepContext(pipeline_context=fake_pc)
    # v1.10.0 H5+H6: inline_detection feedback_loop ciktisini bekler.
    ctx._write_artifacts({
        "final_decompiled_dir": decompiled,
        "file_cache": file_cache,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("inline_detection")
        # v1.10.0 H5+H6: artik feedback_loop'un ciktisi uzerinde calisiyor
        assert "final_decompiled_dir" in spec.requires
        assert "file_cache" in spec.requires
        assert "inline_patterns_detected" in spec.produces


class TestImportError:
    def test_swallows_import_error(self, base_ctx) -> None:
        with patch(
            "karadul.analyzers.inline_detector.InlineDetector",
            side_effect=ImportError,
        ):
            out = InlineDetectionStep().run(base_ctx)
        assert out["inline_patterns_detected"] == 0


class TestBasicRun:
    def test_runs_and_counts(self, base_ctx) -> None:
        """Mock InlineDetector detect_in_code 2 match donerse toplam 4 olmali."""
        fake_det = MagicMock()
        fake_det.return_value.detect_in_code.return_value = ["m1", "m2"]
        fake_det.return_value.annotate_code.side_effect = lambda s: s

        with patch(
            "karadul.analyzers.inline_detector.InlineDetector", fake_det,
        ):
            out = InlineDetectionStep().run(base_ctx)

        # 2 dosya x 2 match = 4
        assert out["inline_patterns_detected"] == 4
        assert base_ctx.stats.get("inline_patterns_detected") == 4


class TestProducesContract:
    def test_produces_match(self, base_ctx) -> None:
        spec = get_step("inline_detection")
        with patch(
            "karadul.analyzers.inline_detector.InlineDetector",
            side_effect=ImportError,
        ):
            out = InlineDetectionStep().run(base_ctx)
        for k in out:
            assert k in spec.produces
