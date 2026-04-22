"""v1.10.0 M1 T3.5 — ProjectBuildStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.project_build import ProjectBuildStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=reconstructed)
    pc.metadata = {}
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "engineering_annotation_decompiled_dir": tmp_path / "annotated",
        "algo_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("project_build")
        assert "engineering_annotation_decompiled_dir" in spec.requires
        assert "project_dir" in spec.produces


class TestBuildSuccess:
    def test_success_publishes_artifact(self, base_ctx, fake_pc) -> None:
        fake_build = MagicMock(success=True, files_written=42)
        fake_cls = MagicMock()
        fake_cls.return_value.build.return_value = fake_build
        with patch(
            "karadul.reconstruction.c_project_builder.CProjectBuilder", fake_cls,
        ):
            out = ProjectBuildStep().run(base_ctx)
        assert out["project_dir"] is not None
        assert base_ctx.stats["project_files"] == 42
        assert "project_dir" in fake_pc.metadata["artifacts_pending"]


class TestBuildException:
    def test_exception_captured(self, base_ctx) -> None:
        fake_cls = MagicMock()
        fake_cls.return_value.build.side_effect = RuntimeError("disk full")
        with patch(
            "karadul.reconstruction.c_project_builder.CProjectBuilder", fake_cls,
        ):
            ProjectBuildStep().run(base_ctx)
        assert any("disk full" in e for e in base_ctx.errors)
