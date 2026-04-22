"""v1.10.0 M1 T3.5 — CommentGenerationStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.comment_generation import CommentGenerationStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=reconstructed)
    pc.metadata = {}
    pc.config.binary_reconstruction.enable_comment_generation = True
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "flow_simplify_decompiled_dir": tmp_path / "decompiled",
        "functions_json_path": tmp_path / "f.json",
        "strings_json_path": tmp_path / "s.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "algo_result": None,
        "computation_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("comment_generation")
        assert "flow_simplify_decompiled_dir" in spec.requires
        assert "comment_generation_decompiled_dir" in spec.produces


class TestDisabled:
    def test_config_disabled_passes_through(self, base_ctx, fake_pc, tmp_path) -> None:
        fake_pc.config.binary_reconstruction.enable_comment_generation = False
        out = CommentGenerationStep().run(base_ctx)
        assert out["comment_generation_decompiled_dir"] == tmp_path / "decompiled"


class TestHappyPath:
    def test_success_sets_commented_dir(self, base_ctx, fake_pc, tmp_path) -> None:
        fake_res = MagicMock(
            success=True,
            total_comments_added=10,
            vulnerability_warnings=1,
            logic_comments=2,
            computation_annotations=3,
            errors=[],
        )
        fake_cls = MagicMock()
        fake_cls.return_value.generate.return_value = fake_res
        with patch(
            "karadul.reconstruction.c_comment_generator.CCommentGenerator", fake_cls,
        ):
            out = CommentGenerationStep().run(base_ctx)
        expected_dir = fake_pc.workspace.get_stage_dir.return_value / "commented"
        assert out["comment_generation_decompiled_dir"] == expected_dir
        assert base_ctx.stats["comments_added"] == 10
        assert "commented_sources" in fake_pc.metadata["artifacts_pending"]


class TestFailurePath:
    def test_errors_propagated(self, base_ctx) -> None:
        fake_res = MagicMock(
            success=False,
            errors=["parse bozuk"],
        )
        fake_cls = MagicMock()
        fake_cls.return_value.generate.return_value = fake_res
        with patch(
            "karadul.reconstruction.c_comment_generator.CCommentGenerator", fake_cls,
        ):
            CommentGenerationStep().run(base_ctx)
        assert "parse bozuk" in base_ctx.errors
