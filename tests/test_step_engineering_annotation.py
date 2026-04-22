"""v1.10.0 M1 T3.5 — EngineeringAnnotationStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.engineering_annotation import EngineeringAnnotationStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=reconstructed)
    pc.metadata = {}
    pc.config.binary_reconstruction.enable_block_annotation = True
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "capa_annotation_decompiled_dir": tmp_path / "decompiled",
        "functions_json_path": tmp_path / "f.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "eng_result": MagicMock(success=True, algorithms=[]),
        "algo_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("engineering_annotation")
        assert "capa_annotation_decompiled_dir" in spec.requires
        assert "engineering_annotation_decompiled_dir" in spec.produces


class TestDisabledBlockAnnotation:
    def test_config_disabled(self, base_ctx, fake_pc, tmp_path) -> None:
        fake_pc.config.binary_reconstruction.enable_block_annotation = False
        out = EngineeringAnnotationStep().run(base_ctx)
        assert out["engineering_annotation_decompiled_dir"] == tmp_path / "decompiled"


class TestNoEngResult:
    def test_eng_result_none(self, base_ctx, tmp_path) -> None:
        base_ctx._write_artifacts({"eng_result": None})
        out = EngineeringAnnotationStep().run(base_ctx)
        assert out["engineering_annotation_decompiled_dir"] == tmp_path / "decompiled"


class TestAnnotatorSuccess:
    def test_annotator_success_updates_dir(self, base_ctx, fake_pc) -> None:
        annot_result = MagicMock(
            success=True,
            total_annotations=5,
            annotated_files=[Path("x.c")],
        )
        fake_cls = MagicMock()
        fake_cls.return_value.annotate.return_value = annot_result
        with patch(
            "karadul.reconstruction.engineering.CodeBlockAnnotator", fake_cls,
        ):
            out = EngineeringAnnotationStep().run(base_ctx)
        expected = fake_pc.workspace.get_stage_dir.return_value / "annotated"
        assert out["engineering_annotation_decompiled_dir"] == expected
        assert base_ctx.stats["block_annotations"] == 5
        assert "annotated_sources" in fake_pc.metadata["artifacts_pending"]
