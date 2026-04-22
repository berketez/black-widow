"""v1.10.0 M1 T3.5 — CapaAnnotationStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.capa_annotation import CapaAnnotationStep


@pytest.fixture
def fake_pc():
    pc = MagicMock()
    pc.metadata = {}
    pc.config.binary_reconstruction.enable_capa = True
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "comment_generation_decompiled_dir": tmp_path / "decompiled",
        "capa_capabilities": {"addr1": [{"name": "cap1"}]},
        "functions_data": {"main": {}},
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("capa_annotation")
        assert "capa_capabilities" in spec.requires
        assert "capa_annotation_decompiled_dir" in spec.produces


class TestDisabled:
    def test_empty_capa_skips(self, base_ctx, tmp_path) -> None:
        base_ctx._write_artifacts({"capa_capabilities": {}})
        out = CapaAnnotationStep().run(base_ctx)
        assert out["capa_annotation_decompiled_dir"] == tmp_path / "decompiled"
        assert "capa_comments_added" not in base_ctx.stats


class TestConfigDisabled:
    def test_config_disabled(self, base_ctx, fake_pc, tmp_path) -> None:
        fake_pc.config.binary_reconstruction.enable_capa = False
        out = CapaAnnotationStep().run(base_ctx)
        assert out["capa_annotation_decompiled_dir"] == tmp_path / "decompiled"


class TestInjectCalled:
    def test_inject_helper_called(self, base_ctx) -> None:
        with patch(
            "karadul.stages._inject_capa_comments", return_value=5,
        ):
            out = CapaAnnotationStep().run(base_ctx)
        assert base_ctx.stats["capa_comments_added"] == 5
