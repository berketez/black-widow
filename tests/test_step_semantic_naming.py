"""v1.10.0 M1 T3.5 — SemanticNamingStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.semantic_naming import SemanticNamingStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.get_stage_dir = MagicMock(return_value=tmp_path / "reconstructed")
    (tmp_path / "reconstructed").mkdir(exist_ok=True)
    pc.metadata = {}
    pc.config.binary_reconstruction.enable_semantic_naming = True
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "decompiled_dir": tmp_path / "decompiled",
        "functions_json_path": tmp_path / "f.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "sig_matches": None,
        "eng_result": None,
        "algo_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("semantic_naming")
        assert "functions_json_path" in spec.requires
        assert "semantic_naming_decompiled_dir" in spec.produces


class TestDisabled:
    def test_eng_result_none_passes_through(self, base_ctx, tmp_path: Path) -> None:
        """eng_result yoksa semantic naming calistirilmaz, decompiled_dir aynen."""
        decompiled = tmp_path / "decompiled"
        base_ctx._write_artifacts({"decompiled_dir": decompiled})
        out = SemanticNamingStep().run(base_ctx)
        assert out["semantic_naming_decompiled_dir"] == decompiled
        assert out["params_renamed"] == 0


class TestConfigDisabled:
    def test_config_false_no_rename(self, base_ctx, fake_pc, tmp_path: Path) -> None:
        fake_pc.config.binary_reconstruction.enable_semantic_naming = False
        base_ctx._write_artifacts({"eng_result": MagicMock()})
        out = SemanticNamingStep().run(base_ctx)
        assert out["params_renamed"] == 0


class TestCollectHelper:
    def test_collect_all_algorithms(self) -> None:
        algo = MagicMock(success=True, algorithms=["a1", "a2"])
        eng = MagicMock(success=True, algorithms=["e1"])
        out = SemanticNamingStep._collect_all_algorithms(algo, eng)
        assert out == ["a1", "a2", "e1"]

    def test_collect_none_safe(self) -> None:
        assert SemanticNamingStep._collect_all_algorithms(None, None) == []
