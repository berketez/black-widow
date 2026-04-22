"""v1.10.0 M1 T3.4 — StructRecoveryStep testleri."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.struct_recovery import StructRecoveryStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    br = SimpleNamespace(enable_struct_recovery=True)
    pc.config = SimpleNamespace(binary_reconstruction=br)
    pc.workspace.get_stage_dir = MagicMock(
        return_value=tmp_path / "reconstructed",
    )
    (tmp_path / "reconstructed").mkdir(exist_ok=True)
    pc.metadata = {}
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    dec = tmp_path / "dec"
    dec.mkdir()
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "final_decompiled_dir": dec,
        "functions_json_path": tmp_path / "f.json",
        "ghidra_types_json_path": tmp_path / "gt.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "updated_algo_result": None,
        "updated_eng_result": None,
        "computation_result": None,
    })
    return ctx


class TestRegistry:
    def test_struct_recovery_registered(self) -> None:
        spec = get_step("struct_recovery")
        assert "final_decompiled_dir" in spec.requires
        assert "updated_eng_result" in spec.requires
        assert "struct_recovery_decompiled_dir" in spec.produces
        assert "struct_recovery_result" in spec.produces
        assert "timing_struct_recovery" in spec.produces


class TestBasicRun:
    def test_eng_result_none_passes_through(self, base_ctx, tmp_path: Path) -> None:
        """eng_result yoksa struct recovery calistirilmaz; input=output."""
        out = StructRecoveryStep().run(base_ctx)
        assert out["struct_recovery_decompiled_dir"] == tmp_path / "dec"
        assert out["struct_recovery_result"] is None

    def test_config_disabled(self, base_ctx, fake_pc, tmp_path: Path) -> None:
        fake_pc.config.binary_reconstruction.enable_struct_recovery = False
        # eng_result verilse de calisir mi diye kontrol
        base_ctx._write_artifacts({"updated_eng_result": MagicMock()})
        out = StructRecoveryStep().run(base_ctx)
        assert out["struct_recovery_result"] is None


class TestProducesContract:
    def test_produces_match(self, base_ctx) -> None:
        spec = get_step("struct_recovery")
        out = StructRecoveryStep().run(base_ctx)
        for k in out:
            assert k in spec.produces


class TestCollectHelper:
    def test_collect_all_algorithms(self) -> None:
        algo = MagicMock(success=True, algorithms=["a1"])
        eng = MagicMock(success=True, algorithms=["e1", "e2"])
        out = StructRecoveryStep._collect_all_algorithms(algo, eng)
        assert out == ["a1", "e1", "e2"]

    def test_collect_none_safe(self) -> None:
        assert StructRecoveryStep._collect_all_algorithms(None, None) == []
