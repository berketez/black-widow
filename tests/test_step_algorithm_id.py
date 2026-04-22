"""v1.10.0 M1 T3.2 — AlgorithmIdStep testleri.

stages.py L1568-1601'den tasindi (crypto CAlgorithmIdentifier).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.algorithm_id import AlgorithmIdStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "algos.json")
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_algorithm_id = True
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "decompiled_dir": tmp_path / "dec",
        "functions_json_path": tmp_path / "functions.json",
        "strings_json_path": tmp_path / "strings.json",
    })
    return ctx


class TestAlgoRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("algorithm_id")
        assert "decompiled_dir" in spec.requires
        assert "algo_result" in spec.produces
        assert "parallel_algo_eng" in spec.parallelizable_with


class TestDisabled:
    def test_disabled_returns_none(self, base_ctx, fake_pc) -> None:
        fake_pc.config.binary_reconstruction.enable_algorithm_id = False
        out = AlgorithmIdStep().run(base_ctx)
        assert out["algo_result"] is None
        assert "timing_algorithm_id" in base_ctx.stats


class TestHappyPath:
    def test_identify_success(self, base_ctx, fake_pc) -> None:
        fake_algo = MagicMock()
        fake_algo.name = "AES"
        fake_algo.category = "crypto"
        fake_algo.confidence = 0.9
        fake_algo.function_name = "aes_encrypt"
        fake_algo.evidence = []

        fake_res = MagicMock()
        fake_res.success = True
        fake_res.total_detected = 1
        fake_res.by_category = {"crypto": 1}
        fake_res.algorithms = [fake_algo]

        fake_ident = MagicMock()
        fake_ident.return_value.identify.return_value = fake_res

        with patch(
            "karadul.reconstruction.c_algorithm_id.CAlgorithmIdentifier",
            fake_ident,
        ):
            out = AlgorithmIdStep().run(base_ctx)

        assert out["algo_result"] is fake_res
        assert base_ctx.stats["algorithms_detected"] == 1
        assert "algorithms" in fake_pc.metadata["artifacts_pending"]

    def test_unsuccessful_result_not_saved(self, base_ctx, fake_pc) -> None:
        """success=False ise artifact yazilmaz."""
        fake_res = MagicMock()
        fake_res.success = False

        fake_ident = MagicMock()
        fake_ident.return_value.identify.return_value = fake_res

        with patch(
            "karadul.reconstruction.c_algorithm_id.CAlgorithmIdentifier",
            fake_ident,
        ):
            out = AlgorithmIdStep().run(base_ctx)

        assert out["algo_result"] is fake_res
        assert "artifacts_pending" not in fake_pc.metadata or \
            "algorithms" not in fake_pc.metadata.get("artifacts_pending", {})


class TestErrors:
    def test_exception_recorded(self, base_ctx, fake_pc) -> None:
        fake_ident = MagicMock()
        fake_ident.return_value.identify.side_effect = RuntimeError("kapu")

        with patch(
            "karadul.reconstruction.c_algorithm_id.CAlgorithmIdentifier",
            fake_ident,
        ):
            out = AlgorithmIdStep().run(base_ctx)

        assert out["algo_result"] is None
        assert any("Algorithm ID hatasi" in e for e in base_ctx.errors)
