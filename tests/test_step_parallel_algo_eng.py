"""v1.10.0 M1 T3.2 — ParallelAlgoEngStep testleri.

stages.py L1603-1721'den tasindi. Test kapsamlari:
- BinaryNameExtractor + EngineeringAnalyzer paralel calistirilir (2 future)
- Per-future dict pattern: worker'lar shared state'e yazmaz, main merge eder
- ImportError yakalanir, error dict'e kaydedilir
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.parallel_algo_eng import (
    ParallelAlgoEngStep,
    _run_binary_name_extraction,
    _run_engineering_analysis,
)


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "x.json")
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_binary_name_extraction = True
    pc.config.binary_reconstruction.enable_engineering_analysis = True
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "decompiled_dir": tmp_path / "dec",
        "functions_json_path": tmp_path / "functions.json",
        "strings_json_path": tmp_path / "strings.json",
        "call_graph_json_path": tmp_path / "cg.json",
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("parallel_algo_eng")
        assert "binary_name_result" in spec.produces
        assert "eng_result" in spec.produces
        assert "algorithm_id" in spec.parallelizable_with


# ---------------------------------------------------------------------------
# Worker dogrudan — state leak olmadigini dogrula
# ---------------------------------------------------------------------------


class TestWorkerIsolation:
    def test_binary_name_worker_returns_dict(self, fake_pc, tmp_path) -> None:
        """Worker tek bir dict doner — shared state'e yazmaz."""
        fake_name = MagicMock()
        fake_name.original_name = "FUN_1000"
        fake_name.recovered_name = "validate_input"
        fake_name.source = "dbg"
        fake_name.confidence = 0.9
        fake_name.class_name = None

        fake_res = MagicMock()
        fake_res.success = True
        fake_res.names = [fake_name]
        fake_res.class_methods = {}

        fake_ext = MagicMock()
        fake_ext.return_value.extract.return_value = fake_res

        with patch(
            "karadul.reconstruction.binary_name_extractor.BinaryNameExtractor",
            fake_ext,
        ):
            out = _run_binary_name_extraction(
                pc=fake_pc,
                strings_json=tmp_path / "s.json",
                functions_json=tmp_path / "f.json",
                call_graph_json=tmp_path / "cg.json",
            )

        assert out["success"] is True
        assert out["result"] == {"FUN_1000": "validate_input"}
        assert out["stats"]["binary_names_extracted"] == 1

    def test_engineering_worker_skipped(self, fake_pc, tmp_path) -> None:
        fake_pc.config.binary_reconstruction.enable_engineering_analysis = False
        out = _run_engineering_analysis(
            pc=fake_pc,
            decompiled_dir=tmp_path / "dec",
            functions_json=tmp_path / "f.json",
        )
        assert out == {"success": False, "skipped": True}

    def test_engineering_worker_exception(self, fake_pc, tmp_path) -> None:
        fake_ana = MagicMock()
        fake_ana.return_value.identify.side_effect = RuntimeError("kabu")
        with patch(
            "karadul.reconstruction.engineering.EngineeringAlgorithmAnalyzer",
            fake_ana,
        ):
            out = _run_engineering_analysis(
                pc=fake_pc,
                decompiled_dir=tmp_path / "dec",
                functions_json=tmp_path / "f.json",
            )
        assert out["success"] is False
        assert "Engineering algorithm analysis hatasi" in out["error"]


# ---------------------------------------------------------------------------
# Step orchestration — iki future baglar, merge eder
# ---------------------------------------------------------------------------


class TestStepOrchestration:
    def test_both_succeed_merged(self, base_ctx, fake_pc, tmp_path) -> None:
        """Her iki worker basarili — sonuclar ve stats ayri ayri merge edilir."""
        # Binary name
        fake_name = MagicMock()
        fake_name.original_name = "FUN_1"
        fake_name.recovered_name = "foo"
        fake_name.source = "dbg"
        fake_name.confidence = 1.0
        fake_name.class_name = None
        fake_name_res = MagicMock()
        fake_name_res.success = True
        fake_name_res.names = [fake_name]
        fake_name_res.class_methods = {}

        fake_ext = MagicMock()
        fake_ext.return_value.extract.return_value = fake_name_res

        # Engineering
        fake_eng_res = MagicMock()
        fake_eng_res.success = True
        fake_eng_res.total_detected = 5
        fake_eng_res.by_category = {"dsp": 5}
        fake_eng_res.algorithms = []
        fake_eng_res.to_dict.return_value = {}

        fake_ana = MagicMock()
        fake_ana.return_value.identify.return_value = fake_eng_res

        with patch(
            "karadul.reconstruction.binary_name_extractor.BinaryNameExtractor",
            fake_ext,
        ), patch(
            "karadul.reconstruction.engineering.EngineeringAlgorithmAnalyzer",
            fake_ana,
        ):
            out = ParallelAlgoEngStep().run(base_ctx)

        assert out["binary_name_result"] == {"FUN_1": "foo"}
        assert out["eng_result"] is fake_eng_res
        assert base_ctx.stats["binary_names_extracted"] == 1
        assert base_ctx.stats["engineering_algorithms_detected"] == 5
        assert "timing_name_eng_parallel" in base_ctx.stats
        assert "binary_names" in fake_pc.metadata["artifacts_pending"]
        assert "engineering_algorithms" in fake_pc.metadata["artifacts_pending"]

    def test_one_error_other_succeeds(self, base_ctx, fake_pc, tmp_path) -> None:
        """Biri hata verir, digeri basarili — error kaydedilir, digeri calisir."""
        fake_ext = MagicMock()
        fake_ext.return_value.extract.side_effect = RuntimeError("bombom")

        fake_eng_res = MagicMock()
        fake_eng_res.success = True
        fake_eng_res.total_detected = 2
        fake_eng_res.by_category = {}
        fake_eng_res.algorithms = []
        fake_eng_res.to_dict.return_value = {}

        fake_ana = MagicMock()
        fake_ana.return_value.identify.return_value = fake_eng_res

        with patch(
            "karadul.reconstruction.binary_name_extractor.BinaryNameExtractor",
            fake_ext,
        ), patch(
            "karadul.reconstruction.engineering.EngineeringAlgorithmAnalyzer",
            fake_ana,
        ):
            out = ParallelAlgoEngStep().run(base_ctx)

        assert out["binary_name_result"] == {}
        assert out["eng_result"] is fake_eng_res
        assert any(
            "Binary name extraction hatasi" in e for e in base_ctx.errors
        )
