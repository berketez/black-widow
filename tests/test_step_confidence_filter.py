"""v1.10.0 M1 T3.2 — ConfidenceFilterStep testleri.

stages.py L1723-1908'den tasindi. Tek step 5 alt adimi kapsar:
1. Calibration
2. Merge
3. Match budget
4. Byte pattern merge
5. CAPA merge
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import _confidence_helpers as _ch
from karadul.pipeline.steps.confidence_filter import ConfidenceFilterStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "cal.json")
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.max_algo_matches = 100
    pc.config.binary_reconstruction.enable_capa = False
    # load_json default: static/capa_capabilities yok
    pc.workspace.load_json = MagicMock(side_effect=FileNotFoundError)
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "eng_result": None,
        "algo_result": None,
        "binary_name_result": {},
        "byte_pattern_names": {},
        "c_files": [],
        "file_cache": {},
    })
    return ctx


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("confidence_filter")
        assert "eng_result" in spec.requires
        assert "byte_pattern_names" in spec.requires
        assert "extracted_names" in spec.produces
        assert "calibrated_matches" in spec.produces


# ---------------------------------------------------------------------------
# Byte pattern merge (helper)
# ---------------------------------------------------------------------------


class TestBytePatternMerge:
    def test_does_not_overwrite_existing(self) -> None:
        extracted = {"FUN_1": "manual_name"}
        bp = {"FUN_1": "bp_name", "FUN_2": "new_bp_name"}
        out = _ch.run_byte_pattern_merge(
            byte_pattern_names=bp, extracted_names=extracted,
        )
        # FUN_1'e dokunmamis olmali
        assert out["FUN_1"] == "manual_name"
        assert out["FUN_2"] == "new_bp_name"

    def test_empty_bp_returns_same(self) -> None:
        extracted = {"x": "y"}
        out = _ch.run_byte_pattern_merge(
            byte_pattern_names={}, extracted_names=extracted,
        )
        assert out is extracted


# ---------------------------------------------------------------------------
# Match budget
# ---------------------------------------------------------------------------


class TestMatchBudget:
    def test_under_budget_no_change(self) -> None:
        ctx = StepContext(pipeline_context=MagicMock())
        pc = MagicMock()
        pc.config.binary_reconstruction.max_algo_matches = 100

        algo = MagicMock()
        algo.success = True
        algo.algorithms = [MagicMock(confidence=0.5) for _ in range(10)]
        eng = MagicMock()
        eng.success = True
        eng.algorithms = [MagicMock(confidence=0.7) for _ in range(10)]
        orig_algo_ids = [id(a) for a in algo.algorithms]
        orig_eng_ids = [id(a) for a in eng.algorithms]

        _ch.run_match_budget(pc=pc, algo_result=algo, eng_result=eng, ctx=ctx)

        assert [id(a) for a in algo.algorithms] == orig_algo_ids
        assert [id(a) for a in eng.algorithms] == orig_eng_ids
        assert "match_budget_original" not in ctx.stats

    def test_over_budget_highest_conf_kept(self) -> None:
        ctx = StepContext(pipeline_context=MagicMock())
        pc = MagicMock()
        pc.config.binary_reconstruction.max_algo_matches = 3

        # 5 algo (conf 0.1..0.5), 5 eng (conf 0.6..1.0)
        algo = MagicMock()
        algo.success = True
        algo.algorithms = [MagicMock(confidence=0.1 * i) for i in range(1, 6)]
        eng = MagicMock()
        eng.success = True
        eng.algorithms = [MagicMock(confidence=0.5 + 0.1 * i) for i in range(1, 6)]

        _ch.run_match_budget(pc=pc, algo_result=algo, eng_result=eng, ctx=ctx)

        # En yuksek 3 confidence: 1.0, 0.9, 0.8 — hepsi eng'den
        assert len(algo.algorithms) == 0
        assert len(eng.algorithms) == 3
        assert ctx.stats["match_budget_original"] == 10
        assert ctx.stats["match_budget_kept"] == 3


# ---------------------------------------------------------------------------
# Step bas-uc (tam run)
# ---------------------------------------------------------------------------


class TestStepRun:
    def test_all_disabled_returns_empty(self, base_ctx, fake_pc) -> None:
        """eng/algo yoksa sadece byte-pattern merge (bos) ve capa (disabled)."""
        out = ConfidenceFilterStep().run(base_ctx)
        assert out["calibrated_matches"] is None
        assert out["algo_result_filtered"] is None
        assert out["eng_result_filtered"] is None
        assert out["extracted_names"] == {}
        assert out["capa_capabilities"] == {}

    def test_byte_pattern_merged_into_extracted_names(
        self, base_ctx, fake_pc,
    ) -> None:
        base_ctx._write_artifacts({
            "binary_name_result": {"FUN_A": "dbg_foo"},
            "byte_pattern_names": {"FUN_A": "bp_foo", "FUN_B": "bp_bar"},
        })
        out = ConfidenceFilterStep().run(base_ctx)
        # FUN_A degismedi (dbg onceligi), FUN_B eklendi
        assert out["extracted_names"] == {
            "FUN_A": "dbg_foo", "FUN_B": "bp_bar",
        }

    def test_binary_name_result_not_mutated(self, base_ctx) -> None:
        """Step orijinal binary_name_result'i mutate etmemeli (kopyalanmali)."""
        orig = {"FUN_A": "name"}
        base_ctx._write_artifacts({
            "binary_name_result": orig,
            "byte_pattern_names": {"FUN_B": "bp"},
        })
        out = ConfidenceFilterStep().run(base_ctx)
        # Orijinal dict dokunulmamis
        assert orig == {"FUN_A": "name"}
        # Sonucta her iki key var
        assert out["extracted_names"] == {"FUN_A": "name", "FUN_B": "bp"}


# ---------------------------------------------------------------------------
# CAPA merge
# ---------------------------------------------------------------------------


class TestCapaMerge:
    def test_disabled_returns_empty(self, base_ctx, fake_pc) -> None:
        fake_pc.config.binary_reconstruction.enable_capa = False
        ctx = StepContext(pipeline_context=fake_pc)
        out = _ch.run_capa_merge(pc=fake_pc, extracted_names={}, ctx=ctx)
        assert out == {}

    def test_adds_name_when_empty_slot(self, fake_pc) -> None:
        """CAPA capability'si olan ama isim almayan func'a isim verilir."""
        fake_pc.config.binary_reconstruction.enable_capa = True
        fake_pc.workspace.load_json = MagicMock(return_value={
            "success": True,
            "function_capabilities": {
                "0x1000": [{"name": "encrypt data", "namespace": "crypto"}],
            },
        })

        ctx = StepContext(pipeline_context=fake_pc)
        extracted: dict = {}

        cap_cls = MagicMock()
        cap_cls.side_effect = lambda name, namespace: MagicMock(
            name=name, namespace=namespace,
        )
        with patch(
            "karadul.analyzers.capa_scanner.CAPACapability",
            cap_cls,
        ), patch(
            "karadul.analyzers.capa_scanner.rank_capabilities",
            lambda caps: caps,
        ), patch(
            "karadul.analyzers.capa_scanner.capability_to_function_name",
            lambda _n: "encrypt_data",
        ):
            out = _ch.run_capa_merge(
                pc=fake_pc, extracted_names=extracted, ctx=ctx,
            )

        assert extracted["0x1000"] == "encrypt_data"
        assert ctx.stats["capa_names_added"] == 1
        # Ham veri capa_capabilities'de saklandi
        assert "0x1000" in out

    def test_skips_already_named(self, fake_pc) -> None:
        """Zaten isim verilmis func CAPA tarafindan ezilmez."""
        fake_pc.config.binary_reconstruction.enable_capa = True
        fake_pc.workspace.load_json = MagicMock(return_value={
            "success": True,
            "function_capabilities": {
                "0x1000": [{"name": "x", "namespace": "y"}],
            },
        })

        ctx = StepContext(pipeline_context=fake_pc)
        extracted = {"0x1000": "existing"}

        with patch(
            "karadul.analyzers.capa_scanner.CAPACapability", MagicMock(),
        ), patch(
            "karadul.analyzers.capa_scanner.rank_capabilities", lambda c: c,
        ), patch(
            "karadul.analyzers.capa_scanner.capability_to_function_name",
            lambda _n: "should_not_use",
        ):
            _ch.run_capa_merge(
                pc=fake_pc, extracted_names=extracted, ctx=ctx,
            )

        assert extracted["0x1000"] == "existing"
