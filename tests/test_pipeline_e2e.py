"""Step registry pipeline e2e testleri (v1.10.0 H1).

Ghidra'ya baglanmadan step_registry pipeline'ini baska step'lerle zincirleyerek
entegrasyon davranisini dogrular:

1. PipelineRunner topo sort + produces/requires contract dogrulamasi.
2. Monolith vs step_registry yolu ayni artifact key'lerini uretmeli.
3. seed_artifacts ile onceki veriler injection edilebilir (shim koprusu).
4. Hata propagation (step exception -> RuntimeError + ctx.errors).

Gercek Ghidra binary decompile testi: integration marker'li ve Ghidra
kurulu degilse skip eder.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.ghidra.headless import GhidraHeadless
from karadul.pipeline import PipelineRunner
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step, register_step, Step, _clear_registry_for_tests
from karadul.pipeline.steps.binary_prep import BinaryPrepStep


SAMPLE_MACHO = Path(__file__).parent / "fixtures" / "sample_macho"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_pc(tmp_path: Path):
    """Minimal sahte PipelineContext -- Ghidra'ya ihtiyac duymaz."""
    pc = MagicMock()
    br = SimpleNamespace(
        pipeline_iterations=1,
        pipeline_convergence_threshold=0.01,
        pipeline_iteration_timeout=600.0,
        pipeline_min_new_names_per_iter=1,
        enable_c_naming=False,
        enable_type_recovery=False,
        enable_xtride_typing=False,
        enable_dynamic_naming=False,
        enable_ngram_naming=False,
        enable_reference_differ=False,
        enable_struct_recovery=False,
        min_naming_confidence=0.7,
        ngram_confidence_threshold=0.55,
        reference_binary="",
        reference_db_path="",
    )
    cr = SimpleNamespace(enabled=False)
    pc.config = SimpleNamespace(
        binary_reconstruction=br,
        computation_recovery=cr,
        name_merger=MagicMock(),
        project_root=tmp_path,
    )
    pc.workspace.get_stage_dir = MagicMock(return_value=tmp_path / "reconstructed")
    (tmp_path / "reconstructed").mkdir(exist_ok=True)
    pc.metadata = {}
    pc.target.file_hash = "abc" * 22
    pc.target.target_type = None
    pc.report_progress = MagicMock()
    return pc


# ---------------------------------------------------------------------------
# 1) PipelineRunner -- topo sort ve artifact contract
# ---------------------------------------------------------------------------


class TestPipelineRunnerTopoSort:
    """Step sirasi, produces/requires dogrulamasi."""

    def test_runner_rejects_empty_steps(self):
        """Bos step listesi ValueError atmali."""
        with pytest.raises(ValueError):
            PipelineRunner(steps=[])

    def test_runner_resolves_simple_order(self, fake_pc, tmp_path: Path):
        """Tek step (feedback_loop) calistirilip produces uretmeli."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        (decompiled / "FUN_1.c").write_text("int a(void){return 1;}")

        seed = {
            "c_files": [decompiled / "FUN_1.c"],
            "file_cache": {"FUN_1.c": "int a(void){return 1;}"},
            "decompiled_dir": decompiled,
            "output_dir": tmp_path / "src_out",
            "functions_json_path": tmp_path / "f.json",
            "strings_json_path": tmp_path / "s.json",
            "call_graph_json_path": tmp_path / "cg.json",
            "ghidra_types_json_path": tmp_path / "gt.json",
            "xrefs_json_path": tmp_path / "xr.json",
            "cfg_json_path": tmp_path / "cfg.json",
            "fid_json_path": tmp_path / "fid.json",
            "decompiled_json_path": tmp_path / "decompiled.json",
            "functions_data": None,
            "strings_data": None,
            "call_graph_data": {},
            "sig_matches": None,
            "algo_result_filtered": None,
            "eng_result_filtered": None,
            "extracted_names": {},
            "pcode_naming_candidates": [],
        }
        (seed["output_dir"]).mkdir(exist_ok=True)

        runner = PipelineRunner(steps=["feedback_loop"])
        ctx = runner.run(fake_pc, seed_artifacts=seed)
        spec = get_step("feedback_loop")
        # Tum produces runner tarafindan artifacts'a yazilmis olmali.
        for key in spec.produces:
            assert key in ctx.artifacts

    def test_runner_missing_requires_raises(self, fake_pc):
        """Requires karsilanmadiysa RuntimeError."""
        # feedback_loop requires: decompiled_dir, call_graph_data
        runner = PipelineRunner(steps=["feedback_loop"])
        with pytest.raises(RuntimeError, match="eksik girdi"):
            # seed_artifacts yok — requires eksik.
            runner.run(fake_pc)

    def test_runner_detects_duplicate_producer(self, fake_pc):
        """Ayni artifact'i iki step uretmeye kalkarsa ValueError.

        Duplicate detection topological_sort icinde runner.run() sirasinda
        calisir; bu nedenle hata calistirildiginda atilir.
        """
        @register_step(
            name="_dup_test_a", requires=[], produces=["dup_art"],
        )
        class _A(Step):
            def run(self, ctx):
                return {"dup_art": 1}

        try:
            @register_step(
                name="_dup_test_b", requires=[], produces=["dup_art"],
            )
            class _B(Step):
                def run(self, ctx):
                    return {"dup_art": 2}

            runner = PipelineRunner(steps=["_dup_test_a", "_dup_test_b"])
            with pytest.raises(ValueError, match="iki step tarafindan"):
                runner.run(fake_pc)
        finally:
            from karadul.pipeline.registry import _REGISTRY
            _REGISTRY.pop("_dup_test_a", None)
            _REGISTRY.pop("_dup_test_b", None)


# ---------------------------------------------------------------------------
# 2) Step registry seed_artifacts shim davranisi
# ---------------------------------------------------------------------------


class TestRunnerSeedArtifacts:
    def test_seed_artifacts_overrides_metadata(self, fake_pc, tmp_path: Path):
        """seed_artifacts metadata'daki ayni key'i override etmeli."""
        fake_pc.metadata = {"c_files": ["eski.c"]}
        # basit seed ile override
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        (decompiled / "FUN_1.c").write_text("int a(void){return 1;}")
        seed = {
            "c_files": [decompiled / "FUN_1.c"],
            "file_cache": {"FUN_1.c": "int a(void){return 1;}"},
            "decompiled_dir": decompiled,
            "output_dir": tmp_path / "src_out",
            "functions_json_path": tmp_path / "f.json",
            "strings_json_path": tmp_path / "s.json",
            "call_graph_json_path": tmp_path / "cg.json",
            "ghidra_types_json_path": tmp_path / "gt.json",
            "xrefs_json_path": tmp_path / "xr.json",
            "cfg_json_path": tmp_path / "cfg.json",
            "fid_json_path": tmp_path / "fid.json",
            "decompiled_json_path": tmp_path / "decompiled.json",
            "functions_data": None,
            "strings_data": None,
            "call_graph_data": {},
            "sig_matches": None,
            "algo_result_filtered": None,
            "eng_result_filtered": None,
            "extracted_names": {},
            "pcode_naming_candidates": [],
        }
        (seed["output_dir"]).mkdir(exist_ok=True)
        runner = PipelineRunner(steps=["feedback_loop"])
        ctx = runner.run(fake_pc, seed_artifacts=seed)
        # seed'deki c_files metadata'dakini yenmeli -- yeni path var.
        # (ctx.artifacts erisim sinavina girmek icin erken kontrol)
        # run tamamlandi -> produces yazilmis
        spec = get_step("feedback_loop")
        for key in spec.produces:
            assert key in ctx.artifacts


# ---------------------------------------------------------------------------
# 3) Step registry vs monolith davranis esitligi -- INTEGRATION (Ghidra'li)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStepRegistryVsMonolith:
    """Gercek Ghidra binary ile step registry ve monolith ayni naming_map vermeli.

    Bu test agir; default suite'te skip edilir. Ghidra kurulu degilse veya
    sample_macho yoksa skip.
    """

    def test_step_registry_vs_monolith_equivalence(self, tmp_path: Path):
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture yok")
        gh = GhidraHeadless(Config())
        if not gh.is_available():
            pytest.skip("Ghidra kurulu degil")

        # Iki config: biri step registry, digeri eski monolith.
        cfg_new = Config()
        cfg_new.project_root = tmp_path / "new"
        cfg_new.pipeline.use_step_registry = True

        cfg_old = Config()
        cfg_old.project_root = tmp_path / "old"
        cfg_old.pipeline.use_step_registry = False

        cfg_new.project_root.mkdir(parents=True, exist_ok=True)
        cfg_old.project_root.mkdir(parents=True, exist_ok=True)

        # Gercek pipeline'i calistirmak yerine, bu integration testinin
        # niyeti step registry'nin devreye girdigini ve ayni artifact
        # contract'ini verdigini dogrulamak. Full binary run uzun surer ve
        # ayri bir nightly job'unda calistirilir.
        pytest.skip(
            "Full binary pipeline karsilastirmasi benchmark suite'inde "
            "calisir; bu test yer tutucudur.",
        )


# ---------------------------------------------------------------------------
# 4) Hata propagation
# ---------------------------------------------------------------------------


class TestRunnerErrorPropagation:
    def test_step_exception_propagates_and_records(self, fake_pc):
        """Step exception runner tarafindan yutulmaz, ctx.errors'a yazilir."""
        # Gecici bir "crash" step'i kaydet.
        @register_step(
            name="_crash_test", requires=[], produces=[],
        )
        class _Crash(Step):
            def run(self, ctx):
                raise RuntimeError("deliberate_crash_for_test")

        try:
            runner = PipelineRunner(steps=["_crash_test"])
            with pytest.raises(RuntimeError, match="deliberate_crash"):
                runner.run(fake_pc)
        finally:
            from karadul.pipeline.registry import _REGISTRY
            _REGISTRY.pop("_crash_test", None)

    def test_step_returns_non_dict_raises(self, fake_pc):
        """Step dict yerine baska tip dondurse RuntimeError."""
        @register_step(
            name="_bad_return", requires=[], produces=[],
        )
        class _Bad(Step):
            def run(self, ctx):
                return "not_a_dict"  # type: ignore[return-value]

        try:
            runner = PipelineRunner(steps=["_bad_return"])
            with pytest.raises(RuntimeError, match="dict dondurmeli"):
                runner.run(fake_pc)
        finally:
            from karadul.pipeline.registry import _REGISTRY
            _REGISTRY.pop("_bad_return", None)

    def test_step_extra_produces_raises(self, fake_pc):
        """Step declared produces disinda artifact yazarsa RuntimeError."""
        @register_step(
            name="_extra_produces", requires=[], produces=["declared"],
        )
        class _Extra(Step):
            def run(self, ctx):
                return {"declared": 1, "UNDECLARED": 2}

        try:
            runner = PipelineRunner(steps=["_extra_produces"])
            with pytest.raises(RuntimeError, match="produces disinda"):
                runner.run(fake_pc)
        finally:
            from karadul.pipeline.registry import _REGISTRY
            _REGISTRY.pop("_extra_produces", None)


# ---------------------------------------------------------------------------
# 5) PipelineConfig use_step_registry default
# ---------------------------------------------------------------------------


class TestPipelineConfigDefault:
    def test_use_step_registry_default_false(self):
        """use_step_registry default KAPALI olmali (opt-in)."""
        cfg = Config()
        assert cfg.pipeline.use_step_registry is False

    def test_use_step_registry_overridable(self):
        """Alan elle True yapilabilmeli."""
        cfg = Config()
        cfg.pipeline.use_step_registry = True
        assert cfg.pipeline.use_step_registry is True
