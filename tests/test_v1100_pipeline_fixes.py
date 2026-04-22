"""KARADUL v1.10.0 Pipeline Fix Sprint — regresyon testleri.

Bu dosya pipeline seviyesindeki fix'lerin dogrulamasini icerir.
Kapsam:

- C1: feedback_loop pc.metadata None defansif baslangic.
- C4: resolve_call_graph augmented JSON yuklemesi (onceki kod oksule duser,
  dosyayi hic okumazdi).
- H2: ParallelNamingRunner serial cagri kaldirildi; runner sentezlenmis
  CNamingResult dondurur ve `_run_c_namer` decompiled_dir'i bu bos ciktiya
  yonlendirmez.
- H3: confidence_filter `extracted_names_final` da yayinliyor (Phase 3
  step'leri feedback_loop'tan etkilenmeyen kopyayi kullanabilir).
- H5+H6: inline_detection art.ik `final_decompiled_dir`'i tuketiyor ve
  feedback_loop post-loop file_cache refresh uyguluyor.
- H10: Aho-Corasick merger subdirectory yapisini koruyor (ayni ada sahip
  farkli `.c` dosyalari artik birbirini ezmiyor).
- M14: registry ayni artifact'i iki step production ederse `ValueError`.
- M15: iter>0 naming cikis dizini cleanup (stale rmtree).
- M19: `pipeline_iterations < 1` -> ValueError (silent `max(1, ...)` yerine).
- convergence_reason: `finalize` step'i stats'e yaziyor.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import (
    Step,
    _REGISTRY,
    _clear_registry_for_tests,
    get_step,
    register_step,
)
from karadul.pipeline.runner import PipelineRunner


# ---------------------------------------------------------------------------
# Ortak fixture: feedback_loop'a bos pipeline verisi verilmis ctx
# ---------------------------------------------------------------------------


def _mk_fake_pc(tmp_path: Path, max_iter: int = 1, metadata=None):
    pc = MagicMock()
    br = SimpleNamespace(
        pipeline_iterations=max_iter,
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
    pc.workspace.get_stage_dir = MagicMock(
        return_value=tmp_path / "reconstructed",
    )
    (tmp_path / "reconstructed").mkdir(exist_ok=True)
    pc.metadata = metadata  # <-- kasten None verilebilir (C1)
    pc.target.file_hash = "abc" * 22
    pc.target.target_type = None
    pc.report_progress = MagicMock()
    return pc


def _mk_artifacts(tmp_path: Path):
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir(exist_ok=True)
    a = decompiled / "FUN_1.c"
    a.write_text("int a(void){return 1;}")
    return {
        "c_files": [a],
        "file_cache": {"FUN_1.c": a.read_text()},
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


# ---------------------------------------------------------------------------
# C1 — pc.metadata None ise feedback_loop baslamadan inisiyatif alir
# ---------------------------------------------------------------------------


class TestC1FeedbackLoopMetadataNone:
    """pc.metadata None verildiginde feedback_loop crash ETMEMELI."""

    def test_metadata_none_does_not_crash(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep

        pc = _mk_fake_pc(tmp_path, max_iter=1, metadata=None)
        (tmp_path / "src_out").mkdir(exist_ok=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts(_mk_artifacts(tmp_path))

        # Eski kodda `pc.metadata["file_cache"] = ...` veya
        # `pc.metadata.setdefault(...)` AttributeError firlatir.
        out = FeedbackLoopStep().run(ctx)
        assert "naming_result" in out
        # metadata da dolduruldu mu?
        assert isinstance(pc.metadata, dict)


# ---------------------------------------------------------------------------
# C4 — resolve_call_graph augmented JSON'u yukler ve merge eder
# ---------------------------------------------------------------------------


class TestC4ResolveCallGraph:
    def test_no_augmented_returns_cache(self) -> None:
        from karadul.pipeline.steps._deep_tracing_helpers import (
            resolve_call_graph,
        )

        out = resolve_call_graph(
            augmented_cg_json=None, call_graph_data={"edges": [{"a": 1}]},
        )
        assert out == {"edges": [{"a": 1}]}

    def test_augmented_missing_file_returns_cache(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._deep_tracing_helpers import (
            resolve_call_graph,
        )

        out = resolve_call_graph(
            augmented_cg_json=tmp_path / "does_not_exist.json",
            call_graph_data={"edges": []},
        )
        assert out == {"edges": []}

    def test_augmented_present_merges_edges(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._deep_tracing_helpers import (
            resolve_call_graph,
        )
        aug = tmp_path / "aug.json"
        aug.write_text(json.dumps({
            "edges": [{"src": "a", "dst": "b"}, {"src": "a", "dst": "c"}],
            "metadata": {"version": "aug-v1"},
        }))
        out = resolve_call_graph(
            augmented_cg_json=aug,
            call_graph_data={"edges": [{"src": "x", "dst": "y"}]},
        )
        # Cache edge korunmali + yeni edge'ler eklenmis
        srcs = {(e["src"], e["dst"]) for e in out["edges"]}
        assert ("x", "y") in srcs
        assert ("a", "b") in srcs
        assert ("a", "c") in srcs
        # metadata augmented'tan eklenmis
        assert out["metadata"]["version"] == "aug-v1"

    def test_augmented_malformed_json_falls_back(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._deep_tracing_helpers import (
            resolve_call_graph,
        )
        aug = tmp_path / "bad.json"
        aug.write_text("{bozuk json")
        out = resolve_call_graph(
            augmented_cg_json=aug,
            call_graph_data={"edges": [{"k": 1}]},
        )
        assert out == {"edges": [{"k": 1}]}

    def test_augmented_deduplicates_identical_edges(self, tmp_path: Path) -> None:
        """Cache ve augmented ayni edge'i iceriyorsa tek sefer yazilmali."""
        from karadul.pipeline.steps._deep_tracing_helpers import (
            resolve_call_graph,
        )
        aug = tmp_path / "aug.json"
        aug.write_text(json.dumps({
            "edges": [{"src": "a", "dst": "b"}],
        }))
        out = resolve_call_graph(
            augmented_cg_json=aug,
            call_graph_data={"edges": [{"src": "a", "dst": "b"}]},
        )
        assert len(out["edges"]) == 1


# ---------------------------------------------------------------------------
# H2 — ParallelNamingRunner serial call kaldirildi
# ---------------------------------------------------------------------------


class TestH2ParallelNamingNoSerialCall:
    """parallel_naming feature flag'i ile koşulan naming, analyze_and_rename
    cagirmamali ve output_files bos bir CNamingResult dondurmeli."""

    def test_no_serial_analyze_and_rename(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._feedback_naming_parallel import (
            _run_with_parallel_runner,
        )

        # Namer: per-file yontemi var, analyze_and_rename cagrilirsa exception
        namer = MagicMock()
        namer.rename_c_file = MagicMock(return_value={})
        namer.analyze_and_rename = MagicMock(
            side_effect=AssertionError(
                "H2: analyze_and_rename artik cagirilmamali",
            ),
        )

        # Runner'in orkestrasyon zincirini gercekle calistirmak yerine
        # basitçe bos c_files gonderip CNamingResult yapisini dogrula.
        config = MagicMock()
        config.perf = SimpleNamespace(
            parallel_naming=True,
            naming_max_workers=1,
            naming_chunk_size=64,
            naming_chunk_timeout=10.0,
        )
        namer_dir = tmp_path / "src"
        namer_dir.mkdir()
        (namer_dir / "a.c").write_text("int a(void){return 0;}")

        stats: dict = {}
        errors: list = []
        result = _run_with_parallel_runner(
            c_namer=namer,
            namer_dir=namer_dir,
            namer_output=tmp_path / "out",
            functions_json=tmp_path / "f.json",
            strings_json=tmp_path / "s.json",
            call_graph_json=tmp_path / "cg.json",
            xrefs_json=tmp_path / "xr.json",
            extracted_names={},
            config=config,
            stats=stats,
            errors=errors,
        )

        # Serial cagri yapilmamis olmali
        namer.analyze_and_rename.assert_not_called()
        # CNamingResult geldi — output_files BOS (runner diske yazmiyor)
        from karadul.reconstruction.c_namer import CNamingResult
        assert isinstance(result, CNamingResult)
        assert result.output_files == []

    def test_synthesized_result_has_naming_map(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._feedback_naming_parallel import (
            _run_with_parallel_runner,
        )
        # Namer per-file: "old_sym" -> aday donduruyor
        cand = SimpleNamespace(
            new_name="clean_name", confidence=0.9, strategy="unit_test",
        )

        def fake_rename(_path, _content):
            return {"old_sym": [cand]}

        namer = MagicMock()
        namer.rename_c_file = fake_rename

        config = MagicMock()
        config.perf = SimpleNamespace(
            parallel_naming=True,
            naming_max_workers=1, naming_chunk_size=64, naming_chunk_timeout=10.0,
        )
        namer_dir = tmp_path / "src2"
        namer_dir.mkdir()
        (namer_dir / "a.c").write_text("int a(void){return 0;}")

        result = _run_with_parallel_runner(
            c_namer=namer, namer_dir=namer_dir,
            namer_output=tmp_path / "out",
            functions_json=tmp_path / "f.json",
            strings_json=tmp_path / "s.json",
            call_graph_json=tmp_path / "cg.json",
            xrefs_json=tmp_path / "xr.json",
            extracted_names={}, config=config,
            stats={}, errors=[],
        )
        assert result.success is True
        assert result.naming_map == {"old_sym": "clean_name"}
        assert result.high_confidence == 1  # 0.9 >= 0.7


# ---------------------------------------------------------------------------
# H3 — confidence_filter extracted_names_final yayinliyor
# ---------------------------------------------------------------------------


class TestH3ExtractedNamesFinalProduced:
    def test_confidence_filter_produces_final(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("confidence_filter")
        assert "extracted_names_final" in spec.produces
        assert "extracted_names" in spec.produces

    def test_final_is_shallow_copy(self, tmp_path: Path) -> None:
        """extracted_names_final downstream mutate edilse bile
        extracted_names (feedback_loop'a gider) etkilenmemeli."""
        from karadul.pipeline.steps.confidence_filter import (
            ConfidenceFilterStep,
        )
        pc = MagicMock()
        pc.workspace.save_json = MagicMock(return_value=tmp_path / "x.json")
        pc.workspace.load_json = MagicMock(side_effect=FileNotFoundError)
        pc.metadata = {}
        pc.config = MagicMock()
        pc.config.binary_reconstruction.max_algo_matches = 100
        pc.config.binary_reconstruction.enable_capa = False

        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "eng_result": None,
            "algo_result": None,
            "binary_name_result": {"FUN_A": "foo"},
            "byte_pattern_names": {"FUN_B": "bar"},
            "c_files": [],
            "file_cache": {},
        })

        out = ConfidenceFilterStep().run(ctx)
        # Iki dict de FUN_A ve FUN_B iceriyor
        assert out["extracted_names"] == {"FUN_A": "foo", "FUN_B": "bar"}
        assert out["extracted_names_final"] == {"FUN_A": "foo", "FUN_B": "bar"}
        # Farkli objeler (shallow kopya)
        assert out["extracted_names"] is not out["extracted_names_final"]

        # extracted_names'i mutate et — final etkilenmedi
        out["extracted_names"]["FUN_C"] = "baz"
        assert "FUN_C" not in out["extracted_names_final"]


# ---------------------------------------------------------------------------
# H5+H6 — inline_detection final_decompiled_dir ve feedback_loop refresh
# ---------------------------------------------------------------------------


class TestH5H6InlineDetectionWiring:
    def test_requires_final_decompiled_dir(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("inline_detection")
        assert "final_decompiled_dir" in spec.requires
        assert "decompiled_dir" not in spec.requires

    def test_feedback_loop_refresh_after_loop(self, tmp_path: Path) -> None:
        """Feedback loop'un son iterasyonundan sonra file_cache guncellenir."""
        from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep

        pc = _mk_fake_pc(tmp_path, max_iter=1, metadata={})
        (tmp_path / "src_out").mkdir(exist_ok=True)
        artifacts = _mk_artifacts(tmp_path)
        decompiled = artifacts["decompiled_dir"]  # _mk_artifacts'te mkdir yapildi
        # Disariya yazilmis ama file_cache'de henuz olmayan yeni bir dosya
        # (tipik senaryo: post-loop feedback_loop baska bir dir'a yazdi).
        (decompiled / "NEW_FN.c").write_text("int x(void){return 0;}")
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts(artifacts)

        FeedbackLoopStep().run(ctx)
        # Post-loop refresh: NEW_FN.c file_cache'de olmali (full rglob).
        assert "NEW_FN.c" in artifacts["file_cache"]


# ---------------------------------------------------------------------------
# H10 — merger subdirectory korunuyor
# ---------------------------------------------------------------------------


class TestH10MergerSubdirectoryPreserved:
    """Iki farkli alt-klasorde ayni ada sahip `.c` dosyalari iki ayri
    ciktiya yazilmali (name collision yok)."""

    def test_subdir_preserved(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._feedback_naming_merger import (
            _apply_aho_replace,
        )
        decompiled = tmp_path / "decompiled"
        (decompiled / "foo").mkdir(parents=True)
        (decompiled / "bar").mkdir()
        # Ayni ad (util.c) ama farkli icerik
        (decompiled / "foo" / "util.c").write_text("int FN_A(void){}")
        (decompiled / "bar" / "util.c").write_text("int FN_B(void){}")

        reconstructed = tmp_path / "rec"
        reconstructed.mkdir()

        artifacts: dict = {}
        naming_map = {"FN_A": "alpha", "FN_B": "beta"}
        _apply_aho_replace(
            iter_index=0,
            decompiled_dir=decompiled,
            reconstructed_dir=reconstructed,
            incremental_files=None,
            final_naming_map=naming_map,
            artifacts=artifacts,
        )
        merge_dir = reconstructed / "merged"
        assert (merge_dir / "foo" / "util.c").exists()
        assert (merge_dir / "bar" / "util.c").exists()
        foo_content = (merge_dir / "foo" / "util.c").read_text()
        bar_content = (merge_dir / "bar" / "util.c").read_text()
        # Aho-Corasick degistirmis ama iki ayri kaynak korunmus
        assert "alpha" in foo_content
        assert "beta" in bar_content
        assert "alpha" not in bar_content  # foo'nun icerigi bar'a sizmamali


# ---------------------------------------------------------------------------
# M14 — registry duplicate producer raise
# ---------------------------------------------------------------------------


class TestM14DuplicateProducerRaises:
    def test_two_steps_same_artifact_raises(self) -> None:
        saved = dict(_REGISTRY)
        try:
            _clear_registry_for_tests()

            @register_step(name="dup_prod_a", produces=["same_art"])
            class A(Step):
                def run(self, ctx):
                    return {"same_art": 1}

            @register_step(name="dup_prod_b", produces=["same_art"])
            class B(Step):
                def run(self, ctx):
                    return {"same_art": 2}

            runner = PipelineRunner(steps=["dup_prod_a", "dup_prod_b"])
            pc = MagicMock()
            pc.metadata = {}
            with pytest.raises(ValueError, match="iki step"):
                runner.run(pc)
        finally:
            _REGISTRY.clear()
            _REGISTRY.update(saved)

    def test_single_producer_ok(self) -> None:
        saved = dict(_REGISTRY)
        try:
            _clear_registry_for_tests()

            @register_step(name="solo_producer", produces=["solo_art"])
            class S(Step):
                def run(self, ctx):
                    return {"solo_art": 42}

            runner = PipelineRunner(steps=["solo_producer"])
            pc = MagicMock()
            pc.metadata = {}
            step_ctx = runner.run(pc)
            assert step_ctx.artifacts["solo_art"] == 42
        finally:
            _REGISTRY.clear()
            _REGISTRY.update(saved)


# ---------------------------------------------------------------------------
# M15 — iter>0 naming output cleanup
# ---------------------------------------------------------------------------


class TestM15NamerOutputCleanup:
    def test_stale_output_removed(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._feedback_naming import _compute_namer_output

        reconstructed = tmp_path / "rec"
        reconstructed.mkdir()
        # Onceki iter'den kalma stale dosya
        out_iter1 = reconstructed / "src_iter1"
        out_iter1.mkdir()
        (out_iter1 / "STALE.c").write_text("int stale(void){}")
        assert (out_iter1 / "STALE.c").exists()

        # iter_index=1 -> src_iter1 yeniden olusturulur, STALE silinir
        returned = _compute_namer_output(
            reconstructed, tmp_path / "out", iter_index=1,
        )
        assert returned == out_iter1
        assert out_iter1.exists()
        assert not (out_iter1 / "STALE.c").exists()

    def test_iter0_does_not_touch_output(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps._feedback_naming import _compute_namer_output

        reconstructed = tmp_path / "rec"
        reconstructed.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "KEEP.c").write_text("int keep(void){}")

        returned = _compute_namer_output(reconstructed, out_dir, iter_index=0)
        assert returned == out_dir
        assert (out_dir / "KEEP.c").exists()  # iter0'da temizlik YOK


# ---------------------------------------------------------------------------
# M19 — pipeline_iterations validation
# ---------------------------------------------------------------------------


class TestM19PipelineIterationsValidation:
    def test_zero_iterations_raises(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep
        pc = _mk_fake_pc(tmp_path, max_iter=0, metadata={})
        (tmp_path / "src_out").mkdir(exist_ok=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts(_mk_artifacts(tmp_path))
        with pytest.raises(ValueError, match="pipeline_iterations"):
            FeedbackLoopStep().run(ctx)

    def test_negative_iterations_raises(self, tmp_path: Path) -> None:
        from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep
        pc = _mk_fake_pc(tmp_path, max_iter=-5, metadata={})
        (tmp_path / "src_out").mkdir(exist_ok=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts(_mk_artifacts(tmp_path))
        with pytest.raises(ValueError, match="pipeline_iterations"):
            FeedbackLoopStep().run(ctx)

    def test_positive_iterations_ok(self, tmp_path: Path) -> None:
        """Sinir: 1 gecerli ve tek iter koşmali."""
        from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep
        pc = _mk_fake_pc(tmp_path, max_iter=1, metadata={})
        (tmp_path / "src_out").mkdir(exist_ok=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts(_mk_artifacts(tmp_path))
        out = FeedbackLoopStep().run(ctx)
        assert len(out["iteration_stats"]) == 1


# ---------------------------------------------------------------------------
# Finalize convergence_reason -> stats
# ---------------------------------------------------------------------------


class TestFinalizeConvergenceReasonInStats:
    def test_convergence_reason_copied_to_stats(self, tmp_path: Path) -> None:
        import time
        from karadul.pipeline.steps.finalize import FinalizeStep

        pc = MagicMock()
        pc.metadata = {"artifacts_pending": {"x": "p"}}
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": Path("/tmp/fake"),
            "convergence_reason": "no_new_names",
            "__stage_name": "binary_reconstruction",
            "__pipeline_start": time.monotonic(),
        })
        out = FinalizeStep().run(ctx)
        assert out["stage_result"].stats["convergence_reason"] == "no_new_names"

    def test_missing_convergence_reason_defaults_unknown(
        self, tmp_path: Path,
    ) -> None:
        """convergence_reason artifact'i yoksa 'unknown' olarak kaydedilir."""
        from karadul.pipeline.steps.finalize import FinalizeStep

        pc = MagicMock()
        pc.metadata = {"artifacts_pending": {}}
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "deep_tracing_result": {},
            "engineering_analysis_result": None,
            "project_dir": None,
        })
        out = FinalizeStep().run(ctx)
        assert out["stage_result"].stats["convergence_reason"] == "unknown"
