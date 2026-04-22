"""v1.10.0 M1 T3.4 — FeedbackLoopStep + helpers testleri."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import _feedback_helpers as _fh
from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep


# ---------------------------------------------------------------------------
# Pure helper testleri
# ---------------------------------------------------------------------------


class TestBuildCgNeighbors:
    def test_empty_returns_empty(self) -> None:
        assert _fh.build_cg_neighbors(None) == {}
        assert _fh.build_cg_neighbors({}) == {}

    def test_symmetric_callers_callees(self) -> None:
        data = {
            "foo": {
                "callees": [{"name": "bar"}, "baz"],
                "callers": [{"name": "main"}],
            },
        }
        nb = _fh.build_cg_neighbors(data)
        assert "bar" in nb["foo"]
        assert "baz" in nb["foo"]
        assert "main" in nb["foo"]
        # symmetric
        assert "foo" in nb["bar"]
        assert "foo" in nb["baz"]
        assert "foo" in nb["main"]

    def test_non_dict_node_ignored(self) -> None:
        data = {"a": "not_a_dict", "b": {"callees": [{"name": "c"}]}}
        nb = _fh.build_cg_neighbors(data)
        assert "a" not in nb  # bozuk dugum atlandi
        assert "c" in nb["b"]


class TestExtractNamedSet:
    def test_from_final_naming_map(self) -> None:
        out = _fh.extract_named_set(
            naming_result=None,
            final_naming_map={"a": "x", "b": "y"},
        )
        assert out == {"a", "b"}

    def test_from_naming_result_fallback(self) -> None:
        nr = MagicMock()
        nr.naming_map = {"k1": "v1"}
        out = _fh.extract_named_set(
            naming_result=nr, final_naming_map=None,
        )
        assert out == {"k1"}

    def test_empty_when_no_source(self) -> None:
        assert _fh.extract_named_set(
            naming_result=None, final_naming_map=None,
        ) == set()


class TestCheckConvergence:
    """v1.10.0 M2 T6: API guncellendi (current_named + min_absolute_new).

    Detayli bug-fix testleri: tests/test_convergence_fix.py
    """

    def test_first_iteration_never_converges(self) -> None:
        c, r = _fh.check_convergence(
            iter_index=0, prev_named=set(), current_named=set(),
            threshold=0.01,
        )
        assert c is False
        assert r == "first_iteration"

    def test_ratio_below_threshold_converges(self) -> None:
        # prev: 1000, current: prev + 5 yeni -> ratio 0.005 < 0.01
        prev = set(range(1000))
        current = prev | set(range(1000, 1005))
        c, r = _fh.check_convergence(
            iter_index=1, prev_named=prev, current_named=current,
            threshold=0.01,
        )
        assert c is True
        assert r.startswith("convergence_ratio_")

    def test_ratio_above_threshold_does_not_converge(self) -> None:
        # prev: 100, current: prev + 5 yeni -> ratio 0.05 > 0.01
        prev = set(range(100))
        current = prev | set(range(100, 105))
        c, r = _fh.check_convergence(
            iter_index=1, prev_named=prev, current_named=current,
            threshold=0.01,
        )
        assert c is False
        assert r == "continuing"

    def test_empty_prev_zero_new_converges(self) -> None:
        # Iki iter ust uste bos -> naming verisi hic yok
        c, r = _fh.check_convergence(
            iter_index=1, prev_named=set(), current_named=set(),
            threshold=0.01,
        )
        assert c is True
        assert r == "no_naming_data_two_iters"

    def test_empty_prev_nonzero_new_never_converges(self) -> None:
        # Onceki bos ama simdi ilk sinyal geldi -> devam
        c, r = _fh.check_convergence(
            iter_index=1, prev_named=set(), current_named={"a"},
            threshold=0.5,
        )
        assert c is False
        assert r == "empty_prev_first_signal"


class TestComputeIncrementalFiles:
    def test_iter0_no_newly_named_returns_none(self) -> None:
        out = _fh.compute_incremental_files(
            iter_index=0,
            newly_named=set(),
            cg_neighbors={"a": {"b"}},
            current_cfiles={"a.c": Path("/tmp/a.c")},
            func_count=10,
        )
        assert out is None

    def test_no_cg_returns_none(self) -> None:
        out = _fh.compute_incremental_files(
            iter_index=1,
            newly_named={"a"},
            cg_neighbors={},
            current_cfiles={"a.c": Path("/tmp/a.c")},
            func_count=10,
        )
        assert out is None

    def test_subset_includes_neighbors(self, tmp_path: Path) -> None:
        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        c = tmp_path / "c.c"
        for p in (a, b, c):
            p.write_text("")
        out = _fh.compute_incremental_files(
            iter_index=1,
            newly_named={"a"},
            cg_neighbors={"a": {"b"}, "b": {"a"}},
            current_cfiles={"a.c": a, "b.c": b, "c.c": c},
            func_count=3,
        )
        assert out is not None
        stems = {p.stem for p in out}
        assert stems == {"a", "b"}

    def test_too_large_falls_back_to_full(self, tmp_path: Path) -> None:
        # 100 dosyadan 85'i hedef (%85 > %80 esigi) -> None
        files = {}
        neighbors = {"sym0": set()}
        newly = {"sym0"}
        for i in range(85):
            p = tmp_path / f"sym{i}.c"
            p.touch()
            files[p.name] = p
            neighbors.setdefault("sym0", set()).add(f"sym{i}")
        # geri kalan 15 dosya alakasiz
        for i in range(85, 100):
            p = tmp_path / f"other{i}.c"
            p.touch()
            files[p.name] = p
        out = _fh.compute_incremental_files(
            iter_index=1,
            newly_named=newly,
            cg_neighbors=neighbors,
            current_cfiles=files,
            func_count=100,
        )
        assert out is None  # fallback full


# ---------------------------------------------------------------------------
# Step registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_feedback_loop_registered(self) -> None:
        spec = get_step("feedback_loop")
        assert "decompiled_dir" in spec.requires
        assert "call_graph_data" in spec.requires
        assert "naming_result" in spec.produces
        assert "final_decompiled_dir" in spec.produces
        assert "convergence_reason" in spec.produces


# ---------------------------------------------------------------------------
# FeedbackLoopStep — minimal integration (her faz mock'lu)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    # config
    br = SimpleNamespace(
        pipeline_iterations=1,
        pipeline_convergence_threshold=0.01,
        pipeline_iteration_timeout=600.0,
        pipeline_min_new_names_per_iter=1,  # v1.10.0 M2 T6
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
    pc.metadata = {}
    pc.target.file_hash = "abc" * 22
    pc.target.target_type = None
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_artifacts(tmp_path: Path):
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
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


@pytest.fixture
def base_ctx(fake_pc, base_artifacts):
    (base_artifacts["output_dir"]).mkdir(exist_ok=True)
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts(base_artifacts)
    return ctx


class TestFeedbackLoopMaxIter1:
    def test_runs_single_iter_returns_all_keys(self, base_ctx) -> None:
        out = FeedbackLoopStep().run(base_ctx)
        spec = get_step("feedback_loop")
        # tum produces key'leri dondurulmus
        for k in spec.produces:
            assert k in out
        # sadece 1 iter
        assert len(out["iteration_stats"]) == 1
        assert out["iteration_stats"][0]["iteration"] == 1
        # convergence sebep max_iter (iterasyon 1 = max, convergence kontrolu
        # yapilmadi)
        assert out["convergence_reason"] == "max_iter"

    def test_final_decompiled_dir_is_path(self, base_ctx, tmp_path: Path) -> None:
        out = FeedbackLoopStep().run(base_ctx)
        assert isinstance(out["final_decompiled_dir"], Path)


class TestFeedbackLoopProducesContract:
    def test_only_declared_produces(self, base_ctx) -> None:
        """Step'in dondurdugu dict produces'tan kiwi olmamali."""
        spec = get_step("feedback_loop")
        out = FeedbackLoopStep().run(base_ctx)
        for k in out:
            assert k in spec.produces, f"bilinmeyen key: {k}"


class TestFeedbackLoopRunnerIntegration:
    """PipelineRunner uzerinden feedback_loop + struct_recovery birlikte."""

    def test_phase2_runner_sequence(self, fake_pc, base_artifacts) -> None:
        """Runner feedback_loop -> struct_recovery sirayla calistirip
        produces contract'ina uymali."""
        from karadul.pipeline import PipelineRunner
        fake_pc.config.binary_reconstruction.enable_struct_recovery = False
        runner = PipelineRunner(steps=["feedback_loop", "struct_recovery"])
        step_ctx = runner.run(fake_pc, seed_artifacts=base_artifacts)

        # feedback_loop produces
        assert "naming_result" in step_ctx.artifacts
        assert "final_decompiled_dir" in step_ctx.artifacts
        assert "iteration_stats" in step_ctx.artifacts
        # struct_recovery produces
        assert "struct_recovery_decompiled_dir" in step_ctx.artifacts
        assert "struct_recovery_result" in step_ctx.artifacts


class TestFeedbackLoopIterationStats:
    def test_iteration_stats_shape(self, base_ctx, fake_pc) -> None:
        fake_pc.config.binary_reconstruction.pipeline_iterations = 3
        out = FeedbackLoopStep().run(base_ctx)
        # Her iter stats dict'i beklenen alanlara sahip
        for s in out["iteration_stats"]:
            assert "iteration" in s
            assert "new_names" in s
            assert "total_names" in s
            assert "duration" in s

    def test_convergence_early_stops(self, base_ctx, fake_pc) -> None:
        """max_iter=5, ama convergence iter 2'de olabilir cunku yeni isim
        gelmedigi icin (enable_c_naming=False) prev==cur.

        v1.10.0 M2 T6 sonrasi yeni reason string'leri:
        - "no_naming_data_two_iters": iki iter ust uste prev=cur=empty
        - "no_new_names": yeni isim gelmedi
        - "convergence_ratio_X.XXX": ratio < threshold
        """
        fake_pc.config.binary_reconstruction.pipeline_iterations = 5
        out = FeedbackLoopStep().run(base_ctx)
        assert len(out["iteration_stats"]) <= 5
        reason = out["convergence_reason"]
        # convergence sebebini kontrol et (T6 sonrasi genisletilmis set)
        acceptable = {
            "no_naming_data_two_iters",
            "no_new_names",
            "max_iter",
            "iteration_timeout",
        }
        assert reason in acceptable or reason.startswith("convergence_ratio_"), (
            f"Beklenmeyen reason: {reason!r}"
        )


# ---------------------------------------------------------------------------
# v1.10.0 H2: Flag-open (enable_c_naming + enable_type_recovery) iterasyon
# convergence davranisi. Gercek namer/type_recoverer calisir ama base_artifacts
# bos oldugu icin (tek dummy C dosyasi) yeni isim uretmemeli => convergence.
# ---------------------------------------------------------------------------


class TestFeedbackLoopFlagsEnabled:
    """H2: flag'leri acarak gercek iter convergence olcumu."""

    def test_c_naming_enabled_converges_when_no_symbols(
        self, base_ctx, fake_pc,
    ) -> None:
        """enable_c_naming=True + bos extracted_names -> convergence."""
        fake_pc.config.binary_reconstruction.enable_c_naming = True
        fake_pc.config.binary_reconstruction.pipeline_iterations = 3

        out = FeedbackLoopStep().run(base_ctx)

        # En az 1 iter calismis olmali
        assert len(out["iteration_stats"]) >= 1
        # Hic yeni isim uretilmediyse ya erken durdu (no_new_names /
        # no_naming_data) ya da max_iter'a ulasti.
        reason = out["convergence_reason"]
        acceptable_prefixes = (
            "no_naming_data_two_iters", "no_new_names",
            "max_iter", "iteration_timeout", "empty_prev_first_signal",
        )
        assert (
            reason in acceptable_prefixes
            or reason.startswith("convergence_ratio_")
        ), f"Beklenmeyen reason: {reason!r}"

    def test_type_recovery_enabled_produces_stats(
        self, base_ctx, fake_pc,
    ) -> None:
        """enable_type_recovery=True -> type_recovery fazi en az bir kez
        cagrilir ve iteration_stats sekli bozulmamis olmali."""
        fake_pc.config.binary_reconstruction.enable_type_recovery = True
        fake_pc.config.binary_reconstruction.pipeline_iterations = 2

        out = FeedbackLoopStep().run(base_ctx)

        # Iterasyon stats dolu ve her kayit required key'leri icermeli.
        assert len(out["iteration_stats"]) >= 1
        for s in out["iteration_stats"]:
            assert "iteration" in s
            assert "new_names" in s
            assert "duration" in s
            # duration gercek bir sayi (ne kadar kucuk olursa olsun >= 0).
            assert s["duration"] >= 0.0

    def test_both_flags_enabled_terminates_within_max_iter(
        self, base_ctx, fake_pc,
    ) -> None:
        """Hem c_naming hem type_recovery acik -> max_iter icinde donmeli."""
        fake_pc.config.binary_reconstruction.enable_c_naming = True
        fake_pc.config.binary_reconstruction.enable_type_recovery = True
        fake_pc.config.binary_reconstruction.pipeline_iterations = 4

        out = FeedbackLoopStep().run(base_ctx)

        assert len(out["iteration_stats"]) <= 4
        # final_decompiled_dir Path
        assert isinstance(out["final_decompiled_dir"], Path)
        # convergence_reason string ve bos degil
        assert isinstance(out["convergence_reason"], str)
        assert out["convergence_reason"]

    def test_convergence_iteration_count_monotonic(
        self, base_ctx, fake_pc,
    ) -> None:
        """iteration_stats[i]['iteration'] ardisik olmali (1,2,3,...)."""
        fake_pc.config.binary_reconstruction.enable_c_naming = True
        fake_pc.config.binary_reconstruction.pipeline_iterations = 3

        out = FeedbackLoopStep().run(base_ctx)

        iters = [s["iteration"] for s in out["iteration_stats"]]
        assert iters == list(range(1, len(iters) + 1)), (
            f"iterasyon numaralari ardisik degil: {iters}"
        )
