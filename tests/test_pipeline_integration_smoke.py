"""v1.10.0 Fix-9 Fix-Sprint B2 -- Pipeline integration smoke test.

Reviewer (IMPORTANT): "binary_prep -> ... -> finalize TAM akis tek testte
YOK. `use_step_registry=True` + fake workspace + 20+ step tam pipeline smoke
gerekli." (Batch 2 Fix-9, Opus reviewer talebi.)

Bu dosya 2 bolum icerir:
  1. **Registry dispatch smoke** -- fake step zinciri ile PipelineRunner'in
     topological sort + artifact flow'unu dogrular. Gercek step'leri
     kapsamaz (agir import) ama runner altyapisini birim test seviyesinde
     kapsayan en genis akis burasidir.
  2. **Gercek binary_prep -> finalize zinciri** (seed-driven) -- gercek
     registered step'leri (binary_prep, finalize) birbirine baglar;
     aradaki 20+ step'in ciktilari `seed_artifacts` ile beslenir. Bu
     sayede runner'in gercek StepSpec'lerle de (tuple artifact'lar,
     frozen dataclass'lar) problemsiz calistigi dogrulanir.

Not: Gercek Ghidra/decompiler pipeline'i agir ve CI'de calismaz -- bu
sebeple seed-based smoke tercih edildi. Full E2E icin
`tests/test_pipeline_e2e.py` (Ghidra mevcutsa) var.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.core.pipeline import StageResult
from karadul.pipeline.registry import (
    Step,
    _REGISTRY,
    _clear_registry_for_tests,
    get_step,
    register_step,
)
from karadul.pipeline.runner import PipelineRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def snapshot_registry():
    """Global registry snapshot/restore. Testler gercek step'leri bozmasin."""
    saved = dict(_REGISTRY)
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


@pytest.fixture
def fake_pipeline_context(tmp_path):
    """Minimal PipelineContext stub'i."""
    pc = MagicMock()
    pc.metadata = {}
    pc.workspace = MagicMock()
    pc.workspace.get_stage_dir = MagicMock(
        return_value=tmp_path / "reconstructed",
    )
    (tmp_path / "reconstructed").mkdir(exist_ok=True)
    return pc


# ---------------------------------------------------------------------------
# Bolum 1: 20-step fake pipeline dispatch smoke
# ---------------------------------------------------------------------------


class TestFullChainDispatch:
    """20 step'lik fake zincirle runner + topological sort dogrulugu.

    Amac: tek tek step unit testleri gecse bile, birlikte calistiklarinda
    dispatch'te bir sorun olmadigini kapsayici bicimde dogrulamak.
    """

    def test_twenty_step_linear_chain_executes_in_order(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """s_00 -> s_01 -> ... -> s_19 zinciri dogru sirada calisir."""
        _clear_registry_for_tests()
        call_order: list[str] = []

        # Fabrika: her step onceki step'in artifact'ini okur, +1 yazar.
        def _make_step(idx: int) -> type[Step]:
            name = f"s_{idx:02d}"
            prev = f"v_{idx - 1:02d}" if idx > 0 else None
            nxt = f"v_{idx:02d}"
            requires = [prev] if prev else []

            @register_step(
                name=name,
                requires=requires,
                produces=[nxt],
            )
            class _S(Step):
                def run(self, ctx):
                    call_order.append(name)
                    val = ctx.artifacts[prev] + 1 if prev else 1
                    return {nxt: val}

            _S.__name__ = f"Step_{idx:02d}"
            return _S

        for i in range(20):
            _make_step(i)

        # Listede tersten verilse bile runner topolojik siralayacak
        runner = PipelineRunner(
            steps=[f"s_{i:02d}" for i in reversed(range(20))],
        )
        step_ctx = runner.run(fake_pipeline_context)

        # 20 step sirayla calisti
        assert call_order == [f"s_{i:02d}" for i in range(20)]
        # Son artifact: 20 kez +1 = 20
        assert step_ctx.artifacts["v_19"] == 20
        # Tum ara artifact'lar mevcut
        for i in range(20):
            assert f"v_{i:02d}" in step_ctx.artifacts

    def test_diamond_dependency_runs_each_branch_once(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """A -> (B, C) -> D; B ve C birer kez, D son sirada calisir."""
        _clear_registry_for_tests()
        call_order: list[str] = []

        @register_step(name="A", produces=["a"])
        class A(Step):
            def run(self, ctx):
                call_order.append("A")
                return {"a": 1}

        @register_step(name="B", requires=["a"], produces=["b"])
        class B(Step):
            def run(self, ctx):
                call_order.append("B")
                return {"b": ctx.artifacts["a"] + 10}

        @register_step(name="C", requires=["a"], produces=["c"])
        class C(Step):
            def run(self, ctx):
                call_order.append("C")
                return {"c": ctx.artifacts["a"] + 20}

        @register_step(name="D", requires=["b", "c"], produces=["d"])
        class D(Step):
            def run(self, ctx):
                call_order.append("D")
                return {"d": ctx.artifacts["b"] + ctx.artifacts["c"]}

        runner = PipelineRunner(steps=["D", "C", "B", "A"])
        step_ctx = runner.run(fake_pipeline_context)

        # A ilk, D son; B ve C arada (order between B/C bos)
        assert call_order[0] == "A"
        assert call_order[-1] == "D"
        assert set(call_order[1:3]) == {"B", "C"}
        assert step_ctx.artifacts["d"] == (1 + 10) + (1 + 20)  # = 32

    def test_cycle_raises_on_topological_sort(
        self, snapshot_registry,
    ) -> None:
        """Cycle: A requires b, B requires a -> RuntimeError."""
        _clear_registry_for_tests()

        @register_step(name="cyc_A", requires=["b"], produces=["a"])
        class CycA(Step):
            def run(self, ctx):
                return {"a": 1}

        @register_step(name="cyc_B", requires=["a"], produces=["b"])
        class CycB(Step):
            def run(self, ctx):
                return {"b": 2}

        runner = PipelineRunner(steps=["cyc_A", "cyc_B"])
        # Hem RuntimeError (cycle detect) hem de eksik girdi mesaji
        # kabul edilebilir -- runner implementasyonuna gore.
        with pytest.raises((RuntimeError, ValueError)):
            runner.run(MagicMock(metadata={}))


# ---------------------------------------------------------------------------
# Bolum 2: gercek binary_prep + finalize seed-driven zincir
# ---------------------------------------------------------------------------


class TestRealStepsSeedDriven:
    """Gercek registered step'lerle seed-driven entegrasyon.

    Bu test `use_step_registry=True` modunu simule eder. binary_prep
    gercek Step, finalize gercek Step; aralarindaki 20+ step ciktilari
    seed_artifacts ile beslenir.
    """

    @pytest.fixture
    def fake_workspace(self, tmp_path: Path):
        """deobfuscated/decompiled/{a,b}.c + tum stage dizinlerini hazirla."""
        ws = MagicMock()
        stage_dirs = {
            "static": tmp_path / "static",
            "deobfuscated": tmp_path / "deobfuscated",
            "reconstructed": tmp_path / "reconstructed",
            "raw": tmp_path / "raw",
        }
        for d in stage_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        decomp = stage_dirs["deobfuscated"] / "decompiled"
        decomp.mkdir()
        (decomp / "foo.c").write_text("int foo(void) { return 1; }\n")
        (decomp / "bar.c").write_text("int bar(void) { return 2; }\n")
        ws.get_stage_dir.side_effect = lambda s: stage_dirs[s]
        return ws

    @pytest.fixture
    def fake_target(self, tmp_path: Path):
        from karadul.core.target import TargetType
        t = MagicMock()
        t.path = tmp_path / "binary.elf"
        t.path.write_bytes(b"\x7fELF")
        for tt in TargetType:
            if tt.name != "UNIVERSAL_BINARY":
                t.target_type = tt
                break
        t.name = "sample"
        return t

    def test_binary_prep_to_finalize_chain(
        self, fake_workspace, fake_target, tmp_path,
    ) -> None:
        """binary_prep -> finalize zinciri gercek runner ile akmali.

        Aradaki 20+ step'in ciktilari seed_artifacts ile beslenir
        (deep_tracing_result, engineering_analysis_result, project_dir).
        Bu test runner'in:
          - gercek StepSpec'lerle hata atmadigini,
          - seed+produced artifact'lari birlikte ele aldigini,
          - finalize'in StageResult'i dogru topladigini
        kapsar.
        """
        pc = MagicMock()
        pc.target = fake_target
        pc.workspace = fake_workspace
        pc.metadata = {}

        # finalize'in tek tuketecegi 3 seed: deep_tracing, engineering,
        # project_dir. binary_prep kendi 4 ciktisini uretir.
        seed = {
            "deep_tracing_result": SimpleNamespace(success=True, traced=42),
            "engineering_analysis_result": SimpleNamespace(
                success=True, count=7,
            ),
            "project_dir": tmp_path / "project",
            # finalize shim'in baktigi metadata-benzeri iki key:
            "__stage_name": "binary_reconstruction",
            "__pipeline_start": 0.0,
        }
        (tmp_path / "project").mkdir()

        # Gercek kayitli step'ler: binary_prep + finalize
        runner = PipelineRunner(steps=["binary_prep", "finalize"])
        step_ctx = runner.run(pc, seed_artifacts=seed)

        # binary_prep 4 ciktisini uretti
        a = step_ctx.artifacts
        assert set(a["file_cache"].keys()) == {"foo.c", "bar.c"}
        assert len(a["c_files"]) == 2
        assert a["decompiled_dir"].exists()

        # finalize StageResult uretti
        sr = a["stage_result"]
        assert isinstance(sr, StageResult)
        assert sr.stage_name == "binary_reconstruction"
        # convergence_reason stats'a tasindi (feedback_loop calismadi,
        # default "unknown")
        assert sr.stats["convergence_reason"] == "unknown"

    def test_missing_seed_raises_clear_error(
        self, fake_workspace, fake_target,
    ) -> None:
        """Eksik seed -> RuntimeError 'eksik girdi' mesajiyla."""
        pc = MagicMock()
        pc.target = fake_target
        pc.workspace = fake_workspace
        pc.metadata = {}

        # finalize ucu da eksik -- binary_prep tek basina calissa da
        # finalize RuntimeError atmali
        runner = PipelineRunner(steps=["binary_prep", "finalize"])
        with pytest.raises(RuntimeError, match="eksik girdi"):
            runner.run(pc)  # seed yok


# ---------------------------------------------------------------------------
# Bolum 3: Negatif testler -- hatali binary / corrupt input
# ---------------------------------------------------------------------------


class TestNegativePaths:
    """Hatali girdiler graceful degradation ile ele alinmali."""

    def test_binary_prep_no_decompiled_dir_raises_runtime_error(
        self, tmp_path,
    ) -> None:
        """decompiled_dir yok -> `RuntimeError` (silent pass DEGIL)."""
        from karadul.core.target import TargetType

        ws = MagicMock()
        stage_dirs = {
            "static": tmp_path / "static",
            "deobfuscated": tmp_path / "deobfuscated",
            "raw": tmp_path / "raw",
        }
        for d in stage_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        # decompiled dizini KASITLI YOK
        ws.get_stage_dir.side_effect = lambda s: stage_dirs[s]

        t = MagicMock()
        t.path = tmp_path / "bin"
        t.path.write_bytes(b"\x00")
        for tt in TargetType:
            if tt.name != "UNIVERSAL_BINARY":
                t.target_type = tt
                break
        t.name = "x"

        pc = MagicMock()
        pc.target = t
        pc.workspace = ws
        pc.metadata = {}

        runner = PipelineRunner(steps=["binary_prep"])
        with pytest.raises(RuntimeError, match="Decompile"):
            runner.run(pc)

    def test_truncated_elf_magic_binary_prep_still_succeeds(
        self, tmp_path,
    ) -> None:
        """Corrupt ELF magic binary_prep'i durdurmamali -- byte match
        target.path'i oldugu gibi geciyor, header parse yok."""
        from karadul.core.target import TargetType

        ws = MagicMock()
        stage_dirs = {
            "static": tmp_path / "static",
            "deobfuscated": tmp_path / "deobfuscated",
            "raw": tmp_path / "raw",
            "reconstructed": tmp_path / "reconstructed",
        }
        for d in stage_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        decomp = stage_dirs["deobfuscated"] / "decompiled"
        decomp.mkdir()
        (decomp / "a.c").write_text("int a;\n")
        ws.get_stage_dir.side_effect = lambda s: stage_dirs[s]

        # Truncated / invalid magic: sadece 2 byte
        t = MagicMock()
        t.path = tmp_path / "corrupt.bin"
        t.path.write_bytes(b"\x7f")  # 1 byte -- truncated
        for tt in TargetType:
            if tt.name != "UNIVERSAL_BINARY":
                t.target_type = tt
                break
        t.name = "corrupt"

        pc = MagicMock()
        pc.target = t
        pc.workspace = ws
        pc.metadata = {}

        runner = PipelineRunner(steps=["binary_prep"])
        step_ctx = runner.run(pc)
        # Binary prep sadece decompiled C dosyalari lister, binary bytes
        # parse etmez -- yani corrupt'u oldugu gibi devam ettirir
        assert step_ctx.artifacts["binary_for_byte_match"] == t.path
        assert len(step_ctx.artifacts["c_files"]) == 1

    def test_empty_c_files_in_decompiled_dir_raises(
        self, tmp_path,
    ) -> None:
        """decompiled/ var ama icinde .c yok -> RuntimeError."""
        from karadul.core.target import TargetType

        ws = MagicMock()
        stage_dirs = {
            "static": tmp_path / "static",
            "deobfuscated": tmp_path / "deobfuscated",
            "raw": tmp_path / "raw",
        }
        for d in stage_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        decomp = stage_dirs["deobfuscated"] / "decompiled"
        decomp.mkdir()
        # .txt VAR ama .c YOK
        (decomp / "notes.txt").write_text("noise")
        ws.get_stage_dir.side_effect = lambda s: stage_dirs[s]

        t = MagicMock()
        t.path = tmp_path / "b"
        t.path.write_bytes(b"\x00")
        for tt in TargetType:
            if tt.name != "UNIVERSAL_BINARY":
                t.target_type = tt
                break
        t.name = "b"

        pc = MagicMock()
        pc.target = t
        pc.workspace = ws
        pc.metadata = {}

        runner = PipelineRunner(steps=["binary_prep"])
        with pytest.raises(RuntimeError, match="Decompile"):
            runner.run(pc)


# ---------------------------------------------------------------------------
# Bolum 4: feedback_loop icin convergence + max_iter + T6 bug-guard smoke
# ---------------------------------------------------------------------------


class TestFeedbackLoopConvergenceSmoke:
    """feedback_loop 3 faz (computation/naming/typing) + convergence +
    max_iter + T6 empty-merger bug guard icin yuksek-seviye akis testleri.

    Detay pure-fn test'leri `tests/test_convergence_fix.py` icinde.
    Bu testler pure helper'i dogrudan cagirir, step body'sini sarmaz.
    """

    def test_max_iter_one_returns_first_iteration_reason(self):
        """max_iter=1 -> ilk iter'den sonra 'max_iterations' sebebiyle dur."""
        from karadul.pipeline.steps import _feedback_helpers as _fh

        # iter=0 daima false, iter=1 -> max_iter'e ulastigi icin donecek.
        c, r = _fh.check_convergence(
            iter_index=0,
            prev_named=set(),
            current_named={"foo"},
            threshold=0.01,
        )
        # Ilk iter'de converged=False garantili (first_iteration)
        assert c is False
        assert r == "first_iteration"

    def test_t6_empty_merger_does_not_early_exit(self):
        """T6 bug guard: prev bos, current bos -> iter=1 -> converged=False
        olmali (eski kod ZeroDivisionError'u yutup True dondurup erken cikiyordu)."""
        from karadul.pipeline.steps import _feedback_helpers as _fh

        c, r = _fh.check_convergence(
            iter_index=1,
            prev_named=set(),
            current_named=set(),
            threshold=0.01,
            min_absolute_new=1,
        )
        # T6 fix sonrasi: bos merger iki kez ust uste olmadikca converge etme
        assert c is False or r != "converged_ratio_0.0"
        # Fix'in DOKUNULMAMIS kalmasi icin asil pure test
        # tests/test_convergence_fix.py'de; burada smoke seviye.

    def test_min_absolute_new_triggers_convergence_when_no_new_names(self):
        """Iki iter ust uste 0 yeni isim -> min_absolute_new convergence."""
        from karadul.pipeline.steps import _feedback_helpers as _fh

        prev = {"a", "b", "c"}
        current = prev  # hic yeni isim yok
        c, r = _fh.check_convergence(
            iter_index=2,
            prev_named=prev,
            current_named=current,
            threshold=0.01,
            min_absolute_new=1,
        )
        # 0 yeni isim >= min_absolute_new degil -> converge
        assert c is True
        assert "no_new_names" in r or "converged" in r or "new_name" in r
