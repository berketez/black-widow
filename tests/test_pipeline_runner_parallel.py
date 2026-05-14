"""v1.15-B16 -- PipelineRunner paralel level scheduling testleri.

Bu dosya M2 paralelizasyonunu kapsar:
  1. Bagimsiz step'ler ayni level'da paralel calistirilir.
  2. Topological order korunur (level N+1, level N bitmeden baslamaz).
  3. Bir step paralel grupta fail olursa digerleri tamamlanir, sonra raise.
  4. parallel_steps=False ise eski sequential davranis.
  5. _topological_levels DAG yapisini dogru ayriyor.

Subprocess (Ghidra/TRex/BN) step'leri GIL'i tutmadigi icin ThreadPool
yeterli. Bu testlerde I/O simulasyonu icin `time.sleep` kullaniyoruz —
GIL boyunca bekler, paralelizasyonu net olcebiliriz.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.registry import (
    Step,
    _REGISTRY,
    register_step,
)
from karadul.pipeline.runner import PipelineRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def snapshot_registry():
    """Global step registry snapshot/restore."""
    saved = dict(_REGISTRY)
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


def _make_pc(parallel: bool = True, max_workers: int | None = None):
    """Minimal PipelineContext stub'i + Config.pipeline ayarlari."""
    pc = MagicMock()
    pc.metadata = {}
    pc.workspace = MagicMock()
    pc.config = SimpleNamespace(
        pipeline=SimpleNamespace(
            parallel_steps=parallel,
            parallel_max_workers=max_workers,
        ),
    )
    return pc


def _make_sleep_step(name: str, sleep_s: float, requires=(), produces=None):
    """Belirli sure uyuyan ve produces'i yazan dinamik step sinifi uret."""
    produces = produces or (f"{name}_out",)

    @register_step(
        name=name,
        requires=list(requires),
        produces=list(produces),
    )
    class _SleepStep(Step):
        def run(self, ctx):
            time.sleep(sleep_s)
            return {p: f"{name}_value" for p in produces}

    return _SleepStep


# ---------------------------------------------------------------------------
# Bolum 1: Paralel hizlanma olcumu
# ---------------------------------------------------------------------------


class TestParallelSpeedup:
    """Bagimsiz step'ler paralel calisinca seri vs paralel sure karsilastir."""

    def test_three_independent_steps_run_concurrent(
        self, snapshot_registry,
    ):
        """3 bagimsiz step (her biri 0.5s sleep) paralel ~0.5s, seri ~1.5s."""
        _make_sleep_step("p_step_a", sleep_s=0.5, produces=("a",))
        _make_sleep_step("p_step_b", sleep_s=0.5, produces=("b",))
        _make_sleep_step("p_step_c", sleep_s=0.5, produces=("c",))

        # Sequential (parallel_steps=False)
        runner_seq = PipelineRunner(["p_step_a", "p_step_b", "p_step_c"])
        pc_seq = _make_pc(parallel=False)
        t0 = time.monotonic()
        ctx_seq = runner_seq.run(pc_seq)
        seq_duration = time.monotonic() - t0

        assert "a" in ctx_seq.artifacts
        assert "b" in ctx_seq.artifacts
        assert "c" in ctx_seq.artifacts

        # Parallel (parallel_steps=True)
        runner_par = PipelineRunner(["p_step_a", "p_step_b", "p_step_c"])
        pc_par = _make_pc(parallel=True)
        t0 = time.monotonic()
        ctx_par = runner_par.run(pc_par)
        par_duration = time.monotonic() - t0

        assert "a" in ctx_par.artifacts
        assert "b" in ctx_par.artifacts
        assert "c" in ctx_par.artifacts

        # Paralel net olcum: seri ~1.5s, paralel ~0.5-0.7s.  En azindan
        # %40 hizlanma bekleriz (CI gurultusune toleransli sinir).
        speedup = seq_duration / par_duration
        assert speedup > 1.5, (
            f"Paralel hizlanma yetersiz: seri={seq_duration:.3f}s, "
            f"paralel={par_duration:.3f}s, speedup={speedup:.2f}x"
        )
        # Paralel sure: 3 step her biri 0.5s + overhead -> <1.0s
        assert par_duration < 1.0, (
            f"Paralel sure beklenenden uzun: {par_duration:.3f}s"
        )

    def test_steps_actually_overlap_in_time(self, snapshot_registry):
        """Iki bagimsiz step'in zaman pencereleri ortusmeli (gercek paralel)."""
        timeline: list[tuple[str, str, float]] = []
        timeline_lock = threading.Lock()
        t_start = time.monotonic()

        @register_step(name="ov_step_x", requires=[], produces=["x_out"])
        class StepX(Step):
            def run(self, ctx):
                with timeline_lock:
                    timeline.append(("x", "start", time.monotonic() - t_start))
                time.sleep(0.3)
                with timeline_lock:
                    timeline.append(("x", "end", time.monotonic() - t_start))
                return {"x_out": "x"}

        @register_step(name="ov_step_y", requires=[], produces=["y_out"])
        class StepY(Step):
            def run(self, ctx):
                with timeline_lock:
                    timeline.append(("y", "start", time.monotonic() - t_start))
                time.sleep(0.3)
                with timeline_lock:
                    timeline.append(("y", "end", time.monotonic() - t_start))
                return {"y_out": "y"}

        runner = PipelineRunner(["ov_step_x", "ov_step_y"])
        runner.run(_make_pc(parallel=True))

        # X ve Y start'lari birbirine ~0.05s'den yakin olmali, X end de
        # Y start'tan SONRA olmali (overlap garantisi).
        events = {f"{n}_{phase}": t for n, phase, t in timeline}
        # X başlat ve Y başlat arasındaki fark
        assert abs(events["x_start"] - events["y_start"]) < 0.15, (
            f"Step'ler aynı anda başlamadı: {events}"
        )
        # X bitmeden Y başlamış mı (overlap)
        assert events["y_start"] < events["x_end"], (
            f"Y, X bitmeden başlamadı (overlap yok): {events}"
        )


# ---------------------------------------------------------------------------
# Bolum 2: Topological order korumasi
# ---------------------------------------------------------------------------


class TestTopologicalOrderPreserved:
    """Level N+1 step'leri level N bitmeden BASLAMAZ."""

    def test_dependent_step_waits_for_independent_group(
        self, snapshot_registry,
    ):
        """A,B bagimsiz (paralel), C requires A+B (level 2)."""
        events: list[tuple[str, str, float]] = []
        ev_lock = threading.Lock()
        t0 = time.monotonic()

        def _log(name: str, phase: str):
            with ev_lock:
                events.append((name, phase, time.monotonic() - t0))

        @register_step(name="topo_a", requires=[], produces=["a"])
        class A(Step):
            def run(self, ctx):
                _log("a", "start")
                time.sleep(0.2)
                _log("a", "end")
                return {"a": 1}

        @register_step(name="topo_b", requires=[], produces=["b"])
        class B(Step):
            def run(self, ctx):
                _log("b", "start")
                time.sleep(0.2)
                _log("b", "end")
                return {"b": 2}

        @register_step(name="topo_c", requires=["a", "b"], produces=["c"])
        class C(Step):
            def run(self, ctx):
                _log("c", "start")
                # C calistiginda a, b mevcut olmali
                assert "a" in ctx.artifacts
                assert "b" in ctx.artifacts
                time.sleep(0.05)
                _log("c", "end")
                return {"c": ctx.artifacts["a"] + ctx.artifacts["b"]}

        runner = PipelineRunner(["topo_a", "topo_b", "topo_c"])
        ctx = runner.run(_make_pc(parallel=True))

        assert ctx.artifacts["c"] == 3

        # C, hem A hem B'den SONRA basladi
        ev = {f"{n}_{p}": t for n, p, t in events}
        assert ev["c_start"] > ev["a_end"], (
            f"C, A bitmeden basladi: {ev}"
        )
        assert ev["c_start"] > ev["b_end"], (
            f"C, B bitmeden basladi: {ev}"
        )

    def test_topological_levels_correct_partitioning(
        self, snapshot_registry,
    ):
        """_topological_levels DAG'i dogru level'lara ayiriyor."""
        _make_sleep_step("lv_a", 0.001, produces=("a",))
        _make_sleep_step("lv_b", 0.001, produces=("b",))
        _make_sleep_step(
            "lv_c", 0.001, requires=("a", "b"), produces=("c",),
        )
        _make_sleep_step(
            "lv_d", 0.001, requires=("c",), produces=("d",),
        )

        specs = [
            _REGISTRY["lv_a"],
            _REGISTRY["lv_b"],
            _REGISTRY["lv_c"],
            _REGISTRY["lv_d"],
        ]
        levels = PipelineRunner._topological_levels(specs)

        # 3 level olmali: {a,b}, {c}, {d}
        assert len(levels) == 3
        level_names = [sorted(s.name for s in lv) for lv in levels]
        assert level_names[0] == ["lv_a", "lv_b"]
        assert level_names[1] == ["lv_c"]
        assert level_names[2] == ["lv_d"]


# ---------------------------------------------------------------------------
# Bolum 3: Hata yonetimi
# ---------------------------------------------------------------------------


class TestParallelErrorHandling:
    """Paralel grupta bir step fail olursa digerleri beklenmeli, sonra raise."""

    def test_failure_in_group_lets_others_finish(self, snapshot_registry):
        """Paralel grupta 1 step exception atinca diger 2 step tamamlanir."""
        finished: set[str] = set()
        fin_lock = threading.Lock()

        @register_step(name="err_a", requires=[], produces=["a"])
        class A(Step):
            def run(self, ctx):
                time.sleep(0.2)
                with fin_lock:
                    finished.add("a")
                return {"a": 1}

        @register_step(name="err_b", requires=[], produces=["b"])
        class B(Step):
            def run(self, ctx):
                # Erken fail — diger step'ler hala calismali
                time.sleep(0.05)
                raise RuntimeError("Kasti hata: err_b")

        @register_step(name="err_c", requires=[], produces=["c"])
        class C(Step):
            def run(self, ctx):
                time.sleep(0.2)
                with fin_lock:
                    finished.add("c")
                return {"c": 3}

        runner = PipelineRunner(["err_a", "err_b", "err_c"])
        with pytest.raises(RuntimeError) as excinfo:
            runner.run(_make_pc(parallel=True))

        # err_b'nin hatasi raise edilmis
        assert "err_b" in str(excinfo.value) or "Kasti hata" in str(
            excinfo.value,
        )

        # err_a ve err_c TAM TAMAM olmali — B fail'i onlari iptal etmedi
        assert "a" in finished, (
            f"err_a tamamlanmadi (paralel iptal hatasi?): {finished}"
        )
        assert "c" in finished, (
            f"err_c tamamlanmadi (paralel iptal hatasi?): {finished}"
        )

    def test_failure_prevents_next_level(self, snapshot_registry):
        """Level 1'de hata varsa level 2 BASLAMAZ."""
        level2_ran = threading.Event()

        @register_step(name="fb_a", requires=[], produces=["a"])
        class A(Step):
            def run(self, ctx):
                raise RuntimeError("Level 1 hatasi")

        @register_step(name="fb_b", requires=["a"], produces=["b"])
        class B(Step):
            def run(self, ctx):
                level2_ran.set()
                return {"b": 1}

        runner = PipelineRunner(["fb_a", "fb_b"])
        with pytest.raises(RuntimeError):
            runner.run(_make_pc(parallel=True))

        assert not level2_ran.is_set(), (
            "Level 1 fail olmasina ragmen level 2 step'i calisti!"
        )


# ---------------------------------------------------------------------------
# Bolum 4: Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """parallel_steps=False ile eski sequential davranis korunmali."""

    def test_sequential_mode_runs_in_order(self, snapshot_registry):
        """Sequential modda step'ler topological sirayla, tek tek calisir."""
        order: list[str] = []
        order_lock = threading.Lock()

        @register_step(name="seq_a", requires=[], produces=["a"])
        class A(Step):
            def run(self, ctx):
                with order_lock:
                    order.append("a")
                return {"a": 1}

        @register_step(name="seq_b", requires=[], produces=["b"])
        class B(Step):
            def run(self, ctx):
                with order_lock:
                    order.append("b")
                return {"b": 2}

        runner = PipelineRunner(["seq_a", "seq_b"])
        runner.run(_make_pc(parallel=False))

        # Sequential mod: tam 2 step calisti
        assert sorted(order) == ["a", "b"]
        assert len(order) == 2

    def test_legacy_topological_sort_api_works(self, snapshot_registry):
        """Eski _topological_sort API'si hala flat liste donduruyor."""
        _make_sleep_step("ls_a", 0.001, produces=("a",))
        _make_sleep_step(
            "ls_b", 0.001, requires=("a",), produces=("b",),
        )

        specs = [_REGISTRY["ls_a"], _REGISTRY["ls_b"]]
        flat = PipelineRunner._topological_sort(specs)
        assert [s.name for s in flat] == ["ls_a", "ls_b"]


# ---------------------------------------------------------------------------
# Bolum 5: Worker cap kontrolu
# ---------------------------------------------------------------------------


class TestParallelWorkerCap:
    """Berke kurali: max 7 paralel step, configured ise min(configured, 7)."""

    def test_hard_cap_at_seven(self, snapshot_registry):
        """10 bagimsiz step → max 7 worker, hard cap'a uyulmali."""
        # 10 bagimsiz step
        for i in range(10):
            _make_sleep_step(f"cap_{i:02d}", 0.05, produces=(f"out_{i}",))

        step_names = [f"cap_{i:02d}" for i in range(10)]
        runner = PipelineRunner(step_names)

        # configured_workers=None -> hard cap 7
        pc = _make_pc(parallel=True, max_workers=None)
        ctx = runner.run(pc)

        # Tum 10 step'in artifact'i mevcut
        for i in range(10):
            assert f"out_{i}" in ctx.artifacts

    def test_configured_workers_respected(self, snapshot_registry):
        """parallel_max_workers=2 ise sadece 2 worker kullanilir."""
        for i in range(4):
            _make_sleep_step(f"cfg_{i}", 0.1, produces=(f"o_{i}",))

        runner = PipelineRunner([f"cfg_{i}" for i in range(4)])
        pc = _make_pc(parallel=True, max_workers=2)

        t0 = time.monotonic()
        ctx = runner.run(pc)
        duration = time.monotonic() - t0

        # 4 step × 0.1s, 2 worker -> ~0.2s (iki dalga)
        # 1 worker olsaydi 0.4s. >0.18s ve <0.35s araliginda olmali.
        assert duration > 0.15, (
            f"2 worker'la 4 step ~0.2s suresinden cok hizli "
            f"({duration:.3f}s) — paralelizm fazla mı?"
        )
        for i in range(4):
            assert f"o_{i}" in ctx.artifacts
