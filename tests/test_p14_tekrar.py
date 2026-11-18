"""P14 / BORU-06: belirlenimci hata aşamayı yeniden koşturmaz; adım hatası iki kipte aynı türle.

Eski davranış (gösterim ``~/karadul_olcum/runs/onarim-2026-11-18/P14/goster/``):
KeyError fırlatan bir aşama 4 kez (1 + ``max_retries``) baştan koşuyordu; tekli düzeyde
(``parallel_steps=False`` ya da düzeyde tek adım) adımın KeyError'ı özgün türüyle çıkıyor,
``stages.py``'nin ``except RuntimeError``'ı yakalamıyor ve aşama yeniden deneme döngüsüne
düşüyordu.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config, RetryConfig
from karadul.core.error_recovery import ErrorRecovery
from karadul.core.pipeline import Pipeline, Stage
from karadul.core.result import StageResult
from karadul.pipeline.registry import Step, _REGISTRY, register_step


def _fast_retry(max_retries: int = 3) -> RetryConfig:
    return RetryConfig(max_retries=max_retries, base_delay=0.001, max_delay=0.002,
                       circuit_breaker_threshold=50, circuit_breaker_reset=60.0)


class _Counter:
    def __init__(self, exc: BaseException | None, succeed_on: int | None = None) -> None:
        self.n = 0
        self.exc = exc
        self.succeed_on = succeed_on

    def __call__(self) -> str:
        self.n += 1
        if self.succeed_on is not None and self.n >= self.succeed_on:
            return "ok"
        assert self.exc is not None
        raise self.exc


class TestErrorRecoveryTransientOnly:
    @pytest.mark.parametrize("exc", [
        KeyError("k"), TypeError("t"), ValueError("v"), RuntimeError("r"),
        FileNotFoundError("f"), subprocess.TimeoutExpired(["ghidra"], 1),
    ])
    def test_deterministic_error_runs_once(self, exc) -> None:
        er = ErrorRecovery(_fast_retry(3))
        op = _Counter(exc)
        with pytest.raises(type(exc)):
            er.execute(op, "op")
        assert op.n == 1

    @pytest.mark.parametrize("exc", [
        ConnectionResetError("c"), TimeoutError("t"), BlockingIOError("b"),
        InterruptedError("i"),
    ])
    def test_transient_error_retried_up_to_limit(self, exc) -> None:
        er = ErrorRecovery(_fast_retry(2))
        op = _Counter(exc)
        with pytest.raises(type(exc)):
            er.execute(op, "op")
        assert op.n == 3  # 1 + max_retries

    def test_transient_then_success(self) -> None:
        er = ErrorRecovery(_fast_retry(3))
        op = _Counter(ConnectionError("x"), succeed_on=2)
        assert er.execute(op, "op") == "ok"
        assert op.n == 2

    def test_deterministic_failure_still_counts_for_breaker(self) -> None:
        cfg = RetryConfig(max_retries=3, base_delay=0.001, max_delay=0.002,
                          circuit_breaker_threshold=1, circuit_breaker_reset=60.0)
        er = ErrorRecovery(cfg)
        with pytest.raises(KeyError):
            er.execute(_Counter(KeyError("k")), "op")
        assert er.get_stats()["breakers"]["op"]["failure_count"] == 1

    def test_custom_retryable(self) -> None:
        er = ErrorRecovery(_fast_retry(2), retryable_exceptions=(KeyError,))
        op = _Counter(KeyError("k"))
        with pytest.raises(KeyError):
            er.execute(op, "op")
        assert op.n == 3

    def test_transient_set_is_narrow(self) -> None:
        from karadul.core.error_recovery import TRANSIENT_EXCEPTIONS

        # OSError'ın tamamı geçici değil (dosya yok / izin yok belirlenimci).
        assert OSError not in TRANSIENT_EXCEPTIONS
        assert not issubclass(FileNotFoundError, TRANSIENT_EXCEPTIONS)
        assert not issubclass(subprocess.TimeoutExpired, TRANSIENT_EXCEPTIONS)


class _CountingStage(Stage):
    name = "static"

    def __init__(self, exc: BaseException | None, succeed_on: int | None = None) -> None:
        self.calls = 0
        self.exc = exc
        self.succeed_on = succeed_on

    def execute(self, context):
        self.calls += 1
        if self.succeed_on is not None and self.calls >= self.succeed_on:
            return StageResult(stage_name=self.name, success=True, duration_seconds=0.0)
        raise self.exc


def _run_pipeline(tmp_path: Path, stage: Stage):
    cfg = Config()
    cfg.retry = _fast_retry(3)
    cfg.project_root = tmp_path
    target = tmp_path / "hedef.bin"
    target.write_bytes(b"\x7fELF" + b"\0" * 60)
    p = Pipeline(cfg)
    p.register_stage(stage)
    return p.run(target, on_stage_start=lambda *a: None)


class TestPipelineStageRetry:
    def test_keyerror_stage_runs_once_and_fails(self, tmp_path) -> None:
        stage = _CountingStage(KeyError("eksik_anahtar"))
        res = _run_pipeline(tmp_path, stage)
        assert stage.calls == 1
        assert res.success is False
        sr = res.stages["static"]
        assert sr.success is False
        assert any("KeyError" in e and "eksik_anahtar" in e for e in sr.errors)

    def test_transient_stage_retried(self, tmp_path) -> None:
        stage = _CountingStage(ConnectionError("ag"), succeed_on=2)
        res = _run_pipeline(tmp_path, stage)
        assert stage.calls == 2
        assert res.stages["static"].success is True


@pytest.fixture
def boom_step():
    name = "_p14_keyerror_step"

    @register_step(name=name, requires=[], produces=["p14_x"])
    class _Boom(Step):
        def run(self, ctx):
            raise KeyError("adim_anahtari")

    try:
        yield name
    finally:
        _REGISTRY.pop(name, None)


def _pc(parallel: bool):
    return SimpleNamespace(
        metadata={},
        config=SimpleNamespace(pipeline=SimpleNamespace(
            parallel_steps=parallel, parallel_max_workers=None)),
    )


class TestRunnerUniformError:
    @pytest.mark.parametrize("parallel", [False, True])
    def test_single_level_keyerror_is_runtime_error(self, boom_step, parallel) -> None:
        from karadul.pipeline.runner import PipelineRunner, StepFailedError

        with pytest.raises(RuntimeError) as ei:
            PipelineRunner([boom_step]).run(_pc(parallel))
        assert isinstance(ei.value, StepFailedError)
        assert ei.value.step_name == boom_step
        assert isinstance(ei.value.__cause__, KeyError)
        assert "adim_anahtari" in str(ei.value)

    def test_parallel_level_error_same_type(self, boom_step) -> None:
        from karadul.pipeline.runner import PipelineRunner, StepFailedError

        @register_step(name="_p14_ok_step", requires=[], produces=["p14_y"])
        class _Ok(Step):
            def run(self, ctx):
                return {"p14_y": 1}

        try:
            with pytest.raises(StepFailedError) as ei:
                PipelineRunner([boom_step, "_p14_ok_step"]).run(_pc(True))
            assert ei.value.step_name == boom_step
            assert isinstance(ei.value.__cause__, KeyError)
        finally:
            _REGISTRY.pop("_p14_ok_step", None)


class _Artifacts(dict):
    def __missing__(self, key: str):
        return None


def test_reconstruct_phase3_keyerror_is_stage_failure(tmp_path, monkeypatch, boom_step) -> None:
    """Faz 3'te tekli düzeyde KeyError: aşama istisnayla kaçmaz, ``success=False`` döner."""
    import karadul.pipeline.runner as runner_mod
    from karadul.stages import ReconstructionStage

    real_runner = runner_mod.PipelineRunner
    decompiled = tmp_path / "static" / "decompiled"
    decompiled.mkdir(parents=True)
    ok_naming = SimpleNamespace(success=True, errors=[])

    class _FakeRunner:
        def __init__(self, steps):
            self.steps = list(steps)

        def run(self, context, seed_artifacts=None):
            if "feedback_loop" in self.steps:
                final_dir = tmp_path / "loop_final"
                final_dir.mkdir(exist_ok=True)
                return SimpleNamespace(
                    artifacts={"naming_result": ok_naming, "computation_result": None,
                               "updated_algo_result": None, "updated_eng_result": None,
                               "final_decompiled_dir": final_dir},
                    stats={}, errors=[], stage_artifacts={})
            if "finalize" in self.steps:
                # Faz 3: GERÇEK koşucu, KeyError fırlatan tek adımlı düzey.
                return real_runner([boom_step]).run(context, seed_artifacts=seed_artifacts)
            return SimpleNamespace(
                artifacts=_Artifacts(c_files=[], decompiled_dir=decompiled, extracted_names={}),
                stats={}, errors=[], stage_artifacts={})

    monkeypatch.setattr(runner_mod, "PipelineRunner", _FakeRunner)

    def stage_dir(stage: str) -> Path:
        d = tmp_path / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    pc = SimpleNamespace(
        target=SimpleNamespace(path=tmp_path / "ikili", file_hash=""),
        workspace=SimpleNamespace(get_stage_dir=stage_dir, path=tmp_path),
        config=Config(), metadata={}, report_progress=lambda *a, **k: None,
    )
    res = ReconstructionStage()._execute_binary(pc, time.monotonic())
    assert res.success is False
    assert any(boom_step in e and "KeyError" in e for e in res.errors), res.errors
