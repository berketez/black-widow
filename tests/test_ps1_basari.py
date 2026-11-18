"""P-S1 kalem 5 (BORU-05): ``reconstruct`` aşamasının başarı bayrağı.

Eskiden ``success = len(artifacts) > 0`` idi; anti_debug adımı JSON'unu her
koşulda yapıt olarak yazdığı için bayrak fiilen hep True'ydu: proje kurulamamış,
adlandırma çökmüş koşu ``reconstruct: OK`` görünüyordu. Ölçüt artık: proje
kuruldu (``project_dir`` yapıtı) VE C adlandırma hatasız; başarılı ama bir adımı
hata bildirmiş koşu ``partial`` (+ nedenler).

Uçtan uca sınama ``_execute_binary``'nin gerçek üç fazlı akışıyla yapılır
(Ghidra yok; koşucular sahte, ``project_build`` ve ``finalize`` GERÇEK adım).
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import Config
from karadul.core.result import StageResult
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.finalize import (
    FinalizeStep,
    c_naming_enabled,
    reconstruct_outcome,
)
from karadul.pipeline.steps.project_build import ProjectBuildStep
from karadul.stages import ReconstructionStage, _finalize_binary_outcome

OK_NAMING = SimpleNamespace(success=True, errors=[])


# ---------------------------------------------------------------------------
# Olcut (saf islev)
# ---------------------------------------------------------------------------

class TestOutcome:
    def test_complete(self) -> None:
        o = reconstruct_outcome(artifacts={"project_dir": Path("/p")}, errors=[],
                                naming_result=OK_NAMING, naming_enabled=True)
        assert o["success"] is True
        assert o["stats"]["reconstruct_status"] == "tam"
        assert o["stats"]["partial"] is False
        assert o["stats"]["partial_reasons"] == []
        assert o["stats"]["reconstruct_failure_reasons"] == []
        assert o["stats"]["reconstruct_naming_status"] == "calisti"

    def test_errors_make_partial_dedup_capped(self) -> None:
        errs = ["struct hatasi"] * 3 + [f"h{i}" for i in range(30)]
        o = reconstruct_outcome(artifacts={"project_dir": Path("/p")}, errors=errs,
                                naming_result=OK_NAMING, naming_enabled=True)
        assert o["success"] is True
        assert o["stats"]["reconstruct_status"] == "kismi"
        assert o["stats"]["partial"] is True
        assert o["stats"]["partial_reasons"][0] == "struct hatasi"
        assert len(o["stats"]["partial_reasons"]) == 20
        assert o["stats"]["reconstruct_error_count"] == 33

    def test_only_anti_debug_artifact_is_failure(self) -> None:
        """BORU-05'in cekirdegi: yapit var ama proje yok -> basarisiz."""
        o = reconstruct_outcome(
            artifacts={"anti_debug_findings": Path("/s/a.json")}, errors=[],
            naming_result=OK_NAMING, naming_enabled=True)
        assert o["success"] is False
        assert o["stats"]["reconstruct_status"] == "basarisiz"
        assert o["stats"]["reconstruct_project_built"] is False
        assert "project_dir" in o["stats"]["reconstruct_failure_reasons"][0]
        assert o["stats"]["partial"] is False

    def test_naming_missing_is_failure(self) -> None:
        o = reconstruct_outcome(artifacts={"project_dir": Path("/p")}, errors=[],
                                naming_result=None, naming_enabled=True)
        assert o["success"] is False
        assert o["stats"]["reconstruct_naming_status"] == "hata"
        assert "sonuc vermedi" in o["stats"]["reconstruct_failure_reasons"][0]

    def test_naming_failed_reason_carried(self) -> None:
        bad = SimpleNamespace(success=False, errors=["Hicbir fonksiyon bilgisi yuklenemedi"])
        o = reconstruct_outcome(artifacts={"project_dir": Path("/p")}, errors=[],
                                naming_result=bad, naming_enabled=True)
        assert o["success"] is False
        assert "Hicbir fonksiyon bilgisi" in o["stats"]["reconstruct_failure_reasons"][0]

    def test_naming_disabled_is_not_failure(self) -> None:
        o = reconstruct_outcome(artifacts={"project_dir": Path("/p")}, errors=[],
                                naming_result=None, naming_enabled=False)
        assert o["success"] is True
        assert o["stats"]["reconstruct_naming_status"] == "kapali"

    def test_c_naming_flag_reading(self) -> None:
        cfg = Config()
        assert c_naming_enabled(cfg) is True
        cfg.binary_reconstruction.enable_c_naming = False
        assert c_naming_enabled(cfg) is False


# ---------------------------------------------------------------------------
# Adimlar
# ---------------------------------------------------------------------------

def _finalize_ctx(**artifacts: Any) -> StepContext:
    pc = MagicMock()
    pc.config = Config()
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        "deep_tracing_result": {}, "engineering_analysis_result": None,
        "project_dir": None, "__stage_name": "reconstruct",
        "__pipeline_start": time.monotonic(), **artifacts,
    })
    return ctx


class TestFinalizeStep:
    def test_artifact_without_project_is_not_success(self) -> None:
        ctx = _finalize_ctx(naming_result=OK_NAMING)
        ctx.produce_artifact("anti_debug_findings", Path("/s/anti_debug_findings.json"))
        sr = FinalizeStep().run(ctx)["stage_result"]
        assert sr.success is False  # eskiden: len(artifacts) > 0 -> True
        assert sr.stats["reconstruct_status"] == "basarisiz"

    def test_project_and_naming_ok(self) -> None:
        ctx = _finalize_ctx(naming_result=OK_NAMING)
        ctx.produce_artifact("project_dir", Path("/r/project"))
        sr = FinalizeStep().run(ctx)["stage_result"]
        assert sr.success is True
        assert sr.stats["reconstruct_status"] == "tam"


class TestProjectBuildStep:
    def _run(self, tmp_path: Path, build):
        pc = MagicMock()
        rec = tmp_path / "reconstructed"
        rec.mkdir()
        pc.workspace.get_stage_dir = MagicMock(return_value=rec)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"engineering_annotation_decompiled_dir": tmp_path / "d",
                              "algo_result": None})
        cls = MagicMock()
        if isinstance(build, Exception):
            cls.return_value.build.side_effect = build
        else:
            cls.return_value.build.return_value = build
        with patch("karadul.reconstruction.c_project_builder.CProjectBuilder", cls):
            out = ProjectBuildStep().run(ctx)
        return out, ctx

    def test_failed_build_returns_no_dir_and_records(self, tmp_path) -> None:
        from karadul.reconstruction.c_project_builder import CProjectBuildResult
        out, ctx = self._run(tmp_path, CProjectBuildResult(success=False, files_written=0))
        assert out["project_dir"] is None  # eskiden yol donuyordu
        assert "project_dir" not in ctx.stage_artifacts
        assert ctx.stats["project_build_status"] == "hata"
        assert any("neden bildirmedi" in e for e in ctx.errors)

    def test_builder_errors_not_duplicated(self, tmp_path) -> None:
        from karadul.reconstruction.c_project_builder import CProjectBuildResult
        out, ctx = self._run(tmp_path, CProjectBuildResult(
            success=False, files_written=2, errors=["Değişmez ihlali: 1 fonksiyon yok"]))
        assert ctx.errors == ["C project build: Değişmez ihlali: 1 fonksiyon yok"]
        assert ctx.stats["project_build_status"] == "hata"

    def test_exception_status(self, tmp_path) -> None:
        out, ctx = self._run(tmp_path, OSError("disk dolu"))
        assert out["project_dir"] is None
        assert ctx.stats["project_build_status"] == "hata"
        assert "disk dolu" in ctx.stats["project_build_status_reason"]

    def test_success_status(self, tmp_path) -> None:
        from karadul.reconstruction.c_project_builder import CProjectBuildResult
        out, ctx = self._run(tmp_path, CProjectBuildResult(success=True, files_written=3))
        assert out["project_dir"] is not None
        assert ctx.stats["project_build_status"] == "calisti"


# ---------------------------------------------------------------------------
# stages.py: Faz 1/2 hatalari birlesince olcut yeniden uygulanir
# ---------------------------------------------------------------------------

class TestStageMerge:
    def test_phase12_errors_make_partial(self) -> None:
        sr = StageResult(stage_name="reconstruct", success=True, duration_seconds=0.0,
                         artifacts={"project_dir": Path("/p")}, stats={},
                         errors=["Struct recovery hatasi: x"])
        _finalize_binary_outcome(sr, OK_NAMING, Config())
        assert sr.success is True
        assert sr.stats["partial"] is True
        assert sr.stats["partial_reasons"] == ["Struct recovery hatasi: x"]

    def test_naming_failure_from_phase2_fails_stage(self) -> None:
        sr = StageResult(stage_name="reconstruct", success=True, duration_seconds=0.0,
                         artifacts={"project_dir": Path("/p")}, stats={}, errors=[])
        _finalize_binary_outcome(sr, SimpleNamespace(success=False, errors=["C naming hatasi"]),
                                 Config())
        assert sr.success is False


class _Artifacts(dict):
    def __missing__(self, key: str):
        return None


def _execute_binary(tmp_path: Path, monkeypatch, *, naming, build_ok: bool):
    """``_execute_binary`` uc faz; Faz 3'te GERCEK project_build (kurucu taklit) + finalize."""
    import karadul.pipeline.runner as runner_mod
    from karadul.reconstruction.c_project_builder import CProjectBuildResult

    decompiled = tmp_path / "static" / "decompiled"
    decompiled.mkdir(parents=True)

    class _FakeRunner:
        def __init__(self, steps):
            self.steps = list(steps)

        def run(self, context, seed_artifacts=None):
            if "feedback_loop" in self.steps:
                final_dir = tmp_path / "loop_final"
                final_dir.mkdir(exist_ok=True)
                return SimpleNamespace(
                    artifacts={"naming_result": naming, "computation_result": None,
                               "updated_algo_result": None, "updated_eng_result": None,
                               "final_decompiled_dir": final_dir},
                    stats={}, errors=[], stage_artifacts={})
            if "finalize" in self.steps:
                ctx = StepContext(pipeline_context=context)
                ctx._write_artifacts(dict(seed_artifacts))
                ctx._write_artifacts({"engineering_annotation_decompiled_dir": decompiled,
                                      "deep_tracing_result": {},
                                      "engineering_analysis_result": None})
                # anti_debug her kosulda JSON yapiti yazar (BORU-05'in tetikleyicisi)
                ctx.produce_artifact("anti_debug_findings", tmp_path / "ad.json")
                cls = MagicMock()
                cls.return_value.build.return_value = CProjectBuildResult(
                    success=build_ok, files_written=5 if build_ok else 0)
                with patch("karadul.reconstruction.c_project_builder.CProjectBuilder", cls):
                    ctx._write_artifacts(ProjectBuildStep().run(ctx))
                return SimpleNamespace(artifacts=FinalizeStep().run(ctx))
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
    return ReconstructionStage()._execute_binary(pc, time.monotonic())


class TestExecuteBinary:
    def test_failed_project_build_is_stage_failure(self, tmp_path, monkeypatch) -> None:
        res = _execute_binary(tmp_path, monkeypatch, naming=OK_NAMING, build_ok=False)
        assert "anti_debug_findings" in res.artifacts  # yapit var ...
        assert res.success is False                   # ... ama basari yok
        assert res.stats["reconstruct_project_built"] is False
        assert res.stats["project_build_status"] == "hata"

    def test_naming_crash_is_stage_failure(self, tmp_path, monkeypatch) -> None:
        res = _execute_binary(tmp_path, monkeypatch, naming=None, build_ok=True)
        assert res.success is False
        assert res.stats["reconstruct_naming_status"] == "hata"

    def test_healthy_run_is_success(self, tmp_path, monkeypatch) -> None:
        res = _execute_binary(tmp_path, monkeypatch, naming=OK_NAMING, build_ok=True)
        assert res.success is True, res.stats.get("reconstruct_failure_reasons")
        assert res.stats["reconstruct_status"] in ("tam", "kismi")
