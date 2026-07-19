"""Saglamlik (robustness) fix regresyon testleri -- R1, R2, R4.

Bu testler asagidaki sozlesme degisikliklerini kilitler:

R1  StageResult.skipped alani + PipelineResult success/failed/skipped mantigi
    + JSONReporter skipped_stages ayrimi + DynamicAnalysisStage skip yolu.
    Motivasyon: her statik analiz pipeline.success=False raporluyordu cunku
    dinamik (Frida) asamasi cross-arch/yabanci binary'yi spawn edemeyip
    success=False donuyordu. Artik bu ATLANMA (skipped) sayilir, pipeline'i
    FAILED yapmaz.

R2  BSim idempotent ingest guard'inin (_exe_already_ingested) guvenli
    degradasyonu (PyGhidra JVM disinda False doner -> eski kor-ingest korunur).

R4  --no-lmdb-sigdb CLI flag'i (default use_lmdb_sigdb=True oldugundan asil
    anlamli override budur).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import PipelineResult, StageResult
from karadul.core.target import TargetDetector
from karadul.core.workspace import Workspace
from karadul.reporting.json_report import JSONReporter
from karadul.stages import DynamicAnalysisStage


_CAT_FIXTURE = (
    Path(__file__).parent
    / "fixtures" / "coreutils" / "binaries" / "stripped" / "cat"
)


# ---------------------------------------------------------------------------
# R1: StageResult.skipped sozlesmesi
# ---------------------------------------------------------------------------

class TestStageResultSkippedContract:
    def test_skipped_defaults_false(self) -> None:
        sr = StageResult(stage_name="s", success=True, duration_seconds=1.0)
        assert sr.skipped is False

    def test_to_dict_includes_skipped(self) -> None:
        sr = StageResult(stage_name="dynamic", success=False,
                         duration_seconds=0.2, skipped=True)
        d = sr.to_dict()
        assert d["skipped"] is True
        assert d["success"] is False

    def test_from_dict_roundtrip(self) -> None:
        sr = StageResult(stage_name="dynamic", success=False,
                         duration_seconds=0.2, skipped=True,
                         stats={"skip_reason": "no frida"})
        back = StageResult.from_dict(sr.to_dict())
        assert back.skipped is True
        assert back.success is False
        assert back.stats["skip_reason"] == "no frida"

    def test_from_dict_backward_compat_no_skipped_key(self) -> None:
        # Eski raporlarda "skipped" alani yok -> False'a duser (patlamamali).
        legacy = {
            "stage_name": "static",
            "success": True,
            "duration_seconds": 3.0,
        }
        sr = StageResult.from_dict(legacy)
        assert sr.skipped is False
        assert sr.success is True

    def test_summary_shows_skip(self) -> None:
        sr = StageResult(stage_name="dynamic", success=False,
                         duration_seconds=0.1, skipped=True)
        assert sr.summary().startswith("[SKIP]")
        ok = StageResult(stage_name="static", success=True, duration_seconds=1.0)
        assert ok.summary().startswith("[OK]")
        bad = StageResult(stage_name="x", success=False, duration_seconds=1.0)
        assert bad.summary().startswith("[FAIL]")


# ---------------------------------------------------------------------------
# R1: PipelineResult success/failed/skipped mantigi
# ---------------------------------------------------------------------------

class TestPipelineResultSkippedLogic:
    def _pr_with_skip(self) -> PipelineResult:
        pr = PipelineResult(target_name="cat", target_hash="abc")
        pr.add_stage_result(StageResult("identify", True, 0.1))
        pr.add_stage_result(StageResult("static", True, 1.0))
        pr.add_stage_result(StageResult("dynamic", False, 0.2, skipped=True,
                                        stats={"skip_reason": "cross-arch"}))
        pr.add_stage_result(StageResult("report", True, 0.2))
        return pr

    def test_skipped_stage_does_not_fail_pipeline(self) -> None:
        pr = self._pr_with_skip()
        assert pr.success is True

    def test_get_failed_stages_excludes_skipped(self) -> None:
        pr = self._pr_with_skip()
        assert pr.get_failed_stages() == []

    def test_get_skipped_stages(self) -> None:
        pr = self._pr_with_skip()
        assert pr.get_skipped_stages() == ["dynamic"]

    def test_real_failure_still_fails_pipeline(self) -> None:
        pr = PipelineResult(target_name="x", target_hash="y")
        pr.add_stage_result(StageResult("identify", True, 0.1))
        pr.add_stage_result(StageResult("static", False, 1.0,
                                        errors=["boom"]))  # gercek hata
        assert pr.success is False
        assert pr.get_failed_stages() == ["static"]
        assert pr.get_skipped_stages() == []

    def test_summary_lists_skipped_separately(self) -> None:
        s = self._pr_with_skip().summary()
        assert "SUCCESS" in s
        assert "Skipped: dynamic" in s
        assert "Failed:" not in s


# ---------------------------------------------------------------------------
# R1: JSONReporter skipped_stages ayrimi
# ---------------------------------------------------------------------------

class TestJSONReporterSkipped:
    def test_skipped_stages_separated_from_failed(self, tmp_path: Path) -> None:
        ws = Workspace(base_dir=tmp_path / "ws", target_name="cat")
        ws.create()
        pr = PipelineResult(target_name="cat", target_hash="abc",
                            workspace_path=ws.path)
        pr.add_stage_result(StageResult("identify", True, 0.1))
        pr.add_stage_result(StageResult("static", True, 1.0))
        pr.add_stage_result(StageResult("dynamic", False, 0.2, skipped=True,
                                        stats={"skip_reason": "cross-arch"}))

        import json
        report_path = JSONReporter().generate(pr, ws)
        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert data["pipeline"]["success"] is True
        assert data["summary"]["skipped_stages"] == ["dynamic"]
        assert data["summary"]["failed_stages"] == []
        assert data["pipeline"]["stages"]["dynamic"]["skipped"] is True
        assert data["pipeline"]["stages"]["dynamic"]["success"] is False


# ---------------------------------------------------------------------------
# R1: DynamicAnalysisStage Frida yokken ATLANIR (skipped, hata degil)
# ---------------------------------------------------------------------------

class TestDynamicStageSkip:
    def test_skipped_helper(self) -> None:
        sr = DynamicAnalysisStage()._skipped(0.0, "test reason")
        assert sr.skipped is True
        assert sr.success is False
        assert sr.stats["skip_reason"] == "test reason"
        assert sr.errors == []  # skip bir hata degil -> errors bos

    @pytest.mark.skipif(not _CAT_FIXTURE.exists(), reason="cat fixture yok")
    def test_frida_unavailable_yields_skipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        # Frida'yi "kurulu degil" gostererek deterministik skip yolu tetikle.
        import karadul.frida.session as fsession
        monkeypatch.setattr(fsession, "FRIDA_AVAILABLE", False)

        cfg = Config()
        cfg.project_root = tmp_path
        tinfo = TargetDetector().detect(_CAT_FIXTURE)
        ws = Workspace(base_dir=tmp_path / "ws", target_name=tinfo.name)
        ws.create()
        ctx = PipelineContext(target=tinfo, workspace=ws, config=cfg)

        sr = DynamicAnalysisStage().execute(ctx)
        assert sr.skipped is True
        assert sr.success is False
        assert "skip_reason" in sr.stats


# ---------------------------------------------------------------------------
# R2: BSim idempotent ingest guard guvenli degradasyon
# ---------------------------------------------------------------------------

class TestBSimIdempotentGuard:
    def test_exe_already_ingested_safe_without_ghidra(self) -> None:
        # PyGhidra JVM disinda QueryExeInfo import edilemez -> guard False
        # doner (eski kor-ingest davranisi korunur, patlamamali).
        from karadul.ghidra.bsim import _BSimNativeWrapper
        wrapper = _BSimNativeWrapper(Path("/tmp/does-not-matter"))

        class _FakeProgram:
            def getExecutableMD5(self):  # noqa: N802 (Ghidra API adi)
                return "deadbeef"

        result = wrapper._exe_already_ingested(object(), _FakeProgram())
        assert result is False

    def test_guard_method_exists(self) -> None:
        from karadul.ghidra.bsim import _BSimNativeWrapper
        assert hasattr(_BSimNativeWrapper, "_exe_already_ingested")


# ---------------------------------------------------------------------------
# R4: --no-lmdb-sigdb CLI flag'i
# ---------------------------------------------------------------------------

class TestNoLmdbSigdbFlag:
    def test_option_registered(self) -> None:
        from karadul.cli import analyze
        names = {p.name for p in analyze.params}
        assert "no_lmdb_sigdb" in names
        assert "lmdb_sigdb" in names  # eski flag geriye uyum icin duruyor

    def test_help_shows_no_lmdb_sigdb(self) -> None:
        from click.testing import CliRunner
        from karadul.cli import analyze
        out = CliRunner().invoke(analyze, ["--help"]).output
        assert "--no-lmdb-sigdb" in out
        assert "--lmdb-sigdb" in out
