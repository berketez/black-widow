"""P14 / BORU-07: `karadul batch` hedef durumu, özeti ve çıkış kodu dürüst; işçi çökmesi yalıtılmış.

Eski davranış (gösterim ``~/karadul_olcum/runs/onarim-2026-11-18/P14/goster/boru07_*``):
``success = pipeline_result.success or any(aşama başarılı)``; ``identify`` koşulsuz başarılı
olduğu için statik aşaması düşen hedef BAŞARILI sayılıyordu, kısmi ayrı görünmüyordu. Bir
işçi süreci sert ölünce (``os._exit``) 5 hedefin 5'i düşüyordu.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from karadul import batch
from karadul.core.result import PipelineResult, StageResult


def _result(*stages: StageResult) -> PipelineResult:
    pr = PipelineResult(target_name="t", target_hash="", workspace_path=Path("/tmp/x"))
    for sr in stages:
        pr.add_stage_result(sr)
    return pr


IDENT = StageResult("identify", True, 0.1)
STATIC_OK = StageResult("static", True, 1.0)
STATIC_FAIL = StageResult("static", False, 1.0, errors=["Ghidra analizi basarisiz: zaman asimi"])
RECON_OK = StageResult("reconstruct", True, 1.0)
RECON_PARTIAL = StageResult("reconstruct", True, 1.0,
                            stats={"partial": True, "partial_reasons": ["Semantic naming hatasi"]},
                            errors=["Semantic naming hatasi"])
DYN_SKIP = StageResult("dynamic", False, 0.0, skipped=True, stats={"skip_reason": "frida yok"})
# P-S1: aşama yalnız bayrakla kısmi (errors boş) — kural partial_reasons'ı da okumalı.
RECON_PARTIAL_FLAG = StageResult("reconstruct", True, 1.0,
                                 stats={"partial": True, "partial_reasons": ["proje eksik"]})

CASES = {
    "static_dustu": (_result(IDENT, STATIC_FAIL), "basarisiz"),
    "kismi": (_result(IDENT, STATIC_OK, RECON_PARTIAL), "kismi"),
    "kismi_yalniz_bayrak": (_result(IDENT, STATIC_OK, RECON_PARTIAL_FLAG), "kismi"),
    "tam": (_result(IDENT, STATIC_OK, RECON_OK), "tam"),
    "tam_atlanan_asamayla": (_result(IDENT, STATIC_OK, DYN_SKIP, RECON_OK), "tam"),
    "asama_yok": (_result(), "basarisiz"),
}


def _single(tmp_path: Path, pr: PipelineResult):
    target = tmp_path / "ikili"
    target.write_bytes(b"\x7fELF")
    with patch("karadul.core.pipeline.Pipeline.run", return_value=pr):
        return batch.analyze_single_target("hedef", str(target), tmp_path)


class TestTargetStatus:
    @pytest.mark.parametrize("case", sorted(CASES))
    def test_status_matches_analyze_rule(self, tmp_path, case) -> None:
        pr, expected = CASES[case]
        r = _single(tmp_path, pr)
        assert getattr(r, "status", None) == expected
        assert r.success is (expected != "basarisiz")

    def test_failed_static_is_not_success(self, tmp_path) -> None:
        r = _single(tmp_path, _result(IDENT, STATIC_FAIL))
        assert r.success is False
        assert "static" in r.failure_reasons
        assert r.to_dict()["status"] == "basarisiz"

    def test_partial_reasons_carried(self, tmp_path) -> None:
        r = _single(tmp_path, _result(IDENT, STATIC_OK, RECON_PARTIAL))
        assert r.partial_reasons == {"reconstruct": ["Semantic naming hatasi"]}

    def test_pipeline_exception_is_failed(self, tmp_path) -> None:
        target = tmp_path / "ikili"
        target.write_bytes(b"\x7fELF")
        with patch("karadul.core.pipeline.Pipeline.run", side_effect=RuntimeError("patladi")):
            r = batch.analyze_single_target("hedef", str(target), tmp_path)
        assert r.success is False and r.status == "basarisiz"
        assert "patladi" in r.failure_reasons["pipeline"][0]

    def test_missing_target_skipped(self, tmp_path) -> None:
        r = batch.analyze_single_target("hedef", str(tmp_path / "yok"), tmp_path)
        assert r.skipped is True and r.status == "atlandi" and r.success is False


class TestSingleSourceRule:
    """``analyze`` (cli._analysis_outcome) ile ``batch`` aynı kuralı kullanmalı."""

    @pytest.mark.parametrize("case", sorted(CASES))
    def test_cli_and_core_agree(self, case) -> None:
        from karadul.cli import _analysis_outcome
        from karadul.core.pipeline import analysis_outcome

        pr, _ = CASES[case]
        assert analysis_outcome(pr) == _analysis_outcome(pr)

    def test_finalize_uses_same_strings(self) -> None:
        from karadul.core import pipeline as core
        from karadul.pipeline.steps import finalize

        assert (finalize.OUTCOME_COMPLETE, finalize.OUTCOME_PARTIAL, finalize.OUTCOME_FAILED) == (
            core.OUTCOME_COMPLETE, core.OUTCOME_PARTIAL, core.OUTCOME_FAILED)


def _r(status: str, skipped: bool = False) -> batch.BatchTargetResult:
    return batch.BatchTargetResult(name=status, path="/x", category="x",
                                   success=status in ("tam", "kismi"),
                                   status=status, skipped=skipped)


class TestSummary:
    @pytest.mark.parametrize("statuses, code, counts", [
        (["tam", "tam"], 0, (2, 0, 0, 0)),
        (["tam", "kismi"], 3, (1, 1, 0, 0)),
        (["tam", "atlandi"], 3, (1, 0, 0, 1)),
        (["tam", "basarisiz", "kismi"], 1, (1, 1, 1, 0)),
        (["atlandi", "atlandi"], 1, (0, 0, 0, 2)),
        ([], 1, (0, 0, 0, 0)),
    ])
    def test_exit_code_and_counts(self, statuses, code, counts) -> None:
        results = [_r(s, skipped=(s == "atlandi")) for s in statuses]
        s = batch.batch_summary(results)
        assert s["exit_code"] == code
        assert (s["complete"], s["partial"], s["failed"], s["skipped"]) == counts
        assert s["successful"] == counts[0] + counts[1]
        assert s["total_targets"] == len(statuses)


# --- işçi çökmesi (süreç havuzu) --------------------------------------------

def _crashing_worker(args):
    """Üst düzey (süreç havuzuna gönderilebilir): 'olen' hedefi süreci sert öldürür."""
    name, path_str = args[0], args[1]
    if name == "olen":
        os._exit(9)
    time.sleep(0.3)
    return batch.BatchTargetResult(name=name, path=path_str, category="x",
                                   success=True, status="tam")


class TestWorkerCrashIsolated:
    def test_only_crashing_target_fails(self, tmp_path) -> None:
        targets = {"olen": "/x/olen", "a": "/x/a", "b": "/x/b", "c": "/x/c", "e": "/x/e"}
        seen: list[str] = []
        results = batch.analyze_parallel(targets, tmp_path, max_workers=3,
                                         callback=lambda r: seen.append(r.name),
                                         worker=_crashing_worker)
        assert [r.name for r in results] == list(targets)  # hedef sırası korunur
        by_name = {r.name: r for r in results}
        assert by_name["olen"].success is False
        assert by_name["olen"].status == "basarisiz"
        assert "BrokenProcessPool" in by_name["olen"].errors[0]
        assert all(by_name[n].success and by_name[n].status == "tam" for n in "abce")
        assert sorted(seen) == sorted(targets)  # her hedef için bir kez
