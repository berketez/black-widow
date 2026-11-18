"""P14 / BORU-07: `karadul batch analyze` satırları, özet tablosu, rapor ve çıkış kodu dürüst.

Bu test `yamalar/P14__cli.py.patch` ile birlikte gelir (cli.py P14'ün dosyası değil).
Eski davranış: her hedef BAŞARILI / OK, `batch_report.json`'da kısmi yok, çıkış her zaman 0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul import batch
from karadul.cli import main as karadul_main


def _r(name: str, status: str, skipped: bool = False, **kw) -> batch.BatchTargetResult:
    return batch.BatchTargetResult(name=name, path=f"/x/{name}", category="binary",
                                   success=status in ("tam", "kismi"), status=status,
                                   skipped=skipped, **kw)


def _invoke(tmp_path: Path, monkeypatch, results: list[batch.BatchTargetResult]):
    monkeypatch.setattr(batch, "resolve_targets", lambda spec: {r.name: r.path for r in results})

    def fake_parallel(targets, project_root, skip_dynamic=True, max_workers=None,
                      callback=None, worker=None, config_path=None):
        for r in results:
            if callback:
                callback(r)
        return list(results)

    monkeypatch.setattr(batch, "analyze_parallel", fake_parallel)
    res = CliRunner().invoke(karadul_main, [
        "batch", "analyze", "--targets", "x", "--output-dir", str(tmp_path)])
    report = json.loads((tmp_path / "workspaces" / "batch_report.json").read_text())
    return res, report


@pytest.mark.parametrize("statuses, code", [
    (["tam", "tam"], 0),
    (["tam", "kismi"], 3),
    (["tam", "basarisiz"], 1),
    (["tam", "atlandi"], 3),
])
def test_exit_code_matches_summary(tmp_path, monkeypatch, statuses, code) -> None:
    results = [
        _r(f"h{i}", s, skipped=(s == "atlandi"),
           failure_reasons={"static": ["Ghidra dustu"]} if s == "basarisiz" else {},
           partial_reasons={"reconstruct": ["Semantic naming hatasi"]} if s == "kismi" else {})
        for i, s in enumerate(statuses)
    ]
    res, report = _invoke(tmp_path, monkeypatch, results)
    assert res.exit_code == code, res.output
    assert report["exit_code"] == code
    assert [r["status"] for r in report["results"]] == statuses


def test_failed_target_not_shown_as_success(tmp_path, monkeypatch) -> None:
    results = [_r("discord", "basarisiz", failure_reasons={"static": ["Ghidra dustu"]}),
               _r("poe", "kismi", partial_reasons={"reconstruct": ["Semantic naming hatasi"]})]
    res, report = _invoke(tmp_path, monkeypatch, results)
    out = res.output
    assert "discord: BASARISIZ" in out
    assert "poe: KISMI" in out
    assert "BASARILI" not in out
    assert "Ghidra dustu" in out          # neden stderr'de (CliRunner birleştirir)
    assert (report["complete"], report["partial"], report["failed"]) == (0, 1, 1)
