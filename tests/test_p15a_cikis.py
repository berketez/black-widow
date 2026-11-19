"""P15a / MEK-01: `karadul analyze` başarısız ya da kısmi analizde çıkış kodu ve hata satırları.

Eski davranış: boru hattı başarısız olsa da (ör. boş dosya: `static` "Analyzer
bulunamadi", `reconstruct` "Deobfuscate edilmis dosya bulunamadi") CLI hiçbir hata
satırı basmıyor, sonuç tablosunu yazıp 0 ile çıkıyordu; `--json`'da da 0.

Çıkış kodları: 0 tam, 1 başarısız, 2 kullanım / ayar hatası, 3 kısmi.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import karadul.cli as cli_mod
from karadul.cli import (
    EXIT_ANALYSIS_FAILED,
    EXIT_ANALYSIS_OK,
    EXIT_ANALYSIS_PARTIAL,
    _analysis_outcome,
    main as karadul_main,
)
from karadul.core.result import PipelineResult, StageResult


def _sr(name: str, success: bool = True, *, skipped: bool = False,
        errors: list[str] | None = None, stats: dict | None = None) -> StageResult:
    return StageResult(stage_name=name, success=success, duration_seconds=0.1,
                       errors=list(errors or []), stats=dict(stats or {}), skipped=skipped)


def _pr(*stages: StageResult, ws: Path = Path(".")) -> PipelineResult:
    pr = PipelineResult(target_name="t", target_hash="0" * 64, workspace_path=ws)
    for s in stages:
        pr.add_stage_result(s)
    return pr


# ---------------------------------------------------------------------------
# Durum hesabı
# ---------------------------------------------------------------------------

class TestOutcome:
    def test_all_ok_is_complete(self) -> None:
        out = _analysis_outcome(_pr(_sr("identify"), _sr("static"), _sr("report")))
        assert out["status"] == "tam" and out["exit_code"] == EXIT_ANALYSIS_OK == 0
        assert out["failed"] == {} and out["partial"] == {}

    def test_skipped_stage_is_not_a_failure(self) -> None:
        out = _analysis_outcome(_pr(
            _sr("identify"), _sr("dynamic", False, skipped=True,
                                 stats={"skip_reason": "frida yok"}), _sr("report")))
        assert out["exit_code"] == 0

    def test_failed_stage_exit_1_with_reason(self) -> None:
        out = _analysis_outcome(_pr(
            _sr("identify"),
            _sr("static", False, errors=["Analyzer bulunamadi: X"]),
            _sr("report")))
        assert out["status"] == "basarisiz" and out["exit_code"] == EXIT_ANALYSIS_FAILED == 1
        assert out["failed"] == {"static": ["Analyzer bulunamadi: X"]}

    def test_failed_stage_without_errors_still_has_a_reason(self) -> None:
        out = _analysis_outcome(_pr(_sr("static", False)))
        assert out["exit_code"] == 1 and out["failed"]["static"]

    def test_ok_stage_with_errors_is_partial(self) -> None:
        out = _analysis_outcome(_pr(
            _sr("static", errors=["Ghidra adımı başarısız (strings): x"]), _sr("report")))
        assert out["status"] == "kismi" and out["exit_code"] == EXIT_ANALYSIS_PARTIAL == 3
        assert out["partial"] == {"static": ["Ghidra adımı başarısız (strings): x"]}

    def test_reconstruct_partial_flag_is_partial(self) -> None:
        out = _analysis_outcome(_pr(_sr("reconstruct", stats={
            "reconstruct_status": "kismi", "partial": True,
            "partial_reasons": ["Faz 1 hatası"]})))
        assert out["exit_code"] == 3
        assert out["partial"] == {"reconstruct": ["Faz 1 hatası"]}

    def test_partial_false_is_not_partial(self) -> None:
        out = _analysis_outcome(_pr(_sr("reconstruct", stats={
            "reconstruct_status": "tam", "partial": False, "partial_reasons": []})))
        assert out["exit_code"] == 0

    def test_failure_wins_over_partial(self) -> None:
        out = _analysis_outcome(_pr(
            _sr("static", errors=["uyarı"]), _sr("reconstruct", False, errors=["çöktü"])))
        assert out["exit_code"] == 1
        assert out["partial"] == {"static": ["uyarı"]}

    def test_no_stage_is_failure(self) -> None:
        assert _analysis_outcome(_pr())["exit_code"] == 1


# ---------------------------------------------------------------------------
# CLI: gerçek boru hattı, tanınmayan girdi (Ghidra'ya gitmez)
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    p = tmp_path / "bos"
    p.write_bytes(b"")
    return p


def test_analyze_empty_file_exits_nonzero_and_prints_stage_errors(
    empty_file: Path, tmp_path: Path,
) -> None:
    runner = CliRunner()
    res = runner.invoke(karadul_main, [
        "analyze", str(empty_file), "--skip-dynamic", "--output-dir", str(tmp_path / "ws"),
    ])
    assert res.exit_code == 1, res.output
    assert "analiz başarısız" in res.stderr
    # P-S4: tanınmayan türde gerçek neden (eskiden "Analyzer bulunamadi").
    assert "static: Desteklenmiyor: hedef türü tanınmadı" in res.stderr
    # P-S4: reconstruct artık JS hattına düşüp yanlış gerekçeyle ("Deobfuscate
    # edilmis dosya bulunamadi") başarısız olmuyor; tanınmayan türde 'atlandı'.
    assert "reconstruct:" not in res.stderr
    assert "başarısız" in res.stdout  # tablo satırı "Durum"


def test_analyze_empty_file_json_exits_nonzero(empty_file: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(karadul_main, [
        "analyze", str(empty_file), "--skip-dynamic", "--json",
        "--output-dir", str(tmp_path / "ws"),
    ])
    assert res.exit_code == 1, res.output
    payload = json.loads(res.stdout)  # stdout'ta yalnız JSON
    assert payload["success"] is False
    assert payload["outcome"] == "basarisiz" and payload["exit_code"] == 1
    assert "static" in payload["failure_reasons"]
    # P-S4: tanınmayan türde gerçek neden (eskiden "Analyzer bulunamadi").
    assert "static: Desteklenmiyor: hedef türü tanınmadı" in res.stderr


# ---------------------------------------------------------------------------
# CLI: sahte boru hattı ile tam / kısmi
# ---------------------------------------------------------------------------

class _FakePipeline:
    def __init__(self, result: PipelineResult) -> None:
        self._result = result
        self.registered_stages = ["identify", "static", "reconstruct"]

    def run(self, *a, **k) -> PipelineResult:
        return self._result


def _run_with(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: PipelineResult,
              *extra: str):
    target = tmp_path / "hedef.js"
    target.write_text("var a = 1;\n", encoding="utf-8")
    monkeypatch.setattr(cli_mod, "build_pipeline", lambda cfg, **k: _FakePipeline(result))
    return CliRunner().invoke(karadul_main, [
        "analyze", str(target), "--skip-dynamic", "--output-dir", str(tmp_path / "ws"), *extra,
    ])


def test_clean_run_exits_zero(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    res = _run_with(monkeypatch, tmp_path, _pr(_sr("identify"), _sr("static"),
                                               ws=tmp_path))
    assert res.exit_code == 0, res.output
    assert "HATA" not in res.stderr and "UYARI" not in res.stderr


def test_partial_run_exits_3_and_warns(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result = _pr(_sr("identify"), _sr("reconstruct", stats={
        "reconstruct_status": "kismi", "partial": True,
        "partial_reasons": ["Faz 2 adı uygulanamadı"]}), ws=tmp_path)
    res = _run_with(monkeypatch, tmp_path, result)
    assert res.exit_code == 3, res.output
    assert "kısmi" in res.stderr
    assert "reconstruct: Faz 2 adı uygulanamadı" in res.stderr


def test_partial_run_json_exit_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result = _pr(_sr("static", errors=["Ghidra adımı başarısız (xref): z"]), ws=tmp_path)
    res = _run_with(monkeypatch, tmp_path, result, "--json")
    assert res.exit_code == 3, res.output
    payload = json.loads(res.stdout)
    assert payload["outcome"] == "kismi"
    assert payload["partial_reasons"] == {"static": ["Ghidra adımı başarısız (xref): z"]}


def test_long_error_line_is_not_wrapped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    long_reason = "Decompile edilmis C dosyasi bulunamadi (decompiled_dir=" + "x" * 160 + ")"
    res = _run_with(monkeypatch, tmp_path,
                    _pr(_sr("reconstruct", False, errors=[long_reason]), ws=tmp_path))
    assert res.exit_code == 1
    assert f"  reconstruct: {long_reason}\n" in res.stderr


def test_many_errors_are_capped_on_screen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    errs = [f"hata {i}" for i in range(12)]
    res = _run_with(monkeypatch, tmp_path, _pr(_sr("static", False, errors=errs), ws=tmp_path))
    assert res.exit_code == 1
    assert "static: hata 4" in res.stderr and "static: hata 5" not in res.stderr
    assert "7 hata daha" in res.stderr
