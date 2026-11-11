"""Çıktıdaki beş küçük hata (2026-11-11).

Rapor sayaçları (docs/arge/2026-11-11_rapor_sayaclari/sonuc.md) ve temiz harita
(docs/arge/2026-11-11_temiz_harita/sonuc.md) onarımlarında görülüp dokunulmayan, kullanıcıya
yanlış ya da eksik bilgi gösteren çıktılar. Hiçbiri ad davranışını değiştirmez.

1. Markdown raporu ithal sayısı bilinmiyorken "0" yazıyordu (JSON raporu "N/A" yazıyor).
"""

from __future__ import annotations

from pathlib import Path

from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.reporting.markdown_report import MarkdownReporter


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ikili")
    ws.create()
    return ws


def _result(ws: Workspace, stages: dict[str, dict]) -> PipelineResult:
    result = PipelineResult(target_name="ikili", target_hash="0" * 64, workspace_path=ws.path)
    for name, stats in stages.items():
        result.add_stage_result(StageResult(
            stage_name=name, success=True, duration_seconds=1.0, stats=stats,
        ))
    return result


# ---------------------------------------------------------------------------
# 1. Markdown raporu: ithal sayısı
# ---------------------------------------------------------------------------


def _markdown_imports_line(tmp_path: Path, static_stats: dict) -> str:
    """``reports/report.md`` yazılır ve ithal satırı geri okunur."""
    ws = _workspace(tmp_path)
    path = MarkdownReporter().generate(_result(ws, {"static": static_stats}), ws)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if "Imports found" in ln]
    assert len(lines) == 1
    return lines[0]


class TestMarkdownImports:
    def test_sayi_varsa_yazilir(self, tmp_path) -> None:
        line = _markdown_imports_line(tmp_path, {"ghidra_function_count": 250, "imports_found": 63})
        assert line == "- **Imports found:** 63"

    def test_gercek_sifir_korunur(self, tmp_path) -> None:
        """İthal listesi okundu ve boşsa sayı gerçekten 0'dır."""
        line = _markdown_imports_line(tmp_path, {"imports_found": 0})
        assert line == "- **Imports found:** 0"

    def test_bilinmiyorsa_sifir_degil(self, tmp_path) -> None:
        line = _markdown_imports_line(tmp_path, {"ghidra_function_count": 250})
        assert line == "- **Imports found:** N/A"
