"""P15a (P01 notu): hacker_cli'nin istihbarat uyarıları ölü koddu.

`_show_intelligence_alerts` anahtarları raporun kökünde arıyordu
(`security_mechanisms`, `algorithms`, `subsystems`); gerçek `intelligence_report.json`'da
bunlar `architecture` altında ve güvenlik anahtarının adı `security`. Sonuç: hiçbir satır
basılmıyordu. Onarımda olağan koruma (risk_level "standard", ör. yığın koruması) ALERT
olarak değil bilgi satırı olarak basılır; algoritmalar "CRYPTO" diye değil kategorisiyle.

Rapor biçimi `debian/coreutils/true` gerçek çıktısındaki (P15a koşusu) yapıdan alındı.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

import karadul.hacker_cli as hc

REAL_SHAPE = {
    "architecture": {
        "app_name": "true", "app_type": "cli_tool",
        "subsystems": [{"name": "Localization", "description": "x", "evidence": ["locale"],
                        "confidence": 0.22, "category": "config", "evidence_kinds": ["string"]}],
        "algorithms": [{"name": "zlib", "category": "compression", "confidence": 0.9}],
        "security": [
            {"name": "Stack Protection", "description": "x", "risk_level": "standard",
             "evidence": ["__stack_chk_fail"], "evidence_kinds": ["symbol"]},
            {"name": "Anti-Debugging", "description": "x", "risk_level": "elevated",
             "evidence": ["ptrace"], "evidence_kinds": ["symbol"]},
        ],
        "protocols": [], "function_analyses": [], "architecture_summary": "",
    },
    "raw_cluster_counts": {}, "total_strings_analyzed": 1,
}


def _render(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: dict) -> str:
    static = tmp_path / "static"
    static.mkdir()
    (static / "intelligence_report.json").write_text(json.dumps(report), encoding="utf-8")
    buf = io.StringIO()
    monkeypatch.setattr(hc, "console", Console(file=buf, width=200, theme=hc.KARADUL_THEME))
    hc._show_intelligence_alerts(SimpleNamespace(workspace_path=tmp_path), "00:00")
    return buf.getvalue()


def test_alerts_read_architecture_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _render(tmp_path, monkeypatch, REAL_SHAPE)
    assert "Subsystem: Localization" in out
    assert "ALGORİTMA: zlib (compression)" in out


def test_standard_protection_is_not_an_alert(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    out = _render(tmp_path, monkeypatch, REAL_SHAPE)
    assert "Güvenlik mekanizması iddiası: Anti-Debugging (elevated; kanıt 1)" in out
    assert "Koruma: Stack Protection (standard)" in out
    assert "iddiası: Stack Protection" not in out and "ALERT" not in out
    assert "CRYPTO" not in out


def test_empty_report_prints_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _render(tmp_path, monkeypatch, {"architecture": {"security": [], "algorithms": [],
                                                           "subsystems": []}})
    assert out == ""
