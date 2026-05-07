"""v1.13 Dalga 1 — Markdown + HTML report yeni section testleri.

Test edilen 3 yeni section:
  1. Anti-Debug Findings (workspace static/anti_debug_findings.json)
  2. Detected Packer (workspace static/packer_fingerprints.json)
  3. Malware IOC (workspace static/signature_matches.json — Sliver/CS filter)

Davranis:
  - JSON yoksa bolum atlanir (hata atilmaz)
  - Severity: score >= 0.7 high, >= 0.4 medium, < 0.4 info/low
  - Tablo formatinda render: technique/symbol, category, confidence, evidence
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.markdown_report import MarkdownReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="v113_target")
    ws.create()
    return ws


@pytest.fixture
def base_result(workspace: Workspace) -> PipelineResult:
    """Minimum PipelineResult — static stage var, tier1 alanlari ekstradan eklenebilir."""
    result = PipelineResult(
        target_name="suspect.bin",
        target_hash="deadbeef" * 8,
        workspace_path=workspace.path,
    )
    result.add_stage_result(StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.1,
        stats={"target_type": "elf", "language": "go", "file_size": 8_500_000},
    ))
    result.add_stage_result(StageResult(
        stage_name="static",
        success=True,
        duration_seconds=4.2,
        stats={"functions_found": 1234, "strings_found": 5678, "imports_found": 42},
    ))
    result.total_duration = 4.3
    return result


def _write_json(workspace: Workspace, stage: str, name: str, data: dict) -> None:
    """Workspace'e JSON yaz (save_json yerine direkt — testlerde hizli)."""
    if not name.endswith(".json"):
        name = f"{name}.json"
    target = workspace.path / stage / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Anti-Debug section
# ---------------------------------------------------------------------------

def test_markdown_anti_debug_skipped_when_json_missing(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    """JSON dosyasi yoksa Anti-Debug section render edilmemeli (hata atmamali)."""
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Anti-Debug Findings" not in md


def test_markdown_anti_debug_high_severity(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    """Anti-Debug high severity (score >= 0.7) dogru render."""
    _write_json(workspace, "static", "anti_debug_findings", {
        "score": 0.85,
        "findings": [
            {
                "technique": "IsDebuggerPresent",
                "category": "windows_api",
                "confidence": 0.95,
                "evidence": "kernel32.IsDebuggerPresent import",
            },
            {
                "technique": "ptrace_TRACEME",
                "category": "linux_syscall",
                "confidence": 0.88,
                "evidence": "syscall ptrace(0,...) detected",
            },
        ],
    })

    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Anti-Debug Findings" in md
    assert "[HIGH]" in md
    assert "0.85" in md
    assert "IsDebuggerPresent" in md
    assert "ptrace_TRACEME" in md
    assert "kernel32.IsDebuggerPresent import" in md


def test_markdown_anti_debug_medium_and_info_severity(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    """Score 0.5 -> [MED], score 0.2 -> [INFO]."""
    _write_json(workspace, "static", "anti_debug_findings", {
        "score": 0.5,
        "findings": [{"technique": "rdtsc_check", "category": "timing",
                      "confidence": 0.6, "evidence": "rdtsc instruction"}],
    })
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "[MED]" in md
    assert "[HIGH]" not in md.split("Anti-Debug")[1].split("##")[0]


# ---------------------------------------------------------------------------
# 2. Packer section
# ---------------------------------------------------------------------------

def test_markdown_packer_skipped_when_json_missing(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Detected Packer" not in md


def test_markdown_packer_renders_packers_list(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(workspace, "static", "packer_fingerprints", {
        "score": 0.75,
        "packers": [
            {"technique": "UPX", "category": "packer", "confidence": 0.99,
             "evidence": "UPX!! magic header at offset 0x100"},
            {"technique": "ASPack", "category": "packer", "confidence": 0.6,
             "evidence": "section name .aspack"},
        ],
    })
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Detected Packer" in md
    assert "[HIGH]" in md
    assert "UPX" in md
    assert "ASPack" in md
    assert "UPX!! magic header" in md


# ---------------------------------------------------------------------------
# 3. Malware IOC section
# ---------------------------------------------------------------------------

def test_markdown_malware_ioc_skipped_when_no_matches(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Malware IOC" not in md


def test_markdown_malware_ioc_filters_sliver_and_cs(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    """signature_matches'ten sadece tier1 family/category/tier filtrelenir."""
    _write_json(workspace, "static", "signature_matches", {
        "matches": [
            # Tier-1 Sliver
            {"symbol": "github.com/bishopfox/sliver/implant/sliver/handlers",
             "family": "sliver", "lib": "sliver", "tier": "1",
             "category": "malware",
             "purpose": "Sliver implant handler dispatch"},
            # Tier-1 CS
            {"symbol": "ReflectiveLoader", "family": "cobaltstrike",
             "lib": "cobaltstrike", "tier": "1", "category": "malware",
             "purpose": "Cobalt Strike Beacon reflective loader"},
            # Non-tier1 — filtrelenmeli
            {"symbol": "_EVP_EncryptInit_ex", "family": "", "lib": "openssl",
             "tier": "", "category": "crypto", "purpose": "AES init"},
        ],
    })
    md = MarkdownReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Malware IOC" in md
    assert "[HIGH]" in md
    assert "**Sliver:** 1 sembol" in md
    assert "**Cobalt Strike:** 1 sembol" in md
    assert "ReflectiveLoader" in md
    # Crypto sembolu IOC bolumune sizmamali
    ioc_section = md.split("## Malware IOC")[1].split("##")[0]
    assert "_EVP_EncryptInit_ex" not in ioc_section


# ---------------------------------------------------------------------------
# 4. HTML reporter — paralel dogrulama
# ---------------------------------------------------------------------------

def test_html_anti_debug_renders_table(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(workspace, "static", "anti_debug_findings", {
        "score": 0.9,
        "findings": [{"technique": "IsDebuggerPresent",
                      "category": "windows_api", "confidence": 0.95,
                      "evidence": "import"}],
    })
    html = HTMLReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "<h2>Anti-Debug Findings</h2>" in html
    assert "IsDebuggerPresent" in html
    assert "HIGH" in html


def test_html_packer_renders_table(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(workspace, "static", "packer_fingerprints", {
        "score": 0.8,
        "packers": [{"technique": "UPX", "category": "packer",
                     "confidence": 1.0, "evidence": "UPX!! magic"}],
    })
    html = HTMLReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "<h2>Detected Packer</h2>" in html
    assert "UPX" in html


def test_html_malware_ioc_renders_table(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(workspace, "static", "signature_matches", {
        "matches": [
            {"symbol": "ReflectiveLoader", "family": "cobaltstrike",
             "lib": "cobaltstrike", "tier": "1", "category": "malware",
             "purpose": "CS Beacon"},
        ],
    })
    html = HTMLReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "<h2>Malware IOC</h2>" in html
    assert "ReflectiveLoader" in html
    assert "cobaltstrike" in html


def test_html_sections_skipped_when_json_missing(
    base_result: PipelineResult, workspace: Workspace
) -> None:
    """HTML reporter JSON yoksa 3 section'i hic render etmez."""
    html = HTMLReporter().generate(base_result, workspace).read_text(encoding="utf-8")
    assert "Anti-Debug Findings" not in html
    assert "Detected Packer" not in html
    assert "Malware IOC" not in html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
