"""Rapor render — GERCEK detector artifact semasi regresyon testleri.

Neden ayri dosya: mevcut ``test_report_v113_sections.py`` SENTETIK sema
kullanir (``packers``/``technique``/top-level ``score``). Bu sema gercekte
HIC uretilmez — packer_fingerprint step ``fingerprints``/``packer_name`` yazar,
anti_debug step skoru ``summary.anti_debug_score`` altina koyar. Bu anahtar
uyusmazligi yuzunden gercek UPX tespiti rapora hic ulasmiyordu (bolum bostu).

Buradaki testler GERCEK semayla besler; eski (kirik) kodda bu testler
BASARISIZ olur (bolum bos), duzeltilmis kodda gecer. Ayrica UPX runtime'da
varsa gercek paketlenmis binary uzerinden uctan uca detector->rapor zinciri
test edilir (yoksa skip).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.analyzers.packer_fingerprint import PackerFingerprintDetector
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.markdown_report import MarkdownReporter
from karadul.reporting.sarif_report import SARIFReporter

# coreutils stripped 'cat' — aarch64 ELF, UPX ile paketlenebilir
_CAT_FIXTURE = (
    Path(__file__).parent
    / "fixtures" / "coreutils" / "binaries" / "stripped" / "cat"
)


# GERCEK packer_fingerprint step artifact semasi
_REAL_PACKER_ARTIFACT = {
    "binary_path": "/tmp/cat_upx",
    "total_fingerprints": 1,
    "fingerprints": [
        {
            "packer_name": "UPX",
            "version": "5.20",
            "confidence": 0.99,
            "evidence": [
                "string: UPX 5.20 Copyright",
                "string: $Info: This file is packed with the UPX",
                "string: UPX!",
            ],
            "category": "compressor",
            "platform": "elf",
            "layers_matched": 3,
        }
    ],
}

# GERCEK anti_debug step artifact semasi — skor summary altinda, top-level YOK
_REAL_ANTIDEBUG_ARTIFACT = {
    "binary_path": "/tmp/suspect",
    "total_findings": 2,
    "findings": [
        {
            "technique": "ptrace_TRACEME",
            "category": "ptrace",
            "confidence": 0.9,
            "evidence": "ptrace(PTRACE_TRACEME) syscall",
            "platform": "linux",
            "description": "ptrace kendini izleme",
        },
        {
            "technique": "IsDebuggerPresent",
            "category": "windows_api",
            "confidence": 0.85,
            "evidence": "kernel32.IsDebuggerPresent import",
            "platform": "windows",
            "description": "WinAPI debugger kontrolu",
        },
    ],
    "summary": {
        "total": 2,
        "by_category": {"ptrace": 1, "windows_api": 1},
        "by_platform": {"linux": 1, "windows": 1},
        "high_confidence": [],
        "techniques": ["IsDebuggerPresent", "ptrace_TRACEME"],
        "max_confidence": 0.9,
        "anti_debug_score": 0.95,
    },
}


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="cat_upx")
    ws.create()
    return ws


@pytest.fixture
def result(workspace: Workspace) -> PipelineResult:
    """static stage functions_found=7 — uyari 'neden 7 fonksiyon' baglami."""
    r = PipelineResult(
        target_name="cat_upx",
        target_hash="ab" * 32,
        workspace_path=workspace.path,
    )
    r.add_stage_result(StageResult(
        stage_name="identify", success=True, duration_seconds=0.1,
        stats={"target_type": "elf", "language": "c", "file_size": 17548},
    ))
    r.add_stage_result(StageResult(
        stage_name="static", success=True, duration_seconds=2.0,
        stats={"functions_found": 7, "strings_found": 5, "imports_found": 3},
    ))
    r.total_duration = 2.1
    return r


def _write_json(ws: Workspace, stage: str, name: str, data: dict) -> None:
    target = ws.path / stage / f"{name}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown — gercek sema
# ---------------------------------------------------------------------------

def test_markdown_packer_real_schema_renders(
    result: PipelineResult, workspace: Workspace
) -> None:
    """fingerprints/packer_name semasi -> bolum DOLU (eski kodda BOS olurdu)."""
    _write_json(workspace, "static", "packer_fingerprints", _REAL_PACKER_ARTIFACT)
    md = MarkdownReporter().generate(result, workspace).read_text(encoding="utf-8")

    assert "## Detected Packer" in md
    assert "[HIGH]" in md                 # score max(conf)=0.99 -> high
    assert "score: 0.99" in md
    seg = md.split("## Detected Packer")[1].split("\n## ")[0]
    assert "UPX" in seg
    assert "5.20" in seg                  # version kolonu
    assert "compressor" in seg            # category
    # evidence liste -> okunabilir join (str repr degil)
    assert "string: UPX!" in seg
    assert "['string" not in seg          # liste repr'i SIZMAMALI


def test_markdown_packer_honest_warning(
    result: PipelineResult, workspace: Workspace
) -> None:
    """Dürüst uyari: paketli binary'de decompile aciklamasi + acma komutu."""
    _write_json(workspace, "static", "packer_fingerprints", _REAL_PACKER_ARTIFACT)
    md = MarkdownReporter().generate(result, workspace).read_text(encoding="utf-8")
    seg = md.split("## Detected Packer")[1].split("\n## ")[0]

    assert "paketlenmiş" in seg
    assert "açıcı" in seg or "unpacker" in seg
    assert "upx -d" in seg                # UPX icin dogru acma komutu
    assert "7 fonksiyon" in seg           # static.functions_found baglami


def test_markdown_packer_non_upx_generic_unpack_hint(
    result: PipelineResult, workspace: Workspace
) -> None:
    """UPX disi packer -> upx -d degil, jenerik unpack ipucu."""
    artifact = {
        "total_fingerprints": 1,
        "fingerprints": [{
            "packer_name": "Themida", "version": None, "confidence": 0.8,
            "evidence": ["section: .themida"], "category": "protector",
            "platform": "pe", "layers_matched": 1,
        }],
    }
    _write_json(workspace, "static", "packer_fingerprints", artifact)
    md = MarkdownReporter().generate(result, workspace).read_text(encoding="utf-8")
    seg = md.split("## Detected Packer")[1].split("\n## ")[0]
    assert "Themida" in seg
    assert "upx -d" not in seg
    assert "unpack" in seg


# ---------------------------------------------------------------------------
# Anti-debug — skor summary.anti_debug_score altinda (regresyon)
# ---------------------------------------------------------------------------

def test_markdown_anti_debug_score_from_summary(
    result: PipelineResult, workspace: Workspace
) -> None:
    """Top-level score YOK; summary.anti_debug_score=0.95 -> HIGH.

    Eski kod ``data.get('score')`` okuyordu -> 0.0 -> hep INFO (yanlis).
    """
    _write_json(
        workspace, "static", "anti_debug_findings", _REAL_ANTIDEBUG_ARTIFACT
    )
    md = MarkdownReporter().generate(result, workspace).read_text(encoding="utf-8")

    assert "## Anti-Debug Findings" in md
    seg = md.split("## Anti-Debug Findings")[1].split("\n## ")[0]
    assert "[HIGH]" in seg                 # 0.95 -> high (eski kodda INFO idi)
    assert "0.95" in seg
    assert "ptrace_TRACEME" in seg


# ---------------------------------------------------------------------------
# HTML — gercek sema
# ---------------------------------------------------------------------------

def test_html_packer_real_schema_renders(
    result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(workspace, "static", "packer_fingerprints", _REAL_PACKER_ARTIFACT)
    html = HTMLReporter().generate(result, workspace).read_text(encoding="utf-8")

    assert "<h2>Detected Packer</h2>" in html
    assert "UPX" in html
    assert "5.20" in html
    assert "paketlenmiş" in html          # uyari banner
    assert "upx -d" in html
    assert "7 fonksiyon" in html


def test_html_anti_debug_score_from_summary(
    result: PipelineResult, workspace: Workspace
) -> None:
    _write_json(
        workspace, "static", "anti_debug_findings", _REAL_ANTIDEBUG_ARTIFACT
    )
    html = HTMLReporter().generate(result, workspace).read_text(encoding="utf-8")
    assert "<h2>Anti-Debug Findings</h2>" in html
    assert "HIGH" in html                 # eski kod INFO gosterirdi


# ---------------------------------------------------------------------------
# SARIF — packer_fingerprints -> KRDL004
# ---------------------------------------------------------------------------

def test_sarif_packer_fingerprint_krdl004(
    result: PipelineResult, workspace: Workspace
) -> None:
    """packer_fingerprints.json artifact'i SARIF KRDL004 result'a donusur."""
    _write_json(workspace, "static", "packer_fingerprints", _REAL_PACKER_ARTIFACT)
    sarif = json.loads(
        SARIFReporter().generate(result, workspace).read_text(encoding="utf-8")
    )
    krdl004 = [
        r for r in sarif["runs"][0]["results"]
        if r.get("ruleId") == "KRDL004"
        and r.get("properties", {}).get("source") == "packer_fingerprints"
    ]
    assert len(krdl004) == 1
    r0 = krdl004[0]
    assert r0["level"] == "error"          # conf 0.99 >= 0.7 -> error
    assert "UPX" in r0["message"]["text"]
    assert "5.20" in r0["message"]["text"]
    assert r0["properties"]["confidence"] == pytest.approx(0.99)
    assert r0["properties"]["layers_matched"] == 3


def test_sarif_packer_no_artifact_no_krdl004_from_fingerprints(
    result: PipelineResult, workspace: Workspace
) -> None:
    """Artifact yoksa packer_fingerprints kaynakli KRDL004 uretilmez."""
    sarif = json.loads(
        SARIFReporter().generate(result, workspace).read_text(encoding="utf-8")
    )
    from_fp = [
        r for r in sarif["runs"][0]["results"]
        if r.get("properties", {}).get("source") == "packer_fingerprints"
    ]
    assert from_fp == []


# ---------------------------------------------------------------------------
# Gercek UPX — uctan uca detector -> artifact -> rapor (UPX yoksa skip)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    shutil.which("upx") is None, reason="UPX runtime'da yok (CI'da olmayabilir)"
)
@pytest.mark.skipif(
    not _CAT_FIXTURE.exists(), reason="coreutils cat fixture yok"
)
def test_real_upx_detector_to_report(
    tmp_path: Path, result: PipelineResult, workspace: Workspace
) -> None:
    """Gercek UPX-paketli binary: PackerFingerprintDetector -> rapor zinciri.

    KISIT: UPX Mach-O paketlemez; aarch64 ELF (coreutils cat) paketlenir.
    Bu test detector'un GERCEK ciktisiyla rapor render'ini dogrular — sentetik
    fixture'in gercekle ayni kaldigini garanti eder.
    """
    packed = tmp_path / "cat_upx"
    proc = subprocess.run(
        ["upx", "-q", "-o", str(packed), str(_CAT_FIXTURE)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0 or not packed.exists():
        pytest.skip(f"upx paketleme basarisiz: {proc.stderr[:200]}")

    # Gercek detector cikti -> step'in yazdigi payload semasiyla artifact
    fps = PackerFingerprintDetector(packed).detect()
    assert fps, "Gercek UPX binary'de packer tespit edilemedi"
    payload = {
        "binary_path": str(packed),
        "total_fingerprints": len(fps),
        "fingerprints": [fp.to_dict() for fp in fps],
    }
    _write_json(workspace, "static", "packer_fingerprints", payload)

    md = MarkdownReporter().generate(result, workspace).read_text(encoding="utf-8")
    assert "## Detected Packer" in md
    assert "UPX" in md
    assert "paketlenmiş" in md

    sarif = json.loads(
        SARIFReporter().generate(result, workspace).read_text(encoding="utf-8")
    )
    krdl004 = [
        r for r in sarif["runs"][0]["results"]
        if r.get("properties", {}).get("source") == "packer_fingerprints"
    ]
    assert len(krdl004) >= 1
    assert "UPX" in krdl004[0]["message"]["text"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
