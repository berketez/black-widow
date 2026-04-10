#!/usr/bin/env python3
"""3 yeni hedefi (Element, Codex App, Cursor) pipeline'dan gecir.

Element.app  -> ASAR, Electron  (32MB)
Codex.app    -> ASAR, Electron  (40MB, OpenAI)
Cursor       -> JS dosyalari    (4 adet, VS Code fork)

Her hedef icin:
1. Pipeline (identify + static + deobfuscate + report) calistirir
2. Sonuclari workspaces/<hedef>/ altina kaydeder
3. Ozet rapor olusturur

Kullanim:
    cd /Users/apple/Desktop/black-widow
    python scripts/analyze-new-targets.py
    python scripts/analyze-new-targets.py --target element
    python scripts/analyze-new-targets.py --target codex
    python scripts/analyze-new-targets.py --target cursor
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Proje root'u
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.config import Config
from karadul.core.pipeline import Pipeline
from karadul.stages import (
    IdentifyStage,
    StaticAnalysisStage,
    DeobfuscationStage,
    ReportStage,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("new-targets")


# ============================================================================
# HEDEF TANIMLARI
# ============================================================================

# Element.app -- Matrix client, ASAR icinde
ELEMENT_TARGETS = {
    "element": "/Applications/Element.app/Contents/Resources/app.asar",
}

# Codex.app -- OpenAI Codex desktop, ASAR icinde
CODEX_TARGETS = {
    "codex-app": "/Applications/Codex.app/Contents/Resources/app.asar",
}

# Cursor -- VS Code fork, ASAR yok, dogrudan JS dosyalari
CURSOR_TARGETS = {
    "cursor-main": "/Applications/Cursor.app/Contents/Resources/app/out/main.js",
    "cursor-cli": "/Applications/Cursor.app/Contents/Resources/app/out/cli.js",
    "cursor-agent": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-agent-exec/dist/main.js",
    "cursor-always-local": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-always-local/dist/main.js",
}

ALL_NEW_TARGETS = {
    **ELEMENT_TARGETS,
    **CODEX_TARGETS,
    **CURSOR_TARGETS,
}


@dataclass
class AnalysisResult:
    """Tek hedef analiz sonucu."""
    name: str
    path: str
    target_type: str = ""
    language: str = ""
    success: bool = False
    duration: float = 0.0
    functions_found: int = 0
    strings_found: int = 0
    imports_found: int = 0
    webpack_modules: int = 0
    tech_stack: str = ""
    workspace: str = ""
    report_html: str = ""
    interesting_findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "target_type": self.target_type,
            "language": self.language,
            "success": self.success,
            "duration": round(self.duration, 2),
            "functions_found": self.functions_found,
            "strings_found": self.strings_found,
            "imports_found": self.imports_found,
            "webpack_modules": self.webpack_modules,
            "tech_stack": self.tech_stack,
            "workspace": self.workspace,
            "report_html": self.report_html,
            "interesting_findings": self.interesting_findings,
            "errors": self.errors,
            "stats": self.stats,
        }


def analyze_single(name: str, path_str: str, project_root: Path) -> AnalysisResult:
    """Tek bir hedefi pipeline'dan gecir."""
    result = AnalysisResult(name=name, path=path_str)
    target_path = Path(path_str)

    if not target_path.exists():
        result.errors.append(f"Dosya bulunamadi: {path_str}")
        return result

    start = time.monotonic()

    try:
        cfg = Config()
        cfg.project_root = project_root

        # Buyuk dosyalar icin timeout artir
        file_size_mb = target_path.stat().st_size / (1024 * 1024)
        if file_size_mb > 20:
            cfg.timeouts.subprocess = 300  # 5 dakika
            cfg.timeouts.babel_parse = 180
            cfg.timeouts.synchrony = 300

        pipeline = Pipeline(cfg)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage())
        pipeline.register_stage(ReportStage())

        pipeline_result = pipeline.run(target_path)

        result.success = pipeline_result.success or any(
            sr.success for sr in pipeline_result.stages.values()
        )
        result.workspace = str(pipeline_result.workspace_path)

        # Identify stage sonuclari
        if "identify" in pipeline_result.stages:
            id_stats = pipeline_result.stages["identify"].stats
            result.target_type = id_stats.get("target_type", "unknown")
            result.language = id_stats.get("language", "unknown")
            bundler = id_stats.get("bundler", "unknown")
            result.tech_stack = f"{result.target_type} / {result.language} / {bundler}"

        # Static analysis sonuclari
        if "static" in pipeline_result.stages:
            st = pipeline_result.stages["static"]
            stats = st.stats
            result.functions_found = stats.get(
                "functions_found", stats.get("js_file_count", 0)
            )
            result.strings_found = stats.get(
                "strings_found", stats.get("string_count", 0)
            )
            result.imports_found = stats.get("imports_found", 0)
            result.webpack_modules = stats.get(
                "webpack_bundles", stats.get("webpack_modules", 0)
            )
            result.stats["static"] = stats

        # Deobfuscation sonuclari
        if "deobfuscate" in pipeline_result.stages:
            deob = pipeline_result.stages["deobfuscate"]
            result.stats["deobfuscate"] = deob.stats

        # Report stage -- HTML rapor yolunu bul
        if "report" in pipeline_result.stages:
            report_artifacts = pipeline_result.stages["report"].artifacts
            for rname, rpath in report_artifacts.items():
                if "html" in str(rname).lower():
                    result.report_html = str(rpath) if rpath else ""

        # Hatalari topla
        for stage_name, sr in pipeline_result.stages.items():
            if sr.errors:
                result.errors.extend([f"[{stage_name}] {e}" for e in sr.errors])

    except Exception as exc:
        import traceback
        result.errors.append(f"Pipeline hatasi: {type(exc).__name__}: {exc}")
        logger.error("Pipeline exception:\n%s", traceback.format_exc())

    result.duration = time.monotonic() - start
    return result


def resolve_target_group(group: str) -> dict[str, str]:
    """Hedef grubunu coz."""
    g = group.lower().strip()
    if g == "element":
        return dict(ELEMENT_TARGETS)
    elif g == "codex":
        return dict(CODEX_TARGETS)
    elif g == "cursor":
        return dict(CURSOR_TARGETS)
    elif g == "all":
        return dict(ALL_NEW_TARGETS)
    else:
        # Tekil hedef adi
        if g in ALL_NEW_TARGETS:
            return {g: ALL_NEW_TARGETS[g]}
        return {}


def print_summary(results: list[AnalysisResult]) -> None:
    """Sonuc ozetini yazdir."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()

        table = Table(
            title="New Targets Analysis Summary",
            border_style="cyan",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Target", style="bold")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Functions", justify="right")
        table.add_column("Strings", justify="right")
        table.add_column("Imports", justify="right")
        table.add_column("Webpack", justify="right")
        table.add_column("Duration", justify="right")

        for i, r in enumerate(results, 1):
            status = "[green]OK[/green]" if r.success else "[red]FAIL[/red]"
            table.add_row(
                str(i),
                r.name,
                r.target_type,
                status,
                str(r.functions_found),
                str(r.strings_found),
                str(r.imports_found),
                str(r.webpack_modules),
                f"{r.duration:.1f}s",
            )

        console.print(table)

        # Her hedef icin ilginc bulgular
        for r in results:
            if r.report_html:
                console.print(f"\n  [cyan]{r.name}[/cyan] HTML rapor: {r.report_html}")
            if r.errors:
                console.print(f"  [red]{r.name} hatalari:[/red]")
                for e in r.errors[:5]:
                    console.print(f"    {e}")

    except ImportError:
        print("\n=== Analysis Summary ===")
        for r in results:
            status = "OK" if r.success else "FAIL"
            print(
                f"  [{status}] {r.name}: "
                f"funcs={r.functions_found}, strings={r.strings_found}, "
                f"imports={r.imports_found}, webpack={r.webpack_modules}, "
                f"{r.duration:.1f}s"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Element, Codex, Cursor")
    parser.add_argument(
        "--target", "-t",
        default="all",
        help="Hedef grubu: element, codex, cursor, all veya tekil hedef adi",
    )
    args = parser.parse_args()

    targets = resolve_target_group(args.target)
    if not targets:
        print(f"HATA: Bilinmeyen hedef: {args.target}", file=sys.stderr)
        print(f"Gecerli hedefler: {', '.join(ALL_NEW_TARGETS.keys())}")
        sys.exit(1)

    print(f"\nAnaliz: {len(targets)} hedef")
    print(f"Hedefler: {', '.join(targets.keys())}\n")

    project_root = PROJECT_ROOT
    results: list[AnalysisResult] = []

    for name, path_str in targets.items():
        print(f"\n{'='*60}")
        print(f"  HEDEF: {name}")
        print(f"  YOL:   {path_str}")
        print(f"{'='*60}\n")

        result = analyze_single(name, path_str, project_root)
        results.append(result)

        if result.success:
            print(f"\n  -> BASARILI ({result.duration:.1f}s)")
        else:
            print(f"\n  -> BASARISIZ ({result.duration:.1f}s)")

    # Ozet
    print_summary(results)

    # JSON rapor
    report_path = project_root / "workspaces" / "new_targets_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "targets_analyzed": len(results),
        "successful": sum(1 for r in results if r.success),
        "failed": sum(1 for r in results if not r.success),
        "total_duration": sum(r.duration for r in results),
        "results": [r.to_dict() for r in results],
    }
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\nJSON rapor: {report_path}")


if __name__ == "__main__":
    main()
