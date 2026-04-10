#!/usr/bin/env python3
"""Tum hedefleri toplu analiz et.

Tanimi yapilmis Electron uygulamalarini, JS bundle'larini ve native
binary'leri sirayla pipeline'dan gecirir.

Kullanim:
    python scripts/batch-analyze.py --targets electron
    python scripts/batch-analyze.py --targets binary
    python scripts/batch-analyze.py --targets all
    python scripts/batch-analyze.py --targets discord,poe

Her hedef icin:
1. ASAR ise: extract et, ana JS'i bul
2. Pipeline'i calistir (identify + static + deobfuscate + report)
3. Sonuclari workspaces/<target-name>/ altina kaydet
4. Ozet rapor olustur
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Proje root'unu path'e ekle
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# HEDEF TANIMLARI
# ============================================================================

ELECTRON_TARGETS: dict[str, str] = {
    "discord": "/Applications/Discord.app/Contents/Resources/app.asar",
    "claude-desktop": "/Applications/Claude.app/Contents/Resources/app.asar",
    "codex-app": "/Applications/Codex.app/Contents/Resources/app.asar",
    "element": "/Applications/Element.app/Contents/Resources/app.asar",
    "poe": "/Applications/Poe.app/Contents/Resources/app.asar",
}

JS_TARGETS: dict[str, str] = {
    "claude-code-cli": "/opt/homebrew/lib/node_modules/@anthropic-ai/.claude-code-2DTsDk1V/cli.js",
}

CURSOR_TARGETS: dict[str, str] = {
    "cursor-main": "/Applications/Cursor.app/Contents/Resources/app/out/main.js",
    "cursor-cli": "/Applications/Cursor.app/Contents/Resources/app/out/cli.js",
    "cursor-agent": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-agent-exec/dist/main.js",
    "cursor-always-local": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-always-local/dist/main.js",
}

BINARY_TARGETS: dict[str, str] = {
    "codex-cli": "/opt/homebrew/Caskroom/codex/0.116.0/codex-aarch64-apple-darwin",
    "avast": "/Applications/Avast.app/Contents/MacOS/Avast",
    "excel": "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel",
}

ALL_TARGETS = {
    **ELECTRON_TARGETS,
    **JS_TARGETS,
    **CURSOR_TARGETS,
    **BINARY_TARGETS,
}


@dataclass
class TargetResult:
    """Tek bir hedefin analiz sonucu."""

    name: str
    path: str
    category: str
    success: bool = False
    duration: float = 0.0
    functions_found: int = 0
    strings_found: int = 0
    tech_stack: str = ""
    modules: list[str] = field(default_factory=list)
    workspace: str = ""
    errors: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""


def get_target_category(name: str) -> str:
    """Hedefin kategorisini dondur."""
    if name in ELECTRON_TARGETS:
        return "electron"
    elif name in JS_TARGETS:
        return "js_bundle"
    elif name in CURSOR_TARGETS:
        return "cursor"
    elif name in BINARY_TARGETS:
        return "binary"
    return "unknown"


def resolve_targets(target_spec: str) -> dict[str, str]:
    """Target spec'i cevirip uygun hedefleri dondur.

    Args:
        target_spec: "electron", "binary", "js", "cursor", "all", veya
                     "discord,poe,avast" gibi virgule ayrilmis isimler.

    Returns:
        Hedef adi -> dosya yolu eslesmesi.
    """
    spec = target_spec.lower().strip()

    if spec == "all":
        return dict(ALL_TARGETS)
    elif spec == "electron":
        return dict(ELECTRON_TARGETS)
    elif spec == "binary":
        return dict(BINARY_TARGETS)
    elif spec == "js":
        return dict(JS_TARGETS)
    elif spec == "cursor":
        return dict(CURSOR_TARGETS)
    else:
        # Virgule ayrilmis isimler
        names = [n.strip() for n in spec.split(",")]
        result = {}
        for name in names:
            if name in ALL_TARGETS:
                result[name] = ALL_TARGETS[name]
            else:
                print(f"UYARI: Bilinmeyen hedef: {name}", file=sys.stderr)
        return result


def analyze_target(name: str, path_str: str, project_root: Path, skip_dynamic: bool = True) -> TargetResult:
    """Tek bir hedefi analiz et.

    Args:
        name: Hedef adi.
        path_str: Hedef dosya yolu.
        project_root: Proje root dizini.
        skip_dynamic: Dinamik analizi atla.

    Returns:
        TargetResult: Analiz sonucu.
    """
    from karadul.config import Config
    from karadul.core.pipeline import Pipeline
    from karadul.core.target import TargetDetector, TargetType
    from karadul.stages import (
        IdentifyStage,
        StaticAnalysisStage,
        DeobfuscationStage,
        ReportStage,
    )

    result = TargetResult(
        name=name,
        path=path_str,
        category=get_target_category(name),
    )

    target_path = Path(path_str)

    # Dosya var mi kontrol et
    if not target_path.exists():
        result.skipped = True
        result.skip_reason = f"Dosya bulunamadi: {path_str}"
        return result

    start = time.monotonic()

    try:
        # Config ve pipeline olustur
        cfg = Config()
        cfg.project_root = project_root

        pipeline = Pipeline(cfg)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage())
        pipeline.register_stage(ReportStage())

        # Pipeline calistir
        pipeline_result = pipeline.run(target_path)

        result.success = pipeline_result.success or any(
            sr.success for sr in pipeline_result.stages.values()
        )
        result.workspace = str(pipeline_result.workspace_path)

        # Stats cikar
        if "static" in pipeline_result.stages:
            stats = pipeline_result.stages["static"].stats
            result.functions_found = stats.get("functions_found", stats.get("ghidra_function_count", 0))
            result.strings_found = stats.get("strings_found", stats.get("string_count", 0))

        # Tech stack belirle
        if "identify" in pipeline_result.stages:
            stats = pipeline_result.stages["identify"].stats
            result.tech_stack = f"{stats.get('target_type', 'unknown')} / {stats.get('language', 'unknown')}"

        # Hatalari topla
        for stage_name, sr in pipeline_result.stages.items():
            if sr.errors:
                result.errors.extend([f"[{stage_name}] {e}" for e in sr.errors])

    except Exception as exc:
        result.errors.append(f"Pipeline hatasi: {type(exc).__name__}: {exc}")

    result.duration = time.monotonic() - start
    return result


def print_summary(results: list[TargetResult]) -> None:
    """Sonuc ozet tablosunu yazdir."""
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()

        table = Table(title="Batch Analysis Summary", border_style="cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Target", style="bold")
        table.add_column("Category")
        table.add_column("Status")
        table.add_column("Functions", justify="right")
        table.add_column("Strings", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Tech Stack")

        for i, r in enumerate(results, 1):
            if r.skipped:
                status = "[yellow]SKIPPED[/yellow]"
            elif r.success:
                status = "[green]OK[/green]"
            else:
                status = "[red]FAIL[/red]"

            table.add_row(
                str(i),
                r.name,
                r.category,
                status,
                str(r.functions_found) if not r.skipped else "-",
                str(r.strings_found) if not r.skipped else "-",
                f"{r.duration:.1f}s" if not r.skipped else "-",
                r.tech_stack or r.skip_reason,
            )

        console.print(table)

        # Basarisizlari goster
        failed = [r for r in results if not r.success and not r.skipped]
        if failed:
            console.print(f"\n[red]Basarisiz hedefler ({len(failed)}):[/red]")
            for r in failed:
                for err in r.errors[:3]:
                    console.print(f"  [dim]{r.name}:[/dim] {err}")

    except ImportError:
        # Rich yoksa duz text
        print("\n=== Batch Analysis Summary ===")
        for r in results:
            status = "SKIP" if r.skipped else ("OK" if r.success else "FAIL")
            print(f"  [{status}] {r.name}: {r.functions_found} funcs, {r.strings_found} strings, {r.duration:.1f}s")


def save_batch_report(results: list[TargetResult], output_path: Path) -> None:
    """Batch sonuclarini JSON olarak kaydet."""
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_targets": len(results),
        "successful": sum(1 for r in results if r.success),
        "failed": sum(1 for r in results if not r.success and not r.skipped),
        "skipped": sum(1 for r in results if r.skipped),
        "total_duration": sum(r.duration for r in results),
        "results": [],
    }

    for r in results:
        report["results"].append({
            "name": r.name,
            "path": r.path,
            "category": r.category,
            "success": r.success,
            "skipped": r.skipped,
            "skip_reason": r.skip_reason,
            "duration": round(r.duration, 2),
            "functions_found": r.functions_found,
            "strings_found": r.strings_found,
            "tech_stack": r.tech_stack,
            "workspace": r.workspace,
            "errors": r.errors,
        })

    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nBatch rapor kaydedildi: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Black Widow Batch Analyzer")
    parser.add_argument(
        "--targets", "-t",
        required=True,
        help="Hedef grubu: electron, binary, js, cursor, all veya virgule ayrilmis isimler",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=str(PROJECT_ROOT),
        help="Workspace ust dizini (varsayilan: proje root)",
    )
    parser.add_argument(
        "--skip-dynamic",
        action="store_true",
        default=True,
        help="Dinamik analizi atla (varsayilan: True)",
    )

    args = parser.parse_args()

    targets = resolve_targets(args.targets)

    if not targets:
        print("HATA: Gecerli hedef bulunamadi.", file=sys.stderr)
        sys.exit(1)

    print(f"\nBatch Analysis: {len(targets)} hedef")
    print(f"Hedefler: {', '.join(targets.keys())}")
    print()

    project_root = Path(args.output_dir).resolve()
    results: list[TargetResult] = []

    for name, path_str in targets.items():
        print(f"\n{'='*60}")
        print(f"  Hedef: {name}")
        print(f"  Yol:   {path_str}")
        print(f"{'='*60}")

        result = analyze_target(name, path_str, project_root, skip_dynamic=args.skip_dynamic)
        results.append(result)

        if result.skipped:
            print(f"  -> ATLANDI: {result.skip_reason}")
        elif result.success:
            print(f"  -> BASARILI ({result.duration:.1f}s)")
        else:
            print(f"  -> BASARISIZ ({result.duration:.1f}s)")

    # Ozet
    print_summary(results)

    # Rapor kaydet
    report_path = project_root / "workspaces" / "batch_report.json"
    save_batch_report(results, report_path)


if __name__ == "__main__":
    main()
