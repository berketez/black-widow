#!/usr/bin/env python3
"""Cursor TUM extension'larini tam pipeline + param-recovery ile analiz et.

Black Widow v1.0 -- Karadul

Her Cursor extension icin:
  1. Pipeline: identify -> static -> deobfuscate -> reconstruct -> report
  2. Reconstruction icinde otomatik param_recovery calisir (stages.py'de entegre)
  3. Sonuclari workspaces/Cursor-*/reconstructed/ altinda raporlar

Kullanim:
    python scripts/batch-cursor-full.py [--skip-existing] [--only <name>]
    python scripts/batch-cursor-full.py --only cursor-agent-exec
    python scripts/batch-cursor-full.py --skip-existing
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Proje root'una ekle
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.batch import CURSOR_TARGETS, analyze_single_target, BatchTargetResult


def main() -> None:
    parser = argparse.ArgumentParser(description="Cursor extension batch analysis")
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Zaten analiz edilmis extension'lari atla",
    )
    parser.add_argument(
        "--only", type=str, default=None,
        help="Sadece belirtilen extension'i analiz et (orn: cursor-agent-exec)",
    )
    parser.add_argument(
        "--with-reconstruct", action="store_true", default=True,
        help="Reconstruction stage'i dahil et (varsayilan: True)",
    )
    args = parser.parse_args()

    workspaces_dir = PROJECT_ROOT / "workspaces"

    # Hedef listesi
    if args.only:
        if args.only in CURSOR_TARGETS:
            targets = {args.only: CURSOR_TARGETS[args.only]}
        else:
            print(f"[HATA] Bilinmeyen hedef: {args.only}")
            print(f"  Mevcut hedefler: {', '.join(CURSOR_TARGETS.keys())}")
            sys.exit(1)
    else:
        targets = dict(CURSOR_TARGETS)

    print(f"=== Cursor Full Pipeline ===")
    print(f"  Hedef sayisi: {len(targets)}")
    print(f"  Reconstruction: {'evet' if args.with_reconstruct else 'hayir'}")
    print()

    results: list[BatchTargetResult] = []
    total_start = time.monotonic()

    for i, (name, path_str) in enumerate(targets.items(), 1):
        target_path = Path(path_str)

        # Dosya var mi kontrol
        if not target_path.exists():
            print(f"[{i}/{len(targets)}] {name}: ATLANIYIOR (dosya yok)")
            results.append(BatchTargetResult(
                name=name, path=path_str, category="cursor",
                skipped=True, skip_reason="Dosya bulunamadi",
            ))
            continue

        # Skip existing
        if args.skip_existing:
            # workspace_name = name with Cursor- prefix
            ws_name = f"Cursor-{name}" if not name.startswith("Cursor-") else name
            ws_dir = workspaces_dir / ws_name
            if ws_dir.exists() and any(ws_dir.iterdir()):
                print(f"[{i}/{len(targets)}] {name}: ATLANIYIOR (zaten mevcut)")
                results.append(BatchTargetResult(
                    name=name, path=path_str, category="cursor",
                    skipped=True, skip_reason="Zaten analiz edilmis",
                ))
                continue

        size = target_path.stat().st_size
        size_mb = size / (1024 * 1024)
        print(f"[{i}/{len(targets)}] {name} ({size_mb:.1f}MB) ...")

        start = time.monotonic()

        # Pipeline calistir -- reconstruct stage dahil
        # (stages.py'deki ReconstructionStage otomatik olarak ParamRecovery calistirir)
        try:
            from karadul.config import Config
            from karadul.core.pipeline import Pipeline
            from karadul.stages import (
                IdentifyStage,
                StaticAnalysisStage,
                DeobfuscationStage,
                ReconstructionStage,
                ReportStage,
            )

            cfg = Config()
            cfg.project_root = PROJECT_ROOT

            pipeline = Pipeline(cfg)
            pipeline.register_stage(IdentifyStage())
            pipeline.register_stage(StaticAnalysisStage())
            pipeline.register_stage(DeobfuscationStage())
            if args.with_reconstruct:
                pipeline.register_stage(ReconstructionStage())
            pipeline.register_stage(ReportStage())

            pipeline_result = pipeline.run(target_path)

            duration = time.monotonic() - start

            # Sonuclari topla
            result = BatchTargetResult(
                name=name,
                path=path_str,
                category="cursor",
                success=pipeline_result.success or any(
                    sr.success for sr in pipeline_result.stages.values()
                ),
                duration=duration,
                workspace=str(pipeline_result.workspace_path),
            )

            # Stats
            if "static" in pipeline_result.stages:
                stats = pipeline_result.stages["static"].stats
                result.functions_found = stats.get("functions_found", 0)
                result.strings_found = stats.get("strings_found", 0)

            if "identify" in pipeline_result.stages:
                stats = pipeline_result.stages["identify"].stats
                result.tech_stack = (
                    f"{stats.get('target_type', 'unknown')} / "
                    f"{stats.get('language', 'unknown')}"
                )

            # Reconstruction stats
            recon_stats = {}
            if "reconstruct" in pipeline_result.stages:
                recon = pipeline_result.stages["reconstruct"]
                recon_stats = recon.stats

            # Errors
            for stage_name, sr in pipeline_result.stages.items():
                if sr.errors:
                    result.errors.extend([f"[{stage_name}] {e}" for e in sr.errors[:3]])

            results.append(result)

            # Ozet
            status = "OK" if result.success else "FAIL"
            param_info = ""
            if recon_stats.get("params_recovered", 0) > 0:
                param_info = f", params={recon_stats['params_recovered']} (applied={recon_stats.get('params_applied', 0)})"
            vars_renamed = recon_stats.get("variables_renamed", 0)

            print(f"  [{status}] {duration:.1f}s, funcs={result.functions_found}, vars={vars_renamed}{param_info}")

            if result.errors:
                for err in result.errors[:2]:
                    print(f"  WARN: {err[:100]}")

        except Exception as exc:
            duration = time.monotonic() - start
            result = BatchTargetResult(
                name=name, path=path_str, category="cursor",
                duration=duration,
                errors=[f"Pipeline hatasi: {type(exc).__name__}: {exc}"],
            )
            results.append(result)
            print(f"  [FAIL] {duration:.1f}s -- {exc}")

    total_duration = time.monotonic() - total_start

    # Ozet tablo
    print()
    print(f"{'='*60}")
    print(f"CURSOR BATCH SONUC -- {len(results)} hedef, {total_duration:.1f}s")
    print(f"{'='*60}")
    print(f"{'Extension':<30} {'Durum':<8} {'Sure':>6} {'Funcs':>7} {'Hata':>5}")
    print(f"{'-'*30} {'-'*8} {'-'*6} {'-'*7} {'-'*5}")

    ok_count = 0
    fail_count = 0
    skip_count = 0

    for r in results:
        if r.skipped:
            status = "SKIP"
            skip_count += 1
        elif r.success:
            status = "OK"
            ok_count += 1
        else:
            status = "FAIL"
            fail_count += 1

        dur = f"{r.duration:.1f}s" if r.duration > 0 else "-"
        funcs = str(r.functions_found) if r.functions_found > 0 else "-"
        errs = str(len(r.errors)) if r.errors else "-"
        print(f"  {r.name:<28} {status:<8} {dur:>6} {funcs:>7} {errs:>5}")

    print()
    print(f"  OK: {ok_count}  FAIL: {fail_count}  SKIP: {skip_count}")

    # JSON rapor kaydet
    report_path = PROJECT_ROOT / "workspaces" / "cursor-batch-report.json"
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_duration": round(total_duration, 2),
        "total_targets": len(results),
        "ok": ok_count,
        "fail": fail_count,
        "skip": skip_count,
        "results": [r.to_dict() for r in results],
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Rapor: {report_path}")


if __name__ == "__main__":
    main()
