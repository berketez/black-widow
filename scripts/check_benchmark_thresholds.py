#!/usr/bin/env python3
"""
Benchmark threshold checker for Karadul CI gate.

Usage:
    python scripts/check_benchmark_thresholds.py \
        --current /tmp/bench_current.json \
        --baseline benchmarks/baseline_metrics.json \
        --report /tmp/bench_report.md

Exit codes:
    0 - All thresholds passed
    1 - One or more hard-fail thresholds violated
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Hard-fail thresholds (CI blocks commit if violated)
# ---------------------------------------------------------------------------
DEFAULT_THRESHOLDS = {
    "f1_min": 0.85,
    "fun_residue_max_pct": 5.0,
    "type_precision_min": 0.75,
    "regression_warning_pct": 5.0,   # relative drop → warning only
    "regression_fail_pct": 10.0,     # relative drop → hard-fail
}


def load_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(p) as f:
        return json.load(f)


def extract_metrics(bench: dict, binary_key: str = "sample_macho") -> dict:
    """
    Supports two JSON shapes:
    1. benchmark_report.json  → bench["metrics"]
    2. baseline_metrics.json  → bench["binaries"][binary_key]
    """
    if "metrics" in bench:
        return bench["metrics"]
    if "binaries" in bench and binary_key in bench["binaries"]:
        return bench["binaries"][binary_key]
    # Fallback: try root keys directly (flat format)
    return bench


def check_thresholds(
    current: dict,
    baseline: dict | None,
    thresholds: dict,
    binary_key: str = "sample_macho",
) -> tuple[list[str], list[str], list[str]]:
    """
    Returns (failures, warnings, passes).
    Each item is a markdown-formatted string.
    """
    failures: list[str] = []
    warnings: list[str] = []
    passes: list[str] = []

    m = extract_metrics(current, binary_key)

    # ------------------------------------------------------------------
    # 1. Absolute thresholds (hard-fail)
    # ------------------------------------------------------------------
    f1 = m.get("f1", 0.0)
    f1_min = thresholds["f1_min"]
    if f1 >= f1_min:
        passes.append(f"F1 = **{f1:.4f}** >= {f1_min} (PASS)")
    else:
        failures.append(f"F1 = **{f1:.4f}** < {f1_min} (FAIL: hard threshold)")

    fun_residue = m.get("fun_residue_pct", 0.0)
    fun_max = thresholds["fun_residue_max_pct"]
    if fun_residue <= fun_max:
        passes.append(f"FUN residue = **{fun_residue:.2f}%** <= {fun_max}% (PASS)")
    else:
        failures.append(
            f"FUN residue = **{fun_residue:.2f}%** > {fun_max}% (FAIL: hard threshold)"
        )

    type_prec = m.get("type_precision", 0.0)
    type_min = thresholds["type_precision_min"]
    # type_precision 0.0 means "no type data available" — skip when no type info
    if type_prec == 0.0:
        warnings.append(
            f"type_precision = **{type_prec:.4f}** — no type recovery data, threshold skipped"
        )
    elif type_prec >= type_min:
        passes.append(f"type_precision = **{type_prec:.4f}** >= {type_min} (PASS)")
    else:
        failures.append(
            f"type_precision = **{type_prec:.4f}** < {type_min} (FAIL: hard threshold)"
        )

    # ------------------------------------------------------------------
    # 2. Regression vs baseline (relative change)
    # ------------------------------------------------------------------
    if baseline is not None:
        b = extract_metrics(baseline, binary_key)
        baseline_f1 = b.get("f1", 0.0)
        if baseline_f1 > 0.0:
            rel_drop_pct = (baseline_f1 - f1) / baseline_f1 * 100.0
            warn_pct = thresholds["regression_warning_pct"]
            fail_pct = thresholds["regression_fail_pct"]

            if rel_drop_pct <= 0.0:
                passes.append(
                    f"F1 regression = **+{-rel_drop_pct:.2f}%** vs baseline {baseline_f1:.4f} (PASS)"
                )
            elif rel_drop_pct < warn_pct:
                passes.append(
                    f"F1 regression = **-{rel_drop_pct:.2f}%** vs baseline {baseline_f1:.4f} (PASS, within {warn_pct}%)"
                )
            elif rel_drop_pct < fail_pct:
                warnings.append(
                    f"F1 regression = **-{rel_drop_pct:.2f}%** vs baseline {baseline_f1:.4f} "
                    f"(WARNING: >{warn_pct}% drop)"
                )
            else:
                failures.append(
                    f"F1 regression = **-{rel_drop_pct:.2f}%** vs baseline {baseline_f1:.4f} "
                    f"(FAIL: >{fail_pct}% drop)"
                )

    return failures, warnings, passes


def build_report(
    current_path: str,
    baseline_path: str | None,
    failures: list[str],
    warnings: list[str],
    passes: list[str],
    current_metrics: dict,
) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    status_icon = "PASS" if not failures else "FAIL"
    status_emoji = "OK" if not failures else "BLOCKED"

    lines = [
        f"## Karadul Benchmark Gate — {status_icon} [{status_emoji}]",
        f"",
        f"**Run time:** {now}  ",
        f"**Binary:** `sample_macho` (mock mode)  ",
        f"**Baseline:** `{baseline_path or 'n/a'}`",
        f"",
    ]

    m = current_metrics
    lines += [
        "### Current Metrics",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| F1 | {m.get('f1', 0):.4f} |",
        f"| Precision | {m.get('precision', 0):.4f} |",
        f"| Recall | {m.get('recall', 0):.4f} |",
        f"| Accuracy | {m.get('accuracy', 0):.2f}% |",
        f"| Recovery Rate | {m.get('recovery_rate', 0):.2f}% |",
        f"| FUN Residue | {m.get('fun_residue_pct', 0):.2f}% |",
        f"| Type Precision | {m.get('type_precision', 0):.4f} |",
        f"",
    ]

    if passes:
        lines.append("### Passed Checks")
        for p in passes:
            lines.append(f"- {p}")
        lines.append("")

    if warnings:
        lines.append("### Warnings")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    if failures:
        lines.append("### FAILURES (hard-fail)")
        for f in failures:
            lines.append(f"- {f}")
        lines.append("")

    if not failures:
        lines.append("> All benchmark thresholds passed. Commit is clear.")
    else:
        lines.append(
            "> **Commit blocked.** Fix the above failures before merging to main."
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Karadul benchmark threshold checker")
    parser.add_argument("--current", required=True, help="Current benchmark JSON path")
    parser.add_argument("--baseline", default=None, help="Baseline metrics JSON path")
    parser.add_argument("--report", default=None, help="Output markdown report path")
    parser.add_argument(
        "--binary-key",
        default="sample_macho",
        help="Key inside 'binaries' dict in baseline (default: sample_macho)",
    )
    args = parser.parse_args()

    current = load_json(args.current)
    baseline = load_json(args.baseline) if args.baseline else None

    # Merge thresholds: baseline file may override defaults
    thresholds = dict(DEFAULT_THRESHOLDS)
    if baseline and "thresholds" in baseline:
        thresholds.update(baseline["thresholds"])

    failures, warnings, passes = check_thresholds(
        current, baseline, thresholds, args.binary_key
    )

    current_metrics = extract_metrics(current, args.binary_key)
    report_md = build_report(
        args.current,
        args.baseline,
        failures,
        warnings,
        passes,
        current_metrics,
    )

    if args.report:
        Path(args.report).write_text(report_md)
        print(f"Report written to: {args.report}")

    print(report_md)

    if failures:
        print(f"\n[FAIL] {len(failures)} hard threshold(s) violated.", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n[PASS] All thresholds passed ({len(passes)} checks, {len(warnings)} warnings).")
        sys.exit(0)


if __name__ == "__main__":
    main()
