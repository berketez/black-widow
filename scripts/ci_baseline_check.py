#!/usr/bin/env python3
"""
CI baseline check for Karadul v1.11.0+ benchmark gate.

Reads the committed baseline JSON, extracts renamed_f1, and compares it
against an absolute floor (and optionally a previously-saved regression
baseline stored at .benchmark-baseline.json in the repo root).

Exit codes:
    0 - renamed_f1 >= floor and no regression detected
    1 - renamed_f1 < floor OR regression vs committed baseline

Usage (CI):
    python scripts/ci_baseline_check.py \
        --baseline benchmarks/stripped_baseline_2026_04_23_real.json \
        --floor 0.0

Usage (local, with regression comparison):
    python scripts/ci_baseline_check.py \
        --baseline benchmarks/stripped_baseline_2026_04_23_real.json \
        --prev-baseline .benchmark-baseline.json \
        --floor 0.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults (updated per Dalga milestone)
# ---------------------------------------------------------------------------
DEFAULT_FLOOR: float = 0.0
# v1.11 beta: stripped user functions are not resolved yet → renamed_f1 = 0.0
# v1.13 target: raise to 0.5 when stripped ELF naming is implemented


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"ERROR: baseline file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def extract_renamed_f1(data: dict) -> float:
    """Extract renamed_f1 from two supported JSON shapes.

    Shape 1 (stripped_baseline_2026_04_23_real.json):
        { "metrics": { "renamed_f1": 0.0, ... }, ... }

    Shape 2 (flat format from check_benchmark_thresholds.py):
        { "renamed_f1": 0.0, ... }
    """
    if "metrics" in data and isinstance(data["metrics"], dict):
        return float(data["metrics"].get("renamed_f1", 0.0))
    return float(data.get("renamed_f1", 0.0))


def check_floor(renamed_f1: float, floor: float) -> bool:
    """Return True if renamed_f1 satisfies the floor threshold."""
    return renamed_f1 >= floor


def check_regression(
    current_f1: float, prev_data: dict | None
) -> tuple[bool, str]:
    """Compare current renamed_f1 against a previously-saved baseline.

    Returns (ok, message).
    ok=True means no regression; ok=False means hard-fail regression.

    Regression rule: if previous renamed_f1 > 0.0 and current is lower,
    that is a regression. When both are 0.0 (v1.11 beta state), it is not
    a regression — it is the expected baseline.
    """
    if prev_data is None:
        return True, "No previous baseline found — skipping regression check."

    prev_f1 = extract_renamed_f1(prev_data)
    if prev_f1 <= 0.0:
        return True, f"Previous renamed_f1={prev_f1:.4f} (zero baseline) — regression check skipped."

    if current_f1 >= prev_f1:
        return True, f"renamed_f1={current_f1:.4f} >= prev={prev_f1:.4f} (no regression)"

    drop_pct = (prev_f1 - current_f1) / prev_f1 * 100.0
    msg = (
        f"REGRESSION: renamed_f1 dropped from {prev_f1:.4f} to {current_f1:.4f} "
        f"({drop_pct:.1f}% relative drop)"
    )
    return False, msg


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Karadul CI: renamed_f1 gate check"
    )
    parser.add_argument(
        "--baseline",
        default="benchmarks/stripped_baseline_2026_04_23_real.json",
        help="Path to the committed benchmark baseline JSON "
             "(default: benchmarks/stripped_baseline_2026_04_23_real.json)",
    )
    parser.add_argument(
        "--prev-baseline",
        default=".benchmark-baseline.json",
        help="Path to a previously committed regression baseline JSON. "
             "If missing, regression check is skipped. "
             "(default: .benchmark-baseline.json)",
    )
    parser.add_argument(
        "--floor",
        type=float,
        default=DEFAULT_FLOOR,
        help=f"Minimum acceptable renamed_f1 (default: {DEFAULT_FLOOR}). "
             "Hard-fail if current < floor.",
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    prev_path = Path(args.prev_baseline)
    floor: float = args.floor

    # ------------------------------------------------------------------
    # 1. Load current baseline
    # ------------------------------------------------------------------
    data = load_json(baseline_path)
    renamed_f1 = extract_renamed_f1(data)
    print(f"[check] baseline: {baseline_path}")
    print(f"[check] renamed_f1 = {renamed_f1:.4f}  floor = {floor:.4f}")

    # ------------------------------------------------------------------
    # 2. Floor check
    # ------------------------------------------------------------------
    floor_ok = check_floor(renamed_f1, floor)
    if floor_ok:
        print(f"[PASS]  renamed_f1 {renamed_f1:.4f} >= floor {floor:.4f}", flush=True)
    else:
        print(f"[FAIL]  renamed_f1 {renamed_f1:.4f} < floor {floor:.4f}", flush=True)

    # ------------------------------------------------------------------
    # 3. Regression check (optional; skipped if prev file absent)
    # ------------------------------------------------------------------
    prev_data: dict | None = None
    if prev_path.exists():
        try:
            prev_data = load_json(prev_path)
        except SystemExit:
            prev_data = None
    else:
        print(
            f"[info]  {prev_path} not found — regression check skipped "
            f"(first run or baseline not committed yet)",
            flush=True,
        )

    reg_ok, reg_msg = check_regression(renamed_f1, prev_data)
    tag = "[PASS] " if reg_ok else "[FAIL] "
    print(f"{tag} {reg_msg}", flush=True)

    # ------------------------------------------------------------------
    # 4. Exit
    # ------------------------------------------------------------------
    if floor_ok and reg_ok:
        print("[OK]    Benchmark gate passed.", flush=True)
        sys.exit(0)
    else:
        print("[BLOCKED] Benchmark gate failed — see [FAIL] lines above.", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
