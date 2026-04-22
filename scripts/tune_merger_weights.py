#!/usr/bin/env python3
"""NameMerger source weights tuning — scipy.optimize.minimize (Nelder-Mead).

Amaç:
    `karadul/config.py::NameMergerConfig.source_weights` 27 değerini
    gercek binary + debug symbol çiftleri üzerinde F1 max olacak sekilde
    kalibre eder.

Girdi formati:
    `sigs/tuning/` altinda stripped binary + debug sembolleri ciftleri:
        sigs/tuning/train/binary1.json   # stripped analiz ciktisi
        sigs/tuning/train/binary1_gt.json # debug sembollerden ground truth
        ...
        sigs/tuning/val/...               # validation holdout (%20)

    JSON format (analysis output):
        {
            "functions": {
                "FUN_00401000": {
                    "name_candidates": [
                        {"name": "init_config", "source": "c_namer", "confidence": 0.9},
                        {"name": "setup_config", "source": "string_intel", "confidence": 0.7},
                        ...
                    ],
                    "ground_truth": "parse_config"  # _gt.json'dan eslestirilmis
                },
                ...
            }
        }

Cikti:
    `sigs/tuned_weights.json`:
        {
            "weights": {"binary_extractor": 0.97, "c_namer": 0.92, ...},
            "validation_f1_before": 0.654,
            "validation_f1_after": 0.712,
            "iterations": 48,
            "converged": true
        }

Kullanim:
    python scripts/tune_merger_weights.py --data-dir sigs/tuning/ --output sigs/tuned_weights.json

FALLBACK: Eger `sigs/tuning/` yoksa heuristik "sensible default"lar
yazilir (NSRL-benzeri guven olcegi).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Heuristic defaults (NSRL NIST signature confidence olcegi)
# ---------------------------------------------------------------------------

# Sig DB (FLIRT, byte pattern) en yuksek guvenilirlik: ters muhendislik
# icin altin standart. NSRL'de "exact hash match" guveni ~1.0.
# Algorithm template/fusion: orta-yuksek, cross-check edilmis kaynaklar.
# Heuristic (string intel, type guess): dusuk guven.
_HEURISTIC_WEIGHTS: dict[str, float] = {
    # Exact kaynaklar (FLIRT, FunctionID hash-based) — 1.0
    "signature_db": 1.0,
    "function_id": 0.95,
    "swift_demangle": 1.0,
    "byte_pattern": 1.0,
    "binary_extractor": 1.0,
    "sig_db_params": 1.0,
    # Strong sources — 0.85-0.95
    "c_namer": 1.0,            # Ghidra tabanli analiz (dusurulmemeli)
    "signature_based": 0.95,
    "signature_fusion": 0.95,
    "reference_differ": 0.95,
    "computation_fusion": 0.90,
    "rtti_extraction": 0.90,   # ileride eklenecek
    "pcode_dataflow": 0.90,
    "cfg_iso_template": 0.85,
    "algorithm_template": 0.85,
    "source_matcher": 0.85,
    "capa_capability": 0.85,
    "bsim": 0.85,
    "interprocedural_propagation": 0.85,
    "computation_struct_recovery": 0.80,
    "string_intel": 0.80,
    "cross_binary_transfer": 0.80,
    # Moderate sources — 0.65-0.80
    "call_graph_propagation": 0.75,
    "callee_profile": 0.75,
    "struct_context": 0.70,
    "call_context": 0.65,
    # Weak sources — 0.30-0.55
    "type_heuristic": 0.55,
    "llm4decompile": 0.50,
    "computation_recovery": 0.90,  # overall pipeline
}


# ---------------------------------------------------------------------------
# Data loading & scoring
# ---------------------------------------------------------------------------


def _load_tuning_data(data_dir: Path) -> tuple[list[dict], list[dict]]:
    """Tuning + validation split'ini yukle.

    Returns:
        (train_samples, val_samples). Her sample:
            {"candidates": [{"name": str, "source": str, "confidence": float}],
             "ground_truth": str}
    """
    train = []
    val = []
    for split_name, dest in [("train", train), ("val", val)]:
        split_dir = data_dir / split_name
        if not split_dir.exists():
            logger.warning("%s dizini yok: %s", split_name, split_dir)
            continue
        for json_file in sorted(split_dir.glob("*.json")):
            if json_file.name.endswith("_gt.json"):
                continue
            gt_file = json_file.parent / (json_file.stem + "_gt.json")
            if not gt_file.exists():
                continue
            try:
                data = json.loads(json_file.read_text())
                gt_data = json.loads(gt_file.read_text())
            except (OSError, json.JSONDecodeError):
                continue

            funcs = data.get("functions", {})
            gts = gt_data.get("functions", {})
            for fn_addr, fn_data in funcs.items():
                gt = gts.get(fn_addr)
                if not gt:
                    continue
                dest.append({
                    "candidates": fn_data.get("name_candidates", []),
                    "ground_truth": gt,
                })
    return train, val


def _bayesian_merge(
    candidates: list[dict],
    weights: dict[str, float],
    default_weight: float = 0.7,
) -> Optional[str]:
    """Naive Bayes isim secimi (NameMerger davranisi).

    Her isim icin log-odds toplam, en yukseki kazanir.
    """
    import math
    if not candidates:
        return None

    # isim -> log-odds toplam
    scores: dict[str, float] = {}
    for c in candidates:
        name = c.get("name", "")
        source = c.get("source", "")
        conf = c.get("confidence", 0.5)
        w = weights.get(source, default_weight)
        # Log-odds: log(p / (1-p)) * w
        if conf <= 0.0 or conf >= 1.0:
            conf = max(0.01, min(0.99, conf))
        log_odds = math.log(conf / (1 - conf)) * w
        scores[name] = scores.get(name, 0.0) + log_odds

    if not scores:
        return None
    best = max(scores.items(), key=lambda x: x[1])
    return best[0]


def _evaluate_f1(
    samples: list[dict],
    weights: dict[str, float],
) -> float:
    """F1 skor hesapla verilen weight setiyle."""
    tp = fp = fn = 0
    for s in samples:
        gt = s["ground_truth"]
        pred = _bayesian_merge(s["candidates"], weights)
        if pred is None:
            fn += 1
        elif pred == gt:
            tp += 1
        else:
            fp += 1

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    return f1


def _tune_weights(
    train: list[dict],
    val: list[dict],
    initial: dict[str, float],
) -> tuple[dict[str, float], dict]:
    """Nelder-Mead ile weight tuning.

    Signature_db + exact kaynaklar (weight=1.0) sabit tutulur; sadece
    heuristic kaynaklar optimize edilir (9-12 degisken).
    """
    try:
        from scipy.optimize import minimize
    except ImportError:
        logger.error("scipy kurulu degil — tuning yapilamaz")
        return initial, {"error": "scipy not installed"}

    # Sabit = 1.0 olanlari don ayir
    fixed = {k: v for k, v in initial.items() if v >= 0.98}
    mutable = {k: v for k, v in initial.items() if v < 0.98}
    mutable_keys = sorted(mutable.keys())
    x0 = [mutable[k] for k in mutable_keys]

    def objective(x: list[float]) -> float:
        # x degerleri [0.01, 1.0] araliga clamp
        clamped = [max(0.01, min(1.0, float(xi))) for xi in x]
        w = dict(fixed)
        for k, v in zip(mutable_keys, clamped):
            w[k] = v
        f1 = _evaluate_f1(train, w)
        return -f1  # minimize -> max F1

    start = time.monotonic()
    result = minimize(
        objective,
        x0=x0,
        method="Nelder-Mead",
        options={"maxiter": 200, "xatol": 0.01, "fatol": 0.001},
    )
    elapsed = time.monotonic() - start

    tuned = dict(fixed)
    for k, v in zip(mutable_keys, result.x):
        tuned[k] = max(0.01, min(1.0, float(v)))

    # Validation F1
    f1_before = _evaluate_f1(val, initial)
    f1_after = _evaluate_f1(val, tuned)

    report = {
        "validation_f1_before": f1_before,
        "validation_f1_after": f1_after,
        "train_samples": len(train),
        "val_samples": len(val),
        "iterations": int(result.nit),
        "converged": bool(result.success),
        "elapsed_seconds": round(elapsed, 2),
    }

    return tuned, report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NameMerger weights tuning scripti",
    )
    parser.add_argument(
        "--data-dir", type=Path, default=_PROJECT_ROOT / "sigs" / "tuning",
        help="Tuning verisi dizini (train/ + val/ altdizinleriyle)",
    )
    parser.add_argument(
        "--output", type=Path, default=_PROJECT_ROOT / "sigs" / "tuned_weights.json",
        help="Cikti JSON yolu",
    )
    parser.add_argument(
        "--heuristic-only", action="store_true",
        help="Veri bakmadan sadece heuristik defaults yaz",
    )
    args = parser.parse_args()

    # Mevcut config'den baslangic weights al
    from karadul.config import NameMergerConfig
    initial = dict(NameMergerConfig().source_weights)
    logger.info("Mevcut weights yuklendi: %d kaynak", len(initial))

    if args.heuristic_only or not args.data_dir.exists():
        logger.info(
            "Tuning verisi yok veya --heuristic-only -> heuristik defaults yazılıyor",
        )
        # Mevcut weight'lere heuristik'i uygula
        merged = dict(initial)
        for k, v in _HEURISTIC_WEIGHTS.items():
            merged[k] = v
        out = {
            "weights": merged,
            "method": "heuristic",
            "note": (
                "Tuning verisi yok; NSRL-benzeri heuristik guven olcegine "
                "gore ayarlandi. Gercek tuning icin sigs/tuning/ altina "
                "train/ + val/ stripped+debug json ciftleri koyup tekrar calistir."
            ),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(out, indent=2))
        logger.info("Heuristic weights yazildi: %s", args.output)
        return 0

    logger.info("Tuning verisi okunuyor: %s", args.data_dir)
    train, val = _load_tuning_data(args.data_dir)
    logger.info("Train: %d sample, Val: %d sample", len(train), len(val))

    if not train or not val:
        logger.error("Yeterli train veya val verisi yok; heuristik kullanın")
        return 1

    logger.info("Tuning basliyor (Nelder-Mead)...")
    tuned, report = _tune_weights(train, val, initial)

    out = {
        "weights": tuned,
        "method": "nelder_mead",
        **report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2))
    logger.info("Tuned weights yazildi: %s", args.output)
    logger.info(
        "F1 before=%.4f after=%.4f delta=%+.4f",
        report["validation_f1_before"],
        report["validation_f1_after"],
        report["validation_f1_after"] - report["validation_f1_before"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
