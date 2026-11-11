"""Deney 1: derin çağrı zinciri izlemenin "ilk 3 hedef" sınırı.

Sınır: pipeline/steps/_deep_tracing_helpers.py:304-309 — DeepCallChainTracer(max_depth=8,
max_targets=3).trace_auto(..., top_n=3). Toplu geçiş yalnız 3 hedefi izler; geri kalan bütün
fonksiyonlar için iz yoktur (DeepTraceConfig.max_trace_depth=10 / max_trace_targets=5,
config.py:610-611, okunmuyor). İz içinde ek sınırlar: deep_tracer.py:49-52
(_TRACE_TIMEOUT 300 sn, _AUTO_TIMEOUT 600 sn, _MAX_NODES_PER_TRACE 5000, _MAX_CALLEES_PER_NODE 100)
ve algo_priority_depth=5 (deep_tracer.py:344).

Girdi: saklı çağrı grafiği (deobfuscated/ghidra_call_graph.json; yeni ürünle aynı) ve HEAD
kodunun algoritma tespitleri (CAlgorithmIdentifier.identify + EngineeringAlgorithmAnalyzer,
ürün durumu: alan kapısı kapalı). Eski ürünün algorithms.json'u kullanılmaz (yeni ürün o
tespitlerin çoğunu artık vermiyor; tree'de 78 -> 0).

Kollar: ürün ayarı (max_depth=8, algo_priority_depth=5) ve büyük bütçe (max_depth=64,
algo_priority_depth=64, düğüm ve çağrılan tavanı 10^6).

Örneklem (önceden yazıldı): ürünün _select_targets ile seçtiği 3 hedef dışındaki fonksiyonların
havuzu (ikili, ad) sırasına dizilir; random.Random(20261111).sample(havuz, 30).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import karadul.reconstruction.engineering.deep_tracer as dt  # noqa: E402
from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier  # noqa: E402
from karadul.reconstruction.engineering.analyzer import EngineeringAlgorithmAnalyzer  # noqa: E402
from say_sinirlar import BINARIES, workspace  # noqa: E402

SEED = 20261111
SAMPLE = 30


def pick(ws: Path, name: str) -> Path:
    p = ws / "deobfuscated" / name
    return p if p.exists() else ws / "static" / name


def trace(tracer, target, cg, algos, big: bool):
    saved = (dt._MAX_NODES_PER_TRACE, dt._MAX_CALLEES_PER_NODE)
    if big:
        dt._MAX_NODES_PER_TRACE, dt._MAX_CALLEES_PER_NODE = 10**6, 10**6
    try:
        t0 = time.monotonic()
        r = tracer.trace(target_function=target, call_graph=cg, algorithms=algos)
        return r, time.monotonic() - t0
    finally:
        dt._MAX_NODES_PER_TRACE, dt._MAX_CALLEES_PER_NODE = saved


def descendant_labels(result, root_labels: set[str]) -> set[str]:
    if not result.success or result.root is None:
        return set()
    return set(result.algorithms_found) - root_labels


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    pool = []
    ctx = {}
    census = {}
    for label, base in BINARIES.items():
        ws = workspace(base)
        cg = json.loads(pick(ws, "ghidra_call_graph.json").read_text(encoding="utf-8"))
        deob = ws / "deobfuscated/decompiled"
        fjson = pick(ws, "ghidra_functions.json")
        sjson = pick(ws, "ghidra_strings.json")
        ca = CAlgorithmIdentifier().identify(deob, fjson, sjson).algorithms
        en = EngineeringAlgorithmAnalyzer()
        errs: list[str] = []
        meta = en._load_json(fjson, errs)
        files = en._collect_c_files(deob, errs)
        gate = en._detect_domain(meta, files)
        raw = []
        for f in files:
            raw.extend(en._analyze_file(f, meta, gate))
        eng = en._deduplicate(en._combine_evidence(raw))
        algos = list(ca) + list(eng)
        algo_funcs = {a.function_name for a in algos}
        targets = dt.DeepCallChainTracer(max_depth=8, max_targets=3)._select_targets(cg, algos, 3)
        names = sorted({info.get("name", "") for info in cg.get("nodes", {}).values()} - {""})
        ctx[label] = (cg, algos)
        census[label] = {
            "functions_in_call_graph": len(names),
            "algorithm_detections_head": len(algos),
            "functions_with_detection": len(algo_funcs),
            "product_targets": targets,
        }
        for n in names:
            if n not in targets:
                pool.append((label, n))
        print(label, census[label], flush=True)

    pool.sort()
    sample = random.Random(SEED).sample(pool, min(SAMPLE, len(pool)))
    rows = []
    for label, name in sample:
        cg, algos = ctx[label]
        root_labels = {a.name for a in algos if a.function_name == name}
        row = {"binary": label, "function": name, "own_labels": sorted(root_labels)}
        for arm, big in (("product", False), ("big", True)):
            tracer = dt.DeepCallChainTracer(max_depth=64 if big else 8,
                                            algo_priority_depth=64 if big else 5)
            r, secs = trace(tracer, name, cg, algos, big)
            row[arm] = {
                "success": r.success, "nodes": r.total_nodes, "depth": r.max_depth_reached,
                "descendant_labels": sorted(descendant_labels(r, root_labels)),
                "errors": r.errors, "seconds": round(secs, 4),
            }
        rows.append(row)
    summary = {
        "n": len(rows),
        "product_with_descendant_labels": sum(1 for r in rows if r["product"]["descendant_labels"]),
        "big_with_descendant_labels": sum(1 for r in rows if r["big"]["descendant_labels"]),
        "big_extra_over_product": sum(1 for r in rows
                                      if set(r["big"]["descendant_labels"]) - set(r["product"]["descendant_labels"])),
        "product_seconds_max": max(r["product"]["seconds"] for r in rows),
        "big_seconds_max": max(r["big"]["seconds"] for r in rows),
        "big_seconds_median": sorted(r["big"]["seconds"] for r in rows)[len(rows) // 2],
        "big_nodes_median": sorted(r["big"]["nodes"] for r in rows)[len(rows) // 2],
    }
    print("sample", summary)
    Path(args.out).write_text(json.dumps({"seed": SEED, "pool_size": len(pool), "census": census,
                                          "summary": summary, "rows": rows},
                                         indent=1, ensure_ascii=False, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
