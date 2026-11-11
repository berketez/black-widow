"""Deney 1 denetimi: bütün havuzda derin iz (ürün ayarı ve büyük bütçe) — örneklemin yerine geçmez.

deney1_derin_iz.py ile aynı girdi ve aynı ürün izleyicisi; havuzdaki HER fonksiyon için
"kökün kendi etiketinde olmayan, alt ağaçtan gelen algoritma etiketi" var mı sayılır.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2]))

import deney1_derin_iz as d1  # noqa: E402
import karadul.reconstruction.engineering.deep_tracer as dt  # noqa: E402
from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier  # noqa: E402
from say_sinirlar import BINARIES, workspace  # noqa: E402


def main() -> None:
    out = {}
    for label, base in BINARIES.items():
        ws = workspace(base)
        cg = json.loads(d1.pick(ws, "ghidra_call_graph.json").read_text(encoding="utf-8"))
        deob = ws / "deobfuscated/decompiled"
        algos = CAlgorithmIdentifier().identify(
            deob, d1.pick(ws, "ghidra_functions.json"), d1.pick(ws, "ghidra_strings.json")).algorithms
        # Mühendislik kolu ürün durumunda (kapı kapalı) bu yedi ikilide 0 tespit verdi (deney2).
        targets = dt.DeepCallChainTracer(max_depth=8, max_targets=3)._select_targets(cg, algos, 3)
        names = sorted({i.get("name", "") for i in cg.get("nodes", {}).values()} - {""} - set(targets))
        res = {"pool": len(names), "product": 0, "big": 0, "big_only": 0,
               "product_truncated": 0, "seconds": 0.0}
        t0 = time.monotonic()
        prod = dt.DeepCallChainTracer(max_depth=8, algo_priority_depth=5)
        big = dt.DeepCallChainTracer(max_depth=64, algo_priority_depth=64)
        for n in names:
            own = {a.name for a in algos if a.function_name == n}
            rp, _ = d1.trace(prod, n, cg, algos, big=False)
            rb, _ = d1.trace(big, n, cg, algos, big=True)
            lp = d1.descendant_labels(rp, own)
            lb = d1.descendant_labels(rb, own)
            res["product"] += bool(lp)
            res["big"] += bool(lb)
            res["big_only"] += bool(lb - lp)
            res["product_truncated"] += bool(rp.errors)
        res["seconds"] = round(time.monotonic() - t0, 1)
        out[label] = res
        print(label, res, flush=True)
    (HERE / "deney1_tam_sayim.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
