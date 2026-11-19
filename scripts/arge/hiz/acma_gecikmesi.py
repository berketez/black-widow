#!/usr/bin/env python3
"""HIZ kalem 4 (disk): küçük dosya açma / yazma gecikmesi.

(1) Var olan bir dizindeki ilk N dosyayı salt okur açar-okur-kapatır;
(2) kendi yazma alanında (``--yaz``) N küçük dosya oluşturur (silme YOK; dosyalar kalır).
Açılış başına gecikme dağılımı (ortanca, p90, p99) basılır. Makine yükü de kaydedilir.

Kullanım:
    python scripts/arge/hiz/acma_gecikmesi.py --oku <dizin> --yaz <yeni dizin> --n 2000
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from pathlib import Path


def _dag(xs: list[float]) -> dict:
    xs = sorted(xs)
    return {"n": len(xs), "ortanca_ms": 1e3 * statistics.median(xs),
            "p90_ms": 1e3 * xs[int(len(xs) * 0.9)], "p99_ms": 1e3 * xs[int(len(xs) * 0.99)],
            "toplam_sn": sum(xs)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oku", type=Path, required=True)
    ap.add_argument("--yaz", type=Path, help="verilmezse yazma ölçülmez")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    out = {"yuk": os.getloadavg()}
    dosyalar = sorted(e.path for e in os.scandir(a.oku.expanduser()) if e.is_file())[: a.n]
    ac, oku = [], []
    for p in dosyalar:
        t0 = time.perf_counter()
        fh = open(p, "rb")
        t1 = time.perf_counter()
        fh.read()
        fh.close()
        t2 = time.perf_counter()
        ac.append(t1 - t0)
        oku.append(t2 - t1)
    out["oku_ac"] = _dag(ac)
    out["oku_oku_kapat"] = _dag(oku)
    olus, yazk = [], []
    veri = b"x" * 4096
    yaz = a.yaz.expanduser() if a.yaz else None
    if yaz is not None:
        yaz.mkdir(parents=True, exist_ok=False)
    for i in range(a.n if yaz is not None else 0):
        p = yaz / ("f%05d.c" % i)
        t0 = time.perf_counter()
        fh = open(p, "xb")
        t1 = time.perf_counter()
        fh.write(veri)
        fh.close()
        t2 = time.perf_counter()
        olus.append(t1 - t0)
        yazk.append(t2 - t1)
    if olus:
        out["yeni_olustur"] = _dag(olus)
        out["yeni_yaz_kapat"] = _dag(yazk)
    out["yuk_son"] = os.getloadavg()
    for k in ("oku_ac", "oku_oku_kapat", "yeni_olustur", "yeni_yaz_kapat"):
        if k not in out:
            continue
        d = out[k]
        print("%-16s n=%d ortanca %.3f ms  p90 %.3f ms  p99 %.3f ms  toplam %.2f sn" % (
            k, d["n"], d["ortanca_ms"], d["p90_ms"], d["p99_ms"], d["toplam_sn"]))
    print("yük:", out["yuk"], "→", out["yuk_son"])
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
