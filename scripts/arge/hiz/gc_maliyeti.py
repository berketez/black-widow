#!/usr/bin/env python3
"""HIZ kalem 4: decompile sonuçları bellekteyken Python döngüsel çöp toplayıcısının maliyeti.

Ürün decompile sırasında her fonksiyonun seçici pcode'unu Python listeleri olarak toplar ve
hepsini ``_all_functions`` içinde ``pcode.jsonl`` yazılana kadar tutar
(``karadul/ghidra/headless.py:1522-1577``, ``:1303-1306``, ``:454-465``). Bu betik aynı veriyi
``pcode.jsonl``'den belleğe alır (aynı şekil: op = [mnemonic, out, [girdiler]]) ve
  - izlenen kap (container) sayısını,
  - tek bir tam toplamanın (``gc.collect()``, GIL tutulur) süresini,
  - aynı veriyi baştan kurarken toplayıcının kaç kez ve ne kadar koştuğunu (``gc.callbacks``)
ölçer. ``gc.freeze()`` sonrası tam toplamanın süresi de yazılır.

Kullanım:
    python scripts/arge/hiz/gc_maliyeti.py --jsonl <static/ghidra_output/pcode.jsonl> \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/gc_maliyeti.json
"""

from __future__ import annotations

import argparse
import gc
import json
import time
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True, type=Path)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()

    olay = {"sayi": [0, 0, 0], "sure": [0.0, 0.0, 0.0]}
    bas = {}

    def cb(phase, info):
        g = info.get("generation", 0)
        if phase == "start":
            bas[g] = time.perf_counter()
        elif g in bas:
            olay["sayi"][g] += 1
            olay["sure"][g] += time.perf_counter() - bas.pop(g)

    gc.collect()
    gc.callbacks.append(cb)
    t0 = time.perf_counter()
    tum = []
    with a.jsonl.expanduser().open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            # Ürünün tuttuğu şekil: sonuç sözlüğü + pcode_ops + pcode_high_vars
            tum.append({"name": r["n"], "address": r["a"], "success": True,
                        "pcode_ops": r["ops"], "pcode_high_vars": r["vars"]})
    kur = time.perf_counter() - t0
    gc.callbacks.remove(cb)
    kap = len(gc.get_objects())
    t1 = time.perf_counter()
    gc.collect()
    tam = time.perf_counter() - t1
    gc.freeze()
    t2 = time.perf_counter()
    gc.collect()
    donuk = time.perf_counter() - t2
    gc.unfreeze()
    out = {"fonksiyon": len(tum), "izlenen_kap": kap, "kurulum_sn": kur,
           "kurulum_sirasinda_gc": olay, "tam_toplama_sn": tam, "freeze_sonrasi_tam_toplama_sn": donuk,
           "esikler": gc.get_threshold()}
    print(json.dumps(out, indent=1))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
