#!/usr/bin/env python3
"""HIZ kalem 4 ek (Berke'nin düzeltmesi, 2026-11-19): donanıma sabitlenmiş sayıların dökümü.

``karadul/`` altında işçi / iş parçacığı / yığın / bellek sayısını belirleyen satırları bulur
ve üç sınıfa ayırır:
  T  türetilmiş: ``CPU_PERF_CORES`` / ``GHIDRA_HEAP_MB`` / ``os.cpu_count()``'tan,
  S  sabit: düz sayı (ör. ``max_workers=2``, ``min(10, ...)``, ``_MAX_PARALLEL_WORKERS = 10``),
  K  karışık: türetilmiş değer sabit tavan / tabanla kırpılıyor.
Yorum satırları ve test dizinleri atlanır. Salt okur.

Kullanım (depo kökünden):
    python scripts/arge/hiz/sabit_tarama.py [--kok karadul] [--cikti <json>]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DESEN = re.compile(
    r"max_workers\s*=|n_workers\s*=|num_workers\s*=|n_threads\s*=|workers\s*=\s*(?:min|max|\d)"
    r"|_MAX_PARALLEL_WORKERS\s*=|_HARD_PARALLEL_CAP\s*=|PARALLEL_WORKERS\s*=|ActiveProcessorCount"
    r"|ParallelGCThreads|ConcGCThreads|-max-cpu|Xmx|GHIDRA_HEAP_MB\s*=|TOTAL_MEMORY_MB\s*\*"
    r"|cpu_count\(\)|perflevel|return 8192|chunk_size\s*=\s*max\(1,\s*\w+\s*//"
    r"|gc_threads\s*=|conc_threads\s*=|total\s*\*\s*0\.\d|_detect_cpu_cores\(\)"
)
SAYI = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])")
TURETILMIS = re.compile(r"CPU_PERF_CORES|total|GHIDRA_HEAP_MB|TOTAL_MEMORY_MB|cpu_count\(\)|heap_mb|n_threads|self\.config\.|config\.")


def siniflandir(satir: str) -> str:
    kod = satir.split("#", 1)[0]
    sayilar = [s for s in SAYI.findall(kod) if s not in ("0", "1")]
    tur = bool(TURETILMIS.search(kod))
    if tur and sayilar:
        return "K"
    if tur:
        return "T"
    if sayilar:
        return "S"
    return "T"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kok", default="karadul", type=Path)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    bulgular = []
    for p in sorted(a.kok.rglob("*.py")):
        if "tests" in p.parts or "__pycache__" in p.parts:
            continue
        try:
            satirlar = p.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, s in enumerate(satirlar, 1):
            st = s.strip()
            if not st or st.startswith("#") or st.startswith('"') or st.startswith("'"):
                continue
            kod = s.split("#", 1)[0]
            if DESEN.search(kod):
                bulgular.append({"yer": "%s:%d" % (p, i), "sinif": siniflandir(s), "satir": st[:150]})
    for sinif, ad in (("S", "Sabit sayı"), ("K", "Türetilmiş + sabit kırpma"), ("T", "Türetilmiş")):
        sec = [b for b in bulgular if b["sinif"] == sinif]
        print("### %s (%d)" % (ad, len(sec)))
        print()
        print("| Yer | Satır |")
        print("|---|---|")
        for b in sec:
            print("| `%s` | `%s` |" % (b["yer"], b["satir"].replace("|", "\\|")))
        print()
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(bulgular, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
