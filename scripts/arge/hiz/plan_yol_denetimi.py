#!/usr/bin/env python3
"""HIZ kalem 7: PLAN.md'de geçen dosya yollarının varlığını ve satır atıflarının aralığını denetler.

`karadul/…`, `tests/…`, `scripts/…`, `docs/…` yolları çıkarılır; var olmayanlar "yeni" sözcüğüyle
aynı satırda geçiyorsa beklenen sayılır. `dosya.py:N` / `N–M` atıflarında satır sayısı aşılıyorsa
uyarı verir.

Kullanım (depo kökünden):
    python scripts/arge/hiz/plan_yol_denetimi.py docs/arge/2026-11-19_mythos/hiz/PLAN.md
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

YOL = re.compile(r"`((?:karadul|tests|scripts|docs)/[A-Za-z0-9_./<>\-]+)")
ATIF = re.compile(r"`((?:karadul)/[A-Za-z0-9_./\-]+\.py)`\s*\(([^)]*)\)")


def main() -> None:
    p = Path(sys.argv[1])
    eksik_beklenen, eksik_beklenmeyen, var = set(), set(), set()
    for satir in p.read_text(encoding="utf-8").splitlines():
        for m in YOL.finditer(satir):
            y = m.group(1).rstrip(".,")
            if "<" in y or "*" in y:
                continue
            yol = Path(y)
            if yol.exists():
                var.add(y)
            elif "yeni" in satir or "üretilen" in satir or "HZ0.md" in y or "HZ9.md" in y or "on_kayit" in y:
                eksik_beklenen.add(y)
            else:
                eksik_beklenmeyen.add(y)
    print("var: %d" % len(var))
    print("yeni (beklenen): %d" % len(eksik_beklenen))
    for y in sorted(eksik_beklenen):
        print("   ", y)
    print("YOK ve 'yeni' denmemiş: %d" % len(eksik_beklenmeyen))
    for y in sorted(eksik_beklenmeyen):
        print("   !!", y)
    # satır aralığı denetimi
    tekrar = 0
    for satir in p.read_text(encoding="utf-8").splitlines():
        for m in re.finditer(r"`(karadul/[A-Za-z0-9_./\-]+\.py)`[^`|]*?\(([^)]*)\)", satir):
            dosya = Path(m.group(1))
            if not dosya.exists():
                continue
            n = sum(1 for _ in dosya.open(encoding="utf-8"))
            for sayi in re.findall(r"\b(\d{2,5})\b", m.group(2)):
                if int(sayi) > n:
                    tekrar += 1
                    print("   satır aşımı:", dosya, sayi, ">", n)
    print("satır aşımı: %d" % tekrar)


if __name__ == "__main__":
    main()
