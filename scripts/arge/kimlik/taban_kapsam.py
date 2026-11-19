#!/usr/bin/env python
"""KİMLİK hattı — taban ürünün (a62f15e) birim başına nüfus içi doğru ad kapsamı, OLGU tablosundan.

Karşılaştırma satırı için: ``nufusta`` ve ``hukum == "dogru"`` sayımı (birim ve OLGU kaynak sınıfı başına).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/taban_kapsam.py
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import olgu_capraz  # noqa: E402
from veri import ks1  # noqa: E402


def main() -> int:
    say: dict[str, list[int]] = {}
    with gzip.open(olgu_capraz.OLGU, "rt", encoding="utf-8") as f:
        for satir in f:
            k = json.loads(satir)
            if not k.get("nufusta"):
                continue
            for anahtar in (k["birim"], "sınıf:" + k["kaynak_sinifi"], "TOPLAM"):
                s = say.setdefault(anahtar, [0, 0, 0])
                s[0] += 1
                s[1] += k.get("hukum") == "dogru"
                s[2] += k.get("hukum") == "yanlis"
    for anahtar, (n, d, y) in sorted(say.items()):
        o = ks1.oran(d, n)
        print(f"{anahtar:26s} nüfus {n:6d} doğru {d:5d} yanlış {y:4d} doğru ad kapsamı {o['oran'] * 100:5.1f}% "
              f"[{o['aralik'][0] * 100:.1f}, {o['aralik'][1] * 100:.1f}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
