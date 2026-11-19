#!/usr/bin/env python3
"""HIZ kalem 2 ek: decompile ``.c`` dosyalarının boyut dağılımı (deobfuscate / istihbarat maliyeti için).

Kullanım:
    python scripts/arge/hiz/c_boyut.py <ad>=<decompiled dizini> [<ad>=<dizin> ...]
"""

from __future__ import annotations

import os
import statistics
import sys


def main() -> None:
    print("| İkili | dosya | toplam MB | ortanca KB | p99 KB | en büyük KB | en büyük %1'in bayt payı |")
    print("|---|---|---|---|---|---|---|")
    for arg in sys.argv[1:]:
        ad, d = arg.split("=", 1)
        d = os.path.expanduser(d)
        s = sorted(e.stat().st_size for e in os.scandir(d) if e.name.endswith(".c"))
        ust = s[int(len(s) * 0.99):]
        print("| %s | %d | %.1f | %.1f | %.0f | %.0f | %.0f %% |" % (
            ad, len(s), sum(s) / 1e6, statistics.median(s) / 1e3, s[int(len(s) * 0.99)] / 1e3,
            s[-1] / 1e3, 100.0 * sum(ust) / sum(s)))


if __name__ == "__main__":
    main()
