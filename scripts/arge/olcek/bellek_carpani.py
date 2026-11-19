#!/usr/bin/env python
"""ÖLÇEK kalem 2–3: Ghidra çıktı JSON'larının Python belleğindeki karşılığı (bayt / disk baytı).

Ürün, Ghidra köprüsünde bütün çıktıları Python sözlüğü olarak bellekte tutar
(``karadul/ghidra/headless.py`` ``scripts_output``), sonra reconstruct adımları aynı dosyaları
``read_text`` + ``json.loads`` ile yeniden okur. Bu betik her dosyayı AYRI bir alt süreçte
``json.loads(read_text())`` ile açar ve azami RSS artışını ölçer (macOS ``ru_maxrss`` bayt).

Çarpan = (RSS_sonra − RSS_önce) / dosya baytı. Tepe = metin + nesneler birlikte (ürünün yolu da
böyle: önce ``read_text``, sonra ``json.loads``).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/bellek_carpani.py \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/bellek_carpani.json DOSYA [DOSYA …]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_COCUK = r"""
import json, resource, sys
from pathlib import Path
p = Path(sys.argv[1])
r0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
d = json.loads(p.read_text(encoding="utf-8"))
r1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"rss_once": r0, "rss_sonra": r1}))
"""


def olc(p: Path) -> dict:
    out = subprocess.run([sys.executable, "-I", "-c", _COCUK, str(p)], capture_output=True,
                         text=True, check=True)
    r = json.loads(out.stdout)
    boyut = p.stat().st_size
    r.update({"dosya": str(p), "bayt": boyut,
              "carpan": round((r["rss_sonra"] - r["rss_once"]) / boyut, 2) if boyut else None})
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cikti", required=True, type=Path)
    ap.add_argument("dosyalar", nargs="+", type=Path)
    a = ap.parse_args(argv)
    sonuc = []
    for p in a.dosyalar:
        r = olc(p.expanduser())
        sonuc.append(r)
        print(f"{r['bayt']/2**20:8.1f} MiB  çarpan {r['carpan']:5.2f}  {p}")
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
