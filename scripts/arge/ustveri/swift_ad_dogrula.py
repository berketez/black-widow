"""Swift erişim fonksiyonu adının (üst veriden kurulan tip adı) sembolle tam eşitliği (sembollü ikili gerekir).

`xcrun swift-demangle` yalnız sembol metnini çözer (sistem aracı); hedef ikili çalıştırılmaz.
Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/swift_ad_dogrula.py <ikili> [--dilim arm64] [--cikti x.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho  # noqa: E402
import swift_meta  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    m = macho.load(a.ikili, a.dilim)
    sw = swift_meta.Swift(m)
    tipler = [t for t in sw.types() if t["erisim"] and t["ad"]]
    sym = collections.defaultdict(list)
    for s in m.defined_symbols():
        if s.name.startswith("_$s") and s.name.endswith("Ma"):
            sym[s.value].append(s.name)
    girdi = []
    for t in tipler:
        for n in sym.get(t["erisim"], []):
            girdi.append((t, n))
    out = subprocess.run(["xcrun", "swift-demangle"], input="\n".join(n for _t, n in girdi) + "\n",
                         capture_output=True, text=True, timeout=300).stdout.splitlines()
    on = "type metadata accessor for "
    ayni = uzanti = adsiz_baglam = farkli = 0
    ornek = []
    gorulen = set()
    for (t, _n), satir in zip(girdi, out):
        if t["adres"] in gorulen:
            continue
        gorulen.add(t["adres"])
        gt = satir[len(on):] if satir.startswith(on) else satir
        if gt == t["ad"]:
            ayni += 1
        elif "(uzantı)" in t["ad"]:
            uzanti += 1
        elif "(adsız)" in t["ad"]:
            adsiz_baglam += 1
        else:
            farkli += 1
            if len(ornek) < 8:
                ornek.append((t["ad"][:70], gt[:90]))
    r = {"ikili": a.ikili, "tip": len(tipler), "sembollu": len(gorulen), "ad_tam_ayni": ayni,
         "uzanti_baglaminda": uzanti, "adsiz_baglamda": adsiz_baglam, "farkli": farkli, "farkli_ornek": ornek}
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
