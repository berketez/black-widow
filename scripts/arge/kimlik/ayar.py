#!/usr/bin/env python
"""KİMLİK hattı — parametre ayarı, YALNIZ keşif çiftinde (htop, iki yön).

Izgara taranır; her nokta için iki yönün havuzlanmış nüfus içi kesinliği (Wilson) ve kapsamı yazılır.
Seçim kuralı (DEFTER.md §5.3): Wilson alt sınırı ≥ 0,95 olan noktalar içinde en yüksek havuz kapsamı;
eşitlikte daha tutucu (yüksek T, yüksek marj, yüksek kütle) nokta.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/ayar.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import ks1  # noqa: E402

IZGARA = {
    "T": [0.3, 0.4, 0.5, 0.6, 0.7],
    "marj": [0.05, 0.1, 0.15, 0.2, 0.3],
    "kutle": [0.5, 1.0, 1.5, 2.0, 3.0],
    "sabit_carpani": [0.0, 0.5, 1.0],
    "komsu_sart": [False, True],
}


def nokta(cift_veri, p: esle.Param) -> dict:
    d = y = nuf = 0
    yonler = []
    for Q, R in cift_veri:
        s = esle.esle(Q, R, p)
        o = esle.olc(Q, R, s.esler)
        d += o["dogru"]
        y += o["yanlis"]
        nuf += o["nufus"]
        yonler.append({"sorgu": Q.kimlik, "dogru": o["dogru"], "yanlis": o["yanlis"], "nufus": o["nufus"]})
    return {"dogru": d, "yanlis": y, "nufus": nuf, "kesinlik": ks1.oran(d, d + y), "kapsam": ks1.oran(d, nuf),
            "yonler": yonler}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    cift_veri = []
    for x, y in ciftler.grup("kesif_htop"):
        X, Y = veri.yukle(x), veri.yukle(y)
        cift_veri += [(X, Y), (Y, X)]
    satirlar = []
    for T, marj, kutle, sc, ks in itertools.product(*IZGARA.values()):
        carpan = tuple((t, sc if t == "s" else c) for t, c in esle.Param().carpan)
        turler = tuple(t for t in esle.Param().turler if not (t == "s" and sc == 0.0))
        p = replace(esle.Param(), T=T, marj=marj, kutle=kutle, carpan=carpan, turler=turler, komsu_sart=ks)
        n = nokta(cift_veri, p)
        n["param"] = {"T": T, "marj": marj, "kutle": kutle, "sabit_carpani": sc, "komsu_sart": ks}
        satirlar.append(n)
    uygun = [s for s in satirlar if s["kesinlik"]["aralik"] and s["kesinlik"]["aralik"][0] >= 0.95]
    uygun.sort(key=lambda s: (-s["dogru"], -s["param"]["T"], -s["param"]["marj"], -s["param"]["kutle"]))
    print(f"ızgara {len(satirlar)} nokta; Wilson alt ≥ 0,95 olan {len(uygun)}")
    for s in uygun[:15]:
        k = s["kesinlik"]
        print(f"  {s['param']}  doğru {s['dogru']} yanlış {s['yanlis']} kesinlik {k['oran']:.3f} "
              f"(alt {k['aralik'][0]:.3f}) kapsam {s['kapsam']['oran'] * 100:.1f}%")
    en = sorted(satirlar, key=lambda s: -s["dogru"])[:5]
    print("en yüksek kapsam (kesinlik koşulsuz):")
    for s in en:
        k = s["kesinlik"]
        print(f"  {s['param']}  doğru {s['dogru']} yanlış {s['yanlis']} kesinlik {k['oran']:.3f} (alt {k['aralik'][0]:.3f})")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps({"izgara": IZGARA, "satirlar": satirlar}, ensure_ascii=False, indent=1),
                          encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
