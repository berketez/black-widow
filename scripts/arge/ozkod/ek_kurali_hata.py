#!/usr/bin/env python3
"""K1'in kâhin çapayla verdiği YANLIŞ adların dökümü (dondurulmuş ölçümden SONRA, tanı için).

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali_hata.py --taraf sinama
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402
import ek_kurali as E  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    ap.add_argument("--dogru", type=int, default=0, help="birim başına bu kadar doğru örnek de bas")
    a = ap.parse_args()
    for d in V.hepsi(taraf_=a.taraf):
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = {x: list(v) for x, v in d["gt_adlar"].items()}
        n_dogru = 0
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            t, durum = E.tahmin(fa, ad[fa], gruplar, kaynak, E.MIN_DESTEK)
            if t is None:
                continue
            gt = d["gt_adlar"][fa]
            dogru = K.gt_esit(t, gt)
            if dogru and n_dogru >= a.dogru:
                continue
            n_dogru += dogru
            turler = sorted({g[0] for g, _ in ad[fa]})
            print(f"{d['birim']}/{d['ad']} {'DOGRU ' if dogru else 'YANLIS'} GT `{gt[0]}` ← `{t}` "
                  f"[{'+'.join(turler)}] dizgiler: {sorted({s for _g, s in ad[fa]})[:6]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
