#!/usr/bin/env python3
"""K1 (kâhin çapa) adlarının GT'ye yakınlığı üç düzeyde + belirteç kesinliği / duyarlılığı.

Dondurulmuş ``ek_kurali.py`` değişmez; bu betik onun ``adaylar`` / ``tahmin`` fonksiyonlarını
çağırır ve yalnız sayar. Düzeyler:
  karakter  : hesaplanan ad == GT adı (ürün ölçüsü; kural adı snake_case yazar)
  norm      : belirteç dizileri eşit (ayraç / büyük-küçük harf biçimi serbest)
  ayracsiz  : harf ve rakam dışı her şey atılıp küçültülünce eşit (belirteç sınırı da serbest)
Belirteç ölçüleri (mikro; ≥ 2 karakter, rakam dışı belirteç kümesi üstünde):
  kesinlik = |aday ∩ GT| / |aday|, duyarlılık = |aday ∩ GT| / |GT|; en iyi GT takma adı alınır.
Hangi ölçünün insan yargısıyla uyuştuğu ÖLÇÜ hattının işidir; burada yalnız sayılır.

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali_belirtec.py --taraf sinama
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402
import ek_kurali as E  # noqa: E402


def ayracsiz(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s).lower()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    a = ap.parse_args()
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=a.taraf):
        c = birim[d["birim"]]
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = {x: list(v) for x, v in d["gt_adlar"].items()}
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            t, _durum = E.tahmin(fa, ad[fa], gruplar, kaynak, E.MIN_DESTEK)
            if t is None:
                continue
            gt = d["gt_adlar"][fa]
            c["ad"] += 1
            c["karakter"] += t in gt
            c["norm"] += K.gt_esit(t, gt)
            c["ayracsiz"] += any(ayracsiz(t) == ayracsiz(g) for g in gt)
            tb = set(V.ad_belirtecleri(t))
            en_iyi = max(((len(tb & set(V.ad_belirtecleri(g))), len(set(V.ad_belirtecleri(g))))
                          for g in gt), key=lambda x: (x[0] / x[1] if x[1] else 0))
            c["ortak"] += en_iyi[0]
            c["aday_belirtec"] += len(tb)
            c["gt_belirtec"] += en_iyi[1]
    top: Counter = Counter()
    for c in birim.values():
        top.update(c)
    print(f"## K1 adlarının yakınlığı — taraf: {a.taraf}")
    print("| birim | ad | karakter | norm | ayraçsız | belirteç kesinliği | belirteç duyarlılığı |")
    print("|---|---:|---|---|---|---|---|")
    for b, c in sorted(birim.items()) + [("**toplam**", top)]:
        n = c["ad"]
        if not n:
            continue
        print(f"| {b} | {n} | {V.wilson(c['karakter'], n)} | {V.wilson(c['norm'], n)} | {V.wilson(c['ayracsiz'], n)} "
              f"| {c['ortak']} / {c['aday_belirtec']} (%{100 * c['ortak'] / c['aday_belirtec']:.1f}) "
              f"| {c['ortak']} / {c['gt_belirtec']} (%{100 * c['ortak'] / c['gt_belirtec']:.1f}) |")
    cikti = V.ARGE_KOKU / "ek_kurali" / f"ek_kurali_belirtec_{a.taraf}.json"
    cikti.write_text(json.dumps({b: dict(c) for b, c in birim.items()}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
