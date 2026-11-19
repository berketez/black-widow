#!/usr/bin/env python3
"""K1'in BUGÜN (ve önerilen onarımlardan sonra) elde edilebilir çapalarla getirisi.

Dondurulmuş ``ek_kurali.py`` değişmez (``adaylar`` / ``tahmin`` çağrılır; MIN_DESTEK = 2,
MIN_ORAN = 0,5). Yalnız çapa adlarının kaynağı değişir:
  A  on_ad + ks1 : ürünün ön ad kanalları (``on_ad:*``, ``ks1:*``) + Ghidra'nın jenerik olmayan adı
                   (``oz_ad`` adları çapa DEĞİL: ölçülmüş kesinliği %47)
  B  A + R1      : A + R1'i sağlayan ``oz_ad`` adları, kanıt dizgisinin harfleriyle (ÖK-1 + ÖK-2 sonrası)
  C  A + G1      : A + G1 adları (tekil tanımlayıcı dizgi; ÖK-3 girerse)
  D  hepsi       : ürünün bugünkü bütün adları (``ek_kurali.py``'deki "urun" kipiyle aynı; denetim)
Hedef: nüfusta, o kipte çapa adı OLMAYAN fonksiyonlar. Sayılan: ad / doğru (norm) / karakter eşit.

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali_capa.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402
import ek_kurali as E  # noqa: E402
import oz_ad_ayrim as O  # noqa: E402
import oz_ad_uretici as G  # noqa: E402

KIPLER = ("A on_ad+ks1", "B A+R1", "C A+G1", "D hepsi")


def main() -> int:
    f1 = V.ks1()._f1()
    say: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for taraf_ in ("kesif", "sinama"):
        r1 = {(o["birim"], o["ikili"], o["adres"]): o for o in O.ozellikler(taraf_)}
        for d in V.hepsi(taraf_=taraf_):
            ad = E.adaylar(d)
            gruplar = defaultdict(list)
            for fa, liste in ad.items():
                for grup, s in liste:
                    gruplar[grup].append((fa, s))
            ghidra = {a: [f["ad"]] for a, f in d["fonk"].items()
                      if not f["thunk"] and not f["dis"] and not f1.is_generic_name(f["ad"], [a])}
            kaynak = {k_: dict(ghidra) for k_ in KIPLER}
            for a, r in d["urun"].items():
                kaynak["D hepsi"][a] = [r["ad"]]
                if r["kanal"].startswith(("on_ad:", "ks1:")):
                    for k_ in KIPLER[:3]:
                        kaynak[k_][a] = [r["ad"]]
                elif r["kanal"] == O.KANAL:
                    o = r1[(d["birim"], d["ad"], a)]
                    if O.kural_tut(o):
                        kaynak["B A+R1"].setdefault(a, [o["kanit"]])
            for a, s in G.g1(d).items():
                kaynak["C A+G1"].setdefault(a, [s])
            for k_ in KIPLER:
                for anahtar in ((taraf_, k_), (d["birim"], k_), ("hepsi", k_)):
                    say[anahtar]["capa_adli_fn"] += sum(1 for a in kaynak[k_] if a in ad)
                for fa in sorted(d["nufus"]):
                    if fa not in ad or fa in kaynak[k_]:
                        continue
                    t, _durum = E.tahmin(fa, ad[fa], gruplar, kaynak[k_], E.MIN_DESTEK)
                    if t is None:
                        continue
                    gt = d["gt_adlar"][fa]
                    bugun = d["urun"].get(fa)
                    for anahtar in ((taraf_, k_), (d["birim"], k_), ("hepsi", k_)):
                        c = say[anahtar]
                        c["ad"] += 1
                        c["dogru"] += K.gt_esit(t, gt)
                        c["karakter"] += K.karakter_esit(t, gt)
                        c["bugun_adsiz_dogru"] += K.gt_esit(t, gt) and bugun is None
    print("| kesit | kip | çift adayı olan çapa fonksiyonu | ad | doğru (norm; Wilson) | karakter eşit | doğru ve bugün adsız |")
    print("|---|---|---:|---:|---|---:|---:|")
    kesitler = ["hepsi", "kesif", "sinama"] + list(V.BIRIMLER)
    for kesit in kesitler:
        for k_ in KIPLER:
            c = say.get((kesit, k_))
            if not c or not (c["ad"] or kesit in ("hepsi", "kesif", "sinama")):
                continue
            print(f"| {kesit} | {k_} | {c['capa_adli_fn']} | {c['ad']} | {V.wilson(c['dogru'], c['ad'])} | {c['karakter']} | {c['bugun_adsiz_dogru']} |")
    (V.ARGE_KOKU / "ek_kurali_capa.json").write_text(
        json.dumps({"|".join(a): dict(c) for a, c in say.items()}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
