#!/usr/bin/env python3
"""ÖLÇÜ hattı Ö9: ayırt edici belirteç duyarlılığı (ikili içi idf ağırlıklı duyarlılık).

Tanım ve ön kayıt: ``docs/arge/2026-11-19_mythos/olcu/DEFTER.md`` §11.
    idf(t) = ln(N / df(t));  Ridf = Σ idf(karşılanan GT belirteçleri) / Σ idf(GT belirteçleri);
    F1idf = harmonik(Ps, Ridf).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/idf.py \
        --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/idf.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import kimlik as kimlik_modulu  # noqa: E402
import olcu  # noqa: E402
import roc  # noqa: E402
from sabitler import OLCU_AYAR_KESINLIK, OLCU_HEDEFLERI  # noqa: E402

IDF_OLCULERI = ("Rs", "F1s", "Ridf", "F1idf")


def idf_tablosu(gt: dict[str, list[str]]) -> tuple[dict[str, float], int]:
    df: Counter = Counter()
    for adlar in gt.values():
        df.update(set().union(*(set(olcu.belirtecler(a)) for a in adlar)) if adlar else set())
    n = len(gt)
    return {t: math.log(n / c) for t, c in df.items()}, n


def ridf(aday: str, gt_adlari: list[str], idf: dict[str, float], n: int) -> tuple[float, float]:
    sa = set(olcu.belirtecler(aday))
    en = (0.0, 0.0)
    for g in gt_adlari:
        sg = set(olcu.belirtecler(g))
        if not sa or not sg:
            continue
        agirlik = {t: idf.get(t, math.log(n)) for t in sg}
        toplam = sum(agirlik.values())
        karsilanan = sum(w for t, w in agirlik.items() if any(olcu.eslesir(a, t) for a in sa))
        r = karsilanan / toplam if toplam else 0.0
        p = sum(1 for a in sa if any(olcu.eslesir(a, t) for t in sg)) / len(sa)
        f = 2 * p * r / (p + r) if p + r else 0.0
        if f > en[1] or (f == en[1] and r > en[0]):
            en = (r, f)
    return en


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--etiketler", type=Path, required=True)
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    tablolar: dict = {}
    hesaplanan = []
    for s in roc.yukle(a.etiketler):
        anahtar = kimlik_modulu.ikili_anahtari(s)
        if anahtar not in taban:
            continue
        if anahtar not in tablolar:
            tablolar[anahtar] = idf_tablosu(taban[anahtar]["gt"])
        idf, n = tablolar[anahtar]
        r, f = ridf(s["aday"], [g.lstrip("_") for g in s["gt"]], idf, n)
        s["puan"].update({"Ridf": r, "F1idf": f})
        hesaplanan.append(s)
    k = roc.kumeler(hesaplanan)
    sonuc: dict = {"sema": "karadul-arge-olcu-idf/1", "auc": {}, "O9b": {}}
    for ad, ks in k.items():
        alt = [s for s in ks if not s["esit"]]
        sonuc["auc"][ad] = {"n": len(alt)}
        for hedef, olumlu in OLCU_HEDEFLERI.items():
            h = [s["etiket"] in olumlu for s in alt]
            sonuc["auc"][ad][hedef] = {o: (None if (v := roc.auc([s["puan"][o] for s in alt], h)) is None else round(v, 4))
                                       for o in IDF_OLCULERI}
    tabakalar = [k["A (G4-L3-htop)"], k["B (P15c tekil)"], k["C (G4-L3-tmux, L1 dışı)"]]
    sonuc["O9a"] = [roc.fark_onyukleme(tabakalar, x, y, h) for h in OLCU_HEDEFLERI for x, y in (("Ridf", "Rs"), ("F1idf", "F1s"))]
    sonuc["O9a_ayar"] = [roc.fark_onyukleme([k["AYAR (G4-L1-tmux)"]], x, y, h)
                         for h in OLCU_HEDEFLERI for x, y in (("Ridf", "Rs"), ("F1idf", "F1s"))]
    alt = [s for s in k["AYAR (G4-L1-tmux)"] if not s["esit"]]
    for o in ("Ridf", "F1idf"):
        en = None
        for t in sorted({s["puan"][o] for s in alt if s["puan"][o] > 0}):
            kb = [s for s in alt if s["puan"][o] >= t]
            y = sum(1 for s in kb if s["etiket"] in OLCU_HEDEFLERI["yakin"])
            if len(kb) >= 5 and (en is None or y / len(kb) > en["kesinlik"]):
                en = {"esik": round(t, 4), "kabul": len(kb), "yakin": y, "kesinlik": round(y / len(kb), 4)}
        sonuc["O9b"][o] = {"en_yuksek_kesinlik_kabul>=5": en, "esik_var": bool(en and en["kesinlik"] >= OLCU_AYAR_KESINLIK)}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for hedef in OLCU_HEDEFLERI:
        print(f"== AUC hedef={hedef}:", *IDF_OLCULERI)
        for ad, t in sonuc["auc"].items():
            print("  ", ad.ljust(28)[:28], str(t["n"]).rjust(4), *(("-" if t[hedef][o] is None else f"{t[hedef][o]:.3f}").rjust(7) for o in IDF_OLCULERI))
    for f in sonuc["O9a"]:
        print("Ö9a sınama", f)
    for f in sonuc["O9a_ayar"]:
        print("Ö9a ayar  ", f)
    print("Ö9b", json.dumps(sonuc["O9b"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
