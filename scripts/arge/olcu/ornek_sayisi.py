#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 6 (G3): iki değerlendiricili etiketleme için gereken örnek sayısı (aralık hedefinden).

(a) Oran: Wilson %95 aralığının yarı genişliği ≤ w olan en küçük n (``ks1_olc.oran`` ile; beklenen oran p).
(b) Kappa: iki değerlendirici, ikili hüküm; büyük örneklem yaklaşıklığı SE(κ) = sqrt(po(1−po) / (n(1−pe)²)),
    pe = p² + (1−p)², po = κ(1−pe) + pe; %95 yarı genişlik ≤ h olan en küçük n.
(c) Tabakalı tahminci: "yakın" oranını tam eşit olmayan adlarda tahmin etmek için basit rastgele örnek ile
    Neyman paylaştırmalı iki tabaka (örtüşen / ayrık) karşılaştırması. Tabaka payları ve oranları sınama
    havuzunun vekil etiketlerinden okunur (``bantlar.json``); yön göstericidir.
(d) AUC: Hanley–McNeil (1982) SE; olumlu payı verildiğinde SE(AUC) ≤ s için gereken toplam n.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/ornek_sayisi.py \
        --bantlar ~/karadul_olcum/runs/arge-2026-11-19/olcu/bantlar.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/ornek_sayisi.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402

Z95 = 1.959964
ORAN_BEKLENEN = (0.05, 0.10, 0.20, 0.30, 0.50)
ORAN_YARI_GENISLIK = (0.03, 0.05, 0.10)
KAPPA_BEKLENEN = (0.6, 0.7, 0.8, 0.9)
KAPPA_YAYGINLIK = (0.10, 0.30, 0.50)
KAPPA_YARI_GENISLIK = (0.10, 0.15)
AUC_BEKLENEN = (0.75, 0.80, 0.90)
AUC_OLUMLU_PAYI = (0.10, 0.30)
AUC_SE = (0.02, 0.03)


def wilson_n(p: float, w: float) -> int:
    n = 1
    while True:
        k = round(p * n)
        alt, ust = ks1_olc.oran(k, n)["aralik"]
        if (ust - alt) / 2 <= w:
            return n
        n += 1


def kappa_n(kappa: float, p: float, h: float) -> int:
    pe = p * p + (1 - p) * (1 - p)
    po = kappa * (1 - pe) + pe
    return math.ceil((Z95 / h) ** 2 * po * (1 - po) / (1 - pe) ** 2)


def auc_se(a: float, n1: int, n2: int) -> float:
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    return math.sqrt((a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n2 - 1) * (q2 - a * a)) / (n1 * n2))


def auc_n(a: float, pay: float, s: float) -> int:
    n = 10
    while True:
        n1 = max(1, round(n * pay))
        if auc_se(a, n1, n - n1) <= s:
            return n
        n += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bantlar", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    sonuc: dict = {"sema": "karadul-arge-olcu-ornek/1"}
    sonuc["oran"] = {str(p): {str(w): wilson_n(p, w) for w in ORAN_YARI_GENISLIK} for p in ORAN_BEKLENEN}
    sonuc["kappa"] = {str(k): {str(p): {str(h): kappa_n(k, p, h) for h in KAPPA_YARI_GENISLIK}
                               for p in KAPPA_YAYGINLIK} for k in KAPPA_BEKLENEN}
    sonuc["auc"] = {str(x): {str(pay): {str(s): auc_n(x, pay, s) for s in AUC_SE} for pay in AUC_OLUMLU_PAYI}
                    for x in AUC_BEKLENEN}
    u = json.loads(a.bantlar.read_text(encoding="utf-8"))["uclu_tahminci"]
    sonuc["tabakali"] = {}
    for kume in ("AYAR (G4-L1-tmux)", "SINAMA HAVUZU (A+B+C)"):
        o, y = u[kume]["ortusen"], u[kume]["ayrik"]
        n = o["n"] + y["n"]
        w1, w2 = o["n"] / n, y["n"] / n
        p1, p2 = o["yakin"]["oran"], y["yakin"]["oran"]
        p = w1 * p1 + w2 * p2
        s1, s2 = math.sqrt(p1 * (1 - p1)), math.sqrt(p2 * (1 - p2))
        satir = {"pay_ortusen": round(w1, 4), "yakin_ortusen": p1, "yakin_ayrik": p2, "yakin_toplam": round(p, 4)}
        for w in ORAN_YARI_GENISLIK:
            srs = math.ceil((Z95 / w) ** 2 * p * (1 - p))
            ney = math.ceil((Z95 / w) ** 2 * (w1 * s1 + w2 * s2) ** 2)
            satir[str(w)] = {"basit_rastgele": srs, "neyman": ney,
                             "neyman_ortusen_payi": round(w1 * s1 / (w1 * s1 + w2 * s2), 3)}
        sonuc["tabakali"][kume] = satir
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(sonuc, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
