#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 2 (ek): ROC eğrisi noktaları ve AUC'nin önyükleme aralığı (vekil hüküm).

``roc.py``'nin kümeleri ve AUC'siyle aynı; ek olarak ölçü başına ROC noktaları (eşik, FPR, TPR) ve AUC için
%95 yüzdelik aralığı (küme içi tabakalı önyükleme; tohum ve tekrar ``sabitler.py``).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/roc_egri.py \
        --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/roc_egri.json
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import olcu  # noqa: E402
import roc  # noqa: E402
from sabitler import OLCU_HEDEFLERI, OLCU_ONYUKLEME, OLCU_TOHUM  # noqa: E402

EGRI_KUMELERI = {"AYAR (G4-L1-tmux)": ["AYAR (G4-L1-tmux)"],
                 "SINAMA HAVUZU (A+B+C)": ["A (G4-L3-htop)", "B (P15c tekil)", "C (G4-L3-tmux, L1 dışı)"],
                 "SINAMA, tmux'suz (A+B')": ["A (G4-L3-htop)", "B' (P15c, tmux'suz)"]}


def egri(puanlar: list[float], hedef: list[bool]) -> list[list[float]]:
    poz, neg = sum(hedef), len(hedef) - sum(hedef)
    noktalar = []
    for t in sorted(set(puanlar), reverse=True):
        tp = sum(1 for p, h in zip(puanlar, hedef) if h and p >= t)
        fp = sum(1 for p, h in zip(puanlar, hedef) if not h and p >= t)
        noktalar.append([round(t, 4), round(fp / neg, 4), round(tp / poz, 4)])
    return noktalar


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--etiketler", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    k = roc.kumeler(roc.yukle(a.etiketler))
    sonuc: dict = {"sema": "karadul-arge-olcu-roc-egri/1", "tohum": OLCU_TOHUM, "tekrar": OLCU_ONYUKLEME, "kume": {}}
    for ad, parcalar in EGRI_KUMELERI.items():
        tabakalar = [[s for s in k[p] if not s["esit"]] for p in parcalar]
        hepsi = [s for t in tabakalar for s in t]
        sonuc["kume"][ad] = {}
        for hedef, olumlu in OLCU_HEDEFLERI.items():
            h = [s["etiket"] in olumlu for s in hepsi]
            rng = random.Random(OLCU_TOHUM)
            ornekler = [[rng.choice(t) for t in tabakalar for _ in t] for _ in range(OLCU_ONYUKLEME)]
            cikti = {}
            for o in olcu.SUREKLI_AD_OLCULERI:
                nokta = roc.auc([s["puan"][o] for s in hepsi], h)
                dagilim = sorted(v for orn in ornekler
                                 if (v := roc.auc([s["puan"][o] for s in orn], [s["etiket"] in olumlu for s in orn])) is not None)
                cikti[o] = {"auc": round(nokta, 4),
                            "aralik": [round(dagilim[int(0.025 * len(dagilim))], 4),
                                       round(dagilim[int(0.975 * len(dagilim)) - 1], 4)],
                            "egri": egri([s["puan"][o] for s in hepsi], h)}
            sonuc["kume"][ad][hedef] = {"n": len(hepsi), "olumlu": sum(h), "olcu": cikti}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False) + "\n", encoding="utf-8")
    for ad, v in sonuc["kume"].items():
        for hedef, d in v.items():
            print(f"== {ad} | {hedef} | n={d['n']} olumlu={d['olumlu']}")
            print("   " + "  ".join(f"{o}:{c['auc']:.3f}[{c['aralik'][0]:.3f},{c['aralik'][1]:.3f}]" for o, c in d["olcu"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
