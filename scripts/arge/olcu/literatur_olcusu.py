#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 3: literatürle karşılaştırılabilir belirteç ölçüsü, taban koşusunda.

Tanım NERO'nunki (David, Alon, Yahav, OOPSLA 2020; arXiv 1902.09122, değerlendirme bölümü): kesinlik,
duyarlılık ve F1 hedef alt belirteçler üstünde; büyük/küçük harf, sıra ve yineleme duyarsız; alfabetik
olmayan karakterler yok sayılır. SymLM (CCS 2022) ve SymGen (NDSS 2025) aynı tp / fp / fn sayımını
kullanır, üstüne CodeWordNet ile "anlamca yakın" sözcük eşleştirir (gömme tabanlı; burada YOK).
İki nüfus: (a) ürünün ad verdiği fonksiyonlar; (b) ad bekleyen nüfusun tamamı (ad verilmeyen fonksiyon
boş tahmindir: tp = fp = 0, fn = |GT|). Mikro = belirteç sayımlarının toplamından; makro = fonksiyon
başına F1'in ortalaması; ``symlm_*`` = SymLM denklem 18'in toplaması (fonksiyon başına P ve R'nin
ortalaması, F1 bunların harmonik ortalaması). GT'nin birden çok adı varsa F1'i en yüksek olan alınır.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/literatur_olcusu.py \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/literatur_olcusu.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))

import olcu  # noqa: E402

_ALT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")


def alt_belirtecler(ad: str) -> frozenset:
    """NERO tarzı: alfabetik olmayanlar ayırıcı, deve yazımı bölünür, küçük harf, küme."""
    return frozenset(m.group(0).lower() for parca in re.split(r"[^A-Za-z]+", olcu.ek_soy(ad))
                     for m in _ALT_RE.finditer(parca))


def say(aday: str | None, gt_adlari: list[str]) -> tuple[int, int, int, float]:
    """(tp, |aday|, |gt|, f1) — GT adları üstünde F1'i en yüksek olan."""
    sa = alt_belirtecler(aday) if aday else frozenset()
    en = None
    for g in gt_adlari:
        sg = alt_belirtecler(g)
        tp = len(sa & sg)
        f1 = 2 * tp / (len(sa) + len(sg)) if sa and sg else 0.0
        if en is None or f1 > en[3]:
            en = (tp, len(sa), len(sg), f1)
    return en or (0, len(sa), 0, 0.0)


def ozet(satirlar: list[tuple[int, int, int, float]]) -> dict:
    tp, na, ng = (sum(s[i] for s in satirlar) for i in range(3))
    p, r = (tp / na if na else None), (tp / ng if ng else None)
    f1ler = sorted(s[3] for s in satirlar)
    # SymLM (CCS 2022) denklem 18: P ve R fonksiyon başına oranların ortalaması, F1 bu ikisinin harmonik
    # ortalaması. Boş tahminde (ad verilmemiş) fonksiyonun P ve R'si 0 sayılır.
    mp = sum((s[0] / s[1] if s[1] else 0.0) for s in satirlar) / len(satirlar) if satirlar else None
    mr = sum((s[0] / s[2] if s[2] else 0.0) for s in satirlar) / len(satirlar) if satirlar else None
    return {"n": len(satirlar), "mikro_P": p and round(p, 4), "mikro_R": r and round(r, 4),
            "mikro_F1": round(2 * p * r / (p + r), 4) if p and r else 0.0,
            "symlm_P": mp and round(mp, 4), "symlm_R": mr and round(mr, 4),
            "symlm_F1": round(2 * mp * mr / (mp + mr), 4) if mp and mr else 0.0,
            "makro_F1": round(sum(f1ler) / len(f1ler), 4) if f1ler else None,
            "medyan_F1": f1ler[len(f1ler) // 2] if f1ler else None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    ad_verilen, nufus, nufus_adli = [], [], []
    for ik in taban.values():
        adlar = {k["adres"]: k for k in ik["adlar"]}
        ad_verilen.extend(say(k["ad"], k["gt"]) for k in ik["adlar"])
        for adres in ik["nufus_adresleri"]:
            k = adlar.get(adres)
            s = say(k["ad"] if k else None, ik["gt"][adres])
            nufus.append(s)
            if k:
                nufus_adli.append(s)
    sonuc = {"sema": "karadul-arge-olcu-literatur/1", "tanim": "NERO (OOPSLA 2020): alt belirteç, harf/sıra/yineleme duyarsız, alfabetik",
             "ad_verilen": ozet(ad_verilen), "nufus": ozet(nufus), "nufusta_ad_verilen": ozet(nufus_adli)}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(sonuc, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
