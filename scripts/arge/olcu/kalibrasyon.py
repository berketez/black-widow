#!/usr/bin/env python3
"""ÖLÇÜ hattı B2: güven ↔ gerçekleşen doğruluk (kalibrasyon), taban koşusunda (geliştirme seti içi).

Girdi OLGU tablosu (``urun_olcude`` satırları: ``guven``, ``kanal``, ``hukum``, ``urun_adi``, ``gt_adlari``).
İki hüküm: tam eşitlik; tam + biçim (``olcu.harf_tam``). Kanal ve güven değeri başına gerçekleşen oran,
Brier puanı ve ECE (0,1 genişlikli kutular; kutu ağırlığı ad sayısı). Örnek ve tekil ad düzeyinde.
Uyarı: ön ad kanallarının güveni bu setin ölçülmüş kesinliğinin Wilson alt sınırıdır (döngüsel);
``string_context`` güveni adlandırıcının sezgisidir (bağımsız).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/kalibrasyon.py \
        --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/kalibrasyon.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import olcu  # noqa: E402

KUTU_GENISLIGI = 0.1
KALIBRASYON_HUKUMLERI = ("tam", "tam+bicim")


def ozet(satirlar: list[dict], hukum: str) -> dict:
    n = len(satirlar)
    if not n:
        return {"n": 0}
    brier = sum((s["guven"] - s[hukum]) ** 2 for s in satirlar) / n
    kutular: dict[int, list[dict]] = defaultdict(list)
    for s in satirlar:
        kutular[min(int(s["guven"] / KUTU_GENISLIGI), int(1 / KUTU_GENISLIGI) - 1)].append(s)
    ece = sum(len(ks) / n * abs(sum(s["guven"] for s in ks) / len(ks) - sum(s[hukum] for s in ks) / len(ks))
              for ks in kutular.values())
    degerler: dict[str, list[dict]] = defaultdict(list)
    for s in satirlar:
        degerler[f"{s['guven']:.3f}"].append(s)
    return {"n": n, "ortalama_guven": round(sum(s["guven"] for s in satirlar) / n, 4),
            "gerceklesen": ks1_olc.oran(sum(s[hukum] for s in satirlar), n),
            "brier": round(brier, 4), "ece": round(ece, 4),
            "guven_degeri": {g: ks1_olc.oran(sum(s[hukum] for s in ks), len(ks)) for g, ks in sorted(degerler.items())}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--olgu", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    satirlar, guvensiz = [], 0
    with gzip.open(a.olgu, "rt", encoding="utf-8") as f:
        for satir in f:
            s = json.loads(satir)
            if not s["urun_olcude"]:
                continue
            if s.get("guven") is None:
                guvensiz += 1
                continue
            tam = s["hukum"] == "dogru"
            satirlar.append({"kanal": s["kanal"], "guven": float(s["guven"]), "tam": int(tam),
                             "tam+bicim": int(tam or olcu.harf_tam(s["urun_adi"], s["gt_adlari"] or [])),
                             "tekil": (s["program"], s["urun_adi"], (s["gt_adlari"] or [None])[0])})
    tekil = list({s["tekil"]: s for s in satirlar}.values())
    sonuc: dict = {"sema": "karadul-arge-olcu-kalibrasyon/1", "ad": len(satirlar), "guvensiz": guvensiz,
                   "tekil_ad": len(tekil), "ornek": {}, "tekil": {}}
    for duzey, veri in (("ornek", satirlar), ("tekil", tekil)):
        kanallar = sorted({s["kanal"] for s in veri})
        for kanal in ["TOPLAM"] + kanallar:
            alt = veri if kanal == "TOPLAM" else [s for s in veri if s["kanal"] == kanal]
            sonuc[duzey][kanal] = {h: ozet(alt, h) for h in KALIBRASYON_HUKUMLERI}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("ad", len(satirlar), "güvensiz", guvensiz, "tekil", len(tekil))
    for duzey in ("ornek", "tekil"):
        print(f"== {duzey}: kanal | n | ort. güven | tam: gerçekleşen, Brier, ECE | tam+biçim: gerçekleşen, Brier, ECE")
        for kanal, v in sonuc[duzey].items():
            t, b = v["tam"], v["tam+bicim"]
            print(f"  {kanal:30s} {t['n']:5d} {t['ortalama_guven']:.3f} | {t['gerceklesen']['oran']:.3f} {t['brier']:.4f} {t['ece']:.4f}"
                  f" | {b['gerceklesen']['oran']:.3f} {b['brier']:.4f} {b['ece']:.4f}")
    print("== oz_ad, güven değeri başına (örnek; tam+biçim):")
    for g, o in sonuc["ornek"]["string_context/oz_ad"]["tam+bicim"]["guven_degeri"].items():
        t = sonuc["ornek"]["string_context/oz_ad"]["tam"]["guven_degeri"][g]
        print(f"  güven {g}: n={o['n']:4d} tam {t['k']} ({t['oran']}) tam+biçim {o['k']} ({o['oran']}) {o['aralik']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
