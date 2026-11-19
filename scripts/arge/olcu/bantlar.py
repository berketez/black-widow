#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 2 (devam): eşik bantları, uzlaşı eşiği (F1 ≥ 0,5) ve alt küme / üst küme tablosu.

Ö3'te hiçbir ölçü ayar kümesinde 0,90 kesinliğe ulaşamadı; bu betik nedenini gösterir:
  - ``bant``: ölçü bandı başına vekil etiket dağılımı (tam eşit olmayan çiftler);
  - ``esik``: "ölçü ≥ t" kabulünün ``yakin`` / ``yaniltmaz`` kesinliği ve yakaladığı ``yakin`` payı;
  - ``kume_iliskisi``: aday belirteçleri GT'nin alt kümesi mi (P = 1), üst kümesi mi (R = 1),
    kısmi mi, ayrık mı → etiket dağılımı (aykırı öncül 1'in doğrudan sınaması);
  - ``uclu_tahminci``: üç bölgeli ayrım (tam eşit / örtüşme var / örtüşme yok) ve her bölgede
    ``yakin`` oranı (etiketleme yükünü azaltan tabakalı tahmincinin girdisi).
Sınama kümelerindeki bant tabloları betimseldir (ön kayıtlı tek okuma değildir).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/bantlar.py \
        --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/bantlar.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import roc  # noqa: E402
from sabitler import OLCU_HEDEFLERI  # noqa: E402

BANT_SINIRLARI = (0.0, 0.25, 0.5, 0.75, 1.0)
BANT_OLCULERI = ("P", "F1", "Ps", "F1s", "Pz", "F1z", "as5", "duz")
ESIK_NOKTALARI = (0.34, 0.5, 0.67, 0.8, 1.0)
GOSTERILEN = ("AYAR (G4-L1-tmux)", "A (G4-L3-htop)", "B (P15c tekil)", "C (G4-L3-tmux, L1 dışı)",
              "SINAMA HAVUZU (A+B+C)", "SINAMA, tmux'suz (A+B')")


def bant_adi(v: float) -> str:
    if v == 0:
        return "0"
    if v == 1:
        return "1"
    for alt, ust in zip(BANT_SINIRLARI, BANT_SINIRLARI[1:]):
        if alt < v <= ust or (alt == 0 and 0 < v <= ust):
            return f"({alt:.2f},{ust:.2f}]" if ust < 1 else f"({alt:.2f},1)"
    return "?"


def dagilim(ks: list[dict]) -> dict:
    c = Counter(s["etiket"] for s in ks)
    n = len(ks)
    return {"n": n, "dogru_tarif": c["dogru_tarif"] + c["tam"], "yalniz_alan": c["yalniz_alan"], "yanlis": c["yanlis"],
            "yakin": ks1_olc.oran(c["dogru_tarif"] + c["tam"], n), "yanlis_orani": ks1_olc.oran(c["yanlis"], n)}


def kume_iliskisi(s: dict) -> str:
    p, r = s["puan"]["Ps"], s["puan"]["Rs"]
    if p == 0 and r == 0:
        return "ayrik (P=0)"
    if p == 1 and r == 1:
        return "ayni kume, sira/esanlam farki"
    if p == 1:
        return "aday ⊂ GT (P=1, R<1)"
    if r == 1:
        return "aday ⊃ GT (P<1, R=1)"
    return "kismi (P<1, R<1)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--etiketler", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    k = roc.kumeler(roc.yukle(a.etiketler))
    sonuc: dict = {"sema": "karadul-arge-olcu-bant/1", "bant": {}, "esik": {}, "kume_iliskisi": {}, "uclu_tahminci": {}}
    for ad in GOSTERILEN:
        hepsi = k[ad]
        alt = [s for s in hepsi if not s["esit"]]
        sonuc["bant"][ad] = {o: {b: dagilim([s for s in alt if bant_adi(s["puan"][o]) == b])
                                 for b in sorted({bant_adi(s["puan"][o]) for s in alt})} for o in BANT_OLCULERI}
        toplam_yakin = sum(1 for s in alt if s["etiket"] in OLCU_HEDEFLERI["yakin"])
        sonuc["esik"][ad] = {}
        for o in BANT_OLCULERI:
            sonuc["esik"][ad][o] = {}
            for t in ESIK_NOKTALARI:
                kabul = [s for s in alt if s["puan"][o] >= t]
                d = dagilim(kabul)
                d["yakalanan_yakin"] = ks1_olc.oran(d["dogru_tarif"], toplam_yakin)
                sonuc["esik"][ad][o][str(t)] = d
        sonuc["kume_iliskisi"][ad] = {b: dagilim([s for s in alt if kume_iliskisi(s) == b])
                                      for b in sorted({kume_iliskisi(s) for s in alt})}
        ortusen = [s for s in alt if s["puan"]["Ps"] > 0]
        ayrik = [s for s in alt if s["puan"]["Ps"] == 0]
        sonuc["uclu_tahminci"][ad] = {
            "toplam": len(hepsi), "tam_esit": len(hepsi) - len(alt),
            "ortusen": dagilim(ortusen), "ayrik": dagilim(ayrik),
            "yakinin_ortusende_payi": ks1_olc.oran(
                sum(1 for s in ortusen if s["etiket"] in OLCU_HEDEFLERI["yakin"]), toplam_yakin)}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    def satir(d: dict) -> str:
        y, w = d["yakin"], d["yanlis_orani"]
        ya = "-" if y["oran"] is None else f"{y['oran']:.3f} [{y['aralik'][0]:.3f},{y['aralik'][1]:.3f}]"
        wa = "-" if w["oran"] is None else f"{w['oran']:.3f}"
        return f"n={d['n']:4d} dt={d['dogru_tarif']:3d} ya={d['yalniz_alan']:3d} yn={d['yanlis']:3d} yakin={ya} yanlis={wa}"

    for ad in GOSTERILEN:
        print(f"\n######## {ad}")
        print("-- küme ilişkisi (sözlüklü):")
        for b, d in sonuc["kume_iliskisi"][ad].items():
            print(f"   {b:32s} {satir(d)}")
        print("-- eşik kabulü:")
        for o in BANT_OLCULERI:
            for t, d in sonuc["esik"][ad][o].items():
                yy = d["yakalanan_yakin"]
                print(f"   {o:4s} >= {t:4s} {satir(d)} yakalanan={yy['k']}/{yy['n']}")
        u = sonuc["uclu_tahminci"][ad]
        print(f"-- üçlü: toplam {u['toplam']} tam_eşit {u['tam_esit']} | örtüşen {satir(u['ortusen'])} | ayrık {satir(u['ayrik'])}"
              f" | yakının örtüşende payı {u['yakinin_ortusende_payi']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
