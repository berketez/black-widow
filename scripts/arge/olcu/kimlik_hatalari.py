#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 4 (devam): KİMLİK hattının yanlış eşlemelerini (ikizler dahil) aynı ölçülerle say.

Girdi KİMLİK hattının hata dökümüdür (salt okunur): ``hata_dok_<nokta>.json``; her bölümün her yönünde
``ornek[sinif]`` = [[sorgu GT adları], [verilen (başvuru) adları], aşama, …]. Soru: kimlik eşlemesinin
YANLIŞ verdiği adların kaçı mutlak bir belirteç eşiğiyle "yakın" sayılırdı? Hüküm üretmez.
Dökümdeki örnek sayısı sınıf sayımından azsa (kırpılmış liste) kapsam ayrıca yazılır.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/kimlik_hatalari.py \
        --dok ~/karadul_olcum/runs/arge-2026-11-19/kimlik/hata_dok_kural.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/kimlik_hatalari_kural.json
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
import olcu  # noqa: E402

HATA_ESIKLERI = (0.5, 0.8)


def yonler(bolum) -> list[dict]:
    if isinstance(bolum, dict) and "yonler" in bolum:
        return bolum["yonler"]
    if isinstance(bolum, dict):
        return [y for v in bolum.values() for y in yonler(v)]
    if isinstance(bolum, list):
        return [y for v in bolum for y in yonler(v)]
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dok", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    dok = json.loads(a.dok.read_text(encoding="utf-8"))
    sonuc: dict = {"sema": "karadul-arge-olcu-kimlik-hata/1", "nokta": dok.get("nokta"), "bolum": {}}
    toplam: Counter = Counter()
    ornekler = []
    for bolum, icerik in dok.items():
        c: Counter = Counter()
        for y in yonler(icerik):
            c["sinif_sayimi"] += sum(y.get("siniflar", {}).values())
            for sinif, liste in (y.get("ornek") or {}).items():
                for oge in liste:
                    gt, verilen = oge[0], oge[1]
                    en = {o: 0.0 for o in ("F1", "F1s")}
                    bicim = False
                    for v in verilen:
                        p = olcu.puanla(v, gt)
                        en = {o: max(en[o], p[o]) for o in en}
                        bicim = bicim or olcu.harf_tam(v, gt)
                    c["ornek"] += 1
                    c[f"sinif:{sinif}"] += 1
                    c["bicim"] += bicim
                    c["ayrik"] += en["F1s"] == 0
                    for t in HATA_ESIKLERI:
                        c[f"F1>={t}"] += en["F1"] >= t
                        c[f"F1s>={t}"] += en["F1s"] >= t
                    ornekler.append({"bolum": bolum, "sinif": sinif, "gt": gt, "verilen": verilen,
                                     "F1": round(en["F1"], 3), "F1s": round(en["F1s"], 3), "bicim": bicim})
        if c["ornek"]:
            sonuc["bolum"][bolum] = dict(sorted(c.items()))
            toplam.update(c)
    sonuc["toplam"] = {k: (v if k in ("ornek", "sinif_sayimi") or k.startswith("sinif:") else ks1_olc.oran(v, toplam["ornek"]))
                       for k, v in sorted(toplam.items())}
    sonuc["ornekler"] = ornekler
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for b, c in sonuc["bolum"].items():
        print(b, c)
    print("TOPLAM", {k: (v if not isinstance(v, dict) else f"{v['k']}/{v['n']} {v['aralik']}") for k, v in sonuc["toplam"].items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
