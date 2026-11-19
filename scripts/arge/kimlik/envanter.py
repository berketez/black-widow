#!/usr/bin/env python
"""KİMLİK hattı — kalem 1: çift envanteri ve eşlemenin tavanı.

Her çift ve yön (sorgu Q → başvuru R) için: fonksiyon, GT'li fonksiyon, nüfus (ad bekleyen), iki tarafta da
geçen ad sayısı ve nüfusun tavanı (GT adı R'nin GT adları arasında olanlar). Yalnız GT ve var olan Ghidra
çıktısı okunur.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/envanter.py kesif_htop sinama_tmux … --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import veri  # noqa: E402
from veri import ks1  # noqa: E402


def yon(q: veri.Ikili, r: veri.Ikili) -> dict:
    r_adlar = {n for f in r.fonk.values() for n in f.gt}
    q_adlar = {n for f in q.fonk.values() for n in f.gt}
    nufus = [q.fonk[a] for a in q.nufus]
    tavan = [f for f in nufus if set(f.gt) & r_adlar]
    # tekil tavan: adı R'de tam bir fonksiyonda geçenler (statik ad çakışması yok)
    r_say: dict[str, int] = {}
    for f in r.fonk.values():
        for n in f.gt:
            r_say[n] = r_say.get(n, 0) + 1
    return {
        "sorgu": q.kimlik, "basvuru": r.kimlik,
        "q_fonk": len(q.fonk), "q_gtli": sum(1 for f in q.fonk.values() if f.gt),
        "q_bilinen": sum(1 for f in q.fonk.values() if f.bilinen),
        "r_fonk": len(r.fonk), "r_gtli": sum(1 for f in r.fonk.values() if f.gt),
        "q_ad": len(q_adlar), "r_ad": len(r_adlar), "ortak_ad": len(q_adlar & r_adlar),
        "nufus": len(nufus), "tavan": ks1.oran(len(tavan), len(nufus)),
        "tavan_r_tekil": sum(1 for f in tavan if any(r_say.get(n) == 1 for n in f.gt)),
        "nufus_cagiransiz": sum(1 for f in nufus if not f.cagiran),
        "nufus_dizgili": sum(1 for f in nufus if f.dizgiler),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("gruplar", nargs="+")
    p.add_argument("--json", type=Path)
    a = p.parse_args(argv)
    onbellek: dict[str, veri.Ikili] = {}

    def al(k: str) -> veri.Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k, pcode=False)
        return onbellek[k]

    cikti = {}
    for g in a.gruplar:
        satirlar = []
        for x, y in ciftler.grup(g):
            for q, r in ((x, y), (y, x)):
                s = yon(al(q), al(r))
                satirlar.append(s)
                t = s["tavan"]
                print(f"{g:14s} {q:28s} → {r:28s} fonk {s['q_fonk']:5d} nüfus {s['nufus']:5d} "
                      f"tavan {t['k']:5d} ({(t['oran'] or 0) * 100:5.1f}%) ortak ad {s['ortak_ad']:5d} "
                      f"çağıransız {s['nufus_cagiransiz']:5d} dizgili {s['nufus_dizgili']:5d}")
        cikti[g] = satirlar
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
