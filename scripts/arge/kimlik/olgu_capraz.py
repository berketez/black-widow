#!/usr/bin/env python
"""KİMLİK hattı — OLGU tablosuyla çapraz denetim (kalem 6) ve kaynak sınıfı başına eşleme sonucu.

1. ``a1``: ``a1_pay.fonksiyon_siniflari`` (set içi kopya sınıfı; ad + boyut) × OLGU ``kaynak_sinifi`` (dbgsym
   DWARF'ından) çapraz tablosu, nüfus içinde. İki bağımsız sayımın tutarlılığı.
2. ``esleme``: dondurulmuş "kural" noktasında, sorgusu Debian ELF olan yönlerde (kaynak sınıfı yalnız orada
   biliniyor) kaynak sınıfı başına nüfus, tavan, doğru, yanlış.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/olgu_capraz.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a1_pay  # noqa: E402
import ciftler  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import ks1  # noqa: E402

OLGU = veri.OLCUM / "runs" / "arge-2026-11-19" / "olgu" / "olgu.jsonl.gz"
ESLEME_GRUPLARI = ("sinama_tmux", "sinama_cu_mac", "sinama_cu_ic", "surum")


def olgu_oku() -> dict[tuple[str, str, int], str]:
    """(birim, ikili, adres) → kaynak_sinifi; yalnız nüfus satırları."""
    out = {}
    with gzip.open(OLGU, "rt", encoding="utf-8") as f:
        for satir in f:
            k = json.loads(satir)
            if k.get("nufusta"):
                out[(k["birim"], k["ikili"], int(k["adres"]))] = k["kaynak_sinifi"]
    return out


def olgu_anahtari(kimlik: str, adres: int) -> tuple[str, str, int]:
    p = kimlik.split("/")
    return f"{p[0]}/{p[1]}", p[-1], adres


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    olgu = olgu_oku()
    print(f"OLGU nüfus satırı: {len(olgu)}")

    # 1. A1 sınıfı × kaynak sınıfı
    sinif, _, _ = a1_pay.fonksiyon_siniflari()
    capraz: dict[str, dict[str, int]] = {}
    eksik = 0
    for (k, adr), x in sinif.items():
        ks_ = olgu.get(olgu_anahtari(k, adr))
        if ks_ is None:
            eksik += 1
            continue
        capraz.setdefault(ks_, {y: 0 for y in a1_pay.A1_SINIFLARI})[x] += 1
    print(f"A1 sınıfı × OLGU kaynak sınıfı (nüfus {len(sinif)}; OLGU'da karşılığı olmayan {eksik}):")
    print(f"  {'kaynak sınıfı':18s} " + " ".join(f"{y:>15s}" for y in a1_pay.A1_SINIFLARI) + f" {'toplam':>8s}")
    for ks_, s in sorted(capraz.items()):
        print(f"  {ks_:18s} " + " ".join(f"{s[y]:15d}" for y in a1_pay.A1_SINIFLARI) + f" {sum(s.values()):8d}")

    # 2. Kaynak sınıfı başına eşleme (sorgu Debian ELF)
    onbellek: dict[str, veri.Ikili] = {}

    def al(k: str) -> veri.Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    esleme: dict[str, Any] = {}
    for g in ESLEME_GRUPLARI:
        say: dict[str, dict[str, int]] = {}
        for c in ciftler.grup(g):
            for qk, rk in (c, c[::-1]):
                if not qk.startswith("debian/"):
                    continue
                Q, R = al(qk), al(rk)
                s = esle.esle(Q, R, esle.DONUK)
                r_adlar = {n for f in R.fonk.values() for n in f.gt}
                for adr in Q.nufus:
                    ks_ = olgu.get(olgu_anahtari(qk, adr), "olguda_yok")
                    t = say.setdefault(ks_, {"nufus": 0, "tavan": 0, "dogru": 0, "yanlis": 0})
                    t["nufus"] += 1
                    if set(Q.fonk[adr].gt) & r_adlar:
                        t["tavan"] += 1
                    e = s.esler.get(adr)
                    if e is not None:
                        h = esle.hukum(Q, R, adr, e.r)
                        if h in ("dogru", "yanlis"):
                            t[h] += 1
        print(f"{g} (kural noktası; sorgu Debian ELF):")
        for ks_, t in sorted(say.items()):
            o = ks1.oran(t["dogru"], t["dogru"] + t["yanlis"])
            ar = f"{o['oran']:.3f} [{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}]" if o["aralik"] else "—"
            print(f"  {ks_:18s} nüfus {t['nufus']:5d} tavan {t['tavan']:5d} doğru {t['dogru']:5d} yanlış {t['yanlis']:4d} "
                  f"kesinlik {ar} kapsam {t['dogru'] / t['nufus'] * 100:5.1f}%")
            t["kesinlik"] = o
        esleme[g] = say
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps({"a1_capraz": capraz, "olguda_eksik": eksik, "esleme": esleme},
                                     ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
