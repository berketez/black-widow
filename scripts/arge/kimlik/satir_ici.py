#!/usr/bin/env python
"""KİMLİK hattı — satır içi kapısı (KEŞİF; DEFTER.md §5.7 madde 5).

Kabul edilen her eşlemede kanıt kütlesi dengesi ``denge = min(w_q, w_r) / max(w_q, w_r)`` (``esle.Esleme.denge``).
Bir derleyici çağrılanı çağıranın içine aldığında içeren fonksiyonun kanıtı öbür taraftaki karşılığından çok
olur; denge küçülür. Kapı: ``denge < esik`` ise ad verilmez (kanıt satırı). Eşik yalnız htop'ta seçilir.

Her grup ve eşik için: kalan doğru / yanlış, kapının düşürdüğü doğru ve yanlış (hata sınıfıyla).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/satir_ici.py kesif_htop … [--nokta kural] --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

DENGE_ESIKLERI = [0.0, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--nokta", default="kural", choices=sorted(esle.NOKTALAR))
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    p = esle.NOKTALAR[a.nokta]
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    cikti: dict[str, Any] = {"nokta": a.nokta}
    for g in a.gruplar:
        kayit = []      # (denge, hüküm, satır içi türü mü)
        nuf = 0
        for c in ciftler.grup(g):
            for qk, rk in (c, c[::-1]):
                Q, R = al(qk), al(rk)
                nuf += len(Q.nufus)
                r_ad: dict[str, list[int]] = {}
                for adr, f in R.fonk.items():
                    for n in f.gt:
                        r_ad.setdefault(n, []).append(adr)
                q_ad = {n for f in Q.fonk.values() for n in f.gt}
                for q, e in esle.esle(Q, R, p).esler.items():
                    if not Q.fonk[q].nufusta or e.asama == "ad":
                        continue
                    h = esle.hukum(Q, R, q, e.r)
                    if h not in ("dogru", "yanlis"):
                        continue
                    ic = False
                    if h == "yanlis":
                        gercek = [x for n in Q.fonk[q].gt for x in r_ad.get(n, [])]
                        if gercek:
                            ic = e.r in {c2 for x in gercek for c2 in (R.fonk[x].cagiran | R.fonk[x].cagrilan)}
                        else:
                            ic = bool(set(R.fonk[e.r].gt) & q_ad)
                    kayit.append((e.denge, h, ic))
        satirlar = []
        for esik in DENGE_ESIKLERI:
            kalan = [k for k in kayit if k[0] >= esik]
            dusen = [k for k in kayit if k[0] < esik]
            d = sum(1 for k in kalan if k[1] == "dogru")
            y = sum(1 for k in kalan if k[1] == "yanlis")
            o = ks1.oran(d, d + y)
            s = {"esik": esik, "dogru": d, "yanlis": y, "kesinlik": o,
                 "dusen_dogru": sum(1 for k in dusen if k[1] == "dogru"),
                 "dusen_yanlis": sum(1 for k in dusen if k[1] == "yanlis"),
                 "dusen_satir_ici": sum(1 for k in dusen if k[2]),
                 "kalan_satir_ici": sum(1 for k in kalan if k[2]), "nufus": nuf}
            satirlar.append(s)
            print(f"{g:14s} {a.nokta:9s} denge ≥ {esik:.1f}: doğru {d:5d} yanlış {y:4d} kesinlik {o['oran']:.3f} "
                  f"[{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}] kapsam {d / nuf * 100:5.1f}% | düşen doğru "
                  f"{s['dusen_dogru']:4d}, düşen yanlış {s['dusen_yanlis']:3d} (satır içi türü {s['dusen_satir_ici']}); "
                  f"kalan satır içi türü {s['kalan_satir_ici']}")
        cikti[g] = satirlar
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
