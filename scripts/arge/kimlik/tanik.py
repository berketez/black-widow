#!/usr/bin/env python
"""KİMLİK hattı — satır içi tanığı ("çağıranın çağrılanı" tanığı). Araştırma betiği; DEFTER.md §5.17.

Sorun: bir derleme X'i çağıranı Y'nin içine alınca X'in kanıtı (dizgi, içe aktarım) Y'de görünür; eşleyici
X_q → Y_r (ya da tersi) eşler. Tanık, eşleme bittikten sonra yalnız eşlenmiş çağrı kenarlarına bakar:

  K1: q'nun bir çağıranı p var ve p'nin çağırıp q'nun ÇAĞIRMADIĞI eşlenmiş bir z'yi r çağırıyor
      (r, q'dan "fazlasını" yapıyor: q'nun çağıranının işini de içeriyor → q, r'nin içine alınmış olabilir).
  K2: simetriği başvuru tarafında: r'nin bir çağıranı p' var ve p''nün çağırıp r'nin çağırmadığı eşlenmiş bir z'yi
      q çağırıyor (q, r'nin çağıranının işini içeriyor → r, q'nun içine alınmış olabilir).

Yaygın yardımcılar (herkesin çağırdığı ``xmalloc`` türü) tanık sayılmaz: z'nin çağıran sayısı ≤ ``kmax`` olmalı
(iki tarafta da). Tanığı olan eşlemeye ad verilmez (kanıt satırı). ``kmax`` yalnız keşif gruplarında seçilir.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/tanik.py <grup>... [--nokta kural] [--kmax 3] --json <çıktı>
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

KMAX_IZGARA = [1, 2, 3, 5, 10, 10 ** 9]


def taniklar(Q: Ikili, R: Ikili, sonuc: esle.Sonuc, kmax: int) -> dict[int, str]:
    """q → "K1", "K2" ya da "K1+K2" (tanığı olan eşlemeler)."""
    M = {q: e.r for q, e in sonuc.esler.items()}
    Minv = {r: q for q, r in M.items()}

    def seyrek(z: int) -> bool:
        return len(R.fonk[z].cagiran) <= kmax and len(Q.fonk[Minv[z]].cagiran) <= kmax

    out: dict[int, str] = {}
    for q, r in M.items():
        fq, fr = Q.fonk[q], R.fonk[r]
        Cq = {M[c] for c in fq.cagrilan if c in M}
        Cr = {c for c in fr.cagrilan if c in Minv}
        k1 = any(z != r and seyrek(z)
                 for p in fq.cagiran
                 for z in ({M[c] for c in Q.fonk[p].cagrilan if c in M} - Cq) & Cr)
        k2 = any(z != r and seyrek(z)
                 for p2 in fr.cagiran
                 for z in ({c for c in R.fonk[p2].cagrilan if c in Minv} - Cr) & Cq)
        if k1 or k2:
            out[q] = "+".join(n for n, v in (("K1", k1), ("K2", k2)) if v)
    return out


def _sinif(Q: Ikili, R: Ikili, q: int, r: int, r_ad: dict, q_ad: set) -> str:
    """hata_dok ile aynı sınıflama (doğru için 'dogru')."""
    h = esle.hukum(Q, R, q, r)
    if h != "yanlis":
        return h
    gercek = [x for n in Q.fonk[q].gt for x in r_ad.get(n, [])]
    if not gercek:
        return "satir_ici" if set(R.fonk[r].gt) & q_ad else "tek_tarafli"
    if r in {c for x in gercek for c in (R.fonk[x].cagiran | R.fonk[x].cagrilan)}:
        return "komsu"
    return "diger"


def olc(gruplar: list[str], nokta: str, kmaxlar: list[int], al) -> dict[str, Any]:
    p = esle.NOKTALAR[nokta]
    cikti: dict[str, Any] = {}
    for g in gruplar:
        kayit: dict[int, list[tuple[str, bool]]] = {k: [] for k in kmaxlar}
        nuf = 0
        for c in ciftler.grup(g):
            for qk, rk in (c, c[::-1]):
                Q, R = al(qk), al(rk)
                nuf += len(Q.nufus)
                s = esle.esle(Q, R, p)
                r_ad: dict[str, list[int]] = {}
                for adr, f in R.fonk.items():
                    for n in f.gt:
                        r_ad.setdefault(n, []).append(adr)
                q_ad = {n for f in Q.fonk.values() for n in f.gt}
                for kmax in kmaxlar:
                    t = taniklar(Q, R, s, kmax)
                    for q, e in s.esler.items():
                        if not Q.fonk[q].nufusta or e.asama == "ad":
                            continue
                        sn = _sinif(Q, R, q, e.r, r_ad, q_ad)
                        if sn in ("adsiz", "hukumsuz"):
                            continue
                        kayit[kmax].append((sn, q in t))
        satirlar = []
        for kmax in kmaxlar:
            ks_ = kayit[kmax]
            tum_d = sum(1 for sn, _ in ks_ if sn == "dogru")
            tum_y = len(ks_) - tum_d
            dusen = [sn for sn, t in ks_ if t]
            kalan = [sn for sn, t in ks_ if not t]
            dd = sum(1 for sn in dusen if sn == "dogru")
            dy = len(dusen) - dd
            kd = sum(1 for sn in kalan if sn == "dogru")
            ky = len(kalan) - kd
            o = ks1.oran(kd, kd + ky)
            ic_once = sum(1 for sn, _ in ks_ if sn in ("satir_ici", "komsu"))
            ic_dusen = sum(1 for sn in dusen if sn in ("satir_ici", "komsu"))
            s_ = {"kmax": kmax, "once": {"dogru": tum_d, "yanlis": tum_y}, "kalan": {"dogru": kd, "yanlis": ky},
                  "kesinlik": o, "dusen_dogru": dd, "dusen_yanlis": dy, "satir_ici_once": ic_once,
                  "satir_ici_dusen": ic_dusen, "tek_tarafli_dusen": sum(1 for sn in dusen if sn == "tek_tarafli"),
                  "nufus": nuf}
            satirlar.append(s_)
            ot = ks1.oran(dd, dd + dy)      # tanığı TAŞIYAN eşlemelerin kesinliği (alt kanal olarak)
            s_["tanikli_kesinlik"] = ot
            ks_ad = "∞" if kmax >= 10 ** 9 else str(kmax)
            print(f"{g:15s} {nokta:9s} kmax {ks_ad:>2s}: önce {tum_d}/{tum_y} → kalan {kd:5d}/{ky:3d} kesinlik "
                  f"{o['oran']:.3f} [{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}] kapsam {kd / nuf * 100:5.1f}% | düşen doğru "
                  f"{dd:4d}, düşen yanlış {dy:3d} (satır içi türü {ic_dusen}/{ic_once}, tek taraflı "
                  f"{s_['tek_tarafli_dusen']})"
                  + (f" | tanıklı alt kanal kesinliği {ot['oran']:.3f} [{ot['aralik'][0]:.3f}, {ot['aralik'][1]:.3f}]"
                     if ot["aralik"] else ""))
        cikti[g] = satirlar
    return cikti


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--nokta", default="kural", choices=sorted(esle.NOKTALAR))
    ap.add_argument("--kmax", type=int, default=None, help="tek değer (dondurulmuş sınama); verilmezse ızgara")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    cikti = olc(a.gruplar, a.nokta, [a.kmax] if a.kmax is not None else KMAX_IZGARA, al)
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps({"nokta": a.nokta, "gruplar": cikti}, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
