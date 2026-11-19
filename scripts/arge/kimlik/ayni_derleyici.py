#!/usr/bin/env python
"""KİMLİK hattı — aynı derleyici, farklı program (coreutils içi): birleşim ve çok başvurulu ölçüm.

DEFTER.md §5.7 madde 2-3 (kurallar sayılardan önce yazıldı). Taze çiftler: ada göre sıralı coreutils listesinde
5, 15, …, 95. indisli ikili sorgu.
  Bölüm 1 (tek başvuru = bir sonraki ikili; iki yön):
    (a) ``yayilim``: dondurulmuş kural noktası (``esle.DONUK``);
    (b) ``cfg_komut``: CFG yapısı + komut adı çoklu kümesi iki tarafta tekil (``ciplak.cfg_tekil``);
    (c) ``birlesim``: ikisi farklı başvuru fonksiyonu gösteriyorsa ad yok; biri susuyorsa öbürü.
  Bölüm 2 (çok başvuru = sorgudan sonraki ``--basvuru`` ikili, dairesel; yalnız sorgu yönü):
    her başvuruyla (c); fonksiyon başına öneren başvuruların ad kümeleri kesişiyorsa ad (kesişim), kesişmiyorsa
    ad yok. OLGU ``kaynak_sinifi`` başına rapor.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/ayni_derleyici.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import ciplak  # noqa: E402
import esle  # noqa: E402
import ikiz  # noqa: E402
import olgu_capraz  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

TAZE_BASLANGIC = 5
TAZE_ADIM = 10


def birlesim(Q: Ikili, R: Ikili) -> tuple[dict[int, int], dict[int, int], dict[int, int]]:
    ya = {q: e.r for q, e in esle.esle(Q, R, esle.DONUK).esler.items() if e.asama != "ad"}
    cf = ciplak.cfg_tekil(Q, R, komut=True)
    bi: dict[int, int] = {}
    for q in set(ya) | set(cf):
        a, b = ya.get(q), cf.get(q)
        if a is not None and b is not None and a != b:
            continue
        bi[q] = a if a is not None else b
    return ya, cf, bi


def cfg_ikizleri(Q: Ikili, R: Ikili) -> list[int]:
    """CFG yapısı + komut çoklu kümesi R'de var ama iki taraftan birinde tekil DEĞİL: CFG-iso'nun ayıramadığı
    nüfus fonksiyonları (H3'ün ``quotearg_*`` ↔ ``*_mem`` türü ikizleri)."""
    def anahtar(f: veri.Fonk):
        return (f.blok, f.kenar, ciplak._wl(f), f.komutlar)

    def grupla(I: Ikili) -> dict[Any, int]:
        d: dict[Any, int] = {}
        for f in I.fonk.values():
            if f.blok >= ciplak.CFG_EN_AZ_BLOK:
                k = anahtar(f)
                d[k] = d.get(k, 0) + 1
        return d
    gq, gr = grupla(Q), grupla(R)
    out = []
    for a in Q.nufus:
        f = Q.fonk[a]
        if f.blok < ciplak.CFG_EN_AZ_BLOK:
            continue
        k = anahtar(f)
        if gr.get(k, 0) >= 1 and (gq[k] > 1 or gr[k] > 1):
            out.append(a)
    return out


def say(Q: Ikili, R: Ikili, es: dict[int, int]) -> tuple[int, int]:
    d = y = 0
    for q, r in es.items():
        if not Q.fonk[q].nufusta:
            continue
        h = esle.hukum(Q, R, q, r)
        d += h == "dogru"
        y += h == "yanlis"
    return d, y


def _satir(ad: str, d: int, y: int, n: int) -> str:
    o = ks1.oran(d, d + y)
    ar = f"{o['oran']:.3f} [{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}]" if o["aralik"] else "—"
    return f"{ad:28s} doğru {d:5d} yanlış {y:4d} kesinlik {ar} kapsam {d}/{n} = {d / n * 100:.1f}%"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--basvuru", type=int, default=5)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    adlar = ciftler.coreutils_adlari()
    sorgular = list(range(TAZE_BASLANGIC, len(adlar) - 1, TAZE_ADIM))
    onbellek: dict[str, Ikili] = {}

    def al(i: int) -> Ikili:
        k = f"debian/coreutils/{adlar[i % len(adlar)]}"
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    cikti: dict[str, Any] = {"sorgular": [adlar[i] for i in sorgular]}
    # Bölüm 1
    top = {k: [0, 0] for k in ("yayilim", "cfg_komut", "birlesim")}
    nuf = 0
    celiski = 0
    ikiz_say = {"ikiz": 0, "yayilim_dogru": 0, "yayilim_yanlis": 0, "aile_isabet": 0, "aile_iska": 0, "sessiz": 0}
    for i in sorgular:
        for Q, R in ((al(i), al(i + 1)), (al(i + 1), al(i))):
            ya, cf, bi = birlesim(Q, R)
            nuf += len(Q.nufus)
            celiski += sum(1 for q in set(ya) & set(cf) if ya[q] != cf[q] and Q.fonk[q].nufusta)
            for k, es in (("yayilim", ya), ("cfg_komut", cf), ("birlesim", bi)):
                d, y = say(Q, R, es)
                top[k][0] += d
                top[k][1] += y
            # ikiz ayırma: CFG-iso'nun ayıramadığı fonksiyonlarda yayılım (sabit + çağrılan kimliği) ne yapıyor
            sonuc = esle.esle(Q, R, esle.DONUK)
            aile = ikiz.aileler(Q, R, sonuc)
            for q in cfg_ikizleri(Q, R):
                ikiz_say["ikiz"] += 1
                if q in ya:
                    h = esle.hukum(Q, R, q, ya[q])
                    if h == "dogru":
                        ikiz_say["yayilim_dogru"] += 1
                    elif h == "yanlis":
                        ikiz_say["yayilim_yanlis"] += 1
                elif q in aile and aile[q]["boy"] >= 2:
                    ikiz_say["aile_isabet" if set(Q.fonk[q].gt) & set(aile[q]["adlar"]) else "aile_iska"] += 1
                else:
                    ikiz_say["sessiz"] += 1
    print(f"Bölüm 1 — tek başvuru, {len(sorgular)} taze çift × 2 yön, nüfus {nuf}; çelişen (ad verilmeyen) {celiski}")
    for k, (d, y) in top.items():
        print("  " + _satir(k, d, y, nuf))
    oi = ks1.oran(ikiz_say["yayilim_dogru"], ikiz_say["yayilim_dogru"] + ikiz_say["yayilim_yanlis"])
    oa = ks1.oran(ikiz_say["aile_isabet"], ikiz_say["aile_isabet"] + ikiz_say["aile_iska"])
    print(f"  CFG ikizleri (CFG-iso'nun ayıramadığı nüfus fonksiyonu): {ikiz_say['ikiz']}; yayılım ayırdı: doğru "
          f"{oi['k']}/{oi['n']}" + (f" = {oi['oran']:.3f} [{oi['aralik'][0]:.3f}, {oi['aralik'][1]:.3f}]" if oi["aralik"] else "")
          + f"; ad ailesi (küme) isabet {oa['k']}/{oa['n']}"
          + (f" = {oa['oran']:.3f} [{oa['aralik'][0]:.3f}, {oa['aralik'][1]:.3f}]" if oa["aralik"] else "")
          + f"; sessiz {ikiz_say['sessiz']}")
    cikti["ikiz"] = ikiz_say
    cikti["tek_basvuru"] = {"nufus": nuf, "celiski": celiski, **{k: {"dogru": d, "yanlis": y} for k, (d, y) in top.items()}}

    # Bölüm 2
    olgu = olgu_capraz.olgu_oku()
    sinif: dict[str, dict[str, int]] = {}
    for i in sorgular:
        Q = al(i)
        oneri: dict[int, list[set[str]]] = {}
        for j in range(1, a.basvuru + 1):
            R = al(i + j)
            _, _, bi = birlesim(Q, R)
            for q, r in bi.items():
                if R.fonk[r].gt:
                    oneri.setdefault(q, []).append(set(R.fonk[r].gt))
        tum_r_adlar = {n for j in range(1, a.basvuru + 1) for f in al(i + j).fonk.values() for n in f.gt}
        for adr in Q.nufus:
            f = Q.fonk[adr]
            ks_ = olgu.get(olgu_capraz.olgu_anahtari(Q.kimlik, adr), "olguda_yok")
            t = sinif.setdefault(ks_, {"nufus": 0, "tavan": 0, "dogru": 0, "yanlis": 0, "celiski": 0})
            t["nufus"] += 1
            if set(f.gt) & tum_r_adlar:
                t["tavan"] += 1
            if adr not in oneri:
                continue
            kesisim = set.intersection(*oneri[adr])
            if not kesisim:
                t["celiski"] += 1
            elif kesisim & set(f.gt):
                t["dogru"] += 1
            else:
                t["yanlis"] += 1
    print(f"Bölüm 2 — çok başvuru ({a.basvuru} ikili), {len(sorgular)} taze sorgu, kaynak sınıfı başına:")
    tt = {"nufus": 0, "tavan": 0, "dogru": 0, "yanlis": 0, "celiski": 0}
    for ks_, t in sorted(sinif.items()):
        print("  " + _satir(ks_, t["dogru"], t["yanlis"], t["nufus"]) + f" | tavan {t['tavan']} çelişki {t['celiski']}")
        for k in tt:
            tt[k] += t[k]
    print("  " + _satir("TOPLAM", tt["dogru"], tt["yanlis"], tt["nufus"]) + f" | tavan {tt['tavan']} çelişki {tt['celiski']}")
    cikti["cok_basvuru"] = {"basvuru": a.basvuru, "sinif": sinif, "toplam": tt}
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
