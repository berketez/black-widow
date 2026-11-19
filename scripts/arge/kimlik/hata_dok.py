#!/usr/bin/env python
"""KİMLİK hattı — yanlış eşlemelerin dökümü (dondurulmuş sayımdan SONRA; ayar için kullanılmaz).

Her grup ve yön için, dondurulmuş noktada yanlış sayılan eşleme q → r şu sınıflara ayrılır:
  - ``tavan_disi_*``: q'nun GT adı R'de hiç yok. İki alt sınıf:
      ``tek_tarafli``: seçilen r'nin adı da Q'da yok (iki ad da yalnız kendi tarafında: sürümler / platformlar
      arası yeniden adlandırma adayı; aynı fonksiyon olabilir, mekanik doğrulaması yok);
      ``satir_ici``: r'nin adı Q'da başka bir fonksiyonda var (r'nin gerçek karşılığı q değil; q büyük
      olasılıkla R'de r'nin içine alınmış).
  - ``komsu``: q'nun adı R'de var (r*), ama seçilen r, r*'ın çağıranı ya da çağrılanı (satır içine alma
    farkı: kanıt çağrı zincirinde bir basamak kaymış).
  - ``aile``: q ve r adları ``_`` sınırında ortak önek ya da sonek taşıyor (ikiz / ad ailesi).
  - ``diger``.
Sınıflar sırayla denenir (ilk uyan). Ayrıca "tavan içi kesinlik": q'nun adı R'de olanlarla sınırlı kesinlik.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/hata_dok.py sinama_tmux … [--nokta kural] --json <çıktı>
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
import ikiz  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

HATA_SINIFLARI = ("tavan_disi_tek_tarafli", "tavan_disi_satir_ici", "komsu", "aile", "diger")


def yon(Q: Ikili, R: Ikili, p: esle.Param) -> dict[str, Any]:
    s = esle.esle(Q, R, p)
    r_ad: dict[str, list[int]] = {}
    for a, f in R.fonk.items():
        for n in f.gt:
            r_ad.setdefault(n, []).append(a)
    q_ad = {n for f in Q.fonk.values() for n in f.gt}
    say = {k: 0 for k in HATA_SINIFLARI}
    asama = {k: {"dizgi": 0, "yayilim": 0} for k in HATA_SINIFLARI}
    ornek: dict[str, list] = {k: [] for k in HATA_SINIFLARI}
    dogru = dogru_ic = yanlis_ic = 0
    tek_tarafli: list[list[str]] = []
    for q, e in sorted(s.esler.items()):
        fq = Q.fonk[q]
        if not fq.nufusta:
            continue
        h = esle.hukum(Q, R, q, e.r)
        if h == "dogru":
            dogru += 1
            dogru_ic += 1
            continue
        if h != "yanlis":
            continue
        fr = R.fonk[e.r]
        gercek = [a for n in fq.gt for a in r_ad.get(n, [])]
        if not gercek:
            sinif = "tavan_disi_satir_ici" if set(fr.gt) & q_ad else "tavan_disi_tek_tarafli"
        else:
            yanlis_ic += 1
            komsular = {c for a in gercek for c in (R.fonk[a].cagiran | R.fonk[a].cagrilan)}
            if e.r in komsular:
                sinif = "komsu"
            elif any(ikiz.ortak_onek([x, y]) or ikiz.ortak_sonek([x, y]) for x in fq.gt for y in fr.gt):
                sinif = "aile"
            else:
                sinif = "diger"
        if sinif == "tavan_disi_tek_tarafli":
            tek_tarafli.append(["|".join(fq.gt), "|".join(fr.gt)])
        say[sinif] += 1
        asama[sinif][e.asama] = asama[sinif].get(e.asama, 0) + 1
        if len(ornek[sinif]) < 8:
            ornek[sinif].append([list(fq.gt), list(fr.gt), e.asama, round(e.puan, 2), round(e.kutle, 2)])
    # ad ailesi: küme isabeti, q'nun adı R'de olanlar (tavan içi) ve olmayanlar ayrı
    aile_ic = [0, 0]
    aile_dis = 0
    nufus = set(Q.nufus)
    for q, bilgi in ikiz.aileler(Q, R, s).items():
        if q not in nufus or not Q.fonk[q].gt or bilgi["boy"] < 2:
            continue
        gt = set(Q.fonk[q].gt)
        if not any(n in r_ad for n in gt):
            aile_dis += 1
        else:
            aile_ic[0 if gt & set(bilgi["adlar"]) else 1] += 1
    return {"sorgu": Q.kimlik, "basvuru": R.kimlik, "dogru": dogru, "siniflar": say, "asama": asama,
            "tek_tarafli_ciftler": tek_tarafli,
            "aile_tavan_ici": {"isabet": aile_ic[0], "iska": aile_ic[1]}, "aile_tavan_disi": aile_dis,
            "tavan_ici": {"dogru": dogru_ic, "yanlis": yanlis_ic}, "ornek": ornek}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--nokta", default="kural", choices=sorted(esle.NOKTALAR))
    ap.add_argument("--json", type=Path)
    ap.add_argument("--ornek", action="store_true")
    a = ap.parse_args(argv)
    p = esle.NOKTALAR[a.nokta]
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    cikti: dict[str, Any] = {"nokta": a.nokta}
    for g in a.gruplar:
        satirlar = [yon(al(x), al(y), p) for c in ciftler.grup(g) for x, y in (c, c[::-1])]
        top = {k: sum(s["siniflar"][k] for s in satirlar) for k in HATA_SINIFLARI}
        top_asama = {k: {a_: sum(s["asama"][k].get(a_, 0) for s in satirlar) for a_ in ("dizgi", "yayilim")}
                     for k in HATA_SINIFLARI}
        d = sum(s["dogru"] for s in satirlar)
        y = sum(top.values())
        ic_y = sum(s["tavan_ici"]["yanlis"] for s in satirlar)
        o_tum, o_ic = ks1.oran(d, d + y), ks1.oran(d, d + ic_y)
        print(f"{g:14s} {a.nokta}: doğru {d} yanlış {y} → {top} (aşama: {top_asama})")
        print(f"{'':14s} kesinlik {o_tum['oran']:.3f} [{o_tum['aralik'][0]:.3f}, {o_tum['aralik'][1]:.3f}]; "
              f"tavan içi kesinlik {d}/{d + ic_y} = {o_ic['oran']:.3f} [{o_ic['aralik'][0]:.3f}, {o_ic['aralik'][1]:.3f}]")
        # tek taraflı çiftlerin karşılıklılığı: A → B yönünde (x, y) ile B → A yönünde (y, x) birlikte mi çıkıyor
        karsilikli = toplam_tt = 0
        for i in range(0, len(satirlar) - 1, 2):
            ileri = {tuple(c) for c in satirlar[i]["tek_tarafli_ciftler"]}
            geri = {(c[1], c[0]) for c in satirlar[i + 1]["tek_tarafli_ciftler"]}
            karsilikli += len(ileri & geri)
            toplam_tt += len(ileri | geri)
        print(f"{'':14s} tek taraflı (yeniden adlandırma adayı) tekil çift {toplam_tt}; iki yönde de aynı çift {karsilikli}")
        o_tt = ks1.oran(d, d + y - top["tavan_disi_tek_tarafli"])
        print(f"{'':14s} tek taraflılar hüküm dışı bırakılırsa (YÖN GÖSTERİCİ; sınıf doğrulanmadı): {d}/{d + y - top['tavan_disi_tek_tarafli']}"
              + (f" = {o_tt['oran']:.3f} [{o_tt['aralik'][0]:.3f}, {o_tt['aralik'][1]:.3f}]" if o_tt["aralik"] else ""))
        ai = sum(s["aile_tavan_ici"]["isabet"] for s in satirlar)
        ak = sum(s["aile_tavan_ici"]["iska"] for s in satirlar)
        ad_ = sum(s["aile_tavan_disi"] for s in satirlar)
        o_a = ks1.oran(ai, ai + ak)
        print(f"{'':14s} ad ailesi (küme): tavan içi isabet {ai}/{ai + ak}"
              + (f" = {o_a['oran']:.3f} [{o_a['aralik'][0]:.3f}, {o_a['aralik'][1]:.3f}]" if o_a["aralik"] else "")
              + f"; tavan dışı (isabet olanaksız) {ad_}")
        if a.ornek:
            for s in satirlar:
                for k in HATA_SINIFLARI:
                    for o in s["ornek"][k][:4]:
                        print(f"{'':6s}{s['sorgu']:24s} {k:10s} {o}")
        cikti[g] = {"yonler": satirlar, "siniflar": top, "asama": top_asama, "kesinlik": o_tum, "tavan_ici_kesinlik": o_ic,
                    "aile_tavan_ici": o_a, "aile_tavan_disi": ad_,
                    "tek_tarafli_haric_kesinlik": o_tt, "tek_tarafli_tekil_cift": toplam_tt, "tek_tarafli_karsilikli": karsilikli}
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
