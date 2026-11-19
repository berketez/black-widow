#!/usr/bin/env python
"""KİMLİK hattı — kalem 4: kapıda kalan (ayrılamayan) fonksiyonlar ve ad ailesi.

Yayılım bittiğinde eşlenmemiş q için aday listesi (puan, kütle, r) durur. Aile kuralı (htop'ta ayarlanır,
``AILE``'de dondurulur):
  - en iyi adayın puanı ≥ ``T_aile`` ve kütlesi ≥ ``kutle_aile`` olmalı (kanıtsız aile yok);
  - aile = puanı (en iyi − ``pencere``)'den büyük-eşit adaylar, en çok ``en_cok`` üye; daha fazlası varsa
    aile verilmez (çok geniş küme ad sayılmaz).
Hükümler:
  - ``kume``: q'nun GT adı ailenin adları arasında mı (küme düzeyi kesinlik);
  - ``sonek`` / ``etiketli``: aynısı ortak sonek için; ``etiketli`` = önek ya da sonek etiketi olan aileler;
  - ``onek``: aile adlarının ``_`` sınırındaki en uzun ortak öneki (en az bir belirteç) varsa ve q'nun GT adı
    o önekle başlıyorsa doğru; önek yoksa bu düzeyde ad verilmez.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import esle  # noqa: E402
from veri import Ikili, ks1  # noqa: E402


@dataclass(frozen=True)
class AileParam:
    T_aile: float = 0.3
    kutle_aile: float = 0.5
    pencere: float = 0.2
    en_cok: int = 8


AILE = AileParam()


def ortak_onek(adlar: list[str]) -> str:
    """``_`` ile ayrılmış belirteçlerde en uzun ortak önek; CamelCase öneki (``Sinif_``) de belirteçtir."""
    if not adlar:
        return ""
    parcalar = [a.split("_") for a in adlar]
    ortak = []
    for kol in zip(*parcalar):
        if all(k == kol[0] for k in kol):
            ortak.append(kol[0])
        else:
            break
    onek = "_".join(ortak)
    return onek if onek.strip("_") else ""


def ortak_sonek(adlar: list[str]) -> str:
    """``_`` sınırında en uzun ortak sonek (htop'taki ``Sinif_eylem`` ikizleri: ``*_delete``)."""
    ters = ortak_onek(["_".join(reversed(a.split("_"))) for a in adlar])
    return "_".join(reversed(ters.split("_"))) if ters else ""


def aileler(Q: Ikili, R: Ikili, sonuc: esle.Sonuc, ap: AileParam = AILE) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for q, liste in sonuc.adaylar.items():
        if not liste:
            continue
        en_puan, en_kutle, _ = liste[0]
        if en_puan < ap.T_aile or en_kutle < ap.kutle_aile:
            continue
        uyeler = [r for puan, _m, r in liste if puan >= en_puan - ap.pencere]
        if len(uyeler) > ap.en_cok or len(uyeler) < 1:
            continue
        adlar = sorted({n for r in uyeler for n in R.fonk[r].gt})
        if not adlar:
            continue
        cok = len(adlar) > 1
        out[q] = {"uyeler": uyeler, "adlar": adlar, "onek": ortak_onek(adlar) if cok else "",
                  "sonek": ortak_sonek(adlar) if cok else "", "boy": len(uyeler)}
    return out


def olc(Q: Ikili, R: Ikili, sonuc: esle.Sonuc, ap: AileParam = AILE) -> dict[str, Any]:
    nufus = set(Q.nufus)
    a = aileler(Q, R, sonuc, ap)
    kume = [0, 0]
    onek = [0, 0]
    sonek = [0, 0]
    etiketli = [0, 0]     # önek ya da sonek etiketi olan aileler
    tek = [0, 0]          # tek üyeli "aile": kapının marj yüzünden değil karşılıklılık yüzünden reddettikleri
    boylar: dict[int, int] = {}
    ornek = []
    for q, bilgi in a.items():
        if q not in nufus or not Q.fonk[q].gt:
            continue
        gt = set(Q.fonk[q].gt)
        boylar[bilgi["boy"]] = boylar.get(bilgi["boy"], 0) + 1
        isabet = bool(gt & set(bilgi["adlar"]))
        if bilgi["boy"] == 1:
            tek[0 if isabet else 1] += 1
            continue
        kume[0 if isabet else 1] += 1
        ok_o = ok_s = False
        if bilgi["onek"]:
            ok_o = any(g == bilgi["onek"] or g.startswith(bilgi["onek"] + "_") for g in gt)
            onek[0 if ok_o else 1] += 1
        if bilgi["sonek"]:
            ok_s = any(g == bilgi["sonek"] or g.endswith("_" + bilgi["sonek"]) for g in gt)
            sonek[0 if ok_s else 1] += 1
        if bilgi["onek"] or bilgi["sonek"]:
            # etiket doğru: verilen her etiket (önek ve / veya sonek) GT adıyla uyuşuyor
            tam = (ok_o or not bilgi["onek"]) and (ok_s or not bilgi["sonek"])
            etiketli[0 if tam else 1] += 1
        if len(ornek) < 12:
            ornek.append({"gt": sorted(gt), "aile": bilgi["adlar"], "onek": bilgi["onek"],
                          "sonek": bilgi["sonek"], "isabet": isabet})
    kalan = [q for q in nufus if q not in sonuc.esler]
    return {"kalan_nufus": len(kalan), "adayli": sum(1 for q in kalan if q in sonuc.adaylar),
            "aile_boyu": dict(sorted(boylar.items())),
            "kume": ks1.oran(kume[0], kume[0] + kume[1]),
            "onek": ks1.oran(onek[0], onek[0] + onek[1]),
            "sonek": ks1.oran(sonek[0], sonek[0] + sonek[1]),
            "etiketli": ks1.oran(etiketli[0], etiketli[0] + etiketli[1]),
            "tek_uyeli": ks1.oran(tek[0], tek[0] + tek[1]),
            "ornek": ornek}
