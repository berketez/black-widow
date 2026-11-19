#!/usr/bin/env python
"""ÖLÇEK kalem 1 + 3: envanterdeki kurulumlar için bugünkü akışın STATİK aşama süresi (TAHMİN).

Girdi: ``envanter.py`` çıktıları (kurulum başına JSON), ``olcek_egri.py`` çıktısı (``egri.json``:
modeller, kalibrasyon, iki noktalı üs) ve ``gosteri_oku.py`` çıktısı (çapa). Hiçbir ikili okunmaz;
yalnız envanterin üst verisi (boyut, ``file`` türündeki mimari sayısı, sha256) kullanılır.

Bileşen başına:
  dilim baytı s = dosya boyutu / mimari sayısı  (EŞİT BÖLME VARSAYIMI; fat başlığı bilerek okunmadı.
                  Gösteri dosyasında gerçek dilim / eşit bölme = 26 627 984 / 27 150 280 = 0,98)
  kod baytı    m ∈ [s × oran_p10, s × oran_p90]  (açık kaynak kalibrasyonu, ``egri.json`` "kalibrasyon")
  statik süre  T(m):
     m ≤ ÖRNEKLEM_UST_KOD (örneklemin en büyük kod baytı): ``static_sn|metin_bayt`` modeli (nokta)
     ÖRNEKLEM_UST_KOD < m ≤ m_çapa: iki noktalı üsle ara değerleme (örneklemin en büyüğü ↔ çapa)
     m >  ÖRNEKLEM_UST_KOD: T_çapa × (m / m_çapa)^b
        doğrusal senaryo: b = 1 (çapa ölçeğinde sabit gider ihmal edilir; adımların örneklem üsleri 1'i
        kapsıyor ya da aşıyor) → [alt (kod oranı p10); üst (kod oranı p90)]
        kötümser senaryo: b = köprünün iki noktalı üssü (örneklemin en büyüğü → gösteri; ``egri.json``),
        en çok 2 → kod oranı p90 ile tek değer (yön gösterici)
     T_çapa = gösteri statik aşaması (köprü + köprü dışı; koşu sürüyorsa o ana kadarki ALT SINIR)
Reconstruct (yalnız ana bileşende koşar) SAYILMAZ: toplam alt sınırdır.

Senaryolar:
  S0 bugünkü kural (``karadul/core/target.py:244-311``; bağlı dosyalar ayrı bileşen; JAR / Electron hariç)
  S1 S0'da aynı sha256 bir kez
  S2 S1'den yol adına göre üçüncü taraf çalışma zamanı sınıfları çıkarılırsa (DOĞRULANMAMIŞ sınıflama)
  S3 kurulumdaki bütün tekil Mach-O çalıştırılabilir / dylib / bundle (kapsam tam)

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/paket_tahmin.py \
        --envanter ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter \
        --egri ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json \
        --gosteri ~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_<saat>.json \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/paket_tahmin.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ANALIZ_SINIFLARI = ("Mach-O çalıştırılabilir", "Mach-O dylib", "Mach-O bundle")
UCUNCU_TARAF = {"Electron", "Chromium / CEF", "Qt", "LLVM / Clang", "Python çalışma zamanı",
                "Java çalışma zamanı", "Güncelleyici (Sparkle / Squirrel)", "ReactiveObjC / Mantle",
                "FFmpeg", "Boost", "ICU", "OpenSSL", "OpenCASCADE", "wxWidgets", "VTK",
                "BLAS / LAPACK / MKL", "Swift çalışma zamanı", "Node.js", "CUDA / Metal / ML",
                "Microsoft Office paylaşılan"}


def model_t(m: dict[str, Any], x: float) -> float:
    sg = m["sabit_guc"]
    return sg["c0"] + sg["c1"] * x ** sg["b"]


class Sure:
    def __init__(self, egri: dict, capa_t: float, capa_m: float, kod_ust: float) -> None:
        self.m_kucuk = egri["modeller"]["static_sn|metin_bayt"]
        kal = egri["kalibrasyon"]["metin_orani"]
        self.oran = (kal["p10"], kal["p90"])
        b2 = ((egri.get("iki_nokta_us") or {}).get("ghidra_kopru_sn|metin_bayt") or {}).get("b2")
        self.b = (1.0, 1.0, min(max(1.0, b2 if b2 is not None else 1.0), 2.0))
        self.capa_t, self.capa_m, self.kod_ust = capa_t, capa_m, kod_ust

    def tek(self, m: float, uc: int) -> float:
        if m <= self.kod_ust:
            return model_t(self.m_kucuk, m)
        if m <= self.capa_m:
            # örneklemin en büyüğü ile çapa ARASI: iki noktalı üs bu iki gerçek noktadan geçer
            # (ara değerleme); doğrusal çapa ölçeklemesi burada örneklemi aşırı öngörür.
            return self.capa_t * (m / self.capa_m) ** self.b[2]
        return self.capa_t * (m / self.capa_m) ** self.b[uc]

    def bilesen(self, s: float) -> tuple[float, float, float, float, float]:
        m_lo, m_hi = s * self.oran[0], s * self.oran[1]
        return self.tek(m_lo, 0), self.tek(m_hi, 1), self.tek(m_hi, 2), m_lo, m_hi


def senaryo(bilesenler: list[dict], sure: Sure) -> dict[str, Any]:
    lo = hi = kotu = bayt = 0.0
    buyuk = 0
    en_buyuk = 0.0
    for c in bilesenler:
        s = c["bayt"] / max(1, c.get("mimari_sayisi") or 1)
        a, b, k, m_lo, m_hi = sure.bilesen(s)
        lo += a
        hi += b
        kotu += k
        bayt += s
        buyuk += m_hi > sure.kod_ust
        en_buyuk = max(en_buyuk, s)
    return {"bilesen": len(bilesenler), "dilim_bayt_kestirimi": round(bayt),
            "en_buyuk_dilim_bayt": round(en_buyuk), "orneklem_ustu_bilesen": buyuk,
            "sure_alt_sn": round(lo), "sure_ust_sn": round(hi), "sure_kotumser_sn": round(kotu)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--envanter", required=True, type=Path)
    ap.add_argument("--egri", required=True, type=Path)
    ap.add_argument("--gosteri", required=True, type=Path)
    ap.add_argument("--kunye", required=True, type=Path, help="olcek_a62f15e_metin.json (örneklem üst sınırı)")
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args(argv)
    egri = json.loads(a.egri.read_text(encoding="utf-8"))
    g = json.loads(a.gosteri.read_text(encoding="utf-8"))
    kunye = json.loads(a.kunye.read_text(encoding="utf-8"))["kayitlar"]
    kod_ust = max(k["metin_bayt"] for k in kunye if k.get("metin_bayt"))
    kopru = (g.get("ghidra_status") or {}).get("duration_seconds") or 0.0
    capa_t = kopru + (g.get("static_kopru_disi_sn") or 0.0)
    sure = Sure(egri, capa_t, float(g["metin_bayt"]), float(kod_ust))
    sonuc: dict[str, Any] = {"capa_statik_sn": capa_t, "capa_kod_bayt": g["metin_bayt"],
                             "orneklem_ust_kod_bayt": kod_ust, "b": sure.b, "metin_orani": sure.oran,
                             "kurulumlar": []}
    for p in sorted(a.envanter.glob("*.json")):
        if p.name == "ozet.json":
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        o = d["ozet"]
        r: dict[str, Any] = {"ad": o["ad"], "lisans": o["lisans_sinifi"], "bayt": o["bayt"]}
        macho = [k for k in d["kayitlar"] if k["sinif"] in ANALIZ_SINIFLARI]
        tekil: dict[str, dict] = {}
        for k in macho:
            if k["sha256"] and k["sha256"] not in tekil:
                tekil[k["sha256"]] = k
        r["S3_tum_tekil_macho"] = senaryo(list(tekil.values()), sure)
        if d["karadul"]:
            s0 = [c for app in d["karadul"] for c in app["bilesenler"]
                  if c["kural"] not in ("Electron", "Resources/**/*.jar")]
            gor: set = set()
            s1 = []
            for c in s0:
                if c.get("sha256") and c["sha256"] not in gor:
                    gor.add(c["sha256"])
                    s1.append(c)
            s2 = [c for c in s1 if c.get("bilesen") not in UCUNCU_TARAF]
            r["S0_bugun"] = senaryo(s0, sure)
            r["S1_yineleme_bir_kez"] = senaryo(s1, sure)
            r["S2_ucuncu_taraf_disi"] = senaryo(s2, sure)
            r["jar_ve_electron_bileseni"] = sum(1 for app in d["karadul"] for c in app["bilesenler"]
                                                if c["kural"] in ("Electron", "Resources/**/*.jar"))
        sonuc["kurulumlar"].append(r)
    a.cikti.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"çapa statik {capa_t:.0f} sn (köprü {kopru:.0f} + köprü dışı {g.get('static_kopru_disi_sn')}); "
          f"çapa kod {g['metin_bayt']}; örneklem üst kod {kod_ust}; b {sure.b}; kod oranı {sure.oran}")
    print("| kurulum | senaryo | bileşen | dilim (MiB, eşit bölme) | en büyük dilim (MiB) | örneklem üstü | "
          "statik süre, doğrusal [alt; üst] (saat) | kötümser (saat) |")
    print("|---|---|---|---|---|---|---|---|")
    for r in sonuc["kurulumlar"]:
        for k in ("S0_bugun", "S1_yineleme_bir_kez", "S2_ucuncu_taraf_disi", "S3_tum_tekil_macho"):
            if k in r:
                s = r[k]
                print(f"| {r['ad']} | {k} | {s['bilesen']} | {s['dilim_bayt_kestirimi']/2**20:.0f} | "
                      f"{s['en_buyuk_dilim_bayt']/2**20:.0f} | {s['orneklem_ustu_bilesen']} | "
                      f"[{s['sure_alt_sn']/3600:.1f}; {s['sure_ust_sn']/3600:.1f}] | {s['sure_kotumser_sn']/3600:.1f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
