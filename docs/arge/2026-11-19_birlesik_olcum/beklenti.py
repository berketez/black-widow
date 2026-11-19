#!/usr/bin/env python3
"""Birleşik ölçümün ön kayıtlı nokta beklentisi: yalnız taban kolun (yeni2) ölçüm JSON'undan aritmetik.

Girdi yalnız ``docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json`` (1.22.1, f30ac9a; ölçülmüş).
Yeni koşunun (urun-onarim-a62f15e) hiçbir çıktısı okunmaz. Birim × kanal sayıları üstünde onarım
paketlerinin ölçülmüş etkileri uygulanır (kaynaklar ``on_kayit.md`` §3):

- ``on_ad:gnulib`` (P-S3 + P-S3b, Ghidra'sız yeniden oynatma, 119 ikili): coreutils 837 ad / 620
  doğru → 732 / 732; debian/zstd 2 / 1 → 1 / 1 (``usage`` gelenek kanalı); öbür birimler → 0.
- ``string_context/kebap_ad`` (P12b): 239 → 0 (hepsi yanlıştı).
- ``api_param_reverse`` (P12a AD-02): 85 → 0 (1 doğru kaybı: openssl).
- Öbür kanallar değişmez.

Varsayımlar (ön kayıtta açık): kaldırılan anahtara başka kanal ad yazmaz; gnulib'in yeni 112 doğru
adı ad bekleyen nüfustadır (tabanda kanalın 843 adının 842'si nüfustaydı). Çıktıda fonksiyon adı
yoktur. Hesap makro kuralını ``urun_olc.makro_kesri`` ile aynı uygular (N_MIN = 10; aynı programın
platform birimleri önce ortalanır).

Kullanım: python3 docs/arge/2026-11-19_birlesik_olcum/beklenti.py [--json <çıktı>]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from fractions import Fraction
from pathlib import Path

DEPO = Path(__file__).resolve().parents[3]
TABAN = DEPO / "docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.json"
_spec = importlib.util.spec_from_file_location("ks1_olc", DEPO / "scripts/measurement/ks1_olc.py")
ks1 = importlib.util.module_from_spec(_spec)
sys.modules["ks1_olc"] = ks1
_spec.loader.exec_module(ks1)  # type: ignore[union-attr]
N_MIN = ks1.N_MIN  # urun_olc ile aynı makro eşiği (ön kayıt seçimi 4)

# Kanal başına yeni (ad, doğru, nüfustaki ad, nüfustaki doğru); None = değişmez, birim yoksa 0.
GNULIB = "on_ad:gnulib"
KEBAP = "string_context/kebap_ad"
ROL = "api_param_reverse"
GNULIB_YENI = {"debian/coreutils": (732, 732, 732, 732), "debian/zstd": (1, 1, 1, 1)}


def wilson(k: int, n: int):
    """Wilson %95 aralığı: ölçüm aracının kendi işlevi (``ks1_olc.oran``)."""
    return ks1.oran(k, n)["aralik"]


def birim_beklentisi(kanallar: dict) -> dict:
    out = {}
    for kanal, v in kanallar.items():
        satir = (v["ad_verilen"], v["dogru"], v["kapsam"]["k"], v["dogru_kapsam"]["k"])
        out[kanal] = satir
    return out


def uygula(birim: str, kanallar: dict) -> dict:
    yeni = dict(kanallar)
    if GNULIB in yeni or birim in GNULIB_YENI:
        yeni[GNULIB] = GNULIB_YENI.get(birim, (0, 0, 0, 0))
    for k in (KEBAP, ROL):
        if k in yeni:
            yeni[k] = (0, 0, 0, 0)
    return {k: v for k, v in yeni.items() if v[0] > 0}


def topla(kanallar: dict) -> tuple[int, int, int, int]:
    return tuple(sum(v[i] for v in kanallar.values()) for i in range(4))  # type: ignore[return-value]


def makro(oranlar: dict[str, tuple[int, int]]) -> tuple[float | None, dict, list]:
    giren = sorted(b for b, (_, n) in oranlar.items() if n >= N_MIN)
    prog: dict[str, list[Fraction]] = {}
    for b in giren:
        k, n = oranlar[b]
        prog.setdefault(b.split("/", 1)[1], []).append(Fraction(k, n))
    pm = {p: sum(v) / len(v) for p, v in sorted(prog.items())}
    ort = sum(pm.values()) / len(pm) if pm else None
    return (None if ort is None else round(float(ort), 6),
            {p: round(float(v), 6) for p, v in pm.items()}, giren)


def ozet(birimler: dict[str, dict], nufus: dict[str, int]) -> dict:
    ad = dogru = nf = nfd = 0
    yanlis_oran, kapsam_oran, dkapsam_oran = {}, {}, {}
    birim_satir = {}
    for b, kanallar in sorted(birimler.items()):
        a, d, k, kd = topla(kanallar)
        ad, dogru, nf, nfd = ad + a, dogru + d, nf + k, nfd + kd
        yanlis_oran[b] = (a - d, a)
        kapsam_oran[b] = (k, nufus[b])
        dkapsam_oran[b] = (kd, nufus[b])
        birim_satir[b] = {"ad": a, "dogru": d, "yanlis": a - d, "nufusta_ad": k,
                          "nufusta_dogru": kd, "nufus": nufus[b],
                          "yanlis_orani": None if a == 0 else round((a - d) / a, 6)}
    toplam_nufus = sum(nufus.values())
    my, my_prog, my_giren = makro(yanlis_oran)
    mk, _, _ = makro(kapsam_oran)
    mdk, _, _ = makro(dkapsam_oran)
    kanal_havuz: dict[str, list[int]] = {}
    for kanallar in birimler.values():
        for k, v in kanallar.items():
            h = kanal_havuz.setdefault(k, [0, 0])
            h[0] += v[0]
            h[1] += v[1]
    return {
        "havuz": {"ad": ad, "dogru": dogru, "yanlis": ad - dogru,
                  "yanlis_orani": round((ad - dogru) / ad, 6), "yanlis_wilson": wilson(ad - dogru, ad),
                  "kapsam": [nf, toplam_nufus, round(nf / toplam_nufus, 6)],
                  "dogru_kapsam": [nfd, toplam_nufus, round(nfd / toplam_nufus, 6)]},
        "makro": {"yanlis_orani": my, "program": my_prog, "giren_birimler": my_giren,
                  "kapsam": mk, "dogru_kapsam": mdk},
        "kanal": {k: {"ad": v[0], "dogru": v[1], "yanlis": v[0] - v[1],
                      "kesinlik_wilson": wilson(v[1], v[0])} for k, v in sorted(kanal_havuz.items())},
        "birim": birim_satir,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", type=Path, default=None)
    a = ap.parse_args()
    taban = json.loads(TABAN.read_text(encoding="utf-8"))
    nufus = {b: v["nufus"] for b, v in taban["birimler"].items()}
    once = {b: birim_beklentisi(v["ozet"]["kanal"]) for b, v in taban["birimler"].items()}
    sonra = {b: uygula(b, k) for b, k in once.items()}
    belge = {"kaynak": str(TABAN.relative_to(DEPO)), "n_min": N_MIN,
             "taban_yeniden_hesap": ozet(once, nufus), "beklenti": ozet(sonra, nufus)}
    # Sağlama: tabanın yeniden hesabı ölçülmüş tabanla aynı olmalı.
    t = taban["toplam"]["fonksiyon"]
    h = belge["taban_yeniden_hesap"]
    assert h["havuz"]["ad"] == t["havuz"]["ad_verilen"] and h["havuz"]["dogru"] == t["havuz"]["dogru"]
    assert abs(h["makro"]["yanlis_orani"] - t["makro"]["yanlis_orani"]["makro"]) < 1e-6
    metin = json.dumps(belge, ensure_ascii=False, indent=1) + "\n"
    if a.json:
        a.json.write_text(metin, encoding="utf-8")
    b = belge["beklenti"]
    print("havuz:", b["havuz"])
    print("makro:", b["makro"])
    for k, v in b["kanal"].items():
        print(f"  {k:32} {v}")
    for k, v in b["birim"].items():
        print(f"  {k:20} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
