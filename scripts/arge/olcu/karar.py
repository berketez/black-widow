#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 5: dört düzeyli çıktı (ad / ad ailesi / kanıt satırı / boş) için maliyet modeli ve
kanalların ölçülmüş kesinliklerinden belirlenimci düzey seçimi (taslak; ürüne girmedi).

Kayıp modeli (fonksiyon başına; doğru ad = 0):
    boş = 1                    (analist işi baştan yapar)
    kanıt satırı = e           (0 < e ≤ 1; kanıtın yardımı 1 − e; ölçülmedi → parametre)
    yanlış ad = L              (L ≥ 1: yanlış adın maliyeti eksik adın L katı)
    doğru aile = a, yanlış aile = L   (0 < a < e; aile iddiası da yanıltabilir → aynı L, tutucu)
Beklenen kayıp: ad (1 − p)·L; aile p_a·a + (1 − p_a)·L. p yerine kanalın ölçülmüş kesinliğinin Wilson %95
alt sınırı kullanılır (``MEASURED_PRE_NAME_PRECISION`` ile aynı tutuculuk).
Kural: düzey = en küçük beklenen kayıp; eşitlikte daha zayıf iddia (kanıt > aile > ad sırasıyla tercih).
K-2 gereği kanıtı olan kanal "boş" yazmaz (e ≤ 1 olduğu için kanıt satırı boşa baskındır).
Ad düzeyinin başa baş noktası: p > 1 − e / L. e = 1'de L* = 1 / (1 − p).

Aile tanımları (mekanik; ikisi de raporlanır, hiçbiri insan hükmüyle doğrulanmadı):
    ``aile_onek``   : adayın ilk belirteci GT adının ilk belirteciyle aynı (modül öneki) ya da ad doğru;
    ``aile_kardes`` : aday GT adına en az başka her fonksiyona olduğu kadar benziyor (b ≥ r, b > 0) ya da ad doğru.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/karar.py \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/karar.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import kimlik as kimlik_modulu  # noqa: E402
import olcu  # noqa: E402

KAYIP_L = (2, 5, 10, 20, 50, 100)     # yanlış ad / eksik ad maliyet oranı taraması
KAYIP_E = (1.0, 0.5)                  # kanıt satırının kaybı (1 = yardımı yok, 0,5 = işin yarısını görür)
KAYIP_A = 0.25                        # doğru ailenin kaybı (parametre; ölçülmedi)
KARAR_HUKUMLERI = ("tam", "tam+bicim")
KARAR_AILE_TANIMLARI = ("aile_onek", "aile_kardes")


def duzey(p_ad: float, p_aile: float, L: float, e: float) -> str:
    kayip = {"kanit": e, "aile": p_aile * KAYIP_A + (1 - p_aile) * L, "ad": (1 - p_ad) * L}
    return min(("kanit", "aile", "ad"), key=lambda d: (kayip[d], ("kanit", "aile", "ad").index(d)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    say: dict[str, Counter] = defaultdict(Counter)
    for ik in taban.values():
        if not ik["adlar"]:
            continue
        gt_ikili = kimlik_modulu.IkiliGt(ik["gt"])
        for k in ik["adlar"]:
            tam = k["durum"] == "dogru"
            bicim = tam or olcu.harf_tam(k["ad"], k["gt"])
            ta = olcu.belirtecler(k["ad"])
            onek = bicim or any(ta and (tg := olcu.belirtecler(g)) and ta[0] == tg[0] for g in k["gt"])
            kardes = bicim
            if not kardes and k["gt"]:
                bz = gt_ikili.benzerlikler(k["ad"])
                b = bz[k["adres"]][0]
                r = max((v[0] for adr, v in bz.items() if adr != k["adres"]), default=0.0)
                kardes = b > 0 and b >= r
            for kanal in (k["kanal"], "TOPLAM"):
                c = say[kanal]
                c["ad"] += 1
                c["tam"] += tam
                c["tam+bicim"] += bicim
                c["aile_onek"] += onek
                c["aile_kardes"] += kardes
    sonuc: dict = {"sema": "karadul-arge-olcu-karar/1",
                   "model": {"L": KAYIP_L, "e": KAYIP_E, "a": KAYIP_A, "p": "Wilson %95 alt sınırı"}, "kanal": {}}
    for kanal, c in sorted(say.items()):
        satir: dict = {"ad": c["ad"]}
        for h in KARAR_HUKUMLERI + KARAR_AILE_TANIMLARI:
            o = ks1_olc.oran(c[h], c["ad"])
            alt = o["aralik"][0]
            satir[h] = {**o, "L_basabas": None if alt >= 1 else round(1 / (1 - alt), 2)}
        satir["duzey"] = {}
        for h in KARAR_HUKUMLERI:
            for aile in KARAR_AILE_TANIMLARI:
                for e in KAYIP_E:
                    satir["duzey"][f"{h}|{aile}|e={e}"] = {
                        str(L): duzey(satir[h]["aralik"][0], satir[aile]["aralik"][0], L, e) for L in KAYIP_L}
        sonuc["kanal"][kanal] = satir
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    print("== kanal: ad | tam k (Wilson alt; L*) | tam+biçim | aile_onek | aile_kardes")
    for kanal, s in sonuc["kanal"].items():
        print(f"  {kanal:30s} n={s['ad']:5d} " + " | ".join(
            f"{h}: {s[h]['k']} ({s[h]['aralik'][0]:.3f}; L*={s[h]['L_basabas']})" for h in KARAR_HUKUMLERI + KARAR_AILE_TANIMLARI))
    for h in KARAR_HUKUMLERI:
        for e in KAYIP_E:
            print(f"\n== düzey (hüküm={h}, aile=aile_kardes, e={e}); L = {KAYIP_L}")
            for kanal, s in sonuc["kanal"].items():
                d = s["duzey"][f"{h}|aile_kardes|e={e}"]
                print(f"  {kanal:30s} " + "  ".join(f"{L}:{d[str(L)]:5s}" for L in KAYIP_L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
