"""Kalem 1: taban ve ÖLÇÜ hattının ana sayılarını OLGU tablosundan yeniden türetir.

Hat betikleri kullanılmaz. Çıktı: metin (stdout) + --json.
Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/turet_taban.py --json $V/turet_taban.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict

from ortak import bicim_anahtari, klon_soy, olgu_oku, program, wilson, yaz

ALAN = {
    "birim", "ikili", "platform", "adres", "nufusta", "urun_adi", "urun_olcude", "hukum",
    "kanal", "gt_adlari", "guven", "kaynak_sinifi", "dw_tanim_dosyasi", "dw_birim_yolu",
}


def gt_soy(ad: str, platform: str) -> str:
    a = klon_soy(ad)
    if platform == "mac" and a.startswith("_"):
        a = a[1:]
    return a


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    satirlar = list(olgu_oku(ALAN))
    c: dict = {}

    nufus = [r for r in satirlar if r["nufusta"]]
    adli = [r for r in satirlar if r["urun_olcude"]]
    dogru = [r for r in adli if r["hukum"] == "dogru"]
    yanlis = [r for r in adli if r["hukum"] == "yanlis"]
    c["taban"] = {
        "satir": len(satirlar), "nufus": len(nufus), "ad": len(adli), "dogru": len(dogru),
        "yanlis": len(yanlis), "nufusta_dogru": sum(1 for r in dogru if r["nufusta"]),
    }
    print("TABAN", c["taban"], "yanlış", yaz(len(yanlis), len(adli)))

    # kanal kırılımı
    kanal = defaultdict(lambda: [0, 0])
    for r in adli:
        kanal[r["kanal"]][1] += 1
        kanal[r["kanal"]][0] += r["hukum"] == "dogru"
    c["kanal"] = {k: v for k, v in sorted(kanal.items())}
    print("\nKANAL (doğru / ad; Wilson)")
    for k, (d, n) in sorted(kanal.items()):
        print(f"  {k:40s} {yaz(d, n)}")

    # biçim: yanlışların kaçı yalnız biçimce farklı
    def bicim_mi(r, cakisma):
        u = bicim_anahtari(r["urun_adi"], cakisma_soy=cakisma)
        return any(u == bicim_anahtari(gt_soy(g, r["platform"])) for g in (r["gt_adlari"] or []))

    bicim_dar = [r for r in yanlis if bicim_mi(r, False)]
    bicim_genis = [r for r in yanlis if bicim_mi(r, True)]
    yalniz_harf = [r for r in yanlis if any(
        r["urun_adi"].lower() == gt_soy(g, r["platform"]).lower() and r["urun_adi"] != gt_soy(g, r["platform"])
        for g in (r["gt_adlari"] or []))]
    c["bicim"] = {
        "yalniz_harf": len(yalniz_harf),
        "harf_ve_altcizgi_ve_klon": len(bicim_dar),
        "arti_cakisma_eki": len(bicim_genis),
        "birim_genis": dict(Counter(r["birim"] for r in bicim_genis)),
        "kanal_genis": dict(Counter(r["kanal"] for r in bicim_genis)),
    }
    print("\nBİÇİM (119 yanlış içinde)", c["bicim"])
    bicim_kume = {(r["birim"], r["ikili"], r["adres"]) for r in bicim_genis}

    # program düzeyi makro (n >= 10 olan programlar)
    def makro(yanlis_say):
        prog = defaultdict(lambda: [0, 0])
        for r in adli:
            prog[program(r["birim"])][1] += 1
            prog[program(r["birim"])][0] += yanlis_say(r)
        oran = {p: (y / n) for p, (y, n) in prog.items() if n >= 10}
        return sum(oran.values()) / len(oran), {p: (y, n) for p, (y, n) in prog.items()}

    m_tam, prog_tam = makro(lambda r: r["hukum"] == "yanlis")
    m_bic, prog_bic = makro(lambda r: r["hukum"] == "yanlis" and (r["birim"], r["ikili"], r["adres"]) not in bicim_kume)
    c["makro"] = {"tam": m_tam, "tam_bicim": m_bic, "program_tam": prog_tam, "program_bicim": prog_bic}
    print(f"\nMAKRO yanlış (program, n>=10): tam {m_tam:.4f}; tam+biçim {m_bic:.4f}")
    for p in sorted(prog_tam):
        y, n = prog_tam[p]
        yb, _ = prog_bic[p]
        _, alt, ust = wilson(y, n)
        print(f"  {p:14s} n={n:5d} yanlış {y:4d} ({y/n:.3f}; Wilson {alt:.3f}–{ust:.3f})  biçimle {yb:4d} ({yb/n:.3f})")

    # tekil ad: (program, ürün adı, GT'nin ilk adı)
    tekil = {}
    for r in adli:
        gt0 = (r["gt_adlari"] or [None])[0]
        anahtar = (program(r["birim"]), r["urun_adi"], gt0)
        tekil.setdefault(anahtar, r)
    t_dogru = sum(1 for r in tekil.values() if r["hukum"] == "dogru")
    t_bicim = sum(1 for r in tekil.values() if r["hukum"] == "yanlis" and (r["birim"], r["ikili"], r["adres"]) in bicim_kume)
    kanal_tekil = defaultdict(lambda: [0, 0])
    for r in tekil.values():
        kanal_tekil[r["kanal"]][1] += 1
        kanal_tekil[r["kanal"]][0] += r["hukum"] == "dogru"
    c["tekil"] = {"tekil_ad": len(tekil), "dogru": t_dogru, "bicim": t_bicim,
                  "kanal": {k: v for k, v in sorted(kanal_tekil.items())}}
    print(f"\nTEKİL ad {len(tekil)}; doğru {t_dogru}; biçim {t_bicim}; yanlış (tam) {yaz(len(tekil)-t_dogru, len(tekil))};"
          f" yanlış (tam+biçim) {yaz(len(tekil)-t_dogru-t_bicim, len(tekil))}")
    for k, (d, n) in sorted(kanal_tekil.items()):
        _, alt, _ = wilson(d, n)
        print(f"  {k:40s} {d} / {n} (alt {alt:.3f}; L* {1/(1-alt):.1f})")

    # tekil nüfus: (program, tanım dosyası, GT ilk adı)
    tn = set()
    for r in nufus:
        tn.add((program(r["birim"]), r["dw_tanim_dosyasi"] or r["dw_birim_yolu"], (r["gt_adlari"] or [None])[0]))
    c["tekil_nufus"] = len(tn)
    print(f"\nTEKİL nüfus (program, tanım dosyası, GT adı): {len(tn)}")

    # program başına doğru ad: coreutils dışı
    dis = sum(1 for r in dogru if program(r["birim"]) != "coreutils")
    tmux = sum(1 for r in dogru if program(r["birim"]) == "tmux")
    c["coreutils_disi_dogru"] = dis
    c["tmux_dogru"] = tmux
    print(f"coreutils dışı doğru ad {dis}; tmux (iki platform) {tmux}")
    nd = defaultdict(lambda: [0, 0])
    for r in nufus:
        nd[r["birim"]][1] += 1
        nd[r["birim"]][0] += r["hukum"] == "dogru"
    c["nufus_birim"] = dict(nd)
    print("\nNÜFUS içi doğru / nüfus (birim)")
    for b, (d, n) in sorted(nd.items()):
        print(f"  {b:22s} {d:5d} / {n:6d} ({d/n:.3f})")

    # kalibrasyon: oz_ad güven sınıfları
    oz = [r for r in adli if r["kanal"] == "string_context/oz_ad"]
    gs = defaultdict(lambda: [0, 0, 0])
    for r in oz:
        g = gs[r["guven"]]
        g[2] += 1
        g[0] += r["hukum"] == "dogru"
        g[1] += r["hukum"] == "dogru" or (r["birim"], r["ikili"], r["adres"]) in bicim_kume
    c["oz_ad_guven"] = {str(k): v for k, v in gs.items()}
    print("\noz_ad güven sınıfı → [tam, tam+biçim, n]:", dict(gs))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=1, default=str)


if __name__ == "__main__":
    main()
