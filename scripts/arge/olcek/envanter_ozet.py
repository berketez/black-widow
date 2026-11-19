#!/usr/bin/env python
"""ÖLÇEK kalem 1: envanter çıktılarından özet tablo (Markdown) ve kurulumlar arası yineleme.

Girdi: ``envanter.py`` çıktı dizini. Yalnız üst veri (yol, boyut, ``file`` türü, sha256) kullanılır.
Çıktı: ekrana Markdown tablolar; ``--cikti`` ile JSON.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/envanter_ozet.py \
        --envanter ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter_ozet.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ANALIZ = ("Mach-O çalıştırılabilir", "Mach-O dylib", "Mach-O bundle")
GIB = 2 ** 30
MIB = 2 ** 20


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--envanter", required=True, type=Path)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args(argv)
    kurulumlar = []
    sha_kurulum: dict[str, set[str]] = defaultdict(set)
    sha_bayt: dict[str, int] = {}
    for p in sorted(a.envanter.glob("*.json")):
        if p.name == "ozet.json":
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        o = d["ozet"]
        macho = [k for k in d["kayitlar"] if k["sinif"] in ANALIZ]
        tekil = {k["sha256"]: k for k in macho if k["sha256"]}
        for h, k in tekil.items():
            sha_kurulum[h].add(o["ad"])
            sha_bayt[h] = k["bayt"]
        ucuncu = sum(k["bayt"] for k in macho if k["bilesen"] != "sınıflanmamış")
        toplam_macho_bayt = sum(k["bayt"] for k in macho)
        bilesen_bayt = Counter()
        for k in macho:
            bilesen_bayt[k["bilesen"]] += k["bayt"]
        r = {
            "ad": o["ad"], "lisans": o["lisans_sinifi"], "kok": o["kok"],
            "kok_app": o["kok"].endswith(".app"),
            "dosya": o["dosya"], "bayt": o["bayt"], "on_suzgecte_acilmayan": o.get("on_suzgecte_acilmayan"),
            "macho": len(macho), "macho_bayt": toplam_macho_bayt,
            "macho_evrensel": sum(1 for k in macho if k["evrensel"]),
            "macho_tekil": len(tekil), "macho_tekil_bayt": sum(k["bayt"] for k in tekil.values()),
            "en_buyuk_macho": max((k["bayt"] for k in macho), default=0),
            "en_buyuk_macho_yol": max(macho, key=lambda k: k["bayt"])["yol"] if macho else None,
            "macho_25mb_ustu": sum(1 for k in macho if k["bayt"] >= 25 * 10**6),
            "macho_100mb_ustu": sum(1 for k in macho if k["bayt"] >= 100 * 10**6),
            "macho_1mb_alti": sum(1 for k in macho if k["bayt"] < 10**6),
            "ucuncu_taraf_bayt_payi": ucuncu / toplam_macho_bayt if toplam_macho_bayt else None,
            "bilesen_bayt_ilk3": bilesen_bayt.most_common(4),
            "sinif_sayilari": o["sinif_sayilari"],
            "jar": sum(1 for k in d["kayitlar"] if k["yol"].endswith(".jar")),
            "asar": sum(1 for k in d["kayitlar"] if k["yol"].endswith(".asar")),
        }
        if d["karadul"]:
            comps = [c for app in d["karadul"] for c in app["bilesenler"]]
            r["karadul_app_sayisi"] = len(d["karadul"])
            r["karadul_bilesen"] = len(comps)
            r["karadul_bilesen_tekil_sha"] = len({c["sha256"] for c in comps if c.get("sha256")})
            r["karadul_bilesen_bayt"] = sum(c["bayt"] for c in comps)
            r["karadul_kapsam_disi_macho"] = sum(x["kapsam_disi_macho_sayisi"] for x in d["karadul"])
            r["karadul_kapsam_disi_bayt"] = sum(x["kapsam_disi_macho_bayt"] for x in d["karadul"])
            r["karadul_en_buyuk_bilesen"] = max((x["en_buyuk_bilesen_bayt"] for x in d["karadul"]), default=0)
        kurulumlar.append(r)
    # kurulumlar arası: aynı sha256 birden çok kurulumda
    ortak = {h: sorted(k) for h, k in sha_kurulum.items() if len(k) > 1}
    cift = Counter()
    cift_bayt = Counter()
    for h, ks in ortak.items():
        for i in range(len(ks)):
            for j in range(i + 1, len(ks)):
                cift[(ks[i], ks[j])] += 1
                cift_bayt[(ks[i], ks[j])] += sha_bayt[h]
    sonuc = {"kurulumlar": kurulumlar,
             "kurulumlar_arasi": [{"cift": list(c), "dosya": n, "bayt": cift_bayt[c]}
                                  for c, n in cift.most_common()]}
    if a.cikti:
        a.cikti.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1), encoding="utf-8")
    print("| kurulum | lisans | toplam GiB | dosya | Mach-O (adet / GiB) | evrensel | tekil sha (adet / GiB) | "
          "en büyük Mach-O (MiB) | ≥ 25 MB / ≥ 100 MB | < 1 MB | 3. taraf payı (bayt, yol adından) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in kurulumlar:
        print(f"| {r['ad']} | {r['lisans']} | {r['bayt']/GIB:.2f} | {r['dosya']} | {r['macho']} / "
              f"{r['macho_bayt']/GIB:.2f} | {r['macho_evrensel']} | {r['macho_tekil']} / "
              f"{r['macho_tekil_bayt']/GIB:.2f} | {r['en_buyuk_macho']/MIB:.0f} | {r['macho_25mb_ustu']} / "
              f"{r['macho_100mb_ustu']} | {r['macho_1mb_alti']} | "
              f"{(r['ucuncu_taraf_bayt_payi'] or 0)*100:.0f} % |")
    print("\n| kurulum | kök .app mı | Karadul bileşeni (S0) | tekil sha | bileşen GiB | kapsam dışı Mach-O (adet / MiB) | en büyük bileşen (MiB) | ilk bileşen sınıfları (bayt) |")
    print("|---|---|---|---|---|---|---|---|")
    for r in kurulumlar:
        ilk = "; ".join(f"{b} {v/MIB:.0f} MiB" for b, v in r["bilesen_bayt_ilk3"])
        if "karadul_bilesen" in r:
            print(f"| {r['ad']} | {'evet' if r['kok_app'] else 'hayır (' + str(r['karadul_app_sayisi']) + ' .app)'} | "
                  f"{r['karadul_bilesen']} | {r['karadul_bilesen_tekil_sha']} | {r['karadul_bilesen_bayt']/GIB:.2f} | "
                  f"{r['karadul_kapsam_disi_macho']} / {r['karadul_kapsam_disi_bayt']/MIB:.0f} | "
                  f"{r['karadul_en_buyuk_bilesen']/MIB:.0f} | {ilk} |")
        else:
            print(f"| {r['ad']} | hayır (.app yok) | — (hedef verilemez: `target.py:189-194`) | — | — | — | — | {ilk} |")
    print("\nKurulumlar arası aynı sha256 (Mach-O):")
    for x in sonuc["kurulumlar_arasi"][:15]:
        print(f"  {x['cift'][0]} ↔ {x['cift'][1]}: {x['dosya']} dosya, {x['bayt']/MIB:.0f} MiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
