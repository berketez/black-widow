"""G8 özet: koşulları C0 ile eşli karşılaştırır, ön kayıtlı karar kuralını uygular.

Girdi : workspaces/2026-10-19_g8/veri/olcum_C*.json, secim.json, ikili_kanit.json,
        BELGE/yerlesim_dogrulama.json
Çıktı : BELGE/sonuc.json (fonksiyon başına önce/sonra dahil), ekrana Markdown tabloları

Bootstrap (ön kayıt §6): eşli farkların ortalaması için yüzdelik güven aralığı,
10 000 yeniden örnekleme, tohum 18419053266058711754. Yüzdelikler sıralı örneklemden
alt = s[floor(0.025*(B-1))], üst = s[ceil(0.975*(B-1))].
"""

from __future__ import annotations

import json
import math
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

BOOT_TOHUM = 18419053266058711754   # SHA-256("karadul-g8-bootstrap-2026-10-19")[:16]
B = 10_000
ESIK_GORELI = 0.25

# (anahtar, sayı anahtarı, iyileşme yönü: -1 azalış, +1 artış)
BIRINCIL = [
    ("undefined_100", "undefined", -1),
    ("ptr_aritmetik_100", "ptr_aritmetik", -1),
    ("tip_donusumu_100", "tip_donusumu", -1),
    ("ok_erisim_100", "ok_erisim", +1),
    ("varsayilan_ad_100", "varsayilan_ad", -1),
]
IKINCIL = [
    ("ptr_aritmetik_genis_100", "ptr_aritmetik_genis", -1),
    ("varsayilan_genel_100", "varsayilan_genel", -1),
    ("fun_ad_100", "fun_ad", -1),
]
HAM = ("satir", "undefined", "ptr_aritmetik", "ptr_aritmetik_genis", "tip_donusumu", "ok_erisim",
       "varsayilan_ad", "varsayilan_genel", "fun_ad")
ADLAR = {
    "undefined_100": "U/100 (undefined*)",
    "ptr_aritmetik_100": "P1/100 (ham işaretçi aritmetiği)",
    "tip_donusumu_100": "C/100 (tip dönüşümü)",
    "ok_erisim_100": "A/100 (-> erişimi)",
    "varsayilan_ad_100": "D/100 (varsayılan ad)",
    "ptr_aritmetik_genis_100": "P2/100 (geniş)",
    "varsayilan_genel_100": "G/100 (FUN_/DAT_/LAB_...)",
    "fun_ad_100": "F/100 (FUN_)",
}


def bootstrap_ga(farklar: list[float]) -> tuple[float, float]:
    rng = random.Random(BOOT_TOHUM)
    n = len(farklar)
    ort = []
    for _ in range(B):
        ort.append(sum(farklar[rng.randrange(n)] for _ in range(n)) / n)
    ort.sort()
    return ort[math.floor(0.025 * (B - 1))], ort[math.ceil(0.975 * (B - 1))]


def yukle(k: str) -> dict:
    return json.loads((ortak.VERI / f"olcum_{k}.json").read_text())


def esle(once: list[dict], sonra: list[dict], rol: str) -> list[tuple[dict, dict]]:
    s = {x["adres"]: x for x in sonra if x["rol"] == rol}
    out = []
    for x in once:
        if x["rol"] != rol:
            continue
        y = s.get(x["adres"])
        if x["olcut"] is not None and y is not None and y["olcut"] is not None:
            out.append((x, y))
    return out


def olcut_ozeti(ciftler: list[tuple[dict, dict]], anahtar: str, sayi: str, yon: int, birincil: bool) -> dict:
    a = [x["olcut"][anahtar] for x, _ in ciftler]
    b = [y["olcut"][anahtar] for _, y in ciftler]
    fark = [bb - aa for aa, bb in zip(a, b)]
    lo, hi = bootstrap_ga(fark)
    sa = sum(x["olcut"][sayi] for x, _ in ciftler)
    sb = sum(y["olcut"][sayi] for _, y in ciftler)
    la = sum(x["olcut"]["satir"] for x, _ in ciftler)
    lb = sum(y["olcut"]["satir"] for _, y in ciftler)
    ha = 100.0 * sa / la if la else 0.0
    hb = 100.0 * sb / lb if lb else 0.0
    goreli = (hb - ha) / ha if ha else (math.inf if hb > 0 else 0.0)
    iyi = sum(1 for f in fark if f * yon > 0)
    kotu = sum(1 for f in fark if f * yon < 0)
    if yon < 0:
        ga_tutar = hi < 0
        goreli_tutar = goreli <= -ESIK_GORELI
    else:
        ga_tutar = lo > 0
        goreli_tutar = (ha == 0 and hb > 0) or goreli >= ESIK_GORELI
    out = {
        "n": len(ciftler),
        "ort_once": statistics.fmean(a), "ort_sonra": statistics.fmean(b),
        "medyan_once": statistics.median(a), "medyan_sonra": statistics.median(b),
        "ort_fark": statistics.fmean(fark), "ga95": [lo, hi],
        "havuz_once": ha, "havuz_sonra": hb, "havuz_goreli_degisim": goreli if math.isfinite(goreli) else "sonsuz",
        "toplam_sayi_once": sa, "toplam_sayi_sonra": sb,
        "iyilesen": iyi, "kotulesen": kotu, "degismeyen": len(fark) - iyi - kotu,
    }
    if birincil:
        out["ga_olcutu"] = ga_tutar
        out["goreli_olcutu"] = goreli_tutar
        out["anlamli_kazanc"] = bool(ga_tutar and goreli_tutar)
    return out


def tanimlayici(ciftler: list[tuple[dict, dict]]) -> dict:
    la = [x["olcut"]["satir"] for x, _ in ciftler]
    lb = [y["olcut"]["satir"] for _, y in ciftler]
    ta = [x["sure_ort_sn"] for x, _ in ciftler]
    tb = [y["sure_ort_sn"] for _, y in ciftler]
    return {
        "satir_toplam": [sum(la), sum(lb)], "satir_medyan": [statistics.median(la), statistics.median(lb)],
        "satir_ort_fark": statistics.fmean([b - a for a, b in zip(la, lb)]),
        "sure_medyan_sn": [statistics.median(ta), statistics.median(tb)],
        "sure_toplam_sn": [sum(ta), sum(tb)],
        "sure_medyan_orani": statistics.median(tb) / statistics.median(ta) if statistics.median(ta) else None,
    }


def main() -> None:
    kosullar = [k for k in ("C0", "C1", "C2", "C3", "C4") if (ortak.VERI / f"olcum_{k}.json").exists()]
    veri = {k: yukle(k) for k in kosullar}
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    sonuc: dict = {
        "kunye": ortak.kunye(),
        "onkayit_sha256": ortak.sha256(ortak.BELGE / "onkayit.md"),
        "olcut_sha256": ortak.sha256(ortak.BELGE / "olcut.py"),
        "secim": {"tohum": secim["tohum"], "aday_sayisi": secim["aday_sayisi"],
                  "hedefler": [{k: h[k] for k in ("sira", "adres", "ad", "dosya", "prototip_metni", "govde_bayt")}
                               for h in secim["hedefler"]],
                  "cagiran_sayisi": len(secim["cagiranlar"]), "elenen": secim["elenenler"],
                  "isinma": secim["isinma"]},
        "kosullar": {},
        "karsilastirmalar": {},
    }
    for k in kosullar:
        u = veri[k]["uygulama"]
        fk = veri[k]["fonksiyonlar"]
        sonuc["kosullar"][k] = {
            "uygulama": {a: u.get(a) for a in ("ad", "prototip", "tam", "ad_yazilan", "prototip_uygulanan",
                                               "uygulama_sn", "tip_denetimi")},
            "decompile_basarisiz": [x["adres"] for x in fk if x["olcut"] is None],
            "belirlenimci_degil": [x["adres"] for x in fk if x.get("belirlenimci") is False],
            "olcum_toplam_sn": veri[k]["olcum_toplam_sn"],
        }
    for k in kosullar:
        if k == "C0":
            continue
        sonuc["karsilastirmalar"][f"{k}-C0"] = {}
        for rol in ("hedef", "cagiran"):
            ciftler = esle(veri["C0"]["fonksiyonlar"], veri[k]["fonksiyonlar"], rol)
            ozet = {"birincil": {}, "ikincil": {}, "tanimlayici": tanimlayici(ciftler)}
            for anahtar, sayi, yon in BIRINCIL:
                ozet["birincil"][anahtar] = olcut_ozeti(ciftler, anahtar, sayi, yon, True)
            for anahtar, sayi, yon in IKINCIL:
                ozet["ikincil"][anahtar] = olcut_ozeti(ciftler, anahtar, sayi, yon, False)
            ozet["anlamli_kazanc_sayisi"] = sum(1 for v in ozet["birincil"].values() if v["anlamli_kazanc"])
            sonuc["karsilastirmalar"][f"{k}-C0"][rol] = ozet

    # G8 kararı (ön kayıt §6): C3 ↔ C0, hedefler
    if "C3-C0" in sonuc["karsilastirmalar"]:
        h = sonuc["karsilastirmalar"]["C3-C0"]["hedef"]
        sonuc["g8_karari"] = {
            "kural": "5 birincil ölçütün en az ikisinde anlamlı kazanç (GA sıfırı dışlar ve havuz oranı ≥%25 iyileşir)",
            "anlamli_olcutler": [a for a, v in h["birincil"].items() if v["anlamli_kazanc"]],
            "sayi": h["anlamli_kazanc_sayisi"],
            "sonuc": "geri yazma kazancı var" if h["anlamli_kazanc_sayisi"] >= 2 else "geri yazma kazancı yok",
            "U_ve_P1_birlikte": h["birincil"]["undefined_100"]["anlamli_kazanc"]
                                and h["birincil"]["ptr_aritmetik_100"]["anlamli_kazanc"],
        }

    # Fonksiyon başına önce/sonra (hedefler ve çağıranlar), bütün koşullar
    tablo = []
    adres_sirasi = [("hedef", h["adres"], h["ad"]) for h in secim["hedefler"]] + \
                   [("cagiran", c["adres"], None) for c in secim["cagiranlar"]]
    for rol, adr, ad in adres_sirasi:
        satir = {"rol": rol, "adres": adr, "gt_ad": ad, "kosullar": {}}
        for k in kosullar:
            x = next(f for f in veri[k]["fonksiyonlar"] if f["adres"] == adr)
            o = x["olcut"]
            satir["kosullar"][k] = {"ghidra_adi": x["ghidra_adi"], "sure_ort_sn": x["sure_ort_sn"],
                                    "belirlenimci": x.get("belirlenimci"),
                                    # ham sayılar; 100 satır oranı = 100 * sayı / satir
                                    "sayilar": None if o is None else {a: o[a] for a in HAM}}
        tablo.append(satir)
    sonuc["fonksiyonlar"] = tablo

    # Yerleşim doğrulaması ve ikili kanıt özetleri
    yd = json.loads((ortak.BELGE / "yerlesim_dogrulama.json").read_text())
    ik = json.loads((ortak.VERI / "ikili_kanit.json").read_text())
    sonuc["yerlesim_dogrulama_ozeti"] = {
        "window_pane_boyut": yd["window_pane"]["boyut"], "window_pane_alan": len(yd["window_pane"]["bilesenler"]),
        "kapanis": {k: yd["kapanis"][k] for k in ("yapi_sayisi", "adli", "ozet", "bit_alanli_yapilar")},
        "tmux_h_yapilari": {k: yd["tmux_h_yapilari"][k] for k in ("sayi", "ozet")},
        "ikili_sizeof_kaniti": ik["sizeof_window_pane_0x6e0"],
        "hedef_ofset_jaccard": {x["ad"]: x.get("jaccard") for x in ik["hedef_ofset_karsilastirmasi"]},
        "hedef_komut_sayisi_sise_bizim": {x["ad"]: [x.get("komut_sise"), x.get("komut_bizim")]
                                          for x in ik["hedef_ofset_karsilastirmasi"]},
    }
    ortak.json_yaz(ortak.BELGE / "sonuc.json", sonuc)

    # Ekran özeti
    for kar, roller in sonuc["karsilastirmalar"].items():
        for rol, oz in roller.items():
            print(f"\n## {kar} — {rol} (n={oz['birincil']['undefined_100']['n']}), anlamlı: {oz['anlamli_kazanc_sayisi']}/5")
            print("| ölçüt | ort. önce | ort. sonra | ort. fark [%95 GA] | havuz önce→sonra (göreli) | iyi/kötü/aynı | anlamlı |")
            print("|---|---|---|---|---|---|---|")
            for grup in ("birincil", "ikincil"):
                for a, v in oz[grup].items():
                    g = v["havuz_goreli_degisim"]
                    gs = g if isinstance(g, str) else f"{100*g:+.0f}%"
                    print(f"| {ADLAR[a]} | {v['ort_once']:.1f} | {v['ort_sonra']:.1f} | {v['ort_fark']:+.1f} "
                          f"[{v['ga95'][0]:+.1f}, {v['ga95'][1]:+.1f}] | {v['havuz_once']:.1f}→{v['havuz_sonra']:.1f} ({gs}) "
                          f"| {v['iyilesen']}/{v['kotulesen']}/{v['degismeyen']} | {v.get('anlamli_kazanc', '-')} |")
            t = oz["tanimlayici"]
            print(f"satır toplam {t['satir_toplam']}, medyan {t['satir_medyan']}; süre medyan {t['sure_medyan_sn']} "
                  f"(oran {t['sure_medyan_orani']})")
    if "g8_karari" in sonuc:
        print("\nG8 kararı:", sonuc["g8_karari"])


if __name__ == "__main__":
    main()
