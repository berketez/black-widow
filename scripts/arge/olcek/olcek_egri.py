#!/usr/bin/env python
"""ÖLÇEK kalem 3: ölçekleme eğrisi, doğrusal üstü adımlar ve dış değerleme (tahmin).

Girdi: ``olcek_topla.py`` çıktısı (119 ikili, a62f15e) ve ``gosteri_oku.py`` çıktısı (Ollama
arm64 dilimi; koşu sürüyorsa yalnız biten Ghidra adımları).

Modeller (her süre / disk ölçüsü y, boyut ölçüsü x için):
  (A) güç yasası      log10 y = a + b log10 x        (OLS; b için önyükleme %95 aralığı)
  (B) sabit + güç     y = c0 + c1 · x^b              (eğri uydurma; c0 ≥ 0 sabit giderdir:
                                                       JVM açılışı, içe aktarma, Python modülleri)
"Doğrusal üstü" hükmü: (B)'nin b'sinin önyükleme %95 alt sınırı > 1,05. (A) yalnız karşılaştırma
içindir (küçük ikilide sabit gider b'yi aşağı çeker).

Dış değerleme (TAHMİN, çapalı): örneklem en çok 3,2 MB / 5 697 fonksiyon; 100 MB onun ~30 katı.
Bu yüzden değerleme hedefe en yakın GERÇEK noktadan (gösteri dilimi) yapılır ve ölçek değişkeni dosya
baytı değil KOD baytıdır (``__text`` / ``.text``; gösteri diliminin 26,6 MB'ının 5,5 MB'ı kod):
  t_adım(hedef) = t_adım(çapa) × (x_hedef / x_çapa)^b
  x = kod baytı (otomatik analiz, çağrı grafiği, xref, CFG) ya da fonksiyon sayısı (decompile, BSim);
  b aralığı = (B) modelinin o x'e göre b'sinin %95 aralığı; aralık GENIS_ARALIK'tan genişse köprü
  toplamının kod baytına göre aralığı → [alt, üst] (A senaryosu). Kötümser B senaryosu: örneklemin en
  büyük ikilisiyle gösteri arasındaki iki noktalı üs (örneklem aralığından büyükse), en çok
  UST_US_SINIRI = 2 (VARSAYIM: hiçbir adım tümü-çiftlerden kötü değil). B yön göstericidir.
  Dosya baytı → kod baytı ve kod MiB başına fonksiyon oranları ``--kalibrasyon`` dosyasından (açık kaynak büyük Mach-O; ``metin_boyutu.py --ek-cikti``; evrensel
  dosyada dilim = dosya / mimari sayısı varsayımı): alt uç p10, üst uç p90. Nokta değer yok; [alt, üst].

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/olcek_egri.py \
        --kunye ~/karadul_olcum/runs/arge-2026-11-19/olcek/olcek_a62f15e_metin.json \
        --bellek-carpani ~/karadul_olcum/runs/arge-2026-11-19/olcek/bellek_carpani.json \
        --gosteri ~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_<saat>.json \
        --kalibrasyon ~/karadul_olcum/runs/arge-2026-11-19/olcek/yogunluk.json \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import warnings
from pathlib import Path
from typing import Any, Callable

import numpy as np
from scipy.optimize import curve_fit

ONYUKLEME = 400
ONYUKLEME_TOHUMU = 20261119
UST_US_SINIRI = 2.0  # kötümser senaryoda üs en çok 2 (tümü-çiftler); VARSAYIM, belgelerde yazılı
GENIS_ARALIK = 1.0  # b'nin %95 aralığı bundan genişse adımın üssü örneklemde belirlenmemiş sayılır
MB = 1024 * 1024
HEDEF_BAYT = {"25 MB": 25 * MB, "100 MB": 100 * MB, "300 MB": 300 * MB, "1 GB": 1024 * MB}

# y ölçüleri: (ad, çıkarıcı)
def _g(*yol: str) -> Callable[[dict], Any]:
    def f(k: dict) -> Any:
        v: Any = k
        for p in yol:
            if not isinstance(v, dict):
                return None
            v = v.get(p)
        return v
    return f


Y_OLCULERI: list[tuple[str, Callable[[dict], Any]]] = [
    ("toplam_sn", _g("toplam_sn")),
    ("static_sn", _g("asama_sn", "static")),
    ("reconstruct_sn", _g("asama_sn", "reconstruct")),
    ("ghidra_kopru_sn", _g("ghidra_sn")),
    ("otomatik_analiz_sn", _g("otomatik_analiz_sn")),
    ("g:ilk_adim(jvm+ice_aktarma+analiz)", _g("ghidra_adim_sn", "otomatik_analiz+fonksiyonlar")),
    ("g:cagri_grafigi", _g("ghidra_adim_sn", "cagri_grafigi")),
    ("g:decompile", _g("ghidra_adim_sn", "decompile")),
    ("g:xref", _g("ghidra_adim_sn", "xref")),
    ("g:cfg", _g("ghidra_adim_sn", "cfg")),
    ("g:bsim", _g("ghidra_adim_sn", "bsim")),
    # statik aşamanın köprü dışı kısmı: otool / strings / nm / lief + köprü sonrası (ikili istihbarat
    # `analyze_decompiled`, YARA, capa) — macho.py:251-423 ve :472-531, stages.py:570-577
    ("static_kopru_disi_sn", lambda k: ((k.get("asama_sn") or {}).get("static") or 0) - (k.get("ghidra_sn") or 0)
     if (k.get("asama_sn") or {}).get("static") and k.get("ghidra_sn") else None),
    ("disk_calisma_alani_bayt", _g("disk_calisma_alani", "ayrilan")),
    ("disk_calisma_alani_dosya", _g("disk_calisma_alani", "dosya")),
    ("disk_out_bayt", _g("disk_out", "ayrilan")),
    ("ghidra_json_toplam_bayt", lambda k: sum((k.get("ghidra_json_bayt") or {}).values()) or None),
]
X_OLCULERI: list[tuple[str, Callable[[dict], Any]]] = [
    ("fonk_toplam", _g("fonk_toplam")),
    ("cfg_blok", _g("cfg_blok")),
    ("analiz_bayt", _g("analiz_bayt")),
    ("metin_bayt", _g("metin_bayt")),
]


def _adim_olculeri(kayitlar: list[dict]) -> list[tuple[str, Callable[[dict], Any]]]:
    """reconstruct ``timing_*`` adımları: toplamda en çok süre alan 15'i (iter adımları dahil)."""
    toplam: dict[str, float] = {}
    for k in kayitlar:
        for a, v in (k.get("adim_sn") or {}).items():
            if isinstance(v, (int, float)):
                toplam[a] = toplam.get(a, 0.0) + float(v)
    secilen = sorted(toplam, key=lambda a: -toplam[a])[:15]
    return [(f"r:{a}", _g("adim_sn", a)) for a in secilen]


def _cift(kayitlar, fy, fx):
    xs, ys = [], []
    for k in kayitlar:
        x, y = fx(k), fy(k)
        if isinstance(x, (int, float)) and isinstance(y, (int, float)) and x > 0 and y > 0:
            xs.append(float(x))
            ys.append(float(y))
    return np.array(xs), np.array(ys)


def _guc(x, y):
    lx, ly = np.log10(x), np.log10(y)
    b, a = np.polyfit(lx, ly, 1)
    tahmin = a + b * lx
    ss_res = float(np.sum((ly - tahmin) ** 2))
    ss_tot = float(np.sum((ly - ly.mean()) ** 2)) or 1e-12
    return float(a), float(b), 1 - ss_res / ss_tot


def _sabit_guc_model(x, c0, c1, b):
    return c0 + c1 * np.power(x, b)


def _sabit_guc(x, y):
    """log uzayında artık: göreli hata eşit tartılır (küçük ve büyük ikili aynı ağırlıkta)."""
    def f(xx, c0, lc1, b):
        return np.log10(np.maximum(_sabit_guc_model(xx, c0, 10 ** lc1, b), 1e-9))
    p0 = (float(np.min(y)) * 0.5, math.log10(max(float(np.median(y / x)), 1e-9)), 1.0)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        p, _ = curve_fit(f, x, np.log10(y), p0=p0,
                         bounds=([0.0, -12.0, 0.3], [float(np.max(y)), 6.0, 3.0]), maxfev=20000)
    return float(p[0]), float(10 ** p[1]), float(p[2])


def uydur(x: np.ndarray, y: np.ndarray, rng: np.random.Generator) -> dict[str, Any]:
    n = len(x)
    out: dict[str, Any] = {"n": n, "x_aralik": [float(x.min()), float(x.max())]}
    if n < 6 or len(set(x.tolist())) < 4:
        out["yetersiz"] = True
        return out
    a, b, r2 = _guc(x, y)
    out["guc"] = {"a": a, "b": b, "r2": r2}
    try:
        c0, c1, bb = _sabit_guc(x, y)
        out["sabit_guc"] = {"c0": c0, "c1": c1, "b": bb}
    except (RuntimeError, ValueError) as exc:
        out["sabit_guc_hata"] = str(exc)
    bs_guc, bs_sg = [], []
    for _ in range(ONYUKLEME):
        i = rng.integers(0, n, n)
        if len(set(x[i].tolist())) < 4:
            continue
        bs_guc.append(_guc(x[i], y[i])[1])
        try:
            bs_sg.append(_sabit_guc(x[i], y[i]))
        except (RuntimeError, ValueError):
            pass
    if bs_guc:
        out["guc"]["b_ga95"] = [float(np.percentile(bs_guc, 2.5)), float(np.percentile(bs_guc, 97.5))]
    if bs_sg:
        arr = np.array(bs_sg)
        out["sabit_guc"]["b_ga95"] = [float(np.percentile(arr[:, 2], 2.5)),
                                      float(np.percentile(arr[:, 2], 97.5))]
        out["sabit_guc"]["_onyukleme"] = arr.tolist()
    out["dogrusal_ustu"] = bool(bs_sg and out["sabit_guc"]["b_ga95"][0] > 1.05)
    # birim maliyet: alt ve üst dörttebir
    q1, q3 = np.percentile(x, 25), np.percentile(x, 75)
    alt, ust = y[x <= q1] / x[x <= q1], y[x >= q3] / x[x >= q3]
    out["birim_maliyet_medyan"] = {"alt_ceyrek": float(np.median(alt)), "ust_ceyrek": float(np.median(ust))}
    return out


def ongor(model: dict[str, Any], x: float) -> dict[str, Any] | None:
    sg = model.get("sabit_guc")
    if not sg or "_onyukleme" not in sg:
        return None
    arr = np.array(sg["_onyukleme"])
    tah = arr[:, 0] + arr[:, 1] * np.power(x, arr[:, 2])
    nokta = sg["c0"] + sg["c1"] * x ** sg["b"]
    return {"nokta": float(nokta), "p5": float(np.percentile(tah, 5)), "p95": float(np.percentile(tah, 95))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kunye", required=True, type=Path)
    ap.add_argument("--gosteri", type=Path)
    ap.add_argument("--bellek-carpani", type=Path,
                    help="bellek_carpani.py çıktısı: köprü JSON'u → Python belleği aralığı")
    ap.add_argument("--kalibrasyon", type=Path,
                    help="metin_boyutu.py --ek-cikti: açık kaynak büyük Mach-O (etiket 'çapa' = gösteri)")
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args(argv)
    rng = np.random.default_rng(ONYUKLEME_TOHUMU)
    kayitlar = json.loads(a.kunye.read_text(encoding="utf-8"))["kayitlar"]
    kayitlar = [k for k in kayitlar if k.get("basari")]
    y_olc = Y_OLCULERI + _adim_olculeri(kayitlar)
    sonuc: dict[str, Any] = {"n_kayit": len(kayitlar), "modeller": {}, "oranlar": {},
                             "gosteri_kiyas": {}, "dis_degerleme_TAHMIN": {}}
    for yad, fy in y_olc:
        for xad, fx in X_OLCULERI:
            x, y = _cift(kayitlar, fy, fx)
            sonuc["modeller"][f"{yad}|{xad}"] = uydur(x, y, rng)

    # x / bayt oranları (dilim baytı başına fonksiyon, blok)
    for xad, fx in X_OLCULERI[:2]:
        r = [fx(k) / k["analiz_bayt"] for k in kayitlar
             if isinstance(fx(k), (int, float)) and k.get("analiz_bayt")]
        sonuc["oranlar"][f"{xad}_bayt_basina"] = {
            "p10": float(np.percentile(r, 10)), "medyan": float(np.median(r)),
            "p90": float(np.percentile(r, 90)), "n": len(r)}

    # Gösteri (örneklem dışı) kıyası: biten Ghidra adımları
    if a.gosteri and a.gosteri.exists():
        g = json.loads(a.gosteri.read_text(encoding="utf-8"))
        bas = g.get("ghidra_bas_sayilari") or {}
        gx = {"fonk_toplam": (bas.get("functions.json") or {}).get("total"),
              "cfg_blok": (bas.get("cfg.json") or {}).get("total_blocks"),
              "analiz_bayt": next((d["bayt"] for d in g.get("dosyalar", [])
                                   if d["yol"].endswith("_arm64")), None),
              "metin_bayt": g.get("metin_bayt")}
        adim = dict(g.get("ghidra_adim_sn_mtime") or {})
        if g.get("static_kopru_disi_sn") is not None:
            adim["static_kopru_disi"] = g["static_kopru_disi_sn"]
        if (g.get("ghidra_status") or {}).get("duration_seconds"):
            adim["ghidra_kopru"] = g["ghidra_status"]["duration_seconds"]
        eslem = {"ghidra_kopru_sn": "ghidra_kopru", "g:ilk_adim(jvm+ice_aktarma+analiz)": "otomatik_analiz+fonksiyonlar",
                 "g:cagri_grafigi": "cagri_grafigi", "g:decompile": "decompile",
                 "g:xref": "xref", "g:cfg": "cfg", "g:bsim": "bsim",
                 "static_kopru_disi_sn": "static_kopru_disi"}
        sonuc["gosteri_x"] = gx
        for yad, gad in eslem.items():
            if gad not in adim:
                continue
            for xad, xv in gx.items():
                if not xv:
                    continue
                m = sonuc["modeller"].get(f"{yad}|{xad}") or {}
                o = ongor(m, float(xv))
                if o:
                    o["gozlenen"] = adim[gad]
                    o["gozlenen_ongoru_orani"] = adim[gad] / o["nokta"] if o["nokta"] else None
                    o["gozlenen_p95_icinde"] = o["p5"] <= adim[gad] <= o["p95"]
                    sonuc["gosteri_kiyas"][f"{yad}|{xad}"] = o
        # ÖLÇ-0 ön kaydı: gösteri koşusunun henüz bitmemiş kısımları için örneklem modelinin öngörüsü
        # (fonksiyon sayısı ve kod baytı gösterinin kendi değerleri; p5–p95 önyükleme).
        sonuc["gosteri_onkayit"] = {}
        for yad in ("reconstruct_sn", "toplam_sn", "disk_calisma_alani_bayt", "disk_calisma_alani_dosya",
                    "disk_out_bayt"):
            for xad in ("fonk_toplam", "metin_bayt"):
                xv = gx.get(xad)
                o = ongor(sonuc["modeller"].get(f"{yad}|{xad}") or {}, float(xv)) if xv else None
                if o:
                    sonuc["gosteri_onkayit"][f"{yad}|{xad}"] = o
        # İki noktalı üs: örneklemin en büyük ikilisi (kod baytına göre) ile gösteri arasında,
        # b2 = ln(t_gösteri / t_örneklem) / ln(x_gösteri / x_örneklem). Aralık değil; yön gösterir.
        en_buyuk = max((k for k in kayitlar if k.get("metin_bayt")), key=lambda k: k["metin_bayt"])
        sonuc["iki_nokta_us"] = {"orneklem_ikili": en_buyuk["anahtar"].split("/ws/")[0]}
        yfun = dict(y_olc)
        for yad, gad in eslem.items():
            t1 = yfun[yad](en_buyuk) if yad in yfun else None
            t2 = adim.get(gad)
            if not t1 or not t2:
                continue
            for xad in ("fonk_toplam", "metin_bayt"):
                x1, x2 = en_buyuk.get(xad), gx.get(xad)
                if x1 and x2 and x1 != x2:
                    sonuc["iki_nokta_us"][f"{yad}|{xad}"] = {
                        "t_orneklem": t1, "t_gosteri": t2, "x_orneklem": x1, "x_gosteri": x2,
                        "b2": math.log(t2 / t1) / math.log(x2 / x1)}
        # dilim baytı başına oranlara gösteri noktasını ayrıca yaz (Go + Swift; örneklemde yok)
        if gx["analiz_bayt"]:
            sonuc["oranlar"]["gosteri"] = {
                "fonk_toplam_bayt_basina": (gx["fonk_toplam"] or 0) / gx["analiz_bayt"],
                "cfg_blok_bayt_basina": (gx["cfg_blok"] or 0) / gx["analiz_bayt"]}

    # Dış değerleme (TAHMİN, çapalı): çapa = gösteri dilimi; ölçek değişkeni KOD BAYTI
    gx = sonuc.get("gosteri_x") or {}
    if a.gosteri and a.gosteri.exists() and gx.get("metin_bayt") and a.kalibrasyon:
        g = json.loads(a.gosteri.read_text(encoding="utf-8"))
        adim = dict(g.get("ghidra_adim_sn_mtime") or {})
        kal = [k for k in json.loads(a.kalibrasyon.read_text(encoding="utf-8"))
               if k.get("metin_bayt") and k.get("fonksiyon_baslangici")]
        capa = next((k for k in kal if k.get("etiket") == "çapa"), None)
        kal_b = [k for k in kal if k.get("etiket") != "çapa"]
        # dosya baytı → kod baytı (evrensel dosyada eşit bölme varsayımı) ve kod MiB başına fonksiyon
        oran_m = [k["metin_bayt"] / (k["dosya_bayt"] / max(1, k.get("mimari_sayisi") or 1)) for k in kal_b]
        yog = [k["fonk_per_metin_mib"] for k in kal_b]
        capa_m = float(gx["metin_bayt"])
        capa_yog = float(capa["fonk_per_metin_mib"]) if capa else None
        sonuc["kalibrasyon"] = {
            "n": len(kal_b),
            "metin_orani": {"p10": float(np.percentile(oran_m, 10)), "medyan": float(np.median(oran_m)),
                            "p90": float(np.percentile(oran_m, 90))},
            "fonk_per_metin_mib": {"p10": float(np.percentile(yog, 10)), "medyan": float(np.median(yog)),
                                   "p90": float(np.percentile(yog, 90))},
            "capa_fonk_per_metin_mib": capa_yog, "capa_metin_bayt": capa_m}
        kal_s = sonuc["kalibrasyon"]
        surgen = None
        if "bsim" not in adim and g.get("son_dosyadan_beri_sn") and g.get("kosu_suruyor"):
            surgen = float(g["son_dosyadan_beri_sn"])  # BSim (ya da sonraki adım) en az bu kadar
        plan = [("otomatik_analiz+fonksiyonlar", "g:ilk_adim(jvm+ice_aktarma+analiz)|metin_bayt", False),
                ("dizgiler", None, False), ("cagri_grafigi", "g:cagri_grafigi|metin_bayt", False),
                ("decompile", "g:decompile|fonk_toplam", True), ("tipler", None, False),
                ("xref", "g:xref|metin_bayt", False), ("pcode_yazimi", None, False),
                ("cfg", "g:cfg|metin_bayt", False), ("bsim", "g:bsim|fonk_toplam", True)]
        kopru_b = ((sonuc["modeller"].get("ghidra_kopru_sn|metin_bayt") or {})
                   .get("sabit_guc") or {}).get("b_ga95", [1.0, 1.0])
        sonuc["kopru_b_ga95"] = kopru_b
        capa_f = capa_m / 2**20 * capa_yog  # çapanın LC_FUNCTION_STARTS sayısı
        # LC_FUNCTION_STARTS → Ghidra fonksiyon sayısı (modeller Ghidra sayısıyla kuruldu): çapadaki oran
        lc_ghidra = float(gx["fonk_toplam"]) / capa_f if gx.get("fonk_toplam") and capa_f else 1.0
        sonuc["lc_ghidra_orani"] = lc_ghidra
        carp = []
        if a.bellek_carpani and a.bellek_carpani.exists():
            carp = [x["carpan"] for x in json.loads(a.bellek_carpani.read_text(encoding="utf-8"))
                    if x.get("carpan")]

        def degerle(m_lo: float, m_hi: float, f_lo: float, f_hi: float) -> dict[str, Any]:
            d: dict[str, Any] = {"metin_kestirimi": [m_lo, m_hi], "fonksiyon_kestirimi": [f_lo, f_hi],
                                 "capa_metin_bayt": capa_m, "capa_fonksiyon": capa_f}
            top_lo = top_hi = top_kotu = 0.0
            for etiket, anahtar, fonk in plan:
                t0 = adim.get(etiket)
                alt_sinir = False
                if t0 is None and etiket == "bsim" and surgen is not None:
                    t0, alt_sinir = surgen, True
                if t0 is None:
                    continue
                b_kaynak = "adımın kendi modeli"
                if anahtar:
                    m = sonuc["modeller"].get(anahtar) or {}
                    b_lo, b_hi = (m.get("sabit_guc") or {}).get("b_ga95", [1.0, 1.0])
                    if b_hi - b_lo > GENIS_ARALIK:
                        b_lo, b_hi = kopru_b
                        b_kaynak = "köprü toplamı (adımın aralığı > %.1f)" % GENIS_ARALIK
                    # Örneklem dışı kanıt (yön gösterici): örneklemin en büyüğü → gösteri iki noktalı
                    # üssü. Kötümser senaryo B bu üssü kullanır, ama ÜST_US_SINIRI ile sınırlı:
                    # adımların hiçbiri algoritma olarak tümü-çiftlerden (n²) kötü değil (VARSAYIM).
                    b2 = ((sonuc.get("iki_nokta_us") or {}).get(anahtar) or {}).get("b2")
                else:
                    b_lo = b_hi = 1.0
                    b2 = None
                    b_kaynak = "doğrusal varsayım (küçük adım)"
                b_B = min(max(b_hi, b2 if b2 is not None else b_hi), UST_US_SINIRI)
                x_lo, x_hi = (f_lo / capa_f, f_hi / capa_f) if fonk else (m_lo / capa_m, m_hi / capa_m)
                lo, hi, kotu = t0 * x_lo ** b_lo, t0 * x_hi ** b_hi, t0 * x_hi ** b_B
                d[etiket] = {"capa_sn": t0, "b": [b_lo, b_hi], "b_kaynak": b_kaynak,
                             "b2_iki_nokta": b2, "b_kotumser": b_B,
                             "olcek": "fonksiyon" if fonk else "kod baytı", "katsayi": [x_lo, x_hi],
                             "alt_sn": lo, "ust_sn": hi, "kotumser_sn": kotu, "capa_alt_sinir": alt_sinir}
                top_lo += lo
                top_hi += hi
                top_kotu += kotu
            d["ghidra_kopru_toplam"] = {"alt_sn": top_lo, "ust_sn": top_hi, "kotumser_sn": top_kotu,
                                        "not": "BSim çapası koşu sürerken alt sınırdır" if surgen else ""}
            for yad in ("reconstruct_sn", "disk_calisma_alani_bayt", "disk_calisma_alani_dosya",
                        "disk_out_bayt", "ghidra_json_toplam_bayt"):
                m = sonuc["modeller"].get(f"{yad}|fonk_toplam") or {}
                lo, hi = ongor(m, f_lo * lc_ghidra), ongor(m, f_hi * lc_ghidra)
                if lo and hi:
                    d[f"{yad} (örneklem modeli, çapasız)"] = {"alt": lo["p5"], "ust": hi["p95"]}
            j_ = d.get("ghidra_json_toplam_bayt (örneklem modeli, çapasız)")
            if j_ and carp:
                d["python_kopru_bellegi_bayt (TAHMİN: JSON × çarpan)"] = {
                    "alt": j_["alt"] * min(carp), "ust": j_["ust"] * max(carp)}
            return d

        for hedef, bayt in HEDEF_BAYT.items():
            m_lo = bayt * kal_s["metin_orani"]["p10"]
            m_hi = bayt * kal_s["metin_orani"]["p90"]
            f_lo = m_lo / 2**20 * kal_s["fonk_per_metin_mib"]["p10"]
            f_hi = m_hi / 2**20 * kal_s["fonk_per_metin_mib"]["p90"]
            d = degerle(m_lo, m_hi, f_lo, f_hi)
            d["dosya_bayt"] = bayt
            sonuc["dis_degerleme_TAHMIN"][hedef] = d
        # Adı bilinen açık kaynak hedefler: kod baytı ve fonksiyon başlangıcı ölçülü (kalibrasyon yok)
        for k in kal_b:
            if k.get("adli_hedef"):
                d = degerle(float(k["metin_bayt"]), float(k["metin_bayt"]),
                            float(k["fonksiyon_baslangici"]), float(k["fonksiyon_baslangici"]))
                d["dosya_bayt"] = k["dosya_bayt"]
                d["yol"] = k["yol"]
                sonuc["dis_degerleme_TAHMIN"][f"{k['adli_hedef']}: {Path(k['yol']).name}"] = d

    # önyükleme dizilerini dosyaya yazma (büyük); yalnız özet
    for m in sonuc["modeller"].values():
        if "sabit_guc" in m:
            m["sabit_guc"].pop("_onyukleme", None)
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1), encoding="utf-8")

    # Ekran özeti
    print(f"kayıt: {sonuc['n_kayit']}; oranlar: {json.dumps(sonuc['oranlar'], ensure_ascii=False)}")
    print("\n| ölçü | x | n | güç b [GA95] | sabit+güç c0 | b [GA95] | doğrusal üstü | birim maliyet alt→üst çeyrek |")
    for key, m in sonuc["modeller"].items():
        if m.get("yetersiz") or "guc" not in m:
            continue
        yad, xad = key.split("|")
        g_, sg = m["guc"], m.get("sabit_guc", {})
        print(f"| {yad} | {xad} | {m['n']} | {g_['b']:.2f} [{g_.get('b_ga95', [0, 0])[0]:.2f}, "
              f"{g_.get('b_ga95', [0, 0])[1]:.2f}] | {sg.get('c0', float('nan')):.3g} | "
              f"{sg.get('b', float('nan')):.2f} [{sg.get('b_ga95', [0, 0])[0]:.2f}, "
              f"{sg.get('b_ga95', [0, 0])[1]:.2f}] | {m.get('dogrusal_ustu')} | "
              f"{m['birim_maliyet_medyan']['alt_ceyrek']:.3g} → {m['birim_maliyet_medyan']['ust_ceyrek']:.3g} |")
    print("\nGösteri (örneklem dışı) kıyası:")
    for key, o in sonuc["gosteri_kiyas"].items():
        print(f"  {key}: gözlenen {o['gozlenen']:.1f} sn; öngörü {o['nokta']:.1f} [{o['p5']:.1f}, {o['p95']:.1f}]; "
              f"oran {o['gozlenen_ongoru_orani']:.2f}; aralık içinde {o['gozlenen_p95_icinde']}")
    if sonuc.get("gosteri_onkayit"):
        print("\nGösteri için örneklem öngörüsü (ÖLÇ-0 ön kaydı; p5–p95):")
        for k, o in sonuc["gosteri_onkayit"].items():
            print(f"  {k}: {o['nokta']:.4g} [{o['p5']:.4g}, {o['p95']:.4g}]")
    if sonuc.get("iki_nokta_us"):
        print(f"\nİki noktalı üs (örneklem: {sonuc['iki_nokta_us']['orneklem_ikili']} → gösteri):")
        for k, v in sonuc["iki_nokta_us"].items():
            if isinstance(v, dict):
                print(f"  {k}: {v['t_orneklem']:.1f} → {v['t_gosteri']:.1f} sn; x {v['x_orneklem']:.0f} → "
                      f"{v['x_gosteri']:.0f}; b2 = {v['b2']:.2f}")
    if sonuc.get("kalibrasyon"):
        print(f"\nKalibrasyon: {json.dumps(sonuc['kalibrasyon'], ensure_ascii=False)}")
    for hedef, d in sonuc["dis_degerleme_TAHMIN"].items():
        print(f"\nTAHMİN {hedef}: kod {d['metin_kestirimi'][0]/2**20:.0f}–{d['metin_kestirimi'][1]/2**20:.0f} MiB")
        for k, v in d.items():
            if isinstance(v, dict) and "alt_sn" in v:
                print(f"  {k}: [{v['alt_sn']:.0f}, {v['ust_sn']:.0f}] sn"
                      + (" (çapa alt sınır)" if v.get("capa_alt_sinir") else ""))
            elif isinstance(v, dict) and "alt" in v:
                print(f"  {k}: [{v['alt']:.4g}, {v['ust']:.4g}]")
        print(f"  fonksiyon kestirimi: [{d['fonksiyon_kestirimi'][0]:.0f}, {d['fonksiyon_kestirimi'][1]:.0f}]; "
              f"köprü toplamı [{d['ghidra_kopru_toplam']['alt_sn']/3600:.1f}, {d['ghidra_kopru_toplam']['ust_sn']/3600:.1f}] saat; "
              f"kötümser (B) {d['ghidra_kopru_toplam']['kotumser_sn']/3600:.1f} saat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
