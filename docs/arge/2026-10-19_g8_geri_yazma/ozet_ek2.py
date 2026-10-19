"""G8 ek 2 özeti: K4 ve K4' karşılaştırmaları, fonksiyon başına ortalama göreli değişim, okumalar.

onkayit_ek2.md §3-§5. Eşli analiz ozet.py'nin işlevleriyle (değiştirilmeden).
Çıktı: BELGE/sonuc_ek2.json
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import ozet  # noqa: E402
import ozet_ek  # noqa: E402

KARS = [("K4", "C0"), ("K4", "C2"), ("K4", "K2"), ("K4p", "C0"), ("K4p", "C3"), ("K4p", "K4")]
TANIMLAYICI = {("K4p", "K4")}


def fonksiyon_ortalamasi(ciftler: list, anahtar: str) -> dict:
    """Taban oranı > 0 olan fonksiyonlarda (sonra - önce) / önce ortalaması (onkayit_ek2 §3)."""
    oran = [(y["olcut"][anahtar] - x["olcut"][anahtar]) / x["olcut"][anahtar]
            for x, y in ciftler if x["olcut"][anahtar] > 0]
    sonra = [y["olcut"][anahtar] for _, y in ciftler]
    return {"ortalama_goreli": statistics.fmean(oran) if oran else None, "kullanilan": len(oran),
            "toplam": len(ciftler), "sonra_ortalama_oran": statistics.fmean(sonra) if sonra else None}


def main() -> None:
    O = {k: ozet_ek.yukle(k) for k in ("C0", "C2", "C3", "K2", "K4", "K4p")}
    sonuc: dict = {
        "kunye": ortak.kunye(),
        "onkayit_ek2_sha256": ortak.sha256(ortak.BELGE / "onkayit_ek2.md"),
        "olcut_sha256": ortak.sha256(ortak.BELGE / "olcut.py"),
        "ozet_sha256": ortak.sha256(ortak.BELGE / "ozet.py"),
        "kosullar": {k: {"uygulama": {a: O[k]["uygulama"].get(a) for a in
                                      ("parametre_adlandirilan", "parametre_kaynak_toplam", "parametre_ghidra_toplam",
                                       "eslenemeyen", "kaynakta_yok", "tip_yazilan_parametre", "donus_tipi_yazilan",
                                       "hatali", "uygulama_sn", "tip_denetimi")},
                         "fonksiyon_uygulamasi": O[k]["uygulama"]["fonksiyonlar"],
                         "decompile_basarisiz": [x["adres"] for x in O[k]["fonksiyonlar"] if x["olcut"] is None],
                         "belirlenimci_degil": [x["adres"] for x in O[k]["fonksiyonlar"] if x.get("belirlenimci") is False],
                         "olcum_toplam_sn": O[k]["olcum_toplam_sn"]}
                     for k in ("K4", "K4p")},
        "karsilastirmalar": {},
    }
    for sonra, once in KARS:
        kar = ozet_ek.karsilastir(O[once], O[sonra])
        for rol in ("hedef", "cagiran"):
            ciftler = ozet.esle(O[once]["fonksiyonlar"], O[sonra]["fonksiyonlar"], rol)
            kar[rol]["fonksiyon_ortalamasi"] = {a: fonksiyon_ortalamasi(ciftler, a)
                                               for a, _, _ in ozet.BIRINCIL + ozet.IKINCIL}
        kar["tanimlayici_yalniz"] = (sonra, once) in TANIMLAYICI
        sonuc["karsilastirmalar"][f"{sonra}-{once}"] = kar

    def havuz(k: str, a: str, rol: str = "hedef") -> float:
        # koşulun havuz oranı: K4-C0 karşılaştırmasının "önce"si C0, öbürleri "sonra"
        if k == "C0":
            return sonuc["karsilastirmalar"]["K4-C0"][rol]["birincil"][a]["havuz_once"]
        tablo = {"C2": ("K4-C2", "havuz_once"), "K2": ("K4-K2", "havuz_once"), "C3": ("K4p-C3", "havuz_once"),
                 "K4": ("K4-C0", "havuz_sonra"), "K4p": ("K4p-C0", "havuz_sonra")}
        kar, alan = tablo[k]
        return sonuc["karsilastirmalar"][kar][rol]["birincil"][a][alan]

    k4c0 = sonuc["karsilastirmalar"]["K4-C0"]["hedef"]["birincil"]
    r1 = k4c0["tip_donusumu_100"]["havuz_goreli_degisim"]
    r1 = r1 if not isinstance(r1, str) else float("inf")
    okumalar = {
        "R1": {"deger": r1, "tutar": r1 <= 0},
        "R2a": {"K4": havuz("K4", "tip_donusumu_100"), "C2": havuz("C2", "tip_donusumu_100"),
                "K2": havuz("K2", "tip_donusumu_100")},
        "R2b": {"K4": havuz("K4", "varsayilan_ad_100"), "C2": havuz("C2", "varsayilan_ad_100")},
        "R3": {"anlamli": sonuc["karsilastirmalar"]["K4p-C0"]["hedef"]["anlamli_kazanc_sayisi"],
               "anlamli_olcutler": sonuc["karsilastirmalar"]["K4p-C0"]["hedef"]["anlamli_olcutler"],
               "K4p_C": havuz("K4p", "tip_donusumu_100"), "C3_C": havuz("C3", "tip_donusumu_100")},
    }
    okumalar["R2a"]["tutar"] = okumalar["R2a"]["K4"] < okumalar["R2a"]["C2"] and okumalar["R2a"]["K4"] < okumalar["R2a"]["K2"]
    okumalar["R2b"]["tutar"] = okumalar["R2b"]["K4"] - okumalar["R2b"]["C2"] <= 5.0
    okumalar["R3"]["tutar"] = okumalar["R3"]["anlamli"] >= 2 and okumalar["R3"]["K4p_C"] <= okumalar["R3"]["C3_C"]
    oneri = []
    if okumalar["R1"]["tutar"] and okumalar["R2a"]["tutar"] and okumalar["R2b"]["tutar"]:
        oneri.append("Yerleşim yoksa yalnız ad yaz, tipe dokunma.")
    if okumalar["R3"]["tutar"]:
        oneri.append("Yerleşimi doğrulanmış yapılar için tip de yaz.")
    okumalar["oneri"] = oneri
    sonuc["okumalar"] = okumalar
    sonuc["havuz_oranlari_hedef"] = {k: {a: havuz(k, a) for a, _, _ in ozet.BIRINCIL}
                                     for k in ("C0", "C2", "K2", "K4", "C3", "K4p")}
    sonuc["havuz_oranlari_cagiran"] = {k: {a: havuz(k, a, "cagiran") for a, _, _ in ozet.BIRINCIL}
                                       for k in ("C0", "C2", "K2", "K4", "C3", "K4p")}
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    sat = []
    for rol, adr, ad in ([("hedef", h["adres"], h["ad"]) for h in secim["hedefler"]] +
                         [("cagiran", c["adres"], None) for c in secim["cagiranlar"]]):
        s = {"rol": rol, "adres": adr, "gt_ad": ad, "kosullar": {}}
        for k in ("C0", "C2", "K2", "K4", "C3", "K4p"):
            x = next(f for f in O[k]["fonksiyonlar"] if f["adres"] == adr)
            o = x["olcut"]
            s["kosullar"][k] = {"sayilar": None if o is None else {a: o[a] for a in ozet.HAM},
                                "sure_ort_sn": x["sure_ort_sn"]}
        sat.append(s)
    sonuc["fonksiyonlar"] = sat
    ortak.json_yaz(ortak.BELGE / "sonuc_ek2.json", sonuc)

    for kar, v in sonuc["karsilastirmalar"].items():
        if not isinstance(v, dict) or "hedef" not in v:
            continue
        for rol in ("hedef", "cagiran"):
            oz = v[rol]
            print(f"\n## {kar} — {rol}: anlamlı {oz['anlamli_kazanc_sayisi']}/5 {oz['anlamli_olcutler']}")
            for a, x in oz["birincil"].items():
                fo = oz["fonksiyon_ortalamasi"][a]
                g = x["havuz_goreli_degisim"]
                gs = g if isinstance(g, str) else f"{100 * g:+.0f}%"
                fos = (f"{100 * fo['ortalama_goreli']:+.0f}% (n={fo['kullanilan']})" if fo["ortalama_goreli"] is not None
                       else f"taban 0; sonra ort. {fo['sonra_ortalama_oran']:.1f}")
                print(f"  {ozet.ADLAR[a]:34s} havuz {x['havuz_once']:6.1f} -> {x['havuz_sonra']:6.1f} ({gs:>7s}) | "
                      f"fonk. ort. {fos:>18s} | fark {x['ort_fark']:+6.1f} [{x['ga95'][0]:+.1f}, {x['ga95'][1]:+.1f}] "
                      f"{x['iyilesen']}/{x['kotulesen']}/{x['degismeyen']} {x['anlamli_kazanc']}")
    print("\nokumalar:", json.dumps(okumalar, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
