"""G8 ek koşulların özeti: onkayit_ek.md §3'teki karşılaştırmalar ve karar okuması.

Eşli analiz ozet.py'nin işlevleriyle (değiştirilmeden) yapılır.
Çıktı: BELGE/sonuc_ek.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import ozet  # noqa: E402


def yukle(k: str) -> dict:
    return json.loads((ortak.VERI / f"olcum_{k}.json").read_text())


def karsilastir(once: dict, sonra: dict, sure_tabani: dict | None = None) -> dict:
    out = {}
    for rol in ("hedef", "cagiran"):
        ciftler = ozet.esle(once["fonksiyonlar"], sonra["fonksiyonlar"], rol)
        oz = {"birincil": {}, "ikincil": {}}
        for anahtar, sayi, yon in ozet.BIRINCIL:
            oz["birincil"][anahtar] = ozet.olcut_ozeti(ciftler, anahtar, sayi, yon, True)
        for anahtar, sayi, yon in ozet.IKINCIL:
            oz["ikincil"][anahtar] = ozet.olcut_ozeti(ciftler, anahtar, sayi, yon, False)
        oz["anlamli_kazanc_sayisi"] = sum(1 for v in oz["birincil"].values() if v["anlamli_kazanc"])
        oz["anlamli_olcutler"] = [a for a, v in oz["birincil"].items() if v["anlamli_kazanc"]]
        sure_ciftleri = ozet.esle((sure_tabani or once)["fonksiyonlar"], sonra["fonksiyonlar"], rol)
        oz["tanimlayici"] = ozet.tanimlayici(ciftler)
        oz["sure_ayni_surec"] = ozet.tanimlayici(sure_ciftleri)
        out[rol] = oz
    return out


def ayni_metin(k1: str, k2: str) -> dict:
    a, b = ortak.CIKTILAR / k1, ortak.CIKTILAR / k2
    adlar = sorted(p.name for p in a.glob("*.c"))
    farkli = [n for n in adlar if not (b / n).exists() or (a / n).read_text() != (b / n).read_text()]
    return {"dosya": len(adlar), "farkli": farkli}


def main() -> None:
    C0, C2, C3 = yukle("C0"), yukle("C2"), yukle("C3")
    K = {k: yukle(k) for k in ("K0", "K1", "K1y", "K2", "K3_C0", "K3_C3")
         if (ortak.VERI / f"olcum_{k}.json").exists()}
    sonuc: dict = {
        "kunye": ortak.kunye(),
        "onkayit_ek_sha256": ortak.sha256(ortak.BELGE / "onkayit_ek.md"),
        "olcut_sha256": ortak.sha256(ortak.BELGE / "olcut.py"),
        "ozet_sha256": ortak.sha256(ortak.BELGE / "ozet.py"),
        "belirlenimcilik_K0_C0": ayni_metin("C0", "K0") if "K0" in K else None,
        "koşullar": {k: {"uygulama": {a: v["uygulama"].get(a) for a in
                                      ("kosul", "ad_yazilan", "prototip_uygulanan", "uygulama_sn",
                                       "void_eslenen_parametre", "programdaki_bilesik_tip_sayisi_tmux",
                                       "yapi_baglanan", "tip_denetimi", "yapi")},
                         "decompile_basarisiz": [x["adres"] for x in v["fonksiyonlar"] if x["olcut"] is None],
                         "belirlenimci_degil": [x["adres"] for x in v["fonksiyonlar"] if x.get("belirlenimci") is False],
                         "olcum_toplam_sn": v["olcum_toplam_sn"]}
                     for k, v in K.items()},
        "karsilastirmalar": {},
    }
    taban_sure = K.get("K0")
    if "K1" in K:
        sonuc["karsilastirmalar"]["K1-C0"] = karsilastir(C0, K["K1"], taban_sure)
    if "K1y" in K:
        sonuc["karsilastirmalar"]["K1y-C0"] = karsilastir(C0, K["K1y"], taban_sure)
    if "K2" in K:
        sonuc["karsilastirmalar"]["K2-C0"] = karsilastir(C0, K["K2"], taban_sure)
        sonuc["karsilastirmalar"]["K2-C2"] = karsilastir(C2, K["K2"])
    if "K3_C3" in K and "K3_C0" in K:
        sonuc["karsilastirmalar"]["K3_C3-K3_C0"] = karsilastir(K["K3_C0"], K["K3_C3"])

    # Tavan payı (havuz oranı): (K1 - C0) / (C3 - C0)
    c3 = karsilastir(C0, C3)
    if "K1-C0" in sonuc["karsilastirmalar"]:
        pay = {}
        for rol in ("hedef", "cagiran"):
            pay[rol] = {}
            for a, _, _ in ozet.BIRINCIL:
                k1 = sonuc["karsilastirmalar"]["K1-C0"][rol]["birincil"][a]
                t = c3[rol]["birincil"][a]
                payda = t["havuz_sonra"] - t["havuz_once"]
                pay[rol][a] = (k1["havuz_sonra"] - k1["havuz_once"]) / payda if payda else None
        sonuc["tavan_payi_K1"] = pay

    # Karar okuması (onkayit_ek §3)
    okuma = {}
    if "K1-C0" in sonuc["karsilastirmalar"]:
        n = sonuc["karsilastirmalar"]["K1-C0"]["hedef"]["anlamli_kazanc_sayisi"]
        okuma["K1"] = {"anlamli": n, "okuma": "bugünkü bilgiyle kazanç var; G14-G15 öne alınabilir" if n >= 2
                       else "kazanç bugün erişilebilir değil; önce tip/yapı kurtarma; geri yazma öne alınmaz"}
    dog = json.loads((ortak.VERI / "k1_yerlesim_dogrulugu.json").read_text())
    if "K1y-C0" in sonuc["karsilastirmalar"]:
        n = sonuc["karsilastirmalar"]["K1y-C0"]["hedef"]["anlamli_kazanc_sayisi"]
        b = dog["bagli_toplam"]
        toplam = sum(b.values())
        oran = b["dogru"] / toplam if toplam else None
        okuma["K1y"] = {"anlamli": n, "alan_dogrulugu": oran,
                        "okuma": "sözdizimsel ölçütler yanlış yerleşimi ödüllendiriyor; kapıya alan doğruluğu eklenmeli"
                        if (n >= 1 and oran is not None and oran < 0.5) else
                        "ön kayıtlı uyarı koşulu (anlamlı kazanç ve alan doğruluğu < %50) oluşmadı"}
    if "K2-C0" in sonuc["karsilastirmalar"]:
        v = sonuc["karsilastirmalar"]["K2-C0"]["hedef"]["birincil"]["tip_donusumu_100"]
        okuma["K2"] = {"C_havuz_C0": v["havuz_once"], "C_havuz_K2": v["havuz_sonra"],
                       "okuma": "C2'deki artış opak yapı işaretçisinden; kural: yerleşimi bilinmeyen yapıya void *"
                       if v["havuz_sonra"] <= v["havuz_once"] else "artışın kaynağı başka; kural yeniden düşünülür"}
    if "K3_C3-K3_C0" in sonuc["karsilastirmalar"]:
        n = sonuc["karsilastirmalar"]["K3_C3-K3_C0"]["hedef"]["anlamli_kazanc_sayisi"]
        okuma["K3"] = {"anlamli": n, "okuma": "tek yapı bulgusu client'ta tekrarlandı" if n >= 2
                       else "bulgu window_pane'e özgü olabilir; genellenmez"}
    sonuc["karar_okumasi"] = okuma

    # Karadul kapsamı, ayrıştırma ve yerleşim doğruluğu, K3 yerleşim doğrulaması
    k1 = json.loads((ortak.VERI / "k1_karadul.json").read_text())
    sonuc["karadul_kapsami"] = {"kapsam": k1["kapsam"], "bag_uretimi": k1["bag_uretimi"],
                                "hedefler": [{k: h[k] for k in ("adres", "gt_ad", "karadul_ad", "karadul_ad_kaynagi",
                                                                "merged_ilk_parametre", "bagli_yapi")}
                                             | {"karadul_imza": (h["karadul_imza"] or {}).get("metin"),
                                                "c0_imza": (h["c0_imza"] or {}).get("metin")}
                                             for h in k1["hedefler"]]}
    if (ortak.VERI / "k1_ayristirma.json").exists():
        sonuc["k1_ayristirma"] = json.loads((ortak.VERI / "k1_ayristirma.json").read_text())
    sonuc["karadul_yerlesim_dogrulugu"] = {"gercek": dog["gercek"], "bagli_toplam": dog["bagli_toplam"],
                                           "kaynak_listesindeki_toplam": dog["kaynak_listesindeki_toplam"],
                                           "yapilar": {a: {k: v.get(k) for k in ("bagli", "boyut", "kaynaklar", "sayilar")}
                                                       for a, v in dog["yapilar"].items()}}
    k3y = json.loads((ortak.BELGE / "k3_yerlesim_dogrulama.json").read_text())
    k3s = json.loads((ortak.VERI / "k3_secim.json").read_text())
    sonuc["k3"] = {"secim": {"aday_sayisi": k3s["aday_sayisi"], "elenen": k3s["elenenler"],
                             "hedefler": [{k: h[k] for k in ("sira", "adres", "ad", "dosya", "prototip_metni")}
                                          for h in k3s["hedefler"]],
                             "cagiran_sayisi": len(k3s["cagiranlar"])},
                   "yerlesim": {"client_boyut": k3y["client"]["boyut"], "alan": len(k3y["client"]["bilesenler"]),
                                "kapanis": {k: k3y["kapanis"][k] for k in ("yapi_sayisi", "ozet", "bit_alanli_yapilar")},
                                "sizeof_kaniti": k3y["ikili_sizeof_kaniti"],
                                "ofset_jaccard": {x["ad"]: x.get("jaccard") for x in k3y["hedef_ofset_karsilastirmasi"]}}}

    # Fonksiyon başına önce/sonra ham sayılar
    def tablo(secim: dict, kosullar: dict) -> list:
        sat = []
        for rol, adr, ad in ([("hedef", h["adres"], h["ad"]) for h in secim["hedefler"]] +
                             [("cagiran", c["adres"], None) for c in secim["cagiranlar"]]):
            s = {"rol": rol, "adres": adr, "gt_ad": ad, "kosullar": {}}
            for k, v in kosullar.items():
                x = next(f for f in v["fonksiyonlar"] if f["adres"] == adr)
                o = x["olcut"]
                s["kosullar"][k] = {"ghidra_adi": x["ghidra_adi"], "sure_ort_sn": x["sure_ort_sn"],
                                    "belirlenimci": x.get("belirlenimci"),
                                    "sayilar": None if o is None else {a: o[a] for a in ozet.HAM}}
            sat.append(s)
        return sat

    secim = json.loads((ortak.VERI / "secim.json").read_text())
    sonuc["fonksiyonlar_window_pane"] = tablo(secim, {k: v for k, v in
                                                      {"C0": C0, "C2": C2, "C3": C3, **{k: K[k] for k in
                                                       ("K1", "K1y", "K2") if k in K}}.items()})
    if "K3_C0" in K:
        sonuc["fonksiyonlar_client"] = tablo(k3s, {k: K[k] for k in ("K3_C0", "K3_C3") if k in K})
    ortak.json_yaz(ortak.BELGE / "sonuc_ek.json", sonuc)

    for kar, roller in sonuc["karsilastirmalar"].items():
        for rol, oz in roller.items():
            print(f"\n## {kar} — {rol} (n={oz['birincil']['undefined_100']['n']}), anlamlı: "
                  f"{oz['anlamli_kazanc_sayisi']}/5 {oz['anlamli_olcutler']}")
            for grup in ("birincil", "ikincil"):
                for a, v in oz[grup].items():
                    g = v["havuz_goreli_degisim"]
                    gs = g if isinstance(g, str) else f"{100 * g:+.0f}%"
                    print(f"  {ozet.ADLAR[a]:34s} {v['havuz_once']:6.1f} -> {v['havuz_sonra']:6.1f} ({gs:>7s}) "
                          f"fark {v['ort_fark']:+6.1f} [{v['ga95'][0]:+.1f}, {v['ga95'][1]:+.1f}] "
                          f"{v['iyilesen']}/{v['kotulesen']}/{v['degismeyen']} {v.get('anlamli_kazanc', '-')}")
            t = oz["sure_ayni_surec"]
            print(f"  satır {oz['tanimlayici']['satir_toplam']}; süre (aynı süreç) toplam {t['sure_toplam_sn']}")
    print("\ntavan payı K1:", sonuc.get("tavan_payi_K1"))
    print("karar okuması:", json.dumps(okuma, ensure_ascii=False, indent=1))
    print("belirlenimcilik K0=C0:", sonuc["belirlenimcilik_K0_C0"])


if __name__ == "__main__":
    main()
