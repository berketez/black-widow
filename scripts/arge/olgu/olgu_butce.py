#!/usr/bin/env python3
"""OLGU kapsam bütçesi (liste A1): olgu tablosundan ``BUTCE.md`` ve ``butce.json``.

Yalnız sayılar yazılır; GT'den fonksiyon adı geçmez (dizin adları ve kanal adları geçer).
Oranlar ``ks1_olc.oran`` (Wilson %95). Çağrı: ``olgu_tablosu.py butce``.

Tanımlar (SEMA.md §7)
---------------------
- *İç fonksiyon*: thunk ve dış fonksiyon olmayan Ghidra fonksiyonu.
- *Nüfus*: ``nufusta`` (``ks1_olc.GtBirimi.nufus``; C++ ikili dışarıda).
- *Nüfusta doğru / yanlış*: ``urun_olcude`` ve ``nufusta`` satırlarda hüküm.
- *Ad verilen / doğru / yanlış (tümü)*: ``urun_olcude`` satırlar (nüfus dışındakiler dahil:
  CRT, klon, GT'de karşılıksız) — taban ölçümünün havuz tanımı.
- *Nüfusta adsız*: nüfusta olup ölçüye giren adı olmayan.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import olgu_tablosu as ot

SINIF_SIRASI = ot.KAYNAK_SINIFLARI
DILIM_SIRASI = tuple(ad for _, ad in ot.BOYUT_DILIMLERI) + (ot.BOYUT_EN_BUYUK,)
ALT_SINIF_EN_COK = 20


def _bos() -> Counter:
    return Counter()


def say_(satirlar: Iterable[dict[str, Any]], anahtar: Callable[[dict[str, Any]], Any],
         dogru_degeri: str) -> dict[Any, Counter]:
    """Anahtar başına sayaçlar: fonksiyon (iç), nüfus, nüfusta ad/doğru/yanlış, tümünde ad/doğru/yanlış."""
    out: dict[Any, Counter] = defaultdict(_bos)
    for s in satirlar:
        k = anahtar(s)
        c = out[k]
        ic = not (s["thunk"] or s["dis"])
        c["satir"] += 1
        c["ic"] += int(ic)
        olcude = s["urun_olcude"]
        dogru = olcude and s["hukum"] == dogru_degeri
        if olcude:
            c["ad"] += 1
            c["dogru"] += int(dogru)
            c["yanlis"] += int(not dogru)
        if s["nufusta"]:
            c["nufus"] += 1
            if olcude:
                c["nufus_ad"] += 1
                c["nufus_dogru"] += int(dogru)
                c["nufus_yanlis"] += int(not dogru)
            else:
                c["nufus_adsiz"] += 1
    return out


def _yuzde(k: int, n: int) -> str:
    return "—" if not n else f"%{100 * k / n:.1f}".replace(".", ",")


def _aralik(oran: Callable[[int, int], dict[str, Any]], k: int, n: int) -> str:
    if not n:
        return "—"
    o = oran(k, n)
    a, b = o["aralik"]
    return f"%{100 * o['oran']:.1f} (%{100 * a:.1f}–%{100 * b:.1f})".replace(".", ",")


def _sayi(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def _sirala(anahtarlar: Iterable[Any], sira: tuple[str, ...]) -> list[Any]:
    return sorted(anahtarlar, key=lambda k: (sira.index(k) if k in sira else len(sira), str(k)))


def butce(satirlar: list[dict[str, Any]], oran: Callable[[int, int], dict[str, Any]], dogru_degeri: str
          ) -> dict[str, Any]:
    """Bütün kırılımların sayıları (JSON'a gider; Markdown bundan yazılır)."""
    tam = all("yaprak" in s for s in satirlar)

    def say(kume: Iterable[dict[str, Any]], anahtar: Callable[[dict[str, Any]], Any]) -> dict[Any, Counter]:
        return say_(kume, anahtar, dogru_degeri)

    kir: dict[str, dict[Any, Counter]] = {
        "toplam": say(satirlar, lambda s: "toplam"),
        "sinif": say(satirlar, lambda s: s["kaynak_sinifi"]),
        "sinif_kanit": say(satirlar, lambda s: (s["kaynak_sinifi"], s["kaynak_kaniti"])),
        "birim_sinif": say(satirlar, lambda s: (s["birim"], s["kaynak_sinifi"])),
        "birim": say(satirlar, lambda s: s["birim"]),
        "boyut": say(satirlar, lambda s: s["boyut_dilimi"]),
        "sinif_boyut": say(satirlar, lambda s: (s["kaynak_sinifi"], s["boyut_dilimi"])),
        "alt_sinif": say((s for s in satirlar if s["nufusta"]),
                         lambda s: (s["birim"], s["kaynak_sinifi"], s["kaynak_alt_sinifi"])),
        "harici": say((s for s in satirlar if s["nufusta"]), lambda s: (s["kaynak_sinifi"], s["dw_harici"])),
        "sinif_kanal": say((s for s in satirlar if s["urun_olcude"]),
                           lambda s: (s["kaynak_sinifi"], s["kanal"])),
    }
    # Tekil kaynak fonksiyonu: aynı programda aynı tanım dosyası + aynı GT adı tek fonksiyondur
    # (106 coreutils ikilisindeki gnulib kopyaları, redis-tools'un 4 ikilisindeki ortak kod).
    tekil: dict[str, dict[tuple, list[bool]]] = defaultdict(dict)
    for s in satirlar:
        if not s["nufusta"]:
            continue
        anahtar = (s["program"], s["dw_tanim_dosyasi"] or s["dw_birim_yolu"], (s["gt_adlari"] or [None])[0])
        tekil[s["kaynak_sinifi"]].setdefault(anahtar, []).append(s["urun_olcude"] and s["hukum"] == dogru_degeri)
    kir["tekil"] = {k: Counter({"ornek": sum(len(v) for v in d.values()), "tekil": len(d),
                                "tekil_hep_dogru": sum(1 for v in d.values() if all(v)),
                                "tekil_en_az_bir_dogru": sum(1 for v in d.values() if any(v))})
                    for k, d in tekil.items()}
    if tam:
        kir["yaprak"] = say(satirlar, lambda s: (s["kaynak_sinifi"], s["yaprak"]))
        kir["dizgi"] = say(satirlar, lambda s: (s["kaynak_sinifi"], bool(s["dizgi_sayisi"])))
        kir["kayit"] = say(satirlar, lambda s: (s["kaynak_sinifi"], s["kayit_cifti_var"]))
        kir["veri_yeri"] = say(satirlar, lambda s: (s["kaynak_sinifi"], bool(s["veri_yeri_sayisi"])))
        kir["cagri_dizgi"] = say(satirlar, lambda s: (s["kaynak_sinifi"], bool(s["cagri_dizgileri"])))
    return {"tam": tam, "kirilimlar": {ad: {json.dumps(k, ensure_ascii=False): dict(v) for k, v in d.items()}
                                       for ad, d in kir.items()},
            "_ham": kir}


# --------------------------------------------------------------------------------------------
# Markdown


def _ana_tablo(kir: dict[Any, Counter], anahtarlar: list[Any], ad: Callable[[Any], str],
               oran: Callable[[int, int], dict[str, Any]], toplam: Optional[Counter] = None,
               ilk: str = "Sınıf") -> list[str]:
    sat = ["| " + " | ".join([ilk, "Satır", "İç fonksiyon", "Nüfus", "Nüfus payı", "Nüfusta ad", "Nüfusta doğru",
                              "Nüfusta yanlış", "Nüfusta adsız", "Doğru ad kapsamı (%95)", "Ad (tümü)",
                              "Doğru (tümü)", "Yanlış (tümü)"]) + " |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    T = toplam["nufus"] if toplam else 0
    for k in anahtarlar:
        c = kir[k]
        sat.append(f"| {ad(k)} | {_sayi(c['satir'])} | {_sayi(c['ic'])} | {_sayi(c['nufus'])} | {_yuzde(c['nufus'], T)} | "
                   f"{_sayi(c['nufus_ad'])} | {_sayi(c['nufus_dogru'])} | {_sayi(c['nufus_yanlis'])} | "
                   f"{_sayi(c['nufus_adsiz'])} | {_aralik(oran, c['nufus_dogru'], c['nufus'])} | {_sayi(c['ad'])} | "
                   f"{_sayi(c['dogru'])} | {_sayi(c['yanlis'])} |")
    if toplam is not None:
        c = toplam
        sat.append(f"| **Toplam** | {_sayi(c['satir'])} | {_sayi(c['ic'])} | {_sayi(c['nufus'])} | %100 | {_sayi(c['nufus_ad'])} | "
                   f"{_sayi(c['nufus_dogru'])} | {_sayi(c['nufus_yanlis'])} | {_sayi(c['nufus_adsiz'])} | "
                   f"{_aralik(oran, c['nufus_dogru'], c['nufus'])} | {_sayi(c['ad'])} | {_sayi(c['dogru'])} | "
                   f"{_sayi(c['yanlis'])} |")
    return sat


def _ikili_tablo(kir: dict[Any, Counter], siniflar: list[str], degerler: list[Any], baslik: str,
                 deger_adi: Callable[[Any], str], oran: Callable[[int, int], dict[str, Any]]) -> list[str]:
    """Sınıf × ikili özellik: nüfus, nüfusta doğru, nüfusta adsız, doğru kapsamı."""
    sat = [f"| Sınıf | {baslik} | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |",
           "|---|---|---|---|---|---|---|"]
    topl: dict[Any, Counter] = defaultdict(_bos)
    for s in siniflar:
        for d in degerler:
            c = kir.get((s, d))
            if not c or not c["nufus"]:
                continue
            topl[d].update(c)
            sat.append(f"| {s} | {deger_adi(d)} | {_sayi(c['nufus'])} | {_sayi(c['nufus_dogru'])} | "
                       f"{_sayi(c['nufus_yanlis'])} | {_sayi(c['nufus_adsiz'])} | "
                       f"{_aralik(oran, c['nufus_dogru'], c['nufus'])} |")
    for d in degerler:
        c = topl[d]
        if c["nufus"]:
            sat.append(f"| **Toplam** | {deger_adi(d)} | {_sayi(c['nufus'])} | {_sayi(c['nufus_dogru'])} | "
                       f"{_sayi(c['nufus_yanlis'])} | {_sayi(c['nufus_adsiz'])} | "
                       f"{_aralik(oran, c['nufus_dogru'], c['nufus'])} |")
    return sat


def markdown(b: dict[str, Any], kunye: dict[str, Any], oran: Callable[[int, int], dict[str, Any]]) -> str:
    kir = b["_ham"]
    toplam = kir["toplam"]["toplam"]
    siniflar = _sirala(kir["sinif"], SINIF_SIRASI)
    sat = ["# Kapsam bütçesi (A1) — taban a62f15e, 119 ikili", "",
           "- Kaynak: olgu tablosu `" + kunye["tablo"] + "` (sha256 `" + kunye["tablo_sha256"][:16] + "…`, "
           f"{_sayi(kunye['satir'])} satır).",
           "- Üreten: `scripts/arge/olgu/olgu_tablosu.py butce` (bu belgedeki her sayı bu komutun çıktısı); "
           "tablo `olgu_tablosu.py uret` ile. Alanlar `SEMA.md`'de.",
           f"- Tutarlılık kapısı: **{kunye.get('kapi', 'koşulmadı')}** (`olgu_tablosu.py dogrula`; nüfus 21 371, "
           "ad verilen 1 800, doğru 1 681, yanlış 119, nüfusta doğru 1 212, birim başına sayılar ve öğe düzeyi "
           "hükümler taban ölçümüyle birebir).",
           "- Bu belgede GT'den fonksiyon adı geçmez; yalnız sayılar, sınıf, dizin ve kanal adları.",
           "- Oranların aralığı Wilson %95 (`ks1_olc.oran`). Geliştirme seti içi sayım; genelleme iddiası değil.", "",
           "## 1. Kaynak sınıfı başına (ana tablo)", "",
           "Sınıf tanımları `SEMA.md` §4. *Nüfus*: ad bekleyen fonksiyonlar (Ghidra'nın jenerik bıraktığı, GT'de "
           "adı olan, CRT / dışa aktarılan / klon olmayan; C++ ikili dışarıda). *Nüfusta adsız*: nüfusta olup "
           "ölçüye giren adı olmayan. *Tümü* sütunları taban ölçümünün havuzudur (nüfus dışındaki adlar dahil).", ""]
    sat += _ana_tablo(kir["sinif"], siniflar, lambda k: f"`{k}`", oran, toplam)
    sat += ["", "Tekil kaynak fonksiyonu (nüfus): aynı programda aynı tanım dosyası ve aynı GT adı bir sayılır "
            "(coreutils'in 106 ikilisindeki gnulib kopyaları, redis-tools'un 4 ikilisindeki ortak kod tek sayılır). "
            "Mac'te tanım dosyası yok: anahtar program + GT adı.", "",
            "| Sınıf | Nüfus (örnek) | Tekil | Örnek / tekil | Tekilde her örneği doğru | Tekilde en az bir örneği doğru |",
            "|---|---|---|---|---|---|"]
    for k in [x for x in siniflar if x in kir["tekil"]]:
        c = kir["tekil"][k]
        sat.append(f"| `{k}` | {_sayi(c['ornek'])} | {_sayi(c['tekil'])} | "
                   f"{c['ornek'] / c['tekil']:.2f} | {_sayi(c['tekil_hep_dogru'])} | {_sayi(c['tekil_en_az_bir_dogru'])} |"
                   .replace(".", ",", 1) if c["tekil"] else f"| `{k}` | 0 | 0 | — | 0 | 0 |")
    ct = Counter()
    for c in kir["tekil"].values():
        ct.update(c)
    sat.append(f"| **Toplam** | {_sayi(ct['ornek'])} | {_sayi(ct['tekil'])} | {ct['ornek'] / ct['tekil']:.2f} | "
               f"{_sayi(ct['tekil_hep_dogru'])} | {_sayi(ct['tekil_en_az_bir_dogru'])} |".replace(".", ",", 1))
    sat += ["", "## 2. Sınıf × kanıt (sınıfın hangi olgudan geldiği)", "",
            "| Sınıf | Kanıt | İç fonksiyon | Nüfus | Nüfusta doğru |", "|---|---|---|---|---|"]
    for (s, kn) in sorted(kir["sinif_kanit"], key=lambda t: (SINIF_SIRASI.index(t[0]) if t[0] in SINIF_SIRASI
                                                              else 99, str(t[1]))):
        c = kir["sinif_kanit"][(s, kn)]
        sat.append(f"| `{s}` | `{kn}` | {_sayi(c['ic'])} | {_sayi(c['nufus'])} | {_sayi(c['nufus_dogru'])} |")
    sat += ["", "## 3. Sınıf × kanal (ölçüye giren adlar)", "",
            "| Sınıf | Kanal | Ad (tümü) | Doğru | Yanlış | Nüfusta ad | Nüfusta doğru |", "|---|---|---|---|---|---|---|"]
    for (s, kn) in sorted(kir["sinif_kanal"], key=lambda t: (SINIF_SIRASI.index(t[0]) if t[0] in SINIF_SIRASI
                                                              else 99, -kir["sinif_kanal"][t]["ad"], str(t[1]))):
        c = kir["sinif_kanal"][(s, kn)]
        sat.append(f"| `{s}` | `{kn}` | {_sayi(c['ad'])} | {_sayi(c['dogru'])} | {_sayi(c['yanlis'])} | "
                   f"{_sayi(c['nufus_ad'])} | {_sayi(c['nufus_dogru'])} |")
    sat += ["", "## 4. Birim × sınıf (nüfus / nüfusta doğru)", ""]
    birimler = sorted(kir["birim"])
    sat.append("| Birim | " + " | ".join(f"`{s}`" for s in siniflar) + " | Toplam |")
    sat.append("|---|" + "---|" * (len(siniflar) + 1))
    for bm in birimler:
        hucre = []
        for s in siniflar:
            c = kir["birim_sinif"].get((bm, s))
            hucre.append("—" if not c or not c["nufus"] else f"{_sayi(c['nufus'])} / {_sayi(c['nufus_dogru'])}")
        c = kir["birim"][bm]
        sat.append(f"| {bm} | " + " | ".join(hucre) + f" | {_sayi(c['nufus'])} / {_sayi(c['nufus_dogru'])} |")
    sat += ["", "Birim satırları (bütün sütunlar):", ""]
    sat += _ana_tablo(kir["birim"], birimler, lambda k: k, oran, toplam, ilk="Birim")
    sat += ["", "## 5. Boyut dilimi (Ghidra gövde baytı)", ""]
    sat += _ana_tablo(kir["boyut"], [d for d in DILIM_SIRASI if d in kir["boyut"]], lambda k: f"`{k}`", oran, toplam,
                      ilk="Boyut (bayt)")
    sat += ["", "Sınıf × boyut (nüfus / nüfusta doğru):", "",
            "| Sınıf | " + " | ".join(f"`{d}`" for d in DILIM_SIRASI) + " |", "|---|" + "---|" * len(DILIM_SIRASI)]
    for s in siniflar:
        hucre = []
        for d in DILIM_SIRASI:
            c = kir["sinif_boyut"].get((s, d))
            hucre.append("—" if not c or not c["nufus"] else f"{_sayi(c['nufus'])} / {_sayi(c['nufus_dogru'])}")
        if any(h != "—" for h in hucre):
            sat.append(f"| `{s}` | " + " | ".join(hucre) + " |")
    sat += ["", f"## 6. Alt sınıf (dizin) başına nüfus — en büyük {ALT_SINIF_EN_COK}", "",
            "| Birim | Sınıf | Dizin | Nüfus | Nüfusta doğru | Nüfusta adsız |", "|---|---|---|---|---|---|"]
    alt = sorted(kir["alt_sinif"].items(), key=lambda t: (-t[1]["nufus"], str(t[0])))
    for (bm, s, d), c in alt[:ALT_SINIF_EN_COK]:
        sat.append(f"| {bm} | `{s}` | {'—' if d is None else f'`{d}`'} | {_sayi(c['nufus'])} | {_sayi(c['nufus_dogru'])} | "
                   f"{_sayi(c['nufus_adsiz'])} |")
    sat.append(f"| (kalan {len(alt) - ALT_SINIF_EN_COK} dizin) | | | "
               f"{_sayi(sum(c['nufus'] for _, c in alt[ALT_SINIF_EN_COK:]))} | "
               f"{_sayi(sum(c['nufus_dogru'] for _, c in alt[ALT_SINIF_EN_COK:]))} | "
               f"{_sayi(sum(c['nufus_adsiz'] for _, c in alt[ALT_SINIF_EN_COK:]))} |")
    sat += ["", "## 7. Nüfusta `DW_AT_external` (dışa açık bildirim) × sınıf", "",
            "| Sınıf | `DW_AT_external` | Nüfus | Nüfusta doğru |", "|---|---|---|---|"]
    for (s, h) in sorted(kir["harici"], key=lambda t: (SINIF_SIRASI.index(t[0]) if t[0] in SINIF_SIRASI else 99,
                                                        str(t[1]))):
        c = kir["harici"][(s, h)]
        sat.append(f"| `{s}` | {'—' if h is None else ('evet' if h else 'hayır')} | {_sayi(c['nufus'])} | "
                   f"{_sayi(c['nufus_dogru'])} |")
    if b["tam"]:
        evet_hayir = lambda d: "var" if d else "yok"   # noqa: E731
        for no, (anahtar, baslik, aciklama) in enumerate((
                ("yaprak", "Yaprak", "çağrı grafiğinde çağırdığı fonksiyon yok ve P-code'da `CALLIND` yok"),
                ("dizgi", "Doğrudan dizgi", "Ghidra'nın bu fonksiyona bağladığı en az bir dizgi"),
                ("veri_yeri", "Veri yeri", "adresi bir veri yuvasında duruyor (yeniden konumlandırma / fixup)"),
                ("kayit", "Kayıt çifti", "veri yuvasının ± 4 komşusunda en az bir dizgi işaretçisi"),
                ("cagri_dizgi", "Çağrı dizgisi", "kendi içindeki bir `CALL`'a dizgi sabiti geçiyor (P-code)"),
        ), start=8):
            degerler = [True, False]
            ad = (lambda d: "evet" if d else "hayır") if anahtar == "yaprak" else evet_hayir
            sat += ["", f"## {no}. {baslik} var / yok × sınıf", "", f"{baslik}: {aciklama}.", ""]
            sat += _ikili_tablo(kir[anahtar], siniflar, degerler, baslik, ad, oran)
    else:
        sat += ["", "## 8–12. Yaprak, doğrudan dizgi, veri yeri, kayıt çifti, çağrı dizgisi", "",
                "Kanıt ve kayıt çifti alanları tablonun bu sürümünde yok (çekirdek aşama); ikinci teslimde eklenir."]
    return "\n".join(sat) + "\n"


def main_butce(a: Any, m: Any) -> int:
    satirlar = list(ot.tablo_oku(a.tablo))
    kunye_yolu = a.tablo.with_name(a.tablo.name.replace(".jsonl.gz", "") + "_kunye.json")
    kunye = json.loads(kunye_yolu.read_text(encoding="utf-8"))
    dogrulama = a.tablo.with_name("dogrulama.json")
    if dogrulama.is_file():
        d = json.loads(dogrulama.read_text(encoding="utf-8"))
        kapi_tutar = d["tuttu"] and d["tablo_sha256"] == kunye["tablo_sha256"]
        kunye["kapi"] = "tuttu" if kapi_tutar else "tutmadı ya da başka tablo"
    b = butce(satirlar, m.ks1.oran, m.uo.DOGRU)
    metin = markdown(b, kunye, m.ks1.oran)
    a.md.parent.mkdir(parents=True, exist_ok=True)
    a.md.write_text(metin, encoding="utf-8")
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps({"tablo": str(a.tablo), "tablo_sha256": kunye["tablo_sha256"], "tam": b["tam"],
                                  "kirilimlar": b["kirilimlar"]}, ensure_ascii=False, indent=1) + "\n",
                      encoding="utf-8")
    print(f"butce: {a.md} ve {a.json}")
    return 0
