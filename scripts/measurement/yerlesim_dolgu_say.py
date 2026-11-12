#!/usr/bin/env python3
"""Yerleşim: fonksiyonlar arası dolgu dağılımının GT'SİZ sayımı (ölçüm değil, mekanizma denetimi).

Soru: adres yerleşiminin dayandığı sinyal (ardışık iki fonksiyon arasında eşik ile hizalama arasında
kalan dolgu) hangi ikilide var, hangisinde yok? Bu betik yalnız çalışma alanındaki Ghidra çıktısını
okur (``static/ghidra_functions.json``: adres, boyut, thunk; ``static/ghidra_combined_results.json``:
bellek blokları). Hata ayıklama bilgisi, kaynak dosya etiketi ya da ürünün modül ataması OKUNMAZ;
hiçbir uyum sayısı hesaplanmaz.

Tanımlar ürün kodundan içe aktarılır (tek tanım): dolgu ``c_project_builder.function_gaps``,
dilimleme ve sinyal ``c_project_builder.slice_by_padding``; eşik ve hizalama
``karadul/config.py`` → ``BinaryReconstructionConfig.address_placement_*``.

- Dolgu: aynı bellek bloğundaki ardışık iki fonksiyon arasında, bir öncekinin bitişinden sonrakinin
  başına kadarki bayt; yalnız yürütülebilir blokta ölçülür.
- Kutular: negatif (gövdeler örtüşüyor), 0, 1 … eşik−1, eşik … hizalama−1 (sinyal bandı), ≥ hizalama.
- "Sinyal yok": sinyal bandında hiç dolgu yok (ürün bu ikilide eski yerleşime döner).
- Ana kod bloğu: thunk olmayan fonksiyonu en çok olan yürütülebilir blok (ELF ``.text``, Mach-O
  ``__text``). Toplam fonksiyon sayısı ölçü olmaz: PLT bloğunda ``.text``'ten çok fonksiyon olabilir.

Mekanizma denetimi (GT'siz; varsayım: derleyici fonksiyonu yalnız hizalama sınırına az baytla
ulaşabiliyorsa doldurur, bağlayıcı her girdi bölümünü hizalamaya tamamlar): ana kod bloğunda
(a) pozitif dolgudan sonra başlayan fonksiyonların adresi hizalamanın katı mı, (b) dolgular kaçın
katı, (c) fonksiyon başlangıçlarının hizalamaya göre kalan dağılımı, (d) "yasak kalanlı" başlangıç
sayısı: kalanı ``hizalama − eşik``'ten büyük olan başlangıç (varsayılan rejimde derleyici orada
durmaz, sınıra kadar doldururdu). (d) bir ARAÇ ZİNCİRİ göstergesidir; ürün kuralı DEĞİLDİR, yalnız
raporlanır.

Çıktıda fonksiyon adı yoktur: yalnız sayılar ve bellek bloğu adları.

Kullanım
--------
    python -m scripts.measurement.yerlesim_dolgu_say \\
        --kok debian13=~/karadul_olcum/runs/urun-yeni-93a2956 \\
        --kok eski=~/karadul_olcum/runs/aday-f893d72 \\
        --json docs/arge/2026-11-12_yerlesim/dolgu_sayimi.json \\
        --md docs/arge/2026-11-12_yerlesim/dolgu_sayimi.md
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)

from karadul.config import Config  # noqa: E402
from karadul.reconstruction import c_project_builder as cpb  # noqa: E402


def _ks1_yukle() -> ModuleType:
    """``ks1_olc.py``'yi dosya yolundan yükle: yalnız ortak sabitler için (GT okunmaz)."""
    spec = importlib.util.spec_from_file_location("ks1_olc", _BURASI / "ks1_olc.py")
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


ks1 = _ks1_yukle()

SEMA = "karadul-yerlesim-dolgu-sayimi/1"
CALISMA_ALANI_ISARETI = ("ws", "workspaces")     # <ikili>/ws/workspaces/<ad>/<zaman>/static
STATIC = "static"
KUTU_NEGATIF = "negatif"
KUTU_SIFIR = "0"
ONDALIK = ks1.ONDALIK


class StaticAlani:
    """Kurucunun okuyucularına verilen en küçük çalışma alanı: yalnız ``static`` dizini."""

    def __init__(self, static: Path) -> None:
        self._static = Path(static)

    def get_stage_dir(self, ad: str) -> Path:
        if ad != STATIC:
            raise KeyError(ad)
        return self._static


def ayarlar() -> tuple[int, int]:
    """(dolgu eşiği, hizalama): merkezi yapılandırmanın öntanımlı değerleri."""
    br = Config().binary_reconstruction
    return br.address_placement_padding_threshold, br.address_placement_alignment


def kutu_adlari(esik: int, hiza: int) -> tuple[str, ...]:
    return (KUTU_NEGATIF, KUTU_SIFIR, f"1-{esik - 1}", f"{esik}-{hiza - 1}", f">={hiza}")


def kutu(dolgu: int, esik: int, hiza: int) -> str:
    adlar = kutu_adlari(esik, hiza)
    if dolgu < 0:
        return adlar[0]
    if dolgu == 0:
        return adlar[1]
    if dolgu < esik:
        return adlar[2]
    return adlar[3] if dolgu < hiza else adlar[4]


def calisma_alanlari(kok: Path) -> dict[str, Path]:
    """Kökün altındaki çalışma alanları: anahtar (köke göre ikili yolu) → ``static`` dizini.

    Aynı ikilinin birden çok koşusu varsa zaman damgası en büyük olan alınır.
    """
    bulunan: dict[str, Path] = {}
    for yol in sorted(Path(kok).rglob(f"{STATIC}/ghidra_functions.json")):
        parcalar = yol.relative_to(kok).parts
        for i in range(len(parcalar) - 1):
            if parcalar[i:i + 2] == CALISMA_ALANI_ISARETI:
                bulunan["/".join(parcalar[:i])] = yol.parent     # sıralı dolaşım: sonuncu en yeni
                break
    return bulunan


def ikili_sayimi(static: Path, esik: int, hiza: int) -> dict[str, Any]:
    """Bir ikilinin dolgu sayımı (GT'siz)."""
    kurucu = cpb.CProjectBuilder(None)
    alan = StaticAlani(static)
    boyut = kurucu._load_function_sizes(alan)
    bloklar = kurucu._load_memory_blocks(alan)
    ham = json.loads((Path(static) / "ghidra_functions.json").read_text(encoding="utf-8"))
    thunk = {int(f["address"], 16) for f in ham.get("functions", []) if f.get("is_thunk")}
    bilgi = {}
    birlesik = Path(static) / "ghidra_combined_results.json"
    if birlesik.is_file():
        bilgi = json.loads(birlesik.read_text(encoding="utf-8")).get("program_info") or {}

    bosluklar = cpb.function_gaps(boyut, bloklar)
    duzen = cpb.slice_by_padding(boyut, bloklar, esik, hiza)
    blok_fonksiyon: Counter = Counter(g.block for g in bosluklar)
    blok_govde: Counter = Counter(g.block for g in bosluklar if g.address not in thunk)
    yurutulebilir = [i for i in blok_fonksiyon if i is not None and bloklar[i].executable]
    ana = max(yurutulebilir, key=lambda i: (blok_govde[i], -i)) if yurutulebilir else None

    kutular = {ad: 0 for ad in kutu_adlari(esik, hiza)}
    ana_kutular = dict(kutular)
    degerler: Counter = Counter()          # ana kod bloğunda dolgu değeri → sayı
    kalan: Counter = Counter()             # ana kod bloğunda başlangıç adresi mod hizalama
    pozitif = pozitif_hizali = 0
    for g in bosluklar:
        if g.block == ana:
            kalan[g.address % hiza] += 1
        if g.gap is None:
            continue
        kutular[kutu(g.gap, esik, hiza)] += 1
        if g.block != ana:
            continue
        ana_kutular[kutu(g.gap, esik, hiza)] += 1
        degerler[g.gap] += 1
        if g.gap > 0:
            pozitif += 1
            pozitif_hizali += int(g.address % hiza == 0)

    def blok_adi(i: Optional[int]) -> str:
        return "(blok yok)" if i is None else bloklar[i].name

    thunk_blok: Counter = Counter()
    for g in bosluklar:
        if g.address in thunk:
            tur = ("blok_yok" if g.block is None else
                   "ana_kod" if g.block == ana else
                   "yurutulebilir_diger" if bloklar[g.block].executable else "yurutulemez")
            thunk_blok[tur] += 1
    n_ana = blok_fonksiyon[ana] if ana is not None else len(bosluklar)
    return {
        "bicim": bilgi.get("executable_format"), "dil": bilgi.get("language"),
        "fonksiyon": len(boyut), "thunk": len(thunk & set(boyut)),
        "blok_bilgisi": bool(bloklar),
        "ana_kod_blogu": blok_adi(ana) if bloklar else None, "ana_kod_fonksiyon": n_ana,
        "blok_fonksiyon": {blok_adi(i): n for i, n in sorted(
            blok_fonksiyon.items(), key=lambda kv: (-1 if kv[0] is None else kv[0]))},
        "thunk_yeri": dict(sorted(thunk_blok.items())),
        "olculen_cift": duzen.measured_gaps, "kutular": kutular, "ana_kutular": ana_kutular,
        "ana_dolgu_degerleri": {str(k): v for k, v in sorted(degerler.items())},
        "ana_baslangic_kalani": {str(k): v for k, v in sorted(kalan.items())},
        "pozitif_dolgu": pozitif, "pozitif_dolgu_sonrasi_hizali": pozitif_hizali,
        "yasak_kalanli_baslangic": sum(v for k, v in kalan.items() if 0 < hiza - k < esik),
        "sinyal_dolgu": duzen.signal_gaps, "sinyal_var": duzen.has_padding_signal,
        "sinyal_yogunlugu": (round(duzen.signal_gaps / duzen.measured_gaps, ONDALIK)
                             if duzen.measured_gaps else None),
        "dolgu_siniri": duzen.padding_cuts, "blok_siniri": duzen.block_cuts,
        "dilim": len(duzen.slices),
    }


def grup_ozeti(ikililer: dict[str, dict[str, Any]], esik: int, hiza: int) -> dict[str, Any]:
    """Grup (anahtarın üst yolu) başına toplam: kutular toplanır; sinyalsiz ikililer listelenir."""
    gruplar: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for anahtar, s in sorted(ikililer.items()):
        ust, _, ad = anahtar.rpartition("/")
        gruplar.setdefault(ust or ad, []).append((anahtar, s))
    out: dict[str, Any] = {}
    for grup, uyeler in sorted(gruplar.items()):
        yogunluk = [s["sinyal_yogunlugu"] for _, s in uyeler if s["sinyal_yogunlugu"] is not None]
        out[grup] = {
            "ikili": len(uyeler),
            "bicim": sorted({str(s["bicim"]) for _, s in uyeler}),
            "ana_kod_blogu": sorted({str(s["ana_kod_blogu"]) for _, s in uyeler}),
            "fonksiyon": sum(s["fonksiyon"] for _, s in uyeler),
            "olculen_cift": sum(s["olculen_cift"] for _, s in uyeler),
            "kutular": {ad: sum(s["kutular"][ad] for _, s in uyeler) for ad in kutu_adlari(esik, hiza)},
            "sinyalsiz_ikili": sorted(a for a, s in uyeler if not s["sinyal_var"]),
            "sinyal_yogunlugu": ({"en_az": min(yogunluk), "ortanca": round(statistics.median(yogunluk), ONDALIK),
                                  "en_cok": max(yogunluk)} if yogunluk else None),
            "yasak_kalan_payi": {
                "en_az": min(round(s["yasak_kalanli_baslangic"] / s["ana_kod_fonksiyon"], ONDALIK)
                             for _, s in uyeler),
                "en_cok": max(round(s["yasak_kalanli_baslangic"] / s["ana_kod_fonksiyon"], ONDALIK)
                              for _, s in uyeler)},
            "pozitif_dolgu": sum(s["pozitif_dolgu"] for _, s in uyeler),
            "pozitif_dolgu_sonrasi_hizali": sum(s["pozitif_dolgu_sonrasi_hizali"] for _, s in uyeler),
            "thunk_yeri": dict(sorted(sum((Counter(s["thunk_yeri"]) for _, s in uyeler), Counter()).items())),
            "blok_bilgisi_olmayan": sum(1 for _, s in uyeler if not s["blok_bilgisi"]),
        }
    return out


def say(kokler: dict[str, Path]) -> dict[str, Any]:
    esik, hiza = ayarlar()
    ikililer: dict[str, dict[str, Any]] = {}
    for etiket, kok in kokler.items():
        for anahtar, static in calisma_alanlari(kok).items():
            ikililer[f"{etiket}/{anahtar}"] = ikili_sayimi(static, esik, hiza)
    return {"sema": SEMA, "uyari": "GT'siz sayım; uyum ölçüsü içermez",
            "esik": esik, "hizalama": hiza, "kutular": list(kutu_adlari(esik, hiza)),
            "kokler": {e: str(k) for e, k in kokler.items()},
            "gruplar": grup_ozeti(ikililer, esik, hiza), "ikililer": ikililer}


def _oran(k: int, n: int) -> str:
    return "—" if not n else f"{k / n:.3f}".replace(".", ",")


def markdown(s: dict[str, Any]) -> str:
    adlar = s["kutular"]
    satirlar = ["# Yerleşim: fonksiyonlar arası dolgu sayımı (GT'siz)", "",
                f"- Eşik {s['esik']} bayt, hizalama {s['hizalama']} bayt (`karadul/config.py`); sinyal bandı "
                f"`{adlar[3]}`.",
                "- Dolgu yalnız yürütülebilir bellek bloklarında, aynı bloktaki ardışık fonksiyonlar arasında "
                "ölçülür. Uyum ölçüsü ve ad içermez.",
                "- Kökler: " + "; ".join(f"`{e}` = `{k}`" for e, k in s["kokler"].items()) + ".", "",
                "| Grup | İkili | Biçim | Ana kod bloğu | Fonksiyon | Ölçülen çift | "
                + " | ".join(f"`{a}`" for a in adlar)
                + " | Sinyalsiz ikili | Sinyal yoğunluğu (en az / ortanca / en çok) | "
                  "Pozitif dolgudan sonra hizalı başlangıç | Yasak kalanlı başlangıç payı (en az / en çok) |",
                "|---|---|---|---|---|---|" + "---|" * len(adlar) + "---|---|---|---|"]
    for grup, g in s["gruplar"].items():
        y = g["sinyal_yogunlugu"]
        yogunluk = "—" if y is None else " / ".join(
            f"{y[a]:.4f}".replace(".", ",") for a in ("en_az", "ortanca", "en_cok"))
        satirlar.append(
            f"| {grup} | {g['ikili']} | {', '.join(g['bicim'])} | {', '.join(g['ana_kod_blogu'])} | "
            f"{g['fonksiyon']} | {g['olculen_cift']} | "
            + " | ".join(str(g["kutular"][a]) for a in adlar)
            + f" | {len(g['sinyalsiz_ikili'])} | {yogunluk} | "
            f"{g['pozitif_dolgu_sonrasi_hizali']} / {g['pozitif_dolgu']} "
            f"({_oran(g['pozitif_dolgu_sonrasi_hizali'], g['pozitif_dolgu'])}) | "
            + " / ".join(f"{g['yasak_kalan_payi'][a]:.4f}".replace(".", ",") for a in ("en_az", "en_cok"))
            + " |")
    sinyalsiz = [a for g in s["gruplar"].values() for a in g["sinyalsiz_ikili"]]
    satirlar += ["", f"Sinyal bandında hiç dolgusu olmayan ikili: {len(sinyalsiz)} / {len(s['ikililer'])}"
                 + (": " + ", ".join(f"`{a}`" for a in sinyalsiz) if sinyalsiz else "") + ".", "",
                 "## Thunk'ların yeri (blok türüne göre)", "",
                 "| Grup | Thunk: ana kod bloğunda | Thunk: başka yürütülebilir blokta | "
                 "Thunk: yürütülemez blokta | Blok bilgisi olmayan ikili |", "|---|---|---|---|---|"]
    for grup, g in s["gruplar"].items():
        t = g["thunk_yeri"]
        satirlar.append(f"| {grup} | {t.get('ana_kod', 0)} | {t.get('yurutulebilir_diger', 0)} | "
                        f"{t.get('yurutulemez', 0)} | {g['blok_bilgisi_olmayan']} |")
    satirlar += ["", "## İkili başına (sinyal bandı ve komşu kutular)", "",
                 "| İkili | Fonksiyon | Ölçülen çift | " + " | ".join(f"`{a}`" for a in adlar)
                 + " | Sinyal | Dilim |", "|---|---|---|" + "---|" * len(adlar) + "---|---|"]
    for anahtar, i in s["ikililer"].items():
        satirlar.append(f"| `{anahtar}` | {i['fonksiyon']} | {i['olculen_cift']} | "
                        + " | ".join(str(i["kutular"][a]) for a in adlar)
                        + f" | {'var' if i['sinyal_var'] else 'YOK'} | {i['dilim']} |")
    return "\n".join(satirlar) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kok", action="append", required=True, metavar="ETİKET=YOL",
                    help="çalışma alanlarının kökü (yinelenebilir); yalnız okunur")
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--md", type=Path, default=None)
    a = ap.parse_args(argv)
    kokler: dict[str, Path] = {}
    for girdi in a.kok:
        etiket, ayrac, yol = girdi.partition("=")
        if not ayrac or not etiket or not yol:
            ap.error(f"--kok ETİKET=YOL biçiminde olmalı: {girdi}")
        kok = Path(yol).expanduser()
        if not kok.is_dir():
            print(f"DURDU: {kok}: dizin yok", file=sys.stderr)
            return 2
        kokler[etiket] = kok
    sonuc = say(kokler)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(markdown(sonuc), encoding="utf-8")
    print(f"say: {len(sonuc['ikililer'])} ikili, {len(sonuc['gruplar'])} grup; "
          f"sinyalsiz {sum(len(g['sinyalsiz_ikili']) for g in sonuc['gruplar'].values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
