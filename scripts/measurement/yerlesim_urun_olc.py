#!/usr/bin/env python3
"""Yerleşim: yeni ürün işlevinin GELİŞTİRME SETİNDE yeniden üretimi (ön kayıtsız; ürün iddiası değil).

Ne yapar
--------
Saklı çalışma alanlarında (ölçülen koşu; salt okunur) proje kurucuyu (``CProjectBuilder``) gerçek
girdisiyle yeniden çalıştırır; çıktı geçici dizine yazılır:

1. **Bayrak kapalı:** yeniden kurulan proje ağacı, saklı ağaçla (``reconstructed/project``) bayt bayt
   karşılaştırılır. Aynı çıkması iki şeyi gösterir: (a) kurucunun girdisi doğru bulundu, (b) bayrak
   kapalıyken bugünkü kod, ölçülen sürümün çıktısını değiştirmeden üretiyor.
   ``compile_commands.json`` proje kökünün mutlak yolunu içerir; karşılaştırmadan önce yalnız o yol
   saklı köke çevrilir. ``analysis/algorithms.md`` karşılaştırmaya girmez: kurucuya verilen algoritma
   sonucunun ``detection_method`` alanı çalışma alanında saklı değildir.
2. **Bayrak açık** (``enable_address_placement``): ağaç, ön kayıtlı ölçümün okuyucusuyla
   (``harita_olc.urun_oku``) okunur ve aynı ölçüyle (``harita_olc.olculer``; ARI) değerlendirilir.

Nüfus ve GT sınıf kodları ön kayıtlı ölçümün çıktısından (``harita_olcumu.json`` → ``ogeler``) alınır;
GT yeniden okunmaz, ad içermez. Toplama kuralı ``harita_olc.makro`` (ikili → birim → program → makro).

Satırlar
--------
- ``urun_eski``, ``b1``: ön kayıtlı ölçümün tanımları (sağlama: ölçümdeki makrolarla aynı olmalı).
- ``kesif_s2``: keşif betiğinin ``s2_dolgu16`` satırı (``yerlesim_kesfi.json``; okunur, hesaplanmaz).
- ``urun_yeni``: bayrak açıkken kurucunun yazdığı ağaç (dizin = modül; ``main.c`` = ``.``).
- ``s2_islev``: ``c_project_builder.slice_by_padding`` doğrudan (bellek blokları ile; giriş noktası
  ayrımı ve geri düşüş yok).
- ``s2_bloksuz``: aynı işlev, bellek bloğu verilmeden (keşfin tanımı).
- ``duyarlilik_bant`` (YALNIZ DUYARLILIK; seçilmedi): sınır yalnız eşik ≤ dolgu < hizalama iken.

Eşik ve hizalama ``karadul/config.py``'den okunur; bu betik yeni değer denemez.

Kullanım
--------
    python -m scripts.measurement.yerlesim_urun_olc \\
        --kosu ~/karadul_olcum/runs/urun-yeni-93a2956 \\
        --olcum docs/arge/2026-11-11_harita/harita_olcumu.json \\
        --kesif docs/arge/2026-11-11_harita/yerlesim_kesfi.json \\
        --json docs/arge/2026-11-12_yerlesim/gelistirme_yeniden_uretim.json \\
        --md docs/arge/2026-11-12_yerlesim/gelistirme_yeniden_uretim.md
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Optional, Sequence

REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)

from karadul.config import Config  # noqa: E402
from karadul.reconstruction import c_project_builder as cpb  # noqa: E402


def _harita_yukle() -> ModuleType:
    """``harita_olc.py``'yi dosya yolundan yükle (ön kayıtla sabit dosya; içe aktarılır, değişmez)."""
    spec = importlib.util.spec_from_file_location("harita_olc", _BURASI / "harita_olc.py")
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


h = _harita_yukle()
ks1 = h.ks1

SEMA = "karadul-yerlesim-urun-olc/1"
DUZEY = h.KARAR_DUZEYI
ONDALIK = ks1.ONDALIK
STATIC = "static"
RECONSTRUCTED = "reconstructed"
PROJE = "project"
DERLEME_KOMUTLARI = "compile_commands.json"    # proje kökünün mutlak yolunu içeren tek dosya
ALGORITMA_RAPORU = "analysis/algorithms.md"
# Bayt karşılaştırmasına girmeyen dosyalar: girdisi çalışma alanında tam saklı olmayanlar
# (``algoritma_sonucu``). Yerleşimle ilgisi yoktur; kurucunun o işlevi değişmedi.
KARSILASTIRMA_DISI = frozenset({ALGORITMA_RAPORU})
# Kurucunun girdisi olabilecek dizinler (``reconstructed`` altında), hattın son adımından geriye.
KAYNAK_ADAYLARI = ("annotated", "commented", "semantic_named", "struct_recovered", "typed", "merged",
                   "src")
SATIR_URUN_ESKI = "urun_eski"
SATIR_B1 = h.SATIR_B1
SATIR_KESIF = "kesif_s2"
SATIR_URUN_YENI = "urun_yeni"
SATIR_ISLEV = "s2_islev"
SATIR_BLOKSUZ = "s2_bloksuz"
SATIR_BANT = "duyarlilik_bant"
YERLESIM_SATIRLARI = (SATIR_URUN_ESKI, SATIR_B1, SATIR_KESIF, SATIR_URUN_YENI, SATIR_ISLEV,
                      SATIR_BLOKSUZ, SATIR_BANT)
KESIF_SATIRI = "s2_dolgu16"                    # keşif JSON'undaki satır adı (dosya adı gibi sabit)


class SakliAlan:
    """Saklı çalışma alanını kurucuya salt okunur sunar (``static`` ve ``reconstructed``)."""

    def __init__(self, kosu: Path) -> None:
        self._kosu = Path(kosu)

    def get_stage_dir(self, ad: str) -> Path:
        if ad not in (STATIC, RECONSTRUCTED):
            raise KeyError(ad)
        return self._kosu / ad


def ayarli_config(acik: bool) -> Config:
    cfg = Config()
    cfg.binary_reconstruction.enable_address_placement = acik
    return cfg


def agac_ozeti(kok: Path, yol_cevirisi: Optional[tuple[str, str]] = None) -> dict[str, str]:
    """Göreli yol → sha256. ``yol_cevirisi`` verilirse ``compile_commands.json``'da kök yolu çevrilir.

    ``analysis/algorithms.md`` özete girmez (``KARSILASTIRMA_DISI``).
    """
    out: dict[str, str] = {}
    for dosya in sorted(p for p in Path(kok).rglob("*") if p.is_file()):
        goreli = dosya.relative_to(kok).as_posix()
        if goreli in KARSILASTIRMA_DISI:
            continue
        veri = dosya.read_bytes()
        if yol_cevirisi and dosya.name == DERLEME_KOMUTLARI:
            veri = veri.replace(yol_cevirisi[0].encode(), yol_cevirisi[1].encode())
        out[goreli] = hashlib.sha256(veri).hexdigest()
    return out


def algoritma_sonucu(kosu: Path) -> Any:
    """Kurucuya verilen ``algorithm_results``'ın saklı kısmı (``reconstructed/algorithms.json``).

    Saklı kayıtta ``detection_method`` alanı yoktur; bu yüzden ``analysis/algorithms.md`` yeniden
    üretilemez ve karşılaştırmaya girmez. README'deki "Algorithms detected" satırı yalnız güvenlere
    bakar; o satır yeniden üretilir. Saklı ağaçta ``algorithms.md`` yoksa kurucuya sonuç verilmemiştir.
    """
    kayit = Path(kosu) / RECONSTRUCTED / "algorithms.json"
    if not (Path(kosu) / RECONSTRUCTED / PROJE / ALGORITMA_RAPORU).is_file() or not kayit.is_file():
        return None
    return SimpleNamespace(algorithms=[
        SimpleNamespace(name=a.get("name"), category=a.get("category"), confidence=a.get("confidence"),
                        function_name=a.get("function"), detection_method=None,
                        evidence=a.get("evidence"))
        for a in h._json(kayit).get("algorithms") or []])


def kur(kaynak: Path, kosu: Path, cikti: Path, acik: bool) -> cpb.CProjectBuildResult:
    return cpb.CProjectBuilder(ayarli_config(acik)).build(
        source_dir=kaynak, output_dir=cikti, workspace=SakliAlan(kosu),
        algorithm_results=algoritma_sonucu(kosu))


def girdiyi_bul(kosu: Path, gecici: Path) -> dict[str, Any]:
    """Kurucunun girdi dizinini bul: bayrak KAPALI kurulum saklı proje ağacını bayt bayt veren aday.

    Dönen: ``kaynak`` (bulunamadıysa None), ``denenen`` ve eşitlik sayıları.
    """
    sakli = Path(kosu) / RECONSTRUCTED / PROJE
    beklenen = agac_ozeti(sakli)
    denenen: list[str] = []
    for aday in KAYNAK_ADAYLARI:
        kaynak = Path(kosu) / RECONSTRUCTED / aday
        if not kaynak.is_dir() or not any(kaynak.rglob("*.c")):
            continue
        denenen.append(aday)
        cikti = gecici / f"kapali_{aday}" / RECONSTRUCTED / PROJE
        kur(kaynak, kosu, cikti, acik=False)
        bulunan = agac_ozeti(cikti, (str(cikti), str(sakli)))
        if bulunan == beklenen:
            return {"kaynak": aday, "denenen": denenen, "dosya": len(beklenen), "ayni": True}
    return {"kaynak": None, "denenen": denenen, "dosya": len(beklenen), "ayni": False}


def ogeleri_ac(elf: dict[str, Any]) -> tuple[list[int], list[int], list[int]]:
    """Ölçüm JSON'undaki öğeler: (adresler, modül numaraları, dosya sınıf kodları), adres sırasında."""
    sirali = sorted((int(a, 16), v.split()) for a, v in elf["ogeler"].items())
    return [a for a, _ in sirali], [int(v[0]) for _, v in sirali], [int(v[1]) for _, v in sirali]


def bant_dilimi(boyut: dict[int, int], bloklar: list[cpb.MemoryBlock], esik: int, hiza: int
                ) -> dict[int, int]:
    """DUYARLILIK: sınır yalnız blok değişiminde ya da ``esik`` ≤ dolgu < ``hiza`` iken (adres → dilim)."""
    out: dict[int, int] = {}
    dilim = 0
    for g in cpb.function_gaps(boyut, bloklar):
        if g.block_changed or (g.gap is not None and esik <= g.gap < hiza):
            dilim += 1
        out[g.address] = dilim
    return out


def ikili_olcumu(e: Any, elf: dict[str, Any], kesif_ari: Optional[float], gecici: Path
                 ) -> dict[str, Any]:
    """Bir ikilinin yeniden üretimi: girdi bulunur, iki kurulum yapılır, satırlar ölçülür."""
    br = Config().binary_reconstruction
    esik, hiza = br.address_placement_padding_threshold, br.address_placement_alignment
    adresler, moduller, siniflar = ogeleri_ac(elf)
    n = len(adresler)
    girdi = girdiyi_bul(e.kosu, gecici)
    out: dict[str, Any] = {"n": n, "girdi": girdi}
    if girdi["kaynak"] is None:
        return out
    kaynak = Path(e.kosu) / RECONSTRUCTED / girdi["kaynak"]
    acik_kok = gecici / "acik"
    sonuc = kur(kaynak, e.kosu, acik_kok / RECONSTRUCTED / PROJE, acik=True)
    ghidra, _, _ = h._ghidra_adresleri(e)
    urun = h.urun_oku(acik_kok, ghidra)
    eksik = [a for a in adresler if a not in urun.modul]
    if eksik:
        raise SystemExit(f"DURDU: {e.program}/{e.ad}: nüfustan {len(eksik)} adres yeni ağaçta atanmamış")
    yeni = [urun.modul[a] for a in adresler]

    kurucu = cpb.CProjectBuilder(None)
    alan = SakliAlan(e.kosu)
    boyut = kurucu._load_function_sizes(alan)
    bloklar = kurucu._load_memory_blocks(alan)
    bloklu = cpb.slice_by_padding(boyut, bloklar, esik, hiza)
    bloksuz = cpb.slice_by_padding(boyut, [], esik, hiza)
    bant = bant_dilimi(boyut, bloklar, esik, hiza)
    bolmeler = {
        SATIR_URUN_ESKI: moduller,
        SATIR_B1: h.b1_bolme(n, len(set(moduller))),
        SATIR_URUN_YENI: yeni,
        SATIR_ISLEV: [bloklu.slice_of[a] for a in adresler],
        SATIR_BLOKSUZ: [bloksuz.slice_of[a] for a in adresler],
        SATIR_BANT: [bant[a] for a in adresler],
    }
    out["satirlar"] = {s: h.olculer(b, siniflar) for s, b in bolmeler.items()}
    out["kesif_s2_ari"] = kesif_ari
    yerlesim = json.loads((acik_kok / RECONSTRUCTED / PROJE / "analysis" / "placement.json").read_text())
    kok_modul = sum(1 for m in yeni if m == h.KOK_MODUL)
    out.update({
        "kurulum": {"basarili": bool(sonuc.success), "strateji": sonuc.placement_strategy,
                    "geri_dusus": sonuc.placement_fallback_reason or None,
                    "hata": len(sonuc.errors), "eksik": sonuc.functions_missing,
                    "cift": sonuc.functions_duplicated},
        "yerlesim": {a: yerlesim.get(a) for a in (
            "units", "entry_units", "units_placed_by_address", "units_without_address",
            "signal_gaps", "padding_cuts", "block_cuts", "memory_blocks_known")},
        "grup": len(yerlesim.get("groups") or []),
        "nufusta_kok_modul": kok_modul,           # nüfustan main.c'ye giden fonksiyon
        # bölme eşitliği (etiket adından bağımsız): aynı ise iki bölme nüfusu aynı kümelere ayırır
        "ayni_bolme": {
            "urun_yeni=s2_islev": ayni_bolme(yeni, bolmeler[SATIR_ISLEV]),
            "s2_islev=s2_bloksuz": ayni_bolme(bolmeler[SATIR_ISLEV], bolmeler[SATIR_BLOKSUZ]),
        },
    })
    return out


def ayni_bolme(a: Sequence[Any], b: Sequence[Any]) -> bool:
    """İki etiket dizisi aynı bölmeyi mi veriyor (etiket adları farklı olabilir)?"""
    return len(set(zip(a, b))) == len(set(a)) == len(set(b))


def kos(kosu_koku: Path, olcum_yolu: Path, kesif_yolu: Path, yalniz: Optional[set[str]] = None
        ) -> dict[str, Any]:
    olcum = h._json(olcum_yolu)
    kesif = h._json(kesif_yolu)
    elfler = {(ks1.birim_anahtari(e), e.ad): e
              for e in h.projesizleri_isaretle(ks1.elfleri_topla(None, Path(kosu_koku) / "debian"))}
    ikililer: dict[str, dict[str, Any]] = {}
    for birim, v in sorted(olcum["birimler"].items()):
        for ad, elf in sorted(v["elfler"].items()):
            if not elf["duzeyler"][DUZEY]["giris"]:
                continue
            if yalniz is not None and f"{birim}/{ad}" not in yalniz:
                continue
            kesif_ari = kesif["ikili_ari"].get(birim, {}).get(ad, {}).get(KESIF_SATIRI)
            with tempfile.TemporaryDirectory(prefix="yerlesim_urun_olc_") as gecici:
                ikililer[f"{birim}/{ad}"] = ikili_olcumu(elfler[(birim, ad)], elf, kesif_ari, Path(gecici))
    return {"sema": SEMA, "uyari": "GELİŞTİRME SETİ; ön kayıtsız yeniden üretim; ürün iddiası değil",
            "arac": {"harita_olc_sha256": ks1.sha256_dosya(_BURASI / "harita_olc.py"),
                     "olcum_sha256": ks1.sha256_dosya(olcum_yolu),
                     "kesif_sha256": ks1.sha256_dosya(kesif_yolu),
                     "kurucu_sha256": ks1.sha256_dosya(Path(cpb.__file__)),
                     "git_head": ks1._git("rev-parse", "HEAD").stdout.strip()},
            "esik": Config().binary_reconstruction.address_placement_padding_threshold,
            "hizalama": Config().binary_reconstruction.address_placement_alignment,
            "ozet": ozet(ikililer, olcum, kesif), "ikililer": ikililer}


def ozet(ikililer: dict[str, dict[str, Any]], olcum: dict[str, Any], kesif: dict[str, Any]
         ) -> dict[str, Any]:
    """Program tablosu ve makrolar; ön kayıtlı ölçüm ve keşifle sağlama; kurulum sayımları."""
    birimler: dict[str, dict[str, dict[str, Any]]] = {}
    for anahtar, s in ikililer.items():
        birim, ad = anahtar.rsplit("/", 1)
        if "satirlar" in s:
            birimler.setdefault(birim, {})[ad] = s
    satirlar: dict[str, Any] = {}
    for satir in YERLESIM_SATIRLARI:
        if satir == SATIR_KESIF:
            deger = {b: h.ortalama(s["kesif_s2_ari"] for s in v.values()) for b, v in birimler.items()}
        else:
            deger = {b: h.ortalama(s["satirlar"][satir]["ari"] for s in v.values())
                     for b, v in birimler.items()}
        satirlar[satir] = h.makro(deger)
    olcum_satirlari = olcum["ozet"][DUZEY]["satirlar"]
    saglama = {
        SATIR_URUN_ESKI: [h.yuvarla(satirlar[SATIR_URUN_ESKI]["makro"]), olcum_satirlari[h.SATIR_URUN]["ari"]["makro"]],
        SATIR_B1: [h.yuvarla(satirlar[SATIR_B1]["makro"]), olcum_satirlari[h.SATIR_B1]["ari"]["makro"]],
        SATIR_KESIF: [h.yuvarla(satirlar[SATIR_KESIF]["makro"]), kesif["ozet"][KESIF_SATIRI]["ari"]["makro"]],
    }
    olculen = [s for s in ikililer.values() if "satirlar" in s]
    karar = h.karsilastirma_karari(satirlar[SATIR_URUN_YENI]["program"], satirlar[SATIR_B1]["program"])
    return {
        "satirlar": satirlar, "saglama": saglama,
        "saglama_tuttu": all(a == b for a, b in saglama.values()),
        # ön kayıtlı ölçümün karar kuralı (0,05 fark; 2/3 çoğunluk), yeni ürün ↔ B1; geliştirme seti
        "urun_yeni_b1_karsilastirmasi": karar,
        "ikili": len(ikililer), "olculen_ikili": len(olculen),
        "kapali_kurulum_sakliyla_ayni": sum(1 for s in ikililer.values() if s["girdi"]["ayni"]),
        "girdi_dizini": dict(sorted(Counter(str(s["girdi"]["kaynak"]) for s in ikililer.values()).items())),
        "strateji": dict(sorted(Counter(s["kurulum"]["strateji"] for s in olculen).items())),
        "geri_dusus": dict(sorted(Counter(str(s["kurulum"]["geri_dusus"]) for s in olculen).items())),
        "kurulum_basarisiz": sum(1 for s in olculen if not s["kurulum"]["basarili"]),
        "adressiz_birim": sum(s["yerlesim"]["units_without_address"] or 0 for s in olculen),
        "nufusta_kok_modul": sum(s["nufusta_kok_modul"] for s in olculen),
        "bolme_esit": {k: sum(1 for s in olculen if s["ayni_bolme"][k])
                       for k in ("urun_yeni=s2_islev", "s2_islev=s2_bloksuz")},
        "ari_esit": {
            "urun_yeni=kesif_s2": sum(1 for s in olculen
                                      if h.yuvarla(s["satirlar"][SATIR_URUN_YENI]["ari"]) == s["kesif_s2_ari"]),
            "s2_bloksuz=kesif_s2": sum(1 for s in olculen
                                       if h.yuvarla(s["satirlar"][SATIR_BLOKSUZ]["ari"]) == s["kesif_s2_ari"]),
        },
    }


def markdown(s: dict[str, Any]) -> str:
    o = s["ozet"]
    programlar = sorted(o["satirlar"][SATIR_URUN_YENI]["program"])
    k = o["urun_yeni_b1_karsilastirmasi"]
    satirlar = [
        "# Yerleşim: yeni ürün işlevinin geliştirme setinde yeniden üretimi", "",
        "- **Durum: GELİŞTİRME SETİ, ön kayıtsız. Sayılar ürün iddiası değildir.** Eşik ve hizalama bu "
        "sette seçilmişti; burada yeniden ayarlanmadı.",
        f"- Eşik {s['esik']} bayt, hizalama {s['hizalama']} bayt (`karadul/config.py`). Ölçü: dosya düzeyi "
        "ARI, program düzeyi makro (`harita_olc.py`'nin işlevleri).",
        f"- İkili: {o['ikili']}; ölçülen: {o['olculen_ikili']}. Bayrak kapalı kurulumu saklı proje ağacıyla "
        f"bayt bayt aynı çıkan: {o['kapali_kurulum_sakliyla_ayni']}. Kurucunun girdi dizini: "
        + ", ".join(f"`{a}` {n}" for a, n in o["girdi_dizini"].items()) + ".",
        "- Sağlama (bulunan = beklenen): " + "; ".join(
            f"`{a}` {h.sayi(b[0], 6)} = {h.sayi(b[1], 6)}" for a, b in o["saglama"].items())
        + (" — tuttu." if o["saglama_tuttu"] else " — TUTMADI."),
        "- Bayrak açık kurulum: strateji " + ", ".join(f"`{a}` {n}" for a, n in o["strateji"].items())
        + "; geri düşüş " + ", ".join(f"`{a}` {n}" for a, n in o["geri_dusus"].items())
        + f"; başarısız kurulum {o['kurulum_basarisiz']}; adressiz birim {o['adressiz_birim']}; nüfustan "
        f"`main.c`'ye giden fonksiyon {o['nufusta_kok_modul']}.",
        f"- Bölme eşitliği (ikili sayısı): `urun_yeni` = `s2_islev` {o['bolme_esit']['urun_yeni=s2_islev']}; "
        f"`s2_islev` = `s2_bloksuz` {o['bolme_esit']['s2_islev=s2_bloksuz']}. ARI eşitliği (6 hane): "
        f"`urun_yeni` = `kesif_s2` {o['ari_esit']['urun_yeni=kesif_s2']}; `s2_bloksuz` = `kesif_s2` "
        f"{o['ari_esit']['s2_bloksuz=kesif_s2']}.",
        f"- Ön kayıtlı ölçümün karar kuralıyla (0,05; 2/3) `urun_yeni` ↔ `b1`, GELİŞTİRME SETİNDE: "
        f"`{k['karar']}` (makro fark {h.sayi(k['makro_fark'])}; pozitif {k['pozitif']}, negatif "
        f"{k['negatif']}, gerekli {k['gerekli']}). Karar değildir; doğrulama seti gerekir.", "",
        "| Satır | Makro | " + " | ".join(programlar) + " |",
        "|---|---|" + "---|" * len(programlar)]
    for satir in YERLESIM_SATIRLARI:
        m = o["satirlar"][satir]
        satirlar.append(f"| `{satir}` | {h.sayi(m['makro'])} | "
                        + " | ".join(h.sayi(m["program"].get(p)) for p in programlar) + " |")
    satirlar += ["", "`duyarlilik_bant` yalnız duyarlılıktır; seçilmedi, ürün kuralı değildir.", "",
                 "## İkili başına", "",
                 "| İkili | n | Grup | `urun_eski` | `b1` | `kesif_s2` | `urun_yeni` | `s2_islev` | "
                 "`s2_bloksuz` | Nüfustan `main.c`'ye | Geri düşüş |",
                 "|---|---|---|---|---|---|---|---|---|---|---|"]
    for anahtar, i in s["ikililer"].items():
        if "satirlar" not in i:
            satirlar.append(f"| `{anahtar}` | {i['n']} | — | girdi bulunamadı | | | | | | | |")
            continue
        r = i["satirlar"]
        satirlar.append(
            f"| `{anahtar}` | {i['n']} | {i['grup']} | {h.sayi(r[SATIR_URUN_ESKI]['ari'])} | "
            f"{h.sayi(r[SATIR_B1]['ari'])} | {h.sayi(i['kesif_s2_ari'])} | {h.sayi(r[SATIR_URUN_YENI]['ari'])} | "
            f"{h.sayi(r[SATIR_ISLEV]['ari'])} | {h.sayi(r[SATIR_BLOKSUZ]['ari'])} | {i['nufusta_kok_modul']} | "
            f"{i['kurulum']['geri_dusus'] or '—'} |")
    return "\n".join(satirlar) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kosu", type=Path, required=True, help="ölçülen koşunun kökü (salt okunur)")
    ap.add_argument("--olcum", type=Path, required=True, help="ön kayıtlı ölçümün JSON'u")
    ap.add_argument("--kesif", type=Path, required=True, help="keşif betiğinin JSON'u")
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--md", type=Path, default=None)
    ap.add_argument("--yalniz", nargs="*", default=None, metavar="BİRİM/İKİLİ",
                    help="yalnız bu ikililer (deneme için; özet o zaman eksiktir)")
    a = ap.parse_args(argv)
    sonuc = kos(a.kosu.expanduser(), a.olcum, a.kesif, set(a.yalniz) if a.yalniz else None)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(h.yuvarla(sonuc), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(markdown(sonuc), encoding="utf-8")
    o = sonuc["ozet"]
    print(f"yeniden üretim: {o['olculen_ikili']}/{o['ikili']} ikili; kapalı kurulum saklıyla aynı "
          f"{o['kapali_kurulum_sakliyla_ayni']}; urun_yeni makro "
          f"{h.sayi(o['satirlar'][SATIR_URUN_YENI]['makro'])}; sağlama "
          f"{'tuttu' if o['saglama_tuttu'] else 'TUTMADI'}")
    return 0 if o["saglama_tuttu"] else 2


if __name__ == "__main__":
    sys.exit(main())
