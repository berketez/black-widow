#!/usr/bin/env python3
"""Ürün adlarının GT'ye karşı ölçümü: bir koşu kökü (kol) ve iki kolun karşılaştırması.

Soru: ürün (Karadul'un bir koşusu) Ghidra'nın jenerik bıraktığı fonksiyonlara hangi adları verdi,
bu adlar gerçek adla (GT) aynı mı, ad bekleyen fonksiyonların ne kadarını kapsıyor? Cevap birim
(platform/program), boyut tabakası, etiket, kanal ve kanal grubu (üründe susan alt kanallar ile
kalan kanallar) başına verilir. Ön kayıt taslağı:
``docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit_taslak.md``.

GT, adres eşlemesi, ad karşılaştırması, Wilson aralığı ve program sınıfı ``ks1_olc.py``'den içe
aktarılır (o dosya KS-1 ön kaydıyla sabittir; burada değiştirilmez, yeniden yazılmaz). Etiket
sözlüğü ve kanal adı ürün modülünden gelir (``karadul.core.naming_labels``); köken kaydında alt
kanalı yazılmamış ``string_context`` adı ürünün sınıflayıcısıyla sınıflanır
(``karadul.reconstruction.tarif.alt_kanal.classify_record``).

Alt komutlar
------------
``olc``
    Bir kolun ölçümü. İkili başına ``reconstructed/src/naming_map.json`` (``global``) ve yanındaki
    ``naming_provenance.json`` okunur. Anahtarı ``FUN_<onaltılık>`` olan giriş fonksiyon adıdır;
    ``DAT_`` … veri adıdır ve yalnız sayılır. Her fonksiyon adı GT'ye göre hüküm alır
    (``ks1_olc.capa_degerlendir``): tam eşitlik doğrudur (Mach-O'da baştaki tek ``_`` soyulur);
    GT'nin bütün adları derleyici ekliyse (klon) taban eşitliği doğrudur; GT'de o adreste fonksiyon
    yoksa ad eşlenemez ve yanlış sayılır. Ölçüler örnek düzeyindedir (ikili başına ad):
      - kesinlik = doğru / ad verilen; yanlış oranı = yanlış / ad verilen;
      - kapsam = ad bekleyen nüfusta ad verilen / nüfus; tam ad kapsamı = nüfusta doğru / nüfus
        (nüfus: ``ks1_olc.GtBirimi.nufus``).
    Birim başına Wilson %95; toplamda havuz ve program düzeyi makro (aynı programın platform
    birimleri önce ortalanır, sonra programlar eşit ağırlıkla). Çıktıda ad geçmez: yalnız sayılar ve
    adres başına hüküm kodu (``ogeler``; ``karsilastir`` bununla eşler).
``karsilastir``
    İki kolun (taban, yeni) yan yana tablosu ve farklar: birim başına yanlış ve doğru ad sayısı,
    kaybedilen ve kazanılan doğru ad. Öğeler birim, ikili ve adresle eşlenir; iki kol aynı dosyaları
    (sha256) ölçmüş olmalıdır.

Eksiksizlik: birim başına ikili sayısı ``ks1_olc.BEKLENEN_ELF`` ile denetlenir. Eksik, bitmemiş ya
da ad haritası yazılmamış koşu varsa ölçüm durur; ``--eksik-izinli`` ile sürer ve eksikleri listeler.
C++ ikililer ``ks1_olc.cpp_ikili_mi`` kuralıyla ölçülerin dışındadır.

Kullanım
--------
    python scripts/measurement/urun_olc.py olc --kok-debian <n1_debian13> --kok-mac <ol7-a> \\
        --mac-veri <olcum_mac> --kol taban --json <taban.json> --md <taban.md>
    python scripts/measurement/urun_olc.py karsilastir --taban <taban.json> --yeni <yeni.json> \\
        --json <fark.json> --md <fark.md>
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import platform
import re
import sys
from collections import Counter
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Optional

SEMA = "karadul-urun-olc/1"
KARSILASTIR_SEMA = "karadul-urun-karsilastir/1"
REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
OLC_YOLU = Path(__file__).resolve()
KS1_YOLU = _BURASI / "ks1_olc.py"
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)


def _ks1_yukle() -> ModuleType:
    """``ks1_olc.py``'yi dosya yolundan yükle (ön kayıtla sabit dosya; içe aktarılır, değişmez)."""
    spec = importlib.util.spec_from_file_location("ks1_olc", KS1_YOLU)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


ks1 = _ks1_yukle()

import karadul  # noqa: E402

if REPO not in Path(karadul.__file__).resolve().parents:
    # editable kurulum başka bir ağacı gösteriyorsa ürün tanımları o ağaçtan gelirdi
    raise ImportError(f"karadul {karadul.__file__} yolundan yüklendi; beklenen depo {REPO}")

from karadul.core import naming_labels  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal  # noqa: E402

# ---- Ürün çıktısının yerleri (çalışma alanına göre) ----
HARITA_REL = Path("reconstructed") / "src" / "naming_map.json"
KOKEN_REL = HARITA_REL.with_name(naming_labels.NAMING_PROVENANCE_FILE)
HEDEF_REL = Path("raw") / "target_info.json"
RAPOR_REL = Path("reports") / "report.json"

# ---- Anahtar sınıfları ----
# Fonksiyon adı: anahtarı ``FUN_<onaltılık>`` olan giriş (KS-1 bağlamasının anahtar kuralıyla aynı
# biçim; burada adres de yakalanır). Veri adı: Ghidra'nın veri önekleri.
FONKSIYON_ANAHTARI_RE = re.compile(r"^FUN_([0-9a-fA-F]+)$")
VERI_ONEKLERI = ("DAT_", "PTR_", "UNK_")
SINIF_FONKSIYON = "fonksiyon"
SINIF_VERI = "veri"
SINIF_DIGER = "diger"
# Ölçüye girmeyen ``FUN_`` girişleri (sayılır, raporlanır)
ATLAMA_OZDES = "ozdes"                # yeni ad anahtarın kendisi ya da ad değil
ATLAMA_GHIDRA_YOK = "ghidra_yok"      # o adreste Ghidra fonksiyonu yok
ATLAMA_GHIDRA_ADLI = "ghidra_adli"    # Ghidra fonksiyonu zaten adlandırmış (ad bekleyen değil)
ATLAMA_JENERIK = "jenerik_ad"         # ürünün verdiği ad kimlik iddiası değil (adres etiketi)
ATLAMALAR = (ATLAMA_OZDES, ATLAMA_GHIDRA_YOK, ATLAMA_GHIDRA_ADLI, ATLAMA_JENERIK)

# ---- Etiket ve kanal ----
ETIKETSIZ = "etiketsiz"               # köken kaydında ``label`` alanı yok (eski koşu, elle ad)
ETIKETLER = naming_labels.NAME_LABELS + (ETIKETSIZ,)
ETIKET_KESIN = naming_labels.LABEL_CERTAIN
KANAL_KOKEN_YOK = "koken_yok"         # köken kaydı ya da kaydın stratejisi yok
ALT_KANAL_KAYITTAN = "kayittan"
ALT_KANAL_SONRADAN = "sonradan"       # kayıtta yok; ürün sınıflayıcısıyla bu betikte hesaplandı
ALT_KANAL_UYUSMUYOR = "uyusmuyor"     # kayıttaki alt kanal ürün sınıflayıcısının verdiğinden farklı
# Kanal grubu: ürünün karar tablosunda susan ``string_context`` alt kanalları ve kalan her kanal.
# Taban kolda "kalan" grubu susturmanın tek başına bırakacağı adların öngörüsüdür; susturması
# açık bir kolda "susan" grubunda ad kalmamalıdır.
GRUP_SUSAN = "susan"
GRUP_KALAN = "kalan"
KIRILIMLAR = ("etiket", "kanal", "kanal_grubu")

# ---- Hükümler ----
DOGRU = ks1.DURUM_DOGRU
YANLIS = ks1.DURUM_YANLIS
ADSIZ = "adsiz"                       # yalnız ``karsilastir``: o kolda ad yok
SATIRLAR = (ks1.SATIR_ANA, ks1.SATIR_KLON, ks1.SATIR_ESLENEMEDI)
DURUMLAR = (ADSIZ, DOGRU, YANLIS)

# ---- Ölçüler ve seçimler (ön kayıt taslağı §5-§7; eşikler [seçim]) ----
N_MIN = ks1.N_MIN                     # makroya giren birim: paydası en az bu kadar
EN_AZ_PROGRAM = ks1.EN_AZ_PROGRAM     # karar için giren en az farklı program
ONDALIK = ks1.ONDALIK
YANLIS_HEDEFI = 0.10                  # (a) yanlış ad oranı, program düzeyi makro ≤
KESIN_ETIKET_ESIGI = ks1.KESINLIK_ESIGI   # (b) "kesin" etiketli adların kesinliği, makro ≥
KAYIP_INCELEME_SINIRI = 0.15          # (c) kaybedilen doğru ad / tabandaki doğru ad > (havuz ya da birim)
# Karar ölçüleri ve duyarlılık satırları (hepsi ``ks1.oran`` biçiminde)
KARAR_OLCULERI = ("kesinlik", "yanlis_orani", "kapsam", "dogru_kapsam")
DUYARLILIK_OLCULERI = ("nufus_ici_kesinlik", "proje_normallestirmesi", "tekil_kesinlik")
KARAR_TUTUYOR = "tutuyor"
KARAR_TUTMUYOR = "tutmuyor"
KARAR_YETERSIZ = "yetersiz"           # giren program sayısı EN_AZ_PROGRAM'ın altında
KARAR_INCELE = "incele"
KARAR_BEKLENEN = "beklenen_aralikta"
BOYUT_SIRASI = tuple(ad for _, ad in ks1.BOYUT_SINIRLARI) + (ks1.BOYUT_EN_BUYUK,)
TABAKA_ALANLARI = ("boyut_tabakasi", "zenginlik_sinifi")
OGE_AYRACI = " "


OnkosulHatasi = ks1.OnkosulHatasi


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# Ürün çıktısını okuma


def harita_yolu(e: Any) -> Path:
    return Path(e.kosu) / HARITA_REL


def haritasizlari_isaretle(elfler: Iterable[Any]) -> list[Any]:
    """Ad haritası yazılmamış koşu bitmemiş sayılır (``static`` = None): Ghidra çıktısı olup
    adlandırması yarım kalan koşu ölçüme "ad vermedi" diye girmesin."""
    return [e if e.static is None or harita_yolu(e).is_file() else dataclasses.replace(e, static=None)
            for e in elfler]


def haritayi_oku(kosu: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """(genel ad haritası, genel köken kayıtları, kol kimliği). Köken dosyası yoksa kayıtlar boş."""
    belge = _json(Path(kosu) / HARITA_REL)
    genel = belge.get("global") if isinstance(belge, dict) else None
    if not isinstance(genel, dict):
        raise OnkosulHatasi(f"{Path(kosu) / HARITA_REL}: 'global' sözlüğü yok")
    koken_yolu = Path(kosu) / KOKEN_REL
    koken = _json(koken_yolu) if koken_yolu.is_file() else {}
    kayitlar = koken.get(naming_labels.PROVENANCE_GLOBAL) or {}
    susturma = koken.get("silencing")
    kimlik = {"koken_var": koken_yolu.is_file(),
              "susturma": susturma.get("enabled") if isinstance(susturma, dict) else None,
              "genel_esik": koken.get("global_min_confidence")}
    return genel, kayitlar, kimlik


def anahtar_sinifi(anahtar: str) -> tuple[str, Optional[int]]:
    """Anahtarın sınıfı ve (fonksiyonsa) adresi."""
    m = FONKSIYON_ANAHTARI_RE.match(anahtar)
    if m:
        return SINIF_FONKSIYON, int(m.group(1), 16)
    if anahtar.startswith(VERI_ONEKLERI):
        return SINIF_VERI, None
    return SINIF_DIGER, None


def etiket_oku(kayit: Optional[dict[str, Any]]) -> str:
    """Kayıttaki ``label``; alan yoksa ya da sözlükte değilse ``etiketsiz``.

    Ürünün gösterim kuralı (``provenance_label``) etiketsiz kaydı "doğrulanmadı" gösterir; ölçüm
    kayıtta ne yazıyorsa onu sayar, böylece eski koşu yeni koşudan ayırt edilir.
    """
    etiket = (kayit or {}).get("label")
    return etiket if etiket in naming_labels.NAME_LABELS else ETIKETSIZ


def kanal_oku(kayit: Optional[dict[str, Any]]) -> tuple[str, Optional[str]]:
    """(kanal, alt kanalın kaynağı). Kanal adı ürünün kendi kuralıdır (``provenance_channel``):
    ``ks1:<satırlar>``, ``on_ad:<tür>``, ``string_context/<alt kanal>`` ya da strateji.

    ``string_context`` kaydında alt kanal yazılmamışsa (eski koşu) ürün sınıflayıcısıyla hesaplanır;
    yazılmışsa sınıflayıcıyla karşılaştırılır (uyuşmazlık sayılır, kayıttaki değer kullanılır).
    """
    if not kayit:
        return KANAL_KOKEN_YOK, None
    kanal = naming_labels.provenance_channel(kayit)
    if kanal is None:
        return KANAL_KOKEN_YOK, None
    if kayit.get("strategy") != naming_labels.STRATEGY_STRING_CONTEXT or kayit.get("pre_name_kind"):
        return kanal, None
    hesaplanan = alt_kanal.classify_record(kayit)
    if not kayit.get("sub_channel"):
        return f"{naming_labels.STRATEGY_STRING_CONTEXT}/{hesaplanan}", ALT_KANAL_SONRADAN
    return kanal, ALT_KANAL_KAYITTAN if kayit["sub_channel"] == hesaplanan else ALT_KANAL_UYUSMUYOR


def degerlendir_elf(genel: dict[str, Any], koken: dict[str, Any], gfonk: list[dict[str, Any]],
                    gt: Any, platform_: str) -> tuple[list[dict[str, Any]], Counter]:
    """Bir ikilinin fonksiyon adları için kayıt listesi ve anahtar sayacı.

    Kayıt: adres, ad (yalnız bellekte), satır, durum, proje normalleştirmesi, nüfusta mı, etiket,
    kanal. Ölçüye giren ad: anahtarı ``FUN_<onaltılık>``, o adreste Ghidra'nın jenerik adlandırdığı
    bir fonksiyon var, yeni ad anahtardan farklı ve kimlik iddiası taşıyor (``ATLAMALAR`` dışı).
    """
    f1 = ks1._f1()
    ghidra = {g["addr"]: g for g in gfonk}
    kayitlar: list[dict[str, Any]] = []
    sayac: Counter = Counter()
    gorulen: set[int] = set()
    for anahtar in sorted(genel):
        yeni = genel[anahtar]
        sinif_, adres = anahtar_sinifi(anahtar)
        ad_mi = isinstance(yeni, str) and bool(yeni) and yeni != anahtar
        if sinif_ != SINIF_FONKSIYON:
            sayac[f"{sinif_}_anahtari"] += 1
            sayac[f"{sinif_}_ad_verilen"] += int(ad_mi)
            continue
        sayac["fonksiyon_anahtari"] += 1
        if adres in gorulen:
            raise OnkosulHatasi(f"ad haritasında aynı adres iki kez: 0x{adres:x}")
        gorulen.add(adres)
        g = ghidra.get(adres)
        if not ad_mi:
            sayac[ATLAMA_OZDES] += 1
        elif g is None:
            sayac[ATLAMA_GHIDRA_YOK] += 1
        elif not f1.is_generic_name(g["name"], [adres]):
            sayac[ATLAMA_GHIDRA_ADLI] += 1
        elif f1.is_generic_name(yeni, [adres]):
            sayac[ATLAMA_JENERIK] += 1
        else:
            kayit = koken.get(anahtar)
            kanal, alt_kaynak = kanal_oku(kayit)
            if alt_kaynak:
                sayac[f"alt_kanal_{alt_kaynak}"] += 1
            gt_adlari = gt.adlar.get(adres)
            if gt_adlari is None:      # GT'de karşılığı yok: ürün yine de ad yazdı → yanlış
                hukum = {"satir": ks1.SATIR_ESLENEMEDI, "durum": YANLIS, "proje": False}
            else:
                hukum = ks1.capa_degerlendir(yeni, gt_adlari, platform_)
            kayitlar.append({"adres": adres, "ad": yeni, **hukum, "nufusta": adres in gt.nufus,
                             "etiket": etiket_oku(kayit), "kanal": kanal})
    return kayitlar, sayac


# --------------------------------------------------------------------------------------------
# Ölçüler


def olcu(kayitlar: list[dict[str, Any]], nufus: int) -> dict[str, Any]:
    """Karar ölçüleri (örnek düzeyi). Kapsamın payı yalnız nüfustaki adlardır; kesinliğin paydası
    ad verilen bütün fonksiyonlardır (nüfus dışındakiler de: CRT, klon, GT'de karşılıksız)."""
    n = len(kayitlar)
    dogru = sum(1 for k in kayitlar if k["durum"] == DOGRU)
    nf = [k for k in kayitlar if k["nufusta"]]
    return {"ad_verilen": n, "dogru": dogru, "yanlis": n - dogru, "nufus": nufus,
            "kesinlik": ks1.oran(dogru, n), "yanlis_orani": ks1.oran(n - dogru, n),
            "kapsam": ks1.oran(len(nf), nufus),
            "dogru_kapsam": ks1.oran(sum(1 for k in nf if k["durum"] == DOGRU), nufus)}


def tekil_kesinlik(kayitlar: list[dict[str, Any]]) -> dict[str, Any]:
    """Birim içinde aynı ürün adı tek öğedir; bütün örnekleri doğruysa doğrudur (duyarlılık)."""
    gruplar: dict[str, list[bool]] = {}
    for k in kayitlar:
        gruplar.setdefault(k["ad"], []).append(k["durum"] == DOGRU)
    return ks1.oran(sum(1 for g in gruplar.values() if all(g)), len(gruplar))


def fonksiyon_ozeti(kayitlar: list[dict[str, Any]], nufus: int) -> dict[str, Any]:
    """Karar ölçüleri + satır dökümü + duyarlılık satırları (karar dışı)."""
    nf = [k for k in kayitlar if k["nufusta"]]
    satir = {}
    for s in SATIRLAR:
        ks = [k for k in kayitlar if k["satir"] == s]
        satir[s] = {"n": len(ks), "dogru": sum(1 for k in ks if k["durum"] == DOGRU)}
    return {**olcu(kayitlar, nufus), "satir": satir,
            "nufus_ici_kesinlik": ks1.oran(sum(1 for k in nf if k["durum"] == DOGRU), len(nf)),
            "proje_normallestirmesi": ks1.oran(sum(1 for k in kayitlar if k["proje"]), len(kayitlar)),
            "tekil_kesinlik": tekil_kesinlik(kayitlar)}


def kirilim(kayitlar: list[dict[str, Any]], nufus: int, alan: str) -> dict[str, Any]:
    """``alan`` (etiket ya da kanal) değeri başına karar ölçüleri."""
    return {d: olcu([k for k in kayitlar if k[alan] == d], nufus)
            for d in sorted({k[alan] for k in kayitlar})}


def kanal_grubu(kanal: str) -> str:
    """``string_context/<alt kanal>`` ve alt kanal ürünün susan kümesindeyse ``susan``; yoksa ``kalan``."""
    strateji, ayrac, alt = kanal.partition("/")
    susan = (strateji == naming_labels.STRATEGY_STRING_CONTEXT and bool(ayrac)
             and alt in alt_kanal.SILENCED_SUBCHANNELS)
    return GRUP_SUSAN if susan else GRUP_KALAN


def birim_ozeti(kayitlar: list[dict[str, Any]], nufus: int) -> dict[str, Any]:
    gruplu = [{**k, "kanal_grubu": kanal_grubu(k["kanal"])} for k in kayitlar]
    return {"fonksiyon": fonksiyon_ozeti(kayitlar, nufus),
            **{alan: kirilim(gruplu, nufus, alan) for alan in KIRILIMLAR}}


def etiket_kanal_tablosu(kayitlar: Iterable[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    """Etiket × kanal çapraz sayımı (havuz): hangi etiket hangi kanaldan geliyor, kaçı doğru."""
    tablo: dict[str, dict[str, dict[str, int]]] = {}
    for k in kayitlar:
        h = tablo.setdefault(k["etiket"], {}).setdefault(k["kanal"], {"ad_verilen": 0, "dogru": 0})
        h["ad_verilen"] += 1
        h["dogru"] += int(k["durum"] == DOGRU)
    return {e: dict(sorted(kanallar.items())) for e, kanallar in sorted(tablo.items())}


def makro_kesri(oranlar: dict[str, dict[str, Any]], n_min: int = N_MIN
                ) -> tuple[Optional[Fraction], dict[str, Fraction], list[str], list[str]]:
    """Program düzeyi makro (kesirle): paydası ≥ ``n_min`` olan birimler girer; aynı programın
    platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla (``ks1_olc.makro`` kuralı)."""
    giren = sorted(b for b, o in oranlar.items() if o["n"] >= n_min)
    kucuk = sorted(b for b, o in oranlar.items() if 0 < o["n"] < n_min)
    programlar: dict[str, list[str]] = {}
    for b in giren:
        programlar.setdefault(ks1.birim_programi(b), []).append(b)
    prog = {p: sum(Fraction(oranlar[b]["k"], oranlar[b]["n"]) for b in bs) / len(bs)
            for p, bs in sorted(programlar.items())}
    return (sum(prog.values()) / len(prog) if prog else None), prog, giren, kucuk


def program_makrosu(oranlar: dict[str, dict[str, Any]], n_min: int = N_MIN) -> dict[str, Any]:
    ort, prog, giren, kucuk = makro_kesri(oranlar, n_min)
    return {"makro": None if ort is None else round(float(ort), ONDALIK),
            "program": {p: round(float(v), ONDALIK) for p, v in prog.items()},
            "giren_birimler": giren, "kucuk_birimler": kucuk, "n_min": n_min}


def havuz(ozetler: Iterable[dict[str, Any]], olculer: Iterable[str]) -> dict[str, Any]:
    """Birim özetlerinin havuzu: her ölçünün payı ve paydası toplanır."""
    ozetler = list(ozetler)
    out: dict[str, Any] = {a: sum(o[a] for o in ozetler) for a in ("ad_verilen", "dogru", "yanlis", "nufus")}
    for a in olculer:
        out[a] = ks1.oran(sum(o[a]["k"] for o in ozetler), sum(o[a]["n"] for o in ozetler))
    return out


def bos_olcu(nufus: int) -> dict[str, Any]:
    return olcu([], nufus)


def toplam_ozeti(birimler: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Havuz ve program düzeyi makro: fonksiyon adları, etiket ve kanal başına."""
    fonk = {b: v["ozet"]["fonksiyon"] for b, v in birimler.items()}
    olculer = KARAR_OLCULERI + DUYARLILIK_OLCULERI
    out: dict[str, Any] = {"fonksiyon": {
        "havuz": havuz(fonk.values(), olculer),
        "makro": {a: program_makrosu({b: o[a] for b, o in fonk.items()}) for a in olculer}}}
    for alan in KIRILIMLAR:
        degerler = sorted({d for v in birimler.values() for d in v["ozet"][alan]})
        out[alan] = {}
        for d in degerler:
            dilim = {b: v["ozet"][alan].get(d) or bos_olcu(v["nufus"]) for b, v in birimler.items()}
            out[alan][d] = {"havuz": havuz(dilim.values(), KARAR_OLCULERI),
                            "makro": {a: program_makrosu({b: o[a] for b, o in dilim.items()})
                                      for a in KARAR_OLCULERI}}
    return out


def tabaka_ozeti(birimler: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Boyut tabakası ve zenginlik sınıfı başına (birim düzeyi sınıf; ``ks1_olc.sinif``)."""
    out: dict[str, Any] = {}
    for alan in TABAKA_ALANLARI:
        out[alan] = {}
        for d in sorted({str(v["sinif"].get(alan)) for v in birimler.values()}):
            secilen = {b: v["ozet"]["fonksiyon"] for b, v in birimler.items()
                       if str(v["sinif"].get(alan)) == d}
            out[alan][d] = {"birimler": sorted(secilen),
                            "havuz": havuz(secilen.values(), KARAR_OLCULERI),
                            "makro": {a: program_makrosu({b: o[a] for b, o in secilen.items()})
                                      for a in KARAR_OLCULERI}}
    return out


def _esik_karari(kesir: Optional[Fraction], program_sayisi: int, tutar: bool) -> str:
    if kesir is None or program_sayisi < EN_AZ_PROGRAM:
        return KARAR_YETERSIZ
    return KARAR_TUTUYOR if tutar else KARAR_TUTMUYOR


def kol_kararlari(birimler: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Bir kolun kendi başına okunan iki kararı (ön kayıt taslağı §7 a ve b).

    (a) fonksiyon adlarının yanlış oranı: program düzeyi makro ≤ ``YANLIS_HEDEFI``;
    (b) "kesin" etiketli adların kesinliği: program düzeyi makro ≥ ``KESIN_ETIKET_ESIGI``.
    Karşılaştırma kesirlerle yapılır. Giren program sayısı ``EN_AZ_PROGRAM``'ın altındaysa
    ``yetersiz``. Wilson üst sınırı eşiğin altında kalan birimler (b)'de ayrıca listelenir.
    """
    yanlis = {b: v["ozet"]["fonksiyon"]["yanlis_orani"] for b, v in birimler.items()}
    ort, prog, _, _ = makro_kesri(yanlis)
    a = {"olcu": "yanlis_orani", "esik": YANLIS_HEDEFI, **program_makrosu(yanlis),
         "karar": _esik_karari(ort, len(prog), ort is not None and ort <= Fraction(str(YANLIS_HEDEFI)))}
    kesin = {b: (v["ozet"]["etiket"].get(ETIKET_KESIN) or bos_olcu(v["nufus"]))["kesinlik"]
             for b, v in birimler.items()}
    ort, prog, giren, _ = makro_kesri(kesin)
    b_ = {"olcu": "kesinlik", "etiket": ETIKET_KESIN, "esik": KESIN_ETIKET_ESIGI, **program_makrosu(kesin),
          "wilson_ihlali": sorted(b for b in giren if kesin[b]["aralik"][1] < KESIN_ETIKET_ESIGI),
          "karar": _esik_karari(ort, len(prog),
                                ort is not None and ort >= Fraction(str(KESIN_ETIKET_ESIGI)))}
    return {"yanlis_orani": a, "kesin_etiket": b_}


# --------------------------------------------------------------------------------------------
# Bir kolun ölçümü


def oge_yaz(k: dict[str, Any]) -> str:
    """Öğe düzeyi kayıt, adsız: durum, satır, nüfusta mı, etiket, kanal."""
    return OGE_AYRACI.join((k["durum"], k["satir"], str(int(k["nufusta"])), k["etiket"], k["kanal"]))


def oge_oku(metin: str) -> dict[str, Any]:
    durum, satir, nufusta, etiket, kanal = metin.split(OGE_AYRACI)
    return {"durum": durum, "satir": satir, "nufusta": nufusta == "1", "etiket": etiket, "kanal": kanal}


def ghidra_surumleri(elfler: Iterable[Any]) -> dict[str, int]:
    """Koşu raporlarındaki Ghidra sürümü → ikili sayısı (rapor yoksa ``bilinmiyor``)."""
    sayac: Counter = Counter()
    for e in elfler:
        try:
            g = (_json(Path(e.kosu) / RAPOR_REL).get("environment") or {}).get("ghidra") or {}
        except (OSError, ValueError):
            g = {}
        sayac[str(g.get("version") or "bilinmiyor")] += 1
    return dict(sorted(sayac.items()))


def ayni_dosyalar(birimler: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Aynı sha256'lı dosyayı gösteren ikililer (ayrı ikili sayılır; burada yalnız listelenir)."""
    gruplar: dict[str, list[str]] = {}
    for b, v in birimler.items():
        for ad, kunye in v["elfler"].items():
            if kunye.get("dosya_sha256"):
                gruplar.setdefault(kunye["dosya_sha256"], []).append(f"{b}/{ad}")
    return sorted(sorted(g) for g in gruplar.values() if len(g) > 1)


def olc(elfler: list[Any], mac_veri: Optional[Path], indir: Optional[Path],
        beklenen: Optional[dict[str, int]] = ks1.BEKLENEN_ELF, eksik_izinli: bool = False,
        kol: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Bir kolun ölçümü. Eksik ya da bitmemiş koşu varsa durur (``eksik_izinli`` değilse)."""
    elfler = haritasizlari_isaretle(elfler)
    nufus_kunyesi = ks1.nufus_denetle(elfler, beklenen, eksik_izinli)
    biten = [e for e in elfler if e.static is not None]
    siniflar = ks1.sinif(biten)["birimler"]
    ham: dict[str, dict[str, Any]] = {}
    kimlikler: Counter = Counter()
    for e in biten:
        b = ham.setdefault(ks1.birim_anahtari(e), {
            "kayitlar": [], "nufus": 0, "sayac": Counter(), "elfler": {}, "cpp_disarida": [], "ogeler": {}})
        fonk = _json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        if ks1.cpp_ikili_mi(fonk, e.platform):
            b["cpp_disarida"].append(e.ad)     # C++: tam eşitlik tanımsız (ks1_olc ile aynı kural)
            continue
        genel, koken, kimlik = haritayi_oku(e.kosu)
        kimlikler[json.dumps(kimlik, ensure_ascii=False, sort_keys=True)] += 1
        gt = ks1.gt_mac(e, mac_veri) if e.platform == ks1.PLATFORM_MAC else ks1.gt_elf(e, indir)
        gfonk = ks1._f1().load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
        kayitlar, sayac = degerlendir_elf(genel, koken, gfonk, gt, e.platform)
        b["kayitlar"].extend(kayitlar)
        b["nufus"] += len(gt.nufus)
        b["sayac"].update(sayac)
        b["ogeler"][e.ad] = {f"{k['adres']:x}": oge_yaz(k) for k in kayitlar}
        b["elfler"][e.ad] = {
            "ad_verilen": len(kayitlar), "dogru": sum(1 for k in kayitlar if k["durum"] == DOGRU),
            "nufus": len(gt.nufus), "dosya_sha256": _json(Path(e.kosu) / HEDEF_REL).get("file_hash"),
            "harita_sha256": ks1.sha256_dosya(harita_yolu(e)), "kunye": gt.kunye}
    birimler = {}
    for k, b in sorted(ham.items()):
        s = siniflar.get(k) or {}
        birimler[k] = {
            "sinif": {a: s.get(a) for a in TABAKA_ALANLARI + ("dizgi_zenginligi", "ic_fonksiyon_ortanca")},
            "nufus": b["nufus"], "ozet": birim_ozeti(b["kayitlar"], b["nufus"]),
            "anahtar_sayaci": dict(sorted(b["sayac"].items())), "cpp_disarida": sorted(b["cpp_disarida"]),
            "elfler": dict(sorted(b["elfler"].items()))}
    return {"sema": SEMA, "komut": "olc", "kol": kol or {},
            "arac": {"betik_sha256": ks1.sha256_dosya(OLC_YOLU), "ks1_olc_sha256": ks1.sha256_dosya(KS1_YOLU),
                     "git_head": ks1._git("rev-parse", "HEAD").stdout.strip(),
                     "python": platform.python_version(), "ghidra_surumleri": ghidra_surumleri(biten)},
            "secimler": {"n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM, "yanlis_hedefi": YANLIS_HEDEFI,
                         "kesin_etiket_esigi": KESIN_ETIKET_ESIGI,
                         "kayip_inceleme_siniri": KAYIP_INCELEME_SINIRI},
            "nufus": nufus_kunyesi, "kol_kimligi": dict(sorted(kimlikler.items())),
            "ayni_dosyalar": ayni_dosyalar(birimler),
            "birimler": birimler, "toplam": toplam_ozeti(birimler), "tabaka": tabaka_ozeti(birimler),
            "etiket_kanal": etiket_kanal_tablosu(k for b in ham.values() for k in b["kayitlar"]),
            "kararlar": kol_kararlari(birimler),
            "ogeler": {k: dict(sorted(b["ogeler"].items())) for k, b in sorted(ham.items())}}


# --------------------------------------------------------------------------------------------
# İki kolun karşılaştırması


def _ogeler(olcum: dict[str, Any], birim: str, elf: str) -> dict[str, dict[str, Any]]:
    return {a: oge_oku(m) for a, m in ((olcum["ogeler"].get(birim) or {}).get(elf) or {}).items()}


def ozet_tutarliligi(olcum: dict[str, Any], kol: str) -> None:
    """Öğe listesi birim özetiyle aynı sayıları vermeli (elle düzenlenmiş dosyaya karşı)."""
    for b, v in olcum["birimler"].items():
        ogeler = [oge_oku(m) for elf in (olcum["ogeler"].get(b) or {}).values() for m in elf.values()]
        f = v["ozet"]["fonksiyon"]
        if (len(ogeler), sum(1 for o in ogeler if o["durum"] == DOGRU)) != (f["ad_verilen"], f["dogru"]):
            raise OnkosulHatasi(f"{kol} kolu, {b}: öğe listesi özetle tutmuyor")


def birim_farki(taban: dict[str, Any], yeni: dict[str, Any], birim: str, elfler: list[str]) -> dict[str, Any]:
    """Bir birimin ortak ikililerinde geçiş tablosu ve farklar (adresle eşleme)."""
    gecis: Counter = Counter()
    kayip_kanali: Counter = Counter()
    kazanc_kanali: Counter = Counter()
    for elf in elfler:
        t, y = _ogeler(taban, birim, elf), _ogeler(yeni, birim, elf)
        for adres in sorted(set(t) | set(y)):
            td = t[adres]["durum"] if adres in t else ADSIZ
            yd = y[adres]["durum"] if adres in y else ADSIZ
            gecis[(td, yd)] += 1
            if td == DOGRU and yd != DOGRU:
                kayip_kanali[t[adres]["kanal"]] += 1
            if yd == DOGRU and td != DOGRU:
                kazanc_kanali[y[adres]["kanal"]] += 1

    def say_(kol: str, durum: str) -> int:
        return sum(n for (td, yd), n in gecis.items() if (td if kol == "taban" else yd) == durum)

    kollar = {}
    for kol in ("taban", "yeni"):
        dogru, yanlis = say_(kol, DOGRU), say_(kol, YANLIS)
        kollar[kol] = {"ad_verilen": dogru + yanlis, "dogru": dogru, "yanlis": yanlis,
                       "yanlis_orani": ks1.oran(yanlis, dogru + yanlis)}
    silinen, bozulan = gecis[(DOGRU, ADSIZ)], gecis[(DOGRU, YANLIS)]
    return {**kollar,
            "gecis": {f"{td}>{yd}": gecis[(td, yd)] for td in DURUMLAR for yd in DURUMLAR
                      if (td, yd) != (ADSIZ, ADSIZ)},
            "kaybedilen_dogru": silinen + bozulan, "kaybedilen_silinen": silinen,
            "kaybedilen_yanlisa_donen": bozulan,
            "kazanilan_dogru": gecis[(ADSIZ, DOGRU)] + gecis[(YANLIS, DOGRU)],
            "giderilen_yanlis": gecis[(YANLIS, ADSIZ)] + gecis[(YANLIS, DOGRU)],
            "yeni_yanlis": gecis[(ADSIZ, YANLIS)] + gecis[(DOGRU, YANLIS)],
            "kayip_orani": ks1.oran(silinen + bozulan, kollar["taban"]["dogru"]),
            "kayip_kanali": dict(sorted(kayip_kanali.items())),
            "kazanc_kanali": dict(sorted(kazanc_kanali.items()))}


FARK_SAYILARI = ("kaybedilen_dogru", "kaybedilen_silinen", "kaybedilen_yanlisa_donen", "kazanilan_dogru",
                 "giderilen_yanlis", "yeni_yanlis")


def karsilastir(taban: dict[str, Any], yeni: dict[str, Any], eksik_izinli: bool = False) -> dict[str, Any]:
    """İki kolun yan yana tablosu. İki kol aynı ikilileri (sha256) ölçmüş olmalı; yalnız bir kolda
    bulunan ya da dosyası farklı ikili varsa durur (``eksik_izinli`` ile o ikililer dışarıda kalır)."""
    for kol, o in (("taban", taban), ("yeni", yeni)):
        if o.get("sema") != SEMA or o.get("komut") != "olc":
            raise OnkosulHatasi(f"{kol} kolu bir 'olc' çıktısı değil (şema {o.get('sema')!r})")
        ozet_tutarliligi(o, kol)
    sorun, birimler = [], {}
    for b in sorted(set(taban["birimler"]) | set(yeni["birimler"])):
        te = (taban["birimler"].get(b) or {}).get("elfler") or {}
        ye = (yeni["birimler"].get(b) or {}).get("elfler") or {}
        ortak = []
        for elf in sorted(set(te) | set(ye)):
            if elf not in te or elf not in ye:
                sorun.append(f"{b}/{elf}: yalnız {'taban' if elf in te else 'yeni'} kolda")
            elif te[elf].get("dosya_sha256") != ye[elf].get("dosya_sha256"):
                sorun.append(f"{b}/{elf}: iki kolda dosya sha256'sı farklı")
            else:
                ortak.append(elf)
        if ortak:
            birimler[b] = {"elf": len(ortak),
                           "nufus": {"taban": sum(te[e]["nufus"] for e in ortak),
                                     "yeni": sum(ye[e]["nufus"] for e in ortak)},
                           **birim_farki(taban, yeni, b, ortak)}
    if sorun and not eksik_izinli:
        raise OnkosulHatasi("kollar aynı ikilileri ölçmemiş: " + "; ".join(sorun[:8]))
    toplam: dict[str, Any] = {a: sum(v[a] for v in birimler.values()) for a in FARK_SAYILARI}
    for kol in ("taban", "yeni"):
        dogru = sum(v[kol]["dogru"] for v in birimler.values())
        yanlis = sum(v[kol]["yanlis"] for v in birimler.values())
        toplam[kol] = {"ad_verilen": dogru + yanlis, "dogru": dogru, "yanlis": yanlis,
                       "yanlis_orani": ks1.oran(yanlis, dogru + yanlis)}
    for alan in ("kayip_kanali", "kazanc_kanali"):
        sayac: Counter = Counter()
        for v in birimler.values():
            sayac.update(v[alan])
        toplam[alan] = dict(sorted(sayac.items()))
    kayip = {b: v["kayip_orani"] for b, v in birimler.items()}
    toplam["kayip_orani"] = {"havuz": ks1.oran(toplam["kaybedilen_dogru"], toplam["taban"]["dogru"]),
                             "makro": program_makrosu(kayip)}
    havuz_kaybi = toplam["kayip_orani"]["havuz"]
    asan = sorted(b for b, o in kayip.items()
                  if o["n"] >= N_MIN and Fraction(o["k"], o["n"]) > Fraction(str(KAYIP_INCELEME_SINIRI)))
    # (c) inceleme: havuz sınırı aşıyor ya da tabanda en az N_MIN doğru adı olan bir birim aşıyor
    if havuz_kaybi["n"] == 0:
        kayip_karari = KARAR_YETERSIZ
    elif asan or Fraction(havuz_kaybi["k"], havuz_kaybi["n"]) > Fraction(str(KAYIP_INCELEME_SINIRI)):
        kayip_karari = KARAR_INCELE
    else:
        kayip_karari = KARAR_BEKLENEN
    # Yön: iki kolda da en az N_MIN ad verilen her birimde yeni kolun yanlış oranı tabanınkinden düşük mü
    karsilastirilan = sorted(b for b, v in birimler.items()
                             if min(v["taban"]["ad_verilen"], v["yeni"]["ad_verilen"]) >= N_MIN)
    dusmeyen = [b for b in karsilastirilan
                if Fraction(birimler[b]["yeni"]["yanlis"], birimler[b]["yeni"]["ad_verilen"])
                >= Fraction(birimler[b]["taban"]["yanlis"], birimler[b]["taban"]["ad_verilen"])]
    yon = {"karsilastirilan_birimler": karsilastirilan, "dusmeyen_birimler": dusmeyen,
           "karar": KARAR_YETERSIZ if not karsilastirilan else (KARAR_INCELE if dusmeyen else KARAR_BEKLENEN)}
    return {"sema": KARSILASTIR_SEMA, "komut": "karsilastir",
            "kollar": {kol: {"kol": o.get("kol"), "arac": o.get("arac"), "kol_kimligi": o.get("kol_kimligi"),
                             "toplam": o["toplam"]["fonksiyon"],
                             "kesin_etiket": (o["toplam"]["etiket"].get(ETIKET_KESIN) or {}),
                             "kararlar": o.get("kararlar")}
                       for kol, o in (("taban", taban), ("yeni", yeni))},
            "ghidra_ayni": taban["arac"].get("ghidra_surumleri") == yeni["arac"].get("ghidra_surumleri"),
            "sorunlar": sorun, "eksik_izinli": eksik_izinli,
            "birimler": birimler, "toplam": toplam,
            "kararlar": {"kaybedilen_dogru": {"sinir": KAYIP_INCELEME_SINIRI, "havuz": havuz_kaybi,
                                             "siniri_asan_birimler": asan, "karar": kayip_karari},
                         "yanlis_yonu": yon}}


# --------------------------------------------------------------------------------------------
# Markdown


yuzde = ks1.yuzde


def _o(o: Optional[dict[str, Any]]) -> str:
    """``k/n (%x; alt-üst)``; payda sıfırsa ``—``."""
    if not o or not o["n"]:
        return "—"
    return f"{o['k']}/{o['n']} ({yuzde(o['oran'])}; {yuzde(o['aralik'][0])}-{yuzde(o['aralik'][1])})"


def _y(o: Optional[dict[str, Any]]) -> str:
    return "—" if not o or not o["n"] else yuzde(o["oran"])


def birim_sirasi(birimler: dict[str, dict[str, Any]]) -> list[str]:
    """Küçükten büyüğe: boyut tabakası, sonra iç fonksiyon ortancası, sonra ad."""
    def anahtar(b: str) -> tuple[int, float, str]:
        s = birimler[b]["sinif"]
        tabaka = s.get("boyut_tabakasi")
        return (BOYUT_SIRASI.index(tabaka) if tabaka in BOYUT_SIRASI else len(BOYUT_SIRASI),
                float(s.get("ic_fonksiyon_ortanca") or 0), b)
    return sorted(birimler, key=anahtar)


def _olcu_satiri(o: dict[str, Any]) -> str:
    return (f"{o['ad_verilen']} | {o['dogru']} | {o['yanlis']} | {_o(o['kesinlik'])} | "
            f"{_o(o['yanlis_orani'])} | {_o(o['kapsam'])} | {_o(o['dogru_kapsam'])}")


OLCU_BASLIGI = ("Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | "
                "Tam ad kapsamı (%95)")
OLCU_CIZGISI = "---|---|---|---|---|---|---"


def _makro_satiri(makro: dict[str, Any]) -> str:
    return " | ".join(yuzde(makro[a]["makro"]) for a in KARAR_OLCULERI)


def olc_markdown(s: dict[str, Any]) -> str:
    """Bir kolun özeti. Ad içermez."""
    kol, arac, t = s.get("kol") or {}, s["arac"], s["toplam"]
    f = t["fonksiyon"]
    sat = [f"# Ürün adlarının ölçümü: {kol.get('ad') or 'kol'}", "",
           f"- Kökler: Debian `{kol.get('kok_debian') or '—'}`, Mac `{kol.get('kok_mac') or '—'}`.",
           f"- `urun_olc.py` sha256 `{arac['betik_sha256'][:16]}…`; `ks1_olc.py` sha256 "
           f"`{arac['ks1_olc_sha256'][:16]}…`; HEAD `{arac['git_head'][:7]}`; Ghidra "
           f"{', '.join(f'{k} ({v} ikili)' for k, v in arac['ghidra_surumleri'].items()) or '—'}.",
           f"- İkililer: {sum(s['nufus']['biten'].values())} bitti; sorunlar: "
           f"{'; '.join(s['nufus']['sorunlar']) or 'yok'}.",
           "- Kol kimliği (köken kaydından; C++ dışı ikili sayısı): "
           + ("; ".join(f"`{k}` × {v}" for k, v in s["kol_kimligi"].items()) or "—") + ".",
           "- Hüküm tam eşitliktir (Mach-O'da baştaki tek `_` soyulur; klon ekli GT'de taban eşitliği; "
           "GT'de karşılığı olmayan ad yanlış). Sayım örnek düzeyindedir (ikili başına ad). "
           "Bu belgede fonksiyon adı geçmez.", "",
           "## Toplam (fonksiyon adları)", "",
           f"| | {OLCU_BASLIGI} |", f"|---|{OLCU_CIZGISI}|",
           f"| Havuz | {_olcu_satiri(f['havuz'])} |", "",
           "| Program düzeyi makro | Kesinlik | Yanlış oranı | Kapsam | Tam ad kapsamı |", "|---|---|---|---|---|",
           f"| Bütün birimler | {_makro_satiri(f['makro'])} |", "",
           f"Makroya paydası ≥ {s['secimler']['n_min']} olan birimler girer; aynı programın platform "
           "birimleri önce ortalanır. Duyarlılık (karar dışı), havuz: yalnız ad bekleyen nüfustaki adların "
           f"kesinliği {_o(f['havuz']['nufus_ici_kesinlik'])}; proje normalleştirmesiyle doğru "
           f"{_o(f['havuz']['proje_normallestirmesi'])}; tekil adla kesinlik "
           f"{_o(f['havuz']['tekil_kesinlik'])}.", "",
           "## Kararlar (bu kol tek başına)", "",
           "| Karar | Ölçü | Makro | Eşik | Giren programlar | Küçük birimler | Sonuç |",
           "|---|---|---|---|---|---|---|"]
    ka, kb = s["kararlar"]["yanlis_orani"], s["kararlar"]["kesin_etiket"]
    sat.append(f"| (a) yanlış ad oranı | yanlış / ad verilen | {yuzde(ka['makro'])} | ≤ {yuzde(ka['esik'])} | "
               f"{', '.join(ka['program']) or '—'} | {', '.join(ka['kucuk_birimler']) or '—'} | `{ka['karar']}` |")
    sat.append(f"| (b) \"kesin\" etiketli adlar | doğru / \"kesin\" etiketli | {yuzde(kb['makro'])} | "
               f"≥ {yuzde(kb['esik'])} | {', '.join(kb['program']) or '—'} | "
               f"{', '.join(kb['kucuk_birimler']) or '—'} | `{kb['karar']}` |")
    sat += ["", "## Birim başına (küçükten büyüğe)", "",
            f"| Birim | İkili | Boyut | Zenginlik | Ad bekleyen | {OLCU_BASLIGI} | Nüfus içi kesinlik | "
            "Proje norm. | Klon (doğru/n) | Eşlenemeyen |",
            f"|---|---|---|---|---|{OLCU_CIZGISI}|---|---|---|---|"]
    for b in birim_sirasi(s["birimler"]):
        v = s["birimler"][b]
        o, sn = v["ozet"]["fonksiyon"], v["sinif"]
        sat.append(f"| {b} | {len(v['elfler'])} | `{sn.get('boyut_tabakasi')}` | `{sn.get('zenginlik_sinifi')}` | "
                   f"{v['nufus']} | {_olcu_satiri(o)} | {_y(o['nufus_ici_kesinlik'])} | "
                   f"{_y(o['proje_normallestirmesi'])} | {o['satir'][ks1.SATIR_KLON]['dogru']}/"
                   f"{o['satir'][ks1.SATIR_KLON]['n']} | {o['satir'][ks1.SATIR_ESLENEMEDI]['n']} |")
    for alan, baslik in (("etiket", "Etiket"), ("kanal", "Kanal"), ("kanal_grubu", "Kanal grubu")):
        sat += ["", f"## {baslik} başına (havuz ve program düzeyi makro)", ""]
        if alan == "kanal_grubu":
            sat += ["`susan`: ürünün karar tablosunda susan `string_context` alt kanalları; `kalan`: öbür "
                    "bütün kanallar. Susturması kapalı bir kolda `kalan` satırı, susturmanın tek başına "
                    "bırakacağı adların öngörüsüdür (KS-1'in ekleyeceği adlar ve halefler dışında).", ""]
        sat += [f"| {baslik} | {OLCU_BASLIGI} | Makro kesinlik | Makro yanlış | Makro kapsam |",
                f"|---|{OLCU_CIZGISI}|---|---|---|"]
        for d, v in t[alan].items():
            sat.append(f"| `{d}` | {_olcu_satiri(v['havuz'])} | {yuzde(v['makro']['kesinlik']['makro'])} | "
                       f"{yuzde(v['makro']['yanlis_orani']['makro'])} | {yuzde(v['makro']['kapsam']['makro'])} |")
    sat += ["", "## Etiket × kanal (havuz)", "", "| Etiket | Kanal | Ad verilen | Doğru |", "|---|---|---|---|"]
    for etiket, kanallar in s["etiket_kanal"].items():
        for kanal, h in kanallar.items():
            sat.append(f"| `{etiket}` | `{kanal}` | {h['ad_verilen']} | {h['dogru']} |")
    for alan, baslik in (("etiket", "Etiket"), ("kanal_grubu", "Kanal grubu")):
        sat += ["", f"## Birim × {baslik.lower()}", "", f"| Birim | {baslik} | {OLCU_BASLIGI} |",
                f"|---|---|{OLCU_CIZGISI}|"]
        for b in birim_sirasi(s["birimler"]):
            for d, o in s["birimler"][b]["ozet"][alan].items():
                sat.append(f"| {b} | `{d}` | {_olcu_satiri(o)} |")
    for alan, baslik in (("boyut_tabakasi", "Boyut tabakası"), ("zenginlik_sinifi", "Zenginlik sınıfı")):
        sat += ["", f"## {baslik} başına", "",
                f"| {baslik} | Birimler | {OLCU_BASLIGI} | Makro kesinlik | Makro yanlış | Makro kapsam | "
                "Makro tam ad kapsamı |", f"|---|---|{OLCU_CIZGISI}|---|---|---|---|"]
        degerler = s["tabaka"][alan]
        sira = [d for d in BOYUT_SIRASI if d in degerler] + sorted(d for d in degerler if d not in BOYUT_SIRASI)
        for d in sira:
            v = degerler[d]
            sat.append(f"| `{d}` | {', '.join(v['birimler'])} | {_olcu_satiri(v['havuz'])} | "
                       f"{_makro_satiri(v['makro'])} |")
    sat += ["", "## Anahtar sayımı (ad haritasının `global` girişleri)", "",
            "| Birim | `FUN_` anahtarı | Ölçülen ad | " + " | ".join(f"`{a}`" for a in ATLAMALAR)
            + " | Veri anahtarı | Veri adı | Öbür anahtar | Alt kanal: kayıttan / sonradan / uyuşmuyor |",
            "|---|---|---|" + "---|" * len(ATLAMALAR) + "---|---|---|---|"]
    for b in birim_sirasi(s["birimler"]):
        v = s["birimler"][b]
        c = v["anahtar_sayaci"]
        sat.append(f"| {b} | {c.get('fonksiyon_anahtari', 0)} | {v['ozet']['fonksiyon']['ad_verilen']} | "
                   + " | ".join(str(c.get(a, 0)) for a in ATLAMALAR)
                   + f" | {c.get('veri_anahtari', 0)} | {c.get('veri_ad_verilen', 0)} | "
                   f"{c.get('diger_anahtari', 0)} | {c.get('alt_kanal_' + ALT_KANAL_KAYITTAN, 0)} / "
                   f"{c.get('alt_kanal_' + ALT_KANAL_SONRADAN, 0)} / {c.get('alt_kanal_' + ALT_KANAL_UYUSMUYOR, 0)} |")
    cpp = [f"{b}: {', '.join(v['cpp_disarida'])}" for b, v in s["birimler"].items() if v["cpp_disarida"]]
    if cpp:
        sat += ["", "C++ (ölçü dışı): " + "; ".join(cpp) + "."]
    if s["ayni_dosyalar"]:
        sat += ["", "Aynı dosyayı gösteren ikililer (ayrı sayıldı): "
                + "; ".join(" = ".join(g) for g in s["ayni_dosyalar"]) + "."]
    return "\n".join(sat) + "\n"


def karsilastir_markdown(s: dict[str, Any]) -> str:
    """İki kolun yan yana özeti. Ad içermez."""
    t = s["toplam"]
    sat = ["# Ürün adlarının ölçümü: taban ve yeni kol", ""]
    for kol in ("taban", "yeni"):
        k = s["kollar"][kol]
        kimlik = "; ".join(f"`{a}` × {n}" for a, n in (k["kol_kimligi"] or {}).items()) or "—"
        sat.append(f"- {kol}: `{(k['kol'] or {}).get('ad') or '—'}`; "
                   f"HEAD `{(k['arac'] or {}).get('git_head', '')[:7]}`; kol kimliği {kimlik}.")
    sat += [f"- Ghidra sürümleri iki kolda aynı: {'evet' if s['ghidra_ayni'] else 'HAYIR'}; "
            f"eşleme sorunları: {'; '.join(s['sorunlar']) or 'yok'}.",
            "- Öğeler birim, ikili ve adresle eşlenir. Bu belgede fonksiyon adı geçmez.", "",
            "## Yan yana (fonksiyon adları)", "",
            f"| Kol | {OLCU_BASLIGI} | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |",
            f"|---|{OLCU_CIZGISI}|---|---|---|---|"]
    for kol in ("taban", "yeni"):
        f = s["kollar"][kol]["toplam"]
        sat.append(f"| {kol} | {_olcu_satiri(f['havuz'])} | {_makro_satiri(f['makro'])} |")
    sat += ["", "| Kol | \"kesin\" etiketli ad | Doğru | Kesinlik (havuz) | Makro kesinlik | Kapsam (havuz) |",
            "|---|---|---|---|---|---|"]
    for kol in ("taban", "yeni"):
        e = s["kollar"][kol]["kesin_etiket"]
        if not e:
            sat.append(f"| {kol} | 0 | 0 | — | — | — |")
            continue
        h = e["havuz"]
        sat.append(f"| {kol} | {h['ad_verilen']} | {h['dogru']} | {_o(h['kesinlik'])} | "
                   f"{yuzde(e['makro']['kesinlik']['makro'])} | {_o(h['kapsam'])} |")
    sat += ["", "## Kararlar", "", "| Karar | Taban | Yeni |", "|---|---|---|"]
    for anahtar, baslik in (("yanlis_orani", "(a) yanlış ad oranı (makro)"),
                            ("kesin_etiket", "(b) \"kesin\" etiketli adların kesinliği (makro)")):
        hucre = []
        for kol in ("taban", "yeni"):
            k = (s["kollar"][kol]["kararlar"] or {}).get(anahtar) or {}
            hucre.append(f"{yuzde(k.get('makro'))} → `{k.get('karar', '—')}`")
        sat.append(f"| {baslik} | {hucre[0]} | {hucre[1]} |")
    kd, yon = s["kararlar"]["kaybedilen_dogru"], s["kararlar"]["yanlis_yonu"]
    sat += ["", f"(c) Kaybedilen doğru ad (havuz): {_o(kd['havuz'])}; sınır > {yuzde(kd['sinir'])} → "
            f"`{kd['karar']}`. Sınırı aşan birimler: {', '.join(kd['siniri_asan_birimler']) or 'yok'}. "
            f"Program düzeyi makro: {yuzde(t['kayip_orani']['makro']['makro'])}.", "",
            f"Yön: iki kolda da en az {N_MIN} ad verilen birimlerde "
            f"({', '.join(yon['karsilastirilan_birimler']) or '—'}) yeni kolun yanlış oranı tabanınkinden "
            f"düşük olmayanlar: {', '.join(yon['dusmeyen_birimler']) or 'yok'} → `{yon['karar']}`.", "",
            "## Birim başına farklar", "",
            "| Birim | İkili | Taban: ad / doğru / yanlış | Yeni: ad / doğru / yanlış | "
            "Yanlış oranı taban → yeni | "
            "Kaybedilen doğru (silinen + yanlışa dönen) | Kayıp oranı | Kazanılan doğru | Giderilen yanlış | "
            "Yeni yanlış |", "|---|---|---|---|---|---|---|---|---|---|"]

    def satir(ad: str, elf: Any, v: dict[str, Any], kayip: Optional[dict[str, Any]]) -> str:
        a, y = v["taban"], v["yeni"]
        return (f"| {ad} | {elf} | {a['ad_verilen']} / {a['dogru']} / {a['yanlis']} | "
                f"{y['ad_verilen']} / {y['dogru']} / {y['yanlis']} | {_y(a['yanlis_orani'])} → "
                f"{_y(y['yanlis_orani'])} | {v['kaybedilen_dogru']} ({v['kaybedilen_silinen']} + "
                f"{v['kaybedilen_yanlisa_donen']}) | {_o(kayip)} | {v['kazanilan_dogru']} | "
                f"{v['giderilen_yanlis']} | {v['yeni_yanlis']} |")

    for b, v in s["birimler"].items():
        sat.append(satir(b, v["elf"], v, v["kayip_orani"]))
    sat.append(satir("**Toplam**", sum(v["elf"] for v in s["birimler"].values()), t, t["kayip_orani"]["havuz"]))
    sat += ["", "## Kaybedilen ve kazanılan doğru adların kanalı", "",
            "| Yön | Kanal | Ad |", "|---|---|---|"]
    for alan, yon in (("kayip_kanali", "kaybedilen (taban kanalı)"), ("kazanc_kanali", "kazanılan (yeni kanalı)")):
        for kanal, n in t[alan].items():
            sat.append(f"| {yon} | `{kanal}` | {n} |")
    return "\n".join(sat) + "\n"


# --------------------------------------------------------------------------------------------
# CLI


def _yaz(yol: Path, belge: dict[str, Any]) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    o = sub.add_parser("olc", help="bir kolun (koşu kökünün) ölçümü")
    o.add_argument("--kok-debian", type=Path, default=None,
                   help="<kök>/<program>/<elf>/ws/… (BITTI dosyalı koşular)")
    o.add_argument("--kok-mac", type=Path, default=None, help="<kök>/<program>/ws/…")
    o.add_argument("--mac-veri", type=Path, default=REPO / "workspaces" / "olcum_mac",
                   help="Mac GT'sinin veri dizini (macho_measure)")
    o.add_argument("--debian-indir", type=Path,
                   default=Path.home() / "karadul_olcum" / "downloads" / "debian13",
                   help="Debian dbgsym paketlerinin açıldığı dizin")
    o.add_argument("--kol", default=None, help="kolun adı (ör. taban, yeni); çıktıya yazılır")
    o.add_argument("--eksik-izinli", action="store_true",
                   help="eksik ya da bitmemiş koşu varken de ölç (eksikler çıktıda listelenir)")
    k = sub.add_parser("karsilastir", help="iki kolun yan yana tablosu ve farklar")
    k.add_argument("--taban", type=Path, required=True)
    k.add_argument("--yeni", type=Path, required=True)
    k.add_argument("--eksik-izinli", action="store_true",
                   help="yalnız bir kolda bulunan ya da dosyası farklı ikilileri dışarıda bırakıp sür")
    for p in (o, k):
        p.add_argument("--json", type=Path, required=True)
        p.add_argument("--md", type=Path, default=None)
    a = ap.parse_args(argv)
    try:
        if a.komut == "olc":
            elfler = ks1.elfleri_topla(a.kok_mac, a.kok_debian)
            sonuc = olc(elfler, a.mac_veri, a.debian_indir, beklenen=ks1.BEKLENEN_ELF,
                        eksik_izinli=a.eksik_izinli,
                        kol={"ad": a.kol, "kok_debian": a.kok_debian and str(a.kok_debian),
                             "kok_mac": a.kok_mac and str(a.kok_mac)})
            metin = olc_markdown(sonuc)
        else:
            sonuc = karsilastir(_json(a.taban), _json(a.yeni), eksik_izinli=a.eksik_izinli)
            metin = karsilastir_markdown(sonuc)
    except (OnkosulHatasi, ValueError) as hata:
        print(f"DURDU: {hata}", file=sys.stderr)
        return 2
    _yaz(a.json, sonuc)
    if a.md:
        a.md.parent.mkdir(parents=True, exist_ok=True)
        a.md.write_text(metin, encoding="utf-8")
    print(f"{a.komut}: {len(sonuc['birimler'])} birim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
