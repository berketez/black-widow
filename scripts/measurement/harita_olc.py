#!/usr/bin/env python3
"""Harita ölçümü: ürünün modül ataması, fonksiyonların gerçek kaynak dosyası yapısıyla örtüşüyor mu?

Soru: ürün (``karadul/reconstruction/c_project_builder.py``) fonksiyonları alt sistem dizinlerine
ayırıyor. Bu ayrım, fonksiyonun derlendiği kaynak dosyayla (GT: DWARF'ta gövdenin derleme biriminin
kaynak dosyası) ne kadar örtüşüyor ve basit tabanları geçiyor mu? Ön kayıt taslağı:
``docs/arge/2026-11-11_harita/onkayit_taslak.md``.

İki taraf
---------
Ürün (adrese anahtarlı; ad kullanılmaz)
    ``<çalışma alanı>/reconstructed/project/src`` altındaki her ``.c`` dosyasında fonksiyon başlığının
    ``// Address:  <onaltılık>`` satırı. Modül = dosyanın ``src``'ye göre ilk dizini
    (``subsystem_<ad>``); ``src`` kökündeki dosya (``main.c``: giriş noktaları) ``.`` modülüdür.
    Birleşik dosyada (``thunks_and_stubs*.c``) her başlık ayrı fonksiyondur. Adres Ghidra'nın
    fonksiyon listesinde yoksa, birden çok modülde geçiyorsa ya da hiç geçmiyorsa fonksiyon ölçüye
    girmez; hepsi sayılır.
GT (yalnız ELF; dbgsym)
    Fonksiyon evreni ve adres eşlemesi ``ks1_olc.gt_elf``'ten (``.symtab`` fonksiyonları; ofset
    Ghidra'nın görüntü tabanından, sapma kaydı 1). Etiket: o adreste başlayan DWARF somut gövdesinin
    (``DW_AT_low_pc``'li ``DW_TAG_subprogram``) kaynak derleme birimi. Birim seçimi
    ``dwarf_tip.Cozucu``'nun kuralıdır: köken zincirinde (``abstract_origin`` / ``specification``) en
    derinden başlanır, adı olan ve ``<artificial>`` olmayan ilk ``DW_TAG_compile_unit`` alınır (LTO'da
    somut gövde yapay birimdedir; kaynak dosya kökenin birimidir). Etiketin değeri birimin kaynak
    dosyasının yoludur: DWARF 5 satır tablosunun 0. dosyası (derleme diziniyle birleşik, sadeleşmiş);
    yoksa ``DW_AT_name``. Aynı adlı iki birim (ör. iki ayrı dizinde aynı dosya adı) böylece ayrışır.
    Dizin etiketi yolun dizinidir. CRT fonksiyonları, gövdesi olmayan ve etiketleri çelişen adresler
    dışarıdadır; hepsi sayılır.
    Mach-O geliştirme ikililerinin GT'si (``nm``) yalnız ad ve adres taşır; derleme birimi bilgisi
    yoktur. Bu ikililer ölçülmez, nedeniyle listelenir.

Nüfus (ikili başına)
    Ürün modülü ve GT etiketi birlikte okunan fonksiyonlar. İkili bir düzeyde (dosya, dizin) ölçüye
    girer: nüfus ≥ ``ks1_olc.N_MIN``, GT'de en az iki sınıf ve aynı sınıfta en az bir çift varsa.

Ölçüler (ikili başına; düzey: ``dosya`` ve ``dizin``)
    - çift sayımlı kesinlik (aynı modüldeki fonksiyon çiftlerinden aynı kaynak dosyada olanların payı),
      duyarlılık (aynı kaynak dosyadaki çiftlerden aynı modülde olanların payı) ve F1;
    - düzeltilmiş Rand indeksi (ARI): çift uyumu, modül ve sınıf boyutları korunarak yapılan rastgele
      atamanın beklenen değeri çıkarılıp ölçeklenir (rastgele = 0, tam uyum = 1);
    - V-ölçüsü: türdeşlik (modül tek dosyadan mı), tamlık (dosya tek modülde mi), ikisinin harmonik
      ortalaması.
    Karar ölçüsü ARI'dir; öbürleri yön ve ölçek bilgisi verir.

Tabanlar (aynı nüfus, aynı GT)
    - ``b0``: ürünün modül etiketleri fonksiyonlar arasında rastgele karılır (boyutlar korunur);
      sabit tohumlu ``B0_PERMUTASYON`` karma; ortalama, ARI'nin 95. yüzdeliği ve permütasyon p değeri.
      Kapalı biçim beklenen değerler de yazılır (ARI 0; kesinlik = GT çift yoğunluğu).
    - ``b1``: fonksiyonlar adres sırasına dizilir, ürünün modül sayısı kadar bitişik ve eşit parçaya
      bölünür.
    - ``b1_gt`` (yalnız rapor): aynı bölme, parça sayısı GT sınıf sayısı (ürünün bilemeyeceği bilgi).
    - ``tek_modul`` ve ``hepsi_ayri``: yozlaşmış sınırlar.
    - ``urun_misc_tekil`` (yalnız rapor): ``subsystem_misc`` üyeleri tek başına modül sayılır.

Toplama
    İkili → birim (platform/program; giren ikililerin ortalaması) → program (aynı programın platform
    birimleri ortalanır) → programlar eşit ağırlıkla (makro). ``ks1_olc.py``'nin kuralı ve sabitleri.

Alt komutlar
------------
``kuru``
    GT'siz kuru koşu: iki tarafın AYRI AYRI okunabildiğini gösterir (ürün: fonksiyon, modül,
    atanamayan; GT: fonksiyon, etiketli, kaynak dosya, adres eşleme oranı; ortak nüfusun büyüklüğü).
    Modül ile GT etiketi çaprazlanmaz; hiçbir uyum sayısı hesaplanmaz.
``olc``
    Ölçüm. Ön kayıt (``onkayit.md``) commit'lenmeden ve ölçümü belirleyen dosyaların sha256'ları o
    commit'teki ``harita_sabitler.json`` ile aynı olmadan koşmaz.
``sabitle``
    ``harita_sabitler.json``'u bugünkü sha256'larla yazar (ön kayıt commit'inden önce).

Çıktılarda fonksiyon adı ve kaynak dosya adı yoktur: yalnız sayılar, modül adları (ürünün
``subsystem_…`` dizinleri) ve sıra numarasıyla kodlanmış sınıflar.

Kullanım
--------
    python scripts/measurement/harita_olc.py kuru --debian-kosu <kök>/debian --mac-kosu <kök>/mac \\
        --json <kuru.json> --md <kuru.md> [--eksik-izinli]
    python scripts/measurement/harita_olc.py olc --debian-kosu <kök>/debian --mac-kosu <kök>/mac \\
        --json <olcum.json> --md <olcum.md>
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import platform
import posixpath
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass, replace
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Hashable, Iterable, Optional, Sequence

SEMA = "karadul-harita-olc/1"
KURU_SEMA = "karadul-harita-kuru/1"
REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
OLC_YOLU = Path(__file__).resolve()
KS1_YOLU = _BURASI / "ks1_olc.py"
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)


def _ks1_yukle() -> ModuleType:
    """``ks1_olc.py``'yi dosya yolundan yükle (KS-1 ön kaydıyla sabit dosya; içe aktarılır, değişmez)."""
    spec = importlib.util.spec_from_file_location("ks1_olc", KS1_YOLU)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


ks1 = _ks1_yukle()

import dwarf_tip as dt  # noqa: E402

OnkosulHatasi = ks1.OnkosulHatasi

# ---- Ön kayıt ----
ONKAYIT_DIZINI = REPO / "docs" / "arge" / "2026-11-11_harita"
ONKAYIT_YOLU = ONKAYIT_DIZINI / "onkayit.md"
SABITLER_YOLU = ONKAYIT_DIZINI / "harita_sabitler.json"
# Ölçümün sonucunu belirleyen dosyalar (depo köküne göre): bu betik, GT ve adres eşlemesini veren
# yardımcılar. ``olc`` bunların sha256'sını ön kayıt commit'indekiyle karşılaştırır.
OLCUM_DOSYALARI = (
    "scripts/measurement/harita_olc.py",
    "scripts/measurement/ks1_olc.py",
    "scripts/measurement/dwarf_tip.py",
    "scripts/measurement/function_f1.py",
    "tests/benchmark/metrics.py",
)
SABIT_DOSYALAR = OLCUM_DOSYALARI + (
    "tests/test_harita_olc.py",
    "scripts/measurement/mutation_specs_harita_olc.json",
)

# ---- Ürün çıktısının yeri ve biçimi ----
PROJE_SRC_REL = Path("reconstructed") / "project" / "src"
# Fonksiyon başlığındaki adres satırı (``karadul/ghidra/headless.py`` yazar)
ADRES_BASLIGI_RE = re.compile(r"^// Address:\s+([0-9A-Fa-f]+)\s*$", re.MULTILINE)
KOK_MODUL = "."                       # ``src`` kökündeki dosyalar (``main.c``: giriş noktaları)
MISC_MODUL = "subsystem_misc"         # kurala ve topluluğa girmeyenler
TOPLULUK_RE = re.compile(r"^subsystem_group_\d+$")   # çağrı grafı topluluğu
MODUL_ONEKI = "subsystem_"
TUR_GIRIS = "giris"
TUR_TOPLULUK = "topluluk"
TUR_MISC = "misc"
TUR_KURAL = "kural"                   # API kuralı (network, file_io, memory, …)
TUR_DIGER = "diger"
MODUL_TURLERI = (TUR_GIRIS, TUR_KURAL, TUR_TOPLULUK, TUR_MISC, TUR_DIGER)

# ---- GT etiketi ----
YAPAY_BIRIM = "<artificial>"          # LTO'nun LTRANS birimi: kaynak dosya değil
GOVDE_ETIKETI = "DW_TAG_subprogram"
DERLEME_BIRIMI = "DW_TAG_compile_unit"
KOKEN_KENDI = "kendi"                 # etiket somut gövdenin kendi biriminden
KOKEN_KOKEN = "koken"                 # etiket köken zincirindeki birimden (LTO)
YOL_SATIR_TABLOSU = "satir_tablosu"   # DWARF 5 satır tablosunun 0. dosyası
YOL_AD = "ad"                         # yalnız ``DW_AT_name`` (derleme dizini bilinmiyor)
KOK_DIZIN = "."
MAC_GT_NEDENI = "mac_gt_derleme_birimi_tasimiyor"
GT_OKUNAMADI = "gt_okunamadi"         # yalnız kuru koşu: ikilinin GT'si okunurken ön koşul tutmadı

# ---- Ölçüler, tabanlar ve seçimler (ön kayıt taslağı §4-§7; eşikler [seçim]) ----
DUZEY_DOSYA = "dosya"
DUZEY_DIZIN = "dizin"
DUZEYLER = (DUZEY_DOSYA, DUZEY_DIZIN)
KARAR_DUZEYI = DUZEY_DOSYA
CIFT_OLCULERI = ("kesinlik", "duyarlilik", "f1", "ari")
V_OLCULERI = ("turdeslik", "tamlik", "v")
OLCU_ADLARI = CIFT_OLCULERI + V_OLCULERI
KARAR_OLCUSU = "ari"
SATIR_URUN = "urun"
SATIR_B0 = "b0"
SATIR_B1 = "b1"
SATIR_B1_GT = "b1_gt"
SATIR_TEK = "tek_modul"
SATIR_AYRI = "hepsi_ayri"
SATIR_MISC_TEKIL = "urun_misc_tekil"
SATIRLAR = (SATIR_URUN, SATIR_B0, SATIR_B1, SATIR_B1_GT, SATIR_TEK, SATIR_AYRI, SATIR_MISC_TEKIL)
N_MIN = ks1.N_MIN                     # ölçüye giren ikili: nüfusu en az bu kadar fonksiyon
EN_AZ_PROGRAM = ks1.EN_AZ_PROGRAM     # karar için giren en az farklı program
ONDALIK = ks1.ONDALIK
B0_PERMUTASYON = 200
B0_TOHUM_METNI = "karadul-harita-b0-2026-11-11"
B0_YUZDELIK = Fraction(95, 100)
FARK_ESIGI = Fraction(5, 100)         # ürün − B1 makro ARI farkı: bundan küçüğü "ayrışmıyor"
COGUNLUK = Fraction(2, 3)             # farkın yönünü taşıması gereken program payı
KARAR_URUN = "urun_gecer"
KARAR_TABAN = "taban_gecer"
KARAR_AYRISMIYOR = "ayrismiyor"
KARAR_YETERSIZ = "yetersiz"
KARAR_RASTGELEDEN_IYI = "rastgeleden_iyi"
KARAR_AYIRT_EDILEMIYOR = "rastgeleden_ayirt_edilemiyor"
NEDEN_KUCUK = "kucuk"                 # nüfus < N_MIN
NEDEN_TEK_SINIF = "gt_tek_sinif"      # GT'de tek sınıf: ayrım ölçülemez
NEDEN_HEPSI_AYRI = "gt_hepsi_ayri"    # GT'de aynı sınıfta hiç çift yok
NEDEN_YOL_AD = "yol_kaynagi_ad"       # etiketin yolu satır tablosundan okunamadı (bütünlük koşulu)


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# Ürün tarafı: adres → modül


@dataclass
class UrunTarafi:
    """Bir ikilinin modül ataması (adrese anahtarlı) ve okuma sayaçları."""

    modul: dict[int, str]             # tam olarak bir modülde yer alan Ghidra fonksiyonları
    sayac: dict[str, int]


def proje_src(kosu: Path) -> Path:
    return Path(kosu) / PROJE_SRC_REL


def dosya_modulu(goreli: Path) -> str:
    """``src``'ye göre yolun modülü: ilk dizin; kökteki dosya ``KOK_MODUL``."""
    return goreli.parts[0] if len(goreli.parts) > 1 else KOK_MODUL


def modul_turu(modul: str) -> str:
    if modul == KOK_MODUL:
        return TUR_GIRIS
    if TOPLULUK_RE.match(modul):
        return TUR_TOPLULUK
    if modul == MISC_MODUL:
        return TUR_MISC
    return TUR_KURAL if modul.startswith(MODUL_ONEKI) else TUR_DIGER


def urun_oku(kosu: Path, ghidra_adresleri: Iterable[int]) -> UrunTarafi:
    """Proje ağacından adres → modül. Ad kullanılmaz: anahtar başlıktaki adrestir.

    Sayaçlar: ``kaynak_dosya`` (okunan ``.c``), ``basliksiz_dosya`` (adres başlığı olmayan),
    ``baslik`` (başlık satırı), ``ghidra_fonksiyon``, ``atanan`` (tam bir modülde), ``atanamayan``
    (projede hiç geçmeyen Ghidra fonksiyonu), ``coklu_modul`` (birden çok modülde geçen),
    ``yinelenen`` (aynı modülde birden çok kez geçen; atanır), ``ghidra_disi`` (Ghidra'nın fonksiyon
    listesinde olmayan adres), ``modul`` (atanan fonksiyonların modül sayısı).
    """
    src = proje_src(kosu)
    if not src.is_dir():
        raise OnkosulHatasi(f"{src}: proje ağacı yok")
    ghidra = set(ghidra_adresleri)
    yerler: dict[int, list[str]] = {}
    sayac: Counter = Counter()
    for dosya in sorted(src.rglob("*.c")):
        sayac["kaynak_dosya"] += 1
        modul = dosya_modulu(dosya.relative_to(src))
        basliklar = ADRES_BASLIGI_RE.findall(dosya.read_text(encoding="utf-8", errors="replace"))
        if not basliklar:
            sayac["basliksiz_dosya"] += 1
        for metin in basliklar:
            sayac["baslik"] += 1
            yerler.setdefault(int(metin, 16), []).append(modul)
    atama: dict[int, str] = {}
    for adres, moduller in sorted(yerler.items()):
        if adres not in ghidra:
            sayac["ghidra_disi"] += 1
        elif len(set(moduller)) > 1:
            sayac["coklu_modul"] += 1
        else:
            atama[adres] = moduller[0]
            sayac["yinelenen"] += int(len(moduller) > 1)
    sayac["ghidra_fonksiyon"] = len(ghidra)
    sayac["atanan"] = len(atama)
    sayac["atanamayan"] = len(ghidra - set(yerler))
    sayac["modul"] = len(set(atama.values()))
    alanlar = ("kaynak_dosya", "basliksiz_dosya", "baslik", "ghidra_fonksiyon", "atanan", "atanamayan",
               "coklu_modul", "yinelenen", "ghidra_disi", "modul")
    return UrunTarafi(atama, {a: int(sayac.get(a, 0)) for a in alanlar})


def projesizleri_isaretle(elfler: Iterable[Any]) -> list[Any]:
    """Proje ağacı yazılmamış koşu bitmemiş sayılır (``static`` = None): Ghidra çıktısı olup proje
    kurulumu yarım kalan koşu ölçüme "modülsüz" diye girmesin."""
    return [e if e.static is None or proje_src(e.kosu).is_dir() else replace(e, static=None)
            for e in elfler]


# --------------------------------------------------------------------------------------------
# GT tarafı: adres → kaynak dosya


@dataclass(frozen=True)
class Govde:
    """DWARF somut gövdesi (``DW_AT_low_pc``'li ``DW_TAG_subprogram``) ve kaynak dosyası."""

    adres: int                        # dosya adresi
    yol: Optional[str]                # kaynak dosyanın yolu; birim seçilemediyse None
    koken: Optional[str]              # KOKEN_KENDI | KOKEN_KOKEN; etiketsizde None
    yol_kaynagi: Optional[str]        # YOL_SATIR_TABLOSU | YOL_AD


@dataclass
class GtTarafi:
    """Bir ELF'in GT etiketleri, Ghidra adres uzayında."""

    etiket: dict[int, str]            # adres → kaynak dosya yolu
    fonksiyon: set[int]               # CRT dışı GT fonksiyonlarının adresleri (etiketli olsun olmasın)
    sayac: dict[str, int]
    kunye: dict[str, Any]


def kaynak_birimi(c: Any, d: Any) -> tuple[Optional[tuple[str, int, str]], Optional[str]]:
    """Somut gövdenin kaynak derleme birimi: ((dosya rolü, birim ofseti, birim adı), köken).

    Kural ``dwarf_tip.Cozucu._fonksiyon_birimi`` ile aynıdır (köken zincirinde en derinden başla;
    adı olan, yapay olmayan ilk derleme birimi); burada ad yerine birimin kimliği döner, çünkü aynı
    adı taşıyan iki birim ayrı kaynak dosyadır. Zincir çözülemezse gövdenin kendi birimine bakılır
    (``Cozucu.fonksiyon`` ile aynı geri düşüş). Birim seçilemezse (yalnız yapay ya da adsız birim)
    ``(None, None)``.
    """
    try:
        zincir = list(c.koken_zinciri(dt.ANA, d))
    except dt.CozumHatasi:
        zincir = [(dt.ANA, d, "kendi")]
    for rol, k, _ in reversed(zincir):
        birim = c.dosyalar[rol].birimler.get(k.birim)
        if birim is None or birim["etiket"] != DERLEME_BIRIMI:
            continue
        ad = c.birim_adi(rol, k.birim)
        if ad and ad != YAPAY_BIRIM:
            kendi = (rol, k.birim) == (dt.ANA, d.birim)
            return (rol, k.birim, ad), KOKEN_KENDI if kendi else KOKEN_KOKEN
    return None, None


def birim_yolu(c: Any, rol: str, birim: int, ad: str) -> tuple[str, str]:
    """Derleme biriminin kaynak dosyasının yolu ve yolun kaynağı.

    DWARF 5 satır tablosunun 0. dosyası birimin kaynak dosyasıdır ve derleme diziniyle birleşik
    yazılır (``dwarf_tip.dosya_yollari``): özyinelemeli derlemede (her dizin kendi derleme diziniyle)
    aynı adlı dosyaları ayırır. Tablo yoksa, DWARF 5 değilse ya da 0. dosyanın adı birim adıyla
    uyuşmuyorsa sadeleşmiş ``DW_AT_name`` kullanılır.
    """
    ad_yolu = posixpath.normpath(ad)
    tablo = c.dosyalar[rol].birimler[birim].get("dosya_tablosu")
    if isinstance(tablo, dict) and "hata" not in tablo and tablo.get("taban") == 0:
        yollar = tablo.get("yollar") or []
        ilk = yollar[0] if yollar else None
        if ilk and posixpath.basename(ilk) == posixpath.basename(ad_yolu):
            return ilk, YOL_SATIR_TABLOSU
    return ad_yolu, YOL_AD


def dizin_etiketi(yol: str) -> str:
    return posixpath.dirname(yol) or KOK_DIZIN


def dwarf_govdeleri(debug: Path, ek_onbellek: Optional[dict] = None
                    ) -> tuple[list[Govde], dict[str, Any]]:
    """Hata ayıklama dosyasındaki somut gövdeler ve kaynak dosyaları.

    dwz ek dosyası ``.gnu_debugaltlink`` ile bulunur (``dwarf_tip.ek_yukle``); bağ var ama dosya
    bulunamadıysa birim adları çözülemeyebilir: ölçüm durur.
    """
    ana = dt.dosya_yukle(Path(debug), dt.ANA)
    ek, yontem, _ = dt.ek_yukle(ana, None, ek_onbellek)
    if ana.altlink is not None and ek is None:
        raise OnkosulHatasi(f"{debug}: dwz ek dosyası bulunamadı ({yontem})")
    c = dt.Cozucu(ana, ek)
    govdeler: list[Govde] = []
    yapay = 0
    ad_yollari: dict[str, set[str]] = {}     # sadeleşmiş birim adı → kaynak dosya yolları
    for _, d in sorted(ana.dieler.items()):
        if d.etiket != GOVDE_ETIKETI or "DW_AT_low_pc" not in d.oz:
            continue
        adres = dt.deger(d, "DW_AT_low_pc")
        if not isinstance(adres, int):
            continue
        yapay += int(c.birim_adi(dt.ANA, d.birim) == YAPAY_BIRIM)
        secim, koken = kaynak_birimi(c, d)
        if secim is None:
            govdeler.append(Govde(adres, None, None, None))
            continue
        yol, kaynak = birim_yolu(c, *secim)
        ad_yollari.setdefault(posixpath.normpath(secim[2]), set()).add(yol)
        govdeler.append(Govde(adres, yol, koken, kaynak))
    # aynı adı taşıyan ayrı kaynak dosyalar: etiket yalnız addan alınsaydı birleşecek olanlar
    ayni_adli = sum(1 for yollar in ad_yollari.values() if len(yollar) > 1)
    return govdeler, {"ek_yontemi": yontem, "govde": len(govdeler), "yapay_birimde_govde": yapay,
                      "yalniz_ranges_govde": c.yalniz_ranges_govdeler(), "ayni_adli_kaynak": ayni_adli}


def crt_mi(adlar: Iterable[str]) -> bool:
    """GT fonksiyonunun bütün adları CRT adı mı (``function_f1.is_crt_name``; programın kodu değil)."""
    adlar = list(adlar)
    return bool(adlar) and all(ks1._f1().is_crt_name(a) for a in adlar)


def gt_etiketle(adlar: dict[int, list[str]], govdeler: Iterable[Govde], ofset: int
                ) -> tuple[dict[int, str], set[int], dict[str, int]]:
    """GT fonksiyonlarını (Ghidra adresi → adlar) DWARF gövdeleriyle etiketle.

    Dönen: (adres → kaynak dosya yolu, CRT dışı fonksiyon adresleri, sayaçlar). Sayaçlar:
    ``gt_fonksiyon``, ``crt``, ``govdesiz`` (o adreste somut gövde yok), ``etiketsiz`` (gövde var,
    birim seçilemedi), ``celiskili`` (aynı adreste farklı kaynak dosyalı gövdeler), ``etiketli``,
    ``koken_birimi`` (etiketi köken biriminden gelen), ``yol_ad`` (yolu yalnız addan gelen),
    ``kaynak_dosya`` ve ``dizin`` (etiketli fonksiyonların ayrı sınıf sayıları).
    """
    adrese: dict[int, list[Govde]] = {}
    for g in govdeler:
        adrese.setdefault(g.adres + ofset, []).append(g)
    etiket: dict[int, str] = {}
    fonksiyon: set[int] = set()
    sayac: Counter = Counter()
    for adres, isimler in sorted(adlar.items()):
        sayac["gt_fonksiyon"] += 1
        if crt_mi(isimler):
            sayac["crt"] += 1
            continue
        fonksiyon.add(adres)
        buradaki = adrese.get(adres)
        if not buradaki:
            sayac["govdesiz"] += 1
            continue
        etiketli = [g for g in buradaki if g.yol]
        yollar = {g.yol for g in etiketli}
        if not yollar:
            sayac["etiketsiz"] += 1
        elif len(yollar) > 1:
            sayac["celiskili"] += 1
        else:
            etiket[adres] = etiketli[0].yol
            sayac["etiketli"] += 1
            sayac["koken_birimi"] += int(all(g.koken == KOKEN_KOKEN for g in etiketli))
            sayac["yol_ad"] += int(any(g.yol_kaynagi == YOL_AD for g in etiketli))
    sayac["kaynak_dosya"] = len(set(etiket.values()))
    sayac["dizin"] = len({dizin_etiketi(y) for y in etiket.values()})
    alanlar = ("gt_fonksiyon", "crt", "govdesiz", "etiketsiz", "celiskili", "etiketli", "koken_birimi",
               "yol_ad", "kaynak_dosya", "dizin")
    return etiket, fonksiyon, {a: int(sayac.get(a, 0)) for a in alanlar}


def gt_oku(e: Any, indir: Path, ek_onbellek: Optional[dict] = None) -> GtTarafi:
    """Bir ELF'in GT etiketleri. Fonksiyon evreni, hata ayıklama dosyası ve ofset ``ks1_olc.gt_elf``'ten."""
    gt = ks1.gt_elf(e, indir)
    ofset = int(str(gt.kunye["ofset"]), 16)
    govdeler, dwarf = dwarf_govdeleri(Path(gt.kunye["debug"]), ek_onbellek)
    etiket, fonksiyon, sayac = gt_etiketle(gt.adlar, govdeler, ofset)
    return GtTarafi(etiket, fonksiyon, sayac, {**gt.kunye, "dwarf": dwarf})


# --------------------------------------------------------------------------------------------
# Ölçüler


def capraz_tablo(urun: Sequence[Hashable], gt: Sequence[Hashable]) -> Counter:
    """(modül, sınıf) → fonksiyon sayısı. İki dizi aynı fonksiyon sırasındadır."""
    if len(urun) != len(gt):
        raise ValueError(f"etiket dizileri eşit uzunlukta olmalı: {len(urun)} ≠ {len(gt)}")
    return Counter(zip(urun, gt))


def cift(n: int) -> int:
    return n * (n - 1) // 2


def cift_sayilari(tablo: Counter) -> dict[str, int]:
    """Çift sayıları: ``toplam`` (bütün çiftler), ``urun`` (aynı modülde), ``gt`` (aynı sınıfta),
    ``ortak`` (ikisi de)."""
    modul: Counter = Counter()
    sinif: Counter = Counter()
    for (m, s), n in tablo.items():
        modul[m] += n
        sinif[s] += n
    n = sum(tablo.values())
    return {"n": n, "toplam": cift(n), "urun": sum(cift(v) for v in modul.values()),
            "gt": sum(cift(v) for v in sinif.values()), "ortak": sum(cift(v) for v in tablo.values())}


def cift_olculeri(s: dict[str, int]) -> dict[str, Optional[Fraction]]:
    """Çift sayımlı kesinlik, duyarlılık, F1 ve düzeltilmiş Rand indeksi (kesirle).

    ARI = (ortak − beklenen) / ((urun + gt) / 2 − beklenen), beklenen = urun · gt / toplam
    (Hubert ve Arabie 1985; boyutlar sabitken rastgele atamanın beklenen ortak çift sayısı).
    Payda sıfırsa (iki bölme de yozlaşmış) tanımsızdır.
    """
    ortak, urun, gt, toplam = s["ortak"], s["urun"], s["gt"], s["toplam"]
    kesinlik = Fraction(ortak, urun) if urun else None
    duyarlilik = Fraction(ortak, gt) if gt else None
    f1 = Fraction(2 * ortak, urun + gt) if urun + gt else None
    ari = None
    if toplam:
        beklenen = Fraction(urun * gt, toplam)
        payda = Fraction(urun + gt, 2) - beklenen
        ari = (ortak - beklenen) / payda if payda else None
    return {"kesinlik": kesinlik, "duyarlilik": duyarlilik, "f1": f1, "ari": ari}


def _entropi(sayilar: Iterable[int], n: int) -> float:
    return -sum(v / n * math.log(v / n) for v in sayilar if v)


def v_olcusu(tablo: Counter) -> dict[str, Optional[float]]:
    """Türdeşlik, tamlık ve V-ölçüsü (Rosenberg ve Hirschberg 2007).

    Türdeşlik = 1 − H(sınıf | modül) / H(sınıf); tamlık = 1 − H(modül | sınıf) / H(modül).
    Entropisi sıfır olan tarafta (tek sınıf ya da tek modül) oran 1'dir. V harmonik ortalamadır.
    """
    n = sum(tablo.values())
    if not n:
        return {"turdeslik": None, "tamlik": None, "v": None}
    modul: Counter = Counter()
    sinif: Counter = Counter()
    for (m, s), v in tablo.items():
        modul[m] += v
        sinif[s] += v
    h_sinif, h_modul = _entropi(sinif.values(), n), _entropi(modul.values(), n)
    h_ortak = _entropi(tablo.values(), n)
    turdeslik = 1.0 if h_sinif <= 0 else 1.0 - (h_ortak - h_modul) / h_sinif
    tamlik = 1.0 if h_modul <= 0 else 1.0 - (h_ortak - h_sinif) / h_modul
    toplam = turdeslik + tamlik
    return {"turdeslik": turdeslik, "tamlik": tamlik, "v": 2 * turdeslik * tamlik / toplam if toplam > 0 else 0.0}


def olculer(urun: Sequence[Hashable], gt: Sequence[Hashable]) -> dict[str, Any]:
    """Bir bölmenin (modüller) GT sınıflarına göre bütün ölçüleri ve çift sayıları."""
    tablo = capraz_tablo(urun, gt)
    s = cift_sayilari(tablo)
    return {**cift_olculeri(s), **v_olcusu(tablo), "cift": s, "modul": len(set(urun))}


def bitisiklik(siniflar: Sequence[Hashable]) -> dict[str, Any]:
    """GT sınıflarının adres sırasındaki bitişikliği: ``kosu`` (aynı sınıftan ardışık fonksiyon
    öbeği sayısı), ``sinif`` ve ``oran`` = sınıf / koşu (1: her kaynak dosya tek öbek)."""
    kosu = sum(1 for i, s in enumerate(siniflar) if i == 0 or s != siniflar[i - 1])
    sinif = len(set(siniflar))
    return {"kosu": kosu, "sinif": sinif, "oran": Fraction(sinif, kosu) if kosu else None}


def modul_turu_dokumu(moduller: Sequence[str], siniflar: Sequence[Hashable]) -> dict[str, dict[str, int]]:
    """Modül türü başına: modül ve fonksiyon sayısı, aynı modüldeki çiftler ve bunlardan aynı sınıfta
    olanlar (türün çift kesinliğinin payı ve paydası)."""
    tablo = capraz_tablo(moduller, siniflar)
    boyut: Counter = Counter(moduller)
    out = {t: {"modul": 0, "fonksiyon": 0, "cift": 0, "ortak": 0} for t in MODUL_TURLERI}
    for m, n in boyut.items():
        t = out[modul_turu(m)]
        t["modul"] += 1
        t["fonksiyon"] += n
        t["cift"] += cift(n)
    for (m, _), n in tablo.items():
        out[modul_turu(m)]["ortak"] += cift(n)
    return out


# --------------------------------------------------------------------------------------------
# Tabanlar


def b1_bolme(n: int, k: int) -> list[int]:
    """Adres sırasındaki ``n`` fonksiyonu ``k`` bitişik parçaya böl: boyutlar en çok bir farklı,
    fazlalık baştaki parçalarda. Dönen: sıradaki her fonksiyonun parça numarası."""
    if not 1 <= k <= max(n, 1):
        raise ValueError(f"parça sayısı 1..{n} aralığında olmalı: {k}")
    taban, artan = divmod(n, k)
    out: list[int] = []
    for i in range(k):
        out.extend([i] * (taban + (1 if i < artan else 0)))
    return out


def misc_tekil(moduller: Sequence[str]) -> list[Hashable]:
    """``subsystem_misc`` üyeleri tek başına modül: ürün onlar için gruplama iddiası taşımaz."""
    return [(m, i) if m == MISC_MODUL else m for i, m in enumerate(moduller)]


def yuzdelik(degerler: Sequence[Any], pay: Fraction = B0_YUZDELIK) -> Any:
    """En yakın sıra yüzdeliği: sıralı dizide ⌈pay · N⌉. değer."""
    sirali = sorted(degerler)
    return sirali[max(math.ceil(pay * len(sirali)), 1) - 1]


def b0_ozeti(moduller: Sequence[Hashable], siniflar: Sequence[Hashable], tohum_metni: str,
             urun_ari: Optional[Fraction], adet: int = B0_PERMUTASYON) -> dict[str, Any]:
    """Modül etiketleri fonksiyonlar arasında ``adet`` kez karılır (boyutlar korunur).

    Ölçü başına karmaların ortalaması; ARI için 95. yüzdelik ve permütasyon p değeri
    ((1 + ürününkine eşit ya da büyük karma sayısı) / (adet + 1)). Kapalı biçim beklenen değerler:
    kesinlik = GT çift yoğunluğu, duyarlılık = ürün çift yoğunluğu, ARI = 0.
    """
    rng = random.Random(dt.tohum(tohum_metni))
    karisik = list(moduller)
    toplam = {a: 0.0 for a in OLCU_ADLARI}
    sayi: Counter = Counter()
    ariler: list[Fraction] = []
    for _ in range(adet):
        rng.shuffle(karisik)
        o = olculer(karisik, siniflar)
        for a in OLCU_ADLARI:
            if o[a] is not None:
                toplam[a] += float(o[a])
                sayi[a] += 1
        if o["ari"] is not None:
            ariler.append(o["ari"])
    s = cift_sayilari(capraz_tablo(moduller, siniflar))
    out: dict[str, Any] = {a: (toplam[a] / sayi[a] if sayi[a] else None) for a in OLCU_ADLARI}
    out["modul"] = len(set(moduller))
    out["adet"] = adet
    out["ari_p95"] = yuzdelik(ariler) if ariler else None
    out["ari_p"] = (Fraction(1 + sum(1 for a in ariler if a >= urun_ari), len(ariler) + 1)
                    if ariler and urun_ari is not None else None)
    out["beklenen"] = {"kesinlik": Fraction(s["gt"], s["toplam"]) if s["toplam"] else None,
                       "duyarlilik": Fraction(s["urun"], s["toplam"]) if s["toplam"] else None,
                       "ari": Fraction(0)}
    return out


# --------------------------------------------------------------------------------------------
# İkili düzeyi


def giris_engeli(n: int, siniflar: Sequence[Hashable], yol_ad: int = 0) -> Optional[str]:
    """İkili bu düzeyde ölçüye giremiyorsa nedeni; giriyorsa None."""
    if yol_ad:
        return NEDEN_YOL_AD
    if n < N_MIN:
        return NEDEN_KUCUK
    boyut = Counter(siniflar)
    if len(boyut) < 2:
        return NEDEN_TEK_SINIF
    if not any(v > 1 for v in boyut.values()):
        return NEDEN_HEPSI_AYRI
    return None


def duzey_olcumu(moduller: Sequence[str], siniflar: Sequence[Hashable], tohum_metni: str,
                 yol_ad: int = 0) -> dict[str, Any]:
    """Bir ikilinin bir düzeydeki ölçümü. Diziler adres sırasındadır (B1 bu sıraya dayanır)."""
    n = len(moduller)
    engel = giris_engeli(n, siniflar, yol_ad)
    out: dict[str, Any] = {"n": n, "modul": len(set(moduller)), "sinif": len(set(siniflar)),
                           "giris": engel is None, "neden": engel}
    if engel is not None:
        return out
    urun = olculer(moduller, siniflar)
    out["satirlar"] = {
        SATIR_URUN: urun,
        SATIR_B0: b0_ozeti(moduller, siniflar, tohum_metni, urun["ari"]),
        SATIR_B1: olculer(b1_bolme(n, out["modul"]), siniflar),
        SATIR_B1_GT: olculer(b1_bolme(n, out["sinif"]), siniflar),
        SATIR_TEK: olculer([0] * n, siniflar),
        SATIR_AYRI: olculer(list(range(n)), siniflar),
        SATIR_MISC_TEKIL: olculer(misc_tekil(moduller), siniflar),
    }
    out["bitisiklik"] = bitisiklik(siniflar)
    out["modul_turleri"] = modul_turu_dokumu(moduller, siniflar)
    return out


def ortak_nufus(urun: UrunTarafi, gt: GtTarafi) -> list[int]:
    """Ürün modülü ve GT etiketi birlikte okunan fonksiyonlar, adres sırasında."""
    return sorted(set(urun.modul) & set(gt.etiket))


def sinif_dizileri(urun: UrunTarafi, gt: GtTarafi) -> tuple[list[int], list[str], dict[str, list[str]]]:
    adresler = ortak_nufus(urun, gt)
    dosyalar = [gt.etiket[a] for a in adresler]
    return (adresler, [urun.modul[a] for a in adresler],
            {DUZEY_DOSYA: dosyalar, DUZEY_DIZIN: [dizin_etiketi(y) for y in dosyalar]})


def elf_olcumu(urun: UrunTarafi, gt: GtTarafi, tohum_metni: str) -> dict[str, Any]:
    """Bir ikilinin iki düzeydeki ölçümü ve adres başına kodlanmış öğeler (ad içermez)."""
    adresler, moduller, siniflar = sinif_dizileri(urun, gt)
    duzeyler = {d: duzey_olcumu(moduller, siniflar[d], tohum_metni, gt.sayac.get("yol_ad", 0))
                for d in DUZEYLER}
    modul_no = {m: i for i, m in enumerate(sorted(set(moduller)))}
    kod = {d: {s: i for i, s in enumerate(sorted(set(siniflar[d])))} for d in DUZEYLER}
    ogeler = {f"{a:x}": " ".join([str(modul_no[moduller[i]])] + [str(kod[d][siniflar[d][i]]) for d in DUZEYLER])
              for i, a in enumerate(adresler)}
    return {"duzeyler": duzeyler, "moduller": sorted(modul_no, key=modul_no.get), "ogeler": ogeler}


def _oran(k: int, n: int) -> Optional[float]:
    return round(k / n, ONDALIK) if n else None


def huni(urun: UrunTarafi, gt: GtTarafi, ghidra_adresleri: set[int]) -> dict[str, Any]:
    """İki tarafın ayrı ayrı okunuşu ve adres eşlemesi (uyum sayısı yok).

    ``ortak.giris``: ikilinin her düzeyde ölçüye girip girmeyeceği (``giris_engeli``: girmiyorsa
    nedeni). Yalnız ortak nüfusun büyüklüğüne ve GT sınıflarına bakar; modüllere bakmaz.
    """
    etiketli = set(gt.etiket)
    eslesen = len(gt.fonksiyon & ghidra_adresleri)
    etiketli_eslesen = len(etiketli & ghidra_adresleri)
    ortak = sorted(set(urun.modul) & etiketli)
    dosyalar = [gt.etiket[a] for a in ortak]
    siniflar = {DUZEY_DOSYA: dosyalar, DUZEY_DIZIN: [dizin_etiketi(y) for y in dosyalar]}
    giris = {d: giris_engeli(len(ortak), siniflar[d], gt.sayac.get("yol_ad", 0)) for d in DUZEYLER}
    return {"urun": dict(urun.sayac), "gt": dict(gt.sayac),
            "esleme": {"gt_fonksiyon_ghidrada": eslesen,
                       "gt_fonksiyon_orani": _oran(eslesen, len(gt.fonksiyon)),
                       "etiketli_ghidrada": etiketli_eslesen,
                       "etiketli_orani": _oran(etiketli_eslesen, len(etiketli))},
            "ortak": {"n": len(ortak), "modul": len({urun.modul[a] for a in ortak}),
                      "kaynak_dosya": len(set(dosyalar)), "dizin": len(set(siniflar[DUZEY_DIZIN])),
                      "giris": giris}}


# --------------------------------------------------------------------------------------------
# Birim, program ve karar


def ortalama(degerler: Iterable[Any]) -> Any:
    """None olmayanların ortalaması (kesirler kesir kalır); hiç değer yoksa None."""
    d = [v for v in degerler if v is not None]
    return sum(d) / len(d) if d else None


def birim_degeri(elfler: Iterable[dict[str, Any]], duzey: str, satir: str, olcu: str) -> Any:
    """Birimin değeri: ölçüye giren ikililerin ortalaması."""
    return ortalama(e["duzeyler"][duzey]["satirlar"][satir][olcu]
                    for e in elfler if e["duzeyler"][duzey]["giris"])


def program_degerleri(birim_degerleri: dict[str, Any]) -> dict[str, Any]:
    """Birim → program: aynı programın (değeri olan) platform birimleri ortalanır."""
    programlar: dict[str, list[Any]] = {}
    for b, v in sorted(birim_degerleri.items()):
        if v is not None:
            programlar.setdefault(ks1.birim_programi(b), []).append(v)
    return {p: ortalama(vs) for p, vs in sorted(programlar.items())}


def makro(birim_degerleri: dict[str, Any]) -> dict[str, Any]:
    """Program düzeyi makro: programlar eşit ağırlıkla (``ks1_olc.makro`` kuralı)."""
    prog = program_degerleri(birim_degerleri)
    return {"makro": ortalama(prog.values()), "program": prog,
            "giren_birimler": sorted(b for b, v in birim_degerleri.items() if v is not None)}


def karsilastirma_karari(urun: dict[str, Any], taban: dict[str, Any], esik: Fraction = FARK_ESIGI,
                         cogunluk: Fraction = COGUNLUK, en_az_program: int = EN_AZ_PROGRAM
                         ) -> dict[str, Any]:
    """Ürün ↔ taban, program başına eşli fark (ön kayıt taslağı §7).

    ``urun_gecer``: makro fark ≥ ``esik`` ve fark, programların en az ``cogunluk`` payında pozitif.
    ``taban_gecer``: makro fark ≤ −``esik`` ve fark aynı payda negatif. Öbür durumda ``ayrismiyor``.
    İki tarafta da değeri olan program sayısı ``en_az_program``'ın altındaysa ``yetersiz``.
    """
    programlar = sorted(set(urun) & set(taban))
    farklar = {p: urun[p] - taban[p] for p in programlar}
    makro_fark = ortalama(farklar.values())
    pozitif = sum(1 for v in farklar.values() if v > 0)
    negatif = sum(1 for v in farklar.values() if v < 0)
    gerekli = math.ceil(cogunluk * len(programlar))
    if len(programlar) < en_az_program:
        karar = KARAR_YETERSIZ
    elif makro_fark >= esik and pozitif >= gerekli:
        karar = KARAR_URUN
    elif makro_fark <= -esik and negatif >= gerekli:
        karar = KARAR_TABAN
    else:
        karar = KARAR_AYRISMIYOR
    return {"programlar": programlar, "farklar": farklar, "makro_fark": makro_fark, "pozitif": pozitif,
            "negatif": negatif, "gerekli": gerekli, "esik": esik, "karar": karar}


def rastgele_karari(urun: dict[str, Any], b0_p95: dict[str, Any], cogunluk: Fraction = COGUNLUK,
                    en_az_program: int = EN_AZ_PROGRAM) -> dict[str, Any]:
    """Ürün rastgele atamadan ayırt ediliyor mu: programların en az ``cogunluk`` payında ürünün ARI'si
    B0'ın 95. yüzdeliğinin (ikililerin ortalaması) üstünde."""
    programlar = sorted(set(urun) & set(b0_p95))
    ustte = sum(1 for p in programlar if urun[p] > b0_p95[p])
    gerekli = math.ceil(cogunluk * len(programlar))
    if len(programlar) < en_az_program:
        karar = KARAR_YETERSIZ
    else:
        karar = KARAR_RASTGELEDEN_IYI if ustte >= gerekli else KARAR_AYIRT_EDILEMIYOR
    return {"programlar": programlar, "ustte": ustte, "gerekli": gerekli, "karar": karar}


def duzey_ozeti(birimler: dict[str, dict[str, Any]], duzey: str) -> dict[str, Any]:
    """Bir düzeyin program tablosu, makroları ve kararları. ``birimler``: birim → {elfler: {ad: ölçüm}}."""
    def tablo(satir: str, olcu: str) -> dict[str, Any]:
        return makro({b: birim_degeri(v["elfler"].values(), duzey, satir, olcu)
                      for b, v in birimler.items()})
    satirlar = {s: {a: tablo(s, a) for a in OLCU_ADLARI} for s in SATIRLAR}
    satirlar[SATIR_B0]["ari_p95"] = tablo(SATIR_B0, "ari_p95")
    urun = satirlar[SATIR_URUN][KARAR_OLCUSU]["program"]
    giren: Counter = Counter()
    disarida: Counter = Counter()
    bitisik: dict[str, list[Any]] = {}
    turler = {t: {"modul": 0, "fonksiyon": 0, "cift": 0, "ortak": 0} for t in MODUL_TURLERI}
    for b, v in birimler.items():
        for e in v["elfler"].values():
            d = e["duzeyler"][duzey]
            if not d["giris"]:
                disarida[d["neden"]] += 1
                continue
            giren[b] += 1
            bitisik.setdefault(b, []).append(d["bitisiklik"]["oran"])
            for tur, sayilar in d["modul_turleri"].items():
                for alan, n in sayilar.items():
                    turler[tur][alan] += n
    return {"satirlar": satirlar, "giren_ikili": dict(sorted(giren.items())),
            "disarida": dict(sorted(disarida.items())),
            # yalnız rapor: GT'nin adres sırasındaki bitişikliği (makro) ve modül türü dökümü (havuz)
            "bitisiklik": makro({b: ortalama(vs) for b, vs in bitisik.items()}),
            "modul_turleri": turler,
            "kararlar": {
                "rastgele": rastgele_karari(urun, satirlar[SATIR_B0]["ari_p95"]["program"]),
                "b1": karsilastirma_karari(urun, satirlar[SATIR_B1][KARAR_OLCUSU]["program"])}}


# --------------------------------------------------------------------------------------------
# Ön koşullar


def onkosullari_denetle(kok: Path = REPO, onkayit: Path = ONKAYIT_YOLU,
                        sabitler: Path = SABITLER_YOLU) -> dict[str, Any]:
    """Ön kayıt commit'i HEAD'in atası ve ölçüm dosyaları o commit'te sabitlenen sha256'larla aynı
    (``ks1_olc``'nin denetimleriyle; sabitler dosyası aynı şemadadır)."""
    commit = ks1.onkayit_commit(onkayit, kok)
    if not ks1.commit_atasi_mi(commit, kok):
        raise OnkosulHatasi(f"ön kayıt commit'i {commit} HEAD'in atası değil")
    dosyalar = ks1.committeki_sabitler(commit, kok, sabitler).get("dosyalar") or {}
    denetlenen = {}
    for rel in OLCUM_DOSYALARI:
        if rel not in dosyalar:
            raise OnkosulHatasi(f"ön kayıtta {rel} için sha256 yok")
        denetlenen[rel] = ks1.sha256_denetle(Path(kok) / rel, dosyalar[rel])
    return {"onkayit_commit": commit, "onkayit_commit_atasi": True, "sha256": denetlenen}


def sabitle(kok: Path = REPO, hedef: Path = SABITLER_YOLU) -> dict[str, Any]:
    belge = {"sema": ks1.SABITLER_SEMA,
             "dosyalar": {rel: ks1.sha256_dosya(Path(kok) / rel) for rel in SABIT_DOSYALAR}}
    hedef.parent.mkdir(parents=True, exist_ok=True)
    hedef.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return belge


# --------------------------------------------------------------------------------------------
# Komutlar: kuru ve olc


def kosu_kunyesi(kosu: Optional[Path]) -> Optional[dict[str, Any]]:
    """Koşu kökünün künyesi (``<kök>/kosu_kunyesi.json``; ``kosu`` kökün ``debian`` dizinidir):
    ürünün commit'i ve çalışma ağacının temizliği. Dosya yoksa None."""
    if kosu is None:
        return None
    yol = Path(kosu).parent / "kosu_kunyesi.json"
    if not yol.is_file():
        return None
    agac = _json(yol).get("agac") or {}
    return {"dosya": str(yol), "commit": agac.get("commit"), "kirli": agac.get("kirli"),
            "karadul_surumu": agac.get("karadul_surumu")}


def _ghidra_adresleri(e: Any) -> tuple[set[int], int, bool]:
    """(Ghidra fonksiyon adresleri, thunk sayısı, C++ ikili mi)."""
    yol = Path(e.static) / "ghidra_functions.json"
    gfonk = ks1._f1().load_ghidra_functions(yol)
    cpp = ks1.cpp_ikili_mi(_json(yol).get("functions", []), e.platform)
    return {g["addr"] for g in gfonk}, sum(1 for g in gfonk if g["is_thunk"]), cpp


def mac_gt_bilgisi(e: Any, mac_veri: Optional[Path]) -> dict[str, Any]:
    """Mach-O GT'sinin taşıdığı alanlar: derleme birimi bilgisi yok (yalnız ad, adres, sınıf)."""
    if mac_veri is None:
        return {"neden": MAC_GT_NEDENI, "gt_okundu": False}
    try:
        gt = ks1.gt_mac(e, mac_veri)
        kayitlar = _json(Path(gt.kunye["gt"])).get("functions") or []
    except (OnkosulHatasi, OSError, ValueError, KeyError) as hata:
        # GT dosyası bulunamadı ya da analiz edilen dosyayla uyuşmuyor: kuru koşu durmaz, yazar
        return {"neden": MAC_GT_NEDENI, "gt_okundu": False, "hata": f"{type(hata).__name__}: {hata}"}
    alanlar = sorted({a for k in kayitlar if isinstance(k, dict) for a in k})
    return {"neden": MAC_GT_NEDENI, "gt_okundu": True, "gt_fonksiyon": len(gt.adlar),
            "gt_kayit_alanlari": alanlar}


def kuru(elfler: list[Any], indir: Optional[Path], mac_veri: Optional[Path] = None,
         beklenen: Optional[dict[str, int]] = ks1.BEKLENEN_ELF, eksik_izinli: bool = False
         ) -> dict[str, Any]:
    """GT'siz kuru koşu: ikili başına iki tarafın ayrı ayrı okunuşu. Çapraz tablo kurulmaz.

    Ölçümü durduracak GT'siz ön koşullar da burada sınanır: nüfusun eksiksizliği (durur, ``eksik_izinli``
    değilse), Ghidra sürümü ve ikili başına GT okuması (durmaz; hatayı yazar).
    """
    elfler = projesizleri_isaretle(elfler)
    nufus_kunyesi = ks1.nufus_denetle(elfler, beklenen, eksik_izinli)
    try:
        ghidra_kunyesi = ks1.ghidra_denetle(elfler)
    except OnkosulHatasi as hata:
        ghidra_kunyesi = {"hata": str(hata)}
    ek_onbellek: dict = {}
    birimler: dict[str, dict[str, Any]] = {}
    for e in elfler:
        if e.static is None:
            continue
        b = birimler.setdefault(ks1.birim_anahtari(e), {"elfler": {}, "cpp_disarida": []})
        ghidra, thunk, cpp = _ghidra_adresleri(e)
        if cpp:
            b["cpp_disarida"].append(e.ad)
            continue
        urun = urun_oku(e.kosu, ghidra)
        kayit: dict[str, Any] = {"urun": {**urun.sayac, "thunk": thunk}}
        if e.platform == ks1.PLATFORM_MAC:
            kayit["gt"] = mac_gt_bilgisi(e, mac_veri)
            kayit["gt_etiketi"] = False
        else:
            # Kuru koşu, ön koşulu tutmayan ikilide durmaz: hatayı yazar (ölçüm ``olc``'de durur)
            try:
                gt = gt_oku(e, indir, ek_onbellek)
            except (OnkosulHatasi, ValueError, OSError, KeyError) as hata:
                kayit["gt"] = {"neden": GT_OKUNAMADI, "hata": f"{type(hata).__name__}: {hata}"}
                kayit["gt_etiketi"] = False
            else:
                h = huni(urun, gt, ghidra)
                kayit.update(gt=h["gt"], esleme=h["esleme"], ortak=h["ortak"], gt_etiketi=True,
                             lto=gt.kunye["dwarf"]["yapay_birimde_govde"] > 0,
                             kunye={a: gt.kunye[a] for a in ("ofset", "ofset_kaynagi")},
                             dwarf=gt.kunye["dwarf"])
        b["elfler"][e.ad] = kayit
    return {"sema": KURU_SEMA, "komut": "kuru",
            "arac": {"betik_sha256": ks1.sha256_dosya(OLC_YOLU),
                     "git_head": ks1._git("rev-parse", "HEAD").stdout.strip(),
                     "python": platform.python_version(), "ghidra": ghidra_kunyesi},
            "secimler": {"n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM},
            "nufus": nufus_kunyesi,
            "birimler": {k: {"elfler": dict(sorted(v["elfler"].items())),
                             "cpp_disarida": sorted(v["cpp_disarida"])}
                         for k, v in sorted(birimler.items())},
            "toplam": kuru_toplami(birimler)}


def kuru_toplami(birimler: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Birim başına toplamlar: ikili sayıları ve iki tarafın sayaç toplamları."""
    out: dict[str, Any] = {}
    for b, v in sorted(birimler.items()):
        elfler = list(v["elfler"].values())
        etiketli = [k for k in elfler if k.get("gt_etiketi")]
        t: dict[str, Any] = {
            "ikili": len(elfler), "cpp_disarida": len(v["cpp_disarida"]),
            "gt_okunamayan": sum(1 for k in elfler if k["gt"].get("neden") == GT_OKUNAMADI),
            "urun_okunan": sum(1 for k in elfler if k["urun"]["atanan"] > 0),
            "gt_okunan": sum(1 for k in etiketli if k["gt"]["etiketli"] > 0),
            "iki_taraf_okunan": sum(1 for k in etiketli
                                    if k["urun"]["atanan"] > 0 and k["gt"]["etiketli"] > 0),
            "urun": {a: sum(k["urun"][a] for k in elfler) for a in sorted(elfler[0]["urun"])} if elfler else {},
        }
        if etiketli:
            t["gt"] = {a: sum(k["gt"][a] for k in etiketli) for a in sorted(etiketli[0]["gt"])
                       if a not in ("kaynak_dosya", "dizin")}
            t["esleme"] = {a: sum(k["esleme"][a] for k in etiketli)
                           for a in ("gt_fonksiyon_ghidrada", "etiketli_ghidrada")}
            t["ortak_n"] = sum(k["ortak"]["n"] for k in etiketli)
            t["lto_ikili"] = sum(1 for k in etiketli if k["lto"])
            t["ayni_adli_kaynak"] = sum(k["dwarf"]["ayni_adli_kaynak"] for k in etiketli)
            t["girer"] = {d: sum(1 for k in etiketli if k["ortak"]["giris"][d] is None) for d in DUZEYLER}
            t["n_min_alti"] = sum(1 for k in etiketli if k["ortak"]["n"] < N_MIN)
            t["tek_kaynak_dosya"] = sum(1 for k in etiketli if k["ortak"]["kaynak_dosya"] < 2)
            t["tek_dizin"] = sum(1 for k in etiketli if k["ortak"]["dizin"] < 2)
        out[b] = t
    return out


def olc(elfler: list[Any], indir: Optional[Path], mac_veri: Optional[Path] = None, denetle: bool = True,
        beklenen: Optional[dict[str, int]] = ks1.BEKLENEN_ELF, eksik_izinli: bool = False
        ) -> dict[str, Any]:
    """Ölçüm: ürün modülü ↔ GT kaynak dosyası. Ön koşullar tutmazsa durur."""
    onkosul = onkosullari_denetle() if denetle else {"denetlenmedi": True}
    elfler = projesizleri_isaretle(elfler)
    nufus_kunyesi = ks1.nufus_denetle(elfler, beklenen, eksik_izinli)
    ghidra_kunyesi = ks1.ghidra_denetle(elfler) if denetle else {"denetlenmedi": True}
    ek_onbellek: dict = {}
    birimler: dict[str, dict[str, Any]] = {}
    gt_etiketsiz: dict[str, str] = {}
    for e in elfler:
        if e.static is None:
            continue
        birim = ks1.birim_anahtari(e)
        if e.platform == ks1.PLATFORM_MAC:
            gt_etiketsiz[f"{birim}/{e.ad}"] = MAC_GT_NEDENI
            continue
        b = birimler.setdefault(birim, {"elfler": {}, "cpp_disarida": []})
        ghidra, _, cpp = _ghidra_adresleri(e)
        if cpp:
            b["cpp_disarida"].append(e.ad)     # ``ks1_olc`` ile aynı nüfus kuralı
            continue
        urun = urun_oku(e.kosu, ghidra)
        gt = gt_oku(e, indir, ek_onbellek)
        sonuc = elf_olcumu(urun, gt, f"{B0_TOHUM_METNI}|{birim}/{e.ad}")
        sonuc["huni"] = huni(urun, gt, ghidra)
        sonuc["lto"] = gt.kunye["dwarf"]["yapay_birimde_govde"] > 0
        sonuc["kunye"] = gt.kunye
        b["elfler"][e.ad] = sonuc
    birimler = {k: {"elfler": dict(sorted(v["elfler"].items())), "cpp_disarida": sorted(v["cpp_disarida"])}
                for k, v in sorted(birimler.items())}
    return {"sema": SEMA, "komut": "olc", "onkosul": onkosul,
            "arac": {"betik_sha256": ks1.sha256_dosya(OLC_YOLU), "ks1_olc_sha256": ks1.sha256_dosya(KS1_YOLU),
                     "git_head": ks1._git("rev-parse", "HEAD").stdout.strip(),
                     "python": platform.python_version(), "ghidra": ghidra_kunyesi},
            "secimler": {"n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM, "b0_permutasyon": B0_PERMUTASYON,
                         "b0_tohum_metni": B0_TOHUM_METNI, "b0_yuzdelik": B0_YUZDELIK,
                         "fark_esigi": FARK_ESIGI, "cogunluk": COGUNLUK, "karar_olcusu": KARAR_OLCUSU,
                         "karar_duzeyi": KARAR_DUZEYI},
            "nufus": nufus_kunyesi, "gt_etiketsiz": dict(sorted(gt_etiketsiz.items())),
            "ozet": {d: duzey_ozeti(birimler, d) for d in DUZEYLER}, "birimler": birimler}


# --------------------------------------------------------------------------------------------
# Çıktı


def yuvarla(v: Any) -> Any:
    """JSON için: kesir ve ondalık sayılar ``ONDALIK`` haneye yuvarlanır; yapı korunur."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return v
    if isinstance(v, (Fraction, float)):
        return round(float(v), ONDALIK)
    if isinstance(v, dict):
        return {str(k): yuvarla(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [yuvarla(x) for x in v]
    return str(v)


def sayi(v: Any, hane: int = 3) -> str:
    return "—" if v is None else f"{float(v):.{hane}f}".replace(".", ",")


def _yuzde(k: int, n: int) -> str:
    return "—" if not n else f"%{100 * k / n:.1f}".replace(".", ",")


def _kunye_satiri(s: dict[str, Any]) -> str:
    k = s.get("kosu_kunyesi")
    if not k:
        return "- Koşu künyesi: okunmadı."
    return (f"- Koşu künyesi: ürün commit'i `{k.get('commit')}`, sürüm {k.get('karadul_surumu')}, "
            f"kirli dosya {len(k.get('kirli') or [])}.")


def kuru_markdown(s: dict[str, Any]) -> str:
    """Kuru koşu özeti: birim başına üç tablo (ürün, GT, ortak nüfus) ve ikili tablosu. Uyum sayısı
    ve ad içermez."""
    g_k = s["arac"].get("ghidra") or {}
    satirlar = ["# Harita ölçümü: GT'siz kuru koşu", "",
                f"- `harita_olc.py` sha256 `{s['arac']['betik_sha256'][:16]}…`; HEAD `{s['arac']['git_head'][:10]}`.",
                f"- Nüfus: bulunan {sum(s['nufus']['bulunan'].values())} ikili, biten "
                f"{sum(s['nufus']['biten'].values())}; sorunlar: {'; '.join(s['nufus']['sorunlar']) or 'yok'}.",
                _kunye_satiri(s),
                "- Ghidra sürümü denetimi: " + (f"DURUR: {g_k['hata']}" if "hata" in g_k else
                                               f"tamam, sürüm {g_k.get('surum')}, {g_k.get('elf')} ikili") + ".",
                "- Bu koşu iki tarafı ayrı ayrı okur; modül ile GT etiketi çaprazlanmaz.", "",
                "## Ürün tarafı (birim başına)", "",
                "| Birim | İkili | C++ (dışarıda) | Ürün okunan | Ghidra fonksiyonu | Thunk | Modüle atanan | "
                "Atanamayan | Çoklu modül | Ghidra dışı adres | Başlıksız dosya |",
                "|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, t in s["toplam"].items():
        u = t.get("urun") or {}
        satirlar.append(
            f"| {b} | {t['ikili']} | {t['cpp_disarida']} | {t['urun_okunan']} | "
            + " | ".join(str(u.get(a, 0)) for a in ("ghidra_fonksiyon", "thunk", "atanan", "atanamayan",
                                                    "coklu_modul", "ghidra_disi", "basliksiz_dosya")) + " |")
    satirlar += ["", "## GT tarafı (birim başına)", "",
                 "| Birim | GT okunan | GT okunamayan | GT fonksiyonu | CRT | Gövdesiz | Etiketsiz | Çelişkili | "
                 "Etiketli | Etiketli → Ghidra | LTO'lu ikili | Köken biriminden | Yolu addan | Aynı adlı kaynak |",
                 "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, t in s["toplam"].items():
        g = t.get("gt")
        if g is None:
            satirlar.append(f"| {b} | 0 (etiket yok) | {t['gt_okunamayan']} | — | — | — | — | — | — | — | — | — | "
                            "— | — |")
            continue
        satirlar.append(
            f"| {b} | {t['gt_okunan']} | {t['gt_okunamayan']} | {g['gt_fonksiyon']} | {g['crt']} | "
            f"{g['govdesiz']} | {g['etiketsiz']} | {g['celiskili']} | {g['etiketli']} | "
            f"{t['esleme']['etiketli_ghidrada']} ({_yuzde(t['esleme']['etiketli_ghidrada'], g['etiketli'])}) | "
            f"{t['lto_ikili']} | {g['koken_birimi']} | {g['yol_ad']} | {t['ayni_adli_kaynak']} |")
    satirlar += ["", "## Ortak nüfus ve giriş öngörüsü (birim başına)", "",
                 "| Birim | İki taraf da okunan ikili | Ortak nüfus (fonksiyon) | N_MIN altı | Tek kaynak dosya | "
                 "Tek dizin | Dosya düzeyine girer | Dizin düzeyine girer |",
                 "|---|---|---|---|---|---|---|---|"]
    for b, t in s["toplam"].items():
        if t.get("gt") is None:
            satirlar.append(f"| {b} | 0 | — | — | — | — | 0 | 0 |")
            continue
        satirlar.append(
            f"| {b} | {t['iki_taraf_okunan']} | {t['ortak_n']} | {t['n_min_alti']} | {t['tek_kaynak_dosya']} | "
            f"{t['tek_dizin']} | {t['girer'][DUZEY_DOSYA]} | {t['girer'][DUZEY_DIZIN]} |")
    satirlar += ["", "## İkili başına", "",
                 "| Birim | İkili | Ghidra fonksiyonu | Thunk | Modül | Atanan | Atanamayan | GT fonksiyonu | "
                 "Etiketli | Kaynak dosya | Dizin | Köken biriminden | Etiketli → Ghidra | Ortak nüfus | "
                 "Ortakta modül | Ortakta kaynak dosya | Ortakta dizin | LTO | Girmeme nedeni (dosya; dizin) |",
                 "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, v in s["birimler"].items():
        for ad, k in v["elfler"].items():
            u = k["urun"]
            bas = (f"| {b} | `{ad}` | {u['ghidra_fonksiyon']} | {u['thunk']} | {u['modul']} | {u['atanan']} | "
                   f"{u['atanamayan']} | ")
            if not k.get("gt_etiketi"):
                satirlar.append(bas + f"{k['gt'].get('gt_fonksiyon', '—')} | `{k['gt']['neden']}` | — | — | "
                                "— | — | — | — | — | — | — | — |")
                continue
            g, o = k["gt"], k["ortak"]
            satirlar.append(
                bas + f"{g['gt_fonksiyon']} | {g['etiketli']} | {g['kaynak_dosya']} | {g['dizin']} | "
                f"{g['koken_birimi']} | {k['esleme']['etiketli_ghidrada']} "
                f"({_yuzde(k['esleme']['etiketli_ghidrada'], g['etiketli'])}) | {o['n']} | {o['modul']} | "
                f"{o['kaynak_dosya']} | {o['dizin']} | {'evet' if k['lto'] else 'hayır'} | "
                f"{o['giris'][DUZEY_DOSYA] or '—'}; {o['giris'][DUZEY_DIZIN] or '—'} |")
    return "\n".join(satirlar) + "\n"


def olc_markdown(s: dict[str, Any]) -> str:
    """Ölçüm özeti: karar tablosu, makrolar, program tablosu. Ad içermez."""
    sec = s["secimler"]
    satirlar = ["# Harita ölçümü: ürün modülü ↔ kaynak dosya", "",
                f"- Ön kayıt commit'i: `{s['onkosul'].get('onkayit_commit', '—')}`; `harita_olc.py` sha256 "
                f"`{s['arac']['betik_sha256'][:16]}…`; Ghidra `{s['arac']['ghidra'].get('surum', '—')}`.",
                f"- Nüfus: {sum(s['nufus']['biten'].values())} ikili bitti; sorunlar: "
                f"{'; '.join(s['nufus']['sorunlar']) or 'yok'}; GT etiketi olmayan (ölçülmeyen): "
                f"{len(s['gt_etiketsiz'])}.",
                _kunye_satiri(s),
                f"- Seçimler: N_MIN = {sec['n_min']}, en az {sec['en_az_program']} program, B0 "
                f"{sec['b0_permutasyon']} karma, fark eşiği {sayi(sec['fark_esigi'], 2)}, çoğunluk "
                f"{sayi(sec['cogunluk'], 2)}; karar ölçüsü ARI, karar düzeyi `{sec['karar_duzeyi']}`.",
                "- LTO'lu ikili taşıyan birimler: " + (", ".join(sorted(
                    b for b, v in s["birimler"].items() if any(e["lto"] for e in v["elfler"].values()))) or "yok")
                + ".", ""]
    for d in DUZEYLER:
        o = s["ozet"][d]
        kr, kb = o["kararlar"]["rastgele"], o["kararlar"]["b1"]
        satirlar += [f"## Düzey: {d}", "",
                     f"- Giren ikili: {sum(o['giren_ikili'].values())}; dışarıda: "
                     f"{', '.join(f'{k} {v}' for k, v in o['disarida'].items()) or 'yok'}.",
                     f"- Rastgeleye karşı: `{kr['karar']}` ({kr['ustte']}/{len(kr['programlar'])} programda "
                     f"ürün B0'ın 95. yüzdeliğinin üstünde; gerekli {kr['gerekli']}).",
                     f"- B1'e karşı: `{kb['karar']}` (makro fark {sayi(kb['makro_fark'])}; pozitif "
                     f"{kb['pozitif']}, negatif {kb['negatif']}, gerekli {kb['gerekli']}).", "",
                     "| Satır | ARI | Çift kesinliği | Çift duyarlılığı | Çift F1 | Türdeşlik | Tamlık | V |",
                     "|---|---|---|---|---|---|---|---|"]
        for satir in SATIRLAR:
            m = o["satirlar"][satir]
            satirlar.append(f"| `{satir}` | " + " | ".join(
                sayi(m[a]["makro"]) for a in ("ari", "kesinlik", "duyarlilik", "f1", "turdeslik", "tamlik", "v")) + " |")
        satirlar += ["", "| Program | ARI ürün | ARI B0 ort. | ARI B0 p95 | ARI B1 | ARI B1-GT | Fark (ürün − B1) |",
                     "|---|---|---|---|---|---|---|"]
        m = o["satirlar"]
        for p in sorted(m[SATIR_URUN]["ari"]["program"]):
            satirlar.append(
                f"| {p} | {sayi(m[SATIR_URUN]['ari']['program'].get(p))} | "
                f"{sayi(m[SATIR_B0]['ari']['program'].get(p))} | {sayi(m[SATIR_B0]['ari_p95']['program'].get(p))} | "
                f"{sayi(m[SATIR_B1]['ari']['program'].get(p))} | {sayi(m[SATIR_B1_GT]['ari']['program'].get(p))} | "
                f"{sayi(kb['farklar'].get(p))} |")
        bt = o["bitisiklik"]
        satirlar += ["", f"GT bitişikliği (sınıf / adres sırasındaki öbek; 1: her sınıf tek öbek), makro "
                     f"{sayi(bt['makro'])}; program başına: "
                     + (", ".join(f"{p} {sayi(v)}" for p, v in bt["program"].items()) or "—") + ".", "",
                     "| Modül türü | Modül | Fonksiyon | Aynı modülde çift | Bunlardan aynı sınıfta | Çift kesinliği |",
                     "|---|---|---|---|---|---|"]
        for tur, t in o["modul_turleri"].items():
            satirlar.append(f"| `{tur}` | {t['modul']} | {t['fonksiyon']} | {t['cift']} | {t['ortak']} | "
                            f"{sayi(Fraction(t['ortak'], t['cift']) if t['cift'] else None)} |")
        satirlar.append("")
    if s["gt_etiketsiz"]:
        satirlar += ["GT etiketi olmayan ikililer: " + ", ".join(
            f"{k} ({v})" for k, v in s["gt_etiketsiz"].items()) + ".", ""]
    cpp = [f"{b}: {', '.join(v['cpp_disarida'])}" for b, v in s["birimler"].items() if v["cpp_disarida"]]
    if cpp:
        satirlar += ["C++ (ölçü dışı): " + "; ".join(cpp) + ".", ""]
    return "\n".join(satirlar)


def _yaz(yol: Path, belge: dict[str, Any]) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(yuvarla(belge), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------------
# CLI


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    for ad, yardim in (("kuru", "GT'siz kuru koşu: iki taraf ayrı ayrı (çapraz yok)"),
                       ("olc", "ürün modülü ↔ GT kaynak dosyası (ön kayıt commit'inden sonra)")):
        p = sub.add_parser(ad, help=yardim)
        p.add_argument("--mac-kosu", type=Path, default=None)
        p.add_argument("--debian-kosu", type=Path, default=None)
        p.add_argument("--mac-veri", type=Path, default=REPO / "workspaces" / "olcum_mac")
        p.add_argument("--debian-indir", type=Path,
                       default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
        p.add_argument("--json", type=Path, required=True)
        p.add_argument("--md", type=Path, default=None)
        p.add_argument("--eksik-izinli", action="store_true",
                       help="bitmemiş ya da eksik ikili varken de koş (eksikler çıktıda listelenir)")
    sub.add_parser("sabitle", help="harita_sabitler.json'u bugünkü sha256'larla yaz")
    a = ap.parse_args(argv)
    if a.komut == "sabitle":
        for rel, h in sabitle()["dosyalar"].items():
            print(f"{h}  {rel}")
        return 0
    elfler = ks1.elfleri_topla(a.mac_kosu, a.debian_kosu)
    try:
        if a.komut == "kuru":
            sonuc = kuru(elfler, a.debian_indir, a.mac_veri, eksik_izinli=a.eksik_izinli)
        else:
            sonuc = olc(elfler, a.debian_indir, a.mac_veri, eksik_izinli=a.eksik_izinli)
    except OnkosulHatasi as hata:
        print(f"DURDU: {hata}", file=sys.stderr)
        return 2
    sonuc["kosu_kunyesi"] = kosu_kunyesi(a.debian_kosu)
    _yaz(a.json, sonuc)
    if a.md:
        a.md.write_text(kuru_markdown(sonuc) if a.komut == "kuru" else olc_markdown(sonuc),
                        encoding="utf-8")
    print(f"{a.komut}: {len(sonuc['birimler'])} birim, "
          f"{sum(len(v['elfler']) for v in sonuc['birimler'].values())} ikili")
    return 0


if __name__ == "__main__":
    sys.exit(main())
