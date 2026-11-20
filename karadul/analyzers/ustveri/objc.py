"""Objective-C sınıf / kategori / protokol yöntem listesi okuyucu (P-ÜV2; ÜST VERİ hattı).

İkilinin ObjC üst verisinden uygulama adresi (IMP) → ``-[Sınıf seçici]`` / ``+[Sınıf seçici]``.
Ghidra'sız; yalnız dosya baytları. İkili çalıştırılmaz.

Biçim kaynağı: apple-oss-distributions/objc4 ``runtime/objc-runtime-new.h`` (2026-11-19'da okundu;
araştırma başvurusu ``scripts/arge/ustveri/objc_meta.py``, bu modül ondan yeniden yazıldı):

- ``__objc_classlist`` / ``__objc_nlclslist``: sınıf göstericileri. Sınıf (``objc_class``): ``isa`` (+0),
  ``superclass`` (+8), önbellek (2 sözcük), ``bits`` (+32; ``FAST_DATA_MASK`` ile ``class_ro_t``, düşük iki
  bit Swift işareti).
- ``class_ro_t``: bayraklar u32 × 4, ``ivarLayout`` (+16), ``name`` (+24), ``baseMethods`` (+32),
  ``baseProtocols`` (+40).
- Yöntem listesi: ``entsizeAndFlags`` u32 (bayrak maskesi ``0xffff0003``; ``0x80000000`` küçük biçim;
  ``0x40000000`` seçici doğrudan), ``count`` u32. Küçük kayıt 12 bayt: üç int32 göreli ofset (ad → seçici
  başvurusu, tip, IMP), her ofset KENDİ alanının adresine göre. Büyük kayıt 24 bayt: üç gösterici.
- Sınıf yöntemleri (``+``) ``isa``'nın gösterdiği meta sınıfın yöntem listesindedir.
- ``__objc_catlist`` / ``__objc_nlcatlist``: kategori (``category_t``): ad (+0), sınıf (+8; yerel ya da
  ``_OBJC_CLASS_$_X`` bağı), örnek yöntemleri (+16), sınıf yöntemleri (+24), protokoller (+32).
- ``__objc_protolist``: protokol (``protocol_t``): ``mangledName`` (+8), dört yöntem listesi (+24 … +48).

Girdi bir P-ÜV0 görüntü nesnesidir (``karadul.analyzers.ustveri.goruntu.Goruntu``): ``u32`` / ``i32`` /
``u64`` / ``cstr`` / ``gosterici`` (``int`` | ``Bag`` | ``None``) / ``bolumler`` / ``kod_bolumleri`` /
``fonksiyon_baslangiclari()`` / ``gosterici_boyutu`` / ``bicim``. Göreli ofset ve zincirli düzeltme gibi
işler ``gosterici()``'nindir; burada yeniden yazılmaz.

Sahte veri yok: okunamayan kayıt atlanır ve sayaç artar; ad uydurulmaz. Okuyucu istisna atmaz (beklenmeyen
bir hata ``hata`` durumuyla döner).
"""

from __future__ import annotations

import bisect
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from karadul.analyzers.ustveri.goruntu import (
    BICIM_MACHO,
    CSTR_AZAMI,
    DURUM_CALISTI,
    DURUM_DESTEKLENMIYOR,
    DURUM_HATA,
    DURUM_VERI_YOK,
)

logger = logging.getLogger(__name__)

# --- biçim sabitleri (objc4 runtime/objc-runtime-new.h) ----------------------------------------
DATA_MASK = 0x00007FFFFFFFFFF8   # FAST_DATA_MASK
SWIFT_BITS = 0x3                 # FAST_IS_SWIFT_LEGACY | FAST_IS_SWIFT_STABLE
SMALL_LIST_FLAG = 0x80000000     # smallMethodListFlag
DIRECT_SEL_FLAG = 0x40000000     # relativeMethodSelectorsAreDirectFlag
LIST_FLAG_MASK = 0xFFFF0003      # method_list_t::FlagMask
SMALL_ENTSIZE = 12
BIG_ENTSIZE = 24
LIST_PTR_LOW_BITS = 0x3          # yöntem listesi göstericisinin düşük bitleri (liste listesi işareti)

# sınıf / class_ro_t / kategori / protokol alan ofsetleri (64 bit)
CLASS_ISA = 0
CLASS_SUPERCLASS = 8
CLASS_BITS = 32
RO_NAME = 24
RO_BASE_METHODS = 32
RO_BASE_PROTOCOLS = 40
CAT_NAME = 0
CAT_CLASS = 8
CAT_INSTANCE_METHODS = 16
CAT_CLASS_METHODS = 24
CAT_PROTOCOLS = 32
PROTO_NAME = 8
PROTO_METHOD_LISTS = (24, 32, 40, 48)

# --- sağlamlık sınırları (plan kalem 5) ---------------------------------------------------------
MAX_METHODS_PER_LIST = 100_000
MAX_PROTOCOLS_PER_LIST = 10_000
MAX_SUPER_CHAIN = 4_096
CSTR_MAX = CSTR_AZAMI

POINTER_SIZE = 8

# --- bölüm adları ------------------------------------------------------------------------------
CLASS_SECTIONS = ("__objc_classlist", "__objc_nlclslist")
CATEGORY_SECTIONS = ("__objc_catlist", "__objc_nlcatlist")
PROTOCOL_SECTIONS = ("__objc_protolist",)
OBJC_SECTIONS = CLASS_SECTIONS + CATEGORY_SECTIONS + PROTOCOL_SECTIONS

# dış sınıf bağının ad önekleri (Mach-O C öneki `_` olan ve olmayan yazım)
CLASS_BIND_PREFIXES = ("_OBJC_CLASS_$_", "OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "OBJC_METACLASS_$_")

# --- durumlar: ortak dördü goruntu'dan (calisti / veri_yok / desteklenmiyor / hata); okuyucu ve
# üretici adıma özgü ikisi (P-ÜV1 ile aynı adlar) burada ------------------------------------------
DURUM_TUTARSIZ = "tutarsiz"
DURUM_KAPALI = "kapali"

# --- yöntem türleri ve kaynakları ----------------------------------------------------------------
TUR_ORNEK = "-"
TUR_SINIF = "+"
KAYNAK_SINIF = "sinif"
KAYNAK_KATEGORI = "kategori"
BICIM_KUCUK = "kucuk"
BICIM_BUYUK = "buyuk"

# --- arite hükmü --------------------------------------------------------------------------------
ARITE_UYAN = "uyan"
ARITE_UYMAYAN = "uymayan"
ARITE_COZULEMEDI = "cozulemedi"
# tip kodlamasındaki öğeler: dönüş + self + _cmd + argümanlar
ARITE_GIZLI_OGE = 3

# --- okuma hatası sayaçları (kabul: hepsi 0) ------------------------------------------------------
H_LISTE_OKUNAMADI = "yontem_listesi_okunamadi"
H_LISTE_SINIR = "yontem_sayisi_siniri_asildi"
H_KUCUK_BOYUT = "kucuk_liste_kayit_boyu"
H_BUYUK_BOYUT = "buyuk_liste_kayit_boyu"
H_KAYIT_OKUNAMADI = "yontem_kaydi_okunamadi"
H_BOLUM_DISI = "bolum_disi_goreli_ofset"
H_SECICI_COZULEMEDI = "secici_cozulemedi"
H_SINIF_VERISI = "sinif_verisi_okunamadi"
H_PROTOKOL_SINIR = "protokol_sayisi_siniri_asildi"
H_DONGUSEL_UST = "dongusel_ust_sinif"
HATA_SAYACLARI = (
    H_LISTE_OKUNAMADI, H_LISTE_SINIR, H_KUCUK_BOYUT, H_BUYUK_BOYUT, H_KAYIT_OKUNAMADI,
    H_BOLUM_DISI, H_SECICI_COZULEMEDI, H_SINIF_VERISI, H_PROTOKOL_SINIR, H_DONGUSEL_UST,
)
# bilgi sayaçları (hata değil)
B_IMP_BAG = "imp_ice_aktarim_bagi"
B_SINIF_LISTEDE_YOK = "yerel_sinif_listede_yok"  # kategori ya da üst sınıf göstericisi


def tip_arguman_sayisi(enc: str) -> Optional[int]:
    """ObjC yöntem tip kodlamasındaki öğe sayısı (dönüş + self + ``_cmd`` + argümanlar).

    Çözülemezse ``None``. Dilbilgisi: niteleyiciler ``rnNoORVAj``; ``{…}`` yapı, ``(…)`` birlik,
    ``[…]`` dizi (tırnaklı alan adları atlanır), ``^`` gösterici, ``bN`` bit alanı, ``@`` nesne
    (``@"Sınıf"``, ``@?`` blok, ``@?<…>`` blok imzası), öbürleri tek harf; her öğeden sonra isteğe bağlı
    işaretli yığın ofseti.
    """
    n = len(enc)

    def kapanis(i: int, ac: str, kapa: str, tirnak: bool) -> Optional[int]:
        derinlik = 0
        while i < n:
            c = enc[i]
            if c == ac:
                derinlik += 1
            elif c == kapa:
                derinlik -= 1
                if derinlik == 0:
                    return i + 1
            elif tirnak and c == '"':
                j = enc.find('"', i + 1)
                if j < 0:
                    return None
                i = j
            i += 1
        return None

    def tip_sonu(i: int) -> Optional[int]:
        while i < n and enc[i] in "rnNoORVAj":
            i += 1
        if i >= n:
            return None
        c = enc[i]
        if c == "{":
            return kapanis(i, "{", "}", True)
        if c == "(":
            return kapanis(i, "(", ")", True)
        if c == "[":
            return kapanis(i, "[", "]", False)
        if c == "^":
            return tip_sonu(i + 1)
        if c == "b":
            i += 1
            while i < n and enc[i].isdigit():
                i += 1
            return i
        if c == "@":
            i += 1
            if i < n and enc[i] == "?":
                i += 1
                if i < n and enc[i] == "<":
                    return kapanis(i, "<", ">", False)
                return i
            if i < n and enc[i] == '"':
                j = enc.find('"', i + 1)
                return None if j < 0 else j + 1
            return i
        return i + 1

    i = 0
    sayi = 0
    while i < n:
        son = tip_sonu(i)
        if son is None:
            return None
        i = son
        if i < n and enc[i] in "+-":
            i += 1
        while i < n and enc[i].isdigit():
            i += 1
        sayi += 1
    return sayi


def arite_hukmu(secici: Optional[str], tip: Optional[str]) -> str:
    """Seçicideki ``:`` sayısı = tip kodlamasındaki argüman sayısı − 3 mü."""
    if secici is None or tip is None:
        return ARITE_COZULEMEDI
    oge = tip_arguman_sayisi(tip)
    if oge is None:
        return ARITE_COZULEMEDI
    return ARITE_UYAN if oge - ARITE_GIZLI_OGE == secici.count(":") else ARITE_UYMAYAN


def sinif_bagi_adi(bag_adi: str) -> str:
    """İçe aktarılan sınıf bağının adından sınıf adı (``_OBJC_CLASS_$_NSString`` → ``NSString``)."""
    for onek in CLASS_BIND_PREFIXES:
        if bag_adi.startswith(onek):
            return bag_adi[len(onek):]
    return bag_adi


def tam_ad(tur: str, sinif: Optional[str], secici: Optional[str]) -> Optional[str]:
    """``-[Sınıf seçici]`` / ``+[Sınıf seçici]``; sınıf ya da seçici yoksa ``None``."""
    if not sinif or not secici:
        return None
    return f"{tur}[{sinif} {secici}]"


@dataclass
class YontemKaydi:
    """Bir yöntem kaydı. ``imp`` 0 ise uygulama adresi yok (ör. dış bağ)."""

    tur: str
    sinif: Optional[str]
    kategori: Optional[str]
    secici: Optional[str]
    tip: Optional[str]
    imp: int
    swift: bool
    protokolde: bool
    sinif_dis: bool
    kaynak: str
    liste_bicimi: str
    # denetimler (``ObjcOkuyucu.denetle``)
    imp_kodda: Optional[bool] = None
    imp_baslangic: Optional[bool] = None
    arite: str = ARITE_COZULEMEDI
    imp_paylasimli: bool = False

    @property
    def tam_ad(self) -> Optional[str]:
        return tam_ad(self.tur, self.sinif, self.secici)

    @property
    def ad_yazilabilir(self) -> bool:
        """Ad kanalına aday mı: tam ad var, IMP kodda, (tablo varsa) fonksiyon başlangıcı, tekil."""
        return (self.tam_ad is not None and self.imp != 0 and self.imp_kodda is True
                and self.imp_baslangic is not False and not self.imp_paylasimli)

    def as_dict(self) -> dict[str, Any]:
        return {
            "imp": self.imp, "adres": f"{self.imp:#x}" if self.imp else None,
            "tur": self.tur, "sinif": self.sinif, "kategori": self.kategori, "secici": self.secici,
            "tam_ad": self.tam_ad, "tip": self.tip, "swift": self.swift, "protokolde": self.protokolde,
            "sinif_dis": self.sinif_dis, "kaynak": self.kaynak, "liste_bicimi": self.liste_bicimi,
            "imp_kodda": self.imp_kodda, "imp_baslangic": self.imp_baslangic, "arite": self.arite,
            "imp_paylasimli": self.imp_paylasimli, "ad_yazilabilir": self.ad_yazilabilir,
        }


@dataclass
class SinifKaydi:
    adres: int
    ad: Optional[str]
    swift: bool
    ust: Optional[str]
    ust_dis: Optional[bool]
    ust_zinciri: list[str]
    meta: bool
    ornek_yontem: int
    sinif_yontemi: int
    protokoller: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "adres": f"{self.adres:#x}", "ad": self.ad, "swift": self.swift, "ust": self.ust,
            "ust_dis": self.ust_dis, "ust_zinciri": list(self.ust_zinciri), "meta": self.meta,
            "ornek_yontem": self.ornek_yontem, "sinif_yontemi": self.sinif_yontemi,
            "protokoller": list(self.protokoller),
        }


@dataclass
class ObjcSonuc:
    durum: str
    neden: Optional[str] = None
    siniflar: list[SinifKaydi] = field(default_factory=list)
    kategori_sayisi: int = 0
    protokol_sayisi: int = 0
    yontemler: list[YontemKaydi] = field(default_factory=list)
    sayaclar: dict[str, int] = field(default_factory=dict)
    denetim: dict[str, Any] = field(default_factory=dict)

    @property
    def okuma_hatasi(self) -> int:
        return sum(self.sayaclar.get(k, 0) for k in HATA_SAYACLARI)

    def ozet(self) -> dict[str, Any]:
        impli = [y for y in self.yontemler if y.imp]
        return {
            "durum": self.durum, "neden": self.neden,
            "sinif": len(self.siniflar), "swift_sinifi": sum(1 for s in self.siniflar if s.swift),
            "kategori": self.kategori_sayisi, "protokol": self.protokol_sayisi,
            "yontem_kaydi": len(self.yontemler), "imp_li_kayit": len(impli),
            "ad_yazilabilir": sum(1 for y in self.yontemler if y.ad_yazilabilir),
            "okuma_hatasi": self.okuma_hatasi, "sayaclar": dict(self.sayaclar),
            "denetim": dict(self.denetim),
        }


class ObjcOkuyucu:
    """Bir görüntüdeki ObjC sınıf / kategori / protokol yöntem listelerini okur."""

    def __init__(self, goruntu: Any) -> None:
        self.g = goruntu
        self.sayac: Counter = Counter()
        self._bolumler = list(goruntu.bolumler)
        self._bolum_araliklari = sorted((b.adres, b.adres + b.boyut) for b in self._bolumler if b.boyut > 0)
        self._bolum_baslari = [bas for bas, _son in self._bolum_araliklari]
        self._en_buyuk_bolum = max((son - bas for bas, son in self._bolum_araliklari), default=0)
        self._sinif_adi_onbellek: dict[int, Optional[str]] = {}

    # ---- temel okuma ---------------------------------------------------------------------
    def _yerel(self, adres: int) -> Optional[int]:
        """``adres``'teki göstericinin yerel hedefi (içe aktarım bağı ya da 0 ise ``None``)."""
        v = self.g.gosterici(adres)
        if isinstance(v, bool) or not isinstance(v, int) or v == 0:
            return None
        return v

    def _bolumde(self, adres: int) -> bool:
        """``adres`` bir bölümün içinde mi (bölüm başlangıçlarında ikili arama)."""
        i = bisect.bisect_right(self._bolum_baslari, adres) - 1
        while i >= 0:
            bas, son = self._bolum_araliklari[i]
            if adres < son:
                return True
            if adres - bas > self._en_buyuk_bolum:
                return False
            i -= 1
        return False

    def _cstr(self, adres: Optional[int]) -> Optional[str]:
        if not adres:
            return None
        return self.g.cstr(adres, CSTR_MAX)

    def _liste_girdileri(self, bolum_adlari: Iterable[str]) -> list[int]:
        """Gösterici listesi bölümlerindeki yerel hedefler (sırayla, tekrarsız)."""
        out: list[int] = []
        gorulen: set[int] = set()
        for ad in bolum_adlari:
            for b in self.g.bolumler_adli(ad):
                for i in range(b.boyut // POINTER_SIZE):
                    hedef = self._yerel(b.adres + POINTER_SIZE * i)
                    if hedef and hedef not in gorulen:
                        gorulen.add(hedef)
                        out.append(hedef)
        return out

    # ---- yöntem listesi ------------------------------------------------------------------
    def yontem_listesi(self, adres: Optional[int]) -> list[tuple[Optional[str], Optional[str], int, str]]:
        """``[(seçici, tip kodlaması, IMP, liste biçimi)]``; okunamazsa boş liste ve sayaç."""
        if not adres:
            return []
        adres &= ~LIST_PTR_LOW_BITS
        ef = self.g.u32(adres)
        sayi = self.g.u32(adres + 4)
        if ef is None or sayi is None:
            self.sayac[H_LISTE_OKUNAMADI] += 1
            return []
        if sayi > MAX_METHODS_PER_LIST:
            self.sayac[H_LISTE_SINIR] += 1
            return []
        entsize = ef & ~LIST_FLAG_MASK & 0xFFFFFFFF
        taban = adres + 8
        if ef & SMALL_LIST_FLAG:
            if entsize != SMALL_ENTSIZE:
                self.sayac[H_KUCUK_BOYUT] += 1
                return []
            return self._kucuk_liste(taban, sayi, bool(ef & DIRECT_SEL_FLAG))
        if entsize != BIG_ENTSIZE:
            self.sayac[H_BUYUK_BOYUT] += 1
            return []
        return self._buyuk_liste(taban, sayi)

    def _kucuk_liste(self, taban: int, sayi: int, secici_dogrudan: bool):
        out = []
        for i in range(sayi):
            e = taban + SMALL_ENTSIZE * i
            ad_ofs, tip_ofs, imp_ofs = self.g.i32(e), self.g.i32(e + 4), self.g.i32(e + 8)
            if ad_ofs is None or tip_ofs is None or imp_ofs is None:
                self.sayac[H_KAYIT_OKUNAMADI] += 1
                break
            # her ofset kendi alanının adresine göre
            ad_yeri = e + ad_ofs
            tip_yeri = e + 4 + tip_ofs if tip_ofs else None
            imp = e + 8 + imp_ofs if imp_ofs else 0
            if not self._bolumde(ad_yeri) or (tip_yeri is not None and not self._bolumde(tip_yeri)) \
                    or (imp and not self._bolumde(imp)):
                self.sayac[H_BOLUM_DISI] += 1
                continue
            if secici_dogrudan:
                secici = self._cstr(ad_yeri)
            else:
                secici = self._cstr(self._yerel(ad_yeri))  # seçici başvurusu (selref) üstünden
            if secici is None:
                self.sayac[H_SECICI_COZULEMEDI] += 1
            out.append((secici, self._cstr(tip_yeri), imp, BICIM_KUCUK))
        return out

    def _buyuk_liste(self, taban: int, sayi: int):
        out = []
        for i in range(sayi):
            e = taban + BIG_ENTSIZE * i
            if self.g.u64(e) is None:
                self.sayac[H_KAYIT_OKUNAMADI] += 1
                break
            secici = self._cstr(self._yerel(e))
            tip = self._cstr(self._yerel(e + 8))
            imp_ham = self.g.gosterici(e + 16)
            if isinstance(imp_ham, int) and not isinstance(imp_ham, bool):
                imp = imp_ham
            else:
                imp = 0
                if imp_ham is not None:
                    self.sayac[B_IMP_BAG] += 1
            if secici is None:
                self.sayac[H_SECICI_COZULEMEDI] += 1
            out.append((secici, tip, imp, BICIM_BUYUK))
        return out

    # ---- sınıf ---------------------------------------------------------------------------
    def _sinif_ro(self, sinif: int) -> tuple[Optional[int], bool]:
        """``(class_ro_t adresi, Swift mi)``; okunamazsa ``(None, False)``."""
        bits = self.g.gosterici(sinif + CLASS_BITS)
        if isinstance(bits, bool) or not isinstance(bits, int):
            return None, False
        ro = bits & DATA_MASK
        return (ro or None), bool(bits & SWIFT_BITS)

    def _sinif_adi_dogrudan(self, sinif: int) -> Optional[str]:
        if sinif not in self._sinif_adi_onbellek:
            ro, _sw = self._sinif_ro(sinif)
            self._sinif_adi_onbellek[sinif] = self._cstr(self._yerel(ro + RO_NAME)) if ro else None
        return self._sinif_adi_onbellek[sinif]

    def _gosterilen_sinif(self, deger: Any, yerel: dict[int, dict[str, Any]]) -> tuple[Optional[str], Optional[bool]]:
        """Sınıf göstericisinden ``(ad, dış mı)``: yerel sınıf, dış bağ ya da yok."""
        if deger is None:
            return None, None
        if isinstance(deger, int) and not isinstance(deger, bool):
            if deger in yerel:
                return yerel[deger]["ad"], False
            self.sayac[B_SINIF_LISTEDE_YOK] += 1
            return self._sinif_adi_dogrudan(deger), False
        bag_adi = getattr(deger, "ad", None)
        if isinstance(bag_adi, str):
            return sinif_bagi_adi(bag_adi), True
        return None, None

    def _ust_zinciri(self, sinif: int, yerel: dict[int, dict[str, Any]]) -> list[str]:
        """Üst sınıf zinciri (yerel sınıflar boyunca, ilk dış bağda biter); döngü sayaçla kesilir."""
        zincir: list[str] = []
        gorulen = {sinif}
        su_an = sinif
        for _ in range(MAX_SUPER_CHAIN):
            ust = self.g.gosterici(su_an + CLASS_SUPERCLASS)
            if ust is None or ust == 0:
                return zincir
            if isinstance(ust, int) and not isinstance(ust, bool):
                if ust in gorulen:
                    self.sayac[H_DONGUSEL_UST] += 1
                    return zincir
                gorulen.add(ust)
                ad = yerel[ust]["ad"] if ust in yerel else self._sinif_adi_dogrudan(ust)
                zincir.append(ad if ad is not None else f"{ust:#x}")
                su_an = ust
                continue
            bag_adi = getattr(ust, "ad", None)
            if isinstance(bag_adi, str):
                zincir.append(sinif_bagi_adi(bag_adi))
            return zincir
        self.sayac[H_DONGUSEL_UST] += 1
        return zincir

    def siniflar(self) -> dict[int, dict[str, Any]]:
        out: dict[int, dict[str, Any]] = {}
        for c in self._liste_girdileri(CLASS_SECTIONS):
            ro, swift = self._sinif_ro(c)
            if not ro:
                self.sayac[H_SINIF_VERISI] += 1
                continue
            bilgi: dict[str, Any] = {
                "ad": self._cstr(self._yerel(ro + RO_NAME)), "swift": swift,
                "yontem": self.yontem_listesi(self._yerel(ro + RO_BASE_METHODS)),
                "protokol": self.protokol_listesi(self._yerel(ro + RO_BASE_PROTOCOLS)),
                "sinif_yontemi": [], "meta": False,
            }
            meta = self._yerel(c + CLASS_ISA)
            if meta:
                mro, _msw = self._sinif_ro(meta)
                if mro:
                    bilgi["meta"] = True
                    bilgi["sinif_yontemi"] = self.yontem_listesi(self._yerel(mro + RO_BASE_METHODS))
                    bilgi["protokol"] += self.protokol_listesi(self._yerel(mro + RO_BASE_PROTOCOLS))
            out[c] = bilgi
            self._sinif_adi_onbellek[c] = bilgi["ad"]
        return out

    # ---- protokol ------------------------------------------------------------------------
    def protokol_listesi(self, adres: Optional[int]) -> list[int]:
        if not adres:
            return []
        sayi = self.g.u64(adres)
        if sayi is None:
            self.sayac[H_LISTE_OKUNAMADI] += 1
            return []
        if sayi > MAX_PROTOCOLS_PER_LIST:
            self.sayac[H_PROTOKOL_SINIR] += 1
            return []
        out = []
        for i in range(sayi):
            p = self._yerel(adres + POINTER_SIZE + POINTER_SIZE * i)
            if p:
                out.append(p)
        return out

    def protokol(self, adres: int) -> tuple[Optional[str], set[str]]:
        """``(protokol adı, dört yöntem listesindeki seçiciler)``."""
        ad = self._cstr(self._yerel(adres + PROTO_NAME))
        seciciler: set[str] = set()
        for ofs in PROTO_METHOD_LISTS:
            for secici, _tip, _imp, _b in self.yontem_listesi(self._yerel(adres + ofs)):
                if secici is not None:
                    seciciler.add(secici)
        return ad, seciciler

    # ---- kategori ------------------------------------------------------------------------
    def kategoriler(self) -> list[dict[str, Any]]:
        out = []
        for c in self._liste_girdileri(CATEGORY_SECTIONS):
            out.append({
                "ad": self._cstr(self._yerel(c + CAT_NAME)),
                "sinif": self.g.gosterici(c + CAT_CLASS),
                "yontem": self.yontem_listesi(self._yerel(c + CAT_INSTANCE_METHODS)),
                "sinif_yontemi": self.yontem_listesi(self._yerel(c + CAT_CLASS_METHODS)),
                "protokol": self.protokol_listesi(self._yerel(c + CAT_PROTOCOLS)),
            })
        return out

    # ---- denetimler (plan kalem 2) -------------------------------------------------------
    def denetle(self, yontemler: list[YontemKaydi]) -> dict[str, Any]:
        kod = list(self.g.kod_bolumleri)
        baslangic_ham = self.g.fonksiyon_baslangiclari()
        baslangiclar = set(baslangic_ham) if baslangic_ham is not None else None

        def kodda(a: int) -> bool:
            return any(b.icerir(a) for b in kod)

        imp_adlari: dict[int, set[str]] = {}
        for y in yontemler:
            if y.imp and y.tam_ad:
                imp_adlari.setdefault(y.imp, set()).add(y.tam_ad)
        arite = Counter()
        for y in yontemler:
            y.arite = arite_hukmu(y.secici, y.tip)
            if not y.imp:
                continue
            arite[y.arite] += 1
            y.imp_kodda = kodda(y.imp)
            y.imp_baslangic = (y.imp in baslangiclar) if baslangiclar is not None else None
            y.imp_paylasimli = len(imp_adlari.get(y.imp, ())) > 1
        ayrik = sorted({y.imp for y in yontemler if y.imp})
        return {
            "ayrik_imp": len(ayrik),
            "imp_kod_bolumunde": sum(1 for a in ayrik if kodda(a)),
            "imp_kod_disi": sum(1 for a in ayrik if not kodda(a)),
            "imp_fonksiyon_baslangici": (sum(1 for a in ayrik if a in baslangiclar)
                                         if baslangiclar is not None else None),
            "fonksiyon_baslangic_tablosu": baslangiclar is not None,
            "birden_cok_adli_imp": sum(1 for v in imp_adlari.values() if len(v) > 1),
            "arite": {k: arite[k] for k in (ARITE_UYAN, ARITE_UYMAYAN, ARITE_COZULEMEDI)},
        }

    # ---- bütün ---------------------------------------------------------------------------
    def oku(self) -> ObjcSonuc:
        siniflar = self.siniflar()
        kategoriler = self.kategoriler()
        protokol_adresleri = self._liste_girdileri(PROTOCOL_SECTIONS)
        protokoller = {p: self.protokol(p) for p in protokol_adresleri}

        def protokol_secicileri(adresler: list[int]) -> set[str]:
            s: set[str] = set()
            for p in adresler:
                if p not in protokoller:
                    protokoller[p] = self.protokol(p)
                s |= protokoller[p][1]
            return s

        yontemler: list[YontemKaydi] = []
        sinif_kayitlari: list[SinifKaydi] = []
        for c, b in siniflar.items():
            ps = protokol_secicileri(b["protokol"])
            ust_ad, ust_dis = self._gosterilen_sinif(self.g.gosterici(c + CLASS_SUPERCLASS), siniflar)
            for tur, liste in ((TUR_ORNEK, b["yontem"]), (TUR_SINIF, b["sinif_yontemi"])):
                for secici, tip, imp, bicim in liste:
                    yontemler.append(YontemKaydi(
                        tur=tur, sinif=b["ad"], kategori=None, secici=secici, tip=tip, imp=imp,
                        swift=b["swift"], protokolde=secici in ps, sinif_dis=False,
                        kaynak=KAYNAK_SINIF, liste_bicimi=bicim))
            sinif_kayitlari.append(SinifKaydi(
                adres=c, ad=b["ad"], swift=b["swift"], ust=ust_ad, ust_dis=ust_dis,
                ust_zinciri=self._ust_zinciri(c, siniflar), meta=b["meta"],
                ornek_yontem=len(b["yontem"]), sinif_yontemi=len(b["sinif_yontemi"]),
                protokoller=[protokoller[p][0] or f"{p:#x}" for p in b["protokol"]]))
        for k in kategoriler:
            ad, dis = self._gosterilen_sinif(k["sinif"], siniflar)
            ps = protokol_secicileri(k["protokol"])
            for tur, liste in ((TUR_ORNEK, k["yontem"]), (TUR_SINIF, k["sinif_yontemi"])):
                for secici, tip, imp, bicim in liste:
                    yontemler.append(YontemKaydi(
                        tur=tur, sinif=ad, kategori=k["ad"], secici=secici, tip=tip, imp=imp,
                        swift=False, protokolde=secici in ps, sinif_dis=bool(dis),
                        kaynak=KAYNAK_KATEGORI, liste_bicimi=bicim))
        denetim = self.denetle(yontemler)
        sonuc = ObjcSonuc(
            durum=DURUM_CALISTI, siniflar=sinif_kayitlari, kategori_sayisi=len(kategoriler),
            protokol_sayisi=len(protokol_adresleri), yontemler=yontemler,
            sayaclar=dict(self.sayac), denetim=denetim)
        neden = tutarsizlik_nedeni(sonuc)
        if neden is not None:
            sonuc.durum = DURUM_TUTARSIZ
            sonuc.neden = neden
        return sonuc


def tutarsizlik_nedeni(sonuc: ObjcSonuc) -> Optional[str]:
    """Yapı ihlali varsa neden (ad listesi yazılmaz): kod bölümü dışında IMP ya da bölüm dışına göreli ofset.

    Bu iki ihlal biçimin yanlış okunduğunu gösterir (P-ÜV1'in K2 denetiminin karşılığı). Arite uyumsuzluğu
    ve fonksiyon başlangıcı olmayan IMP kayıt düzeyinde işaretlenir (``ad_yazilabilir``), durumu bozmaz.
    """
    disi = sonuc.denetim.get("imp_kod_disi") or 0
    bolum_disi = sonuc.sayaclar.get(H_BOLUM_DISI, 0)
    parcalar = []
    if disi:
        parcalar.append(f"kod bölümü dışında {disi} IMP")
    if bolum_disi:
        parcalar.append(f"bölüm dışına gösteren {bolum_disi} göreli ofset")
    return "; ".join(parcalar) if parcalar else None


def oku(goruntu: Any) -> ObjcSonuc:
    """Görüntüdeki ObjC yöntemlerini oku. İstisna atmaz; durum ``ObjcSonuc.durum``'dadır."""
    try:
        bicim = goruntu.bicim
        bolum_adlari = {b.ad for b in goruntu.bolumler}
        objc_bolumu = any(k in bolum_adlari for k in OBJC_SECTIONS)
        if bicim != BICIM_MACHO:
            if objc_bolumu or any("__objc_" in a for a in bolum_adlari):
                return ObjcSonuc(DURUM_DESTEKLENMIYOR, f"{bicim} biçiminde ObjC üst verisi okunmuyor (yalnız Mach-O)")
            return ObjcSonuc(DURUM_VERI_YOK, f"Mach-O değil ({bicim})")
        if goruntu.gosterici_boyutu != POINTER_SIZE:
            return ObjcSonuc(DURUM_DESTEKLENMIYOR, f"gösterici boyu {goruntu.gosterici_boyutu} (yalnız 64 bit)")
        if not objc_bolumu:
            return ObjcSonuc(DURUM_VERI_YOK, "ObjC sınıf / kategori / protokol listesi bölümü yok")
        return ObjcOkuyucu(goruntu).oku()
    except Exception as exc:  # okuyucu istisna atmaz; beklenmeyen hata durumla döner
        logger.warning("ObjC üst verisi okunamadı: %s", exc)
        return ObjcSonuc(DURUM_HATA, f"{type(exc).__name__}: {exc}")
