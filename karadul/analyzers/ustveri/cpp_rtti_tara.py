"""C++ (Itanium ABI) RTTI / vtable sembolsüz tarayıcı (P-ÜV4; ÜST VERİ hattı; IMZA-16).

Soyulmuş ikilide sınıf adları (typeinfo), vtable'lar ve yuva işlevleri. Sembol tablosuna yalnız zayıf bağ adını
yerel adrese çevirmek için bakılır. Ghidra'sız; yalnız dosya baytları. İkili çalıştırılmaz.

Biçim kaynağı: Itanium C++ ABI §2.5 (vtable yerleşimi), §2.9.5 (RTTI yerleşimi)
(https://itanium-cxx-abi.github.io/cxx-abi/abi.html) ve llvm-project ``libcxxabi/src/private_typeinfo.h``
(araştırma başvurusu ``scripts/arge/ustveri/cpp_rtti_tara.py``; bu modül ondan yeniden yazıldı):

- **typeinfo nesnesi** = ilk sözcüğü ``__cxxabiv1::__class_type_info`` / ``__si_class_type_info`` /
  ``__vmi_class_type_info`` vtable'ına **içe aktarım bağı** olan nesne (bağ ada göre çözüldüğü için soyulmuş
  ikilide de durur). +8: ad dizgisine gösterici (Apple arm64'te en üst bit "tekil değil" işareti: maskelenir,
  işaret kaydedilir; GCC adsız ad alanı adının başına ``*`` koyar: ad parçası sayılmaz, işaret kaydedilir).
  ``si``: +16 taban typeinfo. ``vmi``: +16 bayrak u32, +20 taban sayısı u32, +24'ten 16 baytlık
  (taban typeinfo, ofset-bayrak) kayıtları (bayrak biti 0 sanal, biti 1 açık; ofset = değer >> 8).
- **vtable** = [tepeye uzaklık: düzeltme yeri olmayan, 0 ya da küçük negatif tam sayı] [typeinfo göstericisi]
  [kod göstericileri…]. typeinfo göstericisi bir typeinfo nesnesinin içindeyse vtable değildir. İçe aktarım yuvası
  (ör. ``__cxa_pure_virtual``) atlanır ama sıra numarası ilerler (yuva adresi 0).
- **Zayıf bağ**: dışa açık typeinfo, ad dizgisi ve yuva işlevi başvuruları yeniden konumlama değil ada göre bağ
  olabilir; bağ adı aynı ikilide tanımlıysa yerel adrese çevrilir.
- **Yuva → sınıf** (plan kalem 4): aynı işlev birden çok sınıfın vtable'ında görünüyorsa (devralınan yuva) öbürlerinin
  hepsinin (geçişli) tabanı olan sınıfa bağlanır; böyle tek sınıf yoksa ``belirsiz`` (ad adayı verilmez).

Girdi bir P-ÜV0 görüntü nesnesidir (``karadul.analyzers.ustveri.goruntu.Goruntu``). Yuva adresi bir ad değildir:
``Sınıf_vfunc_N`` yalnız kanıt satırıdır (A-32; bağlama P-ÜV6b). Sahte veri yok: okunamayan kayıt atlanır ve sayaç
artar; ad uydurulmaz. Tarayıcı istisna atmaz (beklenmeyen hata ``hata`` durumuyla döner).
"""

from __future__ import annotations

import bisect
import itertools
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from karadul.analyzers.ustveri.goruntu import (
    BICIM_ELF,
    BICIM_MACHO,
    DURUM_CALISTI,
    DURUM_DESTEKLENMIYOR,
    DURUM_HATA,
    DURUM_KAPALI,
    DURUM_VERI_YOK,
    KISIM_DUZELTME,
    SEMBOL_DIGER,
    SEMBOL_HATA_AYIKLAMA,
    SEMBOL_TANIMSIZ,
    Bag,
)
from karadul.config import BinaryReconstructionConfig

logger = logging.getLogger(__name__)

# --- durumlar: hepsi goruntu'dan (``kapali`` dahil; P-ÜV6b: tek tanım) ------------------------------------------

# --- biçim sabitleri (Itanium ABI §2.9.5; libcxxabi private_typeinfo.h) -----------------------------------------
TUR_CLASS = "class"
TUR_SI = "si"
TUR_VMI = "vmi"
CXXABI_TI_VTABLE = {
    "_ZTVN10__cxxabiv117__class_type_infoE": TUR_CLASS,
    "_ZTVN10__cxxabiv120__si_class_type_infoE": TUR_SI,
    "_ZTVN10__cxxabiv121__vmi_class_type_infoE": TUR_VMI,
}
TI_AD = 8                 # ad dizgisi göstericisi
TI_SI_TABAN = 16          # si: taban typeinfo
TI_VMI_BAYRAK = 16        # vmi: __flags (u32)
TI_VMI_SAYI = 20          # vmi: __base_count (u32)
TI_VMI_TABANLAR = 24      # vmi: __base_info[]
VMI_TABAN_KAYDI = 16      # (__base_type, __offset_flags)
TI_BOYUT = {TUR_CLASS: 16, TUR_SI: 24}
VMI_TABAN_SANAL = 0x1     # __virtual_mask
VMI_TABAN_ACIK = 0x2      # __public_mask
VMI_OFSET_KAYMA = 8       # __offset_shift
AD_TEKIL_OLMAYAN_BITI = 63            # Apple arm64: ad göstericisinin en üst biti
AD_MASKE = (1 << 56) - 1              # high8 alanı (zincirli düzeltme) adresin parçası değil
GCC_YEREL_AD_ON = "*"                 # GCC: adsız ad alanındaki tipin adı "*" ile başlar
SOZCUK = 8                            # yalnız 64 bit
_U64 = 1 << 64

# yuva yürüyüşünü bitiren dış bağ adları (işlev değil: typeinfo / vtable / VTT / ad dizgisi)
_ISLEV_OLMAYAN_ONEKLER = ("_ZTI", "_ZTV", "_ZTS", "_ZTT", "_ZTC")

# --- sağlamlık sınırları (plan kalem 6) -------------------------------------------------------------------------
VMI_TABAN_AZAMI = 64
TEPEYE_UZAKLIK_ALT = -(1 << 20)
AD_AZAMI = 2048                       # ad dizgisi üst sınırı (bayt)
SURE_SINIRI_SN = 10.0                 # tarama süre sınırı (görüntü kurulumu hariç)
_SURE_DENETIM_ARALIGI = 4096
YUVA_AZAMI_ONTANIM = BinaryReconstructionConfig.rtti_max_vtable_entries  # config.py öntanımı (64)

# --- sayaçlar ---------------------------------------------------------------------------------------------------
# okuma hataları / sınırlar
H_AD_OKUNAMADI = "ad_okunamadi"
H_AD_DIS_BAG = "ad_cozulemeyen_bag"
H_VMI_SINIR = "vmi_taban_sayisi_siniri_asildi"
H_YUVA_SINIR = "yuva_siniri_asilan_vtable"
H_DONGUSEL_TABAN = "dongusel_taban"
HATA_SAYACLARI = (H_AD_OKUNAMADI, H_AD_DIS_BAG, H_VMI_SINIR, H_DONGUSEL_TABAN)
# bilgi
B_ZAYIF_TI = "zayif_bagli_typeinfo_adi"
B_ZAYIF_YUVA = "zayif_bagli_yuva"
B_TEKIL_OLMAYAN = "tekil_olmayan_ad"
B_YEREL_AD = "gcc_yerel_ad"
B_DIS_TABAN = "dis_taban"

# --- yuva → sınıf bağı -----------------------------------------------------------------------------------------
BAG_TEK = "tek_sinif"
BAG_TABAN = "en_taban_sinif"
BAG_BELIRSIZ = "belirsiz"

# _coz dönüşü
_YEREL = "yerel"
_DIS = "dis"


@dataclass
class TabanKaydi:
    """typeinfo'nun taban kaydı: yerel typeinfo adresi ya da dış bağ adı."""

    typeinfo: Optional[int] = None       # yerel taban typeinfo adresi
    dis_ad: Optional[str] = None         # dış (içe aktarılan) taban typeinfo sembolü
    sanal: bool = False
    acik: bool = True
    ofset: Optional[int] = None

    def as_dict(self) -> dict[str, Any]:
        return {"typeinfo": self.typeinfo, "dis_ad": self.dis_ad, "sanal": self.sanal, "acik": self.acik,
                "ofset": self.ofset}


@dataclass
class TypeinfoKaydi:
    adres: int
    tur: str
    ad: str                               # ikilideki ad dizgisi (mangled; GCC "*" öneki soyulmuş)
    ad_adresi: int
    tekil_olmayan: bool = False
    yerel_ad: bool = False                # GCC "*" öneki vardı
    zayif_adla_bagli: bool = False
    tabanlar: list[TabanKaydi] = field(default_factory=list)
    boyut: int = 16
    cozulmus: Optional[str] = None        # çözülmüş ad (çözülemezse None)

    @property
    def gorunen_ad(self) -> str:
        return self.cozulmus or self.ad

    def as_dict(self) -> dict[str, Any]:
        return {"adres": self.adres, "tur": self.tur, "ad": self.ad, "cozulmus": self.cozulmus,
                "ad_adresi": self.ad_adresi, "tekil_olmayan": self.tekil_olmayan, "yerel_ad": self.yerel_ad,
                "zayif_adla_bagli": self.zayif_adla_bagli, "tabanlar": [t.as_dict() for t in self.tabanlar]}


@dataclass
class VtableKaydi:
    adres: int                            # tepeye uzaklık sözcüğünün adresi
    typeinfo: int
    tepeye_uzaklik: int
    yuvalar: list[Optional[int]] = field(default_factory=list)  # None: içe aktarım yuvası
    zayif_yuva: int = 0
    kesildi: bool = False                 # yuva üst sınırında kesildi

    @property
    def birincil(self) -> bool:
        return self.tepeye_uzaklik == 0

    def as_dict(self) -> dict[str, Any]:
        return {"adres": self.adres, "typeinfo": self.typeinfo, "tepeye_uzaklik": self.tepeye_uzaklik,
                "yuvalar": [y or 0 for y in self.yuvalar], "zayif_yuva": self.zayif_yuva,
                "kesildi": self.kesildi}


@dataclass
class IslevBagi:
    adres: int
    siniflar: list[int]                   # göründüğü vtable'ların typeinfo adresleri (sıralı, tekil)
    yerler: list[tuple[int, int]]         # (vtable adresi, yuva sırası)
    sinif: Optional[int] = None           # bağlandığı typeinfo (belirsizse None)
    karar: str = BAG_TEK

    def as_dict(self, ti: dict[int, TypeinfoKaydi]) -> dict[str, Any]:
        return {"adres": self.adres, "karar": self.karar,
                "sinif": ti[self.sinif].gorunen_ad if self.sinif is not None else None,
                "sinif_typeinfo": self.sinif,
                "siniflar": [ti[s].gorunen_ad for s in self.siniflar],
                "yerler": [{"vtable": v, "sira": s} for v, s in self.yerler]}


@dataclass
class RttiSonuc:
    durum: str
    neden: Optional[str] = None
    typeinfolar: list[TypeinfoKaydi] = field(default_factory=list)
    vtablelar: list[VtableKaydi] = field(default_factory=list)
    islevler: list[IslevBagi] = field(default_factory=list)
    sayaclar: dict[str, int] = field(default_factory=dict)
    sure_sn: Optional[float] = None

    @property
    def okuma_hatasi(self) -> int:
        return sum(self.sayaclar.get(k, 0) for k in HATA_SAYACLARI)

    def ti_sozlugu(self) -> dict[int, TypeinfoKaydi]:
        return {t.adres: t for t in self.typeinfolar}

    def ozet(self) -> dict[str, Any]:
        return {
            "durum": self.durum, "neden": self.neden,
            "typeinfo": len(self.typeinfolar),
            "typeinfo_tur": dict(Counter(t.tur for t in self.typeinfolar)),
            "vtable": len(self.vtablelar),
            "birincil_vtable": sum(1 for v in self.vtablelar if v.birincil),
            "vtable_olan_sinif": len({v.typeinfo for v in self.vtablelar}),
            "yuva": sum(len(v.yuvalar) for v in self.vtablelar),
            "ice_aktarim_yuvasi": sum(1 for v in self.vtablelar for y in v.yuvalar if y is None),
            "ayrik_islev": len(self.islevler),
            "cok_sinifli_islev": sum(1 for i in self.islevler if len(i.siniflar) > 1),
            "bagli_islev": sum(1 for i in self.islevler if i.sinif is not None),
            "belirsiz_islev": sum(1 for i in self.islevler if i.karar == BAG_BELIRSIZ),
            "okuma_hatasi": self.okuma_hatasi, "sayaclar": dict(self.sayaclar), "sure_sn": self.sure_sn,
        }

    def rtti_classes(self) -> list[dict[str, Any]]:
        """``_add_rtti``'nin beklediği biçim (``_feedback_naming_candidates.py``).

        Her typeinfo için bir kayıt; ``methods`` birincil vtable'ın yuvaları: işlev bu sınıfa bağlıysa adresi, değilse
        (içe aktarım yuvası, başka sınıfa bağlı devralınan yuva, belirsiz işlev) 0. Sıra numarası korunur.
        """
        ti = self.ti_sozlugu()
        bag = {i.adres: i.sinif for i in self.islevler}
        birincil: dict[int, VtableKaydi] = {}
        for v in self.vtablelar:  # adres sırasıyla; sınıfın ilk birincil vtable'ı
            if v.birincil and v.typeinfo not in birincil:
                birincil[v.typeinfo] = v
        out = []
        for t in self.typeinfolar:
            v = birincil.get(t.adres)
            methods = [] if v is None else [y if (y and bag.get(y) == t.adres) else 0 for y in v.yuvalar]
            bases = []
            for b in t.tabanlar:
                if b.typeinfo is not None and b.typeinfo in ti:
                    bases.append(ti[b.typeinfo].gorunen_ad)
                elif b.dis_ad:
                    bases.append(b.dis_ad)
            out.append({"name": t.gorunen_ad, "mangled": t.ad, "methods": methods, "bases": bases,
                        "vtable": v.adres if v is not None else None, "typeinfo": t.adres})
        return out


class RttiTarayici:
    """Bir görüntüdeki Itanium RTTI / vtable kayıtlarını tarar."""

    def __init__(self, goruntu: Any, *, azami_yuva: int = YUVA_AZAMI_ONTANIM,
                 sure_siniri: float = SURE_SINIRI_SN, zaman: Callable[[], float] = time.monotonic) -> None:
        self.g = goruntu
        self.azami_yuva = azami_yuva
        self.sure_siniri = sure_siniri
        self.zaman = zaman
        self.sayac: Counter = Counter()
        self._yerel_tanim: Optional[dict[str, int]] = None
        kod = sorted((b.adres, b.adres + b.boyut) for b in goruntu.bolumler if b.kod and b.bellekte)
        self._kod_bas = [k[0] for k in kod]
        self._kod_son = [k[1] for k in kod]
        self._bas = 0.0
        self._adim = 0

    # ---- yardımcılar ------------------------------------------------------------------------------------------
    def _sure_asildi(self) -> bool:
        self._adim += 1
        if self._adim % _SURE_DENETIM_ARALIGI:
            return False
        return self.zaman() - self._bas > self.sure_siniri

    def _kodda(self, adres: int) -> bool:
        i = bisect.bisect_right(self._kod_bas, adres) - 1
        return i >= 0 and adres < self._kod_son[i]

    def _yerel(self) -> dict[str, int]:
        """Aynı ikilide tanımlı (C++) sembol adı → adres (zayıf bağ çözümü için; ilk istekte)."""
        if self._yerel_tanim is None:
            self._yerel_tanim = {}
            for s in self.g.semboller():
                if not s.ad or s.tur in (SEMBOL_TANIMSIZ, SEMBOL_HATA_AYIKLAMA, SEMBOL_DIGER):
                    continue
                if s.ad.startswith(("_Z", "__Z")):
                    self._yerel_tanim.setdefault(s.ad, s.adres)
        return self._yerel_tanim

    def _coz(self, adres: int) -> Optional[tuple]:
        """Gösterici: ``(yerel, adres, zayıf mı, en üst bit)`` | ``(dis, ad)`` | ``None``."""
        p = self.g.gosterici(adres)
        if p is None:
            return None
        zayif = False
        if isinstance(p, Bag):
            yerel = self._yerel().get(p.ad)
            if yerel is None:
                return (_DIS, p.ad)
            p, zayif = yerel + p.ek, True  # ek "tekil değil" bitini taşıyabilir (64 bit ekli içe aktarım)
        ham = int(p) % _U64
        return (_YEREL, ham & AD_MASKE, zayif, bool(ham >> AD_TEKIL_OLMAYAN_BITI))

    @staticmethod
    def _normal(ad: str) -> str:
        """Mach-O C önekini soy (``__ZTV…`` → ``_ZTV…``); ELF adı değişmez."""
        return ad[1:] if ad.startswith("__Z") else ad

    def _yerler(self) -> list[Iterable[int]]:
        """Gösterici olabilecek sözcük adresleri (yeniden yinelenebilir parçalar; ``_yerleri_gez`` ile gezilir).

        Zincirli düzeltmeli Mach-O'da bütün göstericiler düzeltme yeridir (yalnız onlar); öbür biçimlerde (ELF,
        eski ``LC_DYLD_INFO`` Mach-O, bellek görüntüsü) kod dışı her yüklenen bölümün sözcükleri (``range``: büyük
        bölümde bellek şişmez).
        """
        g = self.g
        if getattr(g, "zincirli_duzeltme", False) and callable(getattr(g, "duzeltmeler", None)):
            return [sorted(g.duzeltmeler())]
        out: list[Iterable[int]] = []
        for b in g.bolumler:
            if b.kod or not b.bellekte or b.boyut < SOZCUK:
                continue
            if g.oku(b.adres, SOZCUK) is None:  # dosyada karşılığı yok (sıfır dolgulu)
                continue
            ilk = b.adres + (-b.adres) % SOZCUK
            out.append(range(ilk, b.adres + b.boyut - SOZCUK + 1, SOZCUK))
        return out

    @staticmethod
    def _yerleri_gez(yerler: list[Iterable[int]]) -> Iterable[int]:
        return itertools.chain.from_iterable(yerler)

    # ---- tarama -----------------------------------------------------------------------------------------------
    def tara(self) -> RttiSonuc:
        # Görüntü hazırlığı (sembol tablosu, düzeltme zinciri) süre sınırına girmez; sınır taramanın kendisi için.
        self._yerel()
        yerler = self._yerler()
        self._bas = self.zaman()
        ti = self._typeinfolar(self._yerleri_gez(yerler))
        if ti is None:
            return self._sure_sonucu()
        duz = (getattr(self.g, "durum", None) or {}).get(KISIM_DUZELTME, {})
        if duz.get("durum") == DURUM_HATA:  # bozuk zincir / tablo: göstericilere güvenilmez
            return RttiSonuc(DURUM_HATA, f"görüntünün düzeltme okuması bozuk: {duz.get('neden')}",
                             sayaclar=dict(self.sayac), sure_sn=round(self.zaman() - self._bas, 3))
        if not ti:
            return RttiSonuc(DURUM_VERI_YOK, "Itanium typeinfo nesnesi bulunamadı", sayaclar=dict(self.sayac),
                             sure_sn=round(self.zaman() - self._bas, 3))
        vt = self._vtablelar(self._yerleri_gez(yerler), ti)
        if vt is None:
            return self._sure_sonucu()
        islevler = self._islev_baglari(vt, ti)
        _adlari_coz(ti.values())
        return RttiSonuc(DURUM_CALISTI, None, sorted(ti.values(), key=lambda t: t.adres), vt, islevler,
                         dict(self.sayac), round(self.zaman() - self._bas, 3))

    def _sure_sonucu(self) -> RttiSonuc:
        return RttiSonuc(DURUM_HATA, f"süre sınırı aşıldı ({self.sure_siniri:g} sn)", sayaclar=dict(self.sayac),
                         sure_sn=round(self.zaman() - self._bas, 3))

    def _typeinfolar(self, yerler: Iterable[int]) -> Optional[dict[int, TypeinfoKaydi]]:
        ti: dict[int, TypeinfoKaydi] = {}
        for loc in yerler:
            if self._sure_asildi():
                return None
            p = self.g.gosterici(loc)
            if not isinstance(p, Bag):
                continue
            tur = CXXABI_TI_VTABLE.get(self._normal(p.ad))
            if tur is None:
                continue
            kayit = self._typeinfo_oku(loc, tur)
            if kayit is not None:
                ti[loc] = kayit
        return ti

    def _typeinfo_oku(self, loc: int, tur: str) -> Optional[TypeinfoKaydi]:
        c = self._coz(loc + TI_AD)
        if c is None or c[0] != _YEREL:
            self.sayac[H_AD_DIS_BAG if c is not None else H_AD_OKUNAMADI] += 1
            return None
        _t, ad_adresi, zayif, tekil_olmayan = c
        ad = self.g.cstr(ad_adresi, AD_AZAMI)
        if not ad:
            self.sayac[H_AD_OKUNAMADI] += 1
            return None
        yerel_ad = ad.startswith(GCC_YEREL_AD_ON)
        if yerel_ad:
            ad = ad[len(GCC_YEREL_AD_ON):]
            self.sayac[B_YEREL_AD] += 1
        if zayif:
            self.sayac[B_ZAYIF_TI] += 1
        if tekil_olmayan:
            self.sayac[B_TEKIL_OLMAYAN] += 1
        k = TypeinfoKaydi(loc, tur, ad, ad_adresi, tekil_olmayan, yerel_ad, zayif)
        if tur == TUR_SI:
            k.tabanlar.append(self._taban(loc + TI_SI_TABAN))
            k.boyut = TI_BOYUT[TUR_SI]
        elif tur == TUR_VMI:
            n = self.g.u32(loc + TI_VMI_SAYI)
            if n is None or n > VMI_TABAN_AZAMI:
                self.sayac[H_VMI_SINIR] += 1
                n = 0
            for i in range(n):
                kayit = loc + TI_VMI_TABANLAR + VMI_TABAN_KAYDI * i
                tb = self._taban(kayit)
                of = self.g.u64(kayit + SOZCUK)
                if of is not None:
                    if of >= 1 << 63:
                        of -= _U64
                    tb.sanal = bool(of & VMI_TABAN_SANAL)
                    tb.acik = bool(of & VMI_TABAN_ACIK)
                    tb.ofset = of >> VMI_OFSET_KAYMA
                k.tabanlar.append(tb)
            k.boyut = TI_VMI_TABANLAR + VMI_TABAN_KAYDI * n
        else:
            k.boyut = TI_BOYUT[TUR_CLASS]
        return k

    def _taban(self, adres: int) -> TabanKaydi:
        c = self._coz(adres)
        if c is None:
            return TabanKaydi()
        if c[0] == _DIS:
            self.sayac[B_DIS_TABAN] += 1
            return TabanKaydi(dis_ad=self._normal(c[1]))
        return TabanKaydi(typeinfo=c[1])

    def _vtablelar(self, yerler: Iterable[int], ti: dict[int, TypeinfoKaydi]) -> Optional[list[VtableKaydi]]:
        ic: set[int] = set()
        for loc, t in ti.items():
            ic.update(range(loc + SOZCUK, loc + t.boyut, SOZCUK))
        vt: list[VtableKaydi] = []
        for loc in yerler:
            if self._sure_asildi():
                return None
            if loc in ic or loc in ti:
                continue
            c = self._coz(loc)
            if c is None or c[0] != _YEREL or c[1] not in ti:
                continue
            ott = self._tepeye_uzaklik(loc - SOZCUK)
            if ott is None:
                continue
            v = VtableKaydi(loc - SOZCUK, c[1], ott)
            self._yuvalari_oku(v, loc + SOZCUK, ti)
            if v.yuvalar:
                vt.append(v)
        return vt

    def _tepeye_uzaklik(self, adres: int) -> Optional[int]:
        """Düzeltme yeri olmayan, ``TEPEYE_UZAKLIK_ALT`` … 0 aralığında tam sayı; değilse ``None``."""
        p = self.g.gosterici(adres)
        if isinstance(p, Bag):
            return None
        ham = self.g.sozcuk(adres)
        if ham is None:
            return None
        if p is not None and p != ham:  # düzeltilen / yeniden konumlanan gösterici
            return None
        deger = ham - _U64 if ham >= 1 << 63 else ham
        if not TEPEYE_UZAKLIK_ALT <= deger <= 0:
            return None
        return deger

    def _yuvalari_oku(self, v: VtableKaydi, a: int, ti: dict[int, TypeinfoKaydi]) -> None:
        # Yürüyüş bir typeinfo nesnesinin başında biter (ilk sözcüğü cxxabiv1 bağı). typeinfo'nun içinden başlayan
        # aday dış döngüde elenir (``ic``): bu yüzden burada iç sözcük denetimi yok.
        while True:
            if a in ti:
                return
            c = self._coz(a)
            if c is None:
                return
            if c[0] == _DIS:
                if self._normal(c[1]).startswith(_ISLEV_OLMAYAN_ONEKLER) or \
                        self._normal(c[1]) in CXXABI_TI_VTABLE:
                    return
                yuva: Optional[int] = None  # içe aktarılan işlev (ör. saf sanal): sıra ilerler
            else:
                if c[1] in ti or not self._kodda(c[1]):
                    return
                yuva = c[1]
                if c[2]:
                    v.zayif_yuva += 1
                    self.sayac[B_ZAYIF_YUVA] += 1
            if len(v.yuvalar) >= self.azami_yuva:
                v.kesildi = True
                self.sayac[H_YUVA_SINIR] += 1
                return
            v.yuvalar.append(yuva)
            a += SOZCUK

    def _islev_baglari(self, vt: list[VtableKaydi], ti: dict[int, TypeinfoKaydi]) -> list[IslevBagi]:
        yer: dict[int, list[tuple[int, int, int]]] = {}
        for v in vt:
            for sira, h in enumerate(v.yuvalar):
                if h:
                    yer.setdefault(h, []).append((v.typeinfo, v.adres, sira))
        taban_onbellek: dict[int, frozenset[int]] = {}
        out: list[IslevBagi] = []
        for h in sorted(yer):
            kayitlar = yer[h]
            siniflar = sorted({k[0] for k in kayitlar})
            ib = IslevBagi(h, siniflar, [(k[1], k[2]) for k in kayitlar])
            if len(siniflar) == 1:
                ib.sinif, ib.karar = siniflar[0], BAG_TEK
            else:
                adaylar = [c for c in siniflar
                           if all(s == c or c in self._tabanlar(s, ti, taban_onbellek) for s in siniflar)]
                if len(adaylar) == 1:
                    ib.sinif, ib.karar = adaylar[0], BAG_TABAN
                else:
                    ib.karar = BAG_BELIRSIZ
            out.append(ib)
        return out

    def _tabanlar(self, t: int, ti: dict[int, TypeinfoKaydi], onbellek: dict[int, frozenset[int]]) -> frozenset[int]:
        """``t``'nin geçişli yerel tabanları (kendisi hariç); döngü sayaçla kesilir."""
        if t in onbellek:
            return onbellek[t]
        gor: set[int] = set()
        yigin = [b.typeinfo for b in ti[t].tabanlar if b.typeinfo is not None] if t in ti else []
        dongu = False
        while yigin:
            x = yigin.pop()
            if x == t:
                dongu = True
                continue
            if x in gor or x not in ti:
                continue
            gor.add(x)
            yigin.extend(b.typeinfo for b in ti[x].tabanlar if b.typeinfo is not None)
        if dongu:
            self.sayac[H_DONGUSEL_TABAN] += 1
        sonuc = frozenset(gor)
        onbellek[t] = sonuc
        return sonuc


def _adlari_coz(kayitlar: Iterable[TypeinfoKaydi]) -> None:
    """Itanium ad çözümü (``cpp_rtti.batch_demangle``; ``_ZTS`` + ad → ``typeinfo name for X``).

    Çözülemeyen ad ``cozulmus = None`` kalır (özgün ad kullanılır); ad uydurulmaz.
    """
    kayitlar = list(kayitlar)
    if not kayitlar:
        return
    try:
        from karadul.analyzers.cpp_rtti import batch_demangle

        cozum = batch_demangle(["_ZTS" + k.ad for k in kayitlar])
    except Exception as exc:  # çözücü yoksa adlar özgün kalır
        logger.debug("RTTI ad çözümü yapılamadı: %s", exc)
        return
    on = "typeinfo name for "
    for k in kayitlar:
        s = cozum.get("_ZTS" + k.ad)
        if s and s.startswith(on) and len(s) > len(on):
            k.cozulmus = s[len(on):]


def tara(goruntu: Any, *, azami_yuva: int = YUVA_AZAMI_ONTANIM, sure_siniri: float = SURE_SINIRI_SN,
         zaman: Callable[[], float] = time.monotonic) -> RttiSonuc:
    """Görüntüdeki Itanium RTTI / vtable kayıtlarını tara. İstisna atmaz; durum ``RttiSonuc.durum``'dadır."""
    try:
        bicim = goruntu.bicim
        if bicim not in (BICIM_MACHO, BICIM_ELF):
            return RttiSonuc(DURUM_DESTEKLENMIYOR, f"{bicim} biçiminde Itanium RTTI taranmıyor (MSVC RTTI: P-ÜV9)")
        if goruntu.gosterici_boyutu != SOZCUK:
            return RttiSonuc(DURUM_DESTEKLENMIYOR, f"gösterici boyu {goruntu.gosterici_boyutu} (yalnız 64 bit)")
        if not isinstance(azami_yuva, int) or isinstance(azami_yuva, bool) or azami_yuva <= 0:
            azami_yuva = YUVA_AZAMI_ONTANIM
        return RttiTarayici(goruntu, azami_yuva=azami_yuva, sure_siniri=sure_siniri, zaman=zaman).tara()
    except Exception as exc:  # tarayıcı istisna atmaz; beklenmeyen hata durumla döner
        logger.warning("C++ RTTI taranamadı: %s", exc)
        return RttiSonuc(DURUM_HATA, f"{type(exc).__name__}: {exc}")
