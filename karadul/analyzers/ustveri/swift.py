"""Swift tip üst verisi okuyucu (P-ÜV3; ÜST VERİ hattı).

İkilinin Swift üst verisinden (``__swift5_types``, ``__swift5_proto``) tip adları, tip başına erişim fonksiyonu
(``type metadata accessor for <Tip>``; ad verilebilir) ve vtable / geçersiz kılma / tanık tablosu yuvaları (yalnız
kanıt satırı: tip + tür + sıra + adres) okunur. Swift üst verisi yöntem adı taşımaz: bu modül yöntem adı üretmez.
Ghidra'sız; yalnız dosya baytları. İkili çalıştırılmaz.

Biçim kaynağı (plan ``ustveri/PLAN.md`` "P-ÜV3": swiftlang/swift ``include/swift/ABI/MetadataValues.h``,
``Metadata.h``, ``GenericContext.h``; 2026-11-19). Makinede ABI başlıkları yok; aşağıdaki her yerleşim yerel derlenen
örneklerde (``scripts/arge/ustveri/swift_ornek/``, Apple Swift 6.4.2) ``/usr/bin/nm`` + ``xcrun swift-demangle``
ile doğrulandı (2026-11-23). Araştırma başvurusu ``scripts/arge/ustveri/swift_meta.py``; bu modül ondan yeniden
yazıldı (hata yolları, sınırlar, durum sözlüğü, nitelikli adın üç eksiği).

- ``__swift5_types``: int32 göreli kayıtlar; düşük iki bit başvuru türü (0 doğrudan betimleyici, 1 dolaylı
  betimleyici, 2 / 3 ObjC sınıfı; bunlar atlanır).
- Bağlam betimleyicisi: bayrak u32 (tür ``& 0x1F``: 0 modül, 1 uzantı, 2 adsız, 3 protokol, 4 opak, 16 sınıf,
  17 yapı, 18 enum; ``0x80`` genel; ``0x20`` ters çevrilebilir protokoller; türe özgü bayraklar üst 16 bit), üst
  bağlam (+4; dolaylı olabilen göreli gösterici: düşük bit 1 ise hedef bir gösterici yuvasıdır).
- Tip: ad (+8), erişim fonksiyonu (+12), alanlar (+16). Sınıfın sabit kısmı 44 bayt. Sınıf artçıları sırayla:
  genel bağlam başlığı (16 bayt: örnekleme önbelleği + kalıp + 8 baytlık temel başlık; parametre baytları 4'e
  hizalı; 12 baytlık gereksinimler; paket bayrağında paket biçimi başlığı), dirençli üst sınıf (4; bit 13), yabancı /
  tekil başlatma (4 / 12; bit 0–1 = 2 / 1), vtable başlığı (ofset u32, boyut u32; bit 15), yöntem betimleyicileri
  (8 bayt: bayrak u32 — tür ``& 0x0F`` 0 yöntem, 1 init, 2 getter, 3 setter, 4 modify, 5 read; ``0x10`` örnek;
  ``0x20`` dinamik; ``0x40`` zaman uyumsuz — ve int32 göreli uygulama), geçersiz kılma tablosu (sayı u32 + 12
  baytlık kayıtlar, uygulama +8; bit 14).
- Uzantı ve adsız bağlamın genel başlığı 8 bayttır (temel başlık; önbellek / kalıp yok). Uzantının genişletilen
  bağlamı (+8) karışık (mangled) tip adıdır; ``\\x01`` / ``\\x02`` + int32 simgesel başvuru içerebilir.
- Adsız bağlam türe özgü bit 0 (``HasMangledName``): genel başlıktan sonra int32 göreli karışık ad. Öntanımlı
  derlemede yok (yerel örnek: ``-O``, ``-Onone``, ``-O -g``'de 0; yalnız
  ``-Xfrontend -enable-anonymous-context-mangled-names`` ile var).
- İçe aktarım bilgisi (türe özgü bit 2, ``HasImportInfo``): ad dizgisinden sonra boş dizgiyle biten etiketli
  dizgiler: ``N`` ABI adı (karışık adda ve ``swift-demangle`` çıktısında görünen ad), ``S`` sembol ad alanı,
  ``R`` ilgili varlık (``related decl 'e' for <ad>``).
- ``__swift5_proto``: uyum betimleyicileri (protokol +0 dolaylı olabilen, tip başvurusu +4 — türü bayrağın bit
  3–5'i —, tanık tablosu kalıbı +8, bayrak +12); tanık tablosunun ilk sözcüğü uyum betimleyicisine gösterir.
- Swift sınıfının ObjC sınıf nesnesinde (``__objc_classlist``) betimleyici göstericisi +64'tedir; sınıfın ObjC
  çalışma zamanı adı (``_TtC…P33_<ayraç>…``) özel (``private``) sınıfın ayracını taşır.

Nitelikli ad (``swift-demangle`` biçimi):
- ``Modül.Dış.İç``; adsız bağlam (``private`` / ``fileprivate``): ``Modül.(Tip in <ayraç>)`` — ayraç adsız
  bağlamın karışık adından ya da sınıfın ObjC adından; bulunamazsa (ör. yerel tip, öntanımlı derlemedeki özel yapı)
  ad verilmez.
- Uzantı: ``(extension in <Modül>):<Genişletilen>.Tip``; genişletilen tip kısıtlı (genel gereksinimi olan) uzantıysa
  ad verilmez.
- İçe aktarılan C / ObjC tipi: ``__C.<ABI adı>``; ilgili varlık ``__C_Synthesized.related decl '<e>' for <ad>``.

Sahte veri yok: okunamayan kayıt atlanır ve sayaç artar; ad uydurulmaz. Okuyucu istisna atmaz.
"""

from __future__ import annotations

import bisect
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from karadul.analyzers.ustveri.goruntu import (
    BICIM_MACHO,
    CSTR_AZAMI,
    DURUM_CALISTI,
    DURUM_DESTEKLENMIYOR,
    DURUM_HATA,
    DURUM_KAPALI,
    DURUM_TUTARSIZ,
    DURUM_VERI_YOK,
)

logger = logging.getLogger(__name__)

# --- durumlar: altısı da goruntu'dan (tutarsiz / kapali dahil; P-ÜV6b: tek tanım) ---------------------

# --- bağlam türleri (MetadataValues.h ContextDescriptorKind) --------------------------------------
KIND_MODULE = 0
KIND_EXTENSION = 1
KIND_ANONYMOUS = 2
KIND_PROTOCOL = 3
KIND_OPAQUE = 4
KIND_CLASS = 16
KIND_STRUCT = 17
KIND_ENUM = 18
TYPE_KINDS = (KIND_CLASS, KIND_STRUCT, KIND_ENUM)
TUR_ADI = {KIND_MODULE: "modul", KIND_EXTENSION: "uzanti", KIND_ANONYMOUS: "adsiz", KIND_PROTOCOL: "protokol",
           KIND_OPAQUE: "opak", KIND_CLASS: "sinif", KIND_STRUCT: "yapi", KIND_ENUM: "enum"}

# --- bağlam bayrakları ----------------------------------------------------------------------------
FLAG_KIND_MASK = 0x1F
FLAG_INVERTIBLE = 0x20
FLAG_UNIQUE = 0x40
FLAG_GENERIC = 0x80
KIND_SPECIFIC_SHIFT = 16

# türe özgü bayraklar (üst 16 bit)
TYPE_MI_MASK = 0x3            # MetadataInitialization
MI_SINGLETON = 1
MI_FOREIGN = 2
TYPE_HAS_IMPORT_INFO = 1 << 2
CLASS_HAS_RESILIENT_SUPER = 1 << 13
CLASS_HAS_OVERRIDE_TABLE = 1 << 14
CLASS_HAS_VTABLE = 1 << 15
ANON_HAS_MANGLED_NAME = 1 << 0

# --- yerleşim ------------------------------------------------------------------------------------
OFS_PARENT = 4
OFS_NAME = 8
OFS_ACCESSOR = 12
OFS_EXTENDED = 8
EXTENSION_GENERIC_HEADER = 12        # uzantıda genel başlık: bayrak + üst + genişletilen bağlamdan sonra
CLASS_FIXED_SIZE = 44
CONTEXT_HEADER_SIZE = 8              # bayrak + üst bağlam
TYPE_GENERIC_HEADER_SIZE = 16        # örnekleme önbelleği + kalıp + temel başlık
BASE_GENERIC_HEADER_SIZE = 8         # NumParams, NumRequirements, NumKeyArguments, Flags (u16 × 4)
GENERIC_REQUIREMENT_SIZE = 12
GENERIC_FLAG_HAS_TYPE_PACKS = 0x1
PACK_SHAPE_HEADER_SIZE = 4
PACK_SHAPE_DESCRIPTOR_SIZE = 8
RESILIENT_SUPER_SIZE = 4
FOREIGN_INIT_SIZE = 4
SINGLETON_INIT_SIZE = 12
VTABLE_HEADER_SIZE = 8
METHOD_DESCRIPTOR_SIZE = 8
OVERRIDE_HEADER_SIZE = 4
OVERRIDE_DESCRIPTOR_SIZE = 12
OVERRIDE_CLASS_OFS = 0
OVERRIDE_METHOD_OFS = 4
OVERRIDE_IMPL_OFS = 8
ASYNC_FP_FUNCTION = 0                # zaman uyumsuz işlev göstericisi: +0 int32 göreli işlev
CONF_PROTOCOL = 0
CONF_TYPEREF = 4
CONF_WITNESS = 8
CONF_FLAGS = 12
CONF_TYPEREF_SHIFT = 3
CONF_TYPEREF_MASK = 0x7
PROTO_NUM_REQUIREMENTS = 16
SWIFT_CLASS_DESCRIPTION = 64         # Swift sınıf nesnesinde betimleyici göstericisi
POINTER_SIZE = 8

# tip başvuru türü (__swift5_types kaydı ve uyum betimleyicisi)
TYPEREF_DIRECT = 0
TYPEREF_INDIRECT = 1
TYPEREF_OBJC_NAME = 2
TYPEREF_OBJC_INDIRECT = 3

# yöntem betimleyicisi bayrakları
METHOD_KIND_MASK = 0x0F
METHOD_IS_INSTANCE = 0x10
METHOD_IS_DYNAMIC = 0x20
METHOD_IS_ASYNC = 0x40
YONTEM_TURU = {0: "yontem", 1: "init", 2: "getter", 3: "setter", 4: "modify", 5: "read"}

# --- sağlamlık sınırları (plan kalem 5) ------------------------------------------------------------
MAX_VTABLE = 20_000
MAX_OVERRIDES = 20_000
MAX_CONTEXT_DEPTH = 64
MAX_WITNESS_SCAN = 512
MAX_GENERIC_PARAMS = 4_096
MAX_MANGLED = 1_024
CSTR_MAX = CSTR_AZAMI

# --- bölümler ----------------------------------------------------------------------------------
TYPES_SECTIONS = ("__swift5_types", "__swift5_types2")
PROTO_SECTIONS = ("__swift5_proto",)
SWIFT_SECTION_PREFIX = "__swift5_"
OBJC_CLASS_SECTIONS = ("__objc_classlist", "__objc_nlclslist")
OBJC_DATA_MASK = 0x00007FFFFFFFFFF8   # objc4 FAST_DATA_MASK (objc.py ile aynı biçim değeri)
OBJC_SWIFT_BITS = 0x3
OBJC_CLASS_BITS = 32
OBJC_RO_NAME = 24

# --- nitelikli ad --------------------------------------------------------------------------------
ACCESSOR_PREFIX = "type metadata accessor for "
IMPORT_MODULES = ("__C", "__C_Synthesized")
IMPORT_TAG_ABI_NAME = "N"
IMPORT_TAG_NAMESPACE = "S"
IMPORT_TAG_RELATED = "R"
IMPORT_KNOWN_TAGS = (IMPORT_TAG_ABI_NAME, IMPORT_TAG_NAMESPACE, IMPORT_TAG_RELATED)
IMPORT_INFO_MAX_PARTS = 16

# alt kümeler (ön kayıt §2: zincirde adsız > uzantı > tipin içe aktarım bilgisi > öbür)
ALT_ADSIZ = "adsiz"
ALT_UZANTI = "uzanti"
ALT_ICE_AKTARIM = "ice_aktarim"
ALT_DIGER = "diger"
ALT_KUMELER = (ALT_ADSIZ, ALT_UZANTI, ALT_ICE_AKTARIM, ALT_DIGER)

# ad verilmeme nedenleri (sayaç)
N_AYRAC_YOK = "adsiz_ayrac_bulunamadi"
N_UZANTI_KISITLI = "uzanti_kisitli"
N_UZANTI_COZULEMEDI = "uzanti_genisletilen_cozulemedi"
N_ICE_AKTARIM = "ice_aktarim_bilgisi_cozulemedi"
N_BAGLAM = "baglam_okunamadi"
N_OPAK = "opak_baglam"
N_DERINLIK = "baglam_derinligi_asildi"

# Swift standart kısaltmaları (``S`` + harf); her satır ``xcrun swift-demangle '$sS<x>Mn'`` ile doğrulandı
# (2026-11-23, Swift 6.4.2)
STD_SUBST = {
    "a": "Swift.Array", "b": "Swift.Bool", "D": "Swift.Dictionary", "d": "Swift.Double",
    "E": "Swift.Encodable", "e": "Swift.Decodable", "F": "Swift.FloatingPoint", "f": "Swift.Float",
    "G": "Swift.RandomNumberGenerator", "H": "Swift.Hashable", "h": "Swift.Set", "I": "Swift.DefaultIndices",
    "i": "Swift.Int", "J": "Swift.Character", "j": "Swift.Numeric", "K": "Swift.BidirectionalCollection",
    "k": "Swift.RandomAccessCollection", "L": "Swift.Comparable", "l": "Swift.Collection",
    "M": "Swift.MutableCollection", "m": "Swift.RangeReplaceableCollection", "N": "Swift.ClosedRange",
    "n": "Swift.Range", "O": "Swift.ObjectIdentifier", "P": "Swift.UnsafePointer",
    "p": "Swift.UnsafeMutablePointer", "Q": "Swift.Equatable", "q": "Swift.Optional",
    "R": "Swift.UnsafeBufferPointer", "r": "Swift.UnsafeMutableBufferPointer", "S": "Swift.String",
    "s": "Swift.Substring", "T": "Swift.Sequence", "t": "Swift.IteratorProtocol", "U": "Swift.UnsignedInteger",
    "u": "Swift.UInt", "V": "Swift.UnsafeRawPointer", "v": "Swift.UnsafeMutableRawPointer",
    "W": "Swift.UnsafeRawBufferPointer", "w": "Swift.UnsafeMutableRawBufferPointer", "X": "Swift.RangeExpression",
    "x": "Swift.Strideable", "Y": "Swift.RawRepresentable", "y": "Swift.StringProtocol", "Z": "Swift.SignedInteger",
    "z": "Swift.BinaryInteger",
}
STD_SUBST_CONCURRENCY = {
    "A": "Swift.Actor", "C": "Swift.CheckedContinuation", "E": "Swift.CancellationError", "F": "Swift.Executor",
    "G": "Swift.TaskGroup", "I": "Swift.AsyncIteratorProtocol", "J": "Swift.UnownedJob", "M": "Swift.MainActor",
    "P": "Swift.TaskPriority", "S": "Swift.AsyncStream", "T": "Swift.Task",
}
NOMINAL_KIND_CHARS = "VCO"
SYMBOLIC_DIRECT = 0x01
SYMBOLIC_INDIRECT = 0x02
SYMBOLIC_MAX = 0x17

# --- okuma hatası sayaçları (kabul: gerçek hedeflerde 0) -----------------------------------------
H_TIP_KAYDI = "tip_kaydi_cozulemedi"
H_TIP_OBJC = "tip_kaydi_objc_sinifi"
H_BAYRAK = "betimleyici_okunamadi"
H_GENEL_BAYRAK = "genel_bayrak_desteklenmiyor"
H_INVERTIBLE = "invertible"
H_VTABLE_ASIRI = "vtable_boyutu_asiri"
H_GK_ASIRI = "gecersiz_kilma_boyutu_asiri"
H_ARTCI = "artci_okunamadi"
H_UYUM = "uyum_kaydi_okunamadi"
HATA_SAYACLARI = (H_TIP_KAYDI, H_BAYRAK, H_VTABLE_ASIRI, H_GK_ASIRI, H_ARTCI, H_UYUM)

YUVA_VTABLE = "vtable"
YUVA_GECERSIZ_KILMA = "gecersiz_kilma"
YUVA_TANIK = "tanik"

_PRIVATE_OBJC_RE = re.compile(r"P(\d+)")


class _Baglam(Exception):
    """İç: nitelikli ad kurulamadı (neden sayacı ``neden``)."""

    def __init__(self, neden: str) -> None:
        super().__init__(neden)
        self.neden = neden


@dataclass
class SwiftTip:
    """Bir tip betimleyicisi (sınıf / yapı / enum)."""

    adres: int
    tur: str
    genel: bool
    kisa_ad: Optional[str]
    nitelikli_ad: Optional[str]
    ad_neden: Optional[str]
    alt_kume: str
    erisim: Optional[int]
    yontemler: list[tuple[str, bool, bool, bool, Optional[int]]] = field(default_factory=list)
    gecersiz_kilma: list[Optional[int]] = field(default_factory=list)
    # kanıt: yöntem betimleyicisi adresleri (vtable sırasıyla) ve geçersiz kılma kaydının hedefi
    # (üst sınıf betimleyicisi, geçersiz kılınan yöntem betimleyicisi)
    yontem_adresleri: list[int] = field(default_factory=list)
    gecersiz_kilma_hedef: list[tuple[Any, Any]] = field(default_factory=list)
    artci_cozuldu: Optional[bool] = None
    erisim_kodda: Optional[bool] = None
    erisim_baslangic: Optional[bool] = None
    erisim_paylasimli: bool = False

    @property
    def ad_yazilabilir(self) -> bool:
        """Ad kanalına aday mı: nitelikli ad var, erişim kodda, (tablo varsa) başlangıç, tekil."""
        return (self.nitelikli_ad is not None and self.erisim is not None and self.erisim_kodda is True
                and self.erisim_baslangic is not False and not self.erisim_paylasimli)

    @property
    def erisim_adi(self) -> Optional[str]:
        return ACCESSOR_PREFIX + self.nitelikli_ad if self.nitelikli_ad is not None else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tip_adresi": f"{self.adres:#x}", "tur": self.tur, "genel": self.genel, "kisa_ad": self.kisa_ad,
            "nitelikli_ad": self.nitelikli_ad, "ad_neden": self.ad_neden, "alt_kume": self.alt_kume,
            "erisim": self.erisim, "adres": f"{self.erisim:#x}" if self.erisim is not None else None,
            "ad": self.erisim_adi, "erisim_kodda": self.erisim_kodda, "erisim_baslangic": self.erisim_baslangic,
            "erisim_paylasimli": self.erisim_paylasimli, "ad_yazilabilir": self.ad_yazilabilir,
            "artci_cozuldu": self.artci_cozuldu,
        }


@dataclass
class SwiftUyum:
    adres: int
    protokol: Optional[str]
    protokol_yerel: bool
    protokol_adres: Optional[int]
    tip: Optional[str]
    tanik_tablosu: Optional[int]
    bayrak: Optional[int]


@dataclass
class SwiftSonuc:
    durum: str
    neden: Optional[str] = None
    tipler: list[SwiftTip] = field(default_factory=list)
    uyumlar: list[SwiftUyum] = field(default_factory=list)
    yuvalar: list[dict[str, Any]] = field(default_factory=list)
    sayaclar: dict[str, int] = field(default_factory=dict)
    denetim: dict[str, Any] = field(default_factory=dict)

    @property
    def okuma_hatasi(self) -> int:
        return sum(self.sayaclar.get(k, 0) for k in HATA_SAYACLARI)

    def swift_types(self) -> list[dict[str, Any]]:
        """Ad verilebilen erişim fonksiyonları (ad kanalının girdisi): yalnız tipler, yuva yok."""
        return [t.as_dict() for t in self.tipler if t.erisim is not None]

    def swift_slots(self) -> list[dict[str, Any]]:
        """Kanıt satırları (vtable / geçersiz kılma / tanık): ad adayı DEĞİL, ``ad`` alanı yok."""
        return [dict(y) for y in self.yuvalar]

    def ozet(self) -> dict[str, Any]:
        tur = Counter(t.tur for t in self.tipler)
        alt = Counter(t.alt_kume for t in self.tipler)
        adli_alt = Counter(t.alt_kume for t in self.tipler if t.nitelikli_ad is not None)
        return {
            "durum": self.durum, "neden": self.neden, "tip": len(self.tipler), "tur": dict(tur),
            "genel_tip": sum(1 for t in self.tipler if t.genel),
            "erisim_fonksiyonu": len({t.erisim for t in self.tipler if t.erisim is not None}),
            "nitelikli_ad": sum(1 for t in self.tipler if t.nitelikli_ad is not None),
            "ad_yazilabilir": sum(1 for t in self.tipler if t.ad_yazilabilir),
            "alt_kume": {k: alt.get(k, 0) for k in ALT_KUMELER},
            "alt_kume_adli": {k: adli_alt.get(k, 0) for k in ALT_KUMELER},
            "uyum": len(self.uyumlar), "yuva": len(self.yuvalar),
            "okuma_hatasi": self.okuma_hatasi, "sayaclar": dict(self.sayaclar), "denetim": dict(self.denetim),
        }


class SwiftOkuyucu:
    """Bir görüntüdeki Swift tip / uyum üst verisini okur."""

    def __init__(self, goruntu: Any) -> None:
        self.g = goruntu
        self.sayac: Counter = Counter()
        self._kod = list(goruntu.kod_bolumleri)
        self._kod_araliklari = sorted((b.adres, b.adres + b.boyut) for b in self._kod if b.boyut > 0)
        self._kod_baslari = [a for a, _ in self._kod_araliklari]
        self._ad_onbellek: dict[int, tuple[Optional[str], set[str], Optional[str]]] = {}
        self._objc_ayrac: Optional[dict[int, str]] = None
        self._adsiz_ayrac: Optional[dict[int, str]] = None

    # ---- temel okuma -------------------------------------------------------------------------
    def kodda(self, adres: Optional[int]) -> bool:
        if adres is None:
            return False
        i = bisect.bisect_right(self._kod_baslari, adres) - 1
        return i >= 0 and adres < self._kod_araliklari[i][1]

    def rel(self, adres: int) -> Optional[int]:
        """Doğrudan göreli gösterici (0 → ``None``)."""
        v = self.g.i32(adres)
        if v is None or v == 0:
            return None
        return adres + v

    def rel_ind(self, adres: int) -> Any:
        """Dolaylı olabilen göreli gösterici: düşük bit 1 ise hedef yuvadaki gösterici (``int`` | ``Bag``)."""
        v = self.g.i32(adres)
        if v is None or v == 0:
            return None
        if v & 1:
            return self.g.gosterici(adres + (v & ~1))
        return adres + v

    def _yerel(self, v: Any) -> Optional[int]:
        if isinstance(v, bool) or not isinstance(v, int) or v == 0:
            return None
        return v

    def _cstr(self, adres: Optional[int]) -> Optional[str]:
        if not adres:
            return None
        return self.g.cstr(adres, CSTR_MAX)

    # ---- genel bağlam ------------------------------------------------------------------------
    def genel_atla(self, pos: int, baslik: int) -> Optional[int]:
        """Genel bağlam başlığını ve artçılarını atla (``baslik``: 16 tip, 8 uzantı / adsız).

        Desteklenmeyen genel bayrakta ``None`` (sayaç ``genel_bayrak_desteklenmiyor``).
        """
        temel = pos + baslik - BASE_GENERIC_HEADER_SIZE
        nparams, nreq, gflags = self.g.u16(temel), self.g.u16(temel + 2), self.g.u16(temel + 6)
        if nparams is None or nreq is None or gflags is None:
            self.sayac[H_ARTCI] += 1
            return None
        if gflags & ~GENERIC_FLAG_HAS_TYPE_PACKS:
            self.sayac[H_GENEL_BAYRAK] += 1
            return None
        if nparams > MAX_GENERIC_PARAMS or nreq > MAX_GENERIC_PARAMS:
            self.sayac[H_ARTCI] += 1
            return None
        pos += baslik + nparams
        pos += (-pos) % 4
        pos += GENERIC_REQUIREMENT_SIZE * nreq
        if gflags & GENERIC_FLAG_HAS_TYPE_PACKS:
            npacks = self.g.u16(pos)
            if npacks is None:
                self.sayac[H_ARTCI] += 1
                return None
            pos += PACK_SHAPE_HEADER_SIZE + PACK_SHAPE_DESCRIPTOR_SIZE * npacks
        return pos

    def _gereksinim_sayisi(self, uzanti: int) -> Optional[int]:
        """Uzantı bağlamının genel gereksinim sayısı (genel değilse 0). Genel başlık genişletilen bağlamdan
        (+8) sonra, +12'dedir."""
        f = self.g.u32(uzanti)
        if f is None:
            return None
        if not f & FLAG_GENERIC:
            return 0
        return self.g.u16(uzanti + EXTENSION_GENERIC_HEADER + 2)

    # ---- nitelikli ad ------------------------------------------------------------------------
    def baglam_adi(self, adres: Any) -> tuple[Optional[str], set[str], Optional[str]]:
        """``(nitelikli ad | None, zincirde görülen alt kümeler, ad verilmeme nedeni)``."""
        iz: set[str] = set()
        if isinstance(adres, int) and not isinstance(adres, bool) and adres in self._ad_onbellek:
            ad, iz0, neden = self._ad_onbellek[adres]
            return ad, set(iz0), neden
        try:
            ad = self._ad(adres, iz, 0)
            sonuc = (ad, iz, None)
        except _Baglam as e:
            sonuc = (None, iz, e.neden)
        if isinstance(adres, int) and not isinstance(adres, bool):
            self._ad_onbellek[adres] = (sonuc[0], set(sonuc[1]), sonuc[2])
        return sonuc

    def _ad(self, adres: Any, iz: set[str], derinlik: int) -> str:
        if derinlik > MAX_CONTEXT_DEPTH:
            raise _Baglam(N_DERINLIK)
        if not isinstance(adres, int) or isinstance(adres, bool):
            bag_adi = getattr(adres, "ad", None)
            if isinstance(bag_adi, str):  # dış betimleyici bağı (``_$s…Mn``)
                ad = self.bag_tip_adi(bag_adi)
                if ad is not None:
                    return ad
            raise _Baglam(N_BAGLAM)
        f = self.g.u32(adres)
        if f is None:
            raise _Baglam(N_BAGLAM)
        tur = f & FLAG_KIND_MASK
        if tur == KIND_MODULE:
            ad = self._cstr(self.rel(adres + OFS_NAME))
            if not ad:
                raise _Baglam(N_BAGLAM)
            return ad
        if tur == KIND_EXTENSION:
            iz.add(ALT_UZANTI)
            nreq = self._gereksinim_sayisi(adres)
            if nreq is None:
                raise _Baglam(N_BAGLAM)
            if nreq:
                raise _Baglam(N_UZANTI_KISITLI)
            modul = self._ad(self.rel_ind(adres + OFS_PARENT), iz, derinlik + 1)
            gen = self.karisik_tip_adi(self.rel(adres + OFS_EXTENDED))
            if gen is None:
                raise _Baglam(N_UZANTI_COZULEMEDI)
            return f"(extension in {modul}):{gen}"
        if tur == KIND_ANONYMOUS:
            # adsız bağlamın adı yalnız çocuğuyla birlikte kurulur (``_tip_bileseni``)
            raise _Baglam(N_AYRAC_YOK)
        if tur in TYPE_KINDS or tur == KIND_PROTOCOL:
            kisa = self._tip_kisa_adi(adres, f)
            ust = self.rel_ind(adres + OFS_PARENT)
            ust_y = self._yerel(ust)
            if ust_y is not None and (self.g.u32(ust_y) or 0) & FLAG_KIND_MASK == KIND_ANONYMOUS:
                iz.add(ALT_ADSIZ)
                ayrac = self.ayrac(ust_y, adres, kisa)
                if ayrac is None:
                    raise _Baglam(N_AYRAC_YOK)
                onek = self._ad(self.rel_ind(ust_y + OFS_PARENT), iz, derinlik + 1)
                return f"{onek}.({kisa} in {ayrac})"
            onek = self._ad(ust, iz, derinlik + 1)
            return f"{onek}.{kisa}"
        if tur == KIND_OPAQUE:
            raise _Baglam(N_OPAK)
        raise _Baglam(N_BAGLAM)

    def _tip_kisa_adi(self, adres: int, f: int) -> str:
        """Tipin adı; içe aktarım bilgisi varsa ABI adı (``N``) ve ilgili varlık (``R``)."""
        p = self.rel(adres + OFS_NAME)
        ad = self._cstr(p)
        if not ad or p is None:
            raise _Baglam(N_BAGLAM)
        if (f >> KIND_SPECIFIC_SHIFT) & TYPE_HAS_IMPORT_INFO and (f & FLAG_KIND_MASK) in TYPE_KINDS:
            parcalar = self.ice_aktarim_bilgisi(p, ad)
            if parcalar is None:
                raise _Baglam(N_ICE_AKTARIM)
            abi = parcalar.get(IMPORT_TAG_ABI_NAME, ad)
            iliskili = parcalar.get(IMPORT_TAG_RELATED)
            if iliskili is not None:
                return f"related decl '{iliskili}' for {abi}"
            return abi
        return ad

    def ice_aktarim_bilgisi(self, ad_adresi: int, ad: str) -> Optional[dict[str, str]]:
        """Ad dizgisinden sonra boş dizgiyle biten etiketli dizgiler; bilinmeyen etiket ya da okuma hatası → None."""
        pos = ad_adresi + len(ad.encode("utf-8")) + 1
        out: dict[str, str] = {}
        for _ in range(IMPORT_INFO_MAX_PARTS):
            s = self.g.cstr(pos, CSTR_MAX)
            if s is None:
                return None
            if s == "":
                return out
            etiket, deger = s[0], s[1:]
            if etiket not in IMPORT_KNOWN_TAGS or etiket in out:
                return None
            out[etiket] = deger
            pos += len(s.encode("utf-8")) + 1
        return None

    def ayrac(self, adsiz: int, cocuk: int, kisa: str) -> Optional[str]:
        """Özel bağlamın ayracı: adsız bağlamın karışık adından, yoksa sınıfın ObjC çalışma zamanı adından."""
        f = self.g.u32(adsiz)
        if f is None:
            return None
        if (f >> KIND_SPECIFIC_SHIFT) & ANON_HAS_MANGLED_NAME:
            pos: Optional[int] = adsiz + CONTEXT_HEADER_SIZE
            if f & FLAG_GENERIC:
                pos = self.genel_atla(adsiz + CONTEXT_HEADER_SIZE, BASE_GENERIC_HEADER_SIZE)
            if pos is not None:
                karisik = self._cstr(self.rel(pos))
                if karisik:
                    a = _karisik_ayrac(karisik, kisa)
                    if a is not None:
                        return a
        return self.adsiz_ayraclari().get(adsiz)

    def adsiz_ayraclari(self) -> dict[int, str]:
        """Adsız bağlam → ayraç, Swift sınıflarının ObjC çalışma zamanı adlarından.

        ObjC adı sınıfın bütün bağlam yolunu taşır (``_TtCV5OrnekP33_<ayraç>8GizliKap7IcSinif``). Sınıf
        betimleyicisinden üst bağlam zinciri yürünür; zincirdeki her adsız bağlam için altındaki tipin kısa
        adıyla ``P<uz><ayraç><uz><kısa ad>`` bileşeni aranır. Eşleme yapısaldır (aynı betimleyici zinciri);
        aynı adsız bağlama iki farklı ayraç düşerse o bağlam eşlenmez (tahmin yok).
        """
        if self._adsiz_ayrac is not None:
            return self._adsiz_ayrac
        aday: dict[int, set[str]] = {}
        for d, objc_adi in self.objc_ayraclari().items():
            cocuk = d
            for _ in range(MAX_CONTEXT_DEPTH):
                ust = self._yerel(self.rel_ind(cocuk + OFS_PARENT))
                fu = self.g.u32(ust) if ust is not None else None
                if ust is None or fu is None:
                    break
                if fu & FLAG_KIND_MASK == KIND_ANONYMOUS:
                    fc = self.g.u32(cocuk)
                    kisa = (self._cstr(self.rel(cocuk + OFS_NAME))
                            if fc is not None and fc & FLAG_KIND_MASK in TYPE_KINDS else None)
                    a = _objc_ayrac(objc_adi, kisa) if kisa else None
                    if a is not None:
                        aday.setdefault(ust, set()).add(a)
                if fu & FLAG_KIND_MASK == KIND_MODULE:
                    break
                cocuk = ust
        self._adsiz_ayrac = {k: next(iter(v)) for k, v in aday.items() if len(v) == 1}
        return self._adsiz_ayrac

    def objc_ayraclari(self) -> dict[int, str]:
        """Swift sınıf betimleyicisi → ObjC çalışma zamanı adı (``__objc_classlist``'teki Swift sınıfları)."""
        if self._objc_ayrac is not None:
            return self._objc_ayrac
        out: dict[int, str] = {}
        for bad in OBJC_CLASS_SECTIONS:
            for b in self.g.bolumler_adli(bad):
                for i in range(b.boyut // POINTER_SIZE):
                    c = self._yerel(self.g.gosterici(b.adres + POINTER_SIZE * i))
                    if c is None:
                        continue
                    bits = self._yerel(self.g.gosterici(c + OBJC_CLASS_BITS))
                    if bits is None or not bits & OBJC_SWIFT_BITS:
                        continue
                    ro = bits & OBJC_DATA_MASK
                    ad = self._cstr(self._yerel(self.g.gosterici(ro + OBJC_RO_NAME))) if ro else None
                    d = self._yerel(self.g.gosterici(c + SWIFT_CLASS_DESCRIPTION))
                    if ad and d is not None:
                        out.setdefault(d, ad)
        self._objc_ayrac = out
        return out

    # ---- karışık tip adı (uzantının genişletilen bağlamı) -----------------------------------------
    def karisik_tip_adi(self, adres: Optional[int]) -> Optional[str]:
        """Genişletilen bağlamın karışık adını ``swift-demangle`` biçimine çevir; desteklenmeyen → None.

        Desteklenen: modül + iç içe nominal (``V`` / ``C`` / ``O``), ``s`` / ``So``, standart kısaltmalar,
        ``\\x01`` / ``\\x02`` simgesel başvuru, genel argümanları yalnız genel parametre olan bağlı genel
        (``SayxG`` → ``Swift.Array``), ``Sg`` (Optional) eki.
        """
        if adres is None:
            return None
        belirtecler = self._karisik_oku(adres)
        if belirtecler is None:
            return None
        return self._karisik_coz(belirtecler)

    def _karisik_oku(self, adres: int) -> Optional[list[Any]]:
        out: list[Any] = []
        pos = adres
        for _ in range(MAX_MANGLED):
            b = self.g.u8(pos)
            if b is None:
                return None
            if b == 0:
                return out
            if 1 <= b <= SYMBOLIC_MAX:
                v = self.g.i32(pos + 1)
                if v is None:
                    return None
                hedef = pos + 1 + v
                if b == SYMBOLIC_DIRECT:
                    out.append(("sembolik", hedef))
                elif b == SYMBOLIC_INDIRECT:
                    out.append(("sembolik", self.g.gosterici(hedef)))
                else:
                    return None
                pos += 5
                continue
            out.append(chr(b))
            pos += 1
        return None

    def bag_tip_adi(self, sembol: str) -> Optional[str]:
        """Dış betimleyici bağının adından (``_$s10Foundation4DateVMn``) nitelikli ad."""
        s = sembol[1:] if sembol.startswith("_") else sembol
        if not s.startswith("$s") or not s.endswith("Mn"):
            return None
        return self._karisik_coz(list(s[2:-2]))

    def _karisik_coz(self, b: list[Any]) -> Optional[str]:
        yigin: list[tuple[str, Any]] = []
        i, n = 0, len(b)

        def ad_al(j: int) -> Optional[tuple[str, int]]:
            k = j
            while k < n and isinstance(b[k], str) and b[k].isdigit():
                k += 1
            sayi = "".join(b[j:k])
            if not sayi or sayi.startswith("0"):
                return None
            uz = int(sayi)
            parca = b[k:k + uz]
            if len(parca) != uz or not all(isinstance(c, str) for c in parca):
                return None
            return "".join(parca), k + uz

        while i < n:
            c = b[i]
            if isinstance(c, tuple):
                hedef = c[1]
                ad, _iz, _neden = self.baglam_adi(hedef)
                if ad is None:
                    return None
                yigin.append(("tip", ad))
                i += 1
                continue
            if c.isdigit():
                r = ad_al(i)
                if r is None:
                    return None
                yigin.append(("ad", r[0]))
                i = r[1]
                continue
            if c == "s":
                yigin.append(("modul", "Swift"))
                i += 1
                continue
            if c == "S":
                if i + 1 >= n or not isinstance(b[i + 1], str):
                    return None
                d = b[i + 1]
                if d == "o":
                    yigin.append(("modul", "__C"))
                    i += 2
                    continue
                if d == "g":  # Optional eki: önceki tip Optional'ın argümanı
                    if not yigin or yigin[-1][0] not in ("tip", "param", "bagli"):
                        return None
                    arg = yigin.pop()
                    yigin.append(("bagli", ("Swift.Optional", [arg])))
                    i += 2
                    continue
                if d == "c":
                    if i + 2 >= n or not isinstance(b[i + 2], str) or b[i + 2] not in STD_SUBST_CONCURRENCY:
                        return None
                    yigin.append(("tip", STD_SUBST_CONCURRENCY[b[i + 2]]))
                    i += 3
                    continue
                if d in STD_SUBST:
                    yigin.append(("tip", STD_SUBST[d]))
                    i += 2
                    continue
                return None
            if c in NOMINAL_KIND_CHARS:
                # modül adı düz tanımlayıcı olarak gelir (``10Foundation4DateV``)
                if len(yigin) < 2 or yigin[-1][0] != "ad" or yigin[-2][0] not in ("modul", "tip", "ad"):
                    return None
                ad = yigin.pop()[1]
                ust = yigin.pop()[1]
                yigin.append(("tip", f"{ust}.{ad}"))
                i += 1
                continue
            if c == "x":
                yigin.append(("param", (0, 0)))
                i += 1
                continue
            if c == "q":  # q_ , q<n>_ : derinlik 0 parametre
                j = i + 1
                while j < n and isinstance(b[j], str) and b[j].isdigit():
                    j += 1
                if j >= n or b[j] != "_":
                    return None
                yigin.append(("param", (0, j - i)))
                i = j + 1
                continue
            if c == "y":
                yigin.append(("isaret", None))
                i += 1
                continue
            if c == "G":
                args = []
                while yigin and yigin[-1][0] != "isaret":
                    args.append(yigin.pop())
                if not yigin:
                    return None
                yigin.pop()
                if not yigin or yigin[-1][0] != "tip":
                    return None
                nom = yigin.pop()[1]
                yigin.append(("bagli", (nom, list(reversed(args)))))
                i += 1
                continue
            return None
        if len(yigin) != 1:
            return None
        tur, deger = yigin[0]
        if tur == "tip":
            return deger
        if tur == "bagli":
            nom, args = deger
            if args and all(a[0] == "param" for a in args):
                return nom  # genişletilen tipin kendi parametreleri: demangle yalnız nominali yazar
        return None

    # ---- tipler ------------------------------------------------------------------------------
    def tip_adresleri(self) -> list[int]:
        out: list[int] = []
        gorulen: set[int] = set()
        for bad in TYPES_SECTIONS:
            for b in self.g.bolumler_adli(bad):
                for i in range(b.boyut // 4):
                    a = b.adres + 4 * i
                    v = self.g.i32(a)
                    if v is None or v == 0:
                        self.sayac[H_TIP_KAYDI] += 1
                        continue
                    tur = v & 3
                    if tur == TYPEREF_DIRECT:
                        d: Any = a + v
                    elif tur == TYPEREF_INDIRECT:
                        d = self.g.gosterici(a + (v & ~3))
                    else:
                        self.sayac[H_TIP_OBJC] += 1
                        continue
                    d = self._yerel(d)
                    if d is None:
                        self.sayac[H_TIP_KAYDI] += 1
                        continue
                    if d not in gorulen:
                        gorulen.add(d)
                        out.append(d)
        return out

    def tip(self, d: int) -> Optional[SwiftTip]:
        f = self.g.u32(d)
        if f is None:
            self.sayac[H_BAYRAK] += 1
            return None
        tur = f & FLAG_KIND_MASK
        kf = f >> KIND_SPECIFIC_SHIFT
        ad, iz, neden = self.baglam_adi(d)
        if neden is not None:
            self.sayac[neden] += 1
        try:
            kisa = self._tip_kisa_adi(d, f) if tur in TYPE_KINDS else None
        except _Baglam:
            kisa = self._cstr(self.rel(d + OFS_NAME))
        if ALT_ADSIZ in iz:
            alt = ALT_ADSIZ
        elif ALT_UZANTI in iz:
            alt = ALT_UZANTI
        elif kf & TYPE_HAS_IMPORT_INFO:
            alt = ALT_ICE_AKTARIM
        else:
            alt = ALT_DIGER
        t = SwiftTip(adres=d, tur=TUR_ADI.get(tur, str(tur)), genel=bool(f & FLAG_GENERIC), kisa_ad=kisa,
                     nitelikli_ad=ad, ad_neden=neden, alt_kume=alt, erisim=self.rel(d + OFS_ACCESSOR))
        if tur == KIND_CLASS:
            t.artci_cozuldu = self._sinif_artcilari(d, f, t)
        return t

    def _sinif_artcilari(self, d: int, f: int, t: SwiftTip) -> bool:
        kf = f >> KIND_SPECIFIC_SHIFT
        pos: Optional[int] = d + CLASS_FIXED_SIZE
        if f & FLAG_INVERTIBLE:  # ters çevrilebilir protokoller: artçı düzeni farklı
            self.sayac[H_INVERTIBLE] += 1
            return False
        if f & FLAG_GENERIC:
            pos = self.genel_atla(pos, TYPE_GENERIC_HEADER_SIZE)
            if pos is None:
                return False
        if kf & CLASS_HAS_RESILIENT_SUPER:
            pos += RESILIENT_SUPER_SIZE
        mi = kf & TYPE_MI_MASK
        if mi == MI_FOREIGN:
            pos += FOREIGN_INIT_SIZE
        elif mi == MI_SINGLETON:
            pos += SINGLETON_INIT_SIZE
        if kf & CLASS_HAS_VTABLE:
            boyut = self.g.u32(pos + 4)
            if boyut is None:
                self.sayac[H_ARTCI] += 1
                return False
            pos += VTABLE_HEADER_SIZE
            if boyut > MAX_VTABLE:
                self.sayac[H_VTABLE_ASIRI] += 1
                return False
            for _ in range(boyut):
                mf = self.g.u32(pos)
                if mf is None:
                    self.sayac[H_ARTCI] += 1
                    return False
                t.yontemler.append((YONTEM_TURU.get(mf & METHOD_KIND_MASK, "?"), bool(mf & METHOD_IS_INSTANCE),
                                    bool(mf & METHOD_IS_DYNAMIC), bool(mf & METHOD_IS_ASYNC), self.rel(pos + 4)))
                t.yontem_adresleri.append(pos)
                pos += METHOD_DESCRIPTOR_SIZE
        if kf & CLASS_HAS_OVERRIDE_TABLE:
            sayi = self.g.u32(pos)
            if sayi is None:
                self.sayac[H_ARTCI] += 1
                return False
            pos += OVERRIDE_HEADER_SIZE
            if sayi > MAX_OVERRIDES:
                self.sayac[H_GK_ASIRI] += 1
                return False
            for _ in range(sayi):
                t.gecersiz_kilma.append(self.rel(pos + OVERRIDE_IMPL_OFS))
                t.gecersiz_kilma_hedef.append((self.rel_ind(pos + OVERRIDE_CLASS_OFS),
                                               self.rel_ind(pos + OVERRIDE_METHOD_OFS)))
                pos += OVERRIDE_DESCRIPTOR_SIZE
        return True

    # ---- uyumlar ve tanık tabloları -----------------------------------------------------------
    def uyumlar(self) -> list[SwiftUyum]:
        out: list[SwiftUyum] = []
        for bad in PROTO_SECTIONS:
            for b in self.g.bolumler_adli(bad):
                for i in range(b.boyut // 4):
                    d = self.rel(b.adres + 4 * i)
                    if d is None:
                        self.sayac[H_UYUM] += 1
                        continue
                    flags = self.g.u32(d + CONF_FLAGS)
                    if flags is None:
                        self.sayac[H_UYUM] += 1
                        continue
                    proto = self.rel_ind(d + CONF_PROTOCOL)
                    proto_y = self._yerel(proto)
                    tk = (flags >> CONF_TYPEREF_SHIFT) & CONF_TYPEREF_MASK
                    tip_ad: Optional[str] = None
                    if tk in (TYPEREF_DIRECT, TYPEREF_INDIRECT):
                        hedef = self.rel(d + CONF_TYPEREF)
                        if hedef is not None and tk == TYPEREF_INDIRECT:
                            hedef = self.g.gosterici(hedef)
                        if hedef is not None:
                            tip_ad = self.baglam_adi(hedef)[0]
                    elif tk == TYPEREF_OBJC_NAME:
                        tip_ad = self._cstr(self.rel(d + CONF_TYPEREF))
                    proto_ad = self.baglam_adi(proto)[0] if proto is not None else None
                    out.append(SwiftUyum(adres=d, protokol=proto_ad, protokol_yerel=proto_y is not None,
                                         protokol_adres=proto_y, tip=tip_ad, tanik_tablosu=self.rel(d + CONF_WITNESS),
                                         bayrak=flags))
        return out

    def tanik_yuvalari(self, uyumlar: list[SwiftUyum]) -> tuple[list[dict[str, Any]], int]:
        """Tanık tablosu kod göstericileri (kanıt). Yerel protokolde gereksinim sayısı kadar; dış protokolde
        ardışık kod göstericisi (başka bir tanık tablosunun başlangıcında durur)."""
        wt_adresleri = {u.tanik_tablosu for u in uyumlar if u.tanik_tablosu}
        gereksinim: dict[int, Optional[int]] = {}
        out: list[dict[str, Any]] = []
        dogrulanan = 0
        for u in uyumlar:
            wt = u.tanik_tablosu
            if not wt:
                continue
            if self.g.gosterici(wt) != u.adres:
                continue
            dogrulanan += 1
            sinir: Optional[int] = None
            if u.protokol_adres is not None:
                pa = u.protokol_adres
                if pa not in gereksinim:
                    gereksinim[pa] = self.g.u32(pa + PROTO_NUM_REQUIREMENTS)
                sinir = gereksinim[pa]
                if sinir is not None and sinir > MAX_WITNESS_SCAN:
                    sinir = MAX_WITNESS_SCAN
            j = 1
            while True:
                if sinir is not None and j > sinir:
                    break
                a = wt + POINTER_SIZE * j
                if sinir is None and (a in wt_adresleri or j > MAX_WITNESS_SCAN):
                    break
                p = self._yerel(self.g.gosterici(a))
                if p is not None and self.kodda(p):
                    out.append({"tur": YUVA_TANIK, "tip": u.tip, "protokol": u.protokol, "sira": j,
                                "adres": p, "uyum": u.adres})
                elif sinir is None:
                    break
                j += 1
        return out, dogrulanan

    def _async_govde(self, impl: int) -> Optional[int]:
        """Zaman uyumsuz yöntemin uygulaması zaman uyumsuz işlev göstericisidir (+0 int32 göreli işlev);
        gövde kodda değilse ``None`` (kanıt alanı; yerel örnekte ``async function pointer to …`` sembolüyle
        doğrulandı)."""
        govde = self.rel(impl + ASYNC_FP_FUNCTION)
        return govde if self.kodda(govde) else None

    # ---- bütün -------------------------------------------------------------------------------
    def oku(self) -> SwiftSonuc:
        tipler = []
        for d in self.tip_adresleri():
            t = self.tip(d)
            if t is not None:
                tipler.append(t)
        uyumlar = self.uyumlar()
        yuvalar: list[dict[str, Any]] = []
        # yöntem betimleyicisi → (tip, vtable sırası, yöntem türü): geçersiz kılma kaydının hedefi için
        betimleyici: dict[int, tuple[SwiftTip, int, str]] = {}
        for t in tipler:
            for sira, (ba, y) in enumerate(zip(t.yontem_adresleri, t.yontemler)):
                betimleyici[ba] = (t, sira, y[0])
        for t in tipler:
            for sira, (ytur, ornek, dinamik, eszamansiz, impl) in enumerate(t.yontemler):
                kodda = self.kodda(impl)
                yuva = {"tur": YUVA_VTABLE, "tip": t.nitelikli_ad, "tip_adresi": t.adres,
                        "yontem_turu": ytur, "sira": sira, "ornek": ornek, "dinamik": dinamik,
                        "zaman_uyumsuz": eszamansiz, "adres": impl, "kodda": kodda}
                if eszamansiz and impl is not None and not kodda:
                    yuva["govde"] = self._async_govde(impl)
                yuvalar.append(yuva)
            for sira, impl in enumerate(t.gecersiz_kilma):
                yuva = {"tur": YUVA_GECERSIZ_KILMA, "tip": t.nitelikli_ad, "tip_adresi": t.adres,
                        "sira": sira, "adres": impl, "kodda": self.kodda(impl),
                        "ust_tip": None, "ust_tip_adresi": None, "ust_sira": None, "yontem_turu": None}
                if sira < len(t.gecersiz_kilma_hedef):
                    hedef = self._yerel(t.gecersiz_kilma_hedef[sira][1])
                    if hedef is not None and hedef in betimleyici:
                        ust, ust_sira, ytur = betimleyici[hedef]
                        yuva.update({"ust_tip": ust.nitelikli_ad, "ust_tip_adresi": ust.adres, "ust_sira": ust_sira,
                                     "yontem_turu": ytur})
                        if ust.yontemler[ust_sira][3] and impl is not None and not yuva["kodda"]:
                            yuva["govde"] = self._async_govde(impl)
                yuvalar.append(yuva)
        tanik, dogrulanan = self.tanik_yuvalari(uyumlar)
        yuvalar.extend(tanik)
        denetim = self.denetle(tipler, yuvalar, uyumlar, dogrulanan)
        sonuc = SwiftSonuc(durum=DURUM_CALISTI, tipler=tipler, uyumlar=uyumlar, yuvalar=yuvalar,
                           sayaclar=dict(self.sayac), denetim=denetim)
        neden = tutarsizlik_nedeni(sonuc)
        if neden is not None:
            sonuc.durum = DURUM_TUTARSIZ
            sonuc.neden = neden
        return sonuc

    def denetle(self, tipler: list[SwiftTip], yuvalar: list[dict[str, Any]], uyumlar: list[SwiftUyum],
                dogrulanan: int) -> dict[str, Any]:
        """Kendi kendini doğrulama sayaçları (plan kalem 6) ve H1 sayıları."""
        bas_ham = self.g.fonksiyon_baslangiclari()
        bas = set(bas_ham) if bas_ham is not None else None
        sayim = Counter(t.erisim for t in tipler if t.erisim is not None)
        for t in tipler:
            if t.erisim is None:
                continue
            t.erisim_kodda = self.kodda(t.erisim)
            t.erisim_baslangic = (t.erisim in bas) if bas is not None else None
            t.erisim_paylasimli = sayim[t.erisim] > 1
        erisim = set(sayim)
        vt = [y for y in yuvalar if y["tur"] == YUVA_VTABLE]
        vt_impl = {y["adres"] for y in vt if y["adres"] is not None}
        gk = {y["adres"] for y in yuvalar if y["tur"] == YUVA_GECERSIZ_KILMA and y["adres"] is not None}
        tanik = {y["adres"] for y in yuvalar if y["tur"] == YUVA_TANIK}

        def basta(k: set[int]) -> Optional[int]:
            return sum(1 for a in k if a in bas) if bas is not None else None

        return {
            "erisim_fonksiyonu": len(erisim), "erisim_kodda": sum(1 for a in erisim if self.kodda(a)),
            "erisim_kod_disi": sum(1 for a in erisim if not self.kodda(a)),
            "erisim_fonksiyon_baslangici": basta(erisim),
            "fonksiyon_baslangic_tablosu": bas is not None,
            "sinif": sum(1 for t in tipler if t.tur == TUR_ADI[KIND_CLASS]),
            "artci_cozulen_sinif": sum(1 for t in tipler if t.artci_cozuldu),
            "yontem_betimleyici": len(vt), "impl_bos": sum(1 for y in vt if y["adres"] is None),
            "ayrik_impl": len(vt_impl), "impl_kodda": sum(1 for a in vt_impl if self.kodda(a)),
            "impl_fonksiyon_baslangici": basta({a for a in vt_impl if self.kodda(a)}),
            "yontem_turu": dict(Counter(y["yontem_turu"] for y in vt)),
            "gecersiz_kilma_kaydi": sum(1 for y in yuvalar if y["tur"] == YUVA_GECERSIZ_KILMA),
            "gecersiz_kilma_ayrik_impl": len(gk), "gecersiz_kilma_kodda": sum(1 for a in gk if self.kodda(a)),
            "uyum_kaydi": len(uyumlar), "yerel_protokole": sum(1 for u in uyumlar if u.protokol_yerel),
            "tanik_tablosu_olan": len({u.tanik_tablosu for u in uyumlar if u.tanik_tablosu}),
            "ilk_sozcugu_dogrulanan": dogrulanan, "tanik_kod_gostericisi_ayrik": len(tanik),
            "tanik_fonksiyon_baslangici": basta(tanik),
        }


def _karisik_ayrac(karisik: str, kisa: str) -> Optional[str]:
    """Adsız bağlamın karışık adında ``<uz><kısa ad><uz><ayraç>LL`` deseninden ayraç (``_ABC…``)."""
    if not kisa.isascii():
        return None
    hedef = f"{len(kisa.encode())}{kisa}"
    bas = 0
    while True:
        k = karisik.find(hedef, bas)
        if k < 0:
            return None
        j = k + len(hedef)
        m = re.match(r"(\d+)", karisik[j:])
        if m and not m.group(1).startswith("0"):
            uz = int(m.group(1))
            ayrac = karisik[j + len(m.group(1)):j + len(m.group(1)) + uz]
            sonra = j + len(m.group(1)) + uz
            if len(ayrac) == uz and karisik[sonra:sonra + 2] == "LL":
                return ayrac
        bas = k + 1


def _objc_ayrac(objc_adi: str, kisa: str) -> Optional[str]:
    """ObjC çalışma zamanı adındaki ``P<uz><ayraç><uz><kısa ad>`` bileşeninden ayraç (eski karışık ad biçimi:
    özel bildirim adı ``P`` + ayraç tanımlayıcısı + ad). Birden çok farklı eşleşme → ``None``."""
    if not kisa.isascii():
        return None
    ad = f"{len(kisa.encode())}{kisa}"
    bulunan: set[str] = set()
    for m in _PRIVATE_OBJC_RE.finditer(objc_adi):
        if m.group(1).startswith("0"):
            continue
        uz = int(m.group(1))
        ayrac = objc_adi[m.end():m.end() + uz]
        if len(ayrac) == uz and objc_adi.startswith(ad, m.end() + uz):
            bulunan.add(ayrac)
    return next(iter(bulunan)) if len(bulunan) == 1 else None


def tutarsizlik_nedeni(sonuc: SwiftSonuc) -> Optional[str]:
    """Yapı ihlali varsa neden (ad listesi yazılmaz): kod bölümü dışında erişim fonksiyonu.

    Erişim fonksiyonu her tipte derleyici üretimi koddur; kod dışına düşmesi biçimin yanlış okunduğunu gösterir
    (P-ÜV1'in K2 denetiminin karşılığı). vtable uygulamasının kod dışı olması (zaman uyumsuz yöntemde zaman uyumsuz
    işlev göstericisi) ihlal değildir.
    """
    disi = sonuc.denetim.get("erisim_kod_disi") or 0
    if disi:
        return f"kod bölümü dışında {disi} erişim fonksiyonu"
    return None


def oku(goruntu: Any) -> SwiftSonuc:
    """Görüntüdeki Swift tip üst verisini oku. İstisna atmaz; durum ``SwiftSonuc.durum``'dadır."""
    try:
        bicim = goruntu.bicim
        adlar = {b.ad for b in goruntu.bolumler}
        swift_var = any(k in adlar for k in TYPES_SECTIONS + PROTO_SECTIONS)
        if bicim != BICIM_MACHO:
            if swift_var or any("swift5_" in a for a in adlar):
                return SwiftSonuc(DURUM_DESTEKLENMIYOR, f"{bicim} biçiminde Swift üst verisi okunmuyor (yalnız Mach-O)")
            return SwiftSonuc(DURUM_VERI_YOK, f"Mach-O değil ({bicim})")
        if goruntu.gosterici_boyutu != POINTER_SIZE:
            return SwiftSonuc(DURUM_DESTEKLENMIYOR, f"gösterici boyu {goruntu.gosterici_boyutu} (yalnız 64 bit)")
        if not swift_var:
            return SwiftSonuc(DURUM_VERI_YOK, "Swift tip / uyum bölümü yok")
        return SwiftOkuyucu(goruntu).oku()
    except Exception as exc:  # okuyucu istisna atmaz; beklenmeyen hata durumla döner
        logger.warning("Swift üst verisi okunamadı: %s", exc)
        return SwiftSonuc(DURUM_HATA, f"{type(exc).__name__}: {exc}")
