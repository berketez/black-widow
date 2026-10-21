#!/usr/bin/env python3
"""dwz farkında DWARF tip okuyucu (plan v2.2 T0a): K1'in gerçek verisi, parametre tipleri.

Debian ve Ubuntu dbgsym paketlerinde dwz, birden çok ikilide ortak olan DIE'leri ek bir
dosyaya taşır. Ana ``.debug`` dosyası ek dosyayı ``.gnu_debugaltlink`` ile gösterir (yol +
ek dosyanın build-id'si) ve ona iki biçimle başvurur:

- ``DW_FORM_GNU_ref_alt``: ek dosyanın ``.debug_info`` ofseti (DIE);
- ``DW_FORM_GNU_strp_alt``: ek dosyanın ``.debug_str`` ofseti (dizgi).

pyelftools 0.32 ek dosya bağlanmadan bunları çözmez (``NotImplementedError: DW_FORM_GNU_ref_alt
to dwo``), ``dwarfdump`` ham ofset basar. Bu betik iki dosyayı ayrı ELF/DWARF olarak açar
(pyelftools'un kendi ek dosya bağlama yolu kapalı: ``follow_links=False``), DIE'leri kendi küçük
kayıtlarına (``Die``) aktarır ve başvuruları kendisi çözer. DIE kimliği daima (dosya rolü,
ofset) çiftidir: ``ana:0x1c5f7``, ``ek:0x365``. DWARF 5'in eş biçimleri (``DW_FORM_ref_sup4/8``,
``DW_FORM_strp_sup``) aynı yoldan çözülür. dwz'siz dosyada ek dosya aranmaz.

Tanımlar
--------
Birimler
    Ana dosyanın bütün birimleri (``DW_TAG_compile_unit`` ve dwz'nin dosya içi
    ``DW_TAG_partial_unit``'leri) ikiliye aittir. Ek dosya bütün paketin ortak deposudur ve
    başka ikililerin tiplerini de taşır; ondan yalnız ana dosyanın ``DW_TAG_imported_unit``
    DIE'lerinden (geçişli) erişilen kısmi birimler bu ikiliye aittir. Bildirimden
    (``DW_AT_declaration``) tanıma giderken yalnız erişilen birimlere bakılır.
Fonksiyon
    Ana dosyada ``DW_AT_low_pc`` taşıyan her ``DW_TAG_subprogram`` (somut gövde). Ad, tip ve
    öbür öznitelikler ``DW_AT_abstract_origin`` ve ``DW_AT_specification`` zinciriyle (dosyalar
    arasında da) aranır; ``ad_kaynagi.yol`` adın zincirin neresinden geldiğini yazar.
Parametre
    Somut DIE'nin ``DW_TAG_formal_parameter`` çocukları; somut DIE'de hiç yoksa kökeninkiler
    (``parametre_kaynagi: soyut``). ``sira`` 1 tabanlıdır (Ghidra'nın ``param_1`` sayımı) ve
    bildirimdeki yeri verir: parametrenin ``abstract_origin``'i kökenin parametre listesinde
    kaçıncıysa. ``somut_sira`` somut DIE'deki yerdir. GCC'nin IPA klonları parametreleri yeniden
    sıralar ya da atar; bu yüzden ikisi klonlarda ayrışabilir. Eşlenemeyen ``sira`` ``None``'dır.
    ``tekrar``: aynı bildirim parametresine DIE sırasında ikinci (ve sonraki) kez bağlanan DIE
    (GCC LTO/IPA-CP çıktısı: sabit değer betimi ya da konumsuz yer tutucu). Tip sayımlarında
    bildirim parametresi başına tek sayım için kullanılır; ABI yargısı DEĞİLDİR (redis
    ``incrRefCount``'ta konumsuz DIE önce, W0'daki gerçek parametre sonra gelir). ``yer``:
    DWARF konum bilgisinin biçimi (``exprloc``, ``loclist``, ``const_value`` ya da boş).
Tip
    ``ham``: typedef, niteleyici ve işaretçi adımlarıyla tam zincir; her adımda etiket, konum ve
    varsa ad. ``kanonik``: typedef soyulur; ``const``, ``volatile``, ``restrict`` ve ``_Atomic``
    atılır, atılanlar ``niteleyiciler``'de kalır; işaretçi derinliği tutulur. Yapı, birlik ve
    enum adıyla yazılır (``struct foo``), anonimse konumuyla (``struct <anon@ek:0x1a2b>``).
    Temel tip adıyla yazılır, fonksiyon tipi ``fonk(<dönüş>; <parametreler>)``, dizi
    ``<eleman>[N]``. ``sinif``: ``yapi*`` (struct, union), ``void*``, ``char*`` (1 baytlık char
    ailesi: char, signed char, unsigned char), ``skaler`` (temel tip ya da enum), ``skaler*``,
    ``fonk*``, ``yapi_degerle``, ``ptr**`` (derinlik >= 2), ``diger``.
Çözülen tip
    Parametrenin (ya da kökeninin) ``DW_AT_type``'ı var, zincirdeki her başvuru doğru dosyada
    bir DIE başına düşüyor, gereken her ad okunuyor ve zincir bir uca (temel tip, yapı, birlik,
    enum, void, fonksiyon tipi, dizi) varıyor. Değilse ``neden`` yazılır (``NEDENLER``).
Klon bayrağı
    ``klon.sonekler``: ``.symtab``'ta gövdenin adresindeki adlardan gelen ``.isra``,
    ``.constprop``, ``.part``, ``.cold`` ekleri. ``klon.abstract_origin``: somut DIE
    ``abstract_origin`` taşıyor; ``klon.origin_inline`` kökenin ``DW_AT_inline`` değeri.
    ``klon.bayrak`` ikisinden biri. Dışarıda bırakma kararı K1 ön kaydında verilir. LTO'lu
    derlemede her somut gövdenin ``abstract_origin``'i vardır (erken hata ayıklama DIE'si,
    ``origin_inline`` boş); ``abstract_origin`` tek başına klon ölçütü olamaz.
Yapı tablosu (``yapilar``)
    Parametrelerin kökündeki yapı ve birlikler; ad taşıyanların erişilen birimlerdeki bütün tam
    tanımları (``tanimlar``) da tabloya girer. Tam tanımda üyeler: ad, ofset, kanonik tip, sınıf.
    Bit alanlarında ``bit_boyutu`` ve ``bit_ofseti`` (DWARF 5: ``DW_AT_data_bit_offset``) dolu,
    ``ofset`` boştur. K1'in "kalıtım ailesi" kuralı ve K2 bunu okur.
Sayımlar (``sayimlar``)
    Parametre ve sınıf sayıları; ``tipi_ek_dosyada`` (tipi tutan başvuru ek dosyaya gidiyor);
    ``sira_farkli_fonksiyon`` ve ``eksik_parametreli_fonksiyon`` (klon belirtileri);
    ``yalniz_ranges_govde`` (çıkarılmayan, ``DW_AT_low_pc``'siz gövdeler);
    ``tum_formal_parameter``: dosyadaki BÜTÜN ``formal_parameter`` DIE'leri (satır içi, soyut,
    bildirim, fonksiyon tipi dahil) ve DIE'nin kendi ``DW_AT_type`` biçimi.

Alt komutlar
------------
    cikar   <debug> [--ek <ek dosya>] [--ikili <ikili>] -o <json>
    toplu   <dbgsym kökü: …/usr/lib/debug> [--ikili-kok <dizin>] -o <çıktı dizini>
    ozet    <json ya da dizin...> [--json <yol> [--yalniz-gruplar]]
            (dizin verilirse dizin başına ara toplam)
    capraz  <json ya da dizin...> [--n 50] [--evren ek|ana|hepsi] [-o <json>]
            (Apple dwarfdump ile bağımsız denetim)

Çapraz denetim (``capraz``)
    Çözülmüş ve tipi ek dosyada olan (``--evren ek``; ``ana`` ve ``hepsi`` de var)
    parametrelerden tohumlu rastgele ``n`` tanesi seçilir. Evren dosya adı, adres ve konuma göre
    sıralanır; seçim ``random.Random(tohum(tohum_metni)).sample``. Her
    biri için ``/usr/bin/dwarfdump -v -F --debug-info=<ofset>`` ile parametrenin DIE'sinden
    başlanır; köken zinciri, tipin tutulduğu DIE, tip zinciri (etiket, konum, ad) ve basit
    uçlarda kanonik biçim yeniden kurulur. ``strp_alt`` adları ek dosyanın ``--debug-str``
    dökümünden okunur. Bu yol pyelftools'u ve bu betiğin çözücüsünü kullanmaz.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import re
import subprocess
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

SEMA = "karadul-dwarf-tip/1"
TOPLU_SEMA = "karadul-dwarf-tip-toplu/1"
OZET_SEMA = "karadul-dwarf-tip-ozet/1"
CAPRAZ_SEMA = "karadul-dwarf-tip-capraz/1"

ANA = "ana"   # ana .debug dosyası
EK = "ek"     # dwz ek dosyası (.gnu_debugaltlink)

# Apple llvm-dwarfdump. PATH'teki conda araçlarına güvenilmez; daima mutlak yol.
DWARFDUMP_YOLU = "/usr/bin/dwarfdump"
ARAC_ZAMAN_ASIMI_S = 120
CAPRAZ_N = 50
CAPRAZ_TOHUM_METNI = "karadul-g9-t0a-capraz-denetim-2026-10-21"
IC_TIP_SINIRI = 16   # iç içe fonksiyon ve dizi tipi derinliği (bozuk veriye karşı koruma)
KOKEN_SINIRI = 16    # abstract_origin / specification zinciri uzunluğu

# --- Başvuru biçimleri
YEREL_BASVURU = frozenset({"DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4", "DW_FORM_ref8",
                           "DW_FORM_ref_udata"})          # birim (CU) başlığına göre
GENEL_BASVURU = frozenset({"DW_FORM_ref_addr"})          # aynı dosyanın .debug_info'su
EK_BASVURU = frozenset({"DW_FORM_GNU_ref_alt", "DW_FORM_ref_sup4", "DW_FORM_ref_sup8"})
EK_DIZGI = frozenset({"DW_FORM_GNU_strp_alt", "DW_FORM_strp_sup"})
SABIT_BICIMLER = frozenset({"DW_FORM_data1", "DW_FORM_data2", "DW_FORM_data4", "DW_FORM_data8",
                            "DW_FORM_udata", "DW_FORM_sdata", "DW_FORM_implicit_const"})
_IMZASIZ_GENISLIK = {"DW_FORM_data1": 8, "DW_FORM_data2": 16, "DW_FORM_data4": 32,
                     "DW_FORM_data8": 64}

# --- Etiketler
T_TYPEDEF = "DW_TAG_typedef"
T_POINTER = "DW_TAG_pointer_type"
REFERANSLAR = frozenset({"DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"})
ATILAN_NITELEYICILER = {"DW_TAG_const_type": "const", "DW_TAG_volatile_type": "volatile",
                        "DW_TAG_restrict_type": "restrict", "DW_TAG_atomic_type": "_Atomic"}
KUME_TURLERI = {"DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union",
                "DW_TAG_class_type": "class", "DW_TAG_enumeration_type": "enum"}
YAPI_TURLERI = frozenset({"struct", "union", "class"})
BIRIM_ETIKETLERI = frozenset({"DW_TAG_compile_unit", "DW_TAG_partial_unit"})
KOKEN_OZELLIKLERI = (("DW_AT_abstract_origin", "abstract_origin"),
                     ("DW_AT_specification", "specification"))

# Yalnız bu öznitelikler saklanır (bellek); geri kalanı kullanılmıyor.
KULLANILAN_OZELLIKLER = frozenset({
    "DW_AT_name", "DW_AT_type", "DW_AT_abstract_origin", "DW_AT_specification",
    "DW_AT_low_pc", "DW_AT_high_pc", "DW_AT_ranges", "DW_AT_declaration", "DW_AT_external",
    "DW_AT_prototyped", "DW_AT_inline", "DW_AT_byte_size", "DW_AT_encoding", "DW_AT_import",
    "DW_AT_data_member_location", "DW_AT_bit_size", "DW_AT_data_bit_offset", "DW_AT_bit_offset",
    "DW_AT_upper_bound", "DW_AT_count", "DW_AT_lower_bound", "DW_AT_language",
    "DW_AT_location", "DW_AT_const_value",
})
# Parametrenin DWARF konum bilgisinin biçimi (``yer``): ifade, konum listesi ya da sabit değer.
YER_IFADE_BICIMLERI = frozenset({"DW_FORM_exprloc", "DW_FORM_block1", "DW_FORM_block2",
                                 "DW_FORM_block4", "DW_FORM_block"})
YER_LISTE_BICIMLERI = frozenset({"DW_FORM_sec_offset", "DW_FORM_loclistx", "DW_FORM_data4",
                                 "DW_FORM_data8"})

# --- Sınıflar (plan v2.2 §5 K1: yalnız yapi* karar ölçüsüne girer)
SINIF_YAPI_PTR = "yapi*"
SINIF_VOID_PTR = "void*"
SINIF_CHAR_PTR = "char*"
SINIF_SKALER = "skaler"
SINIF_SKALER_PTR = "skaler*"
SINIF_FONK_PTR = "fonk*"
SINIF_YAPI_DEGERLE = "yapi_degerle"
SINIF_PTR_PTR = "ptr**"
SINIF_DIGER = "diger"
SINIFLAR = (SINIF_YAPI_PTR, SINIF_VOID_PTR, SINIF_CHAR_PTR, SINIF_SKALER, SINIF_SKALER_PTR,
            SINIF_FONK_PTR, SINIF_YAPI_DEGERLE, SINIF_PTR_PTR, SINIF_DIGER)
CHAR_KODLAMALARI = frozenset({"signed_char", "unsigned_char"})
ATE_ADLARI = {0x01: "address", 0x02: "boolean", 0x03: "complex_float", 0x04: "float",
              0x05: "signed", 0x06: "signed_char", 0x07: "unsigned", 0x08: "unsigned_char",
              0x09: "imaginary_float", 0x0a: "packed_decimal", 0x0b: "numeric_string",
              0x0c: "edited", 0x0d: "signed_fixed", 0x0e: "unsigned_fixed",
              0x0f: "decimal_float", 0x10: "UTF", 0x11: "UCS", 0x12: "ASCII"}
INL_ADLARI = {0: "not_inlined", 1: "inlined", 2: "declared_not_inlined", 3: "declared_inlined"}

KLON_SONEKLERI = (".isra", ".constprop", ".part", ".cold")
_KLON_SONEK_RE = re.compile(r"\.(isra|constprop|part|cold)(?=\.|$)")

# Çözülemeyen tiplerin nedenleri
NEDENLER = {
    "tip_yok": "parametrede ve kökeninde DW_AT_type yok",
    "ek_dosya_yok": "başvuru dwz ek dosyasına gidiyor, ek dosya açılmadı",
    "gecersiz_ofset": "başvuru hedef dosyada bir DIE başına düşmüyor",
    "gecersiz_dizgi_ofseti": "strp_alt ofseti ek dosyanın .debug_str'ı dışında",
    "ek_icinden_ek_basvurusu": "ek dosya ref_alt/strp_alt taşıyor (dwz çoklu dosyada olmaz)",
    "ref_sig8": "tip birimi başvurusu (DW_FORM_ref_sig8) desteklenmiyor",
    "bilinmeyen_bicim": "başvuru biçimi tanınmadı",
    "bilinmeyen_etiket": "tip zincirinde beklenmeyen etiket",
    "ad_cozulemedi": "gereken ad okunamadı",
    "dongu": "zincir döngüye giriyor",
    "derinlik_asimi": "iç içe tip ya da köken zinciri sınırı aşıldı",
}


class CozumHatasi(Exception):
    """Bir başvuru ya da tip çözülemedi; ``neden`` ``NEDENLER`` anahtarlarından biri."""

    def __init__(self, neden: str, ayrinti: str = "") -> None:
        super().__init__(f"{neden}: {ayrinti}" if ayrinti else neden)
        self.neden = neden
        self.ayrinti = ayrinti


class Die:
    """Bir DIE'nin bu betiğin kullandığı kısmı (pyelftools nesnesi dosya kapanınca tutulmaz)."""

    __slots__ = ("ofset", "etiket", "oz", "cocuklar", "birim", "ust")

    def __init__(self, ofset: int, etiket: str, oz: Optional[dict[str, tuple[str, Any, Any]]] = None,
                 cocuklar: Optional[list[int]] = None, birim: int = 0,
                 ust: Optional[int] = None) -> None:
        self.ofset = ofset
        self.etiket = etiket
        self.oz = oz if oz is not None else {}      # öznitelik adı -> (biçim, ham değer, değer)
        self.cocuklar = cocuklar if cocuklar is not None else []
        self.birim = birim                          # birim (CU) başlığının .debug_info ofseti
        self.ust = ust                              # üst DIE ofseti; birim başında None


class DwarfDosyasi:
    """Bir ELF dosyasının DWARF'ı: DIE'ler, birimler, .debug_str ve .symtab fonksiyon adları."""

    def __init__(self, rol: str, dieler: dict[int, Die], birimler: dict[int, dict[str, Any]],
                 dizgi_tablosu: bytes = b"", semboller: Optional[dict[int, list[str]]] = None,
                 *, yol: Optional[Path] = None, build_id: Optional[str] = None,
                 altlink: Optional[tuple[str, str]] = None) -> None:
        if rol not in (ANA, EK):
            raise ValueError(f"rol {ANA!r} ya da {EK!r} olmalı: {rol!r}")
        self.rol = rol
        self.dieler = dieler
        self.birimler = birimler      # birim başlığı ofseti -> {ust, etiket, dieler}
        self.dizgi_tablosu = dizgi_tablosu
        self.semboller = semboller if semboller is not None else {}
        self.yol = yol
        self.build_id = build_id
        self.altlink = altlink        # (yol metni, ek dosyanın build-id'si) ya da None


# ---------------------------------------------------------------------------
# Saf yardımcılar
# ---------------------------------------------------------------------------

def konum(rol: str, ofset: int) -> str:
    return f"{rol}:0x{ofset:x}"


def konum_coz(metin: str) -> tuple[str, int]:
    rol, _, ofset = metin.partition(":")
    if rol not in (ANA, EK) or not ofset.startswith("0x"):
        raise ValueError(f"konum biçimi 'ana:0x..' ya da 'ek:0x..' olmalı: {metin!r}")
    return rol, int(ofset, 16)


def _konum_anahtari(metin: str) -> tuple[str, int]:
    return konum_coz(metin)


def kisa_etiket(etiket: str) -> str:
    return etiket[7:] if etiket.startswith("DW_TAG_") else etiket


def tohum(metin: str) -> int:
    """Ön kayıtlardaki tohum yöntemi: SHA-256(metin)'in ilk 16 hex basamağı."""
    return int(hashlib.sha256(metin.encode("utf-8")).hexdigest()[:16], 16)


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def altlink_coz(veri: bytes) -> tuple[str, str]:
    """``.gnu_debugaltlink`` içeriği: NUL ile biten yol + ek dosyanın build-id baytları."""
    son = veri.find(b"\0")
    if son < 0:
        raise ValueError(".gnu_debugaltlink: yol NUL ile bitmiyor")
    yol = veri[:son].decode("utf-8", "replace")
    build_id = veri[son + 1:].hex()
    if not yol or not build_id:
        raise ValueError(".gnu_debugaltlink: yol ya da build-id boş")
    return yol, build_id


def basvuru_hedefi(rol: str, birim_ofseti: int, bicim: str, ham: int) -> tuple[str, int]:
    """Bir başvuru özniteliğinin hedefi: (dosya rolü, .debug_info ofseti).

    Birim içi biçimler birim başlığına göredir; ``ref_addr`` aynı dosyanın bölümüne göredir;
    ``ref_alt``/``ref_sup`` ek dosyanın bölümüne göredir. Ek dosya başka bir ek dosyaya
    başvuramaz (dwz çoklu dosya kipinde ek dosya kendi içinde kapalıdır).
    """
    if bicim in YEREL_BASVURU:
        return rol, birim_ofseti + ham
    if bicim in GENEL_BASVURU:
        return rol, ham
    if bicim in EK_BASVURU:
        if rol != ANA:
            raise CozumHatasi("ek_icinden_ek_basvurusu", bicim)
        return EK, ham
    if bicim == "DW_FORM_ref_sig8":
        raise CozumHatasi("ref_sig8", f"0x{ham:x}")
    raise CozumHatasi("bilinmeyen_bicim", bicim)


def dizgi_oku(tablo: bytes, ofset: int) -> str:
    """``.debug_str`` tablosundan ofsetteki NUL ile biten dizgi (kuyruk paylaşımı serbest)."""
    if not 0 <= ofset < len(tablo):
        raise CozumHatasi("gecersiz_dizgi_ofseti", f"0x{ofset:x} / {len(tablo)}")
    son = tablo.find(b"\0", ofset)
    if son < 0:
        raise CozumHatasi("gecersiz_dizgi_ofseti", f"0x{ofset:x}: NUL yok")
    return tablo[ofset:son].decode("utf-8", "replace")


def klon_sonekleri(adlar: Iterable[str]) -> list[str]:
    """Sembol adlarındaki GCC klon ekleri (``foo.constprop.0.isra.0`` -> .constprop, .isra)."""
    bulunan: set[str] = set()
    for ad in adlar:
        for m in _KLON_SONEK_RE.finditer(ad):
            bulunan.add("." + m.group(1))
    return sorted(bulunan)


def deger(die: Die, ad: str) -> Any:
    oz = die.oz.get(ad)
    return None if oz is None else oz[2]


def sabit(die: Die, ad: str) -> Optional[int]:
    """Sabit biçimli özniteliğin tamsayı değeri (imzasız biçimde tümleyen okunur); yoksa None."""
    oz = die.oz.get(ad)
    if oz is None or oz[0] not in SABIT_BICIMLER or not isinstance(oz[2], int):
        return None
    v = oz[2]
    genislik = _IMZASIZ_GENISLIK.get(oz[0])
    if genislik is not None and v >= 1 << (genislik - 1) and ad in ("DW_AT_upper_bound",
                                                                    "DW_AT_lower_bound"):
        v -= 1 << genislik      # sınırlar imzalıdır (sıfır uzunluklu dizide üst sınır -1)
    return v


def _uleb128(veri: list[int], i: int) -> tuple[int, int]:
    sonuc = kayma = 0
    while i < len(veri):
        b = veri[i]
        i += 1
        sonuc |= (b & 0x7F) << kayma
        kayma += 7
        if not b & 0x80:
            return sonuc, i
    raise ValueError("ULEB128 yarım")


def uye_ofseti(uye: Die, ust_tur: str) -> Optional[int]:
    """``DW_AT_data_member_location``: sabit ya da tek ``DW_OP_plus_uconst`` ifadesi."""
    oz = uye.oz.get("DW_AT_data_member_location")
    if oz is None:
        return 0 if ust_tur == "union" else None
    v = oz[2]
    if isinstance(v, int):
        return v
    if isinstance(v, list) and v and v[0] == 0x23:     # DW_OP_plus_uconst
        try:
            n, son = _uleb128(v, 1)
        except ValueError:
            return None
        return n if son == len(v) else None
    return None


def dizi_boyutu(alt_aralik: Die) -> Optional[int]:
    sayi = sabit(alt_aralik, "DW_AT_count")
    if sayi is not None:
        return sayi
    ust = sabit(alt_aralik, "DW_AT_upper_bound")
    if ust is None:
        return None                     # esnek dizi ya da VLA
    alt = sabit(alt_aralik, "DW_AT_lower_bound") or 0
    return max(ust - alt + 1, 0)


def sinifla(kok: dict[str, Any], derinlik: int) -> str:
    """Kanonik tipin sınıfı (``SINIFLAR``)."""
    tur = kok.get("tur")
    if derinlik >= 2:
        return SINIF_PTR_PTR
    if derinlik == 1:
        if tur == "void":
            return SINIF_VOID_PTR
        if tur in YAPI_TURLERI:
            return SINIF_YAPI_PTR
        if tur == "temel" and kok.get("kodlama") in CHAR_KODLAMALARI and kok.get("boyut") == 1:
            return SINIF_CHAR_PTR
        if tur in ("temel", "enum"):
            return SINIF_SKALER_PTR
        if tur == "fonk":
            return SINIF_FONK_PTR
        return SINIF_DIGER
    if tur in ("temel", "enum"):
        return SINIF_SKALER
    if tur in YAPI_TURLERI:
        return SINIF_YAPI_DEGERLE
    return SINIF_DIGER


def yer_bilgisi(d: Die) -> Optional[str]:
    """Parametrenin konum bilgisi: ``exprloc`` | ``loclist`` | ``const_value`` | None (yok).

    Yalnız biçime bakar, ifadeyi çözmez. T0b hizalamasında hangi DIE'nin ABI parametresi
    olduğuna karar verirken ham ipucudur (LTO klonlarında konumsuz yer tutucu DIE'ler var)."""
    oz = d.oz.get("DW_AT_location")
    if oz is not None:
        if oz[0] in YER_IFADE_BICIMLERI:
            return "exprloc"
        if oz[0] in YER_LISTE_BICIMLERI:
            return "loclist"
        return oz[0]
    return "const_value" if "DW_AT_const_value" in d.oz else None


def hata_sonucu(neden: str, ayrinti: str = "") -> dict[str, Any]:
    return {"cozuldu": False, "neden": neden, "ayrinti": ayrinti or None}


# ---------------------------------------------------------------------------
# Dosya yükleme (pyelftools yalnız burada)
# ---------------------------------------------------------------------------

def elf_build_id(yol: Path) -> Optional[str]:
    """NT_GNU_BUILD_ID (hex); ELF değilse ya da not yoksa None."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection

    try:
        with open(yol, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return None
            f.seek(0)
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if isinstance(sec, NoteSection) and sec["sh_type"] != "SHT_NOBITS":
                    for not_ in sec.iter_notes():
                        if not_["n_type"] == "NT_GNU_BUILD_ID":
                            return str(not_["n_desc"])
    except (OSError, ELFError, ValueError, EOFError, KeyError):
        return None             # yoklama: bozuk ya da ELF olmayan dosya
    return None


def dosya_yukle(yol: Path, rol: str) -> DwarfDosyasi:
    """ELF dosyasını aç; DIE ağacını, .debug_str'ı, .symtab'ı ve .gnu_debugaltlink'i oku."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection

    dieler: dict[int, Die] = {}
    birimler: dict[int, dict[str, Any]] = {}
    semboller: dict[int, list[str]] = defaultdict(list)
    build_id: Optional[str] = None
    altlink: Optional[tuple[str, str]] = None
    dizgi = b""
    with open(yol, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if isinstance(sec, NoteSection) and sec["sh_type"] != "SHT_NOBITS":
                for not_ in sec.iter_notes():
                    if not_["n_type"] == "NT_GNU_BUILD_ID":
                        build_id = str(not_["n_desc"])
            elif sec.name == ".gnu_debugaltlink":
                altlink = altlink_coz(sec.data())
            elif sec.name == ".debug_str" and sec["sh_type"] != "SHT_NOBITS":
                dizgi = sec.data()
            elif isinstance(sec, SymbolTableSection) and sec.name == ".symtab":
                for s in sec.iter_symbols():
                    if (s["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC")
                            and s["st_shndx"] != "SHN_UNDEF" and s.name):
                        semboller[s["st_value"]].append(s.name)
        if not elf.has_dwarf_info():
            raise ValueError(f"{yol}: DWARF yok")
        dwarf = elf.get_dwarf_info(relocate_dwarf_sections=True, follow_links=False)
        for cu in dwarf.iter_CUs():
            ust_die = cu.get_top_DIE()
            kayit: dict[str, Any] = {"ust": ust_die.offset, "etiket": ust_die.tag, "dieler": []}
            birimler[cu.cu_offset] = kayit
            yigin: list[int] = []
            for die in cu.iter_DIEs():
                if die.tag is None:                 # kardeş listesinin sonu
                    if yigin:
                        yigin.pop()
                    continue
                ust = yigin[-1] if yigin else None
                oz: dict[str, tuple[str, Any, Any]] = {}
                for ad, a in die.attributes.items():
                    if ad in KULLANILAN_OZELLIKLER:
                        v = a.value
                        if isinstance(v, bytes):
                            v = v.decode("utf-8", "replace")
                        oz[ad] = (a.form, a.raw_value, v)
                dieler[die.offset] = Die(die.offset, die.tag, oz, [], cu.cu_offset, ust)
                kayit["dieler"].append(die.offset)
                if ust is not None:
                    dieler[ust].cocuklar.append(die.offset)
                if die.has_children:
                    yigin.append(die.offset)
    return DwarfDosyasi(rol, dieler, birimler, dizgi, dict(semboller), yol=yol,
                        build_id=build_id, altlink=altlink)


def ek_dosyasini_bul(ana_yol: Path, altlink: Optional[tuple[str, str]]
                     ) -> tuple[Optional[Path], str, list[str]]:
    """``.gnu_debugaltlink``'ten ek dosya: (yol, yöntem, build-id'si uymayan adaylar).

    Göreli yol ana dosyanın dizinine göre çözülür. Mutlak yol (Debian/Ubuntu:
    ``/usr/lib/debug/.dwz/...``) ana dosyanın her atasının altında aranır; paket açılmış
    dizinde de bulunur. Bulunamazsa build-id ile ``.build-id/xx/yyyy.debug`` ve ``.dwz/``
    altı taranır. Aday ancak build-id'si ``.gnu_debugaltlink``'tekiyle aynıysa kabul edilir
    (kökte sistemin kendi ``/usr/lib/debug``'ı yanlış dosya olabilir).
    """
    if altlink is None:
        return None, "altlink_yok", []
    yol_metni, beklenen = altlink
    ana = ana_yol.resolve()
    adaylar: list[Path] = []
    p = Path(yol_metni)
    if p.is_absolute():
        goreli = Path(*p.parts[1:])
        adaylar += [ata / goreli for ata in ana.parents]
    else:
        adaylar.append(ana.parent / p)
    uymayan: list[str] = []
    gorulen: set[Path] = set()
    for aday in adaylar:
        aday = aday.resolve() if aday.exists() else aday
        if aday in gorulen or not aday.is_file():
            continue
        gorulen.add(aday)
        if elf_build_id(aday) == beklenen:
            return aday, "debugaltlink", uymayan
        uymayan.append(str(aday))
    for ata in ana.parents:
        aday = ata / ".build-id" / beklenen[:2] / f"{beklenen[2:]}.debug"
        if aday.is_file() and elf_build_id(aday) == beklenen:
            return aday, "build_id", uymayan
        dwz = ata / ".dwz"
        if dwz.is_dir():
            for f in sorted(dwz.rglob("*")):
                if f.is_file() and not f.is_symlink() and elf_build_id(f) == beklenen:
                    return f, "build_id", uymayan
    return None, "bulunamadi", uymayan


# ---------------------------------------------------------------------------
# Çözücü
# ---------------------------------------------------------------------------

class Cozucu:
    """Ana dosya ve (varsa) ek dosya üstünde başvuru, ad ve tip çözümü."""

    def __init__(self, ana: DwarfDosyasi, ek: Optional[DwarfDosyasi] = None) -> None:
        if ana.rol != ANA or (ek is not None and ek.rol != EK):
            raise ValueError("Cozucu(ana=rol 'ana', ek=rol 'ek') bekler")
        self.dosyalar: dict[str, DwarfDosyasi] = {ANA: ana}
        if ek is not None:
            self.dosyalar[EK] = ek
        self._tip_onbellek: dict[tuple[str, int], dict[str, Any]] = {}
        self._erisim: Optional[tuple[set[tuple[str, int]], Counter]] = None
        self._tanimlar: Optional[dict[tuple[str, str], list[str]]] = None
        self._birim_adlari: dict[tuple[str, int], Optional[str]] = {}

    # --- temel erişim
    def die(self, rol: str, ofset: int) -> Die:
        dosya = self.dosyalar.get(rol)
        if dosya is None:
            raise CozumHatasi("ek_dosya_yok", konum(rol, ofset))
        d = dosya.dieler.get(ofset)
        if d is None:
            raise CozumHatasi("gecersiz_ofset", konum(rol, ofset))
        return d

    def hedef(self, rol: str, d: Die, oz_adi: str) -> tuple[str, Die]:
        bicim, ham, _ = d.oz[oz_adi]
        hrol, hofset = basvuru_hedefi(rol, d.birim, bicim, ham)
        return hrol, self.die(hrol, hofset)

    def dizgi(self, rol: str, d: Die, oz_adi: str = "DW_AT_name") -> Optional[str]:
        oz = d.oz.get(oz_adi)
        if oz is None:
            return None
        bicim, ham, v = oz
        if bicim in EK_DIZGI:
            if rol != ANA:
                raise CozumHatasi("ek_icinden_ek_basvurusu", bicim)
            ek = self.dosyalar.get(EK)
            if ek is None:
                raise CozumHatasi("ek_dosya_yok", f"{bicim} 0x{ham:x}")
            return dizgi_oku(ek.dizgi_tablosu, ham)
        if isinstance(v, str):
            return v
        raise CozumHatasi("ad_cozulemedi", f"{bicim} {konum(rol, d.ofset)}")

    def koken_zinciri(self, rol: str, d: Die) -> Iterator[tuple[str, Die, str]]:
        """DIE'nin kendisi, sonra abstract_origin / specification kökenleri (dosyalar arası)."""
        yol = "kendi"
        gorulen: set[tuple[str, int]] = set()
        for _ in range(KOKEN_SINIRI):
            anahtar = (rol, d.ofset)
            if anahtar in gorulen:
                raise CozumHatasi("dongu", konum(rol, d.ofset))
            gorulen.add(anahtar)
            yield rol, d, yol
            for oz_adi, ad in KOKEN_OZELLIKLERI:
                if oz_adi in d.oz:
                    rol, d = self.hedef(rol, d, oz_adi)
                    yol = ad if yol == "kendi" else f"{yol}>{ad}"
                    break
            else:
                return
        raise CozumHatasi("derinlik_asimi", "köken zinciri")

    def ad_bul(self, rol: str, d: Die) -> tuple[Optional[str], dict[str, Any]]:
        for r, k, yol in self.koken_zinciri(rol, d):
            if "DW_AT_name" in k.oz:
                bicim, ham, _ = k.oz["DW_AT_name"]
                kaynak: dict[str, Any] = {"yol": yol, "die": konum(r, k.ofset), "bicim": bicim}
                if bicim in EK_DIZGI:
                    kaynak["ofset"] = ham
                return self.dizgi(r, k, "DW_AT_name"), kaynak
        return None, {"yol": "yok"}

    def koken_degeri(self, rol: str, d: Die, oz_adi: str) -> Any:
        """Köken zincirinde özniteliği taşıyan ilk DIE'deki değer (zincir hatasında None)."""
        try:
            for _, k, _ in self.koken_zinciri(rol, d):
                if oz_adi in k.oz:
                    return k.oz[oz_adi][2]
        except CozumHatasi:
            return None
        return None

    # --- tip
    def parametre_tipi(self, rol: str, d: Die) -> tuple[dict[str, Any], dict[str, Any]]:
        """(tip_kaynagi, tip): DW_AT_type'ı taşıyan DIE (köken zinciriyle) ve çözülmüş tip."""
        kaynak: dict[str, Any] = {"yol": "yok"}
        try:
            for r, k, yol in self.koken_zinciri(rol, d):
                if "DW_AT_type" in k.oz:
                    bicim, ham, _ = k.oz["DW_AT_type"]
                    kaynak = {"yol": yol, "die": konum(r, k.ofset), "bicim": bicim}
                    hrol, hofset = basvuru_hedefi(r, k.birim, bicim, ham)
                    kaynak["hedef"] = konum(hrol, hofset)
                    return kaynak, self.tip_coz(hrol, self.die(hrol, hofset))
        except CozumHatasi as h:
            return kaynak, hata_sonucu(h.neden, h.ayrinti)
        return kaynak, hata_sonucu("tip_yok", konum(rol, d.ofset))

    def tip_coz(self, rol: str, d: Die, ic: int = 0) -> dict[str, Any]:
        anahtar = (rol, d.ofset)
        bellek = self._tip_onbellek.get(anahtar)
        if bellek is not None:
            return bellek
        try:
            sonuc = self._tip_zinciri(rol, d, ic)
        except CozumHatasi as h:
            sonuc = hata_sonucu(h.neden, h.ayrinti)
            if h.neden == "derinlik_asimi":
                return sonuc            # bağlama (derinliğe) bağlı; önbelleğe alınmaz
        self._tip_onbellek[anahtar] = sonuc
        return sonuc

    def _tip_hedefi(self, rol: str, d: Die) -> tuple[str, Optional[Die]]:
        if "DW_AT_type" not in d.oz:
            return rol, None                # void
        return self.hedef(rol, d, "DW_AT_type")

    def _tip_zinciri(self, rol: str, d0: Die, ic: int) -> dict[str, Any]:
        ham: list[dict[str, Any]] = []
        seviyeler: list[str] = []
        typedefler: list[Optional[str]] = []
        niteleyiciler: list[str] = []
        gorulen: set[tuple[str, int]] = set()
        r: str = rol
        d: Optional[Die] = d0
        while True:
            if d is None:
                kok: dict[str, Any] = {"tur": "void", "kimlik": "void"}
                taban = "void"
                break
            if (r, d.ofset) in gorulen:
                raise CozumHatasi("dongu", konum(r, d.ofset))
            gorulen.add((r, d.ofset))
            e = d.etiket
            ad = self.dizgi(r, d, "DW_AT_name")
            adim: dict[str, Any] = {"etiket": kisa_etiket(e), "konum": konum(r, d.ofset)}
            if ad is not None:
                adim["ad"] = ad
            ham.append(adim)
            if e == T_TYPEDEF:
                typedefler.append(ad)
                r, d = self._tip_hedefi(r, d)
                continue
            if e in ATILAN_NITELEYICILER:
                niteleyiciler.append(ATILAN_NITELEYICILER[e])
                r, d = self._tip_hedefi(r, d)
                continue
            if e == T_POINTER:
                seviyeler.append("*")
                r, d = self._tip_hedefi(r, d)
                continue
            if e in REFERANSLAR:            # C++; C'de yok. İşaretçi düzeyi gibi sayılır
                seviyeler.append("&")
                r, d = self._tip_hedefi(r, d)
                continue
            kok, taban = self._uc(r, d, e, ad, ic)
            break
        kanonik = f"{taban} {''.join(seviyeler)}" if seviyeler else taban
        return {"cozuldu": True, "neden": None, "kanonik": kanonik,
                "sinif": sinifla(kok, len(seviyeler)), "derinlik": len(seviyeler), "kok": kok,
                "ham": ham, "typedefler": typedefler, "niteleyiciler": niteleyiciler}

    def _uc(self, r: str, d: Die, e: str, ad: Optional[str], ic: int
            ) -> tuple[dict[str, Any], str]:
        """Tip zincirinin ucu: (kök kaydı, kanonik taban)."""
        k = konum(r, d.ofset)
        if e == "DW_TAG_base_type":
            if not ad:
                raise CozumHatasi("ad_cozulemedi", f"adsız temel tip {k}")
            kod = deger(d, "DW_AT_encoding")
            return ({"tur": "temel", "ad": ad, "kimlik": ad, "konum": k,
                     "kodlama": ATE_ADLARI.get(kod, kod), "boyut": deger(d, "DW_AT_byte_size")},
                    ad)
        if e in KUME_TURLERI:
            tur = KUME_TURLERI[e]
            kimlik = f"{tur} {ad}" if ad else f"{tur} <anon@{k}>"
            return ({"tur": tur, "ad": ad, "kimlik": kimlik, "konum": k,
                     "bildirim": bool(deger(d, "DW_AT_declaration")),
                     "boyut": deger(d, "DW_AT_byte_size")}, kimlik)
        if e == "DW_TAG_subroutine_type":
            s = self._fonk_kanonik(r, d, ic)
            return {"tur": "fonk", "kimlik": s, "konum": k}, s
        if e == "DW_TAG_array_type":
            s = self._dizi_kanonik(r, d, ic)
            return {"tur": "dizi", "kimlik": s, "konum": k}, s
        if e == "DW_TAG_unspecified_type":
            s = ad or "<belirsiz>"
            return {"tur": "belirsiz", "ad": ad, "kimlik": s, "konum": k}, s
        raise CozumHatasi("bilinmeyen_etiket", f"{e} {k}")

    def _ic_kanonik(self, r: str, d: Die, ic: int, *, bos: Optional[str] = "void") -> str:
        """d'nin DW_AT_type'ının kanonik biçimi (fonksiyon tipi ve dizi içi)."""
        if "DW_AT_type" not in d.oz:
            if bos is None:
                raise CozumHatasi("tip_yok", konum(r, d.ofset))
            return bos
        if ic + 1 > IC_TIP_SINIRI:
            raise CozumHatasi("derinlik_asimi", konum(r, d.ofset))
        hr, hd = self.hedef(r, d, "DW_AT_type")
        s = self.tip_coz(hr, hd, ic + 1)
        if not s["cozuldu"]:
            raise CozumHatasi(s["neden"], s.get("ayrinti") or "")
        return s["kanonik"]

    def _fonk_kanonik(self, r: str, d: Die, ic: int) -> str:
        donus = self._ic_kanonik(r, d, ic)
        parcalar: list[str] = []
        degisken = False
        for c_ofset in d.cocuklar:
            c = self.die(r, c_ofset)
            if c.etiket == "DW_TAG_formal_parameter":
                parcalar.append(self._ic_kanonik(r, c, ic, bos=None))
            elif c.etiket == "DW_TAG_unspecified_parameters":
                degisken = True
        if degisken:
            parcalar.append("...")
        if not parcalar:
            parcalar.append("void" if deger(d, "DW_AT_prototyped") else "?")
        return f"fonk({donus}; {', '.join(parcalar)})"

    def _dizi_kanonik(self, r: str, d: Die, ic: int) -> str:
        eleman = self._ic_kanonik(r, d, ic, bos=None)
        boyutlar: list[Optional[int]] = []
        for c_ofset in d.cocuklar:
            c = self.die(r, c_ofset)
            if c.etiket == "DW_TAG_subrange_type":
                boyutlar.append(dizi_boyutu(c))
        return eleman + "".join(f"[{b}]" if b is not None else "[]" for b in boyutlar or [None])

    # --- birimler ve ithal
    def birim_adi(self, rol: str, birim: int) -> Optional[str]:
        anahtar = (rol, birim)
        if anahtar not in self._birim_adlari:
            dosya = self.dosyalar[rol]
            ust = dosya.dieler[dosya.birimler[birim]["ust"]]
            try:
                ad = self.dizgi(rol, ust, "DW_AT_name")
            except CozumHatasi:
                ad = None
            self._birim_adlari[anahtar] = ad
        return self._birim_adlari[anahtar]

    def erisim(self) -> tuple[set[tuple[str, int]], Counter]:
        """İkiliye ait birimler: ana dosyanın hepsi + imported_unit ile (geçişli) erişilenler."""
        if self._erisim is not None:
            return self._erisim
        ana = self.dosyalar[ANA]
        erisilen = {(ANA, b) for b in ana.birimler}
        kuyruk = sorted(erisilen)
        ithal: Counter = Counter()
        while kuyruk:
            r, b = kuyruk.pop()
            dosya = self.dosyalar[r]
            for o in dosya.birimler[b]["dieler"]:
                d = dosya.dieler[o]
                if d.etiket != "DW_TAG_imported_unit" or "DW_AT_import" not in d.oz:
                    continue
                try:
                    hr, hd = self.hedef(r, d, "DW_AT_import")
                except CozumHatasi as h:
                    ithal[f"cozulemeyen:{h.neden}"] += 1
                    continue
                if hd.etiket not in BIRIM_ETIKETLERI or hd.ust is not None:
                    ithal["birim_basi_degil"] += 1
                    continue
                ithal[f"{r}>{hr}"] += 1
                if (hr, hd.birim) not in erisilen:
                    erisilen.add((hr, hd.birim))
                    kuyruk.append((hr, hd.birim))
        self._erisim = (erisilen, ithal)
        return self._erisim

    def tanim_indeksi(self) -> dict[tuple[str, str], list[str]]:
        """(tür, ad) -> erişilen birimlerdeki tam tanımların konumları."""
        if self._tanimlar is not None:
            return self._tanimlar
        erisilen, _ = self.erisim()
        indeks: dict[tuple[str, str], list[str]] = defaultdict(list)
        for r, b in sorted(erisilen):
            dosya = self.dosyalar[r]
            for o in dosya.birimler[b]["dieler"]:
                d = dosya.dieler[o]
                tur = KUME_TURLERI.get(d.etiket)
                if tur is None or deger(d, "DW_AT_declaration"):
                    continue
                try:
                    ad = self.dizgi(r, d, "DW_AT_name")
                except CozumHatasi:
                    continue
                if ad:
                    indeks[(tur, ad)].append(konum(r, o))
        self._tanimlar = dict(indeks)
        return self._tanimlar

    def birim_ozeti(self) -> dict[str, Any]:
        erisilen, ithal = self.erisim()
        ana = self.dosyalar[ANA]
        ek = self.dosyalar.get(EK)
        tur = Counter(b["etiket"] for b in ana.birimler.values())
        return {
            "ana_derleme": tur.get("DW_TAG_compile_unit", 0),
            "ana_kismi": tur.get("DW_TAG_partial_unit", 0),
            "ek_toplam": len(ek.birimler) if ek is not None else 0,
            "ek_erisilen": sum(1 for r, _ in erisilen if r == EK),
            "ithal": dict(sorted(ithal.items())),
        }

    # --- fonksiyonlar
    def _cocuklar(self, rol: str, d: Die, etiket: str) -> list[Die]:
        dosya = self.dosyalar[rol]
        return [dosya.dieler[c] for c in d.cocuklar if dosya.dieler[c].etiket == etiket]

    def yalniz_ranges_govdeler(self) -> int:
        """``DW_AT_low_pc`` yerine yalnız ``DW_AT_ranges`` taşıyan gövdeler (çıkarılmaz, sayılır)."""
        return sum(1 for d in self.dosyalar[ANA].dieler.values()
                   if d.etiket == "DW_TAG_subprogram" and "DW_AT_ranges" in d.oz
                   and "DW_AT_low_pc" not in d.oz)

    def fonksiyonlar(self) -> list[dict[str, Any]]:
        ana = self.dosyalar[ANA]
        liste = [self.fonksiyon(d) for _, d in sorted(ana.dieler.items())
                 if d.etiket == "DW_TAG_subprogram" and "DW_AT_low_pc" in d.oz]
        liste.sort(key=lambda f: (int(f["adres"], 16), f["konum"]))
        return liste

    def fonksiyon(self, d: Die) -> dict[str, Any]:
        ana = self.dosyalar[ANA]
        adres = int(deger(d, "DW_AT_low_pc") or 0)
        kayit: dict[str, Any] = {"ad": None, "adres": f"0x{adres:x}", "boyut": None,
                                 "konum": konum(ANA, d.ofset)}
        yuksek = d.oz.get("DW_AT_high_pc")
        if yuksek is not None and isinstance(yuksek[2], int):
            kayit["boyut"] = yuksek[2] - adres if yuksek[0] == "DW_FORM_addr" else yuksek[2]
        try:
            kayit["ad"], kayit["ad_kaynagi"] = self.ad_bul(ANA, d)
        except CozumHatasi as h:
            kayit["ad_kaynagi"] = {"yol": "hata", "neden": h.neden}
        try:
            zincir = list(self.koken_zinciri(ANA, d))
        except CozumHatasi as h:
            zincir = [(ANA, d, "kendi")]
            kayit["koken_hatasi"] = h.neden
        kayit["birim"] = self._fonksiyon_birimi(zincir)
        adlar = sorted(set(ana.semboller.get(adres, [])))
        kayit["semboller"] = adlar
        sonekler = klon_sonekleri(adlar)
        ao = "DW_AT_abstract_origin" in d.oz
        inline = None
        if len(zincir) > 1:
            v = deger(zincir[1][1], "DW_AT_inline")
            inline = INL_ADLARI.get(v, v) if v is not None else None
        kayit["klon"] = {"sonekler": sonekler, "abstract_origin": ao, "origin_inline": inline,
                         "bayrak": bool(sonekler) or ao}
        kayit["harici"] = bool(self.koken_degeri(ANA, d, "DW_AT_external"))
        kayit["prototipli"] = bool(self.koken_degeri(ANA, d, "DW_AT_prototyped"))
        kayit["degisken_arguman"] = any(self._cocuklar(r, k, "DW_TAG_unspecified_parameters")
                                        for r, k, _ in zincir)
        kayit["parametreler"], kayit["parametre_kaynagi"] = self.parametreler(d, zincir)
        kayit["soyut_parametre_sayisi"] = (
            len(self._cocuklar(zincir[1][0], zincir[1][1], "DW_TAG_formal_parameter"))
            if len(zincir) > 1 else None)
        return kayit

    def _fonksiyon_birimi(self, zincir: list[tuple[str, Die, str]]) -> Optional[str]:
        """En derin kökenden başlayarak adı olan ilk derleme biriminin adı.

        LTO'da somut gövde ``<artificial>`` birimindedir; kaynak dosya kökenin birimindedir.
        """
        yedek = None
        for r, k, _ in reversed(zincir):
            dosya = self.dosyalar[r]
            b = dosya.birimler.get(k.birim)
            if b is None or b["etiket"] != "DW_TAG_compile_unit":
                continue
            ad = self.birim_adi(r, k.birim)
            if ad and ad != "<artificial>":
                return ad
            yedek = yedek or ad
        return yedek

    def parametreler(self, d: Die, zincir: list[tuple[str, Die, str]]
                     ) -> tuple[list[dict[str, Any]], str]:
        somut = [(ANA, p) for p in self._cocuklar(ANA, d, "DW_TAG_formal_parameter")]
        soyut: list[tuple[str, Die]] = []
        if len(zincir) > 1:
            kr, kd, _ = zincir[1]
            soyut = [(kr, p) for p in self._cocuklar(kr, kd, "DW_TAG_formal_parameter")]
        bildirim_sirasi = {(r, p.ofset): i for i, (r, p) in enumerate(soyut, 1)}
        kaynak = "somut"
        ogeler = somut
        if not somut and soyut:
            ogeler, kaynak = soyut, "soyut"
        sonuc: list[dict[str, Any]] = []
        gorulen_koken: set[tuple[str, int]] = set()
        for i, (r, p) in enumerate(ogeler, 1):
            kayit: dict[str, Any] = {"sira": None, "somut_sira": i if kaynak == "somut" else None,
                                     "konum": konum(r, p.ofset), "tekrar": False,
                                     "yer": yer_bilgisi(p)}
            if kaynak == "soyut" or "DW_AT_abstract_origin" not in p.oz:
                kayit["sira"] = i
            else:
                try:
                    hr, hd = self.hedef(r, p, "DW_AT_abstract_origin")
                    kayit["soyut_konum"] = konum(hr, hd.ofset)
                    kayit["sira"] = bildirim_sirasi.get((hr, hd.ofset))
                    # Aynı bildirim parametresine ikinci (ve sonraki) kez bağlanan DIE. GCC'nin
                    # LTO/IPA-CP çıktısında görülür (sabit değer betimi ya da konumsuz yer tutucu).
                    # Tip için zararsız (aynı köken, aynı tip); hangisinin ABI parametresi olduğunu
                    # SÖYLEMEZ: bunu ``yer`` ve T0b'nin konum çözümlemesi belirler.
                    kayit["tekrar"] = (hr, hd.ofset) in gorulen_koken
                    gorulen_koken.add((hr, hd.ofset))
                except CozumHatasi as h:
                    kayit["koken_hatasi"] = h.neden
            try:
                kayit["ad"], kayit["ad_kaynagi"] = self.ad_bul(r, p)
            except CozumHatasi as h:
                kayit["ad"], kayit["ad_kaynagi"] = None, {"yol": "hata", "neden": h.neden}
            kayit["tip_kaynagi"], kayit["tip"] = self.parametre_tipi(r, p)
            sonuc.append(kayit)
        return sonuc, kaynak

    # --- dosyanın bütün formal_parameter DIE'leri
    def _ust_turu(self, d: Die) -> str:
        if d.ust is None:
            return "birim"
        u = self.dosyalar[ANA].dieler[d.ust]
        if u.etiket == "DW_TAG_subprogram":
            if "DW_AT_low_pc" in u.oz or "DW_AT_ranges" in u.oz:
                return "somut"
            return "bildirim" if "DW_AT_declaration" in u.oz else "soyut"
        if u.etiket == "DW_TAG_inlined_subroutine":
            return "satir_ici"
        if u.etiket == "DW_TAG_subroutine_type":
            return "fonk_tipi"
        return "diger"

    def tum_parametre_taramasi(self) -> dict[str, Any]:
        toplam: Counter = Counter()
        cozulen: Counter = Counter()
        nedenler: Counter = Counter()
        kendi_bicim: Counter = Counter()
        for d in self.dosyalar[ANA].dieler.values():
            if d.etiket != "DW_TAG_formal_parameter":
                continue
            if "DW_AT_type" in d.oz:
                kendi_bicim[d.oz["DW_AT_type"][0]] += 1
            tur = self._ust_turu(d)
            _, tip = self.parametre_tipi(ANA, d)
            toplam[tur] += 1
            if tip["cozuldu"]:
                cozulen[tur] += 1
            else:
                nedenler[tip["neden"]] += 1
        return {"toplam": sum(toplam.values()), "cozulen": sum(cozulen.values()),
                "ust_turune_gore": {t: {"toplam": toplam[t], "cozulen": cozulen[t]}
                                    for t in sorted(toplam)},
                "nedenler": dict(sorted(nedenler.items())),
                "kendi_tip_bicimi": dict(sorted(kendi_bicim.items()))}

    # --- yapı tablosu
    def yapi_kaydi(self, k: str) -> dict[str, Any]:
        r, o = konum_coz(k)
        d = self.die(r, o)
        tur = KUME_TURLERI[d.etiket]
        ad = self.dizgi(r, d, "DW_AT_name")
        kayit: dict[str, Any] = {
            "tur": tur, "ad": ad, "kimlik": f"{tur} {ad}" if ad else f"{tur} <anon@{k}>",
            "bildirim": bool(deger(d, "DW_AT_declaration")), "boyut": deger(d, "DW_AT_byte_size"),
            "uyeler": None,
        }
        if not kayit["bildirim"]:
            uyeler = []
            for c in self._cocuklar(r, d, "DW_TAG_member"):
                u: dict[str, Any] = {"ad": self.dizgi(r, c, "DW_AT_name"),
                                     "ofset": uye_ofseti(c, tur)}
                bit = deger(c, "DW_AT_bit_size")
                if bit is not None:
                    u["bit_boyutu"] = bit
                    u["bit_ofseti"] = (deger(c, "DW_AT_data_bit_offset")
                                       if "DW_AT_data_bit_offset" in c.oz
                                       else deger(c, "DW_AT_bit_offset"))
                _, tip = self.parametre_tipi(r, c)
                u["kanonik"] = tip.get("kanonik")
                u["sinif"] = tip.get("sinif")
                if not tip["cozuldu"]:
                    u["neden"] = tip["neden"]
                uyeler.append(u)
            kayit["uyeler"] = uyeler
        return kayit

    def yapilar(self, fonksiyonlar: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        gerekli: set[str] = set()
        for f in fonksiyonlar:
            for p in f["parametreler"]:
                kok = p["tip"].get("kok") if p["tip"]["cozuldu"] else None
                if kok and kok["tur"] in YAPI_TURLERI:
                    gerekli.add(kok["konum"])
        indeks = self.tanim_indeksi()
        tablo: dict[str, dict[str, Any]] = {}
        bekleyen = sorted(gerekli, key=_konum_anahtari)
        while bekleyen:
            k = bekleyen.pop(0)
            if k in tablo:
                continue
            try:
                kayit = self.yapi_kaydi(k)
            except CozumHatasi as h:
                tablo[k] = {"hata": h.neden}
                continue
            if kayit["ad"]:
                kayit["tanimlar"] = list(indeks.get((kayit["tur"], kayit["ad"]), []))
                bekleyen.extend(t for t in kayit["tanimlar"] if t not in tablo)
            tablo[k] = kayit
        return dict(sorted(tablo.items(), key=lambda kv: _konum_anahtari(kv[0])))


# ---------------------------------------------------------------------------
# Belge (ikili başına JSON)
# ---------------------------------------------------------------------------

def _git_head() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent,
                              capture_output=True, text=True, timeout=10,
                              check=False).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def arac_kunyesi() -> dict[str, Any]:
    import elftools
    betik = Path(__file__).resolve()
    return {"betik": "scripts/measurement/dwarf_tip.py", "betik_sha256": sha256_dosya(betik),
            "git_head": _git_head(), "pyelftools": getattr(elftools, "__version__", None),
            "python": platform.python_version()}


def dosya_kunyesi(dosya: Optional[DwarfDosyasi]) -> Optional[dict[str, Any]]:
    if dosya is None:
        return None
    return {"yol": str(dosya.yol) if dosya.yol else None,
            "sha256": sha256_dosya(dosya.yol) if dosya.yol else None,
            "build_id": dosya.build_id}


def parametre_sayimlari(fonksiyonlar: list[dict[str, Any]]) -> dict[str, Any]:
    sayac: Counter = Counter()
    nedenler: Counter = Counter()
    siniflar: Counter = Counter()
    bicimler: Counter = Counter()
    klon: Counter = Counter()
    niteleyici: Counter = Counter()
    yer: Counter = Counter()
    for f in fonksiyonlar:
        sayac["fonksiyon"] += 1
        asil = [p for p in f["parametreler"] if not p.get("tekrar")]
        if len(asil) < len(f["parametreler"]):
            sayac["tekrarli_fonksiyon"] += 1
            sayac["tekrar_parametre"] += len(f["parametreler"]) - len(asil)
        if any(p.get("sira") != p.get("somut_sira") for p in asil
               if p.get("somut_sira") is not None):
            sayac["sira_farkli_fonksiyon"] += 1
        soyut_n = f.get("soyut_parametre_sayisi")
        if soyut_n is not None and len({p.get("sira") for p in asil} - {None}) < soyut_n:
            sayac["eksik_parametreli_fonksiyon"] += 1
        k = f["klon"]
        klon["sonekli"] += bool(k["sonekler"])
        klon["abstract_origin"] += bool(k["abstract_origin"])
        klon["abstract_origin_inline_kokenli"] += bool(k["abstract_origin"] and k["origin_inline"])
        klon["bayrak"] += bool(k["bayrak"])
        for p in f["parametreler"]:
            sayac["parametre"] += 1
            yer[str(p.get("yer"))] += 1
            if p.get("ad") is None:
                sayac["adsiz_parametre"] += 1
            if p.get("sira") is None:
                sayac["sira_belirsiz"] += 1
            tk = p["tip_kaynagi"]
            if tk.get("bicim"):
                bicimler[tk["bicim"]] += 1
            if str(tk.get("hedef", "")).startswith(EK + ":"):
                sayac["tipi_ek_dosyada"] += 1
            if p["tip"]["cozuldu"]:
                sayac["tip_cozulen"] += 1
                siniflar[p["tip"]["sinif"]] += 1
                niteleyici.update(set(p["tip"]["niteleyiciler"]))
            else:
                nedenler[p["tip"]["neden"]] += 1
    return {"fonksiyon": sayac["fonksiyon"], "parametre": sayac["parametre"],
            "tip_cozulen": sayac["tip_cozulen"], "tipi_ek_dosyada": sayac["tipi_ek_dosyada"],
            "adsiz_parametre": sayac["adsiz_parametre"], "sira_belirsiz": sayac["sira_belirsiz"],
            "sira_farkli_fonksiyon": sayac["sira_farkli_fonksiyon"],
            "eksik_parametreli_fonksiyon": sayac["eksik_parametreli_fonksiyon"],
            "tekrarli_fonksiyon": sayac["tekrarli_fonksiyon"],
            "tekrar_parametre": sayac["tekrar_parametre"],
            "niteleyici": dict(sorted(niteleyici.items())),
            "yer": dict(sorted(yer.items())),
            "cozulemeyen_nedenleri": dict(sorted(nedenler.items())),
            "sinif": {s: siniflar.get(s, 0) for s in SINIFLAR},
            "tip_basvuru_bicimi": dict(sorted(bicimler.items())),
            "klon": {a: klon.get(a, 0) for a in ("sonekli", "abstract_origin",
                                                  "abstract_origin_inline_kokenli", "bayrak")}}


def belge_uret(ana: DwarfDosyasi, ek: Optional[DwarfDosyasi], *, ek_yontemi: str,
               ek_uymayan: Optional[list[str]] = None, ikili: Optional[Path] = None,
               ikili_build_id: Optional[str] = None, arac: Optional[dict[str, Any]] = None,
               ikili_esleri: Optional[list[Path]] = None) -> dict[str, Any]:
    coz = Cozucu(ana, ek)
    fonksiyonlar = coz.fonksiyonlar()
    altlink = None
    if ana.altlink is not None:
        altlink = {"yol": ana.altlink[0], "build_id": ana.altlink[1]}
    ikili_kunye = None
    if ikili is not None:
        ikili_kunye = {"yol": str(ikili), "ad": ikili.name, "sha256": sha256_dosya(ikili),
                       "build_id": ikili_build_id, "build_id_uyumu": ikili_build_id == ana.build_id,
                       "ayni_build_id_ikililer": [str(e) for e in ikili_esleri or []]}
    sayimlar = parametre_sayimlari(fonksiyonlar)
    sayimlar["yalniz_ranges_govde"] = coz.yalniz_ranges_govdeler()
    sayimlar["tum_formal_parameter"] = coz.tum_parametre_taramasi()
    return {
        "sema": SEMA,
        "arac": arac if arac is not None else arac_kunyesi(),
        "girdi": {"ana": dosya_kunyesi(ana), "ek": dosya_kunyesi(ek), "ek_yontemi": ek_yontemi,
                  "ek_build_id_uymayan_adaylar": ek_uymayan or [], "debugaltlink": altlink,
                  "ikili": ikili_kunye},
        "birimler": coz.birim_ozeti(),
        "sayimlar": sayimlar,
        "fonksiyonlar": fonksiyonlar,
        "yapilar": coz.yapilar(fonksiyonlar),
    }


def ek_yukle(ana: DwarfDosyasi, ek_yol: Optional[Path], onbellek: Optional[dict] = None
             ) -> tuple[Optional[DwarfDosyasi], str, list[str]]:
    """Ana dosyanın ek dosyası: elle verilen ya da .gnu_debugaltlink'ten bulunan."""
    if ek_yol is not None:
        if ana.altlink is not None and elf_build_id(ek_yol) != ana.altlink[1]:
            raise ValueError(f"{ek_yol}: build-id .gnu_debugaltlink'tekiyle aynı değil "
                             f"({ana.altlink[1]})")
        yol, yontem, uymayan = ek_yol, "elle", []
    else:
        if ana.yol is None:
            return None, "altlink_yok" if ana.altlink is None else "bulunamadi", []
        yol, yontem, uymayan = ek_dosyasini_bul(ana.yol, ana.altlink)
        if yol is None:
            return None, yontem, uymayan
    anahtar = str(Path(yol).resolve())
    if onbellek is not None and anahtar in onbellek:
        return onbellek[anahtar], yontem, uymayan
    ek = dosya_yukle(Path(yol), EK)
    if onbellek is not None:
        onbellek[anahtar] = ek
    return ek, yontem, uymayan


def cikar(debug: Path, *, ek_yol: Optional[Path] = None, ikili: Optional[Path] = None
          ) -> dict[str, Any]:
    ana = dosya_yukle(debug, ANA)
    ek, yontem, uymayan = ek_yukle(ana, ek_yol)
    ikili_bid = elf_build_id(ikili) if ikili is not None else None
    return belge_uret(ana, ek, ek_yontemi=yontem, ek_uymayan=uymayan, ikili=ikili,
                      ikili_build_id=ikili_bid)


def _yaz_json(yol: Path, veri: Any) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(veri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def ikili_haritasi(kok: Path) -> dict[str, list[Path]]:
    """build-id -> o build-id'li ELF ikililer, ada göre sıralı (sembolik bağlar atlanır).

    Aynı ikilinin kopyaları (ör. redis-check-aof ile redis-check-rdb) aynı listeye düşer."""
    harita: dict[str, list[Path]] = defaultdict(list)
    for yol in sorted(kok.rglob("*")):
        if yol.is_symlink() or not yol.is_file():
            continue
        bid = elf_build_id(yol)
        if bid:
            harita[bid].append(yol)
    return dict(harita)


def _guvenli_ad(ad: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", ad) or "_"


def toplu(kok: Path, cikti: Path, *, ikili_kok: Optional[Path] = None,
          ek_yol: Optional[Path] = None) -> dict[str, Any]:
    """Bir dbgsym kökündeki (``…/usr/lib/debug``) bütün ``.build-id/*/*.debug`` dosyaları."""
    debuglar = sorted(kok.glob(".build-id/*/*.debug"))
    if not debuglar:
        raise FileNotFoundError(f"{kok}: .build-id/*/*.debug yok")
    harita = ikili_haritasi(ikili_kok) if ikili_kok is not None else {}
    arac = arac_kunyesi()
    ek_onbellek: dict[str, DwarfDosyasi] = {}
    kullanilan: set[str] = set()
    satirlar = []
    for debug in debuglar:
        ana = dosya_yukle(debug, ANA)
        ek, yontem, uymayan = ek_yukle(ana, ek_yol, ek_onbellek)
        ikililer = harita.get(ana.build_id or "", [])
        ikili = ikililer[0] if ikililer else None
        belge = belge_uret(ana, ek, ek_yontemi=yontem, ek_uymayan=uymayan, ikili=ikili,
                           ikili_build_id=ana.build_id if ikili is not None else None, arac=arac,
                           ikili_esleri=ikililer[1:])
        ad = _guvenli_ad(ikili.name if ikili is not None else (ana.build_id or debug.stem))
        if ad in kullanilan:
            ad = f"{ad}-{(ana.build_id or debug.stem)[:8]}"
        kullanilan.add(ad)
        _yaz_json(cikti / f"{ad}.json", belge)
        s = belge["sayimlar"]
        satirlar.append({"debug": str(debug), "build_id": ana.build_id,
                         "ikili": str(ikili) if ikili is not None else None,
                         "cikti": f"{ad}.json", "ek_yontemi": yontem,
                         "fonksiyon": s["fonksiyon"], "parametre": s["parametre"],
                         "tip_cozulen": s["tip_cozulen"]})
    indeks = {"sema": TOPLU_SEMA, "arac": arac, "kok": str(kok),
              "ikili_kok": str(ikili_kok) if ikili_kok else None,
              "ek_dosyalari": sorted(ek_onbellek), "dosyalar": satirlar}
    _yaz_json(cikti / "toplu.json", indeks)
    return indeks


# ---------------------------------------------------------------------------
# Özet
# ---------------------------------------------------------------------------

def belgeleri_topla(girdiler: Iterable[Path]) -> list[tuple[str, Path, dict[str, Any]]]:
    """(grup, yol, belge). Dizin verilirse içindeki SEMA'lı JSON'lar; grup = dizin adı."""
    sonuc = []
    for g in girdiler:
        if g.is_dir():
            for j in sorted(g.glob("*.json")):
                b = json.loads(j.read_text(encoding="utf-8"))
                if b.get("sema") == SEMA:
                    sonuc.append((g.name, j, b))
        else:
            b = json.loads(g.read_text(encoding="utf-8"))
            if b.get("sema") != SEMA:
                raise ValueError(f"{g}: şema {b.get('sema')!r}, beklenen {SEMA!r}")
            sonuc.append((g.parent.name, g, b))
    return sonuc


_ANONIM_KIMLIK_RE = re.compile(r"<anon@[^>]+>")


def yerlesim_imzasi(y: dict[str, Any]) -> tuple:
    """Yapısal yerleşim imzası: tür, boyut, (üye adı, ofset, kanonik tip). Üye tiplerindeki
    anonim kimlikler (``<anon@ek:0x..>``) ``<anon>``'a indirgenir; aynı anonim tipin iki
    kopyası farklı ofsetlerde durur ve yerleşimi farklı göstermemelidir."""
    return (y["tur"], y["boyut"],
            tuple((u["ad"], u["ofset"], _ANONIM_KIMLIK_RE.sub("<anon>", u["kanonik"] or ""),
                   u.get("bit_boyutu"), u.get("bit_ofseti")) for u in y["uyeler"]))


def kimlik_denetimi(yapilar: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """K1'in "aynı tip" kimliği için yapı tablosundan üç sayım (yalnız tam tanımlar).

    - ``ayni_adli_farkli_yerlesim``: aynı adlı, yapısal olarak farklı tanımlar (ad kimliği
      bunları birleştirir: kesinlik riski);
    - ``ayni_adli_kopyalar``: aynı adlı, yapısal olarak aynı, ayrı konumlu tanımlar (ad kimliği
      için zararsız);
    - ``ayni_yerlesimli_anonim_gruplar``: yapısal olarak aynı, ayrı konumlu anonim tanımlar
      (ofset kimliği bunları ayırır: duyarlılık riski).
    """
    adli: dict[str, dict[tuple, list[str]]] = defaultdict(lambda: defaultdict(list))
    anonim: dict[tuple, list[str]] = defaultdict(list)
    for k, y in yapilar.items():
        if y.get("hata") or y.get("bildirim") or y.get("uyeler") is None:
            continue
        imza = yerlesim_imzasi(y)
        if y["ad"]:
            adli[y["kimlik"]][imza].append(k)
        else:
            anonim[imza].append(k)
    return {"ayni_adli_farkli_yerlesim": sorted(a for a, s in adli.items() if len(s) > 1),
            "ayni_adli_kopyalar": sorted(a for a, s in adli.items()
                                         if any(len(v) > 1 for v in s.values())),
            "ayni_yerlesimli_anonim_gruplar": sorted(sorted(v) for v in anonim.values()
                                                     if len(v) > 1)}


def _pay(k: int, n: int) -> Optional[float]:
    return round(k / n, 6) if n else None


def _topla(satirlar: list[dict[str, Any]]) -> dict[str, Any]:
    t: dict[str, Any] = {"dosya": len(satirlar)}
    for a in ("fonksiyon", "parametre", "tip_cozulen", "tipi_ek_dosyada", "adsiz_parametre",
              "sira_belirsiz", "sira_farkli_fonksiyon", "eksik_parametreli_fonksiyon",
              "tekrarli_fonksiyon", "tekrar_parametre", "yalniz_ranges_govde", "tum_fp_toplam",
              "tum_fp_cozulen"):
        t[a] = sum(s[a] for s in satirlar)
    for a in ("cozulemeyen_nedenleri", "sinif", "tip_basvuru_bicimi", "klon", "niteleyici",
              "yer", "tum_fp_kendi_tip_bicimi"):
        c: Counter = Counter()
        for s in satirlar:
            c.update(s[a])
        t[a] = dict(sorted(c.items())) if a != "sinif" else {x: c.get(x, 0) for x in SINIFLAR}
    t["ayni_adli_farkli_yerlesim"] = sum(len(s["kimlik"]["ayni_adli_farkli_yerlesim"])
                                         for s in satirlar)
    t["ayni_adli_kopyalar"] = sum(len(s["kimlik"]["ayni_adli_kopyalar"]) for s in satirlar)
    t["ayni_yerlesimli_anonim_gruplar"] = sum(len(s["kimlik"]["ayni_yerlesimli_anonim_gruplar"])
                                              for s in satirlar)
    t["cozulen_payi"] = _pay(t["tip_cozulen"], t["parametre"])
    t["ek_dosya_payi"] = _pay(t["tipi_ek_dosyada"], t["parametre"])
    t["tum_fp_cozulen_payi"] = _pay(t["tum_fp_cozulen"], t["tum_fp_toplam"])
    kendi = t["tum_fp_kendi_tip_bicimi"]
    t["tum_fp_kendi_tipi_ref_alt_payi"] = _pay(
        sum(v for b, v in kendi.items() if b in EK_BASVURU), sum(kendi.values()))
    cozulen = t["tip_cozulen"]
    t["sinif_payi"] = {x: _pay(v, cozulen) for x, v in t["sinif"].items()}
    t["klon_payi"] = {x: _pay(v, t["fonksiyon"]) for x, v in t["klon"].items()}
    return t


def ozetle(belgeler: list[tuple[str, Path, dict[str, Any]]]) -> dict[str, Any]:
    satirlar = []
    for grup, yol, b in belgeler:
        s = b["sayimlar"]
        ikili = (b["girdi"].get("ikili") or {}).get("ad")
        tum = s["tum_formal_parameter"]
        satirlar.append({
            "grup": grup, "dosya": yol.name, "ikili": ikili, "ek": b["girdi"]["ek"] is not None,
            "fonksiyon": s["fonksiyon"], "parametre": s["parametre"],
            "tip_cozulen": s["tip_cozulen"], "tipi_ek_dosyada": s["tipi_ek_dosyada"],
            "adsiz_parametre": s["adsiz_parametre"], "sira_belirsiz": s["sira_belirsiz"],
            "sira_farkli_fonksiyon": s["sira_farkli_fonksiyon"],
            "eksik_parametreli_fonksiyon": s["eksik_parametreli_fonksiyon"],
            "tekrarli_fonksiyon": s["tekrarli_fonksiyon"], "tekrar_parametre": s["tekrar_parametre"],
            "yalniz_ranges_govde": s["yalniz_ranges_govde"], "niteleyici": s["niteleyici"],
            "yer": s["yer"],
            "tum_fp_kendi_tip_bicimi": tum["kendi_tip_bicimi"],
            "cozulemeyen_nedenleri": s["cozulemeyen_nedenleri"], "sinif": s["sinif"],
            "tip_basvuru_bicimi": s["tip_basvuru_bicimi"], "klon": s["klon"],
            "tum_fp_toplam": tum["toplam"], "tum_fp_cozulen": tum["cozulen"],
            "kimlik": kimlik_denetimi(b.get("yapilar", {})),
        })
    gruplar = {}
    for g in sorted({s["grup"] for s in satirlar}):
        gruplar[g] = _topla([s for s in satirlar if s["grup"] == g])
    girdi_betikleri = sorted({str((b.get("arac") or {}).get("betik_sha256")) for _, _, b in belgeler})
    return {"sema": OZET_SEMA, "arac": arac_kunyesi(), "girdi_betik_sha256": girdi_betikleri,
            "dosyalar": satirlar, "gruplar": gruplar, "toplam": _topla(satirlar)}


def _yuzde(p: Optional[float]) -> str:
    return "—" if p is None else f"%{100 * p:.2f}"


def ozet_yazdir(oz: dict[str, Any], *, dosya_satirlari: bool = False) -> None:
    if dosya_satirlari:
        for s in oz["dosyalar"]:
            print(f"  {s['grup']}/{s['dosya']}: fonk={s['fonksiyon']} param={s['parametre']} "
                  f"çözülen={s['tip_cozulen']} ek'te={s['tipi_ek_dosyada']} "
                  f"nedenler={s['cozulemeyen_nedenleri'] or '-'}")
    bloklar = list(oz["gruplar"].items()) + [("TOPLAM", oz["toplam"])]
    for ad, t in bloklar:
        print(f"{ad}: dosya={t['dosya']} fonksiyon={t['fonksiyon']} parametre={t['parametre']} "
              f"çözülen={t['tip_cozulen']} ({_yuzde(t['cozulen_payi'])}) "
              f"tipi ek dosyada={t['tipi_ek_dosyada']} ({_yuzde(t['ek_dosya_payi'])}) "
              f"tüm formal_parameter={t['tum_fp_cozulen']}/{t['tum_fp_toplam']} "
              f"({_yuzde(t['tum_fp_cozulen_payi'])})")
        if t["cozulemeyen_nedenleri"]:
            print(f"    çözülemeyen nedenleri: {t['cozulemeyen_nedenleri']}")
        print("    sınıf: " + ", ".join(f"{x}={t['sinif'][x]} ({_yuzde(t['sinif_payi'][x])})"
                                         for x in SINIFLAR))
        print("    klon (fonksiyon payı): " + ", ".join(
            f"{x}={t['klon'].get(x, 0)} ({_yuzde(t['klon_payi'].get(x))})" for x in
            ("sonekli", "abstract_origin", "abstract_origin_inline_kokenli", "bayrak")))
        print(f"    DIE'nin kendi DW_AT_type'ı ref_alt: {_yuzde(t['tum_fp_kendi_tipi_ref_alt_payi'])} "
              f"| yalnız ranges'lı gövde={t['yalniz_ranges_govde']} "
              f"| sırası değişen fonksiyon={t['sira_farkli_fonksiyon']} "
              f"| parametresi düşen fonksiyon={t['eksik_parametreli_fonksiyon']} "
              f"| tekrar parametre={t['tekrar_parametre']} ({t['tekrarli_fonksiyon']} fonksiyon) "
              f"| niteleyici={t['niteleyici']} | parametre konum bilgisi={t['yer']}")
        print(f"    adsız parametre={t['adsiz_parametre']} sıra belirsiz={t['sira_belirsiz']} "
              f"aynı adlı farklı yerleşim={t['ayni_adli_farkli_yerlesim']} "
              f"aynı adlı kopya={t['ayni_adli_kopyalar']} "
              f"aynı yerleşimli anonim grup={t['ayni_yerlesimli_anonim_gruplar']}")


# ---------------------------------------------------------------------------
# Çapraz denetim: Apple dwarfdump (llvm-dwarfdump) ile, bu betiğin çözücüsü kullanılmadan
# ---------------------------------------------------------------------------

_DD_DIE_RE = re.compile(r"^0x([0-9a-fA-F]+):\s+(DW_TAG_\w+)")
_DD_OZ_RE = re.compile(r"^\s+(DW_AT_\w+)\s+\[(DW_FORM_\w+)\]\s+\((.*)\)\s*$")
_DD_ALT_RE = re.compile(r"^<alt 0x([0-9a-fA-F]+)>")
_DD_CU_RE = re.compile(r"^cu \+ 0x[0-9a-fA-F]+ => \{0x([0-9a-fA-F]+)\}")
_DD_MUTLAK_RE = re.compile(r"^0x([0-9a-fA-F]+)")
_DD_STRP_RE = re.compile(r'^\s*\.debug(?:_line)?_str\[0x[0-9a-fA-F]+\] = "(.*)"$')
_DD_STRX_RE = re.compile(r'^\s*indexed \([0-9a-fA-F]+\) string = "(.*)"$')
_DD_ALT_STR_RE = re.compile(r"^alt indirect string, offset: 0x([0-9a-fA-F]+)$")
_DD_DUZ_RE = re.compile(r'^"(.*)"$')
_DD_STR_SATIR_RE = re.compile(r'^0x([0-9a-fA-F]+): "(.*)"$')
_DD_ZINCIR = frozenset({"DW_TAG_typedef", "DW_TAG_pointer_type", "DW_TAG_const_type",
                        "DW_TAG_volatile_type", "DW_TAG_restrict_type", "DW_TAG_atomic_type"})


def dd_ayristir(metin: str) -> Optional[dict[str, Any]]:
    """``dwarfdump -v -F --debug-info=<ofset>`` çıktısındaki ilk DIE: ofset, etiket, öznitelikler."""
    die: Optional[dict[str, Any]] = None
    for satir in metin.splitlines():
        m = _DD_DIE_RE.match(satir)
        if m:
            if die is not None:
                break
            die = {"ofset": int(m.group(1), 16), "etiket": m.group(2), "oz": {}}
            continue
        if die is not None:
            m = _DD_OZ_RE.match(satir)
            if m:
                die["oz"][m.group(1)] = (m.group(2), m.group(3))
    return die


def dd_basvuru(metin: str) -> Optional[tuple[str, int]]:
    """dwarfdump başvuru değeri -> ('ek' | 'ayni', ofset)."""
    for desen, tur in ((_DD_ALT_RE, "ek"), (_DD_CU_RE, "ayni"), (_DD_MUTLAK_RE, "ayni")):
        m = desen.match(metin)
        if m:
            return tur, int(m.group(1), 16)
    return None


def dd_dizgi(metin: str) -> Optional[tuple[str, Any]]:
    """dwarfdump dizgi değeri -> ('dizgi', metin) | ('ek_ofset', ofset)."""
    m = _DD_ALT_STR_RE.match(metin)
    if m:
        return "ek_ofset", int(m.group(1), 16)
    for desen in (_DD_STRP_RE, _DD_STRX_RE, _DD_DUZ_RE):
        m = desen.match(metin)
        if m:
            return "dizgi", m.group(1)
    return None


def dd_str_tablosu(metin: str) -> list[tuple[int, str]]:
    tablo = []
    for satir in metin.splitlines():
        m = _DD_STR_SATIR_RE.match(satir)
        if m:
            tablo.append((int(m.group(1), 16), m.group(2)))
    tablo.sort()
    return tablo


def dd_ofsetteki_dizgi(tablo: list[tuple[int, str]], ofset: int) -> Optional[str]:
    """Ofset bir dizginin ortasına da düşebilir (bağlayıcının kuyruk paylaşımı)."""
    i = bisect_right(tablo, (ofset, "\U0010ffff")) - 1
    if i < 0:
        return None
    bas, s = tablo[i]
    if ofset - bas > len(s.encode("utf-8")):
        return None
    return s.encode("utf-8")[ofset - bas:].decode("utf-8", "replace")


class DwarfdumpOkuyucu:
    def __init__(self, yollar: dict[str, Optional[str]], dwarfdump: str = DWARFDUMP_YOLU) -> None:
        self.yollar = yollar
        self.dwarfdump = dwarfdump
        self._dieler: dict[tuple[str, int], Optional[dict[str, Any]]] = {}
        self._str: Optional[list[tuple[int, str]]] = None
        self.cagri = 0

    def _calistir(self, args: list[str]) -> str:
        self.cagri += 1
        return subprocess.run([self.dwarfdump, *args], capture_output=True, text=True,
                              timeout=ARAC_ZAMAN_ASIMI_S, check=False).stdout

    def die(self, rol: str, ofset: int) -> Optional[dict[str, Any]]:
        anahtar = (rol, ofset)
        if anahtar not in self._dieler:
            yol = self.yollar.get(rol)
            if yol is None:
                return None
            d = dd_ayristir(self._calistir(["-v", "-F", f"--debug-info=0x{ofset:x}", yol]))
            self._dieler[anahtar] = d if d is not None and d["ofset"] == ofset else None
        return self._dieler[anahtar]

    def ek_dizgisi(self, ofset: int) -> Optional[str]:
        if self._str is None:
            yol = self.yollar.get(EK)
            self._str = dd_str_tablosu(self._calistir(["--debug-str", yol])) if yol else []
        return dd_ofsetteki_dizgi(self._str, ofset)

    def hedef(self, rol: str, metin: str) -> tuple[str, int]:
        b = dd_basvuru(metin)
        if b is None:
            raise ValueError(f"başvuru okunamadı: {metin!r}")
        tur, o = b
        if tur == "ek":
            if rol != ANA:
                raise ValueError("ek dosya içinden ek başvurusu")
            return EK, o
        return rol, o

    def ad(self, die: dict[str, Any]) -> tuple[Optional[str], Optional[int]]:
        oz = die["oz"].get("DW_AT_name")
        if oz is None:
            return None, None
        s = dd_dizgi(oz[1])
        if s is None:
            raise ValueError(f"ad okunamadı: {oz!r}")
        if s[0] == "ek_ofset":
            return self.ek_dizgisi(s[1]), s[1]
        return s[1], None


def dd_parametre(okuyucu: DwarfdumpOkuyucu, param_konum: str) -> dict[str, Any]:
    """Parametreyi dwarfdump ile baştan yürü: ad, tipin tutulduğu DIE, ham zincir, basit kanonik."""
    sonuc: dict[str, Any] = {"ad": None, "ad_ofseti": None, "tip_kaynagi": None, "ham": [],
                             "kanonik": None, "hata": None}
    try:
        r, o = konum_coz(param_konum)
        tip: Optional[tuple[str, int]] = None
        ad_bulundu = False
        for _ in range(KOKEN_SINIRI):
            die = okuyucu.die(r, o)
            if die is None:
                sonuc["hata"] = f"DIE yok: {konum(r, o)}"
                return sonuc
            if not ad_bulundu and "DW_AT_name" in die["oz"]:
                sonuc["ad"], sonuc["ad_ofseti"] = okuyucu.ad(die)
                ad_bulundu = True
            if tip is None and "DW_AT_type" in die["oz"]:
                bicim, metin = die["oz"]["DW_AT_type"]
                sonuc["tip_kaynagi"] = {"die": konum(r, o), "bicim": bicim}
                tip = okuyucu.hedef(r, metin)
            if ad_bulundu and tip is not None:
                break
            if "DW_AT_abstract_origin" in die["oz"]:
                r, o = okuyucu.hedef(r, die["oz"]["DW_AT_abstract_origin"][1])
                continue
            break
        if tip is None:
            sonuc["hata"] = "DW_AT_type yok"
            return sonuc
        r, o = tip
        derinlik = 0
        taban: Optional[str] = None
        for _ in range(64):
            die = okuyucu.die(r, o)
            if die is None:
                sonuc["hata"] = f"DIE yok: {konum(r, o)}"
                return sonuc
            ad, _ = okuyucu.ad(die)
            adim: dict[str, Any] = {"etiket": kisa_etiket(die["etiket"]), "konum": konum(r, o)}
            if ad is not None:
                adim["ad"] = ad
            sonuc["ham"].append(adim)
            e = die["etiket"]
            if e in _DD_ZINCIR:
                if e == "DW_TAG_pointer_type":
                    derinlik += 1
                if "DW_AT_type" not in die["oz"]:
                    taban = "void"
                    break
                r, o = okuyucu.hedef(r, die["oz"]["DW_AT_type"][1])
                continue
            if e == "DW_TAG_base_type":
                taban = ad
            elif e in KUME_TURLERI:
                tur = KUME_TURLERI[e]
                taban = f"{tur} {ad}" if ad else f"{tur} <anon@{konum(r, o)}>"
            break
        if taban is not None:
            sonuc["kanonik"] = f"{taban} {'*' * derinlik}" if derinlik else taban
    except ValueError as h:
        sonuc["hata"] = str(h)
    return sonuc


def capraz_farklar(param: dict[str, Any], dd: dict[str, Any]) -> list[str]:
    if dd.get("hata"):
        return [f"dwarfdump: {dd['hata']}"]
    farklar = []
    if param.get("ad") != dd["ad"]:
        farklar.append(f"ad: {param.get('ad')!r} ≠ {dd['ad']!r}")
    if (param.get("ad_kaynagi") or {}).get("ofset") != dd["ad_ofseti"]:
        farklar.append(f"ad ofseti: {(param.get('ad_kaynagi') or {}).get('ofset')} ≠ "
                       f"{dd['ad_ofseti']}")
    tk = param["tip_kaynagi"]
    if dd["tip_kaynagi"] != {"die": tk.get("die"), "bicim": tk.get("bicim")}:
        farklar.append(f"tip kaynağı: {tk.get('die')} {tk.get('bicim')} ≠ {dd['tip_kaynagi']}")
    benim = [(a["etiket"], a["konum"], a.get("ad")) for a in param["tip"].get("ham", [])]
    onun = [(a["etiket"], a["konum"], a.get("ad")) for a in dd["ham"]]
    if benim != onun:
        farklar.append(f"ham zincir: {benim} ≠ {onun}")
    if dd["kanonik"] is not None and dd["kanonik"] != param["tip"].get("kanonik"):
        farklar.append(f"kanonik: {param['tip'].get('kanonik')!r} ≠ {dd['kanonik']!r}")
    return farklar


CAPRAZ_EVRENLERI = ("ek", "ana", "hepsi")


def capraz_evreni(belgeler: list[tuple[str, Path, dict[str, Any]]], evren_turu: str = "ek"
                  ) -> list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]]:
    """(dosya adı, belge, fonksiyon, parametre): çözülmüş parametreler; ``ek``: tipi ek dosyada
    olanlar (dwz yolu), ``ana``: tipi ana dosyada olanlar, ``hepsi``: ikisi."""
    if evren_turu not in CAPRAZ_EVRENLERI:
        raise ValueError(f"evren {CAPRAZ_EVRENLERI} içinden olmalı: {evren_turu!r}")
    evren = []
    for _, yol, b in belgeler:
        for f in b["fonksiyonlar"]:
            for p in f["parametreler"]:
                if not p["tip"]["cozuldu"]:
                    continue
                ekte = str(p["tip_kaynagi"].get("hedef", "")).startswith(EK + ":")
                if evren_turu == "hepsi" or ekte == (evren_turu == "ek"):
                    evren.append((yol.name, b, f, p))
    evren.sort(key=lambda x: (x[0], int(x[2]["adres"], 16), x[3]["konum"]))
    return evren


def capraz(belgeler: list[tuple[str, Path, dict[str, Any]]], *, n: int = CAPRAZ_N,
           tohum_metni: str = CAPRAZ_TOHUM_METNI, dwarfdump: str = DWARFDUMP_YOLU,
           evren_turu: str = "ek") -> dict[str, Any]:
    evren = capraz_evreni(belgeler, evren_turu)
    t = tohum(tohum_metni)
    secilen = random.Random(t).sample(evren, min(n, len(evren)))
    okuyucular: dict[tuple[Optional[str], Optional[str]], DwarfdumpOkuyucu] = {}
    ornekler = []
    for dosya_adi, b, f, p in secilen:
        ana_yol = b["girdi"]["ana"]["yol"]
        ek_yol = (b["girdi"]["ek"] or {}).get("yol")
        okuyucu = okuyucular.get((ana_yol, ek_yol))
        if okuyucu is None:
            okuyucu = DwarfdumpOkuyucu({ANA: ana_yol, EK: ek_yol}, dwarfdump)
            okuyucular[(ana_yol, ek_yol)] = okuyucu
        dd = dd_parametre(okuyucu, p["konum"])
        farklar = capraz_farklar(p, dd)
        ornekler.append({"dosya": dosya_adi, "fonksiyon": f["ad"], "adres": f["adres"],
                         "parametre": p["konum"], "sira": p["sira"], "ad": p.get("ad"),
                         "kanonik": p["tip"]["kanonik"], "dwarfdump_kanonik": dd["kanonik"],
                         "ham_adim": len(dd["ham"]), "tutarli": not farklar, "farklar": farklar})
    return {"sema": CAPRAZ_SEMA, "arac": arac_kunyesi(), "dwarfdump": dwarfdump,
            "tohum_metni": tohum_metni, "tohum": t, "evren_turu": evren_turu,
            "n": len(secilen), "evren": len(evren),
            "tutarli": sum(o["tutarli"] for o in ornekler),
            "dwarfdump_cagrisi": sum(o.cagri for o in okuyucular.values()),
            "kanonik_karsilastirilan": sum(o["dwarfdump_kanonik"] is not None for o in ornekler),
            "ornekler": ornekler}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    c = sub.add_parser("cikar", help="bir .debug dosyasından fonksiyon ve parametre tipleri")
    c.add_argument("debug", type=Path)
    c.add_argument("--ek", type=Path, default=None,
                   help="dwz ek dosyası (verilmezse .gnu_debugaltlink'ten bulunur)")
    c.add_argument("--ikili", type=Path, default=None, help="ana ikili (künye ve build-id için)")
    c.add_argument("-o", "--out", type=Path, required=True)
    t = sub.add_parser("toplu", help="bir dbgsym kökündeki bütün .debug dosyaları")
    t.add_argument("kok", type=Path, help="…/usr/lib/debug")
    t.add_argument("--ikili-kok", type=Path, default=None,
                   help="açılmış ikili paket (build-id ile ikili adı için)")
    t.add_argument("--ek", type=Path, default=None)
    t.add_argument("-o", "--out", type=Path, required=True, help="çıktı dizini")
    o = sub.add_parser("ozet", help="çözülen tip payı, sınıf dağılımı, klon payı")
    o.add_argument("girdiler", nargs="+", type=Path, help="JSON dosyaları ya da dizinler")
    o.add_argument("--json", type=Path, default=None)
    o.add_argument("--dosyalar", action="store_true", help="dosya başına satır da yaz")
    o.add_argument("--yalniz-gruplar", action="store_true",
                   help="--json'a dosya başına satırları yazma (yalnız gruplar ve toplam)")
    x = sub.add_parser("capraz", help="dwarfdump ile tohumlu bağımsız çapraz denetim")
    x.add_argument("girdiler", nargs="+", type=Path)
    x.add_argument("--n", type=int, default=CAPRAZ_N)
    x.add_argument("--tohum-metni", default=CAPRAZ_TOHUM_METNI)
    x.add_argument("--dwarfdump", default=DWARFDUMP_YOLU)
    x.add_argument("--evren", choices=CAPRAZ_EVRENLERI, default="ek",
                   help="ek: tipi dwz ek dosyasında olanlar (varsayılan); ana; hepsi")
    x.add_argument("-o", "--out", type=Path, default=None)
    a = ap.parse_args(argv)
    if a.komut == "cikar":
        belge = cikar(a.debug, ek_yol=a.ek, ikili=a.ikili)
        _yaz_json(a.out, belge)
        s = belge["sayimlar"]
        print(f"{a.out}: fonksiyon={s['fonksiyon']} parametre={s['parametre']} "
              f"çözülen={s['tip_cozulen']} ek={belge['girdi']['ek_yontemi']}")
        return 0
    if a.komut == "toplu":
        indeks = toplu(a.kok, a.out, ikili_kok=a.ikili_kok, ek_yol=a.ek)
        p = sum(s["parametre"] for s in indeks["dosyalar"])
        k = sum(s["tip_cozulen"] for s in indeks["dosyalar"])
        print(f"{a.out}: {len(indeks['dosyalar'])} dosya, parametre={p}, çözülen={k}")
        return 0
    if a.komut == "ozet":
        oz = ozetle(belgeleri_topla(a.girdiler))
        ozet_yazdir(oz, dosya_satirlari=a.dosyalar)
        if a.json:
            if a.yalniz_gruplar:
                oz = {k: v for k, v in oz.items() if k != "dosyalar"}
                oz["girdiler"] = [g.name for g in a.girdiler]
            _yaz_json(a.json, oz)
        return 0
    sonuc = capraz(belgeleri_topla(a.girdiler), n=a.n, tohum_metni=a.tohum_metni,
                   dwarfdump=a.dwarfdump, evren_turu=a.evren)
    print(f"çapraz denetim: {sonuc['tutarli']}/{sonuc['n']} tutarlı (evren {sonuc['evren']}, "
          f"kanonik karşılaştırılan {sonuc['kanonik_karsilastirilan']}, "
          f"dwarfdump çağrısı {sonuc['dwarfdump_cagrisi']})")
    for ornek in sonuc["ornekler"]:
        if not ornek["tutarli"]:
            print(f"  TUTARSIZ {ornek['dosya']} {ornek['fonksiyon']} {ornek['parametre']}: "
                  f"{ornek['farklar']}")
    if a.out:
        _yaz_json(a.out, sonuc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
