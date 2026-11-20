"""İkili görüntü okuyucu (P-ÜV0): üst veri okuyucularının ortak zemini.

Okuyucular (Go ``pclntab``, ObjC, Swift, C++ RTTI) dosya yolu değil bir ``Goruntu`` alır.
Arayüz (PLAN.md "P-ÜV0" kalem 1; ad ve imzalar sabit, P-ÜV1 / P-ÜV2 buna yaslanır):

- ``oku(adres, n) -> bytes | None``: sanal adresten tam ``n`` bayt; aralığın tamamı dosyada
  karşılığı olan tek bir eşlemenin içinde değilse ``None``.
- ``u16``, ``u32``, ``i32``, ``u64``: küçük sonlu (görüntünün bayt sırası) tam sayı ya da ``None``.
- ``cstr(adres, azami=4096) -> str | None``: NUL ile biten dizgi (UTF-8, bozuk bayt ``U+FFFD``);
  ``azami`` bayt içinde NUL yoksa ya da adres okunamıyorsa ``None``.
- ``gosterici(adres) -> int | Bag | None``: ``adres``'teki göstericinin yükleme sonrası değeri
  (görüntü tabanı tercih edilen taban: kaydırma yok). Yeniden konumlama → hedef adres (``int``);
  içe aktarım bağı → ``Bag(ad)``; düzeltme yeri değilse dosyadaki ham sözcük. Okunamıyorsa ya da
  değer 0 ise ``None``.
- ``bolumler`` (``Bolum``: ad, adres, boyut, kod mu), ``bolum_adli(ad)``, ``kod_bolumleri``.
- ``fonksiyon_baslangiclari() -> list[int] | None``: biçimin fonksiyon başlangıcı tablosu
  (Mach-O ``LC_FUNCTION_STARTS``, ELF ``.eh_frame`` FDE başlangıçları); tablo yoksa ``None``.
- ``semboller() -> list[Sembol]`` (ad, adres, tür, dışa açık mı).
- ``giris_adresi``, ``mimari``, ``gosterici_boyutu``, ``bicim`` (``macho`` / ``elf`` / ``pe``).

Sağlamlık sözleşmesi: bozuk ya da kesik dosyada hiçbir yöntem istisna atmaz; okunamayan kısım
``None`` / boş döner ve ``durum`` sözlüğüne ``{"durum": …, "neden": …}`` olarak yazılır
(``calisti`` / ``veri_yok`` / ``desteklenmiyor`` / ``hata``). Desteklenmeyen biçim parçası
(ör. arm64e gösterici biçimi) istisna değil ``desteklenmiyor`` durumudur.

İkili çalıştırılmaz, değiştirilmez; yalnız baytlar okunur.
"""
from __future__ import annotations

import bisect
import struct
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# --- durum sözlüğü (bütün ÜST VERİ okuyucularıyla ortak) ---------------------------------
DURUM_CALISTI = "calisti"
DURUM_VERI_YOK = "veri_yok"
DURUM_DESTEKLENMIYOR = "desteklenmiyor"
DURUM_HATA = "hata"
GECERLI_DURUMLAR = (DURUM_CALISTI, DURUM_VERI_YOK, DURUM_DESTEKLENMIYOR, DURUM_HATA)

# --- biçim adları ------------------------------------------------------------------------
BICIM_MACHO = "macho"
BICIM_ELF = "elf"
BICIM_PE = "pe"

# --- sembol türleri ----------------------------------------------------------------------
SEMBOL_KOD = "kod"                    # kod bölümünde tanımlı
SEMBOL_VERI = "veri"                  # kod dışı bir bölümde tanımlı
SEMBOL_TANIMSIZ = "tanimsiz"          # tanımsız (dışarıdan gelir)
SEMBOL_MUTLAK = "mutlak"              # mutlak değer (bölümsüz)
SEMBOL_HATA_AYIKLAMA = "hata_ayiklama"  # Mach-O stab girdisi
SEMBOL_DIGER = "diger"                # bölüm / dosya sembolü ve öbürleri

# --- durum kısımları ---------------------------------------------------------------------
KISIM_BASLIK = "baslik"                      # başlık + yük komutları / bölüm tablosu
KISIM_DUZELTME = "duzeltme"                  # zincirli düzeltme / yeniden konumlama / bağ
KISIM_SEMBOL = "sembol"
KISIM_FONKSIYON_BASLANGICI = "fonksiyon_baslangici"

CSTR_AZAMI = 4096  # cstr öntanımlı üst sınırı (bayt)


class GoruntuHatasi(Exception):
    """Görüntü kurulamadı (biçim tanınmadı, dosya okunamadı, evrensel dosyada dilim yok).

    ``durum`` alanı ``GECERLI_DURUMLAR``'dan biridir; ``neden`` insan okur metni.
    """

    def __init__(self, neden: str, durum: str = DURUM_HATA) -> None:
        super().__init__(neden)
        self.neden = neden
        self.durum = durum


@dataclass(frozen=True)
class Bag:
    """İçe aktarım bağı: gösterici yükleme anında dış bir sembole bağlanır.

    ``ad`` sembol adı (Mach-O'da baştaki ``_`` dahil, ör. ``_OBJC_CLASS_$_NSObject``);
    ``ek`` bağa eklenen sabit (çoğu kez 0).
    """

    ad: str
    ek: int = 0


@dataclass(frozen=True)
class Bolum:
    """Bölüm: ``ad`` (Mach-O ``sectname``, ELF / PE bölüm adı), sanal ``adres``, ``boyut``, ``kod``.

    ``bolut`` Mach-O bölüt adıdır (``__DATA_CONST``); ELF / PE'de boş. ``dosya_ofseti`` bölümün
    dosyadaki yeri; dosyada karşılığı yoksa (sıfır dolgulu ``__bss`` / ``SHT_NOBITS``) ``None``.
    ``bellekte`` yanlışsa bölüm yüklenmez (ELF'te ``SHF_ALLOC`` yok: ``.symtab``, ``.comment`` …);
    adresi anlamsızdır, hiçbir adresi içermez.
    """

    ad: str
    adres: int
    boyut: int
    kod: bool
    bolut: str = ""
    dosya_ofseti: int | None = None
    bellekte: bool = True

    @property
    def tam_ad(self) -> str:
        return f"{self.bolut},{self.ad}" if self.bolut else self.ad

    def icerir(self, adres: int) -> bool:
        return self.bellekte and self.adres <= adres < self.adres + self.boyut


@dataclass(frozen=True)
class Sembol:
    """Sembol tablosu girdisi: ``ad``, ``adres``, ``tur`` (``SEMBOL_*``), ``disa_acik``.

    ``boyut`` biçim veriyorsa (ELF ``st_size``), yoksa ``None``; ``tablo`` girdinin geldiği tablo
    (``LC_SYMTAB``, ``.symtab``, ``.dynsym`` …).
    """

    ad: str
    adres: int
    tur: str
    disa_acik: bool
    boyut: int | None = None
    tablo: str = ""


def uleb128(veri: bytes, konum: int, son: int | None = None) -> tuple[int, int] | None:
    """İşaretsiz LEB128 çöz: ``(değer, yeni konum)``; veri biterse ``None`` (istisna yok)."""
    sinir = len(veri) if son is None else min(son, len(veri))
    deger = 0
    kayma = 0
    while konum < sinir:
        b = veri[konum]
        konum += 1
        deger |= (b & 0x7F) << kayma
        if not b & 0x80:
            return deger, konum
        kayma += 7
        if kayma > 70:  # 10 bayttan uzun: bozuk
            return None
    return None


def sleb128(veri: bytes, konum: int, son: int | None = None) -> tuple[int, int] | None:
    """İşaretli LEB128 çöz: ``(değer, yeni konum)``; veri biterse ``None``."""
    sinir = len(veri) if son is None else min(son, len(veri))
    deger = 0
    kayma = 0
    while konum < sinir:
        b = veri[konum]
        konum += 1
        deger |= (b & 0x7F) << kayma
        kayma += 7
        if not b & 0x80:
            if b & 0x40:
                deger -= 1 << kayma
            return deger, konum
        if kayma > 70:
            return None
    return None


class Goruntu(ABC):
    """Bir ikili dilimin bellek görüntüsü (yükleme öncesi, tercih edilen tabanda).

    Alt sınıflar ``bicim``, ``mimari``, ``gosterici_boyutu``, ``giris_adresi``, ``bolumler``,
    ``oku``, ``gosterici``, ``fonksiyon_baslangiclari``, ``semboller``'i sağlar; tam sayı ve dizgi
    okuyucuları burada ``oku`` üstüne kuruludur (test için kurulan sahte alt sınıf da yalnız
    ``oku``'yu verirse yeter).
    """

    #: bayt sırası (``struct`` öneki); bütün desteklenen biçimlerde küçük sonlu
    bayt_sirasi: str = "<"
    #: görüntünün kaynağı (dosya yolu + dilim); yalnız bilgi
    kaynak: str = ""

    def __init__(self) -> None:
        self._durum: dict[str, dict[str, str]] = {}

    # ---- kimlik ----------------------------------------------------------------------
    @property
    @abstractmethod
    def bicim(self) -> str:
        """``macho`` / ``elf`` / ``pe``."""

    @property
    @abstractmethod
    def mimari(self) -> str:
        """``arm64``, ``x86_64`` … (Mach-O'da ``lipo -archs`` adı; bilinmiyorsa ``""``)."""

    @property
    @abstractmethod
    def gosterici_boyutu(self) -> int:
        """Gösterici boyutu (bayt): 8 ya da 4."""

    @property
    @abstractmethod
    def giris_adresi(self) -> int | None:
        """Program giriş adresi (sanal); yoksa ``None``."""

    # ---- bölümler --------------------------------------------------------------------
    @property
    @abstractmethod
    def bolumler(self) -> list[Bolum]:
        """Bütün bölümler (dosyadaki sırayla)."""

    def bolum_adli(self, ad: str) -> Bolum | None:
        """Adı ``ad`` olan ilk bölüm. ``"BÖLÜT,bölüm"`` biçimi bölüt adıyla birlikte eşler."""
        bul = self.bolumler_adli(ad)
        return bul[0] if bul else None

    def bolumler_adli(self, ad: str) -> list[Bolum]:
        """Adı ``ad`` olan bütün bölümler (Mach-O'da aynı ad birden çok bölütte olabilir)."""
        if "," in ad:
            bolut, _, bad = ad.partition(",")
            return [b for b in self.bolumler if b.ad == bad and b.bolut == bolut]
        return [b for b in self.bolumler if b.ad == ad]

    @property
    def kod_bolumleri(self) -> list[Bolum]:
        """Yürütülebilir kod bölümleri."""
        return [b for b in self.bolumler if b.kod]

    def adres_bolumu(self, adres: int) -> Bolum | None:
        """``adres``'i içeren bölüm (yoksa ``None``)."""
        for b in self.bolumler:
            if b.icerir(adres):
                return b
        return None

    def kod_mu(self, adres: int) -> bool:
        """``adres`` bir kod bölümünün içinde mi?"""
        return any(b.icerir(adres) for b in self.kod_bolumleri)

    def bolum_baytlari(self, bolum: Bolum) -> bytes | None:
        """Bölümün bütün baytları; dosyada karşılığı yoksa ``None``."""
        if bolum.boyut == 0:
            return b""
        return self.oku(bolum.adres, bolum.boyut)

    # ---- bayt okuma ------------------------------------------------------------------
    @abstractmethod
    def oku(self, adres: int, n: int) -> bytes | None:
        """``adres``'ten tam ``n`` bayt; okunamıyorsa ``None``."""

    def _oku_en_cok(self, adres: int, n: int) -> bytes | None:
        """``adres``'ten başlayıp aynı eşlemede kalan en çok ``n`` bayt (``cstr`` için).

        Öntanım ``oku`` üstüne kuruludur; eşleme tablosu olan alt sınıflar hızlı sürümünü verir.
        """
        if n <= 0:
            return b""
        tam = self.oku(adres, n)
        if tam is not None:
            return tam
        parca = bytearray()
        adim = 64
        while len(parca) < n:
            istek = min(adim, n - len(parca))
            b = self.oku(adres + len(parca), istek)
            if b is None:
                while len(parca) < n:  # eşlemenin sonuna bayt bayt yaklaş
                    tek = self.oku(adres + len(parca), 1)
                    if tek is None:
                        break
                    parca += tek
                break
            parca += b
        return bytes(parca) if parca else None

    def _sayi(self, bicim: str, adres: int) -> int | None:
        boy = struct.calcsize(bicim)
        b = self.oku(adres, boy)
        if b is None or len(b) != boy:
            return None
        return struct.unpack(self.bayt_sirasi + bicim, b)[0]

    def u8(self, adres: int) -> int | None:
        return self._sayi("B", adres)

    def u16(self, adres: int) -> int | None:
        return self._sayi("H", adres)

    def u32(self, adres: int) -> int | None:
        return self._sayi("I", adres)

    def i32(self, adres: int) -> int | None:
        return self._sayi("i", adres)

    def u64(self, adres: int) -> int | None:
        return self._sayi("Q", adres)

    def sozcuk(self, adres: int) -> int | None:
        """Gösterici boyutunda ham sözcük (düzeltme uygulanmadan)."""
        return self.u64(adres) if self.gosterici_boyutu == 8 else self.u32(adres)

    def cstr(self, adres: int, azami: int = CSTR_AZAMI) -> str | None:
        """NUL ile biten dizgi; ``azami`` bayt içinde NUL yoksa ya da okunamıyorsa ``None``."""
        if azami <= 0:
            return None
        b = self._oku_en_cok(adres, azami)
        if not b:
            return None
        son = b.find(b"\0")
        if son < 0:
            return None
        return b[:son].decode("utf-8", "replace")

    # ---- göstericiler ----------------------------------------------------------------
    @abstractmethod
    def gosterici(self, adres: int) -> int | Bag | None:
        """``adres``'teki göstericinin yükleme sonrası değeri (bkz. modül belgesi)."""

    # ---- fonksiyonlar, semboller -----------------------------------------------------
    @abstractmethod
    def fonksiyon_baslangiclari(self) -> list[int] | None:
        """Fonksiyon başlangıç adresleri (artan, tekil); tablo yoksa ``None``."""

    @abstractmethod
    def semboller(self) -> list[Sembol]:
        """Sembol tablosu (tablo yoksa boş liste; neden ``durum``'da)."""

    # ---- durum -----------------------------------------------------------------------
    @property
    def durum(self) -> dict[str, dict[str, str]]:
        """Kısım → ``{"durum": …, "neden": …}`` (kopya)."""
        return {k: dict(v) for k, v in self._durum.items()}

    def _durum_yaz(self, kisim: str, durum: str, neden: str = "") -> None:
        if durum not in GECERLI_DURUMLAR:  # pragma: no cover - programlama hatası
            raise ValueError(f"bilinmeyen durum: {durum}")
        self._durum[kisim] = {"durum": durum, "neden": neden}

    def ozet(self) -> dict[str, Any]:
        """Yerel doğrulama özeti (kalem 7); biçime özgü alanları alt sınıf ekler."""
        fb = self.fonksiyon_baslangiclari()
        return {
            "bicim": self.bicim,
            "mimari": self.mimari,
            "gosterici_boyutu": self.gosterici_boyutu,
            "giris": hex(self.giris_adresi) if self.giris_adresi is not None else None,
            "bolum": len(self.bolumler),
            "kod_bolumu": len(self.kod_bolumleri),
            "sembol": len(self.semboller()),
            "fonksiyon_baslangici": len(fb) if fb is not None else None,
            "durum": self.durum,
        }


class BellekGoruntu(Goruntu):
    """Bellekte kurulan görüntü: sentetik testler ve bölüm baytları elde olan okuyucular için.

    ``bolumler``: ``(ad, adres, veri)``, ``(ad, adres, veri, kod)`` ya da
    ``(ad, adres, veri, kod, bolut)`` demetleri. ``yeniden_konumlamalar``: adres → hedef;
    ``baglar``: adres → ``Bag``. Bu iki sözlükte olmayan adreste ``gosterici`` ham sözcüğü okur.
    """

    def __init__(
        self,
        bolumler: Iterable[tuple],
        *,
        bicim: str = BICIM_MACHO,
        mimari: str = "arm64",
        gosterici_boyutu: int = 8,
        giris_adresi: int | None = None,
        semboller: Iterable[Sembol] = (),
        fonksiyon_baslangiclari: Iterable[int] | None = None,
        yeniden_konumlamalar: Mapping[int, int] | None = None,
        baglar: Mapping[int, Bag] | None = None,
        kaynak: str = "bellek",
    ) -> None:
        super().__init__()
        self._bicim = bicim
        self._mimari = mimari
        self._gb = gosterici_boyutu
        self._giris = giris_adresi
        self.kaynak = kaynak
        self._bolumler: list[Bolum] = []
        self._veriler: list[tuple[int, int, bytes]] = []  # (başlangıç, bitiş, veri)
        for t in bolumler:
            ad, adres, veri = t[0], int(t[1]), bytes(t[2])
            kod = bool(t[3]) if len(t) > 3 else False
            bolut = str(t[4]) if len(t) > 4 else ""
            self._bolumler.append(Bolum(ad, adres, len(veri), kod, bolut, None))
            self._veriler.append((adres, adres + len(veri), veri))
        self._semboller = list(semboller)
        self._fb = sorted(set(fonksiyon_baslangiclari)) if fonksiyon_baslangiclari is not None else None
        self._rk = dict(yeniden_konumlamalar or {})
        self._baglar = dict(baglar or {})
        self._durum_yaz(KISIM_BASLIK, DURUM_CALISTI)

    @property
    def bicim(self) -> str:
        return self._bicim

    @property
    def mimari(self) -> str:
        return self._mimari

    @property
    def gosterici_boyutu(self) -> int:
        return self._gb

    @property
    def giris_adresi(self) -> int | None:
        return self._giris

    @property
    def bolumler(self) -> list[Bolum]:
        return list(self._bolumler)

    def _bul(self, adres: int) -> tuple[int, int, bytes] | None:
        for bas, son, veri in self._veriler:
            if bas <= adres < son:
                return bas, son, veri
        return None

    def oku(self, adres: int, n: int) -> bytes | None:
        if n < 0:
            return None
        e = self._bul(adres)
        if e is None:
            return None
        bas, son, veri = e
        if adres + n > son:
            return None
        return veri[adres - bas:adres - bas + n]

    def _oku_en_cok(self, adres: int, n: int) -> bytes | None:
        e = self._bul(adres)
        if e is None or n <= 0:
            return None
        bas, _son, veri = e
        return veri[adres - bas:adres - bas + n]

    def gosterici(self, adres: int) -> int | Bag | None:
        if adres in self._baglar:
            return self._baglar[adres]
        if adres in self._rk:
            return self._rk[adres]
        v = self.sozcuk(adres)
        return v if v else None

    def fonksiyon_baslangiclari(self) -> list[int] | None:
        return list(self._fb) if self._fb is not None else None

    def semboller(self) -> list[Sembol]:
        return list(self._semboller)


class _DosyaGoruntusu(Goruntu):
    """Dosya baytları + eşleme tablosu (sanal başlangıç, sanal bitiş, dosya ofseti) üstüne okuma."""

    def __init__(self, veri: bytes, kaynak: str = "") -> None:
        super().__init__()
        self._veri = veri
        self.kaynak = kaynak
        self._eslemler: list[tuple[int, int, int]] = []
        self._eslem_baslari: list[int] = []

    def _eslem_kur(self, eslemler: Iterable[tuple[int, int, int]]) -> None:
        """Dosyada karşılığı olan sanal aralıkları kaydet (dosya dışına taşan kısım kırpılır)."""
        boy = len(self._veri)
        temiz = []
        for bas, son, ofs in eslemler:
            if son <= bas or ofs < 0 or ofs >= boy:
                continue
            son = min(son, bas + (boy - ofs))  # kesik dosya: dosyada olmayan kuyruk okunmaz
            temiz.append((bas, son, ofs))
        temiz.sort()
        self._eslemler = temiz
        self._eslem_baslari = [e[0] for e in temiz]

    def _eslem(self, adres: int) -> tuple[int, int, int] | None:
        i = bisect.bisect_right(self._eslem_baslari, adres) - 1
        if i < 0:
            return None
        e = self._eslemler[i]
        return e if adres < e[1] else None

    def dosya_ofseti(self, adres: int) -> int | None:
        """Sanal adresin dosyadaki yeri (dosyada karşılığı yoksa ``None``)."""
        e = self._eslem(adres)
        return None if e is None else e[2] + (adres - e[0])

    def oku(self, adres: int, n: int) -> bytes | None:
        if n < 0:
            return None
        e = self._eslem(adres)
        if e is None or adres + n > e[1]:
            return None
        ofs = e[2] + (adres - e[0])
        return self._veri[ofs:ofs + n]

    def _oku_en_cok(self, adres: int, n: int) -> bytes | None:
        e = self._eslem(adres)
        if e is None or n <= 0:
            return None
        ofs = e[2] + (adres - e[0])
        return self._veri[ofs:ofs + min(n, e[1] - adres)]

    def bolum_baytlari(self, bolum: Bolum) -> bytes | None:
        """Bölümün baytları dosyadaki yerinden (yüklenmeyen bölüm dahil); karşılığı yoksa ``None``."""
        if bolum.boyut == 0:
            return b""
        if bolum.dosya_ofseti is None:
            return None
        return self._dosya_dilimi(bolum.dosya_ofseti, bolum.boyut)

    def _dosya_dilimi(self, ofs: int, boy: int) -> bytes | None:
        """Dosyadan ``[ofs, ofs+boy)``; dosya dışına taşıyorsa ``None``."""
        if ofs < 0 or boy < 0 or ofs + boy > len(self._veri):
            return None
        return self._veri[ofs:ofs + boy]


# =====================================================================================
# Mach-O 64 (kaynak: Xcode SDK <mach-o/loader.h>, <mach-o/nlist.h>, <mach-o/fat.h>,
# <mach-o/fixup-chains.h>; başvuru betiği scripts/arge/ustveri/macho.py)
# =====================================================================================
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
_MACHO_BASLIK = 32

LC_REQ_DYLD = 0x80000000
LC_SYMTAB = 0x2
LC_UNIXTHREAD = 0x5
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_SEGMENT_64 = 0x19
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD
_LC_DYLIB_TURLERI = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB,
                     LC_LOAD_UPWARD_DYLIB)

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
_ARM_THREAD_STATE64 = 6
_X86_THREAD_STATE64 = 4
_X86_THREAD_STATE = 7

# nlist n_type
N_STAB = 0xE0
N_PEXT = 0x10
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_ABS = 0x2
N_SECT = 0xE
_NLIST_64 = 16

# bölüm bayrakları
S_ATTR_KOD = 0x80000000 | 0x00000400  # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
_SECTION_TYPE = 0x000000FF
_S_SIFIR_DOLGU = (0x1, 0xC, 0x12)  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL

# zincirli düzeltme (<mach-o/fixup-chains.h>)
DYLD_CHAINED_PTR_ARM64E = 1
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_64_OFFSET = 6
DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_PTR_START_MULTI = 0x8000
DYLD_CHAINED_IMPORT = 1
DYLD_CHAINED_IMPORT_ADDEND = 2
DYLD_CHAINED_IMPORT_ADDEND64 = 3
_ZINCIR_ADIMI = 4          # sonraki alanı 4 baytlık adımla sayar (biçim 2 ve 6)
_ZINCIR_HEDEF_MASKE = (1 << 36) - 1
_ZINCIR_SONRAKI_KAYMA = 51
_ZINCIR_SONRAKI_MASKE = 0xFFF
_ZINCIR_HIGH8_KAYMA = 36
_ZINCIR_BAG_BITI = 63
_ZINCIR_BAG_SIRA_MASKE = 0xFFFFFF
_ZINCIR_BAG_EK_KAYMA = 24

# LC_DYLD_INFO bağ işlem kodları (<mach-o/loader.h>)
_BIND_OPCODE_MASK = 0xF0
_BIND_IMMEDIATE_MASK = 0x0F
_BIND_DONE = 0x00
_BIND_SET_DYLIB_ORDINAL_IMM = 0x10
_BIND_SET_DYLIB_ORDINAL_ULEB = 0x20
_BIND_SET_DYLIB_SPECIAL_IMM = 0x30
_BIND_SET_SYMBOL = 0x40
_BIND_SET_TYPE_IMM = 0x50
_BIND_SET_ADDEND_SLEB = 0x60
_BIND_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
_BIND_ADD_ADDR_ULEB = 0x80
_BIND_DO_BIND = 0x90
_BIND_DO_BIND_ADD_ADDR_ULEB = 0xA0
_BIND_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
_BIND_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
_U64 = (1 << 64) - 1


def _ad_coz(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


class MachO64Goruntu(_DosyaGoruntusu):
    """İnce (tek dilim) Mach-O 64, küçük sonlu (arm64 / x86_64)."""

    def __init__(self, veri: bytes, kaynak: str = "") -> None:
        super().__init__(veri, kaynak)
        self.cputype = 0
        self.cpusubtype = 0
        self.dosya_turu = 0
        self.bolutler: list[dict[str, Any]] = []
        self._bolumler: list[Bolum] = []
        self._symtab: tuple[int, int, int, int] | None = None
        self.entryoff: int | None = None
        self.unixthread_pc: int | None = None
        self.kitapliklar: list[str] = []
        self._fs_cmd: tuple[int, int] | None = None
        self._zd_cmd: tuple[int, int] | None = None
        self._dyld_info: tuple[int, ...] | None = None
        self._semboller: list[Sembol] | None = None
        self._fb: list[int] | None = None
        self._fb_okundu = False
        self._duzeltme: dict[int, Any] | None = None
        self._ice_aktarimlar: list[str] | None = None
        self._ice_ekler: list[int] = []
        self._duzeltme_bozuk = False
        self._desteksiz_araliklar: list[tuple[int, int]] = []
        self._dyld_baglar: dict[int, Bag] | None = None
        self._baslik_oku()

    # ---- başlık ve yük komutları -----------------------------------------------------
    def _baslik_oku(self) -> None:
        d = self._veri
        if len(d) < _MACHO_BASLIK:
            self._durum_yaz(KISIM_BASLIK, DURUM_HATA, "başlık kesik")
            return
        magic, cpu, sub, ftype, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<IIIIIIII", d, 0)
        if magic != MH_MAGIC_64:
            self._durum_yaz(KISIM_BASLIK, DURUM_DESTEKLENMIYOR, f"Mach-O 64 imzası değil: {magic:#x}")
            return
        self.cputype, self.cpusubtype, self.dosya_turu = cpu, sub, ftype
        son = min(len(d), _MACHO_BASLIK + sizeofcmds)
        pos = _MACHO_BASLIK
        hata = ""
        eslemler = []
        for i in range(ncmds):
            if pos + 8 > son:
                hata = f"yük komutu {i} / {ncmds} kesik"
                break
            cmd, size = struct.unpack_from("<II", d, pos)
            if size < 8 or pos + size > son:
                hata = f"yük komutu {i} boyu geçersiz ({size})"
                break
            try:
                self._komut_oku(cmd, pos, size, eslemler)
            except (struct.error, IndexError, ValueError) as exc:
                hata = f"yük komutu {i} ({cmd:#x}) okunamadı: {exc}"
                break
            pos += size
        self._eslem_kur(eslemler)
        if hata:
            self._durum_yaz(KISIM_BASLIK, DURUM_HATA, hata)
        else:
            self._durum_yaz(KISIM_BASLIK, DURUM_CALISTI)

    def _komut_oku(self, cmd: int, pos: int, size: int, eslemler: list) -> None:
        d = self._veri
        if cmd == LC_SEGMENT_64:
            if size < 72:
                raise ValueError("LC_SEGMENT_64 kısa")
            ad = _ad_coz(d[pos + 8:pos + 24])
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _fl = struct.unpack_from(
                "<QQQQiiII", d, pos + 24)
            if 72 + 80 * nsects > size:
                raise ValueError(f"bölüt {ad}: {nsects} bölüm komuta sığmıyor")
            bolut = {"ad": ad, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff,
                     "filesize": filesize, "maxprot": maxprot, "initprot": initprot}
            self.bolutler.append(bolut)
            if filesize:
                eslemler.append((vmaddr, vmaddr + min(filesize, vmsize or filesize), fileoff))
            sp = pos + 72
            for _ in range(nsects):
                sectname = _ad_coz(d[sp:sp + 16])
                segname = _ad_coz(d[sp + 16:sp + 32])
                addr, ssize, off, _al, _ro, _nr, sflags = struct.unpack_from("<QQIIIII", d, sp + 32)
                sifir = (sflags & _SECTION_TYPE) in _S_SIFIR_DOLGU or off == 0
                self._bolumler.append(Bolum(sectname, addr, ssize, bool(sflags & S_ATTR_KOD), segname,
                                            None if sifir else off))
                sp += 80
        elif cmd == LC_SYMTAB:
            self._symtab = struct.unpack_from("<IIII", d, pos + 8)
        elif cmd == LC_MAIN:
            self.entryoff = struct.unpack_from("<Q", d, pos + 8)[0]
        elif cmd == LC_UNIXTHREAD:
            self._unixthread_oku(pos, size)
        elif cmd in _LC_DYLIB_TURLERI:
            noff = struct.unpack_from("<I", d, pos + 8)[0]
            if 8 <= noff < size:
                self.kitapliklar.append(_ad_coz(d[pos + noff:pos + size]))
        elif cmd == LC_FUNCTION_STARTS:
            self._fs_cmd = struct.unpack_from("<II", d, pos + 8)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            self._zd_cmd = struct.unpack_from("<II", d, pos + 8)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            self._dyld_info = struct.unpack_from("<IIIIIIIIII", d, pos + 8)

    def _unixthread_oku(self, pos: int, size: int) -> None:
        d = self._veri
        flavor, _count = struct.unpack_from("<II", d, pos + 8)
        st = pos + 16
        if self.cputype == CPU_TYPE_X86_64 and flavor == _X86_THREAD_STATE:
            flavor = struct.unpack_from("<I", d, st)[0]  # x86_state_hdr: iç tür + sayı
            st += 8
        if self.cputype == CPU_TYPE_ARM64 and flavor == _ARM_THREAD_STATE64:
            sira = 32  # x0..x28, fp, lr, sp, pc
        elif self.cputype == CPU_TYPE_X86_64 and flavor == _X86_THREAD_STATE64:
            sira = 16  # rax … r15, rip
        else:
            return
        if st + 8 * sira + 8 <= pos + size:
            self.unixthread_pc = struct.unpack_from("<Q", d, st + 8 * sira)[0]

    # ---- kimlik ----------------------------------------------------------------------
    @property
    def bicim(self) -> str:
        return BICIM_MACHO

    @property
    def mimari(self) -> str:
        if not self.cputype:
            return ""
        from karadul.analyzers.macho import _fat_arch_name  # ürünün dilim adlandırması
        return _fat_arch_name(self.cputype, self.cpusubtype)

    @property
    def gosterici_boyutu(self) -> int:
        return 8

    @property
    def goruntu_tabani(self) -> int | None:
        """``__TEXT`` bölütünün sanal adresi (yoksa ``None``)."""
        for b in self.bolutler:
            if b["ad"] == "__TEXT":
                return b["vmaddr"]
        return None

    @property
    def giris_adresi(self) -> int | None:
        if self.entryoff is not None:
            taban = self.goruntu_tabani
            return None if taban is None else taban + self.entryoff
        return self.unixthread_pc

    @property
    def bolumler(self) -> list[Bolum]:
        return list(self._bolumler)

    def bolut_adli(self, ad: str) -> dict[str, Any] | None:
        for b in self.bolutler:
            if b["ad"] == ad:
                return dict(b)
        return None

    # ---- semboller -------------------------------------------------------------------
    def semboller(self) -> list[Sembol]:
        if self._semboller is None:
            self._semboller = self._semboller_oku()
        return list(self._semboller)

    def _semboller_oku(self) -> list[Sembol]:
        if self._symtab is None:
            self._durum_yaz(KISIM_SEMBOL, DURUM_VERI_YOK, "LC_SYMTAB yok")
            return []
        symoff, nsyms, stroff, strsize = self._symtab
        d = self._veri
        str_son = min(stroff + strsize, len(d))
        kod_sira = {i + 1 for i, b in enumerate(self._bolumler) if b.kod}
        out: list[Sembol] = []
        okunan = 0
        for i in range(nsyms):
            p = symoff + _NLIST_64 * i
            if p + _NLIST_64 > len(d):
                break
            strx, n_type, n_sect, _n_desc, value = struct.unpack_from("<IBBHQ", d, p)
            ad = ""
            if strx and stroff + strx < str_son:
                q = stroff + strx
                e = d.find(b"\0", q, str_son)
                ad = d[q:e if e >= 0 else str_son].decode("utf-8", "replace")
            if n_type & N_STAB:
                tur = SEMBOL_HATA_AYIKLAMA
            else:
                t = n_type & N_TYPE
                if t == N_UNDF:
                    tur = SEMBOL_TANIMSIZ
                elif t == N_ABS:
                    tur = SEMBOL_MUTLAK
                elif t == N_SECT:
                    tur = SEMBOL_KOD if n_sect in kod_sira else SEMBOL_VERI
                else:
                    tur = SEMBOL_DIGER
            disa = bool(n_type & N_EXT) and not (n_type & N_PEXT) and not (n_type & N_STAB)
            out.append(Sembol(ad, value, tur, disa, None, "LC_SYMTAB"))
            okunan += 1
        if okunan < nsyms:
            self._durum_yaz(KISIM_SEMBOL, DURUM_HATA, f"sembol tablosu kesik: {okunan} / {nsyms}")
        else:
            self._durum_yaz(KISIM_SEMBOL, DURUM_CALISTI)
        return out

    # ---- LC_FUNCTION_STARTS ----------------------------------------------------------
    def fonksiyon_baslangiclari(self) -> list[int] | None:
        if not self._fb_okundu:
            self._fb = self._fb_oku()
            self._fb_okundu = True
        return list(self._fb) if self._fb is not None else None

    def _fb_oku(self) -> list[int] | None:
        if self._fs_cmd is None:
            self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_VERI_YOK, "LC_FUNCTION_STARTS yok")
            return None
        taban = self.goruntu_tabani
        off, size = self._fs_cmd
        blob = self._dosya_dilimi(off, size)
        if blob is None or taban is None:
            self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_HATA,
                            "tablo dosya dışında" if blob is None else "__TEXT bölütü yok")
            return None
        adres = taban
        out: list[int] = []
        pos = 0
        while pos < len(blob):
            r = uleb128(blob, pos)
            if r is None:
                self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_HATA, "ULEB128 kesik")
                return out
            fark, pos = r
            if fark == 0:
                break
            adres += fark
            out.append(adres)
        self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_CALISTI)
        return out

    # ---- zincirli düzeltmeler --------------------------------------------------------
    @property
    def zincirli_duzeltme(self) -> bool:
        return self._zd_cmd is not None

    def ice_aktarimlar(self) -> list[str]:
        """Zincirli içe aktarım tablosundaki adlar (sırayla); yoksa boş."""
        self.duzeltmeler()
        return list(self._ice_aktarimlar or [])

    def duzeltmeler(self) -> dict[int, Any]:
        """Düzeltme yeri → hedef (``int``) ya da ``("bag", içe aktarım sırası, ek)``.

        İlk istekte kurulur; zincirli düzeltme yoksa boş sözlük.
        """
        if self._duzeltme is None:
            self._duzeltme = {}
            self._ice_aktarimlar = []
            if self._zd_cmd is not None:
                try:
                    self._zincir_oku()
                except (struct.error, IndexError, ValueError) as exc:
                    # Zincir bozuksa hiçbir düzeltme yerine güvenilmez (ham sözcükler kodlu):
                    # sözlük boşaltılır, gosterici bu görüntüde hep None döner.
                    self._duzeltme = {}
                    self._duzeltme_bozuk = True
                    self._durum_yaz(KISIM_DUZELTME, DURUM_HATA, f"zincirli düzeltme okunamadı: {exc}")
            else:
                self._durum_yaz(KISIM_DUZELTME, DURUM_VERI_YOK, "LC_DYLD_CHAINED_FIXUPS yok")
        return self._duzeltme

    def _zincir_oku(self) -> None:
        d = self._veri
        base, size = self._zd_cmd  # type: ignore[misc]
        if base + 28 > len(d) or base + size > len(d):
            self._durum_yaz(KISIM_DUZELTME, DURUM_HATA, "zincirli düzeltme verisi dosya dışında")
            return
        _ver, starts_off, imports_off, symbols_off, imports_count, imports_format, sym_fmt = \
            struct.unpack_from("<IIIIIII", d, base)
        self._ice_aktarimlar = self._zincir_ice_aktarimlar(base, size, imports_off, symbols_off,
                                                           imports_count, imports_format, sym_fmt)
        taban = self.goruntu_tabani
        if taban is None:
            self._durum_yaz(KISIM_DUZELTME, DURUM_HATA, "__TEXT bölütü yok")
            return
        sbase = base + starts_off
        seg_count = struct.unpack_from("<I", d, sbase)[0]
        nedenler: list[str] = []
        durum = DURUM_CALISTI
        for si in range(seg_count):
            seg_info_off = struct.unpack_from("<I", d, sbase + 4 + 4 * si)[0]
            if seg_info_off == 0:
                continue
            p = sbase + seg_info_off
            _sz, page_size, pointer_format, segment_offset, _maxp, page_count = struct.unpack_from(
                "<IHHQIH", d, p)
            seg_bas = taban + segment_offset
            seg_boy = page_size * page_count
            if pointer_format not in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET):
                self._desteksiz_araliklar.append((seg_bas, seg_bas + seg_boy))
                nedenler.append(f"bölüt {si}: gösterici biçimi {pointer_format} desteklenmiyor")
                durum = DURUM_DESTEKLENMIYOR
                continue
            adim_siniri = max(1, seg_boy // _ZINCIR_ADIMI)  # sonsuz döngü koruması
            adim = 0
            for pi in range(page_count):
                start = struct.unpack_from("<H", d, p + 22 + 2 * pi)[0]
                if start == DYLD_CHAINED_PTR_START_NONE:
                    continue
                sayfa = seg_bas + pi * page_size
                if start & DYLD_CHAINED_PTR_START_MULTI:
                    self._desteksiz_araliklar.append((sayfa, sayfa + page_size))
                    nedenler.append(f"bölüt {si} sayfa {pi}: çok başlangıçlı sayfa desteklenmiyor")
                    durum = DURUM_DESTEKLENMIYOR
                    continue
                vm = sayfa + start
                while True:
                    adim += 1
                    if adim > adim_siniri:
                        raise ValueError(f"bölüt {si}: zincir adım sınırı aşıldı ({adim_siniri})")
                    ham = self.u64(vm)
                    if ham is None:
                        raise ValueError(f"düzeltme yeri {vm:#x} dosyada yok")
                    nxt = (ham >> _ZINCIR_SONRAKI_KAYMA) & _ZINCIR_SONRAKI_MASKE
                    if ham >> _ZINCIR_BAG_BITI:
                        ek = (ham >> _ZINCIR_BAG_EK_KAYMA) & 0xFF
                        self._duzeltme[vm] = ("bag", ham & _ZINCIR_BAG_SIRA_MASKE, ek)
                    else:
                        hedef = ham & _ZINCIR_HEDEF_MASKE
                        high8 = (ham >> _ZINCIR_HIGH8_KAYMA) & 0xFF
                        if pointer_format == DYLD_CHAINED_PTR_64_OFFSET:
                            hedef += taban
                        self._duzeltme[vm] = hedef | (high8 << 56)
                    if nxt == 0:
                        break
                    vm += nxt * _ZINCIR_ADIMI
        self._durum_yaz(KISIM_DUZELTME, durum, "; ".join(nedenler))

    def _zincir_ice_aktarimlar(self, base: int, size: int, imports_off: int, symbols_off: int,
                               count: int, fmt: int, sym_fmt: int) -> list[str]:
        d = self._veri
        son = base + size
        if sym_fmt != 0:
            self._durum_yaz(KISIM_DUZELTME, DURUM_DESTEKLENMIYOR, f"sembol biçimi {sym_fmt} (sıkıştırılmış)")
            return [f"#{i}" for i in range(count)]
        kayit = {DYLD_CHAINED_IMPORT: 4, DYLD_CHAINED_IMPORT_ADDEND: 8,
                 DYLD_CHAINED_IMPORT_ADDEND64: 16}.get(fmt)
        if kayit is None:
            raise ValueError(f"içe aktarım biçimi {fmt} bilinmiyor")
        if base + imports_off + kayit * count > son:
            raise ValueError("içe aktarım tablosu düzeltme verisinin dışına taşıyor")
        self._ice_ekler = []
        out = []
        for i in range(count):
            q = base + imports_off + kayit * i
            if fmt == DYLD_CHAINED_IMPORT:
                v = struct.unpack_from("<I", d, q)[0]
                ad_ofs, ek = v >> 9, 0
            elif fmt == DYLD_CHAINED_IMPORT_ADDEND:
                v, ek = struct.unpack_from("<Ii", d, q)
                ad_ofs = v >> 9
            else:
                v, ek = struct.unpack_from("<QQ", d, q)
                ad_ofs = v >> 32
            a = base + symbols_off + ad_ofs
            if a >= son:
                out.append(f"#{i}")
            else:
                e = d.find(b"\0", a, son)
                out.append(d[a:e if e >= 0 else son].decode("utf-8", "replace"))
            self._ice_ekler.append(ek)
        return out

    # ---- LC_DYLD_INFO bağları (eski düzen; göstericiler dosyada ham sanal adres) --------
    def dyld_info_baglari(self) -> dict[int, Bag]:
        """``LC_DYLD_INFO(_ONLY)`` bağ / zayıf bağ / tembel bağ yerleri → ``Bag``."""
        if self._dyld_baglar is None:
            self._dyld_baglar = {}
            if self._dyld_info is not None:
                _ro, _rs, bo, bs, wo, ws, lo, ls, _eo, _es = self._dyld_info
                try:
                    for ofs, boy, tembel in ((bo, bs, False), (wo, ws, False), (lo, ls, True)):
                        if boy:
                            self._bag_kodlari_oku(ofs, boy, tembel)
                except (struct.error, IndexError, ValueError) as exc:
                    self._durum_yaz(KISIM_DUZELTME, DURUM_HATA, f"LC_DYLD_INFO bağları okunamadı: {exc}")
                else:
                    if self._zd_cmd is None:
                        self._durum_yaz(KISIM_DUZELTME, DURUM_CALISTI, "LC_DYLD_INFO bağları")
        return dict(self._dyld_baglar)

    def _bag_kodlari_oku(self, ofs: int, boy: int, tembel: bool) -> None:
        d = self._dosya_dilimi(ofs, boy)
        if d is None:
            raise ValueError("bağ işlem kodları dosya dışında")
        gb = self.gosterici_boyutu
        sinir = max(1, sum(b["vmsize"] for b in self.bolutler) // gb)
        say = 0
        ad = ""
        ek = 0
        adres = 0
        pos = 0

        def bagla() -> None:
            nonlocal say
            say += 1
            if say > sinir:
                raise ValueError("bağ sayısı sınırı aşıldı")
            self._dyld_baglar[adres] = Bag(ad, ek)  # type: ignore[index]

        def uleb() -> int:
            nonlocal pos
            r = uleb128(d, pos)
            if r is None:
                raise ValueError("ULEB128 kesik")
            v, pos = r
            return v

        while pos < len(d):
            b = d[pos]
            pos += 1
            op, imm = b & _BIND_OPCODE_MASK, b & _BIND_IMMEDIATE_MASK
            if op == _BIND_DONE:
                if not tembel:
                    break
            elif op in (_BIND_SET_DYLIB_ORDINAL_IMM, _BIND_SET_DYLIB_SPECIAL_IMM, _BIND_SET_TYPE_IMM):
                pass
            elif op == _BIND_SET_DYLIB_ORDINAL_ULEB:
                uleb()
            elif op == _BIND_SET_SYMBOL:
                e = d.find(b"\0", pos)
                if e < 0:
                    raise ValueError("sembol adı kesik")
                ad = d[pos:e].decode("utf-8", "replace")
                pos = e + 1
            elif op == _BIND_SET_ADDEND_SLEB:
                r = sleb128(d, pos)
                if r is None:
                    raise ValueError("SLEB128 kesik")
                ek, pos = r
            elif op == _BIND_SET_SEGMENT_AND_OFFSET_ULEB:
                if imm >= len(self.bolutler):
                    raise ValueError(f"bölüt sırası {imm} yok")
                adres = (self.bolutler[imm]["vmaddr"] + uleb()) & _U64
            elif op == _BIND_ADD_ADDR_ULEB:
                adres = (adres + uleb()) & _U64
            elif op == _BIND_DO_BIND:
                bagla()
                adres = (adres + gb) & _U64
            elif op == _BIND_DO_BIND_ADD_ADDR_ULEB:
                bagla()
                adres = (adres + gb + uleb()) & _U64
            elif op == _BIND_DO_BIND_ADD_ADDR_IMM_SCALED:
                bagla()
                adres = (adres + gb + imm * gb) & _U64
            elif op == _BIND_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                kez, atla = uleb(), uleb()
                for _ in range(kez):
                    bagla()
                    adres = (adres + atla + gb) & _U64
            else:
                raise ValueError(f"bağ işlem kodu {op:#x} desteklenmiyor")

    # ---- göstericiler ----------------------------------------------------------------
    def gosterici(self, adres: int) -> int | Bag | None:
        if self._zd_cmd is not None:
            fx = self.duzeltmeler()
            if self._duzeltme_bozuk:
                return None
            e = fx.get(adres)
            if e is None:
                for bas, son in self._desteksiz_araliklar:
                    if bas <= adres < son:
                        return None  # bu aralıkta gösterici biçimi çözülemiyor: ham değer yanıltır
                v = self.u64(adres)
                return v if v else None
            if isinstance(e, int):
                return e
            _t, sira, ek = e
            imps = self._ice_aktarimlar or []
            ad = imps[sira] if sira < len(imps) else f"#{sira}"
            ek_toplam = ek + (self._ice_ekler[sira] if sira < len(self._ice_ekler) else 0)
            return Bag(ad, ek_toplam)
        if self._dyld_info is not None:
            bag = self.dyld_info_baglari().get(adres)
            if bag is not None:
                return bag
        v = self.u64(adres)
        return v if v else None

    # ---- özet ------------------------------------------------------------------------
    def ozet(self) -> dict[str, Any]:
        o = super().ozet()
        fx = self.duzeltmeler()
        o.update({
            "dilim": self.mimari,
            "dosya_turu": self.dosya_turu,
            "LC_MAIN": self.entryoff is not None,
            "LC_FUNCTION_STARTS": o["fonksiyon_baslangici"],
            "zincirli_duzeltme": self.zincirli_duzeltme,
            "duzeltme_yeri": len(fx),
            "yeniden_konumlama": sum(1 for v in fx.values() if isinstance(v, int)),
            "ice_aktarim": len(self._ice_aktarimlar or []),
            "dyld_info_bag": len(self.dyld_info_baglari()) if self._dyld_info is not None else None,
            "bagli_kitaplik": len(self.kitapliklar),
            "durum": self.durum,
        })
        return o


def dilimler(veri: bytes) -> list[dict[str, Any]]:
    """Evrensel (fat) Mach-O başlığındaki dilimler (dosya sırasıyla); fat değilse boş liste.

    Dilim adı ürünün adlandırmasıdır (``karadul.analyzers.macho._fat_arch_name``; ``lipo -archs``).
    Başlık bozuksa ``GoruntuHatasi``.
    """
    from karadul.analyzers.macho import _FAT_MAX_ARCH, _fat_arch_name, _fat_slice_rank

    if len(veri) < 8:
        return []
    magic, nfat = struct.unpack_from(">II", veri, 0)
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return []
    if not 0 < nfat <= _FAT_MAX_ARCH:
        raise GoruntuHatasi(f"evrensel başlık: dilim sayısı geçersiz ({nfat})", DURUM_DESTEKLENMIYOR)
    kayit = 32 if magic == FAT_MAGIC_64 else 20
    if 8 + kayit * nfat > len(veri):
        raise GoruntuHatasi("evrensel başlık: dilim tablosu kesik", DURUM_HATA)
    out = []
    for i in range(nfat):
        q = 8 + kayit * i
        if magic == FAT_MAGIC_64:
            cpu, sub, off, size, _al, _r = struct.unpack_from(">iiQQII", veri, q)
        else:
            cpu, sub, off, size, _al = struct.unpack_from(">iiIII", veri, q)
        out.append({"arch": _fat_arch_name(cpu, sub), "cputype": cpu, "cpusubtype": sub & 0xFFFFFFFF,
                    "offset": off, "size": size, "rank": _fat_slice_rank(cpu, sub), "index": i})
    return out


def urun_dilimi(veri: bytes) -> str | None:
    """Ürünün evrensel dosyadan seçeceği dilimin adı (``select_fat_slice``); fat değilse ``None``."""
    from karadul.analyzers.macho import select_fat_slice

    s = select_fat_slice(dilimler(veri))
    return s["arch"] if s else None


# =====================================================================================
# ELF 64 (kaynak: System V gABI; AArch64 ELF psABI; x86-64 psABI; DWARF 5 §6.4 + LSB
# .eh_frame işaretçi kodlaması)
# =====================================================================================
ELF_IMZA = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB, _ELFDATA2MSB = 1, 2
EM_X86_64 = 62
EM_AARCH64 = 183
_EM_ADLARI = {EM_X86_64: "x86_64", EM_AARCH64: "arm64"}
PT_LOAD = 1
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_RELR = 19
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_XINDEX = 0xFFFF
_STB_GLOBAL, _STB_WEAK, _STB_GNU_UNIQUE = 1, 2, 10
_STT_SECTION, _STT_FILE = 3, 4
_STV_DEFAULT, _STV_PROTECTED = 0, 3
_ELF_SYM_64 = 24
_ELF_RELA_64 = 24
_ELF_REL_64 = 16

# yeniden konumlama türleri: (göreli, sembol bağları, dolaylı işlev)
_RK_TURLERI = {
    EM_AARCH64: {"goreli": {1027}, "sembol": {257, 1025, 1026}, "dolayli": {1032}},
    EM_X86_64: {"goreli": {8}, "sembol": {1, 6, 7}, "dolayli": {37}},
}

# .eh_frame işaretçi kodlaması (DW_EH_PE_*)
_PE_OMIT = 0xFF
_PE_BICIM = 0x0F
_PE_UYGULAMA = 0x70
_PE_PCREL = 0x10
_PE_DOLAYLI = 0x80
_PE_BOYUT = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}
_PE_ISARETLI = {0x0A: "h", 0x0B: "i", 0x0C: "q"}
_PE_ISARETSIZ = {0x00: "Q", 0x02: "H", 0x03: "I", 0x04: "Q"}


class ElfGoruntu(_DosyaGoruntusu):
    """ELF 64 (küçük ya da büyük sonlu). Yeniden konumlamalar ``gosterici`` içinde çözülür."""

    def __init__(self, veri: bytes, kaynak: str = "") -> None:
        super().__init__(veri, kaynak)
        self.e_type = 0
        self.e_machine = 0
        self.e_entry = 0
        self.bolum_basligi_sayisi = 0
        self._bolumler: list[Bolum] = []
        self._shdr: list[tuple[int, ...]] = []  # (ad_ofs, tür, bayrak, adres, ofset, boy, link, info, entsize)
        self._semboller: list[Sembol] | None = None
        self._sym_tablolari: dict[int, list[tuple[str, int, int]]] = {}
        self._rk: dict[int, Any] | None = None
        self._rk_sayac: dict[str, int] = {}
        self._fb: list[int] | None = None
        self._fb_okundu = False
        self._baslik_oku()

    # ---- başlık, program ve bölüm başlıkları ------------------------------------------
    def _baslik_oku(self) -> None:
        d = self._veri
        if len(d) < 64 or d[:4] != ELF_IMZA:
            self._durum_yaz(KISIM_BASLIK, DURUM_HATA, "ELF başlığı kesik")
            return
        if d[4] != _ELFCLASS64 or d[5] not in (_ELFDATA2LSB, _ELFDATA2MSB):
            self._durum_yaz(KISIM_BASLIK, DURUM_DESTEKLENMIYOR, f"ELF sınıfı {d[4]} / veri {d[5]}")
            return
        self.bayt_sirasi = "<" if d[5] == _ELFDATA2LSB else ">"
        e = self.bayt_sirasi
        (self.e_type, self.e_machine, _v, self.e_entry, phoff, shoff, _fl, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", d, 16)
        hata = []
        eslemler = []
        if phoff and phentsize >= 56:
            for i in range(phnum):
                q = phoff + i * phentsize
                if q + 56 > len(d):
                    hata.append(f"program başlığı {i} / {phnum} kesik")
                    break
                p_type, _pf, p_off, p_vaddr, _pa, p_filesz, _pm, _al = struct.unpack_from(e + "IIQQQQQQ", d, q)
                if p_type == PT_LOAD and p_filesz:
                    eslemler.append((p_vaddr, p_vaddr + p_filesz, p_off))
        self._eslem_kur(eslemler)
        if shoff and shentsize >= 64:
            if shnum == 0 and shoff + 64 <= len(d):  # genişletilmiş numaralama: sayı 0. bölümde
                shnum = struct.unpack_from(e + "Q", d, shoff + 32)[0]
            if shstrndx == SHN_XINDEX and shoff + 64 <= len(d):
                shstrndx = struct.unpack_from(e + "I", d, shoff + 40)[0]
            self.bolum_basligi_sayisi = shnum
            for i in range(shnum):
                q = shoff + i * shentsize
                if q + 64 > len(d):
                    hata.append(f"bölüm başlığı {i} / {shnum} kesik")
                    break
                (ad_ofs, tur, bayrak, adres, ofs, boy, link, info, _al, entsize) = struct.unpack_from(
                    e + "IIQQQQIIQQ", d, q)
                self._shdr.append((ad_ofs, tur, bayrak, adres, ofs, boy, link, info, entsize))
            str_ofs = self._shdr[shstrndx][4] if shstrndx < len(self._shdr) else None
            str_boy = self._shdr[shstrndx][5] if shstrndx < len(self._shdr) else 0
            for i, (ad_ofs, tur, bayrak, adres, ofs, boy, *_r) in enumerate(self._shdr):
                if i == 0:
                    continue  # SHN_UNDEF boş bölümü
                ad = ""
                if str_ofs is not None and ad_ofs < str_boy:
                    q = str_ofs + ad_ofs
                    son = d.find(b"\0", q, min(len(d), str_ofs + str_boy))
                    ad = d[q:son if son >= 0 else min(len(d), str_ofs + str_boy)].decode("utf-8", "replace")
                dosyada = tur != SHT_NOBITS and ofs + boy <= len(d)
                self._bolumler.append(Bolum(ad, adres, boy, bool(bayrak & SHF_EXECINSTR), "",
                                            ofs if dosyada else None, bool(bayrak & SHF_ALLOC)))
        if hata:
            self._durum_yaz(KISIM_BASLIK, DURUM_HATA, "; ".join(hata))
        elif not self._shdr:
            self._durum_yaz(KISIM_BASLIK, DURUM_VERI_YOK, "bölüm başlık tablosu yok")
        else:
            self._durum_yaz(KISIM_BASLIK, DURUM_CALISTI)

    # ---- kimlik ----------------------------------------------------------------------
    @property
    def bicim(self) -> str:
        return BICIM_ELF

    @property
    def mimari(self) -> str:
        if not self.e_machine:
            return ""
        return _EM_ADLARI.get(self.e_machine, f"em_{self.e_machine}")

    @property
    def gosterici_boyutu(self) -> int:
        return 8

    @property
    def giris_adresi(self) -> int | None:
        return self.e_entry or None

    @property
    def bolumler(self) -> list[Bolum]:
        return list(self._bolumler)

    # ---- semboller -------------------------------------------------------------------
    def _bolum_bayragi(self, shndx: int) -> int | None:
        return self._shdr[shndx][2] if 0 < shndx < len(self._shdr) else None

    def _sembol_tablosu(self, sira: int) -> list[tuple[str, int, int]]:
        """Bölüm ``sira``'daki sembol tablosu: girdi başına (ad, değer, shndx); 0. girdi dahil."""
        if sira in self._sym_tablolari:
            return self._sym_tablolari[sira]
        out: list[tuple[str, int, int]] = []
        self._sym_tablolari[sira] = out
        if not 0 < sira < len(self._shdr):
            return out
        d, e = self._veri, self.bayt_sirasi
        _ad, tur, _b, _a, ofs, boy, link, _i, _es = self._shdr[sira]
        if tur not in (SHT_SYMTAB, SHT_DYNSYM):
            return out
        s_ofs = self._shdr[link][4] if 0 < link < len(self._shdr) else None
        s_son = min(len(d), s_ofs + self._shdr[link][5]) if s_ofs is not None else 0
        for i in range(boy // _ELF_SYM_64):
            q = ofs + i * _ELF_SYM_64
            if q + _ELF_SYM_64 > len(d):
                break
            st_name, _info, _other, shndx, value, _size = struct.unpack_from(e + "IBBHQQ", d, q)
            ad = ""
            if s_ofs is not None and st_name and s_ofs + st_name < s_son:
                a = s_ofs + st_name
                z = d.find(b"\0", a, s_son)
                ad = d[a:z if z >= 0 else s_son].decode("utf-8", "replace")
            out.append((ad, value, shndx))
        return out

    def semboller(self) -> list[Sembol]:
        if self._semboller is None:
            self._semboller = self._semboller_oku()
        return list(self._semboller)

    def _semboller_oku(self) -> list[Sembol]:
        d, e = self._veri, self.bayt_sirasi
        out: list[Sembol] = []
        tablolar = [i for i, h in enumerate(self._shdr) if h[1] in (SHT_SYMTAB, SHT_DYNSYM)]
        if not tablolar:
            self._durum_yaz(KISIM_SEMBOL, DURUM_VERI_YOK, ".symtab / .dynsym yok")
            return out
        kesik = False
        for sira in tablolar:
            tablo_adi = self._bolumler[sira - 1].ad if sira - 1 < len(self._bolumler) else ""
            girdiler = self._sembol_tablosu(sira)
            ofs, boy = self._shdr[sira][4], self._shdr[sira][5]
            if len(girdiler) < boy // _ELF_SYM_64:
                kesik = True
            for i, (ad, value, shndx) in enumerate(girdiler):
                if i == 0:
                    continue  # STN_UNDEF boş girdi
                _n, info, other, _sh, _v, size = struct.unpack_from(e + "IBBHQQ", d, ofs + i * _ELF_SYM_64)
                bag_, tip = info >> 4, info & 0xF
                if shndx == SHN_UNDEF:
                    tur = SEMBOL_TANIMSIZ
                elif shndx == SHN_ABS:
                    tur = SEMBOL_MUTLAK
                elif tip in (_STT_SECTION, _STT_FILE):
                    tur = SEMBOL_DIGER
                elif shndx == SHN_COMMON:
                    tur = SEMBOL_VERI
                else:
                    bayrak = self._bolum_bayragi(shndx)
                    tur = SEMBOL_KOD if bayrak is not None and bayrak & SHF_EXECINSTR else SEMBOL_VERI
                disa = bag_ in (_STB_GLOBAL, _STB_WEAK, _STB_GNU_UNIQUE) and (other & 3) in (
                    _STV_DEFAULT, _STV_PROTECTED)
                out.append(Sembol(ad, value, tur, disa, size, tablo_adi))
        if kesik:
            self._durum_yaz(KISIM_SEMBOL, DURUM_HATA, "sembol tablosu kesik")
        else:
            self._durum_yaz(KISIM_SEMBOL, DURUM_CALISTI)
        return out

    # ---- yeniden konumlama -----------------------------------------------------------
    def yeniden_konumlamalar(self) -> dict[int, Any]:
        """Yer → hedef (``int``), ``Bag`` ya da ``None`` (statik çözülemez: dolaylı işlev / bilinmeyen tür).

        Yalnız yüklenen (``SHF_ALLOC``) ``SHT_RELA`` / ``SHT_REL`` / ``SHT_RELR`` tabloları
        (dinamik bağlayıcının uyguladıkları). İlk istekte kurulur.
        """
        if self._rk is None:
            self._rk = {}
            self._rk_sayac = {"goreli": 0, "bag": 0, "tanimli_sembol": 0, "dolayli": 0,
                              "bilinmeyen": 0, "toplam": 0}
            try:
                self._rk_oku()
            except (struct.error, IndexError, ValueError) as exc:
                self._rk = {}
                self._durum_yaz(KISIM_DUZELTME, DURUM_HATA, f"yeniden konumlama okunamadı: {exc}")
        return self._rk

    def _rk_oku(self) -> None:
        d, e = self._veri, self.bayt_sirasi
        turler = _RK_TURLERI.get(self.e_machine)
        tablolar = [h for h in self._shdr if h[1] in (SHT_RELA, SHT_REL, SHT_RELR) and h[2] & SHF_ALLOC]
        if not tablolar:
            self._durum_yaz(KISIM_DUZELTME, DURUM_VERI_YOK, "yüklenen yeniden konumlama tablosu yok")
            return
        if turler is None:
            self._durum_yaz(KISIM_DUZELTME, DURUM_DESTEKLENMIYOR, f"mimari {self.mimari}")
            return
        sayac = self._rk_sayac
        for _ad, tur, _b, _a, ofs, boy, link, _i, _es in tablolar:
            if ofs + boy > len(d):
                raise ValueError("yeniden konumlama tablosu dosya dışında")
            if tur == SHT_RELR:
                self._relr_oku(ofs, boy)
                continue
            rela = tur == SHT_RELA
            kayit = _ELF_RELA_64 if rela else _ELF_REL_64
            semboller = self._sembol_tablosu(link)
            for i in range(boy // kayit):
                q = ofs + i * kayit
                if rela:
                    yer, info, r_addend = struct.unpack_from(e + "QQq", d, q)
                else:
                    yer, info = struct.unpack_from(e + "QQ", d, q)
                    r_addend = 0
                sayac["toplam"] += 1
                rtur, sym = info & 0xFFFFFFFF, info >> 32
                ek = r_addend if rela else (self.sozcuk(yer) or 0)
                if rtur in turler["goreli"]:
                    self._rk[yer] = ek & _U64
                    sayac["goreli"] += 1
                elif rtur in turler["sembol"]:
                    if sym == 0:
                        self._rk[yer] = ek & _U64
                        sayac["tanimli_sembol"] += 1
                    elif sym < len(semboller):
                        ad, deger, shndx = semboller[sym]
                        if shndx == SHN_UNDEF:
                            self._rk[yer] = Bag(ad, ek)
                            sayac["bag"] += 1
                        else:
                            self._rk[yer] = (deger + ek) & _U64
                            sayac["tanimli_sembol"] += 1
                    else:
                        self._rk[yer] = None
                        sayac["bilinmeyen"] += 1
                elif rtur in turler["dolayli"]:
                    self._rk[yer] = None  # IRELATIVE: değer çözücü işlevin çalışmasıyla belli olur
                    sayac["dolayli"] += 1
                else:
                    self._rk[yer] = None
                    sayac["bilinmeyen"] += 1
        neden = f"bilinmeyen tür {sayac['bilinmeyen']}" if sayac["bilinmeyen"] else ""
        self._durum_yaz(KISIM_DUZELTME, DURUM_CALISTI, neden)

    def _relr_oku(self, ofs: int, boy: int) -> None:
        d, e = self._veri, self.bayt_sirasi
        taban = 0
        for i in range(boy // 8):
            w = struct.unpack_from(e + "Q", d, ofs + 8 * i)[0]
            if w & 1 == 0:
                yerler = [w]
                taban = w + 8
            else:
                yerler = [taban + 8 * (b - 1) for b in range(1, 64) if (w >> b) & 1]
                taban += 63 * 8
            for yer in yerler:
                v = self.sozcuk(yer)
                if v is None:
                    raise ValueError(f"RELR yeri {yer:#x} dosyada yok")
                self._rk[yer] = v  # örtük ek: dosyadaki sözcük (yükleme tabanı 0)
                self._rk_sayac["goreli"] += 1
                self._rk_sayac["toplam"] += 1

    # ---- göstericiler ----------------------------------------------------------------
    def gosterici(self, adres: int) -> int | Bag | None:
        rk = self.yeniden_konumlamalar()
        if adres in rk:
            v = rk[adres]
            return v if v != 0 else None
        w = self.sozcuk(adres)
        return w if w else None

    # ---- .eh_frame FDE başlangıçları --------------------------------------------------
    def fonksiyon_baslangiclari(self) -> list[int] | None:
        if not self._fb_okundu:
            self._fb_okundu = True
            b = self.bolum_adli(".eh_frame")
            if b is None or b.dosya_ofseti is None:
                self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_VERI_YOK, ".eh_frame yok")
                self._fb = None
            else:
                self._fb = self._eh_frame_oku(b)
        return list(self._fb) if self._fb is not None else None

    def _isaretci_oku(self, veri: bytes, pos: int, kod: int, alan_adresi: int) -> tuple[int, int] | None:
        """DW_EH_PE kodlu değeri oku: ``(değer, yeni konum)``; desteklenmeyen kodlamada ``None``."""
        if kod == _PE_OMIT or kod & _PE_DOLAYLI:
            return None
        bicim = kod & _PE_BICIM
        if bicim == 0x01:
            r = uleb128(veri, pos)
        elif bicim == 0x09:
            r = sleb128(veri, pos)
        elif bicim in _PE_BOYUT:
            boy = _PE_BOYUT[bicim]
            if pos + boy > len(veri):
                return None
            harf = _PE_ISARETLI.get(bicim) or _PE_ISARETSIZ[bicim]
            r = (struct.unpack_from(self.bayt_sirasi + harf, veri, pos)[0], pos + boy)
        else:
            return None
        if r is None:
            return None
        deger, yeni = r
        uyg = kod & _PE_UYGULAMA
        if uyg == _PE_PCREL:
            deger += alan_adresi
        elif uyg != 0:
            return None  # textrel / datarel / funcrel / aligned: bağlamsız çözülmez
        return deger & _U64, yeni

    def _cie_oku(self, veri: bytes, bas: int, son: int) -> int | None:
        """CIE'nin FDE işaretçi kodlaması ('R'); yoksa mutlak (0); okunamazsa ``None``."""
        pos = bas
        if pos >= son:
            return None
        surum = veri[pos]
        pos += 1
        z = veri.find(b"\0", pos, son)
        if z < 0:
            return None
        art = veri[pos:z].decode("ascii", "replace")
        pos = z + 1
        if "eh" in art:
            pos += self.gosterici_boyutu
        for oku in (uleb128, sleb128):
            r = oku(veri, pos, son)
            if r is None:
                return None
            pos = r[1]
        if surum == 1:
            pos += 1
        else:
            r = uleb128(veri, pos, son)
            if r is None:
                return None
            pos = r[1]
        kod = 0
        if art.startswith("z"):
            r = uleb128(veri, pos, son)
            if r is None:
                return None
            pos = r[1]
            for ch in art[1:]:
                if pos >= son:
                    return None
                if ch == "R":
                    kod = veri[pos]
                    pos += 1
                elif ch == "L":
                    pos += 1
                elif ch == "P":
                    pk = veri[pos]
                    r2 = self._isaretci_oku(veri, pos + 1, pk & ~_PE_DOLAYLI & 0xFF, 0)
                    if r2 is None:
                        return None
                    pos = r2[1]
                elif ch in "SBG":
                    continue
                else:
                    return kod
        return kod

    def _eh_frame_oku(self, b: Bolum) -> list[int] | None:
        veri = self.bolum_baytlari(b)
        if veri is None:
            self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_HATA, ".eh_frame dosya dışında")
            return None
        e = self.bayt_sirasi
        cieler: dict[int, int | None] = {}
        out: set[int] = set()
        pos = 0
        sorun = ""
        while pos + 4 <= len(veri):
            uzunluk = struct.unpack_from(e + "I", veri, pos)[0]
            if uzunluk == 0:
                break  # sonlandırıcı
            if uzunluk == 0xFFFFFFFF:
                if pos + 12 > len(veri):
                    sorun = "64 bit uzunluk kesik"
                    break
                uzunluk = struct.unpack_from(e + "Q", veri, pos + 4)[0]
                bas, kimlik_boy = pos + 12, 8
            else:
                bas, kimlik_boy = pos + 4, 4
            son = bas + uzunluk
            if son > len(veri) or uzunluk < kimlik_boy:
                sorun = f"kayıt {pos:#x} bölüm dışına taşıyor"
                break
            kimlik = struct.unpack_from(e + ("Q" if kimlik_boy == 8 else "I"), veri, bas)[0]
            if kimlik == 0:
                cieler[pos] = self._cie_oku(veri, bas + kimlik_boy, son)
            else:
                cie_pos = bas - kimlik
                if cie_pos not in cieler and 0 <= cie_pos < len(veri):
                    cu = struct.unpack_from(e + "I", veri, cie_pos)[0]
                    cb = cie_pos + (12 if cu == 0xFFFFFFFF else 4)
                    cs = cb + (struct.unpack_from(e + "Q", veri, cie_pos + 4)[0] if cu == 0xFFFFFFFF else cu)
                    cieler[cie_pos] = self._cie_oku(veri, cb + kimlik_boy, min(cs, len(veri)))
                kod = cieler.get(cie_pos)
                alan = bas + kimlik_boy
                r = None if kod is None else self._isaretci_oku(veri, alan, kod, b.adres + alan)
                if r is None:
                    sorun = f"FDE {pos:#x}: işaretçi kodlaması çözülemedi"
                elif r[0]:
                    out.add(r[0])
            pos = son
        if sorun:
            self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_HATA, sorun)
        else:
            self._durum_yaz(KISIM_FONKSIYON_BASLANGICI, DURUM_CALISTI)
        return sorted(out)

    # ---- özet ------------------------------------------------------------------------
    def ozet(self) -> dict[str, Any]:
        o = super().ozet()
        self.yeniden_konumlamalar()
        tablolar: dict[str, int] = {}
        for s in self.semboller():
            tablolar[s.tablo] = tablolar.get(s.tablo, 0) + 1
        o.update({
            "e_type": self.e_type,
            "bolum_basligi": self.bolum_basligi_sayisi,
            "sembol_tablolari": tablolar,
            "yeniden_konumlama": self._rk_sayac.get("goreli", 0),
            "bag": self._rk_sayac.get("bag", 0),
            "yeniden_konumlama_kaydi": self._rk_sayac.get("toplam", 0),
            "yeniden_konumlama_sayac": dict(self._rk_sayac),
            "durum": self.durum,
        })
        return o


# --- giriş noktaları -----------------------------------------------------------------------

def baytlardan(veri: bytes, dilim: str | None = None, kaynak: str = "") -> Goruntu:
    """Dosya baytlarından görüntü kur (biçimi imzadan tanır).

    Evrensel (fat) Mach-O verilirse ``dilim`` (``arm64``, ``x86_64`` …) zorunludur.
    Biçim tanınmazsa ``GoruntuHatasi(durum="desteklenmiyor")``.
    """
    return _bicim_sec(bytes(veri), dilim, kaynak)


def ac(yol: str | Path, dilim: str | None = None) -> Goruntu:
    """Dosyadan görüntü kur (bkz. ``baytlardan``). Dosya okunamazsa ``GoruntuHatasi``."""
    p = Path(yol)
    try:
        veri = p.read_bytes()
    except OSError as exc:
        raise GoruntuHatasi(f"dosya okunamadı: {exc}", DURUM_HATA) from exc
    return _bicim_sec(veri, dilim, str(p))


def _bicim_sec(veri: bytes, dilim: str | None, kaynak: str) -> Goruntu:
    if len(veri) < 4:
        raise GoruntuHatasi("dosya imza için çok kısa", DURUM_DESTEKLENMIYOR)
    be = struct.unpack_from(">I", veri, 0)[0]
    le = struct.unpack_from("<I", veri, 0)[0]
    if be in (FAT_MAGIC, FAT_MAGIC_64):
        sl = dilimler(veri)
        adlar = [s["arch"] for s in sl]
        if dilim is None:
            raise GoruntuHatasi(f"evrensel dosya: dilim adı zorunlu ({', '.join(adlar)})", DURUM_HATA)
        secilen = [s for s in sl if s["arch"] == dilim]
        if not secilen:
            raise GoruntuHatasi(f"evrensel dosyada {dilim} dilimi yok ({', '.join(adlar)})", DURUM_VERI_YOK)
        s = secilen[0]
        ic = veri[s["offset"]:s["offset"] + s["size"]]  # kesik dosyada eldeki kadar
        if len(ic) < 4 or struct.unpack_from("<I", ic, 0)[0] != MH_MAGIC_64:
            raise GoruntuHatasi(f"{dilim} dilimi Mach-O 64 değil ya da kesik", DURUM_DESTEKLENMIYOR)
        return MachO64Goruntu(ic, f"{kaynak}[{dilim}]")
    if le == MH_MAGIC_64:
        g = MachO64Goruntu(veri, kaynak)
        if dilim is not None and g.mimari != dilim:
            raise GoruntuHatasi(f"ince dosyanın dilimi {g.mimari}, istenen {dilim}", DURUM_VERI_YOK)
        return g
    if le == MH_MAGIC or be in (MH_MAGIC_64, MH_MAGIC):
        raise GoruntuHatasi("32 bit ya da büyük sonlu Mach-O desteklenmiyor", DURUM_DESTEKLENMIYOR)
    if veri[:4] == ELF_IMZA:
        if len(veri) > 4 and veri[4] != _ELFCLASS64:
            raise GoruntuHatasi("32 bit ELF desteklenmiyor", DURUM_DESTEKLENMIYOR)
        return ElfGoruntu(veri, kaynak)
    raise GoruntuHatasi(f"biçim tanınmadı (imza {veri[:4].hex()})", DURUM_DESTEKLENMIYOR)


# --- yerel doğrulama girdisi (kalem 7) -------------------------------------------------------

def ozet_cikar(yol: str | Path, dilim: str | None = None) -> dict[str, Any]:
    """Dosyanın (evrensel dosyada ``dilim``'in) özet sözlüğü; kurulamazsa durum + neden."""
    try:
        g = ac(yol, dilim)
    except GoruntuHatasi as exc:
        return {"ikili": str(yol), "dilim": dilim, "durum": exc.durum, "neden": exc.neden}
    o = g.ozet()
    o["ikili"] = str(yol)
    return o


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        prog="python -m karadul.analyzers.ustveri.goruntu",
        description="İkili görüntü özeti (bölüm, sembol, fonksiyon başlangıcı, düzeltme yeri, "
                    "yeniden konumlama, içe aktarım). İkili çalıştırılmaz.")
    ap.add_argument("ikili")
    ap.add_argument("--dilim", help="evrensel Mach-O'da dilim adı (arm64, x86_64 …); "
                                    "verilmezse bütün dilimler")
    a = ap.parse_args(argv)
    if a.dilim is None:
        try:
            sl = dilimler(Path(a.ikili).read_bytes())
        except (OSError, GoruntuHatasi) as exc:
            print(json.dumps({"ikili": a.ikili, "durum": DURUM_HATA, "neden": str(exc)},
                             ensure_ascii=False, indent=1))
            return 1
        if sl:
            print(json.dumps([ozet_cikar(a.ikili, s["arch"]) for s in sl], ensure_ascii=False, indent=1))
            return 0
    o = ozet_cikar(a.ikili, a.dilim)
    print(json.dumps(o, ensure_ascii=False, indent=1))
    return 0 if "bicim" in o else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
