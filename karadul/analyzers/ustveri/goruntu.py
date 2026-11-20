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
    """

    ad: str
    adres: int
    boyut: int
    kod: bool
    bolut: str = ""
    dosya_ofseti: int | None = None

    @property
    def tam_ad(self) -> str:
        return f"{self.bolut},{self.ad}" if self.bolut else self.ad

    def icerir(self, adres: int) -> bool:
        return self.adres <= adres < self.adres + self.boyut


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
    # Biçim uygulamaları (Mach-O 64, evrensel, ELF 64, PE) sonraki kalemlerde gelir.
    raise GoruntuHatasi("biçim okuyucusu henüz yok", DURUM_DESTEKLENMIYOR)
