"""Go tip verisi okuyucu: itab'lar, somut tipler, yöntem tabloları (P-ÜV7; ÜST VERİ hattı).

Amaç: ``pclntab`` adını, çalışma için zorunlu ikinci bir yapıyla karşılaştırmak (tutarlılık
denetimi ``tutarlilik.py``). Bu modül yalnız tip verisini okur; karar vermez. Ghidra'sız, yalnız
ikili görüntünün baytları (P-ÜV0 ``Goruntu`` arayüzü). İkili çalıştırılmaz.

Biçim kaynağı (resmî Go kaynak ağacı, dal ``release-branch.go1.27``; ARGE turunda 2026-11-19'da
okundu, ``docs/arge/2026-11-19_mythos/ustveri/PLAN.md`` "P-ÜV7 / Biçim"):

- ``src/internal/abi/type.go``: ``Type`` 48 bayt (``TFlag`` +20: bit 0 ``Uncommon``, bit 1
  ``ExtraStar``; ``Kind_`` +23; ``Str`` +40; ``PtrToThis`` +44); ``UncommonType`` (paket yolu i32,
  yöntem sayısı u16, dışa açık u16, ``Moff`` u32, boş u32) türe özgü yapının ardında (yapı 80,
  gösterici 56, dilim 56, dizi 72, kanal 64, arayüz 80, öbürleri 48; eşlem ve fonksiyon türleri
  atlanır); ``Method`` 16 bayt (ad, tip, ``Ifn``, ``Tfn``; metin ofseti −1 / 0 = yok);
  ``InterfaceType``: yöntem dilimi +56 (gösterici) / +64 (uzunluk), ``Imethod`` 8 bayt; ad
  kodlaması: bayrak baytı, değişken uzunluk, baytlar.
- ``src/runtime/iface.go``: itab = arayüz, tip, karma u32 (+ dolgu), ``Fun[]`` +24; boyut
  ``24 + 8 × max(yöntem sayısı, 1)``. 1.27: itab'lar ``types + itaboffset``, uzunluk
  ``itabsize``; 1.26 ve öncesi: ``__itablink`` / ``.itablink`` bölümü (itab göstericileri),
  ``__typelink`` / ``.typelink`` (tip ofsetleri).
- ``src/runtime/symtab.go``: ``moduledata`` sözcük sırası — 37 ``types``; 1.27'de 38
  ``typedesclen``, 39 ``etypes``, 40 ``itaboffset``, 41 ``itabsize``; 1.20–1.26'da 38 ``etypes``
  (``covctrs`` 1.20'de eklendi; 1.18–1.19'da sözcük sırası farklıdır → desteklenmiyor).

Başka sürüm görülürse (sürüm okunamıyor, 1.20'den eski ya da 1.27'den yeni) tahmin edilmez:
durum ``desteklenmiyor`` + neden; denetimin ikinci kaynağı olmaz (adlar ``tek_kaynak`` kalır).

Başvuru (araştırma) betiği: ``scripts/arge/ustveri/go_tip.py``; bu modül ondan yeniden yazıldı
(sınır denetimleri, durum sözlüğü, sürüm kapısı eklendi).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Any

from karadul.analyzers.ustveri.goruntu import (
    DURUM_CALISTI,
    DURUM_DESTEKLENMIYOR,
    DURUM_VERI_YOK,
)

# ---------------------------------------------------------------------------
# Biçim sabitleri
# ---------------------------------------------------------------------------

TIP_BOYU = 48
KIND_MASKESI = 0x1F
TFLAG_UNCOMMON = 1 << 0
TFLAG_EXTRA_STAR = 1 << 1

KIND_ARRAY = 17
KIND_CHAN = 18
KIND_FUNC = 19
KIND_INTERFACE = 20
KIND_MAP = 21
KIND_POINTER = 22
KIND_SLICE = 23
KIND_STRUCT = 25
KIND_EN_BUYUK = 26          # UnsafePointer

# ``Uncommon()``: türe özgü yapının boyu (64 bit). Eşlem ve fonksiyon türü atlanır (yerleşim sürüme
# bağlı; ``Uncommon()``'ın fonksiyon dalı parametre dizisini de hesaba katar).
UNCOMMON_OFSETI = {
    KIND_STRUCT: 80,
    KIND_POINTER: 56,
    KIND_SLICE: 56,
    KIND_ARRAY: 72,
    KIND_CHAN: 64,
    KIND_INTERFACE: 80,
}
ATLANAN_TURLER = frozenset({KIND_FUNC, KIND_MAP})

UNCOMMON_BOYU = 16
YONTEM_BOYU = 16
IMETHOD_BOYU = 8
ITAB_BASLIK_BOYU = 24
ARAYUZ_YONTEM_GOSTERICISI = 56   # InterfaceType.Methods dilimi: gösterici +56, uzunluk +64
ARAYUZ_YONTEM_UZUNLUGU = 64
GOSTERICI_OGESI = 48            # PtrType.Elem

METIN_OFSETI_YOK = frozenset({-1, 0})   # Method.Ifn / Tfn: −1 budanmış, 0 yok

# Akıl sağlığı üst sınırları (bozuk tablo sonsuz yürüyüş / dev okuma yapmasın).
AZAMI_YONTEM = 4096
AZAMI_MOFF = 1 << 20
AZAMI_AD_UZUNLUGU = 1 << 16
AZAMI_ITAB = 1 << 20

# moduledata sözcükleri (64 bit; PLAN "P-ÜV1 / Biçim", "P-ÜV7 / Biçim").
MD_TYPES = 37
MD_ETYPES_126 = 38              # 1.20–1.26
MD_TYPEDESCLEN_127 = 38
MD_ETYPES_127 = 39
MD_ITABOFFSET_127 = 40
MD_ITABSIZE_127 = 41

EN_KUCUK_SURUM = 20             # Go 1.20 (covctrs ile sözcük sırası sabitlendi)
EN_BUYUK_SURUM = 27             # Go 1.27 (resmî kaynaktan okunan en yeni yerleşim)
ITAB_TABLOSU_SURUMU = 27        # 1.27+: itab'lar types + itaboffset

ITABLINK_BOLUMLERI = ("__itablink", ".itablink")
TYPELINK_BOLUMLERI = ("__typelink", ".typelink")

ITAB_KAYNAGI_TABLO = "moduledata.itaboffset"
ITAB_KAYNAGI_ITABLINK = "itablink"

_SURUM_RE = re.compile(r"^go1\.(\d+)(?:\D|$)")


# ---------------------------------------------------------------------------
# Veri yapıları
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoYontem:
    """Somut tipin yöntem tablosu girdisi (``abi.Method``)."""

    ad: str | None
    ad_ofseti: int
    ifn: int | None         # arayüz çağrısı gövdesi (sanal adres); yok / budanmış → None
    tfn: int | None         # olağan yöntem gövdesi


@dataclass
class GoItab:
    adres: int
    arayuz: int                                 # InterfaceType adresi
    tip: int                                    # somut tip adresi
    yontemler: list[tuple[str | None, int]]     # arayüz yöntemleri (ad, ad ofseti)
    fun: list[int | None]                       # Fun[i] (sanal adres; okunamayan None)


@dataclass
class GoUncommon:
    paket: str | None
    yontemler: list[GoYontem] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def kucuk_surum(surum: str | None) -> int | None:
    """``go1.27.4`` → 27; okunamıyorsa None."""
    if not surum:
        return None
    m = _SURUM_RE.match(surum.strip())
    return int(m.group(1)) if m else None


def _gosterici(g: Any, adres: int) -> int | None:
    try:
        v = g.gosterici(adres)
    except Exception:  # noqa: BLE001 - bozuk görüntüde okuyucu durmaz
        return None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _oku(g: Any, adres: int, n: int) -> bytes | None:
    if adres is None or n < 0:
        return None
    try:
        b = g.oku(adres, n)
    except Exception:  # noqa: BLE001
        return None
    return bytes(b) if b is not None else None


def _u64(g: Any, adres: int) -> int | None:
    b = _oku(g, adres, 8)
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


# ---------------------------------------------------------------------------
# Okuyucu
# ---------------------------------------------------------------------------


class GoTipVerisi:
    """Bir Go modülünün tip verisi. Kurucu istisna atmaz: ``durum`` / ``neden`` alanına yazar.

    ``goruntu``: P-ÜV0 ``Goruntu``; ``pcln``: ``go_pclntab.GoPclntab`` (metin tabanı ve
    ``moduledata`` adresi oradan); ``surum``: ``buildinfo`` sürüm dizgisi (``go1.27.4``).
    """

    def __init__(self, goruntu: Any, pcln: Any, surum: str | None) -> None:
        self.g = goruntu
        self.surum = surum
        self.kucuk = kucuk_surum(surum)
        self.text: int = getattr(pcln, "text", 0) or 0
        self.types: int | None = None
        self.etypes: int | None = None
        self.itab_araligi: tuple[int, int] | None = None
        self.itab_kaynagi: str | None = None
        self.durum = DURUM_CALISTI
        self.neden = ""
        md = getattr(pcln, "md", None) or {}
        mda = md.get("adres")
        if self.kucuk is None:
            self._dur(DURUM_DESTEKLENMIYOR, f"Go sürümü okunamadı ({surum!r}); tip yerleşimi tahmin edilmez")
            return
        if not EN_KUCUK_SURUM <= self.kucuk <= EN_BUYUK_SURUM:
            self._dur(DURUM_DESTEKLENMIYOR,
                      f"Go 1.{self.kucuk}: tip verisi yerleşimi yalnız 1.{EN_KUCUK_SURUM}–1.{EN_BUYUK_SURUM} "
                      "için doğrulandı")
            return
        if mda is None:
            self._dur(DURUM_VERI_YOK, "moduledata yok")
            return
        self.types = _gosterici(goruntu, mda + 8 * MD_TYPES)
        if self.kucuk >= ITAB_TABLOSU_SURUMU:
            self.etypes = _gosterici(goruntu, mda + 8 * MD_ETYPES_127)
            itaboff = _u64(goruntu, mda + 8 * MD_ITABOFFSET_127)
            itabsize = _u64(goruntu, mda + 8 * MD_ITABSIZE_127)
            if self.types is not None and itaboff is not None and itabsize is not None:
                bas = self.types + itaboff
                self.itab_araligi = (bas, bas + itabsize)
            self.itab_kaynagi = ITAB_KAYNAGI_TABLO
        else:
            self.etypes = _gosterici(goruntu, mda + 8 * MD_ETYPES_126)
            self.itab_kaynagi = ITAB_KAYNAGI_ITABLINK
        if self.types is None or self.etypes is None or not self.types < self.etypes:
            self._dur(DURUM_DESTEKLENMIYOR,
                      f"moduledata types / etypes akıl dışı ({self.types!r}, {self.etypes!r})")
            return
        if self.itab_araligi is not None:
            bas, son = self.itab_araligi
            if not (self.types <= bas <= son <= self.etypes):
                self._dur(DURUM_DESTEKLENMIYOR,
                          f"itab aralığı types…etypes dışında ({bas:#x}…{son:#x})")
                self.itab_araligi = None
                return
        elif self.kucuk >= ITAB_TABLOSU_SURUMU:
            self._dur(DURUM_DESTEKLENMIYOR, "1.27 itaboffset / itabsize okunamadı")

    def _dur(self, durum: str, neden: str) -> None:
        self.durum = durum
        self.neden = neden

    @property
    def calisti(self) -> bool:
        return self.durum == DURUM_CALISTI

    def ozet(self) -> dict[str, Any]:
        return {
            "durum": self.durum,
            "neden": self.neden,
            "surum": self.surum,
            "kucuk_surum": self.kucuk,
            "types": hex(self.types) if self.types is not None else None,
            "etypes": hex(self.etypes) if self.etypes is not None else None,
            "itab_kaynagi": self.itab_kaynagi,
        }

    # ---- adlar ----------------------------------------------------------
    def ad_ayrintili(self, adres: int) -> tuple[str, int, int] | None:
        """``adres``'teki kodlanmış ad: (ad, ad baytlarının adresi, bayt uzunluğu); okunamazsa None.

        Kodlama: bayrak baytı, değişken uzunluklu boy (en çok 4 bayt), baytlar.
        """
        n = 0
        kayma = 0
        i = 1
        while True:
            b = _oku(self.g, adres + i, 1)
            if not b:
                return None
            c = b[0]
            n |= (c & 0x7F) << kayma
            i += 1
            if not c & 0x80:
                break
            kayma += 7
            if kayma > 28:
                return None
        if n > AZAMI_AD_UZUNLUGU:
            return None
        ham = _oku(self.g, adres + i, n)
        if ham is None:
            return None
        return ham.decode("utf-8", "replace"), adres + i, n

    def ad(self, ofset: int) -> str | None:
        """``types + ofset`` adresindeki ad (``NameOff``); ofset ≤ 0 → None."""
        if ofset is None or ofset <= 0 or self.types is None:
            return None
        r = self.ad_ayrintili(self.types + ofset)
        return r[0] if r else None

    # ---- tipler ---------------------------------------------------------
    def tip_basligi(self, t: int) -> dict[str, int] | None:
        b = _oku(self.g, t, TIP_BOYU)
        if not b or len(b) < TIP_BOYU:
            return None
        tflag = b[20]
        kind = b[23] & KIND_MASKESI
        strr, ptt = struct.unpack_from("<ii", b, 40)
        return {"tflag": tflag, "kind": kind, "str": strr, "ptr_to_this": ptt}

    def tip_adi(self, t: int) -> str | None:
        h = self.tip_basligi(t)
        if not h:
            return None
        s = self.ad(h["str"])
        if s and h["tflag"] & TFLAG_EXTRA_STAR and s.startswith("*"):
            s = s[1:]
        return s

    def metin_adresi(self, ofset: int) -> int | None:
        """``TextOff`` → sanal adres (tek metin bölümü: ``text + ofset``); −1 / 0 → None."""
        if ofset in METIN_OFSETI_YOK:
            return None
        return self.text + ofset

    def uncommon(self, t: int) -> GoUncommon | None:
        """Somut tipin paket yolu ve yöntem tablosu; yoksa / okunamazsa None."""
        if not self.calisti:
            return None
        h = self.tip_basligi(t)
        if not h or not h["tflag"] & TFLAG_UNCOMMON:
            return None
        k = h["kind"]
        if k in ATLANAN_TURLER:
            return None
        u = t + UNCOMMON_OFSETI.get(k, TIP_BOYU)
        b = _oku(self.g, u, UNCOMMON_BOYU)
        if not b or len(b) < UNCOMMON_BOYU:
            return None
        pkgpath, mcount, _xcount, moff, _bos = struct.unpack("<iHHII", b)
        if mcount > AZAMI_YONTEM or moff > AZAMI_MOFF:
            return None
        paket = self.ad(pkgpath) if pkgpath > 0 else None
        if not mcount:
            return GoUncommon(paket, [])
        mb = _oku(self.g, u + moff, YONTEM_BOYU * mcount)
        if mb is None:
            return None
        out = []
        for i in range(mcount):
            ad_off, _mtyp, ifn, tfn = struct.unpack_from("<iiii", mb, YONTEM_BOYU * i)
            out.append(GoYontem(self.ad(ad_off), ad_off, self.metin_adresi(ifn), self.metin_adresi(tfn)))
        return GoUncommon(paket, out)

    def arayuz_yontemleri(self, t: int) -> list[tuple[str | None, int]] | None:
        """Arayüz tipinin yöntemleri (ad, ad ofseti); arayüz değilse / okunamazsa None."""
        if not self.calisti:
            return None
        h = self.tip_basligi(t)
        if not h or h["kind"] != KIND_INTERFACE:
            return None
        mp = _gosterici(self.g, t + ARAYUZ_YONTEM_GOSTERICISI)
        n = _u64(self.g, t + ARAYUZ_YONTEM_UZUNLUGU)
        if n is None or n > AZAMI_YONTEM:
            return None
        if n == 0:
            return []
        if mp is None:
            return None
        b = _oku(self.g, mp, IMETHOD_BOYU * n)
        if b is None:
            return None
        out = []
        for i in range(n):
            ad_off = struct.unpack_from("<i", b, IMETHOD_BOYU * i)[0]
            out.append((self.ad(ad_off), ad_off))
        return out

    # ---- itab'lar -------------------------------------------------------
    def itab_adresleri(self) -> list[int]:
        if not self.calisti:
            return []
        adresler: list[int] = []
        if self.itab_araligi is not None:
            a, son = self.itab_araligi
            while a < son and len(adresler) < AZAMI_ITAB:
                inter = _gosterici(self.g, a)
                if inter is None:
                    break
                ms = self.arayuz_yontemleri(inter)
                if ms is None:
                    break
                adresler.append(a)
                a += ITAB_BASLIK_BOYU + 8 * max(len(ms), 1)
            return adresler
        for ad in ITABLINK_BOLUMLERI:
            for b in self.g.bolumler_adli(ad):
                for i in range(min(b.boyut // 8, AZAMI_ITAB)):
                    v = _gosterici(self.g, b.adres + 8 * i)
                    if v is not None:
                        adresler.append(v)
        return adresler

    def itablar(self) -> list[GoItab]:
        """Bütün itab'lar (arayüz yöntemleri okunamayan itab atlanır)."""
        out = []
        for a in self.itab_adresleri():
            inter = _gosterici(self.g, a)
            typ = _gosterici(self.g, a + 8)
            if inter is None or typ is None:
                continue
            ms = self.arayuz_yontemleri(inter)
            if ms is None:
                continue
            fun = [_gosterici(self.g, a + ITAB_BASLIK_BOYU + 8 * i) for i in range(len(ms))]
            out.append(GoItab(a, inter, typ, ms, fun))
        return out

    def ulasilan_tipler(self, itablar: list[GoItab]) -> set[int]:
        """itab'lardan ulaşılan tipler: itab tipi, gösterici ise öğesi, ``PtrToThis``;
        1.27'den eski sürümde ``typelink`` tipleri de."""
        if not self.calisti or self.types is None:
            return set()
        gor: set[int] = set()
        sira: list[int] = [it.tip for it in itablar]
        if self.kucuk is not None and self.kucuk < ITAB_TABLOSU_SURUMU:
            for ad in TYPELINK_BOLUMLERI:
                for b in self.g.bolumler_adli(ad):
                    blob = _oku(self.g, b.adres, b.boyut) or b""
                    for i in range(len(blob) // 4):
                        off = struct.unpack_from("<i", blob, 4 * i)[0]
                        if off > 0:
                            sira.append(self.types + off)
        while sira:
            t = sira.pop()
            if t is None or t in gor:
                continue
            h = self.tip_basligi(t)
            if not h or h["kind"] == 0 or h["kind"] > KIND_EN_BUYUK:
                continue
            gor.add(t)
            if h["kind"] == KIND_POINTER:
                e = _gosterici(self.g, t + GOSTERICI_OGESI)
                if e is not None:
                    sira.append(e)
            if h["ptr_to_this"] > 0:
                sira.append(self.types + h["ptr_to_this"])
        return gor
