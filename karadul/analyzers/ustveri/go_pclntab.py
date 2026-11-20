"""Go ``pclntab`` okuyucu (P-ÜV1; ÜST VERİ hattı).

Soyulmuş Go ikilisinde fonksiyon adresi → tam ad, kaynak dosya yolu, paket ve paket sınıfı.
Ghidra'sız: yalnız ikili görüntünün baytları (P-ÜV0 ``Goruntu`` arayüzü). İkili çalıştırılmaz.

Desteklenen biçim: Go 1.18–1.27 (``pcHeader`` imzası ``0xfffffff0`` = 1.18–1.19, ``0xfffffff1`` =
1.20+), 64 bit gösterici. Başka bir imza, 32 bit gösterici ya da bulunamayan ``moduledata`` için
okuyucu tahmin etmez: durum ``desteklenmiyor`` + neden.

Biçim kaynağı (resmî Go kaynak ağacı, dal ``release-branch.go1.26`` / ``go1.27``; ARGE turunda
2026-11-19'da okundu, ``docs/arge/2026-11-19_mythos/ustveri/PLAN.md`` "P-ÜV1 / Biçim"):

- ``src/runtime/symtab.go``: ``pcHeader``, ``moduledata``, ``functab``, ``findfuncbucket``,
  ``pcvalue``, ``step``, ``readvarint``, ``funcfile``, ``funcpkgpath``.
- ``src/runtime/runtime2.go``: ``_func``.
- ``src/internal/abi/symtab.go``: imzalar, ``FuncTabBucketSize`` 4096, ``FuncID*``.
- ``src/debug/buildinfo/buildinfo.go``: ``__go_buildinfo`` başlığı.

Go 1.26'dan başlayarak ``pcHeader``'ın eski ``textStart`` alanı 0 yazılır; metin tabanı
``moduledata.text``'ten okunur (kaynağı ``metin_tabani_kaynagi`` alanına yazılır).

Başvuru (araştırma) betikleri: ``scripts/arge/ustveri/go_pclntab.py`` ve ``go_say.py``; bu modül
onlardan yeniden yazıldı (sınır denetimleri, durum sözlüğü, hata yolları eklendi).

Okunan ad derleyicinin yazdığı hâliyle doğrudur ama doğrulanamaz (ad metni çalışma için zorunlu
değildir); bu yüzden yapı denetimleri (K1–K9) sonuca eklenir ve K1, K2, K5, K9'dan biri ihlal
veriyorsa ya da K4 ihlali fonksiyonların %1'ini aşıyorsa durum ``tutarsiz`` olur ve ad listesi
üretilmez (yalnız kanıt: neden + sayılar).
"""

from __future__ import annotations

import bisect
import collections
import math
import struct
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Biçim sabitleri
# ---------------------------------------------------------------------------

MAGIC_118 = 0xFFFFFFF0
MAGIC_120 = 0xFFFFFFF1
DESTEKLENEN_IMZALAR = {MAGIC_118: "go1.18", MAGIC_120: "go1.20+"}
# Desteklenmeyen ama tanınan eski imzalar (yalnız neden metni için).
ESKI_IMZALAR = {0xFFFFFFFB: "go1.2", 0xFFFFFFFA: "go1.16"}

PCHEADER_BOYU = 72          # imza, 2 dolgu, minLC, ptrSize, nfunc, nfiles, textStart, 5 ofset
FUNC_SABIT_BOYU = 44        # _func'un sabit kısmı
FUNC_TAB_KOVA = 4096        # abi.FuncTabBucketSize
FUNC_TAB_ALT_KOVA = 16      # findfuncbucket.subbuckets
FINDFUNC_KOVA_BOYU = 20     # idx u32 + 16 alt kova baytı
DOSYA_YOK = 0xFFFFFFFF      # cutab'da "dosya yok"
BUILDINFO_IMZA = b"\xff Go buildinf:"
FUNC_FLAG_ASM = 1 << 2      # abi.FuncFlagAsm

# moduledata sözcük sırası (64 bit; PLAN "P-ÜV1 / Biçim").
MD_PCHEADER = 0
MD_FUNCNAMETAB = 1          # 1 gösterici, 2 uzunluk, 3 sığa
MD_PCLNTABLE_UZ = 14
MD_FTAB = 16                # 16 gösterici, 17 uzunluk (= nfunc + 1), 18 sığa
MD_FINDFUNCTAB = 19
MD_MINPC = 20
MD_MAXPC = 21
MD_TEXT = 22
MD_ETEXT = 23

# pclntab bölüm adları (Mach-O ``__gopclntab``; ELF ``.gopclntab`` ya da relro ile
# ``.data.rel.ro.gopclntab``) ve buildinfo bölümleri.
PCLNTAB_BOLUMLERI = ("__gopclntab", ".gopclntab", ".data.rel.ro.gopclntab")
BUILDINFO_BOLUMLERI = ("__go_buildinfo", ".go.buildinfo")

# Karar eşiği (PLAN kalem 4): K4 ihlali fonksiyonların bu oranını aşarsa tutarsız.
K4_IHLAL_ORANI = 0.01
# Akıl sağlığı üst sınırı (imza taramasında yanlış eşleşmeyi elemek için).
AZAMI_FONKSIYON = 10_000_000

DURUM_CALISTI = "calisti"
DURUM_VERI_YOK = "veri_yok"
DURUM_DESTEKLENMIYOR = "desteklenmiyor"
DURUM_TUTARSIZ = "tutarsiz"
DURUM_KAPALI = "kapali"
DURUM_HATA = "hata"
DURUMLAR = (DURUM_CALISTI, DURUM_VERI_YOK, DURUM_DESTEKLENMIYOR, DURUM_TUTARSIZ,
            DURUM_KAPALI, DURUM_HATA)

# Paket sınıfları (PLAN kalem 2).
SINIF_KENDI = "kendi"
SINIF_UCUNCU_TARAF = "ucuncu_taraf"
SINIF_STANDART = "standart"
SINIF_CALISMA_ZAMANI = "calisma_zamani"
SINIF_DERLEYICI = "derleyici"
SINIF_PAKETSIZ = "paketsiz"
SINIF_ADSIZ = "adsiz"

# K7: Go ≤ 1.25 arm64'te Duff gövdelerinin ortasına çağrı olağandır.
DUFF_ADLARI = frozenset({"runtime.duffzero", "runtime.duffcopy"})


class GoOkumaHatasi(Exception):
    """Okuyucunun durum + neden ile durması (istisna dışarı sızmaz; ``oku`` yakalar)."""

    def __init__(self, durum: str, neden: str) -> None:
        super().__init__(f"{durum}: {neden}")
        self.durum = durum
        self.neden = neden


class _Kesik(Exception):
    """Tablo okurken sınır dışına çıkıldı."""


# ---------------------------------------------------------------------------
# Veri yapıları
# ---------------------------------------------------------------------------


@dataclass
class GoFonksiyon:
    sira: int
    giris: int              # sanal adres
    bitis: int              # sonraki girişin adresi
    func_off: int           # pclntable içindeki ofset
    name_off: int
    ad: str                 # derleyicinin yazdığı hâliyle (değiştirilmeden)
    args: int
    deferreturn: int
    pcsp: int
    pcfile: int
    pcln: int
    npcdata: int
    cu_offset: int
    baslangic_satiri: int
    func_id: int
    flag: int
    nfuncdata: int
    dosya: str | None = None
    paket: str = ""
    sinif: str = ""

    def kayit(self) -> dict[str, Any]:
        """JSON'a yazılan biçim (adresler onaltılık dizgi)."""
        return {
            "giris": hex(self.giris),
            "bitis": hex(self.bitis),
            "ad": self.ad,
            "dosya": self.dosya,
            "baslangic_satiri": self.baslangic_satiri,
            "paket": self.paket,
            "sinif": self.sinif,
            "func_id": self.func_id,
            "flag": self.flag,
        }


@dataclass
class GoSonuc:
    durum: str
    neden: str = ""
    fonksiyonlar: list[GoFonksiyon] = field(default_factory=list)
    buildinfo: dict[str, Any] | None = None
    butunluk: dict[str, Any] = field(default_factory=dict)
    pclntab: dict[str, Any] = field(default_factory=dict)
    sayim: dict[str, Any] = field(default_factory=dict)
    sure_sn: float | None = None


# ---------------------------------------------------------------------------
# Görüntü erişimi (P-ÜV0 ``Goruntu`` arayüzü; yalnız arayüz yöntemleri kullanılır)
# ---------------------------------------------------------------------------


def _bolumler(g: Any) -> list[tuple[str, int, int, bool]]:
    """``Goruntu.bolumler`` → (ad, adres, boyut, kod mu) demetleri (``Bolum.ad`` kısa addır)."""
    return [(b.ad, b.adres, b.boyut, b.kod) for b in g.bolumler]


def _kod_bolumleri(g: Any) -> list[tuple[str, int, int, bool]]:
    return [(b.ad, b.adres, b.boyut, True) for b in g.kod_bolumleri]


def _gosterici(g: Any, adres: int) -> int | None:
    """Göstericiyi çöz; içe aktarım bağı (``Bag``) ya da okunamayan → None."""
    try:
        v = g.gosterici(adres)
    except Exception:  # noqa: BLE001 - görüntü bozuksa okuyucu durmaz, None
        return None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _oku(g: Any, adres: int, n: int) -> bytes | None:
    try:
        b = g.oku(adres, n)
    except Exception:  # noqa: BLE001
        return None
    return bytes(b) if b is not None else None


# ---------------------------------------------------------------------------
# Kodlama yardımcıları
# ---------------------------------------------------------------------------


def _uvarint(buf: bytes, pos: int) -> tuple[int, int]:
    """``runtime.readvarint`` (uint32, kaydırma ``& 31``)."""
    v = 0
    shift = 0
    n = len(buf)
    while True:
        if pos >= n:
            raise _Kesik("varint sınır dışı")
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << (shift & 31)
        if not b & 0x80:
            return v & 0xFFFFFFFF, pos
        shift += 7


def _zikzak(uv: int) -> int:
    """``step``: tek ise ``^(uv >> 1)``, çift ise ``uv >> 1`` (işaretli)."""
    return -(uv & 1) ^ (uv >> 1)


def _cstr(buf: bytes, pos: int) -> str | None:
    if pos < 0 or pos >= len(buf):
        return None
    end = buf.find(b"\0", pos)
    if end < 0:
        return None
    return buf[pos:end].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Paket ve sınıf
# ---------------------------------------------------------------------------


def paket_adi(ad: str) -> str:
    """``runtime.funcpkgpath`` kuralı; tip parametresi köşeli ayracı önce kesilir."""
    kes = ad.find("[")
    govde = ad if kes < 0 else ad[:kes]
    i = govde.rfind("/")
    j = govde.find(".", i + 1)
    if j < 0:
        return ""
    return govde[:j]


def paket_sinifi(paket: str, ana_modul: str | None) -> str:
    """Paket sınıfı (başvuru: ``scripts/arge/ustveri/go_pclntab.py`` ``sinif``)."""
    if paket == "":
        return SINIF_PAKETSIZ
    if paket.startswith(("type:", "go:")):
        return SINIF_DERLEYICI
    if ana_modul and paket.startswith(ana_modul + "/vendor/"):
        return SINIF_UCUNCU_TARAF  # ana modülün içine kopyalanmış bağımlılıklar
    if paket == "main" or (ana_modul and (paket == ana_modul or paket.startswith(ana_modul + "/"))):
        return SINIF_KENDI
    if paket == "runtime" or paket.startswith(("runtime/", "internal/runtime/")):
        return SINIF_CALISMA_ZAMANI
    if paket.startswith("vendor/"):
        return SINIF_STANDART  # standart kitaplığın içine aldığı golang.org/x kopyaları
    ilk = paket.split("/", 1)[0]
    if "." in ilk:
        return SINIF_UCUNCU_TARAF
    return SINIF_STANDART


def ana_modul_bul(buildinfo: dict[str, Any] | None) -> str | None:
    """``mod`` satırı; yoksa ana paket yolunun ilk üç öğesi (eski derleme düzeni)."""
    if not buildinfo:
        return None
    if buildinfo.get("mod"):
        return buildinfo["mod"]
    yol = buildinfo.get("path")
    if yol:
        return "/".join(yol.split("/")[:3])
    return None


# ---------------------------------------------------------------------------
# buildinfo
# ---------------------------------------------------------------------------


def buildinfo_coz(b: bytes) -> dict[str, Any] | None:
    """``__go_buildinfo`` baytlarını çöz (satır içi biçim, Go 1.18+).

    Döner: ``{"surum", "path", "mod", "mod_surum", "dep", "build"}``; imza yoksa None.
    1.18 öncesi gösterici biçimi: ``{"surum": None, "not": ...}``.
    """
    if not b or not b.startswith(BUILDINFO_IMZA) or len(b) < 32:
        return None
    bayrak = b[15]
    if not bayrak & 2:
        return {"surum": None, "not": "gösterici biçimi (Go 1.18 öncesi); okunmadı"}
    try:
        n, pos = _uvarint(b, 32)
        if pos + n > len(b):
            raise _Kesik("sürüm dizgisi")
        surum = b[pos:pos + n].decode("utf-8", "replace")
        pos += n
        n, pos = _uvarint(b, pos)
        if pos + n > len(b):
            raise _Kesik("modül bilgisi")
        mod = b[pos:pos + n]
    except _Kesik as e:
        return {"surum": None, "not": f"buildinfo kesik: {e}"}
    # modinfo'nun başında ve sonunda 16 baytlık nöbetçi; sondaki nöbetçiden önce '\n'.
    if len(mod) >= 33 and mod[-17:-16] == b"\n":
        mod = mod[16:-16]
    else:
        mod = b""
    bilgi: dict[str, Any] = {"surum": surum, "path": None, "mod": None, "mod_surum": None,
                             "dep": 0, "build": {}}
    for satir in mod.decode("utf-8", "replace").splitlines():
        p = satir.split("\t")
        if p[0] == "path" and len(p) > 1:
            bilgi["path"] = p[1]
        elif p[0] == "mod" and len(p) > 1:
            bilgi["mod"] = p[1]
            bilgi["mod_surum"] = p[2] if len(p) > 2 else None
        elif p[0] == "dep":
            bilgi["dep"] += 1
        elif p[0] == "build" and len(p) > 1 and "=" in p[1]:
            k, v = p[1].split("=", 1)
            bilgi["build"][k] = v
    return bilgi


def buildinfo_oku(g: Any) -> dict[str, Any] | None:
    """Bölüm adıyla, yoksa veri bölümlerinde imza taramasıyla (16 bayt hizalı)."""
    bolumler = _bolumler(g)
    for ad, adres, boyut, _kod in bolumler:
        if ad in BUILDINFO_BOLUMLERI and boyut:
            return buildinfo_coz(_oku(g, adres, boyut) or b"")
    for ad, adres, boyut, kod in bolumler:
        if kod or not boyut:
            continue
        blob = _oku(g, adres, boyut) or b""
        pos = blob.find(BUILDINFO_IMZA)
        while pos >= 0:
            if (adres + pos) % 16 == 0:
                return buildinfo_coz(blob[pos:pos + 64 * 1024])
            pos = blob.find(BUILDINFO_IMZA, pos + 1)
    return None


# ---------------------------------------------------------------------------
# Okuyucu
# ---------------------------------------------------------------------------


class GoPclntab:
    """Tek bir Go modülünün ``pclntab``'ı.

    Kurucu bulamazsa / desteklemezse ``GoOkumaHatasi`` atar (``oku`` bunu durum sözlüğüne çevirir).
    """

    def __init__(self, goruntu: Any) -> None:
        self.g = goruntu
        self.notlar: list[str] = []
        gb = goruntu.gosterici_boyutu
        if gb != 8:
            raise GoOkumaHatasi(DURUM_DESTEKLENMIYOR, f"gösterici boyutu {gb}; yalnız 64 bit")
        self.bolum = self._bolum_bul()
        if self.bolum is not None:
            self.adres = self.bolum[1]
            self.bulma = f"bölüm adı ({self.bolum[0]})"
        else:
            self.adres = self._imza_tara()
            self.bulma = "imza taraması"
        if self.adres is None:
            raise GoOkumaHatasi(DURUM_VERI_YOK, "Go pclntab yok (bölüm adı ve imza taraması)")
        self._baslik_oku()
        self.md = self._moduledata_bul()
        if self.md is None:
            raise GoOkumaHatasi(
                DURUM_DESTEKLENMIYOR,
                f"moduledata bulunamadı (aday {self.md_adaylari}); biçim tahmin edilmez")
        self._metin_tabani_sec()
        self._tablo_oku()
        self._funcs: list[GoFonksiyon] | None = None

    # ---- bulma ----------------------------------------------------------
    def _bolum_bul(self) -> tuple[str, int, int, bool] | None:
        for b in _bolumler(self.g):
            if b[0] in PCLNTAB_BOLUMLERI and b[2] >= PCHEADER_BOYU:
                return b
        return None

    @staticmethod
    def _baslik_akli(h: bytes) -> bool:
        """İmza taramasında başlığın akıl sağlığı: dolgu 0, minLC, ptrSize, ofset sırası."""
        if len(h) < PCHEADER_BOYU:
            return False
        (_m, p1, p2, min_lc, ptr, nfunc, _nf, _ts, fn, cu, ft, pc, pl) = struct.unpack(
            "<IBBBBQQQQQQQQ", h[:PCHEADER_BOYU])
        return (p1 == 0 and p2 == 0 and min_lc in (1, 2, 4) and ptr == 8
                and 0 < nfunc < AZAMI_FONKSIYON
                and PCHEADER_BOYU <= fn <= cu <= ft <= pc <= pl)

    def _imza_tara(self) -> int | None:
        for ad, adres, boyut, kod in _bolumler(self.g):
            if kod or boyut < PCHEADER_BOYU:
                continue
            blob = _oku(self.g, adres, boyut) or b""
            for magic in (MAGIC_120, MAGIC_118):
                kalip = struct.pack("<I", magic) + b"\0\0"
                pos = blob.find(kalip)
                while pos >= 0:
                    if self._baslik_akli(blob[pos:pos + PCHEADER_BOYU]):
                        return adres + pos
                    pos = blob.find(kalip, pos + 1)
        return None

    def _baslik_oku(self) -> None:
        h = _oku(self.g, self.adres, PCHEADER_BOYU)
        if h is None or len(h) < PCHEADER_BOYU:
            raise GoOkumaHatasi(DURUM_TUTARSIZ, "pcHeader okunamadı (kesik)")
        (self.imza, self.dolgu1, self.dolgu2, self.min_lc, self.ptr_size, self.nfunc, self.nfiles,
         _ts_ham, self.funcname_off, self.cu_off, self.filetab_off, self.pctab_off,
         self.pcln_off) = struct.unpack("<IBBBBQQQQQQQQ", h)
        if self.imza not in DESTEKLENEN_IMZALAR:
            eski = ESKI_IMZALAR.get(self.imza)
            raise GoOkumaHatasi(
                DURUM_DESTEKLENMIYOR,
                f"pclntab imzası {self.imza:#x}" + (f" ({eski})" if eski else "") +
                "; desteklenen: Go 1.18–1.27")
        if self.ptr_size != 8:
            raise GoOkumaHatasi(DURUM_DESTEKLENMIYOR, f"ptrSize {self.ptr_size}; yalnız 64 bit")
        if self.min_lc not in (1, 2, 4):
            raise GoOkumaHatasi(DURUM_DESTEKLENMIYOR, f"minLC {self.min_lc} beklenmedik")
        if not (PCHEADER_BOYU <= self.funcname_off <= self.cu_off <= self.filetab_off
                <= self.pctab_off <= self.pcln_off):
            raise GoOkumaHatasi(DURUM_DESTEKLENMIYOR, "pcHeader ofset sırası beklenmedik")
        # Eski textStart bir göstericidir (1.18–1.25); düzeltme / yeniden konumlama çözülür.
        self.baslik_text = _gosterici(self.g, self.adres + 24) or 0

    def _moduledata_bul(self) -> dict[str, Any] | None:
        """``moduledata``: 0. sözcük pcHeader'a, 1. sözcük funcnametab'a gösterici.

        Aday bulma ham tamsayılarla (göstericiler düzeltme kodlu olabilir): 17. ve 18. sözcük ftab
        diliminin uzunluk / sığası (= nfunc + 1); 2. ve 3. sözcük funcnametab uzunluk / sığası.
        Aday, iki göstericisi çözülerek doğrulanır.
        """
        T = self.adres
        fn_adres = T + self.funcname_off
        kaliplar = (
            (struct.pack("<QQ", self.nfunc + 1, self.nfunc + 1), 8 * (MD_FTAB + 1)),
            (struct.pack("<QQ", self.cu_off - self.funcname_off,
                         self.cu_off - self.funcname_off), 8 * (MD_FUNCNAMETAB + 1)),
        )
        denenen: set[int] = set()
        self.md_adaylari = 0
        for ad, adres, boyut, kod in _bolumler(self.g):
            if kod or boyut < 8 * (MD_ETEXT + 1):
                continue
            blob = _oku(self.g, adres, boyut) or b""
            for kalip, geri in kaliplar:
                pos = blob.find(kalip)
                while pos >= 0:
                    aday = adres + pos - geri
                    if aday % 8 == 0 and aday >= adres and aday not in denenen:
                        denenen.add(aday)
                        self.md_adaylari += 1
                        if (_gosterici(self.g, aday + 8 * MD_PCHEADER) == T
                                and _gosterici(self.g, aday + 8 * MD_FUNCNAMETAB) == fn_adres):
                            return self._md_sozcukleri(aday)
                    pos = blob.find(kalip, pos + 1)
        return None

    def _md_sozcukleri(self, aday: int) -> dict[str, Any]:
        def p(i: int) -> int | None:
            return _gosterici(self.g, aday + 8 * i)

        def u(i: int) -> int | None:
            b = _oku(self.g, aday + 8 * i, 8)
            return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

        return {
            "adres": aday,
            "ftab_uzunlugu": u(MD_FTAB + 1),
            "pclntable_uzunlugu": u(MD_PCLNTABLE_UZ),
            "findfunctab": p(MD_FINDFUNCTAB),
            "minpc": p(MD_MINPC),
            "maxpc": p(MD_MAXPC),
            "text": p(MD_TEXT),
            "etext": p(MD_ETEXT),
        }

    def _metin_tabani_sec(self) -> None:
        md_text = self.md.get("text")
        if md_text:
            self.text = md_text
            self.metin_tabani_kaynagi = "moduledata.text"
            if self.baslik_text and self.baslik_text != md_text:
                self.notlar.append(
                    f"başlıktaki textStart ({self.baslik_text:#x}) ≠ moduledata.text ({md_text:#x})")
        elif self.baslik_text:
            self.text = self.baslik_text
            self.metin_tabani_kaynagi = "pcHeader.textStart"
        else:
            raise GoOkumaHatasi(DURUM_DESTEKLENMIYOR, "metin tabanı yok (moduledata.text ve textStart 0)")

    def _tablo_oku(self) -> None:
        """pclntab'ın tamamını tek okumayla al (bütün ofsetler başlığa göre)."""
        boy = self.pcln_off + 8 * (self.nfunc + 1)
        if self.bolum is not None:
            boy = max(boy, self.bolum[2])
        if self.md.get("pclntable_uzunlugu"):
            boy = max(boy, self.pcln_off + self.md["pclntable_uzunlugu"])
        blob = _oku(self.g, self.adres, boy)
        if blob is None or len(blob) < self.pcln_off + 8 * (self.nfunc + 1):
            raise GoOkumaHatasi(DURUM_TUTARSIZ, "pclntab kesik: ftab okunamıyor")
        self.blob = blob

    # ---- tablolar -------------------------------------------------------
    def ad_oku(self, name_off: int) -> str:
        """``moduledata.funcName``: ``nameOff == 0`` → boş ad."""
        if name_off == 0:
            return ""
        if name_off < 0:
            raise _Kesik("negatif nameOff")
        s = _cstr(self.blob, self.funcname_off + name_off)
        if s is None:
            raise _Kesik("ad sınır dışı")
        return s

    def fonksiyonlar(self) -> list[GoFonksiyon]:
        """Bütün ``ftab`` girişleri. Okunamayan giriş ``_Kesik`` atar."""
        if self._funcs is not None:
            return self._funcs
        d = self.blob
        base = self.pcln_off
        n = self.nfunc
        try:
            ftab = struct.unpack_from(f"<{2 * (n + 1)}I", d, base)
        except struct.error as e:
            raise _Kesik(f"ftab: {e}") from e
        text = self.text
        out = []
        self.giris_uyusmazligi = 0
        for i in range(n):
            entryoff, funcoff = ftab[2 * i], ftab[2 * i + 1]
            try:
                (e2, name_off, args, deferreturn, pcsp, pcfile, pcln, npcdata, cu_offset,
                 start_line, func_id, flag, _dolgu, nfuncdata) = struct.unpack_from(
                    "<IiiIIIIIIiBBBB", d, base + funcoff)
            except struct.error as e:
                raise _Kesik(f"_func[{i}] sınır dışı") from e
            if e2 != entryoff:
                self.giris_uyusmazligi += 1
            out.append(GoFonksiyon(
                i, text + entryoff, text + ftab[2 * (i + 1)], funcoff, name_off,
                self.ad_oku(name_off), args, deferreturn, pcsp, pcfile, pcln, npcdata, cu_offset,
                start_line, func_id, flag, nfuncdata))
        self.son_entryoff = ftab[2 * n]
        self._funcs = out
        return out

    def pc_tablosu(self, off: int, giris: int) -> list[tuple[int, int, int]]:
        """pc-değer tablosu: [(değer, başlangıç pc, bitiş pc)] (``runtime.pcvalue`` / ``step``)."""
        if off == 0:
            return []
        d = self.blob
        pos = self.pctab_off + off
        pc = giris
        val = -1
        out = []
        while True:
            uv, pos2 = _uvarint(d, pos)
            if uv == 0 and pc != giris:
                break
            pos = pos2
            val += _zikzak(uv)
            pcdelta, pos = _uvarint(d, pos)
            npc = pc + pcdelta * self.min_lc
            out.append((val, pc, npc))
            if npc == pc and pc == giris and uv == 0:
                break  # ilk çift (0, 0): boş tablo; sonsuz döngüye girme
            pc = npc
        return out

    def dosya_oku(self, f: GoFonksiyon) -> str | None:
        """Giriş adresindeki kaynak dosya (``funcline1`` → ``funcfile``); yoksa None."""
        if f.pcfile == 0:
            return None
        d = self.blob
        uv, _ = _uvarint(d, self.pctab_off + f.pcfile)
        fileno = -1 + _zikzak(uv)
        if fileno < 0:
            return None
        cu = self.cu_off + 4 * (f.cu_offset + fileno)
        if cu + 4 > self.filetab_off:
            raise _Kesik("cutab sınır dışı")
        fileoff = struct.unpack_from("<I", d, cu)[0]
        if fileoff == DOSYA_YOK:
            return None
        s = _cstr(d, self.filetab_off + fileoff)
        if s is None:
            raise _Kesik("filetab sınır dışı")
        return s

    def funcnametab_dizgileri(self) -> dict[int, str]:
        """funcnametab'daki bütün dizgiler (ofset → ad); satır içi adlar da buradadır."""
        blob = self.blob[self.funcname_off:self.cu_off]
        out: dict[int, str] = {}
        pos = 0
        while pos < len(blob):
            e = blob.find(b"\0", pos)
            if e < 0:
                break
            if e > pos:
                out[pos] = blob[pos:e].decode("utf-8", "replace")
            pos = e + 1
        return out

    def ozet(self) -> dict[str, Any]:
        md = self.md or {}
        return {
            "adres": hex(self.adres),
            "bulma": self.bulma,
            "imza": hex(self.imza),
            "imza_adi": DESTEKLENEN_IMZALAR.get(self.imza),
            "minLC": self.min_lc,
            "nfunc": self.nfunc,
            "nfiles": self.nfiles,
            "basliktaki_textStart": hex(self.baslik_text),
            "metin_tabani": hex(self.text),
            "metin_tabani_kaynagi": self.metin_tabani_kaynagi,
            "moduledata": hex(md["adres"]) if md.get("adres") is not None else None,
            "moduledata_adayi": self.md_adaylari,
            "notlar": self.notlar[:10],
        }


# ---------------------------------------------------------------------------
# Yapı denetimleri (K1–K9)
# ---------------------------------------------------------------------------


def _k4(p: GoPclntab, fs: list[GoFonksiyon]) -> dict[str, Any]:
    """pcsp tablosu fonksiyonun tamamını kaplıyor mu (yığın açma buna muhtaç)."""
    girisler = [f.giris for f in fs]
    hiza = 0
    for e in girisler:
        hiza = math.gcd(hiza, e - girisler[0])
    tam = dolgulu = kisa_asm = kisa = tasan = pcspsiz = 0
    for f in fs:
        if f.pcsp == 0:
            pcspsiz += 1
            continue
        tb = p.pc_tablosu(f.pcsp, f.giris)
        son = tb[-1][2] if tb else f.giris
        if son == f.bitis:
            tam += 1
        elif son < f.bitis and f.bitis - son < hiza:
            dolgulu += 1
        elif son < f.bitis and f.flag & FUNC_FLAG_ASM:
            kisa_asm += 1
        elif son < f.bitis:
            kisa += 1
        else:
            tasan += 1
    return {"bakilan": len(fs) - pcspsiz, "ihlal": kisa + tasan, "hiza": hiza, "tam": tam,
            "dolguyla": dolgulu, "kisa_asm": kisa_asm, "kisa": kisa, "tasan": tasan,
            "pcsp_yok": pcspsiz}


def _k5(p: GoPclntab, girisler: list[int]) -> dict[str, Any] | None:
    """``findfunctab`` kovaları ↔ ``ftab`` (``runtime.findfunc`` kovadan ileri tarar)."""
    md = p.md
    if not md.get("findfunctab") or not md.get("minpc") or not md.get("maxpc"):
        return None
    minpc, maxpc = md["minpc"], md["maxpc"]
    if maxpc <= minpc:
        return {"bakilan": 0, "ihlal": 1, "neden": "maxpc ≤ minpc"}
    nb = (maxpc - minpc + FUNC_TAB_KOVA - 1) // FUNC_TAB_KOVA
    blob = _oku(p.g, md["findfunctab"], nb * FINDFUNC_KOVA_BOYU)
    if blob is None or len(blob) < nb * FINDFUNC_KOVA_BOYU:
        return {"kova": nb, "bakilan": 0, "ihlal": 1, "neden": "findfunctab okunamadı"}
    alt = FUNC_TAB_KOVA // FUNC_TAB_ALT_KOVA
    uyumlu = toplam = 0
    for b in range(nb):
        idx = struct.unpack_from("<I", blob, FINDFUNC_KOVA_BOYU * b)[0]
        for s in range(FUNC_TAB_ALT_KOVA):
            pc = minpc + b * FUNC_TAB_KOVA + s * alt
            if pc >= maxpc:
                break
            toplam += 1
            beklenen = bisect.bisect_right(girisler, pc) - 1
            basla = idx + blob[FINDFUNC_KOVA_BOYU * b + 4 + s]
            if basla <= beklenen and beklenen - basla <= alt:
                uyumlu += 1
    return {"kova": nb, "bakilan": toplam, "uyumlu": uyumlu, "ihlal": toplam - uyumlu}


def _bl_hedefleri(p: GoPclntab, lo: int, hi: int) -> list[tuple[int, int]]:
    """arm64: [lo, hi) kod aralığındaki ``bl`` komutlarının (kaynak, hedef) çiftleri."""
    out = []
    for _ad, adres, boyut, _k in _kod_bolumleri(p.g):
        a = max(adres, lo)
        b = min(adres + boyut, hi)
        if a >= b:
            continue
        a += (-a) % 4
        blob = _oku(p.g, a, b - a) or b""
        n = len(blob) // 4
        # Yüksek bayt 0x94–0x97 → üst 6 bit 100101 (bl). Bayt dilimiyle aday bul, sözcükle doğrula.
        ust = blob[3:4 * n:4]
        isaret = ust.translate(_BL_TABLOSU)
        i = isaret.find(b"\x01")
        while i >= 0:
            w = struct.unpack_from("<I", blob, 4 * i)[0]
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            kaynak = a + 4 * i
            out.append((kaynak, kaynak + 4 * imm))
            i = isaret.find(b"\x01", i + 1)
    return out


_BL_TABLOSU = bytes(1 if 0x94 <= x <= 0x97 else 0 for x in range(256))


def butunluk_denetle(p: GoPclntab, fs: list[GoFonksiyon]) -> dict[str, Any]:
    """K1–K9 (hepsi zorunlu alanlardan). Her denetim: bakılan / ihlal (+ ayrıntı)."""
    g = p.g
    md = p.md
    d: dict[str, Any] = {}
    girisler = [f.giris for f in fs]
    n = len(girisler)
    # K0: ftab girişi ile _func.entryOff aynı (ek denetim; çalışma zamanı ikisini eş varsayar).
    d["K0_giris_uyumu"] = {"bakilan": n, "ihlal": getattr(p, "giris_uyusmazligi", 0)}
    # K1: girişler kesin artan.
    k1 = sum(1 for i in range(1, n) if not girisler[i - 1] < girisler[i])
    d["K1_artan"] = {"bakilan": max(n - 1, 0), "ihlal": k1}
    # K2: girişler bir kod bölümünde ve text…etext içinde.
    kod = sorted((a, a + s) for _ad, a, s, _k in _kod_bolumleri(g))
    bas = [k[0] for k in kod]

    def kodda(e: int) -> bool:
        i = bisect.bisect_right(bas, e) - 1
        return i >= 0 and kod[i][0] <= e < kod[i][1]

    bolum_disi = sum(1 for e in girisler if not kodda(e))
    if md.get("text") and md.get("etext"):
        md_disi = sum(1 for e in girisler if not (md["text"] <= e < md["etext"]))
    else:
        md_disi = None
    d["K2_kod_icinde"] = {"bakilan": n, "ihlal": bolum_disi + (md_disi or 0),
                          "bolum_disi": bolum_disi, "moduledata_disi": md_disi}
    # K3: minLC hizası (bilgi).
    d["K3_hiza"] = {"bakilan": n, "ihlal": sum(1 for e in girisler if e % p.min_lc)}
    d["K4_pcsp_kapsama"] = _k4(p, fs)
    d["K5_findfunctab"] = _k5(p, girisler)
    # K6: girişler fonksiyon başlangıcı (tablo varsa; bilgi).
    try:
        fb = g.fonksiyon_baslangiclari()
    except Exception:  # noqa: BLE001
        fb = None
    if fb is not None and n:
        fset = set(fb)
        lo, hi = girisler[0], fs[-1].bitis
        icerde = [a for a in fset if lo <= a < hi]
        eset = set(girisler)
        d["K6_fonksiyon_baslangici"] = {
            "bakilan": n, "ihlal": sum(1 for e in girisler if e not in fset),
            "tablo": len(fset), "go_araliginda": len(icerde),
            "aralikta_pclntabda_olmayan": sum(1 for a in icerde if a not in eset)}
    else:
        d["K6_fonksiyon_baslangici"] = None
    # K7: arm64 bl hedefleri giriş mi (Duff gövdesi ayrık).
    if g.mimari == "arm64" and n:
        lo, hi = girisler[0], fs[-1].bitis
        eset = set(girisler)
        ic = [(s, t) for s, t in _bl_hedefleri(p, lo, hi) if lo <= t < hi]
        duff = baska = 0
        for _s, t in ic:
            if t not in eset:
                ad = fs[bisect.bisect_right(girisler, t) - 1].ad
                if ad in DUFF_ADLARI:
                    duff += 1
                else:
                    baska += 1
        d["K7_bl_hedefi"] = {"bakilan": len(ic), "ihlal": baska,
                             "hedef_giris": len(ic) - duff - baska, "hedef_duff_ici": duff,
                             "hedef_baska_govde_ici": baska}
    else:
        d["K7_bl_hedefi"] = None
    # K8: özel funcID (0 < kimlik < sarmalayıcı kimliği) runtime. önekli ve kimlik tekil.
    if n:
        sarma = max(f.func_id for f in fs)
        ozel = [f for f in fs if 0 < f.func_id < sarma]
        kimlik = collections.Counter(f.func_id for f in ozel)
        onekli = sum(1 for f in ozel if f.ad.startswith("runtime."))
        yinelenen = sum(1 for v in kimlik.values() if v > 1)
        d["K8_funcID"] = {"bakilan": len(ozel), "ihlal": (len(ozel) - onekli) + yinelenen,
                          "sarmalayici_kimligi": sarma, "runtime_onekli": onekli,
                          "yinelenen_kimlik": yinelenen}
    else:
        d["K8_funcID"] = None
    # K9: moduledata minpc / maxpc ftab ile uyumlu.
    if md.get("minpc") and n:
        ihlal = int(md["minpc"] != girisler[0]) + int(md.get("maxpc") != p.text + p.son_entryoff)
        d["K9_minpc_maxpc"] = {"bakilan": 2, "ihlal": ihlal}
    else:
        d["K9_minpc_maxpc"] = {"bakilan": 0, "ihlal": 1, "neden": "moduledata minpc yok"}
    return d


def tutarsizlik_nedeni(d: dict[str, Any], nfunc: int) -> str | None:
    """Karar (PLAN kalem 4): K1, K2, K5, K9 ihlali ya da K4 ihlali > %1 → neden; yoksa None.

    Ek: K0 (ftab ↔ _func giriş uyumu) ihlali ad eşlemesini belirsiz kılar → tutarsız.
    """
    nedenler = []
    for k in ("K0_giris_uyumu", "K1_artan", "K2_kod_icinde", "K5_findfunctab", "K9_minpc_maxpc"):
        v = d.get(k)
        if v and v.get("ihlal", 0) > 0:
            nedenler.append(f"{k} ihlal {v['ihlal']}")
    k4 = d.get("K4_pcsp_kapsama") or {}
    if nfunc and k4.get("ihlal", 0) > K4_IHLAL_ORANI * nfunc:
        nedenler.append(f"K4_pcsp_kapsama ihlal {k4['ihlal']} / {nfunc} (> %{K4_IHLAL_ORANI * 100:g})")
    return "; ".join(nedenler) if nedenler else None


# ---------------------------------------------------------------------------
# Giriş noktası
# ---------------------------------------------------------------------------


def oku(goruntu: Any) -> GoSonuc:
    """Görüntüden Go fonksiyon listesi + buildinfo + yapı denetimleri; istisna atmaz
    (beklenmedik hata ``hata`` durumuyla döner)."""
    t0 = time.perf_counter()
    try:
        sonuc = _oku_ic(goruntu)
    except GoOkumaHatasi as e:
        sonuc = GoSonuc(durum=e.durum, neden=e.neden)
    except _Kesik as e:
        sonuc = GoSonuc(durum=DURUM_TUTARSIZ, neden=f"tablo kesik: {e}")
    except Exception as e:  # noqa: BLE001 - okuyucu analizi düşürmez
        sonuc = GoSonuc(durum=DURUM_HATA, neden=f"{type(e).__name__}: {e}")
    sonuc.sure_sn = round(time.perf_counter() - t0, 3)
    return sonuc


def _oku_ic(goruntu: Any) -> GoSonuc:
    p = GoPclntab(goruntu)
    bi = buildinfo_oku(goruntu)
    ana_modul = ana_modul_bul(bi)
    ozet = p.ozet()
    try:
        fs = p.fonksiyonlar()
        for f in fs:
            f.dosya = p.dosya_oku(f)
            f.paket = paket_adi(f.ad)
            f.sinif = paket_sinifi(f.paket, ana_modul) if f.ad else SINIF_ADSIZ
        d = butunluk_denetle(p, fs)
        dizgiler = p.funcnametab_dizgileri()
    except _Kesik as e:
        return GoSonuc(durum=DURUM_TUTARSIZ, neden=f"tablo kesik: {e}", buildinfo=bi, pclntab=ozet)
    kullanilan = {f.name_off for f in fs if f.name_off}  # nameOff 0 = ad yok (bağ değil)
    d["satir_ici_ad"] = {"funcnametab_dizgi": len(dizgiler),
                         "yalniz_satir_ici": sum(1 for o in dizgiler if o not in kullanilan)}
    sinif_say = collections.Counter(f.sinif for f in fs)
    sayim = {"fonksiyon_girisi": len(fs), "adli": sum(1 for f in fs if f.ad),
             "dosya_yolu_olan": sum(1 for f in fs if f.dosya), "sinif": dict(sinif_say)}
    neden = tutarsizlik_nedeni(d, len(fs))
    if neden is not None:
        return GoSonuc(durum=DURUM_TUTARSIZ, neden=neden, fonksiyonlar=[], buildinfo=bi,
                       butunluk=d, pclntab=ozet, sayim=sayim)
    return GoSonuc(durum=DURUM_CALISTI, fonksiyonlar=fs, buildinfo=bi, butunluk=d,
                   pclntab=ozet, sayim=sayim)
