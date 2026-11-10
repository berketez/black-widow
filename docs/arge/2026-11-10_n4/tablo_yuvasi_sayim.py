#!/usr/bin/env python3
"""N4 karşı incelemesi §5 A1 için GT'siz tavan sayımı: veri tablolarındaki fonksiyon yuvaları.

Soru: ad bekleyen fonksiyonların ne kadarı bir veri tablosundan gösteriliyor ve bunların ne
kadarının kaydında ad kanıtı olabilecek bir dizgi var? Ürün kodu değişmez; yalnız sayım.

Girdiler (saklı koşular):

- ``raw/<ikili>``: ikilinin kopyası. ELF'te ``.rela.dyn`` (``R_AARCH64_RELATIVE`` addend'i,
  ``R_AARCH64_ABS64`` simge + addend), Mach-O'da chained fixup (rebase / bind) okunur.
- ``static/ghidra_functions.json``, ``ghidra_xrefs.json``, ``ghidra_combined_results.json``,
  ``ghidra_strings.json`` ve ``ghidra_output/decompiled/*.c`` (gömülü disassembly ve ``PTR_``
  etiketleri).
- ``reconstructed/src/naming_map.json``: yalnız ``global`` sözlüğünün ANAHTARLARI (ad okunmaz).

GT, dbgsym, DWARF, Mac GT dosyaları (``macho_score.json`` vb.) okunmaz. Çıktıda fonksiyon adı,
dizgi içeriği ve ``FUN_`` anahtarı yoktur; yalnız sayılar, sınıflar, program/ikili ve bölüm adları.
Ad bekleyen nüfus ``on_sayim.py``'deki tanımdır; birim sayıları ``on_sayim.json`` ile denetlenir.

Kullanım:
    python3 -I -B tablo_yuvasi_sayim.py --mac-kosu <koşu> --debian-kosu <koşu> \\
        --on-sayim on_sayim.json --cikti tablo_yuvasi_sayim.json
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import platform
import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import on_sayim as OS  # noqa: E402  (aynı dizindeki ön sayım; yalnız içe aktarılır)

SURUM = 1

# ---------------------------------------------------------------------------------------------
# Tanımlar (bu sayıma özgü; ürün sözlüğü değildir)

SOZCUK = 8                 # AArch64 gösterici boyu (bayt)
EN_BUYUK_ADIM = 64         # kayıt adımı en çok 64 sözcük (512 bayt)
EN_AZ_KAYIT = 3            # tablo: en az 3 kayıt
EN_UZUN_DIZGI = 65536      # NUL bu kadar bayt içinde bulunmalı

# Sözcük türleri. Fonksiyon yuvası: F (iç fonksiyon girişi) ya da X (içe aktarılan fonksiyon).
TUR_F, TUR_X, TUR_T, TUR_S, TUR_E, TUR_D, TUR_Z, TUR_V = "F", "X", "T", "S", "E", "D", "Z", "V"
FONKSIYON_TURLERI = frozenset({TUR_F, TUR_X})
# Faz seçiminde sütun tutarlılığı için kaba sınıf (boş dizgi dizgi sayılır, sıfır ile sayı birdir)
KABA = {TUR_F: "F", TUR_X: "F", TUR_T: "T", TUR_S: "S", TUR_E: "S", TUR_D: "D",
        TUR_Z: "N", TUR_V: "N"}

TANIMLAYICI_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KISA_AD_RE = re.compile(r"[A-Za-z0-9_]+(?:[-.][A-Za-z0-9_]+)+")
KISA_AD_EN_UZUN = 40
DIZGI_SINIFLARI = ("tanimlayici", "kisa_ad", "bicim", "bosluklu", "diger")
AD_KANITI_SINIFLARI = frozenset({"tanimlayici", "kisa_ad"})

ELF_BASLAT_DIZILERI = frozenset({".init_array", ".fini_array", ".preinit_array"})
ELF_DISLANAN = frozenset({".got", ".got.plt", ".dynamic"})
MACHO_VERI_SEGMENTLERI = frozenset({"__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH",
                                    "__AUTH_CONST"})
MACHO_BASLAT = frozenset({"__mod_init_func", "__mod_term_func", "__init_offsets"})
MACHO_DISLANAN = frozenset({"__got", "__la_symbol_ptr", "__nl_symbol_ptr", "__auth_got",
                            "__auth_ptr", "__thread_ptrs", "__thread_vars"})
MACHO_RO_DISLANAN = frozenset({"__unwind_info", "__eh_frame", "__gcc_except_tab"})

R_AARCH64_ABS64 = 257
R_AARCH64_RELATIVE = 1027

KAYIT_DILIMLERI = ((3, "3"), (7, "4-7"), (15, "8-15"), (63, "16-63"), (None, ">=64"))
ADIM_DILIMLERI = ((1, "8"), (2, "16"), (3, "24"), (4, "32"), (8, "40-64"), (16, "72-128"),
                  (32, "136-256"), (None, "264-512"))

_PTR_ETIKETI = re.compile(r"\bPTR_([A-Za-z_][A-Za-z0-9_]*?)_([0-9a-f]{6,16})\b")
_ADRP = re.compile(r"^([xw]\d+),\s*0x([0-9a-f]+)$")
_ADD_IMM = re.compile(r"^(x\d+),\s*(x\d+),\s*#0x([0-9a-f]+)$")
_ADR = re.compile(r"^(x\d+),\s*0x([0-9a-f]+)$")


def dilim(deger: int, dilimler) -> str:
    for ust, ad in dilimler:
        if ust is None or deger <= ust:
            return ad
    raise AssertionError


# ---------------------------------------------------------------------------------------------
# Saf yardımcılar (sentetik baytlarla sınanır)


def dizgi_oku(bolum_baytlari: bytes, ofset: int) -> str | None:
    """Ofsetten başlayan NUL sonlu, yazdırılabilir UTF-8 dizgi; değilse None (boş dizgi '')."""
    if not 0 <= ofset < len(bolum_baytlari):
        return None
    son = bolum_baytlari.find(b"\0", ofset, ofset + EN_UZUN_DIZGI + 1)
    if son < 0:
        return None
    try:
        metin = bolum_baytlari[ofset:son].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(c.isprintable() or c in "\t\n\r" for c in metin):
        return metin
    return None


def dizgi_sinifi(metin: str) -> str:
    """Biçim sınıfı. Sıra: tanımlayıcı, tire/noktalı kısa ad, biçim (%), boşluklu metin, öbür."""
    if TANIMLAYICI_RE.fullmatch(metin):
        return "tanimlayici"
    if (len(metin) <= KISA_AD_EN_UZUN and KISA_AD_RE.fullmatch(metin)
            and any(c.isalpha() for c in metin)):
        return "kisa_ad"
    if "%" in metin:
        return "bicim"
    if " " in metin:
        return "bosluklu"
    return "diger"


class Hedefci:
    """Gösterici hedefini türe çevirir: F, X, T, S, E ya da D."""

    def __init__(self, fonksiyon_girisleri, metin_araliklari, ro_bolumler):
        self.giris = fonksiyon_girisleri          # {adres: "ic"|"thunk"} (iç fonksiyonlar)
        self.metin = sorted(metin_araliklari)     # [(başlangıç, bitiş)] yürütülebilir bölümler
        self.ro = sorted(ro_bolumler)             # [(başlangıç, bitiş, bayt)]
        self.dizgi_onbellek: dict[int, str | None] = {}

    def dizgi(self, adres: int) -> str | None:
        if adres in self.dizgi_onbellek:
            return self.dizgi_onbellek[adres]
        sonuc = None
        for bas, bit, bayt in self.ro:
            if bas <= adres < bit:
                sonuc = dizgi_oku(bayt, adres - bas)
                break
        self.dizgi_onbellek[adres] = sonuc
        return sonuc

    def tur(self, hedef: int) -> str:
        if hedef in self.giris:
            return TUR_F
        if any(bas <= hedef < bit for bas, bit in self.metin):
            return TUR_T
        d = self.dizgi(hedef)
        if d is None:
            return TUR_D
        return TUR_S if d else TUR_E


def bolum_turleri(baytlar: bytes, bas: int, yer_degisim: dict[int, tuple[str, int | None]],
                  hedefci: Hedefci) -> tuple[int, list[str], list[int | None]]:
    """Bölümün 8 bayt hizalı sözcükleri için (ilk hizalı adres, türler, hedefler).

    ``yer_degisim``: sözcük adresi → ("hedef", mutlak hedef) | ("dis_fonksiyon", None) |
    ("dis_veri", None). Yer değişimi olmayan sözcük ham değerine göre Z (sıfır) ya da V'dir.
    """
    ilk = (bas + SOZCUK - 1) // SOZCUK * SOZCUK
    turler: list[str] = []
    hedefler: list[int | None] = []
    for adres in range(ilk, bas + len(baytlar) - SOZCUK + 1, SOZCUK):
        yd = yer_degisim.get(adres)
        if yd is None:
            ham = struct.unpack_from("<Q", baytlar, adres - bas)[0]
            turler.append(TUR_Z if ham == 0 else TUR_V)
            hedefler.append(None)
        elif yd[0] == "hedef":
            turler.append(hedefci.tur(yd[1]))
            hedefler.append(yd[1])
        elif yd[0] == "dis_fonksiyon":
            turler.append(TUR_X)
            hedefler.append(None)
        else:
            turler.append(TUR_D)
            hedefler.append(None)
    return ilk, turler, hedefler


# ---------------------------------------------------------------------------------------------
# Tablo bulma
#
# 1. Sütun koşusu: aynı adımla (s sözcük) ardışık en az 3 fonksiyon yuvası. Daha küçük bir
#    böleninin koşusunun alt örneği olan koşu atılır (ardışık gösterici dizisinde adım en küçük
#    dönemdir).
# 2. Aday tablo: aynı adımlı, aynı kayıt sayılı ve başlangıçları birbirinden < s sözcük uzak
#    sütun koşuları (aynı kayıtları paylaşan sütunlar).
# 3. Seçim: en çok yuvalı aday önce. Faz (kayıt başlangıcı) önce çapalardan (koddan ya da bir veri
#    göstericisinden başvurulan adres), sonra sütun tutarlılığından seçilir. Ardışık kayıt
#    çiftlerinin gösterici sütunlarındaki benzerlik ortalaması BENZERLIK_ESIGI altındaysa aday,
#    eşiğin altındaki çiftlerden bölünür ve parçalar (≥ 3 kayıt) yeniden denenir. Ortalama geçse
#    de kenardaki çiftin benzerliği KENAR_ESIGI altındaysa o kenar kaydı atılır. Kabul edilen
#    tablonun bütün kayıt bölgesi alınır; sonraki adaylar bu bölgeden çıkarılarak küçültülür.
# 4. Aynı puanda, farklı adımlı ve bölgeleri kesişen adaylar 'adım belirsiz' sayılır.

BENZERLIK_ESIGI = 0.9
KENAR_ESIGI = 0.5          # kenar kaydı çifti bunun altındaysa kayıt atılır


def _kosu_uzunluklari(turler: list[str], adim: int, yasak: set[int]) -> list[int]:
    """Her konumdan ileri, ``adim`` aralıkla kesintisiz fonksiyon yuvası sayısı."""
    n = len(turler)
    uz = [0] * n
    for p in range(n - 1, -1, -1):
        if turler[p] in FONKSIYON_TURLERI and p not in yasak:
            uz[p] = 1 + (uz[p + adim] if p + adim < n else 0)
    return uz


def _grupla(adim: int, kosular: list[tuple[int, int]]) -> list[dict]:
    """Aynı kayıt sayılı ve başlangıçları < adim uzak sütun koşularını tek adayda toplar."""
    kayit_sayisina_gore: dict[int, list[int]] = {}
    for p, uz in sorted(kosular):
        kayit_sayisina_gore.setdefault(uz, []).append(p)
    gruplar: list[dict] = []
    for uz, baslar in sorted(kayit_sayisina_gore.items()):
        g = None
        for p in baslar:
            if g is not None and p - g["kosular"][0][0] < adim:
                g["kosular"].append((p, uz))
            else:
                g = {"adim": adim, "kayit": uz, "kosular": [(p, uz)]}
                gruplar.append(g)
    for g in gruplar:
        g["yuvalar"] = frozenset(p + r * adim for p, uz in g["kosular"] for r in range(uz))
    return gruplar


def sutun_kosulari(turler: list[str], adim: int, uzunluk: dict[int, list[int]],
                   en_az: int) -> list[tuple[int, int]]:
    """Bir adımın alt örnek olmayan sütun koşuları: [(başlangıç, kayıt sayısı)]."""
    uz = uzunluk[adim]
    bolenler = [d for d in range(1, adim) if adim % d == 0]
    kosular = []
    for p in range(len(turler)):
        if uz[p] >= en_az and (p - adim < 0 or uz[p - adim] == 0):
            L = uz[p]
            if any(uzunluk[d][p] >= (L - 1) * (adim // d) + 1 for d in bolenler):
                continue
            kosular.append((p, L))
    return kosular


def aday_tablolar(turler: list[str], en_buyuk_adim: int = EN_BUYUK_ADIM,
                  en_az: int = EN_AZ_KAYIT) -> list[dict]:
    uzunluk = {s: _kosu_uzunluklari(turler, s, set()) for s in range(1, en_buyuk_adim + 1)}
    adaylar: list[dict] = []
    for s in range(1, en_buyuk_adim + 1):
        adaylar.extend(_grupla(s, sutun_kosulari(turler, s, uzunluk, en_az)))
    return adaylar


def _kucult(g: dict, alinmis: set[int], en_az: int) -> list[dict]:
    """Alınmış konumları çıkarıp kalan ≥ en_az kayıtlı alt koşularla yeniden gruplar."""
    s = g["adim"]
    yeni = []
    for p, uz in g["kosular"]:
        r = 0
        while r < uz:
            while r < uz and p + r * s in alinmis:
                r += 1
            bas = r
            while r < uz and p + r * s not in alinmis:
                r += 1
            if r - bas >= en_az:
                yeni.append((p + bas * s, r - bas))
    return _grupla(s, yeni)


def pencereler(tablo: dict, b: int) -> range:
    """Faz b (kayıt başlangıcı mod adım) için yuvaları kapsayan kayıt başlangıçları."""
    s = tablo["adim"]
    lo, hi = min(tablo["yuvalar"]), max(tablo["yuvalar"])
    return range(lo - ((lo - b) % s), hi + 1, s)


def sabit_sutun(turler: list[str], s: int, pen: range) -> int:
    """Bütün kayıtlarda aynı kaba sınıfı taşıyan sütun sayısı."""
    n = len(turler)
    sabit = 0
    for j in range(s):
        siniflar = {KABA[turler[w + j]] if 0 <= w + j < n else None for w in pen}
        if len(siniflar) == 1 and None not in siniflar:
            sabit += 1
    return sabit


def faz_sec(turler: list[str], tablo: dict, capalar: frozenset = frozenset()) -> tuple[list[int], str]:
    """Kayıt başlangıcının (mod adım) en iyi değerleri ve seçimin kaynağı.

    Puan sırası: kayıt başlangıcına düşen çapa sayısı; bütün kayıtlarda aynı kaba sınıfı taşıyan
    sütun sayısı; daha az kayıt. Eşit en iyiler birlikte döner (faz belirsiz).
    """
    s = tablo["adim"]
    if s == 1:
        return [0], "adim_1"
    en_iyi: list[int] = []
    en_iyi_puan = None
    for b in range(s):
        pen = pencereler(tablo, b)
        capa = sum(1 for w in pen if w in capalar)
        puan = (capa, sabit_sutun(turler, s, pen), -len(pen))
        if en_iyi_puan is None or puan > en_iyi_puan:
            en_iyi_puan, en_iyi = puan, [b]
        elif puan == en_iyi_puan:
            en_iyi.append(b)
    kaynak = "capa" if en_iyi_puan[0] > 0 else "tutarlilik"
    return en_iyi, kaynak


def cift_benzerlikleri(turler: list[str], s: int, pen: range) -> list[float]:
    """Ardışık kayıt çiftleri için: en az birinde gösterici olan sütunlar içinde iki kayıtta aynı
    kaba sınıfı taşıyanların payı. Sıfır/sayı (N) sütunları sayılmaz; adım 1'de hep 1."""
    n = len(turler)
    pencere = list(pen)

    def sinif(q: int) -> str | None:
        return KABA[turler[q]] if 0 <= q < n else None

    cikti = []
    for a, b in zip(pencere, pencere[1:]):
        if s == 1:
            cikti.append(1.0)
            continue
        sutunlar = [j for j in range(s) if sinif(a + j) != "N" or sinif(b + j) != "N"]
        ayni = sum(1 for j in sutunlar if sinif(a + j) == sinif(b + j))
        cikti.append(ayni / len(sutunlar) if sutunlar else 1.0)
    return cikti


def kayit_benzerligi(turler: list[str], s: int, pen: range) -> float:
    """Ardışık kayıt çifti benzerliklerinin ortalaması (tek kayıtta 1)."""
    ciftler = cift_benzerlikleri(turler, s, pen)
    return sum(ciftler) / len(ciftler) if ciftler else 1.0


def _parcala(g: dict, pen: range, parcalar: list[tuple[int, int]], en_az: int) -> list[dict]:
    """Kayıt dizisinin [r0, r1) parçalarında sütun koşularını kırpıp yeniden gruplar."""
    s = g["adim"]
    yeni = []
    for r0, r1 in parcalar:
        bas, bit = pen[0] + r0 * s, pen[0] + r1 * s          # [bas, bit) kayıt bölgesi
        for p, uz in g["kosular"]:
            k0 = max(0, -(-(bas - p) // s))
            k1 = min(uz - 1, (bit - 1 - p) // s)
            if k1 - k0 + 1 >= en_az:
                yeni.append((p + k0 * s, k1 - k0 + 1))
    return _grupla(s, yeni)


def _bol(g: dict, pen: range, ciftler: list[float], esik: float, en_az: int) -> list[dict]:
    """Eşiğin altındaki çiftlerden kayıt dizisini böler."""
    kesim = [0] + [i + 1 for i, v in enumerate(ciftler) if v < esik] + [len(pen)]
    return _parcala(g, pen, list(zip(kesim, kesim[1:])), en_az)


def _alinmistan_ayir(g: dict, pen: range, alinmis: set[int], en_az: int) -> list[dict]:
    """Penceresi alınmış bir konuma değen kayıtları atar; kalan ardışık kayıtlarla yeniden gruplar."""
    s = g["adim"]
    parcalar = []
    r0 = None
    for r, w in enumerate(pen):
        serbest = not any(q in alinmis for q in range(w, w + s))
        if serbest and r0 is None:
            r0 = r
        elif not serbest and r0 is not None:
            parcalar.append((r0, r))
            r0 = None
    if r0 is not None:
        parcalar.append((r0, len(pen)))
    return _parcala(g, pen, parcalar, en_az)


def bolge(tablo: dict, fazlar: list[int]) -> tuple[int, int]:
    """İlk en iyi fazın kayıt pencerelerinin kapsadığı bölge: [başlangıç, bitiş)."""
    pen = pencereler(tablo, fazlar[0])
    return pen[0], pen[-1] + tablo["adim"]


def tablolari_sec(turler: list[str], capalar: frozenset = frozenset(),
                  en_buyuk_adim: int = EN_BUYUK_ADIM, en_az: int = EN_AZ_KAYIT,
                  esik: float = BENZERLIK_ESIGI,
                  kenar: float = KENAR_ESIGI) -> tuple[list[dict], set[int], Counter]:
    """Dönüş: (tablolar, adım belirsiz bölgedeki konumlar, sayaçlar)."""
    yigin: list = []
    sira = 0

    def it(g):
        nonlocal sira
        heapq.heappush(yigin, (-len(g["yuvalar"]), g["adim"], min(g["yuvalar"]), sira, g))
        sira += 1

    for g in aday_tablolar(turler, en_buyuk_adim, en_az):
        it(g)
    alinmis: set[int] = set()
    belirsiz: set[int] = set()
    sayac: Counter = Counter()
    tablolar: list[dict] = []
    while yigin:
        puan = yigin[0][0]
        parti = []
        while yigin and yigin[0][0] == puan:
            parti.append(heapq.heappop(yigin)[4])
        gecerli = []
        degisti = False
        for g in parti:
            if g["yuvalar"] & alinmis:
                degisti = True
                for k in _kucult(g, alinmis, en_az):
                    it(k)
            else:
                gecerli.append(g)
        if degisti:
            for g in gecerli:
                it(g)
            continue
        uygun = []
        for g in gecerli:
            fazlar, kaynak = faz_sec(turler, g, capalar)
            pen = pencereler(g, fazlar[0])
            ciftler = cift_benzerlikleri(turler, g["adim"], pen)
            benzerlik = sum(ciftler) / len(ciftler) if ciftler else 1.0
            if benzerlik < esik:
                sayac["benzerlik_esigi_alti"] += 1
                for k in _bol(g, pen, ciftler, esik, en_az):   # benzemeyen çiftlerden böl
                    it(k)
                continue
            r0 = 1 if ciftler and ciftler[0] < kenar else 0
            r1 = len(pen) - 1 if ciftler and ciftler[-1] < kenar else len(pen)
            if (r0, r1) != (0, len(pen)):                    # açıkça yabancı kenar kaydı
                sayac["yabanci_kenar_kaydi"] += 1
                for k in _parcala(g, pen, [(r0, r1)], en_az):
                    it(k)
                continue
            g = dict(g, fazlar=fazlar, faz_kaynagi=kaynak, benzerlik=benzerlik,
                     bolge=bolge(g, fazlar), capali=any(w in capalar for w in pen))
            uygun.append(g)
        cakisan = set()
        for i in range(len(uygun)):
            for j in range(i + 1, len(uygun)):
                a, b = uygun[i], uygun[j]
                if (a["adim"] != b["adim"] and a["bolge"][0] < b["bolge"][1]
                        and b["bolge"][0] < a["bolge"][1]):
                    cakisan.update((i, j))
        for i in sorted(cakisan):           # aynı puanda farklı adım: hiçbiri tablo değil
            alan = set(range(*uygun[i]["bolge"]))
            sayac["adim_belirsiz_aday"] += 1
            belirsiz |= alan
            alinmis |= alan
        for i, g in enumerate(uygun):
            if i in cakisan:
                continue
            alan = set(range(*g["bolge"]))
            if alan & alinmis:              # bölgesi alınmış bir bölgeye değiyor
                for k in _alinmistan_ayir(g, pencereler(g, g["fazlar"][0]), alinmis, en_az):
                    it(k)
                continue
            tablolar.append(g)
            alinmis |= alan
    tablolar.sort(key=lambda g: g["bolge"][0])
    return tablolar, belirsiz, sayac


def kayit_dizgileri(turler: list[str], tablo: dict) -> dict[int, tuple]:
    """Tablo bölgesindeki her fonksiyon yuvası → (kesin dizgi konumları, gevşek dizgi konumları).

    Kesin: bütün en iyi fazlarda aynı kayıtta duran dizgiler (kesişim); gevşek: birleşim.
    Yalnız boş olmayan dizgi (S) sayılır.
    """
    s = tablo["adim"]
    bas, bit = tablo["bolge"]
    n = len(turler)
    cikti: dict[int, tuple] = {}
    for p in range(max(0, bas), min(n, bit)):
        if turler[p] not in FONKSIYON_TURLERI:
            continue
        kumeler = []
        for b in tablo["fazlar"]:
            k = p - ((p - b) % s)
            kumeler.append(frozenset(q for q in range(max(0, k), min(n, k + s))
                                     if turler[q] == TUR_S))
        cikti[p] = (frozenset.intersection(*kumeler), frozenset.union(*kumeler))
    return cikti


def tablo_yapisi(turler: list[str], tablo: dict) -> dict:
    """Kayıt sayısı, tam fonksiyon/dizgi sütunu sayısı (ilk en iyi faza göre)."""
    s = tablo["adim"]
    pen = list(pencereler(tablo, tablo["fazlar"][0]))
    n = len(turler)
    fn_sutun = dizgi_sutun = 0
    en_cok_fn = 0
    for w in pen:
        en_cok_fn = max(en_cok_fn, sum(1 for j in range(s) if 0 <= w + j < n
                                       and turler[w + j] in FONKSIYON_TURLERI))
    for j in range(s):
        kolon = [turler[w + j] if 0 <= w + j < n else None for w in pen]
        if all(t in FONKSIYON_TURLERI for t in kolon):
            fn_sutun += 1
        if all(t == TUR_S for t in kolon):
            dizgi_sutun += 1
    return {"adim": s, "kayit": len(pen), "fn_sutun": fn_sutun, "dizgi_sutun": dizgi_sutun,
            "kayitta_en_cok_fn": en_cok_fn, "faz_belirsiz": len(tablo["fazlar"]) > 1,
            "capali": bool(tablo.get("capali"))}


def tablo_sinifi(yapi: dict) -> str:
    """Adım 8 bayt: ardışık göstericiler; dizi mi, yalnız göstericili yapı (vtable) mı baytlardan
    ayırt edilemez. Daha büyük adımda kayıttaki fonksiyon yuvası sayısı ve tam dizgi sütunu."""
    if yapi["adim"] == 1:
        return "gosterici_dizisi"
    cok = yapi["kayitta_en_cok_fn"] >= 2
    dizgili = yapi["dizgi_sutun"] >= 1
    if cok and not dizgili:
        return "cok_fn_dizgisiz"        # sınıf tablosu / vtable benzeri
    if not cok and dizgili:
        return "tek_fn_dizgili"         # ad + işleyici
    if cok and dizgili:
        return "cok_fn_dizgili"
    return "tek_fn_dizgisiz"            # gösterici dizisi ya da {fn, veri}


# ---------------------------------------------------------------------------------------------
# İkili okuma


def _ghidra_bloklari(static_dir: Path) -> tuple[int, dict]:
    bilgi = json.loads((static_dir / "ghidra_combined_results.json").read_text(encoding="utf-8"))
    pi = bilgi["program_info"]
    bloklar = {}
    for b in pi.get("memory_blocks") or []:
        a = OS.onaltilik(b.get("start", ""))
        if a is not None:
            bloklar.setdefault(b["name"], a)
    return int(pi["image_base"], 16), bloklar


def elf_oku(yol: Path, static_dir: Path, giris: dict[int, str]) -> dict:
    """ELF: veri bölümleri (Ghidra adres uzayında) ve yer değişimleri."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    veri = yol.read_bytes()
    taban, bloklar = _ghidra_bloklari(static_dir)
    import io
    e = ELFFile(io.BytesIO(veri))
    yuklemeler = [s["p_vaddr"] for s in e.iter_segments() if s["p_type"] == "PT_LOAD"]
    kayma = taban - min(yuklemeler)
    bolumler = {}
    for s in e.iter_sections():
        if s["sh_addr"] and s["sh_flags"] & 2:
            bolumler[s.name] = s
    if ".text" in bloklar and bloklar[".text"] != bolumler[".text"]["sh_addr"] + kayma:
        raise SystemExit(f"{yol}: Ghidra .text {bloklar['.text']:#x} ≠ ELF + kayma")
    dinsim = e.get_section_by_name(".dynsym")
    yd: dict[int, tuple[str, int | None]] = {}
    sayac = Counter()
    for rs in e.iter_sections():
        if not isinstance(rs, RelocationSection):
            continue
        simgeler = e.get_section(rs["sh_link"]) if rs["sh_link"] else dinsim
        for r in rs.iter_relocations():
            t = r["r_info_type"]
            adres = r["r_offset"] + kayma
            if t == R_AARCH64_RELATIVE:
                yd[adres] = ("hedef", r["r_addend"] + kayma)
                sayac["relative"] += 1
            elif t == R_AARCH64_ABS64:
                sim = simgeler.get_symbol(r["r_info_sym"])
                if sim["st_shndx"] == "SHN_UNDEF":
                    tur = "dis_fonksiyon" if sim["st_info"]["type"] == "STT_FUNC" else "dis_veri"
                    yd[adres] = (tur, None)
                    sayac[f"abs64_{tur}"] += 1
                else:
                    yd[adres] = ("hedef", sim["st_value"] + r["r_addend"] + kayma)
                    sayac["abs64_ic"] += 1
            else:
                sayac["diger_tur"] += 1
    metin = []
    ro = []
    veri_bolumleri = []
    for ad, s in sorted(bolumler.items(), key=lambda kv: kv[1]["sh_addr"]):
        bas = s["sh_addr"] + kayma
        bit = bas + s["sh_size"]
        bayrak = s["sh_flags"]
        if bayrak & 4:
            metin.append((bas, bit))
        elif not bayrak & 1:
            if s["sh_type"] == "SHT_PROGBITS" and not ad.startswith(".eh_frame"):
                ro.append((bas, bit, veri[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]))
        elif s["sh_type"] != "SHT_NOBITS" and ad not in ELF_DISLANAN:
            grup = "baslat" if ad in ELF_BASLAT_DIZILERI else "veri"
            veri_bolumleri.append((ad, grup, bas, veri[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]))
    # kodun adresini GOT üzerinden aldığı iç hedefler
    got_hedefleri = set()
    for ad in (".got", ".got.plt"):
        if ad in bolumler:
            bas = bolumler[ad]["sh_addr"] + kayma
            bit = bas + bolumler[ad]["sh_size"]
            got_hedefleri |= {h for a, (k, h) in yd.items() if k == "hedef" and bas <= a < bit}
    return {"bicim": "elf", "metin": metin, "ro": ro, "veri_bolumleri": veri_bolumleri,
            "yer_degisim": yd, "got_hedefleri": got_hedefleri, "yd_sayac": sayac,
            "kayma": kayma}


def macho_oku(yol: Path, static_dir: Path, giris: dict[int, str], dis_adlar: set[str]) -> dict:
    """Mach-O (chained fixup): veri bölümleri ve rebase/bind'lar; rebase'ler elle de çözülür."""
    import lief

    veri = yol.read_bytes()
    taban, bloklar = _ghidra_bloklari(static_dir)
    ikili = lief.MachO.parse(str(yol))
    if ikili is None or ikili.size != 1:
        raise SystemExit(f"{yol}: tek mimarili Mach-O bekleniyordu")
    b = ikili.at(0)
    if not b.has_dyld_chained_fixups:
        raise SystemExit(f"{yol}: chained fixup yok (desteklenmiyor)")
    bicimler = {str(sc.pointer_format) for sc in b.dyld_chained_fixups.chained_starts_in_segments
                if sc.page_count}
    if bicimler - {"DYLD_CHAINED_PTR_FORMAT.PTR_64_OFFSET"}:
        raise SystemExit(f"{yol}: desteklenmeyen gösterici biçimi {sorted(bicimler)}")
    kayma = taban - b.imagebase
    metin = []
    ro = []
    veri_bolumleri = []
    for seg in b.segments:
        for s in seg.sections:
            bas = s.virtual_address + kayma
            bit = bas + s.size
            sinir = "__text" if s.name == "__text" else None
            if sinir and sinir in bloklar and bloklar[sinir] != bas:
                raise SystemExit(f"{yol}: Ghidra __text {bloklar[sinir]:#x} ≠ Mach-O + kayma")
            bayt = veri[s.offset:s.offset + s.size] if s.offset else b""
            if seg.name == "__TEXT":
                if "PURE_INSTRUCTIONS" in str(s.flags) or "SOME_INSTRUCTIONS" in str(s.flags):
                    metin.append((bas, bit))
                elif s.name not in MACHO_RO_DISLANAN:
                    ro.append((bas, bit, bayt))
            elif seg.name in MACHO_VERI_SEGMENTLERI:
                if "ZEROFILL" in str(s.type) or s.name in MACHO_DISLANAN or not s.offset:
                    continue
                grup = "baslat" if s.name in MACHO_BASLAT else "veri"
                veri_bolumleri.append((f"{seg.name},{s.name}", grup, bas, bayt))
    yd: dict[int, tuple[str, int | None]] = {}
    sayac = Counter()
    ofset_icin = [(s.virtual_address, s.virtual_address + s.size, s.offset) for s in b.sections
                  if s.offset]
    for r in b.relocations:
        if not isinstance(r, lief.MachO.RelocationFixup):
            sayac["diger_tur"] += 1
            continue
        ham = None
        for bas, bit, off in ofset_icin:
            if bas <= r.address < bit:
                ham = struct.unpack_from("<Q", veri, off + r.address - bas)[0]
        elle = None if ham is None or ham >> 63 else \
            b.imagebase + ((((ham >> 36) & 0xFF) << 56) | (ham & ((1 << 36) - 1)))
        if elle != r.target:
            raise SystemExit(f"{yol}: fixup {r.address:#x} elle çözümle uyuşmuyor")
        yd[r.address + kayma] = ("hedef", r.target + kayma)
        sayac["rebase"] += 1
    for bg in b.dyld_chained_fixups.bindings:
        ad = bg.symbol.name if bg.symbol else ""
        tur = "dis_fonksiyon" if ad.lstrip("_") in dis_adlar else "dis_veri"
        yd[bg.address + kayma] = (tur, None)
        sayac[f"bind_{tur}"] += 1
    return {"bicim": "mach-o", "metin": metin, "ro": ro, "veri_bolumleri": veri_bolumleri,
            "yer_degisim": yd, "got_hedefleri": set(), "yd_sayac": sayac, "kayma": kayma}


# ---------------------------------------------------------------------------------------------
# Nüfus (on_sayim.py ile aynı tanım) ve kodda adres alma


def kodda_alinan_adresler(kod: dict[int, list[tuple[int, str, str]]]) -> set[int]:
    """Disassembly'de ``adrp xN, SAYFA`` + ``add xM, xN, #ofset`` ve ``adr xM, ADRES`` ile
    hesaplanan mutlak adresler. Bir yazmaca başka bir komut yazınca sayfa bilgisi silinir."""
    cikti: set[int] = set()
    for _a, komutlar in sorted(kod.items()):
        sayfa: dict[str, int] = {}
        for _pc, mn, isl in komutlar:
            isl = isl.strip()
            ilk = "x" + isl.split(",", 1)[0].strip()[1:] if isl[:1] in ("x", "w") else ""
            if mn == "adrp":
                m = _ADRP.match(isl)
                if m:
                    sayfa["x" + m.group(1)[1:]] = int(m.group(2), 16)
                    continue
            elif mn == "add":
                m = _ADD_IMM.match(isl)
                if m and m.group(2) in sayfa:
                    cikti.add(sayfa[m.group(2)] + int(m.group(3), 16))
            elif mn == "adr":
                m = _ADR.match(isl)
                if m:
                    cikti.add(int(m.group(2), 16))
            if ilk in sayfa and not mn.startswith("st"):
                del sayfa[ilk]
    return cikti


def nufus_oku(static_dir: Path) -> dict:
    """``on_sayim.elf_say``'daki nüfus ve çağıran tanımının aynısı; ek olarak disassembly'den
    kodda adresi alınan fonksiyon girişleri (adrp+add, adr) ve PTR_ etiketleri."""
    fdoc = json.loads((static_dir / "ghidra_functions.json").read_text(encoding="utf-8"))
    xdoc = json.loads((static_dir / "ghidra_xrefs.json").read_text(encoding="utf-8"))
    f: dict[int, dict] = {}
    for kayit in fdoc.get("functions", []):
        a = OS.onaltilik(kayit.get("address", ""))
        if a is None or a in f:
            continue
        ad = str(kayit.get("name") or "")
        dis = bool(kayit.get("is_external")) or bool(kayit.get("is_thunk"))
        tur = ("ic_thunk" if OS.JENERIK_RE.match(ad) else "lib") if dis else "ic"
        f[a] = {"ad": ad, "tur": tur, "dis": bool(kayit.get("is_external"))}
    x_cagrilan: dict[int, set[int]] = {}
    x_cagiran: dict[int, set[int]] = {}
    for anahtar, x in sorted(xdoc.get("function_xrefs", {}).items()):
        a = OS.onaltilik(x.get("address") or anahtar)
        if a is None:
            continue
        x_cagrilan[a] = {h for h in (OS.onaltilik(c.get("address", ""))
                                     for c in x.get("functions_called", [])) if h is not None} - {a}
        x_cagiran[a] = {h for h in (OS.onaltilik(c.get("address", ""))
                                    for c in x.get("called_by", [])) if h is not None} - {a}
    kod_dizini = static_dir / "ghidra_output" / "decompiled"
    kod = OS.komutlari_oku(kod_dizini)
    ozet = {a: OS.govde_ozeti(k) for a, k in kod.items()}

    def ham_hedefler(a: int) -> tuple[set[int], set[int]]:
        xs = set(x_cagrilan.get(a, set()))
        o = ozet.get(a)
        ek: set[int] = set()
        if o:
            ek = {h for h in (o["bl"] | o["kuyruk"]) if h in f and h != a} - xs
        return xs, ek

    def coz(h: int, derinlik: int = 0) -> set[int]:
        v = f.get(h)
        if v is None or v["tur"] != "ic_thunk" or derinlik >= 4:
            return {h}
        xs, ek = ham_hedefler(h)
        alt = (xs | ek) - {h}
        if not alt:
            return {h}
        cikti: set[int] = set()
        for t in sorted(alt):
            cikti |= coz(t, derinlik + 1)
        return cikti

    ic_fonk = [a for a in sorted(f) if f[a]["tur"] == "ic"]
    cagiran: dict[int, set[int]] = {a: set() for a in ic_fonk}
    cagri_sinifi: dict[int, str] = {}
    for a in ic_fonk:
        xs, ek = ham_hedefler(a)
        lib: set[str] = set()
        ic = False
        for h in sorted(xs | ek):
            for t in coz(h):
                v = f.get(t)
                if v is None:
                    continue
                if v["tur"] == "lib":
                    lib.add(OS.import_adi(v["ad"]))
                elif v["tur"] == "ic" and t != a:
                    ic = True
                    cagiran.setdefault(t, set()).add(a)
        # on_sayim.py ana sınıfı: K kütüphane (derleyici eki ve CRT hariç), I iç, Y yaprak
        cagri_sinifi[a] = "K" if lib - OS.DERLEYICI - OS.CRT else ("I" if ic else "Y")
    for a in ic_fonk:
        cagiran[a] |= {c for c in x_cagiran.get(a, set()) if c in cagiran and c != a}
    nufus = [a for a in ic_fonk if OS.BEKLEYEN_RE.match(f[a]["ad"])]

    kod_adresleri = kodda_alinan_adresler(kod)
    adres_alinan = {h for h in kod_adresleri if h in f and f[h]["tur"] == "ic"}

    # Ghidra'nın kodda başvurduğu veri göstericileri: PTR_<önek>_<adres>. Önek sınıfı: jenerik
    # fonksiyon etiketi, kod etiketi, tanımsız veri, dizgi etiketi, adlı simge (ad dışarı verilmez).
    ptr: dict[int, str] = {}
    if kod_dizini.is_dir():
        for yol in sorted(kod_dizini.glob("*.c")):
            metin = yol.read_text(encoding="utf-8", errors="replace")
            for m in _PTR_ETIKETI.finditer(metin):
                onek = m.group(1)
                etiket = ("jenerik_fonksiyon" if onek in ("FUN", "thunk_FUN")
                          else "kod_etiketi" if onek == "LAB" else "tanimsiz_veri" if onek == "DAT"
                          else "dizgi" if onek.startswith("s_") else "adli_simge")
                ptr.setdefault(int(m.group(2), 16), etiket)
    return {"f": f, "nufus": nufus, "cagiran": cagiran, "cagri_sinifi": cagri_sinifi,
            "adres_alinan": adres_alinan,
            "kod_adresleri": kod_adresleri, "ptr": ptr}


def naming_anahtarlari(ws_kok: Path) -> set[str] | None:
    """``reconstructed/src/naming_map.json`` → ``global`` anahtarları (değerler okunmaz)."""
    yol = ws_kok / "reconstructed" / "src" / "naming_map.json"
    if not yol.is_file():
        return None
    veri = json.loads(yol.read_text(encoding="utf-8"))
    g = veri.get("global") if isinstance(veri, dict) else None
    return set(g) if isinstance(g, dict) else None


def ham_ikili(ws_kok: Path) -> Path:
    adaylar = [p for p in sorted((ws_kok / "raw").iterdir())
               if p.is_file() and p.name != "target_info.json"]
    if len(adaylar) != 1:
        raise SystemExit(f"{ws_kok}/raw: {len(adaylar)} ikili (1 bekleniyordu)")
    return adaylar[0]


# ---------------------------------------------------------------------------------------------
# Bir ikilinin sayımı


def capa_kumesi(ik: dict, nf: dict) -> frozenset:
    """Kayıt başlangıcı çapaları: koddan hesaplanan adresler ve bütün yer değişimi hedefleri
    (veri göstericileri ve GOT girdileri). Ghidra adres uzayında."""
    veri_hedefleri = {h for k, h in ik["yer_degisim"].values() if k == "hedef"}
    return frozenset(veri_hedefleri | nf["kod_adresleri"])


def ikili_say(static_dir: Path) -> dict:
    ws_kok = static_dir.parent
    nf = nufus_oku(static_dir)
    f = nf["f"]
    giris = {a: v["tur"] for a, v in f.items() if not v["dis"]}
    dis_adlar = {v["ad"].lstrip("_") for v in f.values() if v["dis"]}
    yol = ham_ikili(ws_kok)
    sihir = yol.read_bytes()[:4]
    if sihir == b"\x7fELF":
        ik = elf_oku(yol, static_dir, giris)
    else:
        ik = macho_oku(yol, static_dir, giris, dis_adlar)
    hedefci = Hedefci(giris, ik["metin"], ik["ro"])
    ghidra_dizgi = {}
    sdoc = json.loads((static_dir / "ghidra_strings.json").read_text(encoding="utf-8"))
    for d in sdoc.get("strings", []):
        a = OS.onaltilik(d.get("address", ""))
        if a is not None:
            ghidra_dizgi[a] = int(d.get("length") or 0)
    dizgi_baslari = sorted(ghidra_dizgi)
    capa_adresleri = capa_kumesi(ik, nf)

    s: Counter = Counter()       # yapı ve çapraz denetim sayaçları
    yapi: Counter = Counter()
    # fonksiyon adresi → kanıtlar
    yuva_veri: set[int] = set()
    yuva_baslat: set[int] = set()
    tablo_kaydi: set[int] = set()
    tablo_sutunu: set[int] = set()
    adim_belirsiz: set[int] = set()
    tablo_turu: dict[int, set[str]] = {}  # fonksiyon → içinde bulunduğu tabloların sınıfları
    capali_tablo_kaydi: set[int] = set()
    kesin_dizgi: dict[int, dict] = {}     # fonksiyon → {"n": en çok dizgi, "sinif": set}
    gevsek_dizgi: dict[int, dict] = {}

    import bisect

    for bolum_adi, grup, bas, bayt in ik["veri_bolumleri"]:
        ilk, turler, hedefler = bolum_turleri(bayt, bas, ik["yer_degisim"], hedefci)
        for i, t in enumerate(turler):
            s[f"sozcuk_{t}"] += 1
            if t in FONKSIYON_TURLERI:
                s[f"fn_yuvasi_{grup}"] += 1
                s[f"fn_yuvasi_bolum:{bolum_adi}"] += 1
            adres = ilk + i * SOZCUK
            if t == TUR_F:
                (yuva_baslat if grup == "baslat" else yuva_veri).add(hedefler[i])
            if t in (TUR_S, TUR_E):
                h = hedefler[i]
                if h in ghidra_dizgi:
                    s["dizgi_yuvasi_ghidra_dizgi_basi"] += 1
                else:
                    k = bisect.bisect_right(dizgi_baslari, h) - 1
                    if k >= 0 and h < dizgi_baslari[k] + ghidra_dizgi[dizgi_baslari[k]]:
                        s["dizgi_yuvasi_ghidra_dizgi_ici"] += 1
                    else:
                        s["dizgi_yuvasi_ghidra_dizgisiz"] += 1
            pt = nf["ptr"].get(adres)
            if pt is not None:
                s[f"ptr_etiketi_{pt}_tur_{t}"] += 1
        if grup != "veri":
            continue
        capalar = frozenset((c - ilk) // SOZCUK for c in capa_adresleri
                            if ilk <= c < ilk + len(turler) * SOZCUK and (c - ilk) % SOZCUK == 0)
        tablolar, belirsiz, sec_sayac = tablolari_sec(turler, capalar)
        yapi.update(sec_sayac)
        for p in belirsiz:
            if turler[p] == TUR_F:
                adim_belirsiz.add(hedefler[p])
        s["adim_belirsiz_bolge_fn_yuvasi"] += sum(1 for p in belirsiz if turler[p] == TUR_F)
        for tb in tablolar:
            y = tablo_yapisi(turler, tb)
            sinif = tablo_sinifi(y)
            yapi["tablo"] += 1
            yapi[f"tablo_sinifi_{sinif}"] += 1
            yapi[f"kayit_{dilim(y['kayit'], KAYIT_DILIMLERI)}"] += 1
            yapi[f"adim_bayt_{dilim(tb['adim'], ADIM_DILIMLERI)}"] += 1
            yapi["kayit_toplam"] += y["kayit"]
            yapi["faz_belirsiz_tablo"] += int(y["faz_belirsiz"])
            yapi[f"faz_kaynagi_{tb['faz_kaynagi']}"] += 1
            yapi["capali_tablo"] += int(y["capali"])
            yapi[f"tablo_bolum:{bolum_adi}"] += 1
            for p in tb["yuvalar"]:
                if turler[p] == TUR_F:
                    tablo_sutunu.add(hedefler[p])
            for p, (kesin, gevsek) in kayit_dizgileri(turler, tb).items():
                yapi["tablo_fn_yuvasi"] += 1
                if turler[p] != TUR_F:
                    continue
                a = hedefler[p]
                tablo_kaydi.add(a)
                tablo_turu.setdefault(a, set()).add(sinif)
                if y["capali"]:
                    capali_tablo_kaydi.add(a)
                for hedef_sozluk, kume in ((kesin_dizgi, kesin), (gevsek_dizgi, gevsek)):
                    if not kume:
                        continue
                    kayit = hedef_sozluk.setdefault(a, {"n": 0, "sinif": set()})
                    kayit["n"] = max(kayit["n"], len(kume))
                    for q in kume:
                        kayit["sinif"].add(dizgi_sinifi(hedefci.dizgi(hedefler[q])))

    # nüfus düzeyi
    adlar = naming_anahtarlari(ws_kok)
    n: Counter = Counter()
    n["isim_bekleyen"] = len(nf["nufus"])
    for a in nf["nufus"]:
        cagrisiz = not nf["cagiran"].get(a)
        n["cagirani_yok" if cagrisiz else "cagirani_var"] += 1
        ks = nf["cagri_sinifi"][a]
        n[f"sinif_{ks}"] += 1
        veri_yuvasi = a in yuva_veri
        tablo = a in tablo_kaydi
        adres_alinan = a in nf["adres_alinan"] or a in ik["got_hedefleri"]
        n["yuva_gosterilen"] += int(veri_yuvasi)
        n["yalniz_baslat_dizisi"] += int(a in yuva_baslat and not veri_yuvasi)
        n["tablo_kaydinda"] += int(tablo)
        n[f"tablo_kaydinda_sinif_{ks}"] += int(tablo)
        n["tablo_sutununda"] += int(a in tablo_sutunu)
        n["capali_tablo_kaydinda"] += int(a in capali_tablo_kaydi)
        turler_a = tablo_turu.get(a, set())
        n["kayit_tablosunda"] += int(bool(turler_a - {"gosterici_dizisi"}))
        n["yalniz_gosterici_dizisinde"] += int(turler_a == {"gosterici_dizisi"})
        for sinif in sorted(turler_a):
            n[f"tablo_sinifinda_{sinif}"] += 1
        n["adim_belirsiz_yuvada_tablosuz"] += int(a in adim_belirsiz and not tablo)
        n["kodda_adresi_alinan"] += int(adres_alinan)
        if cagrisiz:
            n["cagirani_yok_yuva"] += int(veri_yuvasi)
            n["cagirani_yok_tablo"] += int(tablo)
            n["cagirani_yok_kayit_tablosu"] += int(bool(turler_a - {"gosterici_dizisi"}))
            n["cagirani_yok_yuvasiz_kodda_adres"] += int(not veri_yuvasi and adres_alinan)
            n["cagirani_yok_aciklanmayan"] += int(not veri_yuvasi and not adres_alinan
                                                  and a not in yuva_baslat)
        else:
            n["cagirani_var_tablo"] += int(tablo)
        adli = adlar is not None and f[a]["ad"] in adlar
        if tablo:
            n["tablo_ve_bugun_ad_aliyor"] += int(adli)
        for etiket, sozluk in (("kesin", kesin_dizgi), ("gevsek", gevsek_dizgi)):
            k = sozluk.get(a) if tablo else None
            if not k:
                continue
            n[f"{etiket}_kayit_dizgili"] += 1
            n[f"{etiket}_kayit_dizgi_{'1' if k['n'] == 1 else '2+'}"] += 1
            n[f"{etiket}_kayit_dizgili_cagirani_yok"] += int(cagrisiz)
            for sinif in DIZGI_SINIFLARI:
                n[f"{etiket}_dizgi_sinifi_{sinif}"] += int(sinif in k["sinif"])
            ad_kaniti = bool(k["sinif"] & AD_KANITI_SINIFLARI)
            n[f"{etiket}_ad_kanitli"] += int(ad_kaniti)
            n[f"{etiket}_ad_kanitli_capali"] += int(ad_kaniti and a in capali_tablo_kaydi)
            n[f"{etiket}_ust_sinir_capali"] += int(ad_kaniti and not adli
                                                   and a in capali_tablo_kaydi)
            n[f"{etiket}_ad_kanitli_bugun_ad_aliyor"] += int(ad_kaniti and adli)
            n[f"{etiket}_ust_sinir"] += int(ad_kaniti and not adli)
            n[f"{etiket}_ust_sinir_sinif_{ks}"] += int(ad_kaniti and not adli)
            # kayıtta birden çok fonksiyon yuvası: dizgi kaydı adlandırır, yuvayı değil
            n[f"{etiket}_ust_sinir_cok_fn_kaydi"] += int(
                ad_kaniti and not adli and bool(turler_a & {"cok_fn_dizgili", "cok_fn_dizgisiz"}))
    return {"nufus": n, "yapi": yapi, "denetim": s, "yd_sayac": ik["yd_sayac"],
            "bicim": ik["bicim"], "naming_map_var": adlar is not None,
            "girdi_ozeti": hashlib.sha256(yol.read_bytes()).hexdigest()}


# ---------------------------------------------------------------------------------------------
# Birimler, havuz ve çıktı


def oran(pay: int, payda: int) -> float | None:
    return round(pay / payda, 4) if payda else None


ORAN_ANAHTARLARI = (
    ("cagirani_yok", "isim_bekleyen"),
    ("yuva_gosterilen", "isim_bekleyen"),
    ("tablo_kaydinda", "isim_bekleyen"),
    ("kayit_tablosunda", "isim_bekleyen"),
    ("capali_tablo_kaydinda", "isim_bekleyen"),
    ("cagirani_yok_kayit_tablosu", "cagirani_yok"),
    ("cagirani_yok_tablo", "cagirani_yok"),
    ("cagirani_yok_yuva", "cagirani_yok"),
    ("kesin_kayit_dizgili", "tablo_kaydinda"),
    ("gevsek_kayit_dizgili", "tablo_kaydinda"),
    ("kesin_ad_kanitli", "tablo_kaydinda"),
    ("gevsek_ad_kanitli", "tablo_kaydinda"),
    ("tablo_ve_bugun_ad_aliyor", "tablo_kaydinda"),
    ("kesin_ust_sinir", "isim_bekleyen"),
    ("gevsek_ust_sinir", "isim_bekleyen"),
    ("kesin_ust_sinir_capali", "isim_bekleyen"),
)


def oranlar(n: Counter) -> dict:
    return {f"{p}/{q}": oran(n.get(p, 0), n.get(q, 0)) for p, q in ORAN_ANAHTARLARI}


def on_sayim_denetimi(on: dict, birim: str, n: Counter) -> dict:
    s = on["birimler"][birim]["sayim"]
    beklenen_yok = sum(v for k, v in s.items() if k.startswith("cagiran_") and k.endswith("_0"))
    sonuc = {"isim_bekleyen": [n["isim_bekleyen"], s["isim_bekleyen"]],
             "cagirani_yok": [n["cagirani_yok"], beklenen_yok]}
    for k in ("K", "I", "Y"):
        sonuc[f"sinif_{k}"] = [n.get(f"sinif_{k}", 0), s.get(f"sinif_{k}", 0)]
    for k, (biz, onlar) in sonuc.items():
        if biz != onlar:
            raise SystemExit(f"{birim}: {k} {biz} ≠ on_sayim.json {onlar}")
    return sonuc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--mac-kosu", type=Path, required=True)
    ap.add_argument("--debian-kosu", type=Path, required=True)
    ap.add_argument("--on-sayim", type=Path, required=True, help="on_sayim.json")
    ap.add_argument("--cikti", type=Path, required=True)
    args = ap.parse_args()

    on = json.loads(args.on_sayim.read_text(encoding="utf-8"))
    on_betik = Path(OS.__file__).read_bytes()
    if on["kunye"]["betik_sha256"] != hashlib.sha256(on_betik).hexdigest():
        raise SystemExit("on_sayim.json başka bir on_sayim.py sürümünden")
    dizinler = OS.static_dizinleri(args.mac_kosu.expanduser(), args.debian_kosu.expanduser())
    bulunan = Counter(f"{p}/{program}" for p, program, _, _ in dizinler)
    for birim in sorted(set(OS.BEKLENEN_ELF) | set(bulunan)):
        if bulunan.get(birim, 0) != OS.BEKLENEN_ELF.get(birim, 0):
            raise SystemExit(f"{birim}: {bulunan.get(birim, 0)} ikili bulundu")

    birimler: dict[str, dict] = {}
    ikililer = []
    for platform_adi, program, ikili, sd in dizinler:
        r = ikili_say(sd)
        anahtar = f"{platform_adi}/{program}"
        b = birimler.setdefault(anahtar, {"bicim": r["bicim"], "nufus": Counter(),
                                          "yapi": Counter(), "denetim": Counter(),
                                          "yd": Counter(), "ozet": [], "naming_map_eksik": 0})
        b["nufus"].update(r["nufus"])
        b["yapi"].update(r["yapi"])
        b["denetim"].update(r["denetim"])
        b["yd"].update(r["yd_sayac"])
        b["ozet"].append(r["girdi_ozeti"])
        b["naming_map_eksik"] += int(not r["naming_map_var"])
        ikililer.append({"birim": anahtar, "ikili": ikili,
                         **{k: r["nufus"].get(k, 0) for k in
                            ("isim_bekleyen", "cagirani_yok", "tablo_kaydinda",
                             "gevsek_kayit_dizgili", "gevsek_ust_sinir")},
                         "tablo": r["yapi"].get("tablo", 0)})
        print(f"{anahtar:<20}{ikili:<22}{r['nufus']['isim_bekleyen']:>7}"
              f"{r['nufus']['tablo_kaydinda']:>7}{r['yapi'].get('tablo', 0):>6}", file=sys.stderr)

    cikti_birim = {}
    havuzlar = {"tum": Counter(), "debian": Counter(), "mac": Counter()}
    havuz_yapi = {"tum": Counter(), "debian": Counter(), "mac": Counter()}
    for anahtar in sorted(birimler):
        b = birimler[anahtar]
        denetim = on_sayim_denetimi(on, anahtar, b["nufus"])
        cikti_birim[anahtar] = {
            "bicim": b["bicim"],
            "on_sayim_denetimi": denetim,
            "nufus": dict(sorted(b["nufus"].items())),
            "oranlar": oranlar(b["nufus"]),
            "yapi": dict(sorted(b["yapi"].items())),
            "denetim": dict(sorted(b["denetim"].items())),
            "yer_degisim": dict(sorted(b["yd"].items())),
            "naming_map_eksik_ikili": b["naming_map_eksik"],
            "girdi_ozeti": hashlib.sha256("".join(sorted(b["ozet"])).encode()).hexdigest(),
        }
        for h in ("tum", anahtar.split("/")[0]):
            havuzlar[h].update(b["nufus"])
            havuz_yapi[h].update(b["yapi"])
    makro = {}
    for p, q in ORAN_ANAHTARLARI:
        degerler = [v["oranlar"][f"{p}/{q}"] for v in cikti_birim.values()
                    if v["oranlar"][f"{p}/{q}"] is not None]
        makro[f"{p}/{q}"] = round(sum(degerler) / len(degerler), 4) if degerler else None

    belge = {
        "kunye": {
            "betik": "docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py", "surum": SURUM,
            "betik_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "on_sayim_sha256": hashlib.sha256(on_betik).hexdigest(),
            "on_sayim_json_sha256": hashlib.sha256(args.on_sayim.read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "mac_kosu": OS.ev_kisalt(args.mac_kosu), "debian_kosu": OS.ev_kisalt(args.debian_kosu),
            "ikili_sayisi": dict(sorted(bulunan.items())),
            "parametreler": {"sozcuk_bayt": SOZCUK, "en_buyuk_adim_sozcuk": EN_BUYUK_ADIM,
                             "en_az_kayit": EN_AZ_KAYIT, "en_uzun_dizgi": EN_UZUN_DIZGI,
                             "kisa_ad_en_uzun": KISA_AD_EN_UZUN,
                             "benzerlik_esigi": BENZERLIK_ESIGI, "kenar_esigi": KENAR_ESIGI},
            "tanimlar": {
                "fonksiyon_yuvasi": "veri bölümünde 8 bayt hizalı sözcük; yer değişimi hedefi bir "
                                    "Ghidra fonksiyon girişi (iç) ya da içe aktarılan fonksiyon",
                "baslat_dizisi": ".init_array/.fini_array/__mod_init_func ayrı sayılır",
                "dizgi_yuvasi": "hedefi salt okunur, yürütülemeyen bölümde NUL sonlu, "
                                "yazdırılabilir UTF-8 dizgi (boş dizgi ayrı tür)",
                "tablo": "aynı bölümde aynı adımla ≥ 3 kayıt, her kayıtta aynı ofsette fonksiyon "
                         "yuvası; gösterici sütunu benzerliği ≥ eşik; aynı puanda farklı adım: "
                         "belirsiz, tablo değil",
                "kayit_dizgisi": "fonksiyon yuvasıyla aynı kayıt penceresindeki dizgi yuvası",
                "kesin_gevsek": "faz eşitse kesin = bütün eşit fazlarda aynı kayıtta olan "
                                "dizgiler, gevşek = birleşim",
                "capa": "koddan (adrp+add, adr) ya da bir yer değişiminden başvurulan adres",
                "ust_sinir": "tablo kaydı dizgisi tanımlayıcı ya da kısa ad olan, naming_map "
                             "global anahtarlarında olmayan ad bekleyen fonksiyon",
            },
            "dizgi_siniflari": list(DIZGI_SINIFLARI),
            "ad_kaniti_siniflari": sorted(AD_KANITI_SINIFLARI),
            "kayit_dilimleri": [ad for _, ad in KAYIT_DILIMLERI],
            "adim_dilimleri_bayt": [ad for _, ad in ADIM_DILIMLERI],
            "ks1_capalari": "saklı koşularda reconstructed/kesin_capalar.json yok; atlandı",
        },
        "birimler": cikti_birim,
        "havuz": {h: {"nufus": dict(sorted(c.items())), "oranlar": oranlar(c),
                      "yapi": dict(sorted(havuz_yapi[h].items()))}
                  for h, c in havuzlar.items()},
        "makro_birim_ortalamasi": makro,
        "ikililer": sorted(ikililer, key=lambda e: (e["birim"], e["ikili"])),
    }
    args.cikti.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
