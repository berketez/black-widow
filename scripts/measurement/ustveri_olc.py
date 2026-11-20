#!/usr/bin/env python3
"""ÜST VERİ ölçümü (P-ÜV8 kalem 2–4): ad eşitliği, kanal düzeyi kesinlik, H1, bütçe, ürün "önce" sayısı.

Soru: üst veri kanalının (adres → ad) verdiği ad, sembollü ikilinin kendi sembol tablosundaki adla (GT)
aynı mı? Set ve GT ``ustveri_set.py``'den gelir (soyulmuş kopya ↔ özgün ikilinin sembol tablosu).

Ad eşitliği (kalem 2; özgün ad üstünden, ``c_identifier`` uygulanmadan; kurallar YALNIZ burada):
  - GT adı önce Mach-O C önekinden arındırılır (baştaki tek ``_``; ObjC ``-[`` / ``+[`` değişmez).
  - Go: birebir; GT'nin ``.abi0`` / ``.abiinternal`` eki soyulunca birebir; kanal adındaki orta nokta
    (``·``) nokta yazılınca birebir.
  - ObjC: birebir; GT adındaki kategori (``-[Sınıf(Kategori) seçici]``) soyulunca birebir.
  - Swift erişim fonksiyonu: GT adının ``xcrun swift-demangle`` çıktısı kanal adıyla birebir.
  - C++: typeinfo adresinde GT = ``_ZTI`` + kanal adı; vtable adresinde GT = ``_ZTV`` + kanal adı.
  - Ürün adı: birebir ya da Go / ObjC kuralları; duyarlılık satırı "tam + biçim" (``ad_bicimi.harf_tam``).

Sayım (adres başına): kanalın en az bir ad verdiği adres "ad verilen"; GT'de o adreste ad yoksa
"GT'siz" (kesinliğin paydasına GİRMEZ); kanalın oradaki adlarının HEPSİ bir GT adıyla eşitse
"doğru", değilse "yanlış". Kesinlik = doğru / (doğru + yanlış), Wilson %95 (``ks1_olc.oran``).
A-2 satırı: Wilson alt sınırı ≥ ``naming_labels.AD_ESIGI`` (= L / (L + 1)).

Kanal çıktısı bu pakette **araştırma okuyucularından** gelir (``scripts/arge/ustveri/``; ürün
okuyucuları P-ÜV1–4 henüz yok). Her çıktı "araştırma okuyucusu, ürün kanalı değil" etiketini taşır.
Sınama ikililerinde kanal kesinliği hesaplanmaz (``kanal`` alt komutu reddeder; Dalga 2).

Alt komutlar
------------
``kanal-cikar``   bir ikiliden kanal çıktısı (adres → ad) JSON'u (depo dışına yazılır).
``kanal``         keşif ikilisinin soyulmuş kopyasında kanal ↔ GT (adsız sayılar).
``yeniden-uret``  araştırma başvuru listesiyle (``$V/go/<ad>.tsv``, ``$V/objc/<ad>.tsv``) aynı mı.
``h1``            özgün dilim ↔ soyulmuş kopya kanal çıktısı farkı (GT okunmaz).
``butce``         hedef başına nüfus / kesin / yuva / sembol / kalan; başvuru ``$V/butce.json`` ile fark.
``urun-kos``      soyulmuş kopyada ürün koşusu (``urun_kos.calistir``; Ghidra kuyruğu dışarıdan sarar).
``urun``          ürün koşusunun adları ↔ GT: ad verilen / doğru / yanlış / GT'siz, kanal kırılımı.

Hiçbir hedef ikili çalıştırılmaz.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
ARASTIRMA_DIZINI = REPO / "scripts" / "arge" / "ustveri"
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)

import ustveri_set as us  # noqa: E402
from ks1_olc import oran  # noqa: E402
from karadul.core.naming_labels import AD_ESIGI  # noqa: E402

SEMA_KANAL = "karadul-ustveri-kanal/1"
SEMA_OLCUM = "karadul-ustveri-olc/1"
KAYNAK_ARASTIRMA = "arastirma_okuyucusu"
ETIKET_ARASTIRMA = "araştırma okuyucusu, ürün kanalı değil"

KANAL_GO = "go_pclntab"
KANAL_OBJC = "objc_method"
KANAL_SWIFT = "swift_type_accessor"
KANAL_RTTI_TI = "rtti_typeinfo"
KANAL_RTTI_VT = "rtti_vtable"
KANALLAR = (KANAL_GO, KANAL_OBJC, KANAL_SWIFT, KANAL_RTTI_TI, KANAL_RTTI_VT)
GT_FONKSIYON = "fonksiyon"
GT_RTTI = "rtti"
KANAL_GT_TURU = {KANAL_GO: GT_FONKSIYON, KANAL_OBJC: GT_FONKSIYON, KANAL_SWIFT: GT_FONKSIYON,
                 KANAL_RTTI_TI: GT_RTTI, KANAL_RTTI_VT: GT_RTTI}

DURUM_CALISTI = "calisti"
DURUM_VERI_YOK = "veri_yok"
DURUM_HATA = "hata"

DOGRU = "dogru"
YANLIS = "yanlis"
GT_SIZ = "gt_siz"

YAZIM_BIREBIR = "birebir"
YAZIM_ABI = "abi_eki"
YAZIM_ORTA_NOKTA = "orta_nokta"
YAZIM_KATEGORI = "kategori"
YAZIM_DEMANGLE = "demangle"
YAZIM_ONEK = "rtti_oneki"
YAZIM_SIRASI = (YAZIM_BIREBIR, YAZIM_ABI, YAZIM_ORTA_NOKTA, YAZIM_KATEGORI, YAZIM_DEMANGLE, YAZIM_ONEK)

ABI_EKI_RE = re.compile(r"\.abi(?:0|internal)$")
ORTA_NOKTA = "·"
SWIFT_ERISIM_ONEKI = "type metadata accessor for "
RTTI_TI_ONEKI = "_ZTI"
RTTI_VT_ONEKI = "_ZTV"
XCRUN = "/usr/bin/xcrun"
macho_c_adi = us.macho_c_adi

A2_EVET = "evet"
A2_HAYIR = "hayir"
A2_VERI_YOK = "veri_yok"


# =============================================================================================
# Kalem 2 — ad eşitliği (tek yer)


def abi_eki_soy(ad: str) -> str:
    """Go sembolündeki ABI ekini soy (yalnız ``.abi0`` / ``.abiinternal``; başka ek değil)."""
    return ABI_EKI_RE.sub("", ad)


def kategori_soy(ad: str) -> str:
    """ObjC sembolündeki kategori adını soy: ``-[Sınıf(Kategori) seçici]`` → ``-[Sınıf seçici]``."""
    if not ad.startswith(("-[", "+[")):
        return ad
    i, j, bosluk = ad.find("("), ad.find(")"), ad.find(" ")
    if 0 < i < j < bosluk:
        return ad[:i] + ad[j + 1:]
    return ad


def go_yazimi(kanal_adi: str, gt_adi: str) -> Optional[str]:
    g = macho_c_adi(gt_adi)
    if kanal_adi == g:
        return YAZIM_BIREBIR
    soyulmus = abi_eki_soy(g)
    if kanal_adi == soyulmus:
        return YAZIM_ABI
    if ORTA_NOKTA in kanal_adi and kanal_adi.replace(ORTA_NOKTA, ".") in (g, soyulmus):
        return YAZIM_ORTA_NOKTA
    return None


def objc_yazimi(kanal_adi: str, gt_adi: str) -> Optional[str]:
    if kanal_adi == gt_adi:
        return YAZIM_BIREBIR
    if kanal_adi == kategori_soy(gt_adi):
        return YAZIM_KATEGORI
    return None


def swift_yazimi(kanal_adi: str, gt_adi: str, cozum: Optional[dict[str, str]]) -> Optional[str]:
    """``cozum``: GT sembolü → ``swift-demangle`` çıktısı. Çözüm yoksa eşitlik kurulamaz (None)."""
    if not cozum or gt_adi not in cozum:
        return None
    return YAZIM_DEMANGLE if cozum[gt_adi] == kanal_adi else None


def rtti_yazimi(kanal_adi: str, gt_adi: str, onek: str) -> Optional[str]:
    return YAZIM_ONEK if macho_c_adi(gt_adi) == onek + kanal_adi else None


def yazim(kanal: str, kanal_adi: str, gt_adi: str, cozum: Optional[dict[str, str]] = None) -> Optional[str]:
    """Kanal adının GT adına eşitliği ve hangi yazım kuralıyla (None: eşit değil)."""
    if kanal == KANAL_GO:
        return go_yazimi(kanal_adi, gt_adi)
    if kanal == KANAL_OBJC:
        return objc_yazimi(kanal_adi, gt_adi)
    if kanal == KANAL_SWIFT:
        return swift_yazimi(kanal_adi, gt_adi, cozum)
    if kanal == KANAL_RTTI_TI:
        return rtti_yazimi(kanal_adi, gt_adi, RTTI_TI_ONEKI)
    if kanal == KANAL_RTTI_VT:
        return rtti_yazimi(kanal_adi, gt_adi, RTTI_VT_ONEKI)
    raise ValueError(f"bilinmeyen kanal: {kanal}")


def urun_esit(urun_adi: str, gt_adi: str) -> bool:
    """Ürünün yazdığı ad GT adıyla eşit mi (birebir ya da Go / ObjC yazım kuralı)."""
    return (urun_adi == macho_c_adi(gt_adi) or go_yazimi(urun_adi, gt_adi) is not None
            or objc_yazimi(urun_adi, gt_adi) is not None)


def en_iyi_yazim(kanal: str, kanal_adi: str, gt_adlari: Iterable[str],
                 cozum: Optional[dict[str, str]] = None) -> Optional[str]:
    bulunan = [y for y in (yazim(kanal, kanal_adi, g, cozum) for g in gt_adlari) if y is not None]
    return min(bulunan, key=YAZIM_SIRASI.index) if bulunan else None


def adres_hukmu(kanal: str, kanal_adlari: Iterable[str], gt_adlari: Optional[Iterable[str]],
                cozum: Optional[dict[str, str]] = None) -> tuple[str, Optional[str]]:
    """(durum, yazım). GT'de ad yoksa GT'siz; kanalın adlarının HEPSİ eşitse doğru."""
    gt = list(gt_adlari or ())
    if not gt:
        return GT_SIZ, None
    yazimlar = []
    for k in sorted(set(kanal_adlari)):
        y = en_iyi_yazim(kanal, k, gt, cozum)
        if y is None:
            return YANLIS, None
        yazimlar.append(y)
    return DOGRU, (max(yazimlar, key=YAZIM_SIRASI.index) if yazimlar else None)


def wilson_alt_kesin(k: int, n: int) -> Optional[float]:
    """Wilson %95 alt sınırı, yuvarlanmadan (A-2 kararı kesirle karşılaştırılır; A-25).
    Formül ve z ``macho_f1.wilson_interval`` ile aynı (o 4 basamağa yuvarlar)."""
    import macho_f1 as mf
    if n <= 0:
        return None
    z = mf.WILSON_Z_95
    p = k / n
    payda = 1 + z * z / n
    merkez = (p + z * z / (2 * n)) / payda
    yari = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / payda
    return max(0.0, merkez - yari)


def a2_satiri(dogru: int, yanlis: int) -> dict[str, Any]:
    alt = wilson_alt_kesin(dogru, dogru + yanlis)
    if alt is None:
        return {"alt_sinir": None, "esik": round(AD_ESIGI, 6), "karar": A2_VERI_YOK}
    return {"alt_sinir": round(alt, 6), "esik": round(AD_ESIGI, 6),
            "karar": A2_EVET if alt >= AD_ESIGI else A2_HAYIR}


def kanal_olc(cikti: dict[int, set[str]], gt: dict[int, list[str]], kanal: str,
              cozum: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Bir kanalın adres → ad çıktısı ↔ GT. Adsız sayılar döner."""
    sayac: Counter = Counter()
    yazimlar: Counter = Counter()
    for adres, adlar in cikti.items():
        if not adlar:
            continue
        sayac["ad_verilen"] += 1
        sayac["cok_adli"] += int(len(set(adlar)) > 1)
        durum, y = adres_hukmu(kanal, adlar, gt.get(adres), cozum)
        sayac[durum] += 1
        if y is not None:
            yazimlar[y] += 1
    dogru, yanlis = sayac[DOGRU], sayac[YANLIS]
    return {"ad_verilen": sayac["ad_verilen"], "dogru": dogru, "yanlis": yanlis, "gt_siz": sayac[GT_SIZ],
            "cok_adli": sayac["cok_adli"], "yazim": {y: yazimlar[y] for y in YAZIM_SIRASI if yazimlar[y]},
            "kesinlik": oran(dogru, dogru + yanlis), "a2": a2_satiri(dogru, yanlis)}


def swift_cozum(gt_adlari: Iterable[str], cozucu: Optional[Callable[[list[str]], list[str]]] = None
                ) -> dict[str, str]:
    """Swift sembollerinin (``_$s…``) ``swift-demangle`` çıktısı. ``cozucu`` testte enjekte edilir."""
    adlar = sorted({g for g in gt_adlari if macho_c_adi(g).startswith(("$s", "$S"))})
    if not adlar:
        return {}
    if cozucu is None:
        def cozucu(xs: list[str]) -> list[str]:
            r = subprocess.run([XCRUN, "swift-demangle"], input="\n".join(xs) + "\n",
                               capture_output=True, text=True, timeout=600, check=True)
            return r.stdout.splitlines()
    cikis = cozucu(adlar)
    if len(cikis) != len(adlar):
        raise RuntimeError(f"swift-demangle {len(adlar)} girdiye {len(cikis)} satır döndü")
    return dict(zip(adlar, cikis))


# =============================================================================================
# Kanal çıktısı (araştırma okuyucuları)


def _arastirma():
    if str(ARASTIRMA_DIZINI) not in sys.path:
        sys.path.insert(0, str(ARASTIRMA_DIZINI))
    import cpp_rtti_tara
    import go_pclntab
    import macho
    import objc_meta
    import swift_meta
    return macho, go_pclntab, objc_meta, swift_meta, cpp_rtti_tara


def _ekle(harita: dict[int, set[str]], adres: Optional[int], ad: Optional[str]) -> None:
    if isinstance(adres, int) and adres and ad:
        harita.setdefault(adres, set()).add(ad)


def _go(m, ar) -> dict[int, set[str]]:
    _macho, G, _o, _s, _r = ar
    if not m.secs_named("__gopclntab"):
        return {}
    h: dict[int, set[str]] = {}
    for f in G.PclnTab(m).funcs():
        _ekle(h, f.entry, f.name)
    return h


def _objc(m, ar) -> dict[int, set[str]]:
    _macho, _g, O, _s, _r = ar
    if not (m.secs_named("__objc_classlist") or m.secs_named("__objc_catlist")):
        return {}
    h: dict[int, set[str]] = {}
    for s in O.yontemler(m)[4]:
        if s["imp"] and s["sinif"] and s["secici"]:
            _ekle(h, s["imp"], f'{s["tur"]}[{s["sinif"]} {s["secici"]}]')
    return h


def _swift(m, ar) -> dict[int, set[str]]:
    _macho, _g, _o, S, _r = ar
    if not m.secs_named("__swift5_types"):
        return {}
    h: dict[int, set[str]] = {}
    for t in S.Swift(m).types():
        if t["erisim"] and t["ad"]:
            _ekle(h, t["erisim"], SWIFT_ERISIM_ONEKI + t["ad"])
    return h


def _rtti(m, ar) -> tuple[dict[int, set[str]], dict[int, set[str]]]:
    _macho, _g, _o, _s, R = ar
    sonuc = R.tara(m)
    if not sonuc:
        return {}, {}
    ti, vt = sonuc
    ti_h: dict[int, set[str]] = {}
    vt_h: dict[int, set[str]] = {}
    for adres, t in ti.items():
        _ekle(ti_h, adres, t["ad"])
    for v in vt:
        _ekle(vt_h, v["adres"], ti[v["typeinfo"]]["ad"] if v["typeinfo"] in ti else None)
    return ti_h, vt_h


def kanal_ciktisi(yol: Path, dilim: Optional[str] = None) -> dict[str, Any]:
    """Araştırma okuyucularıyla adres → ad. Bir kanal patlarsa öbürleri sürer (durum ``hata``)."""
    ar = _arastirma()
    m = ar[0].load(str(yol), dilim)
    kanallar: dict[str, dict[str, Any]] = {}

    def kaydet(kanal: str, harita: dict[int, set[str]], hata: Optional[str] = None) -> None:
        durum = DURUM_HATA if hata else (DURUM_CALISTI if harita else DURUM_VERI_YOK)
        kanallar[kanal] = {"durum": durum, "neden": hata, "adlar": harita}

    for kanal, fn in ((KANAL_GO, _go), (KANAL_OBJC, _objc), (KANAL_SWIFT, _swift)):
        try:
            kaydet(kanal, fn(m, ar))
        except Exception as e:  # noqa: BLE001 — okuyucu hatası kanala yazılır, ölçüm sürer
            kaydet(kanal, {}, f"{type(e).__name__}: {e}")
    try:
        ti_h, vt_h = _rtti(m, ar)
        kaydet(KANAL_RTTI_TI, ti_h)
        kaydet(KANAL_RTTI_VT, vt_h)
    except Exception as e:  # noqa: BLE001
        kaydet(KANAL_RTTI_TI, {}, f"{type(e).__name__}: {e}")
        kaydet(KANAL_RTTI_VT, {}, f"{type(e).__name__}: {e}")
    return {"schema": SEMA_KANAL, "ikili": str(yol), "sha256": us.sha256_dosya(Path(yol)),
            "dilim": dilim, "kaynak": KAYNAK_ARASTIRMA, "etiket": ETIKET_ARASTIRMA, "kanallar": kanallar}


def kanal_json(belge: dict[str, Any]) -> dict[str, Any]:
    """Kanal çıktısını JSON'a uygun biçime çevir (adres onaltılık, adlar sıralı)."""
    out = {k: v for k, v in belge.items() if k != "kanallar"}
    out["kanallar"] = {k: {"durum": v["durum"], "neden": v["neden"],
                           "adlar": [[f"0x{a:x}", sorted(n)] for a, n in sorted(v["adlar"].items())]}
                       for k, v in belge["kanallar"].items()}
    return out


def kanal_json_oku(yol: Path) -> dict[str, Any]:
    belge = json.loads(Path(yol).read_text(encoding="utf-8"))
    if belge.get("schema") != SEMA_KANAL:
        raise ValueError(f"{yol}: şema {belge.get('schema')!r}")
    belge["kanallar"] = {k: {"durum": v["durum"], "neden": v["neden"],
                             "adlar": {int(a, 16): set(n) for a, n in v["adlar"]}}
                         for k, v in belge["kanallar"].items()}
    return belge


def tsv_oku(kanal: str, yol: Path) -> dict[int, set[str]]:
    """Araştırma başvuru listesi (``go_say.py --liste`` / ``objc_meta.py --liste``) → adres → ad."""
    h: dict[int, set[str]] = {}
    for satir in Path(yol).read_text(encoding="utf-8").splitlines():
        if not satir.strip():
            continue
        p = satir.split("\t")
        if kanal == KANAL_GO:          # adres, bitiş, sınıf, paket, ad, dosya, funcID, bayrak
            _ekle(h, int(p[0], 16), p[4])
        elif kanal == KANAL_OBJC:      # imp, tür, sınıf, kategori, seçici, protokolde, swift, tip
            if p[2] not in ("", "None") and p[4] not in ("", "None"):
                _ekle(h, int(p[0], 16), f"{p[1]}[{p[2]} {p[4]}]")
        else:
            raise ValueError(f"{kanal}: başvuru listesi biçimi yok")
    return h


def harita_farki(a: dict[int, set[str]], b: dict[int, set[str]]) -> dict[str, int]:
    """İki adres → ad haritasının farkı (adsız sayılar)."""
    ortak = set(a) & set(b)
    return {"a": len(a), "b": len(b), "yalniz_a": len(set(a) - set(b)), "yalniz_b": len(set(b) - set(a)),
            "ad_farkli": sum(1 for x in ortak if a[x] != b[x])}


def h1_farki(orig: dict[str, Any], soyulmus: dict[str, Any]) -> dict[str, Any]:
    """Kanal başına özgün ↔ soyulmuş kopya farkı; ``ayni`` yalnız durum ve harita birebir aynıysa."""
    out = {}
    for k in KANALLAR:
        a, b = orig["kanallar"][k], soyulmus["kanallar"][k]
        f = harita_farki(a["adlar"], b["adlar"])
        out[k] = {"durum_orig": a["durum"], "durum_soyulmus": b["durum"], **f,
                  "ayni": a["durum"] == b["durum"] and a["adlar"] == b["adlar"]}
    return out


# =============================================================================================
# Bütçe (araştırma ``butce.py`` ile aynı tanımlar)


def butce_say(nufus: set[int], go: set[int], objc: set[int], sw_erisim: set[int], sw_yuva: set[int],
              rtti: set[int], sembol: set[int]) -> dict[str, Any]:
    """kesin = Go ∪ ObjC ∪ Swift erişim; yuva = (Swift yuva ∪ RTTI yuva) − kesin; kalan = nüfus − kesin − sembol.
    Hepsi nüfusla kesiştirilir."""
    go, objc, sw_erisim, sembol = go & nufus, objc & nufus, sw_erisim & nufus, sembol & nufus
    kesin = go | objc | sw_erisim
    yuva = ((sw_yuva | rtti) & nufus) - kesin
    n = len(nufus)
    kalan = nufus - kesin - sembol
    return {"nufus": n, "go_adi": len(go), "objc_yontemi": len(objc), "swift_erisim": len(sw_erisim),
            "kesin": len(kesin), "swift_yuva": len((sw_yuva & nufus) - kesin),
            "rtti_yuva": len((rtti & nufus) - kesin), "yuva": len(yuva), "sembol": len(sembol),
            "kesin_sembolsuz": len(kesin - sembol), "kesin_veya_sembol": len(kesin | sembol),
            "kalan": len(kalan), "kalanin_yuvalisi": len(yuva - sembol)}


BUTCE_SUTUNLARI = ("nufus", "go_adi", "objc_yontemi", "swift_erisim", "kesin", "swift_yuva", "rtti_yuva",
                   "yuva", "sembol", "kesin_sembolsuz", "kesin_veya_sembol", "kalan", "kalanin_yuvalisi")


def butce_kumeleri(yol: Path, dilim: Optional[str] = None) -> dict[str, Any]:
    """Bir hedefin bütçe kümeleri (araştırma okuyucularıyla; ``butce.py``'nin küme tanımları)."""
    ar = _arastirma()
    macho, G, O, S, R = ar
    m = macho.load(str(yol), dilim)
    go_ad = _go(m, ar)
    fs = m.function_starts()
    if fs is None:
        nufus = set(go_ad) | ({m.entry_vm} if m.entry_vm else set())
        kaynak = "pclntab girişleri (LC_FUNCTION_STARTS yok)"
    else:
        nufus, kaynak = set(fs), "LC_FUNCTION_STARTS"
    objc = set(_objc(m, ar))
    sw_erisim: set[int] = set()
    sw_yuva: set[int] = set()
    if m.secs_named("__swift5_types"):
        sw = S.Swift(m)
        tipler = sw.types()
        sw_erisim = {t["erisim"] for t in tipler if t["erisim"]}
        for t in tipler:
            sw_yuva |= {y[4] for y in t["yontem"] if y[4]}
            sw_yuva |= {a for a in t["gecersiz_kilma"] if a}
        text = m.text_sections()
        wt = {u["wt"]: u for u in sw.conformances() if u["wt"] and m.ptr(u["wt"]) == u["adres"]}
        for w, u in wt.items():
            sinir = m.u32(u["protokol_adres"] + 16) if u["protokol_adres"] else None
            j = 1
            while True:
                if sinir is not None and j > sinir:
                    break
                a = w + 8 * j
                if sinir is None and (a in wt or j > 512):
                    break
                pv = m.ptr(a)
                if isinstance(pv, int) and any(t.addr <= pv < t.addr + t.size for t in text):
                    sw_yuva.add(pv)
                elif sinir is None:
                    break
                j += 1
    rtti: set[int] = set()
    try:
        sonuc = R.tara(m)
    except Exception:  # noqa: BLE001 — araştırma bütçesiyle aynı davranış
        sonuc = None
    if sonuc:
        for v in sonuc[1]:
            rtti |= {h for h in v["yuva"] if h}
    tsec = {t.index for t in m.text_sections()}
    sembol = {s.value for s in m.defined_symbols() if s.n_sect in tsec}
    return {"nufus": nufus, "nufus_kaynagi": kaynak, "go": set(go_ad), "objc": objc, "sw_erisim": sw_erisim,
            "sw_yuva": sw_yuva, "rtti": rtti, "sembol": sembol, "dilim": m.cpu}


def butce(yol: Path, dilim: Optional[str] = None) -> dict[str, Any]:
    k = butce_kumeleri(yol, dilim)
    return {"dilim": k["dilim"], "nufus_kaynagi": k["nufus_kaynagi"],
            **butce_say(k["nufus"], k["go"], k["objc"], k["sw_erisim"], k["sw_yuva"], k["rtti"], k["sembol"])}


def butce_farki(benim: dict[str, Any], basvuru: dict[str, Any]) -> dict[str, list[Any]]:
    return {s: [benim.get(s), basvuru.get(s)] for s in BUTCE_SUTUNLARI if benim.get(s) != basvuru.get(s)}


# =============================================================================================
# Ürün koşusu ve ölçümü (kalem 4: bugünkü ürünün "önce" sayısı)

URUN_ANAHTARI = "mac/{ad}"


def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _uptime() -> str:
    try:
        return subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "okunamadı"


def urun_kos(ad: str, set_kok: Path, agac: Path, kok: Path, zaman_asimi: int) -> dict[str, Any]:
    """Soyulmuş kopyada ürünü bir kez koş (``urun_kos.calistir``); künye ``<kök>/mac/<ad>.kunye.json``."""
    import urun_kos as uk
    man = us.manifest_oku(set_kok)["ikililer"][ad]
    if not man["soyma"]["temiz"]:
        raise SystemExit(f"{ad}: soyulmuş kopyada sembol kaldı; ürün koşusu GT sızdırır")
    girdi = us.yollar(set_kok, ad)["bin"]
    is_ = {"anahtar": URUN_ANAHTARI.format(ad=ad), "girdi": girdi, "sha256": man["stripped_sha256"]}
    kunye = {"amac": "HEDEF kalem 4: bugünkü ürünün 'önce' sayısı (bayraklar öntanımlı)",
             "agac": uk.agac_kunyesi(agac), "ghidra": str(uk.GHIDRA), "python": sys.version.split()[0],
             "girdi": str(girdi), "girdi_sha256": man["stripped_sha256"], "zaman_asimi_sn": zaman_asimi,
             "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
             "KARADUL_CACHE_DIR": os.environ.get("KARADUL_CACHE_DIR"),
             "yuk_basta": _uptime(), "baslangic": _simdi()}
    kok.mkdir(parents=True, exist_ok=True)
    sonuc = uk.calistir(is_, agac, kok, zaman_asimi)
    kunye.update({"bitis": _simdi(), "yuk_sonda": _uptime(), "sonuc": sonuc,
                  "agac_bitiste": uk.agac_kunyesi(agac)})
    yol = kok / "mac" / f"{ad}.kunye.json"
    yol.write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return kunye


def calisma_alani(kosu: Path) -> Path:
    """``<koşu>/ws/workspaces/<ad>/<zaman>`` (tek olmalı)."""
    adaylar = sorted((Path(kosu) / "ws" / "workspaces").glob("*/*/static"))
    if len(adaylar) != 1:
        raise SystemExit(f"{kosu}: {len(adaylar)} çalışma alanı (tam olarak bir tane olmalı)")
    return adaylar[0].parent


def urun_nufusu(gt: dict[int, list[str]], gfonk: list[dict[str, Any]]) -> set[int]:
    """Ad bekleyen nüfus: GT'de program sınıfı, Ghidra'da thunk olmayan ve jenerik adlı fonksiyon."""
    import function_f1 as f1
    import macho_f1 as mf
    adsiz = {g["addr"] for g in gfonk if not g["is_thunk"] and f1.is_generic_name(g["name"], [g["addr"]])}
    return {a for a, n in gt.items() if a in adsiz and mf.fragment_class(n) == mf.CLASS_PROGRAM}


def urun_kayitlari(genel: dict[str, Any], koken: dict[str, Any], gfonk: list[dict[str, Any]],
                   gt: dict[int, list[str]], nufus: set[int]) -> tuple[list[dict[str, Any]], Counter]:
    """Ürünün fonksiyon adları: ``FUN_<adres>`` anahtarı, o adreste Ghidra'nın jenerik adlı fonksiyonu,
    yeni ad jenerik değil (``urun_olc.degerlendir_elf`` süzgeci). Hüküm kalem 2 kurallarıyla."""
    import ad_bicimi
    import function_f1 as f1
    import urun_olc as uo
    ghidra = {g["addr"]: g for g in gfonk}
    kayitlar: list[dict[str, Any]] = []
    sayac: Counter = Counter()
    for anahtar in sorted(genel):
        yeni = genel[anahtar]
        sinif, adres = uo.anahtar_sinifi(anahtar)
        if sinif != uo.SINIF_FONKSIYON:
            continue
        g = ghidra.get(adres)
        if not (isinstance(yeni, str) and yeni and yeni != anahtar):
            sayac["ozdes"] += 1
        elif g is None:
            sayac["ghidra_fonksiyonu_yok"] += 1
        elif not f1.is_generic_name(g["name"], [adres]):
            sayac["ghidra_adli"] += 1
        elif f1.is_generic_name(yeni, [adres]):
            sayac["jenerik_ad"] += 1
        else:
            kanal, _alt = uo.kanal_oku(koken.get(anahtar))
            gt_adlari = gt.get(adres)
            if not gt_adlari:
                durum = GT_SIZ
            else:
                durum = DOGRU if any(urun_esit(yeni, x) for x in gt_adlari) else YANLIS
            bicim = durum == DOGRU or bool(gt_adlari and ad_bicimi.harf_tam(
                yeni, [macho_c_adi(x) for x in gt_adlari]))
            kayitlar.append({"adres": adres, "ad": yeni, "durum": durum, "bicim": bicim,
                             "kanal": kanal, "etiket": uo.etiket_oku(koken.get(anahtar)),
                             "nufusta": adres in nufus})
    return kayitlar, sayac


def urun_ozeti(kayitlar: list[dict[str, Any]], nufus: set[int]) -> dict[str, Any]:
    def say(ks: list[dict[str, Any]]) -> dict[str, Any]:
        d = sum(1 for k in ks if k["durum"] == DOGRU)
        y = sum(1 for k in ks if k["durum"] == YANLIS)
        b = sum(1 for k in ks if k["durum"] != GT_SIZ and k["bicim"])
        return {"ad_verilen": len(ks), "dogru": d, "yanlis": y,
                "gt_siz": sum(1 for k in ks if k["durum"] == GT_SIZ),
                "kesinlik": oran(d, d + y), "tam_bicim_dogru": b}
    nf = [k for k in kayitlar if k["nufusta"]]
    return {"toplam": say(kayitlar),
            "kanal": {c: say([k for k in kayitlar if k["kanal"] == c]) for c in sorted({k["kanal"] for k in kayitlar})},
            "etiket": {e: say([k for k in kayitlar if k["etiket"] == e]) for e in sorted({k["etiket"] for k in kayitlar})},
            "nufus": len(nufus), "nufusta_ad": len(nf),
            "dogru_kapsam": oran(sum(1 for k in nf if k["durum"] == DOGRU), len(nufus))}


def ghidra_gt_ozeti(gt: dict[int, list[str]], gfonk: list[dict[str, Any]]) -> dict[str, Any]:
    """GT fonksiyonlarında Ghidra'nın kendi durumu: fonksiyon açtı mı, jenerik olmayan ad verdi mi, ad GT mi."""
    import function_f1 as f1
    ghidra = {g["addr"]: g for g in gfonk}
    acik = [a for a in gt if a in ghidra]
    adli = [a for a in acik if not f1.is_generic_name(ghidra[a]["name"], [a])]
    dogru = [a for a in adli if any(urun_esit(ghidra[a]["name"], x) for x in gt[a])]
    return {"gt_fonksiyonu": len(gt), "ghidra_fonksiyonu_var": len(acik), "ghidra_jenerik_olmayan_ad": len(adli),
            "ghidra_adi_gt_ile_esit": len(dogru), "ghidra_fonksiyonu": len(gfonk)}


def urun_olc(ad: str, set_kok: Path, kok: Path) -> dict[str, Any]:
    import function_f1 as f1
    import urun_olc as uo
    man = us.manifest_oku(set_kok)["ikililer"][ad]
    kosu = Path(kok) / URUN_ANAHTARI.format(ad=ad)
    bitti = (kosu / "BITTI").read_text(encoding="utf-8").strip() if (kosu / "BITTI").is_file() else None
    ws = calisma_alani(kosu)
    hedef = json.loads((ws / "raw" / "target_info.json").read_text(encoding="utf-8"))
    if hedef.get("file_hash") != man["stripped_sha256"]:
        raise SystemExit(f"{ad}: analiz edilen dosya setin soyulmuş kopyası değil")
    gt, _rtti, _b = us.gt_oku(us.yollar(set_kok, ad)["gt"])
    gfonk = f1.load_ghidra_functions(ws / "static" / "ghidra_functions.json")
    taban = json.loads((ws / "static" / "ghidra_combined_results.json").read_text(encoding="utf-8"))
    goruntu = ((taban.get("program_info") or taban.get("summary", {}).get("program") or {}).get("image_base"))
    genel, koken, kimlik = uo.haritayi_oku(ws)
    nufus = urun_nufusu(gt, gfonk)
    kayitlar, sayac = urun_kayitlari(genel, koken, gfonk, gt, nufus)
    return {"schema": SEMA_OLCUM, "olcum": "urun", "ad": ad, "bolme": man["bolme"], "bitti": bitti,
            "girdi_sha256": man["stripped_sha256"], "ghidra_goruntu_tabani": goruntu, "kol_kimligi": kimlik,
            "atlanan": dict(sayac), "ozet": urun_ozeti(kayitlar, nufus), "ghidra": ghidra_gt_ozeti(gt, gfonk)}


# =============================================================================================
# CLI


def _yaz(yol: Optional[Path], belge: Any) -> None:
    metin = json.dumps(belge, ensure_ascii=False, indent=1)
    if yol:
        Path(yol).parent.mkdir(parents=True, exist_ok=True)
        Path(yol).write_text(metin + "\n", encoding="utf-8")
    print(metin)


def kanal_olcumu(ad: str, set_kok: Path, cikti: Optional[dict[str, Any]] = None,
                 sinama_izni: bool = False) -> dict[str, Any]:
    """Keşif ikilisinin soyulmuş kopyasında kanal ↔ GT. Sınama ikilisi reddedilir (Dalga 2)."""
    if us.bolme(ad) != us.BOLME_KESIF and not sinama_izni:
        raise SystemExit(f"{ad}: sınama ikilisi — kanal kesinliği bu pakette hesaplanmaz (Dalga 2)")
    y = us.yollar(set_kok, ad)
    if cikti is None:
        cikti = kanal_ciktisi(y["bin"])
    fonk, rtti, _b = us.gt_oku(y["gt"])
    cozum = swift_cozum([n for v in fonk.values() for n in v]) if cikti["kanallar"][KANAL_SWIFT]["adlar"] else {}
    out = {}
    for k in KANALLAR:
        kc = cikti["kanallar"][k]
        gt = fonk if KANAL_GT_TURU[k] == GT_FONKSIYON else rtti
        out[k] = {"durum": kc["durum"], "neden": kc["neden"], **kanal_olc(kc["adlar"], gt, k, cozum)}
    return {"schema": SEMA_OLCUM, "olcum": "kanal", "ad": ad, "bolme": us.bolme(ad), "kaynak": cikti["kaynak"],
            "etiket": cikti["etiket"], "ikili_sha256": cikti["sha256"], "kanallar": out}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    kc = alt.add_parser("kanal-cikar")
    kc.add_argument("--ikili", type=Path, required=True)
    kc.add_argument("--dilim")
    kc.add_argument("--json", type=Path, required=True)
    k = alt.add_parser("kanal")
    k.add_argument("--ad", required=True)
    k.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    k.add_argument("--json", type=Path)
    yu = alt.add_parser("yeniden-uret")
    yu.add_argument("--ikili", type=Path, required=True)
    yu.add_argument("--kanal", choices=(KANAL_GO, KANAL_OBJC), required=True)
    yu.add_argument("--tsv", type=Path, required=True)
    h = alt.add_parser("h1")
    h.add_argument("--ad", required=True)
    h.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    h.add_argument("--json", type=Path)
    b = alt.add_parser("butce")
    b.add_argument("hedef", nargs="+", help="ad=yol[:dilim]")
    b.add_argument("--basvuru", type=Path, help="araştırma $V/butce.json")
    b.add_argument("--json", type=Path)
    uk = alt.add_parser("urun-kos")
    uk.add_argument("--ad", required=True)
    uk.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    uk.add_argument("--agac", type=Path, required=True)
    uk.add_argument("--kok", type=Path, required=True)
    uk.add_argument("--zaman-asimi", type=int, default=3600)
    uo_ = alt.add_parser("urun")
    uo_.add_argument("--ad", required=True)
    uo_.add_argument("--set-kok", type=Path, default=us.VARSAYILAN_KOK)
    uo_.add_argument("--kok", type=Path, required=True)
    uo_.add_argument("--json", type=Path)
    a = ap.parse_args(argv)

    if a.komut == "kanal-cikar":
        belge = kanal_json(kanal_ciktisi(a.ikili, a.dilim))
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(belge, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({k: {"durum": v["durum"], "adres": len(v["adlar"]), "neden": v["neden"]}
                          for k, v in belge["kanallar"].items()}, ensure_ascii=False))
    elif a.komut == "kanal":
        _yaz(a.json, kanal_olcumu(a.ad, a.set_kok.expanduser()))
    elif a.komut == "yeniden-uret":
        benim = kanal_ciktisi(a.ikili)["kanallar"][a.kanal]["adlar"]
        _yaz(None, {"kanal": a.kanal, "ikili": str(a.ikili), "fark": harita_farki(benim, tsv_oku(a.kanal, a.tsv))})
    elif a.komut == "h1":
        y = us.yollar(a.set_kok.expanduser(), a.ad)
        _yaz(a.json, {"schema": SEMA_OLCUM, "olcum": "h1", "ad": a.ad, "kaynak": KAYNAK_ARASTIRMA,
                      "etiket": ETIKET_ARASTIRMA,
                      "kanallar": h1_farki(kanal_ciktisi(y["orig"]), kanal_ciktisi(y["bin"]))})
    elif a.komut == "butce":
        basvuru = ({r["ad"]: r for r in json.loads(a.basvuru.read_text(encoding="utf-8"))}
                   if a.basvuru else {})
        out = []
        for hd in a.hedef:
            ad, yol = hd.split("=", 1)
            dilim = None
            if ":" in yol:
                yol, dilim = yol.rsplit(":", 1)
            r = {"ad": ad, **butce(Path(yol).expanduser(), dilim)}
            if ad in basvuru:
                r["basvuru_farki"] = butce_farki(r, basvuru[ad])
            out.append(r)
        _yaz(a.json, out)
    elif a.komut == "urun-kos":
        kunye = urun_kos(a.ad, a.set_kok.expanduser(), a.agac.expanduser().resolve(),
                         a.kok.expanduser().resolve(), a.zaman_asimi)
        print(json.dumps(kunye["sonuc"], ensure_ascii=False))
        return 0 if kunye["sonuc"]["durum"] in ("tamam", "kismi") else 1
    elif a.komut == "urun":
        _yaz(a.json, urun_olc(a.ad, a.set_kok.expanduser(), a.kok.expanduser()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
