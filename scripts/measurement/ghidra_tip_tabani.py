#!/usr/bin/env python3
"""Çıplak Ghidra'nın tip tabanı ve K1 ölçüleri (plan v2.2 T0c).

Girdiler T0b'nin çıktılarıdır; bu betik Ghidra'yı yeniden koşmaz:

- ``--hizalama``: ``parametre_hizala.py`` belgeleri (``karadul-parametre-hizalama/1``);
- ``--ghidra``: ``ghidra_parametre.py`` belgeleri (``karadul-ghidra-parametre/1``; Karadul'un
  Ghidra ayarlarıyla decompiler parametreleri);
- ``--dwarf``: ``dwarf_tip.py toplu`` çıktı dizinleri (T0c sürümü: yapı tablosunda ``yerlesim``,
  ``ilk_uye``, ``takma_adlar``, ``koken``). Belge, hizalama belgesindeki build-id ile bulunur.

Tanımlar
--------
Uygun fonksiyon
    Adresle eşlenmiş, klon değil (``klon`` nedeni yok), Ghidra thunk'ı değil, birimi C, decompile
    başarılı (T0b §9 madde 3).
Nüfus (a)
    Uygun fonksiyonlarda ``depolama_kaynagi == "dwarf"`` ve ``eslesme == "tam"`` olan parametreler.
    Ghidra parametresi ``decompile.parametreler[depolama_ortagi - 1]``.
Sınıf grupları
    DWARF sınıfı ``yapi*``, ``char*``, ``void*``, ``skaler``; geri kalanı (``skaler*``, ``ptr**``,
    ``fonk*``, ``yapi_degerle``, ``diger``) ``diger``.
Adlı tip doğruluğu (a)
    Ghidra tip dizgisi (``str(DataType)``) (ad, işaretçi derinliği) adaylarına çevrilir
    (``ghidra_tipi``): yerleşik ad C adına (``GHIDRA_TEMEL``: ``ulong`` → ``long unsigned int``),
    ``typedef AD TABAN`` biçiminde hem AD (derinlik 0) hem TABAN'ın adayları, ``undefinedN``,
    dizi ve ``code`` aday vermez. DWARF tarafında kabul edilen çiftler (``dwarf_kabul_ciftleri``):
    zincirdeki her typedef adı (önündeki işaretçi sayısıyla), kökün adı (temel tip, yapı, birlik,
    enum, ``void``; tam derinlikle) ve kök yapının takma adları (aynı (tür, ad)'lı bütün yapı
    kayıtlarının ``takma_adlar``'ı; anonimse kökün kendi kaydınınki). Ghidra adaylarıyla kesişim
    boş değilse doğru. Yanında: işaretçi derinliği doğru payı ve Ghidra tip türü dağılımı.
K1 nüfusu (b)
    Nüfus (a)'nın DWARF sınıfı ``yapi*`` olanları. Gerçek sınıf ``dwarf_tip.k1_kimligi``
    (katı) ve ``dwarf_tip.k1_aile_haritasi`` (aile); kimliksiz kökler (``cok_tanimli``,
    ``yerlesim_eksik``, ``hata``) karar ölçüsünden çıkar, ayrı sayılır.
Ghidra kümesi (b)
    Ghidra'nın derinlik 1'de verdiği, yerleşik ya da Ghidra typedef haritasında yerleşiğe inen
    olmayan ad (``ghidra_yapi_etiketi``). Aynı ikilide aynı etiketi alan parametreler bir küme;
    etiketsiz parametre tekildir. Ghidra typedef haritası Ghidra belgelerinin kendisinden
    (``typedef AD TABAN`` dizgileri) kurulur, DWARF'a bakılmaz.
K1 ölçüleri
    Çiftler ikili içinde kurulur, sayılar program içinde toplanır, oran program başına alınır,
    programlar arasında makro ortalama (tanımsız oranlı program ortalamaya girmez, sayısı
    yazılır). Çift kesinliği: aynı kümedeki çiftlerden gerçek sınıfı aynı olanların payı. Çift
    duyarlılığı: gerçek sınıfı aynı çiftlerden aynı kümedekilerin payı. Kapsam: en az iki üyeli
    kümedeki parametrelerin payı (payda K1 nüfusu; ayrıca uygun fonksiyonlardaki bütün ``yapi*``
    ve DWARF'taki bütün ``yapi*``). B-cubed kesinlik en az iki üyeli kümelerdeki öğelerde,
    B-cubed duyarlılık gerçek sınıfı en az iki üyeli öğelerde ortalanır.
Tabakalar
    ``dwarf_tip.k1_tabakasi``: ``kutuphane`` (köken ``sistem`` ya da ``gnulib``), ``program``,
    ``bilinmiyor`` (köken yok). Tabaka, nüfusu o tabakadaki parametrelere kısıtlar; kümeler
    kısıtlanmış nüfusta yeniden sayılır. Duyarlılık kuralı ``tanimsiz_dis``: opak tipler
    kütüphane.
Önemsiz tabanlar (c)
    ``tekil``: her parametre kendi kümesinde (kapsam 0). ``tek_sinif``: bir ikilideki bütün
    ``yapi*`` parametreleri tek kümede. Ghidra yalnız işaretçi boyutunu (8) görseydi "aynı
    boyuttaki bütün yapı işaretçileri tek sınıfta" tabanı budur; çift kesinliği şans düzeyidir.
    Bilgi için ``kahin_boyut``: etiket gösterilen yapının DWARF ``sizeof``'u (araç bunu bilemez).
Negatif kontrol (d)
    Ön kayıt taslağı §2.3: her ikilide küme etiketleri parametreler arasında karıştırılır (küme
    boyutu dağılımı aynen korunur), ``KARISTIRMA_N`` kez, tek tohumlu ``random.Random``
    (``KARISTIRMA_TOHUM_METNI``; ikililer sıralı). Her karıştırmada makro çift kesinliği
    hesaplanır; yüzdelik en yakın sıra yöntemiyle (``v[ceil(q n) - 1]``).
Kapsam tavanı (e)
    Uygun fonksiyonlardaki DWARF ``yapi*`` parametrelerinin hizalananlara oranı (T0b §9 madde 5).
    Ek tavan: kâhin kapsamı, K1 nüfusunda gerçek sınıfı ikilide en az iki üyeli parametrelerin
    payı (kusursuz kümelemenin kapsamı).

Alt komutlar
------------
    olc  --hizalama <dizin> --ghidra <dizin> --dwarf <dizin> -o <çıktı dizini>
         [--karistirma N] [--tohum-metni METİN]

Çıktı: ``<çıktı>/taban.json`` (özet, yollar ``~`` ile) ve ``<çıktı>/parametreler.jsonl``
(parametre başına kayıt).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import platform
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

SEMA = "karadul-ghidra-tip-tabani/1"
HIZALAMA_SEMA = "karadul-parametre-hizalama/1"
GHIDRA_SEMA = "karadul-ghidra-parametre/1"
DWARF_SEMA = "karadul-dwarf-tip/1"
KARISTIRMA_N = 1000
KARISTIRMA_TOHUM_METNI = "karadul-g11-t0c-negatif-kontrol-2026-10-21"
YUZDELIK = 0.99
SINIF_GRUPLARI = ("yapi*", "char*", "void*", "skaler", "diger")
TABAKALAR = ("hepsi", "kutuphane", "program", "bilinmiyor")
DUZEYLER = ("kati", "aile")
KIMLIKLI_DURUMLAR = frozenset({"tanim", "bildirim_cozuldu", "opak"})

# Ghidra yerleşik tip adı -> DWARF (GCC) temel tip adı
GHIDRA_TEMEL = {
    "char": "char", "uchar": "unsigned char", "byte": "unsigned char", "sbyte": "signed char",
    "schar": "signed char", "short": "short int", "ushort": "short unsigned int",
    "word": "short unsigned int", "int": "int", "uint": "unsigned int", "dword": "unsigned int",
    "long": "long int", "ulong": "long unsigned int", "qword": "long unsigned int",
    "longlong": "long long int", "ulonglong": "long long unsigned int", "float": "float",
    "double": "double", "longdouble": "long double", "float10": "long double", "bool": "_Bool",
    "wchar_t": "wchar_t", "wchar16": "char16_t", "wchar32": "char32_t", "int128": "__int128",
    "uint128": "__int128 unsigned",
}
GHIDRA_CHAR = frozenset({"char", "uchar", "byte", "sbyte", "schar"})
_BILINMEYEN_RE = re.compile(r"undefined\d*")
_DIZI_RE = re.compile(r"\[\d*\]")
_ON_EKLER = ("const ", "volatile ", "struct ", "union ", "enum ")
TYPEDEF_SINIRI = 8

_DT_YOLU = Path(__file__).resolve().parent / "dwarf_tip.py"


def _dwarf_tip_modulu() -> Any:
    """``dwarf_tip.py``'yi aynı dizinden yükle (``python -I`` altında da çalışsın diye)."""
    ad = "dwarf_tip_ghidra_tip_tabani"
    if ad in sys.modules:
        return sys.modules[ad]
    spec = importlib.util.spec_from_file_location(ad, _DT_YOLU)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


dt = _dwarf_tip_modulu()


# ---------------------------------------------------------------------------
# Saf yardımcılar
# ---------------------------------------------------------------------------

def tohum(metin: str) -> int:
    return int(hashlib.sha256(metin.encode("utf-8")).hexdigest()[:16], 16)


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _pay(k: float, n: float) -> Optional[float]:
    return round(k / n, 6) if n else None


def ev_yolu(yol: Any) -> str:
    """Depoya girecek metinde ev dizini ``~`` olarak yazılır."""
    s = str(yol)
    ev = str(Path.home())
    return "~" + s[len(ev):] if s == ev or s.startswith(ev + "/") else s


def sinif_grubu(sinif: Optional[str]) -> str:
    return sinif if sinif in ("yapi*", "char*", "void*", "skaler") else "diger"


def yuzdelik(degerler: list[float], q: float = YUZDELIK) -> Optional[float]:
    """En yakın sıra yöntemi: ``v[ceil(q n) - 1]`` (sıralı ``v``)."""
    if not degerler:
        return None
    v = sorted(degerler)
    return v[max(0, math.ceil(q * len(v)) - 1)]


def makro(degerler: Iterable[Optional[float]]) -> dict[str, Any]:
    tanimli = [d for d in degerler if d is not None]
    return {"deger": round(sum(tanimli) / len(tanimli), 6) if tanimli else None,
            "program_sayisi": len(tanimli)}


# ---------------------------------------------------------------------------
# Ghidra tip dizgisi
# ---------------------------------------------------------------------------

def ghidra_typedef_haritasi(tipler: Iterable[str]) -> tuple[dict[str, str], list[str]]:
    """``typedef AD TABAN`` dizgilerinden AD -> TABAN; farklı tabanlı adlar ``cakisan``'da."""
    harita: dict[str, set[str]] = defaultdict(set)
    for t in tipler:
        s = (t or "").strip()
        if s.startswith("typedef "):
            parca = s.split(None, 2)
            if len(parca) == 3:
                harita[parca[1]].add(parca[2].strip())
    cakisan = sorted(a for a, v in harita.items() if len(v) > 1)
    return {a: sorted(v)[0] for a, v in harita.items()}, cakisan


def _yerlesige_iner_mi(ad: str, typedefler: dict[str, str]) -> Optional[str]:
    """Ghidra typedef zinciri yerleşik bir skalere ya da undefined'a iniyorsa onun adı."""
    gorulen = set()
    simdiki = ad
    for _ in range(TYPEDEF_SINIRI):
        if simdiki in gorulen:
            return None
        gorulen.add(simdiki)
        taban = typedefler.get(simdiki)
        if taban is None:
            return None
        if taban.endswith("*") or _DIZI_RE.search(taban):
            return None
        if taban in GHIDRA_TEMEL or _BILINMEYEN_RE.fullmatch(taban):
            return taban
        simdiki = taban
    return None


def ghidra_tipi(metin: Optional[str], typedefler: Optional[dict[str, str]] = None
                ) -> dict[str, Any]:
    """Ghidra ``str(DataType)`` dizgisi -> ``{"tur", "taban", "derinlik", "adaylar"}``.

    ``tur``: ``bilinmiyor`` (undefinedN), ``temel`` (yerleşik skaler), ``temel_typedef`` (Ghidra
    typedef haritasında yerleşiğe inen ad), ``void``, ``kod`` (``code``), ``dizi``, ``adli``
    (başka her ad), ``typedef`` (``typedef AD TABAN`` biçimi), ``bos``. ``adaylar``: (ad,
    derinlik) çiftleri; yerleşikler C adına çevrilir."""
    typedefler = typedefler or {}
    s = (metin or "").strip()
    if not s:
        return {"tur": "bos", "taban": None, "derinlik": 0, "adaylar": []}
    if s.startswith("typedef "):
        parca = s.split(None, 2)
        ad = parca[1] if len(parca) > 1 else ""
        ic = ghidra_tipi(parca[2] if len(parca) > 2 else "", typedefler)
        adaylar = sorted({(ad, 0), *(tuple(a) for a in ic["adaylar"])})
        return {"tur": "typedef", "taban": ad, "derinlik": 0, "ic": ic,
                "adaylar": [list(a) for a in adaylar]}
    derinlik = 0
    while s.endswith("*"):
        derinlik += 1
        s = s[:-1].rstrip()
    degisti = True
    while degisti:
        degisti = False
        for on in _ON_EKLER:
            if s.startswith(on):
                s, degisti = s[len(on):].strip(), True
    adaylar: set[tuple[str, int]] = set()
    if _DIZI_RE.search(s):
        tur = "dizi"
    elif _BILINMEYEN_RE.fullmatch(s):
        tur = "bilinmiyor"
    elif s in GHIDRA_TEMEL:
        tur = "temel"
        adaylar = {(GHIDRA_TEMEL[s], derinlik)}
    elif s == "void":
        tur = "void"
        adaylar = {("void", derinlik)}
    elif s == "code":
        tur = "kod"
    else:
        yerlesik = _yerlesige_iner_mi(s, typedefler)
        if yerlesik is not None:
            tur = "temel_typedef"
            adaylar = {(s, derinlik)}
            if yerlesik in GHIDRA_TEMEL:
                adaylar.add((GHIDRA_TEMEL[yerlesik], derinlik))
        else:
            tur = "adli"
            adaylar = {(s, derinlik)}
    return {"tur": tur, "taban": s, "derinlik": derinlik,
            "adaylar": [list(a) for a in sorted(adaylar)]}


def ghidra_turu_etiketi(g: dict[str, Any]) -> str:
    """Rapor için Ghidra tip türü: ``bilinmiyor``, ``bilinmiyor*``, ``temel``, ``temel*``,
    ``char*``, ``void*``, ``adli``, ``adli*``, ``dizi``, ``kod*``, ``typedef:<iç tür>``."""
    if g["tur"] == "typedef":
        return "typedef:" + ghidra_turu_etiketi(g["ic"])
    yildiz = "*" if g["derinlik"] >= 1 else ""
    if g["tur"] in ("temel", "temel_typedef"):
        if g["derinlik"] == 1 and g["taban"] in GHIDRA_CHAR:
            return "char*"
        return "temel" + yildiz
    if g["tur"] == "void":
        return "void" + yildiz
    if g["tur"] == "kod":
        return "kod" + yildiz
    return g["tur"] + yildiz


def etkin_derinlik(g: dict[str, Any]) -> int:
    """typedef biçiminde iç tipin derinliği (``typedef p_t foo *`` -> 1), yoksa kendi derinliği."""
    return etkin_derinlik(g["ic"]) if g["tur"] == "typedef" else g["derinlik"]


def ghidra_yapi_etiketi(g: dict[str, Any]) -> Optional[str]:
    """K1 kümesi: derinlik 1'de adlı (yerleşik olmayan) tip; typedef biçiminde tabanınınki."""
    if g["tur"] == "typedef":
        return ghidra_yapi_etiketi(g["ic"])
    if g["tur"] == "adli" and g["derinlik"] == 1:
        return g["taban"]
    return None


def dwarf_kabul_ciftleri(tip: dict[str, Any], takma_adlar: Iterable[str] = ()
                         ) -> set[tuple[str, int]]:
    """DWARF tipinin Ghidra'da doğru sayılacak (ad, derinlik) çiftleri (modül belgesi (a))."""
    if not tip.get("cozuldu"):
        return set()
    toplam = tip["derinlik"]
    k = 0
    ciftler: set[tuple[str, int]] = set()
    for adim in tip.get("ham") or []:
        e = adim["etiket"]
        if e == "typedef" and adim.get("ad"):
            ciftler.add((adim["ad"], k))
        elif e in ("pointer_type", "reference_type", "rvalue_reference_type"):
            k += 1
    kok = tip.get("kok") or {}
    if kok.get("tur") in ("temel", "struct", "union", "class", "enum") and kok.get("ad"):
        ciftler.add((kok["ad"], toplam))
    elif kok.get("tur") == "void":
        ciftler.add(("void", toplam))
    for a in takma_adlar:
        ciftler.add((a, toplam))
    return ciftler


def adli_tip_dogru_mu(g: dict[str, Any], kabul: set[tuple[str, int]]) -> bool:
    return any((a, d) in kabul for a, d in g["adaylar"])


# ---------------------------------------------------------------------------
# K1 ölçüleri
# ---------------------------------------------------------------------------

def _c2(n: int) -> int:
    return n * (n - 1) // 2


def k1_sayimlari(ogeler: list[tuple[Optional[str], str]]) -> dict[str, float]:
    """Bir ikilinin (küme etiketi ya da None, gerçek sınıf) listesinden toplanabilir sayılar."""
    etiket = Counter(e for e, _ in ogeler if e is not None)
    gercek = Counter(t for _, t in ogeler)
    ortak = Counter((e, t) for e, t in ogeler if e is not None)
    kapsanan = sum(n for n in etiket.values() if n >= 2)
    b3p = sum(m * m / etiket[e] for (e, t), m in ortak.items() if etiket[e] >= 2)
    b3r = sum(m * m / gercek[t] for (e, t), m in ortak.items() if gercek[t] >= 2)
    b3r += sum(1 / gercek[t] for e, t in ogeler if e is None and gercek[t] >= 2)
    return {"n": len(ogeler), "kapsanan": kapsanan,
            "kume_cifti": sum(_c2(n) for n in etiket.values()),
            "dogru_cift": sum(_c2(m) for m in ortak.values()),
            "gercek_cift": sum(_c2(n) for n in gercek.values()),
            "b3p_toplam": b3p, "b3p_n": kapsanan,
            "b3r_toplam": b3r, "b3r_n": sum(n for n in gercek.values() if n >= 2),
            "kahin_kapsanan": sum(n for n in gercek.values() if n >= 2)}


def k1_topla(sayimlar: Iterable[dict[str, float]]) -> dict[str, float]:
    t: Counter = Counter()
    for s in sayimlar:
        t.update(s)
    return dict(t)


def k1_oranlari(t: dict[str, float]) -> dict[str, Optional[float]]:
    return {"cift_kesinligi": _pay(t.get("dogru_cift", 0), t.get("kume_cifti", 0)),
            "cift_duyarliligi": _pay(t.get("dogru_cift", 0), t.get("gercek_cift", 0)),
            "kapsam": _pay(t.get("kapsanan", 0), t.get("n", 0)),
            "b3_kesinlik": _pay(t.get("b3p_toplam", 0), t.get("b3p_n", 0)),
            "b3_duyarlilik": _pay(t.get("b3r_toplam", 0), t.get("b3r_n", 0)),
            "kahin_kapsam": _pay(t.get("kahin_kapsanan", 0), t.get("n", 0))}


def program_k1(ikililer: dict[str, list[tuple[Optional[str], str]]]) -> dict[str, Any]:
    """Program: ikili başına sayımların toplamı ve oranlar."""
    t = k1_topla(k1_sayimlari(o) for _, o in sorted(ikililer.items()))
    return {"sayimlar": {k: (round(v, 6) if isinstance(v, float) else v) for k, v in t.items()},
            **k1_oranlari(t)}


def makro_k1(programlar: dict[str, dict[str, Any]]) -> dict[str, Any]:
    alanlar = ("cift_kesinligi", "cift_duyarliligi", "kapsam", "b3_kesinlik", "b3_duyarlilik",
               "kahin_kapsam")
    return {a: makro(p[a] for _, p in sorted(programlar.items())) for a in alanlar}


def karistirma_kontrolu(veri: dict[str, dict[str, list[tuple[Optional[str], str]]]], *,
                        n: int = KARISTIRMA_N, tohum_metni: str = KARISTIRMA_TOHUM_METNI,
                        q: float = YUZDELIK) -> dict[str, Any]:
    """Negatif kontrol: program -> ikili -> [(etiket, gerçek)]. Etiketler ikili içinde
    karıştırılır (küme boyutları korunur); her karıştırmada makro çift kesinliği."""
    def makro_kesinlik(v: dict[str, dict[str, list[tuple[Optional[str], str]]]]) -> Optional[float]:
        return makro(program_k1(ik)["cift_kesinligi"] for _, ik in sorted(v.items()))["deger"]

    gozlenen = makro_kesinlik(veri)
    rng = random.Random(tohum(tohum_metni))
    dagilim: list[float] = []
    program_dagilimi: dict[str, list[float]] = defaultdict(list)
    for _ in range(n):
        karisik: dict[str, dict[str, list[tuple[Optional[str], str]]]] = {}
        for p, ikililer in sorted(veri.items()):
            karisik[p] = {}
            for i, ogeler in sorted(ikililer.items()):
                etiketler = [e for e, _ in ogeler]
                rng.shuffle(etiketler)
                karisik[p][i] = [(e, t) for e, (_, t) in zip(etiketler, ogeler)]
            pk = program_k1(karisik[p])["cift_kesinligi"]
            if pk is not None:
                program_dagilimi[p].append(pk)
        m = makro_kesinlik(karisik)
        if m is not None:
            dagilim.append(m)
    esik = yuzdelik(dagilim, q)
    return {"n": n, "tohum_metni": tohum_metni, "tohum": tohum(tohum_metni), "yuzdelik": q,
            "gozlenen": gozlenen, "karisik_yuzdelik": esik,
            "karisik_ortalama": round(sum(dagilim) / len(dagilim), 6) if dagilim else None,
            "fark": round(gozlenen - esik, 6) if gozlenen is not None and esik is not None else None,
            "program": {p: {"gozlenen": program_k1(ik)["cift_kesinligi"],
                            "karisik_yuzdelik": yuzdelik(program_dagilimi[p], q)}
                        for p, ik in sorted(veri.items())}}


# ---------------------------------------------------------------------------
# Belgeler
# ---------------------------------------------------------------------------

def _yukle(yol: Path, sema: str) -> dict[str, Any]:
    b = json.loads(yol.read_text(encoding="utf-8"))
    if b.get("sema") != sema:
        raise ValueError(f"{yol}: şema {b.get('sema')!r}, beklenen {sema!r}")
    return b


def dwarf_indeksi(dwarf_kok: Path) -> dict[str, Path]:
    """build-id -> DWARF belgesi (her alt dizinin ``toplu.json``'ından)."""
    indeks: dict[str, Path] = {}
    for toplu in sorted(dwarf_kok.glob("*/toplu.json")):
        for s in json.loads(toplu.read_text(encoding="utf-8"))["dosyalar"]:
            if s.get("build_id"):
                indeks[s["build_id"]] = toplu.parent / s["cikti"]
    return indeks


def uygun_mu(f: dict[str, Any]) -> bool:
    """Uygun fonksiyon (modül belgesi): adresle eşlenmiş, klonsuz, thunk dışı, C, decompile."""
    ghidra = f.get("ghidra") or {}
    dil = (f.get("dwarf") or {}).get("dil")
    return (f.get("eslesme") == "adres" and not f.get("klon") and not ghidra.get("thunk")
            and dil == "C" and bool(f.get("decompile")))


def takma_ad_haritalari(yapilar: dict[str, dict[str, Any]]
                        ) -> tuple[dict[tuple[str, str], set[str]], dict[str, set[str]]]:
    """(tür, ad) -> takma adlar (bütün kayıtların birleşimi); konum -> takma adlar."""
    adli: dict[tuple[str, str], set[str]] = defaultdict(set)
    konumlu: dict[str, set[str]] = {}
    for k, y in yapilar.items():
        if y.get("hata"):
            continue
        konumlu[k] = set(y.get("takma_adlar") or [])
        if y.get("ad"):
            adli[(y["tur"], y["ad"])].update(y.get("takma_adlar") or [])
    return adli, konumlu


def kok_takma_adlari(tip: dict[str, Any], adli: dict[tuple[str, str], set[str]],
                     konumlu: dict[str, set[str]]) -> set[str]:
    kok = tip.get("kok") or {}
    if kok.get("tur") not in ("struct", "union", "class"):
        return set()
    if kok.get("ad"):
        return adli.get((kok["tur"], kok["ad"]), set())
    return konumlu.get(kok.get("konum"), set())


def ikili_kayitlari(h: dict[str, Any], g: dict[str, Any], d: dict[str, Any],
                    typedefler: dict[str, str]) -> dict[str, Any]:
    """Bir ikilinin (a) ve K1 kayıtları, sayımlar ve tutarlılık denetimi."""
    ikili = h["girdi"]["ikili"]
    dfonk = {f["konum"]: f for f in d["fonksiyonlar"]}
    gfonk = {f["giris"]: f for f in g["fonksiyonlar"]}
    yapilar = d.get("yapilar") or {}
    aile = dt.k1_aile_haritasi(yapilar)
    adli, konumlu = takma_ad_haritalari(yapilar)
    kayitlar: list[dict[str, Any]] = []
    sayac: Counter = Counter()
    for f in h["fonksiyonlar"]:
        if f.get("eslesme") != "adres":
            continue
        sayac["dwarf_yapi_hepsi"] += sum(1 for s in f["parametreler"]
                                         if s["dwarf"]["sinif"] == "yapi*")
        if not uygun_mu(f):
            continue
        df = dfonk.get(f["dwarf"]["konum"])
        gf = gfonk.get(f["ghidra"]["giris"])
        if df is None or gf is None:
            sayac["fonksiyon_bulunamadi"] += 1
            continue
        dpar = {p["konum"]: p for p in df["parametreler"]}
        gp = (gf.get("decompile") or {}).get("parametreler") or []
        for s in f["parametreler"]:
            sd = s["dwarf"]
            if sd["sinif"] == "yapi*":
                sayac["uygun_yapi"] += 1
            if s.get("depolama_kaynagi") != "dwarf" or s.get("eslesme") != "tam":
                if sd["sinif"] == "yapi*":
                    sayac[f"uygun_yapi_disari:{s.get('depolama_kaynagi')}:{s.get('eslesme')}:"
                          f"{s.get('sinif')}"] += 1
                continue
            p = dpar.get(sd["konum"])
            if p is None or not 1 <= s["depolama_ortagi"] <= len(gp):
                sayac["parametre_bulunamadi"] += 1
                continue
            tip = p["tip"]
            if tip.get("kanonik") != sd["tip"] or tip.get("sinif") != sd["sinif"]:
                sayac["tip_uyusmazligi"] += 1
            gpar = gp[s["depolama_ortagi"] - 1]
            gt = ghidra_tipi(gpar["tip"], typedefler)
            kabul = dwarf_kabul_ciftleri(tip, kok_takma_adlari(tip, adli, konumlu))
            kayit: dict[str, Any] = {
                "ikili": ikili, "fonksiyon": f["dwarf"]["ad"], "adres": f["dwarf"]["adres"],
                "konum": sd["konum"], "dwarf_tip": tip.get("kanonik"), "dwarf_sinif": sd["sinif"],
                "grup": sinif_grubu(sd["sinif"]), "ghidra_tip": gpar["tip"],
                "ghidra_turu": ghidra_turu_etiketi(gt), "tip_kilitli": bool(gpar.get("tip_kilitli")),
                "adli_dogru": adli_tip_dogru_mu(gt, kabul),
                "derinlik_dogru": etkin_derinlik(gt) == tip.get("derinlik"),
            }
            if sd["sinif"] == "yapi*":
                kk = (tip.get("kok") or {}).get("konum")
                kim = dt.k1_kimligi(kk, yapilar)
                kayit.update({
                    "kok": kk, "k1_durum": kim["durum"], "kimlik": kim["kimlik"],
                    "aile": aile.get(kim["kimlik"], kim["kimlik"]) if kim["kimlik"] else None,
                    "tabaka": dt.k1_tabakasi(kk, yapilar) or "bilinmiyor",
                    "tabaka_tanimsiz_dis": dt.k1_tabakasi(kk, yapilar, tanimsiz_dis=True)
                    or "bilinmiyor",
                    "ghidra_etiketi": ghidra_yapi_etiketi(gt),
                    "kahin_boyut": _kahin_boyut(kim, yapilar),
                })
            kayitlar.append(kayit)
    return {"ikili": ikili, "paket": h["girdi"].get("paket"), "kayitlar": kayitlar,
            "sayac": dict(sayac)}


def _kahin_boyut(kim: dict[str, Any], yapilar: dict[str, dict[str, Any]]) -> Optional[str]:
    if kim["durum"] not in ("tanim", "bildirim_cozuldu"):
        return None
    b = (yapilar.get(kim["konum"]) or {}).get("boyut")
    return f"boyut:{b}" if isinstance(b, int) else None


# ---------------------------------------------------------------------------
# Ölçüm
# ---------------------------------------------------------------------------

def _k1_ogeleri(kayitlar: list[dict[str, Any]], etiket_alani: str, duzey: str,
                tabaka: str, tabaka_alani: str = "tabaka") -> list[tuple[Optional[str], str]]:
    ogeler = []
    for k in kayitlar:
        if k.get("dwarf_sinif") != "yapi*" or k.get("kimlik") is None:
            continue
        if tabaka != "hepsi" and k.get(tabaka_alani) != tabaka:
            continue
        if etiket_alani == "tekil":
            e: Optional[str] = None
        elif etiket_alani == "tek_sinif":
            e = "tek"
        else:
            e = k.get(etiket_alani)
        ogeler.append((e, k["kimlik"] if duzey == "kati" else k["aile"]))
    return ogeler


def k1_tablosu(veri: dict[str, dict[str, list[dict[str, Any]]]], etiket_alani: str,
               tabaka_alani: str = "tabaka") -> dict[str, Any]:
    """tabaka -> düzey -> {program -> ölçüler, makro}."""
    sonuc: dict[str, Any] = {}
    for tabaka in TABAKALAR:
        sonuc[tabaka] = {}
        for duzey in DUZEYLER:
            programlar = {p: program_k1({i: _k1_ogeleri(kl, etiket_alani, duzey, tabaka,
                                                        tabaka_alani)
                                         for i, kl in sorted(ikililer.items())})
                          for p, ikililer in sorted(veri.items())}
            sonuc[tabaka][duzey] = {"program": programlar, "makro": makro_k1(programlar)}
    return sonuc


def adli_tablosu(veri: dict[str, dict[str, list[dict[str, Any]]]]) -> dict[str, Any]:
    """(a): program -> grup -> sayılar ve paylar; makro ve toplam."""
    programlar: dict[str, Any] = {}
    toplam: dict[str, Counter] = defaultdict(Counter)
    turler_toplam: dict[str, Counter] = defaultdict(Counter)
    for p, ikililer in sorted(veri.items()):
        satir: dict[str, Any] = {}
        sayi: dict[str, Counter] = defaultdict(Counter)
        turler: dict[str, Counter] = defaultdict(Counter)
        for _, kl in sorted(ikililer.items()):
            for k in kl:
                c = sayi[k["grup"]]
                c["n"] += 1
                c["dogru"] += k["adli_dogru"]
                c["derinlik_dogru"] += k["derinlik_dogru"]
                anahtar = "kilitli" if k["tip_kilitli"] else "kilitsiz"
                c[f"{anahtar}_n"] += 1
                c[f"{anahtar}_dogru"] += k["adli_dogru"]
                turler[k["grup"]][k["ghidra_turu"]] += 1
        for grup in SINIF_GRUPLARI:
            c = sayi[grup]
            toplam[grup].update(c)
            turler_toplam[grup].update(turler[grup])
            satir[grup] = {"n": c["n"], "dogru": c["dogru"], "pay": _pay(c["dogru"], c["n"]),
                           "derinlik_dogru_payi": _pay(c["derinlik_dogru"], c["n"]),
                           "kilitli_n": c["kilitli_n"], "kilitli_pay": _pay(c["kilitli_dogru"],
                                                                           c["kilitli_n"]),
                           "kilitsiz_n": c["kilitsiz_n"],
                           "kilitsiz_pay": _pay(c["kilitsiz_dogru"], c["kilitsiz_n"]),
                           "ghidra_turleri": dict(turler[grup].most_common())}
        programlar[p] = satir
    return {
        "program": programlar,
        "makro": {g: {"pay": makro(programlar[p][g]["pay"] for p in programlar),
                      "derinlik_dogru_payi": makro(programlar[p][g]["derinlik_dogru_payi"]
                                                   for p in programlar),
                      "kilitsiz_pay": makro(programlar[p][g]["kilitsiz_pay"] for p in programlar),
                      "kilitli_pay": makro(programlar[p][g]["kilitli_pay"] for p in programlar)}
                  for g in SINIF_GRUPLARI},
        "toplam": {g: {"n": toplam[g]["n"], "dogru": toplam[g]["dogru"],
                       "pay": _pay(toplam[g]["dogru"], toplam[g]["n"]),
                       "kilitli_n": toplam[g]["kilitli_n"],
                       "ghidra_turleri": dict(turler_toplam[g].most_common())}
                   for g in SINIF_GRUPLARI}}


def nufus_tablosu(sayaclar: dict[str, Counter], veri: dict[str, dict[str, list[dict[str, Any]]]]
                  ) -> dict[str, Any]:
    """(e) ve nüfus: program -> uygun/hizalanan/tavan, K1 durumları, tabakalar."""
    programlar: dict[str, Any] = {}
    toplam: Counter = Counter()
    for p in sorted(veri):
        s = sayaclar[p]
        yapi = [k for kl in veri[p].values() for k in kl if k["dwarf_sinif"] == "yapi*"]
        durum = Counter(k["k1_durum"] for k in yapi)
        k1 = [k for k in yapi if k["kimlik"] is not None]
        satir = {
            "dwarf_yapi_hepsi": s["dwarf_yapi_hepsi"], "uygun_yapi": s["uygun_yapi"],
            "hizalanan_yapi": len(yapi), "tavan": _pay(len(yapi), s["uygun_yapi"]),
            "uygun_disari": {k.split(":", 1)[1]: v for k, v in sorted(s.items())
                             if k.startswith("uygun_yapi_disari:")},
            "k1_durum": dict(sorted(durum.items())), "k1_nufus": len(k1),
            "kimliksiz": len(yapi) - len(k1),
            "tabaka": dict(sorted(Counter(k["tabaka"] for k in k1).items())),
            "tabaka_tanimsiz_dis": dict(sorted(Counter(k["tabaka_tanimsiz_dis"]
                                                       for k in k1).items())),
            "kimlik_sayisi": len({(k["ikili"], k["kimlik"]) for k in k1}),
            "aile_sayisi": len({(k["ikili"], k["aile"]) for k in k1}),
        }
        programlar[p] = satir
        for a in ("dwarf_yapi_hepsi", "uygun_yapi", "hizalanan_yapi", "k1_nufus", "kimliksiz"):
            toplam[a] += satir[a]
    return {"program": programlar,
            "toplam": {**dict(toplam), "tavan": _pay(toplam["hizalanan_yapi"],
                                                     toplam["uygun_yapi"])},
            "tavan_makro": makro(programlar[p]["tavan"] for p in programlar)}


def kapsam_paydalari(veri: dict[str, dict[str, list[dict[str, Any]]]], sayaclar: dict[str, Counter],
                     etiket_alani: str = "ghidra_etiketi") -> dict[str, Any]:
    """Kapsamın üç paydası: K1 nüfusu, uygun fonksiyonlardaki yapi*, DWARF'taki bütün yapi*."""
    programlar = {}
    for p in sorted(veri):
        kapsanan = 0
        for kl in veri[p].values():
            ogeler = _k1_ogeleri(kl, etiket_alani, "kati", "hepsi")
            kapsanan += k1_sayimlari(ogeler)["kapsanan"]
        n_k1 = sum(1 for kl in veri[p].values() for k in kl
                   if k["dwarf_sinif"] == "yapi*" and k["kimlik"] is not None)
        programlar[p] = {"kapsanan": kapsanan, "k1_nufusu": _pay(kapsanan, n_k1),
                         "uygun_yapi": _pay(kapsanan, sayaclar[p]["uygun_yapi"]),
                         "dwarf_yapi_hepsi": _pay(kapsanan, sayaclar[p]["dwarf_yapi_hepsi"])}
    return {"program": programlar,
            "makro": {a: makro(programlar[p][a] for p in programlar)
                      for a in ("k1_nufusu", "uygun_yapi", "dwarf_yapi_hepsi")}}


def kume_ornekleri(veri: dict[str, dict[str, list[dict[str, Any]]]], n: int = 12
                   ) -> dict[str, Any]:
    """Ghidra kümelerinin en büyükleri: etiket, boyut, gerçek kimlik dağılımı (denetim için)."""
    sonuc = {}
    for p, ikililer in sorted(veri.items()):
        kumeler: list[dict[str, Any]] = []
        for i, kl in sorted(ikililer.items()):
            grup: dict[str, Counter] = defaultdict(Counter)
            for k in kl:
                if k["dwarf_sinif"] == "yapi*" and k["kimlik"] and k["ghidra_etiketi"]:
                    grup[k["ghidra_etiketi"]][k["kimlik"].split(" #")[0]] += 1
            for e, c in grup.items():
                kumeler.append({"ikili": i, "etiket": e, "boyut": sum(c.values()),
                                "gercek": dict(c.most_common(4))})
        kumeler.sort(key=lambda x: (-x["boyut"], x["ikili"], x["etiket"]))
        sonuc[p] = kumeler[:n]
    return sonuc


def _git_head() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent,
                              capture_output=True, text=True, timeout=10,
                              check=False).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def arac_kunyesi() -> dict[str, Any]:
    return {"betik": "scripts/measurement/ghidra_tip_tabani.py",
            "betik_sha256": sha256_dosya(Path(__file__).resolve()),
            "dwarf_tip_sha256": sha256_dosya(_DT_YOLU), "git_head": _git_head(),
            "python": platform.python_version()}


def olc(hizalama: Path, ghidra: Path, dwarf: Path, cikti: Path, *, karistirma: int = KARISTIRMA_N,
        tohum_metni: str = KARISTIRMA_TOHUM_METNI) -> dict[str, Any]:
    indeks = dwarf_indeksi(dwarf)
    hbelgeler = sorted(j for j in hizalama.glob("*.json") if j.name != "hizalama_indeksi.json")
    gbelgeler = {j.stem: j for j in ghidra.glob("*.json") if j.name != "toplu.json"}
    gtipler: list[str] = []
    gyuklu: dict[str, dict[str, Any]] = {}
    for ad, j in sorted(gbelgeler.items()):
        g = _yukle(j, GHIDRA_SEMA)
        gyuklu[ad] = g
        for f in g["fonksiyonlar"]:
            gtipler.extend(p.get("tip") for p in f.get("liste_parametreleri") or [])
            gtipler.append(f.get("donus_tipi"))
            dec = f.get("decompile") or {}
            gtipler.append(dec.get("donus_tipi"))
            gtipler.extend(p.get("tip") for p in dec.get("parametreler") or [])
    typedefler, cakisan = ghidra_typedef_haritasi(t for t in gtipler if t)
    veri: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    sayaclar: dict[str, Counter] = defaultdict(Counter)
    girdiler: dict[str, Any] = {"hizalama_betik": set(), "dwarf_betik": set(), "ghidra_betik": set()}
    cikti.mkdir(parents=True, exist_ok=True)
    with open(cikti / "parametreler.jsonl", "w", encoding="utf-8") as jl:
        for hj in hbelgeler:
            h = _yukle(hj, HIZALAMA_SEMA)
            ikili = h["girdi"]["ikili"]
            dyol = indeks.get(h["girdi"]["build_id"])
            if dyol is None or ikili not in gyuklu:
                raise FileNotFoundError(f"{ikili}: DWARF ya da Ghidra belgesi yok")
            d = _yukle(dyol, DWARF_SEMA)
            if d["girdi"]["ana"]["build_id"] != h["girdi"]["build_id"]:
                raise ValueError(f"{ikili}: build-id uyuşmuyor")
            girdiler["hizalama_betik"].add((h.get("arac") or {}).get("betik_sha256"))
            girdiler["dwarf_betik"].add((d.get("arac") or {}).get("betik_sha256"))
            girdiler["ghidra_betik"].add((gyuklu[ikili].get("arac") or {}).get("betik_sha256"))
            sonuc = ikili_kayitlari(h, gyuklu[ikili], d, typedefler)
            paket = sonuc["paket"] or ikili
            veri[paket][ikili] = sonuc["kayitlar"]
            sayaclar[paket].update(sonuc["sayac"])
            for k in sonuc["kayitlar"]:
                jl.write(json.dumps(k, ensure_ascii=False) + "\n")
    veri = dict(sorted(veri.items()))
    k1_veri = {p: {i: [(k["ghidra_etiketi"], k["kimlik"]) for k in kl
                       if k["dwarf_sinif"] == "yapi*" and k["kimlik"] is not None]
                   for i, kl in ikililer.items()} for p, ikililer in veri.items()}
    k1_veri_aile = {p: {i: [(k["ghidra_etiketi"], k["aile"]) for k in kl
                            if k["dwarf_sinif"] == "yapi*" and k["kimlik"] is not None]
                        for i, kl in ikililer.items()} for p, ikililer in veri.items()}
    kahin_veri = {p: {i: [(k["kahin_boyut"], k["kimlik"]) for k in kl
                          if k["dwarf_sinif"] == "yapi*" and k["kimlik"] is not None]
                      for i, kl in ikililer.items()} for p, ikililer in veri.items()}
    tutarlilik = {a: sum(s.get(a, 0) for s in sayaclar.values())
                  for a in ("tip_uyusmazligi", "parametre_bulunamadi", "fonksiyon_bulunamadi")}
    ozet = {
        "sema": SEMA, "arac": arac_kunyesi(),
        "girdi": {"hizalama": ev_yolu(hizalama), "ghidra": ev_yolu(ghidra), "dwarf": ev_yolu(dwarf),
                  "hizalama_belgesi": len(hbelgeler),
                  **{a: sorted(str(x) for x in v) for a, v in girdiler.items()}},
        "ghidra_typedef": {"ad": len(typedefler), "cakisan": cakisan},
        "tutarlilik": tutarlilik,
        "nufus": nufus_tablosu(sayaclar, veri),
        "a_adli_tip": adli_tablosu(veri),
        "b_ghidra_k1": k1_tablosu(veri, "ghidra_etiketi"),
        "b_ghidra_k1_tanimsiz_dis": {t: v for t, v in k1_tablosu(
            veri, "ghidra_etiketi", "tabaka_tanimsiz_dis").items() if t in ("kutuphane",
                                                                              "program")},
        "b_kapsam_paydalari": kapsam_paydalari(veri, sayaclar),
        "b_kume_ornekleri": kume_ornekleri(veri),
        "c_onemsiz": {"tekil": k1_tablosu(veri, "tekil"), "tek_sinif": k1_tablosu(veri, "tek_sinif"),
                      "kahin_boyut": k1_tablosu(veri, "kahin_boyut")},
        "d_negatif_kontrol": {
            "ghidra_kati": karistirma_kontrolu(k1_veri, n=karistirma, tohum_metni=tohum_metni),
            "ghidra_aile": karistirma_kontrolu(k1_veri_aile, n=karistirma,
                                               tohum_metni=tohum_metni),
            "kahin_boyut_kati": karistirma_kontrolu(kahin_veri, n=karistirma,
                                                    tohum_metni=tohum_metni)},
    }
    (cikti / "taban.json").write_text(json.dumps(ozet, ensure_ascii=False, indent=1) + "\n",
                                      encoding="utf-8")
    return ozet


def _yz(p: Optional[float]) -> str:
    return "—" if p is None else f"%{100 * p:.1f}"


def ozet_yazdir(oz: dict[str, Any]) -> None:
    n = oz["nufus"]
    print(f"tutarlılık: {oz['tutarlilik']}; Ghidra typedef: {oz['ghidra_typedef']['ad']} ad, "
          f"çakışan {len(oz['ghidra_typedef']['cakisan'])}")
    print(f"nüfus: uygun yapi* {n['toplam']['uygun_yapi']}, hizalanan {n['toplam']['hizalanan_yapi']}"
          f" (tavan {_yz(n['toplam']['tavan'])}), K1 {n['toplam']['k1_nufus']}, kimliksiz "
          f"{n['toplam']['kimliksiz']}")
    a = oz["a_adli_tip"]
    print("(a) adlı tip doğruluğu, makro: " + ", ".join(
        f"{g} {_yz(a['makro'][g]['pay']['deger'])}" for g in SINIF_GRUPLARI))
    for tabaka in TABAKALAR:
        for duzey in DUZEYLER:
            m = oz["b_ghidra_k1"][tabaka][duzey]["makro"]
            print(f"(b) Ghidra {tabaka}/{duzey}: kesinlik {_yz(m['cift_kesinligi']['deger'])} "
                  f"({m['cift_kesinligi']['program_sayisi']} program), duyarlılık "
                  f"{_yz(m['cift_duyarliligi']['deger'])}, kapsam {_yz(m['kapsam']['deger'])}, "
                  f"kâhin kapsam {_yz(m['kahin_kapsam']['deger'])}")
    for ad, k in oz["d_negatif_kontrol"].items():
        print(f"(d) {ad}: gözlenen {k['gozlenen']}, %99 {k['karisik_yuzdelik']}, fark {k['fark']}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    o = sub.add_parser("olc", help="çıplak Ghidra tip tabanı ve K1 ölçüleri")
    o.add_argument("--hizalama", type=Path, required=True)
    o.add_argument("--ghidra", type=Path, required=True)
    o.add_argument("--dwarf", type=Path, required=True)
    o.add_argument("-o", "--out", type=Path, required=True, help="çıktı dizini")
    o.add_argument("--karistirma", type=int, default=KARISTIRMA_N)
    o.add_argument("--tohum-metni", default=KARISTIRMA_TOHUM_METNI)
    a = ap.parse_args(argv)
    oz = olc(a.hizalama, a.ghidra, a.dwarf, a.out, karistirma=a.karistirma,
             tohum_metni=a.tohum_metni)
    ozet_yazdir(oz)
    return 0


if __name__ == "__main__":
    sys.exit(main())
