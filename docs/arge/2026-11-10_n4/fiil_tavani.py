#!/usr/bin/env python3
"""N4 fiil tavanı: geliştirme setinde isim bekleyenlerin GT adlarındaki fiil sınıfları ve üç kural
ailesinin (F-ROL, F-API, F-ETKİ) kusursuz çalışsa en çok kaç fonksiyona doğru fiil verebileceği.

Tanımlar ``fiil_tavani.md``'nin "Tanımlar" bölümündedir (GT açılmadan önce yazıldı). Kısaca:

- Nüfus, K/I/Y sınıfı ve fonksiyon başına çağrı kümeleri ``on_sayim.elf_say``'den alınır: o fonksiyon
  çağrılır ve dönüş anındaki yerel değişkenleri okunur (tanım tek yerde kalsın diye yeniden yazılmadı).
- GT yalnız ``scripts/measurement/ks1_olc.py``'nin ``gt_mac`` / ``gt_elf`` fonksiyonlarıyla okunur.
- Bir GT adının fiil durumu ``on_sayim.fiil_durumu`` ile bulunur (sözlük v0; değiştirilmez).
- Çıktıda fonksiyon adı, GT adı, adres ve sözlük dışı fiil sözcüğü yoktur; yalnız sayılar vardır.
  Adlar yalnız bellekte tutulur. ``--elle-denetim`` 40 örneği uçbirime basar; dosyaya yönlendirilmez.
- Sözlük, aile kümeleri ve eşikler bu ölçüme bakılarak değiştirilmez (sonuç yalnız karar girdisidir).

Kullanım:
    python3 -B docs/arge/2026-11-10_n4/fiil_tavani.py \\
        --mac-kosu workspaces/olcum_mac/runs/ol7-a-9a36142 --mac-veri workspaces/olcum_mac \\
        --debian-kosu ~/karadul_olcum/n1_debian13 \\
        --ek-fiil-listesi ~/karadul_olcum/runs/n4-fiil-tavani-2026-11-10/ek_fiil_listesi.txt \\
        --cikti docs/arge/2026-11-10_n4/fiil_tavani.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import random
import re
import sys
from collections import Counter
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Optional

SURUM = 1
BURASI = Path(__file__).resolve().parent
REPO = BURASI.parents[2]
ON_SAYIM_YOLU = BURASI / "on_sayim.py"
ON_SAYIM_JSON = BURASI / "on_sayim.json"
BELGE_YOLU = BURASI / "fiil_tavani.md"
KS1_YOLU = REPO / "scripts" / "measurement" / "ks1_olc.py"


def _yukle(ad: str, yol: Path) -> ModuleType:
    if ad in sys.modules:
        return sys.modules[ad]
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


on_sayim = _yukle("n4_on_sayim", ON_SAYIM_YOLU)
ks1 = _yukle("ks1_olc", KS1_YOLU)

# ---------------------------------------------------------------------------------------------
# Tanımlar (fiil_tavani.md T2-T6). Sözlük ``on_sayim``'dadır; burada yalnız aile kümeleri var.

FIIL_DURUMLARI = ("tek_sinif", "cok_sinif", "yalniz_genel", "fiilsiz", "parca", "gt_yok", "cpp_disarida")
ADLI_FIIL_DURUMLARI = FIIL_DURUMLARI[:4]                      # GT adı olan ve fiil durumu hesaplanan
YAPISAL_SINIFLAR = ("K", "I", "Y")
BICIMLER = ("yalniz_fiil", "fiil_nesne", "nesne_fiil", "onek_fiil_nesne")

# Taslak §4.2: ailelerin üretebildiği fiil sınıfları
F_API_SINIFLARI = frozenset({"open", "close", "read", "write", "print", "parse", "encode", "find",
                             "sort", "lock", "unlock", "start", "stop", "wait"})
F_ETKI_ILK = frozenset({"create", "destroy"})
F_ETKI_ADAY = frozenset({"init", "get", "set", "is", "copy", "compare"})
# Kaydeden API → rol adının ilk belirtecinin sınıfı (rules.py:213-248). None: rol adı fiilsiz.
ROL_SINIFI = {"qsort": "compare", "bsearch": "compare", "atexit": "fini",
              "sigaction": "handle", "signal": "handle", "event_once": "handle",
              "event_set": "handle", "bufferevent_new": "handle", "pthread_create": None}
F_ROL_SINIFLARI = frozenset(s for s in ROL_SINIFI.values() if s and s != on_sayim.GENEL_SINIF)
ILK_SURUM_SINIFLARI = F_API_SINIFLARI | F_ETKI_ILK | F_ROL_SINIFLARI
ADAYLI_SINIFLAR = ILK_SURUM_SINIFLARI | F_ETKI_ADAY

AYIRICI = frozenset({"malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup"})
BIRAKICI = frozenset({"free"})
FK2_IC_CAGRI_SINIRI = 3            # taslak S13
SARMALAYICI_AZAMI_KOMUT = 32       # bu ölçüme özgü seçimler (T4)
SARMALAYICI_AZAMI_IC = 1
SARMALAYICI_AZAMI_ADIM = 4
ONEK_EN_AZ_AD = 5                  # T6
EN_SIK = 10                        # T5
ELLE_TOHUM = 20261110              # T7
ELLE_TABAKALAR = (("tek_sinif", 16), ("fiilsiz", 14), ("cok_sinif", 5), ("yalniz_genel", 5))
ONDALIK = ks1.ONDALIK
GEREKLI_YERELLER = frozenset({"f", "bilgi_f", "nufus", "kod", "ozet"})
ESLESEN_SAYIMLAR = ("isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y", "K_ayirt_edici",
                    "K_ayirt_edici_ic_cagri_0", "K_ayirt_edici_ic_cagri_1-3",
                    "K_ayirt_edici_ic_cagri_4+")

assert ADAYLI_SINIFLAR <= set(on_sayim.FIIL_SOZLUGU), "aile sınıfı sözlükte yok"
assert on_sayim.GENEL_SINIF not in ADAYLI_SINIFLAR
assert AYIRICI | BIRAKICI <= on_sayim.BELLEK_DIZGI and not AYIRICI & BIRAKICI


# ---------------------------------------------------------------------------------------------
# GT adından fiil (T2), ad biçimi (T6), sözlük dışı fiil listesi (T5)


def ek_listeyi_oku(yol: Path) -> dict[str, frozenset[str]]:
    """Sözlük dışı fiil ölçme listesi: ``[acik]`` ve ``[belirsiz]`` kesimleri. Denetimler tutmazsa durur."""
    kesimler: dict[str, set[str]] = {"acik": set(), "belirsiz": set()}
    kesim = None
    for satir in Path(yol).read_text(encoding="utf-8").splitlines():
        s = satir.split("#", 1)[0].strip()
        if not s:
            continue
        m = re.fullmatch(r"\[(\w+)\]", s)
        if m:
            kesim = m.group(1)
            if kesim not in kesimler:
                raise ValueError(f"bilinmeyen kesim: {kesim}")
            continue
        if kesim is None:
            raise ValueError("kesim başlığından önce belirteç")
        kesimler[kesim].update(s.split())
    hepsi = kesimler["acik"] | kesimler["belirsiz"]
    if not kesimler["acik"]:
        raise ValueError("acik kesimi boş")
    if any(not re.fullmatch(r"[a-z]+", t) for t in hepsi):
        raise ValueError("belirteçler yalnız küçük ASCII harf olmalı")
    if kesimler["acik"] & kesimler["belirsiz"]:
        raise ValueError("bir belirteç iki kesimde")
    if hepsi & set(on_sayim.BELIRTEC_SINIFI):
        raise ValueError("ölçme listesi sözlük v0 ile kesişiyor")
    return {k: frozenset(v) for k, v in kesimler.items()}


def taban_adlar(gt_adlari: Iterable[str], platform_: str) -> tuple[list[str], bool]:
    """(sıralı taban adlar, bütün adlar derleyici ekli mi). Tabanı boş kalan parça adı atılır."""
    tabanlar: set[str] = set()
    n = ekli = 0
    for ham in gt_adlari:
        n += 1
        ad = ks1.platform_adi(ham, platform_)
        t = ks1.klon_tabani(ad)
        if t is None:
            tabanlar.add(ad)
        else:
            ekli += 1
            if t:
                tabanlar.add(t)
    return sorted(tabanlar), n > 0 and ekli == n


def ozel_siniflar(ad: str) -> frozenset[str]:
    """Addaki sözlük sınıfları, genel sınıf hariç (``on_sayim.fiil_durumu`` ile aynı küme)."""
    return frozenset(on_sayim.BELIRTEC_SINIFI[t] for t in on_sayim.belirtecler(ad)
                     if t in on_sayim.BELIRTEC_SINIFI) - {on_sayim.GENEL_SINIF}


def ad_bicimi(ad: str) -> Optional[str]:
    """Sözlük fiilinin (genel hariç; ilki) addaki konumu. Rakam belirteçleri atılır."""
    bel = [t for t in on_sayim.belirtecler(ad) if not t.isdigit()]
    konum = next((i for i, t in enumerate(bel)
                  if on_sayim.BELIRTEC_SINIFI.get(t, on_sayim.GENEL_SINIF) != on_sayim.GENEL_SINIF), None)
    if konum is None:
        return None
    if len(bel) == 1:
        return "yalniz_fiil"
    if konum == 0:
        return "fiil_nesne"
    if konum == len(bel) - 1:
        return "nesne_fiil"
    return "onek_fiil_nesne"


def gt_fiili(gt_adlari: Optional[Iterable[str]], platform_: str,
             ek: Optional[dict[str, frozenset[str]]] = None) -> dict[str, Any]:
    """Bir fonksiyonun GT adlarından fiil durumu. ``anahtar`` ve ``adlar`` yalnız bellekte kalır."""
    bos = {"durum": "gt_yok", "fiil": None, "siniflar": (), "klon_ekli": False, "cok_adli": False,
           "anahtar": None, "adlar": (), "bicim": None, "ilk_belirtec": None, "ek_acik": (),
           "ek_belirsiz": ()}
    if gt_adlari is None:
        return bos
    gt_adlari = list(gt_adlari)
    tabanlar, klon = taban_adlar(gt_adlari, platform_)
    if not tabanlar:
        return {**bos, "durum": "parca", "klon_ekli": klon, "cok_adli": len(gt_adlari) > 1}
    birlesik = "_".join(tabanlar)
    durum, fiil = on_sayim.fiil_durumu(birlesik)
    siniflar = tuple(sorted(ozel_siniflar(birlesik)))
    assert (durum == "tek_sinif") == (len(siniflar) == 1) and (durum == "cok_sinif") == (len(siniflar) > 1)
    bicim = None
    if durum == "tek_sinif":
        bicim = next(b for b in (ad_bicimi(t) for t in tabanlar) if b)
    belirtec = on_sayim.belirtecler(tabanlar[0])
    ek_acik: tuple[str, ...] = ()
    ek_belirsiz: tuple[str, ...] = ()
    if ek and durum in ("fiilsiz", "yalniz_genel"):
        hepsi = set(on_sayim.belirtecler(birlesik))
        ek_acik = tuple(sorted(hepsi & ek["acik"]))
        ek_belirsiz = tuple(sorted(hepsi & ek["belirsiz"]))
    return {"durum": durum, "fiil": fiil, "siniflar": siniflar, "klon_ekli": klon,
            "cok_adli": len(tabanlar) > 1, "anahtar": "\n".join(tabanlar), "adlar": tuple(tabanlar),
            "bicim": bicim, "ilk_belirtec": belirtec[0] if belirtec else None,
            "ek_acik": ek_acik, "ek_belirsiz": ek_belirsiz}


# ---------------------------------------------------------------------------------------------
# GT'siz erişim (T4): on_sayim'in fonksiyon başına ara verisinden


def elf_ayrinti(static_dir: Path) -> tuple[dict, dict]:
    """``on_sayim.elf_say``'i çağırır; (dönüş değeri, dönüş anındaki yerel değişkenler)."""
    yakalanan: dict[str, Any] = {}
    hedef = on_sayim.elf_say.__code__

    def izle(frame, olay, _arg):
        if olay == "return" and frame.f_code is hedef:
            yakalanan.update(frame.f_locals)

    eski = sys.getprofile()
    sys.setprofile(izle)
    try:
        sonuc = on_sayim.elf_say(static_dir)
    finally:
        sys.setprofile(eski)
    eksik = GEREKLI_YERELLER - set(yakalanan)
    if eksik:
        raise RuntimeError(f"on_sayim.elf_say değişmiş: yerel değişken yok: {sorted(eksik)}")
    return sonuc, {k: yakalanan[k] for k in GEREKLI_YERELLER}


def komut_sayilari(f: dict[int, dict], ozet: dict[int, Any]) -> dict[int, int]:
    """``on_sayim``'deki ``n_komut`` ile aynı: disassembly varsa komut sayısı, yoksa boyut / 4."""
    return {a: (ozet[a]["n"] if ozet.get(a) else max(1, v["boyut"] // 4)) for a, v in f.items()}


def sarmalayici_vekilleri(bilgi: dict[int, dict], komut: dict[int, int],
                          aile: frozenset[str]) -> set[int]:
    """FK1'in cömert vekili: ``aile``'nin (ayırıcı ya da bırakıcı) iç sarmalayıcıları (T4)."""
    temel = set()
    for a, b in bilgi.items():
        kalan = b["lib"] - b["hata"]
        if (kalan and kalan <= aile and len(b["ic"]) <= SARMALAYICI_AZAMI_IC
                and komut[a] <= SARMALAYICI_AZAMI_KOMUT):
            temel.add(a)
    hepsi = set(temel)
    for _ in range(SARMALAYICI_AZAMI_ADIM):
        yeni = {a for a, b in bilgi.items()
                if a not in hepsi and not b["lib"] and len(b["ic"]) == 1
                and next(iter(b["ic"])) in hepsi and komut[a] <= SARMALAYICI_AZAMI_KOMUT}
        if not yeni:
            break
        hepsi |= yeni
    return hepsi


def rol_erisimi(bilgi: dict[int, dict], kod: dict[int, list],
                tara: Optional[Callable] = None) -> dict[int, set[str]]:
    """Adresi, kayıt API'si çağıran bir iç fonksiyonda kurulan iç fonksiyonlar → rol sınıfları.

    Fiilsiz rol (``pthread_create``) ``"yok"`` olarak yazılır.
    """
    tara = tara or ks1._mf().scan_code_refs
    baslar = set(bilgi)
    cikti: dict[int, set[str]] = {}
    for r in sorted(bilgi):
        apiler = bilgi[r]["lib"] & set(ROL_SINIFI)
        if not apiler or r not in kod:
            continue
        metin = "\n".join(f"{pc:x}: {mn} {isl}" for pc, mn, isl in kod[r])
        for t in sorted(tara(metin, baslar)["address_taken"] - {r}):
            cikti.setdefault(t, set()).update(ROL_SINIFI[a] or "yok" for a in apiler)
    return cikti


def erisim_bayraklari(b: dict, ayirici_sarm: set[int], birakici_sarm: set[int],
                      roller: Iterable[str]) -> dict[str, Any]:
    """Bir fonksiyonun yapısal sınıfı ve ailelerin ön koşulları (GT'siz)."""
    sinif = "K" if b["lib"] else ("I" if b["ic"] else "Y")
    ayirt_edici = bool(b["lib"] - b["hata"] - b["bellek"])
    o = b.get("ozet")
    create_d = bool(b["lib"] & AYIRICI)
    destroy_d = bool(b["lib"] & BIRAKICI)
    return {
        "sinif": sinif,
        "api_genis": ayirt_edici,
        "api_fk2": ayirt_edici and len(b["ic"]) <= FK2_IC_CAGRI_SINIRI,
        "create_dogrudan": create_d, "destroy_dogrudan": destroy_d,
        "create_sarmalayici": create_d or bool(b["ic"] & ayirici_sarm),
        "destroy_sarmalayici": destroy_d or bool(b["ic"] & birakici_sarm),
        "cagri_yapan": sinif != "Y",
        "yaprak": sinif == "Y",
        "yazmaz": not (o and o["yazar"]),
        "ayirmaz": not create_d,
        "rol": tuple(sorted(roller)),
    }


def elf_kayitlari(birim: str, elf: str, platform_: str, yerel: dict, gt_adlar: Optional[dict],
                  ks1_nufus: Iterable[int] = (), ek: Optional[dict] = None,
                  tara: Optional[Callable] = None) -> list[dict[str, Any]]:
    """Nüfustaki her fonksiyon için bir kayıt. ``gt_adlar`` None ise ELF C++'tır (GT okunmadı)."""
    f, bilgi, kod, ozet = yerel["f"], yerel["bilgi_f"], yerel["kod"], yerel["ozet"]
    komut = komut_sayilari(f, ozet)
    ayirici = sarmalayici_vekilleri(bilgi, komut, AYIRICI)
    birakici = sarmalayici_vekilleri(bilgi, komut, BIRAKICI)
    roller = rol_erisimi(bilgi, kod, tara)
    ks1_nufus = set(ks1_nufus)
    kayitlar = []
    for a in sorted(yerel["nufus"]):
        k = erisim_bayraklari(bilgi[a], ayirici, birakici, roller.get(a, ()))
        if gt_adlar is None:
            k.update(gt_fiili(None, platform_), durum="cpp_disarida")
        else:
            k.update(gt_fiili(gt_adlar.get(a), platform_, ek))
        k.update(birim=birim, elf=elf, adres=a, ks1_nufusunda=a in ks1_nufus, onekli=False)
        kayitlar.append(k)
    return kayitlar


def yeniden_say(kayitlar: list[dict[str, Any]]) -> dict[str, int]:
    """Kayıtlardan ön sayımın sayaçları (``on_sayim`` ile eşleşme denetimi için)."""
    s = Counter({a: 0 for a in ESLESEN_SAYIMLAR})
    for k in kayitlar:
        s["isim_bekleyen"] += 1
        s[f"sinif_{k['sinif']}"] += 1
    return dict(s)


# ---------------------------------------------------------------------------------------------
# Sayım (T3-T6)


def hedef_siniflar(k: dict[str, Any], cok_dahil: bool) -> frozenset[str]:
    if k["durum"] == "tek_sinif":
        return frozenset({k["fiil"]})
    if cok_dahil and k["durum"] == "cok_sinif":
        return frozenset(k["siniflar"])
    return frozenset()


def isabetler(k: dict[str, Any], cok_dahil: bool = False) -> dict[str, bool]:
    """Ailelerin tavan isabetleri: erişim (ön koşul) ∧ GT başvuru sınıfı ailenin verebildiği sınıf."""
    h = hedef_siniflar(k, cok_dahil)
    c, d = "create" in h, "destroy" in h
    i = {
        "f_api_fk2": k["api_fk2"] and bool(h & F_API_SINIFLARI),
        "f_api_genis": k["api_genis"] and bool(h & F_API_SINIFLARI),
        "f_etki_create_dogrudan": k["create_dogrudan"] and c,
        "f_etki_destroy_dogrudan": k["destroy_dogrudan"] and d,
        "f_etki_create_sarmalayici": k["create_sarmalayici"] and c,
        "f_etki_destroy_sarmalayici": k["destroy_sarmalayici"] and d,
        "f_etki_create_cagri": k["cagri_yapan"] and c,
        "f_etki_destroy_cagri": k["cagri_yapan"] and d,
        "aday_get": k["yaprak"] and "get" in h,
        "aday_set": k["yaprak"] and "set" in h,
        "aday_is": k["yazmaz"] and "is" in h,
        "aday_init": k["ayirmaz"] and "init" in h,
        "aday_copy": "copy" in h,
        "aday_compare": "compare" in h,
        "f_rol": bool(set(k["rol"]) & F_ROL_SINIFLARI & h),
        "f_rol_erisimsiz": bool(h & F_ROL_SINIFLARI),
        "erisimsiz_ilk": bool(h & ILK_SURUM_SINIFLARI),
        "erisimsiz_aday": bool(h & ADAYLI_SINIFLAR),
        "sozluk": bool(h),
    }
    for duzey in ("dogrudan", "sarmalayici", "cagri"):
        i[f"f_etki_{duzey}"] = i[f"f_etki_create_{duzey}"] or i[f"f_etki_destroy_{duzey}"]
    i["f_etki_aday"] = any(i[f"aday_{s}"] for s in sorted(F_ETKI_ADAY))
    i["birlesik_ilk_dar"] = i["f_rol"] or i["f_api_fk2"] or i["f_etki_sarmalayici"]
    i["birlesik_ilk_genis"] = i["f_rol"] or i["f_api_genis"] or i["f_etki_cagri"]
    i["birlesik_aday_genis"] = i["birlesik_ilk_genis"] or i["f_etki_aday"]
    return i


ERISIM_ALANLARI = ("api_fk2", "api_genis", "create_dogrudan", "destroy_dogrudan",
                   "create_sarmalayici", "destroy_sarmalayici", "cagri_yapan", "yaprak", "yazmaz",
                   "ayirmaz")
ISABET_ALANLARI = tuple(sorted(isabetler(
    {**{a: False for a in ERISIM_ALANLARI}, "durum": "fiilsiz", "fiil": None, "siniflar": (), "rol": ()})))


def _en_sik(sayac: Counter) -> list[int]:
    return sorted(sayac.values(), reverse=True)[:EN_SIK]


def say(kayitlar: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Bir kayıt kümesinin bütün sayıları. Çıktıda ad, adres ve belirteç yoktur."""
    kayitlar = list(kayitlar)
    durum: Counter = Counter({d: 0 for d in FIIL_DURUMLARI})
    klon: Counter = Counter()
    kiy = {s: Counter({d: 0 for d in FIIL_DURUMLARI}) for s in YAPISAL_SINIFLAR}
    pay: Counter = Counter({s: 0 for s in on_sayim.FIIL_SOZLUGU})
    uyelik: Counter = Counter({s: 0 for s in on_sayim.FIIL_SOZLUGU if s != on_sayim.GENEL_SINIF})
    erisim: Counter = Counter({a: 0 for a in ERISIM_ALANLARI})
    rol_durum: Counter = Counter()
    rol_sinifi: Counter = Counter()
    tavan = {ad: Counter({a: 0 for a in ISABET_ALANLARI}) for ad in ("tek_sinif", "cok_sinif_dahil")}
    bicim: Counter = Counter({b: 0 for b in BICIMLER})
    acik: Counter = Counter()
    hepsi: Counter = Counter()
    dis = Counter({"aday_ad": 0, "acik_tasiyan": 0, "acik_ya_da_belirsiz_tasiyan": 0})
    diger = Counter({"cok_adli": 0, "ks1_nufusunda": 0, "adli": 0, "onekli": 0,
                     "onekli_tek_sinif": 0})
    for k in kayitlar:
        d = k["durum"]
        durum[d] += 1
        kiy[k["sinif"]][d] += 1
        klon[d] += int(k["klon_ekli"])
        diger["cok_adli"] += int(k["cok_adli"])
        diger["ks1_nufusunda"] += int(k["ks1_nufusunda"])
        if d in ADLI_FIIL_DURUMLARI:
            diger["adli"] += 1
            diger["onekli"] += int(k["onekli"])
            diger["onekli_tek_sinif"] += int(k["onekli"] and d == "tek_sinif")
        if d == "tek_sinif":
            pay[k["fiil"]] += 1
            bicim[k["bicim"]] += 1
        for s in k["siniflar"]:
            uyelik[s] += 1
        for a in ERISIM_ALANLARI:
            erisim[a] += int(bool(k[a]))
        if k["rol"]:
            erisim["rol"] += 1
            rol_durum[d] += 1
            for r in k["rol"]:
                rol_sinifi[r] += 1
        for ad, cok in (("tek_sinif", False), ("cok_sinif_dahil", True)):
            for alan, deger in isabetler(k, cok).items():
                tavan[ad][alan] += int(deger)
        if d in ("fiilsiz", "yalniz_genel"):
            dis["aday_ad"] += 1
            dis["acik_tasiyan"] += int(bool(k["ek_acik"]))
            dis["acik_ya_da_belirsiz_tasiyan"] += int(bool(k["ek_acik"] or k["ek_belirsiz"]))
            acik.update(k["ek_acik"])
            hepsi.update(k["ek_acik"])
            hepsi.update(k["ek_belirsiz"])
    erisim.setdefault("rol", 0)
    return {
        "nufus": len(kayitlar),
        "durum": dict(durum),
        "sozlukte_fiil_var": durum["tek_sinif"] + durum["cok_sinif"],
        "klon_ekli": {d: klon[d] for d in FIIL_DURUMLARI},
        "sinif_payi": dict(sorted(pay.items())),
        "sinif_uyeligi_cok_dahil": dict(sorted(uyelik.items())),
        "kiy_durum": {s: dict(kiy[s]) for s in YAPISAL_SINIFLAR},
        "erisim": dict(sorted(erisim.items())),
        "rol_erisim_durum": {d: rol_durum[d] for d in FIIL_DURUMLARI},
        "rol_erisim_sinifi": dict(sorted(rol_sinifi.items())),
        "tavan": {ad: dict(sorted(t.items())) for ad, t in tavan.items()},
        "sozluk_disi": {**dis, "farkli_acik": len(acik), "farkli_acik_ya_da_belirsiz": len(hepsi),
                        "en_sik_acik": _en_sik(acik), "en_sik_acik_ya_da_belirsiz": _en_sik(hepsi)},
        "ad_bicimi": dict(bicim),
        "diger": dict(diger),
    }


def onek_isaretle(kayitlar: list[dict[str, Any]]) -> None:
    """Modül öneki vekili (T6): ilk belirteç sözlükte yok ve birimde ≥ 5 farklı GT adının ilk belirteci."""
    adlar: dict[str, set[str]] = {}
    for k in kayitlar:
        if k["anahtar"] is not None and k["ilk_belirtec"]:
            adlar.setdefault(k["birim"], set()).add((k["ilk_belirtec"], k["anahtar"]))
    sayac = {b: Counter(ilk for ilk, _ in s) for b, s in adlar.items()}
    for k in kayitlar:
        ilk = k["ilk_belirtec"]
        k["onekli"] = bool(ilk and k["anahtar"] is not None and ilk not in on_sayim.BELIRTEC_SINIFI
                           and sayac[k["birim"]][ilk] >= ONEK_EN_AZ_AD)


_VEYA_ALANLARI = ERISIM_ALANLARI + ("ks1_nufusunda", "klon_ekli")


def tekil(kayitlar: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Birim içinde aynı GT adı bir kez (T3). Erişim bayrakları örneklerin VEYA'sıdır; GT adı
    olmayan kayıtlar atılır. Tekil kaydın yapısal sınıfı ilk örneğinkidir (tabloda kullanılmaz)."""
    gruplar: dict[tuple[str, str], dict[str, Any]] = {}
    for k in sorted(kayitlar, key=lambda k: (k["birim"], k["elf"], k["adres"])):
        if k["anahtar"] is None:
            continue
        g = gruplar.get((k["birim"], k["anahtar"]))
        if g is None:
            gruplar[(k["birim"], k["anahtar"])] = dict(k)
            continue
        for a in _VEYA_ALANLARI:
            g[a] = bool(g[a] or k[a])
        g["rol"] = tuple(sorted(set(g["rol"]) | set(k["rol"])))
    return [gruplar[a] for a in sorted(gruplar)]


def _duz(d: dict[str, Any], on: str = "") -> dict[str, int]:
    cikti: dict[str, int] = {}
    for a, v in d.items():
        if isinstance(v, dict):
            cikti.update(_duz(v, f"{on}{a}."))
        elif isinstance(v, int) and not isinstance(v, bool):
            cikti[f"{on}{a}"] = v
    return cikti


MAKRO_BOLUMLERI = ("durum", "sinif_payi", "erisim", "tavan")


def makro(birim_sayimlari: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Program düzeyi makro: sayı / nüfus önce aynı programın birimlerinde, sonra programlarda ortalanır."""
    programlar: dict[str, list[str]] = {}
    for b in sorted(birim_sayimlari):
        if birim_sayimlari[b]["nufus"] > 0:
            programlar.setdefault(ks1.birim_programi(b), []).append(b)
    oranlar: dict[str, float] = {}
    if programlar:
        alanlar = sorted({a for b in birim_sayimlari.values()
                          for a in _duz({m: b[m] for m in MAKRO_BOLUMLERI})})
        for alan in alanlar:
            prog = []
            for p in sorted(programlar):
                bs = programlar[p]
                prog.append(sum(Fraction(_duz({m: birim_sayimlari[b][m] for m in MAKRO_BOLUMLERI})
                                         .get(alan, 0), birim_sayimlari[b]["nufus"]) for b in bs) / len(bs))
            oranlar[alan] = round(float(sum(prog) / len(prog)), ONDALIK)
    return {"programlar": {p: bs for p, bs in sorted(programlar.items())}, "oran": oranlar}


def ozetle(kayitlar: list[dict[str, Any]]) -> dict[str, Any]:
    """Birim, havuz, Mac ikilisi ve makro; örnek düzeyi ve tekil görünümde."""
    onek_isaretle(kayitlar)
    birimler = sorted({k["birim"] for k in kayitlar})
    tek = tekil(kayitlar)
    cikti: dict[str, Any] = {"birimler": {}}
    for b in birimler:
        cikti["birimler"][b] = {"ornek": say(k for k in kayitlar if k["birim"] == b),
                                "tekil": say(k for k in tek if k["birim"] == b)}
    mac = [b for b in birimler if b.startswith("mac/")]
    cikti["havuz"] = {"ornek": say(kayitlar), "tekil": say(tek)}
    cikti["mac_ikilisi"] = {"ornek": say(k for k in kayitlar if k["birim"] in mac),
                            "tekil": say(k for k in tek if k["birim"] in mac)}
    cikti["makro"] = {g: makro({b: v[g] for b, v in cikti["birimler"].items()})
                      for g in ("ornek", "tekil")}
    return cikti


# ---------------------------------------------------------------------------------------------
# Koşu


def sha256_dosya(yol: Path) -> str:
    return hashlib.sha256(Path(yol).read_bytes()).hexdigest()


def tanimlar_sha256(belge: Path = BELGE_YOLU) -> Optional[str]:
    if not belge.is_file():
        return None
    m = re.search(r"<!-- TANIMLAR-BAS -->\n(.*?)<!-- TANIMLAR-SON -->",
                  belge.read_text(encoding="utf-8"), re.S)
    return hashlib.sha256(m.group(1).encode("utf-8")).hexdigest() if m else None


def topla(mac_kosu: Path, mac_veri: Path, debian_kosu: Path, debian_indir: Path,
          ek: dict[str, frozenset[str]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Bütün ELF'lerin kayıtları ve denetim künyesi. ``on_sayim`` ile eşleşmezse durur."""
    elfler = ks1.elfleri_topla(mac_kosu, debian_kosu)
    ks1.nufus_denetle(elfler)
    kayitlar: list[dict[str, Any]] = []
    cpp: Counter = Counter()
    elf_sayisi: Counter = Counter()
    for e in elfler:
        birim = ks1.birim_anahtari(e)
        elf_sayisi[birim] += 1
        sonuc, yerel = elf_ayrinti(Path(e.static))
        fonk = json.loads((Path(e.static) / "ghidra_functions.json").read_text(encoding="utf-8"))
        if ks1.cpp_ikili_mi(fonk.get("functions", []), e.platform):
            cpp[birim] += 1
            yeni = elf_kayitlari(birim, e.ad, e.platform, yerel, None)
        else:
            gt = (ks1.gt_mac(e, mac_veri) if e.platform == ks1.PLATFORM_MAC
                  else ks1.gt_elf(e, debian_indir))
            yeni = elf_kayitlari(birim, e.ad, e.platform, yerel, gt.adlar, gt.nufus, ek)
        s = yeniden_say(yeni)
        s["K_ayirt_edici"] = sum(1 for k in yeni if k["api_genis"])
        for k in yeni:
            if k["api_genis"]:
                ni = len(yerel["bilgi_f"][k["adres"]]["ic"])
                s[f"K_ayirt_edici_ic_cagri_{'0' if ni == 0 else ('1-3' if ni <= 3 else '4+')}"] += 1
        for alan in ESLESEN_SAYIMLAR:
            if s[alan] != sonuc["sayim"].get(alan, 0):
                raise RuntimeError(f"{birim}/{e.ad}: {alan} on_sayim ile tutmuyor "
                                   f"({s[alan]} ≠ {sonuc['sayim'].get(alan, 0)})")
        kayitlar.extend(yeni)
    return kayitlar, {"elf_sayisi": dict(sorted(elf_sayisi.items())),
                      "cpp_disarida_elf": dict(sorted(cpp.items()))}


def on_sayimla_karsilastir(birimler: dict[str, Any], on_json: Path = ON_SAYIM_JSON) -> dict[str, Any]:
    """Birim başına nüfus ve K/I/Y, ``on_sayim.json`` ile aynı olmalı; değilse durur."""
    beklenen = json.loads(on_json.read_text(encoding="utf-8"))["birimler"]
    if sorted(beklenen) != sorted(birimler):
        raise RuntimeError("birim kümesi on_sayim.json ile aynı değil")
    for b in sorted(birimler):
        s, o = beklenen[b]["sayim"], birimler[b]["ornek"]
        bulunan = {"isim_bekleyen": o["nufus"],
                   **{f"sinif_{x}": sum(o["kiy_durum"][x].values()) for x in YAPISAL_SINIFLAR}}
        for alan, deger in bulunan.items():
            if deger != s.get(alan, 0):
                raise RuntimeError(f"{b}: {alan} {deger} ≠ on_sayim.json {s.get(alan, 0)}")
    return {"on_sayim_json_sha256": sha256_dosya(on_json), "eslesen_birim": len(birimler),
            "eslesen_alanlar": ["isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y"]}


def elle_denetim_ornegi(kayitlar: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """T7: tohumu sabit 40 kayıt; her tabakanın yarısı Mac, yarısı Debian birimlerinden."""
    sirali = sorted(kayitlar, key=lambda k: (k["birim"], k["elf"], k["adres"]))
    secilen = []
    for i, (durum, n) in enumerate(ELLE_TABAKALAR):
        mac = [k for k in sirali if k["durum"] == durum and k["birim"].startswith("mac/")]
        deb = [k for k in sirali if k["durum"] == durum and not k["birim"].startswith("mac/")]
        n_deb = n // 2
        r = random.Random(ELLE_TOHUM + i)
        secilen += r.sample(mac, min(n - n_deb, len(mac))) + r.sample(deb, min(n_deb, len(deb)))
    return secilen


# ---------------------------------------------------------------------------------------------
# Markdown tabloları (yalnız sayılar)


def _s(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def _y(k: int, n: int) -> str:
    return "—" if n == 0 else f"%{100 * k / n:.1f}".replace(".", ",")


def _sy(k: int, n: int) -> str:
    return f"{_s(k)} ({_y(k, n)})"


def _yo(x: Optional[float]) -> str:
    return "—" if x is None else f"%{100 * x:.1f}".replace(".", ",")


def _satirlar(belge: dict[str, Any], gorunum_: str) -> list[tuple[str, dict[str, Any]]]:
    s = [(f"`{b}`", v[gorunum_]) for b, v in belge["birimler"].items()]
    return s + [("**Mac ikilisi**", belge["mac_ikilisi"][gorunum_]), ("**havuz**", belge["havuz"][gorunum_])]


def _tablo(baslik: list[str], satirlar: list[list[str]]) -> list[str]:
    return (["| " + " | ".join(baslik) + " |", "|" + "---|" * len(baslik)]
            + ["| " + " | ".join(s) + " |" for s in satirlar] + [""])


TAVAN_SUTUNLARI = (("F-API fk2", "f_api_fk2"), ("F-API geniş", "f_api_genis"),
                   ("F-ETKİ doğrudan", "f_etki_dogrudan"), ("F-ETKİ sarmalayıcı dahil", "f_etki_sarmalayici"),
                   ("F-ETKİ çağrı yapan", "f_etki_cagri"), ("F-ROL", "f_rol"),
                   ("Birleşik: ilk sürüm, dar", "birlesik_ilk_dar"),
                   ("Birleşik: ilk sürüm, geniş", "birlesik_ilk_genis"),
                   ("Birleşik: adaylar dahil, geniş", "birlesik_aday_genis"),
                   ("Erişimsiz: 18 sınıf", "erisimsiz_ilk"), ("Erişimsiz: 23 sınıf", "erisimsiz_aday"))


def markdown(belge: dict[str, Any]) -> str:
    c: list[str] = []
    for g, ad in (("ornek", "örnek düzeyi"), ("tekil", "tekil GT adı")):
        sat = _satirlar(belge, g)
        mk = belge["makro"][g]["oran"]
        c.append(f"#### Fiil durumu ({ad})\n")
        c += _tablo(["Birim", "Nüfus", "Tek sınıf", "Çok sınıf", "Yalnız genel", "Fiilsiz", "Parça",
                     "GT'de yok", "C++ (okunmadı)"],
                    [[b, _s(v["nufus"])] + [_sy(v["durum"][d], v["nufus"]) for d in FIIL_DURUMLARI]
                     for b, v in sat]
                    + [["**program makrosu**", "—"] + [_yo(mk.get(f"durum.{d}")) for d in FIIL_DURUMLARI]])
        for tur, ek_ad in (("tek_sinif", "başvuru = tek sınıflı ad"),
                           ("cok_sinif_dahil", "duyarlılık: çok sınıflı adlar da")):
            c.append(f"#### Aile tavanı ({ad}; {ek_ad})\n")
            c += _tablo(["Birim", "Nüfus"] + [a for a, _ in TAVAN_SUTUNLARI],
                        [[b, _s(v["nufus"])] + [_sy(v["tavan"][tur][k], v["nufus"]) for _, k in TAVAN_SUTUNLARI]
                         for b, v in sat]
                        + [["**program makrosu**", "—"] + [_yo(mk.get(f"tavan.{tur}.{k}"))
                                                           for _, k in TAVAN_SUTUNLARI]])
    sat = _satirlar(belge, "ornek")
    c.append("#### F-ETKİ ayrıntısı (örnek düzeyi; başvuru = tek sınıflı ad)\n")
    etki = (("GT `create`", None, "create"), ("… doğrudan", "f_etki_create_dogrudan", None),
            ("… sarmalayıcı dahil", "f_etki_create_sarmalayici", None), ("… çağrı yapan", "f_etki_create_cagri", None),
            ("GT `destroy`", None, "destroy"), ("… doğrudan", "f_etki_destroy_dogrudan", None),
            ("… sarmalayıcı dahil", "f_etki_destroy_sarmalayici", None), ("… çağrı yapan", "f_etki_destroy_cagri", None),
            ("Adaylar (6 fiil)", "f_etki_aday", None))
    c += _tablo(["Birim"] + [a for a, _, _ in etki],
                [[b] + [_sy(v["sinif_payi"][s] if s else v["tavan"]["tek_sinif"][k], v["nufus"])
                        for _, k, s in etki] for b, v in sat])
    c.append("#### Erişim: ön koşulu sağlayan fonksiyonlar (GT'siz; örnek düzeyi)\n")
    eris = (("F-API fk2", "api_fk2"), ("F-API geniş", "api_genis"), ("Ayırıcı: doğrudan", "create_dogrudan"),
            ("Ayırıcı: sarmalayıcı dahil", "create_sarmalayici"), ("Bırakıcı: doğrudan", "destroy_dogrudan"),
            ("Bırakıcı: sarmalayıcı dahil", "destroy_sarmalayici"), ("Çağrı yapan", "cagri_yapan"),
            ("F-ROL (adresi kayıt yerinde kurulan)", "rol"))
    c += _tablo(["Birim", "Nüfus"] + [a for a, _ in eris],
                [[b, _s(v["nufus"])] + [_sy(v["erisim"][k], v["nufus"]) for _, k in eris] for b, v in sat])
    c.append("#### F-ROL ayrıntısı (örnek düzeyi)\n")
    c += _tablo(["Birim", "Erişilen", "… rolü `compare`", "… rolü `fini`", "… rolü genel", "… rolü fiilsiz",
                 "Erişilenlerde GT tek sınıf", "… GT yalnız genel", "… GT fiilsiz", "İsabet",
                 "Erişimsiz: GT `compare` ya da `fini`"],
                [[b, _s(v["erisim"]["rol"])]
                 + [_s(v["rol_erisim_sinifi"].get(r, 0)) for r in ("compare", "fini", "handle", "yok")]
                 + [_s(v["rol_erisim_durum"][d]) for d in ("tek_sinif", "yalniz_genel", "fiilsiz")]
                 + [_s(v["tavan"]["tek_sinif"]["f_rol"]), _s(v["tavan"]["tek_sinif"]["f_rol_erisimsiz"])]
                 for b, v in sat])
    c.append("#### K / I / Y × fiil durumu (örnek düzeyi; payda sınıfın nüfusu)\n")
    kiy = []
    for b, v in sat:
        for x in YAPISAL_SINIFLAR:
            n = sum(v["kiy_durum"][x].values())
            kiy.append([b, x, _s(n)] + [_sy(v["kiy_durum"][x][d], n) for d in FIIL_DURUMLARI])
    c += _tablo(["Birim", "Sınıf", "Nüfus", "Tek sınıf", "Çok sınıf", "Yalnız genel", "Fiilsiz", "Parça",
                 "GT'de yok", "C++"], kiy)
    c.append("#### Sözlük sınıfı başına pay (tek sınıflı adlar; sayı ve nüfusa oranı)\n")
    secili = [("`mac/tmux`", belge["birimler"].get("mac/tmux", {}).get("ornek")),
              ("`mac/htop`", belge["birimler"].get("mac/htop", {}).get("ornek")),
              ("havuz (örnek)", belge["havuz"]["ornek"]), ("havuz (tekil)", belge["havuz"]["tekil"])]
    secili = [(a, v) for a, v in secili if v]
    def _aile(s: str) -> str:
        return ("F-API" if s in F_API_SINIFLARI else "F-ETKİ ilk" if s in F_ETKI_ILK
                else "F-ETKİ aday" + (" / F-ROL" if s in F_ROL_SINIFLARI else "") if s in F_ETKI_ADAY
                else "F-ROL" if s in F_ROL_SINIFLARI else "—")
    c += _tablo(["Sınıf", "Aile"] + [a for a, _ in secili] + ["makro (örnek)", "makro (tekil)"],
                [[f"`{s}`", _aile(s)] + [_sy(v["sinif_payi"][s], v["nufus"]) for _, v in secili]
                 + [_yo(belge["makro"][g]["oran"].get(f"sinif_payi.{s}")) for g in ("ornek", "tekil")]
                 for s in on_sayim.FIIL_SOZLUGU if s != on_sayim.GENEL_SINIF])
    for g, ad in (("ornek", "örnek düzeyi"), ("tekil", "tekil GT adı")):
        sat = _satirlar(belge, g)
        c.append(f"#### Sözlük dışı fiil: kapalı ölçme listesiyle ({ad})\n")
        c += _tablo(["Birim", "Nüfus", "Fiilsiz + yalnız genel", "`acik` taşıyan", "`acik` ya da `belirsiz` taşıyan",
                     "Farklı `acik` belirteç", "Farklı belirteç (iki kesim)", "En sık 10 (`acik`): fonksiyon sayıları"],
                    [[b, _s(v["nufus"]), _sy(v["sozluk_disi"]["aday_ad"], v["nufus"]),
                      _sy(v["sozluk_disi"]["acik_tasiyan"], v["nufus"]),
                      _sy(v["sozluk_disi"]["acik_ya_da_belirsiz_tasiyan"], v["nufus"]),
                      _s(v["sozluk_disi"]["farkli_acik"]), _s(v["sozluk_disi"]["farkli_acik_ya_da_belirsiz"]),
                      ", ".join(str(x) for x in v["sozluk_disi"]["en_sik_acik"]) or "—"] for b, v in sat])
        c.append(f"#### Ad biçimi ({ad}; payda tek sınıflı adlar) ve modül öneki vekili (payda GT adı olanlar)\n")
        c += _tablo(["Birim", "Tek sınıflı ad"] + [f"`{x}`" for x in BICIMLER]
                    + ["GT adı olan", "Önekli (vekil)", "Tek sınıflılarda önekli"],
                    [[b, _s(v["durum"]["tek_sinif"])]
                     + [_sy(v["ad_bicimi"][x], v["durum"]["tek_sinif"]) for x in BICIMLER]
                     + [_s(v["diger"]["adli"]), _sy(v["diger"]["onekli"], v["diger"]["adli"]),
                        _sy(v["diger"]["onekli_tek_sinif"], v["durum"]["tek_sinif"])] for b, v in sat])
    sat = _satirlar(belge, "ornek")
    c.append("#### Yan sayılar (örnek düzeyi)\n")
    c += _tablo(["Birim", "Nüfus", "KS-1 nüfusunda", "Birden çok takma adlı", "Klon ekli: tek sınıf",
                 "Klon ekli: çok sınıf", "Klon ekli: fiilsiz", "Klon ekli: parça"],
                [[b, _s(v["nufus"]), _sy(v["diger"]["ks1_nufusunda"], v["nufus"]), _s(v["diger"]["cok_adli"])]
                 + [_s(v["klon_ekli"][d]) for d in ("tek_sinif", "cok_sinif", "fiilsiz", "parca")]
                 for b, v in sat])
    return "\n".join(c)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--mac-kosu", type=Path, required=True)
    ap.add_argument("--mac-veri", type=Path, required=True)
    ap.add_argument("--debian-kosu", type=Path, required=True)
    ap.add_argument("--debian-indir", type=Path,
                    default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    ap.add_argument("--ek-fiil-listesi", type=Path, required=True)
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--md-tablolar", type=Path, default=None)
    ap.add_argument("--elle-denetim", action="store_true",
                    help="40 örneği GT adlarıyla uçbirime basar (dosyaya yönlendirme)")
    a = ap.parse_args(argv)
    ek = ek_listeyi_oku(a.ek_fiil_listesi.expanduser())
    kayitlar, denetim = topla(a.mac_kosu.expanduser(), a.mac_veri.expanduser(),
                              a.debian_kosu.expanduser(), a.debian_indir.expanduser(), ek)
    ozet = ozetle(kayitlar)
    denetim.update(on_sayimla_karsilastir(ozet["birimler"]))
    belge = {
        "kunye": {
            "betik": "docs/arge/2026-11-10_n4/fiil_tavani.py", "surum": SURUM,
            "betik_sha256": sha256_dosya(Path(__file__)),
            "on_sayim_py_sha256": sha256_dosya(ON_SAYIM_YOLU),
            "ks1_olc_py_sha256": sha256_dosya(KS1_YOLU),
            "tanimlar_sha256": tanimlar_sha256(),
            "git_head": ks1._git("rev-parse", "HEAD").stdout.strip(),
            "python": platform.python_version(),
            "mac_kosu": on_sayim.ev_kisalt(a.mac_kosu.resolve()),
            "debian_kosu": on_sayim.ev_kisalt(a.debian_kosu.resolve()),
            "ek_fiil_listesi": {"yol": on_sayim.ev_kisalt(a.ek_fiil_listesi.resolve()),
                                "sha256": sha256_dosya(a.ek_fiil_listesi.expanduser()),
                                "acik": len(ek["acik"]), "belirsiz": len(ek["belirsiz"])},
            "aileler": {"f_api": sorted(F_API_SINIFLARI), "f_etki_ilk": sorted(F_ETKI_ILK),
                        "f_etki_aday": sorted(F_ETKI_ADAY), "f_rol": sorted(F_ROL_SINIFLARI),
                        "rol_sinifi": {k: v for k, v in sorted(ROL_SINIFI.items())},
                        "ayirici": sorted(AYIRICI), "birakici": sorted(BIRAKICI)},
            "secimler": {"fk2_ic_cagri_siniri": FK2_IC_CAGRI_SINIRI,
                         "sarmalayici_azami_komut": SARMALAYICI_AZAMI_KOMUT,
                         "sarmalayici_azami_ic": SARMALAYICI_AZAMI_IC,
                         "sarmalayici_azami_adim": SARMALAYICI_AZAMI_ADIM,
                         "onek_en_az_ad": ONEK_EN_AZ_AD, "en_sik": EN_SIK, "elle_tohum": ELLE_TOHUM},
            "fiil_sozlugu_v0_sha256": hashlib.sha256(json.dumps(
                {k: list(v) for k, v in on_sayim.FIIL_SOZLUGU.items()}, sort_keys=True).encode()).hexdigest(),
        },
        "denetim": denetim,
        **ozet,
    }
    a.cikti.write_text(json.dumps(belge, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                       encoding="utf-8")
    if a.md_tablolar:
        a.md_tablolar.write_text(markdown(belge), encoding="utf-8")
    h = belge["havuz"]["ornek"]
    print(f"{len(belge['birimler'])} birim, nüfus {h['nufus']}, tek sınıf {h['durum']['tek_sinif']}, "
          f"birleşik (ilk sürüm, dar) {h['tavan']['tek_sinif']['birlesik_ilk_dar']}")
    if a.elle_denetim:
        for k in elle_denetim_ornegi(kayitlar):
            print(f"{k['birim']:<20}{k['durum']:<14}{str(k['fiil'] or ','.join(k['siniflar'])):<18}"
                  f"{k['bicim'] or '-':<16}{'A' if k['ek_acik'] else ('B' if k['ek_belirsiz'] else '-'):<3}"
                  f"{' | '.join(k['adlar'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
