#!/usr/bin/env python3
"""OLGU: taban ürün koşusunun (a62f15e, 119 ikili) bütün fonksiyonları için fonksiyon başına olgu
tablosu ve kapsam bütçesi (ARGE 2026-11-19, liste A1).

Hat metni ``docs/arge/2026-11-19_mythos/OLGU.md``; alan tanımları ``.../olgu/SEMA.md``.

Ölçüm tanımları kopyalanmaz: GT, nüfus ve hüküm ölçüm betiklerinden içe aktarılır
(``ks1_olc.gt_elf`` / ``gt_mac``, ``urun_olc.haritayi_oku`` / ``degerlendir_elf`` /
``kanal_grubu``). Betikler ``--olcum-agaci``'ndan (varsayılan: taban ölçümünün koşulduğu ürün
ağacı ``~/karadul_olcum/urun-a62f15e``) dosya yoluyla yüklenir; ``karadul`` paketi de o ağaçtan
gelir (``urun_olc`` bunu denetler). DWARF ``dwarf_tip``'in dwz farkında okuyucusuyla okunur.

Alt komutlar
------------
``uret``      Tabloyu yazar (``olgu.jsonl.gz``, satır = ikili + adres) ve künyesini
              (``olgu_kunye.json``). ``--asama cekirdek`` yalnız çekirdek + kaynak sınıfı alanları;
              ``--asama tam`` kanıt ve kayıt çifti alanları da. ``--dogrula`` ile yazdıktan sonra
              tutarlılık kapısını koşar.
``dogrula``   Tutarlılık kapısı: tablodan yeniden hesaplanan toplamlar taban ölçümüyle birebir
              (``TABAN_HAVUZ`` ve ``TABAN_BIRIM``: ``docs/arge/2026-11-19_birlesik_olcum/sonuc.md``
              §2) ve öğe düzeyinde ``urun_olcumu_onarim.json`` ``ogeler`` ile aynı olmalı. Çıkış 0 =
              tuttu, 1 = tutmadı.
``butce``     Kapsam bütçesi: ``BUTCE.md`` (yalnız sayılar) ve ``butce.json``.

Kullanım (depo kökünden)
------------------------
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olgu/olgu_tablosu.py uret --asama tam --is 4 --dogrula
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olgu/olgu_tablosu.py dogrula
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olgu/olgu_tablosu.py butce
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib
import importlib.util
import json
import os
import platform as _platform
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Optional

sys.dont_write_bytecode = True
_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

import olgu_ikili as oi  # noqa: E402

SEMA = "karadul-arge-olgu/1"
REPO = Path(__file__).resolve().parents[3]
EV = Path.home()
VARSAYILAN_KOK = EV / "karadul_olcum" / "runs" / "urun-onarim-a62f15e"
VARSAYILAN_AGAC = EV / "karadul_olcum" / "urun-a62f15e"
VARSAYILAN_CIKTI_DIZINI = EV / "karadul_olcum" / "runs" / "arge-2026-11-19" / "olgu"
VARSAYILAN_TABLO = VARSAYILAN_CIKTI_DIZINI / "olgu.jsonl.gz"
VARSAYILAN_MAC_VERI = REPO / "workspaces" / "olcum_mac"          # taban ölçümünün --mac-veri'si
VARSAYILAN_INDIR = EV / "karadul_olcum" / "downloads" / "debian13"  # urun_olc'un varsayılanı
BELGE_DIZINI = REPO / "docs" / "arge" / "2026-11-19_mythos" / "olgu"
OLCUM_JSON = REPO / "docs" / "arge" / "2026-11-19_birlesik_olcum" / "urun_olcumu_onarim.json"

ASAMA_CEKIRDEK = "cekirdek"
ASAMA_TAM = "tam"

# ---- Tutarlılık kapısının beklentileri: sonuc.md §2 (taban ölçümü a62f15e) ----
TABAN_HAVUZ = {"nufus": 21371, "ad_verilen": 1800, "dogru": 1681, "yanlis": 119, "nufusta_dogru": 1212,
            "nufusta_ad": 1315}
# birim → (ad verilen, doğru, yanlış); sonuc.md §2 "Birim başına", onarim sütunu
TABAN_BIRIM = {
    "debian/coreutils": (1281, 1271, 10), "debian/tmux": (166, 148, 18), "mac/tmux": (236, 205, 31),
    "debian/zstd": (55, 9, 46), "debian/openssl": (26, 23, 3), "debian/redis-tools": (15, 12, 3),
    "debian/sqlite3": (12, 5, 7), "debian/htop": (4, 3, 1), "debian/tree": (5, 5, 0), "mac/htop": (0, 0, 0),
}
TABAN_IKILI = 119
TABAN_FONKSIYON = 66983     # sonuc.md §1 B6: Ghidra fonksiyon sayısı (iki kolda aynı)

# ---- Kaynak sınıfı (SEMA.md §4; kalıplar 119 ikilinin DWARF birim yollarından) ----
SINIF_GNULIB = "gnulib"
SINIF_UCUNCU = "ucuncu_taraf"
SINIF_UYUMLULUK = "uyumluluk"
SINIF_PROJE_KITAPLIGI = "proje_kitapligi"
SINIF_PROGRAM = "program"
SINIF_DERLEYICI = "derleyici"
SINIF_SISTEM = "sistem"
SINIF_ICE_AKTARIM = "ice_aktarim"
SINIF_BILINMIYOR = "bilinmiyor"
KAYNAK_SINIFLARI = (SINIF_GNULIB, SINIF_UCUNCU, SINIF_UYUMLULUK, SINIF_PROJE_KITAPLIGI, SINIF_PROGRAM,
                    SINIF_SISTEM, SINIF_DERLEYICI, SINIF_ICE_AKTARIM, SINIF_BILINMIYOR)
UCUNCU_TARAF_DIZINLERI = frozenset({"deps", "contrib", "third_party", "thirdparty", "third-party",
                                    "vendor", "external", "extern"})
UYUMLULUK_DIZINLERI = frozenset({"compat"})
# Programın kendi projesinin ayrıca dağıtılan kitaplığı (statik kopya): yol öneki
PROJE_KITAPLIGI_ONEKLERI = (("lib",), ("programs", "lib"))
# Derleyici / C çalışma zamanı: glibc başlangıç dosyaları ve GCC'nin crtstuff'ı
DERLEYICI_YOL_PARCALARI = ("csu/", "sysdeps/", "crtstuff.c", "libgcc/")
KANIT_TANIM = "tanim_dosyasi"
KANIT_BIRIM = "derleme_birimi"
KANIT_ARANGES = "aranges_birimi"
KANIT_ARANGES_LTO = "aranges_lto"        # aranges birimi LTO bölümü (<artificial>): köken okunamaz
LTO_BIRIMI = "<artificial>"
KANIT_CRT = "gt_crt_adi"
KANIT_DWARF_YOK = "dwarf_yok"              # GT'de adı var, DWARF'ta hiçbir birim kapsamıyor
KANIT_DWARF_GT_YOK = "dwarf_yok_gt_yok"    # GT'de de yok (bağlayıcı kalıbı, PLT başı vb.)
KANIT_ICE_AKTARIM = "ice_aktarim"          # Ghidra thunk ya da dış fonksiyon
KANIT_MAC = "mac_dwarf_yok"
KANIT_GT_YOK = "gt_yok"

# ---- Satır alanları (SEMA.md; test_olgu_tablosu bununla denetler) ----
CEKIRDEK_ALANLARI = (
    "birim", "program", "ikili", "platform", "adres", "adres_hex", "dosya_adresi", "boyut", "boyut_dilimi",
    "komut_sayisi", "thunk", "dis", "ghidra_adi", "ghidra_kaynagi", "ghidra_jenerik", "cpp_disarida",
    "gt_adlari", "gt_export", "gt_crt", "gt_klon", "gt_sinif", "nufusta",
    "urun_adi", "urun_olcude", "urun_atlama", "hukum", "satir", "proje", "etiket", "kanal", "kanal_ana",
    "alt_kanal", "kanal_grubu", "guven", "strateji", "on_ad_turu",
    "dw_eslesme", "dw_adi", "dw_birim", "dw_derleme_dizini", "dw_birim_yolu", "dw_tanim_dosyasi", "dw_harici",
    "kaynak_sinifi", "kaynak_alt_sinifi", "kaynak_kaniti")
KANIT_ALANLARI = (
    "dizgiler", "dizgi_sayisi", "cagrilanlar", "cagiranlar", "cagrilan_sayisi", "cagiran_sayisi",
    "dolayli_cagri", "cagri_dizgileri", "pcode_var", "yaprak",
    "veri_yerleri", "veri_yeri_sayisi", "kayit_cifti_var", "cagri_ciftleri")

# ---- Boyut dilimi (bayt; BUTCE kırılımı) ----
BOYUT_DILIMLERI = ((16, "<16"), (64, "16-63"), (256, "64-255"), (1024, "256-1023"), (4096, "1024-4095"))
BOYUT_EN_BUYUK = ">=4096"


# --------------------------------------------------------------------------------------------
# Ölçüm modüllerinin yüklenmesi


_MODULLER: dict[str, SimpleNamespace] = {}


def olcum_yukle(agac: Path) -> SimpleNamespace:
    """``<agac>/scripts/measurement`` modülleri: urun_olc (o da ks1_olc'u ve karadul'u yükler),
    ks1_olc, function_f1, macho_f1, macho_measure, dwarf_tip."""
    agac = Path(agac).resolve()
    if str(agac) in _MODULLER:
        return _MODULLER[str(agac)]
    if _MODULLER:
        raise RuntimeError("bir süreçte tek ölçüm ağacı yüklenebilir")
    olcum = agac / "scripts" / "measurement"
    for p in (str(agac), str(olcum)):
        if p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("urun_olc", olcum / "urun_olc.py")
    uo = importlib.util.module_from_spec(spec)
    sys.modules["urun_olc"] = uo
    spec.loader.exec_module(uo)
    ks1 = uo.ks1
    f1, mf = ks1._f1(), ks1._mf()
    import dwarf_tip
    import macho_measure
    for m in (f1, mf, dwarf_tip, macho_measure, ks1, uo):
        if Path(m.__file__).resolve().parent != olcum:
            raise ImportError(f"{m.__name__} {m.__file__} yolundan yüklendi; beklenen {olcum}")
    import karadul
    if agac not in Path(karadul.__file__).resolve().parents:
        raise ImportError(f"karadul {karadul.__file__}; beklenen ağaç {agac}")
    ns = SimpleNamespace(agac=agac, uo=uo, ks1=ks1, f1=f1, mf=mf, dt=dwarf_tip, mm=macho_measure,
                         karadul=karadul)
    _MODULLER[str(agac)] = ns
    return ns


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


def _hex(a: str) -> Optional[int]:
    try:
        return int(str(a), 16)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------------------------
# DWARF: adres → derleme birimi, tanım dosyası, DW_AT_external


def derleme_dizinleri(debug: Path) -> dict[int, Optional[str]]:
    """Ana dosyanın derleme birimi başlığı ofseti → ``DW_AT_comp_dir`` (yalnız compile_unit)."""
    from elftools.elf.elffile import ELFFile
    out: dict[int, Optional[str]] = {}
    with open(debug, "rb") as f:
        dw = ELFFile(f).get_dwarf_info(relocate_dwarf_sections=True, follow_links=False)
        for cu in dw.iter_CUs():
            ust = cu.get_top_DIE()
            if ust.tag != "DW_TAG_compile_unit":
                continue
            a = ust.attributes.get("DW_AT_comp_dir")
            v = None
            if a is not None:
                try:
                    v = a.value.decode("utf-8", "replace") if isinstance(a.value, bytes) else str(a.value)
                except Exception:       # noqa: BLE001 - dwz ek dizgisi; çözülmezse yok sayılır
                    v = None
            out[cu.cu_offset] = v
    return out


def aranges_birimleri(debug: Path) -> Any:
    """``.debug_aranges`` (yoksa None): adres → birim ofseti sorgusu için pyelftools nesnesi."""
    from elftools.elf.elffile import ELFFile
    f = open(debug, "rb")       # noqa: SIM115 - nesne dosya açıkken kullanılır, çağıran kapatır
    dw = ELFFile(f).get_dwarf_info(relocate_dwarf_sections=True, follow_links=False)
    return f, dw.get_aranges()


def dwarf_haritasi(m: SimpleNamespace, debug: Path, ek_onbellek: dict) -> dict[str, Any]:
    """dbgsym'den dosya adresi → DWARF olguları; birim ofseti → yol (aranges için)."""
    dt = m.dt
    ana = dt.dosya_yukle(debug, dt.ANA)
    ek, ek_yontemi, _ = dt.ek_yukle(ana, None, ek_onbellek)
    coz = dt.Cozucu(ana, ek)
    cdirs = derleme_dizinleri(debug)
    gnulib = coz.gnulib_dizinleri()

    def birim_yolu(rol: str, birim: int) -> tuple[Optional[str], Optional[str], Optional[str]]:
        ad = coz.birim_adi(rol, birim)
        cd = cdirs.get(birim) if rol == dt.ANA else None
        return ad, cd, oi.kaynak_yolu(ad, cd)

    fonk: dict[int, dict[str, Any]] = {}
    cift = 0
    for _ofset, d in sorted(ana.dieler.items()):
        if d.etiket != "DW_TAG_subprogram" or "DW_AT_low_pc" not in d.oz:
            continue
        adres = int(dt.deger(d, "DW_AT_low_pc") or 0)
        if not adres:
            continue
        if adres in fonk:
            cift += 1
            continue
        try:
            zincir = list(coz.koken_zinciri(dt.ANA, d))
        except dt.CozumHatasi:
            zincir = [(dt.ANA, d, "kendi")]
        # _fonksiyon_birimi'nin kuralı (en derin kökenden adı olan ilk compile_unit; LTO'da
        # <artificial> atlanır); burada birimin konumu da gerekiyor (comp_dir için)
        birim_konumu, yedek = None, None
        for r, k, _ in reversed(zincir):
            b = coz.dosyalar[r].birimler.get(k.birim)
            if b is None or b["etiket"] != "DW_TAG_compile_unit":
                continue
            ad = coz.birim_adi(r, k.birim)
            if ad and ad != "<artificial>":
                birim_konumu = (r, k.birim)
                break
            yedek = yedek or (r, k.birim)
        birim_konumu = birim_konumu or yedek
        b_ad, b_cd, b_yol = birim_yolu(*birim_konumu) if birim_konumu else (None, None, None)
        if b_ad != coz._fonksiyon_birimi(zincir):
            raise RuntimeError(f"{debug}: birim adı dwarf_tip ile tutmuyor (0x{adres:x})")
        tanim = None
        for r, k, _ in zincir:
            if "DW_AT_decl_file" in k.oz:
                tanim = coz.kaynak_dosyasi(r, k)
                break
        try:
            dw_ad = coz.ad_bul(dt.ANA, d)[0]
        except dt.CozumHatasi:
            dw_ad = None
        fonk[adres] = {"dw_eslesme": "subprogram", "dw_adi": dw_ad, "dw_birim": b_ad,
                       "dw_derleme_dizini": b_cd, "dw_birim_yolu": b_yol,
                       "dw_tanim_dosyasi": oi.kaynak_yolu(tanim, None) if tanim else None,
                       "dw_harici": bool(coz.koken_degeri(dt.ANA, d, "DW_AT_external"))}
    birimler = {}
    for bofset, kayit in ana.birimler.items():
        if kayit["etiket"] == "DW_TAG_compile_unit":
            birimler[bofset] = birim_yolu(dt.ANA, bofset)
    return {"fonk": fonk, "birimler": birimler, "gnulib": gnulib, "ek_yontemi": ek_yontemi,
            "cift_low_pc": cift, "yalniz_ranges": coz.yalniz_ranges_govdeler()}


def _onek_mi(parcalar: list[str], onek: tuple[str, ...]) -> bool:
    return tuple(parcalar[:len(onek)]) == onek


def kaynak_sinifla(yol: Optional[str], gnulib: Iterable[str], dt: Any) -> tuple[str, Optional[str]]:
    """Yol → (sınıf, alt sınıf). Sıra: sistem, derleyici, gnulib, üçüncü taraf, uyumluluk,
    proje kitaplığı, program. Alt sınıf: sınıfı belirleyen dizin (ya da yolun dizini)."""
    if not yol:
        return SINIF_BILINMIYOR, None
    if dt.koken_sinifi(yol, ()) == "sistem":
        return SINIF_SISTEM, None
    if any(p in yol for p in DERLEYICI_YOL_PARCALARI):
        return SINIF_DERLEYICI, None
    if dt.koken_sinifi(yol, gnulib) == "gnulib":
        return SINIF_GNULIB, posixpath_dirname(yol)
    parcalar = yol.split("/")
    dizinler = parcalar[:-1]
    for i, p in enumerate(dizinler):
        if p in UCUNCU_TARAF_DIZINLERI:
            return SINIF_UCUNCU, "/".join(dizinler[i:i + 2])
    for i, p in enumerate(dizinler):
        if p in UYUMLULUK_DIZINLERI:
            return SINIF_UYUMLULUK, "/".join(dizinler[i:i + 1])
    for onek in PROJE_KITAPLIGI_ONEKLERI:
        if _onek_mi(dizinler, onek):
            return SINIF_PROJE_KITAPLIGI, "/".join(dizinler[:len(onek) + 1])
    return SINIF_PROGRAM, posixpath_dirname(yol) or "."


def posixpath_dirname(yol: str) -> str:
    return yol.rsplit("/", 1)[0] if "/" in yol else ""


# --------------------------------------------------------------------------------------------
# Bir ikilinin satırları


def _boyut_dilimi(boyut: Optional[int]) -> Optional[str]:
    if boyut is None:
        return None
    for sinir, ad in BOYUT_DILIMLERI:
        if boyut < sinir:
            return ad
    return BOYUT_EN_BUYUK


def _komut_sayilari(static: Path) -> dict[int, int]:
    yol = static / "ghidra_cfg.json"
    if not yol.is_file():
        return {}
    out = {}
    for f in _json(yol).get("functions", []):
        a = _hex(f.get("address"))
        if a is not None:
            out[a] = sum(int(b.get("instruction_count") or 0) for b in f.get("blocks", []))
    return out


def _urun_adi_gecerli(f1: Any, anahtar: str, ad: Any, adres: int) -> Optional[str]:
    """Ad haritasındaki değer bir ad mı (anahtarın kendisi, boş ya da jenerik değil)."""
    if not isinstance(ad, str) or not ad or ad == anahtar or f1.is_generic_name(ad, [adres]):
        return None
    return ad


def satirlari_kur(m: SimpleNamespace, e: Any, fonk_ham: list[dict[str, Any]], cpp: bool, gt: Any,
                  gt_ayrinti: dict[int, dict[str, Any]], ofset: int, genel: dict[str, Any], koken: dict[str, Any],
                  kayitlar: list[dict[str, Any]], dwarf: Optional[dict[str, Any]], aranges: Any,
                  komut: dict[int, int]) -> list[dict[str, Any]]:
    """Ghidra fonksiyonu başına çekirdek ve kaynak sınıfı alanları (SEMA.md §1–§4).

    ``kayitlar``: ``urun_olc.degerlendir_elf``'in bu ikili için döndürdüğü kayıtlar (hüküm buradan).
    """
    ks1, uo, f1 = m.ks1, m.uo, m.f1
    platform_ = e.platform
    birim = ks1.birim_anahtari(e)
    mac = platform_ == ks1.PLATFORM_MAC
    hukum = {k["adres"]: k for k in kayitlar}
    satirlar = []
    for g in fonk_ham:
        adres = _hex(g.get("address"))
        anahtar = f"FUN_{adres:08x}"
        satir: dict[str, Any] = {
            "birim": birim, "program": e.program, "ikili": e.ad, "platform": platform_,
            "adres": adres, "adres_hex": f"{adres:x}", "dosya_adresi": adres - ofset,
            "boyut": g.get("size"), "boyut_dilimi": _boyut_dilimi(g.get("size")),
            "komut_sayisi": komut.get(adres), "thunk": bool(g.get("is_thunk")), "dis": bool(g.get("is_external")),
            "ghidra_adi": g.get("name"), "ghidra_kaynagi": g.get("source"),
            "ghidra_jenerik": f1.is_generic_name(g.get("name"), [adres]), "cpp_disarida": cpp}
        # GT
        if gt is None:
            satir.update(gt_adlari=None, gt_export=None, gt_crt=None, gt_klon=None, gt_sinif=None,
                         nufusta=False)
        else:
            adlar = gt.adlar.get(adres)
            ay = gt_ayrinti.get(adres) or {}
            satir.update(gt_adlari=adlar, gt_export=(adres in gt.export_gt) if adlar else None,
                         gt_crt=ay.get("crt") if adlar else None,
                         gt_klon=ks1.gt_klon_mu(adlar, platform_) if adlar else None,
                         gt_sinif=ay.get("sinif") if adlar else None,
                         nufusta=(adres in gt.nufus) and not cpp)
        # Ürün
        ham_ad = genel.get(anahtar)
        satir["urun_adi"] = _urun_adi_gecerli(f1, anahtar, ham_ad, adres)
        k = hukum.get(adres)
        kayit = koken.get(anahtar) or {}
        satir.update(urun_olcude=k is not None, hukum=k["durum"] if k else None,
                     satir=k["satir"] if k else None, proje=k["proje"] if k else None,
                     etiket=k["etiket"] if k else None, kanal=k["kanal"] if k else None,
                     kanal_grubu=uo.kanal_grubu(k["kanal"]) if k else None,
                     guven=kayit.get("confidence"), strateji=kayit.get("strategy"),
                     on_ad_turu=kayit.get("pre_name_kind"), urun_atlama=_atlama(m, anahtar, ham_ad, adres, g, k))
        if k:
            ana, _, alt = k["kanal"].partition("/")
            satir.update(kanal_ana=ana, alt_kanal=alt or None)
        else:
            satir.update(kanal_ana=None, alt_kanal=None)
        # Kaynak sınıfı
        satir.update(_kaynak_alanlari(m, satir, dwarf, aranges, mac, gt is not None))
        satirlar.append(satir)
    return satirlar


def ikili_isle(gorev: dict[str, Any]) -> dict[str, Any]:
    """Bir ikilinin bütün Ghidra fonksiyonları için satırlar ve künye (işçi süreçte koşar)."""
    bas = time.monotonic()
    m = olcum_yukle(Path(gorev["agac"]))
    ks1, uo, f1, dt = m.ks1, m.uo, m.f1, m.dt
    platform_ = gorev["platform"]
    static, kosu = Path(gorev["static"]), Path(gorev["kosu"])
    e = ks1.Elf(platform_, gorev["program"], gorev["ad"], static, kosu)
    birim = ks1.birim_anahtari(e)
    fonk_ham = _json(static / "ghidra_functions.json").get("functions", [])
    cpp = ks1.cpp_ikili_mi(fonk_ham, platform_)
    kunye: dict[str, Any] = {"birim": birim, "ikili": e.ad, "platform": platform_, "cpp_disarida": cpp,
                             "static": str(static)}
    mac = platform_ == ks1.PLATFORM_MAC
    # --- GT (ölçümün kendi fonksiyonları)
    gt, gt_ayrinti, ofset = None, {}, 0
    try:
        if mac:
            gt = ks1.gt_mac(e, Path(gorev["mac_veri"]))
            gt_belge = _json(m.mm.gt_path(Path(gorev["mac_veri"]), e.program))
            for fn in gt_belge.get("functions", []):
                gt_ayrinti[int(fn["addr"], 16)] = {"sinif": fn.get("sinif")}
        else:
            gt = ks1.gt_elf(e, Path(gorev["indir"]))
            ofset = int(gt.kunye["ofset"], 16)
            hedef = _json(kosu / "raw" / "target_info.json")
            gt_tam = f1.extract_gt(Path(gt.kunye["debug"]), Path(hedef["path"]),
                                   corpus=e.program, binary=e.ad)
            for fn in gt_tam["functions"]:
                gt_ayrinti[int(fn["addr"], 16) + ofset] = {"crt": fn["crt"], "bind": fn["bind"],
                                                           "boyut": fn["size"], "export": fn["exported"]}
        kunye["gt"] = {k: v for k, v in gt.kunye.items()}
        kunye["gt_nufus"] = len(gt.nufus)
    except ks1.OnkosulHatasi as h:
        kunye["gt_hatasi"] = str(h)
    # --- Ürünün ad haritası ve hüküm (urun_olc'un kendi fonksiyonu)
    genel, koken, kimlik = uo.haritayi_oku(kosu)
    gfonk = f1.load_ghidra_functions(static / "ghidra_functions.json")
    if cpp or gt is None:
        kayitlar, sayac = [], Counter()
    else:
        kayitlar, sayac = uo.degerlendir_elf(genel, koken, gfonk, gt, platform_)
    kunye["kol_kimligi"] = kimlik
    kunye["anahtar_sayaci"] = dict(sorted(sayac.items()))
    # --- DWARF
    dwarf: Optional[dict[str, Any]] = None
    aranges_dosya, aranges = None, None
    if not mac and gt is not None:
        debug = Path(gt.kunye["debug"])
        dwarf = dwarf_haritasi(m, debug, {})
        aranges_dosya, aranges = aranges_birimleri(debug)
        kunye["dwarf"] = {"debug": str(debug), "subprogram": len(dwarf["fonk"]), "gnulib": dwarf["gnulib"],
                          "ek_yontemi": dwarf["ek_yontemi"], "cift_low_pc": dwarf["cift_low_pc"],
                          "yalniz_ranges": dwarf["yalniz_ranges"], "aranges": aranges is not None}
    komut = _komut_sayilari(static)
    satirlar = satirlari_kur(m, e, fonk_ham, cpp, gt, gt_ayrinti, ofset, genel, koken, kayitlar, dwarf, aranges,
                             komut)
    if aranges_dosya is not None:
        aranges_dosya.close()
    if gorev["asama"] == ASAMA_TAM:
        kunye["kanit"] = kanit_ekle(m, satirlar, static, kosu, genel, ofset, mac, e)
    kunye["satir"] = len(satirlar)
    kunye["sure_sn"] = round(time.monotonic() - bas, 2)
    return {"kunye": kunye, "satirlar": satirlar}


def _atlama(m: SimpleNamespace, anahtar: str, ham_ad: Any, adres: int, g: dict[str, Any],
            k: Optional[dict[str, Any]]) -> Optional[str]:
    """Ad haritasında anahtarı olup ölçüye girmeyen adın nedeni (``urun_olc.ATLAMALAR``; bilgi
    alanı, hükmü değiştirmez). Haritada anahtar yoksa ya da ad ölçüye girdiyse None."""
    uo, f1 = m.uo, m.f1
    if ham_ad is None or k is not None:
        return None
    if not (isinstance(ham_ad, str) and ham_ad and ham_ad != anahtar):
        return uo.ATLAMA_OZDES
    if not f1.is_generic_name(g.get("name"), [adres]):
        return uo.ATLAMA_GHIDRA_ADLI
    if f1.is_generic_name(ham_ad, [adres]):
        return uo.ATLAMA_JENERIK
    return "olcu_disi"          # GT'siz ya da C++ ikili


def _kaynak_alanlari(m: SimpleNamespace, s: dict[str, Any], dwarf: Optional[dict[str, Any]], aranges: Any,
                     mac: bool, gt_var: bool) -> dict[str, Any]:
    bos = {"dw_eslesme": None, "dw_adi": None, "dw_birim": None, "dw_derleme_dizini": None,
           "dw_birim_yolu": None, "dw_tanim_dosyasi": None, "dw_harici": None}
    if s["dis"] or s["thunk"]:
        # içe aktarım: kodu ikilide değil (PLT kapısı ya da dış sembol)
        return {**bos, "dw_eslesme": "yok", "kaynak_sinifi": SINIF_ICE_AKTARIM, "kaynak_alt_sinifi": None,
                "kaynak_kaniti": KANIT_ICE_AKTARIM}
    if mac:
        return {**bos, "dw_eslesme": "yok", "kaynak_sinifi": SINIF_BILINMIYOR, "kaynak_alt_sinifi": None,
                "kaynak_kaniti": KANIT_MAC}
    if not gt_var or dwarf is None:
        return {**bos, "kaynak_sinifi": SINIF_BILINMIYOR, "kaynak_alt_sinifi": None, "kaynak_kaniti": KANIT_GT_YOK}
    dosya_adresi = s["dosya_adresi"]
    d = dwarf["fonk"].get(dosya_adresi)
    if d is not None:
        yol, kanit = (d["dw_tanim_dosyasi"], KANIT_TANIM) if d["dw_tanim_dosyasi"] else (d["dw_birim_yolu"], KANIT_BIRIM)
        sinif, alt = kaynak_sinifla(yol, dwarf["gnulib"], m.dt)
        return {**bos, **d, "kaynak_sinifi": sinif, "kaynak_alt_sinifi": alt, "kaynak_kaniti": kanit}
    birim = None
    if aranges is not None:
        try:
            birim = aranges.cu_offset_at_addr(dosya_adresi)
        except Exception:       # noqa: BLE001 - pyelftools adres bulunamayınca çeşitli hatalar atar
            birim = None
    if birim is not None and birim in dwarf["birimler"]:
        b_ad, b_cd, b_yol = dwarf["birimler"][birim]
        if b_ad == LTO_BIRIMI:
            # LTO bölümü: kodun hangi kaynak dosyadan geldiğini birim adı söylemez
            sinif, alt, kanit = SINIF_BILINMIYOR, None, KANIT_ARANGES_LTO
        else:
            (sinif, alt), kanit = kaynak_sinifla(b_yol, dwarf["gnulib"], m.dt), KANIT_ARANGES
        return {**bos, "dw_eslesme": "aranges", "dw_birim": b_ad, "dw_derleme_dizini": b_cd,
                "dw_birim_yolu": b_yol, "kaynak_sinifi": sinif, "kaynak_alt_sinifi": alt,
                "kaynak_kaniti": kanit}
    if s["gt_crt"]:
        return {**bos, "dw_eslesme": "yok", "kaynak_sinifi": SINIF_DERLEYICI, "kaynak_alt_sinifi": "crt",
                "kaynak_kaniti": KANIT_CRT}
    if s["gt_adlari"]:
        # Kaynaktan derlenen her nesne dbgsym'de DWARF taşıyor; GT'de adı olup hiçbir birimin
        # kapsamadığı kod araç zincirinin hazır nesnelerinden (libgcc, bağlayıcı kaplaması).
        # Geliştirme setinde 157 / 157 satırda GT adıyla denetlendi (DEFTER.md §2).
        return {**bos, "dw_eslesme": "yok", "kaynak_sinifi": SINIF_DERLEYICI, "kaynak_alt_sinifi": "dwarf_yok",
                "kaynak_kaniti": KANIT_DWARF_YOK}
    return {**bos, "dw_eslesme": "yok", "kaynak_sinifi": SINIF_BILINMIYOR, "kaynak_alt_sinifi": None,
            "kaynak_kaniti": KANIT_DWARF_GT_YOK}


# --------------------------------------------------------------------------------------------
# Kanıt alanları (kalem 5) ve kayıt çiftleri (kalem 6)


CAGRI_CIFTI_DESTEKLENMIYOR = "desteklenmiyor"   # P-code dökümünde fonksiyon işaretçisi argümanı yok
GOT_BOLUMLERI = frozenset({".got", "__DATA_CONST,__got", "__DATA,__got"})


def ikili_goruntusu(m: SimpleNamespace, kosu: Path, e: Any, mac: bool) -> tuple[Any, dict[int, int], dict[str, Any]]:
    """Analiz edilen (soyulmuş) ikilinin görüntüsü ve veri yuvaları. Dosya sha256'sı koşunun
    ``target_info.json``'ıyla aynı olmalı. Mac'te koşunun kendi ``raw/<ad>`` kopyası okunur."""
    hedef = _json(kosu / "raw" / "target_info.json")
    yol = kosu / "raw" / e.ad if mac else Path(hedef["path"])
    if not yol.is_file() and mac:
        yol = Path(hedef["path"])
    if sha256_dosya(yol) != hedef.get("file_hash"):
        raise RuntimeError(f"{yol}: sha256 koşunun target_info'suyla aynı değil")
    if mac:
        g, yuva, kunye = oi.macho_oku(yol, m.mf.read_fixups(yol), m.mf.parse_dyld_fixups)
    else:
        g, yuva, kunye = oi.elf_oku(yol)
    kunye["ikili"] = str(yol)
    return g, yuva, kunye


def _pcode(static: Path) -> dict[int, list[Any]]:
    yol = static / "ghidra_output" / "pcode.jsonl"
    if not yol.is_file():
        bilgi = _json(static / "ghidra_pcode.json")
        yol = Path(bilgi.get("jsonl_path") or "")
    out: dict[int, list[Any]] = {}
    if not yol.is_file():
        return out
    with open(yol, encoding="utf-8") as f:
        for satir in f:
            if satir.strip():
                d = json.loads(satir)
                a = _hex(d.get("a"))
                if a is not None:
                    out[a] = d.get("ops") or []
    return out


def kanit_ekle(m: SimpleNamespace, satirlar: list[dict[str, Any]], static: Path, kosu: Path,
               genel: dict[str, Any], ofset: int, mac: bool, e: Any) -> dict[str, Any]:
    """Satırlara kanıt (kalem 5) ve kayıt çifti (kalem 6) alanlarını ekler; künye döner.

    Adresler tabloda Ghidra uzayındadır (``adres`` gibi); ikili okunurken ``ofset`` düşülür.
    """
    xr = _json(static / "ghidra_xrefs.json").get("function_xrefs") or {}
    dugum = _json(static / "ghidra_call_graph.json").get("nodes") or {}
    gdizgi: dict[int, str] = {}
    for d in _json(static / "ghidra_strings.json").get("strings", []):
        a = _hex(d.get("address"))
        if a is not None and isinstance(d.get("value"), str):
            gdizgi[a] = d["value"]
    pcode = _pcode(static)
    g, yuva, kunye = ikili_goruntusu(m, kosu, e, mac)
    satir_adr = {s["adres"]: s for s in satirlar}

    def dizgi_ghidra_adr(a: int) -> Optional[str]:
        """Ghidra adresindeki dizgi: ikiliden okunabiliyorsa o, yoksa Ghidra'nın değeri."""
        metin = oi.cstr_oku(g, a - ofset)
        return metin if metin is not None else gdizgi.get(a)

    def dizgi_dosya_adr(t: int) -> Optional[str]:
        return dizgi_ghidra_adr(t + ofset)

    def bolum_adi(a: int) -> Optional[str]:
        b = g.bolum_bul(a)
        return b.ad if b else None

    kayit = oi.kayit_ciftleri({s["dosya_adresi"] for s in satirlar}, yuva, dizgi_dosya_adr, bolum_adi)
    sayac = Counter()
    for s in satirlar:
        a = s["adres"]
        # --- kalem 5: doğrudan dizgiler (Ghidra'nın fonksiyona bağladığı)
        dz = {}
        for d in (xr.get(f"{a:08x}") or {}).get("strings_used") or []:
            da = _hex(d.get("address"))
            if da is None or da in dz:
                continue
            metin = dizgi_ghidra_adr(da)
            if metin is None:
                metin = d.get("value") if isinstance(d.get("value"), str) else ""
            mk, kirp = oi.kirp(metin)
            dz[da] = {"a": da, "m": mk, "k": kirp}
        s["dizgiler"] = [dz[k] for k in sorted(dz)]
        s["dizgi_sayisi"] = len(dz)
        # --- çağrı komşuları (Ghidra çağrı grafiği)
        n = dugum.get(f"{a:08x}") or {}
        cagrilan = {}
        for c in n.get("callees") or []:
            ca = _hex(c.get("address"))
            if ca is None or ca in cagrilan:
                continue
            hs = satir_adr.get(ca)
            ice = bool(hs and (hs["thunk"] or hs["dis"]))
            cagrilan[ca] = {"a": ca, "ad": (hs["ghidra_adi"] if ice else None),
                            "u": hs["urun_adi"] if hs else None}
        s["cagrilanlar"] = [cagrilan[k] for k in sorted(cagrilan)]
        s["cagiranlar"] = sorted({x for x in (_hex(c.get("address")) for c in n.get("callers") or [])
                                  if x is not None})
        s["cagrilan_sayisi"], s["cagiran_sayisi"] = len(s["cagrilanlar"]), len(s["cagiranlar"])
        ops = pcode.get(a)
        if ops is None:
            s["dolayli_cagri"] = None
            s["cagri_dizgileri"] = []
        else:
            cd, callind = oi.cagri_dizgileri(ops, dizgi_ghidra_adr)
            for x in cd:
                x["g"] = x["a"] in gdizgi
            s["dolayli_cagri"] = callind
            s["cagri_dizgileri"] = cd
        s["pcode_var"] = ops is not None
        s["yaprak"] = s["cagrilan_sayisi"] == 0 and s["dolayli_cagri"] is not True
        # --- kalem 6: kayıt çiftleri
        yerler = []
        for y in kayit.get(s["dosya_adresi"], []):
            got = y["b"] in GOT_BOLUMLERI
            yerler.append({"y": y["y"] + ofset, "b": y["b"], "got": got,
                           "d": [] if got else [{**d, "a": d["a"] + ofset, "g": d["a"] + ofset in gdizgi}
                                                 for d in y["d"]]})
        s["veri_yerleri"] = yerler
        s["veri_yeri_sayisi"] = len(yerler)
        s["kayit_cifti_var"] = any(y["d"] for y in yerler)
        s["cagri_ciftleri"] = CAGRI_CIFTI_DESTEKLENMIYOR
        sayac["pcode_var"] += int(s["pcode_var"])
        sayac["dizgili"] += int(bool(dz))
        sayac["veri_yerli"] += int(bool(yerler))
        sayac["kayit_ciftli"] += int(s["kayit_cifti_var"])
        sayac["cagri_dizgili"] += int(bool(s["cagri_dizgileri"]))
    kunye["sayac"] = dict(sayac)
    kunye["ghidra_dizgi"] = len(gdizgi)
    kunye["pcode_fonksiyon"] = len(pcode)
    return kunye


# --------------------------------------------------------------------------------------------
# Üretim


def gorevler(kok: Path, agac: Path, mac_veri: Path, indir: Path, asama: str, ks1: Any
             ) -> list[dict[str, Any]]:
    elfler = ks1.elfleri_topla(kok / "mac", kok / "debian")
    sorun = [f"{ks1.birim_anahtari(e)}/{e.ad}" for e in elfler if e.static is None]
    if sorun:
        raise RuntimeError(f"bitmemiş koşu: {sorun[:5]}")
    return [{"platform": e.platform, "program": e.program, "ad": e.ad, "static": str(e.static),
             "kosu": str(e.kosu), "agac": str(agac), "mac_veri": str(mac_veri), "indir": str(indir),
             "asama": asama} for e in elfler]


def _isci_baslat(agac: str) -> None:
    sys.dont_write_bytecode = True
    olcum_yukle(Path(agac))


def uret(kok: Path, agac: Path, mac_veri: Path, indir: Path, cikti: Path, asama: str, is_: int,
         yalniz: Optional[list[str]] = None) -> dict[str, Any]:
    m = olcum_yukle(agac)
    isler = gorevler(kok, agac, mac_veri, indir, asama, m.ks1)
    if yalniz:
        isler = [g for g in isler if f"{g['platform']}/{g['program']}/{g['ad']}" in yalniz
                 or f"{g['platform']}/{g['program']}" in yalniz]
    bas = time.monotonic()
    sonuclar: list[dict[str, Any]] = []
    # büyük ikililer önce (sürenin kuyruğu kısalsın)
    isler.sort(key=lambda g: -Path(g["static"], "ghidra_functions.json").stat().st_size)
    if is_ <= 1:
        for g in isler:
            sonuclar.append(ikili_isle(g))
    else:
        with ProcessPoolExecutor(max_workers=is_, initializer=_isci_baslat, initargs=(str(agac),)) as ex:
            sonuclar = list(ex.map(ikili_isle, isler))
    sonuclar.sort(key=lambda r: (r["kunye"]["birim"], r["kunye"]["ikili"]))
    cikti.parent.mkdir(parents=True, exist_ok=True)
    gecici = cikti.with_name(cikti.name + ".yaziliyor")
    n = 0
    with gzip.open(gecici, "wt", encoding="utf-8", compresslevel=6) as f:
        for r in sonuclar:
            for s in sorted(r["satirlar"], key=lambda s: s["adres"]):
                f.write(json.dumps(s, ensure_ascii=False, sort_keys=True) + "\n")
                n += 1
    os.replace(gecici, cikti)
    kunye = {"sema": SEMA, "asama": asama, "komut": sys.argv, "kok": str(kok), "olcum_agaci": str(agac),
             "olcum_agaci_head": _git_head(agac), "repo_head": _git_head(REPO),
             "betik_sha256": {p.name: sha256_dosya(p) for p in (Path(__file__).resolve(), _BURASI / "olgu_ikili.py")},
             "olcum_sha256": {n_: sha256_dosya(m.agac / "scripts" / "measurement" / n_)
                              for n_ in ("urun_olc.py", "ks1_olc.py", "function_f1.py", "macho_f1.py",
                                         "macho_measure.py", "dwarf_tip.py")},
             "python": _platform.python_version(), "is": is_, "sure_sn": round(time.monotonic() - bas, 1),
             "satir": n, "ikili": len(sonuclar), "tablo": str(cikti), "tablo_sha256": sha256_dosya(cikti),
             "ikililer": [r["kunye"] for r in sonuclar]}
    kunye_yolu = cikti.with_name(cikti.name.replace(".jsonl.gz", "") + "_kunye.json")
    kunye_yolu.write_text(json.dumps(kunye, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return kunye


def _git_head(kok: Path) -> Optional[str]:
    try:
        return subprocess.run(["git", "-C", str(kok), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def tablo_oku(yol: Path) -> Iterable[dict[str, Any]]:
    with gzip.open(yol, "rt", encoding="utf-8") as f:
        for satir in f:
            if satir.strip():
                yield json.loads(satir)


# --------------------------------------------------------------------------------------------
# Tutarlılık kapısı (kalem 3)


def dogrula(tablo: Path, olcum_json: Path, oge_yaz: Any, dogru_degeri: str,
            havuz: Optional[dict[str, int]] = None, birim_beklenen: Optional[dict[str, tuple[int, int, int]]] = None,
            ikili_sayisi: int = TABAN_IKILI, satir_sayisi: int = TABAN_FONKSIYON) -> dict[str, Any]:
    """Tablodan yeniden hesaplanan sayılar taban ölçümüyle birebir mi.

    Denetimler: (1) satır ve ikili sayısı; (2) havuz toplamları (``TABAN_HAVUZ``); (3) birim başına
    ad / doğru / yanlış (``TABAN_BIRIM``) ve nüfus (ölçüm JSON'unun ``birimler``); (4) ikili
    başına nüfus ve ad / doğru (``elfler``); (5) öğe düzeyi: her ölçülen adın ``urun_olc.oge_yaz``
    metni ölçüm JSON'unun ``ogeler``'iyle aynı, iki yönde de eksiksiz. ``oge_yaz``: urun_olc'unki.
    """
    olcum = _json(olcum_json)
    toplam = Counter()
    birim = defaultdict(Counter)
    ikili = defaultdict(Counter)
    ogeler: dict[str, dict[str, dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    ikililer = set()
    for s in tablo_oku(tablo):
        b = s["birim"]
        ikililer.add((b, s["ikili"]))
        toplam["satir"] += 1
        if s["nufusta"]:
            toplam["nufus"] += 1
            birim[b]["nufus"] += 1
            ikili[(b, s["ikili"])]["nufus"] += 1
        if s["urun_olcude"]:
            dogru = s["hukum"] == dogru_degeri
            for c in (toplam, birim[b], ikili[(b, s["ikili"])]):
                c["ad_verilen"] += 1
                c["dogru"] += int(dogru)
                c["yanlis"] += int(not dogru)
            if s["nufusta"]:
                toplam["nufusta_ad"] += 1
                toplam["nufusta_dogru"] += int(dogru)
            ogeler[b][s["ikili"]][s["adres_hex"]] = oge_yaz(
                {"durum": s["hukum"], "satir": s["satir"], "nufusta": s["nufusta"], "etiket": s["etiket"],
                 "kanal": s["kanal"]})
    denetim: list[dict[str, Any]] = []

    def esit(ad: str, bulunan: Any, beklenen: Any) -> None:
        denetim.append({"denetim": ad, "bulunan": bulunan, "beklenen": beklenen, "tuttu": bulunan == beklenen})

    havuz = TABAN_HAVUZ if havuz is None else havuz
    birim_beklenen = TABAN_BIRIM if birim_beklenen is None else birim_beklenen
    esit("ikili_sayisi", len(ikililer), ikili_sayisi)
    esit("satir_sayisi (Ghidra fonksiyonu)", toplam["satir"], satir_sayisi)
    for a, v in havuz.items():
        esit(f"havuz.{a}", toplam[a], v)
    for b, (ad, dg, yn) in sorted(birim_beklenen.items()):
        esit(f"{b}.ad/dogru/yanlis", [birim[b]["ad_verilen"], birim[b]["dogru"], birim[b]["yanlis"]], [ad, dg, yn])
        ob = olcum["birimler"][b]
        esit(f"{b}.nufus", birim[b]["nufus"], ob["nufus"])
        for e, kun in ob["elfler"].items():
            ik = ikili[(b, e)]
            if [ik["nufus"], ik["ad_verilen"], ik["dogru"]] != [kun["nufus"], kun["ad_verilen"], kun["dogru"]]:
                esit(f"{b}/{e}.nufus/ad/dogru", [ik["nufus"], ik["ad_verilen"], ik["dogru"]],
                     [kun["nufus"], kun["ad_verilen"], kun["dogru"]])
    esit("birim_kumesi", sorted({b for b, _ in ikililer}), sorted(birim_beklenen))
    # öğe düzeyi
    fark = []
    olcum_oge = olcum["ogeler"]
    for b in sorted(set(olcum_oge) | set(ogeler)):
        for e in sorted(set(olcum_oge.get(b, {})) | set(ogeler.get(b, {}))):
            t = ogeler.get(b, {}).get(e, {})
            o = olcum_oge.get(b, {}).get(e, {})
            for a in sorted(set(t) | set(o)):
                if t.get(a) != o.get(a):
                    fark.append({"birim": b, "ikili": e, "adres": a, "tablo": t.get(a), "olcum": o.get(a)})
    esit("oge_farki", len(fark), 0)
    tuttu = all(d["tuttu"] for d in denetim)
    return {"sema": SEMA + "/dogrula", "tablo": str(tablo), "tablo_sha256": sha256_dosya(tablo),
            "olcum_json": str(olcum_json), "olcum_json_sha256": sha256_dosya(olcum_json),
            "tuttu": tuttu, "denetimler": denetim, "oge_farki_ornek": fark[:20],
            "toplam": dict(toplam), "oge_sayisi": sum(len(x) for v in ogeler.values() for x in v.values())}


# --------------------------------------------------------------------------------------------
# CLI


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    u = sub.add_parser("uret", help="tabloyu yaz")
    u.add_argument("--kok", type=Path, default=VARSAYILAN_KOK)
    u.add_argument("--mac-veri", type=Path, default=VARSAYILAN_MAC_VERI)
    u.add_argument("--debian-indir", type=Path, default=VARSAYILAN_INDIR)
    u.add_argument("--asama", choices=(ASAMA_CEKIRDEK, ASAMA_TAM), default=ASAMA_TAM)
    u.add_argument("--is", dest="is_", type=int, default=4)
    u.add_argument("--yalniz", action="append", default=None, help="platform/program[/ikili] (sınama için)")
    u.add_argument("--dogrula", action="store_true", help="yazdıktan sonra tutarlılık kapısını koş")
    d = sub.add_parser("dogrula", help="tutarlılık kapısı")
    b = sub.add_parser("butce", help="kapsam bütçesi (BUTCE.md + butce.json)")
    b.add_argument("--md", type=Path, default=BELGE_DIZINI / "BUTCE.md")
    b.add_argument("--json", type=Path, default=VARSAYILAN_CIKTI_DIZINI / "butce.json")
    for p in (u, d, b):
        p.add_argument("--olcum-agaci", type=Path, default=VARSAYILAN_AGAC)
        p.add_argument("--tablo", type=Path, default=VARSAYILAN_TABLO)
    for p in (u, d):
        p.add_argument("--olcum-json", type=Path, default=OLCUM_JSON)
        p.add_argument("--dogrulama-json", type=Path, default=None)
    a = ap.parse_args(argv)
    m = olcum_yukle(a.olcum_agaci)
    if a.komut == "uret":
        kunye = uret(a.kok, m.agac, a.mac_veri, a.debian_indir, a.tablo, a.asama, a.is_, a.yalniz)
        print(f"uret: {kunye['ikili']} ikili, {kunye['satir']} satır, {kunye['sure_sn']} sn → {a.tablo}")
        if not a.dogrula:
            return 0
    if a.komut in ("uret", "dogrula"):
        sonuc = dogrula(a.tablo, a.olcum_json, m.uo.oge_yaz, m.uo.DOGRU)
        yol = a.dogrulama_json or a.tablo.with_name("dogrulama.json")
        sonuc["olcum_agaci"] = str(m.agac)
        yol.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        for dn in sonuc["denetimler"]:
            if not dn["tuttu"] or dn["denetim"].startswith("havuz"):
                print(f"{'TUTTU' if dn['tuttu'] else 'TUTMADI'}  {dn['denetim']}: {dn['bulunan']} (beklenen {dn['beklenen']})")
        print(f"KAPI: {'TUTTU' if sonuc['tuttu'] else 'TUTMADI'} ({len(sonuc['denetimler'])} denetim) → {yol}")
        return 0 if sonuc["tuttu"] else 1
    if a.komut == "butce":
        import olgu_butce
        return olgu_butce.main_butce(a, m)
    return 2


if __name__ == "__main__":
    sys.exit(main())
