#!/usr/bin/env python3
"""KS-1 kesin çapalar (plan v2.2 N1): GT'siz sayım, program sınıfı eş değişkeni ve GT'ye karşı ölçüm.

Ön kayıt: ``docs/arge/2026-10-21_g11_n1/ks1_onkayit.md``. Çıkarıcı:
``karadul/reconstruction/tarif/kesin.py``.

Alt komutlar
------------
``say``
    GT'siz sayım: tür ve birim (platform, program) başına koruma hunisi (yuva → dizgi → K1 … K5 →
    çapa), parça ve export sayıları. Ad yazmaz.
``sinif``
    Program sınıfı eş değişkeni (GT'siz): dizgi zenginliği (snake_case tanımlayıcı biçimli dizgi
    sayısı / iç fonksiyon sayısı) ve boyut tabakası. Değerler platform başına kilitlenir.
``olc``
    Çapa ↔ GT (adım 2; ön kayıt commit'lenmeden koşmaz). Satır ve birim başına kesinlik ve Wilson %95
    aralığı, kapsam ve satır kararı. Kesinliğe parça dışındaki bütün çapalar girer: klon ekli GT
    adında taban eşitliği doğrudur, GT'de karşılığı olmayan çapa yanlıştır. Karar kaynak program
    düzeyindedir: aynı programın platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla;
    tekil ve örnek düzeyi makrolarının küçüğü ≥ %95 olmalı ve giren hiçbir birimin Wilson üst sınırı
    %95'in altında kalmamalıdır. Koşu başında ön koşullar denetlenir:
      - ön kayıt dosyasını ekleyen commit HEAD'in atası;
      - ölçümü belirleyen dosyaların (``OLCUM_DOSYALARI``) sha256'sı o commit'teki
        ``ks1_sabitler.json`` ile aynı;
      - birim başına ELF sayısı beklenenle aynı, hepsi bitmiş ve aynı sabitlenmiş Ghidra sürümüyle.
``sabitle``
    ``ks1_sabitler.json``'u bugünkü dosyaların sha256'larıyla yazar (ön kayıt commit'inden önce).

Birimler
--------
- Mac: ``<koşu>/<program>/ws/workspaces/<program>/<zaman>/static`` (tmux, htop).
- Debian: ``<koşu>/<program>/<elf>/ws/workspaces/<elf>/<zaman>/static``; ``BITTI`` dosyası olmayan
  ELF "bekliyor" sayılır. Bir program (ör. coreutils) birden çok ELF'ten oluşur; birim programdır.

Kullanım
--------
    python scripts/measurement/ks1_olc.py say --mac-kosu <ol7-a> --debian-kosu <n1_debian13> --json <j>
    python scripts/measurement/ks1_olc.py sinif --mac-kosu <ol7-a> --debian-kosu <n1_debian13> --json <j>
    python scripts/measurement/ks1_olc.py olc --mac-kosu <ol7-a> --mac-veri <olcum_mac> \\
        --debian-kosu <n1_debian13> --json <j> --md <m>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Optional

SEMA = "karadul-ks1-olc/1"
REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

KESIN_YOLU = REPO / "karadul" / "reconstruction" / "tarif" / "kesin.py"
OLC_YOLU = Path(__file__).resolve()
ONKAYIT_DIZINI = REPO / "docs" / "arge" / "2026-10-21_g11_n1"
ONKAYIT_YOLU = ONKAYIT_DIZINI / "ks1_onkayit.md"
SABITLER_YOLU = ONKAYIT_DIZINI / "ks1_sabitler.json"
SABITLER_SEMA = "karadul-ks1-sabitler/1"
KESIN_REL = "karadul/reconstruction/tarif/kesin.py"
# Ölçümün sonucunu belirleyen dosyalar (depo köküne göre): çıkarıcı, bu betik ve GT, ofset ile
# nüfusu üreten yardımcılar. ``olc`` bunların sha256'sını ön kayıt commit'indekiyle karşılaştırır.
OLCUM_DOSYALARI = (
    KESIN_REL,
    "scripts/measurement/ks1_olc.py",
    "scripts/measurement/function_f1.py",
    "scripts/measurement/macho_f1.py",
    "scripts/measurement/macho_measure.py",
    "tests/benchmark/metrics.py",
)
# Ön kayıtla sabitlenen bütün dosyalar: ölçüm dosyaları + testler ve mutant belirtimi
SABIT_DOSYALAR = OLCUM_DOSYALARI + (
    "tests/test_tarif_kesin.py",
    "tests/test_ks1_olc.py",
    "scripts/measurement/mutation_specs_ks1.json",
)

PLATFORM_MAC = "mac"
PLATFORM_DEBIAN = "debian"
BITTI = "BITTI"
ONDALIK = 6
# Nüfusun beklenen büyüklüğü (ön kayıt §7), birim (platform/program) başına: ölçüm yalnız biten
# ELF'leri sayıp yarım koşuyu geçirmesin. Mac 2, Debian 117 ELF.
BEKLENEN_ELF = {
    "mac/tmux": 1, "mac/htop": 1,
    "debian/tmux": 1, "debian/htop": 1, "debian/tree": 1, "debian/zstd": 2,
    "debian/redis-tools": 4, "debian/sqlite3": 1, "debian/openssl": 1, "debian/coreutils": 106,
}

# ---- Ön kayıt seçimleri (ks1_onkayit.md §8-§9) ----
N_MIN = 10              # karara girmek için birimdeki en az tekil öğe
EN_AZ_PROGRAM = 2       # satırın karara girmesi için N_MIN'i geçen en az FARKLI kaynak program
KESINLIK_ESIGI = 0.95   # makro ortalama eşiği (plan v2.1 3.2); Wilson üst sınırı koşulu da bununla
ZENGINLIK_ESIGI = 0.05  # dizgi zenginliği sınıfı: iki platformda ortak mutlak eşik
GORUNUMLER = ("tekil", "ornek_duzeyi")   # karar, ikisinin makrosunun küçüğüyle verilir
# Program sınıfı: snake_case tanımlayıcı biçimli dizgi
SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
BOYUT_SINIRLARI = ((500, "kucuk"), (2000, "orta"))   # iç fonksiyon sayısı: <500, <2000, ≥2000
BOYUT_EN_BUYUK = "buyuk"

# Derleyici ekleri: GT adının bütün takma adları bunlardan birini taşıyorsa çapa "klon" satırına
# düşer; doğruluğu, ekler soyularak bulunan taban adla tam eşitliktir.
KLON_EKI_RE = re.compile(r"\.(?:isra|constprop|part|cold|lto_priv|clone|llvm|__uniq)(?:\.\d+)*$")
DIS_PARCA_RE = re.compile(r"^_?OUTLINED_FUNCTION_\d+$")
# C++ ikili (GT adları mangled; tam eşitlik tanımsız): içe aktarılan adlardan biri mangled (``_Z``;
# Ghidra çoğunu açtığı için yetmez), C++ istisna kişiliği ya da C++ istisna ABI'si.
# ``__cxa_finalize`` / ``__cxa_atexit`` C ikililerinde de vardır, işaret değildir. Mach-O'da adın
# baştaki tek ``_``'ı soyulduktan sonra aranır (``__Znwm``, ``___cxa_throw``).
CPP_ISARETLERI = ("_Z", "__gxx_personality", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_throw",
                  "__cxa_rethrow")

OFSET_KAYNAGI = "ghidra_entry"   # ``function_f1.derive_image_offset``'in kanıtlı kaynağı
DURUM_DOGRU = "dogru"
DURUM_YANLIS = "yanlis"
SATIR_ANA = "ana"
SATIR_KLON = "klon"
SATIR_ESLENEMEDI = "eslenemedi"


class OnkosulHatasi(RuntimeError):
    """Ön kayıt koşulu tutmuyor: ölçüm durur."""


# --------------------------------------------------------------------------------------------
# Ön koşullar ve içe aktarma


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _git(*arglar: str, kok: Path = REPO) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *arglar], cwd=kok, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as hata:
        raise OnkosulHatasi(f"git çalıştırılamadı: {hata}") from None


def onkayit_commit(yol: Path = ONKAYIT_YOLU, kok: Path = REPO) -> str:
    """Ön kayıt dosyasını depoya ilk ekleyen commit (HEAD'in geçmişinde)."""
    rel = Path(yol).resolve().relative_to(Path(kok).resolve()).as_posix()
    r = _git("log", "--diff-filter=A", "--format=%H", "--", rel, kok=kok)
    satirlar = [s for s in r.stdout.split() if s.strip()]
    if r.returncode != 0 or not satirlar:
        raise OnkosulHatasi(f"ön kayıt commit'lenmemiş: {rel}")
    return satirlar[-1]


def commit_atasi_mi(commit: str, kok: Path = REPO) -> bool:
    r = _git("merge-base", "--is-ancestor", commit, "HEAD", kok=kok)
    if r.returncode not in (0, 1):
        raise OnkosulHatasi(f"git merge-base: {r.stderr.strip() or r.returncode}")
    return r.returncode == 0


def committeki_sabitler(commit: str, kok: Path = REPO,
                        yol: Path = SABITLER_YOLU) -> dict[str, Any]:
    rel = Path(yol).resolve().relative_to(Path(kok).resolve()).as_posix()
    r = _git("show", f"{commit}:{rel}", kok=kok)
    if r.returncode != 0:
        raise OnkosulHatasi(f"{commit} commit'inde {rel} yok")
    belge = json.loads(r.stdout)
    if belge.get("sema") != SABITLER_SEMA:
        raise OnkosulHatasi(f"{rel}: şema {belge.get('sema')!r}, beklenen {SABITLER_SEMA!r}")
    return belge


def sha256_denetle(yol: Path, beklenen: str) -> str:
    gercek = sha256_dosya(yol)
    if gercek != beklenen:
        raise OnkosulHatasi(f"{yol}: sha256 {gercek}, ön kayıttaki {beklenen}")
    return gercek


def onkosullari_denetle(kok: Path = REPO, onkayit: Path = ONKAYIT_YOLU,
                        sabitler: Path = SABITLER_YOLU) -> dict[str, Any]:
    """Ön kayıt commit'i HEAD'in atası; ölçüm dosyaları ön kayıttaki sha256'larla aynı."""
    commit = onkayit_commit(onkayit, kok)
    if not commit_atasi_mi(commit, kok):
        raise OnkosulHatasi(f"ön kayıt commit'i {commit} HEAD'in atası değil")
    belge = committeki_sabitler(commit, kok, sabitler)
    dosyalar = belge.get("dosyalar") or {}
    denetlenen = {}
    for rel in OLCUM_DOSYALARI:
        if rel not in dosyalar:
            raise OnkosulHatasi(f"ön kayıtta {rel} için sha256 yok")
        denetlenen[rel] = sha256_denetle(Path(kok) / rel, dosyalar[rel])
    return {"onkayit_commit": commit, "onkayit_commit_atasi": True, "sha256": denetlenen}


def _yukle(ad: str, yol: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(ad, yol)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


def kesin_modulu(beklenen_sha256: Optional[str] = None) -> ModuleType:
    """Çıkarıcı; sha256 verilirse içe aktarmadan önce denetlenir."""
    if beklenen_sha256 is not None:
        sha256_denetle(KESIN_YOLU, beklenen_sha256)
    return _yukle("ks1_kesin_olcumde", KESIN_YOLU)


def sabitle(kok: Path = REPO, hedef: Path = SABITLER_YOLU) -> dict[str, Any]:
    belge = {"sema": SABITLER_SEMA,
             "dosyalar": {rel: sha256_dosya(Path(kok) / rel) for rel in SABIT_DOSYALAR}}
    hedef.parent.mkdir(parents=True, exist_ok=True)
    hedef.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return belge


# --------------------------------------------------------------------------------------------
# Birimler


@dataclass(frozen=True)
class Elf:
    """Bir ikili (Mac'te program = ikili)."""

    platform: str
    program: str
    ad: str
    static: Optional[Path]   # bitmediyse None
    kosu: Path               # ws/ ve raw/ içeren çalışma alanı (static'in üstü)


def _tek_static(kok: Path) -> Path:
    """``<kok>/ws/workspaces/<ad>/<zaman>/static``: tam olarak bir tane olmalı.

    Çalışma alanı adı ELF adına eşit varsayılmaz: Karadul adı temizler (coreutils ``[`` → ``_``).
    """
    taban = kok / "ws" / "workspaces"
    adlar = sorted(a for a in (taban.iterdir() if taban.is_dir() else []) if a.is_dir())
    adaylar = sorted(z / "static" for a in adlar for z in a.iterdir() if (z / "static").is_dir())
    if len(adaylar) != 1:
        raise ValueError(f"{kok}: {len(adaylar)} çalışma alanı (tam olarak bir tane olmalı)")
    return adaylar[0]


def mac_elfleri(kosu: Path) -> list[Elf]:
    out = []
    for d in sorted(p for p in Path(kosu).iterdir() if p.is_dir()):
        if not (d / "ws").is_dir():
            continue
        st = _tek_static(d)
        out.append(Elf(PLATFORM_MAC, d.name, d.name, st, st.parent))
    return out


def debian_elfleri(kosu: Path) -> list[Elf]:
    out = []
    for prog in sorted(p for p in Path(kosu).iterdir() if p.is_dir()):
        for d in sorted(p for p in prog.iterdir() if p.is_dir()):
            if not (d / BITTI).is_file():
                out.append(Elf(PLATFORM_DEBIAN, prog.name, d.name, None, d))
                continue
            st = _tek_static(d)
            out.append(Elf(PLATFORM_DEBIAN, prog.name, d.name, st, st.parent))
    return out


def elfleri_topla(mac_kosu: Optional[Path], debian_kosu: Optional[Path],
                  static: Iterable[Path] = ()) -> list[Elf]:
    elfler: list[Elf] = []
    if mac_kosu:
        elfler += mac_elfleri(mac_kosu)
    if debian_kosu:
        elfler += debian_elfleri(debian_kosu)
    for st in static:
        st = Path(st)
        elfler.append(Elf("tek", st.parent.parent.name, st.parent.parent.name, st, st.parent))
    return elfler


def birim_anahtari(e: Elf) -> str:
    return f"{e.platform}/{e.program}"


# --------------------------------------------------------------------------------------------
# GT'siz: sayım ve program sınıfı


def _json(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8"))


def cpp_ikili_mi(fonksiyonlar: list[dict[str, Any]], platform_: str = PLATFORM_DEBIAN) -> bool:
    """İçe aktarılan (thunk/dış) adlardan biri C++ çalışma zamanına ait mi (GT'siz).

    Mach-O'da Ghidra içe aktarılan adı baştaki ``_`` ile verir (``___assert_rtn``); işaret, tek ``_``
    soyulduktan sonra aranır. Soyulmadan aransaydı ``_ZSTD_…`` gibi C adları ``_Z`` sayılırdı.
    """
    return any(platform_adi(str(f.get("name") or ""), platform_).startswith(CPP_ISARETLERI)
               for f in fonksiyonlar if f.get("is_thunk") or f.get("is_external"))


def ic_fonksiyon_sayisi(fonksiyonlar: list[dict[str, Any]]) -> int:
    return sum(1 for f in fonksiyonlar if not f.get("is_thunk") and not f.get("is_external"))


def snake_dizgi_sayisi(dizgiler: list[dict[str, Any]]) -> int:
    return sum(1 for s in dizgiler if isinstance(s.get("value"), str) and SNAKE_RE.match(s["value"]))


def boyut_tabakasi(ic_fonksiyon: float) -> str:
    for sinir, ad in BOYUT_SINIRLARI:
        if ic_fonksiyon < sinir:
            return ad
    return BOYUT_EN_BUYUK


def elf_sinif_olcusu(static: Path, platform_: str = PLATFORM_DEBIAN) -> dict[str, Any]:
    fonk = _json(Path(static) / "ghidra_functions.json").get("functions", [])
    dizgi = _json(Path(static) / "ghidra_strings.json").get("strings", [])
    return {"ic_fonksiyon": ic_fonksiyon_sayisi(fonk), "snake_dizgi": snake_dizgi_sayisi(dizgi),
            "cpp": cpp_ikili_mi(fonk, platform_)}


def _ortanca(degerler: list[float]) -> Optional[float]:
    d = sorted(degerler)
    if not d:
        return None
    k = len(d) // 2
    return float(d[k]) if len(d) % 2 else (d[k - 1] + d[k]) / 2


def birim_sinifi(olculer: list[dict[str, Any]]) -> dict[str, Any]:
    """Birim (program) düzeyi: zenginlik = Σ snake dizgi / Σ iç fonksiyon; boyut = ELF ortancası."""
    toplam_f = sum(o["ic_fonksiyon"] for o in olculer)
    toplam_s = sum(o["snake_dizgi"] for o in olculer)
    ortanca = _ortanca([o["ic_fonksiyon"] for o in olculer])
    return {"elf": len(olculer), "ic_fonksiyon": toplam_f, "snake_dizgi": toplam_s,
            "dizgi_zenginligi": round(toplam_s / toplam_f, ONDALIK) if toplam_f else None,
            "ic_fonksiyon_ortanca": ortanca,
            "boyut_tabakasi": boyut_tabakasi(ortanca) if ortanca is not None else None}


def sinif(elfler: list[Elf]) -> dict[str, Any]:
    birimler: dict[str, list[dict[str, Any]]] = {}
    bekleyen = []
    for e in elfler:
        if e.static is None:
            bekleyen.append(f"{birim_anahtari(e)}/{e.ad}")
            continue
        birimler.setdefault(birim_anahtari(e), []).append(
            {"elf": e.ad, **elf_sinif_olcusu(e.static, e.platform)})
    tablo = {b: {**birim_sinifi(o), "elfler": o} for b, o in sorted(birimler.items())}
    # zenginlik sınıfı: iki platformda ortak, önceden yazılmış mutlak eşik (ön kayıt §9). Platform
    # içi ortanca kullanılsaydı aynı program platform değişince sınıf değiştirirdi.
    for t in tablo.values():
        z = t["dizgi_zenginligi"]
        t["zenginlik_esigi"] = ZENGINLIK_ESIGI
        t["zenginlik_sinifi"] = None if z is None else ("zengin" if z >= ZENGINLIK_ESIGI else "yoksul")
    return {"sema": SEMA, "komut": "sinif", "birimler": tablo, "bekleyen": sorted(bekleyen),
            "tanim": {"snake_re": SNAKE_RE.pattern, "boyut_sinirlari": BOYUT_SINIRLARI,
                      "zenginlik_esigi": ZENGINLIK_ESIGI}}


def say(elfler: list[Elf], kesin: Optional[ModuleType] = None) -> dict[str, Any]:
    """GT'siz sayım. Çıktıda ad yok: huni sayaçları, rol ve tür sayıları."""
    kesin = kesin or kesin_modulu()
    birimler: dict[str, dict[str, Any]] = {}
    bekleyen = []
    for e in elfler:
        if e.static is None:
            bekleyen.append(f"{birim_anahtari(e)}/{e.ad}")
            continue
        r = kesin.extract_anchors(e.static)
        b = birimler.setdefault(birim_anahtari(e), {
            "elf": 0, "abi": set(), "sayac": Counter(), "rol_tur": Counter(), "cpp_elf": 0})
        b["elf"] += 1
        b["abi"].add(str(r.abi))
        b["sayac"].update(r.counts)
        for c in r.anchors.values():
            b["rol_tur"][f"{c.role}:{'+'.join(c.types)}"] += 1
        fonk = _json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        b["cpp_elf"] += int(cpp_ikili_mi(fonk, e.platform))
    tablo = {}
    for k, b in sorted(birimler.items()):
        tablo[k] = {"elf": b["elf"], "abi": sorted(b["abi"]), "cpp_elf": b["cpp_elf"],
                    "sayac": dict(sorted(b["sayac"].items())),
                    "rol_tur": dict(sorted(b["rol_tur"].items()))}
    return {"sema": SEMA, "komut": "say", "ks1_surumu": kesin.KS1_VERSION,
            "kesin_sha256": sha256_dosya(KESIN_YOLU), "birimler": tablo, "bekleyen": sorted(bekleyen)}


# --------------------------------------------------------------------------------------------
# GT'ye karşı değerlendirme (adım 2)

DIZGI_TURLERI = "dizgi_turleri"   # birleşik satır: assert + func_kalibi + func_aktarma, çapa başına bir
ASSERT_UST = "assert_ust"         # parçadan üst fonksiyona kaldırılmış assert çapaları (ayrı karar)
# Karar satırları (ön kayıt §8): tür başına; assert kendi gövdesinde ve kaldırılmış olarak ayrı
KARAR_SATIRLARI = ("assert", ASSERT_UST, "func_kalibi", "func_aktarma")
# Yalnız raporlananlar: export ad üretmez (Ghidra'nın adını işaretler), birleşik satır karar
# satırlarının toplamıdır ve başarısız bir satırı örtebilir. Bunlar için karar hesaplanmaz.
RAPOR_SATIRLARI = ("export", DIZGI_TURLERI)
BUTUN_SATIRLAR = KARAR_SATIRLARI + RAPOR_SATIRLARI


def _f1() -> ModuleType:
    import function_f1
    return function_f1


def _mf() -> ModuleType:
    import macho_f1
    return macho_f1


def platform_adi(ad: str, platform_: str) -> str:
    """Mach-O simgesinin baştaki tek ``_``'ı C adına ait değildir; soyulur."""
    if platform_ == PLATFORM_MAC and ad.startswith("_"):
        return ad[1:]
    return ad


def klon_tabani(ad: str) -> Optional[str]:
    """Derleyici eklerini soy; ek yoksa None. Makine dışlayıcısı parçasının tabanı boştur."""
    if DIS_PARCA_RE.match(ad):
        return ""
    cur, degisti = ad, False
    while True:
        yeni = KLON_EKI_RE.sub("", cur)
        if yeni == cur or not yeni:
            break
        cur, degisti = yeni, True
    return cur if degisti else None


def gt_klon_mu(gt_adlari: list[str], platform_: str) -> bool:
    """GT fonksiyonunun bütün takma adları derleyici ekli mi (klon, soğuk parça, dışlanmış parça)."""
    adlar = [platform_adi(g, platform_) for g in gt_adlari]
    return bool(adlar) and all(klon_tabani(g) is not None for g in adlar)


def capa_degerlendir(capa_ad: str, gt_adlari: list[str], platform_: str) -> dict[str, Any]:
    """Tek çapanın GT'ye göre durumu (ön kayıt §6).

    ``satir``: ``ana`` (GT adlarından en az biri eksiz) ya da ``klon`` (bütün adlar ekli).
    ``durum``: ana satırda çapa adı bir GT adına tam eşit (Mach-O'da baştaki ``_`` soyulmuş);
    klon satırında eki soyulmuş bir tabana tam eşit. Büyük/küçük harf, önek ya da ek yok sayılmaz.
    İki satır da kesinliğe girer (``karar_ogeleri``).
    ``proje``: ``function_f1.match_strict`` (proje normalleştirmesi; yalnız duyarlılık satırı).
    """
    adlar = [platform_adi(g, platform_) for g in gt_adlari]
    if gt_klon_mu(gt_adlari, platform_):
        satir, dogru = SATIR_KLON, capa_ad in [klon_tabani(g) for g in adlar]
    else:
        satir, dogru = SATIR_ANA, capa_ad in adlar
    return {"satir": satir, "durum": DURUM_DOGRU if dogru else DURUM_YANLIS,
            "proje": bool(_f1().match_strict(capa_ad, adlar))}


def oran(k: int, n: int) -> dict[str, Any]:
    if n == 0:
        return {"k": 0, "n": 0, "oran": None, "aralik": None}
    return {"k": k, "n": n, "oran": round(k / n, ONDALIK), "aralik": _mf().wilson_interval(k, n)}


@dataclass
class GtBirimi:
    """Bir ELF'in GT'si, Ghidra adres uzayında."""

    adlar: dict[int, list[str]]     # adres → GT adları (takma adlar)
    nufus: set[int]                 # ad bekleyen: program sınıfı, Ghidra'da adsız, CRT/export değil
    export_gt: set[int]             # dışa aktarılan GT fonksiyonları (ELF)
    kunye: dict[str, Any]


def degerlendir_elf(capalar: dict[str, Any], gt: GtBirimi, platform_: str,
                    dizgi_turleri: Iterable[str]) -> list[dict[str, Any]]:
    """Çapa başına bir kayıt: türler, rol, satır, durum, nüfusta mı. Ad yalnız bellekte kalır."""
    dizgi_turleri = set(dizgi_turleri)
    kayitlar = []
    for adres, c in capalar.items():
        a = int(adres, 16)
        adlar = gt.adlar.get(a)
        k = {"adres": a, "ad": c.name, "turler": list(c.types), "rol": c.role,
             "dizgi": bool(dizgi_turleri & set(c.types)), "nufusta": a in gt.nufus,
             "export_gt": a in gt.export_gt}
        if adlar is None:
            k.update(satir=SATIR_ESLENEMEDI, durum=None, proje=None)
        else:
            k.update(capa_degerlendir(c.name, adlar, platform_))
        kayitlar.append(k)
    return kayitlar


def gorunum(kayitlar: list[dict[str, Any]], satir: str) -> list[dict[str, Any]]:
    """Bir karar satırının kayıtları; her kayıt bir kez.

    ``assert``: assert türlü, rolü ``kendi``. ``assert_ust``: rolü ``ust`` ya da ``parca`` (parçalar
    yalnız ayrı sayılır). Öbür türler türe göre; ``dizgi_turleri`` bütün dizgi türleri.
    """
    if satir == DIZGI_TURLERI:
        return [k for k in kayitlar if k["dizgi"]]
    if satir == "assert":
        return [k for k in kayitlar if "assert" in k["turler"] and k["rol"] == "kendi"]
    if satir == ASSERT_UST:
        return [k for k in kayitlar if k["rol"] in ("ust", "parca")]
    return [k for k in kayitlar if satir in k["turler"]]


def karar_ogeleri(kayitlar: list[dict[str, Any]], tekil: bool,
                  yalniz_ana: bool = False) -> list[dict[str, Any]]:
    """Kesinliğe giren öğeler (ön kayıt §6-§7): parça dışındaki bütün çapalar.

    Ana satırda tam eşitlik, klon satırında taban eşitliği doğrudur; GT'de karşılığı olmayan
    (eşlenemeyen) çapa yanlıştır: ürün hepsine ad yazar. ``yalniz_ana``: yalnız ana satır (eski
    tanım; duyarlılık satırı). Tekilde aynı ad bir öğedir ve bütün örnekleri doğruysa doğrudur.
    """
    secilen = [k for k in kayitlar
               if k["rol"] != "parca" and (k["satir"] == SATIR_ANA or not yalniz_ana)]
    if not tekil:
        return [{"ornek": 1, "dogru": k["durum"] == DURUM_DOGRU, "proje": bool(k["proje"])}
                for k in secilen]
    gruplar: dict[str, list[dict[str, Any]]] = {}
    for k in secilen:
        gruplar.setdefault(k["ad"], []).append(k)
    return [{"ornek": len(g), "dogru": all(x["durum"] == DURUM_DOGRU for x in g),
             "proje": all(bool(x["proje"]) for x in g)} for _, g in sorted(gruplar.items())]


def kesinlik_ozeti(kayitlar: list[dict[str, Any]], tekil: bool = True,
                   yalniz_ana: bool = False) -> dict[str, Any]:
    ogeler = karar_ogeleri(kayitlar, tekil, yalniz_ana)
    n = len(ogeler)
    return {"n": n, "kesinlik": oran(sum(1 for o in ogeler if o["dogru"]), n),
            "proje_normallestirmesi": oran(sum(1 for o in ogeler if o["proje"]), n)}


def ayri_satirlar(kayitlar: list[dict[str, Any]]) -> dict[str, Any]:
    """Döküm: klon satırı ve eşlenemeyenler (kesinliğe girer), parça çapaları (girmez)."""
    def say_(ks: list[dict[str, Any]]) -> dict[str, Any]:
        return {"n": len(ks), "dogru": sum(1 for k in ks if k["durum"] == DURUM_DOGRU)}
    return {"klon": say_([k for k in kayitlar if k["rol"] != "parca" and k["satir"] == SATIR_KLON]),
            "parca": say_([k for k in kayitlar if k["rol"] == "parca" and k["satir"] != SATIR_ESLENEMEDI]),
            "eslenemedi": {"n": sum(1 for k in kayitlar
                                    if k["rol"] != "parca" and k["satir"] == SATIR_ESLENEMEDI)}}


def kapsam_ozeti(kayitlar: list[dict[str, Any]], nufus: int, alan: str = "nufusta") -> dict[str, Any]:
    """Kapsam = nüfusta çapalanan / nüfus; tam ad kapsamı = nüfusta doğru çapa / nüfus.

    ``alan``: çapanın paydaya ait olduğunu gösteren kayıt alanı. Dizgi türlerinde ``nufusta`` (ad
    bekleyen nüfus); export satırında ``export_gt`` (dışa aktarılan GT fonksiyonları; bunlar ad
    bekleyen nüfusa girmez).
    """
    nf = [k for k in kayitlar if k["rol"] != "parca" and k[alan]]
    return {"nufus": nufus, "kapsam": oran(len(nf), nufus),
            "dogru_kapsam": oran(sum(1 for k in nf if k["durum"] == DURUM_DOGRU), nufus)}


def birim_programi(birim: str) -> str:
    """``platform/program`` → program. Aynı kaynak programın platform birimleri tek programdır."""
    return birim.split("/", 1)[1]


def _kesir(ozet: dict[str, Any]) -> Fraction:
    return Fraction(ozet["kesinlik"]["k"], ozet["kesinlik"]["n"])


def makro(birim_ozetleri: dict[str, dict[str, Any]], n_min: int = N_MIN,
          en_az_program: int = EN_AZ_PROGRAM, esik: float = KESINLIK_ESIGI) -> dict[str, Any]:
    """Satır kararı (ön kayıt §8). ``birim_ozetleri``: birim → {tekil, ornek_duzeyi} özetleri.

    1. Giren birim: tekil n ≥ ``n_min``.
    2. Görünüm başına (tekil, örnek düzeyi): aynı kaynak programın giren platform birimlerinin
       kesinliği ortalanır, sonra programlar eşit ağırlıkla ortalanır (makro).
    3. ``yetersiz``: giren farklı program sayısı < ``en_az_program``.
    4. ``kesin``: iki görünümün makrosu da ≥ eşik (karar makrosu = küçüğü) ve hiçbir görünümde
       giren bir birimin Wilson üst sınırı eşiğin altında değil; yoksa ``kesin_degil``.

    Eşik karşılaştırması kesirlerle yapılır (yuvarlama yok); Wilson sınırı ``macho_f1``'in
    yuvarladığı değerdir.
    """
    sinir = Fraction(str(esik))
    giren = sorted(b for b, o in birim_ozetleri.items() if o["tekil"]["n"] >= n_min)
    kucuk = sorted(b for b, o in birim_ozetleri.items() if 0 < o["tekil"]["n"] < n_min)
    programlar: dict[str, list[str]] = {}
    for b in giren:
        programlar.setdefault(birim_programi(b), []).append(b)
    gorunumler: dict[str, Any] = {}
    tam: list[Fraction] = []
    for g in GORUNUMLER:
        prog = {p: sum(_kesir(birim_ozetleri[b][g]) for b in bs) / len(bs)
                for p, bs in sorted(programlar.items())}
        ort = sum(prog.values()) / len(prog) if prog else None
        if ort is not None:
            tam.append(ort)
        ihlal = sorted(b for b in giren if birim_ozetleri[b][g]["kesinlik"]["aralik"][1] < esik)
        gorunumler[g] = {"makro_kesinlik": None if ort is None else round(float(ort), ONDALIK),
                         "program_kesinligi": {p: round(float(v), ONDALIK) for p, v in prog.items()},
                         "wilson_ihlali": ihlal}
    karar_makrosu = min(tam) if tam else None
    if len(programlar) < en_az_program:
        karar = "yetersiz"
    elif karar_makrosu >= sinir and not any(gorunumler[g]["wilson_ihlali"] for g in GORUNUMLER):
        karar = "kesin"
    else:
        karar = "kesin_degil"
    return {"giren_birimler": giren, "giren_programlar": sorted(programlar), "kucuk_birimler": kucuk,
            "gorunumler": gorunumler,
            "karar_makrosu": None if karar_makrosu is None else round(float(karar_makrosu), ONDALIK),
            "karar": karar, "esik": esik, "n_min": n_min, "en_az_program": en_az_program,
            "havuz": havuz(birim_ozetleri, "tekil"), "havuz_ornek": havuz(birim_ozetleri, "ornek_duzeyi")}


def havuz(birim_ozetleri: dict[str, dict[str, Any]], gorunum_: str) -> dict[str, Any]:
    """Bütün birimlerin (küçükler dahil) havuzlanmış kesinliği; kararı değiştirmez."""
    return oran(sum(o[gorunum_]["kesinlik"]["k"] for o in birim_ozetleri.values()),
                sum(o[gorunum_]["n"] for o in birim_ozetleri.values()))


def gt_mac(e: Elf, mac_veri: Path) -> GtBirimi:
    import macho_measure as mm
    f1, mf = _f1(), _mf()
    yol = mm.gt_path(Path(mac_veri), e.program)
    belge = _json(yol)
    hedef = _json(e.kosu / "raw" / "target_info.json")
    if hedef.get("file_hash") != belge.get("stripped_sha256"):
        raise OnkosulHatasi(f"{e.program}: analiz edilen dosya GT'nin strip'li kopyası değil")
    adlar = mf.gt_from_json(belge)
    gfonk = f1.load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
    adsiz = {g["addr"] for g in gfonk
             if not g["is_thunk"] and f1.is_generic_name(g["name"], [g["addr"]])}
    nufus = {a for a, n in adlar.items() if a in adsiz and mf.fragment_class(n) == mf.CLASS_PROGRAM
             and not gt_klon_mu(n, PLATFORM_MAC)}
    return GtBirimi(adlar, nufus, set(), {"gt": str(yol), "gt_fonksiyon": len(adlar)})


def gt_elf(e: Elf, indir: Path) -> GtBirimi:
    f1 = _f1()
    hedef = _json(e.kosu / "raw" / "target_info.json")
    soyulmus = Path(hedef["path"])
    if f1.sha256_file(soyulmus) != hedef.get("file_hash"):
        raise OnkosulHatasi(f"{e.ad}: analiz edilen dosyanın sha256'sı değişmiş")
    bid = f1.read_elf_info(soyulmus)["build_id"]
    adaylar = sorted(Path(indir).glob(f"x_*-dbgsym_*/usr/lib/debug/.build-id/{bid[:2]}/{bid[2:]}.debug"))
    if len(adaylar) != 1:
        raise OnkosulHatasi(f"{e.ad}: build-id {bid} için {len(adaylar)} hata ayıklama dosyası")
    gt = f1.extract_gt(adaylar[0], soyulmus, corpus=e.program, binary=e.ad)
    gfonk = f1.load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
    ofset, kaynak = f1.derive_image_offset(gfonk, int(gt["entry"], 16), gt["elf_type"])
    if kaynak != OFSET_KAYNAGI:
        # Ghidra'da ``entry`` yoksa yardımcı varsayılan tabana düşer; adres eşlemesi kanıtsız kalır
        raise OnkosulHatasi(f"{e.ad}: ofset Ghidra entry'den türetilemedi (kaynak: {kaynak})")
    turler = f1.classify_detected(gfonk, gt["exec_sections"], ofset)
    adsiz = {g["addr"] - ofset for g in gfonk if not g["is_thunk"]
             and turler.get(g["addr"] - ofset) == "code"
             and f1.is_generic_name(g["name"], [g["addr"] - ofset, g["addr"]])}
    adlar: dict[int, list[str]] = {}
    nufus: set[int] = set()
    export_gt: set[int] = set()
    for fn in gt["functions"]:
        dosya = int(fn["addr"], 16)
        adlar[dosya + ofset] = list(fn["names"])
        if fn.get("exported"):
            export_gt.add(dosya + ofset)
        elif not fn["crt"] and dosya in adsiz and not gt_klon_mu(fn["names"], PLATFORM_DEBIAN):
            nufus.add(dosya + ofset)
    return GtBirimi(adlar, nufus, export_gt,
                    {"debug": str(adaylar[0]), "ofset": f"0x{ofset:x}", "ofset_kaynagi": kaynak,
                     "gt_fonksiyon": len(gt["functions"])})


def birim_ozeti(kayitlar: list[dict[str, Any]], nufus: int, export_gt: int,
                satirlar: Iterable[str] = BUTUN_SATIRLAR) -> dict[str, Any]:
    """Satır başına: iki karar görünümü, duyarlılık satırları, döküm ve kapsam.

    Duyarlılık (karar dışı): ``yalniz_ana`` eski tanımdır (klon ve eşlenemeyen dışarıda);
    ``tek_turlu`` yalnız bir türü taşıyan çapalardır (türün tek başına kesinliği).
    """
    out: dict[str, Any] = {}
    for t in satirlar:
        g = gorunum(kayitlar, t)
        out[t] = {"tekil": kesinlik_ozeti(g, tekil=True), "ornek_duzeyi": kesinlik_ozeti(g, tekil=False),
                  "duyarlilik": {
                      "yalniz_ana": kesinlik_ozeti(g, tekil=True, yalniz_ana=True),
                      "tek_turlu": kesinlik_ozeti([k for k in g if len(k["turler"]) == 1], tekil=True)},
                  "ayri": ayri_satirlar(g),
                  "kapsam": (kapsam_ozeti(g, export_gt, alan="export_gt") if t == "export"
                             else kapsam_ozeti(g, nufus))}
    return out


def nufus_denetle(elfler: list[Elf], beklenen: Optional[dict[str, int]] = BEKLENEN_ELF,
                  eksik_izinli: bool = False) -> dict[str, Any]:
    """Birim (platform/program) başına bulunan ELF sayısı beklenenle aynı ve hepsi bitmiş olmalı;
    değilse ölçüm durur. Beklenmeyen birim de sorundur. ``beklenen`` None ise sayı denetlenmez."""
    bulunan = Counter(birim_anahtari(e) for e in elfler)
    biten = Counter(birim_anahtari(e) for e in elfler if e.static is not None)
    sorun = []
    if beklenen is not None:
        for b in sorted(set(beklenen) | set(bulunan)):
            if bulunan.get(b, 0) != beklenen.get(b, 0):
                sorun.append(f"{b}: {bulunan.get(b, 0)} ELF bulundu, beklenen {beklenen.get(b, 0)}")
    bekleyen = sorted(f"{birim_anahtari(e)}/{e.ad}" for e in elfler if e.static is None)
    if bekleyen:
        sorun.append(f"{len(bekleyen)} ELF bitmemiş ya da hatalı: {bekleyen[:5]}")
    if sorun and not eksik_izinli:
        raise OnkosulHatasi("nüfus eksik: " + "; ".join(sorun))
    return {"bulunan": dict(sorted(bulunan.items())), "biten": dict(sorted(biten.items())),
            "beklenen": beklenen, "eksik_izinli": eksik_izinli, "sorunlar": sorun}


def ghidra_surumu(kosu: Path) -> Optional[str]:
    """Koşu raporundaki Ghidra sürümü; rapor yoksa ya da koşu sabitlenmiş sürümle yapılmadıysa None."""
    try:
        ortam = _json(Path(kosu) / "reports" / "report.json").get("environment") or {}
    except (OSError, ValueError):
        return None
    g = ortam.get("ghidra") or {}
    return g.get("version") if g.get("matches_pinned") is True and g.get("version") else None


def ghidra_denetle(elfler: list[Elf]) -> dict[str, Any]:
    """Biten bütün ELF'ler aynı, sabitlenmiş Ghidra sürümüyle analiz edilmiş olmalı; değilse durur."""
    surumler: Counter = Counter()
    sorunlu = []
    for e in elfler:
        if e.static is None:
            continue
        surum = ghidra_surumu(e.kosu)
        if surum is None:
            sorunlu.append(f"{birim_anahtari(e)}/{e.ad}")
        else:
            surumler[surum] += 1
    if sorunlu:
        raise OnkosulHatasi(f"Ghidra sürümü doğrulanamadı ({len(sorunlu)} ELF): {sorunlu[:5]}")
    if len(surumler) > 1:
        raise OnkosulHatasi(f"ELF'ler farklı Ghidra sürümleriyle analiz edilmiş: {dict(surumler)}")
    return {"surum": next(iter(surumler), None), "elf": sum(surumler.values())}


def olc(elfler: list[Elf], mac_veri: Optional[Path], indir: Optional[Path],
        denetle: bool = True, beklenen: Optional[dict[str, int]] = BEKLENEN_ELF,
        eksik_izinli: bool = False) -> dict[str, Any]:
    onkosul = onkosullari_denetle() if denetle else {"denetlenmedi": True}
    nufus_kunyesi = nufus_denetle(elfler, beklenen, eksik_izinli)
    ghidra = ghidra_denetle(elfler) if denetle else {"denetlenmedi": True}
    kesin = kesin_modulu(onkosul.get("sha256", {}).get(KESIN_REL))
    birimler: dict[str, dict[str, Any]] = {}
    bekleyen = []
    for e in elfler:
        if e.static is None:
            bekleyen.append(f"{birim_anahtari(e)}/{e.ad}")
            continue
        b = birimler.setdefault(birim_anahtari(e), {
            "kayitlar": [], "nufus": 0, "export_gt": 0, "elfler": {}, "cpp_disarida": []})
        fonk = _json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        if cpp_ikili_mi(fonk, e.platform):
            b["cpp_disarida"].append(e.ad)   # C++: tam eşitlik tanımsız; yalnız GT'siz sayım (§7)
            continue
        gt = gt_mac(e, mac_veri) if e.platform == PLATFORM_MAC else gt_elf(e, indir)
        r = kesin.extract_anchors(e.static)
        kayitlar = degerlendir_elf(r.anchors, gt, e.platform, kesin.STRING_TYPES)
        b["kayitlar"].extend(kayitlar)
        b["nufus"] += len(gt.nufus)
        b["export_gt"] += len(gt.export_gt)
        b["elfler"][e.ad] = {"capa": len(r.anchors), "nufus": len(gt.nufus), "kunye": gt.kunye}
    sonuc_birim = {k: {"turler": birim_ozeti(b["kayitlar"], b["nufus"], b["export_gt"]),
                       "nufus": b["nufus"], "export_gt": b["export_gt"],
                       "cpp_disarida": b["cpp_disarida"], "elfler": b["elfler"]}
                   for k, b in sorted(birimler.items())}
    kararlar = {t: makro({k: v["turler"][t] for k, v in sonuc_birim.items()})
                for t in KARAR_SATIRLARI}
    # karar dışı satırlar: yalnız havuz (birim ayrıntısı ``birimler`` altında)
    rapor = {t: {g: havuz({k: v["turler"][t] for k, v in sonuc_birim.items()}, g) for g in GORUNUMLER}
             for t in RAPOR_SATIRLARI}
    siniflar = {b: {k: v for k, v in t.items() if k != "elfler"}
                for b, t in sinif(elfler)["birimler"].items()}
    return {"sema": SEMA, "komut": "olc", "onkosul": onkosul,
            "arac": {"betik_sha256": sha256_dosya(OLC_YOLU), "kesin_sha256": sha256_dosya(KESIN_YOLU),
                     "git_head": _git("rev-parse", "HEAD").stdout.strip(),
                     "python": platform.python_version(), "ks1_surumu": kesin.KS1_VERSION,
                     "ghidra": ghidra},
            "secimler": {"n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM, "esik": KESINLIK_ESIGI,
                         "zenginlik_esigi": ZENGINLIK_ESIGI},
            "nufus": nufus_kunyesi, "birimler": sonuc_birim, "kararlar": kararlar,
            "rapor_satirlari": rapor, "sinif": siniflar, "bekleyen": sorted(bekleyen)}


# --------------------------------------------------------------------------------------------
# Markdown (say)


def say_markdown(s: dict[str, Any], turler: Iterable[str]) -> str:
    satirlar = ["| Birim | Tür | Yuva | Dizgi | K0 sonrası | K1 sonrası | K2 sonrası | Aday fonksiyon | "
                "K3 sonrası | K4 sonrası | Çapa (K5 sonrası) |",
                "|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, v in s["birimler"].items():
        for t in turler:
            c = v["sayac"]
            hucre = [str(c.get(f"{a}:{t}", 0)) for a in
                     ("1_yuva", "2_dizgi", "3_K0_sonrasi", "4_K1_sonrasi", "5_K2_sonrasi",
                      "6_aday_fonksiyon", "7_K3_sonrasi", "8_K4_sonrasi", "9_capa")]
            satirlar.append(f"| {b} | `{t}` | " + " | ".join(hucre) + " |")
    return "\n".join(satirlar) + "\n"


def yuzde(x: Optional[float]) -> str:
    return "—" if x is None else f"%{x * 100:.1f}".replace(".", ",")


def _aralik(o: dict[str, Any]) -> str:
    a = o.get("aralik")
    return "—" if not a else f"{yuzde(a[0])}-{yuzde(a[1])}"


def _k_n(o: dict[str, Any]) -> str:
    return f"{o['k']}/{o['n']}"


def olc_markdown(s: dict[str, Any]) -> str:
    """Ölçüm özeti: karar tablosu, rapor satırları, birim × satır kesinlik ve kapsam. Ad içermez."""
    sec = s["secimler"]
    satirlar = ["# KS-1 ölçümü (adım 2)", "",
                f"- Ön kayıt commit'i: `{s['onkosul'].get('onkayit_commit', '—')}`; "
                f"`kesin.py` sha256 `{s['arac']['kesin_sha256'][:16]}…`; "
                f"`ks1_olc.py` sha256 `{s['arac']['betik_sha256'][:16]}…`; "
                f"Ghidra `{s['arac']['ghidra'].get('surum', '—')}`.",
                f"- Nüfus: {sum(s['nufus']['biten'].values())} ELF bitti; sorunlar: "
                f"{'; '.join(s['nufus']['sorunlar']) or 'yok'}.",
                f"- Seçimler: N_MIN = {sec['n_min']}, en az {sec['en_az_program']} farklı program, "
                f"eşik {yuzde(sec['esik'])}; karar makrosu = tekil ve örnek düzeyi makrolarının küçüğü; "
                f"giren hiçbir birimin Wilson üst sınırı eşiğin altında olamaz.", "", "## Karar", "",
                "| Satır | Makro (tekil) | Makro (örnek) | Karar makrosu | Giren programlar | "
                "Giren birimler | Küçük birimler | Wilson ihlali | Havuz (tekil) | Karar |",
                "|---|---|---|---|---|---|---|---|---|---|"]
    for t, k in s["kararlar"].items():
        gt_, go = k["gorunumler"]["tekil"], k["gorunumler"]["ornek_duzeyi"]
        ihlal = sorted(set(gt_["wilson_ihlali"]) | set(go["wilson_ihlali"]))
        h = k["havuz"]
        satirlar.append(
            f"| `{t}` | {yuzde(gt_['makro_kesinlik'])} | {yuzde(go['makro_kesinlik'])} | "
            f"{yuzde(k['karar_makrosu'])} | {', '.join(k['giren_programlar']) or '—'} | "
            f"{', '.join(k['giren_birimler']) or '—'} | {', '.join(k['kucuk_birimler']) or '—'} | "
            f"{', '.join(ihlal) or '—'} | {_k_n(h)} ({_aralik(h)}) | `{k['karar']}` |")
    satirlar += ["", "## Yalnız raporlanan satırlar (karar yok)", "",
                 "| Satır | Havuz (tekil) | %95 aralık | Havuz (örnek) |", "|---|---|---|---|"]
    for t, r in s["rapor_satirlari"].items():
        satirlar.append(f"| `{t}` | {_k_n(r['tekil'])} ({yuzde(r['tekil']['oran'])}) | "
                        f"{_aralik(r['tekil'])} | {_k_n(r['ornek_duzeyi'])} "
                        f"({yuzde(r['ornek_duzeyi']['oran'])}) |")
    satirlar += ["", "## Birim başına", "",
                 "| Birim | Satır | n (tekil) | Kesinlik | %95 aralık | Örnek düzeyi | Yalnız ana | "
                 "Tek türlü | Proje norm. | Klon (doğru/n) | Eşlenemeyen | Parça (doğru/n) | Kapsam | "
                 "Tam ad kapsamı |",
                 "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, v in s["birimler"].items():
        for t, o in v["turler"].items():
            tk, ok, ay, kp, du = o["tekil"], o["ornek_duzeyi"], o["ayri"], o["kapsam"], o["duyarlilik"]
            if not (tk["n"] or ay["parca"]["n"]):
                continue
            satirlar.append(
                f"| {b} | `{t}` | {tk['n']} | {yuzde(tk['kesinlik']['oran'])} | {_aralik(tk['kesinlik'])} | "
                f"{_k_n(ok['kesinlik'])} | {_k_n(du['yalniz_ana']['kesinlik'])} | "
                f"{_k_n(du['tek_turlu']['kesinlik'])} | {_k_n(tk['proje_normallestirmesi'])} | "
                f"{ay['klon']['dogru']}/{ay['klon']['n']} | {ay['eslenemedi']['n']} | "
                f"{ay['parca']['dogru']}/{ay['parca']['n']} | {yuzde(kp['kapsam']['oran'])} "
                f"({kp['kapsam']['k']}/{kp['nufus']}) | {yuzde(kp['dogru_kapsam']['oran'])} |")
    satirlar += ["", "## Program sınıfı (eş değişken, GT'siz)", "",
                 "| Birim | Dizgi zenginliği | Zenginlik sınıfı | Boyut tabakası |", "|---|---|---|---|"]
    for b, t in s["sinif"].items():
        z = t["dizgi_zenginligi"]
        satirlar.append(f"| {b} | {'—' if z is None else f'{z:.3f}'.replace('.', ',')} | "
                        f"`{t['zenginlik_sinifi']}` | `{t['boyut_tabakasi']}` |")
    if any(v["cpp_disarida"] for v in s["birimler"].values()):
        cpp = [f"{b}: {', '.join(v['cpp_disarida'])}" for b, v in s["birimler"].items() if v["cpp_disarida"]]
        satirlar += ["", "C++ (kesinlik dışı): " + ", ".join(cpp) + "."]
    return "\n".join(satirlar) + "\n"


# --------------------------------------------------------------------------------------------
# CLI


def _ortak(p: argparse.ArgumentParser) -> None:
    p.add_argument("--mac-kosu", type=Path, default=None)
    p.add_argument("--debian-kosu", type=Path, default=None)
    p.add_argument("--static", type=Path, action="append", default=[])
    p.add_argument("--json", type=Path, required=True)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    s = sub.add_parser("say", help="GT'siz sayım (koruma hunisi)")
    _ortak(s)
    s.add_argument("--md", type=Path, default=None)
    c = sub.add_parser("sinif", help="program sınıfı eş değişkeni (GT'siz)")
    _ortak(c)
    o = sub.add_parser("olc", help="çapa ↔ GT (ön kayıt commit'inden sonra)")
    _ortak(o)
    o.add_argument("--mac-veri", type=Path, default=REPO / "workspaces" / "olcum_mac")
    o.add_argument("--debian-indir", type=Path,
                   default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    o.add_argument("--md", type=Path, default=None)
    o.add_argument("--eksik-izinli", action="store_true",
                   help="bitmemiş ya da eksik ELF varken de ölç (eksikler çıktıda listelenir)")
    sub.add_parser("sabitle", help="ks1_sabitler.json'u bugünkü sha256'larla yaz")
    a = ap.parse_args(argv)
    if a.komut == "sabitle":
        belge = sabitle()
        for rel, h in belge["dosyalar"].items():
            print(f"{h}  {rel}")
        return 0
    elfler = elfleri_topla(a.mac_kosu, a.debian_kosu, a.static)
    if a.komut == "say":
        sonuc = say(elfler)
    elif a.komut == "sinif":
        sonuc = sinif(elfler)
    else:
        try:
            sonuc = olc(elfler, a.mac_veri, a.debian_indir, eksik_izinli=a.eksik_izinli)
        except OnkosulHatasi as hata:
            print(f"DURDU: {hata}", file=sys.stderr)
            return 2
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1, default=str) + "\n",
                      encoding="utf-8")
    if a.komut == "say" and a.md:
        a.md.write_text(say_markdown(sonuc, ("assert", "func_kalibi", "func_aktarma")), encoding="utf-8")
    if a.komut == "olc" and a.md:
        a.md.write_text(olc_markdown(sonuc), encoding="utf-8")
    print(f"{a.komut}: {len(sonuc.get('birimler', {}))} birim, bekleyen {len(sonuc.get('bekleyen', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
