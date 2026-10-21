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
    Çapa ↔ GT (adım 2; ön kayıt commit'lenmeden koşmaz). Tür ve birim başına kesinlik ve Wilson %95
    aralığı, birimler arası makro ortalama, kapsam; klon ekli GT adları, parça çapaları ve
    eşlenemeyenler ayrı satırda. Koşu başında ön koşullar denetlenir:
      - ön kayıt dosyasını ekleyen commit HEAD'in atası;
      - ``kesin.py`` ve bu betiğin sha256'sı o commit'teki ``ks1_sabitler.json`` ile aynı.
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
# Ön kayıtla sabitlenen dosyalar (depo köküne göre)
SABIT_DOSYALAR = (
    "karadul/reconstruction/tarif/kesin.py",
    "scripts/measurement/ks1_olc.py",
    "tests/test_tarif_kesin.py",
    "tests/test_ks1_olc.py",
    "scripts/measurement/mutation_specs_ks1.json",
)

PLATFORM_MAC = "mac"
PLATFORM_DEBIAN = "debian"
BITTI = "BITTI"
ONDALIK = 6
# Nüfusun beklenen büyüklüğü (ön kayıt §7): ölçüm yalnız biten ELF'leri sayıp yarım koşuyu geçirmesin
BEKLENEN_ELF = {PLATFORM_MAC: 2, PLATFORM_DEBIAN: 117}

# ---- Ön kayıt seçimleri (ks1_onkayit.md §8-§9; [seçim] maddeleri, varsayılanlar) ----
N_MIN = 10              # makro ortalamaya girmek için birimdeki en az çapa
EN_AZ_BIRIM = 2         # bir türün karara girmesi için N_MIN'i geçen en az birim
KESINLIK_ESIGI = 0.95   # makro ortalama eşiği (plan v2.1 3.2)
# Program sınıfı: snake_case tanımlayıcı biçimli dizgi
SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
BOYUT_SINIRLARI = ((500, "kucuk"), (2000, "orta"))   # iç fonksiyon sayısı: <500, <2000, ≥2000
BOYUT_EN_BUYUK = "buyuk"

# Derleyici ekleri: GT adının bütün takma adları bunlardan birini taşıyorsa çapa "klon" satırına
# düşer (tür kesinliğine girmez). Taban ad, ekler soyularak bulunur.
KLON_EKI_RE = re.compile(r"\.(?:isra|constprop|part|cold|lto_priv|clone|llvm|__uniq)(?:\.\d+)*$")
DIS_PARCA_RE = re.compile(r"^_?OUTLINED_FUNCTION_\d+$")
# C++ ikili (GT adları mangled; tam eşitlik tanımsız): içe aktarılan adlardan biri mangled (``_Z``;
# Ghidra çoğunu açtığı için yetmez), C++ istisna kişiliği ya da C++ istisna ABI'si.
# ``__cxa_finalize`` / ``__cxa_atexit`` C ikililerinde de vardır, işaret değildir.
CPP_ISARETLERI = ("_Z", "__gxx_personality", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_throw",
                  "__cxa_rethrow")

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
    """Ön kayıt commit'i HEAD'in atası; kesin.py ve bu betik ön kayıttaki sha256'larla aynı."""
    commit = onkayit_commit(onkayit, kok)
    if not commit_atasi_mi(commit, kok):
        raise OnkosulHatasi(f"ön kayıt commit'i {commit} HEAD'in atası değil")
    belge = committeki_sabitler(commit, kok, sabitler)
    dosyalar = belge.get("dosyalar") or {}
    denetlenen = {}
    for rel in ("karadul/reconstruction/tarif/kesin.py", "scripts/measurement/ks1_olc.py"):
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


def cpp_ikili_mi(fonksiyonlar: list[dict[str, Any]]) -> bool:
    """İçe aktarılan (thunk/dış) adlardan biri C++ çalışma zamanına ait mi (GT'siz)."""
    return any(str(f.get("name") or "").startswith(CPP_ISARETLERI)
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


def elf_sinif_olcusu(static: Path) -> dict[str, Any]:
    fonk = _json(Path(static) / "ghidra_functions.json").get("functions", [])
    dizgi = _json(Path(static) / "ghidra_strings.json").get("strings", [])
    return {"ic_fonksiyon": ic_fonksiyon_sayisi(fonk), "snake_dizgi": snake_dizgi_sayisi(dizgi),
            "cpp": cpp_ikili_mi(fonk)}


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
        birimler.setdefault(birim_anahtari(e), []).append({"elf": e.ad, **elf_sinif_olcusu(e.static)})
    tablo = {b: {**birim_sinifi(o), "elfler": o} for b, o in sorted(birimler.items())}
    # zenginlik sınıfı: platform içinde ortancaya göre ([seçim], ön kayıt §9)
    platformlar = sorted({b.split("/")[0] for b in tablo})
    for p in platformlar:
        degerler = [t["dizgi_zenginligi"] for b, t in tablo.items()
                    if b.startswith(p + "/") and t["dizgi_zenginligi"] is not None]
        esik = _ortanca(degerler)
        for b, t in tablo.items():
            if b.startswith(p + "/"):
                z = t["dizgi_zenginligi"]
                t["zenginlik_esigi"] = esik
                t["zenginlik_sinifi"] = (None if z is None or esik is None
                                         else ("zengin" if z >= esik else "yoksul"))
    return {"sema": SEMA, "komut": "sinif", "birimler": tablo, "bekleyen": sorted(bekleyen),
            "tanim": {"snake_re": SNAKE_RE.pattern, "boyut_sinirlari": BOYUT_SINIRLARI,
                      "zenginlik_esigi": "platform içindeki birimlerin ortancası"}}


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
        b["cpp_elf"] += int(cpp_ikili_mi(fonk))
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
KARAR_SATIRLARI = ("assert", ASSERT_UST, "func_kalibi", "func_aktarma", "export", DIZGI_TURLERI)


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


def ana_ogeler(kayitlar: list[dict[str, Any]], tekil: bool) -> list[dict[str, Any]]:
    """Kesinliğe giren öğeler: parça değil, ana satır. Tekilde aynı ad bir öğedir ve bütün
    örnekleri doğruysa doğrudur ([seçim], ön kayıt §7)."""
    ana = [k for k in kayitlar if k["rol"] != "parca" and k["satir"] == SATIR_ANA]
    if not tekil:
        return [{"ornek": 1, "durum": k["durum"], "proje": k["proje"]} for k in ana]
    gruplar: dict[str, list[dict[str, Any]]] = {}
    for k in ana:
        gruplar.setdefault(k["ad"], []).append(k)
    return [{"ornek": len(g),
             "durum": DURUM_DOGRU if all(x["durum"] == DURUM_DOGRU for x in g) else DURUM_YANLIS,
             "proje": all(x["proje"] for x in g)} for _, g in sorted(gruplar.items())]


def kesinlik_ozeti(kayitlar: list[dict[str, Any]], tekil: bool = True) -> dict[str, Any]:
    ogeler = ana_ogeler(kayitlar, tekil)
    n = len(ogeler)
    return {"n": n, "kesinlik": oran(sum(1 for o in ogeler if o["durum"] == DURUM_DOGRU), n),
            "proje_normallestirmesi": oran(sum(1 for o in ogeler if o["proje"]), n)}


def ayri_satirlar(kayitlar: list[dict[str, Any]]) -> dict[str, Any]:
    """Kesinliğe girmeyenler: klon satırı, parça çapaları, eşlenemeyenler."""
    def say_(ks: list[dict[str, Any]]) -> dict[str, Any]:
        return {"n": len(ks), "dogru": sum(1 for k in ks if k["durum"] == DURUM_DOGRU)}
    return {"klon": say_([k for k in kayitlar if k["rol"] != "parca" and k["satir"] == SATIR_KLON]),
            "parca": say_([k for k in kayitlar if k["rol"] == "parca" and k["satir"] != SATIR_ESLENEMEDI]),
            "eslenemedi": {"n": sum(1 for k in kayitlar if k["satir"] == SATIR_ESLENEMEDI)}}


def kapsam_ozeti(kayitlar: list[dict[str, Any]], nufus: int) -> dict[str, Any]:
    """Kapsam = nüfusta çapalanan / nüfus; tam isim kapsamı = nüfusta doğru çapa / nüfus."""
    nf = [k for k in kayitlar if k["rol"] != "parca" and k["nufusta"]]
    return {"nufus": nufus, "kapsam": oran(len(nf), nufus),
            "dogru_kapsam": oran(sum(1 for k in nf if k["durum"] == DURUM_DOGRU), nufus)}


def makro(birim_ozetleri: dict[str, dict[str, Any]], n_min: int = N_MIN,
          en_az_birim: int = EN_AZ_BIRIM, esik: float = KESINLIK_ESIGI) -> dict[str, Any]:
    """Tür kararı (ön kayıt §8): n ≥ n_min birimlerin kesinlik ortalaması ≥ eşik; en az
    ``en_az_birim`` birim gerekir, yoksa ``yetersiz``."""
    giren = {b: o for b, o in sorted(birim_ozetleri.items()) if o["n"] >= n_min}
    kucuk = sorted(b for b, o in birim_ozetleri.items() if 0 < o["n"] < n_min)
    ortalama = (round(sum(o["kesinlik"]["oran"] for o in giren.values()) / len(giren), ONDALIK)
                if giren else None)
    if len(giren) < en_az_birim:
        karar = "yetersiz"
    else:
        karar = "kesin" if ortalama >= esik else "kesin_degil"
    havuz_n = sum(o["n"] for o in birim_ozetleri.values())
    havuz_k = sum(o["kesinlik"]["k"] for o in birim_ozetleri.values())
    return {"giren_birimler": sorted(giren), "kucuk_birimler": kucuk, "makro_kesinlik": ortalama,
            "karar": karar, "esik": esik, "n_min": n_min, "en_az_birim": en_az_birim,
            "havuz": oran(havuz_k, havuz_n)}


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
    nufus = {a for a, n in adlar.items() if a in adsiz and mf.fragment_class(n) == mf.CLASS_PROGRAM}
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
                satirlar: Iterable[str] = KARAR_SATIRLARI) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for t in satirlar:
        g = gorunum(kayitlar, t)
        out[t] = {"tekil": kesinlik_ozeti(g, tekil=True), "ornek_duzeyi": kesinlik_ozeti(g, tekil=False),
                  "ayri": ayri_satirlar(g),
                  "kapsam": kapsam_ozeti(g, export_gt if t == "export" else nufus)}
    return out


def nufus_denetle(elfler: list[Elf], beklenen: Optional[dict[str, int]] = BEKLENEN_ELF,
                  eksik_izinli: bool = False) -> dict[str, Any]:
    """Bulunan ELF sayısı beklenenle aynı ve hepsi bitmiş olmalı; değilse ölçüm durur."""
    bulunan = Counter(e.platform for e in elfler)
    biten = Counter(e.platform for e in elfler if e.static is not None)
    sorun = []
    for p, n in sorted((beklenen or {}).items()):
        if bulunan.get(p, 0) != n:
            sorun.append(f"{p}: {bulunan.get(p, 0)} ELF bulundu, beklenen {n}")
    bekleyen = sorted(f"{birim_anahtari(e)}/{e.ad}" for e in elfler if e.static is None)
    if bekleyen:
        sorun.append(f"{len(bekleyen)} ELF bitmemiş ya da hatalı: {bekleyen[:5]}")
    if sorun and not eksik_izinli:
        raise OnkosulHatasi("nüfus eksik: " + "; ".join(sorun))
    return {"bulunan": dict(sorted(bulunan.items())), "biten": dict(sorted(biten.items())),
            "beklenen": beklenen, "eksik_izinli": eksik_izinli, "sorunlar": sorun}


def olc(elfler: list[Elf], mac_veri: Optional[Path], indir: Optional[Path],
        denetle: bool = True, beklenen: Optional[dict[str, int]] = BEKLENEN_ELF,
        eksik_izinli: bool = False) -> dict[str, Any]:
    onkosul = onkosullari_denetle() if denetle else {"denetlenmedi": True}
    nufus_kunyesi = nufus_denetle(elfler, beklenen, eksik_izinli)
    kesin = kesin_modulu(onkosul.get("sha256", {}).get("karadul/reconstruction/tarif/kesin.py"))
    birimler: dict[str, dict[str, Any]] = {}
    bekleyen = []
    for e in elfler:
        if e.static is None:
            bekleyen.append(f"{birim_anahtari(e)}/{e.ad}")
            continue
        b = birimler.setdefault(birim_anahtari(e), {
            "kayitlar": [], "nufus": 0, "export_gt": 0, "elfler": {}, "cpp_disarida": []})
        fonk = _json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        if cpp_ikili_mi(fonk):
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
    kararlar = {t: makro({k: v["turler"][t]["tekil"] for k, v in sonuc_birim.items()})
                for t in KARAR_SATIRLARI}
    return {"sema": SEMA, "komut": "olc", "onkosul": onkosul,
            "arac": {"betik_sha256": sha256_dosya(OLC_YOLU), "kesin_sha256": sha256_dosya(KESIN_YOLU),
                     "git_head": _git("rev-parse", "HEAD").stdout.strip(),
                     "python": platform.python_version()},
            "secimler": {"n_min": N_MIN, "en_az_birim": EN_AZ_BIRIM, "esik": KESINLIK_ESIGI},
            "nufus": nufus_kunyesi, "birimler": sonuc_birim, "kararlar": kararlar,
            "bekleyen": sorted(bekleyen)}


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


def olc_markdown(s: dict[str, Any]) -> str:
    """Ölçüm özeti: karar tablosu, birim × satır kesinlik ve kapsam. Ad içermez."""
    satirlar = ["# KS-1 ölçümü (adım 2)", "",
                f"- Ön kayıt commit'i: `{s['onkosul'].get('onkayit_commit', '—')}`; "
                f"`kesin.py` sha256 `{s['arac']['kesin_sha256'][:16]}…`; "
                f"`ks1_olc.py` sha256 `{s['arac']['betik_sha256'][:16]}…`.",
                f"- Nüfus: {s['nufus']['biten']} / beklenen {s['nufus']['beklenen']}; sorunlar: "
                f"{'; '.join(s['nufus']['sorunlar']) or 'yok'}.",
                f"- Seçimler: N_MIN = {s['secimler']['n_min']}, en az {s['secimler']['en_az_birim']} birim, "
                f"eşik {yuzde(s['secimler']['esik'])}.", "", "## Karar", "",
                "| Satır | Makro kesinlik | Giren birimler | Küçük birimler | Havuz | Karar |",
                "|---|---|---|---|---|---|"]
    for t, k in s["kararlar"].items():
        h = k["havuz"]
        satirlar.append(f"| `{t}` | {yuzde(k['makro_kesinlik'])} | {', '.join(k['giren_birimler']) or '—'} | "
                        f"{', '.join(k['kucuk_birimler']) or '—'} | {h['k']}/{h['n']} ({_aralik(h)}) | "
                        f"`{k['karar']}` |")
    satirlar += ["", "## Birim başına", "",
                 "| Birim | Satır | n (tekil) | Kesinlik | %95 aralık | Örnek düzeyi | Proje norm. | "
                 "Klon (doğru/n) | Parça (doğru/n) | Eşlenemeyen | Kapsam | Tam ad kapsamı |",
                 "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for b, v in s["birimler"].items():
        for t, o in v["turler"].items():
            tk, ok, ay, kp = o["tekil"], o["ornek_duzeyi"], o["ayri"], o["kapsam"]
            if not (tk["n"] or ay["klon"]["n"] or ay["parca"]["n"] or ay["eslenemedi"]["n"]):
                continue
            satirlar.append(
                f"| {b} | `{t}` | {tk['n']} | {yuzde(tk['kesinlik']['oran'])} | {_aralik(tk['kesinlik'])} | "
                f"{ok['kesinlik']['k']}/{ok['n']} | {tk['proje_normallestirmesi']['k']}/{tk['n']} | "
                f"{ay['klon']['dogru']}/{ay['klon']['n']} | {ay['parca']['dogru']}/{ay['parca']['n']} | "
                f"{ay['eslenemedi']['n']} | {yuzde(kp['kapsam']['oran'])} "
                f"({kp['kapsam']['k']}/{kp['nufus']}) | {yuzde(kp['dogru_kapsam']['oran'])} |")
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
