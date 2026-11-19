#!/usr/bin/env python
"""ÖLÇEK kalem 1: makinedeki büyük kurulumların ÜST VERİ envanteri.

YALNIZ üst veri: yol, boyut, ``file`` türü, sha256. Dizgi dökme, sembol okuma, fat başlığı
ayrıştırma, içerik analizi YOK; hiçbir dosya çalıştırılmaz. Çalıştırma biti olan ya da ikili uzantılı
(``IKILI_UZANTILAR``) dosyaların ilk 4 baytı okunur (``file``'ın yaptığı sihirli sayı denetimi;
Karadul da ``TargetDetector._read_magic`` ile aynısını yapar). Aday dosyaya ``/usr/bin/file -b`` ve
sha256. Ön süzgeç ölçüsü: süzgeçsiz taranan LLVM ve Ollama.app'te kaçırılan Mach-O 0 / 215.

Karadul'un ``.app`` bileşen kuralı (``karadul/core/target.py:238-311``) aynı Python sürümünün
``pathlib`` davranışıyla taklit edilir (kod çağrılmaz; ürünün okuduğu dosyalardan fazlası okunmaz):
  1. ``Contents/MacOS/*`` içindeki Mach-O (ince ya da evrensel; Java sınıfı değil)
  2. ``Contents/Frameworks/**/*.framework`` → ``<fw>/<fw.stem>`` dosyası
  3. ``Contents/Resources/**/*.jar``
  4. ``Contents/Resources/**/*.dylib``
  5. Electron: ``Contents/Resources/app.asar`` ya da ``app/`` (+ package.json / main.js)

Üçüncü taraf bileşen payı YOL ADINDAN (``BILESEN_KALIPLARI``; doğrulanmamış sınıflama).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 nice -n 10 python scripts/arge/olcek/envanter.py \
        --cikti-dizin ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter [--yalniz AD …]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# (ad, kök yol, lisans sınıfı, not). Lisans sınıfı yalnız içerik analizine izin için: hepsinde
# yalnız üst veri okunur.
KURULUMLAR: list[tuple[str, str, str, str]] = [
    ("llvm-23.1.6", "/opt/homebrew/Cellar/llvm/23.1.6", "açık kaynak (Apache-2.0 WITH LLVM-exception)", "Homebrew şişesi"),
    ("KiCad", "/Applications/KiCad", "açık kaynak (GPL-3.0-or-later)", "4 .app + kitaplık"),
    ("FreeCAD", "/Applications/FreeCAD.app", "açık kaynak (LGPL-2.1-or-later)", ""),
    ("Blender", "/Applications/Blender.app", "açık kaynak (GPL-2.0-or-later)", ""),
    ("Ollama", "/Applications/Ollama.app", "açık kaynak (MIT)", "gösteri hedefinin paketi"),
    ("TeX Live", "/usr/local/texlive", "açık kaynak (karışık özgür lisanslar)", "çoğu çalıştırılabilir olmayan dosya"),
    ("Anaconda", "/opt/anaconda3", "karışık (çoğu açık kaynak paket)", "Python dağıtımı; ürünün kendi ortamı"),
    ("Docker", "/Applications/Docker.app", "kapalı", ""),
    ("ChatGPT", "/Applications/ChatGPT.app", "kapalı", ""),
    ("Microsoft Word", "/Applications/Microsoft Word.app", "kapalı", ""),
    ("Microsoft Excel", "/Applications/Microsoft Excel.app", "kapalı", "Word ile paylaşılan dosya sayımı için"),
    ("Google Chrome", "/Applications/Google Chrome.app", "kapalı", ""),
    ("Visual Studio Code", "/Applications/Visual Studio Code.app", "kapalı ikili (kaynak MIT)", "Electron"),
    ("Cursor", "/Applications/Cursor.app", "kapalı", "Electron"),
    ("LM Studio", "/Applications/LM Studio.app", "kapalı", "Electron"),
    ("FL Studio 2025", "/Applications/FL Studio 2025.app", "kapalı", ""),
    ("IBM SPSS Statistics", "/Applications/IBM SPSS Statistics", "kapalı", "Java"),
]

_MACHO = {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"}
_FAT = {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}
_ELF = b"\x7fELF"
_MZ = b"MZ"
_ZIP = b"PK\x03\x04"
IKILI_UZANTILAR = (".dylib", ".so", ".bundle", ".jar", ".asar", ".node", ".a", ".o", ".dll", ".exe",
                   ".kext", ".plugin", ".framework", ".pyd", ".kiface")

# Yol adından bileşen sınıfı (ilk eşleşen). Büyük/küçük harf duyarsız.
BILESEN_KALIPLARI: list[tuple[str, str]] = [
    ("Electron", r"electron framework\.framework|/electron helper|electron\.asar"),
    ("Chromium / CEF", r"chromium embedded framework|google chrome framework|chrome_crashpad_handler|"
                       r"/libegl\.dylib$|/libglesv2\.dylib$|libvk_swiftshader|/libffmpeg\.dylib$|"
                       r"crashpad_handler"),
    ("Qt", r"/qt[a-z0-9]*\.framework/|/libqt[56][a-z0-9]*[^/]*$|/qt/plugins/|/plugins/platforms/"),
    ("LLVM / Clang", r"/libllvm|/libclang|/liblld|/libmlir|/libpolly|/lldb"),
    ("Python çalışma zamanı", r"python\.framework/|/libpython|\.cpython-[0-9]+[^/]*\.so$|/site-packages/|"
                              r"/lib-dynload/"),
    ("Java çalışma zamanı", r"/jre/|/jdk[^/]*/|/jbr/|/libjvm\.dylib$|\.jar$"),
    ("Güncelleyici (Sparkle / Squirrel)", r"sparkle\.framework|squirrel\.framework|/autoupdate"),
    ("ReactiveObjC / Mantle", r"reactiveobjc\.framework|mantle\.framework"),
    ("FFmpeg", r"/libav(codec|format|util|filter|device)|/libsw(scale|resample)|/libpostproc"),
    ("Boost", r"/libboost_"),
    ("ICU", r"/libicu"),
    ("OpenSSL", r"/libssl[.-]|/libcrypto[.-]"),
    ("OpenCASCADE", r"/libtk[a-z0-9]+[.-]"),
    ("wxWidgets", r"/libwx_"),
    ("VTK", r"/libvtk"),
    ("BLAS / LAPACK / MKL", r"/libmkl|/libopenblas|/liblapack|/libblas|/libgfortran"),
    ("Swift çalışma zamanı", r"/libswift"),
    ("Node.js", r"/libnode\.|/bin/node$|/node$"),
    ("Microsoft Office paylaşılan", r"/microsoft[^/]*\.framework/|/mso[0-9a-z]*\.framework/|/office[^/]*\.framework/"),
    ("CUDA / Metal / ML", r"/libtorch|/libcudnn|/libggml|/libllama|/libmlx|/libonnx|/libtensorflow"),
]
_BILESEN_RE = [(ad, re.compile(k, re.I)) for ad, k in BILESEN_KALIPLARI]


def bilesen_sinifi(yol: str) -> str:
    for ad, rx in _BILESEN_RE:
        if rx.search(yol):
            return ad
    return "sınıflanmamış"


def sihir(p: str) -> bytes:
    try:
        with open(p, "rb") as fh:
            return fh.read(4)
    except OSError:
        return b""


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for parca in iter(lambda: fh.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def file_turleri(yollar: list[str]) -> list[str]:
    out: list[str] = []
    for i in range(0, len(yollar), 200):
        dilim = yollar[i:i + 200]
        r = subprocess.run(["/usr/bin/file", "-b", "--", *dilim], capture_output=True, text=True,
                           errors="replace")
        satirlar = r.stdout.splitlines()
        if len(satirlar) != len(dilim):  # güvenli yol: tek tek
            satirlar = [subprocess.run(["/usr/bin/file", "-b", "--", y], capture_output=True, text=True,
                                       errors="replace").stdout.strip() for y in dilim]
        out.extend(satirlar)
    return out


def tur_sinifi(ft: str) -> dict[str, Any]:
    """``file`` çıktısından sınıf, evrensel mi, mimari sayısı (yalnız ``file`` metni)."""
    s: dict[str, Any] = {"evrensel": ft.startswith("Mach-O universal binary"), "mimari_sayisi": 1,
                         "mimariler": []}
    if s["evrensel"]:
        m = re.search(r"with (\d+) architectures", ft)
        s["mimari_sayisi"] = int(m.group(1)) if m else None
        s["mimariler"] = re.findall(r"\[([a-z0-9_]+)(?::|\])", ft)
    low = ft.lower()
    if "mach-o" in low:
        if "dynamically linked shared library" in low:
            s["sinif"] = "Mach-O dylib"
        elif "bundle" in low and "kext" not in low:
            s["sinif"] = "Mach-O bundle"
        elif "executable" in low:
            s["sinif"] = "Mach-O çalıştırılabilir"
        elif "kext" in low:
            s["sinif"] = "Mach-O kext"
        elif "object" in low:
            s["sinif"] = "Mach-O nesne"
        elif "dsym" in low or "companion" in low:
            s["sinif"] = "Mach-O dSYM"
        else:
            s["sinif"] = "Mach-O öbür"
    elif low.startswith("elf"):
        s["sinif"] = "ELF"
    elif low.startswith("pe32") or "ms-dos" in low:
        s["sinif"] = "PE"
    elif "java" in low and "class" in low:
        s["sinif"] = "Java sınıfı"
    elif "zip" in low or "java archive" in low:
        s["sinif"] = "ZIP / JAR"
    else:
        s["sinif"] = "öbür"
    return s


def karadul_bilesenleri(app: Path) -> list[dict[str, Any]]:
    """``TargetDetector._detect_app_bundle``'ın bileşen kuralının taklidi (ürün kodu çağrılmaz)."""
    macos, res, fws = app / "Contents" / "MacOS", app / "Contents" / "Resources", app / "Contents" / "Frameworks"
    comps: list[dict[str, Any]] = []
    if macos.exists():
        for f in sorted(macos.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                m = sihir(str(f))
                if m in _MACHO or m in _FAT:  # Java sınıfı ayrımı aşağıda `file` türüyle
                    comps.append({"yol": str(f), "kural": "MacOS", "bayt": f.stat().st_size})
    if fws.exists():
        for fw in sorted(fws.rglob("*.framework")):
            b = fw / fw.stem
            if b.is_file():
                comps.append({"yol": str(b), "kural": "Frameworks/*.framework", "bayt": b.stat().st_size})
    if res.exists():
        for j in sorted(res.rglob("*.jar")):
            comps.append({"yol": str(j), "kural": "Resources/**/*.jar", "bayt": j.stat().st_size})
        for d in sorted(res.rglob("*.dylib")):
            comps.append({"yol": str(d), "kural": "Resources/**/*.dylib", "bayt": d.stat().st_size})
        asar, appd = res / "app.asar", res / "app"
        if asar.exists() or (appd.exists() and ((appd / "package.json").exists() or (appd / "main.js").exists())):
            e = asar if asar.exists() else appd
            comps.append({"yol": str(e), "kural": "Electron", "bayt": e.stat().st_size if e.is_file() else 0})
    return comps


def tara(ad: str, kok: Path, lisans: str, notu: str, cikti: Path) -> dict[str, Any]:
    t0 = time.monotonic()
    ozet: dict[str, Any] = {"ad": ad, "kok": str(kok), "lisans_sinifi": lisans, "not": notu}
    toplam = Counter()
    gorulen_inode: set[tuple[int, int]] = set()
    adaylar: list[tuple[str, int, int]] = []  # (yol, bayt, inode-tekil mi)
    uzanti = Counter()
    for dp, dn, fn in os.walk(kok, followlinks=False):
        for n in dn:
            if os.path.islink(os.path.join(dp, n)):
                toplam["bag_dizin"] += 1
        for n in fn:
            p = os.path.join(dp, n)
            try:
                st = os.lstat(p)
            except OSError:
                toplam["okunamayan"] += 1
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                toplam["bag_dosya" if os.path.islink(p) else "ozel"] += 1
                continue
            toplam["dosya"] += 1
            toplam["bayt"] += st.st_size
            key = (st.st_dev, st.st_ino)
            tekil = key not in gorulen_inode
            gorulen_inode.add(key)
            if tekil:
                toplam["bayt_inode_tekil"] += st.st_size
            ext = os.path.splitext(n)[1].lower()
            if ext in (".jar", ".asar", ".pyc", ".so", ".dylib", ".node", ".dll", ".exe", ".a"):
                uzanti[ext] += 1
            # Ön süzgeç: dosya açmak bu makinede pahalı (açılışta gerçek zamanlı virüs taraması;
            # 40 bin dosyalık kurulumda 29 dk). Yalnız çalıştırma biti olan ya da ikili uzantılı dosya
            # açılır. LLVM ve Ollama.app envanterinde (süzgeçsiz tarandı) kaçırılan Mach-O: 0 / 215.
            if not (st.st_mode & 0o111) and ext not in IKILI_UZANTILAR:
                toplam["on_suzgecte_acilmayan"] += 1
                continue
            m = sihir(p)
            if m in _MACHO or m in _FAT or m == _ELF or m[:2] == _MZ or ext in (".jar", ".asar"):
                adaylar.append((p, st.st_size, int(tekil)))
    turler = file_turleri([a[0] for a in adaylar])
    kayitlar = []
    for (p, b, tekil), ft in zip(adaylar, turler):
        s = tur_sinifi(ft)
        if s["sinif"] in ("öbür", "Java sınıfı") and not p.endswith((".jar", ".asar")):
            continue  # MZ / cafebabe ile başlayan ama çalıştırılabilir olmayan dosya
        try:
            h = sha256(p)
        except OSError:
            h = None
        kayitlar.append({"yol": p, "bayt": b, "inode_tekil": bool(tekil), "file": ft, **s,
                         "sha256": h, "bilesen": bilesen_sinifi(p),
                         "cerceve_ici": ".framework/" in p, "app_ici": ".app/" in p})
    # .app'ler (kökün kendisi ya da kökün hemen altındaki .app'ler) için Karadul bileşen kuralı
    apps = [kok] if kok.suffix == ".app" else sorted(x for x in kok.iterdir() if x.suffix == ".app")
    karadul = []
    for app in apps:
        comps = karadul_bilesenleri(app)
        tur_haritasi = {k["yol"]: k for k in kayitlar}
        for c in comps:
            k = tur_haritasi.get(c["yol"]) or tur_haritasi.get(os.path.realpath(c["yol"]))
            c["sha256"] = k["sha256"] if k else None
            c["sinif"] = k["sinif"] if k else None
            c["mimari_sayisi"] = k["mimari_sayisi"] if k else None
            c["bilesen"] = bilesen_sinifi(c["yol"])
        comp_yollar = {os.path.realpath(c["yol"]) for c in comps}
        app_macho = [k for k in kayitlar if k["yol"].startswith(str(app) + "/") and k["sinif"].startswith("Mach-O")]
        disarida = [k for k in app_macho if os.path.realpath(k["yol"]) not in comp_yollar]
        karadul.append({
            "app": str(app), "bilesen_sayisi": len(comps),
            "bilesen_bayt": sum(c["bayt"] for c in comps),
            "bilesen_tekil_sha": len({c["sha256"] for c in comps if c["sha256"]}),
            "bilesen_kural_sayilari": dict(Counter(c["kural"] for c in comps)),
            "bilesen_evrensel": sum(1 for c in comps if (c.get("mimari_sayisi") or 1) > 1),
            "en_buyuk_bilesen": max(comps, key=lambda c: c["bayt"])["yol"] if comps else None,
            "en_buyuk_bilesen_bayt": max((c["bayt"] for c in comps), default=0),
            "app_macho_sayisi": len(app_macho), "app_macho_bayt": sum(k["bayt"] for k in app_macho),
            "kapsam_disi_macho_sayisi": len(disarida),
            "kapsam_disi_macho_bayt": sum(k["bayt"] for k in disarida),
            "bilesenler": comps,
        })
    # özet
    macho = [k for k in kayitlar if k["sinif"].startswith("Mach-O")]
    sha_say = Counter(k["sha256"] for k in macho if k["sha256"])
    tekil_bayt = sum(b for b in {k["sha256"]: k["bayt"] for k in macho if k["sha256"]}.values())
    boyutlar = sorted(k["bayt"] for k in macho)

    def yuzdelik(q: float) -> int | None:
        return boyutlar[min(len(boyutlar) - 1, int(q * len(boyutlar)))] if boyutlar else None

    ozet.update({
        "dosya": toplam["dosya"], "bayt": toplam["bayt"], "bayt_inode_tekil": toplam["bayt_inode_tekil"],
        "bag_dosya": toplam["bag_dosya"], "bag_dizin": toplam["bag_dizin"],
        "on_suzgecte_acilmayan": toplam["on_suzgecte_acilmayan"],
        "uzantilar": dict(uzanti),
        "calistirilabilir_aday": len(kayitlar),
        "sinif_sayilari": dict(Counter(k["sinif"] for k in kayitlar)),
        "sinif_baytlari": {s: sum(k["bayt"] for k in kayitlar if k["sinif"] == s)
                           for s in sorted({k["sinif"] for k in kayitlar})},
        "macho": len(macho), "macho_bayt": sum(k["bayt"] for k in macho),
        "macho_evrensel": sum(1 for k in macho if k["evrensel"]),
        "macho_evrensel_bayt": sum(k["bayt"] for k in macho if k["evrensel"]),
        "macho_dilim_bayt_kestirimi_esit_bolme": round(sum(k["bayt"] / (k["mimari_sayisi"] or 1) for k in macho)),
        "macho_tekil_sha": len(sha_say), "macho_tekil_sha_bayt": tekil_bayt,
        "macho_yinelenen_kopya": sum(v - 1 for v in sha_say.values() if v > 1),
        "macho_boyut_yuzdelik": {"p50": yuzdelik(0.5), "p90": yuzdelik(0.9), "p99": yuzdelik(0.99),
                                 "en_buyuk": boyutlar[-1] if boyutlar else None},
        "macho_100mb_ustu": sum(1 for b in boyutlar if b >= 100 * 2**20),
        "macho_25mb_ustu": sum(1 for b in boyutlar if b >= 25 * 2**20),
        "macho_1mb_alti": sum(1 for b in boyutlar if b < 2**20),
        "bilesen_payi_bayt": {s: sum(k["bayt"] for k in macho if k["bilesen"] == s)
                              for s in sorted({k["bilesen"] for k in macho})},
        "bilesen_payi_sayi": dict(Counter(k["bilesen"] for k in macho)),
        "en_buyuk_10": [{"yol": k["yol"], "bayt": k["bayt"], "sinif": k["sinif"],
                         "mimari_sayisi": k["mimari_sayisi"], "bilesen": k["bilesen"]}
                        for k in sorted(macho, key=lambda k: -k["bayt"])[:10]],
        "karadul_app_bilesenleri": [{k: v for k, v in a.items() if k != "bilesenler"} for a in karadul],
        "sure_sn": round(time.monotonic() - t0, 1),
    })
    (cikti / f"{re.sub(r'[^A-Za-z0-9._-]', '_', ad)}.json").write_text(
        json.dumps({"ozet": ozet, "kayitlar": kayitlar, "karadul": karadul}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return ozet


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cikti-dizin", required=True, type=Path)
    ap.add_argument("--yalniz", nargs="*", default=None)
    a = ap.parse_args(argv)
    a.cikti_dizin.mkdir(parents=True, exist_ok=True)
    ozetler = []
    for ad, kok, lisans, notu in KURULUMLAR:
        if a.yalniz and ad not in a.yalniz:
            continue
        k = Path(kok)
        if not k.exists():
            print(f"YOK: {ad} {kok}", file=sys.stderr)
            continue
        o = tara(ad, k, lisans, notu, a.cikti_dizin)
        ozetler.append(o)
        print(f"{ad}: {o['dosya']} dosya, {o['bayt']/2**30:.2f} GiB, Mach-O {o['macho']} "
              f"({o['macho_bayt']/2**30:.2f} GiB), {o['sure_sn']} sn", file=sys.stderr, flush=True)
    (a.cikti_dizin / "ozet.json").write_text(json.dumps(ozetler, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
