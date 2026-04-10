#!/usr/bin/env python3
"""
Karadul Signature DB - MSYS2/MinGW PE DLL Export Extractor
============================================================
MSYS2 mirror'dan MinGW64 paketlerini indirir, .pkg.tar.zst acarak
icindeki .dll dosyalarindan PE export table sembollerini cikarir.

Cikti: sigs/msys2_mingw_exports.json
"""

import io
import json
import os
import re
import struct
import sys
import tempfile
import time
from datetime import datetime
from html.parser import HTMLParser

import requests

# --- Lazy imports (pip install if missing) ---
try:
    import pefile
except ImportError:
    print("[!] pefile not found, installing...")
    os.system(f"{sys.executable} -m pip install pefile -q")
    import pefile

try:
    import zstandard
except ImportError:
    print("[!] zstandard not found, installing...")
    os.system(f"{sys.executable} -m pip install zstandard -q")
    import zstandard

try:
    import tarfile
except ImportError:
    pass  # tarfile is stdlib

# ============================================================
# Config
# ============================================================

MIRROR_BASE = "https://mirror.msys2.org/mingw/mingw64/"
SIGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigs")
OUTPUT_PATH = os.path.join(SIGS_DIR, "msys2_mingw_exports.json")
TMP_DIR = tempfile.mkdtemp(prefix="msys2_sigs_")

# Hedef paketler: (paket_adi, lib_adi)
# Paket adi MSYS2'deki isim, lib_adi bizim DB'de gorunecek isim
TARGET_PACKAGES = [
    ("mingw-w64-x86_64-gcc-libs", "gcc_runtime"),
    ("mingw-w64-x86_64-openssl", "openssl"),
    ("mingw-w64-x86_64-zlib", "zlib"),
    ("mingw-w64-x86_64-qt5-base", "qt5"),
    ("mingw-w64-x86_64-boost", "boost"),
    ("mingw-w64-x86_64-curl", "curl"),
    ("mingw-w64-x86_64-sqlite3", "sqlite3"),
    ("mingw-w64-x86_64-ffmpeg", "ffmpeg"),
    ("mingw-w64-x86_64-opencv", "opencv"),
    ("mingw-w64-x86_64-python", "python"),
    ("mingw-w64-x86_64-gtk3", "gtk3"),
    ("mingw-w64-x86_64-glib2", "glib2"),
    ("mingw-w64-x86_64-cairo", "cairo"),
    ("mingw-w64-x86_64-pango", "pango"),
    ("mingw-w64-x86_64-freetype", "freetype"),
    ("mingw-w64-x86_64-harfbuzz", "harfbuzz"),
    ("mingw-w64-x86_64-libpng", "libpng"),
    ("mingw-w64-x86_64-libjpeg-turbo", "libjpeg"),
    ("mingw-w64-x86_64-libtiff", "libtiff"),
    ("mingw-w64-x86_64-libxml2", "libxml2"),
    ("mingw-w64-x86_64-SDL2", "sdl2"),
    ("mingw-w64-x86_64-gettext-runtime", "gettext"),
    ("mingw-w64-x86_64-gdk-pixbuf2", "gdk_pixbuf"),
    ("mingw-w64-x86_64-atk", "atk"),
    ("mingw-w64-x86_64-jasper", "jasper"),
    ("mingw-w64-x86_64-openblas", "openblas"),
    ("mingw-w64-x86_64-fftw", "fftw"),
    ("mingw-w64-x86_64-lz4", "lz4"),
    ("mingw-w64-x86_64-xz", "xz"),
    ("mingw-w64-x86_64-bzip2", "bzip2"),
]

# .dll ismine gore ozel lib mapping (DLL adi -> kaynagi)
DLL_LIB_OVERRIDES = {
    "libgcc_s_seh-1.dll": "gcc_runtime",
    "libstdc++-6.dll": "gcc_runtime",
    "libwinpthread-1.dll": "gcc_runtime",
    "libgomp-1.dll": "gcc_runtime",
    "libatomic-1.dll": "gcc_runtime",
    "libquadmath-0.dll": "gcc_runtime",
    "libssp-0.dll": "gcc_runtime",
}

# Skip patterns: compiler internal, import thunks, entry points
# NOT: Tek "_" ile baslayan C sembolleri (orn _TIFFClose) GECERLI
# C++ mangled "_Z..." sembolleri de GECERLI (demangle edilebilir)
SKIP_PATTERNS = [
    re.compile(r"^DllMain"),                  # Entry point
    re.compile(r"^__imp_"),                   # Import thunks
    re.compile(r"^__IMPORT_DESCRIPTOR"),       # PE import descriptor
    re.compile(r"^__NULL_IMPORT_DESCRIPTOR"),  # PE null import
    re.compile(r"^\?\?_"),                    # MSVC mangled destructors (cok generic)
    re.compile(r"^__head_"),                  # MinGW internal head symbols
    re.compile(r"^__lib\d"),                  # MinGW internal lib markers
    re.compile(r"^___"),                      # Triple underscore (compiler internal)
]

# Minimum sembol uzunlugu
MIN_SYMBOL_LEN = 3


# ============================================================
# HTML Index Parser
# ============================================================

class PkgListParser(HTMLParser):
    """MSYS2 mirror HTML index sayfasindan .pkg.tar.zst dosya isimlerini cikarir."""

    def __init__(self):
        super().__init__()
        self.packages = []  # (filename, size_str)
        self._in_a = False
        self._current_href = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, val in attrs:
                if name == "href" and val.endswith(".pkg.tar.zst"):
                    self.packages.append(val)


def fetch_package_index():
    """Mirror'dan paket listesini indir ve parse et."""
    print(f"[*] Fetching package index from {MIRROR_BASE}")
    resp = requests.get(MIRROR_BASE, timeout=60)
    resp.raise_for_status()

    parser = PkgListParser()
    parser.feed(resp.text)
    print(f"    Found {len(parser.packages)} total package files")
    return parser.packages


def find_latest_version(all_packages, pkg_name):
    """
    Verilen paket adinin en son versiyonunu bul.
    MSYS2 isimlendirmesi: mingw-w64-x86_64-openssl-3.2.1-1-any.pkg.tar.zst
    Paket adi: mingw-w64-x86_64-openssl
    Versiyon: 3.2.1-1
    Arch: any

    Ayni paketin birden fazla versiyonu olabilir.
    En son versiyonu (listede en altta olan) aliyoruz.
    """
    # pkg_name + "-" ile baslayan dosyalari bul
    prefix = pkg_name + "-"
    candidates = []

    for fname in all_packages:
        if not fname.startswith(prefix):
            continue
        # pkg_name'den sonraki kisimda versiyon olmali
        rest = fname[len(prefix):]
        # rest: "3.2.1-1-any.pkg.tar.zst"
        # Versiyon genelde rakamla baslar, ama bazen harfle de baslayabilir
        # Onemli olan: baska bir paketle karismasin
        # Ornegin: mingw-w64-x86_64-gtk3-3.24.0-1 vs mingw-w64-x86_64-gtk3-print-backends-...
        # rest'in "-any.pkg.tar.zst" ile bitmesini kontrol et
        if "-any.pkg.tar.zst" in rest:
            # versiyon kismi: rest'ten "-any.pkg.tar.zst" cikar
            ver_part = rest.replace("-any.pkg.tar.zst", "")
            # Versiyon MUTLAKA rakamla baslamali.
            # Bu sayede mingw-w64-x86_64-python-urllib3 gibi
            # alt paketler mingw-w64-x86_64-python ile karismaz.
            # (urllib3 rakamla baslamaz, 3.12.0 baslar)
            if ver_part and ver_part[0].isdigit():
                candidates.append(fname)

    if not candidates:
        return None

    # Listedeki son eleman genelde en yeni versiyon (mirror'da sirali)
    return candidates[-1]


# ============================================================
# Package Download + Extract
# ============================================================

def download_package(filename):
    """Paketi indir, /tmp'ye kaydet, path dondur."""
    url = MIRROR_BASE + filename
    local_path = os.path.join(TMP_DIR, filename)

    if os.path.exists(local_path):
        print(f"    [CACHE] {filename}")
        return local_path

    print(f"    [DL] {filename} ...", end="", flush=True)
    t0 = time.time()
    resp = requests.get(url, timeout=120, stream=True)
    resp.raise_for_status()

    total = 0
    with open(local_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            total += len(chunk)

    elapsed = time.time() - t0
    size_mb = total / (1024 * 1024)
    print(f" {size_mb:.1f} MB in {elapsed:.1f}s")
    return local_path


def extract_dlls_from_package(pkg_path):
    """
    .pkg.tar.zst arsivinden .dll dosyalarini cikar.
    Dosyalari temp dizine cikarir, path listesi dondurur.
    """
    dlls = []
    extract_dir = os.path.join(TMP_DIR, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        dctx = zstandard.ZstdDecompressor()
        with open(pkg_path, "rb") as f:
            reader = dctx.stream_reader(f)
            # tarfile streaming mode ile ac
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    if member.isfile() and member.name.lower().endswith(".dll"):
                        # Dosyayi extract et
                        try:
                            fobj = tar.extractfile(member)
                            if fobj is None:
                                continue
                            data = fobj.read()
                            # Gecici dosyaya kaydet
                            dll_name = os.path.basename(member.name)
                            out_path = os.path.join(extract_dir, dll_name)
                            # Ayni isimde DLL varsa (farkli paketlerden) numara ekle
                            if os.path.exists(out_path):
                                base, ext = os.path.splitext(dll_name)
                                i = 1
                                while os.path.exists(out_path):
                                    out_path = os.path.join(extract_dir, f"{base}_{i}{ext}")
                                    i += 1
                            with open(out_path, "wb") as wf:
                                wf.write(data)
                            dlls.append((out_path, member.name, dll_name))
                        except Exception as e:
                            print(f"      [WARN] Extract failed for {member.name}: {e}")
    except Exception as e:
        print(f"    [ERR] Failed to open archive: {e}")

    return dlls


# ============================================================
# PE Export Extraction
# ============================================================

def extract_pe_exports(dll_path):
    """
    PE dosyasinin export table'indan named export'lari cikarir.
    Ordinal-only export'lari atlar.
    """
    exports = []
    try:
        pe = pefile.PE(dll_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("utf-8", errors="replace")
                    exports.append(name)

        pe.close()
    except pefile.PEFormatError:
        pass  # PE degil, atla
    except Exception as e:
        print(f"      [WARN] PE parse error: {os.path.basename(dll_path)}: {e}")

    return exports


def should_skip_symbol(name):
    """Filtrelenecek sembolleri kontrol et."""
    if len(name) < MIN_SYMBOL_LEN:
        return True
    for pattern in SKIP_PATTERNS:
        if pattern.match(name):
            return True
    return False


def infer_lib_from_dll_name(dll_name, pkg_lib_name):
    """
    DLL dosya adindan daha spesifik bir lib adi cikar.
    Ornegin: libavcodec-61.dll -> ffmpeg/avcodec
             libssl-3-x64.dll -> openssl/ssl
    """
    # Oncelikle override'lara bak
    if dll_name in DLL_LIB_OVERRIDES:
        return DLL_LIB_OVERRIDES[dll_name]

    # lib prefix ve versiyon suffix'lerini temizle
    base = dll_name
    # .dll uzantisini cikar
    if base.lower().endswith(".dll"):
        base = base[:-4]

    # lib prefix cikar
    if base.startswith("lib"):
        base = base[3:]

    # Versiyon numaralarini cikar: "-61", "-3-x64" gibi
    # Basit yaklasim: son "-sayi" veya "-sayi-arch" kaliplarini temizle
    base = re.sub(r"-\d+(-x64|-x86)?$", "", base)
    base = re.sub(r"-\d+\.\d+(\.\d+)*$", "", base)

    if base:
        return f"{pkg_lib_name}/{base}"
    return pkg_lib_name


# ============================================================
# Main Processing
# ============================================================

def load_existing_signatures():
    """Mevcut tum signature DB'lerini yukle (dedup icin)."""
    existing = set()
    for fname in os.listdir(SIGS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(SIGS_DIR, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            if "signatures" in data:
                existing.update(data["signatures"].keys())
        except Exception:
            pass
    return existing


def process_package(pkg_name, lib_name, all_packages):
    """
    Tek bir paketi isle:
    1. En son versiyonu bul
    2. Indir
    3. DLL'leri cikar
    4. PE export'lari oku
    """
    latest = find_latest_version(all_packages, pkg_name)
    if not latest:
        print(f"  [SKIP] {pkg_name}: not found in index")
        return {}

    print(f"\n[*] Processing: {pkg_name}")
    print(f"    Latest: {latest}")

    # Indir
    try:
        pkg_path = download_package(latest)
    except Exception as e:
        print(f"    [ERR] Download failed: {e}")
        return {}

    # DLL'leri cikar
    dlls = extract_dlls_from_package(pkg_path)
    print(f"    Found {len(dlls)} DLL(s)")

    # Her DLL'den export'lari al
    sigs = {}
    for dll_path, member_path, dll_name in dlls:
        exports = extract_pe_exports(dll_path)
        effective_lib = infer_lib_from_dll_name(dll_name, lib_name)

        valid_count = 0
        for sym in exports:
            if should_skip_symbol(sym):
                continue
            # Anahtar olarak sembol adini kullan
            if sym not in sigs:
                sigs[sym] = {
                    "lib": effective_lib,
                    "dll": dll_name,
                    "purpose": "",
                    "category": "mingw_dll"
                }
                valid_count += 1

        if exports:
            print(f"      {dll_name}: {len(exports)} exports, {valid_count} valid")

        # DLL dosyasini temizle (disk tasarrufu)
        try:
            os.remove(dll_path)
        except OSError:
            pass

    # Paket dosyasini temizle
    try:
        os.remove(pkg_path)
    except OSError:
        pass

    return sigs


def main():
    print("=" * 60)
    print("Karadul MSYS2/MinGW PE DLL Signature Extractor")
    print("=" * 60)
    print(f"Output: {OUTPUT_PATH}")
    print(f"Temp dir: {TMP_DIR}")
    print(f"Targets: {len(TARGET_PACKAGES)} packages")
    print()

    # Mevcut signature'lari yukle
    existing = load_existing_signatures()
    print(f"[*] Existing signatures in DB: {len(existing):,}")

    # Mirror index'i indir
    all_packages = fetch_package_index()

    # Her paketi isle
    all_sigs = {}
    pkg_stats = []

    for pkg_name, lib_name in TARGET_PACKAGES:
        sigs = process_package(pkg_name, lib_name, all_packages)
        count_before = len(all_sigs)
        all_sigs.update(sigs)
        count_after = len(all_sigs)
        added = count_after - count_before
        pkg_stats.append((pkg_name, len(sigs), added))

    # Dedup: mevcut DB'de olan sembolleri say
    net_new = 0
    for sym in all_sigs:
        if sym not in existing:
            net_new += 1
    already_known = len(all_sigs) - net_new

    # Sonuclari JSON'a yaz
    output = {
        "meta": {
            "generator": "karadul-sig-gen-msys2",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "msys2_mingw64_mirror",
            "packages_processed": len([s for s in pkg_stats if s[1] > 0]),
            "total_symbols": len(all_sigs),
            "net_new": net_new,
        },
        "signatures": all_sigs,
    }

    os.makedirs(SIGS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    # Temizlik
    try:
        import shutil
        shutil.rmtree(TMP_DIR, ignore_errors=True)
    except Exception:
        pass

    # Rapor
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"\n{'Package':<45} {'Found':>8} {'Added':>8}")
    print("-" * 65)
    for pkg_name, found, added in pkg_stats:
        short = pkg_name.replace("mingw-w64-x86_64-", "")
        print(f"  {short:<43} {found:>8,} {added:>8,}")
    print("-" * 65)
    print(f"  {'TOTAL':<43} {len(all_sigs):>8,}")
    print()
    print(f"  Total unique symbols:   {len(all_sigs):>10,}")
    print(f"  Already in DB:          {already_known:>10,}")
    print(f"  Net new signatures:     {net_new:>10,}")
    print(f"\n  Output: {OUTPUT_PATH}")
    print(f"  Size:   {os.path.getsize(OUTPUT_PATH) / 1024:.1f} KB")
    print()


if __name__ == "__main__":
    main()
