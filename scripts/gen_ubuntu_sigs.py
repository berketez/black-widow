#!/usr/bin/env python3
"""
Ubuntu/Debian APT Repo'dan ELF Binary Signature Cikarma
========================================================
macOS'ta pure Python ile calisan:
  1. Ubuntu mirror'dan .deb paketlerini indirir
  2. .deb = ar archive -> data.tar.* icerigini cikarir
  3. .so dosyalarindan pyelftools ile .dynsym sembollerini okur
  4. JSON'a kaydeder

Docker/Linux VM gerektirmez.

Cikti: sigs/ubuntu_elf_signatures.json
"""

import hashlib
import gzip
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.common.exceptions import ELFError
except ImportError:
    print("[ERROR] pyelftools gerekli: pip install pyelftools")
    sys.exit(1)

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False
    print("[WARN] zstandard yok, pip install zstandard ile kur. zst sikistirmali .deb'ler atlanacak.")

# --- Konfigurasyon ---
PROJECT_ROOT = Path("/Users/apple/Desktop/black-widow")
OUTPUT_PATH = PROJECT_ROOT / "sigs" / "ubuntu_elf_signatures.json"
COMBINED_PATH = PROJECT_ROOT / "sigs" / "combined_1M.json"
TEMP_DIR = Path(tempfile.mkdtemp(prefix="karadul-ubuntu-"))

# Ubuntu 24.04 LTS (Noble Numbat) amd64
UBUNTU_MIRROR = "http://archive.ubuntu.com/ubuntu"
PACKAGES_URLS = [
    f"{UBUNTU_MIRROR}/dists/noble/main/binary-amd64/Packages.gz",
    f"{UBUNTU_MIRROR}/dists/noble/universe/binary-amd64/Packages.gz",
]
POOL_BASE = f"{UBUNTU_MIRROR}/"

# Indirilecek paketler -- en cok sembol iceren kutuphaneler
TARGET_PACKAGES = {
    # --- Temel C/C++ runtime ---
    "libc6",
    "libstdc++6",
    "libgcc-s1",
    # --- OpenSSL / Crypto ---
    "libssl3",
    "libssl3t64",
    "libgnutls30",
    "libgnutls30t64",
    "libgcrypt20",
    "libgcrypt20t64",
    # --- Python ---
    "libpython3.12",
    "libpython3.12t64",
    "libpython3.12-dev",
    # --- Qt5 (universe) ---
    "libqt5core5t64",
    "libqt5gui5t64",
    "libqt5widgets5t64",
    "libqt5network5t64",
    "libqt5dbus5t64",
    "libqt5sql5t64",
    "libqt5xml5t64",
    # Noble'daki gercek Qt5 isimleri
    "libqt5core5a",
    "libqt5gui5a",
    "libqt5widgets5a",
    "libqt5network5a",
    "libqt5dbus5a",
    "libqt5sql5a",
    "libqt5xml5a",
    # --- Qt6 (universe) ---
    "libqt6core6t64",
    "libqt6gui6t64",
    "libqt6widgets6t64",
    "libqt6network6t64",
    "libqt6core6",
    "libqt6gui6",
    "libqt6widgets6",
    "libqt6network6",
    # --- GTK ---
    "libgtk-3-0t64",
    "libgtk-4-1",
    "libgdk-pixbuf-2.0-0",
    "libglib2.0-0t64",
    "libgio-2.0-0",
    "libgobject-2.0-0",
    "libpango-1.0-0",
    "libcairo2",
    # --- Boost ---
    "libboost-filesystem1.83.0",
    "libboost-system1.83.0",
    "libboost-thread1.83.0",
    "libboost-regex1.83.0",
    "libboost-iostreams1.83.0",
    "libboost-program-options1.83.0",
    "libboost-serialization1.83.0",
    "libboost-chrono1.83.0",
    "libboost-atomic1.83.0",
    "libboost-locale1.83.0",
    # --- Media / FFmpeg (universe) ---
    "libavcodec60",
    "libavcodec-extra60",
    "libavformat60",
    "libavformat-extra60",
    "libavutil58",
    "libswscale7",
    "libavfilter9",
    "libavfilter-extra9",
    "libswresample4",
    # --- OpenCV ---
    "libopencv-core406t64",
    "libopencv-imgproc406t64",
    "libopencv-highgui406t64",
    "libopencv-calib3d406t64",
    "libopencv-features2d406t64",
    "libopencv-dnn406t64",
    # --- Network ---
    "libcurl4t64",
    "libcurl4",
    "libnghttp2-14",
    "libssh-4",
    # --- Database ---
    "libsqlite3-0",
    "libpq5",
    "libmysqlclient21",
    # --- XML / JSON ---
    "libxml2",
    "libxslt1.1",
    "libjson-c5",
    # --- Compression ---
    "zlib1g",
    "liblzma5",
    "libbz2-1.0",
    "libzstd1",
    "liblz4-1",
    # --- Graphics ---
    "libvulkan1",
    "libegl1",
    "libglx0",
    "libgl1",
    "libglx-mesa0",
    "libwayland-client0",
    "libx11-6",
    "libxcb1",
    # --- Protobuf / gRPC (universe) ---
    "libprotobuf32t64",
    "libprotobuf32",
    "libprotobuf-lite32t64",
    "libgrpc++1.51t64",
    "libgrpc37t64",
    "libgrpc37",
    "libgrpc29t64",
    # --- System ---
    "libsystemd0",
    "libudev1",
    "libdbus-1-3",
    "libpcre2-8-0",
    "libffi8",
    "libreadline8t64",
    "libncurses6",
    "libncursesw6",
    "libtinfo6",
    # --- Audio ---
    "libpulse0",
    "libasound2t64",
    "libasound2",
    "libopus0",
    "libvorbis0a",
    "libflac12t64",
    # --- Image ---
    "libjpeg-turbo8",
    "libpng16-16t64",
    "libpng16-16",
    "libtiff6",
    "libwebp7",
    # --- Math / Science (universe icin gsl/hdf5) ---
    "liblapack3",
    "libblas3",
    "libgsl27",
    "libgslcblas0",
    "libfftw3-double3",
    "libhdf5-103-1t64",
    "libhdf5-cpp-103-1t64",
    # --- Misc ---
    "libicu74",
    "libpcap0.8t64",
    "libusb-1.0-0",
    "libuv1t64",
    "libuv1",
    "libev4t64",
    "libev4",
    # --- Ek universe paketleri ---
    "libopencv-imgcodecs406t64",
    "libopencv-flann406t64",
    "libopencv-contrib406t64",
}

# Ek olarak onemli -dev paketleri (header + static lib)
DEV_PACKAGES = {
    "libc6-dev",
    "libstdc++-13-dev",
}

ALL_TARGET = TARGET_PACKAGES | DEV_PACKAGES

# Kategori tespiti icin paket adi -> kategori eslestirmesi
CATEGORY_MAP = [
    (r"^libc6", "linux_glibc"),
    (r"^libstdc\+\+", "linux_libstdcpp"),
    (r"^libgcc", "linux_libgcc"),
    (r"^libssl|^libcrypto|^libgnutls|^libgcrypt", "linux_crypto"),
    (r"^libpython", "linux_python"),
    (r"^libqt[56]", "linux_qt"),
    (r"^libgtk|^libgdk|^libglib|^libgio|^libgobject|^libpango|^libcairo", "linux_gtk"),
    (r"^libboost", "linux_boost"),
    (r"^libav|^libsw", "linux_ffmpeg"),
    (r"^libopencv", "linux_opencv"),
    (r"^libcurl|^libnghttp|^libssh", "linux_network"),
    (r"^libsqlite|^libpq|^libmysql", "linux_database"),
    (r"^libxml|^libxslt|^libjson", "linux_xml"),
    (r"^zlib|^liblzma|^libbz2|^libzstd|^liblz4", "linux_compression"),
    (r"^libvulkan|^libegl|^libglx|^libgl[01x]|^libwayland|^libx11|^libxcb|^libmesa", "linux_graphics"),
    (r"^libprotobuf|^libgrpc", "linux_rpc"),
    (r"^libsystemd|^libudev|^libdbus|^libpcre|^libffi|^libreadline|^libncurses|^libtinfo", "linux_system"),
    (r"^libpulse|^libasound|^libopus|^libvorbis|^libflac", "linux_audio"),
    (r"^libjpeg|^libpng|^libtiff|^libwebp", "linux_image"),
    (r"^liblapack|^libblas|^libgsl|^libfftw|^libhdf5", "linux_math"),
    (r"^libicu", "linux_icu"),
    (r"^libpcap", "linux_pcap"),
    (r"^libusb", "linux_usb"),
    (r"^libuv|^libev", "linux_async"),
]


def get_category(pkg_name: str) -> str:
    """Paket adindan kategori tespit et."""
    for pattern, cat in CATEGORY_MAP:
        if re.match(pattern, pkg_name):
            return cat
    return "linux_ubuntu"


def get_lib_name(pkg_name: str) -> str:
    """Paket adindan kutuphane adini cikar."""
    # t64 suffix'ini kaldir
    name = re.sub(r"t64$", "", pkg_name)
    # Versiyon numaralarini kaldir (sondaki rakamlar)
    name = re.sub(r"[\d._-]+$", "", name)
    # -dev suffix'i kaldir
    name = re.sub(r"-dev$", "", name)
    # lib prefix'ini kaldir
    if name.startswith("lib"):
        name = name[3:]
    return name if name else pkg_name


# ============================================================
# .deb Archive Parse (Pure Python - ar format)
# ============================================================

def parse_ar_archive(data: bytes):
    """
    .deb dosyasi bir 'ar' arsividir.
    Yapisi:
      - 8 byte magic: "!<arch>\n"
      - Her uye:
        - 60 byte header (isim, timestamp, owner, group, mode, size, magic)
        - Icerik (size byte)
        - Eger size tek ise +1 byte padding

    Yield: (member_name, member_data)
    """
    AR_MAGIC = b"!<arch>\n"
    if not data.startswith(AR_MAGIC):
        raise ValueError("Gecersiz ar archive (magic mismatch)")

    offset = len(AR_MAGIC)
    while offset < len(data):
        if offset + 60 > len(data):
            break

        header = data[offset : offset + 60]
        ar_name = header[0:16].decode("ascii", errors="replace").strip()
        ar_size_str = header[48:58].decode("ascii", errors="replace").strip()
        ar_fmag = header[58:60]

        if ar_fmag != b"`\n":
            # Bozuk header, dur
            break

        try:
            ar_size = int(ar_size_str)
        except ValueError:
            break

        offset += 60
        member_data = data[offset : offset + ar_size]
        offset += ar_size

        # ar padding: tek boyutlu uyeler icin 1 byte \n eklenir
        if ar_size % 2 != 0:
            offset += 1

        # Ismi temizle (/ ile biter genellikle)
        clean_name = ar_name.rstrip("/").strip()
        yield clean_name, member_data


def extract_data_tar(deb_data: bytes):
    """
    .deb iceriginden data.tar.* uyesini bul ve tarfile olarak ac.
    Dondurur: tarfile nesnesi veya None
    """
    for name, member_data in parse_ar_archive(deb_data):
        if name.startswith("data.tar"):
            # Sikistirma tipini belirle
            if name.endswith(".xz") or name.endswith(".lzma"):
                try:
                    decompressed = lzma.decompress(member_data)
                    return tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")
                except lzma.LZMAError as e:
                    print(f"    [WARN] lzma decompress hatasi: {e}")
                    return None
            elif name.endswith(".gz"):
                try:
                    return tarfile.open(fileobj=io.BytesIO(member_data), mode="r:gz")
                except Exception as e:
                    print(f"    [WARN] gzip tar hatasi: {e}")
                    return None
            elif name.endswith(".bz2"):
                try:
                    return tarfile.open(fileobj=io.BytesIO(member_data), mode="r:bz2")
                except Exception as e:
                    print(f"    [WARN] bz2 tar hatasi: {e}")
                    return None
            elif name.endswith(".zst"):
                if not HAS_ZSTD:
                    print(f"    [WARN] zstd sikistirma desteklenmiyor (pip install zstandard): {name}")
                    return None
                try:
                    dctx = zstd.ZstdDecompressor()
                    decompressed = dctx.decompress(member_data, max_output_size=500 * 1024 * 1024)
                    return tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")
                except Exception as e:
                    print(f"    [WARN] zstd decompress hatasi: {e}")
                    return None
            else:
                # Sikistirilmamis tar
                try:
                    return tarfile.open(fileobj=io.BytesIO(member_data), mode="r:")
                except Exception:
                    return None
    return None


# ============================================================
# ELF Symbol Extraction (pyelftools)
# ============================================================

def extract_elf_symbols(elf_data: bytes, filename: str = ""):
    """
    ELF binary'den .dynsym sembollerini cikar.
    Sadece STT_FUNC ve STB_GLOBAL/STB_WEAK olan sembolleri alir.

    Return: (defined_symbols: set, undefined_symbols: set)
      - defined: bu .so'dan export edilen (gercek implementasyon)
      - undefined: bu .so'nun import ettigi (baska lib'den)
    """
    defined = set()
    undefined = set()
    try:
        elf = ELFFile(io.BytesIO(elf_data))
    except ELFError:
        return defined, undefined
    except Exception:
        return defined, undefined

    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue

        for sym in section.iter_symbols():
            # Sadece fonksiyon sembolleri
            if sym.entry.st_info.type != "STT_FUNC":
                continue
            # Sadece global veya weak binding
            bind = sym.entry.st_info.bind
            if bind not in ("STB_GLOBAL", "STB_WEAK"):
                continue
            name = sym.name
            if not name:
                continue
            # SHN_UNDEF (0) = imported, diger = exported/defined
            if sym.entry.st_shndx == "SHN_UNDEF":
                undefined.add(name)
            else:
                defined.add(name)

    return defined, undefined


# ============================================================
# Packages.gz Parse
# ============================================================

def download_with_retry(url, max_retries=3, timeout=60):
    """URL'den veri indir, retry ile."""
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "karadul-sig-gen/1.0 (signature extraction)"
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"    [RETRY] {url} - {e} - {wait}s bekleniyor...")
                time.sleep(wait)
            else:
                print(f"    [FAIL] {url} - {e}")
                return None
    return None


def parse_packages_gz(data: bytes):
    """
    Packages.gz icerigini parse et.
    Her paket bos satirla ayrilir.
    Dondurur: {package_name: {"filename": ..., "size": ..., ...}}
    """
    text = gzip.decompress(data).decode("utf-8", errors="replace")
    packages = {}
    current = {}

    for line in text.splitlines():
        if line == "":
            if "Package" in current and "Filename" in current:
                packages[current["Package"]] = current
            current = {}
            continue

        if line.startswith(" ") or line.startswith("\t"):
            # Continuation line, skip
            continue

        if ":" in line:
            key, _, val = line.partition(":")
            current[key.strip()] = val.strip()

    # Son paket
    if "Package" in current and "Filename" in current:
        packages[current["Package"]] = current

    return packages


def find_matching_packages(all_packages: dict, targets: set):
    """
    Target paketleri all_packages'tan bul.
    Exact match + fuzzy match (t64 suffix, versiyon farkliliklari).
    """
    matched = {}

    # Exact match first
    for name in targets:
        if name in all_packages:
            matched[name] = all_packages[name]

    # Fuzzy: t64 suffix varyasyonlari
    remaining = targets - set(matched.keys())
    for name in remaining:
        # libc6 -> libc6 (zaten exact match)
        # libssl3 icin libssl3t64'u dene
        candidates = [
            name + "t64",
            name.replace("t64", ""),
            # libav versiyonlari: libavcodec60 bulunamazsa libavcodec-extra60 dene
            name.replace("lib", "lib") + "-extra",
        ]
        for cand in candidates:
            if cand in all_packages and cand not in matched:
                matched[name] = all_packages[cand]
                matched[name]["_resolved_name"] = cand
                break

    return matched


# ============================================================
# Main Pipeline
# ============================================================

def process_deb(pkg_name: str, pkg_info: dict, stats: dict):
    """
    Tek bir .deb paketini isle:
    1. Indir
    2. ar parse -> data.tar.* cikar
    3. .so dosyalarindan ELF sembolleri oku
    4. Sonuclari dondur

    Return: dict {symbol_name: {"lib": ..., "purpose": "", "category": ...}}
    """
    filename = pkg_info["Filename"]
    url = POOL_BASE + filename
    resolved = pkg_info.get("_resolved_name", pkg_name)
    size_str = pkg_info.get("Size", "?")

    print(f"  [{stats['done']+1}/{stats['total']}] {pkg_name} ({resolved}) - {int(size_str)//1024}KB")

    deb_data = download_with_retry(url, timeout=120)
    if deb_data is None:
        print(f"    [SKIP] Indirilemedi: {pkg_name}")
        stats["failed"] += 1
        stats["done"] += 1
        return {}

    # ar parse -> data.tar.*
    try:
        tar = extract_data_tar(deb_data)
    except Exception as e:
        print(f"    [SKIP] ar parse hatasi: {pkg_name}: {e}")
        stats["failed"] += 1
        stats["done"] += 1
        return {}

    if tar is None:
        print(f"    [SKIP] data.tar.* bulunamadi: {pkg_name}")
        stats["failed"] += 1
        stats["done"] += 1
        return {}

    # .so dosyalarini bul ve sembol cikar
    category = get_category(pkg_name)
    lib_name = get_lib_name(resolved)
    results = {}
    so_count = 0
    sym_count = 0

    try:
        for member in tar.getmembers():
            if not member.isfile():
                continue

            name = member.name
            # .so, .so.X, .so.X.Y.Z dosyalarini al
            # Ayrica .a (static archive icindeki .o'lar) da islenebilir ama ELF degil genellikle
            basename = os.path.basename(name)

            is_so = ".so" in basename
            is_elf_exec = basename in ("ld-linux-x86-64.so.2", "ld-linux.so.2") or \
                          name.endswith("/bin/" + basename) or \
                          "/sbin/" in name

            if not is_so and not is_elf_exec:
                continue

            try:
                f = tar.extractfile(member)
                if f is None:
                    continue
                elf_data = f.read()
            except Exception:
                continue

            # ELF magic check
            if len(elf_data) < 4 or elf_data[:4] != b"\x7fELF":
                continue

            so_count += 1
            defined_syms, undefined_syms = extract_elf_symbols(elf_data, basename)

            # Her sembol icin .so dosya adindan daha spesifik lib adi cikar
            # libssl.so.3 -> "ssl", libcrypto.so.3 -> "crypto"
            so_lib = basename
            if so_lib.startswith("lib"):
                so_lib = so_lib[3:]
            # .so ve sonrasini kes
            so_lib_clean = re.split(r"\.so", so_lib)[0]
            if not so_lib_clean:
                so_lib_clean = lib_name

            # Defined (exported) semboller -- bu lib'in kendi fonksiyonlari
            for sym in defined_syms:
                # defined her zaman kazanir (onceki undefined'i ezer)
                existing = results.get(sym)
                if existing is None or existing.get("_undef"):
                    results[sym] = {
                        "lib": so_lib_clean,
                        "purpose": "",
                        "category": category,
                    }
                sym_count += 1

            # Undefined (imported) semboller -- sadece baska yerde defined degilse ekle
            for sym in undefined_syms:
                if sym not in results:
                    results[sym] = {
                        "lib": so_lib_clean,
                        "purpose": "",
                        "category": category,
                        "_undef": True,  # merge sirasinda defined tarafindan ezilebilir
                    }
                sym_count += 1

    except Exception as e:
        print(f"    [WARN] tar iteration hatasi: {e}")
    finally:
        tar.close()

    print(f"    -> {so_count} .so dosyasi, {len(results)} unique sembol ({sym_count} total)")
    stats["so_files"] += so_count
    stats["symbols"] += len(results)
    stats["done"] += 1

    return results


def load_existing_signatures():
    """Mevcut combined DB'den tum sembol isimlerini yukle (net new hesabi icin)."""
    existing = set()
    if COMBINED_PATH.exists():
        try:
            data = json.loads(COMBINED_PATH.read_text())
            sigs = data.get("signatures", [])
            if isinstance(sigs, dict):
                existing = set(sigs.keys())
            elif isinstance(sigs, list):
                # combined_1M.json format: list of {"name": ..., ...}
                for entry in sigs:
                    if isinstance(entry, dict) and "name" in entry:
                        existing.add(entry["name"])
            print(f"[INFO] Mevcut combined DB: {len(existing):,} sembol")
        except Exception as e:
            print(f"[WARN] Combined DB okunamadi: {e}")
    return existing


def main():
    print("=" * 70)
    print("Karadul Ubuntu ELF Signature Generator")
    print("=" * 70)
    print(f"Hedef: Ubuntu 24.04 LTS (Noble) amd64")
    print(f"Hedef paket sayisi: {len(ALL_TARGET)}")
    print(f"Temp dizin: {TEMP_DIR}")
    print()

    # 1. Mevcut DB'yi yukle (net new hesabi icin)
    existing_sigs = load_existing_signatures()

    # 2. Packages.gz indir ve parse et (main + universe)
    all_packages = {}
    for i, pkg_url in enumerate(PACKAGES_URLS):
        repo_name = "main" if "main" in pkg_url else "universe"
        print(f"[1/3] Packages.gz indiriliyor ({repo_name})...")
        pkg_data = download_with_retry(pkg_url, timeout=120)
        if pkg_data is None:
            print(f"  [WARN] {repo_name} Packages.gz indirilemedi, atlanıyor")
            continue

        print(f"  Packages.gz boyutu: {len(pkg_data) // 1024}KB")
        print("  Parse ediliyor...")
        repo_packages = parse_packages_gz(pkg_data)
        print(f"  {repo_name} paket sayisi: {len(repo_packages):,}")
        # Merge -- main oncelikli (onceden eklenmis olanlari ezme)
        for name, info in repo_packages.items():
            if name not in all_packages:
                all_packages[name] = info

    if not all_packages:
        print("[FATAL] Hicbir Packages.gz indirilemedi!")
        sys.exit(1)
    print(f"  Toplam paket (birlesik): {len(all_packages):,}")

    # 3. Hedef paketleri bul
    matched = find_matching_packages(all_packages, ALL_TARGET)
    found_names = set(matched.keys())
    missing = ALL_TARGET - found_names
    if missing:
        print(f"\n  [WARN] Bulunamayan paketler ({len(missing)}):")
        for m in sorted(missing):
            print(f"    - {m}")
    print(f"\n  Eslesen paket: {len(matched)}")

    # 4. Her paketi isle
    print(f"\n[2/3] .deb paketleri indiriliyor ve isleniyor...")
    all_signatures = {}
    stats = {
        "done": 0,
        "total": len(matched),
        "failed": 0,
        "so_files": 0,
        "symbols": 0,
    }

    for pkg_name, pkg_info in sorted(matched.items()):
        try:
            sigs = process_deb(pkg_name, pkg_info, stats)
            # Merge: defined semboller her zaman kazanir
            for sym, info in sigs.items():
                existing = all_signatures.get(sym)
                if existing is None:
                    all_signatures[sym] = info
                elif existing.get("_undef") and not info.get("_undef"):
                    # Onceki undefined idi, simdi defined geliyor -> degistir
                    all_signatures[sym] = info
                # else: onceki defined, bunu atla
        except KeyboardInterrupt:
            print("\n[INTERRUPT] Kullanici durdurdu. Simdiye kadar toplananlar kaydedilecek.")
            break
        except Exception as e:
            print(f"    [ERROR] {pkg_name}: {e}")
            stats["failed"] += 1
            stats["done"] += 1

    # 5. _undef marker'ini temizle ve net new hesapla
    for sym in all_signatures:
        all_signatures[sym].pop("_undef", None)
    new_symbols = set(all_signatures.keys()) - existing_sigs
    print(f"\n[3/3] Sonuclar kaydediliyor...")

    # 6. JSON ciktisi olustur
    output = {
        "meta": {
            "generator": "karadul-sig-gen-ubuntu",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "Ubuntu 24.04 LTS (Noble) amd64",
            "packages_processed": stats["done"],
            "packages_failed": stats["failed"],
            "so_files_processed": stats["so_files"],
            "total_symbols": len(all_signatures),
            "net_new_vs_combined": len(new_symbols),
        },
        "signatures": dict(sorted(all_signatures.items())),
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False))

    # 7. Ozet
    print()
    print("=" * 70)
    print("OZET")
    print("=" * 70)
    print(f"  Islenen paket:      {stats['done']}")
    print(f"  Basarisiz:          {stats['failed']}")
    print(f"  .so dosyasi:        {stats['so_files']}")
    print(f"  Toplam sembol:      {len(all_signatures):,}")
    print(f"  Net new (combined): {len(new_symbols):,}")
    print(f"  Cikti:              {OUTPUT_PATH}")
    print()

    # Kategori dagilimi
    cat_counts = defaultdict(int)
    for sig in all_signatures.values():
        cat_counts[sig["category"]] += 1
    print("  Kategori dagilimi:")
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:30s} {cnt:>8,}")

    # Lib dagilimi (top 20)
    lib_counts = defaultdict(int)
    for sig in all_signatures.values():
        lib_counts[sig["lib"]] += 1
    print(f"\n  Top 20 kutuphane (sembol sayisina gore):")
    for lib, cnt in sorted(lib_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"    {lib:30s} {cnt:>8,}")

    # Temizlik
    try:
        import shutil
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    except Exception:
        pass

    print(f"\n[DONE] {len(all_signatures):,} sembol kaydedildi -> {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
