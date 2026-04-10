#!/usr/bin/env python3
"""
Karadul Signature Generator - PyPI Native Wheels
=================================================
PyPI'daki populer Python paketlerinin manylinux ve win_amd64 wheel'lerinden
native sembol (fonksiyon) isimlerini cikarir.

Calisma mantigi:
1. PyPI JSON API ile her paketin wheel URL'lerini bul
2. manylinux_x86_64 ve win_amd64 wheel'lerini indir (.whl = ZIP)
3. ZIP icindeki .so dosyalarini pyelftools ile parse et (ELF .dynsym)
4. ZIP icindeki .pyd dosyalarini pefile ile parse et (PE export table)
5. Mevcut signature DB'leri ile overlap kontrolu yap
6. Sonucu sigs/pypi_native_symbols.json olarak kaydet

Notlar:
- Linux .so'lar versioned symbols icerir (func@@GLIBC_2.17)
- Windows .pyd'ler DLL export table'da farkli isimler icerir
- Her platform farkli kaynak -> dusuk overlap bekleniyor
- Wheel'ler /tmp/'ye indirilir, islenir, silinir
"""

import io
import json
import os
import re
import struct
import sys
import tempfile
import time
import zipfile
from collections import defaultdict
from pathlib import Path

import requests

try:
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError
except ImportError:
    print("HATA: pyelftools kurulu degil. pip install pyelftools")
    sys.exit(1)

try:
    import pefile
except ImportError:
    print("HATA: pefile kurulu degil. pip install pefile")
    sys.exit(1)


# ============================================================================
# Konfiguerasyon
# ============================================================================

SIGS_DIR = Path("/Users/apple/Desktop/black-widow/sigs")
OUTPUT_PATH = SIGS_DIR / "pypi_native_symbols.json"

# Hedef paketler: C extension iceren en populer paketler
TARGET_PACKAGES = [
    "numpy",
    "scipy",
    "pandas",
    "scikit-learn",
    "matplotlib",
    "pillow",
    "opencv-python-headless",
    "cryptography",
    "cffi",
    "pynacl",
    "lxml",
    "ujson",
    "orjson",
    "msgpack",
    "grpcio",
    "protobuf",
    "psycopg2-binary",
    "pyarrow",
    "h5py",
    "shapely",
    "pydantic-core",
    "regex",
    "rapidfuzz",
    "tokenizers",
    "safetensors",
    "markupsafe",
    "charset-normalizer",
    "yarl",
    "aiohttp",
    "frozenlist",
]

# Wheel secim kriterleri
# manylinux_2_17_x86_64 en yaygin tag
LINUX_PATTERNS = [
    "manylinux_2_17_x86_64",
    "manylinux2014_x86_64",
    "manylinux_2_28_x86_64",
    "manylinux_2_5_x86_64",
    "manylinux1_x86_64",
    "linux_x86_64",
]

WIN_PATTERNS = [
    "win_amd64",
]

# Genel minimum sembol filtresi: cok kisa veya noise olan semboller
MIN_SYMBOL_LEN = 3

# Sembol blacklist: standart runtime sembolleri, burada istemiyoruz
SYMBOL_BLACKLIST_PREFIXES = (
    "_init",
    "_fini",
    "__bss_start",
    "_edata",
    "_end",
    "__libc_",
    "__cxa_",
    "__gxx_",
    "__gcc_",
    "_Jv_",
    "__do_global_",
    "__dso_handle",
    "__TMC_END__",
    "_ITM_",
    "__stack_chk_",
    "__ctype_",
)


# ============================================================================
# PyPI API
# ============================================================================

def get_wheel_urls(package_name: str) -> dict[str, str]:
    """PyPI JSON API ile paketin wheel URL'lerini bul.

    Returns:
        {"linux": url, "windows": url} - bulunanlari dondurur
    """
    api_url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(api_url, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  [HATA] PyPI API hatasi ({package_name}): {e}")
        return {}

    data = resp.json()
    urls_list = data.get("urls", [])

    result = {}

    # Linux wheel bul
    for pattern in LINUX_PATTERNS:
        if "linux" in result:
            break
        for item in urls_list:
            fname = item.get("filename", "")
            if fname.endswith(".whl") and pattern in fname:
                # cp312 veya cp311 tercih et (daha guncel)
                result["linux"] = item["url"]
                break

    # Windows wheel bul
    for pattern in WIN_PATTERNS:
        if "windows" in result:
            break
        for item in urls_list:
            fname = item.get("filename", "")
            if fname.endswith(".whl") and pattern in fname:
                result["windows"] = item["url"]
                break

    return result


# ============================================================================
# Binary parsers
# ============================================================================

def extract_elf_symbols(data: bytes, filename: str) -> list[str]:
    """ELF binary'den (.so) exported fonksiyon sembollerini cikar.

    pyelftools ile .dynsym section'ini parse eder.
    FUNC tipindeki GLOBAL/WEAK sembolleri alir.
    Versioned symbol'leri temizler (@@GLIBC_2.17 -> fonksiyon adi).
    """
    symbols = []
    try:
        f = io.BytesIO(data)
        elf = ELFFile(f)

        # .dynsym section'ini bul (dynamic symbols)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            # Bazi ELF'lerde section adi farkli olabilir
            for section in elf.iter_sections():
                if section.header.sh_type == "SHT_DYNSYM":
                    dynsym = section
                    break

        if dynsym is None:
            return symbols

        for sym in dynsym.iter_symbols():
            # Sadece fonksiyonlari al
            if sym.entry.st_info.type != "STT_FUNC":
                continue

            # GLOBAL veya WEAK binding
            binding = sym.entry.st_info.bind
            if binding not in ("STB_GLOBAL", "STB_WEAK"):
                continue

            # Undefined (imported) semboller: st_shndx == SHN_UNDEF
            # Bunlari da alalim (hangi fonksiyonlari kullandigini gosterir)
            # Ama exported olanlari ayri isaretleme sansimiz var
            # Simdilik hepsini alalim

            name = sym.name
            if not name:
                continue

            # Versioned symbol temizligi: func@@GLIBC_2.17 -> func
            if "@@" in name:
                name = name.split("@@")[0]
            elif "@" in name:
                name = name.split("@")[0]

            symbols.append(name)

    except (ELFError, Exception) as e:
        # Bozuk veya parse edilemeyen dosya
        pass

    return symbols


def extract_pe_symbols(data: bytes, filename: str) -> list[str]:
    """PE binary'den (.pyd / .dll) exported fonksiyon sembollerini cikar.

    pefile ile export directory'yi parse eder.
    """
    symbols = []
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("ascii", errors="ignore")
                    if name:
                        symbols.append(name)

        pe.close()
    except Exception:
        pass

    return symbols


def filter_symbols(symbols: list[str]) -> list[str]:
    """Noise sembolleri filtrele."""
    filtered = []
    for sym in symbols:
        # Minimum uzunluk
        if len(sym) < MIN_SYMBOL_LEN:
            continue

        # Blacklist prefix kontrolu
        if any(sym.startswith(prefix) for prefix in SYMBOL_BLACKLIST_PREFIXES):
            continue

        filtered.append(sym)

    return filtered


# ============================================================================
# Wheel processing
# ============================================================================

def process_wheel(url: str, package_name: str, platform: str) -> dict[str, list[str]]:
    """Bir wheel dosyasini indir, icindeki native binary'leri isle.

    Args:
        url: Wheel download URL'si
        package_name: Paket adi (numpy, scipy, ...)
        platform: "linux" veya "windows"

    Returns:
        {dosya_adi: [sembol_listesi], ...}
    """
    results = {}

    # Wheel'i download et (bellekte tut, diske yazmaya gerek yok)
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
        wheel_data = resp.content
    except requests.RequestException as e:
        print(f"  [HATA] Download basarisiz ({package_name} {platform}): {e}")
        return results

    # ZIP olarak ac
    try:
        zf = zipfile.ZipFile(io.BytesIO(wheel_data))
    except zipfile.BadZipFile:
        print(f"  [HATA] Gecersiz ZIP ({package_name} {platform})")
        return results

    # Icindeki native binary'leri bul
    for entry in zf.namelist():
        is_so = entry.endswith(".so") or ".so." in entry.split("/")[-1]
        is_pyd = entry.endswith(".pyd")
        is_dll = entry.endswith(".dll")

        if not (is_so or is_pyd or is_dll):
            continue

        try:
            binary_data = zf.read(entry)
        except Exception:
            continue

        # Cok kucuk dosyalar muhtemelen stub
        if len(binary_data) < 1024:
            continue

        fname = entry.split("/")[-1]

        if platform == "linux" and is_so:
            syms = extract_elf_symbols(binary_data, fname)
        elif platform == "windows" and (is_pyd or is_dll):
            syms = extract_pe_symbols(binary_data, fname)
        else:
            continue

        syms = filter_symbols(syms)

        if syms:
            results[fname] = syms

    zf.close()
    return results


def extract_lib_name_from_entry(entry_name: str, package_name: str) -> str:
    """Wheel icindeki dosya yolundan library adini cikar.

    Ornekler:
        numpy/core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so -> numpy
        scipy/linalg/_flapack.cpython-312-x86_64-linux-gnu.so -> scipy
        numpy.libs/libopenblas64_.so.0 -> numpy (vendored lib)
    """
    parts = entry_name.split("/")

    # .libs dizini: vendored library
    if len(parts) >= 2 and parts[0].endswith(".libs"):
        return parts[0].replace(".libs", "").replace("-", "_").lower()

    # Ilk dizin genelde paket adi
    if len(parts) >= 2:
        top = parts[0].replace("-", "_").lower()
        # .dist-info dizinini atla
        if ".dist-info" in top:
            return package_name.replace("-", "_").lower()
        return top

    return package_name.replace("-", "_").lower()


# ============================================================================
# Mevcut DB yukleme
# ============================================================================

def load_existing_symbols() -> set[str]:
    """Mevcut signature DB'lerindeki tum sembol adlarini yukle."""
    existing = set()
    for json_file in SIGS_DIR.glob("*.json"):
        if json_file.name == "pypi_native_symbols.json":
            continue
        try:
            with open(json_file) as f:
                data = json.load(f)
            sigs = data.get("signatures", {})
            if isinstance(sigs, list):
                for s in sigs:
                    if "name" in s:
                        existing.add(s["name"])
            elif isinstance(sigs, dict):
                existing.update(sigs.keys())
        except (json.JSONDecodeError, OSError):
            pass
    return existing


# ============================================================================
# Main
# ============================================================================

def main():
    start_time = time.time()

    print("=" * 70)
    print("Karadul PyPI Native Wheel Signature Generator")
    print("=" * 70)
    print(f"Hedef paket sayisi: {len(TARGET_PACKAGES)}")
    print()

    # Tum sonuclari topla
    # lib_name -> set of symbols
    lib_symbols: dict[str, set[str]] = defaultdict(set)

    # Platform bazli istatistik
    stats = {
        "packages_attempted": 0,
        "packages_with_symbols": 0,
        "linux_wheels": 0,
        "windows_wheels": 0,
        "linux_binaries": 0,
        "windows_binaries": 0,
        "linux_symbols_raw": 0,
        "windows_symbols_raw": 0,
        "download_errors": 0,
        "per_package": {},
    }

    for i, pkg in enumerate(TARGET_PACKAGES, 1):
        print(f"[{i:2d}/{len(TARGET_PACKAGES)}] {pkg}")
        stats["packages_attempted"] += 1

        # Wheel URL'lerini bul
        urls = get_wheel_urls(pkg)

        if not urls:
            print(f"  -> Wheel bulunamadi, atlaniyor")
            continue

        pkg_total = 0
        pkg_key = pkg.replace("-", "_").lower()

        # Linux wheel isle
        if "linux" in urls:
            wheel_url = urls["linux"]
            wheel_fname = wheel_url.split("/")[-1]
            print(f"  Linux: {wheel_fname[:70]}...")

            results = process_wheel(wheel_url, pkg, "linux")
            stats["linux_wheels"] += 1

            for fname, syms in results.items():
                stats["linux_binaries"] += 1
                stats["linux_symbols_raw"] += len(syms)
                lib_symbols[pkg_key].update(syms)
                pkg_total += len(syms)

            if results:
                print(f"         {len(results)} binary, {sum(len(s) for s in results.values())} sembol")
            else:
                print(f"         Native binary bulunamadi")

        # Windows wheel isle
        if "windows" in urls:
            wheel_url = urls["windows"]
            wheel_fname = wheel_url.split("/")[-1]
            print(f"  Win:   {wheel_fname[:70]}...")

            results = process_wheel(wheel_url, pkg, "windows")
            stats["windows_wheels"] += 1

            for fname, syms in results.items():
                stats["windows_binaries"] += 1
                stats["windows_symbols_raw"] += len(syms)
                lib_symbols[pkg_key].update(syms)
                pkg_total += len(syms)

            if results:
                print(f"         {len(results)} binary, {sum(len(s) for s in results.values())} sembol")
            else:
                print(f"         Native binary bulunamadi")

        if pkg_total > 0:
            stats["packages_with_symbols"] += 1
            unique_count = len(lib_symbols[pkg_key])
            print(f"  -> {unique_count} unique sembol")
            stats["per_package"][pkg_key] = unique_count

    # Tum unique semboller
    all_unique = set()
    for syms in lib_symbols.values():
        all_unique.update(syms)

    print()
    print(f"[OVERLAP] Mevcut signature DB'leri yukleniyor...")
    existing_symbols = load_existing_symbols()
    print(f"  {len(existing_symbols):,} mevcut sembol yuklendi")

    overlap = all_unique & existing_symbols
    new_only = all_unique - existing_symbols
    print(f"  Overlap: {len(overlap):,}")
    print(f"  Net new: {len(new_only):,}")

    # JSON olustur
    print()
    print(f"[KAYIT] JSON olusturuluyor...")

    signatures = {}
    for lib_name, syms in sorted(lib_symbols.items()):
        for sym in sorted(syms):
            if sym not in signatures:
                signatures[sym] = {
                    "lib": lib_name,
                    "purpose": "",
                    "category": "pypi_native",
                }

    output = {
        "meta": {
            "generator": "karadul-sig-gen-pypi",
            "date": time.strftime("%Y-%m-%d"),
            "source": "PyPI native wheels (manylinux_x86_64 + win_amd64)",
            "packages_attempted": stats["packages_attempted"],
            "packages_with_symbols": stats["packages_with_symbols"],
            "linux_wheels": stats["linux_wheels"],
            "windows_wheels": stats["windows_wheels"],
            "linux_binaries": stats["linux_binaries"],
            "windows_binaries": stats["windows_binaries"],
            "linux_symbols_raw": stats["linux_symbols_raw"],
            "windows_symbols_raw": stats["windows_symbols_raw"],
            "unique_symbols": len(signatures),
            "overlap_with_existing": len(overlap),
            "net_new_symbols": len(new_only),
            "library_stats": {
                lib: len(syms) for lib, syms in sorted(
                    lib_symbols.items(), key=lambda x: -len(x[1])
                )
            },
        },
        "signatures": signatures,
    }

    os.makedirs(OUTPUT_PATH.parent, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    file_size = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
    elapsed = time.time() - start_time

    # Final rapor
    print()
    print("=" * 70)
    print("SONUC")
    print("=" * 70)
    print(f"Paket (denenen):      {stats['packages_attempted']}")
    print(f"Paket (basarili):     {stats['packages_with_symbols']}")
    print(f"Linux wheel:          {stats['linux_wheels']}")
    print(f"Windows wheel:        {stats['windows_wheels']}")
    print(f"Linux binary (.so):   {stats['linux_binaries']}")
    print(f"Windows binary (.pyd):{stats['windows_binaries']}")
    print(f"Linux ham sembol:     {stats['linux_symbols_raw']:,}")
    print(f"Windows ham sembol:   {stats['windows_symbols_raw']:,}")
    print(f"Unique sembol:        {len(signatures):,}")
    print(f"Mevcut DB overlap:    {len(overlap):,}")
    print(f"NET NEW:              {len(new_only):,}")
    print(f"Dosya boyutu:         {file_size:.1f} MB")
    print(f"Sure:                 {elapsed:.1f} saniye")
    print(f"Kayit:                {OUTPUT_PATH}")
    print("=" * 70)

    # Per-package tablo
    print()
    print("Paket bazli sembol sayilari:")
    print(f"{'Paket':<30s} {'Unique':>10s}")
    print("-" * 42)
    for lib, count in sorted(stats["per_package"].items(), key=lambda x: -x[1]):
        print(f"  {lib:<28s} {count:>10,}")

    print()
    print("Bitti.")


if __name__ == "__main__":
    main()
