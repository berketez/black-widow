#!/usr/bin/env python3
"""
Homebrew Extra Signature Generator
====================================
Popüler C/C++ kütüphanelerini Homebrew ile kurar ve sembollerini çıkarır.
Mevcut homebrew_deep.json ve homebrew_symbols.json ile dedup yapar.

Çıktı: sigs/homebrew_extra.json
"""

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --- Konfigürasyon ---
BASE_DIR = "/Users/apple/Desktop/black-widow"
OUTPUT_PATH = os.path.join(BASE_DIR, "sigs", "homebrew_extra.json")
EXISTING_SIGS = [
    os.path.join(BASE_DIR, "sigs", "homebrew_deep.json"),
    os.path.join(BASE_DIR, "sigs", "homebrew_symbols.json"),
]
CELLAR_DIR = "/opt/homebrew/Cellar"
MIN_DISK_GB = 5

# Kurulacak paketler (büyükten küçüğe, sembol potansiyeline göre)
PACKAGES = [
    ("boost", "boost", "C++ library collection"),
    ("qt@6", "qt", "UI framework"),
    ("opencv", "opencv", "Computer vision"),
    ("ffmpeg", "ffmpeg", "Video/audio codecs"),
    ("protobuf", "protobuf", "Protocol Buffers"),
    ("grpc", "grpc", "RPC framework"),
    ("abseil", "abseil", "Google C++ utilities"),
    ("gstreamer", "gstreamer", "Media framework"),
    ("vtk", "vtk", "3D visualization"),
    ("cgal", "cgal", "Computational geometry"),
    ("poco", "poco", "C++ network/utility"),
    ("sdl2", "sdl2", "Game/multimedia"),
    ("glfw", "glfw", "OpenGL window management"),
    ("bullet", "bullet", "Physics simulation"),
    ("eigen", "eigen", "Linear algebra (header-only)"),
    ("lapack", "lapack", "Linear algebra (Fortran)"),
    ("fftw", "fftw", "FFT library"),
    ("hdf5", "hdf5", "HDF5 data format"),
    ("netcdf", "netcdf", "NetCDF data format"),
    ("gdal", "gdal", "Geospatial data"),
]


def check_disk_space():
    """Minimum disk alanı kontrolü."""
    result = subprocess.run(["df", "-g", "/"], capture_output=True, text=True)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4:
            avail_gb = int(parts[3])
            return avail_gb
    return 0


def get_installed_packages():
    """Homebrew ile kurulu paketleri döndür."""
    result = subprocess.run(
        ["brew", "list", "--formula"],
        capture_output=True, text=True
    )
    return set(result.stdout.strip().split("\n"))


def install_package(pkg_name):
    """Bir paketi Homebrew ile kur. Başarı/başarısızlık döndür."""
    print(f"    brew install {pkg_name} ...")
    start = time.time()
    try:
        result = subprocess.run(
            ["brew", "install", pkg_name],
            capture_output=True, text=True,
            timeout=600  # 10 dakika
        )
        elapsed = time.time() - start
        if result.returncode == 0:
            print(f"    [OK] {pkg_name} kuruldu ({elapsed:.1f}s)")
            return True
        else:
            # "already installed" kontrolü
            if "already installed" in result.stderr.lower():
                print(f"    [OK] {pkg_name} zaten kurulu ({elapsed:.1f}s)")
                return True
            print(f"    [FAIL] {pkg_name} kurulamadı ({elapsed:.1f}s)")
            # İlk birkaç satır hata mesajı
            for line in result.stderr.splitlines()[:5]:
                print(f"      {line}")
            return False
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] {pkg_name} - 600s aşıldı, atlanıyor")
        return False
    except Exception as e:
        print(f"    [ERROR] {pkg_name}: {e}")
        return False


def find_package_libs(pkg_name):
    """
    Bir paket için /opt/homebrew/Cellar/<pkg>/ altındaki tüm
    .dylib, .a, .so dosyalarını bul.
    Sadece Cellar dizininden arar (hızlı ve doğru).
    """
    valid_extensions = {".dylib", ".a", ".so"}
    files = []
    seen = set()

    # Cellar'da tüm eşleşen dizinleri bul
    cellar_dirs = []
    pkg_base = re.sub(r"@.*$", "", pkg_name)

    if os.path.isdir(CELLAR_DIR):
        for d in os.listdir(CELLAR_DIR):
            d_base = re.sub(r"@.*$", "", d)
            if d == pkg_name or d_base == pkg_base:
                cellar_dirs.append(os.path.join(CELLAR_DIR, d))

    # Qt özel: qtbase, qtsvg, qtdeclarative vs. hepsini dahil et
    if pkg_base == "qt":
        for d in os.listdir(CELLAR_DIR):
            if d.startswith("qt") and d not in [os.path.basename(x) for x in cellar_dirs]:
                cellar_dirs.append(os.path.join(CELLAR_DIR, d))

    for search_dir in cellar_dirs:
        if not os.path.isdir(search_dir):
            continue

        for root, dirs, filenames in os.walk(search_dir, followlinks=True):
            for fname in filenames:
                fpath = os.path.join(root, fname)

                # Extension kontrolü
                ext = os.path.splitext(fname)[1]
                if ext not in valid_extensions:
                    parts = fname.split(".")
                    has_valid = any(("." + p) in valid_extensions for p in parts)
                    if not has_valid:
                        continue

                try:
                    realpath = os.path.realpath(fpath)
                except OSError:
                    continue

                if realpath in seen:
                    continue
                seen.add(realpath)

                if not os.path.isfile(realpath):
                    continue

                files.append((fpath, realpath))

    return files


def run_nm(filepath, is_static=False):
    """nm çalıştır ve sembol isimlerini döndür."""
    if is_static:
        cmd = ["nm", "-g", filepath]
    else:
        cmd = ["nm", "-gU", filepath]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        symbols = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-2] in ("T", "S", "D"):
                sym = parts[-1]
                if sym.startswith("_"):
                    sym = sym[1:]
                symbols.append(sym)
            elif len(parts) == 2 and parts[0] in ("T", "S", "D"):
                sym = parts[1]
                if sym.startswith("_"):
                    sym = sym[1:]
                symbols.append(sym)
        return symbols
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        return []


def demangle_symbols(mangled_list):
    """c++filt ile toplu demangle."""
    result = {}
    CHUNK = 5000

    for i in range(0, len(mangled_list), CHUNK):
        chunk = mangled_list[i:i + CHUNK]
        # macOS c++filt çift underscore bekler: _Zfoo -> __Zfoo
        input_text = "\n".join("_" + s for s in chunk)
        try:
            proc = subprocess.run(
                ["c++filt"],
                input=input_text,
                capture_output=True, text=True,
                timeout=60
            )
            demangled = proc.stdout.splitlines()
            for orig, dem in zip(chunk, demangled):
                dem = dem.strip()
                # Başındaki _ kaldır (macOS prefix)
                if dem.startswith("_") and not dem.startswith("__"):
                    dem = dem[1:]
                result[orig] = dem
        except (subprocess.TimeoutExpired, OSError):
            for sym in chunk:
                result[sym] = sym
    return result


def load_existing_signatures():
    """Mevcut imza dosyalarından tüm anahtarları yükle (dedup için)."""
    existing = set()
    for path in EXISTING_SIGS:
        if not os.path.isfile(path):
            print(f"  [SKIP] Mevcut DB bulunamadi: {path}")
            continue
        try:
            print(f"  Yükleniyor: {path}")
            with open(path, "r") as f:
                data = json.load(f)
            sigs = data.get("signatures", {})
            existing.update(sigs.keys())
            print(f"    -> {len(sigs)} imza yüklendi")
        except Exception as e:
            print(f"  [HATA] {path}: {e}")
    return existing


def categorize_package(brew_name):
    """Paket adından kategori çıkar."""
    categories = {
        "boost": "cpp-utility",
        "qt": "ui-framework",
        "opencv": "computer-vision",
        "ffmpeg": "media",
        "protobuf": "serialization",
        "grpc": "networking",
        "abseil": "cpp-utility",
        "gstreamer": "media",
        "vtk": "visualization",
        "cgal": "geometry",
        "poco": "networking",
        "sdl2": "multimedia",
        "glfw": "graphics",
        "bullet": "physics",
        "eigen": "math",
        "lapack": "math",
        "fftw": "math",
        "hdf5": "data-format",
        "netcdf": "data-format",
        "gdal": "geospatial",
    }
    return categories.get(brew_name, "homebrew")


def main():
    print("=" * 70)
    print("  Homebrew Extra Signature Generator")
    print("  Karadul v1.7.5 - Signature DB Genisleme")
    print("=" * 70)

    # 0. Disk kontrolü
    avail = check_disk_space()
    print(f"\n[0] Disk alanı: {avail} GB bos")
    if avail < MIN_DISK_GB:
        print(f"HATA: Minimum {MIN_DISK_GB} GB gerekli, {avail} GB var!")
        sys.exit(1)

    # 1. Mevcut imzaları yükle (dedup için)
    print("\n[1] Mevcut imzalar yukleniyor (dedup icin)...")
    existing_keys = load_existing_signatures()
    print(f"  Toplam mevcut: {len(existing_keys)} imza")

    # 2. Kurulu paketleri kontrol et
    print("\n[2] Homebrew kurulu paketler kontrol ediliyor...")
    installed = get_installed_packages()

    to_install = []
    already_installed = []
    for brew_name, _, desc in PACKAGES:
        base_name = re.sub(r"@.*$", "", brew_name)
        # Tam eşleşme veya base name eşleşmesi
        if brew_name in installed or base_name in installed:
            already_installed.append(brew_name)
        else:
            # Qt gibi varyantları kontrol et
            found = False
            for inst in installed:
                if inst.startswith(base_name):
                    already_installed.append(brew_name)
                    found = True
                    break
            if not found:
                to_install.append(brew_name)

    print(f"  Zaten kurulu ({len(already_installed)}): {', '.join(already_installed)}")
    print(f"  Kurulacak ({len(to_install)}): {', '.join(to_install)}")

    # 3. Kurulumu yap
    install_results = {}
    if to_install:
        print(f"\n[3] {len(to_install)} paket kuruluyor...")
        for idx, pkg in enumerate(to_install):
            print(f"\n  [{idx+1}/{len(to_install)}] {pkg}")

            # Kurulum öncesi disk kontrolü
            avail = check_disk_space()
            if avail < MIN_DISK_GB:
                print(f"    [WARN] Disk az ({avail}GB), kalan paketler atlanıyor")
                for remaining in to_install[idx:]:
                    install_results[remaining] = False
                break

            success = install_package(pkg)
            install_results[pkg] = success
    else:
        print("\n[3] Tüm paketler zaten kurulu, kurulum atlanıyor.")

    # 4. Sembol çıkarma
    print("\n[4] Sembol çıkarma başlıyor...")
    all_signatures = {}
    lib_stats = defaultdict(int)
    package_stats = {}
    total_files = 0
    total_files_with_syms = 0

    for brew_name, sig_name, desc in PACKAGES:
        pkg_start = time.time()
        base_name = re.sub(r"@.*$", "", brew_name)

        # Paket kurulu mu?
        if brew_name in install_results and not install_results[brew_name]:
            print(f"\n  [{sig_name}] ATLANIYOR (kurulum başarısız)")
            package_stats[sig_name] = {"status": "install_failed", "symbols": 0, "time": 0}
            continue

        print(f"\n  [{sig_name}] Kütüphane dosyaları aranıyor...")
        files = find_package_libs(brew_name)

        if not files:
            # Alternatif arama: base name ile
            if brew_name != base_name:
                files = find_package_libs(base_name)

        if not files:
            print(f"    Dosya bulunamadı, atlanıyor")
            package_stats[sig_name] = {"status": "no_files", "symbols": 0, "time": 0}
            continue

        total_files += len(files)
        pkg_syms = 0
        pkg_new = 0
        category = categorize_package(sig_name)

        for fpath, realpath in files:
            is_static = realpath.endswith(".a")
            symbols = run_nm(realpath, is_static)

            if symbols:
                total_files_with_syms += 1

            for sym in symbols:
                # Filtreleme: çok kısa veya anlamsız sembolleri atla
                if len(sym) < 2:
                    continue
                # Compiler-internal sembolleri atla
                if sym.startswith("GCC_") or sym.startswith("__cxa_"):
                    continue

                pkg_syms += 1
                if sym not in existing_keys and sym not in all_signatures:
                    all_signatures[sym] = {
                        "lib": sig_name,
                        "purpose": "",
                        "category": category,
                    }
                    lib_stats[sig_name] += 1
                    pkg_new += 1

        elapsed = time.time() - pkg_start
        print(f"    {len(files)} dosya, {pkg_syms} sembol, {pkg_new} net new ({elapsed:.1f}s)")
        package_stats[sig_name] = {
            "status": "ok",
            "files": len(files),
            "total_symbols": pkg_syms,
            "net_new": pkg_new,
            "time": round(elapsed, 1)
        }

    # 5. C++ demangle
    mangled = [s for s in all_signatures if s.startswith("_Z")]
    demangled_added = 0
    if mangled:
        print(f"\n[5] C++ demangle: {len(mangled)} mangled sembol...")
        demangled_map = demangle_symbols(mangled)
        for msym, dsym in demangled_map.items():
            if dsym and dsym != msym and dsym != ("_" + msym):
                # Mangled sembolün purpose'una demangled ismini yaz
                if msym in all_signatures:
                    all_signatures[msym]["purpose"] = dsym
                # Demangled hali de ayrı bir giriş olarak ekle
                if dsym not in existing_keys and dsym not in all_signatures:
                    all_signatures[dsym] = {
                        "lib": all_signatures[msym]["lib"],
                        "purpose": f"demangled from {msym}",
                        "category": all_signatures[msym]["category"],
                    }
                    lib_stats[all_signatures[msym]["lib"]] += 1
                    demangled_added += 1
        print(f"  Demangled eklenen: {demangled_added} yeni sembol")
    else:
        print("\n[5] Mangled sembol yok, demangle atlanıyor.")

    # 6. JSON yaz
    print(f"\n[6] JSON yazılıyor: {OUTPUT_PATH}")
    output = {
        "meta": {
            "generator": "karadul-sig-gen-homebrew-extra",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "Homebrew extra packages (boost, qt, opencv, etc.)",
            "total_signatures": len(all_signatures),
            "total_libraries": len(lib_stats),
            "total_files_scanned": total_files,
            "files_with_symbols": total_files_with_syms,
            "deduped_against": [os.path.basename(p) for p in EXISTING_SIGS],
            "demangled_added": demangled_added,
            "package_stats": package_stats,
        },
        "signatures": all_signatures,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    fsize = os.path.getsize(OUTPUT_PATH)

    # 7. Rapor
    print("\n" + "=" * 70)
    print("  RAPOR")
    print("=" * 70)
    print(f"  Net new sembol: {len(all_signatures)}")
    print(f"  Mevcut DB'de olan (deduped): {len(existing_keys)}")
    print(f"  Toplam kütüphane: {len(lib_stats)}")
    print(f"  Demangled eklenen: {demangled_added}")
    print(f"  Dosya boyutu: {fsize / (1024*1024):.1f} MB")

    print(f"\n  Paket bazlı özet:")
    print(f"  {'Paket':<20s} {'Durum':<15s} {'Dosya':>6s} {'Toplam':>8s} {'Net New':>8s} {'Süre':>6s}")
    print(f"  {'-'*63}")
    for brew_name, sig_name, desc in PACKAGES:
        stats = package_stats.get(sig_name, {})
        status = stats.get("status", "unknown")
        files = stats.get("files", 0)
        total = stats.get("total_symbols", 0)
        net = stats.get("net_new", 0)
        t = stats.get("time", 0)
        print(f"  {sig_name:<20s} {status:<15s} {files:>6d} {total:>8d} {net:>8d} {t:>5.1f}s")

    print(f"\n  En çok net new sembol (top 10):")
    for lib, count in sorted(lib_stats.items(), key=lambda x: -x[1])[:10]:
        print(f"    {lib:<25s} {count:>8d}")

    print(f"\n  Çıktı: {OUTPUT_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    main()
