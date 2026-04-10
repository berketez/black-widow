#!/usr/bin/env python3
"""
gen_dyld_sigs.py - macOS dyld_shared_cache export'larından signature çıkarma

dyld cache map dosyasından tüm kütüphane yollarını çıkarır,
her biri için `dyld_info -exports` çalıştırır, sembolleri toplar.
Mevcut signature DB'leriyle dedup yapar ve net new'leri kaydeder.

Çıktı: sigs/dyld_cache_exports.json
"""

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Paths
PROJECT_DIR = Path("/Users/apple/Desktop/black-widow")
SIGS_DIR = PROJECT_DIR / "sigs"
OUTPUT_FILE = SIGS_DIR / "dyld_cache_exports.json"
DYLD_CACHE_MAP = Path("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.map")

# ---- Helper: Kütüphane adını yoldan çıkar ----
def lib_name_from_path(path: str) -> str:
    """
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
    -> CoreFoundation

    /usr/lib/system/libdispatch.dylib
    -> libdispatch

    /usr/lib/libobjc.A.dylib
    -> libobjc
    """
    basename = os.path.basename(path)
    # .dylib uzantısını kaldır
    if basename.endswith(".dylib"):
        basename = basename.rsplit(".dylib", 1)[0]
        # libX.A gibi version suffix'leri kaldır
        # Ama "libsystem_c" gibi durumlarda "." olmayabilir
        parts = basename.split(".")
        basename = parts[0]
    # .tbd uzantısını kaldır
    elif basename.endswith(".tbd"):
        basename = basename.rsplit(".tbd", 1)[0]

    return basename


def framework_name_from_path(path: str) -> str:
    """
    Framework path'inden clean framework adı çıkar.
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
    -> CoreFoundation

    /usr/lib/system/libdispatch.dylib -> libdispatch
    """
    # Framework pattern: XXX.framework bul
    m = re.search(r'/([^/]+)\.framework/', path)
    if m:
        return m.group(1)
    return lib_name_from_path(path)


# ---- Kategori tahmin ----
CATEGORY_MAP = {
    # Frameworks
    "CoreFoundation": "foundation",
    "Foundation": "foundation",
    "AppKit": "ui",
    "UIKit": "ui",
    "SwiftUI": "ui",
    "CoreGraphics": "graphics",
    "CoreImage": "graphics",
    "QuartzCore": "graphics",
    "Metal": "graphics",
    "MetalKit": "graphics",
    "CoreData": "data",
    "CoreML": "ml",
    "Security": "security",
    "IOKit": "io",
    "CoreAudio": "audio",
    "AVFoundation": "audio",
    "CoreMedia": "media",
    "CoreVideo": "media",
    "WebKit": "web",
    "Network": "network",
    "SystemConfiguration": "network",
    "CoreBluetooth": "network",
    "CoreLocation": "location",
    "MapKit": "location",
    "Accelerate": "math",
    "vecLib": "math",
    "BLAS": "math",
    "LAPACK": "math",
    "vDSP": "math",
    "CoreText": "text",
    "NaturalLanguage": "text",
    "ImageIO": "graphics",
    "CoreServices": "system",
    "DiskArbitration": "system",
    "CoreTelephony": "system",
    "GameKit": "game",
    "SpriteKit": "game",
    "SceneKit": "game",
    "ARKit": "ar",
    "RealityKit": "ar",
    "Vision": "ml",
    "NaturalLanguage": "ml",
    "CreateML": "ml",
}

# usr/lib common patterns
USRLIB_CATEGORY = {
    "libobjc": "runtime",
    "libdyld": "runtime",
    "libdispatch": "concurrency",
    "libsystem_c": "libc",
    "libsystem_kernel": "kernel",
    "libsystem_pthread": "threading",
    "libsystem_malloc": "memory",
    "libsystem_platform": "system",
    "libsystem_info": "system",
    "libsystem_trace": "debugging",
    "libcorecrypto": "crypto",
    "libSystem": "system",
    "libc++": "cpp_runtime",
    "libc++abi": "cpp_runtime",
    "libxpc": "ipc",
    "libsqlite3": "database",
    "libxml2": "xml",
    "libz": "compression",
    "liblzma": "compression",
    "libcompression": "compression",
    "libcurl": "network",
    "libnetwork": "network",
    "libicucore": "unicode",
}


def guess_category(lib_name: str, fw_name: str) -> str:
    """Kütüphane adından kategori tahmin et."""
    # Önce framework adıyla dene
    if fw_name in CATEGORY_MAP:
        return CATEGORY_MAP[fw_name]
    # lib adıyla dene
    if lib_name in USRLIB_CATEGORY:
        return USRLIB_CATEGORY[lib_name]
    # Pattern-based
    lower = lib_name.lower()
    if "private" in lower or lower.startswith("_"):
        return "private_api"
    if "swift" in lower:
        return "swift_runtime"
    if "metal" in lower:
        return "graphics"
    if "audio" in lower or "sound" in lower:
        return "audio"
    if "network" in lower or "socket" in lower:
        return "network"
    if "crypto" in lower or "security" in lower or "ssl" in lower:
        return "crypto"
    if "ui" in lower and len(lower) < 15:
        return "ui"
    return "macos_system"


# ---- dyld_info ile export çıkarma ----
def extract_exports(lib_path: str) -> list[tuple[str, str]]:
    """
    dyld_info -exports ile bir kütüphanenin export'larını çıkar.
    Returns: list of (symbol_name, offset)
    """
    try:
        result = subprocess.run(
            ["dyld_info", "-exports", lib_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []

        exports = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Format: "0x000F1768  _CFAbsoluteTimeAddGregorianUnits"
            if line.startswith("0x"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    exports.append((parts[1], parts[0]))
            # Re-export format: "[re-export] _symbol (from libXXX)"
            elif line.startswith("[re-export]"):
                m = re.match(r'\[re-export\]\s+(\S+)', line)
                if m:
                    exports.append((m.group(1), "re-export"))
        return exports
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def clean_symbol(sym: str) -> str:
    """
    Sembol adını temizle:
    - Leading underscore kaldır (C convention)
    - ObjC method'ları koru
    """
    if not sym:
        return sym

    # ObjC: +[Class method] veya -[Class method] -> koru
    if sym.startswith("+[") or sym.startswith("-["):
        return sym

    # C++ mangled: __Z ile başlayanlar -> leading _ kaldır
    if sym.startswith("__Z"):
        return sym[1:]  # _ZNS... formatına dönüştür

    # Normal C: _ prefix kaldır
    if sym.startswith("_") and not sym.startswith("__"):
        return sym[1:]

    # __ ile başlayan internal semboller -> olduğu gibi bırak
    return sym


# ---- Mevcut DB yükleme ----
def load_existing_symbols() -> set[str]:
    """Tüm mevcut sig dosyalarındaki sembol adlarını yükle."""
    existing = set()

    for sig_file in SIGS_DIR.glob("*.json"):
        # Kendi çıktımızı atla
        if sig_file.name == "dyld_cache_exports.json":
            continue
        try:
            with open(sig_file) as f:
                data = json.load(f)

            sigs = data.get("signatures", [])
            if isinstance(sigs, list):
                for s in sigs:
                    name = s.get("name", "")
                    if name:
                        existing.add(name)
                        # Underscore varyantlarını da ekle
                        cleaned = clean_symbol(name)
                        if cleaned:
                            existing.add(cleaned)
            elif isinstance(sigs, dict):
                for name in sigs:
                    existing.add(name)
                    cleaned = clean_symbol(name)
                    if cleaned:
                        existing.add(cleaned)
        except (json.JSONDecodeError, KeyError, OSError) as e:
            print(f"  [WARN] {sig_file.name} yüklenemedi: {e}", file=sys.stderr)

    return existing


# ---- Ana fonksiyon ----
def main():
    start_time = time.time()

    print("=" * 60)
    print("dyld_shared_cache Export Signature Generator")
    print("=" * 60)

    # 1. Cache map'ten kütüphane yollarını çıkar
    print(f"\n[1/4] Cache map okunuyor: {DYLD_CACHE_MAP}")
    lib_paths = []
    with open(DYLD_CACHE_MAP) as f:
        for line in f:
            line = line.strip()
            if line.startswith("/"):
                lib_paths.append(line)

    print(f"  {len(lib_paths)} kütüphane yolu bulundu")

    # 2. Mevcut DB yükle
    print(f"\n[2/4] Mevcut signature DB yükleniyor...")
    existing_symbols = load_existing_symbols()
    print(f"  {len(existing_symbols)} mevcut sembol yüklendi (dedup için)")

    # 3. Her kütüphane için export çıkar
    print(f"\n[3/4] Export'lar çıkarılıyor ({len(lib_paths)} kütüphane)...")

    all_signatures = {}  # name -> {lib, purpose, category}
    lib_stats = defaultdict(int)
    errors = 0
    skipped_sip = 0
    total_raw = 0
    duplicates_within = 0  # Aynı sembol farklı kütüphanelerde

    # Thread pool ile parallel çalıştır (dyld_info I/O bound)
    def process_lib(lib_path):
        exports = extract_exports(lib_path)
        fw_name = framework_name_from_path(lib_path)
        lib_name = lib_name_from_path(lib_path)
        category = guess_category(lib_name, fw_name)

        results = []
        for sym, offset in exports:
            cleaned = clean_symbol(sym)
            if not cleaned:
                continue
            # Çok kısa semboller genelde işe yaramaz
            if len(cleaned) < 2:
                continue
            results.append((cleaned, fw_name, category, sym))

        return lib_path, fw_name, results

    processed = 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_lib, lp): lp for lp in lib_paths}

        for future in as_completed(futures):
            processed += 1
            if processed % 500 == 0:
                print(f"  ... {processed}/{len(lib_paths)} işlendi")

            try:
                lib_path, fw_name, results = future.result()

                if not results:
                    # Muhtemelen SIP korumalı veya boş
                    skipped_sip += 1
                    continue

                for cleaned, fw, cat, raw_sym in results:
                    total_raw += 1
                    if cleaned in all_signatures:
                        duplicates_within += 1
                        # Daha spesifik kütüphaneyi tercih et (framework > dylib)
                        existing_lib = all_signatures[cleaned]["lib"]
                        if ".framework" in lib_path and ".framework" not in existing_lib:
                            all_signatures[cleaned] = {
                                "lib": fw,
                                "purpose": "",
                                "category": cat
                            }
                    else:
                        all_signatures[cleaned] = {
                            "lib": fw,
                            "purpose": "",
                            "category": cat
                        }

                lib_stats[fw_name] += len(results)

            except Exception as e:
                errors += 1

    print(f"  Toplam raw export: {total_raw}")
    print(f"  Unique sembol: {len(all_signatures)}")
    print(f"  Kütüphane-içi duplicate: {duplicates_within}")
    print(f"  SIP/boş atlanma: {skipped_sip}")
    print(f"  Hata: {errors}")

    # 4. Dedup - mevcut DB ile karşılaştır
    print(f"\n[4/4] Mevcut DB ile dedup yapılıyor...")

    net_new = {}
    overlap_count = 0

    for name, info in all_signatures.items():
        if name in existing_symbols:
            overlap_count += 1
        else:
            net_new[name] = info

    print(f"  Overlap (mevcut DB'de zaten var): {overlap_count}")
    print(f"  NET NEW sembol: {len(net_new)}")

    # İstatistik: kategori başına
    cat_stats = defaultdict(int)
    for info in net_new.values():
        cat_stats[info["category"]] += 1

    print(f"\n  Kategori dağılımı (net new):")
    for cat, count in sorted(cat_stats.items(), key=lambda x: -x[1])[:20]:
        print(f"    {cat}: {count}")

    # Top kütüphaneler (net new)
    lib_new_stats = defaultdict(int)
    for info in net_new.values():
        lib_new_stats[info["lib"]] += 1

    print(f"\n  Top 20 kütüphane (net new):")
    for lib, count in sorted(lib_new_stats.items(), key=lambda x: -x[1])[:20]:
        print(f"    {lib}: {count}")

    # JSON çıktı - görevdeki format: dict-based signatures
    output = {
        "meta": {
            "generator": "karadul-sig-gen-dyld",
            "date": "2026-04-05",
            "source": "dyld_shared_cache_arm64e",
            "libraries_scanned": len(lib_paths),
            "libraries_with_exports": len(lib_paths) - skipped_sip - errors,
            "total_raw_exports": total_raw,
            "unique_symbols": len(all_signatures),
            "overlap_with_existing_db": overlap_count,
            "net_new_symbols": len(net_new),
            "elapsed_seconds": round(time.time() - start_time, 1)
        },
        "signatures": net_new,
        "total": len(net_new)
    }

    # Ayrıca full (dedup öncesi) versiyonu da kaydet
    full_output = {
        "meta": {
            "generator": "karadul-sig-gen-dyld",
            "date": "2026-04-05",
            "source": "dyld_shared_cache_arm64e",
            "note": "ALL exports including overlaps with existing DB",
            "libraries_scanned": len(lib_paths),
            "total_symbols": len(all_signatures)
        },
        "signatures": all_signatures,
        "total": len(all_signatures)
    }

    print(f"\n  Yazılıyor: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    file_size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"  Dosya boyutu: {file_size_mb:.1f} MB")

    # Full versiyonu da kaydet
    full_path = SIGS_DIR / "dyld_cache_exports_full.json"
    print(f"  Yazılıyor (full): {full_path}")
    with open(full_path, "w") as f:
        json.dump(full_output, f, indent=2, ensure_ascii=False)
    full_size_mb = os.path.getsize(full_path) / (1024 * 1024)
    print(f"  Dosya boyutu (full): {full_size_mb:.1f} MB")

    elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"TAMAMLANDI - {elapsed:.1f} saniye")
    print(f"  {len(net_new)} net new sembol → {OUTPUT_FILE.name}")
    print(f"  {len(all_signatures)} toplam sembol → {full_path.name}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
