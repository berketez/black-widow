#!/usr/bin/env python3
"""
Homebrew Kurulu Paketlerden Deep Signature Cikarma
===================================================
/opt/homebrew/lib/ ve /opt/homebrew/Cellar/ altindaki tum
.dylib, .a, .so dosyalarindan fonksiyon sembollerini cikarir.

Cikti: sigs/homebrew_deep.json
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --- Konfigürasyon ---
SEARCH_DIRS = ["/opt/homebrew/lib", "/opt/homebrew/Cellar"]
EXTENSIONS = {".dylib", ".a", ".so"}
OUTPUT_PATH = "/Users/apple/Desktop/black-widow/sigs/homebrew_deep.json"


def find_library_files():
    """Tum .dylib, .a, .so dosyalarini bul. Symlink'leri coz."""
    files = []
    seen_realpaths = set()

    for search_dir in SEARCH_DIRS:
        if not os.path.isdir(search_dir):
            print(f"  [SKIP] Dizin yok: {search_dir}")
            continue

        for root, dirs, filenames in os.walk(search_dir, followlinks=True):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1]

                # .dylib.X.Y.Z gibi uzantilar icin kontrol
                # libfoo.3.dylib veya libfoo.dylib.3 olabilir
                base = fname
                if ext not in EXTENSIONS:
                    # libfoo.3.2.1.dylib gibi durumlar
                    # veya libfoo.dylib.3 (nadir ama olabilir)
                    parts = fname.split(".")
                    has_valid_ext = any(("." + p) in EXTENSIONS for p in parts)
                    if not has_valid_ext:
                        continue

                # Symlink coz, ayni dosyayi tekrar isleme
                try:
                    realpath = os.path.realpath(fpath)
                except OSError:
                    continue

                if realpath in seen_realpaths:
                    continue
                seen_realpaths.add(realpath)

                if not os.path.isfile(realpath):
                    continue

                files.append((fpath, realpath))

    return files


def extract_lib_name(filepath, realpath=None):
    """
    Dosya yolundan kutuphane adini cikar.
    Oncelikle realpath'ten Cellar bilgisini kullanir (symlink durumu).

    /opt/homebrew/Cellar/openssl@3/3.1.0/lib/libssl.dylib -> "openssl"
    /opt/homebrew/Cellar/ffmpeg/8.1/lib/libavcodec.62.28.100.dylib -> "ffmpeg"
    /opt/homebrew/lib/libgmp.dylib -> "gmp" (realpath Cellar'da degilse)
    """
    # Hem filepath hem realpath'te Cellar ara (realpath oncelikli)
    for path in [realpath, filepath]:
        if path is None:
            continue
        cellar_match = re.search(r"/opt/homebrew/Cellar/([^/]+)/", path)
        if cellar_match:
            pkg = cellar_match.group(1)
            # openssl@3 -> openssl, python@3.13 -> python
            pkg = re.sub(r"@.*$", "", pkg)
            return pkg

    # /opt/homebrew/lib/ altindaki dosyalar icin dosya adindan cikar
    basename = os.path.basename(filepath)
    name = basename

    # lib prefix'ini kaldir
    if name.startswith("lib"):
        name = name[3:]

    # Uzantiyi ve versiyon numaralarini temizle
    # libfoo.3.2.1.dylib -> foo
    parts = name.split(".")
    name = parts[0]

    # Bos kalirsa basename'i dondur
    if not name:
        name = basename.split(".")[0]

    return name


def run_nm(filepath, is_static):
    """
    nm calistir ve sembol isimlerini dondur.
    .a dosyalari icin nm -g, digerleri icin nm -gU.
    """
    if is_static:
        cmd = ["nm", "-g", filepath]
    else:
        cmd = ["nm", "-gU", filepath]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        symbols = []
        for line in result.stdout.splitlines():
            # Format: "0000000000047500 T _func_name"
            # veya sadece "                 U _func_name" (undefined - bunu atliyoruz)
            parts = line.split()
            if len(parts) >= 3 and parts[-2] == "T":
                sym = parts[-1]
                # macOS underscore prefix'ini kaldir
                if sym.startswith("_"):
                    sym = sym[1:]
                symbols.append(sym)
            elif len(parts) == 2 and parts[0] == "T":
                # Bazi formatlarda adres olmayabilir
                sym = parts[1]
                if sym.startswith("_"):
                    sym = sym[1:]
                symbols.append(sym)
        return symbols
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as e:
        return []


def demangle_symbols(mangled_list):
    """
    c++filt ile toplu demangle. Buyuk listeleri chunk'lara boler.
    Dondu: {mangled_name: demangled_name}
    """
    result = {}
    CHUNK = 5000  # c++filt'e bir seferde gonderilecek sembol sayisi

    for i in range(0, len(mangled_list), CHUNK):
        chunk = mangled_list[i:i + CHUNK]
        # macOS c++filt cift underscore bekler: _Zfoo -> __Zfoo olarak gonder
        input_text = "\n".join("_" + s for s in chunk)
        try:
            proc = subprocess.run(
                ["c++filt"],
                input=input_text,
                capture_output=True,
                text=True,
                timeout=60
            )
            demangled = proc.stdout.splitlines()
            for orig, dem in zip(chunk, demangled):
                result[orig] = dem.strip()
        except (subprocess.TimeoutExpired, OSError):
            # c++filt yoksa veya hata verirse mangled haliyle birak
            for sym in chunk:
                result[sym] = sym
    return result


def main():
    print("=" * 60)
    print("Homebrew Deep Signature Generator")
    print("=" * 60)

    # 1. Dosyalari bul
    print("\n[1/3] Kutuphane dosyalari araniyor...")
    files = find_library_files()
    print(f"  Bulunan: {len(files)} benzersiz kutuphane dosyasi")

    if not files:
        print("HATA: Hic kutuphane dosyasi bulunamadi!")
        sys.exit(1)

    # 2. Sembol cikar
    print("\n[2/3] Semboller cikariliyor...")
    signatures = {}
    lib_stats = defaultdict(int)  # lib_name -> symbol_count
    errors = 0
    skipped = 0

    for idx, (original_path, real_path) in enumerate(files):
        if (idx + 1) % 100 == 0 or idx == 0:
            print(f"  [{idx+1}/{len(files)}] isleniyor...")

        ext = os.path.splitext(real_path)[1]
        # .a dosyalarinin uzantisi her zaman .a, ama adi icinde .a olabilir
        is_static = real_path.endswith(".a")

        lib_name = extract_lib_name(original_path, real_path)
        symbols = run_nm(real_path, is_static)

        if not symbols:
            skipped += 1
            continue

        for sym in symbols:
            # C++ mangled isimleri de dahil et (demangled hali ayrica eklenebilir)
            # Ayni fonksiyon bircok lib'de olabilir, ilk bulunan kazanir
            if sym not in signatures:
                signatures[sym] = {
                    "lib": lib_name,
                    "purpose": "",
                    "category": "homebrew"
                }
                lib_stats[lib_name] += 1

    print(f"  Toplam: {len(signatures)} benzersiz sembol")
    print(f"  Hatali/bos: {skipped} dosya atildi")

    # 2b. C++ mangled sembolleri demangle et
    mangled = [s for s in signatures if s.startswith("_Z")]
    if mangled:
        print(f"\n[2b/4] C++ demangle: {len(mangled)} mangled sembol...")
        demangled_map = demangle_symbols(mangled)
        added = 0
        for mangled_sym, demangled_sym in demangled_map.items():
            if demangled_sym and demangled_sym != mangled_sym:
                if demangled_sym not in signatures:
                    signatures[demangled_sym] = {
                        "lib": signatures[mangled_sym]["lib"],
                        "purpose": "",
                        "category": "homebrew"
                    }
                    lib_stats[signatures[mangled_sym]["lib"]] += 1
                    added += 1
        print(f"  Demangled eklenen: {added} yeni sembol")

    # 3. JSON yaz
    print(f"\n[3/3] JSON yaziliyor...")
    output = {
        "meta": {
            "generator": "karadul-sig-gen-homebrew",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "Homebrew installed packages",
            "total_signatures": len(signatures),
            "total_libraries": len(lib_stats),
            "total_files_scanned": len(files),
            "files_with_symbols": len(files) - skipped
        },
        "signatures": signatures
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    fsize = os.path.getsize(OUTPUT_PATH)
    print(f"\n  Yazildi: {OUTPUT_PATH}")
    print(f"  Boyut: {fsize / 1024:.1f} KB")

    # Istatistikler
    print("\n" + "=" * 60)
    print("ISTATISTIKLER")
    print("=" * 60)
    print(f"  Toplam sembol: {len(signatures)}")
    print(f"  Toplam kutuphane: {len(lib_stats)}")
    print(f"\n  En cok sembol iceren 20 kutuphane:")
    for lib, count in sorted(lib_stats.items(), key=lambda x: -x[1])[:20]:
        print(f"    {lib:30s} {count:>6d}")


if __name__ == "__main__":
    main()
