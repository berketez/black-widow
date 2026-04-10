#!/usr/bin/env python3
"""
Karadul Signature Generator - Anaconda Python C Extensions
===========================================================
Anaconda kurulumundaki .so ve .dylib dosyalarindan fonksiyon sembollerini cikarir.

Calisma mantigi:
1. /opt/anaconda3/ altindaki .so ve .dylib dosyalarini bulur
2. nm -gU ile exported text sembollerini cikarir
3. Dosya yolundan library adini cikarir
4. Mevcut signature DB'leri ile overlap kontrolu yapar
5. Sonucu sigs/anaconda_symbols.json olarak kaydeder

Notlar:
- pkgs/ dizini atlanir (duplicate paket versiyonlari icerir)
- __pycache__ dizinleri atlanir
- Stripped binary'ler sessizce atlanir
"""

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ANACONDA_ROOT = Path("/opt/anaconda3")
SIGS_DIR = Path("/Users/apple/Desktop/black-widow/sigs")
OUTPUT_PATH = SIGS_DIR / "anaconda_symbols.json"

# pkgs/ altinda duplicate versiyonlar var, atla
SKIP_DIRS = {"pkgs", "__pycache__", ".git"}


def find_binaries(root: Path) -> list[Path]:
    """Anaconda altindaki tum .so ve .dylib dosyalarini bul.
    pkgs/ dizinini atla (duplicate versiyonlar icerir)."""
    binaries = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip unwanted directories (modifies dirnames in-place)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for fname in filenames:
            if fname.endswith(".so") or fname.endswith(".dylib"):
                binaries.append(Path(dirpath) / fname)
    return binaries


def extract_lib_name(filepath: Path) -> str:
    """Dosya yolundan library/paket adini cikar.

    Kurallar:
    - site-packages altindaysa: ilk dizin adi = paket adi
      ornek: .../site-packages/numpy/core/_multiarray.so -> "numpy"
    - .dylib dosyalarinda lib prefix'ini kaldir
      ornek: libopenblas.dylib -> "openblas"
    - .cpython-XXX-darwin.so pattern'ini temizle
    - Diger durumlarda dosya adi (extension'siz)
    """
    parts = filepath.parts

    # site-packages altinda mi?
    for i, part in enumerate(parts):
        if part == "site-packages" and i + 1 < len(parts):
            pkg_name = parts[i + 1]
            # Bazi paketler tek dosya olarak kurulur: _foo.cpython-312-darwin.so
            if pkg_name.endswith(".so") or pkg_name.endswith(".dylib"):
                pkg_name = _clean_extension_name(pkg_name)
            return pkg_name.lower().rstrip("_").replace("-", "_")

    # .dylib icin lib prefix'ini kaldir
    fname = filepath.stem  # extension'siz
    if filepath.suffix == ".dylib":
        # libfoo.0.dylib gibi durumlar: stem = libfoo.0
        # Tum versiyonlama suffix'lerini temizle
        base = filepath.name
        base = re.sub(r"\.dylib$", "", base)
        base = re.sub(r"\.\d+$", "", base)  # .0, .1 vs
        base = re.sub(r"\.\d+$", "", base)  # .0.0 icin tekrar
        base = re.sub(r"\.\d+$", "", base)  # .0.0.0 icin tekrar
        if base.startswith("lib"):
            base = base[3:]
        return base.lower() if base else fname.lower()

    # .cpython-XXX-darwin.so pattern'ini temizle
    return _clean_extension_name(filepath.name).lower()


def _clean_extension_name(name: str) -> str:
    """cpython ve platform suffix'lerini temizle."""
    # foo.cpython-312-darwin.so -> foo
    name = re.sub(r"\.cpython-\d+-.*\.so$", "", name)
    # foo.abi3.so -> foo
    name = re.sub(r"\.abi3\.so$", "", name)
    # foo.so -> foo
    name = re.sub(r"\.so$", "", name)
    # foo.dylib -> foo
    name = re.sub(r"\.dylib$", "", name)
    return name


def run_nm(filepath: Path) -> list[str]:
    """nm -gU ile exported text sembollerini cikar.
    Hata durumunda bos liste doner (stripped binary vs)."""
    try:
        result = subprocess.run(
            ["nm", "-gU", str(filepath)],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []

        symbols = []
        for line in result.stdout.splitlines():
            # Format: "address T symbol_name"
            parts = line.strip().split()
            if len(parts) >= 3 and parts[1] == "T":
                symbols.append(parts[2])
            elif len(parts) == 2 and parts[0] == "T":
                # Bazi ciktilarda adres olmayabilir
                symbols.append(parts[1])
        return symbols
    except (subprocess.TimeoutExpired, OSError):
        return []


def process_binary(filepath: Path) -> tuple[str, list[str]]:
    """Tek bir binary'yi isle: lib adi + sembol listesi dondur."""
    lib_name = extract_lib_name(filepath)
    symbols = run_nm(filepath)
    return lib_name, symbols


def load_existing_symbols() -> set[str]:
    """Mevcut signature DB'lerindeki tum sembol adlarini yukle (overlap kontrolu icin)."""
    existing = set()
    for json_file in SIGS_DIR.glob("*.json"):
        if json_file.name == "anaconda_symbols.json":
            continue  # Kendimizi atlayalim
        try:
            with open(json_file) as f:
                data = json.load(f)
            sigs = data.get("signatures", [])
            if isinstance(sigs, list):
                for s in sigs:
                    if "name" in s:
                        existing.add(s["name"])
            elif isinstance(sigs, dict):
                existing.update(sigs.keys())
        except (json.JSONDecodeError, OSError):
            pass
    return existing


def main():
    start_time = time.time()

    print(f"[1/5] Anaconda binary'leri araniyor: {ANACONDA_ROOT}")
    binaries = find_binaries(ANACONDA_ROOT)
    print(f"       {len(binaries)} dosya bulundu (.so + .dylib)")

    print(f"[2/5] Semboller cikariliyor (parallel)...")
    # Library bazinda sembol toplama
    lib_symbols: dict[str, set[str]] = defaultdict(set)
    files_processed = 0
    files_with_symbols = 0
    total_raw_symbols = 0

    # ThreadPool ile paralel nm calistir
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_binary, b): b for b in binaries}
        for future in as_completed(futures):
            lib_name, symbols = future.result()
            files_processed += 1
            if symbols:
                files_with_symbols += 1
                total_raw_symbols += len(symbols)
                lib_symbols[lib_name].update(symbols)

            # Ilerleme gostergesi
            if files_processed % 500 == 0:
                print(f"       {files_processed}/{len(binaries)} dosya islendi...")

    print(f"       {files_processed} dosya islendi, {files_with_symbols} dosyada sembol bulundu")
    print(f"       {total_raw_symbols} ham sembol (duplicate dahil)")

    # Unique sembol sayisi
    all_unique = set()
    for syms in lib_symbols.values():
        all_unique.update(syms)
    print(f"       {len(all_unique)} unique sembol")

    print(f"[3/5] Mevcut signature DB'leri yukleniyor (overlap kontrolu)...")
    existing_symbols = load_existing_symbols()
    print(f"       {len(existing_symbols)} mevcut sembol yuklendi")

    overlap = all_unique & existing_symbols
    new_only = all_unique - existing_symbols
    print(f"       Overlap: {len(overlap)} sembol")
    print(f"       Yeni (sadece Anaconda): {len(new_only)} sembol")

    print(f"[4/5] JSON olusturuluyor...")
    # Berke'nin istedigi format: dict bazli, key = func_name
    signatures = {}
    for lib_name, syms in sorted(lib_symbols.items()):
        for sym in sorted(syms):
            # Eger ayni sembol birden fazla lib'de varsa, ilkini tut
            if sym not in signatures:
                signatures[sym] = {
                    "lib": lib_name,
                    "purpose": "",
                    "category": "python_ext"
                }

    output = {
        "meta": {
            "generator": "karadul-sig-gen-anaconda",
            "date": "2026-04-05",
            "source": "Anaconda Python C extensions",
            "anaconda_root": str(ANACONDA_ROOT),
            "files_scanned": files_processed,
            "files_with_symbols": files_with_symbols,
            "total_raw_symbols": total_raw_symbols,
            "unique_symbols": len(signatures),
            "libraries": len(lib_symbols),
            "overlap_with_existing": len(overlap),
            "new_symbols": len(new_only),
            "library_stats": {
                lib: len(syms) for lib, syms in sorted(
                    lib_symbols.items(), key=lambda x: -len(x[1])
                )[:50]  # Top 50 library
            }
        },
        "signatures": signatures
    }

    print(f"[5/5] Kaydediliyor: {OUTPUT_PATH}")
    os.makedirs(OUTPUT_PATH.parent, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    file_size = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
    elapsed = time.time() - start_time

    print(f"\n{'='*60}")
    print(f"SONUC")
    print(f"{'='*60}")
    print(f"Taranan dosya:        {files_processed}")
    print(f"Sembol iceren dosya:  {files_with_symbols}")
    print(f"Library sayisi:       {len(lib_symbols)}")
    print(f"Unique sembol:        {len(signatures)}")
    print(f"Mevcut DB overlap:    {len(overlap)}")
    print(f"Yeni sembol:          {len(new_only)}")
    print(f"Dosya boyutu:         {file_size:.1f} MB")
    print(f"Sure:                 {elapsed:.1f} saniye")
    print(f"Kayit:                {OUTPUT_PATH}")
    print(f"{'='*60}")

    # Top 10 library
    print(f"\nTop 10 Library (sembol sayisina gore):")
    for lib, syms in sorted(lib_symbols.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  {lib:30s} {len(syms):>8,} sembol")


if __name__ == "__main__":
    main()
