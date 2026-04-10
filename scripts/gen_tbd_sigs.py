#!/usr/bin/env python3
"""
macOS SDK .tbd Stub Dosyalarından Sembol Çıkarıcı
==================================================
Xcode / CommandLineTools SDK'daki .tbd (text-based stub) dosyalarını parse ederek
fonksiyon ve sınıf isimlerini Karadul signature DB formatında çıkarır.

.tbd format (tbd-version: 4):
  - exports: / reexported-symbols: bloklarının altındaki
    symbols: [...] ve objc-classes: [...] listelerini parse eder.
  - `_` prefix'i Mach-O convention'ı — kaldırılır.
  - `$ld$previous$...` gibi linker directive'leri ve Swift mangled
    semboller (`_$s...`) filtrelenir (okunaksız, signature olarak faydasız).

Kullanım:
  python3 gen_tbd_sigs.py
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Ayarlar
# ---------------------------------------------------------------------------
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "sigs" / "sdk_tbd_symbols.json"

# SDK path'i bul
def find_sdk_paths():
    """Mevcut tüm macOS SDK'ları bul."""
    sdks = []

    # 1) xcrun ile aktif SDK
    try:
        result = subprocess.run(
            ["xcrun", "--show-sdk-path"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            p = result.stdout.strip()
            if os.path.isdir(p):
                sdks.append(p)
    except Exception:
        pass

    # 2) CommandLineTools altındaki SDK'lar
    clt_base = Path("/Library/Developer/CommandLineTools/SDKs")
    if clt_base.is_dir():
        for d in sorted(clt_base.iterdir()):
            if d.is_dir() and d.name.startswith("MacOSX") and d.name.endswith(".sdk"):
                rp = str(d.resolve())
                if rp not in sdks:
                    sdks.append(rp)

    # 3) Xcode SDK'ları (varsa)
    xcode_base = Path("/Applications")
    if xcode_base.is_dir():
        for app in sorted(xcode_base.iterdir()):
            if app.name.startswith("Xcode") and app.name.endswith(".app"):
                plat = app / "Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs"
                if plat.is_dir():
                    for d in sorted(plat.iterdir()):
                        if d.is_dir() and d.name.endswith(".sdk"):
                            rp = str(d.resolve())
                            if rp not in sdks:
                                sdks.append(rp)

    return sdks


# ---------------------------------------------------------------------------
# .tbd Parser (regex-based, YAML parser gereksiz)
# ---------------------------------------------------------------------------

# Sembolleri yakalayan regex: symbols: [ ... ] (çok satırlı)
# .tbd format çok tutarlı - her zaman [ ] içinde, virgülle ayrılmış
RE_SYMBOLS_BLOCK = re.compile(
    r'(?:^|\n)\s+symbols:\s*\[([^\]]*)\]',
    re.DOTALL
)
RE_OBJC_CLASSES_BLOCK = re.compile(
    r'(?:^|\n)\s+objc-classes:\s*\[([^\]]*)\]',
    re.DOTALL
)

# Filtreleme: bu pattern'ler signature olarak faydasız
SKIP_PATTERNS = (
    "$ld$",           # Linker directive
    "$ld$previous$",  # Eski versiyon uyumluluk
    ".eh",            # Exception handling frame
)


def should_skip_symbol(sym: str) -> bool:
    """Faydasız sembolleri filtrele."""
    # Linker directives
    if "$ld$" in sym:
        return True
    # Swift mangled names: _$s..., _$S... — bunlar okunaksız
    # Ama bazı Swift semboller anlamlı olabilir, sadece $s/$S ile başlayanları atla
    if sym.startswith("$s") or sym.startswith("$S"):
        return True
    # Çok kısa (1-2 char) anlamsız semboller
    if len(sym) <= 1:
        return True
    # .eh exception handling
    if sym.endswith(".eh"):
        return True
    return False


def extract_lib_name(tbd_path: str, install_name: str = "") -> str:
    """Library adını çıkar. Önce install-name'den, yoksa dosya adından."""
    if install_name:
        # '/usr/lib/libz.1.dylib' -> 'libz'
        # '/System/Library/Frameworks/Network.framework/...' -> 'Network'
        base = os.path.basename(install_name)
        # .dylib kaldır
        name = re.sub(r'\.(\d+\.)*dylib$', '', base)
        # Framework ise
        if "/Frameworks/" in install_name:
            parts = install_name.split("/")
            for p in parts:
                if p.endswith(".framework"):
                    name = p.replace(".framework", "")
                    break
        return name

    # Dosya adından
    base = os.path.basename(tbd_path)
    name = base.replace(".tbd", "")
    # Versiyonları temizle: libz.1.2.11 -> libz
    name = re.sub(r'\.\d+(\.\d+)*$', '', name)
    return name


def parse_tbd_file(filepath: str) -> tuple:
    """
    Tek bir .tbd dosyasını parse et.

    Returns:
        (lib_name, symbols_set, objc_classes_set)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except (IOError, OSError):
        return ("", set(), set())

    # install-name çıkar
    install_match = re.search(r"install-name:\s*'([^']*)'", content)
    install_name = install_match.group(1) if install_match else ""

    lib_name = extract_lib_name(filepath, install_name)

    # --- Semboller ---
    symbols = set()
    for m in RE_SYMBOLS_BLOCK.finditer(content):
        raw = m.group(1)
        # Virgülle ayrılmış, opsiyonel whitespace/newline
        # Tek tırnakla sarılı veya sarılmamış olabilir
        for token in re.split(r',\s*', raw):
            token = token.strip().strip("'\"")
            if not token:
                continue
            # _ prefix kaldır (Mach-O convention)
            if token.startswith("_"):
                token = token[1:]
            if should_skip_symbol(token):
                continue
            symbols.add(token)

    # --- ObjC Classes ---
    objc_classes = set()
    for m in RE_OBJC_CLASSES_BLOCK.finditer(content):
        raw = m.group(1)
        for token in re.split(r',\s*', raw):
            token = token.strip().strip("'\"")
            if not token:
                continue
            objc_classes.add(token)

    return (lib_name, symbols, objc_classes)


# ---------------------------------------------------------------------------
# Ana iş
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("macOS SDK .tbd Stub Parser")
    print("=" * 60)

    # SDK'ları bul
    sdk_paths = find_sdk_paths()
    if not sdk_paths:
        print("HATA: Hiçbir macOS SDK bulunamadı!")
        sys.exit(1)

    print(f"\nBulunan SDK'lar ({len(sdk_paths)}):")
    for p in sdk_paths:
        print(f"  - {p}")

    # Tüm .tbd dosyalarını topla (tüm SDK'lardan, deduplicate)
    tbd_files = set()
    for sdk in sdk_paths:
        sdk_path = Path(sdk)
        for tbd in sdk_path.rglob("*.tbd"):
            # Resolve symlink'leri -> aynı dosyayı iki kere parse etme
            resolved = str(tbd.resolve())
            tbd_files.add(resolved)

    print(f"\nToplam benzersiz .tbd dosyası: {len(tbd_files)}")

    # Parse et - iki geçiş:
    #   1) Temel sistem kütüphaneleri (libSystem, libc, libm, libpthread...)
    #   2) Geri kalan herşey
    # Bu sayede abort -> libSystem.B (OpenGL değil) doğru atanır.

    CORE_LIB_PATTERNS = (
        "/usr/lib/libSystem",
        "/usr/lib/system/",
        "/usr/lib/libc.",
        "/usr/lib/libm.",
        "/usr/lib/libpthread",
        "/usr/lib/libdl.",
        "/usr/lib/libobjc.",
    )

    def is_core_lib(tbd_path: str) -> bool:
        """Temel sistem kütüphanesi mi?"""
        for pat in CORE_LIB_PATTERNS:
            if pat in tbd_path:
                return True
        return False

    # .tbd dosyalarını öncelik sırasına göre ayır
    core_tbds = sorted(p for p in tbd_files if is_core_lib(p))
    other_tbds = sorted(p for p in tbd_files if not is_core_lib(p))
    ordered_tbds = core_tbds + other_tbds

    print(f"  Temel sistem kütüphaneleri: {len(core_tbds)}")
    print(f"  Diğer kütüphaneler: {len(other_tbds)}")

    all_signatures = {}  # name -> {"lib": ..., "purpose": "", "category": "macos_sdk"}
    lib_stats = {}       # lib_name -> symbol_count
    objc_count = 0

    for i, tbd_path in enumerate(ordered_tbds):
        if (i + 1) % 500 == 0:
            print(f"  [{i+1}/{len(ordered_tbds)}] işleniyor...")

        lib_name, symbols, objc_classes = parse_tbd_file(tbd_path)

        if not lib_name:
            continue

        count = 0

        # Normal semboller
        for sym in symbols:
            if sym not in all_signatures:
                all_signatures[sym] = {
                    "lib": lib_name,
                    "purpose": "",
                    "category": "macos_sdk"
                }
                count += 1

        # ObjC class'ları
        for cls in objc_classes:
            key = cls  # NSObject, UIView, etc.
            if key not in all_signatures:
                all_signatures[key] = {
                    "lib": lib_name,
                    "purpose": "objc_class",
                    "category": "macos_sdk"
                }
                count += 1
                objc_count += 1

        if count > 0:
            lib_stats[lib_name] = lib_stats.get(lib_name, 0) + count

    # İstatistikler
    print(f"\n{'=' * 60}")
    print(f"Sonuçlar:")
    print(f"  Toplam benzersiz sembol: {len(all_signatures):,}")
    print(f"  ObjC class sayısı:      {objc_count:,}")
    print(f"  Library sayısı:         {len(lib_stats):,}")

    # En çok sembolü olan kütüphaneler
    top_libs = sorted(lib_stats.items(), key=lambda x: -x[1])[:20]
    print(f"\nEn çok sembolü olan 20 kütüphane:")
    for lib, cnt in top_libs:
        print(f"  {lib:40s} {cnt:>8,}")

    # JSON oluştur
    output = {
        "meta": {
            "generator": "karadul-sig-gen-tbd",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "macOS SDK .tbd stubs",
            "sdk_paths": sdk_paths,
            "tbd_files_parsed": len(tbd_files),
            "total_libraries": len(lib_stats)
        },
        "signatures": all_signatures
    }

    # Kaydet
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    file_size = OUTPUT_PATH.stat().st_size / (1024 * 1024)
    print(f"\nKaydedildi: {OUTPUT_PATH}")
    print(f"Dosya boyutu: {file_size:.1f} MB")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
