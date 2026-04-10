#!/usr/bin/env python3
"""macOS system library ve Homebrew kutuphanelerinden FLIRT-benzeri imza cikarma.

Bu script, nm ile binary'lerden export sembollerini cikarir ve
SignatureDB'nin yukluyebilecegi JSON formatinda kaydeder.

Kullanim:
    # Tek bir binary'den cikar:
    python3 scripts/extract-flirt-sigs.py --target /usr/lib/libSystem.B.dylib --output sigs/libSystem.json

    # Homebrew kutuphanelerini tara:
    python3 scripts/extract-flirt-sigs.py --scan-homebrew --output sigs/homebrew_all.json

    # macOS system framework'lerini tara:
    python3 scripts/extract-flirt-sigs.py --scan-system --output sigs/macos_system.json

    # Her ikisini birden:
    python3 scripts/extract-flirt-sigs.py --scan-system --scan-homebrew --output sigs/all.json

Cikti formati (build-signature-db.py ile uyumlu):
    {
        "meta": {"generator": "extract-flirt-sigs", ...},
        "signatures": [
            {"name": "_SSL_CTX_new", "library": "openssl", "category": "openssl", ...},
            ...
        ],
        "total": 12345
    }
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def find_nm() -> str | None:
    """macOS system nm'sini bul (Anaconda nm dylib okuyamayabilir)."""
    for candidate in ["/usr/bin/nm", "/Library/Developer/CommandLineTools/usr/bin/nm"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("nm")


def find_brew() -> str | None:
    """Homebrew brew komutunu bul."""
    return shutil.which("brew")


# ---------------------------------------------------------------------------
# Symbol extraction
# ---------------------------------------------------------------------------

# nm cikti regex: "addr TYPE name"
import re
_NM_LINE_RE = re.compile(
    r"^(?P<addr>[0-9a-fA-F]+)\s+(?P<type>[TtDdBbSsCcUu])\s+(?P<name>\S+)$"
)

# Atlanacak sembol prefix'leri
_SKIP_PREFIXES = (
    "___", "ltmp", "l_", "L_", "GCC_except",
    "_OBJC_CLASS_$", "_OBJC_METACLASS_$", "_OBJC_IVAR_$",
    "__GLOBAL_", ".L", "radr://",
)


def extract_symbols(nm_path: str, binary_path: str) -> list[dict]:
    """nm ile binary'den export sembollerini cikar.

    Returns:
        [{"name": "_func", "library": "lib", ...}, ...] listesi.
    """
    try:
        result = subprocess.run(
            [nm_path, "-g", binary_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  HATA: nm calistirilamadi: {binary_path} -- {e}", file=sys.stderr)
        return []

    # Library adini dosya adindan turet
    lib_name = Path(binary_path).stem
    if lib_name.startswith("lib"):
        lib_name = lib_name[3:]
    # .B, .dylib vs suffix'leri temizle
    lib_name = lib_name.split(".")[0] if "." in lib_name else lib_name

    symbols = []
    seen = set()

    for line in result.stdout.splitlines():
        m = _NM_LINE_RE.match(line.strip())
        if not m:
            continue

        sym_type = m.group("type")
        name = m.group("name")

        # Sadece text (code) ve data sembolleri
        if sym_type.upper() not in ("T", "D", "S"):
            continue

        # Skip filtreleri
        skip = False
        for prefix in _SKIP_PREFIXES:
            if name.startswith(prefix):
                skip = True
                break
        if skip:
            continue

        # Cok kisa isimler
        clean = name.lstrip("_")
        if len(clean) < 2:
            continue

        # Duplikasyon
        if name in seen:
            continue
        seen.add(name)

        symbols.append({
            "name": name,
            "library": lib_name,
            "category": lib_name,
            "purpose": "",
            "confidence": 0.85,
        })

    return symbols


# ---------------------------------------------------------------------------
# System framework tarama
# ---------------------------------------------------------------------------

# macOS system framework konumlari
_SYSTEM_FRAMEWORK_DIRS = [
    "/System/Library/Frameworks",
    "/System/Library/PrivateFrameworks",
]

# Onemli system dylib'ler
_SYSTEM_DYLIBS = [
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/libz.1.dylib",
    "/usr/lib/libsqlite3.dylib",
    "/usr/lib/libxml2.2.dylib",
    "/usr/lib/libcurl.4.dylib",
    "/usr/lib/libresolv.9.dylib",
    "/usr/lib/libncurses.5.4.dylib",
    "/usr/lib/libiconv.2.dylib",
]

# En onemli framework'ler (hepsini taramak cok uzun surer)
_KEY_FRAMEWORKS = [
    "CoreFoundation", "Foundation", "Security", "IOKit",
    "SystemConfiguration", "CoreServices", "CFNetwork",
    "DiskArbitration", "CoreData", "WebKit",
    "CoreLocation", "CoreBluetooth", "CoreGraphics",
    "CoreImage", "CoreML", "Metal", "MetalKit",
    "AVFoundation", "CoreAudio", "AudioToolbox",
    "Network", "EndpointSecurity", "AppKit",
    "StoreKit", "UserNotifications",
]


def scan_system_frameworks(nm_path: str) -> list[dict]:
    """macOS system framework ve dylib'lerden sembol cikar."""
    all_symbols = []

    # System dylib'ler
    for dylib in _SYSTEM_DYLIBS:
        if os.path.exists(dylib):
            print(f"  Taraniyor: {dylib}")
            syms = extract_symbols(nm_path, dylib)
            all_symbols.extend(syms)

    # Key framework'ler
    for fw_dir in _SYSTEM_FRAMEWORK_DIRS:
        if not os.path.isdir(fw_dir):
            continue
        for fw_name in _KEY_FRAMEWORKS:
            fw_path = os.path.join(fw_dir, f"{fw_name}.framework", fw_name)
            if os.path.exists(fw_path):
                print(f"  Taraniyor: {fw_name}.framework")
                syms = extract_symbols(nm_path, fw_path)
                # Library adini framework adina ayarla
                for s in syms:
                    s["library"] = fw_name
                    s["category"] = fw_name
                all_symbols.extend(syms)

    return all_symbols


# ---------------------------------------------------------------------------
# Homebrew tarama
# ---------------------------------------------------------------------------

def get_homebrew_cellar() -> str | None:
    """Homebrew Cellar dizinini bul."""
    # Apple Silicon
    if os.path.isdir("/opt/homebrew/Cellar"):
        return "/opt/homebrew/Cellar"
    # Intel
    if os.path.isdir("/usr/local/Cellar"):
        return "/usr/local/Cellar"
    return None


def scan_homebrew(nm_path: str) -> list[dict]:
    """Homebrew kutuphanelerinden sembol cikar."""
    cellar = get_homebrew_cellar()
    if not cellar:
        print("HATA: Homebrew Cellar bulunamadi", file=sys.stderr)
        return []

    all_symbols = []
    packages = sorted(os.listdir(cellar))
    print(f"  Homebrew: {len(packages)} paket bulundu ({cellar})")

    for pkg in packages:
        pkg_dir = os.path.join(cellar, pkg)
        if not os.path.isdir(pkg_dir):
            continue

        # En son versiyonu al
        versions = sorted(os.listdir(pkg_dir))
        if not versions:
            continue
        latest = os.path.join(pkg_dir, versions[-1])

        # lib/ dizininde .dylib ve .a dosyalari ara
        lib_dir = os.path.join(latest, "lib")
        if not os.path.isdir(lib_dir):
            continue

        lib_files = []
        for root, dirs, files in os.walk(lib_dir):
            for f in files:
                if f.endswith((".dylib", ".a")) and not f.endswith(".dSYM"):
                    lib_files.append(os.path.join(root, f))

        if not lib_files:
            continue

        pkg_symbols = []
        for lib_file in lib_files[:5]:  # Her paket icin max 5 lib
            syms = extract_symbols(nm_path, lib_file)
            # Library adini paket adina ayarla
            for s in syms:
                s["library"] = pkg
                s["category"] = pkg
            pkg_symbols.extend(syms)

        if pkg_symbols:
            print(f"  {pkg}: {len(pkg_symbols)} sembol")
            all_symbols.extend(pkg_symbols)

    return all_symbols


# ---------------------------------------------------------------------------
# Tek binary extraction
# ---------------------------------------------------------------------------

def scan_target(nm_path: str, target: str) -> list[dict]:
    """Tek bir binary'den sembol cikar."""
    if not os.path.exists(target):
        print(f"HATA: Dosya bulunamadi: {target}", file=sys.stderr)
        return []

    print(f"  Taraniyor: {target}")
    return extract_symbols(nm_path, target)


# ---------------------------------------------------------------------------
# Deduplicate
# ---------------------------------------------------------------------------

def deduplicate(symbols: list[dict]) -> list[dict]:
    """Ayni isme sahip sembolleri tekil yap (ilk bulunan kazanir)."""
    seen: set[str] = set()
    result: list[dict] = []
    for s in symbols:
        if s["name"] not in seen:
            seen.add(s["name"])
            result.append(s)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="macOS system + Homebrew kutuphanelerinden FLIRT-benzeri imza cikarma",
    )
    parser.add_argument(
        "--target", "-t",
        help="Tek bir binary dosya yolu",
    )
    parser.add_argument(
        "--scan-system", "-s",
        action="store_true",
        help="macOS system framework ve dylib'leri tara",
    )
    parser.add_argument(
        "--scan-homebrew", "-b",
        action="store_true",
        help="Homebrew kutuphanelerini tara",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Cikti JSON dosyasi yolu",
    )

    args = parser.parse_args()

    if not args.target and not args.scan_system and not args.scan_homebrew:
        parser.error("En az bir kaynak belirtilmeli: --target, --scan-system, --scan-homebrew")

    # nm kontrolu
    nm_path = find_nm()
    if not nm_path:
        print("HATA: nm araci bulunamadi", file=sys.stderr)
        sys.exit(1)
    print(f"nm: {nm_path}")

    start_time = time.time()
    all_symbols: list[dict] = []

    # Tek binary
    if args.target:
        syms = scan_target(nm_path, args.target)
        all_symbols.extend(syms)

    # System frameworks
    if args.scan_system:
        print("\n=== macOS System Framework Taramasi ===")
        syms = scan_system_frameworks(nm_path)
        all_symbols.extend(syms)

    # Homebrew
    if args.scan_homebrew:
        print("\n=== Homebrew Kutuphane Taramasi ===")
        syms = scan_homebrew(nm_path)
        all_symbols.extend(syms)

    # Deduplicate
    before = len(all_symbols)
    all_symbols = deduplicate(all_symbols)
    after = len(all_symbols)

    elapsed = time.time() - start_time

    print(f"\n=== Sonuc ===")
    print(f"Toplam sembol: {before} (deduplicate sonrasi: {after})")
    print(f"Sure: {elapsed:.1f}s")

    # JSON kaydet
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "meta": {
            "generator": "extract-flirt-sigs",
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "nm_path": nm_path,
            "sources": [],
        },
        "signatures": all_symbols,
        "total": len(all_symbols),
    }

    if args.target:
        data["meta"]["sources"].append({"type": "target", "path": args.target})
    if args.scan_system:
        data["meta"]["sources"].append({"type": "system_frameworks"})
    if args.scan_homebrew:
        data["meta"]["sources"].append({"type": "homebrew"})

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"Cikti: {output_path} ({output_path.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
