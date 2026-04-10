#!/usr/bin/env python3
"""macOS system framework'lerinden signature cikarma.

Apple'in SDK'sindaki .tbd (text-based stub) dosyalarini parse ederek
tum export edilen sembolleri (C fonksiyonlari, ObjC class'lari, ObjC
ivar'lari) cikarir. Sonuclari SignatureDB'nin load_external_signatures()
metoduyla yuklenebilir JSON formatinda kaydeder.

Framework konumlari:
  - <SDK>/System/Library/Frameworks/   (AppKit, Foundation, CoreGraphics, vb.)
  - <SDK>/System/Library/PrivateFrameworks/ (opsiyonel)
  - <SDK>/usr/lib/                     (libSystem, libc++, libobjc, vb.)

SDK path otomatik bulunur: xcrun --show-sdk-path

tbd formati (v4):
    --- !tapi-tbd
    tbd-version: 4
    install-name: '/System/Library/Frameworks/AppKit.framework/...'
    exports:
      - targets: [x86_64-macos, arm64-macos]
        symbols: [_NSApp, _NSBeep, ...]
        objc-classes: [NSWindow, NSView, ...]
        objc-ivars: [NSWindow._contentView, ...]

Kullanim:
    python3 scripts/extract-macos-frameworks.py
    python3 scripts/extract-macos-frameworks.py --output sigs/macos_frameworks.json
    python3 scripts/extract-macos-frameworks.py --include-private --include-usr-lib
    python3 scripts/extract-macos-frameworks.py --frameworks AppKit,Foundation,CoreGraphics
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class TBDParseResult:
    """Bir tbd dosyasindan parse edilen veriler."""
    framework: str = ""
    install_name: str = ""
    tbd_path: str = ""
    symbols: list[str] = field(default_factory=list)
    objc_classes: list[str] = field(default_factory=list)
    objc_ivars: list[str] = field(default_factory=list)
    weak_symbols: list[str] = field(default_factory=list)

    @property
    def total_exports(self) -> int:
        return len(self.symbols) + len(self.objc_classes) + len(self.objc_ivars)


# ---------------------------------------------------------------------------
# Framework kategori haritasi
# ---------------------------------------------------------------------------

# Her framework icin hangi kategoriye ait oldugu
FRAMEWORK_CATEGORIES: dict[str, str] = {
    # UI frameworks
    "AppKit": "ui",
    "UIKit": "ui",
    "SwiftUI": "ui",
    "Cocoa": "ui",
    # Foundation
    "Foundation": "foundation",
    "CoreFoundation": "foundation",
    # Graphics
    "CoreGraphics": "graphics",
    "CoreImage": "graphics",
    "CoreAnimation": "graphics",
    "QuartzCore": "graphics",
    "ImageIO": "graphics",
    "Metal": "gpu",
    "MetalKit": "gpu",
    "MetalPerformanceShaders": "gpu",
    "MetalPerformanceShadersGraph": "gpu",
    "OpenGL": "gpu",
    "OpenCL": "gpu",
    # Audio / Video
    "AVFoundation": "media",
    "AVFAudio": "media",
    "AVKit": "media",
    "CoreAudio": "media",
    "CoreMedia": "media",
    "CoreVideo": "media",
    "AudioToolbox": "media",
    "AudioUnit": "media",
    "VideoToolbox": "media",
    "MediaPlayer": "media",
    "MediaToolbox": "media",
    # Security
    "Security": "security",
    "CryptoKit": "security",
    "CryptoTokenKit": "security",
    "LocalAuthentication": "security",
    "AuthenticationServices": "security",
    # Networking
    "Network": "networking",
    "CFNetwork": "networking",
    "NetworkExtension": "networking",
    "MultipeerConnectivity": "networking",
    # Data / Storage
    "CoreData": "data",
    "CloudKit": "data",
    "SQLite3": "data",
    # System
    "IOKit": "system",
    "SystemConfiguration": "system",
    "DiskArbitration": "system",
    "IOSurface": "system",
    "Kernel": "system",
    "EndpointSecurity": "system",
    "SystemExtensions": "system",
    # Web
    "WebKit": "web",
    "JavaScriptCore": "web",
    "SafariServices": "web",
    # Location / Sensor
    "CoreLocation": "location",
    "CoreMotion": "sensor",
    "CoreBluetooth": "bluetooth",
    # ML / AI
    "CoreML": "ml",
    "NaturalLanguage": "ml",
    "Vision": "ml",
    "SoundAnalysis": "ml",
    "CreateML": "ml",
    # Other Apple
    "Combine": "reactive",
    "ObjectiveC": "runtime",
    "Accessibility": "accessibility",
    "StoreKit": "commerce",
    "UserNotifications": "notifications",
    "MapKit": "maps",
    "Contacts": "contacts",
    "EventKit": "calendar",
    "Photos": "photos",
    "PDFKit": "pdf",
    "SceneKit": "3d",
    "SpriteKit": "2d",
    "GameKit": "gaming",
    "GameplayKit": "gaming",
    "GameController": "gaming",
    "ARKit": "ar",
    "RealityKit": "ar",
    "Accelerate": "math",
    "LDAP": "directory",
    "OSLog": "logging",
    "HealthKit": "health",
    "HomeKit": "home",
    "PassKit": "wallet",
    "NotificationCenter": "notifications",
    "ServiceManagement": "system",
}

# Oncelik sirasi -- en yuksek oncelikteki framework'ler once islenir
PRIORITY_FRAMEWORKS = [
    "AppKit",
    "Foundation",
    "CoreFoundation",
    "CoreGraphics",
    "Security",
    "ObjectiveC",
    "SwiftUI",
    "Combine",
    "UIKit",
    "CoreData",
    "WebKit",
    "AVFoundation",
    "Metal",
    "IOKit",
    "SystemConfiguration",
    "CoreAnimation",
    "QuartzCore",
    "CoreImage",
    "CoreAudio",
    "CoreMedia",
    "CoreVideo",
    "Network",
    "CFNetwork",
    "Accelerate",
    "CoreML",
    "Vision",
    "NaturalLanguage",
    "JavaScriptCore",
    "CoreLocation",
    "CoreBluetooth",
    "MapKit",
    "StoreKit",
    "CloudKit",
    "Contacts",
    "Photos",
    "PDFKit",
    "GameKit",
    "SceneKit",
    "SpriteKit",
    "ARKit",
    "Accessibility",
    "UserNotifications",
    "EventKit",
    "MultipeerConnectivity",
    "AudioToolbox",
    "AudioUnit",
    "ImageIO",
    "VideoToolbox",
    "LocalAuthentication",
    "AuthenticationServices",
    "EndpointSecurity",
    "ServiceManagement",
    "DiskArbitration",
]


# ---------------------------------------------------------------------------
# tbd parser
# ---------------------------------------------------------------------------

def parse_tbd_file(tbd_path: str | Path) -> TBDParseResult:
    """Apple tbd (text-based stub) dosyasini parse et.

    tbd dosyalari YAML benzeri formatta ama standart YAML degil.
    Ozellikle [ ] icindeki listeler cok satirli olabilir ve
    satirlar virgul + bosluk ile devam edebilir.

    Strateji:
    - Satir satir oku
    - 'exports:' blogunun icindeki 'symbols:', 'objc-classes:',
      'objc-ivars:', 'weak-symbols:' listelerini topla
    - Listelerdeki [ ] arasindaki isimleri parse et
    """
    tbd_path = Path(tbd_path)
    result = TBDParseResult(tbd_path=str(tbd_path))

    try:
        content = tbd_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        print(f"  UYARI: {tbd_path} okunamiyor: {exc}", file=sys.stderr)
        return result

    # install-name'den framework adini cikar
    m = re.search(r"install-name:\s*'([^']+)'", content)
    if m:
        result.install_name = m.group(1)
        # /System/Library/Frameworks/AppKit.framework/... -> AppKit
        parts = result.install_name.split("/")
        for part in parts:
            if part.endswith(".framework"):
                result.framework = part.replace(".framework", "")
                break
        if not result.framework:
            # /usr/lib/libobjc.A.dylib -> libobjc
            for part in reversed(parts):
                if part.startswith("lib") and (".dylib" in part or ".tbd" in part):
                    result.framework = re.sub(r"\..*$", "", part)
                    break
            if not result.framework:
                result.framework = parts[-1] if parts else tbd_path.stem

    if not result.framework:
        result.framework = tbd_path.stem

    # tbd dosyasini satir satir parse et
    lines = content.split("\n")
    in_exports = False
    in_reexports = False
    current_field = None  # "symbols", "objc-classes", "objc-ivars", "weak-symbols"
    bracket_buffer = ""
    bracket_depth = 0

    for line in lines:
        stripped = line.strip()

        # Bos satir veya yorum
        if not stripped or stripped.startswith("#"):
            continue

        # exports: blogu basladimi?
        if stripped == "exports:" or stripped.startswith("exports:"):
            in_exports = True
            in_reexports = False
            continue

        # re-exports blogu -- bunlari da dahil edebiliriz ama ayri tutabiliriz
        if stripped == "re-exports:" or stripped.startswith("re-exports:"):
            in_exports = True  # re-exports'lari da al
            in_reexports = True
            continue

        # Diger top-level bloklar exports'u kapatir
        if not line.startswith(" ") and not line.startswith("\t"):
            if stripped.endswith(":") and stripped not in ("exports:", "re-exports:"):
                in_exports = False
                current_field = None
                bracket_buffer = ""
                bracket_depth = 0
                continue

        if not in_exports:
            continue

        # exports icindeki alt-alanlari tani
        # "symbols:", "objc-classes:", "objc-ivars:", "weak-symbols:"
        for field_name in ("symbols", "objc-classes", "objc-ivars", "weak-symbols"):
            if f"{field_name}:" in stripped:
                current_field = field_name
                # Ayni satirda [ basladimi?
                idx = stripped.index(f"{field_name}:")
                rest = stripped[idx + len(field_name) + 1:].strip()
                bracket_buffer = rest
                bracket_depth = rest.count("[") - rest.count("]")
                if bracket_depth <= 0 and "[" in rest:
                    # Tamamen ayni satirda kapandi
                    _extract_names(bracket_buffer, result, current_field)
                    bracket_buffer = ""
                    bracket_depth = 0
                    current_field = None if bracket_depth <= 0 else current_field
                break
        else:
            # Devam satiri mi?
            if current_field and bracket_depth > 0:
                bracket_buffer += " " + stripped
                bracket_depth += stripped.count("[") - stripped.count("]")
                if bracket_depth <= 0:
                    _extract_names(bracket_buffer, result, current_field)
                    bracket_buffer = ""
                    bracket_depth = 0
                    current_field = None
            elif current_field and bracket_depth == 0 and bracket_buffer:
                # Onceki alan tamamlandi, yeni alana bakilmali
                pass

    # Eger buffer'da kalan varsa (dosya sonunda kapanmamis bracket)
    if bracket_buffer and current_field:
        _extract_names(bracket_buffer, result, current_field)

    return result


def _extract_names(
    bracket_text: str,
    result: TBDParseResult,
    field_name: str,
) -> None:
    """[ ... ] icindeki isimleri cikar ve sonuca ekle.

    Isimler virgul ile ayrilmis, bazi isimler tek tirnak icinde olabilir.
    Ornek: [ _NSApp, _NSBeep, '__swift_FORCE_LOAD_$_swiftAppKit' ]
    """
    # Bracket'lari temizle
    text = bracket_text.strip()
    if text.startswith("["):
        text = text[1:]
    if text.endswith("]"):
        text = text[:-1]

    # Virgul ile ayir
    parts = text.split(",")
    names = []
    for part in parts:
        name = part.strip().strip("'\"")
        if name:
            names.append(name)

    # Hedef listeye ekle
    if field_name == "symbols":
        result.symbols.extend(names)
    elif field_name == "objc-classes":
        result.objc_classes.extend(names)
    elif field_name == "objc-ivars":
        result.objc_ivars.extend(names)
    elif field_name == "weak-symbols":
        result.weak_symbols.extend(names)


# ---------------------------------------------------------------------------
# Sembol filtreleme
# ---------------------------------------------------------------------------

# Bu semboller noise -- linker hint'leri, versiyonlama vs.
_NOISE_PREFIXES = (
    "$ld$",           # linker directive (ld$add, ld$hide, ld$previous)
    "$ld$previous$",
    "$ld$add$",
    "$ld$hide$",
    "$ld$install_name$",
    ".objc_class_name_",
)

_NOISE_PATTERNS = re.compile(
    r"^("
    r"\$ld\$"             # linker directives
    r"|\.objc_class_name_"  # old-style ObjC class names
    r"|_OBJC_EHTYPE_"      # ObjC exception type metadata (duplike, class zaten var)
    r"|_OBJC_METACLASS_"   # ObjC metaclass (duplike, class zaten var)
    r"|_OBJC_IVAR_"        # ObjC ivar (ivar listesinden zaten aliniyor)
    r")"
)


def is_useful_symbol(name: str) -> bool:
    """Sembolun kullanisli bir export olup olmadigini kontrol et.

    Linker directive'leri ($ld$...), metaclass'lar, ve diger
    gurultu sembollerini filtreler.
    """
    if not name:
        return False

    # Linker directive'leri -- hicbir zaman binary'de gorulmez
    if name.startswith("$ld$"):
        return False

    # Metaclass ve EHTYPE -- zaten objc-classes'tan aliniyor
    if _NOISE_PATTERNS.match(name):
        return False

    # Cok kisa isimler (tek karakter gibi) genelde noise
    stripped = name.lstrip("_")
    if len(stripped) < 2:
        return False

    return True


def classify_symbol(name: str) -> str:
    """Sembolun tipini belirle: c_func, objc_class, swift, constant, other."""
    if name.startswith("_OBJC_CLASS_$_"):
        return "objc_class"
    if name.startswith("_$s") or name.startswith("$s"):
        return "swift"
    if name.startswith("_") and name[1:2].isupper():
        # _NSWindow gibi -- muhtemelen C fonksiyon veya global
        return "c_func"
    if name.startswith("_") and name[1:2].islower():
        return "c_func"
    if name.startswith("__Z") or name.startswith("___Z"):
        return "cpp_mangled"
    return "c_func"


# ---------------------------------------------------------------------------
# ObjC class'larindan ek semboller uret
# ---------------------------------------------------------------------------

def generate_objc_symbol_variants(class_name: str) -> list[str]:
    """Bir ObjC class ismi icin binary'de gorulebilecek sembol varyantlarini uret.

    Binary'de genelde su formatlar gorulur:
    - _OBJC_CLASS_$_NSWindow
    - +[NSWindow alloc]     (Ghidra bunu gosterebilir)
    - -[NSWindow init]      (Ghidra instance method)
    """
    return [
        f"_OBJC_CLASS_$_{class_name}",
    ]


# ---------------------------------------------------------------------------
# SDK path bulma
# ---------------------------------------------------------------------------

def find_sdk_path() -> Path:
    """macOS SDK path'ini bul."""
    try:
        result = subprocess.run(
            ["xcrun", "--show-sdk-path"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            sdk = Path(result.stdout.strip())
            if sdk.exists():
                return sdk
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback: bilinen konumlar
    candidates = [
        Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"),
        Path("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"),
    ]
    for c in candidates:
        if c.exists():
            return c

    raise RuntimeError(
        "macOS SDK bulunamadi. Command Line Tools kurulu mu? "
        "xcode-select --install"
    )


# ---------------------------------------------------------------------------
# Framework TBD dosyalarini bul
# ---------------------------------------------------------------------------

def find_framework_tbds(
    sdk_path: Path,
    include_private: bool = False,
    include_usr_lib: bool = False,
    framework_filter: list[str] | None = None,
) -> list[Path]:
    """SDK icindeki tum framework .tbd dosyalarini bul.

    Args:
        sdk_path: macOS SDK root path
        include_private: PrivateFrameworks dahil mi?
        include_usr_lib: /usr/lib/*.tbd dahil mi?
        framework_filter: Sadece bu framework'leri al (None = hepsi)

    Returns:
        tbd dosya path'lerinin listesi
    """
    tbd_paths = []

    # 1. Public frameworks
    fw_dir = sdk_path / "System" / "Library" / "Frameworks"
    if fw_dir.exists():
        for fw_path in sorted(fw_dir.iterdir()):
            if not fw_path.name.endswith(".framework"):
                continue

            fw_name = fw_path.name.replace(".framework", "")
            if framework_filter and fw_name not in framework_filter:
                continue

            # Her framework'te genelde Versions/X/Name.tbd veya Name.tbd var
            tbds = list(fw_path.rglob("*.tbd"))
            if tbds:
                # En derin (version'lu) olan tercih et
                tbds.sort(key=lambda p: len(p.parts), reverse=True)
                tbd_paths.append(tbds[0])

    # 2. Private frameworks (opsiyonel)
    if include_private:
        priv_fw_dir = sdk_path / "System" / "Library" / "PrivateFrameworks"
        if priv_fw_dir.exists():
            for fw_path in sorted(priv_fw_dir.iterdir()):
                if not fw_path.name.endswith(".framework"):
                    continue

                fw_name = fw_path.name.replace(".framework", "")
                if framework_filter and fw_name not in framework_filter:
                    continue

                tbds = list(fw_path.rglob("*.tbd"))
                if tbds:
                    tbds.sort(key=lambda p: len(p.parts), reverse=True)
                    tbd_paths.append(tbds[0])

    # 3. /usr/lib (opsiyonel)
    if include_usr_lib:
        usr_lib = sdk_path / "usr" / "lib"
        if usr_lib.exists():
            for tbd in sorted(usr_lib.glob("*.tbd")):
                tbd_paths.append(tbd)

    return tbd_paths


# ---------------------------------------------------------------------------
# Signature uretimi
# ---------------------------------------------------------------------------

def build_signatures(
    parse_results: list[TBDParseResult],
    include_swift_mangled: bool = False,
    include_objc_ivars: bool = False,
) -> list[dict]:
    """Parse sonuclarindan load_external_signatures formati uret.

    Her signature: {"name": ..., "library": ..., "category": ..., "confidence": ...}

    Filtreleme kurallari:
    - $ld$ linker directive'leri atla
    - OBJC_METACLASS atlama (class zaten var)
    - Swift mangled isimler opsiyonel (cok uzun ve niche)
    - ObjC class'lari icin _OBJC_CLASS_$_ClassName formatini dahil et
    """
    signatures: list[dict] = []
    seen_names: set[str] = set()

    for result in parse_results:
        fw_name = result.framework
        category = FRAMEWORK_CATEGORIES.get(fw_name, fw_name.lower())

        # --- C/C++ symbols ---
        for sym in result.symbols:
            if not is_useful_symbol(sym):
                continue

            # Swift mangled isimleri opsiyonel
            if not include_swift_mangled:
                if sym.startswith("_$s") or sym.startswith("$s"):
                    continue
                if sym.startswith("_$S") or sym.startswith("$S"):
                    continue
                # Swift previous linker symbols
                if "$previous$" in sym and "swift" in sym.lower():
                    continue

            if sym in seen_names:
                continue
            seen_names.add(sym)

            # OBJC_CLASS_$_ isimleri ozel: class ismi cikar
            purpose = ""
            if sym.startswith("_OBJC_CLASS_$_"):
                class_name = sym[len("_OBJC_CLASS_$_"):]
                purpose = f"ObjC class {class_name}"

            signatures.append({
                "name": sym,
                "library": fw_name,
                "category": category,
                "confidence": 0.95,
                "purpose": purpose,
            })

        # --- ObjC classes ---
        for cls in result.objc_classes:
            # _OBJC_CLASS_$_ClassName formatinda ekle
            objc_sym = f"_OBJC_CLASS_$_{cls}"
            if objc_sym in seen_names:
                continue
            seen_names.add(objc_sym)

            signatures.append({
                "name": objc_sym,
                "library": fw_name,
                "category": category,
                "confidence": 0.95,
                "purpose": f"ObjC class {cls}",
            })

            # Ayrica class ismini de ekle (bazi decompiler'lar sadece class ismini gosterir)
            if cls not in seen_names:
                seen_names.add(cls)
                signatures.append({
                    "name": cls,
                    "library": fw_name,
                    "category": category,
                    "confidence": 0.90,
                    "purpose": f"ObjC class",
                })

        # --- ObjC ivars (opsiyonel) ---
        if include_objc_ivars:
            for ivar in result.objc_ivars:
                ivar_sym = f"_OBJC_IVAR_$_{ivar}"
                if ivar_sym in seen_names:
                    continue
                seen_names.add(ivar_sym)

                signatures.append({
                    "name": ivar_sym,
                    "library": fw_name,
                    "category": category,
                    "confidence": 0.85,
                    "purpose": f"ObjC ivar",
                })

    return signatures


# ---------------------------------------------------------------------------
# nm fallback -- tbd yoksa system binary'lerden cikar
# ---------------------------------------------------------------------------

def extract_via_nm(binary_path: str | Path) -> list[str]:
    """nm ile bir binary'den export edilen sembolleri cikar.

    macOS 11+ SIP korumasiyla bazi binary'ler okunamiyor.
    Bu durumda bos liste doner.
    """
    try:
        result = subprocess.run(
            ["nm", "-gUj", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return []


# ---------------------------------------------------------------------------
# Ana islem
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="macOS system framework'lerinden signature cikarma",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", "-o",
        default="sigs/macos_frameworks.json",
        help="Cikti JSON dosyasinin yolu (default: sigs/macos_frameworks.json)",
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="PrivateFrameworks dahil et",
    )
    parser.add_argument(
        "--include-usr-lib",
        action="store_true",
        help="/usr/lib/*.tbd dahil et",
    )
    parser.add_argument(
        "--include-swift-mangled",
        action="store_true",
        help="Swift mangled semboller dahil et (cok fazla noise ekler)",
    )
    parser.add_argument(
        "--include-objc-ivars",
        action="store_true",
        help="ObjC ivar'lari dahil et",
    )
    parser.add_argument(
        "--frameworks",
        default=None,
        help="Virgullu framework listesi (orn: AppKit,Foundation,CoreGraphics). "
             "Belirtilmezse tum public framework'ler taranir.",
    )
    parser.add_argument(
        "--sdk-path",
        default=None,
        help="macOS SDK path (otomatik bulunur)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Detayli cikti",
    )

    args = parser.parse_args()

    # SDK path
    if args.sdk_path:
        sdk_path = Path(args.sdk_path)
    else:
        sdk_path = find_sdk_path()
    print(f"SDK path: {sdk_path}")

    # Framework filtresi
    fw_filter = None
    if args.frameworks:
        fw_filter = [f.strip() for f in args.frameworks.split(",")]
        print(f"Framework filtresi: {fw_filter}")

    # TBD dosyalarini bul
    t0 = time.time()
    tbd_paths = find_framework_tbds(
        sdk_path,
        include_private=args.include_private,
        include_usr_lib=args.include_usr_lib,
        framework_filter=fw_filter,
    )
    print(f"Bulunan tbd dosyasi: {len(tbd_paths)}")

    # Parse et
    parse_results: list[TBDParseResult] = []
    total_symbols = 0
    total_classes = 0
    total_ivars = 0

    # Oncelik sirasina gore sirala
    def priority_key(path: Path) -> int:
        for part in path.parts:
            if part.endswith(".framework"):
                name = part.replace(".framework", "")
                if name in PRIORITY_FRAMEWORKS:
                    return PRIORITY_FRAMEWORKS.index(name)
        return 999

    tbd_paths.sort(key=priority_key)

    for tbd_path in tbd_paths:
        result = parse_tbd_file(tbd_path)
        if result.total_exports == 0:
            if args.verbose:
                print(f"  SKIP: {tbd_path.name} (bos)")
            continue

        parse_results.append(result)
        total_symbols += len(result.symbols)
        total_classes += len(result.objc_classes)
        total_ivars += len(result.objc_ivars)

        if args.verbose:
            print(
                f"  {result.framework:30s}  "
                f"symbols={len(result.symbols):5d}  "
                f"classes={len(result.objc_classes):4d}  "
                f"ivars={len(result.objc_ivars):4d}"
            )

    print(f"\nParse ozeti:")
    print(f"  Framework sayisi: {len(parse_results)}")
    print(f"  Toplam raw symbol: {total_symbols}")
    print(f"  Toplam ObjC class: {total_classes}")
    print(f"  Toplam ObjC ivar:  {total_ivars}")

    # Signature uret
    signatures = build_signatures(
        parse_results,
        include_swift_mangled=args.include_swift_mangled,
        include_objc_ivars=args.include_objc_ivars,
    )

    elapsed = time.time() - t0

    # Framework bazli istatistik
    fw_stats: dict[str, int] = {}
    for sig in signatures:
        lib = sig["library"]
        fw_stats[lib] = fw_stats.get(lib, 0) + 1

    print(f"\nSignature ozeti (filtrelemeden sonra):")
    print(f"  Toplam signature: {len(signatures)}")
    print(f"  Framework dagilimi:")
    for fw, count in sorted(fw_stats.items(), key=lambda x: -x[1])[:30]:
        print(f"    {fw:35s} {count:6d}")
    if len(fw_stats) > 30:
        remaining = sum(c for fw, c in sorted(fw_stats.items(), key=lambda x: -x[1])[30:])
        print(f"    {'... diger framework':35s} {remaining:6d}")

    # JSON yaz
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "meta": {
            "generator": "extract-macos-frameworks",
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "sdk_path": str(sdk_path),
            "frameworks_scanned": len(parse_results),
            "include_private": args.include_private,
            "include_usr_lib": args.include_usr_lib,
            "include_swift_mangled": args.include_swift_mangled,
            "include_objc_ivars": args.include_objc_ivars,
            "elapsed_seconds": round(elapsed, 2),
        },
        "framework_stats": fw_stats,
        "signatures": signatures,
        "total": len(signatures),
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\nCikti yazildi: {output_path} ({len(signatures)} signature, {elapsed:.1f}s)")

    # Kontrol: 10,000 hedefi
    if len(signatures) < 10000:
        print(
            f"\nUYARI: Hedef 10,000+ signature idi ama {len(signatures)} cikarildi. "
            f"--include-private veya --include-usr-lib eklemeyi dene."
        )


if __name__ == "__main__":
    main()
