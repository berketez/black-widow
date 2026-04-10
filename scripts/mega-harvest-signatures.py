#!/usr/bin/env python3
"""Mega Signature Harvester -- 1M+ unique signature hedefi.

Tum lokal kaynaklardan signature toplar:
  1. macOS SDK PrivateFrameworks tbd dosyalari (~4300 tbd)
  2. macOS SDK usr/lib tbd dosyalari (~530 tbd)
  3. macOS SDK Public Frameworks (Swift mangled + ObjC ivars dahil)
  4. Homebrew Cellar: lib/, bin/, libexec/ (dylib, .a, .so)
  5. Anaconda/Python C extension'lari
  6. Xcode toolchain library'leri
  7. C header dosyalarindan fonksiyon prototype'lari
  8. macOS system binary'lerden nm ile sembol cikarma

Her kaynak ayri JSON olarak kaydedilir, sonra tek combined dosyaya merge edilir.

Kullanim:
    python3 scripts/mega-harvest-signatures.py
    python3 scripts/mega-harvest-signatures.py --output sigs/combined_1M.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Araclar
# ---------------------------------------------------------------------------

def find_nm() -> Optional[str]:
    """System nm'yi bul."""
    for candidate in ["/usr/bin/nm", "/Library/Developer/CommandLineTools/usr/bin/nm"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("nm")


def find_sdk_path() -> Path:
    """macOS SDK path."""
    try:
        r = subprocess.run(["xcrun", "--show-sdk-path"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            p = Path(r.stdout.strip())
            if p.exists():
                return p
    except Exception:
        pass
    fallback = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
    if fallback.exists():
        return fallback
    raise RuntimeError("macOS SDK bulunamadi")


# ---------------------------------------------------------------------------
# Sembol filtreleme
# ---------------------------------------------------------------------------

_SKIP_PATTERNS = re.compile(
    r"^("
    r"_?__cxa_|_?__gxx_|_?__gcc_|_?__emutls_"
    r"|_?_ZT[ISV]|_?_ZGV|_?_ZNSt"
    r"|_?__aeabi_|_?\.L|_?_GLOBAL_"
    r"|_?__do_global_|_?__static_init"
    r"|_?_fini$|_?_init$|_?_start$"
    r"|\$ld\$"
    r"|_OBJC_EHTYPE_|_OBJC_METACLASS_|_OBJC_IVAR_"
    r"|\.objc_class_name_"
    r")"
)


def is_useful_symbol(name: str) -> bool:
    """Kullanisli sembol mu?"""
    if not name or len(name.lstrip("_")) < 2:
        return False
    if _SKIP_PATTERNS.match(name):
        return False
    return True


# ---------------------------------------------------------------------------
# Kategorizasyon
# ---------------------------------------------------------------------------

_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    ("crypto", ["ssl", "tls", "x509", "evp", "rsa", "aes", "sha", "hmac",
                "cipher", "digest", "encrypt", "decrypt", "sign", "verify",
                "pkcs", "asn1", "pem", "bio_", "bn_", "ec_", "dh_", "dsa_"]),
    ("database", ["sqlite", "mysql", "pq", "redis", "mongo", "leveldb",
                   "lmdb", "bson", "hiredis"]),
    ("network", ["curl", "http", "socket", "connect", "bind", "listen",
                 "accept", "send", "recv", "dns", "resolve", "grpc",
                 "nghttp", "ngtcp", "ssh", "websocket"]),
    ("image", ["png", "jpeg", "jpg", "tiff", "webp", "gif", "image",
               "pixel", "bitmap"]),
    ("parsing", ["xml", "json", "yaml", "parse", "serialize", "token",
                 "lexer", "expat", "sax", "dom"]),
    ("compression", ["compress", "deflate", "inflate", "zip", "gzip",
                     "zlib", "lz4", "lz77", "zstd", "snappy", "brotli",
                     "bzip", "lzma", "archive"]),
    ("threading", ["pthread", "mutex", "thread", "atomic", "rwlock",
                   "condvar", "semaphore", "barrier"]),
    ("memory", ["alloc", "malloc", "free", "mmap", "realloc", "calloc",
                "mpool", "arena"]),
    ("audio", ["audio", "sound", "alsa", "pulse", "codec", "sample",
               "pcm", "midi"]),
    ("video", ["avcodec", "avformat", "avutil", "swscale", "swresample",
               "demux", "mux", "h264", "h265", "hevc", "vp9"]),
    ("graphics", ["opengl", "vulkan", "metal", "shader", "render",
                  "texture", "framebuffer", "cairo", "freetype",
                  "harfbuzz", "font", "glyph"]),
    ("math", ["fft", "blas", "lapack", "eigen", "matrix", "vector",
              "gmp", "mpfr", "cblas", "dgemm", "sgemm"]),
    ("regex", ["pcre", "regex", "regexp"]),
    ("unicode", ["icu", "ucnv", "uchar", "unorm", "ubidi", "ucol"]),
    ("logging", ["log_", "spdlog", "glog", "log4"]),
    ("io", ["fopen", "fclose", "fread", "fwrite"]),
]


def categorize(name: str, lib_name: str) -> str:
    n = name.lower()
    for cat, kws in _CATEGORY_RULES:
        if any(kw in n for kw in kws):
            return cat
    lib_lower = lib_name.lower()
    for cat, kws in _CATEGORY_RULES:
        if any(kw in lib_lower for kw in kws):
            return cat
    return lib_name


# ---------------------------------------------------------------------------
# Kutuphane ismi cikarma
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"[\.\-]\d[\d.]*$")

_LIB_NAME_MAP: dict[str, str] = {
    "ssl": "openssl", "crypto": "openssl", "z": "zlib",
    "bz2": "bzip2", "lzma": "liblzma", "xml2": "libxml2",
    "curl": "libcurl", "sqlite3": "sqlite3",
    "event": "libevent", "uv": "libuv", "sodium": "libsodium",
    "png16": "libpng", "png": "libpng", "jpeg": "libjpeg",
    "turbojpeg": "libjpeg", "webp": "libwebp", "tiff": "libtiff",
    "avcodec": "ffmpeg", "avformat": "ffmpeg", "avutil": "ffmpeg",
    "swresample": "ffmpeg", "swscale": "ffmpeg",
    "protobuf": "protobuf", "grpc": "grpc", "cares": "c-ares",
    "pq": "libpq", "ssh2": "libssh2", "yaml": "libyaml",
    "archive": "libarchive", "lz4": "lz4", "zstd": "zstd",
    "iconv": "libiconv", "ffi": "libffi", "expat": "expat",
    "readline": "readline", "gmp": "gmp", "mpfr": "mpfr",
    "fmt": "fmt", "spdlog": "spdlog",
}


def lib_name_from_path(path: Path) -> str:
    name = path.stem
    if name.startswith("lib"):
        name = name[3:]
    name = _VERSION_RE.sub("", name)
    name = re.sub(r"\.\d+$", "", name)
    return _LIB_NAME_MAP.get(name, name)


# ---------------------------------------------------------------------------
# Kaynak 1: TBD dosyalari parse etme
# ---------------------------------------------------------------------------

def parse_tbd_file(tbd_path: Path) -> dict:
    """TBD dosyasini parse et, sembol listesi don."""
    try:
        content = tbd_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"framework": tbd_path.stem, "symbols": [], "objc_classes": [], "objc_ivars": []}

    # Framework adi
    framework = tbd_path.stem
    m = re.search(r"install-name:\s*'([^']+)'", content)
    if m:
        parts = m.group(1).split("/")
        for part in parts:
            if part.endswith(".framework"):
                framework = part.replace(".framework", "")
                break
        else:
            for part in reversed(parts):
                if part.startswith("lib") and (".dylib" in part or ".tbd" in part):
                    framework = re.sub(r"\..*$", "", part)
                    break
            else:
                framework = parts[-1] if parts else tbd_path.stem

    symbols = []
    objc_classes = []
    objc_ivars = []

    # Parse exports/re-exports bloklari
    in_exports = False
    current_field = None
    bracket_buffer = ""
    bracket_depth = 0

    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped in ("exports:", "re-exports:") or stripped.startswith("exports:") or stripped.startswith("re-exports:"):
            in_exports = True
            continue

        if not line.startswith(" ") and not line.startswith("\t"):
            if stripped.endswith(":") and stripped not in ("exports:", "re-exports:"):
                in_exports = False
                current_field = None
                bracket_buffer = ""
                bracket_depth = 0
                continue

        if not in_exports:
            continue

        for field_name in ("symbols", "objc-classes", "objc-ivars", "weak-symbols"):
            if f"{field_name}:" in stripped:
                current_field = field_name
                idx = stripped.index(f"{field_name}:")
                rest = stripped[idx + len(field_name) + 1:].strip()
                bracket_buffer = rest
                bracket_depth = rest.count("[") - rest.count("]")
                if bracket_depth <= 0 and "[" in rest:
                    names = _extract_tbd_names(bracket_buffer)
                    if field_name == "symbols":
                        symbols.extend(names)
                    elif field_name == "objc-classes":
                        objc_classes.extend(names)
                    elif field_name == "objc-ivars":
                        objc_ivars.extend(names)
                    elif field_name == "weak-symbols":
                        symbols.extend(names)
                    bracket_buffer = ""
                    bracket_depth = 0
                    current_field = None
                break
        else:
            if current_field and bracket_depth > 0:
                bracket_buffer += " " + stripped
                bracket_depth += stripped.count("[") - stripped.count("]")
                if bracket_depth <= 0:
                    names = _extract_tbd_names(bracket_buffer)
                    if current_field == "symbols":
                        symbols.extend(names)
                    elif current_field == "objc-classes":
                        objc_classes.extend(names)
                    elif current_field == "objc-ivars":
                        objc_ivars.extend(names)
                    elif current_field == "weak-symbols":
                        symbols.extend(names)
                    bracket_buffer = ""
                    bracket_depth = 0
                    current_field = None

    if bracket_buffer and current_field:
        names = _extract_tbd_names(bracket_buffer)
        if current_field == "symbols":
            symbols.extend(names)
        elif current_field == "objc-classes":
            objc_classes.extend(names)
        elif current_field == "objc-ivars":
            objc_ivars.extend(names)

    return {
        "framework": framework,
        "symbols": symbols,
        "objc_classes": objc_classes,
        "objc_ivars": objc_ivars,
    }


def _extract_tbd_names(text: str) -> list[str]:
    text = text.strip()
    if text.startswith("["):
        text = text[1:]
    if text.endswith("]"):
        text = text[:-1]
    names = []
    for part in text.split(","):
        name = part.strip().strip("'\"")
        if name:
            names.append(name)
    return names


def harvest_tbd_signatures(
    tbd_paths: list[Path],
    include_swift: bool = True,
    include_ivars: bool = True,
    source_label: str = "tbd",
) -> list[dict]:
    """TBD dosyalarindan signature listesi uret."""
    sigs = []
    seen = set()

    for tbd_path in tbd_paths:
        result = parse_tbd_file(tbd_path)
        fw_name = result["framework"]
        cat = fw_name.lower()

        # Symbols
        for sym in result["symbols"]:
            if not is_useful_symbol(sym):
                continue
            # Swift mangled opsiyonel
            if not include_swift:
                if sym.startswith("_$s") or sym.startswith("$s") or \
                   sym.startswith("_$S") or sym.startswith("$S"):
                    continue
            if sym in seen:
                continue
            seen.add(sym)
            sigs.append({
                "name": sym,
                "library": fw_name,
                "category": cat,
                "confidence": 0.90,
                "source": source_label,
            })

        # ObjC classes -> _OBJC_CLASS_$_ClassName
        for cls in result["objc_classes"]:
            objc_sym = f"_OBJC_CLASS_$_{cls}"
            if objc_sym not in seen:
                seen.add(objc_sym)
                sigs.append({
                    "name": objc_sym,
                    "library": fw_name,
                    "category": cat,
                    "confidence": 0.95,
                    "source": source_label,
                })
            if cls not in seen:
                seen.add(cls)
                sigs.append({
                    "name": cls,
                    "library": fw_name,
                    "category": cat,
                    "confidence": 0.90,
                    "source": source_label,
                })

        # ObjC ivars
        if include_ivars:
            for ivar in result["objc_ivars"]:
                ivar_sym = f"_OBJC_IVAR_$_{ivar}"
                if ivar_sym not in seen:
                    seen.add(ivar_sym)
                    sigs.append({
                        "name": ivar_sym,
                        "library": fw_name,
                        "category": cat,
                        "confidence": 0.85,
                        "source": source_label,
                    })

    return sigs


# ---------------------------------------------------------------------------
# Kaynak 2: nm ile binary'lerden sembol cikarma
# ---------------------------------------------------------------------------

def extract_nm_symbols(lib_path: Path, nm_path: str) -> list[tuple[str, str]]:
    """nm ile sembol cikar."""
    actual = str(lib_path.resolve())
    for flags in (["-g", "-U"], ["-g", "--defined-only"]):
        try:
            r = subprocess.run(
                [nm_path] + flags + [actual],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                break
        except Exception:
            pass
    else:
        return []

    symbols = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_type = parts[1]
        sym_name = parts[2]
        if sym_type in ("T", "t", "D", "S"):  # T=text, D=data, S=bss
            if is_useful_symbol(sym_name):
                symbols.append((sym_name, sym_type))
    return symbols


def harvest_binary_signatures(
    binary_paths: list[Path],
    nm_path: str,
    source_label: str = "binary",
    min_symbols: int = 3,
) -> list[dict]:
    """Binary dosyalardan nm ile signature cikar."""
    sigs = []
    seen = set()

    for lib_path in binary_paths:
        lib_name = lib_name_from_path(lib_path)
        raw = extract_nm_symbols(lib_path, nm_path)
        if len(raw) < min_symbols:
            continue

        for sym_name, sym_type in raw:
            if sym_name in seen:
                continue
            seen.add(sym_name)
            clean = sym_name.lstrip("_")
            cat = categorize(clean, lib_name)
            conf = 0.85 if sym_type in ("T", "t") else 0.75
            sigs.append({
                "name": sym_name,
                "library": lib_name,
                "category": cat,
                "confidence": conf,
                "source": source_label,
            })

    return sigs


# ---------------------------------------------------------------------------
# Kaynak 3: C header dosyalarindan fonksiyon prototype cikarma
# ---------------------------------------------------------------------------

# Basit C fonksiyon prototipi regex'i
_C_FUNC_RE = re.compile(
    r"^\s*(?:extern\s+|__attribute__\S*\s+)*"  # extern, attribute
    r"(?:(?:const|static|inline|volatile|unsigned|signed|long|short|struct|enum|union)\s+)*"  # type qualifiers
    r"(?:\w[\w*\s]*?)"   # return type (basitlestirilmis)
    r"\s+\*?\s*"         # pointer
    r"(\w{3,})"          # FONKSIYON ADI (capture group 1) - min 3 char
    r"\s*\("             # acilan parantez
    r"[^;{]*?"           # parametre listesi
    r"\)\s*"             # kapanan parantez
    r"(?:__\w+\s*(?:\([^)]*\)\s*)?)?"  # __attribute__ sonrasi
    r";",                # noktali virgul
    re.MULTILINE,
)

# Daha iyi pattern: fonksiyon bildirimlerini yakala
_FUNC_DECL_RE = re.compile(
    r"(?:^|\n)\s*"
    r"(?:extern\s+|EXTERN\s+|CF_EXPORT\s+|CG_EXTERN\s+|OS_EXPORT\s+|API_AVAILABLE\([^)]*\)\s+|"
    r"API_UNAVAILABLE\([^)]*\)\s+|NS_AVAILABLE\([^)]*\)\s+|__OSX_AVAILABLE\([^)]*\)\s+|"
    r"CG_AVAILABLE_STARTING\([^)]*\)\s+|DISPATCH_EXPORT\s+|XPC_EXPORT\s+|"
    r"SQLITE_API\s+|CURL_EXTERN\s+|XMLPUBFUN\s+|ZEXTERN\s+)*"
    r"(?:(?:const|static|inline|volatile|unsigned|signed|long|short|void|int|float|double|"
    r"char|bool|size_t|ssize_t|uint\d+_t|int\d+_t|pid_t|uid_t|gid_t|off_t|"
    r"CFStringRef|CFTypeRef|CFArrayRef|CFDictionaryRef|CFIndex|CFURLRef|"
    r"CGFloat|CGPoint|CGSize|CGRect|CGColorRef|CGContextRef|CGImageRef|"
    r"NSInteger|NSUInteger|NSString|BOOL|id|Class|SEL|IMP|"
    r"dispatch_\w+_t|xpc_\w+_t|os_\w+_t|"
    r"kern_return_t|IOReturn|mach_port_t|"
    r"struct\s+\w+|enum\s+\w+)\s*\**\s*)+"
    r"\s*(\w{3,})\s*\(",
)

# ObjC @interface, @protocol ile class isimleri
_OBJC_CLASS_RE = re.compile(
    r"@interface\s+(\w+)\s*(?:[:(]|$)",
    re.MULTILINE,
)

_OBJC_PROTOCOL_RE = re.compile(
    r"@protocol\s+(\w+)\s*(?:[<;(]|$)",
    re.MULTILINE,
)

# #define macro fonksiyonlar
_MACRO_FUNC_RE = re.compile(
    r"^#define\s+(\w{4,})\s*\(",
    re.MULTILINE,
)

# typedef fonksiyon pointer'lari -- isim kaydeder
_TYPEDEF_FUNC_RE = re.compile(
    r"typedef\s+\w[\w\s*]*\(\s*\*\s*(\w{3,})\s*\)",
)

# enum value'lar (k ile baslayanlar Apple convention'i)
_ENUM_VALUE_RE = re.compile(
    r"^\s*(k[A-Z]\w{3,})\s*(?:=|,|$)",
    re.MULTILINE,
)

# CF_ENUM / NS_ENUM / NS_OPTIONS isimleri
_NAMED_ENUM_RE = re.compile(
    r"(?:CF_ENUM|NS_ENUM|NS_OPTIONS)\s*\(\s*\w+\s*,\s*(\w+)\s*\)",
)


def extract_header_symbols(header_path: Path) -> list[str]:
    """C/ObjC header dosyasindan sembol isimlerini cikar."""
    try:
        content = header_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    symbols = set()

    # C fonksiyon prototipleri
    for m in _FUNC_DECL_RE.finditer(content):
        name = m.group(1)
        # Compiler keyword'leri atla
        if name in ("if", "else", "for", "while", "do", "switch", "case",
                     "return", "break", "continue", "goto", "sizeof",
                     "typedef", "struct", "enum", "union", "const", "static",
                     "extern", "inline", "volatile", "register", "restrict",
                     "void", "int", "char", "float", "double", "long", "short",
                     "signed", "unsigned", "bool", "auto", "NULL", "nil",
                     "YES", "NO", "TRUE", "FALSE", "true", "false"):
            continue
        symbols.add(name)

    # Basit C fonksiyon regex
    for m in _C_FUNC_RE.finditer(content):
        name = m.group(1)
        if len(name) >= 3 and name[0].islower() and name not in (
            "if", "else", "for", "while", "do", "switch", "return",
            "sizeof", "typedef", "struct", "enum", "union", "void",
            "int", "char", "float", "double", "long", "short", "bool",
            "const", "static", "extern", "inline", "volatile"):
            symbols.add(name)

    # ObjC class'lar
    for m in _OBJC_CLASS_RE.finditer(content):
        cls = m.group(1)
        symbols.add(cls)
        symbols.add(f"_OBJC_CLASS_$_{cls}")

    # ObjC protocol'ler
    for m in _OBJC_PROTOCOL_RE.finditer(content):
        symbols.add(m.group(1))

    # Macro fonksiyonlar
    for m in _MACRO_FUNC_RE.finditer(content):
        name = m.group(1)
        if not name.startswith("_") and not name.isupper():
            symbols.add(name)

    # Typedef fonksiyon pointer'lari
    for m in _TYPEDEF_FUNC_RE.finditer(content):
        symbols.add(m.group(1))

    # Enum value'lar (k ile baslayanlar)
    for m in _ENUM_VALUE_RE.finditer(content):
        symbols.add(m.group(1))

    # CF_ENUM/NS_ENUM isimleri
    for m in _NAMED_ENUM_RE.finditer(content):
        symbols.add(m.group(1))

    return list(symbols)


def harvest_header_signatures(
    header_paths: list[Path],
    source_label: str = "header",
) -> list[dict]:
    """Header dosyalarindan signature cikar."""
    sigs = []
    seen = set()

    for hpath in header_paths:
        # Framework/library adi cikar
        parts = hpath.parts
        lib_name = hpath.stem
        for i, part in enumerate(parts):
            if part.endswith(".framework"):
                lib_name = part.replace(".framework", "")
                break
            if part == "include" and i + 1 < len(parts):
                lib_name = parts[i + 1]
                break

        symbols = extract_header_symbols(hpath)
        for sym in symbols:
            if sym in seen:
                continue
            if not is_useful_symbol(sym) and len(sym) < 3:
                continue
            seen.add(sym)
            cat = categorize(sym, lib_name)
            sigs.append({
                "name": sym,
                "library": lib_name,
                "category": cat,
                "confidence": 0.80,
                "source": source_label,
            })

    return sigs


# ---------------------------------------------------------------------------
# Kaynak 4: Homebrew bin/ ve libexec/ binary'leri
# ---------------------------------------------------------------------------

def find_homebrew_binaries(brew_prefix: Path) -> list[Path]:
    """Homebrew'daki TUM binary dosyalari bul (Cellar dahil)."""
    binaries = []
    seen_resolved = set()

    # Cellar'daki TUM binary dosyalar
    cellar = brew_prefix / "Cellar"
    if cellar.exists():
        for pkg in sorted(cellar.iterdir()):
            if not pkg.is_dir():
                continue
            versions = sorted([v for v in pkg.iterdir() if v.is_dir()],
                              key=lambda v: v.name, reverse=True)
            if not versions:
                continue
            latest = versions[0]

            # lib/, bin/, libexec/ altindaki binary dosyalar
            for subdir_name in ("lib", "bin", "libexec"):
                subdir = latest / subdir_name
                if not subdir.exists():
                    continue
                for pattern in ("*.dylib", "*.a", "*.so", "*.bundle"):
                    for f in subdir.rglob(pattern):
                        try:
                            resolved = str(f.resolve())
                        except OSError:
                            continue
                        if resolved not in seen_resolved:
                            seen_resolved.add(resolved)
                            binaries.append(f)

    # opt/ altindaki symlink'ler
    opt_dir = brew_prefix / "opt"
    if opt_dir.exists():
        for pkg_link in sorted(opt_dir.iterdir()):
            if not pkg_link.is_dir():
                continue
            for subdir_name in ("lib",):
                subdir = pkg_link / subdir_name
                if not subdir.exists():
                    continue
                for pattern in ("*.dylib", "*.a", "*.so"):
                    for f in subdir.rglob(pattern):
                        try:
                            resolved = str(f.resolve())
                        except OSError:
                            continue
                        if resolved not in seen_resolved:
                            seen_resolved.add(resolved)
                            binaries.append(f)

    return binaries


# ---------------------------------------------------------------------------
# Kaynak 5: Anaconda/Python library'leri
# ---------------------------------------------------------------------------

def find_anaconda_libs() -> list[Path]:
    """Anaconda/conda library dosyalarini bul."""
    libs = []
    seen = set()
    conda_dirs = [
        Path("/opt/anaconda3/lib"),
        Path.home() / "anaconda3" / "lib",
        Path.home() / "miniconda3" / "lib",
    ]

    for conda_lib in conda_dirs:
        if not conda_lib.exists():
            continue
        for pattern in ("*.dylib", "*.so", "*.a"):
            for f in conda_lib.rglob(pattern):
                try:
                    resolved = str(f.resolve())
                except OSError:
                    continue
                if resolved not in seen:
                    seen.add(resolved)
                    libs.append(f)

    return libs


# ---------------------------------------------------------------------------
# Kaynak 6: Xcode toolchain
# ---------------------------------------------------------------------------

def find_xcode_toolchain_libs() -> list[Path]:
    """Xcode/CLT toolchain library'leri."""
    libs = []
    seen = set()
    search_dirs = [
        Path("/Library/Developer/CommandLineTools/usr/lib"),
        Path("/Library/Developer/CommandLineTools/Toolchains/XcodeDefault.xctoolchain/usr/lib"),
    ]

    for sdir in search_dirs:
        if not sdir.exists():
            continue
        for pattern in ("*.dylib", "*.a"):
            for f in sdir.rglob(pattern):
                try:
                    resolved = str(f.resolve())
                except OSError:
                    continue
                if resolved not in seen:
                    seen.add(resolved)
                    libs.append(f)

    return libs


# ---------------------------------------------------------------------------
# Merge ve deduplicate
# ---------------------------------------------------------------------------

def merge_all_signatures(
    *sig_lists: list[dict],
    existing_files: list[Path] | None = None,
) -> list[dict]:
    """Tum signature listelerini birlestir, duplike kaldir."""
    seen = set()
    merged = []

    # Onceki dosyalari yukle (builtin onceligini koru)
    if existing_files:
        for fpath in existing_files:
            if not fpath.exists():
                continue
            try:
                with open(fpath) as f:
                    data = json.load(f)
                for sig in data.get("signatures", []):
                    name = sig.get("name", "")
                    if name and name not in seen:
                        seen.add(name)
                        merged.append(sig)
            except Exception as exc:
                print(f"  UYARI: {fpath} okunamadi: {exc}")

    # Yeni signature'lari ekle
    for sig_list in sig_lists:
        for sig in sig_list:
            name = sig.get("name", "")
            if name and name not in seen:
                seen.add(name)
                merged.append(sig)

    return merged


# ---------------------------------------------------------------------------
# Ana program
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Mega Signature Harvester")
    parser.add_argument("--output", "-o", default="sigs/combined_1M.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--skip-headers", action="store_true",
                        help="Header parsing'i atla (hizlandirir)")
    parser.add_argument("--skip-anaconda", action="store_true",
                        help="Anaconda library'leri atla")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    t0 = time.time()

    # Araclar
    nm_path = find_nm()
    if not nm_path:
        print("HATA: nm bulunamadi")
        return 1
    sdk_path = find_sdk_path()
    print(f"SDK: {sdk_path}")
    print(f"nm: {nm_path}")

    brew_prefix = Path("/opt/homebrew") if Path("/opt/homebrew").exists() else Path("/usr/local")
    print(f"Homebrew: {brew_prefix}")

    all_sig_lists = []
    stats = {}

    # =========================================================================
    # KAYNAK 1: Public frameworks (swift + ivars dahil)
    # =========================================================================
    print("\n=== Kaynak 1: Public Frameworks (Swift + Ivars dahil) ===")
    fw_dir = sdk_path / "System" / "Library" / "Frameworks"
    public_tbds = []
    if fw_dir.exists():
        for fw_path in sorted(fw_dir.iterdir()):
            if fw_path.name.endswith(".framework"):
                tbds = list(fw_path.rglob("*.tbd"))
                if tbds:
                    tbds.sort(key=lambda p: len(p.parts), reverse=True)
                    public_tbds.append(tbds[0])
    print(f"  TBD dosyasi: {len(public_tbds)}")
    sigs_public = harvest_tbd_signatures(
        public_tbds, include_swift=True, include_ivars=True,
        source_label="public_framework"
    )
    print(f"  Signature: {len(sigs_public)}")
    stats["public_frameworks"] = len(sigs_public)
    all_sig_lists.append(sigs_public)

    # =========================================================================
    # KAYNAK 2: Private frameworks
    # =========================================================================
    print("\n=== Kaynak 2: Private Frameworks ===")
    priv_fw_dir = sdk_path / "System" / "Library" / "PrivateFrameworks"
    private_tbds = []
    if priv_fw_dir.exists():
        for fw_path in sorted(priv_fw_dir.iterdir()):
            if fw_path.name.endswith(".framework"):
                tbds = list(fw_path.rglob("*.tbd"))
                if tbds:
                    tbds.sort(key=lambda p: len(p.parts), reverse=True)
                    private_tbds.append(tbds[0])
    print(f"  TBD dosyasi: {len(private_tbds)}")
    sigs_private = harvest_tbd_signatures(
        private_tbds, include_swift=True, include_ivars=True,
        source_label="private_framework"
    )
    print(f"  Signature: {len(sigs_private)}")
    stats["private_frameworks"] = len(sigs_private)
    all_sig_lists.append(sigs_private)

    # =========================================================================
    # KAYNAK 3: /usr/lib tbd dosyalari
    # =========================================================================
    print("\n=== Kaynak 3: usr/lib TBD ===")
    usr_lib = sdk_path / "usr" / "lib"
    usr_tbds = []
    if usr_lib.exists():
        for tbd in sorted(usr_lib.rglob("*.tbd")):
            usr_tbds.append(tbd)
    print(f"  TBD dosyasi: {len(usr_tbds)}")
    sigs_usrlib = harvest_tbd_signatures(
        usr_tbds, include_swift=True, include_ivars=True,
        source_label="usr_lib"
    )
    print(f"  Signature: {len(sigs_usrlib)}")
    stats["usr_lib"] = len(sigs_usrlib)
    all_sig_lists.append(sigs_usrlib)

    # =========================================================================
    # KAYNAK 4: Homebrew Cellar (lib + bin + libexec)
    # =========================================================================
    print("\n=== Kaynak 4: Homebrew Cellar (kapsamli) ===")
    brew_bins = find_homebrew_binaries(brew_prefix)
    print(f"  Binary dosya: {len(brew_bins)}")
    sigs_brew = harvest_binary_signatures(
        brew_bins, nm_path, source_label="homebrew_cellar", min_symbols=3
    )
    print(f"  Signature: {len(sigs_brew)}")
    stats["homebrew_cellar"] = len(sigs_brew)
    all_sig_lists.append(sigs_brew)

    # =========================================================================
    # KAYNAK 5: Anaconda/Python C extensions
    # =========================================================================
    if not args.skip_anaconda:
        print("\n=== Kaynak 5: Anaconda/Python ===")
        anaconda_libs = find_anaconda_libs()
        print(f"  Library dosya: {len(anaconda_libs)}")
        if anaconda_libs:
            sigs_anaconda = harvest_binary_signatures(
                anaconda_libs, nm_path, source_label="anaconda", min_symbols=3
            )
            print(f"  Signature: {len(sigs_anaconda)}")
            stats["anaconda"] = len(sigs_anaconda)
            all_sig_lists.append(sigs_anaconda)
        else:
            print("  Anaconda bulunamadi, atlaniyor.")
            stats["anaconda"] = 0
    else:
        stats["anaconda"] = 0

    # =========================================================================
    # KAYNAK 6: Xcode toolchain
    # =========================================================================
    print("\n=== Kaynak 6: Xcode Toolchain ===")
    xcode_libs = find_xcode_toolchain_libs()
    print(f"  Library dosya: {len(xcode_libs)}")
    sigs_xcode = harvest_binary_signatures(
        xcode_libs, nm_path, source_label="xcode_toolchain", min_symbols=3
    )
    print(f"  Signature: {len(sigs_xcode)}")
    stats["xcode_toolchain"] = len(sigs_xcode)
    all_sig_lists.append(sigs_xcode)

    # =========================================================================
    # KAYNAK 7: C Header dosyalari
    # =========================================================================
    if not args.skip_headers:
        print("\n=== Kaynak 7: C/ObjC Header Dosyalari ===")
        header_paths = []
        header_search_dirs = [
            sdk_path / "System" / "Library" / "Frameworks",
            sdk_path / "System" / "Library" / "PrivateFrameworks",
            sdk_path / "usr" / "include",
            Path("/Library/Developer/CommandLineTools/usr/include"),
            brew_prefix / "include",
        ]
        for sdir in header_search_dirs:
            if sdir.exists():
                for h in sdir.rglob("*.h"):
                    header_paths.append(h)
        print(f"  Header dosya: {len(header_paths)}")
        sigs_headers = harvest_header_signatures(header_paths, source_label="header")
        print(f"  Signature: {len(sigs_headers)}")
        stats["headers"] = len(sigs_headers)
        all_sig_lists.append(sigs_headers)
    else:
        stats["headers"] = 0

    # =========================================================================
    # MERGE: Mevcut dosyalar + yeni signature'lar
    # =========================================================================
    print("\n=== Merge: Tum kaynaklar birlestiriliyor ===")
    existing_files = [
        project_root / "signatures_homebrew.json",
        project_root / "signatures_homebrew_bytes.json",
        project_root / "sigs" / "macos_frameworks.json",
        project_root / "sigs" / "macos_frameworks_full.json",
        project_root / "sigs_macos_system.json",
    ]

    merged = merge_all_signatures(*all_sig_lists, existing_files=existing_files)
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SONUC")
    print(f"{'='*60}")
    print(f"Kaynak bazli istatistik:")
    for src, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {src:30s} {count:>8,d}")
    print(f"  {'TOPLAM (merge oncesi)':30s} {sum(stats.values()):>8,d}")
    print(f"  {'Mevcut dosyalardan':30s} {'(var)':>8s}")
    print(f"\n  MERGED TOPLAM (unique):       {len(merged):>8,d}")
    print(f"  Sure: {elapsed:.1f}s")

    # JSON kaydet
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "meta": {
            "generator": "mega-harvest-signatures",
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "sdk_path": str(sdk_path),
            "brew_prefix": str(brew_prefix),
            "elapsed_seconds": round(elapsed, 2),
            "source_stats": stats,
        },
        "signatures": merged,
        "total": len(merged),
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, separators=(",", ":"))  # compact JSON

    file_size = output_path.stat().st_size
    print(f"\nCikti: {output_path}")
    print(f"Dosya boyutu: {file_size / (1024*1024):.1f} MB")

    # Hedef kontrolu
    if len(merged) >= 1_000_000:
        print(f"\n*** HEDEF BASILDI: {len(merged):,d} >= 1,000,000 ***")
    else:
        deficit = 1_000_000 - len(merged)
        print(f"\n*** Hedefe {deficit:,d} signature eksik ***")

    return 0


if __name__ == "__main__":
    sys.exit(main())
