#!/usr/bin/env python3
"""Homebrew kutuphanelerinden otomatik signature cikarma.

Kurulu Homebrew kutuphanelerinin .dylib/.a dosyalarindan nm ile
export edilen sembolleri cikarir, FunctionSignature formatina cevirir
ve JSON olarak kaydeder.

Bu JSON, SignatureDB.load_external_signatures() ile yuklenebilir.

Kullanim:
    python3 scripts/build-signature-db.py --output signatures_homebrew.json
    python3 scripts/build-signature-db.py --library openssl --output ssl_sigs.json
    python3 scripts/build-signature-db.py --scan-cellar --output full_sigs.json

Cikti formati:
    {
        "meta": {"generator": "build-signature-db", "version": "1.0", ...},
        "signatures": [
            {"name": "EVP_EncryptInit_ex", "library": "openssl", "category": "crypto", "confidence": 0.85},
            ...
        ],
        "total": 12345
    }
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
# Araclarin varligi
# ---------------------------------------------------------------------------

def check_tools() -> dict[str, Optional[str]]:
    """nm ve brew komutlarinin varligini kontrol et."""
    tools: dict[str, Optional[str]] = {}

    # nm: macOS system nm'si tercih et (Anaconda/conda nm dylib okuyamayabilir)
    nm_candidates = ["/usr/bin/nm", "/Library/Developer/CommandLineTools/usr/bin/nm"]
    tools["nm"] = None
    for nm in nm_candidates:
        if os.path.isfile(nm) and os.access(nm, os.X_OK):
            tools["nm"] = nm
            break
    if tools["nm"] is None:
        tools["nm"] = shutil.which("nm")

    tools["brew"] = shutil.which("brew")
    return tools


# ---------------------------------------------------------------------------
# Homebrew kesfetme
# ---------------------------------------------------------------------------

def get_brew_prefix() -> Path:
    """Homebrew prefix'ini bul."""
    try:
        r = subprocess.run(
            ["brew", "--prefix"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    # Apple Silicon varsayilan
    if Path("/opt/homebrew").exists():
        return Path("/opt/homebrew")
    # Intel Mac varsayilan
    return Path("/usr/local")


def list_lib_files(brew_prefix: Path) -> list[Path]:
    """Homebrew lib/ dizinindeki .dylib ve .a dosyalarini bul.

    Homebrew'da lib/ icindeki dosyalar genellikle Cellar'a symlink'tir.
    Ayni gercek dosyaya isaret eden birden fazla symlink olabilir
    (ornegin libssl.dylib, libssl.3.dylib, libssl.3.4.0.dylib).
    Bunlarin hepsinden sadece en kisa isimli olani aliriz (canonical).
    """
    lib_dir = brew_prefix / "lib"
    libs: list[Path] = []
    if not lib_dir.exists():
        return libs

    # resolved_path -> shortest_symlink_name eslesmesi
    seen_resolved: dict[str, Path] = {}

    for f in sorted(lib_dir.iterdir()):
        if f.suffix not in (".dylib", ".a"):
            continue
        try:
            resolved = str(f.resolve())
        except OSError:
            continue
        # Ayni gercek dosyayi gosteren en kisa isimli symlink'i tut
        if resolved not in seen_resolved or len(f.name) < len(seen_resolved[resolved].name):
            seen_resolved[resolved] = f

    libs = sorted(seen_resolved.values(), key=lambda p: p.name)
    return libs


def scan_cellar(brew_prefix: Path) -> list[Path]:
    """Homebrew Cellar icindeki TUM .dylib ve .a dosyalarini tara.

    Bu, lib/ dizininden daha kapsamlidir -- her paketin kendi lib/ dizinini
    de tarar.
    """
    cellar = brew_prefix / "Cellar"
    libs: list[Path] = []
    if not cellar.exists():
        return libs

    for pkg_dir in sorted(cellar.iterdir()):
        if not pkg_dir.is_dir():
            continue
        # En son versiyonu bul
        versions = sorted(
            [v for v in pkg_dir.iterdir() if v.is_dir()],
            key=lambda v: v.name,
            reverse=True,
        )
        if not versions:
            continue
        latest = versions[0]
        lib_dir = latest / "lib"
        if lib_dir.exists():
            # Cellar icinde de duplicate'leri onle
            seen_resolved: set[str] = set()
            for pattern in ("*.dylib", "*.a"):
                for f in lib_dir.rglob(pattern):
                    try:
                        resolved = str(f.resolve())
                    except OSError:
                        continue
                    if resolved not in seen_resolved:
                        seen_resolved.add(resolved)
                        libs.append(f)
    return libs


# ---------------------------------------------------------------------------
# Sembol cikarma (nm)
# ---------------------------------------------------------------------------

def extract_symbols(lib_path: Path, nm_path: str = "nm") -> list[tuple[str, str]]:
    """nm ile export edilmis sembolleri cikar.

    Returns:
        list of (symbol_name, symbol_type) tuples.
        symbol_type: T=text(function), D=data, S=bss, etc.
    """
    # Symlink ise resolved path kullan (macOS nm symlink ile ugrasmaz bazen)
    actual_path = str(lib_path.resolve())

    # macOS nm: -g (global/external), -U (undefined gizle, macOS'ta --defined-only yok)
    # GNU nm: -g, --defined-only
    # Her ikisi icin de dene: once macOS stili, sonra GNU stili
    for flags in (["-g", "-U"], ["-g", "--defined-only"]):
        try:
            r = subprocess.run(
                [nm_path] + flags + [actual_path],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    else:
        return []

    symbols: list[tuple[str, str]] = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_type = parts[1]
        sym_name = parts[2]

        # Sadece text (fonksiyon) sembollerini al
        if sym_type not in ("T", "t"):
            continue

        # ObjC metadata atla
        if sym_name.startswith("_OBJC") or sym_name.startswith("."):
            continue

        # Cok kisa semboller anlamsiz
        clean = sym_name.lstrip("_")
        if len(clean) < 3:
            continue

        symbols.append((sym_name, sym_type))

    return symbols


# ---------------------------------------------------------------------------
# Kutuphane isimlendirme
# ---------------------------------------------------------------------------

# Bilinen kutuphane isimleri icin override haritasi
_LIB_NAME_MAP: dict[str, str] = {
    "ssl": "openssl",
    "crypto": "openssl",
    "z": "zlib",
    "bz2": "bzip2",
    "lzma": "liblzma",
    "xml2": "libxml2",
    "curl": "libcurl",
    "sqlite3": "sqlite3",
    "pcre2-8": "pcre2",
    "pcre2-16": "pcre2",
    "pcre2-32": "pcre2",
    "event": "libevent",
    "event_core": "libevent",
    "event_extra": "libevent",
    "event_openssl": "libevent",
    "event_pthreads": "libevent",
    "uv": "libuv",
    "nghttp2": "nghttp2",
    "nghttp3": "nghttp3",
    "ngtcp2": "ngtcp2",
    "sodium": "libsodium",
    "png16": "libpng",
    "png": "libpng",
    "jpeg": "libjpeg",
    "turbojpeg": "libjpeg",
    "webp": "libwebp",
    "tiff": "libtiff",
    "avcodec": "ffmpeg",
    "avformat": "ffmpeg",
    "avutil": "ffmpeg",
    "swresample": "ffmpeg",
    "swscale": "ffmpeg",
    "protobuf": "protobuf",
    "protobuf-lite": "protobuf",
    "grpc": "grpc",
    "gpr": "grpc",
    "cares": "c-ares",
    "hiredis": "hiredis",
    "pq": "libpq",
    "mysqlclient": "mysql",
    "mongoc-1.0": "libmongoc",
    "bson-1.0": "libbson",
    "ssh2": "libssh2",
    "yaml": "libyaml",
    "archive": "libarchive",
    "lz4": "lz4",
    "zstd": "zstd",
    "snappy": "snappy",
    "iconv": "libiconv",
    "icuuc": "icu",
    "icui18n": "icu",
    "icudata": "icu",
    "glib-2.0": "glib",
    "gobject-2.0": "glib",
    "gio-2.0": "glib",
    "gthread-2.0": "glib",
    "freetype": "freetype",
    "harfbuzz": "harfbuzz",
    "fontconfig": "fontconfig",
    "cairo": "cairo",
    "pango-1.0": "pango",
    "readline": "readline",
    "gmp": "gmp",
    "mpfr": "mpfr",
    "ffi": "libffi",
    "expat": "expat",
    "boost_system": "boost",
    "boost_filesystem": "boost",
    "boost_thread": "boost",
    "boost_regex": "boost",
    "boost_program_options": "boost",
    "boost_iostreams": "boost",
    "fmt": "fmt",
    "spdlog": "spdlog",
}

# Versiyon numarasi pattern'i
_VERSION_SUFFIX_RE = re.compile(r"[\.\-]\d[\d.]*$")


def lib_name_from_path(path: Path) -> str:
    """Kutuphane dosya adindan temiz isim cikar.

    libssl.3.dylib -> openssl
    libz.1.3.1.dylib -> zlib
    liblz4.a -> lz4
    """
    name = path.stem
    # lib prefix kaldir
    if name.startswith("lib"):
        name = name[3:]
    # Version suffix kaldir
    name = _VERSION_SUFFIX_RE.sub("", name)
    name = re.sub(r"\.\d+$", "", name)  # trailing .N
    # Bilinen override
    return _LIB_NAME_MAP.get(name, name)


# ---------------------------------------------------------------------------
# Sembol kategorizasyonu
# ---------------------------------------------------------------------------

# Kategori keyword'leri (oncelik sirasina gore)
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
               "pixel", "bitmap", "decode_image", "encode_image"]),
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
    ("regex", ["pcre", "regex", "regexp", "match_pattern"]),
    ("unicode", ["icu", "ucnv", "uchar", "unorm", "ubidi", "ucol"]),
    ("logging", ["log_", "spdlog", "glog", "log4"]),
    ("io", ["fopen", "fclose", "fread", "fwrite", "read", "write",
            "open", "close", "seek", "stat", "readdir", "scandir"]),
    ("ipc", ["pipe", "fifo", "shm_", "mq_", "sem_", "signal"]),
]


def categorize_symbol(name: str, lib_name: str) -> str:
    """Sembol adini ve kutuphane adini kullanarak kategori tahmin et."""
    n = name.lower()
    # Her kural icin keyword eslesme kontrolu
    for category, keywords in _CATEGORY_RULES:
        if any(kw in n for kw in keywords):
            return category
    # Kutuphane adindan kategori
    lib_lower = lib_name.lower()
    for category, keywords in _CATEGORY_RULES:
        if any(kw in lib_lower for kw in keywords):
            return category
    # Fallback: kutuphane adi
    return lib_name


# ---------------------------------------------------------------------------
# Filtreleme: anlamsiz/teknik sembolleri atla
# ---------------------------------------------------------------------------

_SKIP_PATTERNS: list[re.Pattern] = [
    re.compile(r"^_?__cxa_"),         # C++ exception handling
    re.compile(r"^_?__gxx_"),         # GCC internal
    re.compile(r"^_?__gcc_"),         # GCC internal
    re.compile(r"^_?__emutls_"),      # TLS emulation
    re.compile(r"^_?_ZT[ISV]"),       # C++ typeinfo, vtable
    re.compile(r"^_?_ZGV"),           # C++ guard variable
    re.compile(r"^_?_ZNSt"),          # std:: namespace (too generic)
    re.compile(r"^_?__aeabi_"),       # ARM EABI
    re.compile(r"^_?\.L"),            # local labels
    re.compile(r"^_?_GLOBAL_"),       # global constructors
    re.compile(r"^_?__do_global_"),   # global init/fini
    re.compile(r"^_?__static_initialization"),
    re.compile(r"^_?_fini$"),
    re.compile(r"^_?_init$"),
    re.compile(r"^_?_start$"),
]


def should_skip_symbol(name: str) -> bool:
    """Teknik/compiler-generated sembolleri atla."""
    return any(pat.match(name) for pat in _SKIP_PATTERNS)


# ---------------------------------------------------------------------------
# C++ demangling (opsiyonel, c++filt varsa)
# ---------------------------------------------------------------------------

def demangle_symbols(symbols: list[str]) -> dict[str, str]:
    """C++ mangled isimlerini demangle et. c++filt yoksa bos dict dondur."""
    cxxfilt = shutil.which("c++filt")
    if not cxxfilt:
        return {}

    # Sadece mangled isimler (_Z ile baslayanlar)
    mangled = [s for s in symbols if s.lstrip("_").startswith("Z")]
    if not mangled:
        return {}

    try:
        r = subprocess.run(
            [cxxfilt] + mangled,
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return {}
        demangled = r.stdout.strip().splitlines()
        if len(demangled) != len(mangled):
            return {}
        return dict(zip(mangled, demangled))
    except (subprocess.TimeoutExpired, OSError):
        return {}


# ---------------------------------------------------------------------------
# Ana islem
# ---------------------------------------------------------------------------

def process_libraries(
    libs: list[Path],
    nm_path: str,
    min_symbols: int = 5,
    verbose: bool = False,
) -> dict[str, dict]:
    """Kutuphane listesini isle ve unique signature sozlugu olustur.

    Returns:
        {symbol_name: {"name": ..., "library": ..., "category": ..., "confidence": ...}}
    """
    all_sigs: dict[str, dict] = {}
    lib_stats: list[tuple[str, int, str]] = []  # (lib_name, count, file_name)

    for lib_path in libs:
        lib_name = lib_name_from_path(lib_path)
        raw_symbols = extract_symbols(lib_path, nm_path)

        if len(raw_symbols) < min_symbols:
            continue

        count = 0
        for sym_name, sym_type in raw_symbols:
            if should_skip_symbol(sym_name):
                continue

            # Zaten var mi (ilk bulunan kazanir -- daha spesifik kutuphane)
            if sym_name in all_sigs:
                continue

            clean = sym_name.lstrip("_")
            category = categorize_symbol(clean, lib_name)

            all_sigs[sym_name] = {
                "name": sym_name,
                "library": lib_name,
                "category": category,
                "confidence": 0.85,
            }
            count += 1

        if count > 0:
            lib_stats.append((lib_name, count, lib_path.name))
            if verbose:
                print(f"  {lib_name:30s} {count:5d} symbols  ({lib_path.name})")

    # Ozet
    lib_stats.sort(key=lambda x: x[1], reverse=True)
    print(f"\n--- Kutuphane Ozeti ({len(lib_stats)} kutuphane) ---")
    for lib_name, count, fname in lib_stats[:30]:
        print(f"  {lib_name:30s} {count:5d}  ({fname})")
    if len(lib_stats) > 30:
        print(f"  ... ve {len(lib_stats) - 30} kutuphane daha")

    return all_sigs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Homebrew kutuphanelerinden otomatik signature cikarma.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Ornekler:
  %(prog)s --output sigs.json              # Homebrew lib/ tara
  %(prog)s --scan-cellar --output sigs.json # Cellar dahil kapsamli tara
  %(prog)s --library openssl --output ssl.json  # Sadece openssl
  %(prog)s --library curl,zlib --output net.json # Birden fazla
  %(prog)s --verbose --min-symbols 3       # Detayli cikti, min 3 sembol
""",
    )
    parser.add_argument(
        "--output", "-o",
        default="signatures_homebrew.json",
        help="Cikti JSON dosyasi (varsayilan: signatures_homebrew.json)",
    )
    parser.add_argument(
        "--library", "-l",
        help="Sadece bu kutuphane(ler)i tara (virgul ile ayir)",
    )
    parser.add_argument(
        "--scan-cellar",
        action="store_true",
        help="Cellar dizinini de tara (daha kapsamli ama yavas)",
    )
    parser.add_argument(
        "--min-symbols",
        type=int, default=5,
        help="Minimum sembol sayisi (bu kadardan az olan kutuphaneler atlanir)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Detayli cikti",
    )
    args = parser.parse_args()

    # Arac kontrolu
    tools = check_tools()
    nm_path = tools.get("nm")
    if not nm_path:
        print("HATA: nm komutu bulunamadi. Xcode Command Line Tools kurulu mu?",
              file=sys.stderr)
        print("  xcode-select --install", file=sys.stderr)
        return 1

    brew_path = tools.get("brew")
    if not brew_path:
        print("HATA: brew komutu bulunamadi. Homebrew kurulu mu?",
              file=sys.stderr)
        print("  https://brew.sh", file=sys.stderr)
        return 1

    brew_prefix = get_brew_prefix()
    print(f"Homebrew prefix: {brew_prefix}")
    print(f"nm: {nm_path}")

    # Kutuphane listesi
    libs = list_lib_files(brew_prefix)
    if args.scan_cellar:
        cellar_libs = scan_cellar(brew_prefix)
        # Cellar'dan gelenleri ekle (duplicate path'leri atla)
        existing_paths = {str(p) for p in libs}
        for cl in cellar_libs:
            if str(cl) not in existing_paths:
                libs.append(cl)

    print(f"Taranan kutuphane dosyasi: {len(libs)}")

    # Kutuphane filtresi
    if args.library:
        filter_names = [n.strip().lower() for n in args.library.split(",")]
        libs = [
            l for l in libs
            if any(fn in l.name.lower() for fn in filter_names)
        ]
        print(f"Filtre uygulandiktan sonra: {len(libs)} kutuphane")

    if not libs:
        print("UYARI: Hic kutuphane dosyasi bulunamadi.", file=sys.stderr)
        return 1

    # Sembolleri cikar
    start = time.time()
    all_sigs = process_libraries(
        libs, nm_path,
        min_symbols=args.min_symbols,
        verbose=args.verbose,
    )
    elapsed = time.time() - start

    if not all_sigs:
        print("UYARI: Hic sembol cikarilmadi.", file=sys.stderr)
        return 1

    # JSON kaydet
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "meta": {
            "generator": "build-signature-db",
            "version": "1.0",
            "brew_prefix": str(brew_prefix),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "libraries_scanned": len(libs),
            "scan_cellar": args.scan_cellar,
            "elapsed_seconds": round(elapsed, 2),
        },
        "signatures": list(all_sigs.values()),
        "total": len(all_sigs),
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\nToplam: {len(all_sigs)} unique signature -> {output_path}")
    print(f"Sure: {elapsed:.1f}s")

    return 0


if __name__ == "__main__":
    sys.exit(main())
