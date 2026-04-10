#!/usr/bin/env python3
"""Karadul Signature Generator -- Parse C/C++ headers to extract function signatures.

Uses clang AST dump (preferred) or regex fallback to extract function declarations
from macOS SDK headers and Homebrew-installed libraries. Outputs in the JSON format
that SignatureDB.load_external_signatures() expects.

Usage:
    # Generate all signatures (macOS SDK + Homebrew)
    python tools/generate_signatures.py

    # Only macOS SDK
    python tools/generate_signatures.py --sdk-only

    # Only Homebrew
    python tools/generate_signatures.py --brew-only

    # Custom output path
    python tools/generate_signatures.py -o /path/to/output.json

    # Include Go/Rust stdlib signatures
    python tools/generate_signatures.py --with-go --with-rust
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Header -> Library/Category Mapping
# ---------------------------------------------------------------------------

# Map include-path fragments to (library_name, category)
# Order matters: first match wins
_HEADER_LIB_MAP: list[tuple[str, str, str]] = [
    # macOS SDK specific
    ("CommonCrypto/", "CommonCrypto", "crypto"),
    ("EndpointSecurity/", "EndpointSecurity", "security"),
    ("Spatial/", "Spatial", "math"),
    ("dispatch/", "libdispatch", "concurrency"),
    ("xpc/", "libxpc", "ipc"),
    ("os/", "libos", "system"),
    ("objc/", "libobjc", "runtime"),
    ("mach-o/", "libmacho", "binary"),
    ("mach/", "libmach", "kernel"),
    ("kern/", "libkern", "kernel"),
    ("libkern/", "libkern", "kernel"),
    ("simd/", "simd", "math"),
    ("sys/", "libc", "system"),
    ("arpa/", "libc", "network"),
    ("netinet/", "libc", "network"),
    ("netinet6/", "libc", "network"),
    ("net/", "libc", "network"),
    ("bsm/", "libbsm", "security"),
    ("security/", "pam", "security"),
    ("sasl/", "libsasl", "security"),
    ("pthread/", "libpthread", "concurrency"),
    ("readline/", "readline", "misc"),
    ("editline/", "editline", "misc"),
    ("curl/", "libcurl", "network"),
    ("libxml/", "libxml2", "xml"),
    ("libxml2/", "libxml2", "xml"),
    ("libxslt/", "libxslt", "xml"),
    ("libexslt/", "libexslt", "xml"),
    ("libDER/", "libDER", "crypto"),
    ("pcap/", "libpcap", "network"),
    ("cups/", "cups", "misc"),
    ("apache2/", "apache", "network"),
    ("apr-1/", "apr", "misc"),
    ("unicode/", "icu", "text"),
    ("uuid/", "libuuid", "misc"),
    ("ffi/", "libffi", "misc"),
    ("gssapi/", "gssapi", "security"),
    ("krb5/", "kerberos", "security"),
    ("hfs/", "hfs", "filesystem"),
    ("tidy/", "libtidy", "xml"),
    ("rpc/", "rpc", "network"),
    ("xar/", "libxar", "compression"),
    ("hvf/", "hypervisor", "system"),
    ("net-snmp/", "net-snmp", "network"),
    ("architecture/", "architecture", "system"),
    ("atm/", "atm", "kernel"),

    # Homebrew libraries
    ("openssl/", "openssl", "crypto"),
    ("SDL2/", "SDL2", "multimedia"),
    ("cairo/", "cairo", "graphics"),
    ("glib-2.0/", "glib", "misc"),
    ("gnutls/", "gnutls", "crypto"),
    ("nghttp2/", "nghttp2", "network"),
    ("nghttp3/", "nghttp3", "network"),
    ("ngtcp2/", "ngtcp2", "network"),
    ("event2/", "libevent", "event_loop"),
    ("uv/", "libuv", "event_loop"),
    ("libavcodec/", "ffmpeg", "multimedia"),
    ("libavformat/", "ffmpeg", "multimedia"),
    ("libavutil/", "ffmpeg", "multimedia"),
    ("libavfilter/", "ffmpeg", "multimedia"),
    ("libavdevice/", "ffmpeg", "multimedia"),
    ("libswresample/", "ffmpeg", "multimedia"),
    ("libswscale/", "ffmpeg", "multimedia"),
    ("libpng16/", "libpng", "image"),
    ("webp/", "libwebp", "image"),
    ("brotli/", "brotli", "compression"),
    ("lzma/", "liblzma", "compression"),
    ("lzo/", "lzo", "compression"),
    ("nettle/", "nettle", "crypto"),
    ("opus/", "opus", "audio"),
    ("lame/", "lame", "audio"),
    ("vpx/", "libvpx", "multimedia"),
    ("node/", "nodejs", "runtime"),
    ("fontconfig/", "fontconfig", "graphics"),
    ("freetype2/", "freetype", "graphics"),
    ("harfbuzz/", "harfbuzz", "text"),
    ("pixman-1/", "pixman", "graphics"),
    ("jxl/", "libjxl", "image"),
    ("hdr/", "libhdr", "image"),
    ("libheif/", "libheif", "image"),
    ("libde265/", "libde265", "multimedia"),
    ("openjpeg-2.5/", "openjpeg", "image"),
    ("Imath/", "imath", "math"),
    ("OpenEXR/", "openexr", "image"),
    ("dav1d/", "dav1d", "multimedia"),
    ("aom/", "aom", "multimedia"),
    ("svt-av1/", "svt-av1", "multimedia"),
    ("libusb-1.0/", "libusb", "system"),
    ("hwloc/", "hwloc", "system"),
    ("nss/", "nss", "crypto"),
    ("nspr/", "nspr", "crypto"),
    ("ta-lib/", "talib", "math"),
    ("poppler/", "poppler", "document"),
    ("gperftools/", "gperftools", "profiling"),
    ("ImageMagick-7/", "imagemagick", "image"),
    ("faiss/", "faiss", "ml"),
    ("fmt/", "fmt", "misc"),
    ("X11/", "x11", "graphics"),
    ("GL/", "opengl", "graphics"),
    ("xcb/", "xcb", "graphics"),
    ("p11-kit-1/", "p11kit", "crypto"),
    ("libr/", "radare2", "binary"),
    ("openmpi/", "mpi", "parallel"),
    ("ql/", "quantlib", "math"),
]

# Map individual header filenames (no path) to (library, category)
_HEADER_FILE_MAP: dict[str, tuple[str, str]] = {
    "stdio.h": ("libc", "io"),
    "stdlib.h": ("libc", "memory"),
    "string.h": ("libc", "string"),
    "strings.h": ("libc", "string"),
    "unistd.h": ("libc", "system"),
    "fcntl.h": ("libc", "io"),
    "signal.h": ("libc", "signal"),
    "errno.h": ("libc", "error"),
    "assert.h": ("libc", "debug"),
    "ctype.h": ("libc", "string"),
    "wctype.h": ("libc", "string"),
    "wchar.h": ("libc", "string"),
    "locale.h": ("libc", "locale"),
    "math.h": ("libm", "math"),
    "complex.h": ("libm", "math"),
    "tgmath.h": ("libm", "math"),
    "fenv.h": ("libm", "math"),
    "float.h": ("libc", "math"),
    "inttypes.h": ("libc", "types"),
    "stdint.h": ("libc", "types"),
    "stdarg.h": ("libc", "misc"),
    "setjmp.h": ("libc", "flow"),
    "time.h": ("libc", "time"),
    "dirent.h": ("libc", "filesystem"),
    "glob.h": ("libc", "filesystem"),
    "fnmatch.h": ("libc", "filesystem"),
    "ftw.h": ("libc", "filesystem"),
    "fts.h": ("libc", "filesystem"),
    "spawn.h": ("libc", "process"),
    "poll.h": ("libc", "io"),
    "termios.h": ("libc", "io"),
    "syslog.h": ("libc", "logging"),
    "grp.h": ("libc", "system"),
    "pwd.h": ("libc", "system"),
    "regex.h": ("libc", "regex"),
    "search.h": ("libc", "misc"),
    "iconv.h": ("libiconv", "text"),
    "langinfo.h": ("libc", "locale"),
    "dlfcn.h": ("libdl", "dynamic_loading"),
    "semaphore.h": ("libpthread", "concurrency"),
    "netdb.h": ("libc", "network"),
    "ifaddrs.h": ("libc", "network"),
    "resolv.h": ("libresolv", "network"),
    "aio.h": ("libc", "io"),
    "mqueue.h": ("libc", "ipc"),
    "monetary.h": ("libc", "locale"),
    "ndbm.h": ("libc", "database"),
    "nl_types.h": ("libc", "locale"),
    "utmpx.h": ("libc", "system"),
    "wordexp.h": ("libc", "misc"),
    "tar.h": ("libc", "archive"),
    "limits.h": ("libc", "types"),

    # Homebrew standalone headers
    "ares.h": ("c-ares", "network"),
    "ares_dns.h": ("c-ares", "network"),
    "ares_dns_record.h": ("c-ares", "network"),
    "event.h": ("libevent", "event_loop"),
    "evdns.h": ("libevent", "network"),
    "evhttp.h": ("libevent", "network"),
    "evrpc.h": ("libevent", "network"),
    "evutil.h": ("libevent", "misc"),
    "gcrypt.h": ("libgcrypt", "crypto"),
    "gpgme.h": ("gpgme", "crypto"),
    "gpg-error.h": ("libgpg-error", "crypto"),
    "gpgrt.h": ("libgpg-error", "crypto"),
    "gmp.h": ("gmp", "math"),
    "gif_lib.h": ("giflib", "image"),
    "hwloc.h": ("hwloc", "system"),
    "idn2.h": ("libidn2", "network"),
    "jpeglib.h": ("libjpeg", "image"),
    "jmorecfg.h": ("libjpeg", "image"),
    "jerror.h": ("libjpeg", "image"),
    "ksba.h": ("libksba", "crypto"),
    "assuan.h": ("libassuan", "crypto"),
    "ada.h": ("ada", "network"),
    "ada_c.h": ("ada", "network"),
    "zstd.h": ("zstd", "compression"),
    "lz4.h": ("lz4", "compression"),
    "lz4hc.h": ("lz4", "compression"),
    "lz4frame.h": ("lz4", "compression"),
    "zlib.h": ("zlib", "compression"),
    "bzlib.h": ("bzip2", "compression"),
    "png.h": ("libpng", "image"),
    "sqlite3.h": ("sqlite3", "database"),
    "mysql.h": ("mysql", "database"),
    "libpq-fe.h": ("libpq", "database"),
    "hiredis.h": ("hiredis", "database"),
    "pcre2.h": ("pcre2", "regex"),
    "yaml.h": ("libyaml", "serialization"),
    "expat.h": ("expat", "xml"),
    "jansson.h": ("jansson", "json"),
    "cjson/cJSON.h": ("cjson", "json"),
}


def _resolve_lib_category(header_path: str, func_name: str = "") -> tuple[str, str]:
    """Determine library name and category from a header file path and/or function name."""
    # Try path-fragment matching first
    for fragment, lib, cat in _HEADER_LIB_MAP:
        if fragment in header_path:
            return lib, cat

    # Try filename matching
    basename = os.path.basename(header_path)
    if basename in _HEADER_FILE_MAP:
        return _HEADER_FILE_MAP[basename]

    # Try directory-based resolution
    parts = header_path.split("/")
    for i, part in enumerate(parts):
        if part == "include" and i + 1 < len(parts):
            next_part = parts[i + 1]
            if next_part.endswith(".h"):
                break  # fall through to name-based
            return next_part, "misc"

    # Fallback: resolve from function name prefix
    if func_name:
        clean = func_name.lstrip("_")
        return _resolve_lib_from_name(clean)

    return "unknown", "misc"


# Name-prefix -> (library, category) for functions whose header path is ambiguous
_NAME_PREFIX_LIB_MAP: list[tuple[str, str, str]] = [
    ("gnutls_", "gnutls", "crypto"),
    ("gcry_", "libgcrypt", "crypto"),
    ("gpgme_", "gpgme", "crypto"),
    ("gpg_", "gpgme", "crypto"),
    ("uv_", "libuv", "event_loop"),
    ("nghttp2_", "nghttp2", "network"),
    ("nghttp3_", "nghttp3", "network"),
    ("ngtcp2_", "ngtcp2", "network"),
    ("pcap_", "libpcap", "network"),
    ("pthread_", "libpthread", "concurrency"),
    ("hwloc_", "hwloc", "system"),
    ("evhttp_", "libevent", "network"),
    ("event_", "libevent", "event_loop"),
    ("bufferevent_", "libevent", "event_loop"),
    ("evbuffer_", "libevent", "event_loop"),
    ("evdns_", "libevent", "network"),
    ("evrpc_", "libevent", "network"),
    ("ev_", "libevent", "event_loop"),
    ("xpc_", "libxpc", "ipc"),
    ("dispatch_", "libdispatch", "concurrency"),
    ("xml", "libxml2", "xml"),
    ("html", "libxml2", "xml"),
    ("xslt", "libxslt", "xml"),
    ("exslt", "libexslt", "xml"),
    ("slapi_", "ldap", "network"),
    ("ldap_", "ldap", "network"),
    ("curl_", "libcurl", "network"),
    ("SDL_", "SDL2", "multimedia"),
    ("SDL2_", "SDL2", "multimedia"),
    ("cairo_", "cairo", "graphics"),
    ("png_", "libpng", "image"),
    ("jpeg_", "libjpeg", "image"),
    ("gif_", "giflib", "image"),
    ("webp", "libwebp", "image"),
    ("avcodec_", "ffmpeg", "multimedia"),
    ("avformat_", "ffmpeg", "multimedia"),
    ("av_", "ffmpeg", "multimedia"),
    ("sws_", "ffmpeg", "multimedia"),
    ("swr_", "ffmpeg", "multimedia"),
    ("ares_", "c-ares", "network"),
    ("BIO_", "openssl", "crypto"),
    ("SSL_", "openssl", "crypto"),
    ("EVP_", "openssl", "crypto"),
    ("X509_", "openssl", "crypto"),
    ("RSA_", "openssl", "crypto"),
    ("EC_", "openssl", "crypto"),
    ("DH_", "openssl", "crypto"),
    ("DSA_", "openssl", "crypto"),
    ("BN_", "openssl", "crypto"),
    ("HMAC_", "openssl", "crypto"),
    ("SHA", "openssl", "crypto"),
    ("MD5_", "openssl", "crypto"),
    ("AES_", "openssl", "crypto"),
    ("DES_", "openssl", "crypto"),
    ("RAND_", "openssl", "crypto"),
    ("PEM_", "openssl", "crypto"),
    ("ASN1_", "openssl", "crypto"),
    ("PKCS", "openssl", "crypto"),
    ("ECDSA_", "openssl", "crypto"),
    ("ECDH_", "openssl", "crypto"),
    ("OCSP_", "openssl", "crypto"),
    ("CMS_", "openssl", "crypto"),
    ("CRYPTO_", "openssl", "crypto"),
    ("ENGINE_", "openssl", "crypto"),
    ("OBJ_", "openssl", "crypto"),
    ("OSSL_", "openssl", "crypto"),
    ("ossl_", "openssl", "crypto"),
    ("OPENSSL_", "openssl", "crypto"),
    ("i2d_", "openssl", "crypto"),
    ("d2i_", "openssl", "crypto"),
    ("NCONF_", "openssl", "crypto"),
    ("CONF_", "openssl", "crypto"),
    ("TS_", "openssl", "crypto"),
    ("CT_", "openssl", "crypto"),
    ("CTLOG_", "openssl", "crypto"),
    ("SCT_", "openssl", "crypto"),
    ("STORE_", "openssl", "crypto"),
    ("OSSL_STORE_", "openssl", "crypto"),
    ("OSSL_PARAM_", "openssl", "crypto"),
    ("ERR_", "openssl", "crypto"),
    ("COMP_", "openssl", "crypto"),
    ("KDF_", "openssl", "crypto"),
    ("CMAC_", "openssl", "crypto"),
    ("sqlite3_", "sqlite3", "database"),
    ("g_", "glib", "misc"),
    ("dtrace_", "dtrace", "profiling"),
    ("mach_", "libmach", "kernel"),
    ("task_", "libmach", "kernel"),
    ("thread_", "libmach", "kernel"),
    ("vm_", "libmach", "kernel"),
    ("host_", "libmach", "kernel"),
    ("u8_", "icu", "text"),
    ("u16_", "icu", "text"),
    ("u32_", "icu", "text"),
    ("ucnv_", "icu", "text"),
    ("ucol_", "icu", "text"),
    ("ubrk_", "icu", "text"),
    ("unorm_", "icu", "text"),
    ("uset_", "icu", "text"),
    ("uregex_", "icu", "text"),
    ("udat_", "icu", "text"),
    ("unum_", "icu", "text"),
    ("umsg_", "icu", "text"),
    ("mp_", "gmp", "math"),
    ("mpz_", "gmp", "math"),
    ("mpq_", "gmp", "math"),
    ("mpf_", "gmp", "math"),
    ("mpd_", "mpdecimal", "math"),
    ("ns_", "libresolv", "network"),
    ("res_", "libresolv", "network"),
    ("dn_", "libresolv", "network"),
    ("lzma_", "liblzma", "compression"),
    ("lzo", "lzo", "compression"),
    ("BZ2_", "bzip2", "compression"),
    ("LZ4", "lz4", "compression"),
    ("ZSTD_", "zstd", "compression"),
    ("Brotli", "brotli", "compression"),
    ("deflate", "zlib", "compression"),
    ("inflate", "zlib", "compression"),
    ("compress", "zlib", "compression"),
    ("uncompress", "zlib", "compression"),
    ("MPI_", "mpi", "parallel"),
    ("Magick", "imagemagick", "image"),
    ("NSS_", "nss", "crypto"),
    ("PK11_", "nss", "crypto"),
    ("CERT_", "nss", "crypto"),
    ("SEC_", "nss", "crypto"),
    ("nss_", "nss", "crypto"),
    ("PR_", "nspr", "misc"),
    ("CF", "CoreFoundation", "runtime"),
    ("objc_", "libobjc", "runtime"),
    ("class_", "libobjc", "runtime"),
    ("method_", "libobjc", "runtime"),
    ("sel_", "libobjc", "runtime"),
    ("property_", "libobjc", "runtime"),
    ("protocol_", "libobjc", "runtime"),
    ("ivar_", "libobjc", "runtime"),
    ("object_", "libobjc", "runtime"),
    ("swift_", "swift_runtime", "runtime"),
    ("snmp_", "net-snmp", "network"),
    ("netsnmp_", "net-snmp", "network"),
]


def _resolve_lib_from_name(clean_name: str) -> tuple[str, str]:
    """Resolve library from function name prefix."""
    for prefix, lib, cat in _NAME_PREFIX_LIB_MAP:
        if clean_name.startswith(prefix):
            return lib, cat
    return "unknown", "misc"


# ---------------------------------------------------------------------------
# Purpose Generation
# ---------------------------------------------------------------------------

# Common prefix -> purpose description
_PURPOSE_PREFIXES: list[tuple[str, str]] = [
    # POSIX / libc
    ("str", "string operation"),
    ("mem", "memory operation"),
    ("wcs", "wide-char string operation"),
    ("wmem", "wide-char memory operation"),
    ("mbr", "multibyte/wide-char conversion"),
    ("mbs", "multibyte string operation"),
    ("printf", "formatted output"),
    ("scanf", "formatted input"),
    ("fget", "file get operation"),
    ("fput", "file put operation"),
    ("get", "get operation"),
    ("put", "put operation"),
    ("is", "character classification"),
    ("to", "character conversion"),
    ("sem_", "semaphore operation"),
    ("shm_", "shared memory operation"),
    ("mq_", "message queue operation"),
    ("aio_", "async I/O operation"),
    ("posix_spawn", "POSIX process spawn"),
    ("pthread_mutex", "mutex operation"),
    ("pthread_cond", "condition variable operation"),
    ("pthread_rwlock", "read-write lock operation"),
    ("pthread_barrier", "barrier operation"),
    ("pthread_spin", "spinlock operation"),
    ("pthread_key", "thread-local storage"),
    ("pthread_attr", "thread attribute"),
    ("pthread_", "thread operation"),
    ("clock_", "clock operation"),
    ("timer_", "timer operation"),
    ("sigaction", "signal action"),
    ("sig", "signal operation"),

    # OpenSSL
    ("EVP_", "EVP crypto operation"),
    ("SSL_CTX_", "TLS context operation"),
    ("SSL_", "TLS operation"),
    ("BIO_", "BIO I/O abstraction"),
    ("X509_", "X.509 certificate operation"),
    ("RSA_", "RSA crypto operation"),
    ("EC_", "elliptic curve operation"),
    ("DH_", "Diffie-Hellman operation"),
    ("DSA_", "DSA operation"),
    ("HMAC_", "HMAC operation"),
    ("SHA", "SHA hash operation"),
    ("MD5_", "MD5 hash operation"),
    ("AES_", "AES operation"),
    ("DES_", "DES operation"),
    ("RAND_", "random number generation"),
    ("PEM_", "PEM encoding"),
    ("ASN1_", "ASN.1 operation"),
    ("PKCS", "PKCS operation"),
    ("BN_", "bignum operation"),
    ("ECDSA_", "ECDSA operation"),
    ("ECDH_", "ECDH operation"),
    ("OCSP_", "OCSP operation"),
    ("CMS_", "CMS operation"),
    ("CRYPTO_", "crypto utility"),
    ("ENGINE_", "crypto engine"),
    ("OBJ_", "ASN.1 object operation"),

    # Compression
    ("inflate", "zlib decompression"),
    ("deflate", "zlib compression"),
    ("gz", "gzip operation"),
    ("compress", "compression"),
    ("uncompress", "decompression"),
    ("BZ2_bz", "bzip2 operation"),
    ("LZ4", "LZ4 compression"),
    ("ZSTD_", "zstd compression"),

    # Curl
    ("curl_easy_", "curl easy interface"),
    ("curl_multi_", "curl multi interface"),
    ("curl_mime_", "curl MIME operation"),
    ("curl_url_", "curl URL operation"),
    ("curl_ws_", "curl WebSocket"),
    ("curl_share_", "curl share interface"),
    ("curl_", "curl operation"),

    # SQLite
    ("sqlite3_", "SQLite database operation"),

    # FFmpeg
    ("av_", "FFmpeg/libav operation"),
    ("avcodec_", "FFmpeg codec operation"),
    ("avformat_", "FFmpeg format operation"),
    ("sws_", "FFmpeg pixel conversion"),
    ("swr_", "FFmpeg audio resampling"),
    ("avfilter_", "FFmpeg filter operation"),

    # SDL2
    ("SDL_", "SDL2 multimedia operation"),

    # Cairo
    ("cairo_", "Cairo 2D graphics operation"),

    # GLib
    ("g_", "GLib utility"),

    # libpng
    ("png_", "PNG image operation"),

    # PCAP
    ("pcap_", "packet capture operation"),

    # libevent
    ("event_", "event loop operation"),
    ("bufferevent_", "buffered event operation"),
    ("evbuffer_", "event buffer operation"),

    # libuv
    ("uv_", "libuv event loop operation"),

    # c-ares
    ("ares_", "async DNS operation"),

    # ICU
    ("u_", "ICU Unicode operation"),
    ("ucnv_", "ICU converter operation"),
    ("ucol_", "ICU collation operation"),
    ("ubrk_", "ICU break iterator"),
    ("unorm_", "ICU normalization"),
    ("uset_", "ICU set operation"),
    ("uregex_", "ICU regex operation"),
    ("udat_", "ICU date format"),
    ("unum_", "ICU number format"),
    ("umsg_", "ICU message format"),

    # nghttp2
    ("nghttp2_", "HTTP/2 operation"),

    # GnuTLS
    ("gnutls_", "GnuTLS operation"),

    # libgcrypt
    ("gcry_", "libgcrypt operation"),

    # NSS
    ("NSS_", "NSS crypto operation"),
    ("PK11_", "NSS PKCS#11 operation"),
    ("CERT_", "NSS certificate operation"),
    ("SEC_", "NSS security operation"),

    # Dispatch
    ("dispatch_", "GCD dispatch operation"),

    # XPC
    ("xpc_", "XPC operation"),

    # CoreFoundation
    ("CF", "CoreFoundation operation"),

    # libxml2
    ("xml", "XML operation"),

    # Mach kernel
    ("mach_", "Mach kernel operation"),
    ("task_", "Mach task operation"),
    ("thread_", "Mach thread operation"),
    ("vm_", "virtual memory operation"),
    ("host_", "Mach host operation"),

    # Objective-C runtime
    ("objc_", "Objective-C runtime"),
    ("class_", "ObjC class operation"),
    ("method_", "ObjC method operation"),
    ("sel_", "ObjC selector operation"),
    ("property_", "ObjC property operation"),
    ("protocol_", "ObjC protocol operation"),
    ("ivar_", "ObjC ivar operation"),
    ("object_", "ObjC object operation"),
    ("imp_", "ObjC implementation operation"),

    # dyld / dl
    ("dl", "dynamic linker operation"),

    # ImageMagick
    ("Magick", "ImageMagick operation"),

    # MPI
    ("MPI_", "MPI parallel operation"),

    # hwloc
    ("hwloc_", "hardware locality operation"),

    # QuantLib
    ("ql_", "QuantLib finance operation"),

    # Brotli
    ("BrotliEncoder", "Brotli compression"),
    ("BrotliDecoder", "Brotli decompression"),

    # LZMA
    ("lzma_", "LZMA compression"),
]


def _generate_purpose(func_name: str, lib: str) -> str:
    """Generate a short purpose string for a function name."""
    # Strip leading underscore (macOS C symbol convention)
    clean = func_name.lstrip("_")

    for prefix, purpose in _PURPOSE_PREFIXES:
        if clean.startswith(prefix):
            return purpose

    # Generic purpose from library name
    if lib != "unknown":
        return f"{lib} function"

    return "system function"


# ---------------------------------------------------------------------------
# Clang AST Extraction
# ---------------------------------------------------------------------------

def extract_functions_clang(
    headers: list[str],
    include_paths: list[str] | None = None,
    extra_flags: list[str] | None = None,
) -> list[dict[str, str]]:
    """Extract function declarations using clang AST dump.

    Args:
        headers: List of header files to #include.
        include_paths: Additional -I paths.
        extra_flags: Additional clang flags.

    Returns:
        List of {name, header, return_type} dicts.
    """
    if not headers:
        return []

    # Build the source code
    source = "\n".join(f'#include <{h}>' for h in headers)

    cmd = [
        "clang",
        "-fsyntax-only",
        "-Xclang", "-ast-dump=json",
        "-x", "c",
        "-w",  # suppress warnings
    ]

    if include_paths:
        for ip in include_paths:
            cmd.extend(["-I", ip])

    if extra_flags:
        cmd.extend(extra_flags)

    cmd.append("-")

    try:
        result = subprocess.run(
            cmd,
            input=source,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Clang timed out for %d headers", len(headers))
        return []
    except FileNotFoundError:
        logger.error("clang not found. Install Xcode Command Line Tools.")
        return []

    if result.returncode != 0:
        # Some headers may fail; log but don't crash
        logger.debug("Clang returned %d for headers batch", result.returncode)

    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("Failed to parse clang AST JSON output")
        return []

    functions = []
    seen = set()

    for item in data.get("inner", []):
        if item.get("kind") != "FunctionDecl":
            continue

        name = item.get("name", "")
        if not name or name.startswith("__") or name in seen:
            continue

        # Skip compiler builtins
        if name.startswith("__builtin_"):
            continue

        seen.add(name)

        # Extract return type from the type string
        type_info = item.get("type", {})
        qual_type = type_info.get("qualType", "")
        ret_type = qual_type.split("(")[0].strip() if "(" in qual_type else qual_type

        # Try to figure out which header it came from
        loc = item.get("loc", {})
        header = ""
        if "includedFrom" in loc:
            header = loc["includedFrom"].get("file", "")
        elif "file" in loc:
            header = loc.get("file", "")
        elif "expansionLoc" in loc:
            exp = loc["expansionLoc"]
            if "includedFrom" in exp:
                header = exp["includedFrom"].get("file", "")
            elif "file" in exp:
                header = exp.get("file", "")

        functions.append({
            "name": name,
            "header": header,
            "return_type": ret_type,
        })

    return functions


# ---------------------------------------------------------------------------
# Regex Fallback Extraction
# ---------------------------------------------------------------------------

# Regex to match C function declarations
_FUNC_DECL_RE = re.compile(
    r"""
    (?:^|\n)\s*                         # line start
    (?:extern\s+)?                      # optional extern
    (?:__attribute__\s*\([^)]*\)\s*)?   # optional __attribute__
    (?:static\s+inline\s+)?            # optional static inline
    (?:const\s+)?                       # optional const
    (                                   # return type group
        (?:unsigned\s+|signed\s+|long\s+|short\s+)*
        (?:void|int|char|float|double|size_t|ssize_t|off_t|pid_t|uid_t|gid_t
           |FILE|DIR|time_t|clock_t|socklen_t|in_addr_t|mode_t|dev_t|ino_t|nlink_t
           |(?:[A-Z]\w+)                # CapitalizedType
        )
        \s*\**                          # optional pointer stars
    )
    \s+
    (\w+)                               # function name
    \s*\(                               # opening paren
    """,
    re.VERBOSE | re.MULTILINE,
)


def extract_functions_regex(header_path: str) -> list[dict[str, str]]:
    """Extract function declarations using regex (fallback method).

    Less reliable than clang AST but works for headers that clang can't parse.
    """
    try:
        with open(header_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, IOError):
        return []

    functions = []
    seen = set()

    for match in _FUNC_DECL_RE.finditer(content):
        ret_type = match.group(1).strip()
        name = match.group(2)

        if name.startswith("__") or name in seen:
            continue
        if name in ("if", "for", "while", "switch", "return", "sizeof", "typedef"):
            continue

        seen.add(name)
        functions.append({
            "name": name,
            "header": header_path,
            "return_type": ret_type,
        })

    return functions


# ---------------------------------------------------------------------------
# macOS SDK Header Discovery
# ---------------------------------------------------------------------------

_SDK_BASE = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include"

# Headers grouped for batched clang AST extraction
_SDK_HEADER_GROUPS: dict[str, list[str]] = {
    "posix_core": [
        "stdio.h", "stdlib.h", "string.h", "strings.h", "unistd.h",
        "fcntl.h", "signal.h", "errno.h", "ctype.h", "wctype.h",
        "wchar.h", "locale.h", "time.h", "dirent.h", "grp.h", "pwd.h",
        "glob.h", "fnmatch.h", "regex.h", "search.h", "wordexp.h",
        "langinfo.h", "monetary.h", "nl_types.h", "syslog.h",
        "setjmp.h", "assert.h", "limits.h", "float.h", "inttypes.h",
        "stdint.h",
    ],
    "posix_io": [
        "poll.h", "termios.h", "aio.h",
        "sys/stat.h", "sys/types.h", "sys/mman.h", "sys/time.h",
        "sys/wait.h", "sys/ioctl.h", "sys/select.h", "sys/uio.h",
        "sys/resource.h", "sys/file.h", "sys/mount.h",
        "sys/param.h", "sys/sysctl.h", "sys/event.h",
        "sys/socket.h", "sys/un.h", "sys/shm.h", "sys/sem.h",
        "sys/msg.h", "sys/ipc.h",
    ],
    "posix_network": [
        "netinet/in.h", "arpa/inet.h", "netdb.h", "ifaddrs.h",
        "net/if.h",
    ],
    "posix_process": [
        "spawn.h", "semaphore.h",
    ],
    "posix_math": [
        "math.h", "complex.h", "fenv.h",
    ],
    "pthread": [
        "pthread.h",
    ],
    "dlfcn": [
        "dlfcn.h",
    ],
    "iconv": [
        "iconv.h",
    ],
    "dispatch": [
        "dispatch/dispatch.h",
    ],
    "xpc": [
        "xpc/xpc.h",
    ],
    "objc": [
        "objc/runtime.h", "objc/message.h",
    ],
    "common_crypto": [
        "CommonCrypto/CommonCrypto.h",
    ],
    "mach": [
        "mach/mach.h",
    ],
    "curl": [
        "curl/curl.h",
    ],
    "libxml2": [
        "libxml/parser.h", "libxml/tree.h", "libxml/xpath.h",
        "libxml/xmlreader.h", "libxml/xmlwriter.h",
        "libxml/HTMLparser.h", "libxml/HTMLtree.h",
    ],
    "pcap": [
        "pcap/pcap.h",
    ],
    "readline": [
        "readline/readline.h", "readline/history.h",
    ],
    "uuid": [
        "uuid/uuid.h",
    ],
    "macho": [
        "mach-o/loader.h", "mach-o/nlist.h", "mach-o/dyld.h",
    ],
}

# Additional SDK headers for regex-based extraction (harder to clang-parse)
_SDK_REGEX_HEADERS: list[str] = [
    "EndpointSecurity/EndpointSecurity.h",
    "Spatial/Spatial.h",
    "os/log.h", "os/signpost.h", "os/lock.h", "os/activity.h",
]


# ---------------------------------------------------------------------------
# Homebrew Header Discovery
# ---------------------------------------------------------------------------

_BREW_BASE = "/opt/homebrew/include"

# Homebrew header groups for clang AST extraction
_BREW_HEADER_GROUPS: dict[str, list[str]] = {
    "openssl": [
        "openssl/ssl.h", "openssl/evp.h", "openssl/bio.h",
        "openssl/x509.h", "openssl/rsa.h", "openssl/ec.h",
        "openssl/dh.h", "openssl/hmac.h", "openssl/sha.h",
        "openssl/md5.h", "openssl/aes.h", "openssl/rand.h",
        "openssl/pem.h", "openssl/err.h", "openssl/bn.h",
        "openssl/asn1.h", "openssl/pkcs12.h", "openssl/cms.h",
        "openssl/ocsp.h", "openssl/engine.h", "openssl/crypto.h",
        "openssl/objects.h", "openssl/conf.h", "openssl/ct.h",
        "openssl/kdf.h", "openssl/ts.h",
    ],
    "libevent": [
        "event2/event.h", "event2/buffer.h", "event2/bufferevent.h",
        "event2/http.h", "event2/dns.h", "event2/listener.h",
        "event2/util.h", "event2/thread.h",
    ],
    "libuv": [
        "uv.h",
    ],
    "c_ares": [
        "ares.h",
    ],
    "nghttp2": [
        "nghttp2/nghttp2.h",
    ],
    "SDL2": [
        "SDL2/SDL.h",
    ],
    "gnutls": [
        "gnutls/gnutls.h", "gnutls/x509.h", "gnutls/crypto.h",
    ],
    "gcrypt": [
        "gcrypt.h",
    ],
    "gpgme": [
        "gpgme.h",
    ],
    "gmp": [
        "gmp.h",
    ],
    "jpeg": [
        "jpeglib.h",
    ],
    "gif": [
        "gif_lib.h",
    ],
    "idn2": [
        "idn2.h",
    ],
    "hwloc": [
        "hwloc.h",
    ],
}


# ---------------------------------------------------------------------------
# Go stdlib extraction
# ---------------------------------------------------------------------------

def extract_go_stdlib() -> list[dict[str, Any]]:
    """Extract Go standard library function signatures using 'go doc'.

    Requires Go to be installed.
    """
    try:
        result = subprocess.run(
            ["go", "list", "std"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.info("Go not found or timed out, skipping Go stdlib extraction")
        return []

    if result.returncode != 0:
        return []

    packages = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
    # Filter out internal/vendor packages
    packages = [
        p for p in packages
        if not p.startswith("internal/")
        and not p.startswith("vendor/")
        and not p.startswith("cmd/")
    ]

    signatures: list[dict[str, Any]] = []
    seen = set()

    for pkg in packages:
        try:
            doc_result = subprocess.run(
                ["go", "doc", "-all", pkg],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            continue

        if doc_result.returncode != 0:
            continue

        # Extract function declarations: func FuncName(...)
        for match in re.finditer(r'^func\s+(\w+)\(', doc_result.stdout, re.MULTILINE):
            name = match.group(1)
            full_name = f"runtime.{pkg}.{name}" if pkg != "runtime" else f"runtime.{name}"
            # Use Go symbol format: package.Function
            go_name = f"{pkg}.{name}"

            if go_name in seen:
                continue
            seen.add(go_name)

            signatures.append({
                "name": go_name,
                "library": "go_stdlib",
                "category": "go",
                "purpose": f"Go {pkg} function",
            })

    logger.info("Extracted %d Go stdlib signatures", len(signatures))
    return signatures


# ---------------------------------------------------------------------------
# Rust stdlib extraction
# ---------------------------------------------------------------------------

def extract_rust_stdlib() -> list[dict[str, Any]]:
    """Extract Rust standard library demangled function names.

    Uses a curated list of common Rust std patterns that appear in binaries.
    """
    # Rust functions appear in binaries with mangled names
    # Common patterns from std, core, alloc
    _RUST_STD_FUNCS = [
        # std::io
        ("std::io::Read::read", "std::io", "I/O read trait"),
        ("std::io::Write::write", "std::io", "I/O write trait"),
        ("std::io::Write::flush", "std::io", "I/O flush"),
        ("std::io::BufReader::new", "std::io", "buffered reader creation"),
        ("std::io::BufWriter::new", "std::io", "buffered writer creation"),
        ("std::io::copy", "std::io", "stream copy"),
        ("std::io::stdin", "std::io", "stdin handle"),
        ("std::io::stdout", "std::io", "stdout handle"),
        ("std::io::stderr", "std::io", "stderr handle"),

        # std::fs
        ("std::fs::read", "std::fs", "file read"),
        ("std::fs::write", "std::fs", "file write"),
        ("std::fs::read_to_string", "std::fs", "file read to string"),
        ("std::fs::create_dir", "std::fs", "directory creation"),
        ("std::fs::create_dir_all", "std::fs", "recursive directory creation"),
        ("std::fs::remove_file", "std::fs", "file removal"),
        ("std::fs::remove_dir", "std::fs", "directory removal"),
        ("std::fs::remove_dir_all", "std::fs", "recursive directory removal"),
        ("std::fs::rename", "std::fs", "file rename"),
        ("std::fs::copy", "std::fs", "file copy"),
        ("std::fs::metadata", "std::fs", "file metadata"),
        ("std::fs::symlink_metadata", "std::fs", "symlink metadata"),
        ("std::fs::canonicalize", "std::fs", "path canonicalization"),
        ("std::fs::read_dir", "std::fs", "directory reading"),
        ("std::fs::read_link", "std::fs", "symlink reading"),
        ("std::fs::File::open", "std::fs", "file open"),
        ("std::fs::File::create", "std::fs", "file create"),
        ("std::fs::OpenOptions::new", "std::fs", "file open options"),

        # std::net
        ("std::net::TcpStream::connect", "std::net", "TCP connection"),
        ("std::net::TcpListener::bind", "std::net", "TCP listener bind"),
        ("std::net::TcpListener::accept", "std::net", "TCP accept connection"),
        ("std::net::UdpSocket::bind", "std::net", "UDP socket bind"),
        ("std::net::UdpSocket::send_to", "std::net", "UDP send"),
        ("std::net::UdpSocket::recv_from", "std::net", "UDP receive"),
        ("std::net::SocketAddr::new", "std::net", "socket address creation"),
        ("std::net::IpAddr::V4", "std::net", "IPv4 address"),
        ("std::net::IpAddr::V6", "std::net", "IPv6 address"),
        ("std::net::lookup_host", "std::net", "DNS lookup"),

        # std::thread
        ("std::thread::spawn", "std::thread", "thread spawn"),
        ("std::thread::sleep", "std::thread", "thread sleep"),
        ("std::thread::current", "std::thread", "current thread"),
        ("std::thread::park", "std::thread", "thread park"),
        ("std::thread::yield_now", "std::thread", "thread yield"),
        ("std::thread::Builder::new", "std::thread", "thread builder"),
        ("std::thread::JoinHandle::join", "std::thread", "thread join"),

        # std::sync
        ("std::sync::Mutex::new", "std::sync", "mutex creation"),
        ("std::sync::Mutex::lock", "std::sync", "mutex lock"),
        ("std::sync::RwLock::new", "std::sync", "read-write lock creation"),
        ("std::sync::RwLock::read", "std::sync", "read lock"),
        ("std::sync::RwLock::write", "std::sync", "write lock"),
        ("std::sync::Arc::new", "std::sync", "atomic ref count creation"),
        ("std::sync::Arc::clone", "std::sync", "atomic ref count clone"),
        ("std::sync::mpsc::channel", "std::sync", "channel creation"),
        ("std::sync::mpsc::sync_channel", "std::sync", "sync channel creation"),
        ("std::sync::Condvar::new", "std::sync", "condition variable"),
        ("std::sync::Condvar::wait", "std::sync", "condition wait"),
        ("std::sync::Condvar::notify_one", "std::sync", "condition notify one"),
        ("std::sync::Condvar::notify_all", "std::sync", "condition notify all"),
        ("std::sync::Barrier::new", "std::sync", "barrier creation"),
        ("std::sync::Barrier::wait", "std::sync", "barrier wait"),
        ("std::sync::Once::new", "std::sync", "once init"),
        ("std::sync::Once::call_once", "std::sync", "one-time initialization"),

        # std::collections
        ("std::collections::HashMap::new", "std::collections", "hash map creation"),
        ("std::collections::HashMap::insert", "std::collections", "hash map insert"),
        ("std::collections::HashMap::get", "std::collections", "hash map get"),
        ("std::collections::HashMap::remove", "std::collections", "hash map remove"),
        ("std::collections::HashMap::contains_key", "std::collections", "hash map key check"),
        ("std::collections::HashSet::new", "std::collections", "hash set creation"),
        ("std::collections::HashSet::insert", "std::collections", "hash set insert"),
        ("std::collections::BTreeMap::new", "std::collections", "B-tree map creation"),
        ("std::collections::BTreeMap::insert", "std::collections", "B-tree map insert"),
        ("std::collections::BTreeSet::new", "std::collections", "B-tree set creation"),
        ("std::collections::VecDeque::new", "std::collections", "double-ended queue creation"),
        ("std::collections::LinkedList::new", "std::collections", "linked list creation"),
        ("std::collections::BinaryHeap::new", "std::collections", "binary heap creation"),

        # std::string/vec
        ("alloc::string::String::new", "alloc", "string creation"),
        ("alloc::string::String::from", "alloc", "string from conversion"),
        ("alloc::string::String::push_str", "alloc", "string append"),
        ("alloc::string::String::push", "alloc", "string push char"),
        ("alloc::string::String::with_capacity", "alloc", "pre-allocated string"),
        ("alloc::vec::Vec::new", "alloc", "vector creation"),
        ("alloc::vec::Vec::push", "alloc", "vector push"),
        ("alloc::vec::Vec::pop", "alloc", "vector pop"),
        ("alloc::vec::Vec::with_capacity", "alloc", "pre-allocated vector"),
        ("alloc::vec::Vec::extend", "alloc", "vector extend"),
        ("alloc::vec::Vec::reserve", "alloc", "vector reserve"),
        ("alloc::vec::Vec::resize", "alloc", "vector resize"),
        ("alloc::vec::Vec::truncate", "alloc", "vector truncate"),
        ("alloc::vec::Vec::sort", "alloc", "vector sort"),
        ("alloc::boxed::Box::new", "alloc", "heap allocation"),

        # core operations
        ("core::fmt::write", "core", "formatted write"),
        ("core::fmt::Display::fmt", "core", "display formatting"),
        ("core::fmt::Debug::fmt", "core", "debug formatting"),
        ("core::panicking::panic", "core", "panic handler"),
        ("core::panicking::panic_fmt", "core", "formatted panic"),
        ("core::result::unwrap_failed", "core", "unwrap failure"),
        ("core::option::expect_failed", "core", "expect failure"),
        ("core::slice::sort::merge_sort", "core", "merge sort"),
        ("core::slice::sort::quicksort", "core", "quicksort"),
        ("core::ptr::drop_in_place", "core", "drop in place"),
        ("core::ops::function::FnOnce::call_once", "core", "closure call"),
        ("core::ops::function::Fn::call", "core", "function call"),
        ("core::cmp::Ord::cmp", "core", "ordered comparison"),
        ("core::hash::Hash::hash", "core", "hash computation"),
        ("core::iter::Iterator::next", "core", "iterator next"),
        ("core::iter::Iterator::map", "core", "iterator map"),
        ("core::iter::Iterator::filter", "core", "iterator filter"),
        ("core::iter::Iterator::collect", "core", "iterator collect"),
        ("core::iter::Iterator::fold", "core", "iterator fold"),
        ("core::iter::Iterator::for_each", "core", "iterator for_each"),

        # std::process
        ("std::process::Command::new", "std::process", "process command creation"),
        ("std::process::Command::arg", "std::process", "command argument"),
        ("std::process::Command::args", "std::process", "command arguments"),
        ("std::process::Command::spawn", "std::process", "process spawn"),
        ("std::process::Command::output", "std::process", "process output capture"),
        ("std::process::Command::status", "std::process", "process status"),
        ("std::process::exit", "std::process", "process exit"),
        ("std::process::abort", "std::process", "process abort"),

        # std::env
        ("std::env::var", "std::env", "environment variable"),
        ("std::env::args", "std::env", "command arguments"),
        ("std::env::current_dir", "std::env", "current directory"),
        ("std::env::set_current_dir", "std::env", "set current directory"),
        ("std::env::home_dir", "std::env", "home directory"),
        ("std::env::temp_dir", "std::env", "temp directory"),

        # std::path
        ("std::path::Path::new", "std::path", "path creation"),
        ("std::path::Path::exists", "std::path", "path existence check"),
        ("std::path::Path::is_file", "std::path", "file check"),
        ("std::path::Path::is_dir", "std::path", "directory check"),
        ("std::path::Path::join", "std::path", "path join"),
        ("std::path::Path::extension", "std::path", "file extension"),
        ("std::path::Path::file_name", "std::path", "file name"),
        ("std::path::Path::parent", "std::path", "parent directory"),
        ("std::path::PathBuf::new", "std::path", "owned path creation"),
        ("std::path::PathBuf::push", "std::path", "path push"),

        # std::time
        ("std::time::Instant::now", "std::time", "monotonic clock"),
        ("std::time::Instant::elapsed", "std::time", "elapsed time"),
        ("std::time::SystemTime::now", "std::time", "system clock"),
        ("std::time::Duration::from_secs", "std::time", "duration from seconds"),
        ("std::time::Duration::from_millis", "std::time", "duration from millis"),
        ("std::time::Duration::from_nanos", "std::time", "duration from nanos"),

        # Crypto-related
        ("std::hash::BuildHasher::build_hasher", "std", "hasher construction"),
        ("std::hash::Hasher::write", "std", "hasher write"),
        ("std::hash::Hasher::finish", "std", "hasher finish"),
    ]

    signatures = []
    for name, lib, purpose in _RUST_STD_FUNCS:
        signatures.append({
            "name": name,
            "library": "rust_std",
            "category": "rust",
            "purpose": purpose,
        })

    logger.info("Generated %d Rust stdlib signatures", len(signatures))
    return signatures


# ---------------------------------------------------------------------------
# Main Generation Pipeline
# ---------------------------------------------------------------------------

def generate_from_headers(
    header_groups: dict[str, list[str]],
    include_base: str,
    extra_include_paths: list[str] | None = None,
    extra_flags: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate signatures from grouped header files.

    Args:
        header_groups: Group name -> list of header paths.
        include_base: Base include path.
        extra_include_paths: Additional -I paths.
        extra_flags: Additional clang flags.

    Returns:
        List of signature dicts ready for JSON output.
    """
    all_sigs: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    inc_paths = [include_base]
    if extra_include_paths:
        inc_paths.extend(extra_include_paths)

    for group_name, headers in header_groups.items():
        logger.info("Processing header group: %s (%d headers)", group_name, len(headers))

        funcs = extract_functions_clang(headers, inc_paths, extra_flags)

        if not funcs:
            logger.warning("  No functions from clang AST for %s, trying regex fallback", group_name)
            for h in headers:
                full_path = os.path.join(include_base, h)
                if os.path.exists(full_path):
                    funcs.extend(extract_functions_regex(full_path))

        group_added = 0
        for func in funcs:
            name = func["name"]
            if name in seen_names:
                continue
            seen_names.add(name)

            header = func.get("header", "")
            lib, cat = _resolve_lib_category(header, name)

            # For binary analysis, functions appear with _ prefix on macOS
            sig_name = f"_{name}" if not name.startswith("_") else name

            purpose = _generate_purpose(name, lib)

            all_sigs.append({
                "name": sig_name,
                "library": lib,
                "category": cat,
                "purpose": purpose,
            })
            group_added += 1

        logger.info("  -> %d new signatures from %s", group_added, group_name)

    return all_sigs


def generate_from_regex_scan(
    base_dir: str,
    exclude_dirs: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Scan all .h files in a directory tree using regex extraction.

    Slower but catches headers that clang can't parse in batch mode.
    """
    if not os.path.isdir(base_dir):
        return []

    exclude = exclude_dirs or {"c++", "boost", "eigen3", "node", "faiss"}
    all_sigs: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    for root, dirs, files in os.walk(base_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude]

        for fname in files:
            if not fname.endswith(".h"):
                continue

            fpath = os.path.join(root, fname)
            funcs = extract_functions_regex(fpath)

            for func in funcs:
                name = func["name"]
                if name in seen_names:
                    continue
                seen_names.add(name)

                lib, cat = _resolve_lib_category(fpath, name)
                sig_name = f"_{name}" if not name.startswith("_") else name
                purpose = _generate_purpose(name, lib)

                all_sigs.append({
                    "name": sig_name,
                    "library": lib,
                    "category": cat,
                    "purpose": purpose,
                })

    return all_sigs


def deduplicate_against_existing(
    new_sigs: list[dict[str, Any]],
    existing_db_path: str,
) -> list[dict[str, Any]]:
    """Remove signatures that already exist in signature_db.py.

    Reads the existing DB file and removes any new signatures whose names
    already appear in the builtin DB.
    """
    existing_names: set[str] = set()

    try:
        with open(existing_db_path, "r") as f:
            for line in f:
                line = line.strip()
                # Match patterns like: "_function_name": {"lib": ...
                m = re.match(r'^"(_?\w+)":\s*\{', line)
                if m:
                    existing_names.add(m.group(1))
                # Also match: "$sSomeMangledName": {"lib": ...
                m2 = re.match(r'^"(\$\w+)":\s*\{', line)
                if m2:
                    existing_names.add(m2.group(1))
    except (OSError, IOError):
        logger.warning("Could not read existing DB for dedup: %s", existing_db_path)
        return new_sigs

    before = len(new_sigs)
    filtered = [s for s in new_sigs if s["name"] not in existing_names]
    removed = before - len(filtered)

    if removed > 0:
        logger.info("Deduplication: removed %d entries already in builtin DB", removed)

    return filtered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate function signatures from C/C++ headers for Karadul."
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output JSON file path (default: sigs/generated_signatures.json in project root)",
    )
    parser.add_argument("--sdk-only", action="store_true", help="Only process macOS SDK headers")
    parser.add_argument("--brew-only", action="store_true", help="Only process Homebrew headers")
    parser.add_argument("--with-go", action="store_true", help="Include Go stdlib signatures")
    parser.add_argument("--with-rust", action="store_true", help="Include Rust stdlib signatures")
    parser.add_argument("--regex-scan", action="store_true", help="Also run regex scan on all headers")
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Project root directory",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    project_root = Path(args.project_root)
    existing_db = project_root / "karadul" / "analyzers" / "signature_db.py"

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        sigs_dir = project_root / "sigs"
        sigs_dir.mkdir(exist_ok=True)
        output_path = sigs_dir / "generated_signatures.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_signatures: list[dict[str, Any]] = []

    # ---- macOS SDK Headers ----
    if not args.brew_only:
        if os.path.isdir(_SDK_BASE):
            logger.info("=" * 60)
            logger.info("Processing macOS SDK headers: %s", _SDK_BASE)
            logger.info("=" * 60)

            sdk_sigs = generate_from_headers(
                _SDK_HEADER_GROUPS,
                _SDK_BASE,
                extra_include_paths=[
                    os.path.join(_SDK_BASE, "libxml2"),  # libxml2 has its own subdir
                ],
            )
            all_signatures.extend(sdk_sigs)

            # Regex scan for remaining headers
            if args.regex_scan:
                logger.info("Running regex scan on remaining SDK headers...")
                seen_clang = {s["name"] for s in sdk_sigs}
                regex_sigs = generate_from_regex_scan(
                    _SDK_BASE,
                    exclude_dirs={"c++", "_modules", "architecture", "i386", "arm", "arm64", "machine"},
                )
                regex_sigs = [s for s in regex_sigs if s["name"] not in seen_clang]
                all_signatures.extend(regex_sigs)
                logger.info("Regex scan added %d more signatures", len(regex_sigs))
        else:
            logger.warning("macOS SDK not found at %s", _SDK_BASE)

    # ---- Homebrew Headers ----
    if not args.sdk_only:
        if os.path.isdir(_BREW_BASE):
            logger.info("=" * 60)
            logger.info("Processing Homebrew headers: %s", _BREW_BASE)
            logger.info("=" * 60)

            brew_sigs = generate_from_headers(
                _BREW_HEADER_GROUPS,
                _BREW_BASE,
                extra_include_paths=[
                    "/opt/homebrew/opt/openssl/include",
                    "/opt/homebrew/opt/libevent/include",
                ],
            )
            all_signatures.extend(brew_sigs)

            # Regex scan for additional homebrew headers
            if args.regex_scan:
                logger.info("Running regex scan on remaining Homebrew headers...")
                seen_brew = {s["name"] for s in brew_sigs}
                brew_regex = generate_from_regex_scan(
                    _BREW_BASE,
                    exclude_dirs={"c++", "boost", "eigen3", "node", "faiss", "ImageMagick-7"},
                )
                brew_regex = [s for s in brew_regex if s["name"] not in seen_brew]
                all_signatures.extend(brew_regex)
                logger.info("Regex scan added %d more Homebrew signatures", len(brew_regex))
        else:
            logger.warning("Homebrew include dir not found at %s", _BREW_BASE)

    # ---- Go stdlib ----
    if args.with_go:
        logger.info("=" * 60)
        logger.info("Processing Go standard library")
        logger.info("=" * 60)
        go_sigs = extract_go_stdlib()
        all_signatures.extend(go_sigs)

    # ---- Rust stdlib ----
    if args.with_rust:
        logger.info("=" * 60)
        logger.info("Processing Rust standard library")
        logger.info("=" * 60)
        rust_sigs = extract_rust_stdlib()
        all_signatures.extend(rust_sigs)

    # ---- Deduplication ----
    logger.info("=" * 60)
    logger.info("Deduplicating against existing builtin DB...")
    all_signatures = deduplicate_against_existing(all_signatures, str(existing_db))

    # ---- Final dedup within generated set ----
    seen: set[str] = set()
    unique_sigs: list[dict[str, Any]] = []
    for sig in all_signatures:
        if sig["name"] not in seen:
            seen.add(sig["name"])
            unique_sigs.append(sig)
    all_signatures = unique_sigs

    # ---- Stats ----
    lib_counts: dict[str, int] = defaultdict(int)
    cat_counts: dict[str, int] = defaultdict(int)
    for sig in all_signatures:
        lib_counts[sig["library"]] += 1
        cat_counts[sig["category"]] += 1

    logger.info("=" * 60)
    logger.info("GENERATION COMPLETE")
    logger.info("=" * 60)
    logger.info("Total new signatures: %d", len(all_signatures))
    logger.info("")
    logger.info("By library (top 30):")
    for lib, count in sorted(lib_counts.items(), key=lambda x: -x[1])[:30]:
        logger.info("  %-25s %5d", lib, count)
    logger.info("")
    logger.info("By category:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        logger.info("  %-25s %5d", cat, count)

    # ---- Write output ----
    output_data = {
        "version": "1.0",
        "generator": "tools/generate_signatures.py",
        "total": len(all_signatures),
        "stats": {
            "by_library": dict(sorted(lib_counts.items(), key=lambda x: -x[1])),
            "by_category": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
        },
        "signatures": all_signatures,
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=1)

    logger.info("")
    logger.info("Output written to: %s", output_path)
    logger.info("File size: %.1f MB", output_path.stat().st_size / 1024 / 1024)
    logger.info("")
    logger.info("To use: place in project's sigs/ directory or reference in config.")
    logger.info("SignatureDB will auto-load from: <project_root>/sigs/*.json")


if __name__ == "__main__":
    main()
