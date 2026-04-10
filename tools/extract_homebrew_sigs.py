#!/usr/bin/env python3
"""
Extract function signatures from all Homebrew-installed libraries.

Scans /opt/homebrew/Cellar/<pkg>/<version>/lib/ for .dylib and .a files,
runs `nm -gU` to extract exported symbols, categorizes them, and outputs
a JSON signature file compatible with black-widow's signature format.

Deduplicates against existing signatures in combined_1M.json.
"""

import subprocess
import os
import glob
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# ── Config ──────────────────────────────────────────────────────────────────
CELLAR = "/opt/homebrew/Cellar"
OUTPUT = "/Users/apple/Desktop/black-widow/sigs/homebrew_symbols.json"
COMBINED = "/Users/apple/Desktop/black-widow/sigs/combined_1M.json"

# ── Category mapping: prefix → (category, purpose_template) ────────────────
PREFIX_MAP = [
    # Crypto / TLS
    (r'^_SSL_',          'crypto',      'OpenSSL SSL/TLS'),
    (r'^_TLS_',          'crypto',      'TLS protocol'),
    (r'^_EVP_',          'crypto',      'OpenSSL high-level crypto'),
    (r'^_RSA_',          'crypto',      'RSA encryption'),
    (r'^_EC_',           'crypto',      'Elliptic curve crypto'),
    (r'^_DSA_',          'crypto',      'DSA signing'),
    (r'^_DH_',           'crypto',      'Diffie-Hellman key exchange'),
    (r'^_AES_',          'crypto',      'AES encryption'),
    (r'^_SHA\d*_',       'crypto',      'SHA hash'),
    (r'^_MD5_',          'crypto',      'MD5 hash'),
    (r'^_HMAC',          'crypto',      'HMAC authentication'),
    (r'^_BIO_',          'crypto',      'OpenSSL BIO I/O abstraction'),
    (r'^_X509',          'crypto',      'X.509 certificate'),
    (r'^_PEM_',          'crypto',      'PEM encoding'),
    (r'^_ASN1_',         'crypto',      'ASN.1 encoding'),
    (r'^_PKCS',          'crypto',      'PKCS standard'),
    (r'^_OSSL_',         'crypto',      'OpenSSL internal'),
    (r'^_CRYPTO_',       'crypto',      'OpenSSL crypto primitive'),
    (r'^_ERR_',          'crypto',      'OpenSSL error handling'),
    (r'^_BN_',           'crypto',      'OpenSSL bignum arithmetic'),
    (r'^_OPENSSL_',      'crypto',      'OpenSSL utility'),
    (r'^_ENGINE_',       'crypto',      'OpenSSL engine'),
    (r'^_OCSP_',         'crypto',      'OCSP certificate validation'),
    (r'^_CMS_',          'crypto',      'Cryptographic Message Syntax'),
    (r'^_CTLOG',         'crypto',      'Certificate Transparency'),
    (r'^_CT_',           'crypto',      'Certificate Transparency'),

    # Networking
    (r'^_curl_',         'network',     'libcurl HTTP/transfer'),
    (r'^_nghttp',        'network',     'HTTP/2 protocol'),
    (r'^_ngtcp2_',       'network',     'QUIC/TLS transport'),
    (r'^_llhttp_',       'network',     'HTTP parsing'),
    (r'^_event_',        'network',     'libevent async I/O'),
    (r'^_evhttp',        'network',     'libevent HTTP server'),
    (r'^_evdns',         'network',     'libevent DNS'),
    (r'^_bufferevent',   'network',     'libevent buffered I/O'),
    (r'^_evbuffer',      'network',     'libevent buffer'),
    (r'^_evutil',        'network',     'libevent utility'),
    (r'^_ub_',           'network',     'Unbound DNS resolver'),

    # Compression
    (r'^_compress',      'compression', 'zlib compression'),
    (r'^_uncompress',    'compression', 'zlib decompression'),
    (r'^_deflate',       'compression', 'zlib deflate'),
    (r'^_inflate',       'compression', 'zlib inflate'),
    (r'^_gz',            'compression', 'gzip I/O'),
    (r'^_ZSTD_',         'compression', 'Zstandard compression'),
    (r'^_LZ4',           'compression', 'LZ4 compression'),
    (r'^_lzo',           'compression', 'LZO compression'),
    (r'^_BZ2_',          'compression', 'bzip2 compression'),
    (r'^_lzma_',         'compression', 'LZMA compression'),
    (r'^_XZ',            'compression', 'XZ compression'),
    (r'^_brotli_',       'compression', 'Brotli compression'),
    (r'^_BrotliEncoder', 'compression', 'Brotli encoder'),
    (r'^_BrotliDecoder', 'compression', 'Brotli decoder'),

    # Database
    (r'^_sqlite3_',      'database',    'SQLite database'),
    (r'^_PQ',            'database',    'PostgreSQL client'),
    (r'^_pg_',           'database',    'PostgreSQL utility'),
    (r'^_lo_',           'database',    'PostgreSQL large object'),
    (r'^_redis',         'database',    'Redis client'),

    # Image / Graphics
    (r'^_png_',          'graphics',    'PNG image I/O'),
    (r'^_jpeg_',         'graphics',    'JPEG image I/O'),
    (r'^_Magick',        'graphics',    'ImageMagick processing'),
    (r'^_cairo_',        'graphics',    'Cairo 2D graphics'),
    (r'^_pixman_',       'graphics',    'Pixman pixel manipulation'),
    (r'^_Tiff',          'graphics',    'TIFF image I/O'),
    (r'^_TIFFGet',       'graphics',    'TIFF metadata read'),
    (r'^_TIFFSet',       'graphics',    'TIFF metadata write'),
    (r'^_TIFF',          'graphics',    'TIFF image'),
    (r'^_WebP',          'graphics',    'WebP image codec'),
    (r'^_Imf',           'graphics',    'OpenEXR image'),
    (r'^_heif_',         'graphics',    'HEIF image codec'),
    (r'^_opj_',          'graphics',    'OpenJPEG codec'),
    (r'^_avif',          'graphics',    'AVIF image codec'),
    (r'^_SDL_',          'graphics',    'SDL multimedia'),
    (r'^_cms',           'graphics',    'Little CMS color management'),

    # Video / Audio / Media
    (r'^_av_',           'media',       'FFmpeg/libav utility'),
    (r'^_avcodec_',      'media',       'FFmpeg codec'),
    (r'^_avformat_',     'media',       'FFmpeg format'),
    (r'^_avutil_',       'media',       'FFmpeg utility'),
    (r'^_avfilter_',     'media',       'FFmpeg filter'),
    (r'^_sws_',          'media',       'FFmpeg scaling'),
    (r'^_swr_',          'media',       'FFmpeg resampling'),
    (r'^_swresample_',   'media',       'FFmpeg audio resample'),
    (r'^_opus_',         'media',       'Opus audio codec'),
    (r'^_lame_',         'media',       'LAME MP3 encoder'),
    (r'^_x264_',         'media',       'x264 H.264 encoder'),
    (r'^_x265_',         'media',       'x265 H.265 encoder'),
    (r'^_vpx_',          'media',       'VP8/VP9 codec'),
    (r'^_dav1d_',        'media',       'AV1 decoder'),
    (r'^_aom_',          'media',       'AV1 codec'),
    (r'^_svt_',          'media',       'SVT-AV1 encoder'),
    (r'^_vmaf_',         'media',       'VMAF quality metric'),
    (r'^_de265_',        'media',       'H.265 decoder'),

    # Math / Scientific
    (r'^_cblas_',        'math',        'BLAS linear algebra'),
    (r'^_LAPACK',        'math',        'LAPACK linear algebra'),
    (r'^_clapack_',      'math',        'CLAPACK linear algebra'),
    (r'^_openblas_',     'math',        'OpenBLAS linear algebra'),
    (r'^_[sdcz]gemm_',  'math',        'BLAS matrix multiply'),
    (r'^_[sdcz]gemv_',  'math',        'BLAS matrix-vector'),
    (r'^_[sdcz]axpy_',  'math',        'BLAS vector operation'),
    (r'^_[sdcz]scal_',  'math',        'BLAS vector scale'),
    (r'^_[sdcz]dot_',   'math',        'BLAS dot product'),
    (r'^_[sdcz]nrm2_',  'math',        'BLAS vector norm'),
    (r'^_[sdcz]copy_',  'math',        'BLAS vector copy'),
    (r'^_[sdcz]swap_',  'math',        'BLAS vector swap'),
    (r'^_[sdcz]asum_',  'math',        'BLAS absolute sum'),
    (r'^_[sdcz]getrf_', 'math',        'LAPACK LU factorization'),
    (r'^_[sdcz]getrs_', 'math',        'LAPACK LU solve'),
    (r'^_[sdcz]gesv_',  'math',        'LAPACK general solve'),
    (r'^_[sdcz]geev_',  'math',        'LAPACK eigenvalue'),
    (r'^_[sdcz]syev_',  'math',        'LAPACK symmetric eigenvalue'),
    (r'^_[sdcz]potrf_', 'math',        'LAPACK Cholesky'),
    (r'^_[sdcz]geqrf_', 'math',        'LAPACK QR'),
    (r'^_[sdcz]gesvd_', 'math',        'LAPACK SVD'),
    (r'^_[sdcz]trsv_',  'math',        'BLAS triangular solve'),
    (r'^_[sdcz]trsm_',  'math',        'BLAS triangular matrix solve'),
    (r'^_[sdcz]ger_',   'math',        'BLAS outer product'),
    (r'^_faiss_',        'math',        'FAISS similarity search'),
    (r'^_mpfr_',         'math',        'MPFR multi-precision float'),
    (r'^___gmpz_',       'math',        'GMP integer arithmetic'),
    (r'^___gmpq_',       'math',        'GMP rational arithmetic'),
    (r'^___gmpf_',       'math',        'GMP float arithmetic'),
    (r'^___gmp_',        'math',        'GMP arithmetic'),
    (r'^_mpc_',          'math',        'MPC complex arithmetic'),
    (r'^_QuantLib',      'math',        'QuantLib financial math'),
    (r'^_ql_',           'math',        'QuantLib finance'),

    # Text / Regex
    (r'^_pcre2_',        'text',        'PCRE2 regex'),
    (r'^_rl_',           'text',         'readline input'),
    (r'^_readline',      'text',         'readline input'),
    (r'^_history_',      'text',         'readline history'),
    (r'^_add_history',   'text',         'readline history'),
    (r'^_ncurses',       'text',         'ncurses terminal'),
    (r'^_utf8proc_',     'text',         'UTF-8 processing'),
    (r'^_u_',            'text',         'ICU unicode'),
    (r'^_ucal_',         'text',         'ICU calendar'),
    (r'^_udat_',         'text',         'ICU date format'),
    (r'^_ucol_',         'text',         'ICU collation'),
    (r'^_ubrk_',         'text',         'ICU break iterator'),
    (r'^_uconv_',        'text',         'ICU conversion'),
    (r'^_ures_',         'text',         'ICU resource'),
    (r'^_unum_',         'text',         'ICU number format'),

    # GLib / system utilities
    (r'^_g_',            'glib',        'GLib utility'),
    (r'^_g_hash_table',  'glib',        'GLib hash table'),
    (r'^_g_list_',       'glib',        'GLib linked list'),
    (r'^_g_slist_',      'glib',        'GLib singly-linked list'),
    (r'^_g_string_',     'glib',        'GLib string'),
    (r'^_g_array_',      'glib',        'GLib array'),
    (r'^_g_ptr_array',   'glib',        'GLib pointer array'),
    (r'^_g_byte_array',  'glib',        'GLib byte array'),
    (r'^_g_tree_',       'glib',        'GLib tree'),
    (r'^_g_malloc',      'glib',        'GLib memory allocation'),
    (r'^_g_free',        'glib',        'GLib memory free'),
    (r'^_g_io_',         'glib',        'GLib I/O channel'),
    (r'^_g_file_',       'glib',        'GLib file utility'),
    (r'^_g_main_',       'glib',        'GLib main loop'),
    (r'^_g_thread_',     'glib',        'GLib threading'),
    (r'^_g_mutex_',      'glib',        'GLib mutex'),
    (r'^_g_cond_',       'glib',        'GLib condition var'),
    (r'^_g_object_',     'glib',        'GObject system'),
    (r'^_g_signal_',     'glib',        'GObject signal'),
    (r'^_g_type_',       'glib',        'GObject type system'),
    (r'^_g_value_',      'glib',        'GObject value'),

    # Boost C++
    (r'^__ZN5boost',     'cpp',         'Boost C++ library'),

    # Protobuf / serialization
    (r'^_protobuf',      'serialization','Protocol Buffers'),
    (r'^__ZN6google8protobuf', 'serialization', 'Protocol Buffers'),

    # MPI / parallel
    (r'^_MPI_',          'parallel',    'MPI parallel computing'),
    (r'^_PMPI_',         'parallel',    'MPI profiling'),
    (r'^_ompi_',         'parallel',    'Open MPI internal'),
    (r'^_omp_',          'parallel',    'OpenMP parallel'),

    # HW / system
    (r'^_hwloc_',        'system',      'hwloc hardware topology'),
    (r'^_uv_',           'system',      'libuv async I/O'),
    (r'^_usb_',          'system',      'libusb USB access'),
    (r'^_libusb_',       'system',      'libusb USB access'),

    # Node.js
    (r'^_napi_',         'runtime',     'Node.js N-API'),
    (r'^_node_',         'runtime',     'Node.js internal'),

    # Font / text rendering
    (r'^_FT_',           'font',        'FreeType font rendering'),
    (r'^_hb_',           'font',        'HarfBuzz text shaping'),
    (r'^_FcPattern',     'font',        'Fontconfig pattern'),
    (r'^_FcFont',        'font',        'Fontconfig font'),
    (r'^_Fc',            'font',        'Fontconfig'),

    # GPG
    (r'^_gpgme_',        'crypto',      'GPGME crypto'),
    (r'^_gpg_',          'crypto',      'GnuPG crypto'),
    (r'^_gcry_',         'crypto',      'Libgcrypt crypto'),
    (r'^_assuan_',       'crypto',      'Assuan IPC protocol'),
    (r'^_gpgrt_',        'crypto',      'GPG runtime'),
    (r'^_ksba_',         'crypto',      'KSBA X.509/CMS'),
    (r'^_npth_',         'crypto',      'nPth threading'),

    # Java
    (r'^_JNI_',          'runtime',     'JNI interface'),

    # Poppler / PDF
    (r'^_poppler_',      'document',    'Poppler PDF'),

    # Radare2
    (r'^_r_',            'reversing',   'Radare2 RE framework'),

    # GCC runtime
    (r'^___gcc_',        'runtime',     'GCC runtime'),
    (r'^___gfortran_',   'runtime',     'GFortran runtime'),

    # TA-Lib (technical analysis)
    (r'^_TA_',           'math',        'TA-Lib technical analysis'),

    # Nettle
    (r'^_nettle_',       'crypto',      'Nettle crypto'),
    (r'^_gnutls_',       'crypto',      'GnuTLS crypto'),

    # simdjson
    (r'^_simdjson',      'text',        'simdjson JSON parsing'),

    # Misc fallbacks
    (r'^_lib',           'misc',        'library function'),
]

# Compile regexes once
COMPILED_PREFIX_MAP = [(re.compile(pat), cat, purp) for pat, cat, purp in PREFIX_MAP]


def categorize_symbol(name: str) -> tuple:
    """Return (category, purpose) for a symbol name."""
    for regex, cat, purp in COMPILED_PREFIX_MAP:
        if regex.search(name):
            return cat, purp
    return 'misc', 'library function'


def get_pkg_libraries(pkg: str) -> list:
    """Find all .dylib and .a files for a Homebrew package."""
    cellar_path = os.path.join(CELLAR, pkg)
    if not os.path.isdir(cellar_path):
        return []

    libs = []
    for ver in os.listdir(cellar_path):
        lib_dir = os.path.join(cellar_path, ver, 'lib')
        if not os.path.isdir(lib_dir):
            continue
        # .dylib files (prefer these - they're the actual exports)
        libs.extend(glob.glob(os.path.join(lib_dir, '*.dylib')))
        # .a files (static libraries, may have symbols not in dylibs)
        libs.extend(glob.glob(os.path.join(lib_dir, '*.a')))
        # Also check subdirectories (some packages nest libs)
        for subdir in os.listdir(lib_dir):
            sub_path = os.path.join(lib_dir, subdir)
            if os.path.isdir(sub_path) and subdir not in ('pkgconfig', 'cmake', 'engines', 'engines-3', 'ossl-modules'):
                libs.extend(glob.glob(os.path.join(sub_path, '*.dylib')))
                libs.extend(glob.glob(os.path.join(sub_path, '*.a')))
    return libs


def extract_symbols(lib_path: str) -> list:
    """Extract exported text symbols from a library using nm."""
    try:
        result = subprocess.run(
            ['nm', '-gU', lib_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return []

        symbols = []
        for line in result.stdout.splitlines():
            # Format: "0000000000001234 T _symbol_name"
            parts = line.strip().split()
            if len(parts) >= 3:
                sym_type = parts[1]
                sym_name = parts[2]
                # Only text (T), data (D/S), and constant (C) symbols
                if sym_type in ('T', 't', 'D', 'd', 'S', 's', 'C'):
                    symbols.append(sym_name)
            elif len(parts) == 2:
                # Some nm output: "T _symbol_name" (no address for .a)
                sym_type = parts[0]
                sym_name = parts[1]
                if sym_type in ('T', 't', 'D', 'd', 'S', 's', 'C'):
                    symbols.append(sym_name)
        return symbols
    except (subprocess.TimeoutExpired, Exception) as e:
        print(f"  [WARN] Failed to process {lib_path}: {e}", file=sys.stderr)
        return []


def lib_name_from_path(lib_path: str) -> str:
    """Extract clean library name from path."""
    basename = os.path.basename(lib_path)
    # Remove version suffixes: libfoo.3.dylib → libfoo
    name = re.sub(r'\.\d+\.dylib$', '', basename)
    name = re.sub(r'\.dylib$', '', name)
    name = re.sub(r'\.a$', '', name)
    # Remove lib prefix for display
    if name.startswith('lib'):
        name = name[3:]
    return name


def main():
    print("=" * 60)
    print("Homebrew Symbol Extractor for black-widow")
    print("=" * 60)

    # ── Step 1: Load existing symbols for deduplication ─────────────────
    existing_names = set()
    if os.path.exists(COMBINED):
        print(f"\nLoading existing symbols from {os.path.basename(COMBINED)}...")
        with open(COMBINED) as f:
            combined = json.load(f)
        for sig in combined['signatures']:
            existing_names.add(sig['name'])
        print(f"  Loaded {len(existing_names):,} existing symbol names")
        del combined  # Free memory

    # Also load other sig files for dedup
    other_files = [
        '/Users/apple/Desktop/black-widow/sigs/generated_signatures.json',
        '/Users/apple/Desktop/black-widow/sigs/macos_frameworks.json',
        '/Users/apple/Desktop/black-widow/sigs/macos_frameworks_full.json',
    ]
    for fpath in other_files:
        if os.path.exists(fpath):
            try:
                with open(fpath) as f:
                    data = json.load(f)
                sigs = data.get('signatures', [])
                for sig in sigs:
                    existing_names.add(sig['name'])
                print(f"  + {os.path.basename(fpath)}: {len(sigs):,} symbols")
            except Exception as e:
                print(f"  [WARN] Could not load {fpath}: {e}")

    print(f"  Total existing: {len(existing_names):,}")

    # ── Step 2: Get all Homebrew packages ───────────────────────────────
    packages = subprocess.check_output(
        ['brew', 'list', '--formula'], text=True
    ).strip().split('\n')
    print(f"\nFound {len(packages)} Homebrew packages")

    # ── Step 3: Extract symbols ─────────────────────────────────────────
    all_sigs = []
    seen_names = set()  # Track within this extraction
    pkg_stats = {}
    skipped_existing = 0
    total_raw = 0

    for i, pkg in enumerate(packages):
        libs = get_pkg_libraries(pkg)
        if not libs:
            continue

        pkg_count = 0
        for lib_path in libs:
            symbols = extract_symbols(lib_path)
            total_raw += len(symbols)
            lib_display = lib_name_from_path(lib_path)

            for sym in symbols:
                if sym in existing_names:
                    skipped_existing += 1
                    continue
                if sym in seen_names:
                    continue
                seen_names.add(sym)

                cat, purpose = categorize_symbol(sym)
                all_sigs.append({
                    "name": sym,
                    "library": lib_display,
                    "package": pkg,
                    "category": cat,
                    "purpose": purpose,
                    "confidence": 0.90
                })
                pkg_count += 1

        if pkg_count > 0:
            pkg_stats[pkg] = pkg_count
            print(f"  [{i+1:3d}/{len(packages)}] {pkg}: {pkg_count:,} new symbols from {len(libs)} libs")

    # ── Step 4: Summary ─────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"RESULTS:")
    print(f"  Total raw symbols scanned: {total_raw:,}")
    print(f"  Skipped (already in existing): {skipped_existing:,}")
    print(f"  Skipped (duplicates within): {total_raw - skipped_existing - len(all_sigs):,}")
    print(f"  NEW unique signatures: {len(all_sigs):,}")
    print(f"  Packages with symbols: {len(pkg_stats)}")

    # Category breakdown
    cat_counts = defaultdict(int)
    for sig in all_sigs:
        cat_counts[sig['category']] += 1
    print(f"\nCategory breakdown:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:20s}: {count:>8,}")

    # Top packages
    print(f"\nTop 20 packages by symbol count:")
    for pkg, count in sorted(pkg_stats.items(), key=lambda x: -x[1])[:20]:
        print(f"  {pkg:30s}: {count:>8,}")

    # ── Step 5: Write output ────────────────────────────────────────────
    output = {
        "meta": {
            "generator": "tools/extract_homebrew_sigs.py",
            "version": "1.0",
            "timestamp": datetime.now().isoformat(timespec='seconds'),
            "description": "Function signatures from Homebrew-installed libraries",
            "packages_scanned": len(packages),
            "packages_with_symbols": len(pkg_stats),
            "total_raw_symbols": total_raw,
            "skipped_existing": skipped_existing,
            "category_stats": dict(cat_counts),
        },
        "signatures": all_sigs,
        "total": len(all_sigs),
    }

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=None, separators=(',', ':'))

    file_size = os.path.getsize(OUTPUT)
    print(f"\nOutput written to: {OUTPUT}")
    print(f"File size: {file_size / 1024 / 1024:.1f} MB")
    print(f"Total signatures: {len(all_sigs):,}")


if __name__ == '__main__':
    main()
