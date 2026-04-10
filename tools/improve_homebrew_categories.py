#!/usr/bin/env python3
"""
Post-process homebrew_symbols.json:
1. Demangle C++ symbols using c++filt
2. Assign better categories based on demangled names and package context
3. Generate richer purpose strings
"""

import json
import subprocess
import sys
import re
from collections import defaultdict

INPUT = "/Users/apple/Desktop/black-widow/sigs/homebrew_symbols.json"
OUTPUT = INPUT  # Overwrite in place

# ── Package → category/purpose mapping ──────────────────────────────────────
PACKAGE_CATEGORIES = {
    'quantlib':     ('math',        'QuantLib financial computation'),
    'boost':        ('cpp',         'Boost C++ library'),
    'libheif':      ('graphics',    'HEIF/HEIC image codec'),
    'poppler':      ('document',    'Poppler PDF rendering'),
    'icu4c@78':     ('text',        'ICU Unicode/i18n'),
    'pmix':         ('parallel',    'PMIx process management'),
    'open-mpi':     ('parallel',    'Open MPI parallel computing'),
    'openexr':      ('graphics',    'OpenEXR HDR image'),
    'imagemagick':  ('graphics',    'ImageMagick image processing'),
    'x265':         ('media',       'x265 H.265/HEVC encoder'),
    'faiss':        ('math',        'FAISS similarity search'),
    'node':         ('runtime',     'Node.js runtime'),
    'arpack':       ('math',        'ARPACK eigenvalue solver'),
    'harfbuzz':     ('font',        'HarfBuzz text shaping'),
    'jpeg-xl':      ('graphics',    'JPEG XL image codec'),
    'libvpx':       ('media',       'VP8/VP9 video codec'),
    'webp':         ('graphics',    'WebP image codec'),
    'sdl2':         ('graphics',    'SDL2 multimedia'),
    'hwloc':        ('system',      'hwloc hardware topology'),
    'aom':          ('media',       'AV1 video codec'),
    'openblas':     ('math',        'OpenBLAS linear algebra'),
    'gmp':          ('math',        'GMP arbitrary precision'),
    'gnutls':       ('crypto',      'GnuTLS crypto'),
    'gperftools':   ('system',      'Google perftools profiling'),
    'gpgmepp':      ('crypto',      'GPGME C++ binding'),
    'mpdecimal':    ('math',        'mpdecimal decimal arithmetic'),
    'ncurses':      ('text',        'ncurses terminal UI'),
    'nss':          ('crypto',      'NSS crypto'),
    'libde265':     ('media',       'H.265 decoder'),
    'libngtcp2':    ('network',     'QUIC transport'),
    'libnghttp2':   ('network',     'HTTP/2 protocol'),
    'libomp':       ('parallel',    'OpenMP runtime'),
    'libtasn1':     ('crypto',      'ASN.1 parsing'),
    'libusb':       ('system',      'USB device access'),
    'libvmaf':      ('media',       'VMAF quality metric'),
    'libx11':       ('graphics',    'X11 display'),
    'simdjson':     ('text',        'SIMD JSON parsing'),
    'x264':         ('media',       'x264 H.264 encoder'),
    'openjph':      ('graphics',    'JPEG 2000 HT codec'),
    'ada-url':      ('network',     'URL parsing'),
    'ffmpeg':       ('media',       'FFmpeg multimedia'),
    'fmt':          ('cpp',         'fmt string formatting'),
    'gettext':      ('text',        'gettext i18n'),
    'glib':         ('glib',        'GLib utility'),
}

# ── Demangled namespace → more specific purpose ─────────────────────────────
NAMESPACE_PURPOSE = {
    'QuantLib': 'QuantLib financial computation',
    'boost::json': 'Boost JSON parsing',
    'boost::filesystem': 'Boost filesystem',
    'boost::regex': 'Boost regex',
    'boost::asio': 'Boost async I/O',
    'boost::thread': 'Boost threading',
    'boost::system': 'Boost system',
    'boost::program_options': 'Boost CLI options',
    'boost::log': 'Boost logging',
    'boost::serialization': 'Boost serialization',
    'boost::locale': 'Boost locale',
    'boost::math': 'Boost math',
    'boost::container': 'Boost container',
    'boost::iostreams': 'Boost I/O streams',
    'boost::property_tree': 'Boost property tree',
    'boost::spirit': 'Boost parsing',
    'boost::numeric': 'Boost numeric',
    'boost::random': 'Boost random numbers',
    'boost::date_time': 'Boost date/time',
    'boost::chrono': 'Boost chrono',
    'boost::timer': 'Boost timer',
    'boost::wave': 'Boost C++ preprocessor',
    'boost::url': 'Boost URL parsing',
    'boost::nowide': 'Boost UTF-8 I/O',
    'boost': 'Boost C++ library',
    'Magick': 'ImageMagick processing',
    'Poppler': 'Poppler PDF rendering',
    'Imath': 'Imath math library',
    'Iex': 'OpenEXR exception',
    'Imf': 'OpenEXR image',
    'x265': 'x265 HEVC encoder',
    'faiss': 'FAISS similarity search',
}


def demangle_batch(symbols: list) -> dict:
    """Demangle a batch of C++ symbols using c++filt."""
    mangled = [s for s in symbols if s.startswith('__Z') or s.startswith('___Z')]
    if not mangled:
        return {}

    # c++filt can handle stdin batch
    print(f"  Demangling {len(mangled):,} C++ symbols...", file=sys.stderr)
    try:
        result = subprocess.run(
            ['c++filt'],
            input='\n'.join(mangled),
            capture_output=True, text=True, timeout=60
        )
        demangled_lines = result.stdout.strip().split('\n')
        mapping = {}
        for orig, dem in zip(mangled, demangled_lines):
            if dem != orig:  # Only store if actually demangled
                mapping[orig] = dem
        print(f"  Successfully demangled {len(mapping):,} symbols", file=sys.stderr)
        return mapping
    except Exception as e:
        print(f"  [WARN] Demangling failed: {e}", file=sys.stderr)
        return {}


def purpose_from_demangled(demangled: str, pkg: str) -> str:
    """Extract a meaningful purpose from a demangled C++ symbol name."""
    # Try namespace matching
    for ns, purpose in NAMESPACE_PURPOSE.items():
        if ns in demangled:
            return purpose

    # Fall back to package-based purpose
    if pkg in PACKAGE_CATEGORIES:
        return PACKAGE_CATEGORIES[pkg][1]

    return 'library function'


def main():
    print("Loading homebrew_symbols.json...", file=sys.stderr)
    with open(INPUT) as f:
        data = json.load(f)

    sigs = data['signatures']
    print(f"Total signatures: {len(sigs):,}", file=sys.stderr)

    # Collect all symbol names for batch demangling
    all_names = [sig['name'] for sig in sigs]
    demangle_map = demangle_batch(all_names)

    # Process each signature
    cat_changes = defaultdict(int)
    misc_before = sum(1 for s in sigs if s['category'] == 'misc')

    for sig in sigs:
        old_cat = sig['category']
        pkg = sig['package']
        name = sig['name']

        # If still misc, try to improve
        if old_cat == 'misc':
            # Strategy 1: Use package mapping
            if pkg in PACKAGE_CATEGORIES:
                new_cat, new_purpose = PACKAGE_CATEGORIES[pkg]
                sig['category'] = new_cat
                sig['purpose'] = new_purpose
                cat_changes[f'misc -> {new_cat}'] += 1

        # Strategy 2: For C++ symbols, use demangled name for purpose
        if name in demangle_map:
            demangled = demangle_map[name]
            # Extract cleaner purpose from demangled name
            better_purpose = purpose_from_demangled(demangled, pkg)
            if better_purpose != 'library function':
                sig['purpose'] = better_purpose

    misc_after = sum(1 for s in sigs if s['category'] == 'misc')

    # Update category stats in meta
    cat_counts = defaultdict(int)
    for sig in sigs:
        cat_counts[sig['category']] += 1
    data['meta']['category_stats'] = dict(cat_counts)
    data['meta']['demangled_count'] = len(demangle_map)

    # Print summary
    print(f"\n{'=' * 50}", file=sys.stderr)
    print(f"Category improvements:", file=sys.stderr)
    print(f"  misc before: {misc_before:,}", file=sys.stderr)
    print(f"  misc after:  {misc_after:,}", file=sys.stderr)
    for change, count in sorted(cat_changes.items(), key=lambda x: -x[1]):
        print(f"  {change}: {count:,}", file=sys.stderr)

    print(f"\nFinal category breakdown:", file=sys.stderr)
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:20s}: {count:>8,}", file=sys.stderr)

    # Write output
    with open(OUTPUT, 'w') as f:
        json.dump(data, f, indent=None, separators=(',', ':'))

    print(f"\nWritten to {OUTPUT}", file=sys.stderr)


if __name__ == '__main__':
    main()
