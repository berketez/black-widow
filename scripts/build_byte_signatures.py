#!/usr/bin/env python3
"""Homebrew ve sistem kutuphanelerinden byte pattern'li signature DB olustur.

Mevcut signatures_homebrew.json'daki fonksiyon isimlerini kullanarak,
gercek binary'lerden byte pattern cikarir ve yeni bir JSON dosyasina kaydeder.

Kullanim:
    python3 scripts/build_byte_signatures.py

Cikti:
    signatures_homebrew_bytes.json  -- byte pattern'li signature DB

Bu dosya daha sonra BytePatternMatcher tarafindan FUN_xxx eslestirmesinde kullanilir.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

# Proje root'unu path'e ekle
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from karadul.analyzers.flirt_parser import FLIRTParser

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# Steam'in ve Rectangle'in muhtemelen kullandigi kutuphaneler
# (buyuk -> kucuk oncelik sirasinda)
PRIORITY_LIBRARIES = [
    # OpenSSL / BoringSSL
    ("/opt/homebrew/opt/openssl@3/lib/libssl.dylib", "openssl"),
    ("/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib", "openssl"),
    # Compression
    ("/opt/homebrew/lib/libzstd.dylib", "zstd"),
    ("/opt/homebrew/opt/brotli/lib/libbrotlienc.dylib", "brotli"),
    ("/opt/homebrew/opt/brotli/lib/libbrotlidec.dylib", "brotli"),
    ("/opt/homebrew/opt/brotli/lib/libbrotlicommon.dylib", "brotli"),
    # Networking
    ("/opt/homebrew/opt/c-ares/lib/libcares.dylib", "c-ares"),
    ("/opt/homebrew/opt/nghttp2/lib/libnghttp2.dylib", "nghttp2"),
    # SDL2 (Steam)
    ("/opt/homebrew/lib/libSDL2.dylib", "sdl2"),
    # Image
    ("/opt/homebrew/opt/libpng/lib/libpng.dylib", "libpng"),
    ("/opt/homebrew/opt/jpeg-turbo/lib/libjpeg.dylib", "jpeg"),
    ("/opt/homebrew/opt/webp/lib/libwebp.dylib", "webp"),
    # FFmpeg
    ("/opt/homebrew/opt/ffmpeg/lib/libavcodec.dylib", "ffmpeg"),
    ("/opt/homebrew/opt/ffmpeg/lib/libavformat.dylib", "ffmpeg"),
    ("/opt/homebrew/opt/ffmpeg/lib/libavutil.dylib", "ffmpeg"),
    # sqlite
    ("/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib", "sqlite"),
    # ICU
    ("/opt/homebrew/opt/icu4c/lib/libicuuc.dylib", "icu"),
    ("/opt/homebrew/opt/icu4c/lib/libicui18n.dylib", "icu"),
]

# macOS system libraries (Apple Silicon arm64)
SYSTEM_LIBRARIES = [
    # System zlib
    ("/usr/lib/libz.1.dylib", "zlib"),
    # libxml2
    ("/usr/lib/libxml2.2.dylib", "libxml2"),
    # SQLite
    ("/usr/lib/libsqlite3.dylib", "sqlite"),
    # libc++ (C++ standard library)
    ("/usr/lib/libc++.1.dylib", "libc++"),
    # libSystem (POSIX + more)
    ("/usr/lib/libSystem.B.dylib", "libSystem"),
]


def main():
    start = time.monotonic()
    fp = FLIRTParser()

    all_sigs = []
    stats = {}

    # Priority libraries
    for lib_path, lib_name in PRIORITY_LIBRARIES:
        if not Path(lib_path).exists():
            logger.info("  SKIP (bulunamadi): %s", lib_path)
            continue

        sigs = fp.extract_from_binary(lib_path, library_name=lib_name)
        byte_count = sum(1 for s in sigs if s.byte_pattern and len(s.byte_pattern) >= 16)
        logger.info(
            "  %s: %d symbols, %d byte patterns (>= 16)",
            lib_name, len(sigs), byte_count,
        )
        all_sigs.extend(sigs)
        stats[lib_name] = {"symbols": len(sigs), "byte_patterns": byte_count}

    # System libraries
    for lib_path, lib_name in SYSTEM_LIBRARIES:
        if not Path(lib_path).exists():
            logger.info("  SKIP (bulunamadi): %s", lib_path)
            continue

        sigs = fp.extract_from_binary(lib_path, library_name=lib_name)
        byte_count = sum(1 for s in sigs if s.byte_pattern and len(s.byte_pattern) >= 16)
        logger.info(
            "  %s: %d symbols, %d byte patterns (>= 16)",
            lib_name, len(sigs), byte_count,
        )
        all_sigs.extend(sigs)
        stats[lib_name] = {"symbols": len(sigs), "byte_patterns": byte_count}

    # Byte pattern'li olanlari filtrele
    byte_sigs = [s for s in all_sigs if s.byte_pattern and len(s.byte_pattern) >= 16]

    # Duplikasyon kaldir (ayni isim + ayni library)
    seen = set()
    unique_sigs = []
    for s in byte_sigs:
        key = (s.name, s.library)
        if key not in seen:
            seen.add(key)
            unique_sigs.append(s)

    # JSON'a kaydet
    output_path = project_root / "signatures_homebrew_bytes.json"
    data = {
        "meta": {
            "generator": "build_byte_signatures.py",
            "version": "1.0",
            "description": "Homebrew + system library byte pattern signatures for FUN_xxx matching",
            "total_libraries": len(stats),
            "stats": stats,
        },
        "signatures": [
            {
                "name": s.name,
                "library": s.library,
                "category": s.category or s.library,
                "purpose": s.purpose,
                "confidence": s.confidence,
                "size": s.size,
                "byte_pattern": s.byte_pattern.hex() if s.byte_pattern else "",
            }
            for s in unique_sigs
        ],
        "total": len(unique_sigs),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    elapsed = time.monotonic() - start
    logger.info("\n=== Sonuc ===")
    logger.info("Toplam: %d unique byte pattern signature", len(unique_sigs))
    logger.info("Kaydedildi: %s", output_path)
    logger.info("Sure: %.1fs", elapsed)


if __name__ == "__main__":
    main()
