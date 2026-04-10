#!/usr/bin/env python3
"""Black Widow v1.0 -- Naming Pipeline runner.

1962 deobfuscated webpack modulunu 4 katmanli pipeline ile isimlendirir.
"""

import json
import logging
import sys
import time
from pathlib import Path

# Proje root'u PYTHONPATH'e ekle
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from karadul.reconstruction.naming import NamingPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("naming_runner")

MODULES_DIR = project_root / "workspaces/cli/20260321_161226/deobfuscated/webpack_modules/modules"
OUTPUT_DIR = project_root / "workspaces/cli/20260321_161226/reconstructed/named_project"


def main():
    logger.info("=" * 70)
    logger.info("Black Widow v1.0 -- 4 Layer Naming Pipeline")
    logger.info("Modules: %s", MODULES_DIR)
    logger.info("Output:  %s", OUTPUT_DIR)
    logger.info("=" * 70)

    if not MODULES_DIR.exists():
        logger.error("Modul dizini bulunamadi: %s", MODULES_DIR)
        return 1

    module_count = len(list(MODULES_DIR.glob("*.js")))
    logger.info("Toplam modul sayisi: %d", module_count)

    # Pipeline olustur -- LLM olmadan calistir (heuristic fallback)
    # Codex yoksa veya cok yavas olursa heuristic kullanilir
    pipeline = NamingPipeline(use_codex=False, skip_llm=False)

    t0 = time.monotonic()
    manifest = pipeline.run(MODULES_DIR)
    elapsed = time.monotonic() - t0

    # Ozet rapor
    summary = manifest.summary()
    logger.info("")
    logger.info("=" * 70)
    logger.info("SONUCLAR")
    logger.info("=" * 70)
    logger.info("Toplam isimlendirildi: %d / %d", summary["total_named"], module_count)
    logger.info("Ortalama confidence: %.3f", summary["avg_confidence"])
    logger.info("")

    logger.info("Kaynak bazli dagılım:")
    for source, count in sorted(summary["by_source"].items(), key=lambda x: -x[1]):
        logger.info("  %-20s: %d modul", source, count)

    logger.info("")
    logger.info("Kategori bazli dagılım (top 20):")
    for idx, (cat, count) in enumerate(summary["by_category"].items()):
        if idx >= 20:
            break
        logger.info("  %-30s: %d modul", cat, count)

    logger.info("")
    logger.info("Istatistikler:")
    for source, stats in summary.get("statistics", {}).items():
        logger.info("  %s: %s", source, stats)

    logger.info("")
    logger.info("Sure: %.1f saniye", elapsed)

    # Dosyalari uygula
    logger.info("")
    logger.info("Dosyalar uygulanıyor: %s", OUTPUT_DIR)
    pipeline.apply(MODULES_DIR, OUTPUT_DIR, manifest)

    # Cikti dizin yapisini goster
    logger.info("")
    logger.info("Cikti dizin yapisi:")
    for category_dir in sorted(OUTPUT_DIR.iterdir()):
        if category_dir.is_dir():
            file_count = len(list(category_dir.glob("*.js")))
            logger.info("  %s/ (%d dosya)", category_dir.name, file_count)

    # Bazi ornek modulleri goster
    logger.info("")
    logger.info("Ornek isimlendirmeler (yuksek confidence):")
    high_conf = sorted(
        manifest.results.values(),
        key=lambda r: r.confidence,
        reverse=True,
    )[:20]
    for r in high_conf:
        logger.info(
            "  %s -> %s/%s (conf=%.2f, src=%s%s)",
            r.original_file,
            r.category,
            r.new_filename,
            r.confidence,
            r.source,
            f", pkg={r.npm_package}" if r.npm_package else "",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
