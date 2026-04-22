"""InlineDetectionStep — compiler inline pattern tespiti.

stages.py L3391-3431 'den tasindi. Davranis birebir korundu.
InlineDetector ile her decompiled C dosyasinda compiler tarafindan inline
edilen abs/strlen/memcpy gibi fonksiyonlari regex ile bulur ve yorum olarak
ekler. ThreadPoolExecutor ile paralel isler.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="inline_detection",
    requires=[
        # v1.10.0 H5+H6: inline detection feedback_loop'un RENAME/TYPE sonrasi
        # ciktisi uzerinde calismali — eski "decompiled_dir" feedback oncesi
        # hale isaret ediyordu, bu yuzden yeniden adlandirilmis dosyalarda
        # pattern match yapamayabiliyor ve stale file_cache okuyabiliyordu.
        "final_decompiled_dir",
        "file_cache",
    ],
    produces=[
        "inline_patterns_detected",
        "timing_inline_detection",
    ],
    parallelizable_with=[],
)
class InlineDetectionStep(Step):
    """Compiler inline pattern'lerini tespit et (abs, strlen, memcpy, ...)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        decompiled_dir: Path = ctx.artifacts["final_decompiled_dir"]
        file_cache: dict[str, str] = ctx.artifacts["file_cache"]

        step_start = time.monotonic()
        total_inline_detected = 0

        try:
            from karadul.analyzers.inline_detector import InlineDetector

            # Feedback loop sonrası decompiled_dir degismis olabilir (struct,
            # semantic_named vb. yonlendirmeler). Guncel rglob.
            inline_c_files = (
                sorted(decompiled_dir.rglob("*.c"))
                if decompiled_dir.exists() else []
            )

            def _inline_detect_one(c_file: Path) -> int:
                """Tek dosyada inline pattern tespit et ve annotate et."""
                try:
                    # Thread-safe: her thread kendi InlineDetector instance'i.
                    det = InlineDetector()
                    # v1.9.2 QW5: file_cache'den oku (disk I/O tekrari yok)
                    content = (
                        file_cache.get(c_file.name)
                        or c_file.read_text(encoding="utf-8", errors="replace")
                    )
                    matches = det.detect_in_code(content)
                    if matches:
                        annotated = det.annotate_code(content)
                        c_file.write_text(annotated, encoding="utf-8")
                        return len(matches)
                except Exception:
                    logger.debug(
                        "Crypto/obfuscation annotation basarisiz, atlaniyor",
                        exc_info=True,
                    )
                return 0

            with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
                for count in pool.map(_inline_detect_one, inline_c_files):
                    total_inline_detected += count

            if total_inline_detected > 0:
                ctx.stats["inline_patterns_detected"] = total_inline_detected
                logger.info(
                    "Inline Detection: %d pattern tespit edildi (%d dosya, %d worker)",
                    total_inline_detected, len(inline_c_files), CPU_PERF_CORES,
                )
        except ImportError:
            logger.debug("InlineDetector bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("Inline detection hatasi (atlaniyor): %s", exc)

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_inline_detection"] = timing

        return {
            "inline_patterns_detected": total_inline_detected,
            "timing_inline_detection": timing,
        }
