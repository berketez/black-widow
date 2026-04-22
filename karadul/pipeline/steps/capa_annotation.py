"""CapaAnnotationStep — CAPA capability yorum enjeksiyonu.

stages.py L3551-3566 'dan tasindi. Davranis birebir korundu.
confidence_filter step'inin ciktisi olan `capa_capabilities` dict'i varsa
her fonksiyon basina @capability yorumu ekler.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="capa_annotation",
    requires=[
        "comment_generation_decompiled_dir",
        "capa_capabilities",
        "functions_data",
    ],
    produces=[
        "capa_annotation_decompiled_dir",
        "timing_capa_comments",
    ],
    parallelizable_with=[],
)
class CapaAnnotationStep(Step):
    """CAPA capability yorum enjeksiyonu (fonksiyon basina @capability)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["comment_generation_decompiled_dir"]
        capa_capabilities = ctx.artifacts["capa_capabilities"]
        func_data = ctx.artifacts["functions_data"]

        step_start = time.monotonic()

        if capa_capabilities and pc.config.binary_reconstruction.enable_capa:
            try:
                # Geç-import: stages.py'deki helper'i kullan (duplikasyon yok).
                from karadul.stages import _inject_capa_comments
                capa_comments_added = _inject_capa_comments(
                    decompiled_dir, capa_capabilities, func_data,
                )
                if capa_comments_added > 0:
                    ctx.stats["capa_comments_added"] = capa_comments_added
                    logger.info(
                        "CAPA: %d fonksiyona capability yorumu eklendi",
                        capa_comments_added,
                    )
            except Exception as exc:
                logger.debug("CAPA comment injection hatasi: %s", exc)

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_capa_comments"] = timing

        # In-place modifikasyon; decompiled_dir degismez.
        return {
            "capa_annotation_decompiled_dir": decompiled_dir,
            "timing_capa_comments": timing,
        }
