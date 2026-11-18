"""CapaAnnotationStep — CAPA capability yorum enjeksiyonu.

stages.py L3551-3566 'dan tasindi. Davranis birebir korundu.
confidence_filter step'inin ciktisi olan `capa_capabilities` dict'i varsa
her fonksiyon basina @capability yorumu ekler.

K-1 (P-S1): capa'nin koda girisi bayrak arkasinda, ONTANIMLI KAPALI.
P03'ten sonra capa ilk kez gercekten calisiyor; masum PE'lerde 299 iddianin
12'si capa kurallarinin kendi duzenli ifade kusurundan kesin yanlis ("Friday"
-> /frida/i), FLIRT kitaplik suzgeci olmadigi icin statik bagli MSVC CRT
fonksiyonlari kullanici kodu gibi adlandiriliyor (w32.exe: ad haritasinin 15
girisinin 14'u capa'dan; ``parse_pe_header`` = CRT'nin
``_IsNonwritableInCurrentImage``'i). Olculene kadar capa yetenekleri rapora
durumuyla yazilir (``static/capa_scan.json``) ama ad ya da yorum olarak koda
girmez:

- Statik asama ``static/capa_capabilities.json``'u (ad birlestiricinin ve bu
  adimin tek girdisi) yalniz bayrak acikken yazar.
- Bu adim bayrak kapaliyken ``capa_capabilities`` dolu gelse bile yorum yazmaz.

Bayrak: ``binary_reconstruction.enable_capa_code_feed`` (config.py'de alan yok;
eklenene kadar ``CAPA_CODE_FEED_DEFAULT`` gecerli). Acilis kosulu:
``docs/arge/2026-11-18_onarim/P-S1.md`` kalem 4.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# K-1: capa -> kod (ad + @capability yorumu) kanali. Olculmeden acilmaz.
CAPA_CODE_FEED_FLAG = "enable_capa_code_feed"
CAPA_CODE_FEED_DEFAULT = False


def capa_code_feed_enabled(config: Any) -> bool:
    """capa sonuclari koda (ad / yorum) girebilir mi?

    ``binary_reconstruction.enable_capa_code_feed`` yalniz gercek ``True`` ise
    acik sayilir (YAML'dan gelen "false" dizgisi ya da taklit nesne acmaz).
    Alan tanimli degilse ``CAPA_CODE_FEED_DEFAULT`` (kapali).
    """
    recon = getattr(config, "binary_reconstruction", None)
    return getattr(recon, CAPA_CODE_FEED_FLAG, CAPA_CODE_FEED_DEFAULT) is True


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

        feed = capa_code_feed_enabled(pc.config)
        if capa_capabilities and not feed:
            # K-1: veri var ama kanal kapali -> koda hicbir sey yazilmaz.
            ctx.stats["capa_comments_skipped"] = (
                f"{CAPA_CODE_FEED_FLAG}=False (K-1: olculene kadar kapali)"
            )
        if capa_capabilities and feed and pc.config.binary_reconstruction.enable_capa:
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
