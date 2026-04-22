"""FinalizeStep — StageResult toplama ve dondurme.

stages.py L3935-3955 'ten tasindi. Tum onceki step'lerin stats/errors'ini
topladiktan sonra StageResult'i olusturur ve artifact olarak yayinlar.
Cagiran shim bu sonucu alip binary_reconstruction stage'inin return degeri
yapar.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.core.pipeline import StageResult
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="finalize",
    requires=[
        # Post-feedback pipeline'inin "son" step'i olmasi icin bircok step'in
        # ciktisini kuyrukluyoruz — topological sort bunu en sona koyar.
        "deep_tracing_result",
        "engineering_analysis_result",
        "project_dir",
    ],
    produces=[
        "stage_result",
    ],
    parallelizable_with=[],
)
class FinalizeStep(Step):
    """Pipeline sonu: stats ozetle, StageResult olustur."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        stage_name = ctx.artifacts.get(
            "__stage_name", "binary_reconstruction",
        )
        pipeline_start = ctx.artifacts.get("__pipeline_start")

        duration = (
            time.monotonic() - pipeline_start
            if pipeline_start is not None else 0.0
        )

        # shim tarafindan yazilan artifacts_pending + caller-provided artifacts
        # (assembly_analysis, engineering_analysis_md, project_dir, ...) hepsi
        # pc.metadata["artifacts_pending"]'de toplandi.
        pending = (pc.metadata or {}).get("artifacts_pending", {})
        artifacts: dict = dict(pending)

        errors = list(ctx.errors)
        stats = dict(ctx.stats)

        # v1.10.0: feedback_loop'un convergence_reason ciktisi stats'e tasindi.
        # Boylece observability layer (CLI/run reports) hangi sebepten loop'un
        # durdugunu okuyabilir (max_iter / no_new_names / iteration_timeout /
        # convergence_ratio_X.XXX vb.).
        convergence_reason = ctx.artifacts.get("convergence_reason", "unknown")
        stats["convergence_reason"] = convergence_reason

        success = len(artifacts) > 0

        # v1.2.2: Toplam timing ozeti
        timing_keys = [k for k in stats if k.startswith("timing_")]
        timing_total = sum(stats[k] for k in timing_keys)
        logger.info(
            "Binary reconstruction: %d artifact, %.1fs (step toplami %.1fs), %d hata",
            len(artifacts), duration, timing_total, len(errors),
        )
        for tk in sorted(timing_keys):
            logger.debug("  %s: %.1fs", tk, stats[tk])

        stage_result = StageResult(
            stage_name=stage_name,
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

        return {"stage_result": stage_result}
