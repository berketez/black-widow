"""AlgorithmIdStep — crypto algorithm identification (tek basina).

stages.py L1568-1601 arasindaki `_run_algorithm_id` fonksiyonundan step'e
tasindi. Orijinal pipeline bu isi binary_name + engineering ile paralel
calistiriyordu; v1.10.0 M1'de:
- algorithm_id = yalniz crypto identification (bu step)
- parallel_algo_eng = binary_name_extraction + engineering_analysis (ikisi
  paralel, 2 future)

Sebep: crypto algo hizli (~saniye mertebesi), 3 paralel future yerine
ThreadPoolExecutor'i 2 uzun isin icin kullanmak daha temiz ve testlemesi
basit.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="algorithm_id",
    requires=[
        "decompiled_dir",
        "functions_json_path",
        "strings_json_path",
    ],
    produces=["algo_result"],
    parallelizable_with=["parallel_algo_eng"],
)
class AlgorithmIdStep(Step):
    """Crypto Algorithm Identification — CAlgorithmIdentifier."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir = ctx.artifacts["decompiled_dir"]
        functions_json = ctx.artifacts["functions_json_path"]
        strings_json = ctx.artifacts["strings_json_path"]

        step_start = time.monotonic()
        pc.report_progress("Algorithm ID...", 0.22)

        algo_result: Any = None

        if not pc.config.binary_reconstruction.enable_algorithm_id:
            ctx.stats["timing_algorithm_id"] = round(
                time.monotonic() - step_start, 1,
            )
            return {"algo_result": algo_result}

        try:
            from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier

            algo_id = CAlgorithmIdentifier(pc.config)
            algo_result = algo_id.identify(
                decompiled_dir, functions_json, strings_json,
            )
            if algo_result.success:
                algo_path = pc.workspace.save_json(
                    "reconstructed", "algorithms",
                    {
                        "total": algo_result.total_detected,
                        "algorithms": [
                            {
                                "name": a.name,
                                "category": a.category,
                                "confidence": a.confidence,
                                "function": a.function_name,
                                "evidence": a.evidence,
                            }
                            for a in algo_result.algorithms
                        ],
                    },
                )
                ctx.produce_artifact("algorithms", algo_path)
                ctx.stats["algorithms_detected"] = algo_result.total_detected
                ctx.stats["algorithms_by_category"] = algo_result.by_category
                logger.info(
                    "Algorithm ID: %d tespit edildi",
                    algo_result.total_detected,
                )
        except Exception as exc:
            logger.warning("Algorithm identification hatasi: %s", exc)
            ctx.errors.append(f"Algorithm ID hatasi: {exc}")

        ctx.stats["timing_algorithm_id"] = round(
            time.monotonic() - step_start, 1,
        )
        return {"algo_result": algo_result}
