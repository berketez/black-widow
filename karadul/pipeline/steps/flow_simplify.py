"""FlowSimplifyStep — control flow simplification (v1.5.5).

stages.py L3470-3494 'ten tasindi. Davranis birebir korundu.
CFlowSimplifier ile goto elimination, label renaming/inlining, early return,
break/continue detection, if-else restructuring vs. yapar.

Semantic naming decompiled_dir'i degistirmis olabilir; bu step onun ciktisina
calisir (semantic_naming_decompiled_dir). Kendi output directory'si yok —
tum operasyonlar yerinde (in-place) yapilir.
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
    name="flow_simplify",
    requires=[
        "semantic_naming_decompiled_dir",
    ],
    produces=[
        "flow_simplify_decompiled_dir",
        "timing_flow_simplify",
    ],
    parallelizable_with=[],
)
class FlowSimplifyStep(Step):
    """Control flow simplification — CFlowSimplifier."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["semantic_naming_decompiled_dir"]

        step_start = time.monotonic()

        try:
            from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
            flow_simplifier = CFlowSimplifier(pc.config)
            flow_result = flow_simplifier.simplify_directory(decompiled_dir)
            ctx.stats["flow_gotos_eliminated"] = flow_result.gotos_eliminated
            ctx.stats["flow_labels_renamed"] = flow_result.labels_renamed
            ctx.stats["flow_labels_inlined"] = flow_result.labels_inlined
            ctx.stats["flow_early_returns"] = flow_result.early_returns
            ctx.stats["flow_breaks_continues"] = flow_result.breaks_continues
            ctx.stats["flow_ifelse_restructured"] = flow_result.ifelse_restructured
            ctx.stats["flow_cascading_collapsed"] = flow_result.cascading_collapsed
            ctx.stats["flow_multi_target_inlined"] = flow_result.multi_target_inlined
            logger.info(
                "Flow simplify: %d goto eliminated, %d label renamed, "
                "%d early_ret, %d break/cont, %d if-else, %d cascade, %d multi",
                flow_result.gotos_eliminated, flow_result.labels_renamed,
                flow_result.early_returns, flow_result.breaks_continues,
                flow_result.ifelse_restructured, flow_result.cascading_collapsed,
                flow_result.multi_target_inlined,
            )
        except Exception as exc:
            logger.warning("Flow simplify hatasi: %s", exc)

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_flow_simplify"] = timing

        # In-place — decompiled_dir degismez, downstream icin aynen yayinla.
        return {
            "flow_simplify_decompiled_dir": decompiled_dir,
            "timing_flow_simplify": timing,
        }
