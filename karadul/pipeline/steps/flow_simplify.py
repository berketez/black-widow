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


# Sadeleştiricinin güvence sayaçları: sonuç alanı -> rapordaki ``stats`` anahtarı
_GUARD_COUNTERS = {
    "functions_reverted": "flow_functions_reverted",
    "functions_skipped": "flow_functions_skipped",
    "files_failed": "flow_files_failed",
}


def _record_guard_counters(ctx: StepContext, flow_result: Any) -> None:
    """Ard koşul sayaçlarını rapora taşı; geri alınan ya da hata veren varsa uyar.

    ``functions_reverted``: dönüşümden sonra ard koşul (ayraç dengesi, etiketler, çağrı ve
    ``return`` kümeleri, denetim akışı eşdeğerliği) tutmadığı için özgün metni yazılan
    fonksiyon. Sıfırdan büyükse bir dönüşüm hatalıdır; kod korunmuştur ama bu sessiz kalmaz.
    Sayı olmayan alan (eski sonuç nesnesi) yazılmaz.
    """
    for field_name, stat_key in _GUARD_COUNTERS.items():
        value = getattr(flow_result, field_name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            ctx.stats[stat_key] = value
    reverted = ctx.stats.get("flow_functions_reverted", 0)
    failed = ctx.stats.get("flow_files_failed", 0)
    if reverted or failed:
        message = (
            f"Flow simplify: {reverted} fonksiyon ard koşul tutmadığı için özgün hâline "
            f"döndürüldü, {failed} dosya işlenemedi"
        )
        logger.warning(message)
        ctx.errors.append(message)


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
            _record_guard_counters(ctx, flow_result)
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
