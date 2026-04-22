"""DeepTracingStep — v1.1.5 dispatch + data flow + composition + call chain.

stages.py L3760-3933 'ten tasindi. Davranis birebir korundu.
Dort alt-adim yardimci modulde (_deep_tracing_helpers.py):
- Virtual dispatch resolution
- Inter-procedural data flow
- Parameter name propagation
- Algorithm composition analysis
- Deep call chain tracing
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step
from karadul.pipeline.steps import _deep_tracing_helpers as _dh

logger = logging.getLogger(__name__)


@register_step(
    name="deep_tracing",
    requires=[
        "engineering_annotation_decompiled_dir",
        "functions_json_path",
        "call_graph_json_path",
        "strings_json_path",
        "xrefs_json_path",
        "call_graph_data",
        "sig_matches",
    ],
    produces=[
        "deep_tracing_result",
        "timing_deep_tracing",
    ],
    parallelizable_with=[],
)
class DeepTracingStep(Step):
    """Deep Algorithm Tracing — dispatch/data flow/composition/call chain."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        # engineering_annotation sonrasi dosya dizini (downstream path zinciri).
        decompiled_dir: Path = ctx.artifacts["engineering_annotation_decompiled_dir"]
        functions_json: Path = ctx.artifacts["functions_json_path"]
        call_graph_json: Path = ctx.artifacts["call_graph_json_path"]
        strings_json: Path = ctx.artifacts["strings_json_path"]
        xrefs_json: Path = ctx.artifacts["xrefs_json_path"]
        call_graph_data = ctx.artifacts["call_graph_data"]
        sig_matches = ctx.artifacts["sig_matches"]
        eng_result = ctx.artifacts.get("eng_result")
        algo_result = ctx.artifacts.get("algo_result")

        pc.report_progress("Deep Algorithm Tracing...", 0.95)

        step_start = time.monotonic()
        result: dict[str, Any] = {
            "dispatch_result": None,
            "data_flow_result": None,
            "augmented_cg_json": None,
        }

        if pc.config.binary_reconstruction.enable_engineering_analysis:
            reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")

            # 7.1 Virtual Dispatch Resolution
            dispatch_result, augmented_cg_json = _dh.resolve_dispatch(
                decompiled_dir=decompiled_dir,
                functions_json=functions_json,
                call_graph_json=call_graph_json,
                strings_json=strings_json,
                call_graph_data=call_graph_data,
                reconstructed_dir=reconstructed_dir,
                stats=ctx.stats,
                errors=ctx.errors,
                workspace=pc.workspace,
            )
            result["dispatch_result"] = dispatch_result
            result["augmented_cg_json"] = augmented_cg_json

            # 7.2 Inter-Procedural Data Flow
            data_flow_result = _dh.analyze_data_flow(
                decompiled_dir=decompiled_dir,
                functions_json=functions_json,
                call_graph_json=call_graph_json,
                augmented_cg_json=augmented_cg_json,
                xrefs_json=xrefs_json,
                reconstructed_dir=reconstructed_dir,
                stats=ctx.stats,
                errors=ctx.errors,
            )
            result["data_flow_result"] = data_flow_result

            # 7.2.5 Parameter Name Propagation
            _dh.propagate_param_names(
                decompiled_dir=decompiled_dir,
                functions_json=functions_json,
                call_graph_json=call_graph_json,
                augmented_cg_json=augmented_cg_json,
                sig_matches=sig_matches,
                stats=ctx.stats,
                errors=ctx.errors,
            )

            # Composition + Deep Trace icin ortak veri: algoritma listesi +
            # call graph. Orijinal kod `augmented_cgjson` typo'sundan dolayi
            # her zaman cache'ten okuyordu (L3868). Biz de cache'i
            # kullaniyoruz — davranis birebir korunuyor.
            all_algos = self._collect_all_algorithms(algo_result, eng_result)
            resolved_cg = _dh.resolve_call_graph(
                augmented_cg_json=augmented_cg_json,
                call_graph_data=call_graph_data,
            )

            publish = self._make_publish_artifact(pc)

            # 7.3 Algorithm Composition Analysis
            _dh.analyze_composition(
                call_graph_data=resolved_cg,
                all_algos=all_algos,
                data_flow_result=data_flow_result,
                dispatch_result=dispatch_result,
                reconstructed_dir=reconstructed_dir,
                stats=ctx.stats,
                errors=ctx.errors,
                workspace=pc.workspace,
                publish_artifact=publish,
            )

            # 7.4 Deep Call Chain Tracing
            _dh.deep_trace(
                call_graph_data=resolved_cg,
                all_algos=all_algos,
                dispatch_result=dispatch_result,
                reconstructed_dir=reconstructed_dir,
                stats=ctx.stats,
                errors=ctx.errors,
                publish_artifact=publish,
            )

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_deep_tracing"] = timing

        return {
            "deep_tracing_result": result,
            "timing_deep_tracing": timing,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _collect_all_algorithms(algo_result, eng_result) -> list:
        all_algos: list = []
        if algo_result and getattr(algo_result, "success", False):
            all_algos.extend(algo_result.algorithms)
        if eng_result and getattr(eng_result, "success", False):
            all_algos.extend(eng_result.algorithms)
        return all_algos

    @staticmethod
    def _make_publish_artifact(pc):
        """Artifact yayinlayici closure — shim pattern."""
        def _publish(key: str, value: Any) -> None:
            if pc.metadata is None:
                pc.metadata = {}  # type: ignore[attr-defined]
            pc.metadata.setdefault("artifacts_pending", {})[key] = value
        return _publish
