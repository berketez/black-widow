"""StructRecoveryStep — algoritma-bazli struct field isimlendirme.

stages.py L3356-3404'ten tasindi. Davranis birebir korundu:
StructRecoveryEngine algoritma bilgisine dayanarak struct field'larini
anlamli isimlerle yeniden adlandirir ve types_header enrich eder.
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
    name="struct_recovery",
    requires=[
        "final_decompiled_dir",
        "functions_json_path",
        "ghidra_types_json_path",
        "call_graph_json_path",
        "updated_algo_result",
        "updated_eng_result",
        "computation_result",
    ],
    produces=[
        "struct_recovery_decompiled_dir",
        "struct_recovery_result",
        "timing_struct_recovery",
    ],
    parallelizable_with=[],
)
class StructRecoveryStep(Step):
    """StructRecoveryEngine ile struct field'larini isimlendir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        a = ctx.artifacts
        decompiled_dir: Path = a["final_decompiled_dir"]
        functions_json: Path = a["functions_json_path"]
        ghidra_types_json: Path = a["ghidra_types_json_path"]
        call_graph_json: Path = a["call_graph_json_path"]
        algo_result: Any = a["updated_algo_result"]
        eng_result: Any = a["updated_eng_result"]
        computation_result: Any = a["computation_result"]

        step_start = time.monotonic()
        struct_result: Any = None
        resulting_dir = decompiled_dir

        if pc.config.binary_reconstruction.enable_struct_recovery and eng_result:
            try:
                from karadul.reconstruction.engineering import StructRecoveryEngine
                struct_engine = StructRecoveryEngine(pc.config)

                all_algos = self._collect_all_algorithms(algo_result, eng_result)
                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                struct_dir = reconstructed_dir / "struct_recovered"
                struct_dir.mkdir(parents=True, exist_ok=True)

                # v1.5.2: Computation Recovery struct verilerini hazirla
                comp_structs_for_eng = None
                if computation_result and computation_result.success:
                    cs_layer = computation_result.layer_results.get(
                        "constraint_solver",
                    )
                    if cs_layer and hasattr(cs_layer, "structs") and cs_layer.structs:
                        comp_structs_for_eng = [
                            s.to_dict() for s in cs_layer.structs
                        ]

                struct_result = struct_engine.recover(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    ghidra_types_json=ghidra_types_json,
                    call_graph_json=call_graph_json,
                    output_dir=struct_dir,
                    algorithm_matches=all_algos,
                    computation_structs=comp_structs_for_eng,
                )
                if struct_result.success:
                    ctx.stats["structs_enriched"] = struct_result.total_structs
                    ctx.stats["field_access_rewrites"] = (
                        struct_result.field_access_rewrites
                    )
                    if struct_result.types_header_path:
                        ctx.produce_artifact(
                            "enriched_types_header",
                            struct_result.types_header_path,
                        )
                    if struct_result.rewritten_files:
                        resulting_dir = struct_dir
                    logger.info(
                        "Struct Recovery: %d struct, %d field rewrite",
                        struct_result.total_structs,
                        struct_result.field_access_rewrites,
                    )
            except ImportError:
                logger.debug("StructRecoveryEngine bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Struct recovery hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Struct recovery hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_struct_recovery"] = timing

        return {
            "struct_recovery_decompiled_dir": resulting_dir,
            "struct_recovery_result": struct_result,
            "timing_struct_recovery": timing,
        }

    # --- helpers -----------------------------------------------------

    @staticmethod
    def _collect_all_algorithms(algo_result: Any, eng_result: Any) -> list[Any]:
        """stages.py `_collect_all_algorithms` ile ayni."""
        all_algos: list[Any] = []
        if algo_result and getattr(algo_result, "success", False):
            all_algos.extend(algo_result.algorithms)
        if eng_result and getattr(eng_result, "success", False):
            all_algos.extend(eng_result.algorithms)
        return all_algos
