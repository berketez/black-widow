"""SemanticNamingStep — algoritma-bazli parametre isimlendirme.

stages.py L3433-3468 'den tasindi. SemanticParameterNamer ile eng_result
varsa parametreleri anlamli isimlerle yeniden adlandirir. Output dizini
`reconstructed/semantic_named` — rename basarili olursa downstream icin
`decompiled_dir` bu dizine yonlenir (artifact olarak).
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
    name="semantic_naming",
    requires=[
        "decompiled_dir",
        "functions_json_path",
        "call_graph_json_path",
        "sig_matches",
    ],
    produces=[
        "semantic_naming_decompiled_dir",
        "params_renamed",
        "timing_semantic_naming",
    ],
    parallelizable_with=[],
)
class SemanticNamingStep(Step):
    """Algoritma-bazli parametre isimlendirme (SemanticParameterNamer)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["decompiled_dir"]
        functions_json: Path = ctx.artifacts["functions_json_path"]
        call_graph_json: Path = ctx.artifacts["call_graph_json_path"]
        sig_matches: Any = ctx.artifacts["sig_matches"]

        # Feedback loop sonrasi eng_result/algo_result guncel halleri seed
        # olarak ctx'te bulunur (T3.5 shim tarafindan inject edilir).
        eng_result = ctx.artifacts.get("eng_result")
        algo_result = ctx.artifacts.get("algo_result")

        step_start = time.monotonic()
        resulting_dir = decompiled_dir  # Rename basarisiz ise dokunulmaz
        params_renamed = 0

        if pc.config.binary_reconstruction.enable_semantic_naming and eng_result:
            try:
                from karadul.reconstruction.engineering import SemanticParameterNamer
                sem_namer = SemanticParameterNamer(pc.config)

                all_algos = self._collect_all_algorithms(algo_result, eng_result)

                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                sem_dir = reconstructed_dir / "semantic_named"
                sem_dir.mkdir(parents=True, exist_ok=True)

                sem_result = sem_namer.rename(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    output_dir=sem_dir,
                    algorithm_matches=all_algos,
                    signature_matches=sig_matches if sig_matches else None,
                )
                if sem_result and sem_result.success:
                    params_renamed = sem_result.total_renamed
                    ctx.stats["params_renamed"] = params_renamed
                    if sem_result.output_files:
                        resulting_dir = sem_dir
                    logger.info(
                        "Semantic Naming: %d parametre yeniden isimlendi",
                        params_renamed,
                    )
            except ImportError:
                logger.debug("SemanticParameterNamer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Semantic naming hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Semantic naming hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_semantic_naming"] = timing

        return {
            "semantic_naming_decompiled_dir": resulting_dir,
            "params_renamed": params_renamed,
            "timing_semantic_naming": timing,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _collect_all_algorithms(algo_result, eng_result) -> list:
        """stages.py _collect_all_algorithms'in step-local kopyasi.

        Downstream step'ler de ayni veriyi seed'den alacagi icin ortak helper
        daha sonra (M2+) karadul.pipeline.steps._common_helpers'a tasinabilir.
        """
        all_algos: list = []
        if algo_result and getattr(algo_result, "success", False):
            all_algos.extend(algo_result.algorithms)
        if eng_result and getattr(eng_result, "success", False):
            all_algos.extend(eng_result.algorithms)
        return all_algos
