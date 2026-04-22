"""EngineeringAnnotationStep — muhendislik blok yorumlari (CodeBlockAnnotator).

stages.py L3568-3604 'ten tasindi. Davranis birebir korundu.
eng_result varsa algoritma-bazli kod bloklari etrafina muhendislik
aciklamalari ekler. Output dizini `reconstructed/annotated`; basarili
olursa downstream decompiled_dir bu dizine yonlenir.
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
    name="engineering_annotation",
    requires=[
        "capa_annotation_decompiled_dir",
        "functions_json_path",
        "call_graph_json_path",
    ],
    produces=[
        "engineering_annotation_decompiled_dir",
        "timing_block_annotation",
    ],
    parallelizable_with=[],
)
class EngineeringAnnotationStep(Step):
    """Muhendislik kod bloklari annotasyonu (CodeBlockAnnotator)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["capa_annotation_decompiled_dir"]
        functions_json: Path = ctx.artifacts["functions_json_path"]
        call_graph_json: Path = ctx.artifacts["call_graph_json_path"]
        eng_result = ctx.artifacts.get("eng_result")
        algo_result = ctx.artifacts.get("algo_result")

        step_start = time.monotonic()
        resulting_dir = decompiled_dir

        if pc.config.binary_reconstruction.enable_block_annotation and eng_result:
            try:
                from karadul.reconstruction.engineering import CodeBlockAnnotator
                from karadul.pipeline.steps.semantic_naming import SemanticNamingStep

                annotator = CodeBlockAnnotator(pc.config)
                all_algos = SemanticNamingStep._collect_all_algorithms(
                    algo_result, eng_result,
                )

                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                annotated_dir = reconstructed_dir / "annotated"
                annotated_dir.mkdir(parents=True, exist_ok=True)

                annot_result = annotator.annotate(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    output_dir=annotated_dir,
                    algorithm_matches=all_algos,
                )
                if annot_result and annot_result.success:
                    ctx.stats["block_annotations"] = annot_result.total_annotations
                    ctx.stats["annotated_files"] = len(annot_result.annotated_files)
                    self._publish_artifact(
                        pc, "annotated_sources", annotated_dir,
                    )
                    if annot_result.annotated_files:
                        resulting_dir = annotated_dir
                    logger.info(
                        "Block Annotation: %d annotation, %d dosya",
                        annot_result.total_annotations,
                        len(annot_result.annotated_files),
                    )
            except ImportError:
                logger.debug("CodeBlockAnnotator bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Block annotation hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Block annotation hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_block_annotation"] = timing

        return {
            "engineering_annotation_decompiled_dir": resulting_dir,
            "timing_block_annotation": timing,
        }

    @staticmethod
    def _publish_artifact(pc, key: str, value: Any) -> None:
        if pc.metadata is None:
            pc.metadata = {}  # type: ignore[attr-defined]
        pc.metadata.setdefault("artifacts_pending", {})[key] = value
