"""CommentGenerationStep — C yorum ekleme (CCommentGenerator).

stages.py L3496-3549 'dan tasindi. Davranis birebir korundu.
CCommentGenerator ile fonksiyon bazli yorum/vulnerability warning/logic/
computation annotation ekler. Output dizini `reconstructed/commented`;
downstream icin decompiled_dir buraya yonlenir.
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
    name="comment_generation",
    requires=[
        "flow_simplify_decompiled_dir",
        "functions_json_path",
        "strings_json_path",
        "call_graph_json_path",
    ],
    produces=[
        "comment_generation_decompiled_dir",
        "timing_comment_generation",
    ],
    parallelizable_with=[],
)
class CommentGenerationStep(Step):
    """C kaynak dosyalarina yorum ekler (CCommentGenerator)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["flow_simplify_decompiled_dir"]
        functions_json: Path = ctx.artifacts["functions_json_path"]
        strings_json: Path = ctx.artifacts["strings_json_path"]
        call_graph_json: Path = ctx.artifacts["call_graph_json_path"]
        algo_result = ctx.artifacts.get("algo_result")
        computation_result = ctx.artifacts.get("computation_result")

        pc.report_progress("Comment Generation...", 0.75)

        step_start = time.monotonic()
        resulting_dir = decompiled_dir

        if pc.config.binary_reconstruction.enable_comment_generation:
            try:
                from karadul.reconstruction.c_comment_generator import CCommentGenerator
                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                commenter = CCommentGenerator(pc.config)
                comment_dir = reconstructed_dir / "commented"
                comment_dir.mkdir(parents=True, exist_ok=True)
                comment_result = commenter.generate(
                    decompiled_dir=decompiled_dir,
                    output_dir=comment_dir,
                    functions_json=functions_json,
                    strings_json=strings_json,
                    call_graph_json=call_graph_json,
                    algorithm_results=(
                        algo_result.algorithms if algo_result else None
                    ),
                    cfg_matches=(
                        computation_result.layer_results.get(
                            "cfg_fingerprint", {},
                        ).get("matches", [])
                        if computation_result and computation_result.success
                        else None
                    ),
                    formulas_extracted=(
                        computation_result.layer_results.get(
                            "formula_extraction", {},
                        ).get("formulas", [])
                        if computation_result and computation_result.success
                        else None
                    ),
                )
                if comment_result.success:
                    ctx.stats["comments_added"] = comment_result.total_comments_added
                    ctx.stats["vuln_warnings"] = comment_result.vulnerability_warnings
                    ctx.stats["logic_comments"] = comment_result.logic_comments
                    ctx.stats["computation_annotations"] = comment_result.computation_annotations
                    ctx.produce_artifact("commented_sources", comment_dir)
                    resulting_dir = comment_dir
                    logger.info(
                        "Comments: %d yorum eklendi (%d guvenlik, %d logic, %d computation)",
                        comment_result.total_comments_added,
                        comment_result.vulnerability_warnings,
                        comment_result.logic_comments,
                        comment_result.computation_annotations,
                    )
                else:
                    ctx.errors.extend(comment_result.errors)
            except Exception as exc:
                logger.warning("Comment generation hatasi: %s", exc)
                ctx.errors.append(f"Comment generation hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_comment_generation"] = timing

        return {
            "comment_generation_decompiled_dir": resulting_dir,
            "timing_comment_generation": timing,
        }

