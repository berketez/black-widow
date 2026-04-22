"""ProjectBuildStep — organize C proje ciktisi (CProjectBuilder).

stages.py L3606-3627 'den tasindi. Davranis birebir korundu.
CProjectBuilder ile decompiled dosyalari tek bir C projesi olarak
`reconstructed/project/` altina yerlestirir.
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
    name="project_build",
    requires=[
        "engineering_annotation_decompiled_dir",
    ],
    produces=[
        "project_dir",
        "timing_project_build",
    ],
    parallelizable_with=[],
)
class ProjectBuildStep(Step):
    """C proje ciktisi insaasi (CProjectBuilder)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["engineering_annotation_decompiled_dir"]
        algo_result = ctx.artifacts.get("algo_result")

        pc.report_progress("Project Build...", 0.85)

        step_start = time.monotonic()
        project_dir: Path | None = None

        try:
            from karadul.reconstruction.c_project_builder import CProjectBuilder
            reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
            builder = CProjectBuilder(pc.config)
            project_dir = reconstructed_dir / "project"
            build_result = builder.build(
                source_dir=decompiled_dir,
                output_dir=project_dir,
                workspace=pc.workspace,
                algorithm_results=algo_result,
            )
            if build_result.success:
                ctx.stats["project_files"] = build_result.files_written
                ctx.produce_artifact("project_dir", project_dir)
                logger.info(
                    "Project built: %d dosya", build_result.files_written,
                )
        except Exception as exc:
            logger.warning("C project build hatasi: %s", exc)
            ctx.errors.append(f"C project build hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_project_build"] = timing

        return {
            "project_dir": project_dir,
            "timing_project_build": timing,
        }

