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


# Kurucunun fonksiyon sayımı: sonuç alanı -> rapordaki ``stats`` anahtarı
_BUILD_COUNTERS = {
    "functions_total": "project_functions_total",
    "functions_placed": "project_functions_placed",
    "functions_missing": "project_functions_missing",
    "functions_duplicated": "project_functions_duplicated",
}


def _record_build_report(ctx: StepContext, build_result: Any) -> None:
    """Kurucunun sayımını ve hata listesini rapora taşı (başarılı olsun olmasın).

    Kurucu "her girdi fonksiyonu çıktıda tam bir kez" değişmezini kendi denetler ve ihlali
    ``errors`` listesine yazar. Bu liste eskiden adımda yutuluyordu: düşen fonksiyon rapora
    ulaşmıyordu. Sayı olmayan alan (eski sonuç nesnesi) yazılmaz.
    """
    for field_name, stat_key in _BUILD_COUNTERS.items():
        value = getattr(build_result, field_name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            ctx.stats[stat_key] = value
    build_errors = getattr(build_result, "errors", None)
    if isinstance(build_errors, (list, tuple)):
        for err in build_errors:
            logger.warning("C project build: %s", err)
            ctx.errors.append(f"C project build: {err}")


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
        # P-S1 / BORU-05: proje yolu yalniz kurulum basariliysa doner ve yapit
        # olarak kaydedilir; aksi halde None + hata + ``project_build_status``.
        project_dir: Path | None = None
        built = False

        try:
            from karadul.reconstruction.c_project_builder import CProjectBuilder
            reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
            builder = CProjectBuilder(pc.config)
            target_dir = reconstructed_dir / "project"
            build_result = builder.build(
                source_dir=decompiled_dir,
                output_dir=target_dir,
                workspace=pc.workspace,
                algorithm_results=algo_result,
            )
            if build_result.success:
                built = True
                project_dir = target_dir
                ctx.stats["project_files"] = build_result.files_written
                ctx.produce_artifact("project_dir", project_dir)
                logger.info(
                    "Project built: %d dosya", build_result.files_written,
                )
            _record_build_report(ctx, build_result)
            if not built:
                build_errors = getattr(build_result, "errors", None)
                if not (isinstance(build_errors, (list, tuple)) and build_errors):
                    # Kurucu nedensiz basarisiz dondu: hata yine kayda gecsin.
                    ctx.errors.append(
                        "C project build basarisiz (kurucu neden bildirmedi)",
                    )
                ctx.stats["project_build_status"] = "hata"
                ctx.stats["project_build_status_reason"] = (
                    f"kurucu basarisiz dondu ({getattr(build_result, 'files_written', '?')} "
                    f"dosya yazildi)"
                )
        except Exception as exc:
            logger.warning("C project build hatasi: %s", exc)
            ctx.errors.append(f"C project build hatasi: {exc}")
            ctx.stats["project_build_status"] = "hata"
            ctx.stats["project_build_status_reason"] = f"{type(exc).__name__}: {exc}"
        if built:
            ctx.stats["project_build_status"] = "calisti"

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_project_build"] = timing

        return {
            "project_dir": project_dir,
            "timing_project_build": timing,
        }

