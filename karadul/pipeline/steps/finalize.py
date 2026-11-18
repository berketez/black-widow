"""FinalizeStep — StageResult toplama ve dondurme.

stages.py L3935-3955 'ten tasindi. Tum onceki step'lerin stats/errors'ini
topladiktan sonra StageResult'i olusturur ve artifact olarak yayinlar.
Cagiran shim bu sonucu alip binary_reconstruction stage'inin return degeri
yapar.

Basari olcutu (P-S1 / BORU-05): eskiden ``success = len(artifacts) > 0`` idi;
anti_debug adimi JSON'unu her kosulda yazdigi icin bu fiilen hep True'ydu
(proje kurulamamis, adlandirma cokmus kosu "OK"). Artik
``reconstruct_outcome`` tek olcuttur: proje kuruldu (``project_dir`` yapiti var)
VE C adlandirma adimi hatasiz. Basarili ama bir adimi hata vermis kosu
``partial`` (+ nedenler) olarak isaretlenir.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.core.pipeline import (  # noqa: F401  (durum dizgileri buradan da ihrac edilir)
    OUTCOME_COMPLETE,
    OUTCOME_FAILED,
    OUTCOME_PARTIAL,
    StageResult,
)
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# Durum alaninin degerleri (stats["reconstruct_status"]) core.pipeline'dan (P14: tek
# kaynak; analyze / batch analiz durumuyla ayni dizgiler):
#   OUTCOME_COMPLETE "tam"        basarili, hicbir adim hata bildirmedi
#   OUTCOME_PARTIAL  "kismi"      basarili ama en az bir adim hata bildirdi
#   OUTCOME_FAILED   "basarisiz"  proje kurulamadi ya da C adlandirma hatali

# partial_reasons'ta en cok bu kadar (tekillestirilmis) hata iletisi; toplam
# reconstruct_error_count'ta, tam liste StageResult.errors'ta.
_MAX_PARTIAL_REASONS = 20


def c_naming_enabled(config: Any) -> bool:
    """C adlandirma adimi ayarla kapatilmadi mi? (yalniz acik ``False`` kapatir)."""
    recon = getattr(config, "binary_reconstruction", None)
    return getattr(recon, "enable_c_naming", True) is not False


def reconstruct_outcome(
    *,
    artifacts: dict[str, Any],
    errors: list[str],
    naming_result: Any,
    naming_enabled: bool,
) -> dict[str, Any]:
    """Binary reconstruct aşamasının sonucu: basari + durum + nedenler.

    Basari = proje kuruldu (``project_dir`` yapiti) VE C adlandirma hatasiz
    (son yinelemenin ``naming_result.success`` True). Adlandirma ayarla
    kapaliysa basariyi dusurmez (bilinçli secim), durumda ``kapali`` yazar.
    Basariliysa ve ``errors`` bos degilse ``partial``.

    Returns:
        ``success`` (bool) ve ``stats``'a yazilacak alanlar:
        ``reconstruct_status`` (tam / kismi / basarisiz),
        ``reconstruct_failure_reasons`` (list[str]), ``partial`` (bool),
        ``partial_reasons`` (list[str], tekil, en cok 20),
        ``reconstruct_error_count`` (int), ``reconstruct_project_built`` (bool),
        ``reconstruct_naming_status`` (calisti / hata / kapali).
    """
    failure: list[str] = []
    project_built = "project_dir" in artifacts
    if not project_built:
        failure.append("proje kurulamadi (project_dir yapiti yok)")

    if not naming_enabled:
        naming_status = "kapali"
    elif naming_result is None:
        naming_status = "hata"
        failure.append(
            "C adlandirma sonuc vermedi (adim istisnayla dustu ya da calismadi)",
        )
    elif getattr(naming_result, "success", False) is not True:
        naming_status = "hata"
        first = next(iter(getattr(naming_result, "errors", None) or []), "")
        failure.append(
            "C adlandirma basarisiz" + (f": {first}" if first else ""),
        )
    else:
        naming_status = "calisti"

    success = not failure
    unique_errors = list(dict.fromkeys(str(e) for e in errors))
    partial = success and bool(unique_errors)
    if not success:
        status = OUTCOME_FAILED
    elif partial:
        status = OUTCOME_PARTIAL
    else:
        status = OUTCOME_COMPLETE
    return {
        "success": success,
        "stats": {
            "reconstruct_status": status,
            "reconstruct_failure_reasons": failure,
            "partial": partial,
            "partial_reasons": unique_errors[:_MAX_PARTIAL_REASONS] if partial else [],
            "reconstruct_error_count": len(errors),
            "reconstruct_project_built": project_built,
            "reconstruct_naming_status": naming_status,
        },
    }


@register_step(
    name="finalize",
    requires=[
        # Post-feedback pipeline'inin "son" step'i olmasi icin bircok step'in
        # ciktisini kuyrukluyoruz — topological sort bunu en sona koyar.
        "deep_tracing_result",
        "engineering_analysis_result",
        "project_dir",
    ],
    produces=[
        "stage_result",
    ],
    parallelizable_with=[],
)
class FinalizeStep(Step):
    """Pipeline sonu: stats ozetle, StageResult olustur."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        stage_name = ctx.artifacts.get(
            "__stage_name", "binary_reconstruction",
        )
        pipeline_start = ctx.artifacts.get("__pipeline_start")

        duration = (
            time.monotonic() - pipeline_start
            if pipeline_start is not None else 0.0
        )

        # v1.14.0 Dalga 0: artifacts_pending mirror'i tamamen kaldirildi.
        # Stage artifact'lari yalnizca ctx.stage_artifacts'tan okunur
        # (produce_artifact() ile yazilan yeni kanal).
        artifacts: dict = dict(ctx.stage_artifacts)

        errors = list(ctx.errors)
        stats = dict(ctx.stats)

        # v1.10.0: feedback_loop'un convergence_reason ciktisi stats'e tasindi.
        # Boylece observability layer (CLI/run reports) hangi sebepten loop'un
        # durdugunu okuyabilir (max_iter / no_new_names / iteration_timeout /
        # convergence_ratio_X.XXX vb.).
        convergence_reason = ctx.artifacts.get("convergence_reason", "unknown")
        stats["convergence_reason"] = convergence_reason

        # P-S1 / BORU-05: basari = proje kuruldu VE C adlandirma hatasiz.
        # naming_result Faz 2'den tohumla gelir (stages.py). Cagiran (stages.py)
        # Faz 1/2 hatalarini birlestirdikten sonra ayni olcutu yeniden uygular.
        outcome = reconstruct_outcome(
            artifacts=artifacts,
            errors=errors,
            naming_result=ctx.artifacts.get("naming_result"),
            naming_enabled=c_naming_enabled(ctx.pipeline_context.config),
        )
        success = outcome["success"]
        stats.update(outcome["stats"])

        # v1.2.2: Toplam timing ozeti
        timing_keys = [k for k in stats if k.startswith("timing_")]
        timing_total = sum(stats[k] for k in timing_keys)
        logger.info(
            "Binary reconstruction: %d artifact, %.1fs (step toplami %.1fs), %d hata",
            len(artifacts), duration, timing_total, len(errors),
        )
        for tk in sorted(timing_keys):
            logger.debug("  %s: %.1fs", tk, stats[tk])

        stage_result = StageResult(
            stage_name=stage_name,
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

        return {"stage_result": stage_result}
