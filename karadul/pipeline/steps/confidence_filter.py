"""ConfidenceFilterStep — kalibrasyon + merge + match budget + CAPA.

stages.py `_execute_binary` L1723-1908'den tasindi. Davranis birebir korundu.
Bu step asagidakileri sirayla yapar:

1. Confidence Calibration (L1723-1786) — ConfidenceCalibrator ile
   eng_result.algorithms uzerinde call-graph bazli kalibrasyon.
2. Engineering + Crypto Merge (L1789-1802) — algorithms_merged.json artifact.
3. Match Budget (L1804-1845) — en dusuk confidence'li match'leri kes,
   algo_result/eng_result listelerini yerinde kirp (MAX_ALGO_MATCHES).
4. Byte pattern merge (L1846-1858) — byte_pattern_names'i extracted_names
   (binary_name_result) dict'ine, ezmeden birlestir.
5. CAPA merge (L1860-1908) — static stage'in capa_capabilities ciktisindan
   henuz isimlendirilmemis fonksiyonlara isim ata.

Adim-adim implementation icin bkz. `_confidence_helpers.py`. Step bu dosyayi
minimal tutar; detaylar helper modulde.

Not: Adimlarin hepsi ayni veri seti uzerinde sirayla islem yaptiklari icin
tek step olarak birlestirildi. Alt adimlarin ayri step'lere bolunmesi
M2+ refactor sprintine birakildi.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step
from karadul.pipeline.steps import _confidence_helpers as _ch

logger = logging.getLogger(__name__)


@register_step(
    name="confidence_filter",
    requires=[
        "eng_result",
        "algo_result",
        "binary_name_result",
        "byte_pattern_names",
        "c_files",
        "file_cache",
    ],
    produces=[
        "calibrated_matches",
        "algo_result_filtered",
        "eng_result_filtered",
        "extracted_names",
        # v1.10.0 H3: byte_pattern + CAPA merge sonrasi "finalize edilmis"
        # isim haritasi.  extracted_names feedback_loop icinde mutate ediliyor;
        # Phase 3 step'leri (comment_generation vs.) orijinal cikisa erisebilmeli.
        # Icerik extracted_names ile AYNI referansta degil — shallow kopya.
        "extracted_names_final",
        "capa_capabilities",
    ],
    parallelizable_with=[],
)
class ConfidenceFilterStep(Step):
    """Kalibrasyon + merge + match budget + byte pattern + CAPA naming."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        eng_result: Any = ctx.artifacts["eng_result"]
        algo_result: Any = ctx.artifacts["algo_result"]
        # binary_name_result'i kopyala — ustune byte_pattern + CAPA yazacagiz
        # ve orijinal artifact'i mutate etmek istemiyoruz.
        extracted_names: dict[str, str] = dict(
            ctx.artifacts["binary_name_result"],
        )
        byte_pattern_names: dict[str, str] = ctx.artifacts["byte_pattern_names"]
        c_files: list[Path] = ctx.artifacts["c_files"]
        file_cache: dict[str, str] = ctx.artifacts["file_cache"]

        # 1. Calibration
        calibrated_matches = _ch.run_calibration(
            pc=pc,
            eng_result=eng_result,
            c_files=c_files,
            file_cache=file_cache,
            ctx=ctx,
        )

        # 2. Merge
        _ch.run_merge(
            pc=pc,
            algo_result=algo_result,
            eng_result=eng_result,
            calibrated_matches=calibrated_matches,
            ctx=ctx,
        )

        # 3. Match budget — algo_result/eng_result listelerini yerinde kirpar
        _ch.run_match_budget(
            pc=pc,
            algo_result=algo_result,
            eng_result=eng_result,
            ctx=ctx,
        )

        # 4. Byte pattern merge
        extracted_names = _ch.run_byte_pattern_merge(
            byte_pattern_names=byte_pattern_names,
            extracted_names=extracted_names,
        )

        # 5. CAPA merge
        capa_capabilities = _ch.run_capa_merge(
            pc=pc,
            extracted_names=extracted_names,
            ctx=ctx,
        )

        return {
            "calibrated_matches": calibrated_matches,
            # Match budget algo_result/eng_result'i yerinde degistirdi,
            # ayni referansi "_filtered" adiyla tekrar expose ediyoruz.
            "algo_result_filtered": algo_result,
            "eng_result_filtered": eng_result,
            "extracted_names": extracted_names,
            # v1.10.0 H3: feedback_loop extracted_names'i mutate etmeden
            # Phase 3 step'leri isim haritasini referans alabilsin diye
            # shallow kopya (merge sonrasi finalize edilmis hali).
            "extracted_names_final": dict(extracted_names),
            "capa_capabilities": capa_capabilities,
        }
