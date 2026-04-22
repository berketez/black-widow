"""EngineeringAnalysisStep icin yardimci fonksiyonlar.

stages.py L3629-3758 'deki buyuk bloku daha yonetilebilir parcalar halinde
tutmak icin bolundu. Davranis birebir korunuyor — testler aynen gecmeli.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def collect_binary_hints(
    func_data: Any,
    static_dir: Path,
) -> dict[str, str] | None:
    """Binary domain override tespit et — BLAS/ML indikatorleri.

    Orijinal davranis (stages.py L3648-3683):
    1. func_data varsa fonksiyon adlarinda BLAS_ML_INDICATORS arar
    2. Yoksa dynamic_libraries.json'dan blas/lapack/accelerate/mkl taramasi
    """
    from karadul.reconstruction.c_algorithm_id import BLAS_ML_INDICATORS

    if func_data:
        for fn in func_data:
            fn_lower = fn.lower() if isinstance(fn, str) else ""
            if any(ind in fn_lower for ind in BLAS_ML_INDICATORS):
                logger.info(
                    "Binary domain override: ml (indicator in '%s')", fn,
                )
                return {"domain_override": "ml"}

    dyn_libs_path = static_dir / "dynamic_libraries.json"
    if dyn_libs_path.exists():
        try:
            dyn_data = json.loads(dyn_libs_path.read_text())
            libs = dyn_data.get("libraries", [])
            lib_str = " ".join(
                str(l.get("path", l) if isinstance(l, dict) else l).lower()
                for l in libs
            )
            ml_lib_indicators = {
                "blas", "lapack", "accelerate", "openblas",
                "mkl", "cublas", "veclib",
            }
            if any(ind in lib_str for ind in ml_lib_indicators):
                logger.info(
                    "Binary domain override from dynamic_libraries: ml",
                )
                return {"domain_override": "ml"}
        except Exception:
            logger.debug(
                "Binary domain override tespiti basarisiz, atlaniyor",
                exc_info=True,
            )
    return None


def normalize_strings(string_data: Any) -> list | None:
    """DomainClassifier'a verilecek string listesini hazirla.

    Orijinal davranis (stages.py L3686-3697): string_data list ise aynen
    kullan, dict ise 'strings' key'inden degerleri cikar, her biri dict ise
    'value' alanini al, yoksa str() yap.
    """
    if not string_data:
        return None
    if isinstance(string_data, list):
        return string_data
    if isinstance(string_data, dict):
        raw_strings = string_data.get(
            "strings", list(string_data.values()),
        )
        return [
            s["value"] if isinstance(s, dict) else str(s)
            for s in raw_strings
        ]
    return None


def collect_algorithm_list(algo_result, eng_result) -> list:
    """algo_result + eng_result'tan algoritma listesi olustur.

    Orijinal davranis stages.py L3641-3645 ve `_collect_all_algorithms` ile
    ayni — duplikasyonu onlemek icin cagiran step bu helper'i kullaniyor.
    """
    all_algo_list: list = []
    if algo_result and getattr(algo_result, "success", False):
        all_algo_list.extend(algo_result.algorithms)
    if eng_result and getattr(eng_result, "success", False):
        all_algo_list.extend(eng_result.algorithms)
    return all_algo_list


def build_analysis_payload(
    domain_report,
    formulas,
    computation_result,
) -> dict:
    """Engineering analysis JSON payload'unu olustur.

    Orijinal davranis stages.py L3711-3734. Ciktidaki ekstra alanlar:
    - primary_domain: en yuksek skorlu domain (domain_summary varsa)
    - computation_fusion_identifications / _count: fusion verisi varsa
    """
    eng_analysis = {
        "domain_classification": domain_report.to_dict(),
        "formulas": [f.to_dict() for f in formulas],
        "total_formulas": len(formulas),
    }
    if domain_report.domain_summary:
        eng_analysis["primary_domain"] = max(
            domain_report.domain_summary,
            key=domain_report.domain_summary.get,
        )
    if computation_result and getattr(computation_result, "success", False):
        fusion_layer = computation_result.layer_results.get(
            "signature_fusion", {},
        )
        if isinstance(fusion_layer, dict):
            fusion_ids = fusion_layer.get("identifications", {})
            if fusion_ids:
                eng_analysis["computation_fusion_identifications"] = fusion_ids
                eng_analysis["computation_fusion_count"] = len(fusion_ids)
    return eng_analysis
