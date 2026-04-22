"""EngineeringAnalysisStep — Domain Classification + Formula Reconstruction.

stages.py L3629-3758 'den tasindi. Buyuk step oldugu icin helper modulle
bolundu (bkz. _engineering_helpers.py). Davranis birebir korundu.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step
from karadul.pipeline.steps import _engineering_helpers as _eh

logger = logging.getLogger(__name__)


@register_step(
    name="engineering_analysis",
    requires=[
        "project_dir",  # Sadece sira kontrolu icin — project_build sonrasi.
        "functions_data",
    ],
    produces=[
        "engineering_analysis_result",
        "timing_engineering_analysis",
    ],
    parallelizable_with=[],
)
class EngineeringAnalysisStep(Step):
    """Engineering Analysis — Domain Classification + Formula Reconstruction."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        func_data = ctx.artifacts["functions_data"]
        eng_result = ctx.artifacts.get("eng_result")
        algo_result = ctx.artifacts.get("algo_result")
        computation_result = ctx.artifacts.get("computation_result")

        step_start = time.monotonic()
        result_payload: dict[str, Any] | None = None

        should_run = (
            pc.config.binary_reconstruction.enable_engineering_analysis
            and (algo_result or eng_result)
        )

        if should_run:
            try:
                from karadul.reconstruction.engineering import (
                    DomainClassifier,
                    FormulaReconstructor,
                )

                all_algo_list = _eh.collect_algorithm_list(
                    algo_result, eng_result,
                )

                static_dir = pc.workspace.get_stage_dir("static")
                binary_hints = _eh.collect_binary_hints(func_data, static_dir)

                string_data = ctx.artifacts.get("strings_data")
                domain_strings = _eh.normalize_strings(string_data)

                domain_clf = DomainClassifier()
                domain_report = domain_clf.classify(
                    algorithms=all_algo_list,
                    strings=domain_strings,
                    binary_hints=binary_hints,
                )

                formula_rec = FormulaReconstructor()
                formulas = formula_rec.reconstruct(all_algo_list)

                eng_analysis = _eh.build_analysis_payload(
                    domain_report, formulas, computation_result,
                )

                eng_json_path = pc.workspace.save_json(
                    "reconstructed", "engineering_analysis", eng_analysis,
                )
                ctx.produce_artifact("engineering_analysis", eng_json_path)

                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                md_report = formula_rec.generate_report(formulas)
                md_path = reconstructed_dir / "engineering_analysis.md"
                md_path.write_text(md_report, encoding="utf-8")
                ctx.produce_artifact("engineering_analysis_md", md_path)

                ctx.stats["engineering_domains"] = len(domain_report.domain_summary)
                ctx.stats["engineering_formulas"] = len(formulas)
                logger.info(
                    "Engineering Analysis: %d domain, %d formula",
                    len(domain_report.domain_summary), len(formulas),
                )

                result_payload = {
                    "domain_report": domain_report,
                    "formulas": formulas,
                    "eng_analysis": eng_analysis,
                    "json_path": eng_json_path,
                    "md_path": md_path,
                }
            except ImportError:
                logger.debug(
                    "Engineering analysis modulleri bulunamadi, atlaniyor",
                )
            except Exception as exc:
                logger.warning("Engineering analysis hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Engineering analysis hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_engineering_analysis"] = timing

        return {
            "engineering_analysis_result": result_payload,
            "timing_engineering_analysis": timing,
        }

