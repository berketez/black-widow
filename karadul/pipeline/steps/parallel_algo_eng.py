"""ParallelAlgoEngStep — BinaryNameExtractor + EngineeringAnalyzer paralel.

stages.py L1603-1721 arasindaki iki worker (_run_binary_name_extraction +
_run_engineering_analysis) iki paralel future olarak calistirilir.

v1.9.2 thread-safety patterni korundu:
- Her worker kendi dict'ini doner (stats/artifacts/result ayri).
- Main thread'de merge edilir — worker'lar shared state'e yazmaz.
- Boylece `nonlocal` + shared dict anti-pattern'inden kacinilir.

Not: stages.py orijinalinde 3 paralel future vardi (crypto algo ile birlikte).
v1.10.0 M1'de crypto algo `algorithm_id` step'ine ayrildi; bu step sadece
binary_name + engineering'i paralel calistirir.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="parallel_algo_eng",
    requires=[
        "decompiled_dir",
        "functions_json_path",
        "strings_json_path",
        "call_graph_json_path",
    ],
    produces=[
        "binary_name_result",
        "eng_result",
    ],
    parallelizable_with=["algorithm_id"],
)
class ParallelAlgoEngStep(Step):
    """BinaryNameExtractor + EngineeringAnalyzer paralel calistir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir = ctx.artifacts["decompiled_dir"]
        functions_json = ctx.artifacts["functions_json_path"]
        strings_json = ctx.artifacts["strings_json_path"]
        call_graph_json = ctx.artifacts["call_graph_json_path"]

        pc.report_progress(
            "Binary Name Extraction + Engineering Analysis...", 0.25,
        )
        step_start = time.monotonic()

        logger.info(
            "Binary Name Extraction + Engineering Analysis paralel baslatiliyor",
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            name_future = pool.submit(
                _run_binary_name_extraction,
                pc=pc,
                strings_json=strings_json,
                functions_json=functions_json,
                call_graph_json=call_graph_json,
            )
            eng_future = pool.submit(
                _run_engineering_analysis,
                pc=pc,
                decompiled_dir=decompiled_dir,
                functions_json=functions_json,
            )

        name_dict = name_future.result()
        eng_dict = eng_future.result()

        # v1.9.2 thread-safe merge — her future kendi stats/artifacts dict'ini
        # getirir, main thread burada konsolide eder.
        binary_name_result: dict[str, str] = {}
        eng_result: Any = None

        if name_dict.get("success"):
            binary_name_result = name_dict.get("result", {}) or {}
            ctx.stats.update(name_dict.get("stats", {}))
            self._absorb_artifacts(pc, name_dict.get("artifacts", {}))
        elif not name_dict.get("skipped") and "error" in name_dict:
            ctx.errors.append(name_dict["error"])

        if eng_dict.get("success"):
            eng_result = eng_dict.get("result")
            ctx.stats.update(eng_dict.get("stats", {}))
            self._absorb_artifacts(pc, eng_dict.get("artifacts", {}))
        elif not eng_dict.get("skipped") and "error" in eng_dict:
            ctx.errors.append(eng_dict["error"])

        ctx.stats["timing_name_eng_parallel"] = round(
            time.monotonic() - step_start, 1,
        )
        return {
            "binary_name_result": binary_name_result,
            "eng_result": eng_result,
        }

    @staticmethod
    def _absorb_artifacts(pc, artifacts: dict) -> None:
        """Artifact dict'ini pc.metadata['artifacts_pending']'e yaz.

        Runner artifact'lari pipeline artifact'i olarak saklar; eski
        stages.py ise bunlari StageResult.artifacts'a yazmak istiyor.
        Shim modunda aradaki koprüyü metadata uzerinden saglariz.
        """
        if not artifacts:
            return
        if pc.metadata is None:
            pc.metadata = {}  # type: ignore[attr-defined]
        pc.metadata.setdefault("artifacts_pending", {}).update(artifacts)


# ---------------------------------------------------------------------------
# Worker fonksiyonlari — top-level (ThreadPoolExecutor pickle icin)
# ---------------------------------------------------------------------------


def _run_binary_name_extraction(
    *, pc, strings_json, functions_json, call_graph_json,
) -> dict[str, Any]:
    """stages.py L1603-1651'den birebir tasindi."""
    if not pc.config.binary_reconstruction.enable_binary_name_extraction:
        return {"success": False, "skipped": True}
    try:
        from karadul.reconstruction.binary_name_extractor import (
            BinaryNameExtractor,
        )

        extractor = BinaryNameExtractor(pc.config)
        extract_result = extractor.extract(
            strings_json=strings_json,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
        )
        if extract_result.success and extract_result.names:
            names = {
                n.original_name: n.recovered_name
                for n in extract_result.names
            }
            extract_path = pc.workspace.save_json(
                "reconstructed", "binary_names",
                {
                    "total": len(names),
                    "names": {
                        n.original_name: {
                            "recovered": n.recovered_name,
                            "source": n.source,
                            "confidence": n.confidence,
                            "class": n.class_name,
                        }
                        for n in extract_result.names
                    },
                    "classes": extract_result.class_methods,
                },
            )
            logger.info(
                "Binary Name Extraction: %d isim, %d class",
                len(names), len(extract_result.class_methods),
            )
            return {
                "success": True,
                "result": names,
                "stats": {
                    "binary_names_extracted": len(names),
                    "classes_detected": len(extract_result.class_methods),
                },
                "artifacts": {"binary_names": extract_path},
            }
        return {"success": True, "result": {}, "stats": {}, "artifacts": {}}
    except ImportError:
        logger.debug("BinaryNameExtractor bulunamadi, atlaniyor")
        return {"success": False, "skipped": True}
    except Exception as exc:
        logger.warning("Binary name extraction hatasi: %s", exc)
        return {
            "success": False,
            "error": f"Binary name extraction hatasi: {exc}",
        }


def _run_engineering_analysis(
    *, pc, decompiled_dir, functions_json,
) -> dict[str, Any]:
    """stages.py L1653-1686'dan birebir tasindi."""
    if not pc.config.binary_reconstruction.enable_engineering_analysis:
        return {"success": False, "skipped": True}
    try:
        from karadul.reconstruction.engineering import (
            EngineeringAlgorithmAnalyzer,
        )

        eng_analyzer = EngineeringAlgorithmAnalyzer()
        eng_res = eng_analyzer.identify(decompiled_dir, functions_json)
        if eng_res and eng_res.success:
            eng_path = pc.workspace.save_json(
                "reconstructed", "engineering_algorithms", eng_res.to_dict(),
            )
            logger.info(
                "Engineering Algorithm ID: %d tespit edildi",
                eng_res.total_detected,
            )
            return {
                "success": True,
                "result": eng_res,
                "stats": {
                    "engineering_algorithms_detected": eng_res.total_detected,
                    "engineering_by_category": eng_res.by_category,
                },
                "artifacts": {"engineering_algorithms": eng_path},
            }
        return {
            "success": True, "result": eng_res, "stats": {}, "artifacts": {},
        }
    except ImportError:
        logger.debug("EngineeringAlgorithmAnalyzer bulunamadi, atlaniyor")
        return {"success": False, "skipped": True}
    except Exception as exc:
        logger.warning("Engineering algorithm analysis hatasi: %s", exc)
        return {
            "success": False,
            "error": f"Engineering algorithm analysis hatasi: {exc}",
        }
