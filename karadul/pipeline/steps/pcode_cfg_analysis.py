"""PcodeCfgAnalysisStep — P-Code dataflow + CFG analizleri.

stages.py `_execute_binary` L1453-1557'den tasindi. Davranis birebir korundu:
- P-Code JSON stats_only / jsonl / legacy mod tespiti
- PcodeAnalyzer ile streaming/legacy analiz + naming candidate uretimi
- CFGAnalyzer ile block/edge/classification analizi

Not: Orijinal kodda P-Code ve CFG ardarda ama ayri try/except bloklariydi.
Tek step altinda birlestirdik (her iki analiz de Ghidra metadata'sina
bagli, birbirinden bagimsiz; step icinde iki helper metot).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="pcode_cfg_analysis",
    requires=["pcode_json_path", "cfg_json_path"],
    produces=[
        "pcode_result",
        "cfg_result",
        "pcode_naming_candidates",
    ],
    parallelizable_with=[],
)
class PcodeCfgAnalysisStep(Step):
    """P-Code + CFG analizlerini calistir, naming candidate'leri uret."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pcode_json: Path = ctx.artifacts["pcode_json_path"]
        cfg_json: Path = ctx.artifacts["cfg_json_path"]

        pcode_result, pcode_naming_candidates = self._analyze_pcode(
            pcode_json=pcode_json, ctx=ctx,
        )
        cfg_result = self._analyze_cfg(cfg_json=cfg_json, ctx=ctx)

        return {
            "pcode_result": pcode_result,
            "cfg_result": cfg_result,
            "pcode_naming_candidates": pcode_naming_candidates,
        }

    # --- P-Code -------------------------------------------------------

    @staticmethod
    def _analyze_pcode(
        *, pcode_json: Path, ctx: StepContext,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """stages.py L1453-1532: stats_only / JSONL / legacy mod tespiti."""
        step_start = time.monotonic()
        pcode_result: Any = None
        pcode_naming_candidates: list[dict[str, Any]] = []

        if not (pcode_json and pcode_json.exists()):
            ctx.stats["timing_pcode"] = round(
                time.monotonic() - step_start, 1,
            )
            return pcode_result, pcode_naming_candidates

        try:
            with open(pcode_json, "r", encoding="utf-8") as pf:
                header = pf.read(4096)

            is_stats_only = '"mode": "stats_only"' in header
            is_jsonl = '"mode": "jsonl"' in header

            if is_stats_only:
                # v1.4.4: stats_only — 4.7GB parse etme
                pcode_data = json.loads(header)
                ctx.stats["pcode_functions_analyzed"] = pcode_data.get(
                    "total_functions", 0,
                )
                ctx.stats["pcode_total_ops"] = pcode_data.get(
                    "total_pcode_ops", 0,
                )
                logger.info(
                    "P-Code stats-only: %d fonksiyon, %d op",
                    ctx.stats["pcode_functions_analyzed"],
                    ctx.stats["pcode_total_ops"],
                )
            elif is_jsonl:
                pcode_result, pcode_naming_candidates = (
                    PcodeCfgAnalysisStep._analyze_pcode_jsonl(
                        pcode_json=pcode_json, header=header, ctx=ctx,
                    )
                )
            else:
                pcode_result, pcode_naming_candidates = (
                    PcodeCfgAnalysisStep._analyze_pcode_legacy(
                        pcode_json=pcode_json, ctx=ctx,
                    )
                )
        except ImportError:
            logger.debug("PcodeAnalyzer bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("P-Code analiz hatasi: %s", exc)

        ctx.stats["timing_pcode"] = round(time.monotonic() - step_start, 1)
        return pcode_result, pcode_naming_candidates

    @staticmethod
    def _analyze_pcode_jsonl(
        *, pcode_json: Path, header: str, ctx: StepContext,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """v1.5: JSONL streaming analiz."""
        from karadul.analyzers.pcode_analyzer import PcodeAnalyzer

        pcode_data = json.loads(header)
        jsonl_path_str = pcode_data.get("jsonl_path", "")

        if jsonl_path_str:
            jsonl_path = Path(jsonl_path_str)
        else:
            jsonl_path = pcode_json.parent / "pcode.jsonl"

        if not jsonl_path.exists():
            logger.warning("JSONL dosyasi bulunamadi: %s", jsonl_path)
            ctx.stats["pcode_functions_analyzed"] = pcode_data.get(
                "total_functions", 0,
            )
            ctx.stats["pcode_total_ops"] = pcode_data.get(
                "total_pcode_ops", 0,
            )
            return None, []

        pcode_analyzer = PcodeAnalyzer()
        pcode_result = pcode_analyzer.analyze_streaming(jsonl_path)
        ctx.stats["pcode_functions_analyzed"] = pcode_result.total_functions
        ctx.stats["pcode_total_ops"] = pcode_result.total_pcode_ops

        naming_candidates: list[dict[str, Any]] = []
        for func_pcode in pcode_result.functions:
            nc_list = pcode_analyzer.generate_naming_candidates(func_pcode)
            naming_candidates.extend(nc_list)

        ctx.stats["pcode_naming_candidates"] = len(naming_candidates)
        logger.info(
            "P-Code JSONL: %d fonksiyon, %d op, %d naming candidate",
            pcode_result.total_functions,
            pcode_result.total_pcode_ops,
            len(naming_candidates),
        )
        return pcode_result, naming_candidates

    @staticmethod
    def _analyze_pcode_legacy(
        *, pcode_json: Path, ctx: StepContext,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Legacy: tam pcode JSON parse."""
        from karadul.analyzers.pcode_analyzer import PcodeAnalyzer

        pcode_analyzer = PcodeAnalyzer()
        pcode_result = pcode_analyzer.analyze(pcode_json)
        ctx.stats["pcode_functions_analyzed"] = pcode_result.total_functions
        ctx.stats["pcode_total_ops"] = pcode_result.total_pcode_ops

        naming_candidates: list[dict[str, Any]] = []
        for func_pcode in pcode_result.functions:
            nc_list = pcode_analyzer.generate_naming_candidates(func_pcode)
            naming_candidates.extend(nc_list)

        logger.info(
            "P-Code legacy: %d fonksiyon, %d op, %d naming candidate",
            pcode_result.total_functions,
            pcode_result.total_pcode_ops,
            len(naming_candidates),
        )
        return pcode_result, naming_candidates

    # --- CFG ----------------------------------------------------------

    @staticmethod
    def _analyze_cfg(*, cfg_json: Path, ctx: StepContext) -> Any:
        """stages.py L1534-1557: CFG analiz + sinif dagilimi."""
        step_start = time.monotonic()
        cfg_result: Any = None

        if not (cfg_json and cfg_json.exists()):
            ctx.stats["timing_cfg"] = round(time.monotonic() - step_start, 1)
            return cfg_result

        try:
            from karadul.analyzers.cfg_analyzer import CFGAnalyzer
            cfg_analyzer = CFGAnalyzer()
            cfg_result = cfg_analyzer.analyze(cfg_json)
            ctx.stats["cfg_functions_analyzed"] = cfg_result.total_functions
            ctx.stats["cfg_total_blocks"] = cfg_result.total_blocks
            ctx.stats["cfg_total_edges"] = cfg_result.total_edges
            cfg_summary = cfg_analyzer.get_summary(cfg_result)
            ctx.stats["cfg_classification"] = cfg_summary.get(
                "classification_distribution", {},
            )
            logger.info(
                "CFG analiz: %d fonksiyon, %d blok, %d edge",
                cfg_result.total_functions,
                cfg_result.total_blocks,
                cfg_result.total_edges,
            )
        except ImportError:
            logger.debug("CFGAnalyzer bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("CFG analiz hatasi: %s", exc)

        ctx.stats["timing_cfg"] = round(time.monotonic() - step_start, 1)
        return cfg_result
