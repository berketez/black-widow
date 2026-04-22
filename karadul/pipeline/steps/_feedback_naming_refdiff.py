"""Feedback loop — ReferenceDiffer alt-fazi.

stages.py L2566-2650. String'lerden versiyon tespiti + CFG matching.
Yalnizca iter==0 cagrilir.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run_reference_differ(
    *,
    ctx,
    iter_index: int,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    cfg_json: Path,
    refdiff_naming: dict[str, str],
    extracted_names: dict[str, str],
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """ReferenceDiffer: versiyon tespit + naming_map."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not (
        getattr(pc.config.binary_reconstruction, "enable_reference_differ", True)
        and iter_index == 0
    ):
        stats[f"timing_reference_differ_iter{iter_index}"] = round(
            time.monotonic() - step_start, 1,
        )
        return

    try:
        from karadul.reconstruction.reference_differ import (
            ReferenceDiffer, VersionDetector,
        )
        string_data_for_refdiff = string_data if string_data is not None else (
            json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
            if strings_json.exists() else None
        )
        if not string_data_for_refdiff:
            return

        vdetector = VersionDetector()
        detections = vdetector.detect_from_strings(string_data_for_refdiff)
        if not detections:
            return

        stats["refdiff_detections"] = [
            {"lib": d.library, "ver": d.version, "conf": d.confidence}
            for d in detections
        ]

        _match_against_db(
            pc=pc, detections=detections,
            func_data=func_data, string_data=string_data_for_refdiff,
            functions_json=functions_json,
            call_graph_json=call_graph_json, cfg_json=cfg_json,
            refdiff_naming=refdiff_naming, stats=stats,
        )

        if refdiff_naming:
            extracted_names.update(refdiff_naming)
            logger.info(
                "ReferenceDiffer: %d fonksiyon eslesti", len(refdiff_naming),
            )
    except ImportError:
        logger.debug("ReferenceDiffer modulu bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("ReferenceDiffer hatasi (atlaniyor): %s", exc)
        errors.append(f"ReferenceDiffer hatasi: {exc}")
    finally:
        stats[f"timing_reference_differ_iter{iter_index}"] = round(
            time.monotonic() - step_start, 1,
        )


def _match_against_db(
    *,
    pc, detections,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    call_graph_json: Path,
    cfg_json: Path,
    refdiff_naming: dict[str, str],
    stats: dict[str, Any],
) -> None:
    from karadul.reconstruction.reference_differ import ReferenceDiffer

    ref_db_path = getattr(
        pc.config.binary_reconstruction, "reference_db_path", "",
    )
    ref_path = Path(ref_db_path) if ref_db_path else (
        Path.home() / ".cache" / "karadul" / "ref_db"
    )
    ref_path.mkdir(parents=True, exist_ok=True)
    differ = ReferenceDiffer(
        reference_db_path=ref_path, auto_populate=True,
    )
    func_data_for_refdiff = func_data if func_data is not None else (
        json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
        if functions_json.exists() else None
    )
    cfg_data = None
    if cfg_json.exists():
        try:
            cfg_data = json.loads(
                cfg_json.read_text(encoding="utf-8", errors="replace"),
            )
        except Exception:
            logger.debug("CFG JSON parse basarisiz (refdiff)", exc_info=True)
    cg_data = None
    if call_graph_json.exists():
        try:
            cg_data = json.loads(
                call_graph_json.read_text(encoding="utf-8", errors="replace"),
            )
        except Exception:
            logger.debug(
                "Call graph JSON parse basarisiz (refdiff)", exc_info=True,
            )

    for det in detections:
        rd_result = differ.match(
            target_functions=func_data_for_refdiff or {},
            target_strings=string_data,
            target_cfg=cfg_data,
            target_call_graph=cg_data,
            detection=det,
        )
        if rd_result and rd_result.naming_map:
            refdiff_naming.update(rd_result.naming_map)
            stats[f"refdiff_{det.library}_matches"] = rd_result.matched
            stats[f"refdiff_{det.library}_rate"] = rd_result.match_rate
