"""Feedback loop — NameMerger candidate toplayicilari.

stages.py L2663-2846. Her kaynaktan (binary_extractor, c_namer, BinDiff,
ReferenceDiffer, FunctionID, Computation Recovery, P-Code) NamingCandidate
uret, tek bir {sembol: [candidate, ...]} dict'te topla.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

try:
    from karadul.reconstruction.name_merger import NamingCandidate
except ImportError:
    NamingCandidate = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


def collect_candidates(
    *,
    extracted_names: dict[str, str],
    naming_result: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    refdiff_naming: dict[str, str],
    fid_json: Path,
    computation_result: Any,
    pcode_naming_candidates: list[dict],
    iter_index: int,
    stats: dict[str, Any],
) -> dict[str, list]:
    """Tum kaynaklardan candidates_by_symbol sozlugu olustur."""
    candidates_by_symbol: dict[str, list] = {}

    _add_binary_extractor(extracted_names, candidates_by_symbol)
    _add_c_namer(naming_result, candidates_by_symbol)
    _add_bindiff(bindiff_confidence_map, candidates_by_symbol)
    _add_refdiff(refdiff_naming, candidates_by_symbol)
    _add_fid(fid_json, candidates_by_symbol)

    if computation_result and computation_result.success:
        _add_computation(
            computation_result, candidates_by_symbol, iter_index, stats,
        )

    if pcode_naming_candidates:
        _add_pcode(pcode_naming_candidates, candidates_by_symbol)

    return candidates_by_symbol


# ---------------------------------------------------------------------------
# Per-source helper'lari
# ---------------------------------------------------------------------------


def _add_binary_extractor(
    extracted_names: dict[str, str],
    candidates: dict[str, list],
) -> None:
    for old_name, new_name in extracted_names.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.85, "binary_extractor"),
        )


def _add_c_namer(
    naming_result: Any, candidates: dict[str, list],
) -> None:
    if naming_result is None or not hasattr(naming_result, "naming_map"):
        return
    for old_name, new_name in naming_result.naming_map.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.70, "c_namer"),
        )


def _add_bindiff(
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    candidates: dict[str, list],
) -> None:
    if not bindiff_confidence_map:
        return
    for old_name, (new_name, conf, method) in bindiff_confidence_map.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, conf, f"bindiff_{method}"),
        )
    logger.debug(
        "BinDiff: %d candidate (per-match confidence) Name Merger'a eklendi",
        len(bindiff_confidence_map),
    )


def _add_refdiff(
    refdiff_naming: dict[str, str], candidates: dict[str, list],
) -> None:
    if not refdiff_naming:
        return
    for old_name, new_name in refdiff_naming.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.95, "reference_differ"),
        )
    logger.debug(
        "ReferenceDiffer: %d candidate Name Merger'a eklendi",
        len(refdiff_naming),
    )


def _add_fid(fid_json: Path, candidates: dict[str, list]) -> None:
    if not (fid_json and fid_json.exists()):
        return
    try:
        fid_data = json.loads(
            fid_json.read_text(encoding="utf-8", errors="replace"),
        )
        for m in fid_data.get("matches", []):
            fid_name = m.get("name", "")
            fid_addr = m.get("address", "")
            if not fid_name or not fid_addr:
                continue
            fun_key = "FUN_%s" % fid_addr.lstrip("0x").lstrip("0")
            if len(fun_key) >= 2:
                candidates.setdefault(fun_key, []).append(
                    NamingCandidate(fid_name, 0.95, "function_id"),
                )
        logger.debug(
            "FunctionID: %d candidate eklendi",
            fid_data.get("total_matches", 0),
        )
    except Exception as exc:
        logger.debug("FunctionID candidate yuklenemedi: %s", exc)


def _add_computation(
    computation_result: Any,
    candidates: dict[str, list],
    iter_index: int,
    stats: dict[str, Any],
) -> None:
    """Computation Recovery + cross-binary transfer."""
    comp_added = 0
    for nc in computation_result.naming_candidates:
        func_name = nc.get("function_name", "")
        cand_name = nc.get("candidate_name", "")
        cand_conf = nc.get("confidence", 0.0)
        cand_src = nc.get("source", "computation_recovery")
        if not func_name or len(func_name) < 2 or not cand_name:
            continue
        if not _is_unnamed(func_name):
            continue
        if cand_src == "signature_fusion" and cand_conf < 0.40:
            continue
        if cand_src == "callee_profile" and cand_conf < 0.30:
            continue
        candidates.setdefault(func_name, []).append(
            NamingCandidate(cand_name, cand_conf, cand_src),
        )
        comp_added += 1
    if comp_added:
        logger.debug(
            "Computation Recovery: %d naming candidate eklendi", comp_added,
        )

    cross_matches = computation_result.layer_results.get(
        "cross_binary_matches", [],
    )
    if cross_matches and iter_index == 0:
        cross_added = 0
        for cm in cross_matches:
            cm_func = cm.get("func_name", "")
            cm_name = cm.get("matched_name", "")
            cm_conf = cm.get("confidence", 0.0)
            if not cm_func or not cm_name:
                continue
            if not _is_unnamed(cm_func, include_unnamed=False):
                continue
            candidates.setdefault(cm_func, []).append(
                NamingCandidate(
                    cm_name, cm_conf, "cross_binary_transfer",
                    reason="CFG fingerprint match from cached binary %s" % (
                        cm.get("source_binary", "?"),
                    ),
                ),
            )
            cross_added += 1
        if cross_added:
            logger.info(
                "Cross-binary transfer: %d naming candidate eklendi",
                cross_added,
            )
            stats["cross_binary_candidates"] = cross_added


def _add_pcode(
    pcode_naming_candidates: list[dict], candidates: dict[str, list],
) -> None:
    pcode_added = 0
    for nc in pcode_naming_candidates:
        func_name = nc.get("function_name", "")
        cand_name = nc.get("candidate_name", "")
        cand_conf = nc.get("confidence", 0.0)
        cand_src = nc.get("source", "pcode_dataflow")
        if not cand_name or not func_name:
            continue
        if not _is_unnamed(func_name):
            continue
        candidates.setdefault(func_name, []).append(
            NamingCandidate(
                cand_name, cand_conf, cand_src, reason=nc.get("reason", ""),
            ),
        )
        pcode_added += 1
    if pcode_added > 0:
        logger.info("P-Code naming: %d candidate eklendi", pcode_added)


def _is_unnamed(name: str, *, include_unnamed: bool = True) -> bool:
    """FUN_/sub_/thunk_/_unnamed_ prefix kontrolu."""
    if (
        name.startswith("FUN_")
        or name.startswith("sub_")
        or name.startswith("thunk_")
    ):
        return True
    if include_unnamed and name.startswith("_unnamed_"):
        return True
    return False
