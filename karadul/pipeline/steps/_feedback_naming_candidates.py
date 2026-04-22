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
    pcode_naming_candidates: list[dict[str, Any]],
    iter_index: int,
    stats: dict[str, Any],
    bsim_shadow: dict[str, Any] | None = None,
    bsim_fusion_min_similarity: float = 0.7,
    bsim_fusion_max_candidates: int = 3,
) -> dict[str, list[Any]]:
    """Tum kaynaklardan candidates_by_symbol sozlugu olustur.

    bsim_shadow: v1.11.0 BSim kopru. None ise BSim evidence eklenmez
    (shadow mode davranisi). Dict verildiginde ``matches`` alanindaki
    BSim eslemeleri source="bsim" ile eklenir. Caller (run_name_merger),
    shadow_mode=False AND use_bsim_fusion=True oldugunda dict gonderir.
    """
    candidates_by_symbol: dict[str, list[Any]] = {}

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

    if bsim_shadow:
        _add_bsim(
            bsim_shadow=bsim_shadow,
            candidates=candidates_by_symbol,
            min_similarity=bsim_fusion_min_similarity,
            max_per_function=bsim_fusion_max_candidates,
            stats=stats,
        )

    return candidates_by_symbol


# ---------------------------------------------------------------------------
# Per-source helper'lari
# ---------------------------------------------------------------------------


def _add_binary_extractor(
    extracted_names: dict[str, str],
    candidates: dict[str, list[Any]],
) -> None:
    for old_name, new_name in extracted_names.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.85, "binary_extractor"),
        )


def _add_c_namer(
    naming_result: Any, candidates: dict[str, list[Any]],
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
    candidates: dict[str, list[Any]],
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
    refdiff_naming: dict[str, str], candidates: dict[str, list[Any]],
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


def _add_fid(fid_json: Path, candidates: dict[str, list[Any]]) -> None:
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
    candidates: dict[str, list[Any]],
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
    pcode_naming_candidates: list[dict[str, Any]], candidates: dict[str, list[Any]],
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


def _add_bsim(
    *,
    bsim_shadow: dict[str, Any],
    candidates: dict[str, list[Any]],
    min_similarity: float,
    max_per_function: int,
    stats: dict[str, Any],
) -> None:
    """BSim kopru (v1.11.0 Hafta 2): shadow payload -> NamingCandidate.

    Shadow payload formati ``bsim_match.BSimMatchStep._build_shadow_payload``
    tarafindan uretilir:

        {
          "version": "1",
          "mode": "shadow" | "live-dump-only",
          "matches": [
            {"function_addr": "0x...", "function_name": "FUN_xxx",
             "bsim_candidates": [
                {"name": str, "similarity": float, "binary": str}, ...
             ]}
          ]
        }

    Confidence olarak BSim similarity skorunu dogrudan kullaniyoruz.
    Source-bazli weight (``NameMergerConfig.source_weights["bsim"] = 0.85``)
    NameMerger'in kendi Bayesian log-odds fusion'inda uygulanir;
    burada ayrica kesrin carpilmasi double-damping olur.
    """
    matches = bsim_shadow.get("matches") or []
    if not isinstance(matches, list) or not matches:
        return

    added = 0
    skipped_unnamed = 0
    skipped_low_sim = 0
    skipped_no_key = 0
    for entry in matches:
        if not isinstance(entry, dict):
            continue
        func_name = str(entry.get("function_name", "") or "")
        func_addr = str(entry.get("function_addr", "") or "")

        # Hedef sembol anahtari: once function_name (Ghidra FUN_xxx),
        # yoksa function_addr'den FUN_XXX uret.
        old_key = func_name.strip()
        if not old_key and func_addr:
            # "0x004012a0" -> "FUN_004012a0"
            addr_clean = func_addr.lower().lstrip("0x").lstrip("0")
            if addr_clean:
                old_key = f"FUN_{addr_clean}"
        if not old_key or len(old_key) < 2:
            skipped_no_key += 1
            continue

        # Sadece adlandirilmamis fonksiyonlar icin oneri uret
        if not _is_unnamed(old_key):
            skipped_unnamed += 1
            continue

        bsim_cands = entry.get("bsim_candidates") or []
        if not isinstance(bsim_cands, list):
            continue

        # top-N similarity desc (shadow payload zaten sortli ama
        # defansif olarak yeniden sortla)
        ranked = sorted(
            (c for c in bsim_cands if isinstance(c, dict)),
            key=lambda c: float(c.get("similarity", 0.0) or 0.0),
            reverse=True,
        )[:max_per_function]

        for cand in ranked:
            cand_name = str(cand.get("name", "") or "").strip()
            if not cand_name:
                continue
            try:
                sim = float(cand.get("similarity", 0.0) or 0.0)
            except (TypeError, ValueError):
                sim = 0.0
            if sim < min_similarity:
                skipped_low_sim += 1
                continue
            binary = str(cand.get("binary", "") or "")
            candidates.setdefault(old_key, []).append(
                NamingCandidate(
                    cand_name,
                    sim,
                    "bsim",
                    reason=f"BSim match (sim={sim:.3f}, binary={binary})",
                ),
            )
            added += 1

    if added:
        logger.info(
            "BSim fusion: %d naming candidate eklendi (skip: %d unnamed, "
            "%d low-sim, %d no-key)",
            added, skipped_unnamed, skipped_low_sim, skipped_no_key,
        )
        stats["bsim_fusion_candidates"] = added
    else:
        logger.debug(
            "BSim fusion: 0 candidate (skip: %d unnamed, %d low-sim, "
            "%d no-key)",
            skipped_unnamed, skipped_low_sim, skipped_no_key,
        )


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
