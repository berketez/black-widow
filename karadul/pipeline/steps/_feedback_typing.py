"""Feedback loop Faz 3 — CTypeRecoverer + XTRIDE / Dynamic / N-gram naming.

stages.py L2934-3219. Tipik akis:
1. CTypeRecoverer.recover (pre-instantiated)
2. XTRIDE N-gram type inference
3. Dynamic naming (Frida trace tabanli)
4. N-gram name prediction

Alt adimlar bagimsiz:
- _run_type_recovery: bu dosyada (type recovery'nin incremental subset
  mekanigi digerlerinden farkli: sembolik link dizini + kopya fallback).
- XTRIDE/Dynamic/N-gram: _feedback_typing_extras'ta (paralel pattern).
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.steps._feedback_typing_extras import (
    run_dynamic_naming,
    run_ngram_naming,
    run_xtride_typing,
)

logger = logging.getLogger(__name__)


class TypingPhaseResult:
    """Typing fazinin iterasyonluk ciktisi."""

    __slots__ = ("type_result", "decompiled_dir")

    def __init__(self, *, type_result: Any, decompiled_dir: Path) -> None:
        self.type_result = type_result
        self.decompiled_dir = decompiled_dir


def run_typing_phase(
    *,
    ctx,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    rglob_c_files: list[Path],
    type_recoverer: Any,
    functions_json: Path,
    strings_json: Path,
    ghidra_types_json: Path,
    call_graph_json: Path,
    decompiled_json: Path,
    computation_result: Any,
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
    func_count: int,
) -> TypingPhaseResult:
    """Type recovery + XTRIDE/Dynamic/N-gram naming fazlari."""
    type_result = _run_type_recovery(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        reconstructed_dir=reconstructed_dir,
        incremental_files=incremental_files,
        rglob_c_files=rglob_c_files,
        type_recoverer=type_recoverer,
        functions_json=functions_json,
        strings_json=strings_json,
        ghidra_types_json=ghidra_types_json,
        call_graph_json=call_graph_json,
        decompiled_json=decompiled_json,
        computation_result=computation_result,
        stats=stats, errors=errors, artifacts=artifacts,
        func_count=func_count,
    )
    if (
        type_result is not None
        and getattr(type_result, "success", False)
        and getattr(type_result, "output_files", None)
    ):
        type_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
        decompiled_dir = reconstructed_dir / f"typed{type_suffix}"

    run_xtride_typing(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        incremental_files=incremental_files,
        stats=stats, errors=errors,
    )
    run_dynamic_naming(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        incremental_files=incremental_files,
        stats=stats, errors=errors,
    )
    run_ngram_naming(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        incremental_files=incremental_files,
        stats=stats, errors=errors,
    )

    return TypingPhaseResult(
        type_result=type_result, decompiled_dir=decompiled_dir,
    )


# ---------------------------------------------------------------------------
# Type Recovery
# ---------------------------------------------------------------------------


def _run_type_recovery(
    *,
    ctx,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    rglob_c_files: list[Path],
    type_recoverer: Any,
    functions_json: Path,
    strings_json: Path,
    ghidra_types_json: Path,
    call_graph_json: Path,
    decompiled_json: Path,
    computation_result: Any,
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
    func_count: int,
) -> Any | None:
    """CTypeRecoverer.recover — incremental subset destekli."""
    pc = ctx.pipeline_context
    if not pc.config.binary_reconstruction.enable_type_recovery:
        stats[f"timing_type_recovery_iter{iter_index}"] = 0.0
        return None

    step_start = time.monotonic()
    type_result: Any = None
    incr_type_dir: Path | None = None

    try:
        if type_recoverer is None:
            raise ImportError("CTypeRecoverer pre-init basarisiz")

        type_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
        type_dir = reconstructed_dir / f"typed{type_suffix}"
        type_dir.mkdir(parents=True, exist_ok=True)

        comp_structs = _compute_comp_structs(computation_result)

        type_input_dir = decompiled_dir
        if incremental_files is not None and iter_index > 0:
            incr_type_dir = _prepare_incr_subset(
                iter_index=iter_index,
                reconstructed_dir=reconstructed_dir,
                incremental_files=incremental_files,
                rglob_c_files=rglob_c_files,
                func_count=func_count,
            )
            type_input_dir = incr_type_dir

        type_result = type_recoverer.recover(
            type_input_dir, functions_json, type_dir,
            strings_json=strings_json,
            ghidra_types_json=ghidra_types_json,
            computation_structs=comp_structs,
            call_graph_json=call_graph_json,
            decompiled_json=decompiled_json if decompiled_json.exists() else None,
        )
        if type_result.success:
            stats["structs_recovered"] = len(type_result.structs)
            stats["enums_recovered"] = len(type_result.enums)
            stats["total_types_recovered"] = type_result.total_types_recovered
            if type_result.types_header:
                artifacts["types_header"] = type_result.types_header
            logger.info(
                "Type Recovery: %d struct, %d enum",
                len(type_result.structs), len(type_result.enums),
            )
        else:
            errors.extend(type_result.errors)

        # Incremental modda type_dir'e islenmemis dosyalari kopyala
        if incr_type_dir and type_result.success and type_result.output_files:
            for cf in rglob_c_files:
                tdst = type_dir / cf.name
                if not tdst.exists():
                    try:
                        os.link(cf, tdst)
                    except (OSError, NotImplementedError):
                        shutil.copy2(cf, tdst)
    except Exception as exc:
        logger.warning("Type recovery hatasi: %s", exc)
        errors.append(f"Type recovery hatasi: {exc}")
    finally:
        if incr_type_dir and incr_type_dir.exists():
            shutil.rmtree(incr_type_dir, ignore_errors=True)

    stats[f"timing_type_recovery_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )
    logger.info(
        "  Type recovery (iter %d) done: %.1fs",
        iter_index + 1,
        stats[f"timing_type_recovery_iter{iter_index}"],
    )
    return type_result


def _compute_comp_structs(computation_result: Any) -> list | None:
    """Computation Recovery struct'larini TypeRecoverer formatina cevir."""
    if not (computation_result and computation_result.success):
        return None
    cs_layer = computation_result.layer_results.get("constraint_solver")
    if not (cs_layer and hasattr(cs_layer, "structs") and cs_layer.structs):
        return None
    structs = [
        s.to_dict() if hasattr(s, "to_dict") else s
        for s in cs_layer.structs
    ]
    logger.debug(
        "Computation -> TypeRecovery: %d struct aktarilacak", len(structs),
    )
    return structs


def _prepare_incr_subset(
    *,
    iter_index: int,
    reconstructed_dir: Path,
    incremental_files: list[Path],
    rglob_c_files: list[Path],
    func_count: int,
) -> Path:
    """Gecici dizin olustur, incremental dosyalara symlink koy (fallback copy)."""
    incr_dir = Path(
        tempfile.mkdtemp(
            prefix=f"incr_type_iter{iter_index}_",
            dir=reconstructed_dir,
        ),
    )
    incr_names = {f.name for f in incremental_files}
    for cf in rglob_c_files:
        if cf.name in incr_names:
            dst = incr_dir / cf.name
            try:
                dst.symlink_to(cf.resolve())
            except (OSError, NotImplementedError):
                shutil.copy2(cf, dst)
    logger.info(
        "Incremental type recovery: %d/%d files",
        len(incr_names), func_count,
    )
    return incr_dir
