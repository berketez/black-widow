"""Feedback loop — tek iterasyon gövdesi.

FeedbackLoopStep orchestration'unu ince tutmak icin tek iter'in fazlari
(computation -> naming -> typing) bu modulde toplandi.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.pipeline.steps._feedback_computation import run_computation_phase
from karadul.pipeline.steps._feedback_naming import run_naming_phase
from karadul.pipeline.steps._feedback_typing import run_typing_phase

logger = logging.getLogger(__name__)


@dataclass
class LoopState:
    """Loop boyunca tasinan minimal durum."""

    extracted_names: dict[str, str]
    bindiff_confidence_map: dict[str, tuple[str, float, str]]
    loop_decompiled_dir: Path
    last_naming_result: Any = None
    last_computation_result: Any = None


@dataclass
class IterOutcome:
    """Tek iterasyon sonucu."""

    iter_index: int
    iter_duration: float
    current_named_set: set[str]
    newly_named: set[str]
    new_iter_stats: dict[str, Any]
    decompiled_dir: Path


def run_one_iteration(
    *,
    ctx: Any,
    iter_index: int,
    max_iter: int,
    decompiled_dir: Path,
    state: LoopState,
    incremental_files: list[Path] | None,
    reconstructed_dir: Path,
    output_dir: Path,
    prev_named: set[str],
    # injected primitives
    comp_engine: Any,
    c_namer: Any,
    type_recoverer: Any,
    # paths
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    ghidra_types_json: Path,
    xrefs_json: Path,
    cfg_json: Path,
    fid_json: Path,
    decompiled_json: Path,
    # parsed metadata
    func_data: Any,
    string_data: Any,
    sig_matches: Any,
    algo_result: Any,
    eng_result: Any,
    pcode_naming_candidates: list[dict[str, Any]],
    binary_hash_16: str,
    target_type: Any,
    # scalars
    func_count: int,
    # accumulators
    stats: dict[str, Any],
    errors: list[str],
    artifacts_out: dict[str, Any],
) -> IterOutcome:
    """Tek iterasyonu orchestrate et ve outcome dondur."""
    iter_start = time.monotonic()
    pc = ctx.pipeline_context

    processing_count = (
        len(incremental_files)
        if incremental_files is not None else func_count
    )
    logger.info(
        "=== Pipeline iteration %d/%d starting: %d/%d functions%s ===",
        iter_index + 1, max_iter,
        processing_count, func_count,
        " (incremental)" if incremental_files is not None else " (full)",
    )

    # v1.10.0 H6 (perf fix): Ilk iter'de ctx.artifacts["c_files"] zaten
    # mevcut (binary_prep step uretti). Bunu tohum olarak kullan ve rglob
    # atla. Sonraki iter'lerde decompiled_dir degisebilir (naming/typing
    # yeni alt dizinlere yazabilir) -- bu durumda rglob gerek.
    # decompiled_dir'in artifact'in kaynagiyla ayni olup olmadigi state'e
    # bagli; ilk iter disinda defensif rglob koruyoruz.
    if iter_index == 0:
        rglob_c_files = list(
            ctx.artifacts.get("c_files") or []
        )
    else:
        rglob_c_files = (
            sorted(decompiled_dir.rglob("*.c"))
            if decompiled_dir.exists() else []
        )

    # Faz 1: Computation Recovery
    pc.report_progress(
        f"Computation Recovery (iter {iter_index + 1})...", 0.35,
    )
    state.last_computation_result = run_computation_phase(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        reconstructed_dir=reconstructed_dir,
        incremental_files=incremental_files,
        rglob_c_files=rglob_c_files,
        comp_engine=comp_engine,
        functions_json=functions_json,
        call_graph_json=call_graph_json,
        cfg_json=cfg_json,
        ghidra_types_json=ghidra_types_json,
        sig_matches=sig_matches,
        algo_result=algo_result,
        eng_result=eng_result,
        binary_hash_16=binary_hash_16,
        target_type=target_type,
        artifacts=artifacts_out,
        stats=stats,
        func_count=func_count,
    )

    # Faz 2: Naming
    pc.report_progress(
        f"C Variable/Function Naming (iter {iter_index + 1})...", 0.45,
    )
    naming_phase = run_naming_phase(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        reconstructed_dir=reconstructed_dir,
        output_dir=output_dir,
        incremental_files=incremental_files,
        rglob_c_files=rglob_c_files,
        c_namer=c_namer,
        functions_json=functions_json,
        strings_json=strings_json,
        call_graph_json=call_graph_json,
        xrefs_json=xrefs_json,
        fid_json=fid_json,
        cfg_json=cfg_json,
        extracted_names=state.extracted_names,
        func_data=func_data,
        string_data=string_data,
        sig_matches=sig_matches,
        algo_result=algo_result,
        eng_result=eng_result,
        pcode_naming_candidates=pcode_naming_candidates,
        computation_result=state.last_computation_result,
        bindiff_confidence_map=state.bindiff_confidence_map,
        stats=stats, errors=errors, artifacts=artifacts_out,
        func_count=func_count,
    )
    state.last_naming_result = naming_phase.naming_result
    naming_out_dir = naming_phase.decompiled_dir
    state.extracted_names = naming_phase.extracted_names
    current_named_set = naming_phase.current_named_set

    # v1.10.0 H6 (perf fix): Naming dizini degismediyse, Faz 1'de
    # topladigimiz c_files'i yeniden kullan (dosya listesi ayni).
    # Tipik durum: incremental naming, dir ayni kalir -- tek rglob yeter.
    if naming_out_dir == decompiled_dir:
        typing_c_files = rglob_c_files
    else:
        typing_c_files = (
            sorted(naming_out_dir.rglob("*.c"))
            if naming_out_dir.exists() else []
        )
    decompiled_dir = naming_out_dir

    # Faz 3: Typing
    pc.report_progress(
        f"Type Recovery (iter {iter_index + 1})...", 0.60,
    )
    typing_phase = run_typing_phase(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        reconstructed_dir=reconstructed_dir,
        incremental_files=incremental_files,
        rglob_c_files=typing_c_files,
        type_recoverer=type_recoverer,
        functions_json=functions_json,
        strings_json=strings_json,
        ghidra_types_json=ghidra_types_json,
        call_graph_json=call_graph_json,
        decompiled_json=decompiled_json,
        computation_result=state.last_computation_result,
        stats=stats, errors=errors, artifacts=artifacts_out,
        func_count=func_count,
    )
    decompiled_dir = typing_phase.decompiled_dir
    state.loop_decompiled_dir = decompiled_dir

    newly_named = current_named_set - prev_named
    iter_duration = time.monotonic() - iter_start
    iter_stats = {
        "iteration": iter_index + 1,
        "new_names": len(newly_named),
        "total_names": len(current_named_set),
        "duration": round(iter_duration, 2),
    }
    logger.info(
        "Pipeline iteration %d/%d complete: %d new names (total %d), %.1fs",
        iter_index + 1, max_iter,
        len(newly_named), len(current_named_set),
        iter_duration,
    )

    return IterOutcome(
        iter_index=iter_index,
        iter_duration=iter_duration,
        current_named_set=current_named_set,
        newly_named=newly_named,
        new_iter_stats=iter_stats,
        decompiled_dir=decompiled_dir,
    )
