"""Feedback loop Faz 2 — naming orchestration.

stages.py L2312-2932'nin adim-adim cagrim orkestratoru. Alt adimlar:
- _feedback_naming_cnamer: CVariableNamer.analyze_and_rename
- _feedback_naming_bindiff: BinDiff (config + ref_db)
- _feedback_naming_refdiff: ReferenceDiffer (string version + CFG)
- _feedback_naming_merger: NameMerger + Aho-Corasick replacement

Disari sadece `run_naming_phase` ve `NamingPhaseResult` export edilir.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.steps._feedback_naming_bindiff import run_bindiff
from karadul.pipeline.steps._feedback_naming_merger import run_name_merger
from karadul.pipeline.steps._feedback_naming_parallel import (
    _run_with_parallel_runner,
    _should_use_parallel_runner,
)
from karadul.pipeline.steps._feedback_naming_refdiff import run_reference_differ

logger = logging.getLogger(__name__)


class NamingPhaseResult:
    """Naming fazinin iterasyonluk ciktisi."""

    __slots__ = (
        "naming_result",
        "decompiled_dir",
        "bindiff_confidence_map",
        "refdiff_naming",
        "bindiff_names",
        "final_naming_map",
        "current_named_set",
        "extracted_names",
    )

    def __init__(
        self,
        *,
        naming_result: Any,
        decompiled_dir: Path,
        bindiff_confidence_map: dict[str, tuple[str, float, str]],
        refdiff_naming: dict[str, str],
        bindiff_names: dict[str, str],
        final_naming_map: dict[str, str] | None,
        current_named_set: set[str],
        extracted_names: dict[str, str],
    ) -> None:
        self.naming_result = naming_result
        self.decompiled_dir = decompiled_dir
        self.bindiff_confidence_map = bindiff_confidence_map
        self.refdiff_naming = refdiff_naming
        self.bindiff_names = bindiff_names
        self.final_naming_map = final_naming_map
        self.current_named_set = current_named_set
        self.extracted_names = extracted_names


def run_naming_phase(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    output_dir: Path,
    incremental_files: list[Path] | None,
    rglob_c_files: list[Path],
    c_namer: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    xrefs_json: Path,
    fid_json: Path,
    cfg_json: Path,
    extracted_names: dict[str, str],
    func_data: Any,
    string_data: Any,
    sig_matches: Any,
    algo_result: Any,
    eng_result: Any,
    pcode_naming_candidates: list[dict[str, Any]],
    computation_result: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
    func_count: int,
) -> NamingPhaseResult:
    """Iter basina naming fazini uygula."""
    # 1) CVariableNamer
    naming_result = _run_c_namer(
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
        extracted_names=extracted_names,
        stats=stats, errors=errors, artifacts=artifacts,
        func_count=func_count,
    )
    # Full mode basariliysa c_namer output_dir'u kullanilir.
    # v1.10.0 H2: ParallelNamingRunner yolunda output_files bos — disk'e
    # yazilmadigi icin decompiled_dir yonlendirmesi yapilmamali; aksi halde
    # downstream bos bir dizin ile calisir.
    _has_output = bool(getattr(naming_result, "output_files", None))
    if (
        naming_result is not None
        and getattr(naming_result, "success", False)
        and _has_output
        and not (incremental_files is not None and iter_index > 0)
    ):
        decompiled_dir = _compute_namer_output(
            reconstructed_dir, output_dir, iter_index,
        )

    # 2) BinDiff + ReferenceDiffer (yalnizca iter==0)
    bindiff_names: dict[str, str] = {}
    refdiff_naming: dict[str, str] = {}
    if iter_index == 0:
        run_bindiff(
            ctx=ctx, func_data=func_data, string_data=string_data,
            functions_json=functions_json, strings_json=strings_json,
            call_graph_json=call_graph_json,
            bindiff_confidence_map=bindiff_confidence_map,
            bindiff_names=bindiff_names,
            extracted_names=extracted_names,
            stats=stats, errors=errors,
        )
        run_reference_differ(
            ctx=ctx, iter_index=iter_index,
            func_data=func_data, string_data=string_data,
            functions_json=functions_json, strings_json=strings_json,
            call_graph_json=call_graph_json, cfg_json=cfg_json,
            refdiff_naming=refdiff_naming,
            extracted_names=extracted_names,
            stats=stats, errors=errors,
        )

    # 3) NameMerger
    step_start = time.monotonic()
    final_naming_map, current_named_set, decompiled_dir = run_name_merger(
        ctx=ctx, iter_index=iter_index,
        decompiled_dir=decompiled_dir,
        reconstructed_dir=reconstructed_dir,
        incremental_files=incremental_files,
        extracted_names=extracted_names,
        naming_result=naming_result,
        bindiff_confidence_map=bindiff_confidence_map,
        refdiff_naming=refdiff_naming,
        fid_json=fid_json,
        computation_result=computation_result,
        pcode_naming_candidates=pcode_naming_candidates,
        stats=stats, errors=errors, artifacts=artifacts,
    )
    stats[f"timing_name_merger_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )
    logger.info(
        "  Name merger (iter %d) done: %.1fs",
        iter_index + 1,
        stats[f"timing_name_merger_iter{iter_index}"],
    )

    return NamingPhaseResult(
        naming_result=naming_result,
        decompiled_dir=decompiled_dir,
        bindiff_confidence_map=bindiff_confidence_map,
        refdiff_naming=refdiff_naming,
        bindiff_names=bindiff_names,
        final_naming_map=final_naming_map,
        current_named_set=current_named_set,
        extracted_names=extracted_names,
    )


# ---------------------------------------------------------------------------
# CVariableNamer alt adimi (tek kullanimli; kendi modulu gereksiz)
# ---------------------------------------------------------------------------


def _compute_namer_output(
    reconstructed_dir: Path, output_dir: Path, iter_index: int,
) -> Path:
    if iter_index > 0:
        out = reconstructed_dir / f"src_iter{iter_index}"
        # v1.10.0 M15: stale iter ciktisini temizle (onceki kosudan kalan
        # dosyalar yeni isimlendirme ile karismasin).
        if out.exists():
            shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)
        return out
    return output_dir


def _run_c_namer(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    output_dir: Path,
    incremental_files: list[Path] | None,
    rglob_c_files: list[Path],
    c_namer: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    xrefs_json: Path,
    extracted_names: dict[str, str],
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
    func_count: int,
) -> Any | None:
    """CVariableNamer.analyze_and_rename — incremental mode destekli."""
    pc = ctx.pipeline_context
    if not pc.config.binary_reconstruction.enable_c_naming:
        return None

    step_start = time.monotonic()
    naming_result: Any = None
    incr_namer_dir: Path | None = None

    try:
        if c_namer is None:
            raise ImportError("CVariableNamer pre-init basarisiz")

        namer_dir = decompiled_dir
        if incremental_files is not None and iter_index > 0:
            incr_namer_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"incr_naming_iter{iter_index}_",
                    dir=reconstructed_dir,
                ),
            )
            incr_names_set = {f.name for f in incremental_files}
            for cf in rglob_c_files:
                if cf.name in incr_names_set:
                    dst = incr_namer_dir / cf.name
                    try:
                        dst.symlink_to(cf.resolve())
                    except (OSError, NotImplementedError):
                        shutil.copy2(cf, dst)
            namer_dir = incr_namer_dir
            logger.info(
                "Incremental c_namer: %d/%d files",
                len(incr_names_set), func_count,
            )

        namer_output = _compute_namer_output(
            reconstructed_dir, output_dir, iter_index,
        )

        # M2 T2: feature flag aktifse file-level ThreadPool runner,
        # degilse klasik analyze_and_rename (default).
        if _should_use_parallel_runner(pc.config, c_namer):
            naming_result = _run_with_parallel_runner(
                c_namer=c_namer, namer_dir=namer_dir,
                namer_output=namer_output,
                functions_json=functions_json,
                strings_json=strings_json,
                call_graph_json=call_graph_json,
                xrefs_json=xrefs_json,
                extracted_names=extracted_names,
                config=pc.config, stats=stats, errors=errors,
            )
        else:
            naming_result = c_namer.analyze_and_rename(
                namer_dir, functions_json, strings_json,
                call_graph_json, namer_output,
                pre_names=extracted_names or None,
                xrefs_json=xrefs_json if xrefs_json.exists() else None,
            )
        if naming_result.success:
            stats["variables_renamed"] = naming_result.total_renamed
            stats["naming_by_strategy"] = naming_result.by_strategy
            stats["naming_high_confidence"] = naming_result.high_confidence
            artifacts["named_sources"] = namer_output
            logger.info(
                "C Naming: %d isim degistirildi%s",
                naming_result.total_renamed,
                " (incremental)" if (
                    incremental_files is not None and iter_index > 0
                ) else "",
            )
        else:
            errors.extend(naming_result.errors)
    except Exception as exc:
        logger.warning("C naming hatasi: %s", exc)
        errors.append(f"C naming hatasi: {exc}")
    finally:
        if incr_namer_dir and incr_namer_dir.exists():
            shutil.rmtree(incr_namer_dir, ignore_errors=True)

    stats[f"timing_c_naming_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )
    return naming_result
