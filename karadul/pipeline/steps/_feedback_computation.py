"""Feedback loop Faz 1 — ComputationRecoveryEngine iter wrapper.

stages.py L2180-2310 davranisinin birebir kopyasi. Pre-instantiated
ComputationRecoveryEngine ile her iterasyonda recovery calistir, incremental
modda sadece degisen dosyalari isle, sonuc dict'ini geri don.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from karadul.core.target import TargetType

logger = logging.getLogger(__name__)


def run_computation_phase(
    *,
    ctx,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    rglob_c_files: list[Path],
    comp_engine: Any,  # pre-instantiated ComputationRecoveryEngine or None
    functions_json: Path,
    call_graph_json: Path,
    cfg_json: Path,
    ghidra_types_json: Path,
    sig_matches: Any,
    algo_result: Any,
    eng_result: Any,
    binary_hash_16: str,
    target_type: TargetType | None,
    artifacts: dict[str, Any],
    stats: dict[str, Any],
    func_count: int,
) -> Any | None:
    """Tek iterasyon ComputationRecoveryEngine fazini calistir.

    Returns:
        ComputationRecoveryResult veya None (disabled/hata durumunda).
    """
    pc = ctx.pipeline_context
    if not pc.config.computation_recovery.enabled:
        return None

    step_start = time.monotonic()
    computation_result: Any = None
    incr_comp_dir: Path | None = None

    try:
        if comp_engine is None:
            raise ImportError("ComputationRecoveryEngine pre-init basarisiz")

        # Mevcut sonuclari engine'e besle
        existing_sig = {
            "matches": [
                {
                    "original": m.original_name,
                    "matched": m.matched_name,
                    "library": m.library,
                    "confidence": m.confidence,
                }
                for m in sig_matches
            ],
        } if sig_matches else None
        existing_algo = algo_result.to_dict() if (
            algo_result
            and hasattr(algo_result, "to_dict")
            and algo_result.success
        ) else None
        existing_eng = eng_result.to_dict() if (
            eng_result
            and hasattr(eng_result, "to_dict")
            and eng_result.success
        ) else None

        is_go = target_type == TargetType.GO_BINARY

        # Incremental computation — iter>0 ve incremental set varsa
        comp_input_dir = decompiled_dir
        if incremental_files is not None and iter_index > 0:
            incr_comp_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"incr_comp_iter{iter_index}_",
                    dir=reconstructed_dir,
                ),
            )
            incr_names = {f.name for f in incremental_files}
            for cf in rglob_c_files:
                if cf.name in incr_names:
                    cdst = incr_comp_dir / cf.name
                    try:
                        cdst.symlink_to(cf.resolve())
                    except (OSError, NotImplementedError):
                        shutil.copy2(cf, cdst)
            comp_input_dir = incr_comp_dir
            logger.info(
                "Incremental computation: %d/%d files",
                len(incr_names), func_count,
            )

        computation_result = comp_engine.recover(
            decompiled_dir=comp_input_dir,
            functions_json=functions_json if functions_json.exists() else None,
            call_graph_json=call_graph_json if call_graph_json.exists() else None,
            cfg_json=cfg_json if cfg_json.exists() else None,
            ghidra_types_json=ghidra_types_json if ghidra_types_json.exists() else None,
            existing_sig_matches=existing_sig,
            existing_algo_matches=existing_algo,
            existing_eng_matches=existing_eng,
            is_go_binary=is_go,
            binary_hash=binary_hash_16,
        )
        if computation_result and computation_result.success:
            stats["computation_structs_refined"] = computation_result.structs_refined
            stats["computation_arrays_detected"] = computation_result.arrays_detected
            stats["computation_types_propagated"] = computation_result.types_propagated
            stats["computation_cfg_matches"] = computation_result.cfg_matches
            stats["computation_fusion_ids"] = computation_result.fusion_identifications
            stats["computation_formulas"] = computation_result.formulas_extracted
            stats["computation_param_types"] = len(
                computation_result.param_type_inferences or {},
            )
            stats["computation_return_types"] = len(
                computation_result.return_type_inferences or {},
            )
            stats["computation_globals"] = len(
                computation_result.global_variables or [],
            )
            stats["computation_naming_candidates"] = len(
                computation_result.naming_candidates or [],
            )

            # Artifact kaydi
            try:
                comp_path = pc.workspace.save_json(
                    "reconstructed", "computation_recovery",
                    computation_result.to_dict(),
                )
                artifacts["computation_recovery"] = comp_path
            except Exception:
                logger.debug(
                    "Computation recovery artifact kaydi basarisiz",
                    exc_info=True,
                )

            logger.info(
                "Computation Recovery: %d struct, %d array, %d cfg match, "
                "%d fusion id, %d formula",
                computation_result.structs_refined,
                computation_result.arrays_detected,
                computation_result.cfg_matches,
                computation_result.fusion_identifications,
                computation_result.formulas_extracted,
            )
    except ImportError:
        logger.debug("ComputationRecoveryEngine bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Computation recovery hatasi (atlaniyor): %s", exc)
    finally:
        if incr_comp_dir and incr_comp_dir.exists():
            shutil.rmtree(incr_comp_dir, ignore_errors=True)

    stats[f"timing_computation_recovery_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )
    logger.info(
        "  Computation recovery (iter %d) done: %.1fs",
        iter_index + 1,
        stats[f"timing_computation_recovery_iter{iter_index}"],
    )
    return computation_result
