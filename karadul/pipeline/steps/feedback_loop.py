"""FeedbackLoopStep — computation / naming / typing iterasyon orchestrator'i.

stages.py L2059-3354'un step'e sarilmis hali. Inince tutulmustur:
- Tek iter gövdesi `_feedback_loop_iter.run_one_iteration` icinde.
- Pure helper'lar `_feedback_helpers` icinde.
- Faz adimlari `_feedback_computation/_naming/_typing` modullerinde.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step
from karadul.pipeline.steps import _feedback_helpers as _fh
from karadul.pipeline.steps._feedback_loop_iter import (
    LoopState,
    run_one_iteration,
)

logger = logging.getLogger(__name__)


@register_step(
    name="feedback_loop",
    requires=[
        "c_files", "file_cache", "decompiled_dir", "output_dir",
        "functions_json_path", "strings_json_path", "call_graph_json_path",
        "ghidra_types_json_path", "xrefs_json_path", "cfg_json_path",
        "fid_json_path", "decompiled_json_path",
        "functions_data", "strings_data", "call_graph_data",
        "sig_matches", "algo_result_filtered", "eng_result_filtered",
        "extracted_names", "pcode_naming_candidates",
    ],
    produces=[
        "naming_result", "computation_result",
        "updated_algo_result", "updated_eng_result",
        "final_decompiled_dir",
        "iteration_stats", "convergence_reason",
    ],
)
class FeedbackLoopStep(Step):
    """computation -> naming -> typing iterasyonu, convergence'ta duran loop."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        a = ctx.artifacts
        cfg = pc.config.binary_reconstruction

        # v1.10.0 C1: defansif — downstream file_cache / artifacts_pending
        # yazimlari pc.metadata None ise AttributeError atar. Test mock'larinda
        # bu alan bos olabiliyor; baslamadan garantiye al.
        if getattr(pc, "metadata", None) is None:
            pc.metadata = {}

        # --- Config (M19: max_iter validation) ---
        if cfg.pipeline_iterations < 1:
            raise ValueError(
                f"pipeline_iterations >= 1 olmali, alindi: "
                f"{cfg.pipeline_iterations}",
            )
        max_iter = cfg.pipeline_iterations  # v1.10.0 M19: silent max(1, ...) kaldirildi
        conv_threshold = cfg.pipeline_convergence_threshold
        iter_timeout = cfg.pipeline_iteration_timeout
        min_abs_new = cfg.pipeline_min_new_names_per_iter  # v1.10.0 M2 T6

        # --- State ---
        comp_engine, c_namer, type_recoverer = self._pre_instantiate(pc)
        reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
        c_files: list[Path] = a["c_files"]
        func_count = len(c_files)
        cg_neighbors = _fh.build_cg_neighbors(a["call_graph_data"])
        logger.info(
            "Call graph adjacency index: %d nodes", len(cg_neighbors),
        )

        state = LoopState(
            extracted_names=dict(a["extracted_names"]),
            bindiff_confidence_map={},
            loop_decompiled_dir=a["decompiled_dir"],
        )
        prev_named: set[str] = set()
        iteration_stats: list[dict[str, Any]] = []
        convergence_reason = "max_iter"
        incremental_files: list[Path] | None = None
        decompiled_dir: Path = a["decompiled_dir"]
        file_cache: dict[str, str] = a["file_cache"]

        loop_start = time.monotonic()
        if max_iter > 1:
            logger.info(
                "Pipeline feedback loop: max %d iter, threshold %.2f%%, "
                "timeout %.0fs, %d functions",
                max_iter, conv_threshold * 100, iter_timeout, func_count,
            )

        binary_hash_16 = getattr(pc.target, "file_hash", "")[:16]
        target_type = getattr(pc.target, "target_type", None)
        artifacts_out: dict[str, Any] = {}

        # --- Loop ---
        for iter_index in range(max_iter):
            if iter_index > 0:
                decompiled_dir = state.loop_decompiled_dir

            outcome = run_one_iteration(
                ctx=ctx, iter_index=iter_index, max_iter=max_iter,
                decompiled_dir=decompiled_dir,
                state=state, incremental_files=incremental_files,
                reconstructed_dir=reconstructed_dir,
                output_dir=a["output_dir"],
                prev_named=prev_named,
                comp_engine=comp_engine, c_namer=c_namer,
                type_recoverer=type_recoverer,
                functions_json=a["functions_json_path"],
                strings_json=a["strings_json_path"],
                call_graph_json=a["call_graph_json_path"],
                ghidra_types_json=a["ghidra_types_json_path"],
                xrefs_json=a["xrefs_json_path"],
                cfg_json=a["cfg_json_path"],
                fid_json=a["fid_json_path"],
                decompiled_json=a["decompiled_json_path"],
                func_data=a["functions_data"],
                string_data=a["strings_data"],
                sig_matches=a["sig_matches"],
                algo_result=a["algo_result_filtered"],
                eng_result=a["eng_result_filtered"],
                pcode_naming_candidates=a["pcode_naming_candidates"] or [],
                binary_hash_16=binary_hash_16,
                target_type=target_type,
                func_count=func_count,
                stats=ctx.stats, errors=ctx.errors,
                artifacts_out=artifacts_out,
            )
            iteration_stats.append(outcome.new_iter_stats)
            decompiled_dir = outcome.decompiled_dir

            # Per-iter timeout
            if (
                outcome.iter_duration > iter_timeout
                and iter_index < max_iter - 1
            ):
                logger.warning(
                    "Pipeline iteration %d took %.0fs (> %.0fs timeout), "
                    "skipping remaining %d iteration(s)",
                    iter_index + 1, outcome.iter_duration, iter_timeout,
                    max_iter - iter_index - 1,
                )
                convergence_reason = "iteration_timeout"
                break

            # Convergence (v1.10.0 M2 T6: empty-merger bug fix)
            converged, reason = _fh.check_convergence(
                iter_index=iter_index,
                prev_named=prev_named,
                current_named=outcome.current_named_set,
                threshold=conv_threshold,
                min_absolute_new=min_abs_new,
            )
            if converged:
                logger.info(
                    "Pipeline converged (reason=%s) at iter %d",
                    reason, iter_index + 1,
                )
                convergence_reason = reason
                break

            prev_named = outcome.current_named_set.copy()

            # Incremental set for next iter
            if iter_index < max_iter - 1:
                current_cfiles = {
                    cf.name: cf for cf in (
                        sorted(decompiled_dir.rglob("*.c"))
                        if decompiled_dir.exists() else []
                    )
                }
                incremental_files = _fh.compute_incremental_files(
                    iter_index=iter_index,
                    newly_named=outcome.newly_named,
                    cg_neighbors=cg_neighbors,
                    current_cfiles=current_cfiles,
                    func_count=func_count,
                )
                if incremental_files is not None:
                    logger.info(
                        "Incremental set for iter %d: %d files "
                        "(%d newly named + 1-hop neighbors, %.1f%% of total)",
                        iter_index + 2, len(incremental_files),
                        len(outcome.newly_named),
                        100.0 * len(incremental_files) / max(func_count, 1),
                    )
                self._refresh_file_cache(
                    decompiled_dir=decompiled_dir,
                    file_cache=file_cache,
                    incremental_files=incremental_files,
                )
                pc.metadata["file_cache"] = file_cache

        # --- Post-loop ---
        # v1.10.0 H6: son iterasyonun ciktisini da file_cache'e yansit.
        # Aksi halde inline_detection + downstream step'ler feedback_loop
        # oncesi stale icerikle calisirdi. Incremental_files=None => full refresh.
        final_decompiled_dir = state.loop_decompiled_dir
        if final_decompiled_dir and final_decompiled_dir.exists():
            self._refresh_file_cache(
                decompiled_dir=final_decompiled_dir,
                file_cache=file_cache,
                incremental_files=None,
            )
            pc.metadata["file_cache"] = file_cache

        ctx.stats["pipeline_iterations_run"] = len(iteration_stats)
        ctx.stats["pipeline_iteration_details"] = iteration_stats
        ctx.stats["timing_pipeline_loop"] = round(
            time.monotonic() - loop_start, 1,
        )
        logger.info(
            "Pipeline feedback loop: %d iterasyon, toplam %.1fs",
            len(iteration_stats), time.monotonic() - loop_start,
        )

        # v1.11.0 Phase 1C: artifacts_out'u produce_artifact uzerinden yay.
        # artifacts_out loop icinde _feedback_loop_iter.run_one_iteration
        # tarafindan dolduruluyor (computation/naming/typing faz ciktilari).
        if artifacts_out:
            for key, value in artifacts_out.items():
                ctx.produce_artifact(key, value)

        return {
            "naming_result": state.last_naming_result,
            "computation_result": state.last_computation_result,
            "updated_algo_result": a["algo_result_filtered"],
            "updated_eng_result": a["eng_result_filtered"],
            "final_decompiled_dir": state.loop_decompiled_dir,
            "iteration_stats": iteration_stats,
            "convergence_reason": convergence_reason,
        }

    # ----- helpers ---------------------------------------------------

    @staticmethod
    def _pre_instantiate(pc: Any) -> tuple[Any, Any, Any]:
        """v1.9.2 QW4: Engine/Namer/Recoverer instance'larini bir kez olustur."""
        comp_engine = None
        c_namer = None
        type_rec = None
        if pc.config.computation_recovery.enabled:
            try:
                from karadul.reconstruction.recovery_layers import ComputationRecoveryEngine
                comp_engine = ComputationRecoveryEngine(pc.config)
            except ImportError as e:
                # Graceful degradation: recovery_layers opsiyonel, yoksa None kalir.
                logger.debug(
                    "ComputationRecoveryEngine import basarisiz: %s", e, exc_info=True,
                )
        if pc.config.binary_reconstruction.enable_c_naming:
            try:
                from karadul.reconstruction.c_namer import CVariableNamer
                c_namer = CVariableNamer(pc.config)
            except ImportError as e:
                # Graceful degradation: c_namer opsiyonel, yoksa None kalir.
                logger.debug(
                    "CVariableNamer import basarisiz: %s", e, exc_info=True,
                )
        if pc.config.binary_reconstruction.enable_type_recovery:
            try:
                from karadul.reconstruction.c_type_recoverer import CTypeRecoverer
                type_rec = CTypeRecoverer(pc.config)
            except ImportError as e:
                # Graceful degradation: type_recoverer opsiyonel, yoksa None kalir.
                logger.debug(
                    "CTypeRecoverer import basarisiz: %s", e, exc_info=True,
                )
        return comp_engine, c_namer, type_rec

    @staticmethod
    def _refresh_file_cache(
        *,
        decompiled_dir: Path,
        file_cache: dict[str, str],
        incremental_files: list[Path] | None,
    ) -> None:
        """Bir sonraki iterasyon icin file_cache'i guncelle."""
        if incremental_files is not None:
            for cf in incremental_files:
                try:
                    file_cache[cf.name] = cf.read_text(
                        encoding="utf-8", errors="replace",
                    )
                except Exception:
                    logger.debug(
                        "Dosya cache'e okunamadi, atlaniyor", exc_info=True,
                    )
            return

        file_cache.clear()
        if decompiled_dir.exists():
            for cf in sorted(decompiled_dir.rglob("*.c")):
                try:
                    file_cache[cf.name] = cf.read_text(
                        encoding="utf-8", errors="replace",
                    )
                except Exception:
                    logger.debug(
                        "Dosya cache'e okunamadi, atlaniyor",
                        exc_info=True,
                    )
