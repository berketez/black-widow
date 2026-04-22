"""Feedback loop — XTRIDE / Dynamic / N-gram naming alt adimlari.

stages.py L3035-3219. Her biri bagimsiz, ayni arayuz: decompiled_dir'deki
.c dosyalarini tarar, re.compile cache ile in-place rename/edit uygular.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run_xtride_typing(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """XTRIDE N-gram tip cikarimi — undefined8 -> gercek tip."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_xtride_typing:
        stats[f"timing_xtride_typing_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.xtride_typer import XTrideTyper
        xtride = XTrideTyper()
        xtride_total = 0
        xtride_improved = 0

        xfiles = _target_files(decompiled_dir, incremental_files, iter_index)
        pat_cache: dict[str, re.Pattern[str]] = {}
        for xf in xfiles:
            try:
                xcode = xf.read_text(encoding="utf-8", errors="replace")
                xresult = xtride.infer_types(xcode, xf.stem)
                xtride_total += xresult.total_inferred
                if not xresult.inferences:
                    continue
                new_code = xcode
                changed = False
                for xvar, xinf in xresult.inferences.items():
                    if xinf.confidence < 0.50:
                        continue
                    if xvar not in pat_cache:
                        pat_cache[xvar] = re.compile(
                            r"^(\s*)(?:undefined[1248]?|long|ulong)\s+"
                            + re.escape(xvar)
                            + r"(\s*[;=])",
                            re.MULTILINE,
                        )
                    decl_pat = pat_cache[xvar]
                    m = decl_pat.search(new_code)
                    if m:
                        old = m.group(0)
                        new = (
                            f"{m.group(1)}{xinf.inferred_type} {xvar}{m.group(2)}"
                        )
                        new_code = new_code.replace(old, new, 1)
                        changed = True
                        xtride_improved += 1
                if changed:
                    xf.write_text(new_code, encoding="utf-8")
            except Exception:
                logger.debug(
                    "Xtride type inference dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        stats["xtride_total_inferences"] = xtride_total
        stats["xtride_type_improvements"] = xtride_improved
        stats["xtride_pattern_count"] = xtride.pattern_count
        logger.info(
            "  XTRIDE typing (iter %d): %d inferences, %d type improvements "
            "(%d files, %d patterns)",
            iter_index + 1, xtride_total, xtride_improved,
            len(xfiles), xtride.pattern_count,
        )
    except Exception as exc:
        logger.warning("XTRIDE typing hatasi (atlaniyor): %s", exc)
        errors.append(f"XTRIDE typing hatasi: {exc}")
    stats[f"timing_xtride_typing_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


def run_dynamic_naming(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """Frida trace tabanli dynamic naming — var_name -> suggested_name."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_dynamic_naming:
        stats[f"timing_dynamic_naming_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.dynamic_namer import DynamicNamer
        trace_path = (
            pc.workspace.get_stage_dir("dynamic") / "trace_report.json"
        )
        if not trace_path.exists():
            stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return

        dyn_namer = DynamicNamer(trace_report_path=trace_path)
        if not dyn_namer.load_trace():
            stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return

        dyn_total = 0
        dyn_applied = 0
        dyn_threshold = (
            pc.config.binary_reconstruction.ngram_confidence_threshold
        )

        dyn_files = _target_files(
            decompiled_dir, incremental_files, iter_index,
        )
        pat_cache: dict[str, re.Pattern[str]] = {}
        for df in dyn_files:
            try:
                dcode = df.read_text(encoding="utf-8", errors="replace")
                dsuggestions = dyn_namer.infer_names(df.stem, dcode)
                dyn_total += len(dsuggestions)
                if not dsuggestions:
                    continue
                changed = False
                for ds in dsuggestions:
                    if ds.confidence < dyn_threshold:
                        continue
                    if ds.var_name not in pat_cache:
                        pat_cache[ds.var_name] = re.compile(
                            r"\b" + re.escape(ds.var_name) + r"\b",
                        )
                    pat = pat_cache[ds.var_name]
                    new_code, cnt = pat.subn(ds.suggested_name, dcode)
                    if cnt > 0:
                        dcode = new_code
                        changed = True
                        dyn_applied += 1
                if changed:
                    df.write_text(dcode, encoding="utf-8")
            except Exception:
                logger.debug(
                    "Dynamic rename dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        stats["dynamic_total_suggestions"] = dyn_total
        stats["dynamic_names_applied"] = dyn_applied
        logger.info(
            "  Dynamic naming (iter %d): %d suggestions, %d applied",
            iter_index + 1, dyn_total, dyn_applied,
        )
    except Exception as exc:
        logger.warning("Dynamic naming hatasi (atlaniyor): %s", exc)
        errors.append(f"Dynamic naming hatasi: {exc}")
    stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


def run_ngram_naming(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """N-gram degisken isim tahmini."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_ngram_naming:
        stats[f"timing_ngram_naming_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.ngram_namer import NgramNamer
        ngram_db_dir = pc.config.project_root / "sigs" / "ngram_name_db"
        if not ngram_db_dir.is_dir():
            stats[f"timing_ngram_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return

        ngram_namer = NgramNamer(db_dir=ngram_db_dir)
        ngram_total = 0
        ngram_applied = 0
        ngram_threshold = (
            pc.config.binary_reconstruction.ngram_confidence_threshold
        )

        ngram_files = _target_files(
            decompiled_dir, incremental_files, iter_index,
        )
        pat_cache: dict[str, re.Pattern[str]] = {}
        for nf in ngram_files:
            try:
                ncode = nf.read_text(encoding="utf-8", errors="replace")
                nresult = ngram_namer.predict(ncode, nf.stem)
                ngram_total += nresult.total_predicted
                if not nresult.predictions:
                    continue
                changed = False
                for nvar, npred in nresult.predictions.items():
                    if npred.confidence < ngram_threshold:
                        continue
                    if nvar not in pat_cache:
                        pat_cache[nvar] = re.compile(
                            r"\b" + re.escape(nvar) + r"\b",
                        )
                    npat = pat_cache[nvar]
                    nnew, nsubs = npat.subn(npred.predicted_name, ncode)
                    if nsubs > 0:
                        ncode = nnew
                        changed = True
                        ngram_applied += 1
                if changed:
                    nf.write_text(ncode, encoding="utf-8")
            except Exception:
                logger.debug(
                    "N-gram prediction dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        stats["ngram_total_predictions"] = ngram_total
        stats["ngram_names_applied"] = ngram_applied
        logger.info(
            "  N-gram naming (iter %d): %d predictions, %d applied (%d files)",
            iter_index + 1, ngram_total, ngram_applied, len(ngram_files),
        )
    except Exception as exc:
        logger.warning("N-gram naming hatasi (atlaniyor): %s", exc)
        errors.append(f"N-gram naming hatasi: {exc}")
    stats[f"timing_ngram_naming_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


def _target_files(
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    iter_index: int,
) -> list[Path]:
    """Iter'e gore islenecek dosyalar (incremental filtresi dahil)."""
    files = (
        sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
    )
    if incremental_files is not None and iter_index > 0:
        incr = {f.name for f in incremental_files}
        files = [f for f in files if f.name in incr]
    return files
