"""Feedback loop — NameMerger alt-fazi.

stages.py L2656-2929. Candidate toplama icin
`_feedback_naming_candidates.collect_candidates`'e delege eder; merge +
Aho-Corasick replacement bu dosyada.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES
from karadul.pipeline.steps._feedback_naming_candidates import (
    collect_candidates,
)

try:
    from karadul.reconstruction.name_merger import NameMerger
except ImportError:
    NameMerger = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


def run_name_merger(
    *,
    ctx,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    extracted_names: dict[str, str],
    naming_result: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    refdiff_naming: dict[str, str],
    fid_json: Path,
    computation_result: Any,
    pcode_naming_candidates: list[dict],
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
) -> tuple[dict[str, str] | None, set[str], Path]:
    """NameMerger ve Aho-Corasick replacement.

    Returns:
        (final_naming_map, current_named_set, updated_decompiled_dir)
    """
    pc = ctx.pipeline_context
    final_naming_map: dict[str, str] | None = None
    current_named_set: set[str] = set()
    logger.info("  Naming merge (iter %d)...", iter_index + 1)

    if NameMerger is None:
        return final_naming_map, current_named_set, decompiled_dir

    try:
        merger = NameMerger(
            min_confidence=pc.config.binary_reconstruction.min_naming_confidence,
            merger_config=pc.config.name_merger,
        )
        candidates_by_symbol = collect_candidates(
            extracted_names=extracted_names,
            naming_result=naming_result,
            bindiff_confidence_map=bindiff_confidence_map,
            refdiff_naming=refdiff_naming,
            fid_json=fid_json,
            computation_result=computation_result,
            pcode_naming_candidates=pcode_naming_candidates,
            iter_index=iter_index,
            stats=stats,
        )
        if not candidates_by_symbol:
            return final_naming_map, current_named_set, decompiled_dir

        merge_result = merger.merge(candidates_by_symbol)
        final_naming_map = merger.to_naming_map(merge_result)
        logger.info(
            "Name merger: %d merged (%d exact_multi, %d conflicts)",
            merge_result.total_merged,
            merge_result.exact_multi_matches,
            merge_result.conflicts_resolved,
        )
        stats["name_merger_total"] = merge_result.total_merged
        stats["name_merger_exact_multi"] = merge_result.exact_multi_matches
        stats["name_merger_conflicts"] = merge_result.conflicts_resolved

        # Bos/kisa key'leri cikar (regex \b()\b bos string bozulmasini onle)
        final_naming_map = {
            k: v for k, v in final_naming_map.items()
            if k and len(k) >= 2 and v
        }
        if not final_naming_map:
            return final_naming_map, current_named_set, decompiled_dir

        current_named_set = _apply_aho_replace(
            iter_index=iter_index,
            decompiled_dir=decompiled_dir,
            reconstructed_dir=reconstructed_dir,
            incremental_files=incremental_files,
            final_naming_map=final_naming_map,
            artifacts=artifacts,
        )
        if current_named_set:
            merge_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
            decompiled_dir = reconstructed_dir / f"merged{merge_suffix}"
    except Exception as exc:
        logger.warning("Name merger hatasi (atlaniyor): %s", exc)
        errors.append(f"Name merger hatasi: {exc}")

    return final_naming_map, current_named_set, decompiled_dir


def _apply_aho_replace(
    *,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    final_naming_map: dict[str, str],
    artifacts: dict[str, Any],
) -> set[str]:
    """final_naming_map'i Aho-Corasick ile dosyalara paralel uygula."""
    from karadul.reconstruction.aho_replacer import AhoReplacer

    aho = AhoReplacer(final_naming_map)
    merge_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
    merge_dir = reconstructed_dir / f"merged{merge_suffix}"
    merge_dir.mkdir(parents=True, exist_ok=True)

    def _dest_path(c_file: Path) -> Path:
        """v1.10.0 H10: kaynak subdirectory yapisini koru.

        Onceki kod `merge_dir / c_file.name` kullaniyordu — iki farkli
        alt-klasorde ayni `.c` adina sahip dosyalar birbirini eziyordu
        (ornek: `foo/util.c` ve `bar/util.c`).  Simdi dosyayi kaynakli
        goreli yoluyla koruyoruz; `decompiled_dir` disinda kalan nadir
        durumlarda guvenli fallback: sadece dosya adi.
        """
        try:
            rel = c_file.resolve().relative_to(decompiled_dir.resolve())
        except ValueError:
            return merge_dir / c_file.name
        return merge_dir / rel

    def merge_one(c_file: Path) -> int:
        content = c_file.read_text(encoding="utf-8", errors="replace")
        new_content = aho.replace(content)
        dst = _dest_path(c_file)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(new_content, encoding="utf-8")
        return 1 if new_content != content else 0

    all_merge_files = (
        sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
    )
    merge_process, merge_copy_count = _select_merge_files(
        all_merge_files=all_merge_files,
        incremental_files=incremental_files,
        iter_index=iter_index,
        merge_dir=merge_dir,
        decompiled_dir=decompiled_dir,
    )

    renamed_count = 0
    with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
        for result in pool.map(merge_one, merge_process):
            renamed_count += result

    artifacts["merged_names"] = merge_dir
    current_named_set = set(final_naming_map.keys())
    logger.info(
        "Name merger: %d isim dosyalara uygulandi (%d dosya degisti, "
        "%d processed, %d total, %d worker)",
        len(final_naming_map), renamed_count,
        len(merge_process), len(all_merge_files), CPU_PERF_CORES,
    )
    return current_named_set


def _select_merge_files(
    *,
    all_merge_files: list[Path],
    incremental_files: list[Path] | None,
    iter_index: int,
    merge_dir: Path,
    decompiled_dir: Path,
) -> tuple[list[Path], int]:
    """Incremental modda degismeyenleri hardlink'le, islenecekleri dondur."""
    if incremental_files is None or iter_index == 0:
        return all_merge_files, 0

    incr_names = {f.name for f in incremental_files}
    merge_process = [f for f in all_merge_files if f.name in incr_names]
    merge_copy = [f for f in all_merge_files if f.name not in incr_names]
    for cf in merge_copy:
        # v1.10.0 H10: kaynak subdirectory yapisini koru (hardlink + fallback).
        try:
            rel = cf.resolve().relative_to(decompiled_dir.resolve())
        except ValueError:
            rel = Path(cf.name)
        dst = merge_dir / rel
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(cf, dst)
            except (OSError, NotImplementedError):
                shutil.copy2(cf, dst)
    logger.info(
        "Incremental merge: %d files to process, %d copied unchanged",
        len(merge_process), len(merge_copy),
    )
    return merge_process, len(merge_copy)
