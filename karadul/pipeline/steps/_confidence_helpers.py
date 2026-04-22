"""ConfidenceFilterStep icin alt adim helper'lari.

Dosya ayrimi <300 satir kuralina uyum icin yapildi. Step'in ana davranisi
confidence_filter.py'da, adim-adim mantik burada.

Adimlar (stages.py L1723-1908 referanslari):
- _run_calibration       : L1723-1786
- _run_merge             : L1789-1802
- _run_match_budget      : L1804-1845
- _run_byte_pattern_merge: L1846-1858
- _run_capa_merge        : L1860-1908
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Confidence Calibration (stages.py L1723-1786)
# ---------------------------------------------------------------------------


def run_calibration(
    *, pc, eng_result, c_files: list[Path], file_cache: dict[str, str],
    ctx: StepContext,
) -> list | None:
    """ConfidenceCalibrator ile match'leri kalibre et."""
    step_start = time.monotonic()
    calibrated_matches = None

    if not (eng_result and eng_result.success and eng_result.algorithms):
        ctx.stats["timing_confidence_calibration"] = round(
            time.monotonic() - step_start, 1,
        )
        return calibrated_matches

    try:
        from karadul.reconstruction.engineering import ConfidenceCalibrator

        calibrator = ConfidenceCalibrator()

        func_bodies, all_func_names = _extract_func_bodies(c_files, file_cache)
        call_graph = calibrator.build_call_graph_from_bodies(
            func_bodies, all_func_names,
        )
        calibrated_matches = calibrator.calibrate(
            eng_result.algorithms,
            call_graph,
            all_func_names,
            function_bodies=func_bodies or None,
        )

        if calibrated_matches:
            cal_path = pc.workspace.save_json(
                "reconstructed", "engineering_calibrated",
                {
                    "total": len(calibrated_matches),
                    "summary": calibrator.summarize(calibrated_matches),
                    "matches": [cm.to_dict() for cm in calibrated_matches],
                },
            )
            _pin_artifact(pc, "engineering_calibrated", cal_path)
            ctx.stats["engineering_calibrated_count"] = len(calibrated_matches)
            logger.info(
                "Confidence calibration: %d matches calibrated",
                len(calibrated_matches),
            )
    except ImportError:
        logger.debug("ConfidenceCalibrator bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Confidence calibration hatasi: %s", exc)
        ctx.errors.append(f"Confidence calibration hatasi: {exc}")

    ctx.stats["timing_confidence_calibration"] = round(
        time.monotonic() - step_start, 1,
    )
    return calibrated_matches


def _extract_func_bodies(
    c_files: list[Path], file_cache: dict[str, str],
) -> tuple[dict[str, str], list[str]]:
    """C dosyalarindan fonksiyon govdelerini regex ile cikar."""
    func_bodies: dict[str, str] = {}
    all_func_names: list[str] = []
    try:
        for cf in c_files:
            content = file_cache.get(cf.name)
            if content is None:
                try:
                    content = cf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
            for fm in re.finditer(r"\b(\w+)\s*\([^)]*\)\s*\{", content):
                fn = fm.group(1)
                if fn not in func_bodies:
                    func_bodies[fn] = content[fm.start():fm.start() + 3000]
                    all_func_names.append(fn)
    except Exception:
        logger.debug("Fonksiyon body parse basarisiz, atlaniyor", exc_info=True)
    return func_bodies, all_func_names


# ---------------------------------------------------------------------------
# 2. Merge (stages.py L1789-1802)
# ---------------------------------------------------------------------------


def run_merge(*, pc, algo_result, eng_result, calibrated_matches) -> None:
    """algorithms_merged.json artifact uret."""
    if not (eng_result and eng_result.success and eng_result.algorithms):
        return

    merged_algos = {
        "total": (
            (algo_result.total_detected if algo_result and algo_result.success else 0)
            + eng_result.total_detected
        ),
        "crypto_algorithms": [
            a.to_dict() for a in (
                algo_result.algorithms
                if algo_result and algo_result.success else []
            )
        ],
        "engineering_algorithms": [a.to_dict() for a in eng_result.algorithms],
    }
    if calibrated_matches:
        merged_algos["calibrated"] = [cm.to_dict() for cm in calibrated_matches]

    merged_path = pc.workspace.save_json(
        "reconstructed", "algorithms_merged", merged_algos,
    )
    _pin_artifact(pc, "algorithms_merged", merged_path)


# ---------------------------------------------------------------------------
# 3. Match Budget (stages.py L1804-1845)
# ---------------------------------------------------------------------------


def run_match_budget(*, pc, algo_result, eng_result, ctx: StepContext) -> None:
    """En dusuk confidence match'leri kes (MAX_ALGO_MATCHES)."""
    max_algo = pc.config.binary_reconstruction.max_algo_matches
    total = (
        (len(algo_result.algorithms) if algo_result and algo_result.success else 0)
        + (len(eng_result.algorithms) if eng_result and eng_result.success else 0)
    )
    if not (max_algo > 0 and total > max_algo):
        return

    logger.warning(
        "Algorithm match budget: %d > %d, truncating by confidence",
        total, max_algo,
    )
    all_merged: list[tuple[str, Any]] = []
    if algo_result and algo_result.success:
        for a in algo_result.algorithms:
            all_merged.append(("crypto", a))
    if eng_result and eng_result.success:
        for a in eng_result.algorithms:
            all_merged.append(("eng", a))

    def conf_key(item):
        _, a = item
        if hasattr(a, "confidence"):
            return a.confidence
        if isinstance(a, dict):
            return a.get("confidence", 0)
        return 0

    all_merged.sort(key=conf_key, reverse=True)
    all_merged = all_merged[:max_algo]

    kept_crypto = [a for tag, a in all_merged if tag == "crypto"]
    kept_eng = [a for tag, a in all_merged if tag == "eng"]
    if algo_result and algo_result.success:
        algo_result.algorithms = kept_crypto
    if eng_result and eng_result.success:
        eng_result.algorithms = kept_eng
    logger.info(
        "Match budget applied: crypto=%d, eng=%d (total=%d)",
        len(kept_crypto), len(kept_eng), len(kept_crypto) + len(kept_eng),
    )
    ctx.stats["match_budget_original"] = total
    ctx.stats["match_budget_kept"] = len(kept_crypto) + len(kept_eng)


# ---------------------------------------------------------------------------
# 4. Byte pattern merge (stages.py L1846-1858)
# ---------------------------------------------------------------------------


def run_byte_pattern_merge(
    *, byte_pattern_names: dict[str, str], extracted_names: dict[str, str],
) -> dict[str, str]:
    """byte_pattern_names -> extracted_names (ezmez, sadece bos slotlara)."""
    if not byte_pattern_names:
        return extracted_names

    for old_name, new_name in byte_pattern_names.items():
        if old_name not in extracted_names:
            extracted_names[old_name] = new_name
    logger.info(
        "Byte pattern names merged: %d isim (toplam extracted_names: %d)",
        len(byte_pattern_names), len(extracted_names),
    )
    return extracted_names


# ---------------------------------------------------------------------------
# 5. CAPA merge (stages.py L1860-1908)
# ---------------------------------------------------------------------------


def run_capa_merge(
    *, pc, extracted_names: dict[str, str], ctx: StepContext,
) -> dict:
    """CAPA capability sonuclarini naming'e entegre."""
    capa_capabilities: dict = {}
    step_start = time.monotonic()

    if not pc.config.binary_reconstruction.enable_capa:
        ctx.stats["timing_capa_naming"] = round(
            time.monotonic() - step_start, 1,
        )
        return capa_capabilities

    try:
        capa_data = pc.workspace.load_json("static", "capa_capabilities")
        if capa_data and capa_data.get("success"):
            func_caps = capa_data.get("function_capabilities", {})
            capa_capabilities = func_caps  # Ham veri (comment pipeline icin)

            from karadul.analyzers.capa_scanner import (
                CAPACapability,
                capability_to_function_name,
                rank_capabilities,
            )

            added = 0
            for func_addr, cap_list in func_caps.items():
                if func_addr in extracted_names:
                    continue
                if not cap_list:
                    continue
                caps = [
                    CAPACapability(
                        name=c.get("name", ""),
                        namespace=c.get("namespace", ""),
                    )
                    for c in cap_list
                    if isinstance(c, dict)
                ]
                ranked = rank_capabilities(caps)
                if ranked:
                    best_name = capability_to_function_name(ranked[0].name)
                    if best_name:
                        extracted_names[func_addr] = best_name
                        added += 1

            if added > 0:
                logger.info(
                    "CAPA names merged: %d isim (toplam extracted_names: %d)",
                    added, len(extracted_names),
                )
                ctx.stats["capa_names_added"] = added
    except FileNotFoundError:
        logger.debug(
            "CAPA sonuclari bulunamadi (static stage'de calistirilmamis)",
        )
    except Exception as exc:
        logger.debug("CAPA naming entegrasyonu hatasi: %s", exc)

    ctx.stats["timing_capa_naming"] = round(time.monotonic() - step_start, 1)
    return capa_capabilities


# ---------------------------------------------------------------------------
# Ortak yardimci
# ---------------------------------------------------------------------------


def _pin_artifact(pc, name: str, path) -> None:
    """pc.metadata['artifacts_pending'] icine artifact yolunu yaz."""
    if pc.metadata is None:
        pc.metadata = {}  # type: ignore[attr-defined]
    pc.metadata.setdefault("artifacts_pending", {})[name] = path
