"""PackerFingerprintStep — packer/protector fingerprint pipeline entegrasyonu.

v1.13 Dalga 1: ``karadul/analyzers/packer_fingerprint.py`` (35 PASS) modulunu
pipeline'a entegre eder. ``binary_prep`` sonrasi calisir; 3 katmanli tarama
yapar (section names, string markers, entry-point byte pattern).

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_packer_fingerprint``
       False -> NO-OP. Stat: ``status=disabled``.
    2. Binary path: ``binary_for_byte_match`` artifact'i tercih edilir
       (universal binary -> arm64 slice). Yoksa ``pc.target.path``.
    3. ``PackerFingerprintDetector(binary_path).detect()`` cagrir, multi-layer
       boost edilmis fingerprint listesi gelir.
    4. ``static/packer_fingerprints.json`` artifact'i yaz; stats'a ozet
       (toplam, top packer, kategori dagilimi).

Tasarim notu:
    Packer fingerprinting **erken** bir analiz adimi: yuksek confidence ile
    UPX/VMProtect/Themida tespit edildiyse downstream component'ler (decompile,
    unpack, capa) bunu metadata olarak kullanabilir. ``packed_binary.py``
    icindeki ``PackingDetector`` ile entegrasyon Wave 3'e ertelendi (analyzer
    icindeki entegrasyon notuna bakin).

Pipeline'da yer:
    binary_prep
        -> ghidra_metadata
        -> bsim_match
        -> byte_pattern
        -> anti_debug
        -> packer_fingerprint   <-- BURADA (v1.13 Dalga 1)
        -> pcode_cfg_analysis
        ... -> assembly_analysis
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="packer_fingerprint",
    requires=[
        "binary_for_byte_match",  # binary_prep'ten gelir
    ],
    produces=[
        "packer_fingerprints",        # list[dict] — to_dict() ciktilari
        "packer_top_match",           # dict | None — en yuksek confidence
        "packer_fingerprints_path",   # Path | None — JSON artifact yolu
    ],
    parallelizable_with=[
        "ghidra_metadata",
        "byte_pattern",
        "anti_debug",
    ],
)
class PackerFingerprintStep(Step):
    """Packer fingerprint tarayicisi — section/string/entry pattern."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "packer_fingerprints": [],
            "packer_top_match": None,
            "packer_fingerprints_path": None,
        }

        # 1) Flag — opt-out icin BinaryReconstructionConfig.enable_packer_fingerprint
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(
            getattr(recon_cfg, "enable_packer_fingerprint", True),
        )
        if not enabled:
            ctx.stats["timing_packer_fingerprint"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["packer_fingerprint_status"] = "disabled"
            return empty

        # 2) Binary yolu cozumle (anti_debug ile ayni mantik)
        binary_path = self._resolve_binary_path(ctx)
        if binary_path is None or not binary_path.exists():
            logger.warning(
                "packer_fingerprint: binary path yok -> skip",
            )
            ctx.stats["timing_packer_fingerprint"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["packer_fingerprint_status"] = "no_binary"
            return empty

        # 3) Detector cagrisi
        fingerprints_dicts: list[dict[str, Any]] = []
        try:
            from karadul.analyzers.packer_fingerprint import (
                PackerFingerprintDetector,
            )

            detector = PackerFingerprintDetector(binary_path)
            fingerprints = detector.detect()
            fingerprints_dicts = [fp.to_dict() for fp in fingerprints]
        except ImportError:
            logger.debug("PackerFingerprintDetector bulunamadi, atlaniyor")
            ctx.stats["packer_fingerprint_status"] = "module_missing"
        except Exception as exc:
            logger.warning(
                "Packer fingerprint hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"packer_fingerprint: {exc}")
            ctx.stats["packer_fingerprint_status"] = "error"

        # 4) JSON artifact yaz: static/packer_fingerprints.json
        fp_path: Path | None = None
        try:
            payload = {
                "binary_path": str(binary_path),
                "total_fingerprints": len(fingerprints_dicts),
                "fingerprints": fingerprints_dicts,
            }
            fp_path = pc.workspace.save_json(
                "static", "packer_fingerprints", payload,
            )
            ctx.produce_artifact("packer_fingerprints", fp_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning(
                "packer_fingerprints.json yazilamadi: %s", exc,
            )
            ctx.errors.append(f"packer_fingerprint artifact: {exc}")

        # 5) Stat'lar
        top_match: dict[str, Any] | None = None
        ctx.stats["packer_total"] = len(fingerprints_dicts)
        if fingerprints_dicts:
            top_match = fingerprints_dicts[0]  # detect() confidence DESC sort
            ctx.stats["packer_top_name"] = top_match.get("packer_name", "?")
            ctx.stats["packer_top_confidence"] = float(
                top_match.get("confidence", 0.0),
            )
            ctx.stats["packer_top_layers"] = int(
                top_match.get("layers_matched", 0),
            )
            cat_counts: dict[str, int] = {}
            for fp in fingerprints_dicts:
                cat = fp.get("category", "unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            ctx.stats["packer_categories"] = cat_counts
        ctx.stats.setdefault("packer_fingerprint_status", "ok")
        ctx.stats["timing_packer_fingerprint"] = round(
            time.monotonic() - step_start, 3,
        )

        if fingerprints_dicts:
            logger.info(
                "Packer fingerprint: %d eslesme (top: %s @ %.2f, %d katman)",
                len(fingerprints_dicts),
                ctx.stats.get("packer_top_name", "?"),
                ctx.stats.get("packer_top_confidence", 0.0),
                ctx.stats.get("packer_top_layers", 0),
            )
        else:
            logger.info(
                "Packer fingerprint: paketlenmemis binary (eslesme yok)",
            )

        return {
            "packer_fingerprints": fingerprints_dicts,
            "packer_top_match": top_match,
            "packer_fingerprints_path": fp_path,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_binary_path(ctx: StepContext) -> Path | None:
        """``binary_for_byte_match`` -> ``pc.target.path`` fallback."""
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            return bpm
        pc = ctx.pipeline_context
        target_path = getattr(pc.target, "path", None)
        if target_path is None:
            return None
        return Path(target_path) if not isinstance(target_path, Path) else target_path
