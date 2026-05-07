"""AntiDebugStep — anti-debug teknik tespiti pipeline entegrasyonu.

v1.13 Dalga 1: ``karadul/analyzers/anti_debug_detector.py`` (24 PASS) modulunu
pipeline'a entegre eder. ``binary_prep`` sonrasi calisir; arm64 thin slice
resolve edildikten sonra binary uzerinde 3 katmanli tarama yapar (import,
string, bytes).

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_anti_debug_detection``
       False -> NO-OP. Ek artifact yazilmaz, stat sadece ``status=disabled``.
    2. Binary path: ``binary_for_byte_match`` artifact'ini kullan
       (universal binary'lerde arm64 slice'a bagli, ``binary_prep`` cozdu).
       Bulunamazsa ``pc.target.path`` fallback'i.
    3. ``AntiDebugDetector(target=pc.target, binary_path=binary_path).detect()``
       ile findings listesi al.
    4. ``static/anti_debug_findings.json`` artifact'ini yaz; stats'a ozet.

Tasarim notu:
    Step analyzer'a yeni bir API eklemez; mevcut ``AntiDebugDetector.detect()``
    + ``AntiDebugFinding.to_dict()`` cagirir. Hata oldugunda findings=[] ile
    pipeline'i kirmadan devam eder (defensive — pipeline'i tek bir analyzer
    coktugu icin durdurma).

Pipeline'da yer:
    binary_prep (binary_for_byte_match resolve eder)
        -> ghidra_metadata
        -> bsim_match
        -> byte_pattern
        -> anti_debug   <-- BURADA (v1.13 Dalga 1)
        -> packer_fingerprint
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
    name="anti_debug",
    requires=[
        "binary_for_byte_match",  # binary_prep'ten gelir (arm64 slice resolve)
    ],
    produces=[
        "anti_debug_findings",       # list[dict] — to_dict() ciktilari
        "anti_debug_summary",        # dict — kategori/teknik ozeti
        "anti_debug_findings_path",  # Path | None — JSON artifact yolu
    ],
    parallelizable_with=[
        # ghidra_metadata sirasi farkli dosyalar uzerinde calisir (functions.json),
        # anti_debug ise ham binary'i okur. Yine de Phase 1 sirali kosulur,
        # ileride paralelleştirme icin not.
        "ghidra_metadata",
        "byte_pattern",
        "packer_fingerprint",
    ],
)
class AntiDebugStep(Step):
    """Anti-debug teknik tespiti — 3 katman (import/string/bytes)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "anti_debug_findings": [],
            "anti_debug_summary": {},
            "anti_debug_findings_path": None,
        }

        # 1) Flag kontrolu — opt-out icin BinaryReconstructionConfig.enable_anti_debug_detection
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(
            getattr(recon_cfg, "enable_anti_debug_detection", True),
        )
        if not enabled:
            ctx.stats["timing_anti_debug"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["anti_debug_status"] = "disabled"
            return empty

        # 2) Binary yolu cozumle: arm64 slice tercih edilir (binary_prep
        # universal binary'lerde resolve etti). Yoksa target.path fallback.
        binary_path = self._resolve_binary_path(ctx)
        if binary_path is None or not binary_path.exists():
            logger.warning(
                "anti_debug: binary path bulunamadi/erisilemedi -> skip",
            )
            ctx.stats["timing_anti_debug"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["anti_debug_status"] = "no_binary"
            return empty

        # 3) Detector cagrisi — analyzer modulunden import (lazy ki test ile mockla)
        findings_dicts: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        try:
            from karadul.analyzers.anti_debug_detector import (
                AntiDebugDetector,
            )

            detector = AntiDebugDetector(
                target=pc.target,
                binary_path=binary_path,
            )
            findings = detector.detect()
            findings_dicts = [f.to_dict() for f in findings]
            try:
                summary = detector.summary(findings)
            except Exception as exc:  # pragma: no cover - defansif
                logger.debug(
                    "AntiDebugDetector.summary() basarisiz, atlanildi: %s",
                    exc,
                )
                summary = {}
        except ImportError:
            logger.debug("AntiDebugDetector bulunamadi, atlaniyor")
            ctx.stats["anti_debug_status"] = "module_missing"
        except Exception as exc:
            logger.warning(
                "Anti-debug tarama hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"anti_debug: {exc}")
            ctx.stats["anti_debug_status"] = "error"

        # 4) JSON artifact yaz: static/anti_debug_findings.json
        findings_path: Path | None = None
        try:
            payload = {
                "binary_path": str(binary_path),
                "total_findings": len(findings_dicts),
                "findings": findings_dicts,
                "summary": summary,
            }
            findings_path = pc.workspace.save_json(
                "static", "anti_debug_findings", payload,
            )
            ctx.produce_artifact("anti_debug_findings", findings_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning("anti_debug_findings.json yazilamadi: %s", exc)
            ctx.errors.append(f"anti_debug artifact yazimi: {exc}")

        # 5) Stat'lar
        ctx.stats["anti_debug_total"] = len(findings_dicts)
        if findings_dicts:
            # En yuksek confidence'li teknigi log'a yaz (top-1)
            top = findings_dicts[0]
            ctx.stats["anti_debug_top_technique"] = top.get("technique", "?")
            ctx.stats["anti_debug_top_confidence"] = float(
                top.get("confidence", 0.0),
            )
            # Kategori dagilimini stats'a koy (UI/rapor icin)
            cat_counts: dict[str, int] = {}
            for f in findings_dicts:
                cat = f.get("category", "unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            ctx.stats["anti_debug_categories"] = cat_counts
        ctx.stats.setdefault("anti_debug_status", "ok")
        ctx.stats["timing_anti_debug"] = round(
            time.monotonic() - step_start, 3,
        )

        if findings_dicts:
            logger.info(
                "Anti-debug: %d teknik tespit edildi (top: %s @ %.2f)",
                len(findings_dicts),
                ctx.stats.get("anti_debug_top_technique", "?"),
                ctx.stats.get("anti_debug_top_confidence", 0.0),
            )
        else:
            logger.info("Anti-debug: temiz binary, teknik tespit edilmedi")

        return {
            "anti_debug_findings": findings_dicts,
            "anti_debug_summary": summary,
            "anti_debug_findings_path": findings_path,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_binary_path(ctx: StepContext) -> Path | None:
        """Tarama yapilacak binary path'ini cozumle.

        Oncelik:
            1. ``binary_for_byte_match`` artifact'i (binary_prep'ten gelir,
               universal binary'lerde arm64 thin slice'i resolve eder).
            2. ``pc.target.path`` (fallback).
        """
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            return bpm
        pc = ctx.pipeline_context
        target_path = getattr(pc.target, "path", None)
        if target_path is None:
            return None
        return Path(target_path) if not isinstance(target_path, Path) else target_path
