"""BinaryNinjaAnalysisStep — Binary Ninja experimental pipeline entegrasyonu.

v1.15 Dalga 1: ``karadul/analyzers/binaryninja_adapter.py`` (v1.14 D2,
lisanssiz makinelerde graceful skip) modulunu pipeline'a entegre eder.
Binary Ninja Python API mevcutsa BinaryView'den fonksiyon listesi + tip
container'i cikarir.

**release blocker DEGILDIR.** Lisanssiz CI/Mac'lerde sessizce skip eder.

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_binaryninja``
       False -> NO-OP. ``status=disabled``.
    2. ``BinaryNinjaAdapter.is_available()`` False -> ``status=not_available``
       (binaryninja modulu PYTHONPATH'te yok veya lisans yok).
    3. ``adapter.extract_all()`` cagrir; functions + types JSON artifact'lerine
       yazilir (``static/bn_functions.json``, ``static/bn_types.json``).
    4. Hata -> ``status=error`` + ``ctx.errors``.

Tasarim notu:
    - Berke karari (2026-05-09): BN lisansi alinmiyor, experimental kalir.
      Stage hep mevcut, gercek lisansli ortamda otomatik aktif olur.
    - Diger 2 stage (TRex, PDB) ile birlikte v1.15 paralel iz.
    - BN headless analiz buyuk binary'lerde dakikalar surer (timeout=600
      adapter default).

Pipeline'da yer (v1.15+):
    binary_prep
        -> ghidra_metadata
        -> binaryninja_analysis   <-- BURADA (lisans varsa aktif)
        -> ...
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
    name="binaryninja_analysis",
    requires=[
        "binary_for_byte_match",
    ],
    produces=[
        "bn_functions",        # list[dict] -- BNFunction.* alanlari
        "bn_types",            # list[dict] -- BNType.* alanlari
        "bn_functions_path",   # Path | None
        "bn_types_path",       # Path | None
        "bn_status",           # str
    ],
    parallelizable_with=[
        "anti_debug",
        "packer_fingerprint",
        "trex_struct_recovery",
        "pdb_symbol_recovery",
    ],
)
class BinaryNinjaAnalysisStep(Step):
    """Binary Ninja BinaryView'den fonksiyon + tip cikarir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "bn_functions": [],
            "bn_types": [],
            "bn_functions_path": None,
            "bn_types_path": None,
            "bn_status": "skipped",
        }

        # 1) Flag kontrolu (default False — Berke 2026-05-09 karari:
        # lisanssiz, experimental, opt-in)
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(getattr(recon_cfg, "enable_binaryninja", False))
        if not enabled:
            ctx.stats["timing_binaryninja_analysis"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["bn_status"] = "disabled"
            return {**empty, "bn_status": "disabled"}

        # 2) Binary path
        binary_path = self._resolve_binary_path(ctx)
        if binary_path is None or not binary_path.exists():
            logger.warning(
                "binaryninja_analysis: binary path bulunamadi -> skip",
            )
            ctx.stats["bn_status"] = "no_binary"
            ctx.stats["timing_binaryninja_analysis"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "bn_status": "no_binary"}

        # 3) Adapter availability
        adapter = None
        try:
            from karadul.analyzers.binaryninja_adapter import (
                BinaryNinjaAdapter,
            )

            adapter = BinaryNinjaAdapter(binary_path)
        except ImportError:
            logger.debug("BinaryNinjaAdapter import edilemedi -> skip")
            ctx.stats["bn_status"] = "module_missing"
            ctx.stats["timing_binaryninja_analysis"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "bn_status": "module_missing"}

        if not adapter.is_available():
            logger.info(
                "binaryninja_analysis: Binary Ninja Python API bulunamadi "
                "-> skip (lisans + kurulum gerek; release blocker degildir)",
            )
            ctx.stats["bn_status"] = "not_available"
            ctx.stats["timing_binaryninja_analysis"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "bn_status": "not_available"}

        # 4) Extract
        functions_dicts: list[dict[str, Any]] = []
        types_dicts: list[dict[str, Any]] = []
        status = "ok"
        try:
            result = adapter.extract_all()
            for fn in result.functions:
                functions_dicts.append({
                    "name": fn.name,
                    "address": fn.address,
                    "size": fn.size,
                    "return_type": fn.return_type,
                    "parameters": fn.parameters,
                    "is_thunk": fn.is_thunk,
                    "is_imported": fn.is_imported,
                })
            for t in result.types:
                types_dicts.append({
                    "name": t.name,
                    "kind": t.kind,
                    "size": t.size,
                    "fields": t.fields,
                })
            ctx.stats["bn_arch"] = result.arch
            ctx.stats["bn_platform"] = result.platform
            ctx.stats["bn_duration_ms"] = result.duration_ms
        except Exception as exc:
            logger.warning("Binary Ninja analiz hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"binaryninja_analysis: {exc}")
            status = "error"

        # 5) Artifacts
        functions_path: Path | None = None
        types_path: Path | None = None
        try:
            functions_payload = {
                "binary_path": str(binary_path),
                "total_functions": len(functions_dicts),
                "functions": functions_dicts,
            }
            functions_path = pc.workspace.save_json(
                "static", "bn_functions", functions_payload,
            )
            ctx.produce_artifact("bn_functions", functions_path)

            types_payload = {
                "binary_path": str(binary_path),
                "total_types": len(types_dicts),
                "types": types_dicts,
            }
            types_path = pc.workspace.save_json(
                "static", "bn_types", types_payload,
            )
            ctx.produce_artifact("bn_types", types_path)
        except Exception as exc:  # pragma: no cover
            logger.warning("bn artifact yazilamadi: %s", exc)
            ctx.errors.append(f"binaryninja_analysis artifact yazimi: {exc}")

        # 6) Stats
        ctx.stats["bn_total_functions"] = len(functions_dicts)
        ctx.stats["bn_total_types"] = len(types_dicts)
        ctx.stats["bn_status"] = status
        ctx.stats["timing_binaryninja_analysis"] = round(
            time.monotonic() - step_start, 3,
        )

        if functions_dicts or types_dicts:
            logger.info(
                "Binary Ninja: %d fonksiyon + %d tip cikarildi",
                len(functions_dicts), len(types_dicts),
            )

        return {
            "bn_functions": functions_dicts,
            "bn_types": types_dicts,
            "bn_functions_path": functions_path,
            "bn_types_path": types_path,
            "bn_status": status,
        }

    @staticmethod
    def _resolve_binary_path(ctx: StepContext) -> Path | None:
        """binary_for_byte_match -> target.path fallback."""
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            return bpm
        target_path = getattr(
            getattr(ctx.pipeline_context, "target", None), "path", None,
        )
        if target_path is None:
            return None
        return Path(target_path) if not isinstance(target_path, Path) else target_path
