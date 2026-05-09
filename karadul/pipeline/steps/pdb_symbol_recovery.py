"""PdbSymbolRecoveryStep — PDB sembol/tip kurtarma pipeline entegrasyonu.

v1.15 Dalga 1: ``karadul/analyzers/pdb_parser.py`` (v1.14 D1, llvm-pdbutil
sarmalayicisi) modulunu pipeline'a entegre eder. Windows PE binary'leri icin
yan dosya olarak ``<binary>.pdb`` mevcutsa S_GPROC32 sembollerini ve
LF_STRUCTURE tip kayitlarini cikarir.

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_pdb`` False ->
       NO-OP. ``status=disabled``.
    2. Hedef tipi kontrolu: PE binary degilse skip. ``status=not_pe_target``.
    3. PDB dosyasi cozumle: explicit artifact ``pdb_path``, sonra
       ``<binary>.pdb`` (komsu dosya). Bulunamazsa ``status=no_pdb_file``.
    4. ``PDBAdapter.is_available()`` False -> ``status=tool_missing``
       (llvm-pdbutil kurulmamis, brew install llvm).
    5. ``adapter.extract_all()`` cagrir; symbols + types JSON artifact'ine
       yazilir (``static/pdb_symbols.json``, ``static/pdb_types.json``).

Tasarim notu:
    - Stage idempotent.
    - Hata durumlari pipeline'i kirmaz; ``status=error`` + ``ctx.errors``.
    - PE-only dispatch: macho/ELF/Mach-O hedeflerde sessizce skip.

Pipeline'da yer (v1.15+):
    binary_prep
        -> ghidra_metadata
        -> pdb_symbol_recovery   <-- BURADA (PE only, yan .pdb dosyasi)
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
    name="pdb_symbol_recovery",
    requires=[
        "binary_for_byte_match",
    ],
    produces=[
        "pdb_symbols",         # list[dict] -- PDBSymbol.* alanlarinin dict'i
        "pdb_types",           # list[dict] -- PDBType.* alanlarinin dict'i
        "pdb_symbols_path",    # Path | None
        "pdb_types_path",      # Path | None
        "pdb_status",          # str -- "ok"/"disabled"/"not_pe_target"/"no_pdb_file"/"tool_missing"/"error"
    ],
    parallelizable_with=[
        "anti_debug",
        "packer_fingerprint",
        "trex_struct_recovery",
    ],
)
class PdbSymbolRecoveryStep(Step):
    """PE binary yan .pdb dosyasindan sembol + tip cikarir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "pdb_symbols": [],
            "pdb_types": [],
            "pdb_symbols_path": None,
            "pdb_types_path": None,
            "pdb_status": "skipped",
        }

        # 1) Flag kontrolu
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(getattr(recon_cfg, "enable_pdb", True))
        if not enabled:
            ctx.stats["timing_pdb_symbol_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["pdb_status"] = "disabled"
            return {**empty, "pdb_status": "disabled"}

        # 2) PE-only dispatch
        target_type = getattr(getattr(pc, "target", None), "target_type", None)
        is_pe = False
        if target_type is not None:
            # TargetType enum veya string olabilir (test friendly)
            tt_name = getattr(target_type, "name", str(target_type))
            is_pe = "PE" in str(tt_name).upper()
        if not is_pe:
            logger.debug(
                "pdb_symbol_recovery: PE binary degil (target=%s) -> skip",
                target_type,
            )
            ctx.stats["pdb_status"] = "not_pe_target"
            ctx.stats["timing_pdb_symbol_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "pdb_status": "not_pe_target"}

        # 3) PDB dosyasi cozumle
        pdb_path = self._resolve_pdb_path(ctx)
        if pdb_path is None or not pdb_path.exists():
            logger.info(
                "pdb_symbol_recovery: PDB dosyasi bulunamadi -> skip",
            )
            ctx.stats["pdb_status"] = "no_pdb_file"
            ctx.stats["timing_pdb_symbol_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "pdb_status": "no_pdb_file"}

        # 4) llvm-pdbutil mevcut mu?
        adapter = None
        try:
            from karadul.analyzers.pdb_parser import PDBAdapter

            adapter = PDBAdapter(pdb_path=pdb_path)
        except ImportError:
            logger.debug("PDBAdapter import edilemedi -> skip")
            ctx.stats["pdb_status"] = "module_missing"
            ctx.stats["timing_pdb_symbol_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "pdb_status": "module_missing"}

        if not adapter.is_available():
            logger.info(
                "pdb_symbol_recovery: llvm-pdbutil bulunamadi -> skip "
                "(brew install llvm veya KARADUL_LLVM_PDBUTIL env)",
            )
            ctx.stats["pdb_status"] = "tool_missing"
            ctx.stats["timing_pdb_symbol_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "pdb_status": "tool_missing"}

        # 5) Extract
        symbols_dicts: list[dict[str, Any]] = []
        types_dicts: list[dict[str, Any]] = []
        status = "ok"
        try:
            result = adapter.extract_all()
            for s in result.symbols:
                symbols_dicts.append({
                    "name": s.name,
                    "address": s.address,
                    "size": s.size,
                    "section": s.section,
                    "kind": s.kind,
                    "type_index": s.type_index,
                })
            for t in result.types:
                types_dicts.append({
                    "type_id": t.type_id,
                    "kind": t.kind,
                    "name": t.name,
                    "size": t.size,
                    "fields": t.fields,
                })
            ctx.stats["pdb_return_code"] = result.return_code
            ctx.stats["pdb_duration_ms"] = result.duration_ms
            ctx.stats["pdb_version"] = result.pdb_version
        except Exception as exc:
            logger.warning("PDB extract hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"pdb_symbol_recovery: {exc}")
            status = "error"

        # 6) JSON artifacts
        symbols_path: Path | None = None
        types_path: Path | None = None
        try:
            symbols_payload = {
                "pdb_path": str(pdb_path),
                "total_symbols": len(symbols_dicts),
                "symbols": symbols_dicts,
            }
            symbols_path = pc.workspace.save_json(
                "static", "pdb_symbols", symbols_payload,
            )
            ctx.produce_artifact("pdb_symbols", symbols_path)

            types_payload = {
                "pdb_path": str(pdb_path),
                "total_types": len(types_dicts),
                "types": types_dicts,
            }
            types_path = pc.workspace.save_json(
                "static", "pdb_types", types_payload,
            )
            ctx.produce_artifact("pdb_types", types_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning("pdb artifact yazilamadi: %s", exc)
            ctx.errors.append(f"pdb_symbol_recovery artifact yazimi: {exc}")

        # 7) Stat'lar
        ctx.stats["pdb_total_symbols"] = len(symbols_dicts)
        ctx.stats["pdb_total_types"] = len(types_dicts)
        ctx.stats["pdb_status"] = status
        ctx.stats["timing_pdb_symbol_recovery"] = round(
            time.monotonic() - step_start, 3,
        )

        if symbols_dicts or types_dicts:
            logger.info(
                "PDB: %d sembol + %d tip cikarildi",
                len(symbols_dicts), len(types_dicts),
            )
        elif status == "ok":
            logger.info("PDB: dump bos (sembol/tip yok)")

        return {
            "pdb_symbols": symbols_dicts,
            "pdb_types": types_dicts,
            "pdb_symbols_path": symbols_path,
            "pdb_types_path": types_path,
            "pdb_status": status,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_pdb_path(ctx: StepContext) -> Path | None:
        """PDB dosyasi yolunu cozumle.

        Oncelik:
            1. ``pdb_path`` artifact'i (pipeline'da ileride pe_metadata
               step'i tarafindan set edilebilir).
            2. ``<binary>.pdb`` -- binary ile ayni dizinde, .pdb uzantili.
        """
        # 1) Explicit artifact
        explicit = ctx.artifacts.get("pdb_path")
        if isinstance(explicit, Path) and explicit.exists():
            return explicit
        # 2) Binary komsu .pdb
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            sibling = bpm.with_suffix(".pdb")
            if sibling.exists():
                return sibling
        # Target.path'tan da deneyelim
        target_path = getattr(
            getattr(ctx.pipeline_context, "target", None), "path", None,
        )
        if target_path is not None:
            tp = Path(target_path) if not isinstance(target_path, Path) else target_path
            sibling = tp.with_suffix(".pdb")
            if sibling.exists():
                return sibling
        return None
