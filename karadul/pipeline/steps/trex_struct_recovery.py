"""TrexStructRecoveryStep — TRex struct cikarimi pipeline entegrasyonu.

v1.15 Dalga 1: ``karadul/analyzers/trex_adapter.py`` (17 PASS) modulunu
pipeline'a entegre eder. Ghidra IL (lifted) artifact'inden struct yapilarini
cikarir ve ``static/trex_structs.json`` artifact'i olusturur.

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_trex`` False ->
       NO-OP. Stat sadece ``status=disabled``.
    2. ``TRexAdapter.is_available()`` False -> NO-OP. ``status=binary_missing``.
       Bu durum Rust toolchain kurulmamissa veya cargo build yapilmamissa
       (vendor/trex/BUILD_INSTRUCTIONS.md) gorulur. Pipeline kirilmaz.
    3. Ghidra IL (lifted) artifact'i kontrolu: ``ghidra_lifted_il_path``
       artifact'i mevcut degilse skip. Bu artifact henuz pipeline'da
       uretilmiyor (v1.15.5 hedefi); su anda graceful skip ile beklenir.
    4. Mevcutsa: ``TRexAdapter.analyze(lifted_path)`` cagrir, struct'lari
       JSON artifact'ine yazar.

Tasarim notu:
    - Stage idempotent: tekrar calistirilirsa ayni JSON yazilir.
    - Hata durumlari pipeline'i kirmaz (defansif): exception'da bos sonuc
      doner, ``ctx.errors`` listesine eklenir.
    - TRex yoksa stage hata vermez — yalnizca status raporlar.

Pipeline'da yer (v1.15+):
    binary_prep
        -> ghidra_metadata
        -> ghidra_decompile (lifted IL uretir, gelecekte)
        -> trex_struct_recovery   <-- BURADA (lifted IL bekler)
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
    name="trex_struct_recovery",
    requires=[
        # binary_prep cikti olarak gerekli (target.path normalize)
        "binary_for_byte_match",
    ],
    produces=[
        "trex_structs",         # list[dict] -- TRexStruct.to_dict() ciktilari
        "trex_structs_path",    # Path | None -- JSON artifact yolu
        "trex_status",          # str -- "ok"/"disabled"/"binary_missing"/"no_lifted_il"/"error"
    ],
    parallelizable_with=[
        # anti_debug ve packer_fingerprint farkli analizler; trex sadece
        # IL/lifted dosyasi okur, bytes okumaz. Phase 1 sirali, ileride paralel.
        "anti_debug",
        "packer_fingerprint",
    ],
)
class TrexStructRecoveryStep(Step):
    """TRex struct cikarimi (Ghidra IL lifted format) pipeline stage'i."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "trex_structs": [],
            "trex_structs_path": None,
            "trex_status": "skipped",
        }

        # 1) Flag kontrolu — opt-out (default True ileride config'e eklenince)
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(getattr(recon_cfg, "enable_trex", True))
        if not enabled:
            ctx.stats["timing_trex_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["trex_status"] = "disabled"
            return {**empty, "trex_status": "disabled"}

        # 2) TRex binary varligi (Rust toolchain + cargo build kurulmus mu?)
        adapter = None
        try:
            from karadul.analyzers.trex_adapter import TRexAdapter

            adapter = TRexAdapter()
        except ImportError:
            logger.debug("TRexAdapter import edilemedi -> skip")
            ctx.stats["trex_status"] = "module_missing"
            ctx.stats["timing_trex_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "trex_status": "module_missing"}

        if not adapter.is_available():
            logger.info(
                "trex_struct_recovery: TRex binary bulunamadi -> skip "
                "(vendor/trex/BUILD_INSTRUCTIONS.md ile kurulabilir)",
            )
            ctx.stats["trex_status"] = "binary_missing"
            ctx.stats["timing_trex_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "trex_status": "binary_missing"}

        # 3) Ghidra IL (lifted) artifact'i mevcut mu?
        # Bu artifact'i pipeline'da uretecek olan stage henuz yok (v1.15.5
        # hedefi). Su anda graceful skip ile bekleriz; artifact gelirse
        # otomatik olarak aktif olur.
        lifted_path_obj = ctx.artifacts.get("ghidra_lifted_il_path")
        if not isinstance(lifted_path_obj, Path) or not lifted_path_obj.exists():
            logger.info(
                "trex_struct_recovery: Ghidra IL (ghidra_lifted_il_path) "
                "artifact'i bulunamadi -> skip (v1.15.5'te entegre edilecek)",
            )
            ctx.stats["trex_status"] = "no_lifted_il"
            ctx.stats["timing_trex_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return {**empty, "trex_status": "no_lifted_il"}

        # 4) Analiz cagri
        structs_dicts: list[dict[str, Any]] = []
        status = "ok"
        try:
            result = adapter.analyze(lifted_path_obj)
            for s in result.structs:
                structs_dicts.append({
                    "name": s.name,
                    "fields": s.fields,
                    "function": s.function,
                })
            ctx.stats["trex_return_code"] = result.return_code
            ctx.stats["trex_duration_ms"] = result.duration_ms
        except Exception as exc:
            logger.warning("TRex analiz hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"trex_struct_recovery: {exc}")
            status = "error"

        # 5) JSON artifact yaz: static/trex_structs.json
        structs_path: Path | None = None
        if structs_dicts or status == "ok":
            try:
                payload = {
                    "lifted_path": str(lifted_path_obj),
                    "total_structs": len(structs_dicts),
                    "structs": structs_dicts,
                }
                structs_path = pc.workspace.save_json(
                    "static", "trex_structs", payload,
                )
                ctx.produce_artifact("trex_structs", structs_path)
            except Exception as exc:  # pragma: no cover - defansif
                logger.warning("trex_structs.json yazilamadi: %s", exc)
                ctx.errors.append(f"trex_struct_recovery artifact yazimi: {exc}")

        # 6) Stat'lar
        ctx.stats["trex_total_structs"] = len(structs_dicts)
        ctx.stats["trex_status"] = status
        ctx.stats["timing_trex_struct_recovery"] = round(
            time.monotonic() - step_start, 3,
        )

        if structs_dicts:
            logger.info(
                "TRex: %d struct cikarildi", len(structs_dicts),
            )
        elif status == "ok":
            logger.info("TRex: lifted IL'den struct cikarilamadi")

        return {
            "trex_structs": structs_dicts,
            "trex_structs_path": structs_path,
            "trex_status": status,
        }
