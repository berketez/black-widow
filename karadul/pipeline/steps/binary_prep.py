"""BinaryPrepStep — decompiled C dosyalarini hazirlar ve cache eder.

stages.py `_execute_binary` L1162-1217'den tasindi. Davranis birebir
korundu: lipo-thin arm64 slice + decompiled_dir resolve + rglob C +
content cache + metadata injection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from karadul.core.target import TargetType
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="binary_prep",
    requires=[],
    produces=[
        "c_files",
        "file_cache",
        "binary_for_byte_match",
        "decompiled_dir",
    ],
    parallelizable_with=[],
)
class BinaryPrepStep(Step):
    """Decompiled C'yi yukler, cache'ler, arm64 slice'i resolve eder.

    stages.py orijinal kodunun davranisi:
    - Universal binary ise raw/<name>_arm64 slice'i byte match icin kullan
    - decompiled_dir: once deobfuscated/decompiled, yoksa static/ghidra_output/decompiled
    - rglob *.c ile tum decompiled C dosyalarini topla
    - Her dosyanin icerigini RAM'e cache'le (file_cache dict)
    - context.metadata["file_cache"] set et (downstream shim icin)

    Hata:
        RuntimeError: decompiled_dir veya C dosyasi bulunamadi.
    """

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        target = pc.target
        static_dir = pc.workspace.get_stage_dir("static")
        deob_dir = pc.workspace.get_stage_dir("deobfuscated")

        binary_for_byte_match = self._resolve_byte_match_binary(
            target, pc.workspace, ctx,
        )

        decompiled_dir = deob_dir / "decompiled"
        if not decompiled_dir.exists():
            decompiled_dir = static_dir / "ghidra_output" / "decompiled"

        c_files = (
            sorted(decompiled_dir.rglob("*.c"))
            if decompiled_dir.exists()
            else []
        )
        if not c_files:
            raise RuntimeError(
                "Decompile edilmis C dosyasi bulunamadi "
                f"(decompiled_dir={decompiled_dir})",
            )

        ctx.stats["source_c_files"] = len(c_files)
        logger.info(
            "Binary prep: %d C dosyasi islenecek",
            len(c_files),
        )

        file_cache = self._build_file_cache(c_files)

        # Downstream shim icin: metadata["file_cache"] birebir set et
        # (stages.py'deki eski davranisi korumak icin)
        if not hasattr(pc, "metadata") or pc.metadata is None:
            pc.metadata = {}  # type: ignore[attr-defined]
        pc.metadata["file_cache"] = file_cache

        return {
            "c_files": c_files,
            "file_cache": file_cache,
            "binary_for_byte_match": binary_for_byte_match,
            "decompiled_dir": decompiled_dir,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_byte_match_binary(target, workspace, ctx: StepContext) -> Path:
        """Universal binary ise arm64 thin slice'i dondur, aksi halde target.path."""
        binary_for_byte_match = target.path
        if target.target_type == TargetType.UNIVERSAL_BINARY:
            raw_dir = workspace.get_stage_dir("raw")
            thin_arm64 = raw_dir / f"{target.name}_arm64"
            if thin_arm64.exists():
                ctx.stats["byte_match_binary"] = "arm64_slice"
                logger.info(
                    "BytePatternMatcher: arm64 thin slice kullaniliyor: %s",
                    thin_arm64,
                )
                return thin_arm64
            logger.warning(
                "BytePatternMatcher: arm64 thin slice bulunamadi (%s), "
                "fat binary kullanilacak -- arch mismatch olabilir",
                thin_arm64,
            )
        return binary_for_byte_match

    @staticmethod
    def _build_file_cache(c_files: list[Path]) -> dict[str, str]:
        """Tum C dosyalarini tek seferde RAM'e oku.

        v1.4.3'te geri getirildi (lightweight). Downstream moduller ayni
        dosyalari tekrar tekrar okuyordu; tek seferlik okuma I/O'yu azaltir.
        """
        cache: dict[str, str] = {}
        for cf in c_files:
            try:
                cache[cf.name] = cf.read_text(
                    encoding="utf-8", errors="replace",
                )
            except Exception:
                logger.debug(
                    "Dosya cache'e okunamadi: %s, atlaniyor",
                    cf.name, exc_info=True,
                )
        cache_mb = sum(len(v) for v in cache.values()) / (1024 * 1024)
        logger.info("File cache: %d dosya, %.1f MB", len(cache), cache_mb)
        return cache
