"""BinaryPrepStep — decompiled C dosyalarini hazirlar ve cache eder.

stages.py `_execute_binary` L1162-1217'den tasindi. Davranis birebir
korundu: evrensel ikili dilimi + decompiled_dir resolve + rglob C +
content cache + metadata injection.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from karadul.core.target import TargetType
from karadul.exceptions import PipelineStageError
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
    """Decompiled C'yi yukler, cache'ler, evrensel ikilinin dilimini resolve eder.

    stages.py orijinal kodunun davranisi:
    - Evrensel ikili ise statik aşamanın seçtiği dilimi byte match icin kullan
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
            raise PipelineStageError(
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
            pc.metadata = {}
        pc.metadata["file_cache"] = file_cache

        return {
            "c_files": c_files,
            "file_cache": file_cache,
            "binary_for_byte_match": binary_for_byte_match,
            "decompiled_dir": decompiled_dir,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_byte_match_binary(target: Any, workspace: Any, ctx: StepContext) -> Path:
        """Evrensel ikilide statik aşamanın seçtiği dilim, aksi halde target.path.

        Statik aşama (``MachOAnalyzer._extract_universal_slice``) seçimi
        ``static/universal_slice.json``'a yazar; dilim adı gerçek mimariyi taşır
        (``raw/<ad>_arm64e`` gibi). Eski kod sabit ``raw/<ad>_arm64`` arıyordu; o dosya
        x86_64 dilimi de olabiliyordu.
        """
        binary_for_byte_match: Path = target.path
        if target.target_type == TargetType.UNIVERSAL_BINARY:
            raw_dir: Path = workspace.get_stage_dir("raw")
            record_path = workspace.get_stage_dir("static") / "universal_slice.json"
            record: dict[str, Any] = {}
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                logger.warning("universal_slice.json okunamadi (%s): %s", record_path, exc)
            name = record.get("path")
            thin = raw_dir / name if isinstance(name, str) and "/" not in name else None
            if thin is not None and thin.is_file():
                ctx.stats["byte_match_binary"] = "%s_slice" % record.get("selected")
                logger.info("BytePatternMatcher: %s dilimi kullaniliyor: %s",
                            record.get("selected"), thin)
                return thin
            ctx.stats["byte_match_binary"] = "fat"
            ctx.stats["byte_match_slice_error"] = record.get("error") or "dilim kaydı yok"
            logger.warning(
                "BytePatternMatcher: secilen dilim yok (%s), fat binary kullanilacak "
                "-- mimari uyusmazligi olabilir",
                record.get("error") or record_path,
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
