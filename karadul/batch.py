"""Batch analysis -- birden fazla hedefi toplu analiz et.

Electron uygulamalari, JS bundle'lari ve native binary'leri
paralel pipeline'dan gecirir. 10 performance core kullanir.
"""

from __future__ import annotations

import difflib
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Apple Silicon: 10 performance core kullan (E-core haric)
from karadul.config import CPU_PERF_CORES
PARALLEL_WORKERS = CPU_PERF_CORES

# ============================================================================
# HEDEF TANIMLARI
# ============================================================================

ELECTRON_TARGETS: dict[str, str] = {
    "discord": "/Applications/Discord.app/Contents/Resources/app.asar",
    "claude-desktop": "/Applications/Claude.app/Contents/Resources/app.asar",
    "codex-app": "/Applications/Codex.app/Contents/Resources/app.asar",
    "element": "/Applications/Element.app/Contents/Resources/app.asar",
    "poe": "/Applications/Poe.app/Contents/Resources/app.asar",
}

JS_TARGETS: dict[str, str] = {
    "claude-code-cli": "/Users/apple/.local/bin/claude",
}

CURSOR_TARGETS: dict[str, str] = {
    "cursor-main": "/Applications/Cursor.app/Contents/Resources/app/out/main.js",
    "cursor-cli": "/Applications/Cursor.app/Contents/Resources/app/out/cli.js",
    "cursor-agent-exec": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-agent-exec/dist/main.js",
    "cursor-always-local": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-always-local/dist/main.js",
    "cursor-retrieval": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-retrieval/dist/main.js",
    "cursor-mcp": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-mcp/dist/main.js",
    "cursor-commits": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-commits/dist/main.js",
    "cursor-resolver": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-resolver/dist/main.js",
    "cursor-shadow-workspace": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-shadow-workspace/dist/extension.js",
    "cursor-deeplink": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-deeplink/dist/main.js",
}

BINARY_TARGETS: dict[str, str] = {
    "codex-cli": "/opt/homebrew/bin/codex",
    "avast": "/Applications/Avast.app/Contents/MacOS/Avast",
    "excel": "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel",
}

ALL_TARGETS = {
    **ELECTRON_TARGETS,
    **JS_TARGETS,
    **CURSOR_TARGETS,
    **BINARY_TARGETS,
}


@dataclass
class BatchTargetResult:
    """Tek bir hedefin batch analiz sonucu."""

    name: str
    path: str
    category: str
    success: bool = False
    duration: float = 0.0
    functions_found: int = 0
    strings_found: int = 0
    tech_stack: str = ""
    workspace: str = ""
    errors: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "category": self.category,
            "success": self.success,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "duration": round(self.duration, 2),
            "functions_found": self.functions_found,
            "strings_found": self.strings_found,
            "tech_stack": self.tech_stack,
            "workspace": self.workspace,
            "errors": self.errors,
        }


def get_target_category(name: str) -> str:
    """Hedefin kategorisini dondur."""
    if name in ELECTRON_TARGETS:
        return "electron"
    elif name in JS_TARGETS:
        return "js_bundle"
    elif name in CURSOR_TARGETS:
        return "cursor"
    elif name in BINARY_TARGETS:
        return "binary"
    return "unknown"


def resolve_targets(target_spec: str) -> dict[str, str]:
    """Target spec'i cevirip uygun hedefleri dondur.

    Args:
        target_spec: "electron", "binary", "js", "cursor", "all", veya
                     "discord,poe,avast" gibi virgule ayrilmis isimler.
    """
    spec = target_spec.lower().strip()

    if spec == "all":
        return dict(ALL_TARGETS)
    elif spec == "electron":
        return dict(ELECTRON_TARGETS)
    elif spec == "binary":
        return dict(BINARY_TARGETS)
    elif spec == "js":
        return dict(JS_TARGETS)
    elif spec == "cursor":
        return dict(CURSOR_TARGETS)
    else:
        # v1.10.0 E10: Bilinmeyen target adlari icin uyari + oneri.
        # Onceki davranis: sessizce atlama -> kullanici hata tespit edemiyordu.
        names = [n.strip() for n in spec.split(",") if n.strip()]
        result: dict[str, str] = {}
        known_names = list(ALL_TARGETS.keys())
        for name in names:
            if name in ALL_TARGETS:
                result[name] = ALL_TARGETS[name]
            else:
                suggestions = difflib.get_close_matches(
                    name, known_names, n=3, cutoff=0.6,
                )
                if suggestions:
                    logger.warning(
                        "Target bulunamadi: %s, atlaniyor (oneri: %s)",
                        name, ", ".join(suggestions),
                    )
                else:
                    logger.warning("Target bulunamadi: %s, atlaniyor", name)
        return result


def analyze_single_target(
    name: str,
    path_str: str,
    project_root: Path,
    skip_dynamic: bool = True,
) -> BatchTargetResult:
    """Tek bir hedefi pipeline'dan gecir.

    Args:
        name: Hedef adi.
        path_str: Hedef dosya yolu.
        project_root: Workspace'lerin olusturulacagi ust dizin.
        skip_dynamic: Dinamik analizi atla. False ise DynamicAnalysisStage
            (Frida) pipeline'a eklenir.

    v1.10.0 H5 fix: Onceden ``skip_dynamic`` parametresi fonksiyon imzasinda
    vardi ama Pipeline kurarken hic kullanilmiyordu; dolayisiyla
    ``skip_dynamic=False`` cagirisi bile dinamik stage'i calistirmiyordu.
    Artik ``skip_dynamic=False`` durumunda ``DynamicAnalysisStage`` identify
    sonrasi register ediliyor.
    """
    from karadul.config import Config
    from karadul.core.pipeline import Pipeline
    from karadul.stages import (
        IdentifyStage,
        StaticAnalysisStage,
        DeobfuscationStage,
        ReconstructionStage,
        ReportStage,
    )

    result = BatchTargetResult(
        name=name,
        path=path_str,
        category=get_target_category(name),
    )

    target_path = Path(path_str)

    if not target_path.exists():
        result.skipped = True
        result.skip_reason = f"Dosya bulunamadi: {path_str}"
        return result

    start = time.monotonic()

    try:
        cfg = Config()
        cfg.project_root = project_root

        pipeline = Pipeline(cfg)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        # v1.10.0 H5: skip_dynamic=False ise dinamik analizi ekle.
        if not skip_dynamic:
            try:
                from karadul.stages import DynamicAnalysisStage
                pipeline.register_stage(DynamicAnalysisStage())
            except ImportError:
                # Frida opsiyonel -- yoksa dinamik atlanir
                pass
        pipeline.register_stage(DeobfuscationStage())
        pipeline.register_stage(ReconstructionStage())
        pipeline.register_stage(ReportStage())

        pipeline_result = pipeline.run(target_path)

        result.success = pipeline_result.success or any(
            sr.success for sr in pipeline_result.stages.values()
        )
        result.workspace = str(pipeline_result.workspace_path)

        # Stats cikar
        if "static" in pipeline_result.stages:
            stats = pipeline_result.stages["static"].stats
            result.functions_found = stats.get(
                "functions_found",
                stats.get("ghidra_function_count", 0),
            )
            result.strings_found = stats.get(
                "strings_found",
                stats.get("string_count", 0),
            )

        if "identify" in pipeline_result.stages:
            stats = pipeline_result.stages["identify"].stats
            result.tech_stack = (
                f"{stats.get('target_type', 'unknown')} / "
                f"{stats.get('language', 'unknown')}"
            )

        for stage_name, sr in pipeline_result.stages.items():
            if sr.errors:
                result.errors.extend([f"[{stage_name}] {e}" for e in sr.errors])

    except Exception as exc:
        result.errors.append(f"Pipeline hatasi: {type(exc).__name__}: {exc}")

    result.duration = time.monotonic() - start
    return result


def _worker(args: tuple) -> BatchTargetResult:
    """ProcessPoolExecutor icin wrapper (pickle edilebilir fonksiyon)."""
    name, path_str, project_root, skip_dynamic = args
    return analyze_single_target(name, path_str, project_root, skip_dynamic)


def analyze_parallel(
    targets: dict[str, str],
    project_root: Path,
    skip_dynamic: bool = True,
    max_workers: int | None = None,
    callback=None,
) -> list[BatchTargetResult]:
    """Birden fazla hedefi PARALEL analiz et.

    10 performance core kullanarak ayni anda birden fazla binary
    pipeline'dan gecirir. Ghidra JVM her process icin ayri baslatilir.

    Args:
        targets: {isim: path} dict'i.
        project_root: Workspace ust dizini.
        skip_dynamic: Dinamik analizi atla.
        max_workers: Paralel worker sayisi (varsayilan: PARALLEL_WORKERS).
        callback: Her analiz tamamlandiginda cagrilan fonksiyon(result).

    Returns:
        Sonuc listesi (hedef sirasina gore).
    """
    workers = max_workers or PARALLEL_WORKERS
    # Ghidra JVM bellek yogun -- ayni anda en fazla 3 Ghidra
    # (her biri 16GB heap isteyebilir, 36GB RAM ile max 2-3)
    workers = min(workers, 3, len(targets))

    args_list = [
        (name, path_str, project_root, skip_dynamic)
        for name, path_str in targets.items()
    ]

    results: dict[str, BatchTargetResult] = {}

    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_name = {
            executor.submit(_worker, args): args[0]
            for args in args_list
        }

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
            except Exception as exc:
                result = BatchTargetResult(
                    name=name,
                    path=targets[name],
                    category=get_target_category(name),
                    errors=[f"Worker hatasi: {type(exc).__name__}: {exc}"],
                )
            results[name] = result
            if callback:
                callback(result)

    # Orijinal sirada dondur
    return [results[name] for name in targets if name in results]
