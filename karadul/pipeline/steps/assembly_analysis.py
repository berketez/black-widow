"""AssemblyAnalysisStep — Ghidra decompiler fallback: assembly-level analiz.

stages.py L1960-2042 'den tasindi. Davranis birebir korundu:
- functions_json'dan disassembly field'li fonksiyonlari oku
- AssemblyAnalyzer ile calling convention, param count, SIMD, crypto tespit
- Sonuclari stats'a ve `assembly_analysis.json` artifact'ina yaz

Bu step confidence_filter'dan sonra, feedback_loop'tan once calisir.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from karadul.core.target import TargetType
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="assembly_analysis",
    requires=[
        "functions_json_path",
        "functions_data",
    ],
    produces=[
        "asm_results",
        "timing_assembly_analysis",
    ],
    parallelizable_with=[],
)
class AssemblyAnalysisStep(Step):
    """Assembly-level analiz — Ghidra decompile fallback.

    functions_json'da disassembly field'li fonksiyon varsa calling convention,
    param count, stack frame ve crypto/SIMD pattern tespit eder. Sonuclari
    hem stats'a (crypto/simd listesi, toplam sayisi) hem de
    `reconstructed/assembly_analysis.json` dosyasina yazar.

    Hata: Module yok ya da disassembly yoksa sessizce geç — orijinal
    davraniş birebir korunuyor.
    """

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        target = pc.target
        functions_json = ctx.artifacts["functions_json_path"]
        func_data = ctx.artifacts["functions_data"]

        step_start = time.monotonic()
        asm_results: dict[str, Any] = {}

        try:
            from karadul.analyzers.assembly_analyzer import AssemblyAnalyzer

            asm_analyzer = AssemblyAnalyzer()
            if functions_json and functions_json.exists():
                arch = self._detect_arch(target, func_data, functions_json)

                asm_results_raw = asm_analyzer.analyze_from_ghidra_json(
                    functions_json, arch=arch,
                )

                if asm_results_raw:
                    asm_results = asm_results_raw
                    self._write_stats(ctx, asm_results_raw)
                    self._save_artifact(pc, ctx, asm_results_raw)
                    crypto_count = sum(
                        1 for r in asm_results_raw.values()
                        if r.has_crypto_instructions
                    )
                    simd_count = sum(
                        1 for r in asm_results_raw.values()
                        if r.simd_patterns
                    )
                    logger.info(
                        "Assembly Analysis: %d fonksiyon (%d crypto, %d SIMD)",
                        len(asm_results_raw), crypto_count, simd_count,
                    )
        except ImportError:
            logger.debug("AssemblyAnalyzer bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("Assembly analysis hatasi (atlaniyor): %s", exc)

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_assembly_analysis"] = timing

        return {
            "asm_results": asm_results,
            "timing_assembly_analysis": timing,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _detect_arch(target, func_data: Any, functions_json) -> str:
        """Mimariyi target + ghidra metadata'dan cikar.

        Orijinal davranis (L1971-1987):
        - Default x86_64
        - MACHO_BINARY + metadata.processor ARM/aarch64 ise aarch64
        """
        arch = "x86_64"
        asm_func_data = func_data if isinstance(func_data, dict) else None
        if asm_func_data is None:
            try:
                asm_func_data = json.loads(
                    functions_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception:
                logger.debug("Assembly functions JSON parse basarisiz", exc_info=True)
                asm_func_data = {}

        if target.target_type == TargetType.MACHO_BINARY:
            meta = asm_func_data.get("metadata", {}) if isinstance(asm_func_data, dict) else {}
            proc = meta.get("processor", "").lower()
            if "aarch64" in proc or "arm" in proc:
                arch = "aarch64"
        return arch

    @staticmethod
    def _write_stats(ctx: StepContext, asm_results: dict[str, Any]) -> None:
        """Crypto/SIMD fonksiyon listelerini stats'a ekle (top 20)."""
        crypto_funcs = [
            name for name, r in asm_results.items()
            if r.has_crypto_instructions
        ]
        simd_funcs = [
            name for name, r in asm_results.items()
            if r.simd_patterns
        ]
        ctx.stats["asm_functions_analyzed"] = len(asm_results)
        if crypto_funcs:
            ctx.stats["asm_crypto_functions"] = crypto_funcs[:20]
        if simd_funcs:
            ctx.stats["asm_simd_functions"] = simd_funcs[:20]

    @staticmethod
    def _save_artifact(pc, ctx: StepContext, asm_results: dict[str, Any]) -> None:
        """Assembly analysis sonuclarini workspace'e JSON olarak kaydet.

        Orijinal davranista sadece ilk 500 fonksiyon detayi yaziliyordu
        (L2023). Birebir korunuyor.
        """
        try:
            crypto_funcs = [
                name for name, r in asm_results.items()
                if r.has_crypto_instructions
            ]
            simd_funcs = [
                name for name, r in asm_results.items()
                if r.simd_patterns
            ]
            asm_data = {
                "total_analyzed": len(asm_results),
                "crypto_functions": crypto_funcs,
                "simd_functions": simd_funcs,
                "details": {
                    name: {
                        "calling_convention": r.calling_convention,
                        "param_count": r.param_count,
                        "stack_frame_size": r.stack_frame_size,
                        "is_leaf": r.is_leaf_function,
                        "complexity": r.estimated_complexity,
                        "has_crypto": r.has_crypto_instructions,
                        "simd_count": len(r.simd_patterns),
                    }
                    for name, r in list(asm_results.items())[:500]
                },
            }
            asm_path = pc.workspace.save_json(
                "reconstructed", "assembly_analysis", asm_data,
            )
            ctx.produce_artifact("assembly_analysis", asm_path)
        except Exception:
            logger.debug("Assembly analysis artifact kaydi basarisiz", exc_info=True)
