"""BytePatternStep — FUN_xxx fonksiyonlarini byte pattern ile tani.

stages.py `_execute_binary` L1361-1451'den tasindi. Davranis birebir korundu:
- enable_byte_pattern_matching flag'i kontrol
- FLIRT signature'larini topla (homebrew + sigs/ + external + binary-embedded)
- BytePatternMatcher.match_unknown_functions() ile FUN_/sub_/thunk_ match
- to_naming_map() ile {original_name -> recovered_name} dict'i uret

v1.14 D2:
- ``flirt_use_trie`` ve ``flirt_trie_threshold`` flag'lerine gore imza
  sayisi esiği astiginda ``match_unknown_functions_trie`` kullanilir
  (FlirtTrieMatcher prefix trie). Linear path varsayilan fallback olarak
  korunur, davranis bozulmaz.
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
    name="byte_pattern",
    requires=[
        "binary_for_byte_match",
        "functions_json_path",
    ],
    produces=[
        "byte_pattern_result",
        "byte_pattern_names",
    ],
    parallelizable_with=[],
)
class BytePatternStep(Step):
    """BytePatternMatcher + FLIRT signature toplama."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        binary_for_byte_match: Path = ctx.artifacts["binary_for_byte_match"]
        functions_json: Path = ctx.artifacts["functions_json_path"]

        pc.report_progress("Byte pattern matching...", 0.10)
        step_start = time.monotonic()

        byte_pattern_names: dict[str, str] = {}
        bp_result = None

        if not pc.config.binary_reconstruction.enable_byte_pattern_matching:
            ctx.stats["timing_byte_pattern"] = round(
                time.monotonic() - step_start, 1,
            )
            return {
                "byte_pattern_result": None,
                "byte_pattern_names": byte_pattern_names,
            }

        try:
            from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher

            bpm = BytePatternMatcher(
                min_confidence=pc.config.binary_reconstruction.min_naming_confidence,
            )

            all_byte_sigs = self._collect_flirt_signatures(
                pc=pc,
                binary_for_byte_match=binary_for_byte_match,
            )

            if all_byte_sigs:
                # v1.14 D2: trie path secimi (esik + global flag)
                use_trie, threshold = self._trie_decision(
                    pc=pc, sig_count=len(all_byte_sigs),
                )
                strategy = "trie" if use_trie else "linear"
                ctx.stats["flirt_match_strategy"] = strategy
                ctx.stats["flirt_signature_count"] = len(all_byte_sigs)
                ctx.stats["flirt_trie_threshold"] = threshold

                trie_start = time.monotonic()
                if use_trie:
                    bp_result = bpm.match_unknown_functions_trie(
                        binary_path=binary_for_byte_match,
                        functions_json=functions_json,
                        known_signatures=all_byte_sigs,
                    )
                    logger.info(
                        "FLIRT trie matcher: %d pattern, %.0fms scan",
                        len(all_byte_sigs),
                        (time.monotonic() - trie_start) * 1000.0,
                    )
                else:
                    bp_result = bpm.match_unknown_functions(
                        binary_path=binary_for_byte_match,
                        functions_json=functions_json,
                        known_signatures=all_byte_sigs,
                    )
                    logger.info(
                        "FLIRT linear matcher: %d pattern, %.0fms scan",
                        len(all_byte_sigs),
                        (time.monotonic() - trie_start) * 1000.0,
                    )

                byte_pattern_names = self._process_bp_result(
                    bp_result=bp_result,
                    bpm=bpm,
                    ctx=ctx,
                )

        except ImportError:
            logger.debug("BytePatternMatcher bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("Byte pattern matching hatasi: %s", exc)
            ctx.errors.append(f"Byte pattern matching hatasi: {exc}")

        ctx.stats["timing_byte_pattern"] = round(
            time.monotonic() - step_start, 1,
        )
        return {
            "byte_pattern_result": bp_result,
            "byte_pattern_names": byte_pattern_names,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _trie_decision(*, pc: Any, sig_count: int) -> tuple[bool, int]:
        """v1.14 D2: trie path kullanilsin mi karari.

        Args:
            pc: pipeline_context (config flag'leri).
            sig_count: toplanan FLIRT imza sayisi.

        Returns:
            (use_trie, threshold) -- esik degerini de cikti olarak verir
            ki workspace JSON / log'a yazilabilsin.
        """
        cfg = pc.config.binary_reconstruction
        threshold = int(getattr(cfg, "flirt_trie_threshold", 50))
        use_trie_flag = bool(getattr(cfg, "flirt_use_trie", True))
        use_trie = use_trie_flag and sig_count > threshold
        return use_trie, threshold

    @staticmethod
    def _collect_flirt_signatures(*, pc: Any, binary_for_byte_match: Path) -> list[Any]:
        """FLIRT signature'larini homebrew + sigs/ + external + binary'den topla.

        stages.py L1373-1411 ile birebir ayni.
        """
        all_byte_sigs: list[Any] = []
        try:
            from karadul.analyzers.flirt_parser import FLIRTParser
            fp = FLIRTParser()

            project_root = pc.config.project_root

            # Byte pattern'li signature'lar (build_byte_signatures.py ciktisi)
            homebrew_bytes_sigs = project_root / "signatures_homebrew_bytes.json"
            if homebrew_bytes_sigs.exists():
                all_byte_sigs.extend(fp.load_json_signatures(homebrew_bytes_sigs))

            # NOT (perf denetimi 2026-07-13): signatures_homebrew.json (158K imza)
            # ve sigs/ .json'lari ISIM-tabanli, byte-pattern'leri YOK -> trie matcher
            # (byte_pattern>=16 filtresi) hepsini atiyordu (~8s + bellek bosa). Byte
            # matcher'a yalniz gercek byte-pattern'li kaynaklar girmeli: yukaridaki
            # homebrew_bytes.json + sigs/ altindaki .pat dosyalari.
            sigs_dir = project_root / "sigs"
            if sigs_dir.is_dir():
                for pat_file in sigs_dir.rglob("*.pat"):
                    all_byte_sigs.extend(fp.load_pat_file(pat_file))

            ext_paths = pc.config.binary_reconstruction.external_signature_paths
            for ext_path in ext_paths:
                p = Path(ext_path)
                if p.is_file() and p.suffix == ".json":
                    all_byte_sigs.extend(fp.load_json_signatures(p))
                elif p.is_file() and p.suffix == ".pat":
                    all_byte_sigs.extend(fp.load_pat_file(p))
                elif p.is_dir():
                    all_byte_sigs.extend(fp.load_directory(p))

            # Binary'den dogrudan symbol extraction (byte pattern'li).
            # Universal binary ise thin slice kullan (arch uyumu icin).
            binary_sigs = fp.extract_from_binary(binary_for_byte_match)
            all_byte_sigs.extend(binary_sigs)
        except Exception as exc:
            logger.debug("FLIRT signature toplama hatasi: %s", exc)

        return all_byte_sigs

    @staticmethod
    def _process_bp_result(*, bp_result: Any, bpm: Any, ctx: StepContext) -> dict[str, str]:
        """bp_result'i stats'a yaz, naming map olustur, artifact kaydet.

        stages.py L1419-1443 ile ayni davranis.
        """
        pc = ctx.pipeline_context
        byte_pattern_names: dict[str, str] = {}

        if bp_result.total_matched > 0:
            byte_pattern_names = bpm.to_naming_map(bp_result)
            ctx.stats["byte_pattern_matched"] = bp_result.total_matched
            ctx.stats["byte_pattern_total_unknown"] = bp_result.total_unknown
            ctx.stats["byte_pattern_match_rate"] = (
                f"{bp_result.match_rate:.1%}"
            )

            bp_path = pc.workspace.save_json(
                "reconstructed", "byte_pattern_matches",
                {
                    "total_matched": bp_result.total_matched,
                    "total_unknown": bp_result.total_unknown,
                    "match_rate": bp_result.match_rate,
                    "duration_seconds": bp_result.duration_seconds,
                    # v1.14 D2: hangi yol kullanildigi (linear / trie)
                    "flirt_match_strategy": ctx.stats.get(
                        "flirt_match_strategy", "linear",
                    ),
                    "flirt_signature_count": ctx.stats.get(
                        "flirt_signature_count", 0,
                    ),
                    "matches": bp_result.matches,
                },
            )
            ctx.produce_artifact("byte_pattern_matches", bp_path)
            logger.info(
                "Byte Pattern Matching: %d/%d FUN_xxx tanindi (%.1f%%)",
                bp_result.total_matched,
                bp_result.total_unknown,
                bp_result.match_rate * 100,
            )

        if bp_result.errors:
            ctx.errors.extend(bp_result.errors)

        return byte_pattern_names
