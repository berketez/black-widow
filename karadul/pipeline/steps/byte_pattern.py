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

FLIRT yükleme bug'ı (2026-09-25):
- FLIRT imzaları YALNIZ burada yüklenir ve sayılır; sayaçlar
  (``flirt_signatures_loaded`` vb.) 0 dahil her zaman yazılır. Eski
  StaticAnalysisStage sayacı eşleşmeye hiç girmeyen, bayt deseni olmayan
  2,46M isim imzasını sayıyordu.
- PIE ELF: Ghidra image base'i matcher'a verilir (``load_base``).
- Bilinen, bilinçli bekletilen: imza kökü yalnız ``config.project_root``;
  ``--output-dir`` ile imzalar bulunmaz (bkz. ``_collect_flirt_signatures``).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# Bayt desenli FLIRT kaynakları (config.project_root'a göre göreli).
_FLIRT_BYTES_FILE = "signatures_homebrew_bytes.json"
_FLIRT_SIGS_DIR = "sigs"


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

            load_start = time.monotonic()
            all_byte_sigs, sources = self._collect_flirt_signatures(
                pc=pc,
                binary_for_byte_match=binary_for_byte_match,
            )
            # Sayaçlar HER ZAMAN yazılır (0 dahil) ve eşleştiriciye verilen
            # listenin kendisinden hesaplanır (tek kaynak). Eşleştirici koşmazsa
            # eşleşme sayaçları 0 kalır; "koşmadı" bilgisi flirt_match_strategy
            # anahtarının yokluğundan okunur.
            ctx.stats["flirt_signatures_loaded"] = len(all_byte_sigs)
            ctx.stats["flirt_signature_sources"] = sources
            ctx.stats["flirt_load_seconds"] = round(time.monotonic() - load_start, 3)
            ctx.stats["flirt_signatures_matchable"] = 0
            ctx.stats["flirt_functions_scanned"] = 0
            ctx.stats["flirt_functions_named"] = 0

            if all_byte_sigs:
                load_base = self._ghidra_load_base(pc=pc, functions_json=functions_json)
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
                        load_base=load_base,
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
                        load_base=load_base,
                    )
                    logger.info(
                        "FLIRT linear matcher: %d pattern, %.0fms scan",
                        len(all_byte_sigs),
                        (time.monotonic() - trie_start) * 1000.0,
                    )

                # Eşleşme aşamasının gerçek sayaçları.
                ctx.stats["flirt_signatures_matchable"] = bp_result.signatures_considered
                ctx.stats["flirt_functions_scanned"] = bp_result.functions_scanned
                ctx.stats["flirt_functions_named"] = bp_result.total_matched

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
    def _collect_flirt_signatures(
        *, pc: Any, binary_for_byte_match: Path,
    ) -> tuple[list[Any], dict[str, int]]:
        """FLIRT imzalarını homebrew_bytes + sigs/*.pat + harici yollar + binary'den topla.

        Returns:
            (imza listesi, {kaynak dosya: imza sayısı}). Kaynak sözlüğü
            report.json'a yazılır; "hangi dosyadan kaç imza" sorusunun cevabı.
        """
        all_byte_sigs: list[Any] = []
        sources: dict[str, int] = {}

        def _add(source: Any, sigs: Any) -> None:
            sig_list = list(sigs)
            all_byte_sigs.extend(sig_list)
            sources[str(source)] = sources.get(str(source), 0) + len(sig_list)

        project_root = pc.config.project_root
        try:
            from karadul.analyzers.flirt_parser import FLIRTParser
            fp = FLIRTParser()

            # İmza kökü yalnız config.project_root (HEAD davranışı).
            # --output-dir project_root'u ezdiği için imzalar bulunmuyor (bilinen,
            # bilinçli bekletiliyor: imza DB'si seçici değil, redis-server 162/0
            # yanlış isim; veri kökü ayrıştırması ölçüm zemininde FLIRT +
            # ngram_name_db birlikte ele alınacak).

            # Byte pattern'li signature'lar (build_byte_signatures.py ciktisi)
            homebrew_bytes_sigs = project_root / _FLIRT_BYTES_FILE
            if homebrew_bytes_sigs.exists():
                _add(homebrew_bytes_sigs, fp.load_json_signatures(homebrew_bytes_sigs))

            # NOT (perf denetimi 2026-07-13): signatures_homebrew.json (158K imza)
            # ve sigs/ .json'lari ISIM-tabanli, byte-pattern'leri YOK -> trie matcher
            # (byte_pattern>=16 filtresi) hepsini atiyordu (~8s + bellek bosa). Byte
            # matcher'a yalniz gercek byte-pattern'li kaynaklar girmeli: yukaridaki
            # homebrew_bytes.json + sigs/ altindaki .pat dosyalari.
            sigs_dir = project_root / _FLIRT_SIGS_DIR
            if sigs_dir.is_dir():
                for pat_file in sorted(sigs_dir.rglob("*.pat")):
                    _add(pat_file, fp.load_pat_file(pat_file))

            ext_paths = pc.config.binary_reconstruction.external_signature_paths
            for ext_path in ext_paths:
                p = Path(ext_path)
                if p.is_file() and p.suffix == ".json":
                    _add(p, fp.load_json_signatures(p))
                elif p.is_file() and p.suffix == ".pat":
                    _add(p, fp.load_pat_file(p))
                elif p.is_dir():
                    _add(p, fp.load_directory(p))

            # Binary'den dogrudan symbol extraction (byte pattern'li).
            # Universal binary ise thin slice kullan (arch uyumu icin).
            _add(binary_for_byte_match, fp.extract_from_binary(binary_for_byte_match))
        except Exception as exc:
            logger.debug("FLIRT signature toplama hatasi: %s", exc)

        logger.info(
            "FLIRT: %d imza yüklendi (project_root=%s; %s)",
            len(all_byte_sigs),
            project_root,
            ", ".join(f"{Path(k).name}={v}" for k, v in sources.items()) or "kaynak yok",
        )
        return all_byte_sigs, sources

    @staticmethod
    def _ghidra_load_base(*, pc: Any, functions_json: Any) -> Optional[int]:
        """Ghidra program image base'ini oku (``program_info.image_base``).

        Ghidra export'u bunu ``static/ghidra_combined_results.json`` içine
        yazar. PIE ELF'te matcher'ın dosya ofsetini doğru hesaplaması için
        gerekir (bkz. BytePatternMatcher._get_text_segment_info). Bulunamazsa
        None: matcher eski davranışla (kayma 0) devam eder.
        """
        candidates: list[Path] = []
        try:
            static_dir = pc.workspace.get_stage_dir("static")
            if isinstance(static_dir, (str, os.PathLike)):
                candidates.append(Path(static_dir) / "ghidra_combined_results.json")
                candidates.append(
                    Path(static_dir) / "ghidra_output" / "combined_results.json",
                )
        except Exception:
            logger.debug("FLIRT: static dizini alınamadı", exc_info=True)
        if isinstance(functions_json, (str, os.PathLike)):
            candidates.append(Path(functions_json).parent / "ghidra_combined_results.json")

        for path in candidates:
            try:
                if not path.is_file():
                    continue
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                info = data.get("program_info") or (data.get("summary") or {}).get("program") or {}
                raw = info.get("image_base")
                if raw:
                    return int(str(raw), 16)
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        return None

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
