#!/usr/bin/env python3
"""Steam binary reconstruct pipeline -- mevcut Ghidra ciktilari uzerinde.

Ghidra TEKRAR calistirilmaz. Mevcut JSON'lar ve decompiled .c dosyalari
uzerinde tam reconstruction pipeline uygulanir:

1. Algorithm Identification (constant + structural + API tarama)
2. Binary Name Extraction (debug strings, RTTI, build paths, enums)
3. C Variable/Function Naming (6 katmanli strateji)
4. Name Merger (birden fazla kaynaktan gelen isimleri birlestir)
5. Type Recovery (struct, enum, vtable sentezi)
6. Comment Generation (header, syscall, vuln, algorithm, control flow)

Kullanim:
    cd /Users/apple/Desktop/black-widow
    python scripts/steam_reconstruct.py
"""

import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Proje root'u ayarla
PROJECT_ROOT = Path(__file__).parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("steam_reconstruct")

# ---------------------------------------------------------------
# Path tanimlari -- mevcut Ghidra ciktilari
# ---------------------------------------------------------------
WORKSPACE = Path("workspaces/steam_osx/steam_osx/20260323_111359")
GHIDRA_OUTPUT = WORKSPACE / "static" / "ghidra_output"

FUNCTIONS_JSON = GHIDRA_OUTPUT / "functions.json"
STRINGS_JSON = GHIDRA_OUTPUT / "strings.json"
CALL_GRAPH_JSON = GHIDRA_OUTPUT / "call_graph.json"
TYPES_JSON = GHIDRA_OUTPUT / "types.json"
DECOMPILED_DIR = GHIDRA_OUTPUT / "decompiled"

# Reconstruction cikti dizinleri
RECONSTRUCTED_DIR = WORKSPACE / "reconstructed"
REPORT_PATH = Path("workspaces/steam_analysis_reconstruct.json")


def validate_inputs() -> bool:
    """Gerekli dosyalarin varligini kontrol et."""
    missing = []
    for p in [FUNCTIONS_JSON, STRINGS_JSON, CALL_GRAPH_JSON, DECOMPILED_DIR]:
        if not p.exists():
            missing.append(str(p))
    if missing:
        logger.error("Eksik dosyalar: %s", missing)
        return False

    c_count = len(list(DECOMPILED_DIR.glob("*.c")))
    logger.info(
        "Girdi dogrulandi: functions.json=%s, strings.json=%s, "
        "call_graph.json=%s, decompiled=%d .c dosyasi",
        FUNCTIONS_JSON.exists(), STRINGS_JSON.exists(),
        CALL_GRAPH_JSON.exists(), c_count,
    )
    return True


def step_algorithm_id(cfg: Config, results: dict) -> object:
    """Adim 1: Algorithm Identification."""
    logger.info("=" * 60)
    logger.info("ADIM 1: Algorithm Identification")
    logger.info("=" * 60)
    t0 = time.monotonic()

    try:
        from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier
        algo_id = CAlgorithmIdentifier(cfg)
        algo_result = algo_id.identify(
            DECOMPILED_DIR, FUNCTIONS_JSON, STRINGS_JSON,
        )
        dt = time.monotonic() - t0

        if algo_result.success:
            results["algorithms"] = {
                "total_detected": algo_result.total_detected,
                "by_category": algo_result.by_category,
                "duration_s": round(dt, 2),
                "top_algorithms": [
                    {
                        "name": a.name,
                        "category": a.category,
                        "confidence": a.confidence,
                        "function": a.function_name,
                        "evidence": a.evidence[:200],
                    }
                    for a in sorted(
                        algo_result.algorithms,
                        key=lambda x: x.confidence, reverse=True,
                    )[:50]
                ],
            }
            logger.info(
                "Algorithm ID tamamlandi: %d tespit, %.1fs",
                algo_result.total_detected, dt,
            )
        else:
            results["algorithms"] = {"error": "Basarisiz", "duration_s": round(dt, 2)}
            logger.warning("Algorithm ID basarisiz")

        return algo_result
    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("Algorithm ID hatasi: %s", exc, exc_info=True)
        results["algorithms"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return None


def step_binary_name_extraction(cfg: Config, results: dict) -> dict:
    """Adim 2: Binary Name Extraction."""
    logger.info("=" * 60)
    logger.info("ADIM 2: Binary Name Extraction (debug strings, RTTI, enums)")
    logger.info("=" * 60)
    t0 = time.monotonic()

    try:
        from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor
        extractor = BinaryNameExtractor(cfg)
        extract_result = extractor.extract(
            strings_json=STRINGS_JSON,
            functions_json=FUNCTIONS_JSON,
            call_graph_json=CALL_GRAPH_JSON,
        )
        dt = time.monotonic() - t0

        extracted_names = {}
        if extract_result.success and extract_result.names:
            extracted_names = {
                n.original_name: n.recovered_name
                for n in extract_result.names
            }

            # Confidence dagilimi
            high = sum(1 for n in extract_result.names if n.confidence >= 0.7)
            med = sum(1 for n in extract_result.names if 0.4 <= n.confidence < 0.7)
            low = sum(1 for n in extract_result.names if n.confidence < 0.4)

            results["binary_name_extraction"] = {
                "total_extracted": len(extracted_names),
                "classes_detected": len(extract_result.class_methods),
                "source_files_detected": len(extract_result.source_files),
                "by_source": dict(extract_result.by_source),
                "confidence_distribution": {
                    "high_gte_0.7": high,
                    "medium_0.4_0.7": med,
                    "low_lt_0.4": low,
                },
                "duration_s": round(dt, 2),
                "sample_names": [
                    {
                        "original": n.original_name,
                        "recovered": n.recovered_name,
                        "source": n.source,
                        "confidence": n.confidence,
                        "class": n.class_name,
                    }
                    for n in sorted(
                        extract_result.names,
                        key=lambda x: x.confidence, reverse=True,
                    )[:30]
                ],
            }
            logger.info(
                "Binary Name Extraction: %d isim, %d class, %.1fs",
                len(extracted_names), len(extract_result.class_methods), dt,
            )
        else:
            results["binary_name_extraction"] = {
                "total_extracted": 0,
                "duration_s": round(dt, 2),
                "errors": extract_result.errors,
            }
            logger.warning("Binary Name Extraction: hic isim kurtarilamadi")

        return extracted_names
    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("Binary Name Extraction hatasi: %s", exc, exc_info=True)
        results["binary_name_extraction"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return {}


def step_c_naming(cfg: Config, results: dict, extracted_names: dict) -> object:
    """Adim 3: C Variable/Function Naming."""
    logger.info("=" * 60)
    logger.info("ADIM 3: C Variable/Function Naming (6 strateji)")
    logger.info("=" * 60)
    t0 = time.monotonic()

    output_dir = RECONSTRUCTED_DIR / "src"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        from karadul.reconstruction.c_namer import CVariableNamer
        namer = CVariableNamer(cfg)
        naming_result = namer.analyze_and_rename(
            decompiled_dir=DECOMPILED_DIR,
            functions_json=FUNCTIONS_JSON,
            strings_json=STRINGS_JSON,
            call_graph_json=CALL_GRAPH_JSON,
            output_dir=output_dir,
            pre_names=extracted_names or None,
        )
        dt = time.monotonic() - t0

        if naming_result.success:
            results["c_naming"] = {
                "total_renamed": naming_result.total_renamed,
                "by_strategy": naming_result.by_strategy,
                "high_confidence": naming_result.high_confidence,
                "medium_confidence": naming_result.medium_confidence,
                "low_confidence": naming_result.low_confidence,
                "output_files_count": len(naming_result.output_files),
                "duration_s": round(dt, 2),
            }
            logger.info(
                "C Naming: %d renamed (high=%d, med=%d, low=%d), %.1fs",
                naming_result.total_renamed,
                naming_result.high_confidence,
                naming_result.medium_confidence,
                naming_result.low_confidence,
                dt,
            )
        else:
            results["c_naming"] = {
                "total_renamed": 0,
                "errors": naming_result.errors,
                "duration_s": round(dt, 2),
            }
            logger.warning("C Naming basarisiz: %s", naming_result.errors)

        return naming_result
    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("C Naming hatasi: %s", exc, exc_info=True)
        results["c_naming"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return None


def step_name_merger(
    cfg: Config, results: dict,
    extracted_names: dict, naming_result: object,
    current_source_dir: Path,
) -> Path:
    """Adim 4: Name Merger -- birden fazla kaynaktan gelen isimleri birlestir."""
    logger.info("=" * 60)
    logger.info("ADIM 4: Name Merger")
    logger.info("=" * 60)
    t0 = time.monotonic()

    try:
        from karadul.reconstruction.name_merger import NameMerger, NamingCandidate

        merger = NameMerger(
            min_confidence=cfg.binary_reconstruction.min_naming_confidence,
        )
        candidates_by_symbol: dict[str, list] = {}

        # Binary name extractor sonuclari
        for old_name, new_name in extracted_names.items():
            if not old_name or len(old_name) < 2 or not new_name:
                continue
            candidates_by_symbol.setdefault(old_name, []).append(
                NamingCandidate(new_name, 0.85, "binary_extractor")
            )

        # C namer sonuclari
        if naming_result is not None and hasattr(naming_result, "naming_map"):
            for old_name, new_name in naming_result.naming_map.items():
                if not old_name or len(old_name) < 2 or not new_name:
                    continue
                candidates_by_symbol.setdefault(old_name, []).append(
                    NamingCandidate(new_name, 0.70, "c_namer")
                )

        if not candidates_by_symbol:
            dt = time.monotonic() - t0
            results["name_merger"] = {
                "total_merged": 0,
                "note": "Birlestirilecek aday yok",
                "duration_s": round(dt, 2),
            }
            logger.info("Name Merger: birlestirilecek aday yok")
            return current_source_dir

        merge_result = merger.merge(candidates_by_symbol)
        final_naming_map = merger.to_naming_map(merge_result)

        # Bos/kisa key'leri filtrele
        final_naming_map = {
            k: v for k, v in final_naming_map.items()
            if k and len(k) >= 2 and v
        }

        merge_dir = RECONSTRUCTED_DIR / "merged"
        merge_dir.mkdir(parents=True, exist_ok=True)

        applied_count = 0
        if final_naming_map:
            sorted_names = sorted(final_naming_map.keys(), key=len, reverse=True)
            merged_re = re.compile(
                r"\b(" + "|".join(re.escape(n) for n in sorted_names) + r")\b"
            )
            for c_file in sorted(current_source_dir.rglob("*.c")):
                content = c_file.read_text(encoding="utf-8", errors="replace")
                new_content = merged_re.sub(
                    lambda m: final_naming_map[m.group(0)], content,
                )
                (merge_dir / c_file.name).write_text(new_content, encoding="utf-8")
                if content != new_content:
                    applied_count += 1

        dt = time.monotonic() - t0
        results["name_merger"] = {
            "total_candidates": len(candidates_by_symbol),
            "total_merged": merge_result.total_merged,
            "exact_multi_matches": merge_result.exact_multi_matches,
            "conflicts_resolved": merge_result.conflicts_resolved,
            "partial_matches": merge_result.partial_matches,
            "voting_wins": merge_result.voting_wins,
            "final_naming_map_size": len(final_naming_map),
            "files_modified": applied_count,
            "duration_s": round(dt, 2),
        }
        logger.info(
            "Name Merger: %d merged, %d dosyaya uygulandi, %.1fs",
            merge_result.total_merged, applied_count, dt,
        )

        if applied_count > 0:
            return merge_dir
        return current_source_dir

    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("Name Merger hatasi: %s", exc, exc_info=True)
        results["name_merger"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return current_source_dir


def step_type_recovery(cfg: Config, results: dict, current_source_dir: Path) -> Path:
    """Adim 5: Type Recovery."""
    logger.info("=" * 60)
    logger.info("ADIM 5: Type Recovery (struct, enum, vtable)")
    logger.info("=" * 60)
    t0 = time.monotonic()

    type_dir = RECONSTRUCTED_DIR / "typed"
    type_dir.mkdir(parents=True, exist_ok=True)

    try:
        from karadul.reconstruction.c_type_recoverer import CTypeRecoverer
        type_rec = CTypeRecoverer(cfg)
        type_result = type_rec.recover(
            decompiled_dir=current_source_dir,
            functions_json=FUNCTIONS_JSON,
            output_dir=type_dir,
            strings_json=STRINGS_JSON,
            ghidra_types_json=TYPES_JSON if TYPES_JSON.exists() else None,
        )
        dt = time.monotonic() - t0

        if type_result.success:
            results["type_recovery"] = {
                "structs_recovered": len(type_result.structs),
                "enums_recovered": len(type_result.enums),
                "vtables_recovered": len(type_result.vtables) if hasattr(type_result, 'vtables') else 0,
                "total_types_recovered": type_result.total_types_recovered,
                "type_replacements": len(type_result.type_replacements) if hasattr(type_result, 'type_replacements') else 0,
                "output_files": len(type_result.output_files),
                "types_header": str(type_result.types_header) if type_result.types_header else None,
                "duration_s": round(dt, 2),
                "sample_structs": [
                    {
                        "name": s.name,
                        "total_size": s.total_size,
                        "fields_count": len(s.fields),
                        "source_functions_count": len(s.source_functions),
                    }
                    for s in (type_result.structs[:20] if type_result.structs else [])
                ],
                "sample_enums": [
                    {
                        "name": e.name,
                        "values_count": len(e.values),
                        "source_functions_count": len(e.source_functions),
                    }
                    for e in (type_result.enums[:20] if type_result.enums else [])
                ],
            }
            logger.info(
                "Type Recovery: %d struct, %d enum, %d vtable, %.1fs",
                len(type_result.structs), len(type_result.enums),
                len(type_result.vtables) if hasattr(type_result, 'vtables') else 0, dt,
            )
            if type_result.output_files:
                return type_dir
        else:
            results["type_recovery"] = {
                "errors": type_result.errors,
                "duration_s": round(dt, 2),
            }
            logger.warning("Type Recovery basarisiz: %s", type_result.errors)

        return current_source_dir
    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("Type Recovery hatasi: %s", exc, exc_info=True)
        results["type_recovery"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return current_source_dir


def step_comment_generation(
    cfg: Config, results: dict,
    current_source_dir: Path, algo_result: object,
) -> Path:
    """Adim 6: Comment Generation."""
    logger.info("=" * 60)
    logger.info("ADIM 6: Comment Generation")
    logger.info("=" * 60)
    t0 = time.monotonic()

    comment_dir = RECONSTRUCTED_DIR / "commented"
    comment_dir.mkdir(parents=True, exist_ok=True)

    try:
        from karadul.reconstruction.c_comment_generator import CCommentGenerator
        commenter = CCommentGenerator(cfg)
        comment_result = commenter.generate(
            decompiled_dir=current_source_dir,
            output_dir=comment_dir,
            functions_json=FUNCTIONS_JSON,
            strings_json=STRINGS_JSON,
            call_graph_json=CALL_GRAPH_JSON,
            algorithm_results=(
                algo_result.algorithms if algo_result and hasattr(algo_result, 'algorithms') else None
            ),
        )
        dt = time.monotonic() - t0

        if comment_result.success:
            results["comment_generation"] = {
                "total_comments_added": comment_result.total_comments_added,
                "function_headers": comment_result.function_headers,
                "syscall_annotations": comment_result.syscall_annotations,
                "vulnerability_warnings": comment_result.vulnerability_warnings,
                "algorithm_labels": comment_result.algorithm_labels,
                "control_flow_annotations": comment_result.control_flow_annotations,
                "output_files": len(comment_result.output_files),
                "duration_s": round(dt, 2),
            }
            logger.info(
                "Comments: %d yorum (%d header, %d syscall, %d vuln, %d algo, %d control), %.1fs",
                comment_result.total_comments_added,
                comment_result.function_headers,
                comment_result.syscall_annotations,
                comment_result.vulnerability_warnings,
                comment_result.algorithm_labels,
                comment_result.control_flow_annotations,
                dt,
            )
            if comment_result.output_files:
                return comment_dir
        else:
            results["comment_generation"] = {
                "errors": comment_result.errors,
                "duration_s": round(dt, 2),
            }
            logger.warning("Comment generation basarisiz")

        return current_source_dir
    except Exception as exc:
        dt = time.monotonic() - t0
        logger.error("Comment Generation hatasi: %s", exc, exc_info=True)
        results["comment_generation"] = {"error": str(exc), "duration_s": round(dt, 2)}
        return current_source_dir


def compute_final_stats(results: dict, final_source_dir: Path) -> dict:
    """Final istatistikleri hesapla."""
    logger.info("=" * 60)
    logger.info("FINAL ISTATISTIKLER")
    logger.info("=" * 60)

    # functions.json'dan toplam fonksiyon sayisini al
    total_functions = 0
    fun_xxx_original = 0
    try:
        with open(FUNCTIONS_JSON) as f:
            data = json.load(f)
        funcs = data.get("functions", data) if isinstance(data, dict) else data
        total_functions = len(funcs)
        fun_xxx_original = sum(
            1 for fn in funcs if fn.get("name", "").startswith("FUN_")
        )
    except Exception as exc:
        logger.warning("functions.json okunamadi: %s", exc)

    # Final C dosyalarinda kalan FUN_xxx sayisini say
    fun_xxx_remaining = 0
    named_functions = 0
    c_files = sorted(final_source_dir.rglob("*.c")) if final_source_dir.exists() else []

    fun_xxx_pattern = re.compile(r'\bFUN_[0-9a-fA-F]+\b')
    seen_fun_xxx = set()

    for c_file in c_files:
        try:
            content = c_file.read_text(encoding="utf-8", errors="replace")
            matches = fun_xxx_pattern.findall(content)
            seen_fun_xxx.update(matches)
        except Exception:
            pass

    fun_xxx_remaining = len(seen_fun_xxx)
    named_functions = fun_xxx_original - fun_xxx_remaining
    if named_functions < 0:
        named_functions = 0  # Yeni FUN_xxx'ler referanslarda gorunmus olabilir

    stats = {
        "total_functions_in_binary": total_functions,
        "fun_xxx_original_count": fun_xxx_original,
        "fun_xxx_remaining_count": fun_xxx_remaining,
        "functions_named": named_functions,
        "naming_rate_percent": round(
            (named_functions / fun_xxx_original * 100) if fun_xxx_original > 0 else 0, 2,
        ),
        "final_output_dir": str(final_source_dir),
        "final_c_files": len(c_files),
    }

    logger.info("Toplam fonksiyon: %d", total_functions)
    logger.info("Orijinal FUN_xxx: %d", fun_xxx_original)
    logger.info("Kalan FUN_xxx: %d", fun_xxx_remaining)
    logger.info("Isimlendirilen: %d (%%%.1f)", named_functions, stats["naming_rate_percent"])
    logger.info("Final C dosya sayisi: %d", len(c_files))

    return stats


def main():
    """Ana pipeline."""
    total_start = time.monotonic()

    logger.info("=" * 60)
    logger.info("STEAM BINARY RECONSTRUCT PIPELINE")
    logger.info("Workspace: %s", WORKSPACE)
    logger.info("=" * 60)

    # Girdi dogrulama
    if not validate_inputs():
        sys.exit(1)

    cfg = Config()
    results = {
        "pipeline": "steam_reconstruct",
        "workspace": str(WORKSPACE),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    # Reconstructed dizinlerini olustur
    RECONSTRUCTED_DIR.mkdir(parents=True, exist_ok=True)

    # Adim 1 & 2: Algorithm ID + Binary Name Extraction (PARALEL)
    logger.info("Adim 1 & 2 paralel baslatiliyor...")
    algo_result = None
    extracted_names = {}

    def _run_algo():
        nonlocal algo_result
        algo_result = step_algorithm_id(cfg, results)

    def _run_extraction():
        nonlocal extracted_names
        extracted_names = step_binary_name_extraction(cfg, results)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_run_algo)
        f2 = pool.submit(_run_extraction)
        f1.result()
        f2.result()

    # Adim 3: C Naming
    naming_result = step_c_naming(cfg, results, extracted_names)

    # Kaynak dizini takip et -- her adim bir onceki adimin ciktisini alir
    current_source_dir = RECONSTRUCTED_DIR / "src"
    if not any(current_source_dir.rglob("*.c")):
        # src bos ise orijinal decompiled'i kullan
        current_source_dir = DECOMPILED_DIR

    # Adim 4: Name Merger
    current_source_dir = step_name_merger(
        cfg, results, extracted_names, naming_result, current_source_dir,
    )

    # Adim 5: Type Recovery
    current_source_dir = step_type_recovery(cfg, results, current_source_dir)

    # Adim 6: Comment Generation
    current_source_dir = step_comment_generation(
        cfg, results, current_source_dir, algo_result,
    )

    # Final istatistikler
    final_stats = compute_final_stats(results, current_source_dir)
    results["final_stats"] = final_stats

    total_dt = time.monotonic() - total_start
    results["total_duration_s"] = round(total_dt, 2)

    # Raporu kaydet
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)

    logger.info("=" * 60)
    logger.info("PIPELINE TAMAMLANDI: %.1fs", total_dt)
    logger.info("Rapor: %s", REPORT_PATH)
    logger.info("=" * 60)

    return results


if __name__ == "__main__":
    main()
