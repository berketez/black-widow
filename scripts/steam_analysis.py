#!/usr/bin/env python3
"""Steam binary full pipeline analysis (Ghidra-optional).

Bu script Steam binary'sini karadul pipeline ile analiz eder.
Ghidra cok uzun surerse (>2 saat) timeout olur, diger analizler yine calisir.

Kullanim:
    python scripts/steam_analysis.py
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

# Proje root'u ayarla
PROJECT_ROOT = Path(__file__).parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.config import Config
from karadul.core.target import TargetDetector, TargetInfo
from karadul.core.workspace import Workspace
from karadul.core.subprocess_runner import SubprocessRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("steam_analysis")

# ---------------------------------------------------------------
# Steam binary path
# ---------------------------------------------------------------
STEAM_BINARY = Path("/Applications/Steam.app/Contents/MacOS/steam_osx")
REPORT_PATH = PROJECT_ROOT / "workspaces" / "steam_analysis_report.json"


def run_target_detection(binary_path: Path) -> TargetInfo:
    """Hedef dosyayi tani."""
    detector = TargetDetector()
    info = detector.detect(binary_path)
    logger.info(
        "Target detected: %s | Type: %s | Language: %s | Size: %d bytes",
        info.name, info.target_type.value, info.language.value, info.file_size,
    )
    return info


def run_strings_extraction(binary_path: Path, config: Config) -> dict:
    """strings komutu ile string cikarma."""
    logger.info("=== STRINGS EXTRACTION ===")
    start = time.monotonic()
    runner = SubprocessRunner(config)
    string_list = runner.run_strings(binary_path)
    duration = time.monotonic() - start

    if string_list:
        logger.info("Strings: %d string bulundu (%.1fs)", len(string_list), duration)
        # Uzunluga gore kategorize et
        short = sum(1 for s in string_list if len(s) < 10)
        medium = sum(1 for s in string_list if 10 <= len(s) < 50)
        long_ = sum(1 for s in string_list if len(s) >= 50)

        # Ilginc pattern'leri bul
        urls = [s for s in string_list if "http" in s.lower()]
        file_paths = [s for s in string_list if "/" in s and len(s) > 5]
        error_msgs = [s for s in string_list if "error" in s.lower() or "fail" in s.lower()]
        crypto_strings = [s for s in string_list if any(
            kw in s.lower() for kw in ["aes", "rsa", "sha", "ssl", "tls", "cert", "key", "encrypt", "decrypt"]
        )]

        return {
            "total": len(string_list),
            "short_lt10": short,
            "medium_10_50": medium,
            "long_gt50": long_,
            "urls_found": len(urls),
            "file_paths_found": len(file_paths),
            "error_messages_found": len(error_msgs),
            "crypto_related": len(crypto_strings),
            "sample_urls": urls[:20],
            "sample_crypto": crypto_strings[:20],
            "sample_errors": error_msgs[:20],
            "duration_s": round(duration, 2),
        }
    return {"total": 0, "duration_s": round(duration, 2)}


def run_nm_symbols(binary_path: Path, config: Config) -> dict:
    """nm ile symbol table cikarma."""
    logger.info("=== NM SYMBOL EXTRACTION ===")
    start = time.monotonic()
    runner = SubprocessRunner(config)
    result = runner.run_command(
        ["nm", "-g", str(binary_path)],
        timeout=120,
    )
    duration = time.monotonic() - start

    symbols = {"defined": [], "undefined": [], "total": 0}
    if result.success:
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                symbols["defined"].append({
                    "address": parts[0],
                    "type": parts[1],
                    "name": parts[2],
                })
            elif len(parts) == 2:
                symbols["undefined"].append({
                    "type": parts[0],
                    "name": parts[1],
                })

        symbols["total"] = len(symbols["defined"]) + len(symbols["undefined"])
        logger.info(
            "nm: %d defined, %d undefined symbols (%.1fs)",
            len(symbols["defined"]), len(symbols["undefined"]), duration,
        )

        # Symbol type breakdown
        type_counts = {}
        for sym in symbols["defined"]:
            t = sym["type"]
            type_counts[t] = type_counts.get(t, 0) + 1
        symbols["type_breakdown"] = type_counts
    else:
        logger.warning("nm basarisiz: %s", result.stderr[:200] if result.stderr else "unknown")
        symbols["error"] = result.stderr[:500] if result.stderr else "nm failed"

    symbols["duration_s"] = round(duration, 2)
    return symbols


def run_otool_analysis(binary_path: Path, config: Config) -> dict:
    """otool ile dynamic libraries ve load commands."""
    logger.info("=== OTOOL ANALYSIS ===")
    start = time.monotonic()
    runner = SubprocessRunner(config)

    # Dynamic libraries
    otool_l = runner.run_otool(binary_path, flags=["-L"])
    libraries = []
    if otool_l:
        for line in otool_l.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" (")
            if parts:
                lib_path = parts[0].strip()
                version_info = parts[1].rstrip(")") if len(parts) > 1 else ""
                libraries.append({
                    "path": lib_path,
                    "version_info": version_info,
                })

    # Load commands
    otool_load = runner.run_otool(binary_path, flags=["-l"])
    segment_count = 0
    section_count = 0
    if otool_load:
        segment_count = otool_load.count("cmd LC_SEGMENT")
        section_count = otool_load.count("sectname")

    duration = time.monotonic() - start
    logger.info(
        "otool: %d dylibs, %d segments, %d sections (%.1fs)",
        len(libraries), segment_count, section_count, duration,
    )

    return {
        "dylib_count": len(libraries),
        "libraries": libraries,
        "segment_count": segment_count,
        "section_count": section_count,
        "duration_s": round(duration, 2),
    }


def run_yara_scan(binary_path: Path) -> dict:
    """YARA kurallar ile binary tarama."""
    logger.info("=== YARA SCAN ===")
    start = time.monotonic()

    try:
        from karadul.analyzers.yara_scanner import YaraScanner
        scanner = YaraScanner()
        scanner.load_builtin_rules()
        yara_result = scanner.scan_file(binary_path)
        duration = time.monotonic() - start

        matches_data = []
        for m in yara_result.matches:
            matches_data.append({
                "rule": m.rule,
                "tags": m.tags,
                "meta": m.meta,
                "namespace": m.namespace,
            })

        logger.info(
            "YARA: %d kural eslesti / %d toplam kural, backend: %s (%.1fs)",
            len(yara_result.matches), yara_result.total_rules,
            yara_result.backend, duration,
        )

        # Kategorize et
        categories = {}
        for m in yara_result.matches:
            for tag in m.tags:
                categories.setdefault(tag, []).append(m.rule)
            if not m.tags:
                categories.setdefault("untagged", []).append(m.rule)

        return {
            "total_rules": yara_result.total_rules,
            "matched_count": len(yara_result.matches),
            "matches": matches_data,
            "categories": categories,
            "backend": yara_result.backend,
            "scan_time_ms": round(yara_result.scan_time_ms, 2),
            "duration_s": round(duration, 2),
        }

    except Exception as exc:
        duration = time.monotonic() - start
        logger.error("YARA scan hatasi: %s", exc)
        return {"error": str(exc), "duration_s": round(duration, 2)}


def run_flirt_matching(binary_path: Path, config: Config) -> dict:
    """FLIRT signature eslestirme."""
    logger.info("=== FLIRT MATCHING ===")
    start = time.monotonic()

    try:
        from karadul.analyzers.flirt_parser import FLIRTParser

        fp = FLIRTParser()
        all_sigs = []

        # 1. Homebrew signatures
        homebrew_sigs_path = PROJECT_ROOT / "signatures_homebrew.json"
        if homebrew_sigs_path.exists():
            sigs = fp.load_json_signatures(homebrew_sigs_path)
            all_sigs.extend(sigs)
            logger.info("FLIRT: Homebrew sigs: %d", len(sigs))

        # 2. macOS framework signatures (sigs/ dizini)
        sigs_dir = PROJECT_ROOT / "sigs"
        if sigs_dir.is_dir():
            sigs = fp.load_directory(sigs_dir)
            all_sigs.extend(sigs)
            logger.info("FLIRT: sigs/ dizini: %d", len(sigs))

        # 3. sigs_macos_system.json
        macos_sigs_path = PROJECT_ROOT / "sigs_macos_system.json"
        if macos_sigs_path.exists():
            sigs = fp.load_json_signatures(macos_sigs_path)
            all_sigs.extend(sigs)
            logger.info("FLIRT: macOS system sigs: %d", len(sigs))

        # 4. Binary'den dogrudan symbol extraction
        binary_sigs = fp.extract_from_binary(binary_path)
        all_sigs.extend(binary_sigs)
        logger.info("FLIRT: Binary export sigs: %d", len(binary_sigs))

        # Library breakdown
        lib_counts = {}
        for sig in all_sigs:
            lib = sig.library if hasattr(sig, "library") else "unknown"
            lib_counts[lib] = lib_counts.get(lib, 0) + 1

        duration = time.monotonic() - start
        logger.info(
            "FLIRT: Total %d signatures loaded from %d libraries (%.1fs)",
            len(all_sigs), len(lib_counts), duration,
        )

        return {
            "total_signatures_loaded": len(all_sigs),
            "binary_export_symbols": len(binary_sigs),
            "db_signatures": len(all_sigs) - len(binary_sigs),
            "library_breakdown": dict(sorted(lib_counts.items(), key=lambda x: -x[1])[:30]),
            "total_libraries": len(lib_counts),
            "duration_s": round(duration, 2),
        }

    except Exception as exc:
        duration = time.monotonic() - start
        logger.error("FLIRT matching hatasi: %s", exc)
        return {"error": str(exc), "duration_s": round(duration, 2)}


def run_signature_db_matching(binary_path: Path, config: Config) -> dict:
    """SignatureDB ile bilinen fonksiyon symbol eslestirme.

    SignatureDB.match_function() kullanarak nm'den gelen symbol isimlerini
    builtin veritabaniyla eslestirir.
    """
    logger.info("=== SIGNATURE DB MATCHING ===")
    start = time.monotonic()

    try:
        from karadul.analyzers.signature_db import SignatureDB

        db = SignatureDB()

        # nm symbols'dan eslestirme
        runner = SubprocessRunner(config)
        result = runner.run_command(
            ["nm", "-g", str(binary_path)],
            timeout=120,
        )

        matched = []
        unmatched = []

        if result.success:
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 2)
                sym_name = ""
                if len(parts) == 3:
                    sym_name = parts[2]
                elif len(parts) == 2:
                    sym_name = parts[1]

                if sym_name:
                    match_result = db.match_function(sym_name)
                    if match_result is not None:
                        matched.append({
                            "symbol": sym_name,
                            "matched_name": match_result.matched_name,
                            "library": match_result.library,
                            "category": match_result.category,
                            "confidence": match_result.confidence,
                            "match_method": match_result.match_method,
                        })
                    else:
                        unmatched.append(sym_name)

        duration = time.monotonic() - start
        logger.info(
            "SignatureDB: %d matched, %d unmatched (%.1fs)",
            len(matched), len(unmatched), duration,
        )

        # Match kategorileri
        match_categories = {}
        for m in matched:
            cat = m.get("library", m.get("category", "unknown"))
            match_categories.setdefault(cat, []).append(m["symbol"])

        return {
            "total_symbols": len(matched) + len(unmatched),
            "matched": len(matched),
            "unmatched": len(unmatched),
            "match_rate_percent": round(len(matched) / max(1, len(matched) + len(unmatched)) * 100, 1),
            "match_categories": {k: len(v) for k, v in match_categories.items()},
            "sample_matched": [
                {"symbol": m["symbol"], "matched_name": m["matched_name"],
                 "library": m["library"], "confidence": m["confidence"]}
                for m in matched[:30]
            ],
            "sample_unmatched": unmatched[:30],
            "duration_s": round(duration, 2),
        }

    except Exception as exc:
        duration = time.monotonic() - start
        logger.error("SignatureDB hatasi: %s", exc)
        return {"error": str(exc), "duration_s": round(duration, 2)}


def run_lief_analysis(binary_path: Path) -> dict:
    """lief ile Mach-O header analizi."""
    logger.info("=== LIEF ANALYSIS ===")
    start = time.monotonic()

    try:
        import lief
        binary = lief.parse(str(binary_path))
        if binary is None:
            return {"error": "lief could not parse binary"}

        result = {
            "format": str(binary.format),
            "segments": [],
            "sections": [],
            "libraries": [],
        }

        if hasattr(binary, "header"):
            h = binary.header
            result["header"] = {
                "magic": str(h.magic) if hasattr(h, "magic") else None,
                "cpu_type": str(h.cpu_type) if hasattr(h, "cpu_type") else None,
                "file_type": str(h.file_type) if hasattr(h, "file_type") else None,
                "flags": int(h.flags) if hasattr(h, "flags") else None,
            }

        if hasattr(binary, "segments"):
            for seg in binary.segments:
                result["segments"].append({
                    "name": seg.name,
                    "virtual_address": hex(seg.virtual_address),
                    "virtual_size": seg.virtual_size,
                    "file_offset": seg.file_offset,
                    "file_size": seg.file_size,
                })

        if hasattr(binary, "sections"):
            for sec in binary.sections:
                result["sections"].append({
                    "name": sec.name,
                    "segment": sec.segment.name if hasattr(sec, "segment") and sec.segment else None,
                    "size": sec.size,
                    "offset": sec.offset,
                })

        if hasattr(binary, "libraries"):
            for lib in binary.libraries:
                result["libraries"].append(str(lib.name))

        duration = time.monotonic() - start
        logger.info(
            "lief: %d segments, %d sections, %d libraries (%.1fs)",
            len(result["segments"]), len(result["sections"]),
            len(result["libraries"]), duration,
        )
        result["duration_s"] = round(duration, 2)
        return result

    except ImportError:
        return {"error": "lief not installed", "duration_s": 0}
    except Exception as exc:
        duration = time.monotonic() - start
        return {"error": str(exc), "duration_s": round(duration, 2)}


def try_ghidra_analysis(binary_path: Path, config: Config, workspace: Workspace) -> dict:
    """Ghidra headless analiz -- timeout: 2 saat."""
    logger.info("=== GHIDRA HEADLESS ANALYSIS ===")
    logger.info("NOT: Bu adim 8.3MB binary icin 10-60dk surebilir. Timeout: 2 saat.")
    start = time.monotonic()

    try:
        from karadul.ghidra.headless import GhidraHeadless
        from karadul.ghidra.project import GhidraProject

        ghidra = GhidraHeadless(config)
        if not ghidra.is_available():
            return {"available": False, "error": "Ghidra not found"}

        ghidra_proj = GhidraProject(workspace, config)
        ghidra_proj.create()
        scripts = ghidra.get_default_scripts()
        if not scripts:
            return {"available": True, "error": "No Ghidra scripts found"}

        result = ghidra.analyze(
            binary_path=binary_path,
            project_dir=ghidra_proj.project_dir,
            project_name="karadul_steam_osx",
            scripts=scripts,
            output_dir=ghidra_proj.get_output_dir(),
        )

        duration = time.monotonic() - start
        logger.info("Ghidra tamamlandi: %.1f saniye", duration)

        if result and result.get("success"):
            combined = result.get("scripts_output", {}).get("combined_results", {})
            summary = combined.get("summary", {})
            return {
                "available": True,
                "success": True,
                "function_count": summary.get("function_count", 0),
                "string_count": summary.get("string_count", 0),
                "call_graph_edges": summary.get("call_graph_edges", 0),
                "decompiled_success": summary.get("decompiled_success", 0),
                "duration_s": round(duration, 2),
            }
        else:
            return {
                "available": True,
                "success": False,
                "error": result.get("error", "unknown") if result else "null result",
                "duration_s": round(duration, 2),
            }

    except Exception as exc:
        duration = time.monotonic() - start
        logger.error("Ghidra hatasi: %s", exc)
        return {
            "available": True,
            "success": False,
            "error": str(exc),
            "duration_s": round(duration, 2),
        }


def main():
    """Ana analiz pipeline."""
    if not STEAM_BINARY.exists():
        logger.error("Steam binary bulunamadi: %s", STEAM_BINARY)
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("STEAM BINARY FULL ANALYSIS")
    logger.info("Binary: %s", STEAM_BINARY)
    logger.info("Size: %.1f MB", STEAM_BINARY.stat().st_size / (1024 * 1024))
    logger.info("=" * 60)

    config = Config()
    config.project_root = PROJECT_ROOT

    # Target detection
    target_info = run_target_detection(STEAM_BINARY)

    # Workspace olustur
    ws_root = PROJECT_ROOT / "workspaces" / "steam_osx"
    ws_root.mkdir(parents=True, exist_ok=True)
    workspace = Workspace(ws_root, target_info.name)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "binary": str(STEAM_BINARY),
        "binary_size_bytes": STEAM_BINARY.stat().st_size,
        "binary_size_mb": round(STEAM_BINARY.stat().st_size / (1024 * 1024), 1),
        "target_type": target_info.target_type.value,
        "language": target_info.language.value,
        "metadata": target_info.metadata,
    }

    total_start = time.monotonic()

    # Hizli analizler (Ghidra haric)
    report["strings"] = run_strings_extraction(STEAM_BINARY, config)
    report["nm_symbols"] = run_nm_symbols(STEAM_BINARY, config)
    report["otool"] = run_otool_analysis(STEAM_BINARY, config)
    report["yara_scan"] = run_yara_scan(STEAM_BINARY)
    report["flirt"] = run_flirt_matching(STEAM_BINARY, config)
    report["signature_db"] = run_signature_db_matching(STEAM_BINARY, config)
    report["lief"] = run_lief_analysis(STEAM_BINARY)

    # Ghidra analizi -- timeout 2 saat
    ghidra_enabled = "--skip-ghidra" not in sys.argv
    if ghidra_enabled:
        report["ghidra"] = try_ghidra_analysis(STEAM_BINARY, config, workspace)
    else:
        report["ghidra"] = {"skipped": True, "reason": "--skip-ghidra flag"}

    total_duration = time.monotonic() - total_start
    report["total_duration_s"] = round(total_duration, 2)

    # Ozet
    logger.info("=" * 60)
    logger.info("SONUC OZETI")
    logger.info("-" * 60)
    logger.info("Strings: %d", report["strings"].get("total", 0))
    logger.info("nm Symbols: %d (defined: %d, undefined: %d)",
                report["nm_symbols"].get("total", 0),
                len(report["nm_symbols"].get("defined", [])),
                len(report["nm_symbols"].get("undefined", [])))
    logger.info("Dynamic Libraries: %d", report["otool"].get("dylib_count", 0))
    logger.info("YARA Matches: %d / %d rules",
                report["yara_scan"].get("matched_count", 0),
                report["yara_scan"].get("total_rules", 0))
    logger.info("FLIRT Signatures: %d loaded",
                report["flirt"].get("total_signatures_loaded", 0))
    logger.info("SignatureDB: %d matched / %d total (%.1f%%)",
                report["signature_db"].get("matched", 0),
                report["signature_db"].get("total_symbols", 0),
                report["signature_db"].get("match_rate_percent", 0))
    if report.get("ghidra", {}).get("success"):
        logger.info("Ghidra Functions: %d", report["ghidra"].get("function_count", 0))
        logger.info("Ghidra Decompiled: %d", report["ghidra"].get("decompiled_success", 0))
    logger.info("Total Duration: %.1f seconds", total_duration)
    logger.info("=" * 60)

    # Raporu kaydet
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    logger.info("Rapor kaydedildi: %s", REPORT_PATH)


if __name__ == "__main__":
    main()
