#!/usr/bin/env python3
"""Cursor 3 Bundle Full Pipeline Analysis.

3 Cursor bundle'ini sirayla karadul pipeline'indan gecirir,
her biri icin eksik pattern analizi yapar ve sonuclari
workspaces/cursor_analysis_report.json'a kaydeder.

Bundle'lar:
  1. cursor-agent-exec (4.2MB) - Ana agent execution engine
  2. cursor-main (1.3MB) - Ana uygulama bundle'i
  3. cursor-cli (206KB) - CLI yardimci modulu

Kullanim:
    cd /Users/apple/Desktop/black-widow
    python scripts/cursor_3bundle_analysis.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

# Proje kokunu ayarla
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from karadul.cli import main as cli_main
from karadul.config import Config
from karadul.core.pipeline import Pipeline
from karadul.core.target import TargetDetector
from karadul.stages import (
    IdentifyStage,
    StaticAnalysisStage,
    DeobfuscationStage,
    ReconstructionStage,
    ReportStage,
)


# =============================================================
# Bundle tanimlari
# =============================================================
BUNDLES = {
    "cursor-agent-exec": {
        "path": "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-agent-exec/dist/main.js",
        "description": "Agent execution engine (en buyuk bundle)",
    },
    "cursor-main": {
        "path": "/Applications/Cursor.app/Contents/Resources/app/out/main.js",
        "description": "Ana uygulama bundle'i",
    },
    "cursor-cli": {
        "path": "/Applications/Cursor.app/Contents/Resources/app/out/cli.js",
        "description": "CLI yardimci modulu (en kucuk)",
    },
}


# =============================================================
# Minified / okunamayan pattern tespiti
# =============================================================

# 1-2 karakter degisken adlari (a, b, x0, t1, e0, ...)
RE_MINIFIED_VAR = re.compile(r'\b([a-z_$][a-z0-9_$]?)\b')
# Tipik webpack helper isimleri
WEBPACK_HELPERS = {
    "__webpack_require__", "__webpack_exports__", "__unused_webpack_module",
    "__webpack_module_cache__", "__webpack_modules__", "module", "exports",
    "__esModule", "defineProperty", "hasOwnProperty", "Symbol",
    "__WEBPACK_DEFAULT_EXPORT__",
}
# Kisa ama anlamli JS keyword / built-in'ler (bunlari minified sayma)
JS_KEYWORDS = {
    "if", "in", "do", "of", "as", "is", "no", "on",
    "to", "or", "at", "by", "up", "id", "fn", "cb",
    "ok", "el", "it", "js", "ts", "ui",
    "true", "false", "null", "undefined", "this", "new",
    "var", "let", "const", "function", "return", "class",
    "for", "while", "break", "continue", "try", "catch",
    "throw", "typeof", "instanceof", "void", "delete",
    "switch", "case", "default", "import", "export", "from",
    "async", "await", "yield", "get", "set", "static",
}

# Webpack/bundler helper pattern'leri (regex)
RE_WEBPACK_REQUIRE = re.compile(r'__webpack_require__\(\s*[\d"\']+\s*\)')
RE_WEBPACK_EXPORT = re.compile(r'__webpack_exports__')
RE_DEFINE_PROPERTY = re.compile(r'Object\.defineProperty\s*\(')
RE_ESMODULE = re.compile(r'__esModule')
RE_WEBPACK_MODULE_DEF = re.compile(r'(?:/\*\*\*/\s*)?\d+\s*:\s*(?:function|(?:\([^)]*\))\s*=>)')


def analyze_minified_patterns(code: str) -> dict:
    """Verilen kaynak kodda minified / okunamayan pattern'leri tespit et.

    Returns:
        {
            "total_identifiers": int,
            "minified_identifiers": int,
            "minified_ratio": float,
            "top_minified": [(isim, sayi), ...],
            "webpack_helpers_found": [str, ...],
            "webpack_require_count": int,
            "webpack_export_count": int,
            "top_unreadable_patterns": [(pattern, sayi), ...],
        }
    """
    # Tum identifiers'i bul
    all_ids = RE_MINIFIED_VAR.findall(code)
    id_counter = Counter(all_ids)

    # Minified olanlar: 1-2 karakter VE JS keyword degil
    minified_counter = Counter()
    for name, count in id_counter.items():
        if len(name) <= 2 and name not in JS_KEYWORDS:
            minified_counter[name] = count

    # Webpack helper tespiti
    webpack_found = []
    for helper in WEBPACK_HELPERS:
        if helper in code:
            webpack_found.append(helper)

    # Webpack require/export sayilari
    wp_require_count = len(RE_WEBPACK_REQUIRE.findall(code))
    wp_export_count = len(RE_WEBPACK_EXPORT.findall(code))
    wp_define_prop = len(RE_DEFINE_PROPERTY.findall(code))
    wp_esmodule = len(RE_ESMODULE.findall(code))
    wp_module_defs = len(RE_WEBPACK_MODULE_DEF.findall(code))

    total_ids = sum(id_counter.values())
    minified_ids = sum(minified_counter.values())

    # En sik tekrar eden okunamayan pattern'ler
    # (Minified degisken + webpack boilerplate)
    unreadable_patterns = Counter()
    for name, count in minified_counter.most_common(50):
        unreadable_patterns[f"var:{name}"] = count
    if wp_require_count:
        unreadable_patterns["__webpack_require__(...)"] = wp_require_count
    if wp_export_count:
        unreadable_patterns["__webpack_exports__"] = wp_export_count
    if wp_define_prop:
        unreadable_patterns["Object.defineProperty(...)"] = wp_define_prop
    if wp_esmodule:
        unreadable_patterns["__esModule"] = wp_esmodule
    if wp_module_defs:
        unreadable_patterns["webpack_module_def"] = wp_module_defs

    return {
        "total_identifiers": total_ids,
        "minified_identifiers": minified_ids,
        "minified_ratio": round(minified_ids / max(total_ids, 1), 4),
        "top_minified": minified_counter.most_common(30),
        "webpack_helpers_found": sorted(webpack_found),
        "webpack_require_count": wp_require_count,
        "webpack_export_count": wp_export_count,
        "webpack_define_property_count": wp_define_prop,
        "webpack_esmodule_count": wp_esmodule,
        "webpack_module_defs_count": wp_module_defs,
        "top_unreadable_patterns": unreadable_patterns.most_common(20),
    }


def count_renamed_variables(workspace_path: Path) -> dict:
    """Workspace'teki reconstruct sonuclarindan rename istatistiklerini cikar."""
    result = {
        "variables_renamed": 0,
        "modules_extracted": 0,
        "coverage_percent": 0,
    }

    # Pipeline result JSON'dan oku
    reports_dir = workspace_path / "reports"
    if reports_dir.exists():
        for jf in reports_dir.glob("pipeline_result*.json"):
            try:
                data = json.loads(jf.read_text())
                stages = data.get("stages", {})
                if "reconstruct" in stages:
                    rs = stages["reconstruct"].get("stats", {})
                    result["variables_renamed"] = rs.get("variables_renamed", 0)
                    result["modules_extracted"] = rs.get("modules_extracted", 0)
                    result["coverage_percent"] = rs.get("coverage_percent", 0)
                if "deobfuscate" in stages:
                    ds = stages["deobfuscate"].get("stats", {})
                    result["total_modules_deob"] = ds.get("total_modules", 0)
                    result["bundle_format"] = ds.get("bundle_format", "unknown")
            except Exception:
                pass

    return result


def find_deobfuscated_output(workspace_path: Path) -> Path | None:
    """Workspace'teki deobfuscated cikti dosyasini bul."""
    # Tipik yollar:
    # workspace/deobfuscated/02_deep_deobfuscated.js
    # workspace/deobfuscated/01_beautified.js
    # workspace/deobfuscated/00_original*.js
    deob_dir = workspace_path / "deobfuscated"
    if not deob_dir.exists():
        return None

    # En gelismis versiyonu tercih et
    candidates = [
        "02_deep_deobfuscated.js",
        "01_beautified.js",
    ]
    for c in candidates:
        p = deob_dir / c
        if p.exists() and p.stat().st_size > 0:
            return p

    # Fallback: en buyuk .js dosyasi
    js_files = sorted(deob_dir.glob("*.js"), key=lambda f: f.stat().st_size, reverse=True)
    return js_files[0] if js_files else None


def find_modules_dir(workspace_path: Path) -> Path | None:
    """Webpack modulleri dizinini bul."""
    candidates = [
        workspace_path / "deobfuscated" / "webpack_modules",
        workspace_path / "reconstructed" / "src",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return None


def run_pipeline_for_bundle(bundle_name: str, bundle_path: str) -> dict:
    """Tek bir bundle icin full pipeline calistir.

    Returns:
        Pipeline sonuc bilgileri (istatistikler, hatalar, sure).
    """
    print(f"\n{'='*70}")
    print(f"  BUNDLE: {bundle_name}")
    print(f"  PATH:   {bundle_path}")
    print(f"{'='*70}\n")

    target_path = Path(bundle_path)
    if not target_path.exists():
        return {
            "success": False,
            "error": f"Dosya bulunamadi: {bundle_path}",
        }

    start = time.monotonic()

    try:
        cfg = Config.load()

        # Pipeline olustur
        pipeline = Pipeline(cfg)

        # Stage'leri kaydet (dynamic haric)
        pipeline.register_stage(IdentifyStage())
        pipeline.register_stage(StaticAnalysisStage())
        pipeline.register_stage(DeobfuscationStage(use_deep=True))

        try:
            pipeline.register_stage(ReconstructionStage())
        except Exception as exc:
            print(f"  [WARN] ReconstructionStage yuklenemedi: {exc}")

        pipeline.register_stage(ReportStage())

        # Pipeline calistir
        result = pipeline.run(target_path, stages=None)

        duration = time.monotonic() - start

        # Stage sonuclarini topla
        stage_results = {}
        for sname, sresult in result.stages.items():
            stage_results[sname] = {
                "success": sresult.success,
                "duration": round(sresult.duration_seconds, 2),
                "stats": sresult.stats,
                "artifacts_count": len(sresult.artifacts),
                "errors": sresult.errors,
            }

        return {
            "success": result.success,
            "duration": round(duration, 2),
            "workspace": str(result.workspace_path),
            "stages": stage_results,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "duration": round(time.monotonic() - start, 2),
        }


def analyze_output_quality(workspace_path_str: str, original_path: str) -> dict:
    """Pipeline sonrasi ciktilarin kalitesini analiz et.

    Minified pattern'ler, rename istatistikleri, webpack helper tespiti.
    """
    workspace_path = Path(workspace_path_str)
    original = Path(original_path)

    result = {
        "original_file_size": original.stat().st_size if original.exists() else 0,
    }

    # 1. Deobfuscated ciktiyi bul ve analiz et
    deob_output = find_deobfuscated_output(workspace_path)
    if deob_output:
        code = deob_output.read_text(encoding="utf-8", errors="replace")
        result["deobfuscated_file"] = str(deob_output.name)
        result["deobfuscated_size"] = len(code.encode("utf-8"))
        result["pattern_analysis"] = analyze_minified_patterns(code)
    else:
        # Orijinal dosyayi analiz et
        code = original.read_text(encoding="utf-8", errors="replace")
        result["deobfuscated_file"] = None
        result["deobfuscated_size"] = 0
        result["pattern_analysis"] = analyze_minified_patterns(code)
        result["note"] = "Deobfuscated cikti bulunamadi, orijinal analiz edildi"

    # 2. Modul sayisi
    modules_dir = find_modules_dir(workspace_path)
    if modules_dir:
        module_files = list(modules_dir.glob("*.js")) + list(modules_dir.glob("*.mjs"))
        result["modules_extracted"] = len(module_files)
        result["modules_dir"] = str(modules_dir)
    else:
        result["modules_extracted"] = 0

    # 3. Rename istatistikleri
    rename_stats = count_renamed_variables(workspace_path)
    result.update(rename_stats)

    return result


def main():
    """3 bundle'i sirayla analiz et ve rapor uret."""
    print("=" * 70)
    print("  CURSOR 3 BUNDLE FULL PIPELINE ANALYSIS")
    print(f"  Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    all_results = {}
    overall_start = time.monotonic()

    for bundle_name, bundle_info in BUNDLES.items():
        bundle_path = bundle_info["path"]

        # 1. Pipeline calistir
        pipeline_result = run_pipeline_for_bundle(bundle_name, bundle_path)
        all_results[bundle_name] = {
            "description": bundle_info["description"],
            "path": bundle_path,
            "pipeline": pipeline_result,
        }

        # 2. Cikti kalitesi analizi
        if pipeline_result.get("success") and pipeline_result.get("workspace"):
            quality = analyze_output_quality(
                pipeline_result["workspace"],
                bundle_path,
            )
            all_results[bundle_name]["quality"] = quality
        else:
            all_results[bundle_name]["quality"] = {
                "error": "Pipeline basarisiz, kalite analizi yapilamadi",
            }

        print(f"\n  [{bundle_name}] Tamamlandi: "
              f"{'BASARILI' if pipeline_result.get('success') else 'BASARISIZ'} "
              f"({pipeline_result.get('duration', 0):.1f}s)")

    overall_duration = time.monotonic() - overall_start

    # Ozet rapor olustur
    summary = {
        "analysis_date": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_duration_seconds": round(overall_duration, 2),
        "bundles_analyzed": len(BUNDLES),
        "bundles": {},
    }

    for bname, bdata in all_results.items():
        pipeline = bdata.get("pipeline", {})
        quality = bdata.get("quality", {})
        pattern = quality.get("pattern_analysis", {})

        summary["bundles"][bname] = {
            "description": bdata["description"],
            "path": bdata["path"],
            "success": pipeline.get("success", False),
            "duration_seconds": pipeline.get("duration", 0),

            # Eksik pattern analizi sonuclari
            "modules_extracted": quality.get("modules_extracted", 0),
            "variables_renamed": quality.get("variables_renamed", 0),
            "original_file_size_bytes": quality.get("original_file_size", 0),
            "deobfuscated_file": quality.get("deobfuscated_file"),
            "deobfuscated_size_bytes": quality.get("deobfuscated_size", 0),

            # Minified pattern metrikleri
            "total_identifiers": pattern.get("total_identifiers", 0),
            "minified_identifiers": pattern.get("minified_identifiers", 0),
            "minified_ratio": pattern.get("minified_ratio", 0),
            "top_minified_names": pattern.get("top_minified", [])[:15],

            # Webpack helper metrikleri
            "webpack_helpers_found": pattern.get("webpack_helpers_found", []),
            "webpack_require_count": pattern.get("webpack_require_count", 0),
            "webpack_export_count": pattern.get("webpack_export_count", 0),
            "webpack_module_defs_count": pattern.get("webpack_module_defs_count", 0),

            # En sik okunamayan pattern'ler
            "top_unreadable_patterns": pattern.get("top_unreadable_patterns", [])[:10],

            # Pipeline stage detaylari
            "stages": pipeline.get("stages", {}),
        }

    # JSON kaydet
    report_path = PROJECT_ROOT / "workspaces" / "cursor_analysis_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    # Konsol ozeti
    print("\n" + "=" * 70)
    print("  SONUC OZETI")
    print("=" * 70)

    for bname, bsummary in summary["bundles"].items():
        success_str = "OK" if bsummary["success"] else "FAIL"
        print(f"\n  [{success_str}] {bname}:")
        print(f"    Dosya boyutu  : {bsummary['original_file_size_bytes'] / 1024:.0f} KB")
        print(f"    Moduller      : {bsummary['modules_extracted']}")
        print(f"    Renamed vars  : {bsummary['variables_renamed']}")
        print(f"    Minified IDs  : {bsummary['minified_identifiers']} / {bsummary['total_identifiers']} "
              f"({bsummary['minified_ratio']:.1%})")
        print(f"    WP helpers    : {len(bsummary['webpack_helpers_found'])}")
        print(f"    WP require()  : {bsummary['webpack_require_count']}")
        print(f"    Sure          : {bsummary['duration_seconds']:.1f}s")

        if bsummary["top_unreadable_patterns"]:
            print(f"    En sik okunamayan pattern:")
            for pat, cnt in bsummary["top_unreadable_patterns"][:5]:
                print(f"      {cnt:>6}x  {pat}")

    print(f"\n  Toplam sure: {summary['total_duration_seconds']:.1f}s")
    print(f"  Rapor: {report_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
