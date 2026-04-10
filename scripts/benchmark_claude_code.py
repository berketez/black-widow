#!/usr/bin/env python3
"""
Karadul Benchmark Script — Otomatik Reconstruction Kalite Olcumu
================================================================
Orijinal kaynak kodla (Claude Code TS) Karadul reconstruction (C) ciktisini
karsilastirir ve 6 boyutlu kalite puani hesaplar.

Kullanim:
    python3 benchmark_claude_code.py [--samples N] [--output PATH]

Cikti:
    - Terminal ozet tablosu
    - JSON sonuc dosyasi
"""

import argparse
import json
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# ============================================================
# CONFIGURATION
# ============================================================

ORIGINAL_DIR = Path("/Users/apple/Desktop/claudeopen/")
WORKSPACE_DIR = Path("/Users/apple/Desktop/black-widow/workspaces/2.1/20260405_163831")
RECONSTRUCTED_DIR = WORKSPACE_DIR / "reconstructed"
STATIC_DIR = WORKSPACE_DIR / "static"
DEFAULT_OUTPUT = WORKSPACE_DIR / "benchmark_results.json"

DEFAULT_SAMPLE_SIZE = 500
MIN_STRING_LEN = 4          # Minimum string uzunlugu (noise filtresi)
MAX_FILE_READ_SEC = 1.0     # Dosya okuma timeout
RANDOM_SEED = 42


# ============================================================
# HELPERS
# ============================================================

def safe_read(path: Path, timeout: float = MAX_FILE_READ_SEC) -> str:
    """Dosya oku, timeout asilirsa bos dondur."""
    try:
        start = time.monotonic()
        text = path.read_text(errors="replace")
        if time.monotonic() - start > timeout:
            return ""
        return text
    except Exception:
        return ""


def _is_meaningful_string(s: str) -> bool:
    """String'in anlamli olup olmadigini kontrol et (whitespace-only, tek karakter tekrari vb. filtrele)."""
    if len(s) < MIN_STRING_LEN:
        return False
    stripped = s.strip()
    if not stripped:
        return False  # whitespace-only
    if not any(c.isalnum() for c in s):
        return False  # hic alfanumerik karakter yok
    return True


def extract_ts_strings(code: str) -> set[str]:
    """TS/TSX koddan string literal'lari cikar."""
    strings = set()
    # Double-quoted
    for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', code):
        s = m.group(1)
        if _is_meaningful_string(s):
            strings.add(s)
    # Single-quoted
    for m in re.finditer(r"'([^'\\]*(?:\\.[^'\\]*)*)'", code):
        s = m.group(1)
        if _is_meaningful_string(s):
            strings.add(s)
    # Template literal (basit — nested ${} icermeyenler)
    for m in re.finditer(r"`([^`]*?)`", code):
        s = m.group(1)
        if _is_meaningful_string(s) and "${" not in s:
            strings.add(s)
    return strings


def extract_ts_exports(code: str) -> set[str]:
    """TS/TSX'den export edilen fonksiyon/class/const isimlerini cikar."""
    names = set()
    # export function/class/const/let/var/type/interface/enum
    for m in re.finditer(
        r"export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var|type|interface|enum)\s+(\w+)",
        code,
    ):
        names.add(m.group(1))
    # export { ... }
    for m in re.finditer(r"export\s*\{([^}]+)\}", code):
        for name in m.group(1).split(","):
            name = name.strip().split(" as ")[0].strip()
            if name:
                names.add(name)
    return names


def count_c_metrics(code: str) -> dict[str, Any]:
    """Tek bir C dosyasinin kalite metriklerini hesapla."""
    lines = code.split("\n")
    total_lines = len(lines)
    comment_lines = sum(1 for l in lines if l.strip().startswith("//") or l.strip().startswith("/*") or l.strip().startswith("*"))
    blank_lines = sum(1 for l in lines if not l.strip())
    code_lines = total_lines - comment_lines - blank_lines

    # Function name
    func_match = re.search(r"^// Function:\s*(.+)$", code, re.MULTILINE)
    func_name = func_match.group(1).strip() if func_match else "unknown"
    is_unnamed = func_name.startswith("FUN_")

    # Parameters: param_N pattern'leri say
    # Fonksiyon imzasindaki parametreleri bul
    sig_match = re.search(r"\(([^)]*)\)\s*\{", code)
    sig_params_total = 0
    sig_params_named = 0
    if sig_match:
        params = [p.strip() for p in sig_match.group(1).split(",") if p.strip()]
        sig_params_total = len(params)
        sig_params_named = sum(1 for p in params if not re.search(r"\bparam_\d+\b", p))

    # @param annotation'larindaki renamed parametreleri de say
    # Format: @param type renamed_name /* was: param_N */
    annotation_renames = len(re.findall(r"/\* was: param_\d+ \*/", code))

    # Toplam: imzada renamed + annotation'da renamed
    param_generic = sig_params_total - sig_params_named  # imzada hala param_N olanlar
    param_named = sig_params_named + annotation_renames   # isimlendirilmis (imza + annotation)

    # Local variables
    local_generic = len(re.findall(r"\b(?:local_|lVar|iVar|uVar|lStack_|iStack_|uStack_|auStack_|in_)\w+", code))
    local_named = len(re.findall(r"\b(?:result|status|offset|value|count|buffer|size|length|index|str|ptr|node|ctx|handle|self|this|text|key|data)_\w+", code))

    # Type quality
    undefined_types = len(re.findall(r"\bundefined\d*\b", code))
    void_ptr = len(re.findall(r"\bvoid\s*\*", code))
    typed_vars = len(re.findall(r"\b(?:int|long|short|char|bool|float|double|uint|ulong|ushort|uchar|size_t)\b", code))

    # goto count
    goto_count = len(re.findall(r"\bgoto\b", code))

    # Fonksiyon uzunlugu (brace icerigi)
    brace_start = code.find("{")
    if brace_start >= 0:
        func_body_lines = code[brace_start:].count("\n")
    else:
        func_body_lines = code_lines

    return {
        "func_name": func_name,
        "is_unnamed": is_unnamed,
        "total_lines": total_lines,
        "code_lines": code_lines,
        "comment_lines": comment_lines,
        "blank_lines": blank_lines,
        "param_generic": param_generic,
        "param_named": param_named,
        "local_generic": local_generic,
        "local_named": local_named,
        "undefined_types": undefined_types,
        "void_ptr": void_ptr,
        "typed_vars": typed_vars,
        "goto_count": goto_count,
        "func_body_lines": func_body_lines,
    }


# ============================================================
# PHASE 1: STRING BRIDGE
# ============================================================

def build_string_bridge(original_files: list[Path], karadul_strings: set[str]) -> dict:
    """Orijinal TS string'leri ile Karadul string verisini eslestir."""
    print("\n[1/5] String Bridge olusturuluyor...")

    ts_file_strings: dict[str, set[str]] = {}
    all_ts_strings: set[str] = set()

    for fp in original_files:
        code = safe_read(fp)
        if not code:
            continue
        strings = extract_ts_strings(code)
        if strings:
            rel = str(fp.relative_to(ORIGINAL_DIR))
            ts_file_strings[rel] = strings
            all_ts_strings.update(strings)

    # Eslesme bul
    matched_strings = all_ts_strings & karadul_strings
    # Her TS dosyasi icin kac string eslesti
    file_matches: dict[str, int] = {}
    for rel, strings in ts_file_strings.items():
        count = len(strings & karadul_strings)
        if count > 0:
            file_matches[rel] = count

    total_ts = len(all_ts_strings)
    total_matched = len(matched_strings)
    match_rate = total_matched / total_ts * 100 if total_ts else 0
    files_with_match = len(file_matches)
    files_total = len(ts_file_strings)
    file_rate = files_with_match / files_total * 100 if files_total else 0

    # En iyi eslesen dosyalar
    top_files = sorted(file_matches.items(), key=lambda x: -x[1])[:20]

    result = {
        "total_ts_strings": total_ts,
        "total_karadul_strings": len(karadul_strings),
        "matched_strings": total_matched,
        "match_rate_pct": round(match_rate, 2),
        "files_scanned": files_total,
        "files_with_match": files_with_match,
        "file_match_rate_pct": round(file_rate, 2),
        "top_matched_files": [{"file": f, "matches": c} for f, c in top_files],
        "sample_matched_strings": sorted(list(matched_strings))[:50],
    }

    print(f"  TS string'leri: {total_ts:,}")
    print(f"  Karadul string'leri: {len(karadul_strings):,}")
    print(f"  Eslesen: {total_matched:,} ({match_rate:.1f}%)")
    print(f"  Dosya eslesmesi: {files_with_match}/{files_total} ({file_rate:.1f}%)")

    return result


# ============================================================
# PHASE 2: FUNCTION MATCHING
# ============================================================

def match_functions(original_files: list[Path], karadul_func_names: set[str],
                    karadul_class_names: set[str]) -> dict:
    """Orijinal TS export isimlerini Karadul C ciktisinda ara."""
    print("\n[2/5] Fonksiyon eslestirmesi...")

    ts_exports: set[str] = set()
    ts_file_exports: dict[str, set[str]] = {}

    for fp in original_files:
        code = safe_read(fp)
        if not code:
            continue
        exports = extract_ts_exports(code)
        if exports:
            rel = str(fp.relative_to(ORIGINAL_DIR))
            ts_file_exports[rel] = exports
            ts_exports.update(exports)

    # Eslesme: TS export ismi Karadul fonksiyon/class listesinde var mi?
    # Case-insensitive eslesme de dene
    karadul_lower = {n.lower() for n in karadul_func_names | karadul_class_names}

    exact_match = ts_exports & (karadul_func_names | karadul_class_names)
    case_insensitive_match = {e for e in ts_exports if e.lower() in karadul_lower}
    # Substring match: TS export adi Karadul fonksiyon adinin icinde geciyorsa
    substring_match = set()
    for ts_name in ts_exports:
        if len(ts_name) < 4:
            continue
        for k_name in karadul_func_names:
            if ts_name.lower() in k_name.lower() and ts_name not in exact_match:
                substring_match.add(ts_name)
                break

    total_exports = len(ts_exports)
    exact_rate = len(exact_match) / total_exports * 100 if total_exports else 0
    ci_rate = len(case_insensitive_match) / total_exports * 100 if total_exports else 0
    sub_rate = len(substring_match) / total_exports * 100 if total_exports else 0
    total_any = len(exact_match | case_insensitive_match | substring_match)
    any_rate = total_any / total_exports * 100 if total_exports else 0

    result = {
        "total_ts_exports": total_exports,
        "total_karadul_funcs": len(karadul_func_names),
        "total_karadul_classes": len(karadul_class_names),
        "exact_match": len(exact_match),
        "exact_match_rate_pct": round(exact_rate, 2),
        "case_insensitive_match": len(case_insensitive_match),
        "case_insensitive_rate_pct": round(ci_rate, 2),
        "substring_match": len(substring_match),
        "substring_rate_pct": round(sub_rate, 2),
        "any_match": total_any,
        "any_match_rate_pct": round(any_rate, 2),
        "sample_exact_matches": sorted(list(exact_match))[:30],
        "sample_ci_matches": sorted(list(case_insensitive_match - exact_match))[:20],
        "sample_substring_matches": sorted(list(substring_match))[:20],
    }

    print(f"  TS export'lari: {total_exports:,}")
    print(f"  Karadul fonksiyonlar: {len(karadul_func_names):,} | class: {len(karadul_class_names):,}")
    print(f"  Exact match: {len(exact_match):,} ({exact_rate:.1f}%)")
    print(f"  Case-insensitive: {len(case_insensitive_match):,} ({ci_rate:.1f}%)")
    print(f"  Substring: {len(substring_match):,} ({sub_rate:.1f}%)")
    print(f"  Herhangi eslesen: {total_any:,} ({any_rate:.1f}%)")

    return result


# ============================================================
# PHASE 3: MODULE MATCHING
# ============================================================

def match_modules() -> dict:
    """Orijinal TS modul yapisini Karadul subsystem yapisiyla karsilastir."""
    print("\n[3/5] Modul eslestirmesi...")

    # Orijinal dizin yapisi
    ts_modules = set()
    for item in ORIGINAL_DIR.iterdir():
        if item.is_dir() and not item.name.startswith("."):
            ts_modules.add(item.name)

    # Karadul subsystem yapisi
    project_src = RECONSTRUCTED_DIR / "project" / "src"
    karadul_subsystems = set()
    named_subsystems = set()
    generic_subsystems = set()

    if project_src.exists():
        for item in project_src.iterdir():
            if item.is_dir():
                name = item.name
                karadul_subsystems.add(name)
                if re.match(r"subsystem_group_\d+", name):
                    generic_subsystems.add(name)
                else:
                    named_subsystems.add(name)

    # Named subsystem'lerin TS modulleriyle eslesme orani
    # subsystem_file_io -> file IO iliskisi, subsystem_network -> network, vb.
    subsystem_to_module_map = {}
    for sub in named_subsystems:
        # subsystem_ prefix'ini kaldir
        clean = sub.replace("subsystem_", "").lower()
        for mod in ts_modules:
            if clean in mod.lower() or mod.lower() in clean:
                subsystem_to_module_map[sub] = mod

    result = {
        "ts_modules": sorted(ts_modules),
        "ts_module_count": len(ts_modules),
        "karadul_subsystems_total": len(karadul_subsystems),
        "karadul_named_subsystems": sorted(named_subsystems),
        "karadul_generic_subsystems_count": len(generic_subsystems),
        "named_to_module_mapping": subsystem_to_module_map,
        "naming_rate_pct": round(
            len(named_subsystems) / len(karadul_subsystems) * 100
            if karadul_subsystems else 0, 2
        ),
    }

    print(f"  TS modulleri: {len(ts_modules)}")
    print(f"  Karadul subsystem'ler: {len(karadul_subsystems)} (named: {len(named_subsystems)}, generic: {len(generic_subsystems)})")
    print(f"  Named subsystem orani: {result['naming_rate_pct']:.1f}%")
    if subsystem_to_module_map:
        print(f"  Eslesen modüller: {subsystem_to_module_map}")

    return result


# ============================================================
# PHASE 4: CODE QUALITY METRICS
# ============================================================

def _load_pipeline_param_stats() -> dict:
    """param_naming_map.json'dan pipeline-wide rename istatistikleri yukle."""
    pnm_path = RECONSTRUCTED_DIR / "param_naming_map.json"
    if not pnm_path.exists():
        return {}
    try:
        with open(pnm_path) as f:
            data = json.load(f)
        total_renamed = data.get("total_renamed", 0)
        funcs = data.get("functions", {})
        total_functions = len(funcs)
        # Her fonksiyon icin rename edilen parametre sayisi
        funcs_with_rename = sum(1 for v in funcs.values()
                                if isinstance(v, dict) and v.get("renames"))
        return {
            "total_renamed": total_renamed,
            "total_functions": total_functions,
            "funcs_with_rename": funcs_with_rename,
            "rename_coverage_pct": round(
                funcs_with_rename / total_functions * 100 if total_functions else 0, 2
            ),
        }
    except Exception:
        return {}


def compute_code_quality(sample_size: int = DEFAULT_SAMPLE_SIZE) -> dict:
    """Reconstructed C dosyalarindan kalite metrikleri hesapla."""
    print(f"\n[4/5] Kod kalitesi metrikleri (sample={sample_size})...")

    # En iyi kaliteli pipeline stage'i sec: merged > commented > annotated > src
    src_dirs = [
        RECONSTRUCTED_DIR / "merged",
        RECONSTRUCTED_DIR / "commented",
        RECONSTRUCTED_DIR / "annotated",
        RECONSTRUCTED_DIR / "src",
    ]

    source_dir = None
    for d in src_dirs:
        if d.exists():
            source_dir = d
            break

    if not source_dir:
        print("  HATA: Reconstructed C dosyalari bulunamadi!")
        return {}

    print(f"  Kaynak dizin: {source_dir.name}/")

    # Tum C dosyalarini listele
    all_c_files = list(source_dir.glob("*.c"))
    total_files = len(all_c_files)
    print(f"  Toplam C dosyasi: {total_files:,}")

    # Sample al
    random.seed(RANDOM_SEED)
    if total_files > sample_size:
        sampled = random.sample(all_c_files, sample_size)
    else:
        sampled = all_c_files
        sample_size = total_files

    # Her dosyayi analiz et
    metrics_list = []
    for fp in sampled:
        code = safe_read(fp)
        if not code:
            continue
        m = count_c_metrics(code)
        metrics_list.append(m)

    if not metrics_list:
        print("  HATA: Hicbir dosya okunamadi!")
        return {}

    n = len(metrics_list)

    # Aggregate
    unnamed_count = sum(1 for m in metrics_list if m["is_unnamed"])
    unnamed_rate = unnamed_count / n * 100

    total_param_generic = sum(m["param_generic"] for m in metrics_list)
    total_param_named = sum(m["param_named"] for m in metrics_list)
    total_params = total_param_generic + total_param_named
    param_unnamed_rate = total_param_generic / total_params * 100 if total_params else 0

    total_undefined = sum(m["undefined_types"] for m in metrics_list)
    total_void_ptr = sum(m["void_ptr"] for m in metrics_list)
    total_typed = sum(m["typed_vars"] for m in metrics_list)
    total_type_tokens = total_undefined + total_void_ptr + total_typed
    undefined_rate = total_undefined / total_type_tokens * 100 if total_type_tokens else 0
    void_ptr_rate = total_void_ptr / total_type_tokens * 100 if total_type_tokens else 0

    total_goto = sum(m["goto_count"] for m in metrics_list)
    goto_per_func = total_goto / n

    total_comment_lines = sum(m["comment_lines"] for m in metrics_list)
    total_code_lines = sum(m["code_lines"] for m in metrics_list)
    total_all_lines = sum(m["total_lines"] for m in metrics_list)
    comment_rate = total_comment_lines / total_all_lines * 100 if total_all_lines else 0

    avg_func_len = sum(m["func_body_lines"] for m in metrics_list) / n

    total_local_generic = sum(m["local_generic"] for m in metrics_list)
    total_local_named = sum(m["local_named"] for m in metrics_list)
    total_locals = total_local_generic + total_local_named
    local_unnamed_rate = total_local_generic / total_locals * 100 if total_locals else 0

    # Pipeline-wide param rename istatistikleri (param_naming_map.json)
    pipeline_param_stats = _load_pipeline_param_stats()

    result = {
        "source_directory": source_dir.name,
        "total_files_in_dir": total_files,
        "sampled_files": n,
        "func_naming": {
            "unnamed_FUN_count": unnamed_count,
            "named_count": n - unnamed_count,
            "unnamed_rate_pct": round(unnamed_rate, 2),
            "named_rate_pct": round(100 - unnamed_rate, 2),
        },
        "param_naming": {
            "generic_param_N_count": total_param_generic,
            "named_param_count": total_param_named,
            "unnamed_rate_pct": round(param_unnamed_rate, 2),
            "pipeline_total_renamed": pipeline_param_stats.get("total_renamed", 0),
            "pipeline_total_functions": pipeline_param_stats.get("total_functions", 0),
            "pipeline_rename_coverage_pct": pipeline_param_stats.get("rename_coverage_pct", 0),
        },
        "local_naming": {
            "generic_local_count": total_local_generic,
            "named_local_count": total_local_named,
            "unnamed_rate_pct": round(local_unnamed_rate, 2),
        },
        "type_quality": {
            "undefined_count": total_undefined,
            "void_ptr_count": total_void_ptr,
            "typed_count": total_typed,
            "undefined_rate_pct": round(undefined_rate, 2),
            "void_ptr_rate_pct": round(void_ptr_rate, 2),
        },
        "control_flow": {
            "total_goto": total_goto,
            "goto_per_function": round(goto_per_func, 3),
        },
        "documentation": {
            "comment_lines": total_comment_lines,
            "code_lines": total_code_lines,
            "comment_rate_pct": round(comment_rate, 2),
        },
        "complexity": {
            "avg_function_length_lines": round(avg_func_len, 1),
        },
    }

    print(f"  FUN_xxx orani: {unnamed_rate:.1f}% ({unnamed_count}/{n})")
    print(f"  param_N orani: {param_unnamed_rate:.1f}% ({total_param_generic}/{total_params})")
    print(f"  local unnamed orani: {local_unnamed_rate:.1f}%")
    print(f"  undefined tip orani: {undefined_rate:.1f}%")
    print(f"  void* orani: {void_ptr_rate:.1f}%")
    print(f"  goto/fonksiyon: {goto_per_func:.2f}")
    print(f"  Yorum orani: {comment_rate:.1f}%")
    print(f"  Ort. fonksiyon uzunlugu: {avg_func_len:.1f} satir")

    return result


# ============================================================
# PHASE 5: 6-DIMENSIONAL SCORE
# ============================================================

def compute_score(quality: dict, func_match: dict, module_match: dict) -> dict:
    """6 boyutlu kalite puani hesapla. Her boyut 0-100."""
    print("\n[5/5] 6 boyutlu puan hesaplaniyor...")

    # 1. func_name (0.30): Isimlendirilmis fonksiyon orani
    fn = quality.get("func_naming", {})
    func_name_score = fn.get("named_rate_pct", 0)

    # 2. params (0.20): Isimlendirilmis parametre orani
    #    Sample'daki unnamed rate ile pipeline-wide rename coverage'in ortalamasini al
    pn = quality.get("param_naming", {})
    sample_params = 100 - pn.get("unnamed_rate_pct", 100)
    pipeline_coverage = pn.get("pipeline_rename_coverage_pct", sample_params)
    params_score = (sample_params + pipeline_coverage) / 2

    # 3. locals (0.15): Isimlendirilmis local degisken orani
    ln = quality.get("local_naming", {})
    locals_score = 100 - ln.get("unnamed_rate_pct", 100)

    # 4. types (0.15): Dogru tip kullanim orani (100 - undefined - void_ptr)
    tq = quality.get("type_quality", {})
    types_score = 100 - tq.get("undefined_rate_pct", 0) - tq.get("void_ptr_rate_pct", 0)
    types_score = max(0, types_score)

    # 5. comments (0.10): Yorum orani (cap at 30% = 100 score)
    doc = quality.get("documentation", {})
    comment_pct = doc.get("comment_rate_pct", 0)
    comments_score = min(100, comment_pct / 30 * 100)

    # 6. structure (0.10): Modul yapisi kalitesi
    #    - Named subsystem orani (50%)
    #    - Fonksiyon eslesme orani (50%)
    naming_rate = module_match.get("naming_rate_pct", 0)
    func_any_rate = func_match.get("any_match_rate_pct", 0)
    structure_score = (naming_rate * 0.5 + func_any_rate * 0.5)

    # Agirlikli toplam
    weights = {
        "func_name": 0.30,
        "params": 0.20,
        "locals": 0.15,
        "types": 0.15,
        "comments": 0.10,
        "structure": 0.10,
    }

    scores = {
        "func_name": round(func_name_score, 2),
        "params": round(params_score, 2),
        "locals": round(locals_score, 2),
        "types": round(types_score, 2),
        "comments": round(comments_score, 2),
        "structure": round(structure_score, 2),
    }

    weighted_total = sum(scores[k] * weights[k] for k in weights)

    result = {
        "dimensions": scores,
        "weights": weights,
        "weighted_total": round(weighted_total, 2),
        "grade": grade_label(weighted_total),
    }

    print(f"\n  {'Boyut':<15} {'Puan':>8} {'Agirlik':>8} {'Katki':>8}")
    print(f"  {'-'*43}")
    for k in weights:
        katki = scores[k] * weights[k]
        print(f"  {k:<15} {scores[k]:>7.1f} {weights[k]:>7.0%} {katki:>7.1f}")
    print(f"  {'-'*43}")
    print(f"  {'TOPLAM':<15} {weighted_total:>7.1f}   100%")
    print(f"  Grade: {result['grade']}")

    return result


def grade_label(score: float) -> str:
    """Puana gore harf notu ver."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B+"
    elif score >= 60:
        return "B"
    elif score >= 50:
        return "C+"
    elif score >= 40:
        return "C"
    elif score >= 30:
        return "D"
    elif score >= 20:
        return "E"
    else:
        return "F"


# ============================================================
# DATA LOADING
# ============================================================

def load_karadul_strings() -> set[str]:
    """Karadul string verilerini yukle."""
    strings = set()

    # 1. ghidra_strings.json (en kapsamli)
    ghidra_path = STATIC_DIR / "ghidra_strings.json"
    if ghidra_path.exists():
        try:
            with open(ghidra_path) as f:
                data = json.load(f)
            for entry in data.get("strings", []):
                val = entry.get("value", "")
                if _is_meaningful_string(val) and re.match(r"^[\x20-\x7e]+$", val):
                    strings.add(val)
        except Exception as e:
            print(f"  UYARI: ghidra_strings.json okunamadi: {e}")

    # 2. strings_raw.json (fallback)
    raw_path = STATIC_DIR / "strings_raw.json"
    if raw_path.exists():
        try:
            with open(raw_path) as f:
                data = json.load(f)
            for s in data.get("strings", []):
                if _is_meaningful_string(s) and re.match(r"^[\x20-\x7e]+$", s):
                    strings.add(s)
        except Exception as e:
            print(f"  UYARI: strings_raw.json okunamadi: {e}")

    return strings


def load_karadul_func_names() -> tuple[set[str], set[str]]:
    """Karadul fonksiyon ve class isimlerini yukle."""
    func_names = set()
    class_names = set()

    # 1. binary_names.json
    bn_path = RECONSTRUCTED_DIR / "binary_names.json"
    if bn_path.exists():
        try:
            with open(bn_path) as f:
                data = json.load(f)
            # names list
            for name in data.get("names", []):
                if isinstance(name, str):
                    # Swift mangled isimlerden temiz kisimlari cikar
                    # Basit durum: ismi direkt ekle
                    func_names.add(name)
                    # Demangle attempt: $s10Foundation11JSONEncoderC -> JSONEncoder
                    for m in re.finditer(r"(\d+)([A-Z]\w+)", name):
                        clean = m.group(2)
                        if len(clean) >= 4:
                            func_names.add(clean)
            for name in data.get("classes", []):
                if isinstance(name, str):
                    class_names.add(name)
        except Exception as e:
            print(f"  UYARI: binary_names.json okunamadi: {e}")

    # 2. src/ dizininden fonksiyon adlarini cikar (dosya adindan)
    src_dir = RECONSTRUCTED_DIR / "src"
    if src_dir.exists():
        for fp in src_dir.glob("*.c"):
            name = fp.stem
            if not name.startswith("FUN_"):
                func_names.add(name)

    # 3. param_naming_map.json — fonksiyon isim listesi
    pnm_path = RECONSTRUCTED_DIR / "param_naming_map.json"
    if pnm_path.exists():
        try:
            with open(pnm_path) as f:
                data = json.load(f)
            funcs = data.get("functions", {})
            for name in funcs:
                if not name.startswith("FUN_"):
                    func_names.add(name)
        except Exception:
            pass

    return func_names, class_names


def collect_original_files() -> list[Path]:
    """Orijinal TS/TSX dosyalarini topla."""
    files = []
    for ext in ("*.ts", "*.tsx"):
        files.extend(ORIGINAL_DIR.rglob(ext))
    return files


# ============================================================
# SUMMARY TABLE
# ============================================================

def print_summary(results: dict):
    """Terminal ozet tablosu yazdir."""
    print("\n" + "=" * 70)
    print("  KARADUL BENCHMARK SONUCLARI")
    print("  Orijinal: Claude Code (TS) | Reconstruction: Karadul (C)")
    print("=" * 70)

    sb = results.get("string_bridge", {})
    fm = results.get("function_matching", {})
    mm = results.get("module_matching", {})
    cq = results.get("code_quality", {})
    sc = results.get("score", {})

    print(f"\n--- String Bridge ---")
    print(f"  TS string'leri:      {sb.get('total_ts_strings', 0):>8,}")
    print(f"  Karadul string'leri: {sb.get('total_karadul_strings', 0):>8,}")
    print(f"  Eslesen:             {sb.get('matched_strings', 0):>8,} ({sb.get('match_rate_pct', 0):.1f}%)")
    print(f"  Dosya eslesmesi:     {sb.get('files_with_match', 0):>8,}/{sb.get('files_scanned', 0):,} ({sb.get('file_match_rate_pct', 0):.1f}%)")

    print(f"\n--- Fonksiyon Eslestirme ---")
    print(f"  TS export'lar:       {fm.get('total_ts_exports', 0):>8,}")
    print(f"  Exact match:         {fm.get('exact_match', 0):>8,} ({fm.get('exact_match_rate_pct', 0):.1f}%)")
    print(f"  Case-insensitive:    {fm.get('case_insensitive_match', 0):>8,} ({fm.get('case_insensitive_rate_pct', 0):.1f}%)")
    print(f"  Herhangi eslesen:    {fm.get('any_match', 0):>8,} ({fm.get('any_match_rate_pct', 0):.1f}%)")

    print(f"\n--- Modul Eslestirme ---")
    print(f"  TS modulleri:        {mm.get('ts_module_count', 0):>8,}")
    print(f"  Karadul subsys.:     {mm.get('karadul_subsystems_total', 0):>8,}")
    print(f"  Named subsystem:     {len(mm.get('karadul_named_subsystems', [])):>8,}")
    print(f"  Named orani:         {mm.get('naming_rate_pct', 0):>7.1f}%")

    fn = cq.get("func_naming", {})
    pn = cq.get("param_naming", {})
    tq = cq.get("type_quality", {})
    cf = cq.get("control_flow", {})
    doc = cq.get("documentation", {})
    cx = cq.get("complexity", {})

    print(f"\n--- Kod Kalitesi (sample={cq.get('sampled_files', 0)}) ---")
    print(f"  FUN_xxx orani:       {fn.get('unnamed_rate_pct', 0):>7.1f}%")
    print(f"  param_N orani:       {pn.get('unnamed_rate_pct', 0):>7.1f}%")
    print(f"  undefined tip:       {tq.get('undefined_rate_pct', 0):>7.1f}%")
    print(f"  void* orani:         {tq.get('void_ptr_rate_pct', 0):>7.1f}%")
    print(f"  goto/fonksiyon:      {cf.get('goto_per_function', 0):>7.2f}")
    print(f"  Yorum orani:         {doc.get('comment_rate_pct', 0):>7.1f}%")
    print(f"  Ort. fonk. uzunluk:  {cx.get('avg_function_length_lines', 0):>7.1f} satir")

    dims = sc.get("dimensions", {})
    weights = sc.get("weights", {})

    print(f"\n--- 6 Boyutlu Puan ---")
    print(f"  {'Boyut':<15} {'Puan':>8} {'Agirlik':>8} {'Katki':>8}")
    print(f"  {'-'*43}")
    for k in ["func_name", "params", "locals", "types", "comments", "structure"]:
        s = dims.get(k, 0)
        w = weights.get(k, 0)
        print(f"  {k:<15} {s:>7.1f} {w:>7.0%} {s*w:>7.1f}")
    print(f"  {'-'*43}")
    print(f"  {'TOPLAM':<15} {sc.get('weighted_total', 0):>7.1f}   100%    {sc.get('grade', '?')}")

    print("\n" + "=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Karadul Benchmark: Reconstruction vs Original")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLE_SIZE,
                        help=f"Kod kalitesi icin sample boyutu (default: {DEFAULT_SAMPLE_SIZE})")
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT),
                        help=f"JSON cikti dosyasi (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED,
                        help=f"Random seed (default: {RANDOM_SEED})")
    args = parser.parse_args()

    random.seed(args.seed)
    start_time = time.monotonic()

    print("Karadul Benchmark v1.0")
    print(f"Orijinal: {ORIGINAL_DIR}")
    print(f"Reconstructed: {RECONSTRUCTED_DIR}")
    print(f"Sample size: {args.samples}")

    # Veri yukleme
    print("\nVeri yukleniyor...")
    original_files = collect_original_files()
    print(f"  Orijinal TS/TSX: {len(original_files):,} dosya")

    karadul_strings = load_karadul_strings()
    print(f"  Karadul string'ler: {len(karadul_strings):,}")

    karadul_funcs, karadul_classes = load_karadul_func_names()
    print(f"  Karadul fonksiyonlar: {len(karadul_funcs):,} | class: {len(karadul_classes):,}")

    # Phase 1: String Bridge
    string_bridge = build_string_bridge(original_files, karadul_strings)

    # Phase 2: Function Matching
    func_matching = match_functions(original_files, karadul_funcs, karadul_classes)

    # Phase 3: Module Matching
    module_matching = match_modules()

    # Phase 4: Code Quality Metrics
    code_quality = compute_code_quality(sample_size=args.samples)

    # Phase 5: Score
    score = compute_score(code_quality, func_matching, module_matching)

    elapsed = time.monotonic() - start_time

    # Sonuclari birlestir
    results = {
        "metadata": {
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_dir": str(ORIGINAL_DIR),
            "reconstructed_dir": str(RECONSTRUCTED_DIR),
            "original_file_count": len(original_files),
            "sample_size": args.samples,
            "random_seed": args.seed,
            "elapsed_seconds": round(elapsed, 2),
        },
        "string_bridge": string_bridge,
        "function_matching": func_matching,
        "module_matching": module_matching,
        "code_quality": code_quality,
        "score": score,
    }

    # JSON kaydet
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nJSON cikti: {output_path}")

    # Ozet tablo
    print_summary(results)
    print(f"\nToplam sure: {elapsed:.1f}s")

    return results


if __name__ == "__main__":
    main()
