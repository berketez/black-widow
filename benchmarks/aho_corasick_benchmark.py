"""KARADUL Aho-Corasick Optimizasyonu Benchmark.

Regex alternation vs Aho-Corasick performans karsilastirmasi.
QuantLib decompiled ciktilari ile test edilir.

Kullanim:
    python3 benchmarks/aho_corasick_benchmark.py

Cikti: 3 ayri benchmark
    1. AhoReplacer vs regex -- naming_map uygulamasi
    2. AhoFinder vs regex -- fonksiyon body extraction
    3. Structural pre-filter -- engineering pattern scan
"""

import json
import re
import sys
import time
from pathlib import Path

# Proje root'unu PYTHONPATH'e ekle
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from karadul.reconstruction.aho_replacer import AhoReplacer, AhoFinder


def benchmark_replacer(
    naming_map: dict[str, str],
    c_files: list[Path],
    n_files: int = 1000,
) -> dict:
    """AhoReplacer vs regex alternation benchmark."""
    cleaned = {k: v for k, v in naming_map.items() if k and len(k) >= 2}
    files = c_files[:n_files]

    # Dosyalari onceden oku
    contents = []
    total_chars = 0
    for f in files:
        c = f.read_text(encoding="utf-8", errors="replace")
        contents.append(c)
        total_chars += len(c)

    # --- Regex compile ---
    sorted_names = sorted(cleaned.keys(), key=len, reverse=True)
    t0 = time.perf_counter()
    combined = re.compile(
        r"\b(" + "|".join(re.escape(n) for n in sorted_names) + r")\b"
    )
    t_regex_compile = time.perf_counter() - t0

    # --- AC build ---
    t0 = time.perf_counter()
    replacer = AhoReplacer(cleaned)
    t_ac_build = time.perf_counter() - t0

    # --- Regex replace ---
    t0 = time.perf_counter()
    for content in contents:
        _ = combined.sub(lambda m: cleaned[m.group(0)], content)
    t_regex = time.perf_counter() - t0

    # --- AC replace ---
    t0 = time.perf_counter()
    for content in contents:
        _ = replacer.replace(content)
    t_ac = time.perf_counter() - t0

    # Dogruluk kontrolu (ilk 20)
    mismatches = 0
    for content in contents[:20]:
        r1 = combined.sub(lambda m: cleaned[m.group(0)], content)
        r2 = replacer.replace(content)
        if r1 != r2:
            mismatches += 1

    return {
        "name": "AhoReplacer (naming_map apply)",
        "n_files": len(files),
        "n_patterns": len(cleaned),
        "total_chars": total_chars,
        "regex_compile_s": t_regex_compile,
        "ac_build_s": t_ac_build,
        "regex_replace_s": t_regex,
        "ac_replace_s": t_ac,
        "speedup": t_regex / max(t_ac, 0.001),
        "build_speedup": t_regex_compile / max(t_ac_build, 0.001),
        "correctness": "PASS" if mismatches == 0 else f"FAIL ({mismatches} mismatch)",
    }


def benchmark_finder(
    func_names: list[str],
    c_files: list[Path],
    n_files: int = 200,
) -> dict:
    """AhoFinder vs regex alternation benchmark (function body extraction)."""
    files = c_files[:n_files]
    unique_names = list(set(func_names))

    # Satirlari hazirla
    all_lines = []
    for f in files:
        content = f.read_text(encoding="utf-8", errors="replace")
        all_lines.extend(content.split("\n"))

    # --- Regex compile ---
    sorted_names = sorted(unique_names, key=len, reverse=True)
    escaped = [re.escape(n) for n in sorted_names]
    t0 = time.perf_counter()
    combined = re.compile(
        r"\b(" + "|".join(escaped) + r")\s*\([^)]*\)\s*\{?\s*$"
    )
    t_regex_compile = time.perf_counter() - t0

    # --- AC build ---
    t0 = time.perf_counter()
    finder = AhoFinder(unique_names)
    t_ac_build = time.perf_counter() - t0

    _func_suffix_re = re.compile(r"\s*\([^)]*\)\s*\{?\s*$")

    # --- Regex search ---
    regex_matches = 0
    t0 = time.perf_counter()
    for line in all_lines:
        m = combined.search(line)
        if m:
            regex_matches += 1
    t_regex = time.perf_counter() - t0

    # --- AC search ---
    aho_matches = 0
    t0 = time.perf_counter()
    for line in all_lines:
        hits = finder.find_all_words(line)
        for start_pos, name in hits:
            after = line[start_pos + len(name):]
            if _func_suffix_re.match(after):
                aho_matches += 1
                break
    t_ac = time.perf_counter() - t0

    return {
        "name": "AhoFinder (function body extraction)",
        "n_files": len(files),
        "n_func_names": len(unique_names),
        "n_lines": len(all_lines),
        "regex_compile_s": t_regex_compile,
        "ac_build_s": t_ac_build,
        "regex_search_s": t_regex,
        "ac_search_s": t_ac,
        "speedup": t_regex / max(t_ac, 0.001),
        "regex_matches": regex_matches,
        "aho_matches": aho_matches,
        "correctness": "PASS" if regex_matches == aho_matches else f"FAIL ({regex_matches} vs {aho_matches})",
    }


def benchmark_structural(
    c_files: list[Path],
    n_files: int = 200,
) -> dict:
    """Structural pattern pre-filter benchmark."""
    from karadul.reconstruction.engineering.analyzer import EngineeringAlgorithmAnalyzer
    from karadul.reconstruction.engineering.patterns import ENGINEERING_PATTERNS

    files = c_files[:n_files]
    contents = []
    for f in files:
        c = f.read_text(encoding="utf-8", errors="replace")
        contents.append((f.stem, c))

    analyzer = EngineeringAlgorithmAnalyzer()

    # --- Pre-filter ILE ---
    t0 = time.perf_counter()
    results_with = set()
    for fname, code in contents:
        for m in analyzer._scan_structural(code, fname, "0x0"):
            results_with.add((fname, m.name, m.confidence))
    t_with = time.perf_counter() - t0

    # --- Pre-filter OLMADAN ---
    old = analyzer._structural_anchors
    analyzer._structural_anchors = [[frozenset()] for _ in ENGINEERING_PATTERNS]

    t0 = time.perf_counter()
    results_without = set()
    for fname, code in contents:
        for m in analyzer._scan_structural(code, fname, "0x0"):
            results_without.add((fname, m.name, m.confidence))
    t_without = time.perf_counter() - t0
    analyzer._structural_anchors = old

    return {
        "name": "Structural Pattern Pre-filter",
        "n_files": len(files),
        "n_patterns": len(ENGINEERING_PATTERNS),
        "with_filter_s": t_with,
        "without_filter_s": t_without,
        "speedup": t_without / max(t_with, 0.001),
        "detections_with": len(results_with),
        "detections_without": len(results_without),
        "correctness": "PASS" if results_with == results_without else f"FAIL ({len(results_without - results_with)} missing)",
    }


def main():
    workspace = Path(
        "/Users/apple/Desktop/black-widow/workspaces/libQuantLib.0/20260329_200933"
    )
    decompiled_dir = workspace / "static/ghidra_output/decompiled"
    naming_map_path = workspace / "reconstructed/src/naming_map.json"
    functions_json = workspace / "static/ghidra_functions.json"

    if not decompiled_dir.exists():
        print("HATA: QuantLib workspace bulunamadi")
        return

    c_files = sorted(decompiled_dir.glob("*.c"))
    print(f"QuantLib workspace: {len(c_files)} decompiled C dosyasi\n")
    print("=" * 72)

    # 1. AhoReplacer benchmark
    print("\n[1] AhoReplacer vs Regex Alternation\n")
    with open(naming_map_path) as f:
        naming_map = json.load(f)
    r1 = benchmark_replacer(naming_map, c_files, n_files=1000)
    print(f"  Dosya : {r1['n_files']}, Pattern: {r1['n_patterns']}")
    print(f"  Build : Regex={r1['regex_compile_s']:.3f}s  AC={r1['ac_build_s']:.3f}s  ({r1['build_speedup']:.0f}x)")
    print(f"  Replace: Regex={r1['regex_replace_s']:.3f}s  AC={r1['ac_replace_s']:.3f}s  ({r1['speedup']:.0f}x)")
    print(f"  Dogruluk: {r1['correctness']}")
    est_full_regex = r1["regex_replace_s"] / r1["n_files"] * len(c_files)
    est_full_ac = r1["ac_replace_s"] / r1["n_files"] * len(c_files)
    print(f"  19474 dosya tahmini: Regex={est_full_regex:.1f}s  AC={est_full_ac:.1f}s")

    # 2. AhoFinder benchmark
    print(f"\n{'=' * 72}")
    print("\n[2] AhoFinder vs Regex Alternation (function body extraction)\n")
    with open(functions_json) as f:
        data = json.load(f)
    func_names = [fn.get("name", "") for fn in data["functions"] if fn.get("name")]
    r2 = benchmark_finder(func_names, c_files, n_files=200)
    print(f"  Dosya: {r2['n_files']}, Func: {r2['n_func_names']}, Satir: {r2['n_lines']}")
    print(f"  Build : Regex={r2['regex_compile_s']:.3f}s  AC={r2['ac_build_s']:.3f}s")
    print(f"  Search: Regex={r2['regex_search_s']:.3f}s  AC={r2['ac_search_s']:.3f}s  ({r2['speedup']:.0f}x)")
    print(f"  Dogruluk: {r2['correctness']} ({r2['regex_matches']} match)")

    # 3. Structural pre-filter benchmark
    print(f"\n{'=' * 72}")
    print("\n[3] Structural Pattern Pre-filter\n")
    r3 = benchmark_structural(c_files, n_files=200)
    print(f"  Dosya: {r3['n_files']}, Pattern: {r3['n_patterns']}")
    print(f"  Pre-filter ILE    : {r3['with_filter_s']:.2f}s ({r3['detections_with']} tespit)")
    print(f"  Pre-filter OLMADAN: {r3['without_filter_s']:.2f}s ({r3['detections_without']} tespit)")
    print(f"  Hiz: {r3['speedup']:.1f}x")
    print(f"  Dogruluk: {r3['correctness']}")

    # Ozet
    print(f"\n{'=' * 72}")
    print("\n  TOPLAM KAZANC OZETI")
    print(f"  {'Moduel':40s} {'Eski':>8s} {'Yeni':>8s} {'Hiz':>6s}")
    print(f"  {'-'*40} {'-'*8} {'-'*8} {'-'*6}")
    print(f"  {'AhoReplacer (naming_map)':40s} {r1['regex_replace_s']:7.2f}s {r1['ac_replace_s']:7.3f}s {r1['speedup']:5.0f}x")
    print(f"  {'AhoFinder (func body)':40s} {r2['regex_search_s']:7.2f}s {r2['ac_search_s']:7.3f}s {r2['speedup']:5.0f}x")
    print(f"  {'Structural pre-filter':40s} {r3['without_filter_s']:7.2f}s {r3['with_filter_s']:7.2f}s {r3['speedup']:5.1f}x")


if __name__ == "__main__":
    main()
