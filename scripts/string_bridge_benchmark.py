#!/usr/bin/env python3
"""
String-to-Function Deep Mapping — Claude Code Benchmark
========================================================
TS kaynak string literal'lari ile binary string'leri eslestirip,
xref uzerinden C fonksiyonlarina baglar.

Zincir: TS dosyasi -> string literal -> binary string -> xref -> C fonksiyon

Strateji:
  Asama 1: TS string'lerini cikar (regex ile literal extraction)
  Asama 2: Binary xref haritasindan "unique string" seti olustur
           (sadece 1 fonksiyonda kullanilan, 12+ karakter string'ler)
  Asama 3: TS dosyalarini unique string seti ile tara (substring match)
  Asama 4: Ek olarak exact match ile daha kisa string'leri de esle
  Asama 5: Tum eslestirmeleri kalite skorla ve raporla
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime

# ============================================================
# YAPILANDIRMA
# ============================================================
WORKSPACE = "/Users/apple/Desktop/black-widow/workspaces/2.1/20260405_163831"
TS_SOURCE_DIR = "/Users/apple/Desktop/claudeopen"
STRINGS_RAW = f"{WORKSPACE}/static/strings_raw.json"
GHIDRA_STRINGS = f"{WORKSPACE}/static/ghidra_output/strings.json"
GHIDRA_XREFS = f"{WORKSPACE}/static/ghidra_output/xrefs.json"
RECONSTRUCTED_DIR = f"{WORKSPACE}/reconstructed/semantic_named"
OUTPUT_FILE = f"{WORKSPACE}/string_bridge_results.json"

MIN_STRING_LEN = 6   # Minimum string uzunlugu (exact match icin)
MAX_STRING_LEN = 500  # Cok uzun string'ler genelde template/data
UNIQUE_MIN_LEN = 12   # Unique string eslestirme icin minimum uzunluk

# "Generic" string'ler — cok yaygin, eslestirme icin anlamli degil
GENERIC_STRINGS = {
    "undefined", "null", "object", "string", "number", "boolean",
    "function", "symbol", "bigint", "default", "toString", "valueOf",
    "constructor", "prototype", "length", "message", "stack", "name",
    "password", "username", "localhost", "namespace", "Content-Type",
    "application/json", "utf-8", "UTF-8", "text/plain", "text/html",
    "NODE_ENV", "HTTP_PROXY", "HTTPS_PROXY", "HOME", "PATH",
}

# Separator/decoration string'leri — bilgi tasimaz
SEPARATOR_PATTERN = re.compile(r'^[-=_*#~.]{6,}$')


def extract_ts_strings(ts_dir: str) -> dict[str, list[dict]]:
    """
    Tum .ts/.tsx dosyalarindan string literal'lari cikar.
    Returns: {string_value: [{file, line, context}]}
    """
    print("[1/6] TS kaynak dosyalarindan string'ler cikariliyor...")

    string_map = defaultdict(list)
    file_count = 0
    total_strings = 0

    dq_pattern = re.compile(r'"((?:[^"\\]|\\.){6,500})"')
    sq_pattern = re.compile(r"'((?:[^'\\]|\\.){6,500})'")

    skip_patterns = [
        re.compile(r'^\.{0,2}/'),           # relative imports
        re.compile(r'^@[a-z]'),             # scoped packages
        re.compile(r'^\s*$'),               # whitespace only
        re.compile(r'^https?://'),          # URL'ler
        re.compile(r'^\d+\.\d+\.\d+'),     # version strings
    ]

    for root, dirs, files in os.walk(ts_dir):
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', 'dist', 'build', '.next',
            'coverage', '__snapshots__', '.turbo'
        }]

        for fname in files:
            if not fname.endswith(('.ts', '.tsx')):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, ts_dir)
            file_count += 1

            try:
                with open(fpath, 'r', errors='ignore') as f:
                    lines = f.readlines()
            except (OSError, PermissionError):
                continue

            for line_no, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue

                for match in dq_pattern.finditer(line):
                    val = match.group(1)
                    val_clean = val.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
                    if any(p.search(val_clean) for p in skip_patterns):
                        continue
                    string_map[val_clean].append({
                        'file': rel_path,
                        'line': line_no,
                        'context': stripped[:120]
                    })
                    total_strings += 1

                for match in sq_pattern.finditer(line):
                    val = match.group(1)
                    val_clean = val.replace("\\'", "'").replace('\\n', '\n').replace('\\t', '\t')
                    if any(p.search(val_clean) for p in skip_patterns):
                        continue
                    string_map[val_clean].append({
                        'file': rel_path,
                        'line': line_no,
                        'context': stripped[:120]
                    })
                    total_strings += 1

    print(f"  {file_count} TS/TSX dosya tarandi")
    print(f"  {total_strings} string occurrence bulundu")
    print(f"  {len(string_map)} unique string")

    return dict(string_map)


def build_string_xref_map(xrefs_path: str) -> tuple[dict, dict]:
    """
    xrefs.json'dan:
    1. string_value -> [{func_name, func_addr, string_addr}]
    2. func_addr -> {name, strings_used, functions_called, called_by}
    """
    print("[2/6] Xref haritasi olusturuluyor...")

    with open(xrefs_path) as f:
        xdata = json.load(f)

    string_to_funcs = defaultdict(list)
    func_info = {}

    fxrefs = xdata.get('function_xrefs', {})

    for addr, info in fxrefs.items():
        fname = info.get('name', f'FUN_{addr}')
        func_info[addr] = {
            'name': fname,
            'strings_used': [s.get('value', '') for s in info.get('strings_used', [])],
            'functions_called': [c.get('name', '') for c in info.get('functions_called', [])],
            'called_by': [c.get('name', '') for c in info.get('called_by', [])],
        }

        for su in info.get('strings_used', []):
            val = su.get('value', '')
            if len(val) >= MIN_STRING_LEN:
                string_to_funcs[val].append({
                    'func_name': fname,
                    'func_addr': addr,
                    'string_addr': su.get('address', '')
                })

    stats = xdata.get('statistics', {})
    print(f"  {stats.get('total_functions', 0)} toplam fonksiyon")
    print(f"  {len(string_to_funcs)} unique string xref'li")

    return dict(string_to_funcs), func_info


def build_unique_string_set(string_to_funcs: dict) -> dict[str, dict]:
    """
    Sadece 1 fonksiyonda kullanilan, 12+ karakter string'leri sec.
    Bunlar en guvenilir eslestirme adaylari.
    Returns: {string: {func_name, func_addr, string_addr}}
    """
    print("[3/6] Unique string seti olusturuluyor...")

    unique = {}
    for val, funcs in string_to_funcs.items():
        if len(funcs) != 1:
            continue
        if len(val) < UNIQUE_MIN_LEN:
            continue
        if val in GENERIC_STRINGS:
            continue
        if SEPARATOR_PATTERN.match(val):
            continue
        # Cok kisa, sadece harf/rakam olmayan string'leri atla
        if len(val.strip()) < UNIQUE_MIN_LEN:
            continue

        unique[val] = {
            'func_name': funcs[0]['func_name'],
            'func_addr': funcs[0]['func_addr'],
            'string_addr': funcs[0]['string_addr'],
        }

    print(f"  {len(unique)} unique string (1 fonksiyon, >={UNIQUE_MIN_LEN} karakter)")
    return unique


def deep_scan_ts_for_unique_strings(
    ts_dir: str,
    unique_strings: dict[str, dict],
) -> list[dict]:
    """
    TS dosyalarini unique binary string seti ile tara.
    Substring match yapar — regex extraction'dan bagimsiz.
    """
    print("[4/6] TS dosyalari unique string'ler icin taraniyor (substring match)...")

    matches = []
    files_scanned = 0
    skip_dirs = {'node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.turbo'}

    # String'leri uzunluga gore sirala (uzun onceki, daha guvenilir)
    sorted_strings = sorted(unique_strings.keys(), key=len, reverse=True)

    # Her fonksiyonu en fazla 1 kere eslestirelim
    matched_funcs = set()
    # Her TS dosyasini birden fazla eslestirmeye izin ver (farkli fonksiyonlar icin)

    for root, dirs, files in os.walk(ts_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            if not fname.endswith(('.ts', '.tsx')):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, ts_dir)
            files_scanned += 1

            try:
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue

            for ustr in sorted_strings:
                if ustr not in content:
                    continue

                info = unique_strings[ustr]
                if info['func_name'] in matched_funcs:
                    continue

                # Satir numarasini bul
                line_no = 0
                context = ''
                for i, line in enumerate(content.split('\n'), 1):
                    if ustr in line:
                        line_no = i
                        context = line.strip()[:120]
                        break

                matches.append({
                    'string': ustr[:200],
                    'string_length': len(ustr),
                    'ts_file': rel_path,
                    'ts_line': line_no,
                    'ts_context': context,
                    'c_function': info['func_name'],
                    'c_address': info['func_addr'],
                    'string_address': info['string_addr'],
                    'match_type': 'unique_substring',
                })
                matched_funcs.add(info['func_name'])

    print(f"  {files_scanned} dosya tarandi")
    print(f"  {len(matches)} unique string eslesmesi bulundu")

    return matches


def exact_match_strings(
    ts_strings: dict,
    string_to_funcs: dict,
) -> list[dict]:
    """
    TS extracted string'leri ile binary string'lerin exact match'i.
    Unique substring scan'den farkli: daha kisa string'leri de kapsar,
    ama xref olanlari alir.
    """
    print("[5/6] Exact match eslestirmesi yapiliyor...")

    matches = []
    ts_only = 0
    matched_with_func = 0
    matched_no_func = 0

    for ts_str, ts_locations in ts_strings.items():
        if ts_str not in string_to_funcs:
            ts_only += 1
            continue

        func_refs = string_to_funcs[ts_str]
        matched_with_func += 1

        matches.append({
            'string': ts_str[:200],
            'string_length': len(ts_str),
            'ts_locations': ts_locations[:5],
            'c_functions': [
                {
                    'name': fr['func_name'],
                    'address': fr['func_addr'],
                    'string_address': fr['string_addr']
                }
                for fr in func_refs[:10]
            ],
            'match_type': 'exact',
            'ts_file_count': len(set(loc['file'] for loc in ts_locations)),
            'c_func_count': len(func_refs)
        })

    print(f"  TS-only (xref'te yok): {ts_only}")
    print(f"  Exact match + xref: {matched_with_func}")

    return matches


def find_c_file_for_function(func_name: str, recon_dir: str) -> str | None:
    """Fonksiyon adina karsilik gelen C dosyasini bul."""
    candidates = [
        f"{func_name}.c",
        f"{func_name.lstrip('_')}.c",
    ]
    for c in candidates:
        if os.path.exists(os.path.join(recon_dir, c)):
            return c
    return None


def score_and_build_pairs(
    unique_matches: list[dict],
    exact_matches: list[dict],
    func_info: dict,
    recon_dir: str,
) -> list[dict]:
    """
    Tum eslestirmeleri birlestirir, kalite skorlar, C dosya varligini kontrol eder.
    """
    print("[6/6] Fonksiyon ciftleri olusturuluyor ve skorlaniyor...")

    pairs = []
    seen_funcs = set()
    seen_ts_files = set()

    # --- ASAMA A: Unique substring match'ler (en yuksek oncelik) ---
    for m in unique_matches:
        func_name = m['c_function']
        ts_file = m['ts_file']

        if func_name in seen_funcs:
            continue

        c_file = find_c_file_for_function(func_name, recon_dir)

        faddr = m['c_address']
        finfo = func_info.get(faddr, {})
        func_strings = finfo.get('strings_used', [])

        # Kalite skoru (max 9)
        quality_score = 0
        quality_reasons = []

        # 1. Unique string = +3 (zaten unique, en guclu sinyal)
        quality_score += 3
        quality_reasons.append("unique_string_single_func")

        # 2. String uzunlugu
        if m['string_length'] >= 30:
            quality_score += 2
            quality_reasons.append("long_distinctive_string")
        elif m['string_length'] >= 15:
            quality_score += 1
            quality_reasons.append("medium_length_string")

        # 3. Semantic isim
        if not func_name.startswith('FUN_'):
            quality_score += 2
            quality_reasons.append("semantic_func_name")

        # 4. Multi-string context
        if len(func_strings) >= 3:
            quality_score += 1
            quality_reasons.append("multi_string_context")

        # 5. C dosyasi mevcut
        if c_file:
            quality_score += 1
            quality_reasons.append("c_file_exists")

        pair = {
            'ts_file': ts_file,
            'ts_line': m.get('ts_line', 0),
            'ts_context': m.get('ts_context', ''),
            'c_file': c_file,
            'c_function': func_name,
            'c_address': faddr,
            'bridge_string': m['string'][:100],
            'quality_score': quality_score,
            'quality_reasons': quality_reasons,
            'match_type': 'unique_substring',
            'func_total_strings': len(func_strings),
            'func_calls_count': len(finfo.get('functions_called', [])),
            'func_called_by_count': len(finfo.get('called_by', [])),
        }
        pairs.append(pair)
        seen_funcs.add(func_name)
        seen_ts_files.add(ts_file)

    unique_pair_count = len(pairs)

    # --- ASAMA B: Exact match'ler (ek ciftler, farkli fonksiyonlar) ---
    for m in exact_matches:
        for cfunc in m['c_functions']:
            func_name = cfunc['name']
            if func_name in seen_funcs:
                continue

            ts_file = m['ts_locations'][0]['file'] if m['ts_locations'] else None
            if not ts_file:
                continue

            c_file = find_c_file_for_function(func_name, recon_dir)

            faddr = cfunc['address']
            finfo = func_info.get(faddr, {})
            func_strings = finfo.get('strings_used', [])

            quality_score = 0
            quality_reasons = []

            # Uniqueness
            if m['c_func_count'] == 1:
                quality_score += 3
                quality_reasons.append("unique_string_single_func")
            elif m['c_func_count'] <= 3:
                quality_score += 2
                quality_reasons.append("rare_string_few_funcs")
            else:
                quality_score += 1
                quality_reasons.append("common_string_many_funcs")

            # String uzunlugu
            if m['string_length'] >= 30:
                quality_score += 2
                quality_reasons.append("long_distinctive_string")
            elif m['string_length'] >= 15:
                quality_score += 1
                quality_reasons.append("medium_length_string")

            # Semantic isim
            if not func_name.startswith('FUN_'):
                quality_score += 2
                quality_reasons.append("semantic_func_name")

            # Multi-string
            if len(func_strings) >= 3:
                quality_score += 1
                quality_reasons.append("multi_string_context")

            # C file exists
            if c_file:
                quality_score += 1
                quality_reasons.append("c_file_exists")

            # Generic string penalty
            if m['string'][:200] in GENERIC_STRINGS or SEPARATOR_PATTERN.match(m['string'][:200]):
                quality_score = max(0, quality_score - 2)
                quality_reasons.append("PENALTY_generic_string")

            pair = {
                'ts_file': ts_file,
                'ts_line': m['ts_locations'][0].get('line', 0),
                'ts_context': m['ts_locations'][0].get('context', ''),
                'c_file': c_file,
                'c_function': func_name,
                'c_address': faddr,
                'bridge_string': m['string'][:100],
                'quality_score': quality_score,
                'quality_reasons': quality_reasons,
                'match_type': 'exact',
                'func_total_strings': len(func_strings),
                'func_calls_count': len(finfo.get('functions_called', [])),
                'func_called_by_count': len(finfo.get('called_by', [])),
            }
            pairs.append(pair)
            seen_funcs.add(func_name)

            if len(pairs) >= 200:
                break
        if len(pairs) >= 200:
            break

    # Kaliteye gore sirala
    pairs.sort(key=lambda p: p['quality_score'], reverse=True)

    print(f"  {unique_pair_count} unique substring pair")
    print(f"  {len(pairs) - unique_pair_count} ek exact match pair")
    print(f"  Toplam: {len(pairs)} cift")
    if pairs:
        avg_q = sum(p['quality_score'] for p in pairs) / len(pairs)
        print(f"  Ortalama kalite skoru: {avg_q:.1f}/9")

    return pairs


def compute_statistics(
    ts_strings: dict,
    exact_matches: list[dict],
    unique_matches: list[dict],
    pairs: list[dict],
    string_to_funcs: dict,
    func_info: dict
) -> dict:
    """Istatistik raporu olustur."""

    # En cok string referansi olan C fonksiyonlari
    func_string_counts = []
    for addr, info in func_info.items():
        n_strings = len(info.get('strings_used', []))
        if n_strings >= 10:
            func_string_counts.append({
                'name': info['name'],
                'address': addr,
                'string_count': n_strings,
                'called_by_count': len(info.get('called_by', [])),
            })
    func_string_counts.sort(key=lambda x: x['string_count'], reverse=True)

    # Quality distribution
    quality_dist = defaultdict(int)
    for p in pairs:
        quality_dist[p['quality_score']] += 1

    # Pairs with C file
    pairs_with_c = sum(1 for p in pairs if p['c_file'])

    stats = {
        'ts_source': {
            'unique_strings_extracted': len(ts_strings),
            'total_occurrences': sum(len(v) for v in ts_strings.values()),
        },
        'binary': {
            'strings_with_xref': len(string_to_funcs),
            'total_functions': len(func_info),
        },
        'matching': {
            'exact_match_with_xref': len(exact_matches),
            'exact_match_rate_percent': round(
                len(exact_matches) / max(len(ts_strings), 1) * 100, 2
            ),
            'unique_substring_matches': len(unique_matches),
        },
        'function_pairs': {
            'total_pairs': len(pairs),
            'pairs_with_c_file': pairs_with_c,
            'quality_distribution': dict(sorted(quality_dist.items(), reverse=True)),
            'average_quality': round(
                sum(p['quality_score'] for p in pairs) / max(len(pairs), 1), 2
            ),
            'high_quality_pairs_7plus': sum(1 for p in pairs if p['quality_score'] >= 7),
            'medium_quality_pairs_4to6': sum(1 for p in pairs if 4 <= p['quality_score'] <= 6),
        },
        'top_c_functions_by_string_count': func_string_counts[:20],
    }

    return stats


def main():
    print("=" * 70)
    print("String-to-Function Deep Mapping Benchmark")
    print(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    # 1. TS string'lerini cikar
    ts_strings = extract_ts_strings(TS_SOURCE_DIR)
    print()

    # 2. Xref haritasini olustur
    string_to_funcs, func_info = build_string_xref_map(GHIDRA_XREFS)
    print()

    # 3. Unique string seti (sadece 1 fonksiyonda, 12+ karakter)
    unique_strings = build_unique_string_set(string_to_funcs)
    print()

    # 4. TS'yi unique string'lerle deep scan (substring match)
    unique_matches = deep_scan_ts_for_unique_strings(TS_SOURCE_DIR, unique_strings)
    print()

    # 5. Exact match (regex-extracted TS strings vs xref strings)
    exact_matches = exact_match_strings(ts_strings, string_to_funcs)
    print()

    # 6. Skorla ve birlesik cift listesi olustur
    pairs = score_and_build_pairs(unique_matches, exact_matches, func_info, RECONSTRUCTED_DIR)
    print()

    # 7. Istatistikler
    stats = compute_statistics(
        ts_strings, exact_matches, unique_matches, pairs, string_to_funcs, func_info
    )

    # Sonuc JSON
    result = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'workspace': WORKSPACE,
            'ts_source': TS_SOURCE_DIR,
            'min_string_length': MIN_STRING_LEN,
            'unique_min_length': UNIQUE_MIN_LEN,
        },
        'statistics': stats,
        'top_pairs': pairs[:50],
        'all_unique_matches': [
            {
                'string': m['string'][:80],
                'ts_file': m['ts_file'],
                'ts_line': m['ts_line'],
                'c_function': m['c_function'],
            }
            for m in unique_matches
        ],
        'all_exact_matches_summary': {
            'total': len(exact_matches),
            'sample': [
                {
                    'string': m['string'][:80],
                    'ts_file': m['ts_locations'][0]['file'] if m['ts_locations'] else None,
                    'c_functions': [c['name'] for c in m['c_functions'][:3]],
                    'c_func_count': m['c_func_count'],
                }
                for m in exact_matches[:100]
            ]
        }
    }

    # Kaydet
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # ============================================================
    # RAPOR
    # ============================================================
    print("=" * 70)
    print("SONUC RAPORU")
    print("=" * 70)
    print()
    print(f"TS unique string'ler:           {stats['ts_source']['unique_strings_extracted']:>8,}")
    print(f"Binary xref'li string'ler:      {stats['binary']['strings_with_xref']:>8,}")
    print(f"Toplam fonksiyon:               {stats['binary']['total_functions']:>8,}")
    print()
    print(f"--- Eslestirme ---")
    print(f"Unique substring match (TS icinde bulunan): {stats['matching']['unique_substring_matches']:>5}")
    print(f"Exact match (TS literal == binary str):     {stats['matching']['exact_match_with_xref']:>5}  "
          f"({stats['matching']['exact_match_rate_percent']}%)")
    print()
    print(f"--- Fonksiyon Ciftleri ---")
    print(f"Toplam TS<->C cift:       {stats['function_pairs']['total_pairs']:>5}")
    print(f"  C dosyasi mevcut:       {stats['function_pairs']['pairs_with_c_file']:>5}")
    print(f"  Yuksek kalite (7+):     {stats['function_pairs']['high_quality_pairs_7plus']:>5}")
    print(f"  Orta kalite (4-6):      {stats['function_pairs']['medium_quality_pairs_4to6']:>5}")
    print(f"  Ortalama kalite:        {stats['function_pairs']['average_quality']:>5}/9")
    print()

    if pairs:
        print("EN IYI 15 ESLESTIRME:")
        print("-" * 70)
        for i, p in enumerate(pairs[:15], 1):
            print(f"\n  #{i} [Kalite: {p['quality_score']}/9] [{p['match_type']}]")
            print(f"     Nedenler: {', '.join(p['quality_reasons'])}")
            print(f"     TS:     {p['ts_file']}:{p['ts_line']}")
            print(f"     C:      {p['c_file'] or '(dosya yok)'} ({p['c_function']})")
            print(f"     String: \"{p['bridge_string'][:70]}\"")
            print(f"     Func: {p['func_total_strings']} str, "
                  f"{p['func_calls_count']} call, {p['func_called_by_count']} called_by")

    print()
    print(f"Sonuc dosyasi: {OUTPUT_FILE}")
    print()

    # Top C functions by string count
    print("EN COK STRING REFERANSI OLAN C FONKSIYONLARI:")
    print("-" * 70)
    for fc in stats['top_c_functions_by_string_count'][:10]:
        print(f"  {fc['name']:40s}  strings: {fc['string_count']:>4}  called_by: {fc['called_by_count']:>4}")

    return result


if __name__ == '__main__':
    main()
