#!/usr/bin/env python3
"""
Karadul Signature Dedup & Merge Report.

Reads ALL .json files in sigs/, merges them with first-seen-wins priority
(existing combined_1M.json gets highest priority), and produces statistics.

Does NOT modify existing files -- only reads and reports.
Optionally writes combined_all.json for analysis.

Usage:
    python3 dedup_signatures.py                  # Report only
    python3 dedup_signatures.py --write-combined # Also write combined_all.json
    python3 dedup_signatures.py --write-combined --no-combined-1m  # Exclude combined_1M from merge
"""

import json
import os
import sys
import argparse
from datetime import datetime
from collections import defaultdict

SIGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigs")

# Files that are aggregates themselves -- process them first (priority)
PRIORITY_FILES = ["combined_1M.json"]
# Skip these from merge (they are old/meta)
SKIP_FILES = {"combined_all.json", "EXPANSION_PLAN.md"}


def normalize_name(entry):
    """Extract the canonical name from a signature entry.

    Handles both dict-with-name-key and plain-string formats.
    Returns the name string used for dedup.
    """
    if isinstance(entry, dict):
        # Try common key names
        return entry.get("name", entry.get("mangled", entry.get("symbol", "")))
    return str(entry)


def load_sig_file(filepath):
    """Load a signature file and return (list_of_entries, format_info).

    Handles both formats:
    - signatures as list of dicts (each has 'name' key)
    - signatures as dict (keys are names, values are metadata)
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    sigs_raw = data.get("signatures", [])
    meta = data.get("meta", {})

    entries = []

    if isinstance(sigs_raw, list):
        for entry in sigs_raw:
            name = normalize_name(entry)
            if name:
                entries.append((name, entry if isinstance(entry, dict) else {"name": name}))
    elif isinstance(sigs_raw, dict):
        for name, info in sigs_raw.items():
            if isinstance(info, dict):
                entry = {"name": name}
                entry.update(info)
            else:
                entry = {"name": name}
            entries.append((name, entry))

    fmt = "list" if isinstance(sigs_raw, list) else "dict"
    return entries, fmt, meta


def main():
    parser = argparse.ArgumentParser(description="Karadul Signature Dedup & Merge Report")
    parser.add_argument("--write-combined", action="store_true",
                        help="Write combined_all.json output")
    parser.add_argument("--no-combined-1m", action="store_true",
                        help="Exclude combined_1M.json from merge (useful for fresh analysis)")
    args = parser.parse_args()

    print("=" * 78)
    print("  KARADUL SIGNATURE DEDUP & MERGE REPORT")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 78)

    # Find all .json files
    all_files = sorted(f for f in os.listdir(SIGS_DIR)
                       if f.endswith(".json") and f not in SKIP_FILES)

    if args.no_combined_1m:
        all_files = [f for f in all_files if f != "combined_1M.json"]
        print("\n  [NOTE] combined_1M.json excluded from merge\n")

    # Order: priority files first, then rest alphabetically
    ordered_files = []
    for pf in PRIORITY_FILES:
        if pf in all_files:
            ordered_files.append(pf)
            all_files.remove(pf)
    ordered_files.extend(all_files)

    # Merge with first-seen-wins
    merged = {}           # name -> entry dict
    seen_in = {}          # name -> first file it appeared in
    file_stats = {}       # filename -> {total, unique_new, duplicate}
    file_categories = {}  # filename -> {category: count}

    total_raw = 0

    for filename in ordered_files:
        filepath = os.path.join(SIGS_DIR, filename)
        try:
            entries, fmt, meta = load_sig_file(filepath)
        except Exception as e:
            print(f"  ERROR loading {filename}: {e}")
            file_stats[filename] = {"total": 0, "unique_new": 0, "duplicate": 0,
                                    "format": "error", "error": str(e)}
            continue

        unique_new = 0
        duplicate = 0
        cats = defaultdict(int)

        for name, entry in entries:
            total_raw += 1
            cat = entry.get("category", "unknown")
            cats[cat] += 1

            if name not in merged:
                merged[name] = entry
                seen_in[name] = filename
                unique_new += 1
            else:
                duplicate += 1

        file_stats[filename] = {
            "total": len(entries),
            "unique_new": unique_new,
            "duplicate": duplicate,
            "format": fmt,
        }
        file_categories[filename] = dict(cats)

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    print(f"\n{'FILE ANALYSIS':=^78}")
    print(f"\n{'File':<42s} {'Total':>8s} {'New':>8s} {'Dup':>8s} {'Fmt':>5s}")
    print("-" * 78)

    for filename in ordered_files:
        st = file_stats[filename]
        if "error" in st:
            print(f"  {filename:<40s} {'ERROR':>8s}")
            continue
        dup_pct = f"({st['duplicate']*100//max(st['total'],1)}%)"
        print(f"  {filename:<40s} {st['total']:>8,d} {st['unique_new']:>8,d} "
              f"{st['duplicate']:>7,d}{dup_pct:>5s} {st['format']:>5s}")

    print("-" * 78)
    print(f"  {'TOTALS':<40s} {total_raw:>8,d} {len(merged):>8,d} "
          f"{total_raw - len(merged):>7,d}")

    # Category breakdown (global)
    global_cats = defaultdict(int)
    for entry in merged.values():
        cat = entry.get("category", "unknown") if isinstance(entry, dict) else "unknown"
        global_cats[cat] += 1

    print(f"\n{'CATEGORY DISTRIBUTION (after dedup)':=^78}")
    print(f"\n{'Category':<45s} {'Count':>8s} {'%':>7s}")
    print("-" * 62)
    for cat, count in sorted(global_cats.items(), key=lambda x: -x[1])[:30]:
        pct = count * 100.0 / len(merged)
        print(f"  {cat:<43s} {count:>8,d} {pct:>6.1f}%")
    if len(global_cats) > 30:
        rest = sum(c for _, c in sorted(global_cats.items(), key=lambda x: -x[1])[30:])
        print(f"  {'... and ' + str(len(global_cats)-30) + ' more categories':<43s} {rest:>8,d}")

    # Library breakdown
    global_libs = defaultdict(int)
    for entry in merged.values():
        lib = "unknown"
        if isinstance(entry, dict):
            lib = entry.get("library", entry.get("lib", entry.get("category", "unknown")))
        global_libs[lib] += 1

    print(f"\n{'TOP 25 LIBRARIES':=^78}")
    print(f"\n{'Library':<45s} {'Count':>8s} {'%':>7s}")
    print("-" * 62)
    for lib, count in sorted(global_libs.items(), key=lambda x: -x[1])[:25]:
        pct = count * 100.0 / len(merged)
        print(f"  {lib:<43s} {count:>8,d} {pct:>6.1f}%")

    # New signatures per file (what each file uniquely contributes)
    print(f"\n{'UNIQUE CONTRIBUTIONS PER FILE':=^78}")
    print(f"\n{'File':<42s} {'Unique New':>10s} {'% of Total':>12s}")
    print("-" * 66)
    for filename in ordered_files:
        st = file_stats[filename]
        if st.get("unique_new", 0) > 0:
            pct = st["unique_new"] * 100.0 / len(merged)
            print(f"  {filename:<40s} {st['unique_new']:>10,d} {pct:>10.1f}%")

    # Overlap matrix (which files overlap most)
    print(f"\n{'OVERLAP ANALYSIS (top duplicated sources)':=^78}")
    # For each file, count how many of its entries were already seen
    overlap_info = []
    for filename in ordered_files:
        st = file_stats[filename]
        if st.get("duplicate", 0) > 0 and st.get("total", 0) > 0:
            dup_rate = st["duplicate"] * 100.0 / st["total"]
            overlap_info.append((filename, st["duplicate"], dup_rate, st["total"]))

    overlap_info.sort(key=lambda x: -x[2])
    print(f"\n{'File':<42s} {'Dup Count':>10s} {'Dup %':>7s} {'Total':>8s}")
    print("-" * 70)
    for fn, dup, rate, total in overlap_info[:15]:
        print(f"  {fn:<40s} {dup:>10,d} {rate:>6.1f}% {total:>8,d}")

    # Summary
    print(f"\n{'SUMMARY':=^78}")
    print(f"  Files processed:         {len(ordered_files)}")
    print(f"  Total raw entries:       {total_raw:,d}")
    print(f"  Total unique (deduped):  {len(merged):,d}")
    print(f"  Total duplicates:        {total_raw - len(merged):,d}")
    print(f"  Dedup ratio:             {(total_raw - len(merged))*100.0/max(total_raw,1):.1f}%")
    print(f"  Categories:              {len(global_cats)}")
    print(f"  Libraries:               {len(global_libs)}")

    # Write combined if requested
    if args.write_combined:
        output_path = os.path.join(SIGS_DIR, "combined_all.json")

        # Convert merged dict to sorted list
        sig_list = []
        for name in sorted(merged.keys()):
            entry = merged[name]
            if isinstance(entry, dict):
                if "name" not in entry:
                    entry["name"] = name
                sig_list.append(entry)
            else:
                sig_list.append({"name": name})

        output = {
            "meta": {
                "generator": "karadul-dedup-merge",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "total": len(sig_list),
                "files_merged": len(ordered_files),
                "dedup_stats": {
                    "raw_total": total_raw,
                    "unique": len(sig_list),
                    "duplicates_removed": total_raw - len(sig_list),
                }
            },
            "signatures": sig_list
        }

        with open(output_path, "w") as f:
            json.dump(output, f)  # No indent -- file will be huge

        size_mb = os.path.getsize(output_path) / (1024 * 1024)
        print(f"\n  Combined output: {output_path}")
        print(f"  File size: {size_mb:.1f} MB")
        print(f"  Entries: {len(sig_list):,d}")

    print(f"\n{'=' * 78}")


if __name__ == "__main__":
    main()
