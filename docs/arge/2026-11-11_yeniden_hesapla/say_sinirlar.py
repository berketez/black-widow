"""Toplu geçişteki fonksiyon başı sınırların GT'siz sayımı (yeniden hesapla fizibilitesi).

Saklı çalışma alanlarını SALT OKUR; ürün kodunu değiştirmez, yalnız ürün modüllerini
çağırır. Her sayı ya saklı bir çıktıdan okunur ya da sınır koşulu saklı girdide yeniden
değerlendirilir (koşul belirlenimci olduğu için toplu geçişte de aynı fonksiyonlara takılır).

Kullanım (depo kökünden):
    python docs/arge/2026-11-11_yeniden_hesapla/say_sinirlar.py \
        --out docs/arge/2026-11-11_yeniden_hesapla/sayim.json
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from karadul.reconstruction.c_algorithm_id import (  # noqa: E402
    CAlgorithmIdentifier,
    _strip_ghidra_warnings,
)
from karadul.reconstruction.engineering.analyzer import (  # noqa: E402
    EngineeringAlgorithmAnalyzer,
)

HOME = Path.home()
MAC = REPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"
BINARIES = {
    "debian/tmux": HOME / "karadul_olcum/n1_debian13/tmux/tmux",
    "debian/openssl": HOME / "karadul_olcum/n1_debian13/openssl/openssl",
    "debian/sqlite3": HOME / "karadul_olcum/n1_debian13/sqlite3/sqlite3",
    "debian/redis-cli": HOME / "karadul_olcum/n1_debian13/redis-tools/redis-cli",
    "debian/tree": HOME / "karadul_olcum/n1_debian13/tree/tree",
    "mac/tmux": MAC / "tmux",
    "mac/htop": MAC / "htop",
}

BODY_CAP = 5000  # c_algorithm_id.py:1171 ve engineering/analyzer.py:1002 ile aynı değer (yalnız ölçüm için)
DECOMPILED_JSON_CAP = 500  # headless.py:1055 / 1330
VF2_NODE_CAP = 500  # computation/cfg_iso/vf2_matcher.py:46-48

# Ghidra karar derleyicisinin bütçe/sınır kaynaklı uyarıları (kaynak: Ghidra 12.1.2 decompile/cpp)
GHIDRA_WARNINGS = {
    "jumptable_too_many_branches": re.compile(r"Could not recover jumptable at [^.]*\. Too many branches"),
    "type_propagation_not_settling": re.compile(r"Type propagation algorithm not settling"),
    "max_instructions_exceeded": re.compile(r"Exceeded maximum allowable instructions"),
    "max_restarts_exceeded": re.compile(r"Exceeded maximum restarts with more pending"),
}


def workspace(base: Path) -> Path:
    hits = sorted(glob.glob(str(base / "ws/workspaces/*/*/reports/pipeline_result.json")))
    if len(hits) != 1:
        raise SystemExit(f"çalışma alanı tek değil: {base} -> {hits}")
    return Path(hits[0]).parents[1]


def stats_of(ws: Path) -> dict:
    data = json.loads((ws / "reports/pipeline_result.json").read_text(encoding="utf-8"))
    out: dict = {}
    for name, stage in data["stages"].items():
        out.update(stage.get("stats", {}))
        out[f"dur_{name}"] = stage.get("duration_seconds")
    return out


def full_body(content: str, brace_pos: int) -> str:
    """_extract_body'nin sınırsız eşi: kapanan ayraca kadar."""
    depth = 0
    for i in range(brace_pos, len(content)):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[brace_pos:i + 1]
    return content[brace_pos:]


def code_part(text: str) -> str:
    idx = text.find("// --- DISASSEMBLY")
    return text if idx < 0 else text[:idx]


def count_binary(label: str, base: Path) -> dict:
    t0 = time.monotonic()
    ws = workspace(base)
    st = stats_of(ws)
    gout = ws / "static/ghidra_output"
    functions = json.loads((gout / "functions.json").read_text(encoding="utf-8"))
    n_funcs = int(functions.get("total") or len(functions.get("functions", [])))
    dj = json.loads((gout / "decompiled.json").read_text(encoding="utf-8"))
    listed = dj.get("functions", [])
    listed_with_hv = sum(1 for f in listed if f.get("pcode_high_vars"))

    pcode_lines = 0
    pcode_with_vars = 0
    with open(gout / "pcode.jsonl", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            pcode_lines += 1
            if json.loads(line).get("vars"):
                pcode_with_vars += 1

    # Ghidra karar derleyicisi uyarıları (fonksiyon = .c dosyası, yalnız kod kısmı)
    warn_funcs = {k: 0 for k in GHIDRA_WARNINGS}
    for cfile in sorted((gout / "decompiled").glob("*.c")):
        text = code_part(cfile.read_text(encoding="utf-8", errors="replace"))
        for key, rx in GHIDRA_WARNINGS.items():
            if rx.search(text):
                warn_funcs[key] += 1

    # Gövde 5000 karakter kırpması: algorithm_id girdisi deobfuscated/decompiled
    deob = ws / "deobfuscated/decompiled"
    func_re = CAlgorithmIdentifier._FUNC_RE
    n_bodies = 0
    n_truncated = 0
    truncated_lengths: list[int] = []
    for cfile in sorted(deob.rglob("*.c")):
        content = _strip_ghidra_warnings(cfile.read_text(encoding="utf-8", errors="replace"))
        for m in func_re.finditer(content):
            n_bodies += 1
            body = full_body(content, m.end() - 1)
            if len(body) > BODY_CAP:
                n_truncated += 1
                truncated_lengths.append(len(body))

    # Mühendislik taraması alan kapısı (analyzer.py:276, _detect_domain 846-893)
    eng = EngineeringAlgorithmAnalyzer()
    errs: list[str] = []
    fjson = ws / "deobfuscated/ghidra_functions.json"
    if not fjson.exists():
        fjson = ws / "static/ghidra_functions.json"
    func_meta = eng._load_json(fjson, errs)
    c_files = eng._collect_c_files(deob, errs)
    has_domain = eng._detect_domain(func_meta, c_files)

    # CFG-iso: VF2 düğüm tavanı (blok sayısı > 500)
    cfg = json.loads((gout / "cfg.json").read_text(encoding="utf-8"))
    over_node_cap = sum(1 for f in cfg["functions"] if int(f.get("block_count", 0)) > VF2_NODE_CAP)

    # BSim gölge: fonksiyon başı en çok 5 aday (config.py:587)
    bsim_capped = None
    bsim_path = ws / "reconstructed/bsim_shadow.json"
    if bsim_path.exists():
        bs = json.loads(bsim_path.read_text(encoding="utf-8"))
        bsim_capped = sum(1 for m in bs.get("matches", []) if len(m.get("bsim_candidates", [])) >= 5)

    return {
        "workspace": str(ws),
        "n_functions": n_funcs,
        "decompile": {
            "attempted": dj.get("total_attempted"),
            "success": dj.get("success"),
            "failed": dj.get("failed"),
            "skipped": dj.get("skipped"),
            "duration_s": dj.get("duration_seconds"),
        },
        "decompiled_json_cap": {
            "listed": len(listed),
            "listed_with_high_vars": listed_with_hv,
            "not_listed": max(0, n_funcs - len(listed)),
            "pcode_jsonl_functions": pcode_lines,
            "pcode_jsonl_with_vars": pcode_with_vars,
        },
        "ghidra_warning_functions": warn_funcs,
        "body_cap_5000": {
            "bodies_scanned": n_bodies,
            "truncated": n_truncated,
            "truncated_median_len": (sorted(truncated_lengths)[len(truncated_lengths) // 2]
                                     if truncated_lengths else None),
            "truncated_max_len": max(truncated_lengths) if truncated_lengths else None,
        },
        "engineering_domain_gate": {
            "has_domain": has_domain,
            "functions_without_const_struct_scan": 0 if has_domain else n_bodies,
            "func_meta_top_keys": sorted(func_meta.keys())[:5],
            "sampled_files": [p.name for p in c_files[:10]],
        },
        "deep_trace_top3": {
            "trace_targets": st.get("trace_targets"),
            "trace_total_nodes": st.get("trace_total_nodes"),
            "not_traced": (n_funcs - int(st["trace_targets"])) if st.get("trace_targets") is not None else n_funcs,
        },
        "cfg_iso": {
            "over_vf2_node_cap": over_node_cap,
            "matched": st.get("cfg_iso_matched_functions"),
            "total": st.get("cfg_iso_total_functions"),
            "timing_s": st.get("timing_cfg_iso_match"),
        },
        "computation_fusion": {
            "matches": st.get("computation_fusion_matches"),
            "accepted": st.get("computation_fusion_accepted"),
        },
        "bsim_shadow_functions_at_cap5": bsim_capped,
        "timings": {
            "ghidra_duration_s": st.get("ghidra_duration"),
            "dur_static_s": st.get("dur_static"),
            "dur_reconstruct_s": st.get("dur_reconstruct"),
            "c_naming_iter0_s": st.get("timing_c_naming_iter0"),
            "c_naming_iter1_s": st.get("timing_c_naming_iter1"),
            "type_recovery_iter0_s": st.get("timing_type_recovery_iter0"),
            "feedback_loop_s": st.get("feedback_loop_duration_s"),
            "deep_tracing_s": st.get("timing_deep_tracing"),
            "algorithm_id_s": st.get("algorithm_id_duration_s"),
        },
        "count_seconds": round(time.monotonic() - t0, 2),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    result = {label: count_binary(label, base) for label, base in BINARIES.items()}
    Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    for label, r in result.items():
        print(label, json.dumps({
            "N": r["n_functions"],
            "fail": r["decompile"]["failed"],
            "not_listed": r["decompiled_json_cap"]["not_listed"],
            "warn": r["ghidra_warning_functions"],
            "body>5000": r["body_cap_5000"]["truncated"],
            "bodies": r["body_cap_5000"]["bodies_scanned"],
            "has_domain": r["engineering_domain_gate"]["has_domain"],
            "not_traced": r["deep_trace_top3"]["not_traced"],
            "vf2cap": r["cfg_iso"]["over_vf2_node_cap"],
            "bsim5": r["bsim_shadow_functions_at_cap5"],
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()
