#!/usr/bin/env python3
"""ÖL-7 (plan v2.2 N0 a): aynı commit'le iki koşunun çıktıları aynı mı?

Koşu çiftlerini program başına karşılaştırır ve YALNIZ SAYI yazar: çıktıda
fonksiyon adı, yerel ad, GT adı ya da kanıt dizgisi yoktur (strateji adları
kod etiketidir). Girdiler ``macho_measure.py`` koşu dizinleridir:
``workspaces/olcum_mac/runs/<etiket>/<program>/``.

Karşılaştırılanlar (program başına):
  * c_namer girdileri: Ghidra JSON'ları (ayrıştırılmış içerik) ve decompile .c
    dosyaları (bayt) -- fark c_namer'dan önce mi doğuyor?
  * ``reconstructed/src/naming_map.json`` (puanlanan harita; c_namer iter0):
    global bölüm önek grubuna göre (FUN_, DAT_, diğer) ve per_function (yerel).
    "Yalnız son ek farkı": iki ad ``_<sayı>`` son eki atılınca aynı.
  * ``macho_score.json`` satırları: adres başına ``status`` geçişleri, ``pred``.
  * ``out/report.json`` -> ``naming_by_strategy``.
  * İki tarafta da ``naming_provenance.json`` varsa farkların kaynağı:
    kazanan strateji, önerilen ad (son ek öncesi), en üstte eşit güvenli rakip.

Kullanım (depo kökünden; ol7_sayilar.json bu komutla üretildi):
  python3 -I docs/arge/2026-10-21_g9_n0/ol7_analiz.py --data-dir workspaces/olcum_mac \
      --out docs/arge/2026-10-21_g9_n0/ol7_sayilar.json \
      --pair a_vs_b:ol7-a-9a36142:ol7-b-9a36142:htop,tmux \
      --pair a_vs_taban:ol7-a-9a36142:taban-v2-62ad154:htop,tmux \
      --pair s0a_vs_s0b:ol7-s0a-9a36142:ol7-s0b-9a36142:htop
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional

SUFFIX_RE = re.compile(r"_\d+$")
GHIDRA_JSONS = ("ghidra_functions.json", "ghidra_strings.json",
                "ghidra_call_graph.json", "ghidra_xrefs.json")
DECOMPILED_DIRS = ("static/ghidra_output/decompiled", "deobfuscated/decompiled")
SCORE_SUMMARY_KEYS = ("tp", "wrong", "unnamed", "lenient_tp", "named_by_karadul",
                      "precision", "recall", "f1")


# ---------------------------------------------------------------------------
# Koşu dizini
# ---------------------------------------------------------------------------

def ts_dir(run_dir: Path) -> Optional[Path]:
    """function_f1.find_run_artifacts ile aynı kural: en yeni static/ghidra_functions.json."""
    hits = sorted(run_dir.glob("ws/**/static/ghidra_functions.json"))
    return hits[-1].parent.parent if hits else None


def read_json(path: Path) -> Optional[Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_run(data_dir: Path, label: str, program: str) -> dict[str, Any]:
    rdir = data_dir / "runs" / label / program
    ts = ts_dir(rdir)
    if ts is None:
        raise SystemExit(f"{label}/{program}: static/ghidra_functions.json yok")
    rec = ts / "reconstructed"
    report = read_json(rdir / "out" / "report.json") or {}
    nbs = (report.get("pipeline", {}).get("stages", {}).get("reconstruct", {})
           .get("stats", {}).get("naming_by_strategy"))
    score = read_json(rdir / "macho_score.json") or {}
    iters = sorted((p for p in rec.glob("src_iter*") if p.name[8:].isdigit()),
                   key=lambda p: int(p.name[8:]))
    return {
        "label": label, "program": program, "rdir": rdir, "ts": ts,
        "naming": read_json(rec / "src" / "naming_map.json"),
        "provenance": read_json(rec / "src" / "naming_provenance.json"),
        "iters": {p.name: read_json(p / "naming_map.json") for p in iters},
        "naming_by_strategy": nbs,
        "score_rows": {str(r["addr"]): r for r in score.get("rows", [])},
        "score_summary": {k: score.get("summary", {}).get(k) for k in SCORE_SUMMARY_KEYS},
        "meta": read_json(rdir / "run.json") or {},
    }


# ---------------------------------------------------------------------------
# Karşılaştırmalar
# ---------------------------------------------------------------------------

def _leaf_diff(x: Any, y: Any, path: tuple = (), out: Optional[Counter] = None,
               depth: int = 1) -> Counter:
    """Ayrıştırılmış iki JSON arasındaki farklar: "<ilk depth anahtar>:<tür>" -> adet.

    Tür: ``deger`` (yaprak), ``eksik`` (anahtar bir tarafta yok), ``liste_sirasi``
    (aynı öğeler, farklı sıra), ``liste_icerigi`` (öğeler farklı).
    """
    out = Counter() if out is None else out
    top = "/".join(map(str, path[:depth])) or "<kok>"
    if isinstance(x, dict) and isinstance(y, dict):
        for k in set(x) | set(y):
            if k not in x or k not in y:
                out["/".join(map(str, (path + (k,))[:depth])) + ":eksik"] += 1
            else:
                _leaf_diff(x[k], y[k], path + (k,), out, depth)
    elif isinstance(x, list) and isinstance(y, list):
        if x != y:
            same = (len(x) == len(y)
                    and sorted(json.dumps(v, sort_keys=True) for v in x)
                    == sorted(json.dumps(v, sort_keys=True) for v in y))
            out[top + (":liste_sirasi" if same else ":liste_icerigi")] += 1
    elif x != y:
        out[top + ":deger"] += 1
    return out


def compare_inputs(rx: dict[str, Any], ry: dict[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {"ghidra_json": {}, "decompiled": {}}
    for name in GHIDRA_JSONS:
        px, py = rx["ts"] / "static" / name, ry["ts"] / "static" / name
        if not (px.is_file() and py.is_file()):
            res["ghidra_json"][name] = {"present": [px.is_file(), py.is_file()]}
            continue
        same_bytes = sha(px) == sha(py)
        entry: dict[str, Any] = {"bytes_equal": same_bytes}
        if not same_bytes:
            diff = _leaf_diff(read_json(px), read_json(py), depth=1)
            entry["content_equal"] = not diff
            entry["differing_leaves_by_top_key"] = dict(diff)
        else:
            entry["content_equal"] = True
        res["ghidra_json"][name] = entry
    for sub in DECOMPILED_DIRS:
        dx, dy = rx["ts"] / sub, ry["ts"] / sub
        fx = {p.name: sha(p) for p in dx.glob("*.c")} if dx.is_dir() else {}
        fy = {p.name: sha(p) for p in dy.glob("*.c")} if dy.is_dir() else {}
        common = set(fx) & set(fy)
        res["decompiled"][sub] = {
            "n_x": len(fx), "n_y": len(fy),
            "differ": sum(1 for n in common if fx[n] != fy[n]),
            "only_x": len(set(fx) - set(fy)), "only_y": len(set(fy) - set(fx)),
        }
    return res


def _group(key: str) -> str:
    if key.startswith("FUN_"):
        return "FUN_"
    if key.startswith("DAT_"):
        return "DAT_"
    return "diger"


def _name_diff(mx: dict[str, str], my: dict[str, str]) -> dict[str, Any]:
    common = set(mx) & set(my)
    differ = [k for k in common if mx[k] != my[k]]
    suffix_only = [k for k in differ
                   if SUFFIX_RE.sub("", mx[k]) == SUFFIX_RE.sub("", my[k])]
    return {"n_x": len(mx), "n_y": len(my), "same": len(common) - len(differ),
            "differ": len(differ), "differ_suffix_only": len(suffix_only),
            "only_x": len(set(mx) - set(my)), "only_y": len(set(my) - set(mx)),
            "_differ_keys": differ}


def _suffix_permutation_groups(mx: dict[str, str], my: dict[str, str],
                               keys: list[str]) -> dict[str, int]:
    """Son ek farkları aynı taban ad grubu içinde bir yer değiştirme mi?

    Bir taban ad grubu (ör. ``x``, ``x_2``, ``x_3``) iki koşuda aynı ad kümesini
    kullanıyorsa, fark yalnız hangi anahtarın hangi son eki aldığıdır.
    """
    bases = {SUFFIX_RE.sub("", mx[k]) for k in keys}
    perm = other = 0
    for b in bases:
        sx = sorted(v for v in mx.values() if SUFFIX_RE.sub("", v) == b)
        sy = sorted(v for v in my.values() if SUFFIX_RE.sub("", v) == b)
        if sx == sy:
            perm += 1
        else:
            other += 1
    return {"base_groups": len(bases), "same_name_set": perm, "different_name_set": other}


def compare_naming(nx: dict[str, Any], ny: dict[str, Any]) -> dict[str, Any]:
    gx, gy = nx.get("global", {}), ny.get("global", {})
    lx = {f"{f}::{o}": n for f, m in nx.get("per_function", {}).items() for o, n in m.items()}
    ly = {f"{f}::{o}": n for f, m in ny.get("per_function", {}).items() for o, n in m.items()}
    # c_namer'da son ek havuzu (used_new_names) global ve yerel adlara ORTAK:
    # bir taban adın son ek grubu ancak iki kapsamın birleşiminde tam görünür.
    allx = {**lx, **{f"G::{k}": v for k, v in gx.items()}}
    ally = {**ly, **{f"G::{k}": v for k, v in gy.items()}}
    out: dict[str, Any] = {"global": {}}
    for grp in ("FUN_", "DAT_", "diger"):
        sx = {k: v for k, v in gx.items() if _group(k) == grp}
        sy = {k: v for k, v in gy.items() if _group(k) == grp}
        d = _name_diff(sx, sy)
        keys = d.pop("_differ_keys")
        d["suffix_groups"] = _suffix_permutation_groups(
            allx, ally, [f"G::{k}" for k in keys
                         if SUFFIX_RE.sub("", gx[k]) == SUFFIX_RE.sub("", gy[k])])
        out["global"][grp] = d
    d = _name_diff(lx, ly)
    keys = d.pop("_differ_keys")
    d["suffix_groups"] = _suffix_permutation_groups(
        allx, ally, [k for k in keys if SUFFIX_RE.sub("", lx[k]) == SUFFIX_RE.sub("", ly[k])])
    d["functions_with_local_diff"] = len({k.split("::", 1)[0] for k in keys})
    out["local"] = d
    return out


def compare_score(rx: dict[str, Any], ry: dict[str, Any]) -> dict[str, Any]:
    ax, ay = rx["score_rows"], ry["score_rows"]
    common = set(ax) & set(ay)
    trans = Counter()
    pred_same_status = 0
    pred_changed = 0
    for a in common:
        sx, sy = ax[a].get("status"), ay[a].get("status")
        if ax[a].get("pred") != ay[a].get("pred"):
            pred_changed += 1
            if sx == sy:
                pred_same_status += 1
        if sx != sy:
            trans[f"{sx}->{sy}"] += 1
    sumx, sumy = rx["score_summary"], ry["score_summary"]
    return {
        "rows_x": len(ax), "rows_y": len(ay), "rows_common": len(common),
        "status_changed": sum(trans.values()), "transitions": dict(sorted(trans.items())),
        "pred_changed": pred_changed, "pred_changed_same_status": pred_same_status,
        "status_x": dict(Counter(r.get("status") for r in ax.values())),
        "status_y": dict(Counter(r.get("status") for r in ay.values())),
        "summary_x": sumx, "summary_y": sumy,
    }


def compare_strategy(rx: dict[str, Any], ry: dict[str, Any]) -> dict[str, Any]:
    sx, sy = rx["naming_by_strategy"] or {}, ry["naming_by_strategy"] or {}
    keys = sorted(set(sx) | set(sy))
    delta = {k: (sy.get(k, 0) - sx.get(k, 0)) for k in keys if sy.get(k, 0) != sx.get(k, 0)}
    return {"x": sx, "y": sy, "delta_y_minus_x": delta, "equal": not delta}


def compare_iters(rx: dict[str, Any], ry: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for name in sorted(set(rx["iters"]) | set(ry["iters"])):
        nx, ny = rx["iters"].get(name), ry["iters"].get(name)
        if nx is None or ny is None:
            out[name] = {"present": [nx is not None, ny is not None]}
            continue
        c = compare_naming(nx, ny)
        out[name] = {
            "global_FUN_differ": c["global"]["FUN_"]["differ"],
            "global_FUN_differ_suffix_only": c["global"]["FUN_"]["differ_suffix_only"],
            "global_DAT_differ": c["global"]["DAT_"]["differ"],
            "local_differ": c["local"]["differ"],
            "local_differ_suffix_only": c["local"]["differ_suffix_only"],
        }
    return out


# ---------------------------------------------------------------------------
# Köken kaydından kaynak
# ---------------------------------------------------------------------------

def _proposed(rec: dict[str, Any]) -> str:
    return rec.get("proposed_name", rec["new_name"])


def _top_tie(rec: dict[str, Any]) -> bool:
    ru = rec.get("runners_up") or []
    return bool(ru) and ru[0]["confidence"] == rec["confidence"]


def _classify(rx: dict[str, Any], ry: dict[str, Any]) -> str:
    if _proposed(rx) == _proposed(ry):
        return "son_ek_sirasi"            # aynı önerilen ad, farklı çakışma son eki
    if _top_tie(rx) or _top_tie(ry):
        return "esit_guven_sirasi"        # en üstte eşit güvenli rakip; kazanan sıraya bağlı
    if (rx["strategy"], rx["confidence"]) != (ry["strategy"], ry["confidence"]):
        return "farkli_aday"              # kazanan aday farklı, eşitlik yok
    return "diger"


def compare_provenance(px: dict[str, Any], py: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    gx, gy = px.get("global", {}), py.get("global", {})
    lx = {f"{f}::{o}": r for f, m in px.get("per_function", {}).items() for o, r in m.items()}
    ly = {f"{f}::{o}": r for f, m in py.get("per_function", {}).items() for o, r in m.items()}
    for scope, (dx, dy) in (("global", (gx, gy)), ("local", (lx, ly))):
        cats = Counter()
        by_strategy = Counter()
        strategy_pairs = Counter()
        tie_pairs = Counter()
        only_runners = 0
        evidence_differs = 0
        for k in set(dx) & set(dy):
            a, b = dx[k], dy[k]
            if a["new_name"] == b["new_name"]:
                if a.get("runners_up") != b.get("runners_up"):
                    only_runners += 1
                continue
            grp = _group(k) if scope == "global" else "yerel"
            cat = _classify(a, b)
            cats[f"{grp}:{cat}"] += 1
            by_strategy[f"{grp}:{cat}:{a['strategy']}"] += 1
            if a["strategy"] != b["strategy"]:
                strategy_pairs[f"{a['strategy']}|{b['strategy']}"] += 1
            if cat == "esit_guven_sirasi":
                ra = (a.get("runners_up") or [{}])[0]
                tie_pairs[f"{a['strategy']}|{ra.get('strategy')}"] += 1
            if a.get("evidence") != b.get("evidence"):
                evidence_differs += 1
        out[scope] = {
            "differ_by_category": dict(sorted(cats.items())),
            "differ_by_category_strategy": dict(sorted(by_strategy.items())),
            "winner_strategy_pairs_when_strategy_differs": dict(sorted(strategy_pairs.items())),
            "tie_winner_vs_rival_strategy_x": dict(sorted(tie_pairs.items())),
            "same_name_runners_up_differ": only_runners,
            "differ_with_different_evidence": evidence_differs,
        }
    # Tek koşuda bile görülen sıraya bağlı yük: en üstte eşitlik ve son ekli adlar
    def load(p: dict[str, Any]) -> dict[str, Any]:
        g = p.get("global", {})
        loc = [r for m in p.get("per_function", {}).values() for r in m.values()]
        return {
            "global_top_tie": dict(Counter(_group(k) for k, r in g.items() if _top_tie(r))),
            # kazanan|rakip strateji: aynı işçiden mi (sıra sabit) farklı işçiden mi
            "global_FUN_top_tie_pairs": dict(Counter(
                f"{r['strategy']}|{r['runners_up'][0]['strategy']}"
                for k, r in g.items() if k.startswith("FUN_") and _top_tie(r))),
            "global_suffixed": dict(Counter(_group(k) for k, r in g.items() if "proposed_name" in r)),
            "local_top_tie": sum(1 for r in loc if _top_tie(r)),
            "local_suffixed": sum(1 for r in loc if "proposed_name" in r),
            "summary": p.get("summary"),
        }
    out["load_x"], out["load_y"] = load(px), load(py)
    return out


# ---------------------------------------------------------------------------

def compare_pair(data_dir: Path, lx: str, ly: str, program: str) -> dict[str, Any]:
    rx, ry = load_run(data_dir, lx, program), load_run(data_dir, ly, program)
    res: dict[str, Any] = {
        "x": lx, "y": ly,
        "duration_s": [rx["meta"].get("duration_s"), ry["meta"].get("duration_s")],
        "status": [rx["meta"].get("status"), ry["meta"].get("status")],
        "cfg_cache_same": [rx["meta"].get("cfg_cache_before") == rx["meta"].get("cfg_cache_after"),
                           ry["meta"].get("cfg_cache_before") == ry["meta"].get("cfg_cache_after"),
                           rx["meta"].get("cfg_cache_before") == ry["meta"].get("cfg_cache_before")],
        "inputs": compare_inputs(rx, ry),
        "naming_map_src_bytes_equal": (sha(rx["ts"] / "reconstructed/src/naming_map.json")
                                       == sha(ry["ts"] / "reconstructed/src/naming_map.json")),
        "naming": compare_naming(rx["naming"], ry["naming"]),
        "iters": compare_iters(rx, ry),
        "score": compare_score(rx, ry),
        "naming_by_strategy": compare_strategy(rx, ry),
    }
    if rx["provenance"] is not None and ry["provenance"] is not None:
        res["provenance"] = compare_provenance(rx["provenance"], ry["provenance"])
    elif rx["provenance"] is not None:
        res["provenance_x_only_load"] = compare_provenance(rx["provenance"], rx["provenance"])["load_x"]
    return res


def session_info(data_dir: Path, label: str) -> dict[str, Any]:
    s = read_json(data_dir / "runs" / label / "session.json") or {}
    ch = s.get("tree_change") or {}
    return {"commit": (s.get("tree") or {}).get("commit", "")[:10],
            "dirty_files": len((s.get("tree") or {}).get("dirty_files", [])),
            "engine_paths": ch.get("engine_paths"), "tree_changed": s.get("tree_changed_during_run"),
            "ghidra": (s.get("ghidra") or {}).get("version"), "python": s.get("python"),
            "started_at": s.get("started_at"), "finished_at": s.get("finished_at")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--pair", action="append", required=True,
                    help="ad:etiket_x:etiket_y:program1,program2")
    args = ap.parse_args()
    report: dict[str, Any] = {"schema": "karadul.ol7/1", "sessions": {}, "comparisons": {}}
    for spec in args.pair:
        name, lx, ly, progs = spec.split(":")
        for lab in (lx, ly):
            report["sessions"].setdefault(lab, session_info(args.data_dir, lab))
        report["comparisons"][name] = {p: compare_pair(args.data_dir, lx, ly, p)
                                       for p in progs.split(",")}
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"yazıldı: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
