"""Deney 2: algoritma tanıma taramasının fonksiyon başı sınırları.

İki sınır aynı analizin (fonksiyon gövdesinde sabit/yapı/API taraması) kapsamını daraltır:
  * Mühendislik alan kapısı (engineering/analyzer.py:276; _detect_domain 846-893): kapı
    kapalıysa sabit ve yapı katmanı HİÇBİR fonksiyonda koşmaz (yalnız API katmanı).
  * Gövde 5000 karakter kırpması (c_algorithm_id.py:1171, engineering/analyzer.py:1002):
    tarama yalnız gövdenin ilk 5000 karakterini görür.

Kollar (aynı girdi, ürünün kendi tarama yöntemleri):
  CA-0  CAlgorithmIdentifier.identify (ürün, kırpmalı)
  CA-1  aynı, gövde sınırsız (alt sınıfta _extract_body üzerine yazılır)
  EN-0  EngineeringAlgorithmAnalyzer: kapı kapalı (ürünün bu ikililerdeki durumu), kırpmalı
  EN-1  kapı açık, kırpmalı
  EN-2  kapı kapalı, gövde sınırsız
  EN-3  kapı açık, gövde sınırsız

Girdi: saklı çalışma alanının deobfuscated/decompiled dizini (ürünün algorithm_id girdisi;
binary_prep.py:57-59). Kod: HEAD'deki ürün modülleri, değiştirilmeden.

Örneklem (görev kuralı, önceden yazıldı): sınıra takılan fonksiyonların havuzu
(ikili, adres) sırasına dizilir; random.Random(20261111).sample(havuz, 30).
  * Kapı örneklemi: kapı kapalı ikililerdeki bütün fonksiyonlar.
  * Kırpma örneklemi: gövdesi 5000 karakteri aşan fonksiyonlar.
Ayrıca (çevrimdışı ve ucuz olduğu için) bütün havuzun sayımı da verilir; bu ikinci
sayım örneklemin yerine geçmez, onu denetler.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import karadul.reconstruction.engineering.analyzer as eng_mod  # noqa: E402
from karadul.reconstruction.c_algorithm_id import (  # noqa: E402
    CAlgorithmIdentifier,
    _strip_ghidra_warnings,
)
from say_sinirlar import BINARIES, BODY_CAP, full_body, workspace  # noqa: E402

SEED = 20261111
SAMPLE = 30
NAMING_FLOOR = 0.40  # engineering_constant naming floor (analyzer.py:177-183 yorumu)
HIGH = 0.70          # analyzer.py:175 / c_algorithm_id istatistiği


class FullBodyIdentifier(CAlgorithmIdentifier):
    """Ürün tanımlayıcısı; tek fark gövde kırpması yok."""

    @staticmethod
    def _extract_body(content: str, brace_pos: int) -> str:
        if brace_pos >= len(content) or content[brace_pos] != "{":
            return ""
        return full_body(content, brace_pos)


_ORIG_ENG_EXTRACT_BODY = eng_mod._extract_body


def _eng_full_body(content: str, brace_pos: int) -> str:
    if brace_pos >= len(content) or content[brace_pos] != "{":
        return ""
    return full_body(content, brace_pos)


def key_set(matches, floor: float = 0.0) -> set[tuple[str, str]]:
    return {(m.function_name, m.name) for m in matches if m.confidence >= floor}


def run_ca(deob: Path, fjson: Path, sjson: Path, full: bool):
    cls = FullBodyIdentifier if full else CAlgorithmIdentifier
    t0 = time.monotonic()
    res = cls().identify(deob, fjson, sjson)
    return res.algorithms, time.monotonic() - t0


def run_eng(deob: Path, fjson: Path, gate_open: bool, full: bool):
    """identify()'ın süreç içi, sıralı eşi (ProcessPool işçileri yamayı görmez)."""
    eng_mod._extract_body = _eng_full_body if full else _ORIG_ENG_EXTRACT_BODY
    try:
        an = eng_mod.EngineeringAlgorithmAnalyzer()
        errs: list[str] = []
        func_meta = an._load_json(fjson, errs)
        c_files = an._collect_c_files(deob, errs)
        product_gate = an._detect_domain(func_meta, c_files)
        has_domain = True if gate_open else product_gate
        t0 = time.monotonic()
        raw = []
        for f in c_files:
            raw.extend(an._analyze_file(f, func_meta, has_domain))
        combined = an._combine_evidence(raw)
        dedup = an._deduplicate(combined)
        return dedup, time.monotonic() - t0, product_gate
    finally:
        eng_mod._extract_body = _ORIG_ENG_EXTRACT_BODY


def function_bodies(deob: Path) -> list[dict]:
    """(dosya, fonksiyon adı, tam gövde uzunluğu) — sınıra takılan havuzlar için."""
    out = []
    rx = CAlgorithmIdentifier._FUNC_RE
    for cfile in sorted(deob.rglob("*.c")):
        content = _strip_ghidra_warnings(cfile.read_text(encoding="utf-8", errors="replace"))
        for m in rx.finditer(content):
            body = full_body(content, m.end() - 1)
            out.append({"file": str(cfile), "func": m.group(1), "len": len(body)})
    return out


def per_function_rescan(entry: dict, func_meta: dict) -> dict:
    """Örneklemdeki tek fonksiyonu büyük bütçeyle yeniden tara; süre ve yeni etiketler."""
    content = _strip_ghidra_warnings(Path(entry["file"]).read_text(encoding="utf-8", errors="replace"))
    out = {"func": entry["func"], "body_len": entry["len"]}
    for arm, ident in (("ca_cap", CAlgorithmIdentifier()), ("ca_full", FullBodyIdentifier())):
        t0 = time.monotonic()
        names: list = []
        for fname, body, addr in ident._extract_functions(content, func_meta, Path(entry["file"]).stem):
            if fname != entry["func"]:
                continue
            ms = (ident._scan_constants(body, fname, addr) + ident._scan_structural(body, fname, addr)
                  + ident._scan_apis(body, fname, addr))
            names.extend((m.name, m.detection_method, m.confidence) for m in ms)
        out[arm] = {"labels": names, "seconds": round(time.monotonic() - t0, 4)}
    an = eng_mod.EngineeringAlgorithmAnalyzer()
    for arm, gate, full in (("en_product", False, False), ("en_open_full", True, True)):
        eng_mod._extract_body = _eng_full_body if full else _ORIG_ENG_EXTRACT_BODY
        try:
            t0 = time.monotonic()
            ms = [m for m in an._analyze_file(Path(entry["file"]), func_meta, gate)
                  if m.function_name == entry["func"]]
            labels = [(m.name, m.detection_method, m.confidence) for m in an._combine_evidence(ms)]
            out[arm] = {"labels": labels, "seconds": round(time.monotonic() - t0, 4)}
        finally:
            eng_mod._extract_body = _ORIG_ENG_EXTRACT_BODY
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    census: dict = {}
    gate_pool: list[dict] = []
    cap_pool: list[dict] = []
    meta_by_label: dict = {}
    for label, base in BINARIES.items():
        ws = workspace(base)
        deob = ws / "deobfuscated/decompiled"
        fjson = ws / "deobfuscated/ghidra_functions.json"
        if not fjson.exists():
            fjson = ws / "static/ghidra_functions.json"
        sjson = ws / "deobfuscated/ghidra_strings.json"
        if not sjson.exists():
            sjson = ws / "static/ghidra_strings.json"
        meta_by_label[label] = json.loads(fjson.read_text(encoding="utf-8"))

        ca0, t_ca0 = run_ca(deob, fjson, sjson, full=False)
        ca1, t_ca1 = run_ca(deob, fjson, sjson, full=True)
        en0, t_en0, gate = run_eng(deob, fjson, gate_open=False, full=False)
        en1, t_en1, _ = run_eng(deob, fjson, gate_open=True, full=False)
        en2, t_en2, _ = run_eng(deob, fjson, gate_open=False, full=True)
        en3, t_en3, _ = run_eng(deob, fjson, gate_open=True, full=True)

        bodies = function_bodies(deob)
        for b in bodies:
            b["binary"] = label
            if not gate:
                gate_pool.append(b)
            if b["len"] > BODY_CAP:
                cap_pool.append(b)

        def new(a, b, floor=0.0):
            return sorted(key_set(b, floor) - key_set(a, floor))

        census[label] = {
            "product_gate_open": gate,
            "ca": {
                "cap_total": len(ca0), "full_total": len(ca1),
                "new_pairs_any": len(new(ca0, ca1)),
                "new_pairs_ge_0.40": len(new(ca0, ca1, NAMING_FLOOR)),
                "new_pairs_ge_0.70": len(new(ca0, ca1, HIGH)),
                "lost_pairs_any": len(sorted(key_set(ca0) - key_set(ca1))),
                "new_examples": new(ca0, ca1)[:15],
                "seconds_cap": round(t_ca0, 2), "seconds_full": round(t_ca1, 2),
            },
            "eng": {
                "EN0_total": len(en0), "EN1_total": len(en1), "EN2_total": len(en2), "EN3_total": len(en3),
                "gate_new_any": len(new(en0, en1)),
                "gate_new_ge_0.40": len(new(en0, en1, NAMING_FLOOR)),
                "gate_new_ge_0.70": len(new(en0, en1, HIGH)),
                "body_new_any": len(new(en0, en2)),
                "both_new_any": len(new(en0, en3)),
                "both_new_ge_0.40": len(new(en0, en3, NAMING_FLOOR)),
                "both_new_ge_0.70": len(new(en0, en3, HIGH)),
                "both_new_examples": new(en0, en3, NAMING_FLOOR)[:15],
                "functions_with_new_ge_0.40": len({f for f, _ in new(en0, en3, NAMING_FLOOR)}),
                "seconds": {"EN0": round(t_en0, 2), "EN1": round(t_en1, 2),
                            "EN2": round(t_en2, 2), "EN3": round(t_en3, 2)},
            },
            "bodies": len(bodies),
            "bodies_over_cap": sum(1 for b in bodies if b["len"] > BODY_CAP),
        }
        print(label, json.dumps({k: (v if not isinstance(v, dict) else
                                     {kk: vv for kk, vv in v.items() if "examples" not in kk})
                                 for k, v in census[label].items()}, ensure_ascii=False), flush=True)

    rng = random.Random(SEED)
    gate_pool.sort(key=lambda b: (b["binary"], b["file"], b["func"]))
    cap_pool.sort(key=lambda b: (b["binary"], b["file"], b["func"]))
    samples = {
        "gate": rng.sample(gate_pool, min(SAMPLE, len(gate_pool))),
        "body_cap": random.Random(SEED).sample(cap_pool, min(SAMPLE, len(cap_pool))),
    }
    sample_results: dict = {}
    for name, entries in samples.items():
        rows = []
        for e in entries:
            func_meta = eng_mod.EngineeringAlgorithmAnalyzer._load_json(
                Path(e["file"]).parents[1] / "ghidra_functions.json", [])
            r = per_function_rescan(e, func_meta)
            r["binary"] = e["binary"]
            ca_new = ({(n, ) for n, _, c in r["ca_full"]["labels"] if c >= NAMING_FLOOR}
                      - {(n, ) for n, _, c in r["ca_cap"]["labels"] if c >= NAMING_FLOOR})
            en_new = ({(n, ) for n, _, c in r["en_open_full"]["labels"] if c >= NAMING_FLOOR}
                      - {(n, ) for n, _, c in r["en_product"]["labels"] if c >= NAMING_FLOOR})
            r["new_labels_ge_0.40"] = sorted(x[0] for x in ca_new | en_new)
            rows.append(r)
        sample_results[name] = {
            "n": len(rows),
            "functions_with_new_ge_0.40": sum(1 for r in rows if r["new_labels_ge_0.40"]),
            "seconds_per_function_max": max(
                (r["ca_full"]["seconds"] + r["en_open_full"]["seconds"]) for r in rows) if rows else None,
            "seconds_per_function_median": sorted(
                (r["ca_full"]["seconds"] + r["en_open_full"]["seconds"]) for r in rows)[len(rows) // 2] if rows else None,
            "rows": rows,
        }
        print(name, {k: v for k, v in sample_results[name].items() if k != "rows"}, flush=True)

    Path(args.out).write_text(json.dumps({
        "seed": SEED, "sample_size": SAMPLE, "naming_floor": NAMING_FLOOR, "high": HIGH,
        "census": census, "samples": sample_results,
        "pool_sizes": {"gate": len(gate_pool), "body_cap": len(cap_pool)},
    }, indent=1, ensure_ascii=False, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
