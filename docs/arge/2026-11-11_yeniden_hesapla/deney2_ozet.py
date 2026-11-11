"""Deney 2 özeti: sınırları ayrı ayrı say, yeni etiketlerin yöntemini ve yaygınlığını çıkar.

deney2_sonuc.json'u okur; gövde kırpması kolunu (CA) yeniden koşup yeni (fonksiyon, etiket)
çiftlerini yöntem/güven ile döker; alan kapısı kolunun (EN1) etiket yaygınlığını hesaplar:
bir etiket ikilideki fonksiyonların büyük kısmına yapışıyorsa o etiket fonksiyonu ayırt etmez
(GT'siz iç tutarlılık ölçüsü).
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2]))

import deney2_algoritma_tarama as d2  # noqa: E402
from say_sinirlar import BINARIES, workspace  # noqa: E402


def main() -> None:
    res = json.loads((HERE / "deney2_sonuc.json").read_text(encoding="utf-8"))
    out: dict = {"ca_new_pairs": {}, "en1_label_prevalence": {}, "sample_split": {}}
    for label, base in BINARIES.items():
        ws = workspace(base)
        deob = ws / "deobfuscated/decompiled"
        fjson = ws / "deobfuscated/ghidra_functions.json"
        sjson = ws / "deobfuscated/ghidra_strings.json"
        ca0, _ = d2.run_ca(deob, fjson, sjson, full=False)
        ca1, _ = d2.run_ca(deob, fjson, sjson, full=True)
        k0 = d2.key_set(ca0)
        new = [m for m in ca1 if (m.function_name, m.name) not in k0]
        out["ca_new_pairs"][label] = {
            "n": len(new),
            "by_method": dict(collections.Counter(m.detection_method for m in new)),
            "functions": len({m.function_name for m in new}),
            "pairs": [(m.function_name, m.name, m.detection_method, m.confidence) for m in new],
        }
        en1, _, _ = d2.run_eng(deob, fjson, gate_open=True, full=False)
        n_bodies = res["census"][label]["bodies"]
        funcs_per_label = collections.defaultdict(set)
        for m in en1:
            if m.confidence >= d2.NAMING_FLOOR:
                funcs_per_label[m.name].add(m.function_name)
        top = sorted(funcs_per_label.items(), key=lambda kv: -len(kv[1]))[:8]
        labelled = {f for fs in funcs_per_label.values() for f in fs}
        out["en1_label_prevalence"][label] = {
            "bodies": n_bodies,
            "functions_with_any_label_ge_0.40": len(labelled),
            "top_labels": [(name, len(fs), round(len(fs) / n_bodies, 3)) for name, fs in top],
        }
        print(label, out["ca_new_pairs"][label]["by_method"],
              out["en1_label_prevalence"][label]["top_labels"][:4], flush=True)

    for name, s in res["samples"].items():
        rows = s["rows"]

        def labels(arm, r):
            return {x[0] for x in r[arm]["labels"] if x[2] >= d2.NAMING_FLOOR}

        body_new = [r for r in rows if labels("ca_full", r) - labels("ca_cap", r)]
        gate_new = [r for r in rows if labels("en_open_full", r) - labels("en_product", r)]
        secs = sorted(r["ca_full"]["seconds"] + r["en_open_full"]["seconds"] for r in rows)
        out["sample_split"][name] = {
            "n": len(rows),
            "body_cap_new_functions": len(body_new),
            "body_cap_new": [(r["binary"], r["func"], r["body_len"],
                              sorted(labels("ca_full", r) - labels("ca_cap", r))) for r in body_new],
            "gate_new_functions": len(gate_new),
            "gate_labels_per_function": sorted(len(labels("en_open_full", r)) for r in gate_new),
            "rescan_seconds_median": secs[len(secs) // 2] if secs else None,
            "rescan_seconds_max": secs[-1] if secs else None,
        }
        print(name, {k: v for k, v in out["sample_split"][name].items() if k != "body_cap_new"})
    (HERE / "deney2_ozet.json").write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str),
                                          encoding="utf-8")


if __name__ == "__main__":
    main()
