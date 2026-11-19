#!/usr/bin/env python3
"""HIZ kalem 5 (gereksiz iş): ``feedback_loop``'un ikinci ve sonraki turları yeni ad üretiyor mu?

Taban koşusunun her ikilisinde ``reports/pipeline_result.json`` →
``stages.reconstruct.stats.pipeline_iteration_details`` (tur başına ``new_names``, ``duration``)
ve ``convergence_reason`` okunur. Salt okur.

Kullanım:
    python scripts/arge/hiz/tur_sayimi.py --kok ~/karadul_olcum/runs/urun-onarim-a62f15e
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kok", required=True, type=Path)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    kok = a.kok.expanduser()
    satirlar = []
    for pr in sorted(kok.glob("**/ws/workspaces/*/*/reports/pipeline_result.json")):
        d = json.loads(pr.read_text())
        st = (d.get("stages") or {}).get("reconstruct", {}).get("stats", {})
        det = st.get("pipeline_iteration_details") or []
        fb = st.get("feedback_loop_duration_s")
        satirlar.append({
            "ikili": str(pr.parents[4].relative_to(kok)) if len(pr.parents) > 4 else str(pr),
            "turlar": len(det), "neden": st.get("convergence_reason"),
            "yeni_ad": [t.get("new_names") for t in det],
            "tur_sn": [t.get("duration") for t in det],
            "feedback_loop_sn": fb,
        })
    n = len(satirlar)
    neden = collections.Counter(s["neden"] for s in satirlar)
    tur = collections.Counter(s["turlar"] for s in satirlar)
    son_tur_sifir = sum(1 for s in satirlar if s["yeni_ad"] and s["yeni_ad"][-1] == 0)
    ikinci_pozitif = sum(1 for s in satirlar if len(s["yeni_ad"]) > 1 and (s["yeni_ad"][1] or 0) > 0)
    son_tur_sn = sum((s["tur_sn"][-1] or 0) for s in satirlar if s["yeni_ad"] and s["yeni_ad"][-1] == 0 and len(s["tur_sn"]) > 1)
    fb_top = sum(s["feedback_loop_sn"] or 0 for s in satirlar)
    print("ikili: %d" % n)
    print("tur sayısı dağılımı:", dict(tur))
    print("yakınsama nedeni:", dict(neden))
    print("son turu 0 yeni ad üreten ikili: %d / %d" % (son_tur_sifir, n))
    print("ikinci turda > 0 yeni ad üreten ikili: %d / %d" % (ikinci_pozitif, n))
    print("0 yeni ad üreten son turların toplam süresi: %.1f sn (feedback_loop toplamı %.1f sn, pay %.1f %%)" % (
        son_tur_sn, fb_top, 100 * son_tur_sn / fb_top if fb_top else 0))
    ornek = [s for s in satirlar if len(s["yeni_ad"]) > 1 and (s["yeni_ad"][1] or 0) > 0][:10]
    if ornek:
        print("ikinci turda yeni ad üretenlerden örnek:")
        for s in ornek:
            print("  %s yeni_ad=%s tur_sn=%s" % (s["ikili"], s["yeni_ad"], s["tur_sn"]))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(satirlar, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
