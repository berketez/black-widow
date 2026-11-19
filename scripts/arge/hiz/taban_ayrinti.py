#!/usr/bin/env python3
"""HIZ kalem 1 ek: taban zaman kaydından (``zaman_cizelgesi.py taban`` çıktısı) ölçekleme.

Kullanım (depo kökünden):
    python scripts/arge/hiz/taban_ayrinti.py \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman/taban_zaman.json \
        --gosteri ~/karadul_olcum/runs/arge-2026-11-19/hiz/zaman/gosteri_zaman.json

Çıktı: (1) en büyük 8 ikili + gösteri için Ghidra adımları ve fonksiyon başına süre;
(2) adım süresinin fonksiyon sayısına log-log eğimi (en küçük kareler; 1 = doğrusal);
(3) feedback_loop iç kırılımı (timing_*), sınıf başına toplam.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from zaman_cizelgesi import GHIDRA_ADIMLARI  # aynı dizin; tek tanım orada

_ATLANAN = {"strings.json", "types.json", "function_id.json", "bsim_shadow.json",
            "combined_results.json"}
IZLENEN_DOSYALAR = [d for d, _ in GHIDRA_ADIMLARI if d not in _ATLANAN]


def egim(xs: list[float], ys: list[float]) -> float | None:
    pts = [(math.log(x), math.log(y)) for x, y in zip(xs, ys) if x and y and x > 0 and y > 0]
    if len(pts) < 3:
        return None
    mx = sum(p[0] for p in pts) / len(pts)
    my = sum(p[1] for p in pts) / len(pts)
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pts)
    return sxy / sxx if sxx else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--taban", required=True, type=Path)
    ap.add_argument("--gosteri", type=Path)
    a = ap.parse_args()
    kay = json.loads(a.taban.expanduser().read_text())
    gos = json.loads(a.gosteri.expanduser().read_text()) if a.gosteri else None

    satirlar = []
    for k in kay:
        r = {"ad": k["anahtar"], "fn": k["fonksiyon"] or 0, "ghidra": k["ghidra_sure_sn"],
             "oto": k["otomatik_analiz_sn"]}
        for d in IZLENEN_DOSYALAR:
            r[d] = k["ghidra_adim"].get(d)
        r["bsim_kilit"] = (k["bsim"] or {}).get("lock_wait_s")
        r["bsim_ingest"] = (k["bsim"] or {}).get("ingest_s")
        r["bsim_sorgu"] = (k["bsim"] or {}).get("query_s")
        r["bsim_hash"] = (k["bsim"] or {}).get("ingested_functions")
        r["bsim_eslesme"] = (k["bsim"] or {}).get("total_matches")
        b = k["boru"] or {}
        r["toplam"] = b.get("toplam_sn")
        asm = b.get("asamalar") or {}
        r["statik_disi"] = (asm.get("static") or 0) - (k["ghidra_sure_sn"] or 0)
        r["deob"] = asm.get("deobfuscate")
        r["rec"] = asm.get("reconstruct")
        r["fb"] = (b.get("yeniden_kurma_adimlari") or {}).get("feedback_loop")
        r["ic"] = b.get("yeniden_kurma_ic") or {}
        satirlar.append(r)
    if gos:
        g = gos["ghidra"]
        r = {"ad": "GÖSTERİ Ollama", "fn": g["fonksiyon"], "ghidra": g["ghidra_sure_sn"],
             "oto": g["otomatik_analiz_sn"]}
        ad = {x["dosya"]: x["sure_sn"] for x in g["adimlar"]}
        for d in IZLENEN_DOSYALAR:
            r[d] = ad.get(d)
        r["bsim_kilit"] = g["bsim"]["lock_wait_s"]
        r["bsim_ingest"] = g["bsim"]["ingest_s"]
        r["bsim_sorgu"] = g["bsim"]["query_s"]
        r["bsim_hash"] = g["bsim"]["ingested_functions"]
        r["bsim_eslesme"] = g["bsim"]["total_matches"]
        olay = {o["olay"]: o for o in gos["olaylar"]}
        intel = olay.get("static/intelligence_report.json")
        r["statik_disi"] = intel["oncekinden_sn"] if intel else None
        r["toplam"] = r["deob"] = r["rec"] = r["fb"] = None
        r["ic"] = {}
        satirlar.append(r)

    satirlar.sort(key=lambda r: r["fn"])
    print("## En büyük 8 ikili + gösteri: Ghidra adımları (sn) ve ms / fonksiyon")
    print()
    print("| İkili | fn | oto | call_graph | decompile | xref | cfg | BSim (ingest / sorgu / kilit) | hash | eşleşme | Ghidra sonrası statik | deob | feedback_loop | toplam |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in satirlar[-9:]:
        def f(v):
            return "—" if v is None else "%.1f" % v
        print("| %s | %d | %s | %s | %s | %s | %s | %s / %s / %s | %s | %s | %s | %s | %s | %s |" % (
            r["ad"], r["fn"], f(r["oto"]), f(r["call_graph.json"]), f(r["decompiled.json"]),
            f(r["xrefs.json"]), f(r["cfg.json"]), f(r["bsim_ingest"]), f(r["bsim_sorgu"]),
            f(r["bsim_kilit"]), r["bsim_hash"], r["bsim_eslesme"], f(r["statik_disi"]),
            f(r["deob"]), f(r["fb"]), f(r["toplam"])))
    print()
    print("ms / fonksiyon (aynı satırlar):")
    print()
    print("| İkili | fn | decompile | xref | cfg | BSim ingest | BSim sorgu | Ghidra sonrası statik |")
    print("|---|---|---|---|---|---|---|---|")
    for r in satirlar[-9:]:
        def m(v):
            return "—" if (v is None or not r["fn"]) else "%.1f" % (1000.0 * v / r["fn"])
        print("| %s | %d | %s | %s | %s | %s | %s | %s |" % (
            r["ad"], r["fn"], m(r["decompiled.json"]), m(r["xrefs.json"]), m(r["cfg.json"]),
            m(r["bsim_ingest"]), m(r["bsim_sorgu"]), m(r["statik_disi"])))
    print()
    print("## Log-log eğim: adım süresi ~ fonksiyon^eğim (taban 119 ikili; gösteri dahil / hariç)")
    print()
    print("| Adım | eğim (taban) | eğim (taban + gösteri) |")
    print("|---|---|---|")
    taban_s = [r for r in satirlar if not r["ad"].startswith("GÖSTERİ")]
    for d in IZLENEN_DOSYALAR + ["statik_disi", "deob", "fb"]:
        e1 = egim([r["fn"] for r in taban_s], [r[d] for r in taban_s])
        e2 = egim([r["fn"] for r in satirlar], [r[d] for r in satirlar])
        print("| %s | %s | %s |" % (d, "—" if e1 is None else "%.2f" % e1,
                                    "—" if e2 is None else "%.2f" % e2))
    print()
    print("## feedback_loop iç kırılımı (timing_*, taban toplamı, sn)")
    print()
    top: dict[str, float] = {}
    for r in taban_s:
        for k, v in r["ic"].items():
            top[k] = top.get(k, 0.0) + v
    fbt = sum(r["fb"] or 0 for r in taban_s)
    print("feedback_loop toplam: %.1f sn" % fbt)
    print()
    print("| timing_ | toplam (sn) | feedback_loop payı |")
    print("|---|---|---|")
    for k, v in sorted(top.items(), key=lambda x: -x[1])[:25]:
        if "iter" in k:
            print("| %s | %.1f | %.1f %% |" % (k, v, 100 * v / fbt if fbt else 0))
    print()
    print("## İkili başına sabit maliyet: JVM + içe aktarma + fonksiyon listesi (functions.json − otomatik analiz)")
    sabit = sorted(max(0.0, (r["functions.json"] or 0) - (r["oto"] or 0)) for r in taban_s if r["functions.json"] is not None)
    if sabit:
        q = lambda f: sabit[min(len(sabit) - 1, int(f * len(sabit)))]
        print("n=%d ortanca %.1f sn, çeyrekler %.1f / %.1f sn, en az %.1f, en çok %.1f" % (
            len(sabit), q(0.5), q(0.25), q(0.75), sabit[0], sabit[-1]))
    ghs = [r["ghidra"] for r in taban_s if r["ghidra"]]
    tops = [r["toplam"] for r in taban_s if r["toplam"]]
    print("Ghidra köprüsü / toplam duvar (119 toplamı): %.0f / %.0f sn = %.1f %%" % (sum(ghs), sum(tops), 100 * sum(ghs) / sum(tops)))
    print()
    print("## Toplam taban duvar süresi ve sınıf payı")
    tt = sum(r["toplam"] or 0 for r in taban_s)
    print("119 ikili toplam duvar: %.0f sn" % tt)


if __name__ == "__main__":
    main()
