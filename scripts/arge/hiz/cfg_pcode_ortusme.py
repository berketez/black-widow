#!/usr/bin/env python3
"""HIZ kalem 5: ``cfg.json`` ile ``pcode.jsonl`` örtüşüyor mu; biçim kaynaklı şişme ne kadar?

Salt okur. Her iki dosyanın alan yapısı, fonksiyon kümesi kesişimi, bilgi türü ve
``cfg.json``'un ``indent=2`` yerine sıkı (``separators=(",", ":")``) yazılsaydı boyutu.
Ayrıca ``static/ghidra_*.json`` ikinci kopyalarının toplam baytı (``macho.py:434-438``).

Kullanım:
    python scripts/arge/hiz/cfg_pcode_ortusme.py --static <ws>/static
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--static", required=True, type=Path)
    a = ap.parse_args()
    st = a.static.expanduser()
    go = st / "ghidra_output"
    cfg_b = (go / "cfg.json").read_bytes()
    cfg = json.loads(cfg_b)
    sik = json.dumps(cfg, ensure_ascii=False, separators=(",", ":")).encode()
    f0 = cfg["functions"][0] if cfg["functions"] else {}
    b0 = (f0.get("blocks") or [{}])[0]
    print("cfg.json: %.1f MB (indent=2); sıkı yazım %.1f MB (oran %.2f)" % (
        len(cfg_b) / 1e6, len(sik) / 1e6, len(sik) / len(cfg_b)))
    print("  fonksiyon alanları:", sorted(f0.keys()))
    print("  blok alanları:", sorted(b0.keys()))
    adres_cfg = {f["address"] for f in cfg["functions"]}
    pj = go / "pcode.jsonl"
    adres_pc = set()
    pc_alan = set()
    n_pc = 0
    with pj.open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            adres_pc.add(r["a"])
            pc_alan.update(r.keys())
            n_pc += 1
    print("pcode.jsonl: %.1f MB, %d satır, alanlar %s" % (pj.stat().st_size / 1e6, n_pc, sorted(pc_alan)))
    print("fonksiyon kesişimi: cfg %d, pcode %d, ortak %d" % (len(adres_cfg), len(adres_pc), len(adres_cfg & adres_pc)))
    mn = sum(len(b.get("mnemonics") or []) for f in cfg["functions"] for b in f["blocks"])
    mn_bayt = sum(len(json.dumps(b.get("mnemonics") or [])) for f in cfg["functions"] for b in f["blocks"])
    print("cfg komut adı (mnemonics) öğesi: %d; sıkı JSON'da yaklaşık %.1f MB" % (mn, mn_bayt / 1e6))
    kop = [p for p in st.glob("ghidra_*.json") if p.name not in ("ghidra_status.json",)]
    print("static/ghidra_*.json ikinci kopyalar: %d dosya, %.1f MB" % (len(kop), sum(p.stat().st_size for p in kop) / 1e6))
    orj = [p for p in go.glob("*.json")]
    print("ghidra_output/*.json: %d dosya, %.1f MB; pcode.jsonl %.1f MB; decompiled/ ayrı" % (
        len(orj), sum(p.stat().st_size for p in orj) / 1e6, pj.stat().st_size / 1e6))


if __name__ == "__main__":
    main()
