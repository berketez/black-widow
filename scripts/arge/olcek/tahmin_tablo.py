#!/usr/bin/env python
"""ÖLÇEK kalem 3: ``egri.json``'daki dış değerlemeden (TAHMİN) Markdown tablo.

Yalnız ``olcek_egri.py``'nin yazdığı sayıları biçimler; yeni hesap yalnız toplama / çıkarma
(BSim hariç köprü = köprü alt ucu − BSim alt ucu).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/tahmin_tablo.py \
        --egri ~/karadul_olcum/runs/arge-2026-11-19/olcek/egri.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _s(x: float) -> str:
    return f"{x:,.1f}".replace(",", " ").replace(".", ",")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--egri", required=True, type=Path)
    a = ap.parse_args(argv)
    d = json.loads(a.egri.read_text(encoding="utf-8"))
    print("| Hedef | Dosya (MB) | Kod (MiB) | Fonksiyon | Köprü A [alt; üst] (sa) | Köprü B kötümser (sa) | "
          "BSim alt uç (sa) | BSim hariç köprü alt (sa) | Reconstruct [alt; üst] (sa) | Çalışma alanı (GB) | "
          "Dosya (milyon) | Python köprü belleği (GB) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for h, v in d["dis_degerleme_TAHMIN"].items():
        k = v["ghidra_kopru_toplam"]
        bs = (v.get("bsim") or {}).get("alt_sn", 0.0)
        r = v.get("reconstruct_sn (örneklem modeli, çapasız)") or {}
        dk = v.get("disk_calisma_alani_bayt (örneklem modeli, çapasız)") or {}
        df = v.get("disk_calisma_alani_dosya (örneklem modeli, çapasız)") or {}
        pb = v.get("python_kopru_bellegi_bayt (TAHMİN: JSON × çarpan)") or {}
        m, f = v["metin_kestirimi"], v["fonksiyon_kestirimi"]
        kod = _s(m[0] / 2**20) if abs(m[0] - m[1]) < 1 else f"{_s(m[0] / 2**20)}–{_s(m[1] / 2**20)}"
        fon = f"{f[0]:,.0f}".replace(",", " ") if abs(f[0] - f[1]) < 1 else \
            f"{f[0]:,.0f}–{f[1]:,.0f}".replace(",", " ")
        print(f"| {h} | {_s(v['dosya_bayt'] / 1e6)} | {kod} | {fon} | [{_s(k['alt_sn'] / 3600)}; "
              f"{_s(k['ust_sn'] / 3600)}] | {_s(k['kotumser_sn'] / 3600)} | {_s(bs / 3600)} | "
              f"{_s((k['alt_sn'] - bs) / 3600)} | [{_s(r.get('alt', 0) / 3600)}; {_s(r.get('ust', 0) / 3600)}] | "
              f"[{_s(dk.get('alt', 0) / 1e9)}; {_s(dk.get('ust', 0) / 1e9)}] | "
              f"[{_s(df.get('alt', 0) / 1e6)}; {_s(df.get('ust', 0) / 1e6)}] | "
              f"[{_s(pb.get('alt', 0) / 1e9)}; {_s(pb.get('ust', 0) / 1e9)}] |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
