"""Gösteri koşusunun (Ollama arm64 dilimi) bitmiş çıktısını salt okur: süre, durum, ad sayısı. Ad dökülmez.

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/gosteri_oku.py > $V/gosteri_oku.txt
"""
import json
import os
import re
from collections import Counter
from pathlib import Path

G = Path(os.path.expanduser("~/karadul_olcum/runs/gosteri-2026-11-19/ollama"))
for ad in ("BASLADI", "BITTI", "CIKIS"):
    p = G / ad
    print(ad, p.read_text().strip() if p.exists() else "YOK")
gunluk = (G / "kosu.log").read_text(encoding="utf-8", errors="replace")
for kalip in (r"Durum\s+│\s+([^│]+)│", r"Functions recovered\s+│\s+(\d+)", r"Import stubs \(thunk\)\s+│\s+(\d+)",
              r"Variables renamed\s+│\s+(\d+)", r"([\d.]+) real", r"(\d+)\s+maximum resident set size",
              r"(\d+)\s+peak memory footprint", r"(UYARI: analiz kısmi[^\n]+)", r"(static: Desteklenmiyor[^\n]{0,200})",
              r"(Ghidra'da bulunmayan çözümleyici adı[^\n]+)", r"(Pipeline iteration 1 took[^\n]+)"):
    m = re.search(kalip, gunluk)
    print(kalip.split("\\")[0][:28].ljust(30), "→", m.group(1).strip() if m else "bulunamadı")
d = json.load(open(G / "out" / "naming_map.json"))
print("naming_map sürüm", d.get("version"), "total_mappings", d.get("total_mappings"), "total_candidates", d.get("total_candidates"))
m = d.get("mappings") or {}
print("fonksiyon anahtarlı (FUN_) eşleme:", sum(1 for k in m if k.startswith("FUN_")))
print("kanal:", dict(Counter((v.get("channel") or "?") for v in m.values())))
print("etiket:", dict(Counter((v.get("label") or "?") for v in m.values())))
