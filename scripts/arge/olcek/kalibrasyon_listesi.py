#!/usr/bin/env python
"""ÖLÇEK kalem 3: kod oranı / fonksiyon yoğunluğu kalibrasyonu için AÇIK KAYNAK Mach-O listesi.

Envanterden (``envanter.py`` çıktısı) yalnız lisans sınıfı "açık kaynak" olan kurulumların tekil
(sha256) Mach-O çalıştırılabilir / dylib / bundle dosyaları, ``--en-az`` baytın üstündekiler.
Çıktı ``metin_boyutu.py --ek-liste`` biçimindedir: ``<yol>\\t<arch|->\\t<etiket>``. Evrensel
dosyada arm64 dilimi okunur. ``--capa`` verilirse gösteri dilimi "çapa" etiketiyle eklenir.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/kalibrasyon_listesi.py \
        --envanter ~/karadul_olcum/runs/arge-2026-11-19/olcek/envanter --en-az 5000000 \
        --capa ~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/workspaces/Ollama/<zaman>/raw/Ollama_arm64 \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/kalibrasyon_listesi.tsv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--envanter", required=True, type=Path)
    ap.add_argument("--en-az", type=int, default=5_000_000)
    ap.add_argument("--capa", type=Path)
    ap.add_argument("--cikti", required=True, type=Path)
    a = ap.parse_args(argv)
    satirlar = []
    gor: set[str] = set()
    for p in sorted(a.envanter.glob("*.json")):
        if p.name == "ozet.json":
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        if not d["ozet"]["lisans_sinifi"].startswith("açık kaynak"):
            continue
        for k in d["kayitlar"]:
            if k["sinif"] not in ("Mach-O çalıştırılabilir", "Mach-O dylib", "Mach-O bundle"):
                continue
            if k["bayt"] < a.en_az or not k["sha256"] or k["sha256"] in gor:
                continue
            if k["evrensel"] and "arm64" not in (k.get("mimariler") or []):
                continue
            gor.add(k["sha256"])
            arch = "arm64" if k["evrensel"] else "-"
            satirlar.append(f"{k['yol']}\t{arch}\t{d['ozet']['ad']}\t{k.get('mimari_sayisi') or 1}")
    if a.capa:
        satirlar.append(f"{a.capa}\t-\tçapa\t1")
    a.cikti.write_text("\n".join(satirlar) + "\n", encoding="utf-8")
    print(f"{len(satirlar)} satır → {a.cikti}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
