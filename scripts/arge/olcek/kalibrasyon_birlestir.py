#!/usr/bin/env python
"""ÖLÇEK kalem 3: ``metin_boyutu.py --ek-cikti`` dosyalarını tek kalibrasyon dosyasında birleştir.

Aynı yol bir kez. ``--adli <etiket>=<yol parçası>`` ile adı verilen hedefler işaretlenir
(``olcek_egri.py`` bunlar için kalibrasyonsuz, kendi kod baytı ve fonksiyon sayısıyla TAHMİN yazar).
Kod bölümü 0 olan (veri kitaplığı, ör. ICU verisi) kayıtlar oran hesabından çıkar.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/kalibrasyon_birlestir.py \
        --girdi yogunluk_llvm.json yogunluk_kicad.json … --cikti yogunluk.json \
        --adli T100=mlir-transform-opt --adli T300=libtensorflow_cc.2.dylib
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--girdi", nargs="+", required=True, type=Path)
    ap.add_argument("--cikti", required=True, type=Path)
    ap.add_argument("--adli", action="append", default=[])
    a = ap.parse_args(argv)
    adli = [x.split("=", 1) for x in a.adli]
    out, gor = [], set()
    for p in a.girdi:
        for k in json.loads(p.read_text(encoding="utf-8")):
            if k["yol"] in gor or not k.get("metin_bayt") or not k.get("fonksiyon_baslangici"):
                continue
            gor.add(k["yol"])
            for et, parca in adli:
                if parca in k["yol"]:
                    k["adli_hedef"] = et
            out.append(k)
    a.cikti.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(out)} kayıt; adlı: {[(k['adli_hedef'], Path(k['yol']).name) for k in out if k.get('adli_hedef')]}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
