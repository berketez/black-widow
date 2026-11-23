"""BA-1: iki blok açıklama çıktı dizinini bayt bayt karşılaştırır.

``--eski`` dizinindeki her dosya ``--yeni``'de aynı adla aranır ve baytları
karşılaştırılır (eski koşu yarıda kaldıysa yalnız onun yazdığı dosyalar
sayılır). ``block_annotations.json`` ayrıca karşılaştırılır: adımın çıktısı
girdi dışında bir şeye bağlı değil (``block_annotator.py``'de zaman, rastgele,
süreç kimliği kullanımı yok; dosya sırası ``sorted(rglob)``), bu yüzden alan
ayırmadan tam bayt karşılaştırması yapılır.

Kullanım:

    python scripts/arge/ba1/cikti_karsilastir.py --eski <dizin> --yeni <dizin> [--json <dosya>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def karsilastir(eski: Path, yeni: Path) -> dict:
    eski_dosyalar = sorted(p.name for p in eski.iterdir() if p.is_file())
    yeni_dosyalar = {p.name for p in yeni.iterdir() if p.is_file()}
    esit = 0
    farkli: list[str] = []
    yeni_de_yok: list[str] = []
    for ad in eski_dosyalar:
        if ad not in yeni_dosyalar:
            yeni_de_yok.append(ad)
            continue
        if (eski / ad).read_bytes() == (yeni / ad).read_bytes():
            esit += 1
        else:
            farkli.append(ad)
    h = hashlib.sha256()
    for ad in sorted(yeni_dosyalar):
        h.update(ad.encode())
        h.update(hashlib.sha256((yeni / ad).read_bytes()).digest())
    return {
        "eski_dosya": len(eski_dosyalar),
        "yeni_dosya": len(yeni_dosyalar),
        "esit": esit,
        "farkli": len(farkli),
        "farkli_ilk_20": farkli[:20],
        "yenide_yok": len(yeni_de_yok),
        "yenide_yok_ilk_20": yeni_de_yok[:20],
        "yeni_sha256": h.hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eski", required=True)
    ap.add_argument("--yeni", required=True)
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    r = karsilastir(Path(args.eski), Path(args.yeni))
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
