#!/usr/bin/env python
"""KİMLİK hattı — ürünün sürüm tespitçisinin (``reference_differ.VersionDetector``) geliştirme setindeki çıktısı.

"Başvuru derlemesi nereden gelir" sorusunun ilk adımı: ikilinin hangi program / kitaplık ve hangi sürüm olduğunu
bilmek. Ürün kodu değiştirilmez; ``detect_from_strings`` taban koşusunun ``ghidra_strings.json``'ıyla çağrılır.
Birim başına: ikili sayısı, en az bir tespit olan ikili, tespit edilen (kitaplık, sürüm) çiftleri.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/surum_tespit.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a1_pay  # noqa: E402
import veri  # noqa: E402

sys.path.insert(0, str(veri.REPO))
from karadul.reconstruction.reference_differ import VersionDetector  # noqa: E402


def main(argv=None) -> int:
    logging.disable(logging.CRITICAL)
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    birimler: dict[str, dict] = {}
    for k in a1_pay.kimlikler():
        static = veri.ks1._tek_static(veri._spec(k)["kok"])
        tespit = VersionDetector().detect_from_strings(veri._json(static / "ghidra_strings.json"))
        b = birimler.setdefault(a1_pay.birim(k), {"ikili": 0, "tespitli": 0, "tespitler": {}})
        b["ikili"] += 1
        b["tespitli"] += bool(tespit)
        for t in tespit:
            anahtar = f"{t.library} {t.version}"
            b["tespitler"][anahtar] = b["tespitler"].get(anahtar, 0) + 1
    for ad, b in sorted(birimler.items()):
        print(f"{ad:22s} ikili {b['ikili']:4d} tespitli {b['tespitli']:4d} {b['tespitler']}")
    print(f"TOPLAM ikili {sum(b['ikili'] for b in birimler.values())} tespitli {sum(b['tespitli'] for b in birimler.values())}")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(birimler, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
