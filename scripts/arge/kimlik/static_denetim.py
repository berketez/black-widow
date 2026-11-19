#!/usr/bin/env python
"""KİMLİK hattı — `--stage static` koşusunun static/ çıktısı tam koşununkiyle aynı mı (DEFTER.md §5.13).

Eşleyicinin okuduğu altı dosya karşılaştırılır: JSON'lar ayrıştırılıp içerik olarak (koşuya özgü yol / süre
alanları hariç), ``pcode.jsonl`` satır kümesi olarak. Ayrıca iki koşudan yüklenen olgunun (``veri.yukle``'nin
GT'siz alanları) birebir eşitliği.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/static_denetim.py <taban kimliği> <static koşu dizini>
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veri  # noqa: E402
from veri import ks1  # noqa: E402

DOSYALAR = ["ghidra_functions.json", "ghidra_call_graph.json", "ghidra_strings.json", "ghidra_xrefs.json",
            "ghidra_cfg.json"]


def _ozet(yol: Path) -> str:
    return hashlib.sha256(json.dumps(veri._json(yol), sort_keys=True).encode()).hexdigest()[:16]


def main(argv: list[str]) -> int:
    kimlik, dizin = argv[0], Path(argv[1])
    taban = ks1._tek_static(veri._spec(kimlik)["kok"])
    yeni = ks1._tek_static(dizin)
    fark = 0
    for d in DOSYALAR:
        a, b = _ozet(taban / d), _ozet(yeni / d)
        print(f"{d:28s} {'aynı' if a == b else 'FARKLI'} ({a} / {b})")
        fark += a != b
    pa = sorted((taban / "ghidra_output" / "pcode.jsonl").read_text(encoding="utf-8").splitlines())
    pb = sorted((yeni / "ghidra_output" / "pcode.jsonl").read_text(encoding="utf-8").splitlines())
    print(f"{'pcode.jsonl (satır kümesi)':28s} {'aynı' if pa == pb else 'FARKLI'} ({len(pa)} / {len(pb)} satır)")
    fark += pa != pb
    # olgu düzeyi: eşleyicinin gördüğü alanlar
    A = veri.yukle(kimlik)
    eski_tek = ks1._tek_static
    try:
        ks1._tek_static = lambda _kok: yeni       # aynı kimliği yeni static dizininden yükle
        B = veri.yukle(kimlik)
    finally:
        ks1._tek_static = eski_tek
    olgu_fark = 0
    for adr, f in A.fonk.items():
        g = B.fonk.get(adr)
        if g is None or (f.dizgiler, f.iceaktarim, f.cagrilan, f.cagiran, f.sabitler, f.blok, f.kenar, f.komutlar) != \
                (g.dizgiler, g.iceaktarim, g.cagrilan, g.cagiran, g.sabitler, g.blok, g.kenar, g.komutlar):
            olgu_fark += 1
    print(f"olgu (eşleyicinin okuduğu alanlar): {len(A.fonk)} fonksiyon, farklı {olgu_fark}; yalnız yenide "
          f"{len(set(B.fonk) - set(A.fonk))}")
    print("SONUÇ:", "aynı" if fark == 0 and olgu_fark == 0 else f"dosya farkı {fark}, olgu farkı {olgu_fark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
