"""P-ÜV4 yerel örnekleri: derle, soy, GT'yi (sembol tablosu) çıkar.

Kullanım (worktree kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/cpp_ornek/derle.py --kok <dizin>

Her (mimari, -O) çifti için ``<kok>/<mimari>_O<n>/``:
- ``ornek``          — sembollü ikili (``/usr/bin/xcrun clang++``)
- ``ornek.soyulmus`` — ``/usr/bin/strip`` ile soyulmuş kopya (PATH'teki conda strip kullanılmaz)
- ``gt.json``        — sembollü kopyanın ``_ZTI`` / ``_ZTV`` / kod sembolleri (adres → ad)

Derleme çıktısı ÇALIŞTIRILMAZ ve depoya girmez (yalnız analiz edilir).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

KAYNAK = Path(__file__).resolve().parent
ORNEK_CEVIRI_BIRIMLERI = ("ornek_a.cpp", "ornek_b.cpp")
MIMARILER = ("arm64", "x86_64")
ENIYILEMELER = ("0", "2")
CLANG = ["/usr/bin/xcrun", "clang++"]
STRIP = "/usr/bin/strip"


def derle(cikti: Path, mimari: str, eniyileme: str) -> None:
    komut = CLANG + ["-std=c++17", f"-O{eniyileme}", "-arch", mimari, "-o", str(cikti)]
    komut += [str(KAYNAK / k) for k in ORNEK_CEVIRI_BIRIMLERI]
    subprocess.run(komut, check=True, cwd=str(KAYNAK))


def soy(sembollu: Path, soyulmus: Path) -> None:
    shutil.copyfile(sembollu, soyulmus)
    subprocess.run([STRIP, str(soyulmus)], check=True)


def gt_cikar(sembollu: Path) -> dict:
    """Sembollü ikilinin GT'si (P-ÜV0 görüntüsüyle; tanımlı semboller)."""
    sys.path.insert(0, str(KAYNAK.parents[3]))
    from karadul.analyzers.ustveri import goruntu as gr

    g = gr.ac(sembollu)
    zti: dict[str, str] = {}
    ztv: dict[str, str] = {}
    kod: dict[str, list[str]] = {}
    for s in g.semboller():
        if s.tur in (gr.SEMBOL_TANIMSIZ, gr.SEMBOL_HATA_AYIKLAMA, gr.SEMBOL_DIGER) or not s.ad:
            continue
        ad = s.ad[1:] if s.ad.startswith("__Z") else s.ad
        if ad.startswith("_ZTI"):
            zti[hex(s.adres)] = ad
        elif ad.startswith("_ZTV"):
            ztv[hex(s.adres)] = ad
        if s.tur == gr.SEMBOL_KOD:
            kod.setdefault(hex(s.adres), []).append(ad)
    return {"ikili": str(sembollu), "mimari": g.mimari, "ZTI": zti, "ZTV": ztv, "kod": kod}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kok", required=True, type=Path)
    a = ap.parse_args(argv)
    for mimari in MIMARILER:
        for o in ENIYILEMELER:
            d = a.kok / f"{mimari}_O{o}"
            d.mkdir(parents=True, exist_ok=True)
            sembollu = d / "ornek"
            derle(sembollu, mimari, o)
            soy(sembollu, d / "ornek.soyulmus")
            gt = gt_cikar(sembollu)
            (d / "gt.json").write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
            print(f"{d.name}: ZTI {len(gt['ZTI'])}, ZTV {len(gt['ZTV'])}, kod sembolü {len(gt['kod'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
