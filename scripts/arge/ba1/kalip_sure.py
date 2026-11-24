"""BA-1: düzenli ifade süresini AYRI SÜREÇTE, zaman aşımıyla ölçer.

C düzeyindeki ``re`` eşleşmesi iş parçacığından kesilemez ve SIGTERM'e
yanıt vermez; bu yüzden her ölçüm ayrı bir çocuk süreçte koşar,
``subprocess.run(timeout=...)`` süre dolunca çocuğu SIGKILL ile öldürür.

Kullanım (worktree kökünden):

    python scripts/arge/ba1/kalip_sure.py satir <dosya> <satir_no> [--zaman-asimi 20]
    python scripts/arge/ba1/kalip_sure.py buyume [--zaman-asimi 60]

``satir``: dosyanın (1 tabanlı) satırını ``strip()`` edip eski ve yeni
``memcpy`` / ``memset`` / ``memmove`` kalıplarıyla arar.
``buyume``: kapanan ayraçsız 100 / 1 000 / 10 000 / 100 000 karakterlik
satırlarda yeni kalıpların süresini ölçer (hüküm 2).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ana ağaca editable kurulu karadul yerine BU ağacın kodu yüklensin.
KOK = Path(__file__).resolve().parents[3]
if str(KOK) not in sys.path:
    sys.path.insert(0, str(KOK))

# BA-1 öncesi (main 0b4d948) block_annotator.py:324 / 332 / 340 kalıpları.
ESKI_KALIPLAR: dict[str, str] = {
    "memcpy": r"memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
    "memset": r"memset\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
    "memmove": r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
}

# BA-2: ayrı süreçte ölçüm ``scripts/measurement/kalip_denetimi.py``'ye taşındı.
sys.path.insert(0, str(KOK / "scripts" / "measurement"))
from kalip_denetimi import ayri_surecte_ara  # noqa: E402


def yeni_kaliplar() -> dict[str, tuple[str, int]]:
    """Çalışma ağacındaki block_annotator'ın memcpy / memset / memmove kalıpları."""
    from karadul.reconstruction.engineering.block_annotator import MEMORY_PATTERNS

    sonuc: dict[str, tuple[str, int]] = {}
    for pat, _tmpl, _conf in MEMORY_PATTERNS:
        for ad in ("memcpy", "memset", "memmove"):
            if pat.pattern.startswith(ad):
                sonuc[ad] = (pat.pattern, pat.flags)
    return sonuc


def _satir(args: argparse.Namespace) -> int:
    satirlar = Path(args.dosya).read_text(encoding="utf-8", errors="replace").splitlines()
    metin = satirlar[args.satir_no - 1].strip()
    print(f"satır {args.satir_no}: {len(metin)} karakter")
    rapor: dict = {"dosya": args.dosya, "satir_no": args.satir_no,
                   "uzunluk": len(metin), "eski": {}, "yeni": {}}
    if not args.yalniz_yeni:
        for ad, kalip in ESKI_KALIPLAR.items():
            r = ayri_surecte_ara(kalip, [metin], args.zaman_asimi)
            rapor["eski"][ad] = r
            print(f"eski {ad:8s}: {'ZAMAN AŞIMI' if r['zaman_asimi'] else f'{r['sure']*1000:.3f} ms'}"
                  f" (duvar {r['duvar']} sn)")
    for ad, (kalip, bayrak) in yeni_kaliplar().items():
        r = ayri_surecte_ara(kalip, [metin], args.zaman_asimi, bayrak)
        rapor["yeni"][ad] = r
        print(f"yeni {ad:8s}: {'ZAMAN AŞIMI' if r['zaman_asimi'] else f'{r['sure']*1000:.3f} ms'}"
              f" (duvar {r['duvar']} sn) sonuc={r['sonuc']}")
    if args.json:
        Path(args.json).write_text(json.dumps(rapor, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def buyume_girdileri(n: int) -> dict[str, str]:
    """Kapanan ayraçsız, ``n`` karakterlik düşmanca satırlar.

    - ``tek``: tek çağrı, uzun argüman (gerçek satırın biçimi).
    - ``ic_ayrac``: tek çağrı, içinde kapanmamış ``(``.
    - ``yinelenen``: çağrı adı satırda tekrar tekrar (her başlangıç yeniden tarar).
    """
    tek_bas = "runtime_memmove(field_ptr_3,iVar14,"
    govde = "status_2 << 3,ctx,i,"
    tek = (tek_bas + govde * (n // len(govde) + 1))[:n]
    ic = (tek_bas + "(long)" + govde + "(" + govde * (n // len(govde) + 1))[:n]
    birim = "memcpy(a,b,c "
    yin = (birim * (n // len(birim) + 1))[:n]
    return {"tek": tek, "ic_ayrac": ic, "yinelenen": yin}


def _buyume(args: argparse.Namespace) -> int:
    rapor: dict = {"zaman_asimi": args.zaman_asimi, "olcumler": []}
    kaliplar = yeni_kaliplar()
    for n in (100, 1_000, 10_000, 100_000):
        for tur, metin in buyume_girdileri(n).items():
            for ad, (kalip, bayrak) in kaliplar.items():
                r = ayri_surecte_ara(kalip, [metin], args.zaman_asimi, bayrak)
                satir = {"n": n, "girdi": tur, "kalip": ad,
                         "sure_sn": r["sure"], "zaman_asimi": r["zaman_asimi"],
                         "eslesme": None if r["sonuc"] is None else r["sonuc"][0]}
                rapor["olcumler"].append(satir)
                s = "ZAMAN AŞIMI" if r["zaman_asimi"] else f"{r['sure']*1000:10.3f} ms"
                print(f"n={n:>7} {tur:10s} {ad:8s} {s}")
    if args.json:
        Path(args.json).write_text(json.dumps(rapor, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    alt = ap.add_subparsers(dest="komut", required=True)
    s = alt.add_parser("satir")
    s.add_argument("dosya")
    s.add_argument("satir_no", type=int)
    s.add_argument("--zaman-asimi", type=float, default=20.0)
    s.add_argument("--yalniz-yeni", action="store_true")
    s.add_argument("--json")
    b = alt.add_parser("buyume")
    b.add_argument("--zaman-asimi", type=float, default=60.0)
    b.add_argument("--json")
    args = ap.parse_args(argv)
    return _satir(args) if args.komut == "satir" else _buyume(args)


if __name__ == "__main__":
    sys.exit(main())
