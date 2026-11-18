"""P03 ölçümü: YARA'nın iki arka ucu (yara-python, regex yedeği) aynı hükmü mü veriyor?

Masum kapının sabit setlerindeki (``docs/arge/2026-11-18_onarim/P00/setler.json``)
her ikiliyi iki arka uçla tarar; her kural için (kural adı, eşleşen dizgi
kimlikleri kümesi) karşılaştırılır. Fark varsa ikili ve kural yazılır.

Kullanım (worktree kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/p03_olc.py \
        --setler /Users/apple/Black_Widow/docs/arge/2026-11-18_onarim/P00/setler.json \
        --cikti ~/karadul_olcum/runs/onarim-2026-11-18/P03/arka_uc_esitligi.json

Çıkış kodu: 0 = bütün ikililerde iki arka uç aynı; 1 = fark var ya da yara-python yok.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Betiğin kendi ağacı önce yüklensin (karadul ana ağaca editable kurulu;
# yoksa worktree'de ana ağacın kodu ölçülür).
DEPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEPO))


def _imza(sonuc) -> dict[str, list[str]]:
    return {m.rule: sorted({ident for _, ident, _ in m.strings}) for m in sonuc.matches}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--setler", type=Path, required=True)
    ap.add_argument("--set", default="gelistirme,macos,pe,pozitif")
    ap.add_argument("--cikti", type=Path, required=True)
    a = ap.parse_args(argv)

    import karadul
    from karadul.analyzers.yara_scanner import YaraScanner

    if Path(karadul.__file__).resolve().parents[1] != DEPO:
        print(f"yanlış ağaç yüklendi: {karadul.__file__}", file=sys.stderr)
        return 2

    yerli = YaraScanner()
    if not yerli.yara_available:
        print("yara-python yok: eşitlik ölçülemez", file=sys.stderr)
        return 1
    yerli.load_builtin_rules()
    yedek = YaraScanner()
    yedek._yara_available = False
    yedek._yara = None
    yedek.load_builtin_rules()

    setler = json.loads(a.setler.read_text(encoding="utf-8"))["setler"]
    kayitlar = []
    farkli = 0
    olculemeyen = 0
    t0 = time.time()
    for set_adi in a.set.split(","):
        for e in setler[set_adi]:
            yol = Path(e["gercek_yol"])
            try:
                veri = yol.read_bytes()
            except OSError as exc:
                kayitlar.append({"set": set_adi, "ikili": e["anahtar"], "hata": str(exc)})
                olculemeyen += 1
                continue
            r1 = yerli.scan_bytes(veri)
            r2 = yedek.scan_bytes(veri)
            i1, i2 = _imza(r1), _imza(r2)
            ayni = i1 == i2
            farkli += 0 if ayni else 1
            kayit = {"set": set_adi, "ikili": e["anahtar"], "ayni": ayni,
                     "yara_python": i1, "arka_uc_1": r1.backend, "arka_uc_2": r2.backend}
            if not ayni:
                kayit["regex_yedegi"] = i2
            kayitlar.append(kayit)

    ozet = {
        "agac": str(Path(karadul.__file__).resolve().parents[1]),
        "ikili": len(kayitlar),
        "farkli": farkli,
        "olculemeyen": olculemeyen,
        "sure_sn": round(time.time() - t0, 1),
    }
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps({"ozet": ozet, "kayitlar": kayitlar},
                                  ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(ozet, ensure_ascii=False))
    for k in kayitlar:
        if k.get("ayni") is False:
            print("FARK", k["set"], k["ikili"], k["yara_python"], k["regex_yedegi"])
    return 0 if farkli == 0 and olculemeyen == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
