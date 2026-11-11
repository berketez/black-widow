#!/usr/bin/env python3
"""İki kolun Ghidra zemini aynı mı? GT'siz bütünlük denetimi (ürün ölçümünden önce koşulur).

Yeni kol makine yükü altında koşuldu. Ghidra'nın fonksiyon başına derleme zaman aşımı (30 sn, koda
sabit) yük altında bir fonksiyonu düşürürse o fonksiyon yeni kolda adsız görünür ve fark, ürün
değişikliğine yazılır. Bu betik ikili başına şunları iki kolda karşılaştırır:

- Ghidra'nın bulduğu fonksiyon sayısı (``static/ghidra_functions.json``: ``total``),
- derleme sayaçları (``static/ghidra_decompiled.json``: ``total_attempted``, ``success``,
  ``failed``, ``skipped``),
- fonksiyon adres kümesi (aynı adresler mi).

GT okunmaz. Çıktıda fonksiyon adı yoktur.

Kullanım:
    python3 docs/arge/2026-11-10_n1_adim3/kol_butunlugu.py \
        --taban-debian ~/karadul_olcum/n1_debian13 \
        --taban-mac workspaces/olcum_mac/runs/ol7-c-b7faeac \
        --yeni ~/karadul_olcum/runs/urun-yeni-93a2956 --json <çıktı>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SAYACLAR = ("total_attempted", "success", "failed", "skipped")


def _static(kosu: Path) -> Path | None:
    adaylar = sorted((kosu / "ws" / "workspaces").glob("*/*/static"))
    return adaylar[0] if len(adaylar) == 1 else None


def _oku(static: Path | None) -> dict | None:
    if static is None:
        return None
    try:
        fonk = json.loads((static / "ghidra_functions.json").read_text(encoding="utf-8"))
        dec = json.loads((static / "ghidra_decompiled.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    adresler = sorted(str(f.get("address") or f.get("entry") or f.get("addr"))
                      for f in fonk.get("functions", []))
    return {"fonksiyon": fonk.get("total"), "adresler": adresler,
            **{k: dec.get(k) for k in SAYACLAR}}


def _isler(taban_debian: Path, taban_mac: Path, yeni: Path) -> list[tuple[str, Path, Path]]:
    out = []
    for prog in sorted(p for p in taban_debian.iterdir() if p.is_dir()):
        for d in sorted(p for p in prog.iterdir() if p.is_dir()):
            out.append((f"debian/{prog.name}/{d.name}", d, yeni / "debian" / prog.name / d.name))
    for d in sorted(p for p in taban_mac.iterdir() if p.is_dir() and (p / "ws").is_dir()):
        out.append((f"mac/{d.name}", d, yeni / "mac" / d.name))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taban-debian", type=Path, required=True)
    ap.add_argument("--taban-mac", type=Path, required=True)
    ap.add_argument("--yeni", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()

    satirlar, farkli, okunamayan = [], [], []
    toplam = {k: [0, 0] for k in ("fonksiyon", *SAYACLAR)}
    for anahtar, taban, yeni in _isler(a.taban_debian.expanduser(), a.taban_mac.expanduser(),
                                       a.yeni.expanduser()):
        t, y = _oku(_static(taban)), _oku(_static(yeni))
        if t is None or y is None:
            okunamayan.append({"ikili": anahtar, "taban": t is not None, "yeni": y is not None})
            continue
        ayni_adres = t["adresler"] == y["adresler"]
        satir = {"ikili": anahtar, "adresler_ayni": ayni_adres,
                 "yalniz_tabanda": len(set(t["adresler"]) - set(y["adresler"])),
                 "yalniz_yenide": len(set(y["adresler"]) - set(t["adresler"]))}
        for k in toplam:
            satir[k] = [t[k], y[k]]
            toplam[k][0] += t[k] or 0
            toplam[k][1] += y[k] or 0
        satirlar.append(satir)
        if not ayni_adres or any(satir[k][0] != satir[k][1] for k in toplam):
            farkli.append(satir)

    belge = {"ikili_sayisi": len(satirlar), "okunamayan": okunamayan, "toplam": toplam,
             "farkli_ikili_sayisi": len(farkli), "farkli": farkli, "satirlar": satirlar}
    a.json.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"ikili {len(satirlar)} | okunamayan {len(okunamayan)} | farklı {len(farkli)}")
    for k, (t, y) in toplam.items():
        print(f"  {k:16} taban {t:7} | yeni {y:7}")
    for s in farkli[:20]:
        print("  FARK", s["ikili"], {k: s[k] for k in toplam}, "adres aynı:", s["adresler_ayni"],
              "yalnız tabanda", s["yalniz_tabanda"], "yalnız yenide", s["yalniz_yenide"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
