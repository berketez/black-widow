#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 4 (girdi): taban ürün koşusunun adlarını GT adlarıyla birlikte dök.

``urun_olc.py`` çıktısında ad geçmez (yalnız hüküm kodu). Yeniden puanlama için ad gerekir; bu betik
``urun_olc.olc`` döngüsünü aynı işlevlerle (``haritayi_oku``, ``degerlendir_elf``, ``ks1.gt_elf`` /
``gt_mac``) yeniden koşar ve ikili başına şunları yazar: ürünün ad verdiği fonksiyonlar (adres, ad,
hüküm, kanal, etiket, nüfusta mı, GT adları) ve ikilinin bütün GT adları (ikiz çözümlemesi için).
Ölçüm betikleri değiştirilmez; yalnız içe aktarılır. Yalnız geliştirme seti (119 ikili) okunur.

Ürün ağacından koşulur (birleşik ölçümle aynı kural: ad sınıflayıcısı betiğin ağacından gelir):
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=~/karadul_olcum/urun-a62f15e python scripts/arge/olcu/taban_dok.py \
        --agac ~/karadul_olcum/urun-a62f15e --kok ~/karadul_olcum/runs/urun-onarim-a62f15e \
        --mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path


def yukle(agac: Path):
    olcum = agac / "scripts" / "measurement"
    for y in (str(olcum), str(agac)):
        if y not in sys.path:
            sys.path.insert(0, y)
    spec = importlib.util.spec_from_file_location("urun_olc", olcum / "urun_olc.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--agac", type=Path, required=True, help="ürün ağacı (urun_olc.py ve karadul buradan)")
    ap.add_argument("--kok", type=Path, required=True, help="koşu kökü (<kök>/debian, <kök>/mac)")
    ap.add_argument("--mac-veri", type=Path, required=True)
    ap.add_argument("--debian-indir", type=Path, default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    uo = yukle(a.agac.expanduser().resolve())
    ks1 = uo.ks1
    elfler = uo.haritasizlari_isaretle(ks1.elfleri_topla(a.kok / "mac", a.kok / "debian"))
    ks1.nufus_denetle(elfler, ks1.BEKLENEN_ELF, False)
    ikililer, toplam = {}, Counter()
    for e in elfler:
        if e.static is None:
            raise SystemExit(f"bitmemiş koşu: {e}")
        fonk = uo._json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        birim = ks1.birim_anahtari(e)
        if ks1.cpp_ikili_mi(fonk, e.platform):
            toplam["cpp_disarida"] += 1
            continue
        genel, koken, _ = uo.haritayi_oku(e.kosu)
        gt = ks1.gt_mac(e, a.mac_veri) if e.platform == ks1.PLATFORM_MAC else ks1.gt_elf(e, a.debian_indir)
        gfonk = ks1._f1().load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
        kayitlar, _ = uo.degerlendir_elf(genel, koken, gfonk, gt, e.platform)
        adlar = []
        for k in kayitlar:
            gt_adlari = gt.adlar.get(k["adres"]) or []
            adlar.append({"adres": f"{k['adres']:x}", "ad": k["ad"], "durum": k["durum"], "satir": k["satir"],
                          "kanal": k["kanal"], "etiket": k["etiket"], "nufusta": k["nufusta"],
                          "gt": [ks1.platform_adi(g, e.platform) for g in gt_adlari]})
            toplam["ad"] += 1
            toplam[k["durum"]] += 1
        ikililer[f"{birim}::{e.ad}"] = {
            "birim": birim, "ikili": e.ad, "platform": e.platform, "nufus": len(gt.nufus),
            "nufus_adresleri": sorted(f"{x:x}" for x in gt.nufus), "adlar": adlar,
            "gt": {f"{adr:x}": [ks1.platform_adi(g, e.platform) for g in gs] for adr, gs in sorted(gt.adlar.items())}}
        toplam["nufus"] += len(gt.nufus)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps({"sema": "karadul-arge-olcu-taban/1", "kok": str(a.kok), "agac": str(a.agac),
                                  "toplam": dict(toplam), "ikililer": ikililer}, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(json.dumps(dict(toplam), ensure_ascii=False), "ikili:", len(ikililer))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
