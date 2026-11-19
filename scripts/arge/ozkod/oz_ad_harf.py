#!/usr/bin/env python3
"""``oz_ad``: ad, kanıt dizgisinin harfleri korunarak yazılsaydı hüküm ne olurdu? (tanı; sınamada
dondurulmuş R1 ölçümünden SONRA görülen nedenin sayımı)

Ürün ``oz_ad`` adını kanıt dizgisinden küçük harfe çevirerek üretiyor (``ZSTD_getCParamsFromCDict``
→ ``zstd_getcparamsfromcdict``); tam eşitlik ölçüsünde yanlış sayılıyor. Burada her ``oz_ad`` adı
için kanıt dizgisinin KENDİSİ ad olarak hükme sokulur (``ks1_olc.capa_degerlendir``; ürün ölçüsüyle
aynı tanım: tam eşitlik, klon GT'de taban eşitliği). R1 (``oz_ad_ayrim.kural_tut``) ile çaprazlanır.

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/oz_ad_harf.py
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import oz_ad_ayrim as O  # noqa: E402

TANIMLAYICI = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def main() -> int:
    k = V.ks1()
    satirlar = []
    for taraf_ in ("kesif", "sinama"):
        ozellik = {(o["birim"], o["ikili"], o["adres"]): o for o in O.ozellikler(taraf_)}
        for d in V.hepsi(taraf_=taraf_):
            for fa, r in d["urun"].items():
                if r["kanal"] != O.KANAL:
                    continue
                o = ozellik[(d["birim"], d["ad"], fa)]
                kanit = o["kanit"]
                gt = d["gt_adlar"].get(fa)
                gecerli = bool(TANIMLAYICI.match(kanit))
                if gt and gecerli:
                    # gt_adlar platform biçiminde saklı; capa_degerlendir Mach-O'da '_' soyar: ELF kipinde çağır
                    h = k.capa_degerlendir(kanit, gt, k.PLATFORM_DEBIAN)["durum"] == "dogru"
                else:
                    h = False
                satirlar.append({"taraf": taraf_, "birim": d["birim"], "dogru": o["dogru"],
                                 "kanit_dogru": h, "r1": O.kural_tut(o),
                                 "yalniz_harf": (not o["dogru"]) and h})
    def tablo(baslik, anahtar):
        print(f"\n## {baslik}")
        print("| | ad | bugün doğru | kanıt harfleriyle doğru | yanlıştan doğruya dönen | R1 tutulan | R1 tutulanda bugün doğru | R1 tutulanda kanıt harfleriyle doğru (Wilson) |")
        print("|---|---:|---:|---:|---:|---:|---:|---|")
        g: dict[str, list] = defaultdict(list)
        for s in satirlar:
            g[anahtar(s)].append(s)
        for ad, ss in sorted(g.items()):
            r1 = [s for s in ss if s["r1"]]
            print(f"| {ad} | {len(ss)} | {sum(s['dogru'] for s in ss)} | {sum(s['kanit_dogru'] for s in ss)} "
                  f"| {sum(s['yalniz_harf'] for s in ss)} | {len(r1)} | {sum(s['dogru'] for s in r1)} "
                  f"| {V.wilson(sum(s['kanit_dogru'] for s in r1), len(r1))} |")
    tablo("Taraf", lambda s: s["taraf"])
    tablo("Birim", lambda s: s["birim"])
    tablo("Toplam", lambda s: "hepsi")
    (V.ARGE_KOKU / "oz_ad_harf.json").write_text(json.dumps(satirlar, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
