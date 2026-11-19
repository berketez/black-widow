#!/usr/bin/env python
"""KİMLİK hattı — "tek taraflı" (yeniden adlandırma adayı) sınıfının kısmi mekanik denetimi.

tmux çiftinde (Debian 3.5a ↔ Mac 3.8) ``hata_dok`` çıktısındaki tek taraflı çiftler: (3.5a adı, 3.8 adı).
Diskte yalnız 3.8 kaynağı var (kopya: ``K/gcc/src/tmux-3.8``; 3.5a kaynağı yok). Denetlenebilen iki koşul:
  (a) 3.5a adı 3.8 kaynağında tanımlayıcı olarak HİÇ geçmiyor (ad yukarı akışta kalkmış / değişmiş);
  (b) 3.8 adı 3.8 kaynağında bir fonksiyon tanımı olarak geçiyor.
İkisi de tutuyorsa çift "yeniden adlandırma ile tutarlı"dır (aynı fonksiyon olduğunu KANITLAMAZ; 3.5a kaynağı
gerekir). (a) tutmuyorsa eski ad yeni kaynakta hâlâ var: yeniden adlandırma değil (satır içi / başka fonksiyon).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/tek_tarafli_kaynak.py [--nokta kural] --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veri  # noqa: E402

KAYNAK = veri.CIKTI / "gcc" / "src" / "tmux-3.8"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nokta", default="kural")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    belge = veri._json(veri.CIKTI / f"hata_dok_{a.nokta}.json")["sinama_tmux"]["yonler"]
    ciftler: set[tuple[str, str]] = set()      # (3.5a adı, 3.8 adı)
    for y in belge:
        for q_ad, r_ad in y["tek_tarafli_ciftler"]:
            ciftler.add((q_ad, r_ad) if y["sorgu"].startswith("debian/") else (r_ad, q_ad))
    metin = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                      for p in sorted(KAYNAK.rglob("*.[chy]")))
    say = {"cift": 0, "tutarli": 0, "eski_ad_hala_var": 0, "yeni_ad_tanim_degil": 0}
    ornek = {"eski_ad_hala_var": [], "yeni_ad_tanim_degil": []}
    for eski, yeni in sorted(ciftler):
        say["cift"] += 1
        eski_var = any(re.search(rf"\b{re.escape(n)}\b", metin) for n in eski.split("|"))
        # fonksiyon tanımı: satır başında ad + "(" (tmux biçemi: dönüş tipi önceki satırda)
        yeni_tanim = any(re.search(rf"^{re.escape(n)}\(", metin, re.M) for n in yeni.split("|"))
        if eski_var:
            say["eski_ad_hala_var"] += 1
            ornek["eski_ad_hala_var"].append([eski, yeni])
        elif not yeni_tanim:
            say["yeni_ad_tanim_degil"] += 1
            ornek["yeni_ad_tanim_degil"].append([eski, yeni])
        else:
            say["tutarli"] += 1
    print(f"tmux tek taraflı çift (tekil, iki yön birleşik): {say['cift']}")
    print(f"  yeniden adlandırma ile tutarlı (eski ad 3.8 kaynağında yok, yeni ad orada fonksiyon tanımı): {say['tutarli']}")
    print(f"  eski ad 3.8 kaynağında hâlâ geçiyor: {say['eski_ad_hala_var']} {ornek['eski_ad_hala_var'][:8]}")
    print(f"  yeni ad 3.8 kaynağında satır başı tanım olarak bulunamadı: {say['yeni_ad_tanim_degil']} {ornek['yeni_ad_tanim_degil'][:8]}")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps({"say": say, "ornek": ornek}, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
