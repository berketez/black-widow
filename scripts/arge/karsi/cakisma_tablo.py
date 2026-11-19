"""Kalem 6: dosya → (yazan / anan paketler) tablosu.

`plan_tara.py`'nin paket bölmesini kullanır; bir yol yalnız "Dokunmaz / Dokunmayacağı / dokunma" geçen satırlarda
anılıyorsa o paket için "dokunmaz" sayılır, başka bir satırda da anılıyorsa "anar" (yazar ya da okur; planın kendi
"Dokunur" satırı esas alınmalı). Çıktı: Markdown tablo (stdout) + --json.

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/cakisma_tablo.py --json $V/cakisma.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict

import plan_tara as pt

KISA = re.compile(r"`((?:karadul|tests|scripts/measurement|ui)/[A-Za-z0-9_./\-]+\.(?:py|json|html))")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    anar = defaultdict(set)
    dokunmaz = defaultdict(set)
    for hat, yol in pt.BELGELER:
        if not yol.exists():
            continue
        for kimlik, govde in pt.paketlere_bol(yol.read_text(encoding="utf-8"), yol.name):
            p = f"{hat}:{kimlik}"
            for satir in govde.split("\n"):
                yollar = set(KISA.findall(satir))
                if not yollar:
                    continue
                # satırın "dokunmaz" kısmı: işaretten sonrası
                m = re.search(r"[Dd]okunma|değişmez|salt okur", satir)
                if m:
                    once = set(KISA.findall(satir[:m.start()]))
                    sonra = yollar - once
                    for y in once:
                        anar[y].add(p)
                    for y in sonra:
                        dokunmaz[y].add(p)
                else:
                    for y in yollar:
                        anar[y].add(p)
    satirlar = []
    for y in sorted(anar, key=lambda k: (-len(anar[k]), k)):
        if len(anar[y]) < 2:
            continue
        yalniz_d = sorted(dokunmaz[y] - anar[y])
        satirlar.append((y, sorted(anar[y]), yalniz_d))
    print("| Dosya | Anan paket sayısı | Paketler (yazar ya da okur) | Yalnız \"dokunmaz\" diyenler |")
    print("|---|---|---|---|")
    for y, p, d in satirlar:
        print(f"| `{y}` | {len(p)} | {', '.join(p)} | {', '.join(d) or '—'} |")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"anar": {k: sorted(v) for k, v in anar.items()},
                       "dokunmaz": {k: sorted(v) for k, v in dokunmaz.items()}}, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
