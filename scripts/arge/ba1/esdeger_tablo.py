"""BA-1: ``esdeger_ve_onek.py`` dökümünden eşdeğerlik tablosu (Markdown) üretir.

Seçim belirlenimli: her çalışma alanında (dosya, satır) sırasıyla; Ollama'dan
eşleşen ilk 10 + eşleşmeyen ilk 6 + eski kalıbın zaman aşımına uğradığı
satırlar + en uzun 3 satır; S8'in her çalışma alanından eşleşen ilk 2 +
eşleşmeyen ilk 1. Satır metni yazılmaz (depo herkese açık); yalnız yer,
uzunluk, sonuç ve süre.

Kullanım:

    python scripts/arge/ba1/esdeger_tablo.py <esdeger_dokum.json>
"""
from __future__ import annotations

import json
import sys


def _sonuc(r: dict) -> str:
    if r.get("zaman_asimi"):
        return "zaman aşımı"
    if r["r"] is None:
        return "eşleşme yok"
    g = r["r"][1]
    return f"eşleşti (grup uzunlukları {len(g[0])}/{len(g[1])}/{len(g[2])})"


def main(argv: list[str]) -> int:
    kayit = json.load(open(argv[0], encoding="utf-8"))
    secilen: list[dict] = []
    for ws in dict.fromkeys(k["ws"] for k in kayit):
        ws_k = [k for k in kayit if k["ws"] == ws]
        eslesen = [k for k in ws_k if k["yeni"].get("r") is not None]
        eslesmeyen = [k for k in ws_k if k["yeni"].get("r") is None]
        if ws == "ollama":
            parca = eslesen[:10] + eslesmeyen[:6]
            parca += [k for k in ws_k if k["eski"].get("zaman_asimi")]
            parca += sorted(ws_k, key=lambda k: -len(k["metin"]))[:3]
        else:
            parca = eslesen[:2] + eslesmeyen[:1]
        for k in parca:
            if k not in secilen:
                secilen.append(k)
    print("| # | çalışma alanı | dosya:satır | ad | uzunluk | eski sonuç | yeni = eski | eski süre | yeni süre |")
    print("|---:|---|---|---|---:|---|---|---:|---:|")
    for i, k in enumerate(secilen, 1):
        e, y = k["eski"], k["yeni"]
        ayni = "—" if e.get("zaman_asimi") else ("evet" if e["r"] == y["r"] else "HAYIR")
        es = "> 2 sn" if e.get("zaman_asimi") else f"{e['s']*1000:.3f} ms"
        print(f"| {i} | {k['ws']} | {k['dosya']}:{k['satir']} | {k['ad']} | {len(k['metin'])} | "
              f"{_sonuc(e)} | {ayni} | {es} | {y['s']*1000:.3f} ms |")
    print(f"\n{len(secilen)} satır.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
