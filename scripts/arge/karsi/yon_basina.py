"""KİMLİK'in `yayilim_*.json` çıktılarındaki `yonler` alanından yön başına Wilson aralığı (hattın verisi, kendi Wilson'ım).

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/yon_basina.py > $V/yon_basina.txt
"""
import json

from ortak import ARGE, yaz

K = ARGE / "kimlik"
print("KİMLİK: iki yön havuzlu sayılar ↔ yön başına")
for dosya, grup, nokta in (("yayilim_v2_hepsi.json", "sinama_tmux", "tutucu_v2"), ("yayilim_v2_hepsi.json", "sinama_tmux", "kural"),
                           ("yayilim_gcc.json", "derleyici", "kural"), ("yayilim_gcc.json", "derleyici", "tutucu_v2"),
                           ("yayilim_gcc.json", "derleyici_htop", "kural"), ("yayilim_v2_hepsi.json", "sinama_cu_mac", "kural")):
    g = json.load(open(K / dosya))[grup][nokta]
    print(f"\n{grup} / {nokta}")
    for anahtar in ("havuz", "havuz_dizgi", "havuz_yayilim"):
        h = g[anahtar]
        print(f"  {anahtar:14s} havuz: {yaz(h['dogru'], h['dogru'] + h['yanlis'])}")
    for y in g["yonler"]:
        for anahtar in ("toplam", "capa_dizgi", "yayilim"):
            h = y[anahtar]
            print(f"    {y['sorgu']} → {y['basvuru']} {anahtar:10s}: {yaz(h['dogru'], h['dogru'] + h['yanlis'])}")
