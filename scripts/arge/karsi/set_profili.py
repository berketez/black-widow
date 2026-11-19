"""Geliştirme setinin boyut profili (OLGU tablosundan): ikili başına fonksiyon, gövde baytı, platform payı.

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/set_profili.py > $V/set_profili.txt
"""
import statistics
from collections import Counter

from ortak import olgu_oku

c = Counter(); plat = Counter(); bayt = Counter()
for r in olgu_oku({"birim", "ikili", "platform", "nufusta", "boyut", "thunk", "dis"}):
    k = (r["birim"], r["ikili"])
    c[k] += 1
    plat[r["platform"]] += r["nufusta"]
    if not r["dis"] and not r["thunk"]:
        bayt[k] += r["boyut"] or 0
v = sorted(c.values())
print("ikili", len(c), "fonksiyon toplam", sum(v), "ortanca", statistics.median(v), "en büyük", max(v), max(c, key=c.get))
print("fonksiyon gövde baytı: toplam %.1f MiB; en büyük ikili %.2f MiB (%s); ortanca %.3f MiB" % (
    sum(bayt.values()) / 2**20, max(bayt.values()) / 2**20, max(bayt, key=bayt.get), statistics.median(bayt.values()) / 2**20))
print("nüfus platform:", dict(plat))
print("en büyük 6 ikili (fonksiyon):", [(k[0] + "/" + k[1], n) for k, n in c.most_common(6)])
