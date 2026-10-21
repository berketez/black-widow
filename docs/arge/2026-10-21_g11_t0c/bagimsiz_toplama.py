#!/usr/bin/env python3
"""T0c ana sayılarının bağımsız yeniden toplanması (ghidra_tip_tabani.py'nin fonksiyonları kullanılmaz).

Girdi: ``~/karadul_olcum/runs/t0c-a10fde3/taban/parametreler.jsonl`` (parametre başına kayıt) ve
T0b hizalama belgelerinin künyesi (ikili -> paket). Çiftler ikili içinde sayılır, oranlar program
başına alınır, programlar arasında makro ortalama (tanımsız oran ortalamaya girmez).
Koşum: ``python3 -I docs/arge/2026-10-21_g11_t0c/bagimsiz_toplama.py``
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

KOSU = Path.home() / "karadul_olcum/runs"
kayitlar = [json.loads(s) for s in open(KOSU / "t0c-a10fde3/taban/parametreler.jsonl", encoding="utf-8")]
paket = {}
for h in (KOSU / "t0b-1acba60/hizalama").glob("*.json"):
    if h.name != "hizalama_indeksi.json":
        g = json.loads(h.read_text(encoding="utf-8"))["girdi"]
        paket[g["ikili"]] = g["paket"]


def makro(d):
    v = [x for x in d.values() if x is not None]
    return round(sum(v) / len(v), 4) if v else None


# (a) adlı tip doğruluğu, program başına, makro
sayi = defaultdict(lambda: defaultdict(lambda: [0, 0]))
for x in kayitlar:
    c = sayi[paket[x["ikili"]]][x["grup"]]
    c[0] += 1
    c[1] += x["adli_dogru"]
print("(a) makro:", {g: makro({p: sayi[p][g][1] / sayi[p][g][0] for p in sayi if sayi[p][g][0]})
                     for g in ("yapi*", "char*", "void*", "skaler", "diger")},
      "| kilitli parametre:", sum(x["tip_kilitli"] for x in kayitlar), "/", len(kayitlar))


def k1(etiket, gercek, suzgec=lambda x: True):
    kes, duy, kap = {}, {}, {}
    for p in sorted(set(paket.values())):
        kc = dc = gc = kp = n = 0
        for ikili in sorted({x["ikili"] for x in kayitlar if paket[x["ikili"]] == p}):
            o = [x for x in kayitlar if x["ikili"] == ikili and x["dwarf_sinif"] == "yapi*"
                 and x["kimlik"] and suzgec(x)]
            n += len(o)
            et = Counter(etiket(x) for x in o if etiket(x) is not None)
            gr = Counter(x[gercek] for x in o)
            ort = Counter((etiket(x), x[gercek]) for x in o if etiket(x) is not None)
            kc += sum(v * (v - 1) // 2 for v in et.values())
            dc += sum(v * (v - 1) // 2 for v in ort.values())
            gc += sum(v * (v - 1) // 2 for v in gr.values())
            kp += sum(v for v in et.values() if v >= 2)
        kes[p] = dc / kc if kc else None
        duy[p] = dc / gc if gc else None
        kap[p] = kp / n if n else None
    return {"kesinlik": makro(kes), "duyarlilik": makro(duy), "kapsam": makro(kap)}


print("(b) Ghidra katı:", k1(lambda x: x["ghidra_etiketi"], "kimlik"))
print("(b) Ghidra aile:", k1(lambda x: x["ghidra_etiketi"], "aile"))
print("(b) Ghidra kütüphane katı:", k1(lambda x: x["ghidra_etiketi"], "kimlik",
                                       lambda x: x["tabaka"] == "kutuphane"))
print("(b) Ghidra program katı:", k1(lambda x: x["ghidra_etiketi"], "kimlik",
                                     lambda x: x["tabaka"] == "program"))
print("(c) tek sınıf katı/aile kesinliği:", k1(lambda x: "tek", "kimlik")["kesinlik"],
      k1(lambda x: "tek", "aile")["kesinlik"])
kume = defaultdict(set)
for x in kayitlar:
    if x["dwarf_sinif"] == "yapi*" and x["kimlik"] and x["ghidra_etiketi"]:
        kume[(x["ikili"], x["ghidra_etiketi"])].add(x["kimlik"])
print("saf olmayan Ghidra kümesi:", sorted(k for k, v in kume.items() if len(v) > 1))
k1n = [x for x in kayitlar if x["dwarf_sinif"] == "yapi*" and x["kimlik"]]
print("K1 nüfusu:", len(k1n), "| birlik kökü:", sum(x["kimlik"].startswith("union ") for x in k1n),
      "| anonim kök:", sum("<anon>" in x["kimlik"] for x in k1n),
      "| durum:", dict(Counter(x["k1_durum"] for x in k1n)))
aile = defaultdict(set)
sayac = Counter()
for x in k1n:
    aile[(x["ikili"], x["aile"])].add(x["kimlik"])
    sayac[(x["ikili"], x["aile"])] += 1
for (ikili, a), s in sorted(aile.items(), key=lambda kv: -len(kv[1]))[:3]:
    print("en büyük aile:", ikili, len(s), "kimlik,", sayac[(ikili, a)], "parametre")
