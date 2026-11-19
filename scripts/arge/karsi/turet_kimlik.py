"""Kalem 1: KİMLİK hattının OLGU tablosundan türetilebilen sayıları (bağımsız).

- taban ürünün tmux / htop nüfus içi doğru adı
- A1 payı: set içi kopya / öbür platform / başvurusuz
- envanter: nüfus, tavan (adı başvuruda olan), ortak ad
- tekil dizgi çapası (iki tarafta da yalnız bir fonksiyonun andığı dizgi) kesinliği
- yineleme: A1 payının tekil (program, GT adı) düzeyi

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/turet_kimlik.py --json $V/turet_kimlik.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict

from ortak import klon_soy, olgu_oku, program, yaz

ALAN = {"birim", "ikili", "platform", "adres", "boyut", "nufusta", "hukum", "gt_adlari", "thunk", "dis",
        "dizgiler", "kaynak_sinifi", "ghidra_jenerik", "ghidra_adi"}


def norm(ad: str, platform: str) -> str:
    a = klon_soy(ad)
    if platform == "mac" and a.startswith("_"):
        a = a[1:]
    return a


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    S = list(olgu_oku(ALAN))
    for r in S:
        r["adlar"] = {norm(g, r["platform"]) for g in (r["gt_adlari"] or [])}
    c: dict = {}

    # 1. taban kapsam
    def nd(birimler):
        n = [r for r in S if r["birim"] in birimler and r["nufusta"]]
        return sum(1 for r in n if r["hukum"] == "dogru"), len(n)
    c["taban_tmux"] = nd({"debian/tmux", "mac/tmux"})
    c["taban_htop"] = nd({"debian/htop", "mac/htop"})
    print("taban tmux nüfus içi doğru", c["taban_tmux"], "htop", c["taban_htop"])

    # 2. A1 payı
    ikili_adlari = defaultdict(lambda: defaultdict(set))  # birim -> ikili -> {(ad, boyut)}
    ikili_yalniz_ad = defaultdict(lambda: defaultdict(set))
    for r in S:
        for ad in r["adlar"]:
            ikili_adlari[r["birim"]][r["ikili"]].add((ad, r["boyut"]))
            ikili_yalniz_ad[r["birim"]][r["ikili"]].add(ad)
    # ad -> kaç ikilide (birim içinde)
    say_ab = defaultdict(Counter)
    say_a = defaultdict(Counter)
    for b, d in ikili_adlari.items():
        for ik, s in d.items():
            for x in s:
                say_ab[b][x] += 1
    for b, d in ikili_yalniz_ad.items():
        for ik, s in d.items():
            for x in s:
                say_a[b][x] += 1
    prog_plat = defaultdict(set)  # program -> platformlar
    plat_ad = defaultdict(set)  # (program, platform) -> adlar
    for r in S:
        prog_plat[program(r["birim"])].add(r["platform"])
        plat_ad[(program(r["birim"]), r["platform"])] |= r["adlar"]
    a1 = defaultdict(Counter)
    tekil_a1 = defaultdict(set)
    for r in S:
        if not r["nufusta"]:
            continue
        b = r["birim"]
        if any(say_ab[b][(ad, r["boyut"])] >= 2 for ad in r["adlar"]):
            s = "kopya_ad_boyut"
        elif any(say_a[b][ad] >= 2 for ad in r["adlar"]):
            s = "kopya_yalniz_ad"
        else:
            obur = [p for p in prog_plat[program(b)] if p != r["platform"]]
            if obur and any(ad in plat_ad[(program(b), obur[0])] for ad in r["adlar"]):
                s = "obur_platform"
            else:
                s = "basvurusuz"
        a1[b][s] += 1
        a1["TOPLAM"][s] += 1
        tekil_a1[s].add((program(b), min(r["adlar"])))
    c["a1"] = {b: dict(v) for b, v in a1.items()}
    top = a1["TOPLAM"]
    n = sum(top.values())
    print("\nA1 payı (örnek düzeyi), nüfus", n)
    for s in ("kopya_ad_boyut", "kopya_yalniz_ad", "obur_platform", "basvurusuz"):
        print(f"  {s:18s} {top[s]:6d} ({top[s]/n:.3f})")
    for b in sorted(a1):
        if b != "TOPLAM":
            print("   ", b, dict(a1[b]))
    # tekil (program, ad) düzeyi: bir ad birden çok sınıfa düşebilir; öncelik sırasıyla tekilleştir
    gorulen = set()
    tk = Counter()
    for s in ("kopya_ad_boyut", "kopya_yalniz_ad", "obur_platform", "basvurusuz"):
        for x in tekil_a1[s]:
            if x not in gorulen:
                gorulen.add(x)
                tk[s] += 1
    tn = sum(tk.values())
    c["a1_tekil"] = dict(tk)
    print("A1 payı (tekil (program, ad) düzeyi), toplam", tn)
    for s, v in tk.items():
        print(f"  {s:18s} {v:6d} ({v/tn:.3f})")
    # coreutils'siz örnek düzeyi
    cs = Counter()
    for b, v in a1.items():
        if b not in ("TOPLAM", "debian/coreutils"):
            cs.update(v)
    cn = sum(cs.values())
    c["a1_coreutilssiz"] = dict(cs)
    print("A1 payı, coreutils'siz (örnek):", {k: f"{v} ({v/cn:.3f})" for k, v in cs.items()}, "n", cn)

    # 3. envanter ve tekil dizgi çapası: tmux ve htop çiftleri
    def taraf(birim):
        return [r for r in S if r["birim"] == birim and not r["dis"]]

    def cift(qb, rb):
        Q, R = taraf(qb), taraf(rb)
        r_adlar = set().union(*[x["adlar"] for x in R]) if R else set()
        q_nufus = [x for x in Q if x["nufusta"]]
        tavan = sum(1 for x in q_nufus if x["adlar"] & r_adlar)
        q_tum_ad = set().union(*[x["adlar"] for x in Q])
        ortak = len(q_tum_ad & r_adlar)
        # tekil dizgi: metin -> anan fonksiyonlar
        def dizgi_haritasi(T):
            h = defaultdict(set)
            for x in T:
                if x["thunk"]:
                    continue
                for d in x["dizgiler"] or []:
                    h[d["m"]].add(x["adres"])
            return h
        hq, hr = dizgi_haritasi(Q), dizgi_haritasi(R)
        oy = defaultdict(Counter)
        for m, fq in hq.items():
            fr = hr.get(m)
            if fr and len(fq) == 1 and len(fr) == 1 and len(m) >= 4:
                oy[next(iter(fq))][next(iter(fr))] += 1
        r_idx = {x["adres"]: x for x in R}
        q_idx = {x["adres"]: x for x in Q}
        # çelişmeyen oy + karşılıklı teklik
        hedef_say = Counter()
        aday = {}
        for q, o in oy.items():
            if len(o) == 1:
                rr = next(iter(o))
                aday[q] = rr
                hedef_say[rr] += 1
        d = y = 0
        for q, rr in aday.items():
            if hedef_say[rr] != 1:
                continue
            xq = q_idx[q]
            if not xq["nufusta"]:
                continue
            if xq["adlar"] & r_idx[rr]["adlar"]:
                d += 1
            else:
                y += 1
        return {"nufus": len(q_nufus), "tavan": tavan, "ortak_ad": ortak, "dizgi_dogru": d, "dizgi_yanlis": y}

    c["cift"] = {}
    print("\nÇİFTLER (sorgu → başvuru): nüfus, tavan, ortak ad, tekil dizgi çapası doğru / yanlış")
    for qb, rb in (("debian/tmux", "mac/tmux"), ("mac/tmux", "debian/tmux"),
                   ("debian/htop", "mac/htop"), ("mac/htop", "debian/htop")):
        v = cift(qb, rb)
        c["cift"][f"{qb}->{rb}"] = v
        print(f"  {qb} → {rb}: {v}")
    for prog in ("tmux", "htop"):
        d = sum(c["cift"][k]["dizgi_dogru"] for k in c["cift"] if prog in k)
        y = sum(c["cift"][k]["dizgi_yanlis"] for k in c["cift"] if prog in k)
        nn = sum(c["cift"][k]["nufus"] for k in c["cift"] if prog in k)
        print(f"  {prog} iki yön: tekil dizgi {yaz(d, d + y)}; kapsam {d}/{nn} = {d/nn:.3f}")
        c[f"dizgi_{prog}"] = [d, y, nn]

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=1, default=str)


if __name__ == "__main__":
    main()
