"""Kalem 1: ÖZ KOD ve ÖLÇÜ (ikiz yoğunluğu) sayılarını OLGU tablosundan bağımsız türetir.

- oz_ad: kanıt dizgisi (harfleri korunmuş) ad sayılsa kaç yanlış doğruya döner
- kayıt çifti erişimi (OLGU `kayit_cifti_var`), coreutils dışı pay
- basit K1 ("kayıt çifti + sütun eki", kâhin çapa): tablo = sabit adımlı yuva dizisi, bağımsız gerçekleme
- belirteç tavanı (doğrudan dizgi; "bugün" birleşimi)
- modül öneki: adres komşuları ↔ çağrı komşuları
- ikiz yoğunluğu (aynı ikilide F1 >= 0,5 / 0,8 kardeş)

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/turet_ozkod.py --json $V/turet_ozkod.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict

from ortak import belirtecler, f1_kume, klon_soy, olgu_oku, program, wilson, yaz

OZKOD_KESIF_BIRIMLERI = {"debian/coreutils", "debian/tmux", "mac/tmux", "debian/openssl"}
OZKOD_SINAMA_BIRIMLERI = {"debian/sqlite3", "debian/redis-tools", "debian/zstd", "debian/htop", "mac/htop", "debian/tree"}


def taraf(b: str) -> str:
    return "kesif" if b in OZKOD_KESIF_BIRIMLERI else "sinama"


def gt0(r) -> str | None:
    g = r.get("gt_adlari") or []
    if not g:
        return None
    a = klon_soy(g[0])
    if r["platform"] == "mac" and a.startswith("_"):
        a = a[1:]
    return a


def gt_hepsi(r) -> set[str]:
    s = set()
    for g in r.get("gt_adlari") or []:
        a = klon_soy(g)
        if r["platform"] == "mac" and a.startswith("_"):
            a = a[1:]
        s.add(a)
    return s


TANIMLAYICI = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ADBICIM = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,60}$")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    S = [r for r in olgu_oku() if not (r["program"] == "redis-tools" and r["ikili"] == "redis-check-rdb")]
    c: dict = {}
    nufus = [r for r in S if r["nufusta"]]
    c["nufus_117"] = len(nufus)
    print("nüfus (redis-check-rdb'siz)", len(nufus))

    # ---- 1. oz_ad harf
    oz = [r for r in S if r["urun_olcude"] and r["kanal"] == "string_context/oz_ad"]
    sonuc = defaultdict(Counter)
    for r in oz:
        t = taraf(r["birim"])
        sonuc[t]["ad"] += 1
        sonuc[t]["dogru"] += r["hukum"] == "dogru"
        u = re.sub(r"_\d+$", "", r["urun_adi"]).lower()
        # kanıt dizgisi: fonksiyonun andığı, küçük harfli hâli ürün adına eşit tanımlayıcı dizgi
        aday = [d["m"] for d in r["dizgiler"] if TANIMLAYICI.match(d["m"]) and d["m"].lower() in (u, r["urun_adi"].lower())]
        if aday:
            sonuc[t]["kanit_bulundu"] += 1
            if any(x in gt_hepsi(r) for x in aday):
                sonuc[t]["kanit_harfiyle_dogru"] += 1
                if r["hukum"] == "yanlis":
                    sonuc[t]["yanlistan_dogruya"] += 1
                    sonuc[t]["yd_" + r["birim"]] += 1
        elif r["hukum"] == "dogru":
            sonuc[t]["kanit_yok_ama_dogru"] += 1
    c["oz_ad"] = {k: dict(v) for k, v in sonuc.items()}
    print("\noz_ad:", json.dumps(c["oz_ad"], ensure_ascii=False))

    # ---- 2. kayıt çifti erişimi
    er = defaultdict(lambda: [0, 0, 0])
    for r in nufus:
        e = er[r["birim"]]
        e[0] += 1
        e[1] += r["veri_yeri_sayisi"] > 0
        e[2] += bool(r["kayit_cifti_var"])
    c["erisim"] = dict(er)
    print("\nkayıt çifti erişimi (birim: nüfus, veri yuvası olan, pencere çifti olan)")
    tn = tv = tp = dn = dp = 0
    for b, (n, v, p) in sorted(er.items()):
        print(f"  {b:22s} {n:6d} {v:5d} {p:5d} ({p/n:.3f})")
        tn += n; tv += v; tp += p
        if b != "debian/coreutils":
            dn += n; dp += p
    print(f"  toplam {tn} {tv} {tp} ({tp/tn:.3f}); coreutils dışı {dp} / {dn} ({dp/dn:.3f})")
    c["erisim_toplam"] = [tn, tv, tp, dn, dp]

    # ---- 3. basit K1 (kâhin çapa), bağımsız gerçekleme
    # Yuva listesi: (ikili) -> [(yuva_adresi, fonksiyon satırı, komşu dizgiler {o: metin})]
    ikili_yuvalar = defaultdict(list)
    for r in S:
        if r["thunk"] or r["dis"]:
            continue
        for y in r["veri_yerleri"] or []:
            if y.get("got"):
                continue
            kom = {d["o"]: d["m"] for d in (y.get("d") or []) if ADBICIM.match(d["m"])}
            ikili_yuvalar[(r["birim"], r["ikili"])].append((y["y"], r, kom))

    def ad_normu(s: str) -> tuple[str, ...]:
        return tuple(belirtecler(s, rakam=True))

    k1 = defaultdict(Counter)
    k1_birim = defaultdict(Counter)
    for (birim, ikili), yl in ikili_yuvalar.items():
        yl.sort(key=lambda t: t[0])
        # tablo: ardışık yuvalar arası adım sabit (aynı kayıt boyu) → (adım) koşuları
        kosular = []
        i = 0
        while i < len(yl):
            j = i + 1
            adim = None
            while j < len(yl):
                fark = yl[j][0] - yl[j - 1][0]
                if adim is None:
                    if 8 <= fark <= 512 and fark % 8 == 0:
                        adim = fark
                    else:
                        break
                elif fark != adim:
                    break
                j += 1
            if j - i >= 3:
                kosular.append(yl[i:j])
                i = j
            else:
                i += 1
        for kosu in kosular:
            for delta in range(-4, 5):
                if delta == 0:
                    continue
                uyeler = [(r, kom[delta]) for (_, r, kom) in kosu if delta in kom and gt0(r)]
                if len(uyeler) < 3:
                    continue
                # her üye için ek = (önek, sonek) belirteç dizileri: ad = önek + dizgi + sonek
                ekler = []
                for r, m in uyeler:
                    an, mn = ad_normu(gt0(r)), ad_normu(m)
                    ek = None
                    if mn and len(an) >= len(mn):
                        for s in range(0, len(an) - len(mn) + 1):
                            if an[s:s + len(mn)] == mn:
                                ek = (an[:s], an[s + len(mn):])
                                break
                    ekler.append(ek)
                for idx, (r, m) in enumerate(uyeler):
                    if not r["nufusta"]:
                        continue
                    oy = Counter(e for k, e in enumerate(ekler) if k != idx and e is not None)
                    capa = sum(1 for k, e in enumerate(ekler) if k != idx)
                    if not oy:
                        continue
                    sirali = oy.most_common(2)
                    en, sayi = sirali[0]
                    if sayi < 2 or (len(sirali) > 1 and sirali[1][1] == sayi) or sayi * 2 < capa:
                        continue
                    tahmin = en[0] + ad_normu(m) + en[1]
                    anahtar = (birim, ikili, r["adres"])
                    k1_aday.setdefault(anahtar, set()).add(tahmin)
                    k1_satir[anahtar] = r
    return_k1(c, k1, k1_birim)

    # ---- 4. belirteç tavanı
    idx = {(r["birim"], r["ikili"], r["adres"]): r for r in S}

    def kanit_belirtecleri(r, bugun=True):
        t = set()
        for d in r["dizgiler"] or []:
            t.update(belirtecler(d["m"], en_az=2))
        dogrudan = set(t)
        for cg in r["cagrilanlar"] or []:
            if cg.get("ad"):
                t.update(belirtecler(cg["ad"], en_az=2))
            if cg.get("u"):
                t.update(belirtecler(cg["u"], en_az=2))
            k = idx.get((r["birim"], r["ikili"], cg["a"]))
            if k is not None:
                for d in k["dizgiler"] or []:
                    t.update(belirtecler(d["m"], en_az=2))
        for ca in r["cagiranlar"] or []:
            k = idx.get((r["birim"], r["ikili"], ca))
            if k is not None and k.get("urun_adi"):
                t.update(belirtecler(k["urun_adi"], en_az=2))
        for y in r["veri_yerleri"] or []:
            for d in y.get("d") or []:
                t.update(belirtecler(d["m"], en_az=2))
        return dogrudan, t

    tav = defaultdict(Counter)
    for r in nufus:
        g = gt0(r)
        gb = set(belirtecler(g, en_az=2))
        if not gb:
            continue
        dogrudan, bugun = kanit_belirtecleri(r)
        kesitler = ["hepsi"]
        if r["kaynak_sinifi"] == "program":
            kesitler.append("program")
        if r["kaynak_sinifi"] == "gnulib":
            kesitler.append("gnulib")
        for k in kesitler:
            tav[k]["n"] += 1
            tav[k]["dogrudan_en_az_1"] += bool(gb & dogrudan)
            tav[k]["dogrudan_hepsi"] += gb <= dogrudan
            tav[k]["bugun_en_az_1"] += bool(gb & bugun)
            tav[k]["bugun_hepsi"] += gb <= bugun
    c["tavan"] = {k: dict(v) for k, v in tav.items()}
    print("\nbelirteç tavanı")
    for k, v in tav.items():
        n = v["n"]
        print(f"  {k:8s} n={n:6d} doğrudan dizgi ≥1 {v['dogrudan_en_az_1']/n:.3f} hepsi {v['dogrudan_hepsi']/n:.3f};"
              f" bugün ≥1 {v['bugun_en_az_1']/n:.3f} hepsi {v['bugun_hepsi']/n:.3f}")

    # ---- 5. modül öneki: adres komşuları ↔ çağrı komşuları (kâhin)
    ikili_sirali = defaultdict(list)
    for r in S:
        if r["thunk"] or r["dis"] or not gt0(r):
            continue
        ikili_sirali[(r["birim"], r["ikili"])].append(r)

    def onek(r):
        b = belirtecler(gt0(r), rakam=True)
        return b[0] if len(b) >= 2 else None

    on = Counter()
    for anahtar, L in ikili_sirali.items():
        L.sort(key=lambda r: r["adres"])
        for i, r in enumerate(L):
            if not r["nufusta"] or onek(r) is None:
                continue
            on["onekli"] += 1
            if 0 < i < len(L) - 1:
                p, s = onek(L[i - 1]), onek(L[i + 1])
                if p is not None and p == s:
                    on["adres_uzlasan"] += 1
                    on["adres_dogru"] += p == onek(r)
            kom = []
            for cg in r["cagrilanlar"] or []:
                k = idx.get((r["birim"], r["ikili"], cg["a"]))
                if k is not None and gt0(k) and not k["thunk"] and onek(k):
                    kom.append(onek(k))
            for ca in r["cagiranlar"] or []:
                k = idx.get((r["birim"], r["ikili"], ca))
                if k is not None and gt0(k) and onek(k):
                    kom.append(onek(k))
            if kom:
                oy = Counter(kom).most_common(2)
                if len(oy) == 1 or oy[0][1] > oy[1][1]:
                    on["cagri_cogunluk"] += 1
                    on["cagri_dogru"] += oy[0][0] == onek(r)
    c["onek"] = dict(on)
    print("\nmodül öneki (kâhin): önekli", on["onekli"],
          "| adres komşuları uzlaşan:", yaz(on["adres_dogru"], on["adres_uzlasan"]),
          "| çağrı çoğunluğu:", yaz(on["cagri_dogru"], on["cagri_cogunluk"]))

    # ---- 6. ikiz yoğunluğu (aynı ikilide başka fonksiyonun GT adı F1 >= eşik)
    S_tum = list(olgu_oku({"birim", "ikili", "platform", "adres", "nufusta", "gt_adlari", "thunk", "dis", "program", "cpp_disarida"}))
    ikili_gt = defaultdict(list)
    for r in S_tum:
        if r["gt_adlari"]:
            ikili_gt[(r["birim"], r["ikili"])].append(r)
    ikiz = Counter()
    for anahtar, L in ikili_gt.items():
        adlar = {}
        for r in L:
            g = gt0(r)
            adlar.setdefault(g, tuple(sorted(set(belirtecler(g, rakam=True)))))
        tekil = list(adlar.items())
        # belirteç → ad dizinleri
        ters = defaultdict(set)
        for i, (_, bt) in enumerate(tekil):
            for t in bt:
                ters[t].add(i)
        en_iyi = {}
        for i, (ad, bt) in enumerate(tekil):
            aday = set()
            for t in bt:
                aday |= ters[t]
            aday.discard(i)
            m = 0.0
            sb = set(bt)
            for j in aday:
                f = f1_kume(list(sb), list(tekil[j][1]))
                if f > m:
                    m = f
                    if m >= 0.999:
                        break
            en_iyi[ad] = m
        for r in L:
            if not r["nufusta"]:
                continue
            ikiz["nufus"] += 1
            m = en_iyi[gt0(r)]
            ikiz["f1_05"] += m >= 0.5
            ikiz["f1_08"] += m >= 0.8
    c["ikiz"] = dict(ikiz)
    print("\nikiz yoğunluğu: nüfus", ikiz["nufus"], "F1>=0,5:", yaz(ikiz["f1_05"], ikiz["nufus"]),
          "F1>=0,8:", yaz(ikiz["f1_08"], ikiz["nufus"]))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=1, default=str)


k1_aday: dict = {}
k1_satir: dict = {}


def return_k1(c, k1, k1_birim) -> None:
    """K1 adaylarını hükme bağlar: tek ad çıkan fonksiyonlarda norm eşitliği."""
    def norm(s):
        return tuple(belirtecler(s, rakam=True))
    sonuc = defaultdict(Counter)
    birim = defaultdict(Counter)
    for anahtar, adaylar in k1_aday.items():
        r = k1_satir[anahtar]
        t = taraf(r["birim"])
        sonuc[t]["adayli"] += 1
        if len(adaylar) != 1:
            sonuc[t]["cekimser"] += 1
            continue
        tahmin = next(iter(adaylar))
        sonuc[t]["ad"] += 1
        birim[r["birim"]]["ad"] += 1
        ok = any(norm(g) == tahmin for g in gt_hepsi(r))
        sonuc[t]["dogru"] += ok
        birim[r["birim"]]["dogru"] += ok
        if ok:
            sonuc[t]["dogru_bugun_adsiz"] += r["urun_adi"] is None
    c["k1_basit"] = {k: dict(v) for k, v in sonuc.items()}
    c["k1_basit_birim"] = {k: dict(v) for k, v in birim.items()}
    print("\nbasit K1 (kâhin çapa; bağımsız gerçekleme)")
    for t, v in sonuc.items():
        print(f"  {t}: adaylı {v['adayli']} ad {v['ad']} doğru {yaz(v['dogru'], v['ad'])} (bugün adsız {v['dogru_bugun_adsiz']})")
    for b, v in sorted(birim.items()):
        print(f"    {b:22s} {v['dogru']} / {v['ad']}")


if __name__ == "__main__":
    main()
