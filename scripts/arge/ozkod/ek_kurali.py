#!/usr/bin/env python3
"""ÖZ KOD kalem 2 — kayıt çiftinden kuralla ad: "sütun eki" kuralı (K1) ve ölçümü.

Kural K1 (tanımı ``kayit_cifti.py`` belge dizgisinde; burada uygulanır)
---------------------------------------------------------------------
Aday (grup, dizgi) çiftleri:
  T: N4 tablosundaki (adım > 1) fonksiyon yuvası p ve −adım < δ < adım, δ ≠ 0 için p+δ yuvası ad
     biçimli bir dizgiyi gösteriyorsa → grup ("T", tablo, sütun, δ). Faz varsayımı yok.
  N: tablo dışı yuva, çapa nesnesi içinde (≤ 64 sözcük) ad biçimli dizgi → grup
     ("N", nesnenin tür dizisi, yuva ofseti, dizgi ofseti).
  C: çağrı yeri: aynı çağrıda ad biçimli dizgi sabiti ve ``FUN_`` işaretçisi → grup
     ("C", çağrılan, argüman sayısı, fonksiyon argümanı, dizgi argümanı).
Ad: grubun eki (önek, sonek) hedef dışındaki üyelerden ("çapa") öğrenilir: çapa adı =
önek + norm(S_çapa) + sonek (belirteç sınırında tek geçiş). Oy fonksiyon düzeyindedir (bir çapa
fonksiyonu bir eke en çok bir oy verir). En çok oy alan ek ≥ MIN_DESTEK çapa fonksiyonundan
gelmeli, ikinciden kesin fazla olmalı ve gruptaki çapa fonksiyonlarının en az MIN_ORAN'ını
açıklamalı (v2; keşifte görülen: yanlış δ grubunda, ardışık kayıtların aynı fonksiyonu paylaştığı
yerlerde rastlantısal ek oyu çıkıyor ve çelişki üretiyordu). Hedefin bütün (grup, dizgi)
adaylarından çıkan adlar tek bir ada iniyorsa ad verilir; farklı adlar çıkarsa çekimser.

Çapa kipleri
  kahin  : çapa adı = GT (hedef dışındaki bütün üyeler). Üst sınır; "bir fonksiyonun adı
           bilinirse tablodaki öbürleri hesaplanır" önermesinin ölçümü.
  tek    : tek çapa (MIN_DESTEK = 1), sıralı çiftlerin ortalaması (tanı).
  urun   : çapa adı = ürünün bugün verdiği ad (hükmüne bakılmadan) ya da Ghidra'nın jenerik
           olmayan adı. Bugünkü gerçek getiri.
  eksiz  : aday = norm(S); yalnız C grubunda, hedefin tek aday dizgisi varsa (çapa gerekmez).

Sayılan: nüfustaki hedeflerde ad verilen / doğru (norm eşitliği; ayrıca karakter eşitliği).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/ek_kurali.py --taraf kesif [--ornekli]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402

MIN_DESTEK = 2
MIN_ORAN = 0.5
NESNE_GEVSEK = False
BENZETIM_PAYLARI = (0.02, 0.05, 0.10, 0.25)
BENZETIM_TOHUMLARI = (0, 1, 2, 3, 4)
CIKTI = V.ARGE_KOKU / "ek_kurali"


def adaylar(d: dict[str, Any]) -> dict[int, list[tuple[tuple, str]]]:
    """fonksiyon adresi → [(grup, dizgi)] (yinelenenler atılır)."""
    out: dict[int, list[tuple[tuple, str]]] = defaultdict(list)
    for y in d["yuvalar"]:
        fa = y["fn"]
        tb = y["tablo"]
        if tb and tb["adim"] > 1:
            _grup, _ilk, turler, _hedefler, dizgiler = d["bolum_dokumu"][y["bolum"]]
            p, s = y["sira"], tb["adim"]
            for delta in range(-(s - 1), s):
                q = p + delta
                if delta == 0 or q not in dizgiler:
                    continue
                metin = dizgiler[q]
                if metin and K.ad_bicimli(metin):
                    out[fa].append((("T", y["bolum"], tb["tablo"], tb["sutun"], delta), metin))
        elif y["nesne"]:
            ns = y["nesne"]
            for ofs, metin in ns["dizgi"]:
                if metin and K.ad_bicimli(metin):
                    if NESNE_GEVSEK:   # keşifte sınanmamış değişke: tür dizisi yerine yalnız uzunluk
                        out[fa].append((("N2", ns["uzunluk"], -ns["bas"], ofs), metin))
                    else:
                        out[fa].append((("N", ns["turler"], -ns["bas"], ofs), metin))
    for r in K.cagri_ciftleri(d):
        fa = r["fn"]
        if fa not in d["fonk"]:
            continue
        for i, metin in r["dizgiler"]:
            if metin and K.ad_bicimli(metin):
                out[fa].append((("C", r["cagrilan"], r["n_arg"], r["fn_arg"], i), metin))
    return {fa: sorted(set(v), key=str) for fa, v in out.items()}


def _ek_oyu(uyeler: list[tuple[int, str]], hedef: int, ad_kaynagi: dict[int, list[str]],
            min_destek: int) -> Optional[tuple[str, str]]:
    oy: Counter = Counter()
    capa_fn: set[int] = set()
    fn_ekleri: dict[int, set] = defaultdict(set)
    for a, s in uyeler:
        if a == hedef or a not in ad_kaynagi:
            continue
        capa_fn.add(a)
        for ad in ad_kaynagi[a]:
            ek = K.ek_cikar(s, ad)
            if ek is not None:
                fn_ekleri[a].add(ek)
                break
    for a, ekler in fn_ekleri.items():
        for ek in ekler:
            oy[ek] += 1
    if not oy:
        return None
    (ek, n1), *kalan = oy.most_common(2)
    if n1 < min_destek or (kalan and kalan[0][1] == n1) or n1 < MIN_ORAN * len(capa_fn):
        return None
    return ek


def tahmin(fa: int, fa_adaylari: list[tuple[tuple, str]], gruplar: dict[tuple, list[tuple[int, str]]],
           ad_kaynagi: dict[int, list[str]], min_destek: int) -> tuple[Optional[str], str]:
    """(ad | None, durum). durum: 'ad', 'capa_yok', 'celiski'."""
    adlar = set()
    for grup, s in fa_adaylari:
        ek = _ek_oyu(gruplar[grup], fa, ad_kaynagi, min_destek)
        if ek is not None:
            adlar.add(K.ek_uygula(s, ek))
    if not adlar:
        return None, "capa_yok"
    if len(adlar) > 1:
        return None, "celiski"
    return next(iter(adlar)), "ad"


def olc(taraf_: str) -> dict[str, Any]:
    f1 = V.ks1()._f1()
    birim: dict[str, Counter] = defaultdict(Counter)
    ornek: dict[str, list] = defaultdict(list)
    grup_dokumu: list[dict[str, Any]] = []
    for d in V.hepsi(taraf_=taraf_):
        c = birim[d["birim"]]
        ad = adaylar(d)
        gruplar: dict[tuple, list[tuple[int, str]]] = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        gt_kaynak = {a: list(v) for a, v in d["gt_adlar"].items()}
        urun_kaynak: dict[int, list[str]] = {}
        for a, f in d["fonk"].items():
            if not f["thunk"] and not f1.is_generic_name(f["ad"], [a]):
                urun_kaynak[a] = [f["ad"]]
        for a, r in d["urun"].items():
            urun_kaynak[a] = [r["ad"]]
        import random
        benzetim = {}
        sirali = sorted(gt_kaynak)
        for pay in BENZETIM_PAYLARI:
            for tohum in BENZETIM_TOHUMLARI:
                r = random.Random(f"{d['birim']}/{d['ad']}/{pay}/{tohum}")
                benzetim[(pay, tohum)] = {a: gt_kaynak[a] for a in sirali if r.random() < pay}
        c["nufus"] += len(d["nufus"])
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            gt = d["gt_adlar"][fa]
            c["adayli"] += 1
            bugun = d["urun"].get(fa)
            # (a) kâhin çapa
            t, durum = tahmin(fa, ad[fa], gruplar, gt_kaynak, MIN_DESTEK)
            c[f"kahin_{durum}"] += 1
            if t is not None:
                dogru = K.gt_esit(t, gt)
                c["kahin_dogru"] += dogru
                c["kahin_karakter_dogru"] += K.karakter_esit(t, gt)
                c["kahin_dogru_bugun_adsiz"] += dogru and bugun is None
                c["kahin_dogru_bugun_yanlis"] += dogru and bugun is not None and bugun["durum"] != "dogru"
                c["kahin_dogru_bugun_dogru"] += dogru and bugun is not None and bugun["durum"] == "dogru"
                tur = sorted({g[0] for g, _s in ad[fa]})
                c[f"kahin_ad_tur_{'+'.join(tur)}"] += 1
                c[f"kahin_dogru_tur_{'+'.join(tur)}"] += dogru
                if len(ornek[f"{d['birim']}|kahin|{'dogru' if dogru else 'yanlis'}"]) < 10:
                    ornek[f"{d['birim']}|kahin|{'dogru' if dogru else 'yanlis'}"].append((gt[0], t))
            # (b) benzetim: fonksiyonların rastgele p payının adı biliniyor olsaydı
            for pay in BENZETIM_PAYLARI:
                for tohum in BENZETIM_TOHUMLARI:
                    kaynak = benzetim[(pay, tohum)]
                    if fa in kaynak:
                        continue
                    t, durum = tahmin(fa, ad[fa], gruplar, kaynak, MIN_DESTEK)
                    c[f"benz_{pay}_hedef"] += 1
                    if t is not None:
                        c[f"benz_{pay}_ad"] += 1
                        c[f"benz_{pay}_dogru"] += K.gt_esit(t, gt)
            # (c) ürün çapası (bugünkü adlar), MIN_DESTEK ve 1
            for md, etiket in ((MIN_DESTEK, "urun"), (1, "urun1")):
                t, durum = tahmin(fa, ad[fa], gruplar, urun_kaynak, md)
                c[f"{etiket}_{durum}"] += 1
                if t is not None:
                    dogru = K.gt_esit(t, gt)
                    c[f"{etiket}_dogru"] += dogru
                    c[f"{etiket}_dogru_bugun_adsiz"] += dogru and bugun is None
                    if len(ornek[f"{d['birim']}|{etiket}|{'dogru' if dogru else 'yanlis'}"]) < 10:
                        ornek[f"{d['birim']}|{etiket}|{'dogru' if dogru else 'yanlis'}"].append((gt[0], t))
            # (d) eksiz: yalnız C adayları, tek dizgi
            c_dizgileri = {V.norm(s) for g, s in ad[fa] if g[0] == "C"}
            if len(c_dizgileri) == 1:
                t = next(iter(c_dizgileri))
                dogru = K.gt_esit(t, gt)
                c["eksiz_ad"] += 1
                c["eksiz_dogru"] += dogru
                c["eksiz_dogru_bugun_adsiz"] += dogru and bugun is None
                if len(ornek[f"{d['birim']}|eksiz|{'dogru' if dogru else 'yanlis'}"]) < 10:
                    ornek[f"{d['birim']}|eksiz|{'dogru' if dogru else 'yanlis'}"].append((gt[0], t))
        # grup dökümü (GT eki; üye ≥ 3)
        for grup, uyeler in gruplar.items():
            fnler = {a for a, _s in uyeler}
            if len(fnler) < 3:
                continue
            ekler = Counter()
            for a, s in uyeler:
                ek = next((e for g_ in gt_kaynak.get(a, ()) if (e := K.ek_cikar(s, g_)) is not None), None)
                ekler[ek] += 1
            grup_dokumu.append({"birim": d["birim"], "ikili": d["ad"], "tur": grup[0],
                                "grup": str(grup)[:80], "fonksiyon": len(fnler),
                                "nufusta": len(fnler & d["nufus"]),
                                "urun_adli": len(fnler & set(urun_kaynak)),
                                "ekler": [[list(e) if e else None, n] for e, n in ekler.most_common(3)]})
    return {"taraf": taraf_, "min_destek": MIN_DESTEK, "min_oran": MIN_ORAN,
            "birim": {b: dict(c) for b, c in sorted(birim.items())},
            "gruplar": grup_dokumu, "ornek": dict(sorted(ornek.items()))}


def yaz(s: dict[str, Any], ornekli: bool) -> None:
    birim = {b: Counter(c) for b, c in s["birim"].items()}
    top: Counter = Counter()
    for c in birim.values():
        top.update(c)
    satirlar = list(birim.items()) + [("**toplam**", top)]
    print(f"\n## K1 kâhin çapa (MIN_DESTEK = {s['min_destek']}) — taraf: {s['taraf']}")
    print("| birim | nüfus | adaylı | ad verilen | doğru (norm; Wilson) | karakter eşit | çekimser: çapa yok | çelişki | doğruların bugün adsız / yanlış / doğru olanı |")
    print("|---|---:|---:|---:|---|---:|---:|---:|---|")
    for b, c in satirlar:
        print(f"| {b} | {c['nufus']} | {c['adayli']} | {c['kahin_ad']} | {V.wilson(c['kahin_dogru'], c['kahin_ad'])} "
              f"| {c['kahin_karakter_dogru']} | {c['kahin_capa_yok']} | {c['kahin_celiski']} | "
              f"{c['kahin_dogru_bugun_adsiz']} / {c['kahin_dogru_bugun_yanlis']} / {c['kahin_dogru_bugun_dogru']} |")
    print("\n## K1 kâhin, aday türüne göre (T tablo, N nesne, C çağrı)")
    turler = sorted({k[len("kahin_ad_tur_"):] for c in birim.values() for k in c if k.startswith("kahin_ad_tur_")})
    print("| birim | " + " | ".join(turler) + " |")
    print("|---|" + "---|" * len(turler))
    for b, c in satirlar:
        print(f"| {b} | " + " | ".join(f"{c[f'kahin_dogru_tur_{t}']} / {c[f'kahin_ad_tur_{t}']}" for t in turler) + " |")
    print("\n## Ürün çapası (bugünkü adlar) ve eksiz")
    print("| birim | ürün çapası (≥ 2): ad / doğru / doğru ve bugün adsız | ürün çapası (≥ 1): ad / doğru / bugün adsız | eksiz (C): ad / doğru / bugün adsız |")
    print("|---|---|---|---|")
    for b, c in satirlar:
        print(f"| {b} | {c['urun_ad']} / {c['urun_dogru']} / {c['urun_dogru_bugun_adsiz']} "
              f"| {c['urun1_ad']} / {c['urun1_dogru']} / {c['urun1_dogru_bugun_adsiz']} "
              f"| {c['eksiz_ad']} / {c['eksiz_dogru']} / {c['eksiz_dogru_bugun_adsiz']} |")
    print(f"\n## Benzetim: GT'li fonksiyonların rastgele p payının adı biliniyor (çapa); {len(BENZETIM_TOHUMLARI)} tohumun toplamı")
    print("| birim | " + " | ".join(f"p = %{int(100 * p)}: ad / hedef; doğru / ad" for p in BENZETIM_PAYLARI) + " |")
    print("|---|" + "---|" * len(BENZETIM_PAYLARI))
    for b, c in satirlar:
        print(f"| {b} | " + " | ".join(
            f"{c[f'benz_{p}_ad']} / {c[f'benz_{p}_hedef']}; {V.wilson(c[f'benz_{p}_dogru'], c[f'benz_{p}_ad'])}"
            for p in BENZETIM_PAYLARI) + " |")
    print("\n## Gruplar (≥ 3 fonksiyon; ek = GT'den)")
    print("| birim | ikili | tür | fonksiyon | nüfusta | ürün / Ghidra adlı | ek dağılımı |")
    print("|---|---|---|---:|---:|---:|---|")
    for g in sorted(s["gruplar"], key=lambda g: (-g["fonksiyon"], g["grup"])):
        if ornekli:
            ek = "; ".join((f"`{e[0]}` + S + `{e[1]}` × {n}" if e else f"ek yok × {n}") for e, n in g["ekler"])
        else:
            ek = "; ".join((f"ek × {n}" if e else f"ek yok × {n}") for e, n in g["ekler"])
        print(f"| {g['birim']} | {g['ikili']} | {g['tur']} | {g['fonksiyon']} | {g['nufusta']} | {g['urun_adli']} | {ek} |")
    if ornekli:
        print("\n## Örnekler (GT adı ← hesaplanan ad)")
        for k, v in s["ornek"].items():
            print(f"- {k}: " + "; ".join(f"`{g}` ← `{t}`" for g, t in v))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    ap.add_argument("--ornekli", action="store_true")
    ap.add_argument("--nesne-gevsek", action="store_true",
                    help="keşifte sınanmamış değişke: nesne grubunun anahtarı uzunluk (yön gösterici)")
    a = ap.parse_args()
    if a.ornekli and a.taraf != "kesif":
        raise SystemExit("örnek dökümü yalnız keşif tarafında")
    global NESNE_GEVSEK
    NESNE_GEVSEK = a.nesne_gevsek
    s = olc(a.taraf)
    s["nesne_gevsek"] = NESNE_GEVSEK
    s["betik_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(Path(__file__).resolve().parent.glob("*.py"))}
    CIKTI.mkdir(parents=True, exist_ok=True)
    (CIKTI / f"ek_kurali_{a.taraf}{'_nesne_gevsek' if NESNE_GEVSEK else ''}.json").write_text(
        json.dumps(s, ensure_ascii=False, indent=1), encoding="utf-8")
    yaz(s, a.ornekli)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
