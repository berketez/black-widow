#!/usr/bin/env python3
"""ÖZ KOD kalem 3–5: belirteç tavanı, rol derinliği, modül öneki yayılımı (yalnız sayım; kural yok).

Nüfus: ``GtBirimi.nufus`` (ad bekleyen). Kaynak sınıfı OLGU tablosundan
(``~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz`` ``kaynak_sinifi``); dizgi, çağrı ve
kayıt çifti kanıtı bu hattın kendi önbelleğinden (``ozkod_veri``, ``ek_kurali.adaylar``).

Kalem 3 — belirteç tavanı. GT adının belirteçleri (klon eki soyulmuş ilk ad; ≥ 2 karakter, rakam
dışı; ``ozkod_veri.ad_belirtecleri``) şu kaynakların belirteç kümesinde aranır:
  D0  fonksiyonun doğrudan andığı dizgiler
  YOL D0'ın alt kümesi: dosya yolu biçimli dizgiler ('/' içeren ya da .c/.h ile biten)
  D1  derinlik 1 çağrılanların (iç, thunk olmayan) dizgileri
  D2  derinlik 2 çağrılanların dizgileri
  KC  kayıt çifti dizgileri (V ∪ C; ``ek_kurali.adaylar``)
  IM  doğrudan çağrılan içe aktarımların adları (thunk / dış, Ghidra adı jenerik değil)
  KN  çağıran ve çağrılanların BUGÜN bilinen adı (Ghidra'nın jenerik olmayan adı ya da ürünün verdiği ad)
  KN* kâhin: çağıran ve çağrılanların GT adı (komşuların hepsi doğru adlandırılmış olsaydı)
Ölçüler: en az bir belirteci bulunan fonksiyon; bütün belirteçleri bulunan fonksiyon; bulunan
belirteç / toplam belirteç (mikro); ilk belirteç (modül öneki) ve son belirteç ayrı.
Uyarı: tavan belirtecin VARLIĞINI sayar; seçme ve sıralama sorunu ayrıca çözülmelidir.

Kalem 4 — rol derinliği. d(f) = f'den içe aktarım çağıran bir fonksiyona en kısa çağrı uzaklığı
(0: f kendisi çağırıyor; 1–3; yok). "Ayırt edici" içe aktarım: ikilinin iç fonksiyonlarının
≤ %5'inin çağırdığı. Derinlik 1'de içe aktarımı çağıran çağrılanın çağıran sayısı ≥ 5 ise "ortak
sarmalayıcı".

Kalem 5 — modül öneki (A6). Önek = GT adının ilk belirteci (ad ≥ 2 belirteçliyse). Çağrı komşuları
(çağıran ∪ çağrılan, GT'li) ve adres komşuları (adres sırasında önceki / sonraki GT'li fonksiyon).
"Sandviç": bugün adsız bir fonksiyonun adres sırasında önündeki ve arkasındaki en yakın BUGÜN adlı
(Ghidra'nın jenerik olmayan adı ya da ürün adı; ≥ 2 belirteçli) iç fonksiyonların öneki aynıysa o
önek; iki çapa arasındaki fonksiyon sayısı sınırıyla (2, 8, 32, sınırsız). Hüküm: önek = GT öneki.

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/tavan.py
"""
from __future__ import annotations

import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import ek_kurali as E  # noqa: E402

OLGU = V.EV / "karadul_olcum" / "runs" / "arge-2026-11-19" / "olgu" / "olgu.jsonl.gz"
KAYNAKLAR = ("D0", "YOL", "D1", "D2", "KC", "IM", "KN", "KN*")
BIRLESIK = {"bugün (D0 ∪ D1 ∪ KC ∪ IM ∪ KN)": ("D0", "D1", "KC", "IM", "KN"),
            "kâhin (hepsi + D2 + KN*)": ("D0", "D1", "D2", "KC", "IM", "KN", "KN*")}
YOL_RE = re.compile(r"/|\.[ch]$")
AYIRT_PAYI = 0.05
SARMALAYICI_CAGIRAN = 5
EN_DERIN = 3
SANDVIC_UZAKLIKLARI = (2, 8, 32, 0)   # iki çapa arasındaki fonksiyon sayısı sınırı; 0 = sınırsız


def siniflar() -> dict[tuple[str, str, int], str]:
    out = {}
    with gzip.open(OLGU, "rt", encoding="utf-8") as f:
        for satir in f:
            r = json.loads(satir)
            if r["nufusta"] or r.get("kanal"):
                out[(r["birim"], r["ikili"], r["adres"])] = r["kaynak_sinifi"]
    return out


def bel(metinler) -> set[str]:
    out: set[str] = set()
    for m in metinler:
        out.update(b for b in V.belirtecler(m) if len(b) >= 2 and not b.isdigit())
    return out


def main() -> int:
    k = V.ks1()
    f1 = k._f1()
    sinif = siniflar()
    tok: dict[tuple, Counter] = defaultdict(Counter)      # (taraf, sınıf) → sayaç
    rol: dict[tuple, Counter] = defaultdict(Counter)
    onek: dict[tuple, Counter] = defaultdict(Counter)
    ozad: Counter = Counter()
    for d in V.hepsi():
        fonk = d["fonk"]
        ic = {a for a, f in fonk.items() if not f["thunk"] and not f["dis"]}
        ice_aktarim = {a: f["ad"] for a, f in fonk.items()
                       if (f["thunk"] or f["dis"]) and not f1.is_generic_name(f["ad"], [a])}
        fn_dizgi = {a: [d["dizgi_metin"][s] for s in ss] for a, ss in d["fn_dizgi"].items()}
        aday = E.adaylar(d)
        bilinen: dict[int, str] = {}
        for a in ic:
            if not f1.is_generic_name(fonk[a]["ad"], [a]):
                bilinen[a] = fonk[a]["ad"]
        for a, r in d["urun"].items():
            bilinen[a] = r["ad"]
        # içe aktarım çağıranlar
        im_cagiran: dict[int, set[int]] = defaultdict(set)    # içe aktarım → çağıran iç fonksiyonlar
        for a in ic:
            for c in d["cagrilan"].get(a, ()):
                if c in ice_aktarim:
                    im_cagiran[c].add(a)
        ayirt = {c for c, s in im_cagiran.items() if len(s) <= AYIRT_PAYI * max(1, len(ic))}
        dogrudan = {a for s in im_cagiran.values() for a in s}
        dogrudan_ayirt = {a for c in ayirt for a in im_cagiran[c]}

        def derinlik(fa: int, hedef: set[int]) -> int | None:
            if fa in hedef:
                return 0
            gorulen, sinir = {fa}, [fa]
            for dd in range(1, EN_DERIN + 1):
                yeni = []
                for x in sinir:
                    for c in d["cagrilan"].get(x, ()):
                        if c in ic and c not in gorulen:
                            if c in hedef:
                                return dd
                            gorulen.add(c)
                            yeni.append(c)
                sinir = yeni
            return None

        sirali = sorted(a for a in ic if a in d["gt_adlar"])
        sira_no = {a: i for i, a in enumerate(sirali)}

        def gt_onek(a: int) -> str | None:
            adlar = d["gt_adlar"].get(a)
            if not adlar:
                return None
            t = V.ad_belirtecleri(k.klon_tabani(adlar[0]) or adlar[0])
            return t[0] if len(t) >= 2 else None

        # sandviç: adres sırasında (bütün iç fonksiyonlar) önceki ve sonraki BUGÜN adlı fonksiyon
        ic_sirali = sorted(ic)
        ic_no = {a: i for i, a in enumerate(ic_sirali)}
        bugun_onek = {}
        for a in ic_sirali:
            if a in bilinen:
                tb = V.ad_belirtecleri(bilinen[a])
                if len(tb) >= 2:
                    bugun_onek[a] = tb[0]
        onceki: dict[int, tuple[int, str] | None] = {}
        son = None
        for i, a in enumerate(ic_sirali):
            onceki[a] = son
            if a in bugun_onek:
                son = (i, bugun_onek[a])
        sonraki: dict[int, tuple[int, str] | None] = {}
        son = None
        for i in range(len(ic_sirali) - 1, -1, -1):
            a = ic_sirali[i]
            sonraki[a] = son
            if a in bugun_onek:
                son = (i, bugun_onek[a])

        for fa, r in d["urun"].items():
            if r["kanal"] == "string_context/oz_ad":
                s_ = sinif.get((d["birim"], d["ad"], fa), "?")
                ozad[(s_, "ad")] += 1
                ozad[(s_, "dogru")] += r["durum"] == "dogru"

        for fa in d["nufus"]:
            s_ = sinif.get((d["birim"], d["ad"], fa), "?")
            anahtarlar = [(d["taraf"], s_), ("hepsi", s_), (d["taraf"], "hepsi"), ("hepsi", "hepsi"),
                          (d["birim"], "hepsi")]
            gt = d["gt_adlar"][fa]
            taban = k.klon_tabani(gt[0]) or gt[0]
            T = V.ad_belirtecleri(taban)
            if T:
                cagrilan1 = [c for c in d["cagrilan"].get(fa, ()) if c in ic and c != fa]
                cagrilan2 = {c2 for c in cagrilan1 for c2 in d["cagrilan"].get(c, ()) if c2 in ic} - {fa}
                komsu = set(d["cagrilan"].get(fa, ())) | set(d["cagiran"].get(fa, ()))
                d0 = fn_dizgi.get(fa, [])
                kume = {
                    "D0": bel(d0),
                    "YOL": bel(s for s in d0 if YOL_RE.search(s)),
                    "D1": bel(s for c in cagrilan1 for s in fn_dizgi.get(c, [])),
                    "D2": bel(s for c in cagrilan2 for s in fn_dizgi.get(c, [])),
                    "KC": bel(s for _g, s in aday.get(fa, [])),
                    "IM": bel(ice_aktarim[c] for c in d["cagrilan"].get(fa, ()) if c in ice_aktarim),
                    "KN": bel(bilinen[c] for c in komsu if c in bilinen and c != fa),
                    "KN*": bel(n for c in komsu if c in ic and c != fa for n in d["gt_adlar"].get(c, [])[:1]),
                }
                for b_ad, uyeler in BIRLESIK.items():
                    kume[b_ad] = set().union(*(kume[u] for u in uyeler))
                Ts = set(T)
                for an in anahtarlar:
                    c = tok[an]
                    c["fn"] += 1
                    c["belirtec"] += len(Ts)
                    c["cok_belirtecli"] += len(T) >= 2
                    for kaynak, ks in kume.items():
                        ortak = Ts & ks
                        c[f"{kaynak}|enaz1"] += bool(ortak)
                        c[f"{kaynak}|hepsi"] += ortak == Ts
                        c[f"{kaynak}|bulunan"] += len(ortak)
                        c[f"{kaynak}|ilk"] += T[0] in ks
                        if len(T) >= 2:
                            c[f"{kaynak}|son"] += T[-1] in ks
            # rol derinliği
            for hedef_ad, hedef in (("her", dogrudan), ("ayirt", dogrudan_ayirt)):
                dd = derinlik(fa, hedef)
                for an in anahtarlar:
                    rol[an][f"{hedef_ad}|{'yok' if dd is None else dd}"] += 1
                if hedef_ad == "ayirt" and dd == 1:
                    tasiyan = [c for c in d["cagrilan"].get(fa, ()) if c in hedef]
                    ortak_s = any(len(d["cagiran"].get(c, ())) >= SARMALAYICI_CAGIRAN for c in tasiyan)
                    for an in anahtarlar:
                        rol[an]["ayirt|1|ortak_sarmalayici"] += ortak_s
            for an in anahtarlar:
                rol[an]["fn"] += 1
            # önek
            p = gt_onek(fa)
            if p is not None:
                komsu = [c for c in set(d["cagrilan"].get(fa, ())) | set(d["cagiran"].get(fa, ()))
                         if c in ic and c != fa]
                kp = Counter(q for c in komsu if (q := gt_onek(c)) is not None)
                i = sira_no.get(fa)
                adres_k = [sirali[j] for j in (i - 1, i + 1) if i is not None and 0 <= j < len(sirali)]
                ap = [gt_onek(c) for c in adres_k]
                bugun = Counter(V.ad_belirtecleri(bilinen[c])[0] for c in komsu
                                if c in bilinen and len(V.ad_belirtecleri(bilinen[c])) >= 2)
                bugun_adres = [V.ad_belirtecleri(bilinen[c])[0] for c in adres_k
                               if c in bilinen and len(V.ad_belirtecleri(bilinen[c])) >= 2]
                o_, s_n = onceki.get(fa), sonraki.get(fa)
                sandvic = None
                if o_ and s_n and o_[1] == s_n[1] and fa not in bilinen:
                    sandvic = (s_n[0] - o_[0] - 1, o_[1])
                for an in anahtarlar:
                    c = onek[an]
                    c["bugun_adsiz"] += fa not in bilinen
                    if sandvic:
                        for u in SANDVIC_UZAKLIKLARI:
                            if u == 0 or sandvic[0] <= u:
                                c[f"sandvic_{u}_karar"] += 1
                                c[f"sandvic_{u}_dogru"] += sandvic[1] == p
                for an in anahtarlar:
                    c = onek[an]
                    c["fn"] += 1
                    c["cagri_komsu_var"] += bool(kp)
                    c["cagri_ayni_var"] += kp[p] > 0
                    if kp:
                        (en, n1), *kalan = kp.most_common(2)
                        tek = not (kalan and kalan[0][1] == n1)
                        c["cagri_cogunluk_karar"] += tek
                        c["cagri_cogunluk_dogru"] += tek and en == p
                    c["adres_ayni_var"] += p in ap
                    c["adres_iki_yan_ayni"] += len(ap) == 2 and ap[0] == p and ap[1] == p
                    c["adres_iki_yan_uzlasiyor"] += len(ap) == 2 and ap[0] == ap[1] and ap[0] is not None
                    c["adres_iki_yan_uzlasi_dogru"] += len(ap) == 2 and ap[0] == ap[1] == p
                    c["bugun_cagri_karar"] += bool(bugun)
                    if bugun:
                        c["bugun_cagri_dogru"] += bugun.most_common(1)[0][0] == p
                    c["bugun_adres_karar"] += bool(bugun_adres)
                    c["bugun_adres_dogru"] += p in bugun_adres

    def yuz(a: int, b: int) -> str:
        return f"{a} (%{100 * a / b:.1f})" if b else "0"

    satirlar = [("hepsi", "hepsi"), ("kesif", "hepsi"), ("sinama", "hepsi"),
                ("hepsi", "program"), ("hepsi", "gnulib"), ("hepsi", "proje_kitapligi"),
                ("hepsi", "ucuncu_taraf"), ("hepsi", "bilinmiyor")] + [(b, "hepsi") for b in V.BIRIMLER]
    print("## oz_ad kanalının kaynak sınıfı (OLGU ile çapraz denetim; redis-check-rdb tek sayılır)")
    for s_ in sorted({k_[0] for k_ in ozad}):
        print(f"- {s_}: {ozad[(s_, 'ad')]} ad / {ozad[(s_, 'dogru')]} doğru")
    print("\n## Kalem 3 — belirteç tavanı: en az bir belirteci bulunan fonksiyon")
    hepsi_k = list(KAYNAKLAR) + list(BIRLESIK)
    print("| kesit | fonksiyon | " + " | ".join(hepsi_k) + " |")
    print("|---|---:|" + "---:|" * len(hepsi_k))
    for an in satirlar:
        c = tok[an]
        if c["fn"]:
            print(f"| {an[0]} / {an[1]} | {c['fn']} | " + " | ".join(yuz(c[f'{x}|enaz1'], c['fn']) for x in hepsi_k) + " |")
    print("\n## Kalem 3 — bütün belirteçleri bulunan fonksiyon")
    print("| kesit | fonksiyon | " + " | ".join(hepsi_k) + " |")
    print("|---|---:|" + "---:|" * len(hepsi_k))
    for an in satirlar:
        c = tok[an]
        if c["fn"]:
            print(f"| {an[0]} / {an[1]} | {c['fn']} | " + " | ".join(yuz(c[f'{x}|hepsi'], c['fn']) for x in hepsi_k) + " |")
    print("\n## Kalem 3 — bulunan belirteç / toplam belirteç (mikro)")
    print("| kesit | belirteç | " + " | ".join(hepsi_k) + " |")
    print("|---|---:|" + "---:|" * len(hepsi_k))
    for an in satirlar:
        c = tok[an]
        if c["fn"]:
            print(f"| {an[0]} / {an[1]} | {c['belirtec']} | " + " | ".join(yuz(c[f'{x}|bulunan'], c['belirtec']) for x in hepsi_k) + " |")
    print("\n## Kalem 3 — ilk belirteç (modül öneki) / son belirteç bulunma payı")
    print("| kesit | fonksiyon | ≥ 2 belirteçli | " + " | ".join(f"{x} ilk / son" for x in hepsi_k) + " |")
    print("|---|---:|---:|" + "---|" * len(hepsi_k))
    for an in satirlar:
        c = tok[an]
        if c["fn"]:
            print(f"| {an[0]} / {an[1]} | {c['fn']} | {c['cok_belirtecli']} | " + " | ".join(
                f"%{100 * c[f'{x}|ilk'] / c['fn']:.1f} / %{100 * c[f'{x}|son'] / max(1, c['cok_belirtecli']):.1f}"
                for x in hepsi_k) + " |")
    print("\n## Kalem 4 — rol derinliği (içe aktarım çağrısına en kısa uzaklık)")
    print("| kesit | fonksiyon | her içe aktarım: 0 / 1 / 2 / 3 / yok | ayırt edici: 0 / 1 / 2 / 3 / yok | derinlik 1'de taşıyan ortak sarmalayıcı |")
    print("|---|---:|---|---|---|")
    for an in satirlar:
        c = rol[an]
        if c["fn"]:
            print(f"| {an[0]} / {an[1]} | {c['fn']} | " + " / ".join(yuz(c[f'her|{x}'], c['fn']) for x in (0, 1, 2, 3, 'yok'))
                  + " | " + " / ".join(yuz(c[f'ayirt|{x}'], c['fn']) for x in (0, 1, 2, 3, 'yok'))
                  + f" | {yuz(c['ayirt|1|ortak_sarmalayici'], c['ayirt|1'])} |")
    print("\n## Kalem 5 — modül öneki (GT'nin ilk belirteci) komşularda")
    print("| kesit | önekli fonksiyon | çağrı komşusu var | aynı önekli çağrı komşusu var | çağrı çoğunluğu (kâhin): doğru / karar | adres komşusunda aynı önek | iki adres komşusu uzlaşıyor (kâhin): doğru / karar | bugünkü adlarla çağrı çoğunluğu: doğru / karar | bugünkü adlarla adres komşusu: doğru / karar | "
          + " | ".join(f"sandviç (bugünkü adlar, aralık ≤ {u if u else '∞'})" for u in SANDVIC_UZAKLIKLARI) + " |")
    print("|---|---:|---:|---:|---|---:|---|---|---|" + "---|" * len(SANDVIC_UZAKLIKLARI))
    for an in satirlar:
        c = onek[an]
        if c["fn"]:
            n = c["fn"]
            print(f"| {an[0]} / {an[1]} | {n} | {yuz(c['cagri_komsu_var'], n)} | {yuz(c['cagri_ayni_var'], n)} | "
                  f"{V.wilson(c['cagri_cogunluk_dogru'], c['cagri_cogunluk_karar'])} | "
                  f"{yuz(c['adres_ayni_var'], n)} | {V.wilson(c['adres_iki_yan_uzlasi_dogru'], c['adres_iki_yan_uzlasiyor'])} | "
                  f"{V.wilson(c['bugun_cagri_dogru'], c['bugun_cagri_karar'])} | "
                  f"{V.wilson(c['bugun_adres_dogru'], c['bugun_adres_karar'])} | "
                  + " | ".join(V.wilson(c[f'sandvic_{u}_dogru'], c[f'sandvic_{u}_karar']) for u in SANDVIC_UZAKLIKLARI) + " |")
    (V.ARGE_KOKU / "tavan.json").write_text(json.dumps(
        {"belirtec": {"|".join(a): dict(c) for a, c in tok.items()},
         "rol": {"|".join(a): dict(c) for a, c in rol.items()},
         "onek": {"|".join(a): dict(c) for a, c in onek.items()},
         "oz_ad_sinif": {"|".join(a): v for a, v in ozad.items()}}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
