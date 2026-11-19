#!/usr/bin/env python3
"""G1 "tekil tanımlayıcı dizgi → ad (harfleri korunarak)": R1'in süzgeç değil üretici hâli.

Kural G1 (keşifte okunan R1 özelliklerinden; sayım ``--taraf`` başına):
  Fonksiyon f'nin andığı dizgiler içinde ALT ÇİZGİLİ, en az bir küçük harfli, tek bir C
  tanımlayıcısı olan dizgiler (``TANIM``). Tam olarak bir tane farklı S varsa, S'i ikilide yalnız f
  anıyorsa (``n_fn`` = 1) ve S bir kayıt çiftinde (V ∪ C) başka fonksiyonla eşli değilse:
      ad(f) = S   (hiç dönüştürmeden).
  Aynı S iki fonksiyona ad olamaz (n_fn = 1 bunu sağlar).
Hüküm: ``ks1_olc.capa_degerlendir`` (ürün ölçüsü: tam eşitlik; klon GT'de taban eşitliği).

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/oz_ad_uretici.py --taraf kesif
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import ek_kurali as E  # noqa: E402

TANIM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def tanim_mi(s: str) -> bool:
    return bool(TANIM.match(s)) and "_" in s.strip("_") and any(c.islower() for c in s) and len(s) >= 4


def g1(d: dict) -> dict[int, str]:
    """fonksiyon adresi → G1 adı."""
    deger_fn: dict[str, set[int]] = defaultdict(set)
    for sa, fnler in d["dizgi_fn"].items():
        deger_fn[d["dizgi_metin"][sa]].update(fnler)
    kayitli: dict[str, set[int]] = defaultdict(set)
    for fa, liste in E.adaylar(d).items():
        for _g, s in liste:
            kayitli[s].add(fa)
    out = {}
    for fa, adresler in d["fn_dizgi"].items():
        f = d["fonk"].get(fa)
        if f is None or f["thunk"] or f["dis"]:
            continue
        tanimlar = {d["dizgi_metin"][a] for a in adresler if tanim_mi(d["dizgi_metin"][a])}
        if len(tanimlar) != 1:
            continue
        s = next(iter(tanimlar))
        if len(deger_fn[s]) != 1 or (kayitli.get(s, set()) - {fa}):
            continue
        out[fa] = s
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taraf", choices=("kesif", "sinama"), required=True)
    a = ap.parse_args()
    k = V.ks1()
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=a.taraf):
        c = birim[d["birim"]]
        c["nufus"] += len(d["nufus"])
        for fa, s in g1(d).items():
            if fa not in d["nufus"]:
                c["nufus_disi_ad"] += 1
                continue
            gt = d["gt_adlar"][fa]
            dogru = k.capa_degerlendir(s, gt, k.PLATFORM_DEBIAN)["durum"] == "dogru"
            bugun = d["urun"].get(fa)
            durum = "adsiz" if bugun is None else ("dogru" if bugun["durum"] == "dogru" else "yanlis")
            c["ad"] += 1
            c["dogru"] += dogru
            c[f"bugun_{durum}"] += 1
            c[f"dogru_bugun_{durum}"] += dogru
            if bugun is not None:
                c[f"bugun_kanal_{bugun['kanal']}"] += 1
    top: Counter = Counter()
    for c in birim.values():
        top.update(c)
    print(f"## G1 — taraf: {a.taraf}")
    print("| birim | nüfus | ad (nüfusta) | doğru (Wilson) | G1 doğru: bugün adsız / bugün yanlış / bugün doğru | G1 yanlış: bugün adsız / yanlış / doğru |")
    print("|---|---:|---:|---|---|---|")
    for b, c in sorted(birim.items()) + [("**toplam**", top)]:
        print(f"| {b} | {c['nufus']} | {c['ad']} | {V.wilson(c['dogru'], c['ad'])} | "
              f"{c['dogru_bugun_adsiz']} / {c['dogru_bugun_yanlis']} / {c['dogru_bugun_dogru']} | "
              f"{c['bugun_adsiz'] - c['dogru_bugun_adsiz']} / {c['bugun_yanlis'] - c['dogru_bugun_yanlis']} / "
              f"{c['bugun_dogru'] - c['dogru_bugun_dogru']} |")
    print("\nG1'in ad verdiği fonksiyonların bugünkü kanalı: "
          + ", ".join(f"{k_[len('bugun_kanal_'):]} {v}" for k_, v in sorted(top.items()) if k_.startswith("bugun_kanal_")))
    (V.ARGE_KOKU / f"oz_ad_uretici_{a.taraf}.json").write_text(
        json.dumps({b: dict(c) for b, c in birim.items()}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
