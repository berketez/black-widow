#!/usr/bin/env python3
"""E3 — kebap kanalının 0 / 239'u "yanlış hedef" miydi?

1.22.1 koşusunda (``urun-yeni2-f30ac9a``) ``string_context/kebap_ad`` kanalının ad verdiği her
(fonksiyon, kanıt dizgisi) için sayılır:
  - fonksiyon o dizgiyle aynı kayıtta / çağrıda mı (V ∪ C adayları, ``ek_kurali.adaylar``);
  - dizgi BAŞKA bir fonksiyonla kayıtlı mı (dizgiyi anan ≠ dizgiyle kaydedilen);
  - dizginin, adı verilen fonksiyonun GT adıyla ve (varsa) kayıtlı fonksiyonun GT adıyla ilişkisi.
Adresler iki koşuda aynıdır (Ghidra zemini bayt düzeyinde aynı; ``sonuc.md`` B6).

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/kebap_hedef.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402
import ek_kurali as E  # noqa: E402

ESKI_KOK = V.EV / "karadul_olcum" / "runs" / "urun-yeni2-f30ac9a"


def eski_koken(d: dict) -> dict:
    yeni = Path(d["kosu"])
    # …/<platform>/<birim>/<ikili>/ws/workspaces/<ad>/<zaman> → eski kökte aynı göreli yol, zaman farklı
    goreli = yeni.relative_to(V.KOSU_KOKU).parts
    taban = ESKI_KOK.joinpath(*goreli[:-1])
    adaylar = sorted(p for p in taban.iterdir() if p.is_dir()) if taban.is_dir() else []
    if len(adaylar) != 1:
        return {}
    yol = adaylar[0] / "reconstructed" / "src" / "naming_provenance.json"
    if not yol.is_file():
        return {}
    return json.loads(yol.read_text(encoding="utf-8")).get("global") or {}


def main() -> int:
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi():
        c = birim[d["birim"]]
        koken = eski_koken(d)
        ad = E.adaylar(d)
        dizgi_fn: dict[str, set[int]] = defaultdict(set)
        for fa, liste in ad.items():
            for _g, s in liste:
                dizgi_fn[V.norm(s)].add(fa)
        for anahtar, r in koken.items():
            if r.get("sub_channel") != "kebap_ad" or r.get("strategy") != "string_context":
                continue
            try:
                fa = int(anahtar.split("_")[-1], 16)
            except ValueError:
                continue
            dizgi = str(r.get("evidence") or "")
            c["kebap_ad"] += 1
            gt = d["gt_adlar"].get(fa)
            kayitli = dizgi_fn.get(V.norm(dizgi), set())
            c["ayni_kayitta"] += fa in kayitli
            c["baska_fonksiyonla_kayitli"] += bool(kayitli - {fa})
            c["hic_kayitli_degil"] += not kayitli
            if gt:
                c[f"anan_iliski_{K.iliski(dizgi, gt)}"] += 1
            en_iyi = 3
            for o in kayitli - {fa}:
                g2 = d["gt_adlar"].get(o)
                if g2:
                    en_iyi = min(en_iyi, K.ILISKILER.index(K.iliski(dizgi, g2)))
            if kayitli - {fa}:
                c[f"kayitli_iliski_{K.ILISKILER[en_iyi]}"] += 1
    top: Counter = Counter()
    for c in birim.values():
        top.update(c)
    print("## Kebap adı (1.22.1) verilen fonksiyon ↔ dizginin kayıtlı olduğu fonksiyon")
    print("| birim | kebap adı | anan = kayıtlı | dizgi başka fonksiyonla kayıtlı | dizgi hiçbir kayıtta yok | anan fonksiyonun GT'siyle ilişki: tam / ekli / örtüşme / ilgisiz | kayıtlı fonksiyonun GT'siyle: tam / ekli / örtüşme / ilgisiz |")
    print("|---|---:|---:|---:|---:|---|---|")
    for b, c in sorted(birim.items()) + [("**toplam**", top)]:
        if not c["kebap_ad"]:
            continue
        print(f"| {b} | {c['kebap_ad']} | {c['ayni_kayitta']} | {c['baska_fonksiyonla_kayitli']} | {c['hic_kayitli_degil']} | "
              + " / ".join(str(c[f"anan_iliski_{i}"]) for i in K.ILISKILER) + " | "
              + " / ".join(str(c[f"kayitli_iliski_{i}"]) for i in K.ILISKILER) + " |")
    (V.ARGE_KOKU / "kebap_hedef.json").write_text(
        json.dumps({b: dict(c) for b, c in birim.items()}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
