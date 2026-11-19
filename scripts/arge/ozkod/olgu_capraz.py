#!/usr/bin/env python3
"""ÖZ KOD ↔ OLGU çapraz denetimi (tam set): iki bağımsız çıkarım aynı sayıyı veriyor mu?

Karşılaştırılanlar (nüfus fonksiyonları; ``redis-check-rdb`` bu hatta tekrar sayılmadığı için
OLGU'dan da çıkarılır):
  1. nüfus büyüklüğü;
  2. pencere (± 4 sözcük) kayıt çifti: OLGU ``veri_yerleri[].d`` boş değil  ↔  bu hattın ``P`` tanımı;
  3. doğrudan dizgisi olan fonksiyon: OLGU ``dizgiler`` ↔ bu hattın ``fn_dizgi``;
  4. belirteç tavanı D0 (en az bir GT belirteci doğrudan dizgilerde): iki dizgi kümesiyle ayrı ayrı;
  5. çağrı yeri çifti: OLGU ``cagri_ciftleri`` (destekleniyorsa) ↔ bu hattın ``C`` tanımı.
Fark varsa fonksiyon düzeyinde simetrik fark sayısı da basılır.

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/olgu_capraz.py
"""
from __future__ import annotations

import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozkod_veri as V  # noqa: E402
import kayit_cifti as K  # noqa: E402

OLGU = V.EV / "karadul_olcum" / "runs" / "arge-2026-11-19" / "olgu" / "olgu.jsonl.gz"
KUNYE = OLGU.with_name("olgu_kunye.json")


def bel(metinler) -> set[str]:
    out: set[str] = set()
    for m in metinler:
        out.update(b for b in V.belirtecler(m) if len(b) >= 2 and not b.isdigit())
    return out


def main() -> int:
    kunye = json.loads(KUNYE.read_text(encoding="utf-8"))
    print(f"OLGU künyesi: asama = {kunye.get('asama')}, satır = {kunye.get('satir')}, "
          f"tablo sha256 = {str(kunye.get('tablo_sha256'))[:16]}…")
    olgu: dict[tuple[str, str, int], dict] = {}
    with gzip.open(OLGU, "rt", encoding="utf-8") as f:
        for satir in f:
            r = json.loads(satir)
            if r["nufusta"] and (r["birim"], r["ikili"]) not in V.AYNI_DOSYA_ATLA:
                olgu[(r["birim"], r["ikili"], r["adres"])] = r
    k = V.ks1()
    c: dict[str, Counter] = defaultdict(Counter)
    cagri_destek = Counter()
    for d in V.hepsi():
        b = c[d["birim"]]
        ciftler = K.ikili_ciftleri(d)
        for fa in d["nufus"]:
            b["nufus_ozkod"] += 1
            r = olgu.get((d["birim"], d["ad"], fa))
            if r is None:
                b["olguda_yok"] += 1
                continue
            b["nufus_olgu"] += 1
            # 2. pencere çifti
            o_p = any(v.get("d") for v in (r.get("veri_yerleri") or []) if isinstance(v, dict))
            m_p = bool(ciftler.get(fa, {}).get("P"))
            b["P_olgu"] += o_p
            b["P_ozkod"] += m_p
            b["P_fark"] += o_p != m_p
            # 3. doğrudan dizgi
            o_d = [x["m"] for x in (r.get("dizgiler") or []) if isinstance(x, dict) and x.get("m")]
            m_d = [d["dizgi_metin"][s] for s in d["fn_dizgi"].get(fa, [])]
            m_d = [s for s in m_d if s]
            b["D_olgu"] += bool(o_d)
            b["D_ozkod"] += bool(m_d)
            b["D_fark"] += bool(o_d) != bool(m_d)
            # 4. D0 tavanı
            gt = d["gt_adlar"][fa]
            T = set(V.ad_belirtecleri(k.klon_tabani(gt[0]) or gt[0]))
            if T:
                b["T_fn"] += 1
                # OLGU uzun dizgiyi kırpabilir ('k': True); kırpılmış dizgi belirteç kaybettirebilir
                b["T_olgu"] += bool(T & bel(o_d))
                b["T_ozkod"] += bool(T & bel(m_d))
            # 5. çağrı çifti
            oc = r.get("cagri_ciftleri")
            if isinstance(oc, str):
                cagri_destek[oc] += 1
            else:
                cagri_destek["liste"] += 1
                b["C_olgu"] += bool(oc)
            b["C_ozkod"] += bool(ciftler.get(fa, {}).get("C"))
    b_fazla = len(olgu) - sum(x["nufus_olgu"] for x in c.values())
    top: Counter = Counter()
    for x in c.values():
        top.update(x)
    print("\n| birim | nüfus (bu hat / OLGU'da bulunan) | pencere çifti: OLGU / bu hat / farklı fonksiyon | doğrudan dizgili: OLGU / bu hat / farklı | D0 en az 1 belirteç: OLGU / bu hat (payda) | çağrı çifti: OLGU / bu hat |")
    print("|---|---|---|---|---|---|")
    for ad, x in sorted(c.items()) + [("**toplam**", top)]:
        print(f"| {ad} | {x['nufus_ozkod']} / {x['nufus_olgu']} | {x['P_olgu']} / {x['P_ozkod']} / {x['P_fark']} "
              f"| {x['D_olgu']} / {x['D_ozkod']} / {x['D_fark']} | {x['T_olgu']} / {x['T_ozkod']} ({x['T_fn']}) "
              f"| {x['C_olgu'] if cagri_destek.get('liste') else '—'} / {x['C_ozkod']} |")
    print(f"\nOLGU'da olup bu hatta olmayan nüfus satırı: {b_fazla}; OLGU `cagri_ciftleri` alanı: {dict(cagri_destek)}")
    (V.ARGE_KOKU / "olgu_capraz.json").write_text(json.dumps(
        {"kunye_asama": kunye.get("asama"), "tablo_sha256": kunye.get("tablo_sha256"),
         "birim": {a: dict(x) for a, x in c.items()}, "cagri_alani": dict(cagri_destek)}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
