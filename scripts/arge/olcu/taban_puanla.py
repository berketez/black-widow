#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 4: taban koşusunun (a62f15e) 1 800 adını tam eşitliğin yanında yeniden puanla;
ayrıca etiketsiz ikiz yoğunluğu (Ö6).

Girdi ``taban_dok.py`` çıktısıdır. Hüküm üretmez: hangi adın "amaçça doğru" olduğunu söylemez
(etiket yok); yalnız mekanik ölçülerin dağılımını verir. Ayrık (birbirini dışlayan) bölgeler, sırayla:
  - ``tam``: ürünün bugünkü hükmü (``urun_olc``; klon tabanı dahil);
  - ``bicim``: tam değil ama harf dizisi aynı (``olcu.harf_tam``: büyük/küçük harf, ``_``, derleyici eki,
    ``_N`` çakışma eki). Rubrik sürüm 2'nin ``tam`` tanımının mekanik karşılığı; insan hükmü gerektirmez;
  - ``kimlik_adayi``: ayırt edicilik kapısı (b > r) ve F1s ≥ 0,5 — "yakın" ADAYI (hüküm değil);
  - ``ortusen_diger``: sözlüklü belirteç örtüşmesi var ama kapıdan geçmiyor;
  - ``ayrik``: örtüşme yok; ``gt_yok``: adreste GT fonksiyonu yok.
Karşılaştırma bayrakları (ayrık değil): ``uzlasi_F1`` / ``uzlasi_F1s`` = F1 / F1s ≥ 0,5 (literatürün beklediği
eşik; ölçü olarak ÖNERİLMİYOR). Ayrıca yanlış oranı iki hükümle (tam; tam + biçim), birim başına ve
``urun_olc`` kuralıyla program düzeyi makro (birimde en az ``ks1.N_MIN`` ad; platform birimleri önce ortalanır).
İkiz yoğunluğu: ad bekleyen nüfustaki her fonksiyon f için aynı ikilide g ≠ f var mı ki
F1(GT(f), GT(g)) ≥ t (sözlüksüz) ya da GT(g) belirteçleri GT(f)'nin öz alt kümesi (kırpık ad = başka fonksiyon).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/taban_puanla.py \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_puan.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import kimlik as kimlik_modulu  # noqa: E402
import olcu  # noqa: E402

UZLASI_ESIGI = 0.5            # literatürün beklediği eşik; yalnız karşılaştırma satırı
IKIZ_ESIKLERI = (0.5, 0.8)    # Ö6
BOLGELER = ("tam", "bicim", "kimlik_adayi", "ortusen_diger", "ayrik", "gt_yok")
BAYRAKLAR = ("uzlasi_F1", "uzlasi_F1s")


def bolgeler(k: dict, gt_ikili: kimlik_modulu.IkiliGt) -> dict:
    p = olcu.puanla(k["ad"], k["gt"])
    b = r = 0.0
    if k["gt"]:
        bz = gt_ikili.benzerlikler(k["ad"])
        b = bz[k["adres"]][0]
        r = max((v[0] for adr, v in bz.items() if adr != k["adres"]), default=0.0)
    if k["durum"] == "dogru":
        bolge = "tam"
    elif not k["gt"]:
        bolge = "gt_yok"
    elif olcu.harf_tam(k["ad"], k["gt"]):
        bolge = "bicim"
    elif b > r and b >= UZLASI_ESIGI:
        bolge = "kimlik_adayi"
    elif p["Ps"] > 0:
        bolge = "ortusen_diger"
    else:
        bolge = "ayrik"
    return {"bolge": bolge, "uzlasi_F1": p["F1"] >= UZLASI_ESIGI, "uzlasi_F1s": p["F1s"] >= UZLASI_ESIGI,
            "_p": {o: round(p[o], 3) for o in ("P", "R", "F1", "Ps", "Rs", "F1s")}, "_b": round(b, 3), "_r": round(r, 3)}


def ikiz(gt: dict[str, list[str]], nufus: list[str]) -> Counter:
    """Nüfustaki fonksiyonların ikiz sayımı (sözlüksüz belirteç kümeleri; takma adlar birleşik değil, ayrı)."""
    kumeler = {adr: [frozenset(olcu.belirtecler(a)) for a in adlar] for adr, adlar in gt.items()}
    dizin: dict[str, set[str]] = defaultdict(set)
    for adr, ks in kumeler.items():
        for kume in ks:
            for t in kume:
                dizin[t].add(adr)
    c: Counter = Counter()
    for adr in nufus:
        c["nufus"] += 1
        en, kirpik = 0.0, False
        for sf in kumeler.get(adr, []):
            if not sf:
                continue
            for g in set().union(*(dizin[t] for t in sf)) - {adr}:
                for sg in kumeler[g]:
                    ortak = len(sf & sg)
                    if not ortak or sg == sf:
                        en = max(en, 1.0 if sg == sf else 0.0)
                        continue
                    f1 = 2 * ortak / (len(sf) + len(sg))
                    en = max(en, f1)
                    kirpik = kirpik or sg < sf
        for t in IKIZ_ESIKLERI:
            c[f"ikiz>={t}"] += en >= t
        c["ayni_belirtec_kumesi"] += en == 1.0
        c["kirpigi_baska_fonksiyon"] += kirpik
    return c


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    kanal: dict[str, Counter] = defaultdict(Counter)
    yanlis_kanal: dict[str, Counter] = defaultdict(Counter)
    birim: dict[str, Counter] = defaultdict(Counter)
    birim_ikiz: dict[str, Counter] = defaultdict(Counter)
    yanlislar = []
    for anahtar, ik in sorted(taban.items()):
        gt_ikili = kimlik_modulu.IkiliGt(ik["gt"]) if ik["adlar"] else None
        for k in ik["adlar"]:
            b = bolgeler(k, gt_ikili)
            for hedef in (kanal[k["kanal"]], kanal["TOPLAM"], birim[ik["birim"]]):
                hedef["ad"] += 1
                hedef[b["bolge"]] += 1
                for bayrak in BAYRAKLAR:
                    hedef[bayrak] += b[bayrak]
            if k["durum"] != "dogru":
                for hedef in (yanlis_kanal[k["kanal"]], yanlis_kanal["TOPLAM"]):
                    hedef["yanlis"] += 1
                    hedef[b["bolge"]] += 1
                    for bayrak in BAYRAKLAR:
                        hedef[bayrak] += b[bayrak]
                yanlislar.append({"ikili": anahtar, "adres": k["adres"], "ad": k["ad"], "gt": k["gt"],
                                  "kanal": k["kanal"], "bolge": b["bolge"],
                                  **{x: b[x] for x in BAYRAKLAR}, "puan": b["_p"], "b": b["_b"], "r": b["_r"]})
        iz = ikiz(ik["gt"], ik["nufus_adresleri"])
        birim_ikiz[ik["birim"]].update(iz)
        birim_ikiz["TOPLAM"].update(iz)

    def makro(yanlis_say) -> dict:
        """urun_olc kuralı: birimde en az N_MIN ad; aynı programın platform birimleri önce ortalanır."""
        program: dict[str, list[float]] = defaultdict(list)
        for b_, c in birim.items():
            if c["ad"] >= ks1_olc.N_MIN:
                program[b_.split("/", 1)[1]].append(yanlis_say(c) / c["ad"])
        oranlar = {p_: sum(v) / len(v) for p_, v in sorted(program.items())}
        return {"program": {p_: round(v, 4) for p_, v in oranlar.items()},
                "makro": round(sum(oranlar.values()) / len(oranlar), 4)}

    hukumler = {
        "tam": {"havuz": ks1_olc.oran(kanal["TOPLAM"]["ad"] - kanal["TOPLAM"]["tam"], kanal["TOPLAM"]["ad"]),
                **makro(lambda c: c["ad"] - c["tam"])},
        "tam+bicim": {"havuz": ks1_olc.oran(kanal["TOPLAM"]["ad"] - kanal["TOPLAM"]["tam"] - kanal["TOPLAM"]["bicim"],
                                            kanal["TOPLAM"]["ad"]),
                      **makro(lambda c: c["ad"] - c["tam"] - c["bicim"])}}

    def oranli(c: Counter, payda: str) -> dict:
        return {k: (v if k == payda else {**ks1_olc.oran(v, c[payda])}) for k, v in sorted(c.items())}

    sonuc = {"sema": "karadul-arge-olcu-taban-puan/2", "sozluk_sha256": olcu.SOZLUK_SHA256,
             "kanal": {k: oranli(c, "ad") for k, c in sorted(kanal.items())},
             "yanlislar_kanal": {k: oranli(c, "yanlis") for k, c in sorted(yanlis_kanal.items())},
             "birim": {k: oranli(c, "ad") for k, c in sorted(birim.items())},
             "yanlis_orani": hukumler,
             "ikiz": {k: oranli(c, "nufus") for k, c in sorted(birim_ikiz.items())},
             "yanlislar": yanlislar}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    sutunlar = BOLGELER + BAYRAKLAR
    print("== kanal başına (bütün adlar)")
    for k, c in sorted(kanal.items()):
        print(f"  {k:34s} ad={c['ad']:5d} " + " ".join(f"{b}={c[b]}" for b in sutunlar))
    print("\n== yanlışlar (tam eşitlikte yanlış), kanal başına:")
    for k, c in sorted(yanlis_kanal.items()):
        print(f"  {k:34s} yanlis={c['yanlis']:4d} " + " ".join(f"{b}={c[b]}" for b in sutunlar[1:]))
    print("\n== birim başına:")
    for k, c in sorted(birim.items()):
        print(f"  {k:22s} ad={c['ad']:5d} " + " ".join(f"{b}={c[b]}" for b in BOLGELER))
    print("\n== yanlış oranı (hüküm → havuz, program, makro):")
    for h, v in hukumler.items():
        print(f"  {h:10s} havuz={v['havuz']} makro={v['makro']} program={v['program']}")
    print("\n== ikiz yoğunluğu (nüfus):")
    for k, c in sorted(birim_ikiz.items()):
        print(f"  {k:22s} " + " ".join(f"{x}={v}" for x, v in sorted(c.items())) +
              f" | ikiz>=0.5 {ks1_olc.oran(c['ikiz>=0.5'], c['nufus'])['oran']} "
              f"ikiz>=0.8 {ks1_olc.oran(c['ikiz>=0.8'], c['nufus'])['oran']} "
              f"kırpık {ks1_olc.oran(c['kirpigi_baska_fonksiyon'], c['nufus'])['oran']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
