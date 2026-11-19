#!/usr/bin/env python3
"""ÖLÇÜ hattı: göreli (ayırt edicilik) ölçüsü — ad, fonksiyonu aynı ikilideki kardeşlerinden ayırıyor mu?

Tanım ve ön kayıt (Ö8a–c): ``docs/arge/2026-11-19_mythos/olcu/DEFTER.md`` §7.
  b = F1s(aday, GT(f));  r = max_{g ≠ f} F1s(aday, GT(g))  (g: aynı ikilinin bütün GT fonksiyonları)
  ayirt = b − r;  kimlik = b eğer b > r, yoksa 0;  kimlik_R = Rs(aday, GT(f)) eğer b > r, yoksa 0.
GT ad listeleri ``taban_dok.py`` çıktısından (geliştirme seti) gelir.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/kimlik.py \
        --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/kimlik.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import olcu  # noqa: E402
import roc  # noqa: E402
from sabitler import OLCU_AYAR_KESINLIK, OLCU_HEDEFLERI, OLCU_O3  # noqa: E402

KIMLIK_OLCULERI = ("F1s", "Rs", "ayirt", "kimlik", "kimlik_R")
KIMLIK_ESIKLERI = (0.34, 0.5, 0.67, 0.8)


class IkiliGt:
    """Bir ikilinin GT adları üstünde hızlı sözlüklü P/R/F1 (belirteç dağarcığı düzeyinde önbellek)."""

    def __init__(self, gt: dict[str, list[str]]):
        self.adlar = {adres: [frozenset(olcu.belirtecler(a)) for a in adlari] for adres, adlari in gt.items()}
        self.dagarcik = sorted({t for ks in self.adlar.values() for k in ks for t in k})

    def benzerlikler(self, aday: str) -> dict[str, tuple[float, float]]:
        """adres → (F1s, Rs) (takma adlar üstünde en yüksek F1s; Rs o adın duyarlılığı)."""
        sa = frozenset(olcu.belirtecler(aday))
        if not sa:
            return {a: (0.0, 0.0) for a in self.adlar}
        es = {a: frozenset(g for g in self.dagarcik if olcu.eslesir(a, g)) for a in sa}
        hepsi = frozenset().union(*es.values())
        cikti = {}
        for adres, kumeler in self.adlar.items():
            en = (0.0, 0.0)
            for sg in kumeler:
                if not sg or not (sg & hepsi):
                    continue
                p = sum(1 for a in sa if es[a] & sg) / len(sa)
                r = len(sg & hepsi) / len(sg)
                f = 2 * p * r / (p + r) if p + r else 0.0
                if f > en[0]:
                    en = (f, r)
            cikti[adres] = en
        return cikti


def ikili_anahtari(s: dict) -> str:
    parcalar = s["birim"].split("/")
    if len(parcalar) == 3:
        return f"{parcalar[0]}/{parcalar[1]}::{parcalar[2]}"
    return f"{s['birim']}::{parcalar[-1]}"


def adres_anahtari(adres: str) -> str:
    return f"{int(adres, 16):x}"


def kabul(ks: list[dict], o: str, t: float) -> dict:
    alt = [s for s in ks if not s["esit"]]
    kb = [s for s in alt if s["puan"][o] >= t]
    ty = sum(1 for s in alt if s["etiket"] in OLCU_HEDEFLERI["yakin"])
    y = sum(1 for s in kb if s["etiket"] in OLCU_HEDEFLERI["yakin"])
    return {"kabul": len(kb), "yakin": ks1_olc.oran(y, len(kb)),
            "yanlis": ks1_olc.oran(sum(1 for s in kb if s["etiket"] == "yanlis"), len(kb)),
            "yakalanan_yakin": ks1_olc.oran(y, ty)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--etiketler", type=Path, required=True)
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    gtler: dict[str, IkiliGt] = {}
    satirlar = roc.yukle(a.etiketler)
    onkosul = {"gt_listesi_yok": 0, "adres_yok": 0, "gt_adi_uyusmuyor": 0, "hesaplanan": 0}
    hesaplanan = []
    for s in satirlar:
        anahtar = ikili_anahtari(s)
        if anahtar not in taban:
            onkosul["gt_listesi_yok"] += 1
            continue
        adres = adres_anahtari(s["adres"])
        gt_listesi = taban[anahtar]["gt"]
        if adres not in gt_listesi:
            onkosul["adres_yok"] += 1
            continue
        if not ({g.lstrip("_") for g in s["gt"]} & {g.lstrip("_") for g in gt_listesi[adres]}):
            onkosul["gt_adi_uyusmuyor"] += 1
            continue
        if anahtar not in gtler:
            gtler[anahtar] = IkiliGt(gt_listesi)
        bz = gtler[anahtar].benzerlikler(s["aday"])
        b, rs = bz[adres]
        r = max((v[0] for adr, v in bz.items() if adr != adres), default=0.0)
        s["puan"].update({"ayirt": b - r, "kimlik": b if b > r else 0.0, "kimlik_R": rs if b > r else 0.0,
                          "_b": b, "_r": r})
        onkosul["hesaplanan"] += 1
        hesaplanan.append(s)
    k = roc.kumeler(hesaplanan)
    sonuc: dict = {"sema": "karadul-arge-olcu-kimlik/1", "onkosul": onkosul, "auc": {}, "kabul": {}, "kapi": {}}
    for ad, ks in k.items():
        alt = [s for s in ks if not s["esit"]]
        sonuc["auc"][ad] = {"n": len(alt)}
        for hedef, olumlu in OLCU_HEDEFLERI.items():
            h = [s["etiket"] in olumlu for s in alt]
            sonuc["auc"][ad][hedef] = {"olumlu": sum(h), **{
                o: (None if (v := roc.auc([s["puan"][o] for s in alt], h)) is None else round(v, 4))
                for o in KIMLIK_OLCULERI}}
        sonuc["kabul"][ad] = {o: {str(t): kabul(ks, o, t) for t in KIMLIK_ESIKLERI} for o in ("F1s", "kimlik", "kimlik_R")}
        # kapının tek başına etkisi: örtüşen (b > 0) çiftlerde b > r olan / olmayan → etiket dağılımı
        ort = [s for s in alt if s["puan"]["_b"] > 0]
        gecen = [s for s in ort if s["puan"]["_b"] > s["puan"]["_r"]]
        kalan = [s for s in ort if s["puan"]["_b"] <= s["puan"]["_r"]]
        sonuc["kapi"][ad] = {
            "ortusen": len(ort),
            "gecen": {"n": len(gecen),
                      "yakin": ks1_olc.oran(sum(1 for s in gecen if s["etiket"] in OLCU_HEDEFLERI["yakin"]), len(gecen)),
                      "yanlis": ks1_olc.oran(sum(1 for s in gecen if s["etiket"] == "yanlis"), len(gecen))},
            "kalan": {"n": len(kalan),
                      "yakin": ks1_olc.oran(sum(1 for s in kalan if s["etiket"] in OLCU_HEDEFLERI["yakin"]), len(kalan)),
                      "yanlis": ks1_olc.oran(sum(1 for s in kalan if s["etiket"] == "yanlis"), len(kalan))}}
    tabakalar = [k["A (G4-L3-htop)"], k["B (P15c tekil)"], k["C (G4-L3-tmux, L1 dışı)"]]
    sonuc["O8a"] = [roc.fark_onyukleme(tabakalar, x, "F1s", h) for h in OLCU_HEDEFLERI for x in ("kimlik", "ayirt", "kimlik_R")]
    sonuc["O8a_ayar"] = [roc.fark_onyukleme([k["AYAR (G4-L1-tmux)"]], x, "F1s", h)
                         for h in OLCU_HEDEFLERI for x in ("kimlik", "ayirt", "kimlik_R")]
    # Ö8c: ayar kümesinde 0,90 kesinlik veren eşik
    sonuc["O8c"] = {}
    for o in ("kimlik", "kimlik_R", "ayirt"):
        alt = [s for s in k["AYAR (G4-L1-tmux)"] if not s["esit"]]
        sec = None
        for t in sorted({s["puan"][o] for s in alt if s["puan"][o] > 0}):
            kb = [s for s in alt if s["puan"][o] >= t]
            y = sum(1 for s in kb if s["etiket"] in OLCU_HEDEFLERI["yakin"])
            if y / len(kb) >= OLCU_AYAR_KESINLIK:
                sec = {"esik": round(t, 6), "kabul": len(kb), "yakin": y}
                break
        en_iyi = max(((sum(1 for s in alt if s["puan"][o] >= t and s["etiket"] in OLCU_HEDEFLERI["yakin"])
                       / sum(1 for s in alt if s["puan"][o] >= t), t,
                       sum(1 for s in alt if s["puan"][o] >= t))
                      for t in sorted({s["puan"][o] for s in alt if s["puan"][o] > 0})), default=None)
        sonuc["O8c"][o] = {"esik": sec, "en_yuksek_kesinlik": None if en_iyi is None else
                           {"kesinlik": round(en_iyi[0], 4), "esik": round(en_iyi[1], 4), "kabul": en_iyi[2]}}
        if sec:
            hv = kabul(k["SINAMA HAVUZU (A+B+C)"], o, sec["esik"])
            sonuc["O8c"][o]["sinama"] = hv
            sonuc["O8c"][o]["hukum"] = ("olculemedi" if hv["kabul"] < OLCU_O3["en_az_kabul"] else
                                        "tuttu" if hv["yakin"]["oran"] >= OLCU_O3["nokta"]
                                        and hv["yakin"]["aralik"][0] >= OLCU_O3["wilson_alt"] else "tutmadi")
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    print("önkoşul:", onkosul)
    for hedef in OLCU_HEDEFLERI:
        print(f"\n== AUC (tam eşit hariç), hedef={hedef}")
        print("kume".ljust(28), "n".rjust(4), "+".rjust(4), *(o.rjust(9) for o in KIMLIK_OLCULERI))
        for ad, t in sonuc["auc"].items():
            print(ad.ljust(28)[:28], str(t["n"]).rjust(4), str(t[hedef]["olumlu"]).rjust(4),
                  *(("-" if t[hedef][o] is None else f"{t[hedef][o]:.3f}").rjust(9) for o in KIMLIK_OLCULERI))
    print("\n== Ö8a sınama:")
    for f in sonuc["O8a"]:
        print(" ", f)
    print("== Ö8a ayar:")
    for f in sonuc["O8a_ayar"]:
        print(" ", f)
    print("\n== kabul tabloları")
    for ad in ("AYAR (G4-L1-tmux)", "A (G4-L3-htop)", "B (P15c tekil)", "C (G4-L3-tmux, L1 dışı)",
               "SINAMA HAVUZU (A+B+C)", "SINAMA, tmux'suz (A+B')"):
        print(" #", ad, "| kapı:", sonuc["kapi"][ad])
        for o, es in sonuc["kabul"][ad].items():
            for t, d in es.items():
                y, w, c = d["yakin"], d["yanlis"], d["yakalanan_yakin"]
                print(f"    {o:9s} >= {t:4s} kabul={d['kabul']:3d} yakin={y['k']}/{y['n']} {y['aralik']} "
                      f"yanlis={w['k']}/{w['n']} yakalanan={c['k']}/{c['n']}")
    print("\n== Ö8c:", json.dumps(sonuc["O8c"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
