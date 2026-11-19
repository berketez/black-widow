#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 2: aday ölçülerin vekil hükümle uyumu (ROC / AUC), ayar ve sınama.

Bölme, hedefler, ön kayıt (Ö1–Ö5): ``docs/arge/2026-11-19_mythos/olcu/DEFTER.md`` §2–§5.
Hükümlerin hepsi vekil (model) hükmüdür; "insan uyumu" değildir.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/roc.py \
        --etiketler ~/karadul_olcum/runs/arge-2026-11-19/olcu/etiketler.jsonl \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/roc.json
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

BURASI = Path(__file__).resolve().parent
REPO = BURASI.parents[2]
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(REPO / "scripts" / "measurement"))

import ks1_olc  # noqa: E402  (yalnız ``oran``: Wilson %95)
import olcu  # noqa: E402

from sabitler import (OLCU_ASIMETRIK_ADAYLAR as ASIMETRIK_ADAYLAR, OLCU_AYAR_KESINLIK as AYAR_KESINLIK,  # noqa: E402
                      OLCU_HEDEFLERI as HEDEFLER, OLCU_O3, OLCU_O4, OLCU_ONYUKLEME as ONYUKLEME,
                      OLCU_SIRALI_ETIKET as SIRALI, OLCU_TOHUM)

O3_NOKTA, O3_ALT, O3_EN_AZ = OLCU_O3["nokta"], OLCU_O3["wilson_alt"], OLCU_O3["en_az_kabul"]
O4_NOKTA, O4_ALT = OLCU_O4["nokta"], OLCU_O4["wilson_alt"]


def auc(puanlar: list[float], hedef: list[bool]) -> float | None:
    """Mann–Whitney AUC (eşitlikler yarım sayılır). Tek sınıf varsa None."""
    poz = [p for p, h in zip(puanlar, hedef) if h]
    neg = [p for p, h in zip(puanlar, hedef) if not h]
    if not poz or not neg:
        return None
    sirali = sorted(neg)
    import bisect
    toplam = 0.0
    for p in poz:
        alt = bisect.bisect_left(sirali, p)
        ust = bisect.bisect_right(sirali, p)
        toplam += alt + 0.5 * (ust - alt)
    return toplam / (len(poz) * len(neg))


def yukle(yol: Path) -> list[dict]:
    satirlar = []
    for s in yol.read_text(encoding="utf-8").splitlines():
        k = json.loads(s)
        if k["yem"]:
            continue
        k["puan"] = olcu.puanla(k["aday"], k["gt"])
        k["esit"] = k["puan"]["norm_tam"] == 1.0 or k["etiket"] == "tam"
        satirlar.append(k)
    return satirlar


def kumeler(satirlar: list[dict]) -> dict[str, list[dict]]:
    l1 = [s for s in satirlar if s["kume"] == "G4-L1-tmux"]
    l1_adres = {s["adres"] for s in l1}
    l3t = [s for s in satirlar if s["kume"] == "G4-L3-tmux"]
    p15 = [s for s in satirlar if s["kume"] == "P15c" and s["tekil_cift"]]
    k = {
        "AYAR (G4-L1-tmux)": l1,
        "A (G4-L3-htop)": [s for s in satirlar if s["kume"] == "G4-L3-htop"],
        "B (P15c tekil)": p15,
        "B' (P15c, tmux'suz)": [s for s in p15 if s["program"] != "tmux"],
        "C (G4-L3-tmux, L1 dışı)": [s for s in l3t if s["adres"] not in l1_adres],
        "EK G4-L2-tmux-gt": [s for s in satirlar if s["kume"] == "G4-L2-tmux-gt"],
        "EK V1-ajan-tmux": [s for s in satirlar if s["kume"] == "V1-ajan-tmux"],
        "EK V1-ajan-htop": [s for s in satirlar if s["kume"] == "V1-ajan-htop"],
    }
    k["SINAMA HAVUZU (A+B+C)"] = k["A (G4-L3-htop)"] + k["B (P15c tekil)"] + k["C (G4-L3-tmux, L1 dışı)"]
    k["SINAMA, tmux'suz (A+B')"] = k["A (G4-L3-htop)"] + k["B' (P15c, tmux'suz)"]
    return k


def auc_tablosu(ks: list[dict], esitler: bool) -> dict:
    alt = ks if esitler else [s for s in ks if not s["esit"]]
    cikti = {"n": len(alt)}
    for hedef, olumlu in HEDEFLER.items():
        h = [s["etiket"] in olumlu for s in alt]
        cikti[hedef] = {"olumlu": sum(h), "olumsuz": len(h) - sum(h),
                        "auc": {o: (None if (a := auc([s["puan"][o] for s in alt], h)) is None else round(a, 4))
                                for o in olcu.SUREKLI_AD_OLCULERI}}
    return cikti


def fark_onyukleme(tabakalar: list[list[dict]], a: str, b: str, hedef: str) -> dict:
    """AUC(a) − AUC(b) için tabakalı eşli önyükleme (%95 yüzdelik aralığı)."""
    olumlu = HEDEFLER[hedef]
    rng = random.Random(OLCU_TOHUM)
    tabakalar = [[s for s in t if not s["esit"]] for t in tabakalar]
    hepsi = [s for t in tabakalar for s in t]
    h = [s["etiket"] in olumlu for s in hepsi]
    nokta = (auc([s["puan"][a] for s in hepsi], h) or 0) - (auc([s["puan"][b] for s in hepsi], h) or 0)
    farklar = []
    for _ in range(ONYUKLEME):
        ornek = [rng.choice(t) for t in tabakalar for _ in t]
        hh = [s["etiket"] in olumlu for s in ornek]
        x, y = auc([s["puan"][a] for s in ornek], hh), auc([s["puan"][b] for s in ornek], hh)
        if x is not None and y is not None:
            farklar.append(x - y)
    farklar.sort()
    alt, ust = farklar[int(0.025 * len(farklar))], farklar[int(0.975 * len(farklar)) - 1]
    hukum = "tuttu" if alt > 0 else "tutmadi" if ust < 0 else "ayirt_edilemedi"
    return {"a": a, "b": b, "hedef": hedef, "n": len(hepsi), "olumlu": sum(h), "fark": round(nokta, 4),
            "aralik": [round(alt, 4), round(ust, 4)], "tekrar": len(farklar), "hukum": hukum}


def esik_sec(ayar: list[dict], o: str) -> dict | None:
    """Ö3: tam eşit olmayanlarda "puan ≥ t" kabulünün ``yakin`` kesinliği ≥ AYAR_KESINLIK olan en düşük t."""
    alt = [s for s in ayar if not s["esit"]]
    en_iyi = None
    for t in sorted({s["puan"][o] for s in alt if s["puan"][o] > 0}):
        kabul = [s for s in alt if s["puan"][o] >= t]
        dogru = sum(1 for s in kabul if s["etiket"] in HEDEFLER["yakin"])
        if kabul and dogru / len(kabul) >= AYAR_KESINLIK:
            en_iyi = {"olcu": o, "esik": round(t, 6), "kabul": len(kabul), "yakin": dogru}
            break
    return en_iyi


def kabul_oku(ks: list[dict], o: str, t: float) -> dict:
    alt = [s for s in ks if not s["esit"]]
    kabul = [s for s in alt if s["puan"][o] >= t]
    toplam_yakin = sum(1 for s in alt if s["etiket"] in HEDEFLER["yakin"])
    return {"n": len(alt), "kabul": len(kabul),
            "yakin": ks1_olc.oran(sum(1 for s in kabul if s["etiket"] in HEDEFLER["yakin"]), len(kabul)),
            "yaniltmaz": ks1_olc.oran(sum(1 for s in kabul if s["etiket"] in HEDEFLER["yaniltmaz"]), len(kabul)),
            "yakalanan_yakin": ks1_olc.oran(sum(1 for s in kabul if s["etiket"] in HEDEFLER["yakin"]), toplam_yakin)}


def sifir_oku(ks: list[dict], o: str) -> dict:
    alt = [s for s in ks if not s["esit"]]
    sifir = [s for s in alt if s["puan"][o] == 0]
    pozitif = [s for s in alt if s["puan"][o] > 0]
    return {"n": len(alt), "sifir": len(sifir),
            "sifirda_yanlis": ks1_olc.oran(sum(1 for s in sifir if s["etiket"] == "yanlis"), len(sifir)),
            "sifirda_yakin": ks1_olc.oran(sum(1 for s in sifir if s["etiket"] in HEDEFLER["yakin"]), len(sifir)),
            "pozitifte_yanlis": ks1_olc.oran(sum(1 for s in pozitif if s["etiket"] == "yanlis"), len(pozitif)),
            "pozitifte_yakin": ks1_olc.oran(sum(1 for s in pozitif if s["etiket"] in HEDEFLER["yakin"]), len(pozitif))}


def tavan(satirlar: list[dict]) -> dict:
    l1 = {s["adres"]: s for s in satirlar if s["kume"] == "G4-L1-tmux"}
    l3 = {s["adres"]: s for s in satirlar if s["kume"] == "G4-L3-tmux"}
    ortak = sorted(set(l1) & set(l3))
    cift = [(l1[a], l3[a]) for a in ortak if not l1[a]["esit"] and not l3[a]["esit"]]
    cikti = {"ortak": len(ortak), "tam_esit_haric": len(cift)}
    for hedef, olumlu in HEDEFLER.items():
        a_ikili = [x["etiket"] in olumlu for x, _ in cift]
        b_ikili = [y["etiket"] in olumlu for _, y in cift]
        uyum = sum(1 for p, q in zip(a_ikili, b_ikili) if p == q) / len(cift)
        pa, pb = sum(a_ikili) / len(cift), sum(b_ikili) / len(cift)
        pe = pa * pb + (1 - pa) * (1 - pb)
        cikti[hedef] = {
            "L1_olumlu": sum(a_ikili), "L3_olumlu": sum(b_ikili), "ham_uyum": round(uyum, 4),
            "kappa": None if pe == 1 else round((uyum - pe) / (1 - pe), 4),
            "auc_L3_etiketi_L1_hedefi": auc([SIRALI[y["etiket"]] for _, y in cift], a_ikili),
            "auc_L1_etiketi_L3_hedefi": auc([SIRALI[x["etiket"]] for x, _ in cift], b_ikili)}
        # aynı ortak öğelerde ölçülerin L1 hedefine karşı AUC'si (tavanla aynı öğeler)
        cikti[hedef]["olcu_auc_L1_hedefi"] = {
            o: (None if (v := auc([x["puan"][o] for x, _ in cift], a_ikili)) is None else round(v, 4))
            for o in olcu.SUREKLI_AD_OLCULERI}
    for k in ("auc_L3_etiketi_L1_hedefi", "auc_L1_etiketi_L3_hedefi"):
        for hedef in HEDEFLER:
            v = cikti[hedef][k]
            cikti[hedef][k] = None if v is None else round(v, 4)
    return cikti


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--etiketler", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    satirlar = yukle(a.etiketler)
    k = kumeler(satirlar)
    sonuc: dict = {"sema": "karadul-arge-olcu-roc/1", "sozluk_sha256": olcu.SOZLUK_SHA256, "tohum": OLCU_TOHUM,
                   "onyukleme": ONYUKLEME, "auc_tam_esit_haric": {}, "auc_tam_esit_dahil": {}, "tam_esit_olmayanda": {}}
    for ad, ks in k.items():
        sonuc["auc_tam_esit_haric"][ad] = auc_tablosu(ks, esitler=False)
        sonuc["auc_tam_esit_dahil"][ad] = auc_tablosu(ks, esitler=True)
        alt = [s for s in ks if not s["esit"]]          # Ö5
        sonuc["tam_esit_olmayanda"][ad] = {
            "n": len(alt), "tam_esit": len(ks) - len(alt),
            "yakin": ks1_olc.oran(sum(1 for s in alt if s["etiket"] in HEDEFLER["yakin"]), len(alt)),
            "yaniltmaz": ks1_olc.oran(sum(1 for s in alt if s["etiket"] in HEDEFLER["yaniltmaz"]), len(alt))}
    tabakalar = [k["A (G4-L3-htop)"], k["B (P15c tekil)"], k["C (G4-L3-tmux, L1 dışı)"]]
    sonuc["O1_O2"] = [fark_onyukleme(tabakalar, x, y, h)
                      for h in HEDEFLER for x, y in (("P", "F1"), ("Ps", "F1s"), ("Pz", "F1z"), ("as0", "F1z"))]
    sonuc["O1_O2_ayar"] = [fark_onyukleme([k["AYAR (G4-L1-tmux)"]], x, y, h)
                           for h in HEDEFLER for x, y in (("P", "F1"), ("Ps", "F1s"), ("Pz", "F1z"), ("as0", "F1z"))]
    # Ö3
    ayar = k["AYAR (G4-L1-tmux)"]
    esikler = [e for o in olcu.SUREKLI_AD_OLCULERI if (e := esik_sec(ayar, o))]
    esikler.sort(key=lambda e: (-e["yakin"], e["kabul"], olcu.SUREKLI_AD_OLCULERI.index(e["olcu"])))
    sonuc["O3_esikler_ayar"] = esikler
    if esikler:
        sec = esikler[0]
        okuma = {ad: kabul_oku(ks, sec["olcu"], sec["esik"]) for ad, ks in k.items()}
        hv = okuma["SINAMA HAVUZU (A+B+C)"]
        if hv["kabul"] < O3_EN_AZ:
            hukum = "olculemedi"
        else:
            hukum = "tuttu" if hv["yakin"]["oran"] >= O3_NOKTA and hv["yakin"]["aralik"][0] >= O3_ALT else "tutmadi"
        sonuc["O3"] = {"secilen": sec, "okuma": okuma, "hukum": hukum}
        sonuc["O3_butun_olculer_sinama"] = {
            e["olcu"]: {"esik": e["esik"], **kabul_oku(k["SINAMA HAVUZU (A+B+C)"], e["olcu"], e["esik"])}
            for e in esikler}
    # Ö4
    ay = sonuc["auc_tam_esit_haric"]["AYAR (G4-L1-tmux)"]["yaniltmaz"]["auc"]
    asim = max(ASIMETRIK_ADAYLAR, key=lambda o: (ay[o], -ASIMETRIK_ADAYLAR.index(o)))
    okuma4 = {ad: sifir_oku(ks, asim) for ad, ks in k.items()}
    hv4 = okuma4["SINAMA HAVUZU (A+B+C)"]["sifirda_yanlis"]
    sonuc["O4"] = {"secilen_asimetrik": asim, "okuma": okuma4,
                   "hukum": "tuttu" if hv4["oran"] is not None and hv4["oran"] >= O4_NOKTA
                   and hv4["aralik"][0] >= O4_ALT else "tutmadi",
                   "butun_adaylar_sinama": {o: sifir_oku(k["SINAMA HAVUZU (A+B+C)"], o) for o in ASIMETRIK_ADAYLAR + ("F1", "F1s")}}
    sonuc["tavan"] = tavan(satirlar)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    # ---- özet (stdout) ----
    for baslik in ("auc_tam_esit_haric",):
        for hedef in HEDEFLER:
            print(f"\n== AUC, {baslik}, hedef={hedef}")
            print("kume".ljust(28), "n".rjust(4), "+".rjust(4), *(o.rjust(6) for o in olcu.SUREKLI_AD_OLCULERI))
            for ad, t in sonuc[baslik].items():
                print(ad.ljust(28)[:28], str(t["n"]).rjust(4), str(t[hedef]["olumlu"]).rjust(4),
                      *(("  -   " if v is None else f"{v:.3f}").rjust(6) for v in t[hedef]["auc"].values()))
    print("\n== Ö1/Ö2 sınama havuzu:")
    for f in sonuc["O1_O2"]:
        print(" ", f)
    print("== Ö1/Ö2 ayar:")
    for f in sonuc["O1_O2_ayar"]:
        print(" ", f)
    print("\n== Ö3 eşikler (ayar):")
    for e in esikler:
        print(" ", e)
    if esikler:
        print("  seçilen:", sonuc["O3"]["secilen"], "hüküm:", sonuc["O3"]["hukum"])
        for ad, o in sonuc["O3"]["okuma"].items():
            print("  ", ad.ljust(28)[:28], o)
        print("  bütün ölçüler, sınama havuzu:")
        for o, v in sonuc["O3_butun_olculer_sinama"].items():
            print("   ", o, v)
    print("\n== Ö4 seçilen asimetrik:", asim, "hüküm:", sonuc["O4"]["hukum"])
    for ad, o in okuma4.items():
        print("  ", ad.ljust(28)[:28], o)
    for o, v in sonuc["O4"]["butun_adaylar_sinama"].items():
        print("   sınama", o, v)
    print("\n== Ö5 tam eşit olmayanda yakın / yanıltmaz:")
    for ad, o in sonuc["tam_esit_olmayanda"].items():
        print("  ", ad.ljust(28)[:28], o)
    print("\n== Tavan (L1 ∩ L3):", json.dumps(sonuc["tavan"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
