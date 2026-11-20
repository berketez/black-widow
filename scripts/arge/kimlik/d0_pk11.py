#!/usr/bin/env python
"""KİMLİK Dalga 0 — PK-11: gömülü kitaplık kopyası (zstd ``lib/`` ↔ libzstd), tek yön, ön kayıtlı (a)–(c).

Sorgu Q = ``debian/zstd/zstd`` (geliştirme seti), başvuru R = ``kitaplik/libzstd`` (Debian 13 arm64
``libzstd.so.1.5.7``; adları GT'den). Kaynak sınıfı OLGU tablosundan (``olgu_capraz.olgu_oku``). Dört nokta
(``esle.NOKTALAR``), birincil ``kural``. Ek satırlar: ``hata_dok`` sınıflaması (yalnız Q → R yönü),
``tanik`` alt kanalı (``tanik.taniklar``, ``kmax`` süzgeci kapalı), ürünün ``BinaryDiffer`` / ``ReferenceDiffer``
yolu (``urun_bindiff``; iki yönü de koşar, Q → R satırı okunur).

Kullanım (worktree kökünden): ``PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/d0_pk11.py``
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any

_BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(_BURASI))
import d0_veri  # noqa: E402

d0_veri.kur()
import d0_olc  # noqa: E402
import esle  # noqa: E402
import hata_dok  # noqa: E402
import olgu_capraz  # noqa: E402
import tanik  # noqa: E402
import urun_bindiff  # noqa: E402
import veri  # noqa: E402
from veri import ks1  # noqa: E402

import kimlik_ciftler as kc  # noqa: E402

GRUP = "gomulu_kitaplik"
SINIF_KITAPLIK = "proje_kitapligi"
SINIF_PROGRAM = "program"
OLGU_NUFUS_KITAPLIK = 720          # PLAN PK-11 / OLGU BUTCE: zstd'nin proje_kitapligi nüfusu (karşılaştırma için)
KAPSAM_ESIGI = 0.40                # (b)
CEKIMSERLIK_ESIGI = 0.02           # (c)
KMAX_KAPALI = 10 ** 9              # tanık seyreklik süzgeci kapalı (tur 1 dondurulmuş sınaması)
CIKTI = d0_olc.OLCUM_DIZINI


def main() -> int:
    (qk, rk), = kc.grup(GRUP)
    Q, R = veri.yukle(qk), veri.yukle(rk)
    olgu = olgu_capraz.olgu_oku()
    sinif = {a: olgu.get(olgu_capraz.olgu_anahtari(qk, a), "olguda_yok") for a in Q.nufus}
    r_adlar = {n for f in R.fonk.values() for n in f.gt}
    r_ad: dict[str, list[int]] = {}
    for adr, f in R.fonk.items():
        for n in f.gt:
            r_ad.setdefault(n, []).append(adr)
    q_ad = {n for f in Q.fonk.values() for n in f.gt}
    sonuc: dict[str, Any] = {"sorgu": qk, "basvuru": rk, "kunye_Q": Q.kunye, "kunye_R": R.kunye,
                             "olgu_nufus_kitaplik_beklenen": OLGU_NUFUS_KITAPLIK, "noktalar": {}}
    satir_md = []
    for nokta, p in esle.NOKTALAR.items():
        s = esle.esle(Q, R, p)
        tan = tanik.taniklar(Q, R, s, KMAX_KAPALI)
        say: dict[str, dict[str, Any]] = {}
        dogru_ad_programda: list[list[str]] = []
        for a in Q.nufus:
            k = say.setdefault(sinif[a], {"nufus": 0, "tavan": 0, "dogru": 0, "yanlis": 0, "adsiz": 0,
                                         "tanikli": {"dogru": 0, "yanlis": 0}, "hata": {}})
            k["nufus"] += 1
            if set(Q.fonk[a].gt) & r_adlar:
                k["tavan"] += 1
            e = s.esler.get(a)
            if e is None:
                continue
            h = esle.hukum(Q, R, a, e.r)
            if h in ("dogru", "yanlis"):
                k[h] += 1
                if a in tan:
                    k["tanikli"][h] += 1
                if h == "yanlis":
                    hs = tanik._sinif(Q, R, a, e.r, r_ad, q_ad)
                    k["hata"][hs] = k["hata"].get(hs, 0) + 1
                if h == "dogru" and sinif[a] == SINIF_PROGRAM:
                    dogru_ad_programda.append(list(Q.fonk[a].gt))
            elif h == "adsiz":
                k["adsiz"] += 1
        for k in say.values():
            k["kesinlik"] = ks1.oran(k["dogru"], k["dogru"] + k["yanlis"])
            k["alt"] = d0_olc._alt(k["kesinlik"])
            k["kapsam"] = ks1.oran(k["dogru"], k["nufus"])
            k["tanikli_kesinlik"] = ks1.oran(k["tanikli"]["dogru"], sum(k["tanikli"].values()))
        kit = say.get(SINIF_KITAPLIK, {"nufus": 0, "dogru": 0, "yanlis": 0, "alt": None})
        prg = say.get(SINIF_PROGRAM, {"nufus": 0, "dogru": 0, "yanlis": 0})
        a_h = d0_olc.sinif_a(kit.get("alt"))
        a_h = {"hat hedefi tuttu": "kitaplık kopyası bu yolla ad alır (hat hedefi)",
               "ad yazabilir (A-2)": "ad yazabilir"}.get(a_h, a_h)
        kapsam = kit["dogru"] / kit["nufus"] if kit["nufus"] else None
        b_h = ("veri yok" if kapsam is None else
               "A2'nin kitaplık kolu için kullanılabilir" if kapsam >= KAPSAM_ESIGI else "kullanılamaz (< %40)")
        verilen = prg["dogru"] + prg["yanlis"]
        c_oran = verilen / prg["nufus"] if prg["nufus"] else None
        c_h = ("veri yok" if c_oran is None else
               "başvuruda olmayan koda ad yakıştırmıyor" if c_oran <= CEKIMSERLIK_ESIGI else "tutmadı (> %2)")
        sonuc["noktalar"][nokta] = {"sinif": say, "tur": s.tur_sayisi,
                                    "a": {"alt": kit.get("alt"), "hukum": a_h},
                                    "b": {"kapsam": kapsam, "dogru": kit["dogru"], "nufus": kit["nufus"], "hukum": b_h},
                                    "c": {"verilen": verilen, "dogru": prg["dogru"], "yanlis": prg["yanlis"],
                                          "nufus": prg["nufus"], "oran": c_oran, "hukum": c_h,
                                          "dogru_cikan_ad_ornekleri": dogru_ad_programda[:10]}}
        kk = kit.get("kesinlik") or {}
        ar = kk.get("aralik")
        satir_md.append(
            f"| {nokta} | {kit['dogru']} / {kit['yanlis']}"
            + (f" = {kk['oran']:.3f} [{ar[0]:.3f}–{ar[1]:.3f}]" if ar else "") + f" | {a_h} | "
            + (f"{kit['dogru']} / {kit['nufus']} = %{100 * kapsam:.1f}" if kapsam is not None else "—") + f" | {b_h} | "
            + f"{verilen} / {prg['nufus']}" + (f" = %{100 * c_oran:.2f}" if c_oran is not None else "")
            + f" (doğru {prg['dogru']}, yanlış {prg['yanlis']}) | {c_h} |")
    # hata_dok (iki yön koşar; Q → R satırı)
    CIKTI.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hata_dok.main([GRUP, "--nokta", "kural", "--json", str(CIKTI / "hata_pk11_kural.json")])
        urun_bindiff.main([GRUP, "--json", str(CIKTI / "urun_bindiff_pk11.json")])
    (CIKTI / "pk11_betikler.txt").write_text(buf.getvalue(), encoding="utf-8")
    hd = json.loads((CIKTI / "hata_pk11_kural.json").read_text(encoding="utf-8"))[GRUP]["yonler"]
    sonuc["hata_dok_kural_ileri"] = next(y for y in hd if y["sorgu"] == qk)
    ub = json.loads((CIKTI / "urun_bindiff_pk11.json").read_text(encoding="utf-8"))[GRUP]["yonler"]
    sonuc["urun_yolu_ileri"] = [y for y in ub if y["sorgu"] == qk]
    for y in sonuc["urun_yolu_ileri"]:
        print("ürün yolu", y["kip"], {k: (v["dogru"], v["yanlis"]) for k, v in y["yontem"].items()})
    sonuc["kunye"] = d0_olc.kunye()
    (CIKTI / "pk11.json").write_text(json.dumps(sonuc, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    bas = ("| Nokta | `proje_kitapligi` doğru / yanlış [Wilson] | (a) | kapsam | (b) | `program` verilen ad / nüfus | (c) |\n"
           "|---|---|---|---|---|---|---|")
    metin = bas + "\n" + "\n".join(satir_md) + "\n"
    (CIKTI / "pk11.md").write_text(metin, encoding="utf-8")
    print(metin)
    for nokta, v in sonuc["noktalar"].items():
        print(nokta, {s: (k["nufus"], k["tavan"], k["dogru"], k["yanlis"]) for s, k in v["sinif"].items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
