#!/usr/bin/env python
"""KİMLİK hattı — ürünün var olan başvuru eşleyicisinin (``karadul.analyzers.bindiff.BinaryDiffer``) çıplak ölçümü.

Ürün kodu DEĞİŞTİRİLMEZ; ``BinaryDiffer.compare`` iki koşunun var olan Ghidra JSON'larıyla çağrılır:
  - ``config`` kipi: ürünün ``reference_binary`` yolunun yaptığı çağrı (``_feedback_naming_bindiff._config_source``:
    yalnız fonksiyon + dizgi JSON'u);
  - ``refdb`` kipi: ``_refdb_source``'un yaptığı çağrı (+ çağrı grafiği);
  - ``refdiffer`` kipi: ``karadul.reconstruction.reference_differ.ReferenceDiffer.match_direct`` (dizgi + CFG +
    çağrı grafiği; öntanımlı kurucu).
Başvurunun fonksiyon adları GT'den yazılır (sembollü başvuru benzetimi); hüküm ``esle.hukum`` ile, nüfus içinde,
yöntem (``DiffMatch.method``) başına ve toplam. Eşik ürünün öntanımı (``min_confidence`` 0,7).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/urun_bindiff.py kesif_htop sinama_tmux … --json <çıktı>

``--kapi`` (PK-1): eşleşmeler ürünün yöntem kapısından geçirilir
(``karadul.reconstruction.kimlik.yontem_kapisi.ad_verebilir``); kapıdan geçenler ``yontem`` (ad) sayımına,
geçmeyenler ``kanit`` (kanıt satırı) sayımına girer. Seçenek yokken çıktı eskisiyle aynıdır.
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

sys.path.insert(0, str(veri.REPO))
from karadul.analyzers.bindiff import BinaryDiffer  # noqa: E402
from karadul.reconstruction.kimlik.yontem_kapisi import ad_verebilir, ad_veren_yontemler  # noqa: E402
from karadul.reconstruction.reference_differ import ReferenceDiffer  # noqa: E402


def _jsonlar(I: Ikili, adli: bool) -> tuple[dict, dict, dict]:
    f = veri._json(I.static / "ghidra_functions.json")
    cg = veri._json(I.static / "ghidra_call_graph.json")
    st = veri._json(I.static / "ghidra_strings.json")
    if adli:
        f = copy.deepcopy(f)
        for g in f["functions"]:
            fk = I.fonk.get(int(g["address"], 16))
            if fk is not None and fk.gt:
                g["name"] = fk.gt[0]
    return f, cg, st


def olc(Q: Ikili, R: Ikili, kip: str, kapi: bool = False) -> dict[str, Any]:
    qf, qcg, qst = _jsonlar(Q, adli=False)
    rf, rcg, rst = _jsonlar(R, adli=True)
    if kip == "refdiffer":
        # ``ReferenceDiffer.match_direct``: ürünün "kaynak eşleme" katmanının eşleyicisi (öntanımlı kurucu)
        sonuc = ReferenceDiffer().match_direct(
            ref_functions=rf, target_functions=qf, ref_strings=rst, target_strings=qst,
            ref_cfg=veri._json(R.static / "ghidra_cfg.json"), target_cfg=veri._json(Q.static / "ghidra_cfg.json"),
            ref_call_graph=rcg, target_call_graph=qcg)
    else:
        ek = dict(ref_call_graph=rcg, target_call_graph=qcg) if kip == "refdb" else {}
        sonuc = BinaryDiffer().compare(reference=rf, target=qf, ref_strings=rst, target_strings=qst, **ek)
    nufus = set(Q.nufus)
    say: dict[str, list[int]] = {}
    kanit: dict[str, list[int]] = {}       # --kapi: kapıdan düşenler (kanıt satırı)
    for m in sonuc.matches:
        q, r = int(m.target_address, 16), int(m.ref_address, 16)
        if q not in nufus or q not in Q.fonk or r not in R.fonk:
            continue
        h = esle.hukum(Q, R, q, r)
        if h not in ("dogru", "yanlis"):
            continue
        hedef = say if (not kapi or ad_verebilir(m.method)) else kanit
        for anahtar in (m.method, "toplam"):
            s = hedef.setdefault(anahtar, [0, 0])
            s[0 if h == "dogru" else 1] += 1
    cikti = {"sorgu": Q.kimlik, "basvuru": R.kimlik, "kip": kip, "nufus": len(nufus),
             "yontem": {k: {"dogru": d, "yanlis": y} for k, (d, y) in say.items()}}
    if kapi:
        cikti["kapi"] = True
        cikti["kanit"] = {k: {"dogru": d, "yanlis": y} for k, (d, y) in kanit.items()}
    return cikti


def main(argv=None) -> int:
    logging.disable(logging.CRITICAL)
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--kapi", action="store_true",
                    help="PK-1: eşleşmeleri ürünün yöntem kapısından geçir (kalan kanıt satırı sayılır)")
    a = ap.parse_args(argv)
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k, pcode=False)
        return onbellek[k]

    cikti: dict[str, Any] = {}
    if a.kapi:
        cikti["kapi"] = {"ad_veren_yontemler": list(ad_veren_yontemler())}
    tum: dict[str, dict[str, list[int]]] = {}     # kip → yöntem → [doğru, yanlış]; bütün gruplar
    tum_kanit: dict[str, dict[str, list[int]]] = {}   # --kapi: kapıdan düşenler
    for g in a.gruplar:
        satirlar = []
        for kip in ("config", "refdb", "refdiffer"):
            havuz: dict[str, list[int]] = {}
            havuz_kanit: dict[str, list[int]] = {}
            nuf = 0
            for c in ciftler.grup(g):
                for qk, rk in (c, c[::-1]):
                    s = olc(al(qk), al(rk), kip, kapi=a.kapi)
                    satirlar.append(s)
                    nuf += s["nufus"]
                    for alan, hv, tm in (("yontem", havuz, tum), ("kanit", havuz_kanit, tum_kanit)):
                        for k, v in s.get(alan, {}).items():
                            h = hv.setdefault(k, [0, 0])
                            h[0] += v["dogru"]
                            h[1] += v["yanlis"]
                            t = tm.setdefault(kip, {}).setdefault(k, [0, 0])
                            t[0] += v["dogru"]
                            t[1] += v["yanlis"]
            for k, (d, y) in sorted(havuz.items()):
                o = ks1.oran(d, d + y)
                print(f"{g:14s} {kip:6s} {k:16s} doğru {d:5d} yanlış {y:5d} kesinlik {o['oran']:.3f} "
                      f"[{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}] kapsam {d / nuf * 100:5.1f}% (nüfus {nuf})")
            for k, (d, y) in sorted(havuz_kanit.items()):
                print(f"{g:14s} {kip:6s} KANIT {k:16s} doğru {d:5d} yanlış {y:5d}")
            cikti.setdefault(g, {})[kip] = {"havuz": {k: {"dogru": d, "yanlis": y} for k, (d, y) in havuz.items()},
                                           "nufus": nuf}
            if a.kapi:
                cikti[g][kip]["kanit"] = {k: {"dogru": d, "yanlis": y} for k, (d, y) in havuz_kanit.items()}
        cikti[g]["yonler"] = satirlar
    # Yöntem başına bütün grupların havuzu (yöntem kapısı tablosunun kaynağı: PLAN.md PK-1)
    for kip, yy in tum.items():
        for k, (d, y) in sorted(yy.items()):
            o = ks1.oran(d, d + y)
            print(f"{'TÜM GRUPLAR':14s} {kip:9s} {k:18s} doğru {d:5d} yanlış {y:5d} kesinlik {o['oran']:.3f} "
                  f"[{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}]")
    cikti["tum_gruplar"] = {kip: {k: {"dogru": d, "yanlis": y, "kesinlik": ks1.oran(d, d + y)} for k, (d, y) in yy.items()}
                            for kip, yy in tum.items()}
    if a.kapi:
        for kip, yy in tum_kanit.items():
            for k, (d, y) in sorted(yy.items()):
                print(f"{'TÜM GRUPLAR':14s} {kip:9s} KANIT {k:18s} doğru {d:5d} yanlış {y:5d}")
        cikti["tum_gruplar_kanit"] = {kip: {k: {"dogru": d, "yanlis": y} for k, (d, y) in yy.items()}
                                      for kip, yy in tum_kanit.items()}
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
