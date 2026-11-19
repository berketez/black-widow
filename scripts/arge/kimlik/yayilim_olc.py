#!/usr/bin/env python
"""KİMLİK hattı — kalem 3 ve 4: çapalı yayılımın dondurulmuş parametrelerle ölçümü.

Her grup, çift ve yön (Q → R) için, dondurulmuş iki noktada (``esle.NOKTALAR``: kural, tutucu):
  - aşama başına (tekil dizgi çapası / yayılım) ve toplam nüfus içi kesinlik (Wilson) ve kapsam;
  - kapıda kalanlarda ad ailesi (``ikiz.olc``);
  - yanlış eşlemelerin listesi (geliştirme seti adları; kilitli set yok).
``--egri`` verilirse T × kütle ızgarasında kesinlik ↔ kapsam eğrisi de yazılır (bilgi içindir; sınama
birimlerinde nokta SEÇMEK için kullanılmaz).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/yayilim_olc.py sinama_tmux --egri --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import esle  # noqa: E402
import ikiz  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

EGRI_T = [0.3, 0.5, 0.7]
EGRI_KUTLE = [0.5, 1.0, 2.0, 3.0]


def yon(Q: Ikili, R: Ikili, p: esle.Param) -> dict[str, Any]:
    t0 = time.time()
    s = esle.esle(Q, R, p)
    o = esle.olc(Q, R, s.esler)
    yanlislar = [{"q_gt": list(Q.fonk[q].gt), "r_gt": list(R.fonk[e.r].gt), "asama": e.asama, "tur": e.tur,
                  "puan": round(e.puan, 3), "ikinci": round(e.ikinci, 3), "kutle": round(e.kutle, 3)}
                 for q, e in sorted(s.esler.items())
                 if Q.fonk[q].nufusta and esle.hukum(Q, R, q, e.r) == "yanlis"]
    return {"sorgu": Q.kimlik, "basvuru": R.kimlik, "toplam": o,
            "capa_dizgi": esle.olc(Q, R, s.esler, {"dizgi"}),
            "yayilim": esle.olc(Q, R, s.esler, {"yayilim"}),
            "ad_capasi": sum(1 for e in s.esler.values() if e.asama == "ad"),
            "tur": s.tur_sayisi, "aile": ikiz.olc(Q, R, s), "yanlislar": yanlislar,
            "sure_sn": round(time.time() - t0, 2)}


def havuzla(satirlar: list[dict[str, Any]], alan: str = "toplam") -> dict[str, Any]:
    d = sum(s[alan]["dogru"] for s in satirlar)
    y = sum(s[alan]["yanlis"] for s in satirlar)
    n = sum(s[alan]["nufus"] for s in satirlar)
    tv = sum(s[alan]["tavan"] for s in satirlar)
    return {"dogru": d, "yanlis": y, "nufus": n, "tavan": tv, "kesinlik": ks1.oran(d, d + y),
            "kapsam": ks1.oran(d, n), "kapsam_tavan": ks1.oran(d, tv)}


def havuz_aile(satirlar: list[dict[str, Any]]) -> dict[str, Any]:
    out = {}
    for alan in ("kume", "onek", "sonek", "etiketli", "tek_uyeli"):
        out[alan] = ks1.oran(sum(s["aile"][alan]["k"] for s in satirlar), sum(s["aile"][alan]["n"] for s in satirlar))
    return out


def _kn(o: dict[str, Any]) -> str:
    a = o["aralik"]
    return f"{o['k']}/{o['n']}" + (f" = {o['oran']:.3f} [{a[0]:.3f}, {a[1]:.3f}]" if a else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--egri", action="store_true")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k)
        return onbellek[k]

    cikti: dict[str, Any] = {"noktalar": {k: {"T": p.T, "marj": p.marj, "kutle": p.kutle, "carpan": dict(p.carpan)}
                                         for k, p in esle.NOKTALAR.items()},
                             "aile": vars(ikiz.AILE) if hasattr(ikiz.AILE, "__dict__") else str(ikiz.AILE)}
    for g in a.gruplar:
        yonler = [(x, y) for c in ciftler.grup(g) for x, y in (c, c[::-1])]
        gr: dict[str, Any] = {}
        for ad, p in esle.NOKTALAR.items():
            satirlar = []
            for qk, rk in yonler:
                s = yon(al(qk), al(rk), p)
                satirlar.append(s)
                print(f"{g:13s} {ad:7s} {qk:26s} → {rk:26s} {esle.kisa(s['toplam'])} | dizgi çapası "
                      f"{s['capa_dizgi']['dogru']}/{s['capa_dizgi']['dogru'] + s['capa_dizgi']['yanlis']} | aile küme "
                      f"{_kn(s['aile']['kume'])} | {s['sure_sn']} sn")
            h = havuzla(satirlar)
            hd = havuzla(satirlar, "capa_dizgi")
            hy = havuzla(satirlar, "yayilim")
            ha = havuz_aile(satirlar)
            print(f"{g:13s} {ad:7s} HAVUZ toplam   {esle.kisa({**h, 'adsiz': 0})}")
            print(f"{g:13s} {ad:7s} HAVUZ dizgi    {esle.kisa({**hd, 'adsiz': 0})}")
            print(f"{g:13s} {ad:7s} HAVUZ yayılım  {esle.kisa({**hy, 'adsiz': 0})}")
            print(f"{g:13s} {ad:7s} HAVUZ aile: küme {_kn(ha['kume'])}; etiketli {_kn(ha['etiketli'])}; "
                  f"önek {_kn(ha['onek'])}; sonek {_kn(ha['sonek'])}; tek üyeli {_kn(ha['tek_uyeli'])}")
            gr[ad] = {"yonler": satirlar, "havuz": h, "havuz_dizgi": hd, "havuz_yayilim": hy, "havuz_aile": ha}
        if a.egri:
            egri = []
            for T in EGRI_T:
                for kutle in EGRI_KUTLE:
                    p = replace(esle.DONUK, T=T, kutle=kutle)
                    satirlar = []
                    for qk, rk in yonler:
                        Q, R = al(qk), al(rk)
                        satirlar.append({"toplam": esle.olc(Q, R, esle.esle(Q, R, p).esler)})
                    h = havuzla(satirlar)
                    egri.append({"T": T, "kutle": kutle, **h})
                    k = h["kesinlik"]
                    print(f"{g:13s} eğri T {T} kütle {kutle}: doğru {h['dogru']} yanlış {h['yanlis']} kesinlik "
                          f"{(k['oran'] or 0):.3f} (alt {(k['aralik'] or [0])[0]:.3f}) kapsam {(h['kapsam']['oran'] or 0) * 100:.1f}%")
            gr["egri"] = egri
        cikti[g] = gr
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
