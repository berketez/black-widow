#!/usr/bin/env python
"""KİMLİK hattı — kalem 2: var olan yöntemlerin çıplak ölçümü (yeni Ghidra koşusu yok).

Her çift ve yön (Q → R) için, nüfus içinde ad kesinliği ve kapsamı:
  - ``bsim``: Q'nun taban koşusundaki ``ghidra_bsim.json`` içinde R'ye (sha256) düşen eşleşmeler. Fonksiyon
    başına en yüksek benzerlikli R adayı; eşik (≥ 0,7 / ≥ 0,9 / = 1,0) ve "tek en iyi" kapısıyla ayrı ayrı.
    Depoda R o an yoksa (koşu sırası) satır "yok" olur.
  - ``cfg_yapi``: CFG'nin yapısal özeti (blok, kenar, WL özeti) iki tarafta da tekilse eşle.
  - ``cfg_komut``: aynısı + komut adı çoklu kümesi (P11'deki CFG-iso bankasının çift düzeyindeki karşılığı).
  - ``tekil_dizgi``: iki tarafta da yalnız bir fonksiyonda geçen dizgi (``esle.tekil_dizgi_capalari``).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/ciplak.py kesif_htop sinama_tmux … --json <çıktı>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciftler  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import Ikili, ks1  # noqa: E402

CFG_EN_AZ_BLOK = 3     # 1-2 bloklu fonksiyonlarda yapı özeti ayırt edici değil (P11'deki alt sınırla aynı fikir)


def _sha(I: Ikili) -> Optional[str]:
    return veri._json(I.static.parent / "raw" / "target_info.json").get("file_hash")


def bsim(Q: Ikili, R: Ikili) -> Optional[dict[str, dict[int, int]]]:
    """Eşik / kapı adı → {q: r}. R depoda yoksa None."""
    belge = veri._json(Q.static / "ghidra_bsim.json")
    r_sha = _sha(R)
    aday: dict[int, list[tuple[float, int]]] = {}
    for m in belge.get("matches") or []:
        if m.get("matched_exe_sha256") != r_sha:
            continue
        aday.setdefault(int(m["query_address"], 16), []).append((float(m["similarity"]), int(m["matched_address"], 16)))
    if not aday:
        return None
    out: dict[str, dict[int, int]] = {k: {} for k in ("b>=0.7", "b>=0.9", "b=1.0", "b>=0.7_tek", "b>=0.9_tek")}
    for q, l in aday.items():
        l.sort(key=lambda t: (-t[0], t[1]))
        s, r = l[0]
        tek = len(l) == 1 or l[1][0] < s
        if q not in Q.fonk or r not in R.fonk:
            continue
        if s >= 0.7:
            out["b>=0.7"][q] = r
            if tek:
                out["b>=0.7_tek"][q] = r
        if s >= 0.9:
            out["b>=0.9"][q] = r
            if tek:
                out["b>=0.9_tek"][q] = r
        if s >= 1.0:
            out["b=1.0"][q] = r
    return out


def _wl(f: veri.Fonk, tur: int = 3) -> str:
    n = f.blok
    gir = [0] * n
    cik = [0] * n
    kom: list[list[int]] = [[] for _ in range(n)]
    for a, b in f.cfg_kenarlari:
        if a < n and b < n:
            cik[a] += 1
            gir[b] += 1
            kom[a].append(b)
    et = [f"{gir[i]}:{cik[i]}" for i in range(n)]
    for _ in range(tur):
        et = [hashlib.md5((et[i] + "|" + ",".join(sorted(et[j] for j in kom[i]))).encode()).hexdigest()[:12]
              for i in range(n)]
    return hashlib.md5(",".join(sorted(et)).encode()).hexdigest()[:16]


def cfg_tekil(Q: Ikili, R: Ikili, komut: bool) -> dict[int, int]:
    def anahtarlar(I: Ikili) -> dict[Any, list[int]]:
        d: dict[Any, list[int]] = {}
        for a, f in I.fonk.items():
            if f.blok < CFG_EN_AZ_BLOK:
                continue
            k = (f.blok, f.kenar, _wl(f)) + ((f.komutlar,) if komut else ())
            d.setdefault(k, []).append(a)
        return d
    aq, ar = anahtarlar(Q), anahtarlar(R)
    return {qa[0]: ar[k][0] for k, qa in aq.items() if len(qa) == 1 and len(ar.get(k, [])) == 1}


def _olc(Q: Ikili, R: Ikili, es: dict[int, int]) -> dict[str, Any]:
    return esle.olc(Q, R, {q: esle.Esleme(q, r, "ciplak", 0, 1.0, 0.0, 0.0) for q, r in es.items()})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gruplar", nargs="+")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    onbellek: dict[str, Ikili] = {}

    def al(k: str) -> Ikili:
        if k not in onbellek:
            onbellek[k] = veri.yukle(k, pcode=False)
        return onbellek[k]

    cikti: dict[str, Any] = {}
    for g in a.gruplar:
        havuz: dict[str, list[int]] = {}
        satirlar = []
        for x, y in ciftler.grup(g):
            for qk, rk in ((x, y), (y, x)):
                Q, R = al(qk), al(rk)
                yontemler: dict[str, Optional[dict[int, int]]] = {
                    "tekil_dizgi": esle.tekil_dizgi_capalari(Q, R, esle.DONUK),
                    "cfg_yapi": cfg_tekil(Q, R, komut=False),
                    "cfg_komut": cfg_tekil(Q, R, komut=True),
                }
                b = bsim(Q, R)
                if b is None:
                    yontemler["bsim"] = None
                else:
                    yontemler.update(b)
                for ad, es in yontemler.items():
                    if es is None:
                        print(f"{g:14s} {qk:28s} → {rk:28s} {ad:12s} yok (depoda başvuru yoktu)")
                        satirlar.append({"sorgu": qk, "basvuru": rk, "yontem": ad, "olcum": None})
                        continue
                    o = _olc(Q, R, es)
                    satirlar.append({"sorgu": qk, "basvuru": rk, "yontem": ad, "olcum": o})
                    h = havuz.setdefault(ad, [0, 0, 0])
                    h[0] += o["dogru"]
                    h[1] += o["yanlis"]
                    h[2] += o["nufus"]
                    print(f"{g:14s} {qk:28s} → {rk:28s} {ad:12s} {esle.kisa(o)}")
        ozet = {ad: {"dogru": d, "yanlis": y, "nufus": n, "kesinlik": ks1.oran(d, d + y), "kapsam": ks1.oran(d, n)}
                for ad, (d, y, n) in havuz.items()}
        for ad, o in ozet.items():
            k = o["kesinlik"]
            alt = k["aralik"][0] if k["aralik"] else float("nan")
            print(f"{g:14s} HAVUZ {ad:12s} doğru {o['dogru']} yanlış {o['yanlis']} kesinlik {(k['oran'] or 0):.3f} "
                  f"(Wilson alt {alt:.3f}) kapsam {(o['kapsam']['oran'] or 0) * 100:.1f}% (nüfus {o['nufus']})")
        cikti[g] = {"satirlar": satirlar, "havuz": ozet}
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
