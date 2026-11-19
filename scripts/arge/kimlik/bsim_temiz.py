#!/usr/bin/env python
"""KİMLİK hattı — temiz BSim ölçümü (``kos_bsim.sh`` koşularından).

Her depoda yalnız iki ikili var (başvuru önce, sorgu sonra koşuldu); sorgunun ``ghidra_bsim.json``'ı yalnız
başvuruya karşı eşleşme taşır. Hüküm ve eşikler ``ciplak.bsim`` ile aynı; GT ve adresler taban koşusundan
(aynı ikili: sha256 denetlenir).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/bsim_temiz.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ciplak  # noqa: E402
import esle  # noqa: E402
import veri  # noqa: E402
from veri import ks1  # noqa: E402

KOK = veri.CIKTI / "bsim"
# depo → (sorgu kimliği, sorgu koşu dizini, başvuru kimliği)
DEPOLAR = {
    "htop_md": ("debian/htop", "2_debian", "mac/htop"),
    "htop_dm": ("mac/htop", "2_mac", "debian/htop"),
    "tmux_md": ("debian/tmux", "2_debian", "mac/tmux"),
    "tmux_dm": ("mac/tmux", "2_mac", "debian/tmux"),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    cikti: dict[str, Any] = {}
    havuz: dict[str, dict[str, list[int]]] = {}
    for depo, (qk, dizin, rk) in DEPOLAR.items():
        d = KOK / depo / dizin
        if not (d / "BITTI").is_file():
            print(f"{depo}: koşu bitmemiş, atlandı")
            continue
        Q0, R = veri.yukle(qk, pcode=False), veri.yukle(rk, pcode=False)
        static = ks1._tek_static(d)
        if ciplak._sha(replace(Q0, static=static)) != ciplak._sha(Q0):
            raise SystemExit(f"{depo}: koşulan ikili taban koşusundakiyle aynı değil")
        Q = replace(Q0, static=static)
        belge = veri._json(static / "ghidra_bsim.json")
        b = ciplak.bsim(Q, R)
        kunye = {k: belge.get(k) for k in ("total_matches", "total_queries", "bsim_mode", "bsim_status")}
        kunye["known_executables"] = (belge.get("bsim_detail") or {}).get("known_executables")
        print(f"{depo}: {qk} → {rk} {kunye}")
        cikti[depo] = {"sorgu": qk, "basvuru": rk, "kunye": kunye, "olcum": {}}
        if b is None:
            print("   başvuruya eşleşme yok")
            continue
        program = qk.split("/")[1]
        for ad, es in b.items():
            o = ciplak._olc(Q, R, es)
            cikti[depo]["olcum"][ad] = o
            h = havuz.setdefault(program, {}).setdefault(ad, [0, 0, 0])
            h[0] += o["dogru"]
            h[1] += o["yanlis"]
            h[2] += o["nufus"]
            print(f"   {ad:12s} {esle.kisa(o)}")
    for program, hh in havuz.items():
        for ad, (d_, y, n) in hh.items():
            o = ks1.oran(d_, d_ + y)
            ar = f"{o['oran']:.3f} [{o['aralik'][0]:.3f}, {o['aralik'][1]:.3f}]" if o["aralik"] else "—"
            print(f"HAVUZ {program:5s} {ad:12s} doğru {d_} yanlış {y} kesinlik {ar} kapsam {d_ / n * 100:.1f}% (nüfus {n})")
    cikti["havuz"] = {p: {ad: {"dogru": v[0], "yanlis": v[1], "nufus": v[2]} for ad, v in hh.items()} for p, hh in havuz.items()}
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(cikti, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
