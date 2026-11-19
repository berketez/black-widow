#!/usr/bin/env python
"""KİMLİK hattı — kalem 6 (A1'e katkı): ad bekleyen nüfusta "kaynağı set içinde başka yerde bulunan kod" payı.

Geliştirme setinin 119 ikilisi (taban koşusu a62f15e) için yalnız GT ve Ghidra fonksiyon listesi okunur.
Nüfustaki her fonksiyon şu sınıflardan İLK uyana girer:
  1. ``kopya_ad_boyut``: aynı birimin (platform/program) BAŞKA bir ikilisinde aynı GT adı ve aynı fonksiyon
     boyutuyla var (aynı derleyicide aynı kodun kopyası; coreutils'te gnulib + ortak kaynak dosyaları);
  2. ``kopya_ad``: aynı birimin başka ikilisinde aynı adla var ama boyut farklı (aynı ad, farklı gövde:
     ``usage`` / ``main`` gibi programa özgü adlar ya da bağlama göre farklı derlenmiş kopya — üst sınır);
  3. ``baska_derleme``: aynı programın öbür platform derlemesinde aynı adla var (tmux, htop: Debian ↔ Mac);
  4. ``set_ici_yok``: set içinde başka kaynağı görünmüyor (bu, "hiçbir yerde kaynağı yok" demek DEĞİL:
     başvuru derlemesi sette bulunmuyor).
C++ ikilisi ``pzstd`` ürün ölçüsünde olduğu gibi dışarıda.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/a1_pay.py --json <çıktı>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veri  # noqa: E402
from veri import TABAN, ks1  # noqa: E402

OLCU_DISI = {"debian/zstd/pzstd"}
A1_SINIFLARI = ("kopya_ad_boyut", "kopya_ad", "baska_derleme", "set_ici_yok")


def kimlikler() -> list[str]:
    out = []
    for prog in sorted(p for p in (TABAN / "debian").iterdir() if p.is_dir()):
        ikililer = sorted(d.name for d in prog.iterdir() if d.is_dir())
        for b in ikililer:
            out.append(f"debian/{prog.name}" if ikililer == [prog.name] else f"debian/{prog.name}/{b}")
    out += [f"mac/{p.name}" for p in sorted((TABAN / "mac").iterdir()) if p.is_dir()]
    return [k for k in out if k not in OLCU_DISI]


def birim(k: str) -> str:
    p = k.split("/")
    return f"{p[0]}/{p[1]}"


def fonksiyon_siniflari() -> tuple[dict[tuple[str, int], str], int, int]:
    """(kimlik, Ghidra adresi) → A1 sınıfı; nüfustaki her fonksiyon için. Ayrıca (yüklenen, istenen) ikili."""
    ks = kimlikler()
    veriler = {}
    for k in ks:
        try:
            veriler[k] = veri.yukle(k, pcode=False)
        except Exception as e:  # noqa: BLE001 — yüklenemeyen ikili sayılır ve adıyla yazılır
            print(f"YÜKLENEMEDİ {k}: {type(e).__name__}: {e}", file=sys.stderr)
    # ad → {(ikili, boyut)}; birim başına
    ad_dizini: dict[str, dict[str, set[tuple[str, int]]]] = {}
    for k, I in veriler.items():
        d = ad_dizini.setdefault(birim(k), {})
        for f in I.fonk.values():
            for n in f.gt:
                d.setdefault(n, set()).add((k, f.boyut))
    karsi = {"debian/tmux": "mac/tmux", "mac/tmux": "debian/tmux", "debian/htop": "mac/htop", "mac/htop": "debian/htop"}
    out: dict[tuple[str, int], str] = {}
    for k, I in veriler.items():
        b = birim(k)
        for adr in I.nufus:
            f = I.fonk[adr]
            baskalari = {(k2, boy) for n in f.gt for (k2, boy) in ad_dizini[b].get(n, ()) if k2 != k}
            if any(boy == f.boyut for _, boy in baskalari):
                out[(k, adr)] = "kopya_ad_boyut"
            elif baskalari:
                out[(k, adr)] = "kopya_ad"
            elif b in karsi and any(n in ad_dizini.get(karsi[b], {}) for n in f.gt):
                out[(k, adr)] = "baska_derleme"
            else:
                out[(k, adr)] = "set_ici_yok"
    return out, len(veriler), len(ks)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    sinif, yuklenen, istenen = fonksiyon_siniflari()
    say: dict[str, dict[str, int]] = {}
    ikililer: dict[str, set[str]] = {}
    for k in kimlikler():
        ikililer.setdefault(birim(k), set()).add(k)
    for (k, _adr), x in sinif.items():
        s = say.setdefault(birim(k), {y: 0 for y in A1_SINIFLARI} | {"nufus": 0, "ikili": len(ikililer[birim(k)])})
        s["nufus"] += 1
        s[x] += 1
    top = {x: sum(s[x] for s in say.values()) for x in A1_SINIFLARI + ("nufus", "ikili")}
    print(f"{'birim':22s} {'ikili':>5s} {'nüfus':>6s} " + " ".join(f"{x:>15s}" for x in A1_SINIFLARI))
    for b, s in sorted(say.items()):
        print(f"{b:22s} {s['ikili']:5d} {s['nufus']:6d} " + " ".join(f"{s[x]:15d}" for x in A1_SINIFLARI))
    print(f"{'TOPLAM':22s} {top['ikili']:5d} {top['nufus']:6d} " + " ".join(f"{top[x]:15d}" for x in A1_SINIFLARI))
    for x in A1_SINIFLARI:
        o = ks1.oran(top[x], top["nufus"])
        print(f"  {x:15s} {o['k']}/{o['n']} = {o['oran'] * 100:.1f}% [{o['aralik'][0] * 100:.1f}, {o['aralik'][1] * 100:.1f}]")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps({"birimler": say, "toplam": top, "yuklenen": yuklenen, "istenen": istenen},
                                     ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
