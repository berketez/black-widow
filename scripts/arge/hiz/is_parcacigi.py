#!/usr/bin/env python3
"""HIZ kalem 2 ek: bir sürecin iş parçacığı başına birikmiş işlemci süresi (macOS ``ps -M``).

Müdahalesiz: sürece bağlanmaz (jstack / attach yok), yalnız çekirdeğin tuttuğu sayaçları okur.
Java iş parçacığı adları görünmez; en çok süre biriktiren iş parçacıkları ve toplam pay verilir.

Kullanım:
    python scripts/arge/hiz/is_parcacigi.py --pid 74835 \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/is_parcacigi_<saat>.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path


def _sn(s: str) -> float:
    # ps zaman biçimi: [[gg-]ss:]dd:ss.cc
    gun = 0
    if "-" in s:
        g, s = s.split("-", 1)
        gun = int(g)
    parca = s.split(":")
    t = 0.0
    for p in parca:
        t = t * 60 + float(p)
    return gun * 86400 + t


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", required=True, type=int)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    out = subprocess.run(["ps", "-M", "-p", str(a.pid)], capture_output=True, text=True).stdout
    satir = out.splitlines()
    if len(satir) < 2:
        raise SystemExit("süreç yok: %d" % a.pid)
    kayit = []
    for s in satir[1:]:
        p = s.split()
        # İlk satır komut adını taşır; zaman sütunları her satırda STIME, UTIME sırasıyla.
        zaman = [x for x in p if ":" in x and x.replace(":", "").replace(".", "").replace("-", "").isdigit()]
        if len(zaman) < 2:
            continue
        kayit.append({"sistem_sn": _sn(zaman[-2]), "kullanici_sn": _sn(zaman[-1])})
    kayit.sort(key=lambda r: -(r["sistem_sn"] + r["kullanici_sn"]))
    top = sum(r["sistem_sn"] + r["kullanici_sn"] for r in kayit)
    print("zaman: %s  pid %d  iş parçacığı: %d  toplam işlemci: %.0f sn" % (
        dt.datetime.now().strftime("%H:%M:%S"), a.pid, len(kayit), top))
    print("| Sıra | kullanıcı (sn) | sistem (sn) | toplam payı |")
    print("|---|---|---|---|")
    for i, r in enumerate(kayit[:10], 1):
        t = r["sistem_sn"] + r["kullanici_sn"]
        print("| %d | %.1f | %.1f | %.1f %% |" % (i, r["kullanici_sn"], r["sistem_sn"], 100 * t / top if top else 0))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps({"pid": a.pid, "zaman": dt.datetime.now().isoformat(),
                                 "toplam_sn": top, "is_parcaciklari": kayit}, indent=1))


if __name__ == "__main__":
    main()
