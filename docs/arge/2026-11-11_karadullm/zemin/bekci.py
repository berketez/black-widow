"""Bellek ve yük bekçisi (zemin ölçümü, 2026-11-11).

Her `--aralik` saniyede bir:
- `llama-server` adlı bütün süreçlerin RSS'ini (`ps`) ve phys_footprint'ini (`footprint -p`) okur;
- üst sınırı pilotun tanımıyla hesaplar: RSS + footprint (`pilot_protokolu.md` §8, `llm_pilot.py:628`);
- yük ortalamasını (`os.getloadavg`) kaydeder.

Üst sınır `--esik` GiB'ı aşarsa süreci önce SIGTERM, 10 sn sonra hâlâ yaşıyorsa SIGKILL ile sonlandırır
ve olayı kaydeder. `--dur` dosyası oluşunca çıkar. Sonuç `--cikti` JSON dosyasına her örnekte yeniden yazılır.

Kullanım: python3 -I bekci.py --cikti x.json --dur /yol/dur --esik 22 --aralik 3
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path


def footprint_gib(pid: int) -> float | None:
    # macOS `footprint` aracı; çıktıdaki "Footprint: N MB" satırı (llm_pilot.py ile aynı okuma)
    try:
        r = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)", r.stdout)
    if not m:
        return None
    return float(m.group(1)) * {"KB": 1 / 1048576, "MB": 1 / 1024, "GB": 1.0}[m.group(2)]


def llama_surecleri() -> list[tuple[int, float]]:
    # (pid, RSS GiB) — yalnız komut adı llama-server olanlar
    r = subprocess.run(["ps", "-axo", "pid=,rss=,comm="], capture_output=True, text=True)
    out = []
    for satir in r.stdout.splitlines():
        p = satir.strip().split(None, 2)
        if len(p) == 3 and Path(p[2]).name == "llama-server":
            out.append((int(p[0]), int(p[1]) / 1048576))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--dur", type=Path, required=True)
    ap.add_argument("--esik", type=float, default=22.0)
    ap.add_argument("--aralik", type=float, default=3.0)
    ns = ap.parse_args()
    kayit = {"esik_gib": ns.esik, "aralik_sn": ns.aralik, "baslangic": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "ornek_sayisi": 0, "tepe": None, "olaylar": [], "yuk": [], "ornekler": []}
    while not ns.dur.exists():
        t = time.strftime("%Y-%m-%dT%H:%M:%S")
        yuk = os.getloadavg()
        kayit["yuk"].append([t, round(yuk[0], 2), round(yuk[1], 2), round(yuk[2], 2)])
        for pid, rss in llama_surecleri():
            fp = footprint_gib(pid) if rss >= 0.2 else None
            ust = rss + (fp or 0.0)
            o = {"zaman": t, "pid": pid, "rss_gib": round(rss, 3),
                 "footprint_gib": None if fp is None else round(fp, 3), "ust_gib": round(ust, 3)}
            kayit["ornekler"].append(o)
            kayit["ornek_sayisi"] += 1
            if kayit["tepe"] is None or ust > kayit["tepe"]["ust_gib"]:
                kayit["tepe"] = o
            if ust > ns.esik:
                kayit["olaylar"].append({"zaman": t, "pid": pid, "ust_gib": round(ust, 3), "eylem": "SIGTERM"})
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(10)
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                    kayit["olaylar"].append({"zaman": time.strftime("%Y-%m-%dT%H:%M:%S"), "pid": pid, "eylem": "SIGKILL"})
                except ProcessLookupError:
                    pass
        kayit["bitis"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        ns.cikti.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
        time.sleep(ns.aralik)
    kayit["bitis"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ns.cikti.write_text(json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
