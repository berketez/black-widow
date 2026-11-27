"""GS-1 H3: arayüz sunucusunun iptali (``cancel_job``) gerçek alt süreçlerde kaç saniyede bitiyor.

Sunucu modülü ``--agac``'taki ``ui/server.py``'den yüklenir (ürün ağacı). Senaryolar:
  uyan     SIGTERM'e uyan süreç + torun (``sleep``)
  yoksayan SIGTERM'i yok sayan süreç + SIGTERM'i yok sayan torun
  regex    SIGTERM'i yok sayan süreç C düzeyinde takılı düzenli ifadede + torun
  jvm      hüküm 7'nin (c) çocuğu: süreç içi JVM (ürünün yolu) + C düzeyinde takılı düzenli ifade
           (Ghidra JVM'ini başlatır: ``ghidra_kuyruk.sh`` ile koşulur)
Ölçülen: ``cancel_job`` dönene kadar geçen süre, dönen ``sonlandirma``, lider ve torunun öldüğü an.

python scripts/arge/gs1/iptal_olc.py --agac <ürün ağacı> --senaryo uyan yoksayan regex [jvm] --cikti <json>
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BURASI = Path(__file__).resolve().parent
ESKI_KALIP = r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
SATIR = "memmove(a,b," + "x," * 30


def _yasiyor(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _lider(senaryo: str, pidfile: Path) -> list[str]:
    if senaryo == "jvm":
        return [sys.executable, str(BURASI / "sigterm_olc.py"), "cocuk", "c"]
    yok = senaryo in ("yoksayan", "regex")
    torun = ("import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(120)"
             if senaryo == "yoksayan" else "import time;time.sleep(120)")
    satirlar = ["import re,signal,subprocess,sys,time",
                "c=subprocess.Popen([sys.executable,'-c',%r])" % torun, "time.sleep(0.3)"]
    if yok:
        satirlar.append("signal.signal(signal.SIGTERM,signal.SIG_IGN)")
    satirlar.append("open(%r,'w').write(str(c.pid))" % str(pidfile))
    if senaryo == "regex":
        satirlar.append("re.compile(%r).search(%r)" % (ESKI_KALIP, SATIR))
    satirlar.append("time.sleep(120)")
    return [sys.executable, "-c", "\n".join(satirlar)]


def olc(srv, senaryo: str, gecici: Path) -> dict:
    pidfile = gecici / (senaryo + ".torun")
    log = gecici / (senaryo + ".log")
    log.write_text("")
    if senaryo == "jvm":
        proc = subprocess.Popen(_lider(senaryo, pidfile), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, process_group=0,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        for satir in proc.stdout:
            if satir.strip() == b"HAZIR":
                break
        torun = None
        time.sleep(1.0)
    else:
        proc = subprocess.Popen(_lider(senaryo, pidfile), process_group=0)
        son = time.monotonic() + 20
        while time.monotonic() < son and not (pidfile.exists() and pidfile.read_text()):
            time.sleep(0.02)
        torun = int(pidfile.read_text())
        if senaryo == "regex":
            time.sleep(0.5)
    jid = "olc_" + senaryo
    srv._JOBS[jid] = {"proc": proc, "log": str(log), "ws_out": str(gecici / "ws"), "run_dir": str(gecici),
                      "binary": senaryo, "started": time.time(), "lf": None, "closed": True,
                      "cancelled": False, "activated": False}
    t0 = time.monotonic()
    r = srv.cancel_job(jid)
    donus = time.monotonic() - t0
    while proc.poll() is None and time.monotonic() - t0 < 30:
        time.sleep(0.01)
    lider_olum = time.monotonic() - t0
    torun_olum = None
    if torun is not None:
        while _yasiyor(torun) and time.monotonic() - t0 < 30:
            time.sleep(0.01)
        torun_olum = round(time.monotonic() - t0, 3) if not _yasiyor(torun) else None
    srv._JOBS.pop(jid, None)
    return {"senaryo": senaryo, "donus": r, "cancel_sn": round(donus, 3), "lider_olum_sn": round(lider_olum, 3),
            "lider_rc": proc.returncode, "torun_olum_sn": torun_olum,
            "bekleme_sn": srv.IPTAL_BEKLEME_SN}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agac", required=True)
    ap.add_argument("--senaryo", nargs="+", default=["uyan", "yoksayan", "regex"])
    ap.add_argument("--cikti", required=True)
    a = ap.parse_args()
    spec = importlib.util.spec_from_file_location("gs1_iptal_olc_srv", Path(a.agac) / "ui" / "server.py")
    srv = importlib.util.module_from_spec(spec)
    sys.path.insert(0, a.agac)
    spec.loader.exec_module(srv)
    sonuc = []
    with tempfile.TemporaryDirectory() as g:
        for s in a.senaryo:
            sonuc.append(olc(srv, s, Path(g)))
            print(json.dumps(sonuc[-1], ensure_ascii=False), flush=True)
    uptime = subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True).stdout.strip()
    Path(a.cikti).write_text(json.dumps({"uptime": uptime, "agac": a.agac, "sonuclar": sonuc},
                                        ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
