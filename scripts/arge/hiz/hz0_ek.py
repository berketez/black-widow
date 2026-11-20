#!/usr/bin/env python3
"""HZ-0 adım 2: bir ÖLÇ-A koşusuna eşlik eden ek örnekleyici (ürünü sarmaz, yalnız izler).

Verilen süreç (``olcek_kos.py``'nin ``pid.json``'undaki ``karadul_pid``) yaşadığı sürece ``--aralik`` sn'de
bir ``ps -M`` ile iş parçacığı başına birikmiş işlemci süreleri (ayrıştırma ``is_parcacigi._sn``'den);
koşu başında ve sonunda küçük dosya açma gecikmesi (``acma_gecikmesi.py --oku … --n 1000``) ve
donanım künyesi (``hiz/PLAN.md`` §1). Çıktı ``<kök>/hz0_ek.json``.

Açma gecikmesi iki dizinde ölçülür:
- ``--acma-dizini`` (başvuru; koşudan bağımsız, öntanım geliştirme setindeki ``mac/tmux``'un
  ``decompiled/`` dizini): başta ve sonda;
- koşunun kendi ``ws/workspaces/*/*/static/ghidra_output/decompiled`` dizini: sonda (varsa). Avast
  dışlama kolunda (HZ-0 adım 7) dışlanan kökün içindeki dosyalar budur.

Kullanım:
    python scripts/arge/hiz/hz0_ek.py --pid <karadul pid> --kok <olcek_kos kökü> [--aralik 30]
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata as md
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from is_parcacigi import _sn  # noqa: E402  (ps -M zaman ayrıştırması; tek tanım orada)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "measurement"))
from urun_kos import GHIDRA  # noqa: E402  (Ghidra kurulum yolu; tek tanım orada)

BURASI = Path(__file__).resolve().parent
PS_ARALIK_SN = 30.0  # HZ-0 adım 2: 30 sn'de bir ps -M
ACMA_N = 1000
ILK_N = 20  # örnek başına saklanan en çok işlemci biriktirmiş iş parçacığı
ACMA_BASVURU = Path.home() / "karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux"


def _simdi() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _cmd(*arg: str, timeout: float = 30) -> str:
    try:
        p = subprocess.run(list(arg), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (p.stdout or "") + (p.stderr if not p.stdout else "")


def _surum(paket: str) -> str | None:
    try:
        return md.version(paket)
    except md.PackageNotFoundError:
        return None


def donanim_kunyesi(ghidra: Path = GHIDRA) -> dict[str, Any]:
    """``hiz/PLAN.md`` §1 donanım künyesi (macOS; başka platformda bulunabilen karşılıklar)."""
    def sc(k: str) -> str:
        return _cmd("sysctl", "-n", k).strip()

    k: dict[str, Any] = {"zaman": _simdi(), "platform": platform.platform(), "makine": platform.machine(),
                         "cpu_sayisi": os.cpu_count(), "yuk": list(os.getloadavg()),
                         "python": platform.python_version(), "python_yolu": sys.executable,
                         "jpype": _surum("JPype1"), "pyghidra": _surum("pyghidra")}
    if sys.platform == "darwin":
        k["cip"] = sc("machdep.cpu.brand_string")
        k["bellek_bayt"] = sc("hw.memsize")
        n = sc("hw.nperflevels")
        k["nperflevels"] = n
        k["perflevel"] = [{a: sc(f"hw.perflevel{i}.{a}") for a in ("name", "physicalcpu", "logicalcpu",
                                                                     "l2cachesize")}
                          for i in range(int(n) if n.isdigit() else 0)]
        k["sw_vers"] = _cmd("sw_vers").strip().splitlines()
        k["sistem_uzantilari"] = [s for s in _cmd("systemextensionsctl", "list").splitlines() if s.strip()]
    else:
        k["cpuinfo"] = _cmd("lscpu").strip().splitlines()[:30]
        k["bellek"] = _cmd("free", "-m").strip().splitlines()
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin" / "java") if java_home else (shutil.which("java") or "java")
    k["jdk"] = {"java": java, "surum": _cmd(java, "-version").strip().splitlines()[:3],
                "not": "JAVA_HOME / PATH java'sı; PyGhidra'nın süreç içi JVM'i başka olabilir (duman "
                       "2026-11-20: 27.0.1.0.2+1). Koşunun gerçek JVM'i: kunye.json → gc.jvm_surumu"}
    if sys.platform == "darwin":
        k["jdk"]["macos_varsayilan"] = _cmd("/usr/libexec/java_home").strip()
    k["ghidra"] = {"yol": str(ghidra), "surum": None}
    try:
        for satir in (ghidra / "Ghidra" / "application.properties").read_text().splitlines():
            if satir.startswith("application.version="):
                k["ghidra"]["surum"] = satir.split("=", 1)[1].strip()
    except OSError:
        pass
    return k


def is_parcaciklari(pid: int) -> list[dict[str, float]] | None:
    """``ps -M -p <pid>``: iş parçacığı başına (sistem, kullanıcı) işlemci sn; süreç yoksa None."""
    out = _cmd("ps", "-M", "-p", str(pid))
    satir = out.splitlines()
    if len(satir) < 2:
        return None
    kayit = []
    for s in satir[1:]:
        p = s.split()
        zaman = [x for x in p if ":" in x and x.replace(":", "").replace(".", "").replace("-", "").isdigit()]
        if len(zaman) < 2:
            continue
        kayit.append({"sistem_sn": _sn(zaman[-2]), "kullanici_sn": _sn(zaman[-1])})
    return kayit


def yasiyor(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def acma_olc(dizin: Path, cikti: Path, n: int = ACMA_N) -> dict[str, Any]:
    """``acma_gecikmesi.py --oku <dizin> --n <n>`` (salt okur); sonuç JSON'u."""
    if not dizin.is_dir():
        return {"dizin": str(dizin), "olculmedi": "dizin yok"}
    p = subprocess.run([sys.executable, str(BURASI / "acma_gecikmesi.py"), "--oku", str(dizin),
                        "--n", str(n), "--cikti", str(cikti)], capture_output=True, text=True, timeout=600)
    try:
        veri = json.loads(cikti.read_text())
    except (OSError, ValueError):
        return {"dizin": str(dizin), "olculmedi": f"acma_gecikmesi çıkış {p.returncode}: {p.stderr[-300:]}"}
    veri["dizin"] = str(dizin)
    return veri


def basvuru_dizini(kok: Path = ACMA_BASVURU) -> Path:
    """Başvuru açma dizini: verilen koşunun ``decompiled/`` dizini (tek çalışma alanı)."""
    adaylar = sorted(kok.glob("ws/workspaces/*/*/static/ghidra_output/decompiled"))
    return adaylar[-1] if adaylar else kok


def kendi_decompiled(kok: Path) -> Path | None:
    adaylar = sorted(kok.glob("ws/workspaces/*/*/static/ghidra_output/decompiled"))
    return adaylar[-1] if adaylar else None


def izle(pid: int, kok: Path, aralik: float, acma_dizini: Path, en_uzun_sn: float,
         n: int = ACMA_N) -> dict[str, Any]:
    t0 = time.monotonic()
    sonuc: dict[str, Any] = {"pid": pid, "kok": str(kok), "aralik_sn": aralik, "baslangic": _simdi(),
                             "donanim_bas": donanim_kunyesi(),
                             "acma_bas": acma_olc(acma_dizini, kok / "hz0_acma_bas.json", n)}
    ornekler = []
    while yasiyor(pid) and time.monotonic() - t0 < en_uzun_sn:
        ip = is_parcaciklari(pid)
        if ip is None:
            break
        ip.sort(key=lambda r: -(r["sistem_sn"] + r["kullanici_sn"]))
        toplam = sum(r["sistem_sn"] + r["kullanici_sn"] for r in ip)
        ornekler.append({"gecen_sn": round(time.monotonic() - t0, 1), "zaman": _simdi(),
                         "is_parcacigi": len(ip), "toplam_islemci_sn": round(toplam, 2),
                         "ilk": ip[:ILK_N]})
        bitis = time.monotonic() + aralik
        while time.monotonic() < bitis and yasiyor(pid):
            time.sleep(min(1.0, aralik))
    sonuc["ornekler"] = ornekler
    sonuc["izleme_sn"] = round(time.monotonic() - t0, 1)
    sonuc["sure_siniri_doldu"] = time.monotonic() - t0 >= en_uzun_sn
    sonuc["acma_son_basvuru"] = acma_olc(acma_dizini, kok / "hz0_acma_son_basvuru.json", n)
    kendi = kendi_decompiled(kok)
    sonuc["acma_son_kendi"] = (acma_olc(kendi, kok / "hz0_acma_son_kendi.json", n) if kendi
                               else {"olculmedi": "koşunun decompiled/ dizini yok"})
    sonuc["yuk_son"] = list(os.getloadavg())
    sonuc["bitis"] = _simdi()
    return sonuc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pid", type=int, required=True, help="izlenecek süreç (karadul)")
    ap.add_argument("--kok", type=Path, required=True, help="olcek_kos koşu kökü")
    ap.add_argument("--aralik", type=float, default=PS_ARALIK_SN)
    ap.add_argument("--acma-dizini", type=Path, default=None,
                    help="başvuru açma dizini (öntanım: geliştirme setindeki mac/tmux decompiled/)")
    ap.add_argument("--n", type=int, default=ACMA_N)
    ap.add_argument("--en-uzun-sn", type=float, default=6 * 3600.0, help="izleme üst sınırı")
    ap.add_argument("--cikti", type=Path, default=None, help="öntanım <kök>/hz0_ek.json")
    a = ap.parse_args(argv)
    kok = a.kok.expanduser().resolve()
    acma = a.acma_dizini.expanduser() if a.acma_dizini else basvuru_dizini()
    sonuc = izle(a.pid, kok, a.aralik, acma, a.en_uzun_sn, a.n)
    cikti = a.cikti or (kok / "hz0_ek.json")
    cikti.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[hz0_ek] {len(sonuc['ornekler'])} örnek, {sonuc['izleme_sn']} sn → {cikti}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
