#!/usr/bin/env python3
"""HIZ kalem 4 (JPype geçişi): Python ↔ Java geçişinin maliyeti, Ghidra'sız.

Ürünle aynı JPype ve aynı JDK (``--jvm`` ile libjvm yolu) kullanılır; Ghidra yüklenmez.
Ölçülen: geçiş başına duvar süresi (µs), JVM iş parçacığı başına işlemci süresi
(``ThreadMXBean``; "Python Reference Queue" adıyla), Python çöp toplayıcı sayaçları.

Kalıplar (Ghidra döküm döngülerinin biçimi):
  A  ilkel dönüşlü statik çağrı (Math.abs)             — sarmalayıcı yok
  B  Java nesnesi dönen çağrı + nesnede yöntem           — her adımda yeni sarmalayıcı
  C  yineleyici: hasNext / next / nesnede yöntem         — `_extract_cfg` komut döngüsü biçimi
  D  Java nesnesinin str()'ı                             — adres / ad metne çevirme biçimi
Koşullar:
  0  temiz süreç
  1  büyük canlı Python yığını (``--yigin`` milyon küçük sözlük; döküm sözlüklerinin benzeri)
  2  aynı yığın + ``gc.freeze()`` (döngüsel çöp toplayıcı yığını taramaz)
  3  çok sayıda canlı Java sarmalayıcısı Python'da tutulurken (``--canli`` milyon)

Kullanım:
    python scripts/arge/hiz/jpype_gecis.py --jvm <libjvm.dylib> --n 1000000 --yigin 5 --canli 1 \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/jpype_gecis.json
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import time
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jvm", required=True)
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--yigin", type=float, default=5.0, help="milyon sözlük")
    ap.add_argument("--canli", type=float, default=1.0, help="milyon canlı Java sarmalayıcısı")
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()

    import jpype
    import jpype.imports  # noqa: F401  (java.* içe aktarımı)
    jpype.startJVM(a.jvm, "-Xmx2g", "-XX:+UseG1GC", "-Djava.awt.headless=true")
    from java.lang import Math, Integer  # noqa: E402
    from java.util import ArrayList  # noqa: E402
    from java.lang.management import ManagementFactory  # noqa: E402

    mx = ManagementFactory.getThreadMXBean()

    def thread_cpu() -> dict[str, float]:
        out: dict[str, float] = {}
        for tid in mx.getAllThreadIds():
            info = mx.getThreadInfo(tid)
            if info is None:
                continue
            ns = mx.getThreadCpuTime(tid)
            if ns >= 0:
                out[str(info.getThreadName())] = out.get(str(info.getThreadName()), 0.0) + ns / 1e9
        return out

    N = a.n
    lst = ArrayList()
    for i in range(20000):
        lst.add(Integer.valueOf(i))
    m = lst.size()

    def kalip_A():
        s = 0
        for i in range(N):
            s += Math.abs(i)
        return N  # 1 geçiş / adım

    def kalip_B():
        for i in range(N):
            o = lst.get(i % m)
            o.hashCode()
        return 2 * N

    def kalip_C():
        say = 0
        while say < N:
            it = lst.iterator()
            while it.hasNext() and say < N:
                o = it.next()
                o.hashCode()
                say += 1
        return 3 * N

    def kalip_D():
        for i in range(N):
            str(lst.get(i % m))
        return 2 * N

    kaliplar = {"A": kalip_A, "B": kalip_B, "C": kalip_C, "D": kalip_D}

    def kos(etiket: str) -> list[dict]:
        sat = []
        for ad, fn in kaliplar.items():
            gc_once = [s["collections"] for s in gc.get_stats()]
            t_once = thread_cpu()
            t0, c0 = time.perf_counter(), time.process_time()
            gecis = fn()
            dt = time.perf_counter() - t0
            dc = time.process_time() - c0
            t_sonra = thread_cpu()
            gc_sonra = [s["collections"] for s in gc.get_stats()]
            rq = t_sonra.get("Python Reference Queue", 0.0) - t_once.get("Python Reference Queue", 0.0)
            gc_es = sum(t_sonra.get(k, 0.0) - t_once.get(k, 0.0) for k in t_sonra if k.startswith("GC Thread") or k.startswith("G1"))
            r = {"kosul": etiket, "kalip": ad, "gecis": gecis, "duvar_sn": dt, "surec_islemci_sn": dc,
                 "us_gecis": 1e6 * dt / gecis, "ref_queue_sn": rq, "jvm_gc_is_parcacigi_sn": gc_es,
                 "py_gc_toplama": [b - a_ for a_, b in zip(gc_once, gc_sonra)]}
            sat.append(r)
            print("| %s | %s | %.2f | %.3f | %.3f | %.3f | %s |" % (
                etiket, ad, r["us_gecis"], dt, rq, gc_es, r["py_gc_toplama"]))
        return sat

    print("JVM:", a.jvm)
    print("| koşul | kalıp | µs / geçiş | duvar sn | Reference Queue işlemci sn | JVM GC iş parçacığı sn | Python gc toplama (gen0,1,2) |")
    print("|---|---|---|---|---|---|---|")
    sonuc = {"python": platform.python_version(), "jpype": jpype.__version__, "jvm": a.jvm, "n": N,
             "satirlar": []}
    sonuc["satirlar"] += kos("0 temiz")
    yigin = [{"a": i, "b": str(i), "c": [i]} for i in range(int(a.yigin * 1e6))]
    sonuc["satirlar"] += kos("1 yığın %.0fM sözlük" % a.yigin)
    gc.freeze()
    sonuc["satirlar"] += kos("2 yığın + gc.freeze")
    gc.unfreeze()
    del yigin
    gc.collect()
    canli = [lst.get(i % m) for i in range(int(a.canli * 1e6))]
    sonuc["satirlar"] += kos("3 canlı sarmalayıcı %.1fM" % a.canli)
    del canli
    gc.collect()
    son = thread_cpu()
    sonuc["is_parcacigi_toplam"] = dict(sorted(son.items(), key=lambda kv: -kv[1])[:12])
    print("\nJVM iş parçacığı işlemci (toplam, ilk 8):")
    for k, v in list(sonuc["is_parcacigi_toplam"].items())[:8]:
        print("  %-32s %.2f sn" % (k, v))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
