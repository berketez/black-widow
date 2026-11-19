#!/usr/bin/env python3
"""HIZ kalem 4 ek (Berke, 2026-11-19 "tek işlemci için değil, genel"): bugünkü donanım
türetmesi farklı makinelerde ne verir?

Ürünün KENDİ işlevleri çağrılır (``karadul/config.py`` ``_detect_cpu_cores``,
``_detect_available_memory_mb``); işletim sistemi yanıtları yamalanır (``os.cpu_count``,
``os.sysconf``, ``safe_run`` ile ``sysctl``, cgroup sınırı). Yığın formülü kopyalanmaz:
``config.py``'deki ``GHIDRA_HEAP_MB = ...`` satırının sağ yanı kaynak dosyadan okunup
değerlendirilir. Tüketicilerin formülleri (işçi sayıları) dosya:satır ile aşağıda; onlar
kaynaktan okunamayacak kadar dağınık olduğu için elle yazıldı ve satırları belirtildi.

İsteğe bağlı ``--java``: verilen JDK ile ``-Xmx<tavan>m`` için ``UseCompressedOops``'un
gerçek değeri (``-XX:+PrintFlagsFinal -version``; yalnız JVM bayrak dökümü, iş yok).

Kullanım (depo kökünden):
    python scripts/arge/hiz/donanim_turetme.py \
        --java /opt/homebrew/Cellar/openjdk@21/21.0.13.1/libexec/openjdk.jdk/Contents/Home/bin/java \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/donanim_turetme.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

GIB = 1024 ** 3

# (ad, os, ncpu, perflevel0 mantıksal | None, perflevel1 | None, bellek GiB, cgroup MiB | None)
PROFILLER = [
    ("bugün: M4 Max 10+4, 36 GB (ölçüm makinesi)", "darwin", 14, 10, 4, 36, None),
    ("M serisi giriş: 4+4, 8 GB", "darwin", 8, 4, 4, 8, None),
    ("M serisi giriş: 4+6, 16 GB", "darwin", 10, 4, 6, 16, None),
    ("M serisi üst: 16+4, 128 GB", "darwin", 20, 16, 4, 128, None),
    ("M serisi Ultra: 24+8, 192 GB", "darwin", 32, 24, 8, 192, None),
    ("Intel Mac (verim çekirdeği yok): 8 çekirdek / 16 iş parçacığı, 32 GB", "darwin", 16, None, None, 32, None),
    ("Linux x86, verim çekirdeği yok: 16 iş parçacığı, 32 GB", "linux", 16, None, None, 32, None),
    ("Linux melez Intel: 8P(16 i.p.)+16E = 32 mantıksal, 64 GB", "linux", 32, None, None, 64, None),
    ("Linux kapsayıcı: ana makine 64 i.p., cgroup 8 GiB", "linux", 64, None, None, 256, 8192),
    ("Windows: 32 mantıksal (ör. i9-14900HX), 32 GB", "win32", 32, None, None, 32, None),
]


def _heap_ifadesi(config_py: Path) -> str:
    for s in config_py.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^GHIDRA_HEAP_MB\s*=\s*(.+?)\s*(#.*)?$", s)
        if m:
            return m.group(1)
    raise SystemExit("GHIDRA_HEAP_MB satırı bulunamadı")


def benzet(cfgmod, profil) -> dict:
    ad, plat, ncpu, p0, p1, mem_gib, cg = profil

    def fake_safe_run(cmd, **kw):
        key = cmd[-1]
        if key == "hw.perflevel0.logicalcpu" and plat == "darwin" and p0 is not None:
            return SimpleNamespace(returncode=0, stdout="%d\n" % p0)
        if key == "hw.memsize" and plat == "darwin":
            return SimpleNamespace(returncode=0, stdout="%d\n" % (mem_gib * GIB))
        return SimpleNamespace(returncode=1, stdout="")

    def fake_resolve(name, **kw):
        if plat == "win32":
            return None
        return "/usr/sbin/sysctl"

    page = 16384 if plat == "darwin" else 4096

    def fake_sysconf(name):
        if plat == "win32":
            raise AttributeError("os.sysconf yok (Windows)")
        if name == "SC_PAGE_SIZE":
            return page
        if name == "SC_PHYS_PAGES":
            return mem_gib * GIB // page
        raise ValueError(name)

    import karadul.core.safe_subprocess as ss
    with mock.patch("os.cpu_count", return_value=ncpu), \
            mock.patch("os.sysconf", side_effect=fake_sysconf), \
            mock.patch.object(ss, "safe_run", side_effect=fake_safe_run), \
            mock.patch.object(ss, "resolve_tool", side_effect=fake_resolve), \
            mock.patch.object(cfgmod, "_read_cgroup_memory_limit_mb", return_value=cg):
        P = cfgmod._detect_cpu_cores()
        M = cfgmod._detect_available_memory_mb()
    return {"ad": ad, "os": plat, "ncpu": ncpu, "p0": p0, "p1": p1, "bellek_gib": mem_gib,
            "cgroup_mib": cg, "CPU_PERF_CORES": P, "TOTAL_MEMORY_MB": M}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--java", type=Path)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    sys.path.insert(0, str(Path.cwd()))
    import karadul.config as cfgmod
    ifade = _heap_ifadesi(Path(cfgmod.__file__))
    print("config.py yığın ifadesi:", ifade)
    print()
    print("| Profil | ncpu | perflevel0 / 1 | bellek | CPU_PERF_CORES | TOTAL_MEMORY_MB | GHIDRA_HEAP_MB (belleğin %) | decompile iş parçacığı | JVM ActiveProcessorCount | c_namer süreç | c_type_recoverer süreç | struct çözücü süreç | istihbarat süreç (≥10 iş) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    out = []
    for prof in PROFILLER:
        r = benzet(cfgmod, prof)
        P, M = r["CPU_PERF_CORES"], r["TOTAL_MEMORY_MB"]
        heap = eval(ifade, {"max": max, "min": min, "int": int}, {"TOTAL_MEMORY_MB": M})
        gercek_mb = (r["cgroup_mib"] if r["cgroup_mib"] else r["bellek_gib"] * 1024)
        r["GHIDRA_HEAP_MB"] = heap
        r["heap_gercek_bellek_orani"] = heap / gercek_mb
        # Tüketiciler (dosya:satır):
        r["decompile_is_parcacigi"] = P                     # headless.py:1151-1169, 1260
        r["jvm_active_processor_count"] = max(2, P)         # headless.py:68, 81
        r["c_namer_surec"] = min(P, r["ncpu"] or P)         # c_namer.py:2247
        r["c_type_recoverer_surec"] = r["ncpu"] or P        # c_type_recoverer.py:1330, 1455
        r["struct_cozucu_surec"] = max(1, min(P, 10))       # solver.py:41, 678-681
        r["istihbarat_surec"] = 10                          # binary_intelligence.py:2181 min(10, iş)
        out.append(r)
        print("| %s | %d | %s / %s | %s GiB%s | %d | %d | %d (%%%.0f) | %d | %d | %d | %d | %d | %d |" % (
            r["ad"], r["ncpu"], r["p0"], r["p1"], r["bellek_gib"],
            " (cgroup %d MiB)" % r["cgroup_mib"] if r["cgroup_mib"] else "",
            P, M, heap, 100 * r["heap_gercek_bellek_orani"], r["decompile_is_parcacigi"],
            r["jvm_active_processor_count"], r["c_namer_surec"], r["c_type_recoverer_surec"],
            r["struct_cozucu_surec"], r["istihbarat_surec"]))
    sonuc = {"heap_ifadesi": ifade, "profiller": out}
    if a.java:
        print()
        print("JVM sıkıştırılmış göstericiler (UseCompressedOops gerçek değeri):")
        sonuc["oops"] = {}
        for xmx in (31744, 32767, 32768):
            p = subprocess.run([str(a.java), "-Xmx%dm" % xmx, "-XX:+UseCompressedOops",
                                "-XX:+PrintFlagsFinal", "-version"], capture_output=True, text=True)
            m = re.search(r"bool UseCompressedOops\s*=\s*(\w+)", p.stdout)
            uyari = [l for l in p.stderr.splitlines() if "Compressed" in l or "compressed" in l]
            sonuc["oops"][xmx] = {"UseCompressedOops": m.group(1) if m else None, "uyari": uyari}
            print("  -Xmx%dm → UseCompressedOops=%s %s" % (xmx, m.group(1) if m else "?", uyari[:1]))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
