"""Tek fonksiyon yolunun Ghidra maliyeti: proje saklanmadığında (macho.py:937 cleanup) tek bir
fonksiyonu yeniden derlemek için bütün ikili yeniden içe aktarılıp çözümlenmek zorunda.

Ölçülen (ürünle aynı çağrı: pyghidra.open_program(analyze=True), headless.py:249-254):
  1. JVM başlatma süresi
  2. İçe aktarma + otomatik çözümleme süresi (open_program)
  3. DecompInterface.openProgram süresi
  4. 30 fonksiyonun tek tek derlenme süresi (ürünün varsayılan seçenekleri, 30 sn zaman aşımı;
     headless.py:919, 996-1007)
Ghidra projesi deney dizinine yazılır ve sonunda silinir; saklı koşulara dokunulmaz.
JVM yığını 4 GB ile sınırlanır (ana oturumda başka Ghidra koşuları var).

Örneklem (önceden yazıldı): FunctionManager.getFunctions(True) sırası (adres sırası);
random.Random(20261111).sample(fonksiyonlar, 30).

Kullanım: python tek_fonksiyon_maliyet.py <ikili> <deney_dizini> <çıktı.json>
"""

from __future__ import annotations

import json
import os
import random
import shutil
import sys
import time
from pathlib import Path

SEED = 20261111
SAMPLE = 30
GHIDRA = Path(os.environ.get("GHIDRA_INSTALL_DIR",
                             str(Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC")))


def main() -> None:
    binary, workdir, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    proj = workdir / "ghidra_proj"
    if proj.exists():
        shutil.rmtree(proj)
    proj.mkdir(parents=True)
    res: dict = {"binary": str(binary), "size_bytes": binary.stat().st_size,
                 "load_avg_start": os.getloadavg()}

    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    t0 = time.monotonic()
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA)
    launcher.add_vmargs("-Djava.awt.headless=true", "-XX:+UseG1GC", "-Xmx4096m")
    launcher.start()
    res["jvm_start_s"] = round(time.monotonic() - t0, 2)

    t1 = time.monotonic()
    with pyghidra.open_program(binary_path=str(binary), project_location=str(proj),
                               project_name="tek_fonksiyon", analyze=True) as flat_api:
        res["import_and_analyze_s"] = round(time.monotonic() - t1, 2)
        program = flat_api.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        fm = program.getFunctionManager()
        funcs = []
        it = fm.getFunctions(True)
        while it.hasNext():
            funcs.append(it.next())
        res["functions"] = len(funcs)
        sample = random.Random(SEED).sample(funcs, min(SAMPLE, len(funcs)))
        t2 = time.monotonic()
        decomp = DecompInterface()
        decomp.setOptions(DecompileOptions())
        decomp.openProgram(program)
        res["decomp_open_s"] = round(time.monotonic() - t2, 3)
        mon = ConsoleTaskMonitor()
        rows = []
        for f in sample:
            t3 = time.monotonic()
            r = decomp.decompileFunction(f, 30, mon)
            ok = bool(r is not None and r.getDecompiledFunction() is not None)
            rows.append({"name": str(f.getName()), "address": str(f.getEntryPoint()),
                         "size": int(f.getBody().getNumAddresses()), "ok": ok,
                         "seconds": round(time.monotonic() - t3, 4)})
        decomp.dispose()
        secs = sorted(r["seconds"] for r in rows)
        res["decompile_sample"] = {"n": len(rows), "ok": sum(r["ok"] for r in rows),
                                   "median_s": secs[len(secs) // 2], "max_s": secs[-1],
                                   "rows": rows}
    # Proje saklansaydı: disk boyutu ve çözümlemesiz yeniden açma + tek fonksiyon derleme süresi
    res["project_bytes"] = sum(p.stat().st_size for p in proj.rglob("*") if p.is_file())
    t4 = time.monotonic()
    with pyghidra.open_program(binary_path=str(binary), project_location=str(proj),
                               project_name="tek_fonksiyon", analyze=False) as flat_api:
        res["reopen_saved_project_s"] = round(time.monotonic() - t4, 3)
        program = flat_api.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        res["reopen_functions"] = int(program.getFunctionManager().getFunctionCount())
        t5 = time.monotonic()
        decomp = DecompInterface()
        decomp.setOptions(DecompileOptions())
        decomp.openProgram(program)
        f = program.getFunctionManager().getFunctionAt(
            program.getAddressFactory().getAddress(res["decompile_sample"]["rows"][0]["address"]))
        r = decomp.decompileFunction(f, 30, ConsoleTaskMonitor())
        res["reopen_one_function_s"] = round(time.monotonic() - t5, 3)
        res["reopen_one_function_ok"] = bool(r is not None and r.getDecompiledFunction() is not None)
        decomp.dispose()
    res["load_avg_end"] = os.getloadavg()
    shutil.rmtree(proj, ignore_errors=True)
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "decompile_sample"}),
          json.dumps({k: v for k, v in res["decompile_sample"].items() if k != "rows"}))


if __name__ == "__main__":
    main()
