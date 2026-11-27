"""GS-1 ek ölçüm (ön kayıt dışı; hüküm değil): JVM ``-Xrs`` ile başlatılırsa takılı düzenli ifadedeki süreç
SIGTERM'le ölür mü?

``karadul`` içe aktarılmaz: JVM, ürünün ``_ensure_pyghidra_started``'ındaki VM argümanlarıyla
``pyghidra.launcher.HeadlessPyGhidraLauncher``'dan başlatılır (yığın küçük: 1 GB), ``--xrs`` verilirse
``-Xrs`` eklenir. Çocuk ``sigterm_olc.py``'nin işaret dökümünü kullanır. Ghidra JVM'ini başlattığı için
``ghidra_kuyruk.sh`` ile koşulur.

python scripts/arge/gs1/xrs_olc.py surucu --cikti <json>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
import sigterm_olc  # noqa: E402

GHIDRA = Path(os.environ.get("GHIDRA_INSTALL_DIR")
              or Path.home() / "Library" / "BlackWidowBuild" / "ghidra_12.1.2_PUBLIC")


def cocuk(xrs: bool) -> None:
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA)
    vm = ["-Djava.awt.headless=true", "-XX:+UseG1GC", "-Xmx1024m"]
    if xrs:
        vm.append("-Xrs")
    launcher.add_vmargs(*vm)
    launcher.start()
    print(json.dumps({"xrs": xrs, "isleyiciler": sigterm_olc.isleyici_dokumu()}, ensure_ascii=False), flush=True)
    print("HAZIR", flush=True)
    re.compile(sigterm_olc.ESKI_KALIP).search(sigterm_olc.YAPAY_SATIR)
    print("ESLESME_DONDU", flush=True)


def olc(xrs: bool, bekle: float) -> dict:
    arg = ["--xrs"] if xrs else []
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "cocuk", *arg],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, process_group=0)
    dokum = None
    for satir in proc.stdout:
        s = satir.decode(errors="replace").strip()
        if s.startswith("{"):
            dokum = json.loads(s)
        if s == "HAZIR":
            break
    time.sleep(1.0)
    t0 = time.monotonic()
    os.kill(proc.pid, signal.SIGTERM)
    try:
        rc = proc.wait(timeout=bekle)
        olum = round(time.monotonic() - t0, 3)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        rc = proc.wait()
        olum = None
    return {"xrs": xrs, "sigterm_ile_oldu": olum is not None, "olum_sn": olum, "donus_kodu": rc,
            "sigterm_c": (dokum or {}).get("isleyiciler", {}).get("SIGTERM")}


def main() -> None:
    ap = argparse.ArgumentParser()
    alt = ap.add_subparsers(dest="kip", required=True)
    s = alt.add_parser("surucu")
    s.add_argument("--cikti", required=True)
    s.add_argument("--bekle", type=float, default=15.0)
    c = alt.add_parser("cocuk")
    c.add_argument("--xrs", action="store_true")
    a = ap.parse_args()
    if a.kip == "cocuk":
        cocuk(a.xrs)
        return
    sonuc = [olc(False, a.bekle), olc(True, a.bekle)]
    for r in sonuc:
        print(json.dumps(r, ensure_ascii=False), flush=True)
    uptime = subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True).stdout.strip()
    Path(a.cikti).write_text(json.dumps({"uptime": uptime, "sonuclar": sonuc}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
