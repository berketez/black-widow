"""G8 ortak yardımcılar: yollar, künye, JVM başlatma, proje açma, decompile.

Bütün betikler `/opt/anaconda3/bin/python3 -I -B <betik>` ile çalıştırılır:
-I çıkarılmış kaynak arşivini okurken yerel modül gölgelemesini önler,
-B depoya bayt kodu yazmaz (başka ajanların mutant sınamalarını bozmamak için).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

DEPO = Path("/Users/apple/Black_Widow")
BELGE = DEPO / "docs/arge/2026-10-19_g8_geri_yazma"
W = DEPO / "workspaces/2026-10-19_g8"
VERI = W / "veri"
PROJELER = W / "projeler"
CIKTILAR = W / "ciktilar"
GHIDRA = Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC"
STRIP_TMUX = DEPO / "workspaces/2026-10-15_oturum_scratchpad/macho/apple_strip/tmux"
ORIG_TMUX = DEPO / "workspaces/2026-10-15_oturum_scratchpad/macho/orig/tmux"
TMUX_SRC = W / "src/tmux-3.8"
BUILD_G = W / "build_g"

PROJE_ADI = "g8"
PROGRAM_ADI = "tmux"
HEAP_MB = 6144          # görev kuralı: JVM yığını en fazla 8 GB
FUNC_TIMEOUT = 30       # Karadul ile aynı: headless.py _decompile_functions FUNC_TIMEOUT

if str(BELGE) not in sys.path:
    sys.path.insert(0, str(BELGE))


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blok in iter(lambda: f.read(1 << 20), b""):
            h.update(blok)
    return h.hexdigest()


def ghidra_surumu() -> dict:
    props = {}
    for satir in (GHIDRA / "Ghidra/application.properties").read_text().splitlines():
        if "=" in satir and not satir.startswith("#"):
            k, v = satir.split("=", 1)
            props[k.strip()] = v.strip()
    return {
        "application.version": props.get("application.version"),
        "application.release.name": props.get("application.release.name"),
        "application.revision.ghidra": props.get("application.revision.ghidra"),
        "kurulum": str(GHIDRA),
    }


def kunye() -> dict:
    """Her çıktıya yazılan koşu künyesi."""
    try:
        commit = subprocess.run(["git", "-C", str(DEPO), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as exc:  # pragma: no cover
        commit = f"okunamadı: {exc}"
    try:
        import pyghidra
        pyg = pyghidra.__version__
    except Exception:
        pyg = None
    return {
        "zaman": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "depo_commit": commit,
        "ghidra": ghidra_surumu(),
        "pyghidra": pyg,
        "python": sys.version.split()[0],
        "makine": platform.platform(),
        "girdi_strip_sha256": sha256(STRIP_TMUX),
        "girdi_orig_sha256": sha256(ORIG_TMUX),
        "jvm_heap_mb": HEAP_MB,
        "decompile_zaman_asimi_sn": FUNC_TIMEOUT,
    }


def jvm_baslat() -> None:
    """Karadul'un `_ensure_pyghidra_started` fonksiyonuyla JVM'i headless başlatır.

    Fonksiyon yığın boyutunu çağrı anında `karadul.config.GHIDRA_HEAP_MB`'den okur;
    bu süreçte 8 GB sınırı için o değer HEAP_MB'ye çekilir (karadul koduna dokunulmaz).
    """
    if str(DEPO) not in sys.path:
        sys.path.insert(0, str(DEPO))
    import karadul.config as kc
    kc.GHIDRA_HEAP_MB = HEAP_MB
    from karadul.ghidra.headless import _ensure_pyghidra_started
    _ensure_pyghidra_started(GHIDRA)
    from java.lang import Runtime  # type: ignore
    maks = Runtime.getRuntime().maxMemory() // (1024 * 1024)
    if maks > 8192:
        raise RuntimeError(f"JVM yığını {maks} MB; sınır 8192 MB")


def proje_ac(konum: Path):
    """(GhidraProject, Program) döndürür; program yazılabilir açılır."""
    from ghidra.base.project import GhidraProject  # type: ignore
    proje = GhidraProject.openProject(str(konum), PROJE_ADI, True)
    program = proje.openProgram("/", PROGRAM_ADI, False)
    return proje, program


def proje_kopyala(kaynak: Path, hedef: Path) -> None:
    if hedef.exists():
        raise FileExistsError(f"{hedef} zaten var; elle silinmeden üstüne yazılmaz")
    hedef.mkdir(parents=True)
    for ad in (f"{PROJE_ADI}.gpr", f"{PROJE_ADI}.rep"):
        k = kaynak / ad
        if k.is_dir():
            shutil.copytree(k, hedef / ad)
        else:
            shutil.copy2(k, hedef / ad)


class Decompiler:
    """Karadul'un ayarlarıyla decompile: DecompileOptions() varsayılanı, 30 sn sınır."""

    def __init__(self, program):
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
        self.program = program
        self.ifc = DecompInterface()
        self.ifc.setOptions(DecompileOptions())
        if not self.ifc.openProgram(program):
            raise RuntimeError("DecompInterface.openProgram başarısız: " + str(self.ifc.getLastMessage()))
        self.monitor = ConsoleTaskMonitor()

    def c(self, func) -> tuple[str | None, float, str]:
        """(C metni ya da None, süre sn, hata iletisi)."""
        t0 = time.perf_counter()
        res = self.ifc.decompileFunction(func, FUNC_TIMEOUT, self.monitor)
        sure = time.perf_counter() - t0
        df = res.getDecompiledFunction() if res is not None else None
        if df is None:
            msg = res.getErrorMessage() if res is not None else "sonuç yok"
            return None, sure, str(msg)
        return str(df.getC()), sure, ""

    def kapat(self):
        self.ifc.dispose()


def adres(program, hex_adres: str):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(hex_adres, 16))


def json_yaz(p: Path, veri) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(veri, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)
