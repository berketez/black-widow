"""GS-1 hüküm 7: C düzeyinde takılı bir düzenli ifadedeyken süreç SIGTERM'le ölüyor mu?

Ürün kodu değişmeden, ayrı çocuk süreçlerde ölçer. Her koşulda çocuk önce işaret işleyicilerinin
dökümünü (Python düzeyi ``signal.getsignal`` + C düzeyi ``sigaction``; işleyici adresi ``dladdr``
ile kitaplık / simge adına çevrilir) tek satır JSON olarak yazar, ``HAZIR`` satırını basar ve ana iş
parçacığında üstel geri izleyen düzenli ifadeye girer (BA-1'in eski ``memmove`` kalıbı, yapay girdi:
üçüncü argüman 60 karakter, kapanan ayraç yok; 32 karakterde 20 sn'de bitmiyordu). Sürücü ``HAZIR``'dan
1 sn sonra SIGTERM gönderir, ``--bekle`` saniye ölümü bekler; ölmezse SIGKILL ile kapatır.

Koşullar:
  a  yalın Python (yalnız ``re``)
  b  ``karadul analyze``'ın kurduğu işleyiciler: ``karadul.cli.main`` grubu gerçekten koşulur
     (``analyze --help``; grup geri çağrısı işleyicileri kurar), analizin içe aktardığı modüller yüklenir
  c  b + süreç içi JVM, ürünün yolundan (``karadul.ghidra.headless._ensure_pyghidra_started``);
     Ghidra JVM'i başlatır (analiz yok): ``ghidra_kuyruk.sh`` ile koşulur
  d  denetim: yalın Python + Python düzeyinde bir SIGTERM işleyicisi (``signal.signal``)
  e  denetim: c'nin aynısı ama düzenli ifade yerine ``time.sleep`` (ana iş parçacığı GIL'i bırakır)

``--ornekle``: SIGTERM'den 3 sn sonra süreç hâlâ yaşıyorsa ``/usr/bin/sample`` ile 2 sn yerel yığın
örneklemi alınır (hangi iş parçacığı nerede bekliyor).

Kullanım (depo kökünden):
  python scripts/arge/gs1/sigterm_olc.py surucu --kosul a b d --cikti <json>
  ~/karadul_olcum/ghidra_kuyruk.sh GS1 h7:c python scripts/arge/gs1/sigterm_olc.py surucu --kosul c --cikti <json>
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import io
import json
import os
import re
import signal
import subprocess
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

DEPO_KOKU = Path(__file__).resolve().parents[3]
# BA-1'in onarımdan önceki kalıbı (``git show 0b4d948:karadul/reconstruction/engineering/block_annotator.py``).
ESKI_KALIP = r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
YAPAY_SATIR = "memmove(a,b," + "x," * 30  # kapanan ayraç yok
IZLENEN_ISARETLER = ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2")
GHIDRA_ONTANIM = Path.home() / "Library" / "BlackWidowBuild" / "ghidra_12.1.2_PUBLIC"


class _Sigaction(ctypes.Structure):
    # macOS ``struct sigaction``: işleyici birliği (işaretçi), ``sigset_t`` (uint32), ``int sa_flags``
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_uint32), ("flags", ctypes.c_int)]


class _DlInfo(ctypes.Structure):
    _fields_ = [("dli_fname", ctypes.c_char_p), ("dli_fbase", ctypes.c_void_p),
                ("dli_sname", ctypes.c_char_p), ("dli_saddr", ctypes.c_void_p)]


def _c_isleyici(libc: ctypes.CDLL, isaret: int) -> dict:
    eski = _Sigaction()
    if libc.sigaction(isaret, None, ctypes.byref(eski)) != 0:
        return {"hata": "sigaction %d" % ctypes.get_errno()}
    adres = eski.handler or 0
    if adres == 0:
        return {"tur": "SIG_DFL"}
    if adres == 1:
        return {"tur": "SIG_IGN"}
    bilgi = _DlInfo()
    kayit: dict = {"tur": "isleyici", "bayraklar": eski.flags}
    if libc.dladdr(ctypes.c_void_p(adres), ctypes.byref(bilgi)):
        kayit["kitaplik"] = os.path.basename((bilgi.dli_fname or b"").decode(errors="replace"))
        kayit["simge"] = (bilgi.dli_sname or b"").decode(errors="replace") or None
    return kayit


def isleyici_dokumu() -> dict:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    dokum: dict = {}
    for ad in IZLENEN_ISARETLER:
        no = getattr(signal, ad)
        py = signal.getsignal(no)
        if py is signal.SIG_DFL:
            py_ad = "SIG_DFL"
        elif py is signal.SIG_IGN:
            py_ad = "SIG_IGN"
        elif py is None:
            py_ad = "None (Python dışında kurulmuş)"
        else:
            py_ad = "%s.%s" % (getattr(py, "__module__", "?"), getattr(py, "__qualname__", repr(py)))
        dokum[ad] = {"python": py_ad, "c": _c_isleyici(libc, no)}
    return dokum


def _kosul_kur(kosul: str) -> dict:
    ek: dict = {}
    if kosul in ("b", "c", "e"):
        sys.path.insert(0, str(DEPO_KOKU))
        os.chdir(DEPO_KOKU)
        import karadul  # noqa: F401
        ek["karadul_dosyasi"] = karadul.__file__
        from karadul.cli import main
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            try:
                rc = main(["analyze", "--help"], standalone_mode=False)
            except SystemExit as exc:  # click sürümüne göre
                rc = exc.code
        ek["cli_cikis"] = rc
        ek["cli_yardim_satiri"] = len(tampon.getvalue().splitlines())
        # analizin içe aktardığı modüller (içe aktarma anında işleyici kuran var mı)
        import karadul.cli_common  # noqa: F401
        import karadul.core.pipeline  # noqa: F401
        import karadul.ghidra.headless  # noqa: F401
        import karadul.pipeline.runner  # noqa: F401
        import karadul.pipeline.steps  # noqa: F401
        import karadul.stages  # noqa: F401
    if kosul in ("c", "e"):
        from karadul.ghidra import headless
        kurulum = Path(os.environ.get("GHIDRA_INSTALL_DIR") or GHIDRA_ONTANIM)
        t0 = time.monotonic()
        headless._ensure_pyghidra_started(kurulum)
        import jpype
        ek["jvm_baslatma_sn"] = round(time.monotonic() - t0, 2)
        ek["jvm_basladi"] = bool(jpype.isJVMStarted())
        ek["ghidra"] = str(kurulum)
        try:
            from java.lang.management import ManagementFactory  # type: ignore
            ek["jvm_argumanlari"] = [str(a) for a in ManagementFactory.getRuntimeMXBean().getInputArguments()]
        except Exception as exc:  # pragma: no cover - yalnız künye
            ek["jvm_argumanlari_hata"] = repr(exc)
    if kosul == "d":
        def _isleyici(signum, frame):  # noqa: ANN001, ARG001
            os.write(2, b"PYTHON_ISLEYICISI_KOSTU\n")
            sys.exit(99)
        signal.signal(signal.SIGTERM, _isleyici)
    return ek


def cocuk(kosul: str) -> None:
    ek = _kosul_kur(kosul)
    kalip = re.compile(ESKI_KALIP)
    print(json.dumps({"kosul": kosul, "pid": os.getpid(), "pgid": os.getpgrp(),
                      "isleyiciler": isleyici_dokumu(), "ek": ek}, ensure_ascii=False), flush=True)
    print("HAZIR", flush=True)
    if kosul == "e":
        time.sleep(120)  # GIL bırakılır
        print("UYKU_BITTI", flush=True)
        return
    kalip.search(YAPAY_SATIR)  # üstel geri izleme: dönmez
    print("ESLESME_DONDU", flush=True)


def _olc(kosul: str, bekle: float, hazir_sinir: float, gunluk_dizini: Path,
         ornekle: bool = False) -> dict:
    stderr_yolu = gunluk_dizini / ("cocuk_%s.stderr" % kosul)
    with open(stderr_yolu, "wb") as hata:
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "cocuk", kosul],
            cwd=str(DEPO_KOKU), stdout=subprocess.PIPE, stderr=hata, process_group=0,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        sonuc: dict = {"kosul": kosul, "pid": proc.pid}
        dokum = None
        t_bas = time.monotonic()
        assert proc.stdout is not None
        for satir in proc.stdout:
            metin = satir.decode(errors="replace").strip()
            if metin.startswith("{"):
                dokum = json.loads(metin)
            if metin == "HAZIR":
                break
            if time.monotonic() - t_bas > hazir_sinir:
                break
        sonuc["hazirlik_sn"] = round(time.monotonic() - t_bas, 2)
        sonuc["dokum"] = dokum
        if dokum is None or proc.poll() is not None:
            sonuc["hata"] = "çocuk hazır olmadı (rc=%s)" % proc.poll()
            proc.kill()
            proc.wait()
            return sonuc
        time.sleep(1.0)  # düzenli ifadenin içinde olsun
        sonuc["sigterm_oncesi_canli"] = proc.poll() is None
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        try:
            if ornekle:
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    orn = gunluk_dizini / ("ornek_%s.txt" % kosul)
                    subprocess.run(["/usr/bin/sample", str(proc.pid), "2", "-file", str(orn)],
                                   capture_output=True, timeout=60)
                    sonuc["ornek_dosyasi"] = str(orn)
            rc = proc.wait(timeout=max(0.1, bekle - (time.monotonic() - t0)))
            sonuc["sigterm_ile_oldu"] = True
            sonuc["olum_sn"] = round(time.monotonic() - t0, 3)
        except subprocess.TimeoutExpired:
            sonuc["sigterm_ile_oldu"] = False
            sonuc["olum_sn"] = None
            os.killpg(proc.pid, signal.SIGKILL)
            rc = proc.wait()
            sonuc["sigkill_sonrasi_sn"] = round(time.monotonic() - t0, 3)
        sonuc["donus_kodu"] = rc
        sonuc["donus_anlami"] = ("işaretle öldü: %s" % signal.Signals(-rc).name) if rc < 0 else (
            "çıkış kodu %d" % rc)
        kalan = proc.stdout.read().decode(errors="replace").strip() if proc.stdout else ""
        sonuc["kalan_stdout"] = kalan[-500:]
    sonuc["stderr_son"] = stderr_yolu.read_text(errors="replace")[-1500:]
    return sonuc


def surucu(args: argparse.Namespace) -> None:
    cikti = Path(args.cikti)
    cikti.parent.mkdir(parents=True, exist_ok=True)
    sonuclar = []
    for kosul in args.kosul:
        sonuc = _olc(kosul, args.bekle, args.hazir_sinir, cikti.parent, args.ornekle)
        sonuclar.append(sonuc)
        print("%s: SIGTERM ile öldü=%s olum_sn=%s rc=%s" % (
            kosul, sonuc.get("sigterm_ile_oldu"), sonuc.get("olum_sn"), sonuc.get("donus_kodu")), flush=True)
    kunye = {"tarih": time.strftime("%Y-%m-%dT%H:%M:%S"), "python": sys.version,
             "uptime": subprocess.run(["/usr/bin/uptime"], capture_output=True, text=True).stdout.strip(),
             "kalip": ESKI_KALIP, "girdi_uzunlugu": len(YAPAY_SATIR), "bekle_sn": args.bekle}
    cikti.write_text(json.dumps({"kunye": kunye, "sonuclar": sonuclar}, ensure_ascii=False, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    alt = ap.add_subparsers(dest="kip", required=True)
    s = alt.add_parser("surucu")
    s.add_argument("--kosul", nargs="+", default=["a", "b", "d"], choices=["a", "b", "c", "d", "e"])
    s.add_argument("--ornekle", action="store_true")
    s.add_argument("--cikti", required=True)
    s.add_argument("--bekle", type=float, default=15.0)
    s.add_argument("--hazir-sinir", type=float, default=180.0)
    c = alt.add_parser("cocuk")
    c.add_argument("kosul", choices=["a", "b", "c", "d", "e"])
    args = ap.parse_args()
    if args.kip == "surucu":
        surucu(args)
    else:
        cocuk(args.kosul)


if __name__ == "__main__":
    main()
