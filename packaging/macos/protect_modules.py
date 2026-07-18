#!/usr/bin/env python3
"""Black Widow motor koruma aracı — seçici Nuitka .so derleme + kaynak sıyırma.

Amaç
----
Bundle içindeki ``karadul`` paketini tersine mühendisliğe karşı sertleştir.
İki bağımsız katman:

* ``compile``  : mantık modüllerini Nuitka ``--module`` ile native ``.so``'ya
                 çevir (arm64 makine kodu — okumak için Ghidra + ciddi RE
                 emeği gerekir). Docstring/yorum ``--python-flag=no_docstrings``
                 ile silinir. Derlenen modülün ``.py``'si silinir.
* ``strip``    : geriye kalan (derlenmemiş) modüllerin ``.py`` kaynağını sil,
                 yalnız ``.pyc`` bırak. Bariyeri "metin editörü" → "3.12
                 decompiler" (henüz olgunlaşmamış) seviyesine çıkarır.

Build sırası (build_mac_app.sh içinde):
    1. karadul bundle'a kopyalanır
    2. protect_modules.py --phase compile   (BU — compileall'DAN ÖNCE)
    3. compileall  (kalan .py -> .pyc)
    4. protect_modules.py --phase strip      (BU — compileall'DAN SONRA)
    5. codesign + mühür

Neden bu sıra: ``strip`` (.py silme) compileall'DAN SONRA olmalı — yoksa .pyc
üretilmeden .py silinir, Python çalışma zamanında .pyc yazmaya çalışıp mührü
kırar. ``.so`` modüllerinde ne .py ne .pyc kalır → import .so'yu kullanır,
çalışma zamanı yazımı olmaz (mühür açısından .pyc'den DAHA güvenli).

ABI notu: Nuitka ``.so``'su ``-undefined dynamic_lookup`` ile derlenir, belirli
bir libpython'a hard-link ETMEZ → aynı ABI (cpython-312-darwin) tag'li her
CPython 3.12'de yüklenir. 3.12.7 ile derlenen .so, bundle'ın 3.12.13'ünde
çalıştığı ölçümle kanıtlandı (POC 2026-07-18).
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import sysconfig
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# Faz B (string şifreleme) — aynı dizindeki modül. protect_modules script olarak
# çalıştığından dizini sys.path[0]'da; doğrudan import edilir.
try:
    import encrypt_strings
except ImportError:  # pragma: no cover - script dışı kullanım
    encrypt_strings = None  # type: ignore

# --------------------------------------------------------------------------
# Politika: hangi modüller .so'ya derlenMEZ (kaynak sıyırma yine uygulanır)
# --------------------------------------------------------------------------
# __init__ / __main__: paket giriş noktaları — .so derleme finicky, IP değeri
# düşük (çoğu sadece re-export). .pyc olarak kalır (kaynak yine silinir).
_NO_COMPILE_BASENAMES = {"__init__", "__main__"}

# Bilinen sorunlu modüller (Nuitka edge-case) — ölçümle doldurulur, şimdilik boş.
_COMPILE_DENYLIST: set[str] = set()  # karadul'a göreli yol, ör "analyzers/foo.py"

# --------------------------------------------------------------------------
# Bu alt-ağaçlar HAM .py KALMALI (ne .so ne .pyc): harici bir çalıştırıcı bunları
# KAYNAK dosya olarak bekler.
# --------------------------------------------------------------------------
#  * ghidra/scripts/** -> Ghidra headless bu dizini ``-scriptPath`` ile KENDİ
#    PyGhidra/Jython yorumlayıcısında çalıştırır. Ghidra bir ``.so``'yu çalıştıramaz
#    ve ``.pyc``'yi script olarak tanımaz -> ``.py`` şart. Bu modüller bundle
#    CPython'da HİÇ import edilmez (``import ghidra`` yalnız Ghidra JVM'inde çözülür)
#    -> ``.so`` derlemesi KORUMA SAĞLAMAZ, sadece decompile'ı sessizce kırar.
#    Ölçüldü (2026-07-18 full-analiz): scripts .so olunca "Ghidra scriptleri
#    bulunamadi" -> decompile 0 fonksiyon -> deobfuscate/reconstruct fail.
_KEEP_SOURCE_DIRS = ("ghidra/scripts",)


def _keep_as_source(py: Path, package_dir: Path) -> bool:
    rel = py.relative_to(package_dir).as_posix()
    return any(rel == d or rel.startswith(d + "/") for d in _KEEP_SOURCE_DIRS)


# --------------------------------------------------------------------------
# Faz B: string literal ŞİFRELENECEK modüller (CERRAHİ — hepsi değil).
# --------------------------------------------------------------------------
# ``ast.unparse`` tüm modülü yeniden yazar (Tier A'dan riskli); bu yüzden yalnız
# ALGORİTMA-ELE-VEREN string taşıyan crown-jewel modüller/dizinler seçilir.
# Yol prefix'i (dosya veya dizin), karadul paketine göreli. A/B analizi bu
# yolları (naming/gnulib/computation) tetikler -> davranış korunması doğrulanır.
_ENCRYPT_PATHS = (
    "analyzers/gnulib_fingerprints.py",   # anchor string'ler (Berke özellikle istedi)
    "analyzers/packer_fingerprint.py",
    "naming",
    "computation",
    "pipeline/steps/computation_fusion.py",
    "pipeline/steps/computation_struct_recovery.py",
    "pipeline/steps/semantic_naming.py",
    "reconstruction/naming",
    "core/hardening.py",   # Faz C: anti-debug markerları (frida/.app/banner) gizli kalsın
)


def _should_encrypt(py: Path, package_dir: Path) -> bool:
    if encrypt_strings is None:
        return False
    rel = py.relative_to(package_dir).as_posix()
    return any(rel == p or rel.startswith(p + "/") for p in _ENCRYPT_PATHS)


def _iter_py(package_dir: Path):
    for p in sorted(package_dir.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        yield p


def _should_compile(py: Path, package_dir: Path) -> bool:
    if py.stem in _NO_COMPILE_BASENAMES:
        return False
    if _keep_as_source(py, package_dir):  # ghidra/scripts/** -> Ghidra .py bekler
        return False
    rel = py.relative_to(package_dir.parent).as_posix()
    rel_in_pkg = py.relative_to(package_dir).as_posix()
    if rel in _COMPILE_DENYLIST or rel_in_pkg in _COMPILE_DENYLIST:
        return False
    return True


def _compile_one(args: tuple[str, str, str]) -> tuple[str, bool, str]:
    """Tek modülü .so'ya derle. (py_path, nuitka_python, extra_flags) -> sonuç."""
    py_path, nuitka_python, _ = args
    py = Path(py_path)
    out_dir = py.parent
    base = py.stem
    cmd = [
        nuitka_python, "-m", "nuitka", "--module", str(py),
        "--python-flag=no_docstrings",
        "--assume-yes-for-downloads",
        f"--output-dir={out_dir}",
        "--quiet",
        "--no-progressbar",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        # M1/M2: kill edilen Nuitka .build/ (ÜRETİLMİŞ C KAYNAĞI = IP sızıntısı) +
        # yarım .so bırakır. .py korunur (modül kaybı yok) ama artık+stray .so silinmeli.
        _clean_artifacts(out_dir, base, remove_so=True)
        return (py_path, False, "TIMEOUT (>600s)")
    # Nuitka .so adını bul
    so = None
    for cand in out_dir.glob(f"{base}.cpython-*.so"):
        so = cand
        break
    if r.returncode != 0 or so is None or not so.exists():
        err = (r.stderr or r.stdout or "").strip().splitlines()
        tail = " | ".join(err[-2:]) if err else "bilinmeyen hata"
        # M2: başarısızlıkta bozuk/yarım .so'yu DA sil -> yoksa .so (ExtensionFileLoader)
        # geçerli .pyc'yi (SourcelessFileLoader) GÖLGELER -> runtime import crash.
        _clean_artifacts(out_dir, base, remove_so=True)
        return (py_path, False, tail[:300])
    # Başarılı: artıkları temizle (.so'ya DOKUNMA), .py + eski .pyc sil
    _clean_artifacts(out_dir, base, remove_so=False)
    try:
        py.unlink()
    except OSError:  # m7: FileNotFoundError yerine OSError (PermissionError vb. de yut)
        pass
    # eski .pyc varsa sil (import .so'yu tercih eder ama decompile edilebilir fallback bırakma)
    pyc_dir = out_dir / "__pycache__"
    if pyc_dir.is_dir():
        for pyc in pyc_dir.glob(f"{base}.*.pyc"):
            pyc.unlink(missing_ok=True)
    return (py_path, True, f"{so.stat().st_size} byte")


def _clean_artifacts(out_dir: Path, base: str, *, remove_so: bool = False) -> None:
    """Nuitka artıklarını temizle. ``remove_so=True`` (yalnız başarısızlık yolunda):
    yarım/bozuk ``{base}.cpython-*.so``'yu da sil -- bozuk .so, .pyc fallback'i
    gölgeleyip runtime crash yapar. ``.build/`` Nuitka'nın ÜRETTİĞİ C kaynağını
    içerir (korunmak istenen algoritmanın ta kendisi) -> her durumda silinmeli."""
    art = out_dir / f"{base}.build"
    if art.is_dir():
        shutil.rmtree(art, ignore_errors=True)
    for pyi in out_dir.glob(f"{base}.pyi"):
        pyi.unlink(missing_ok=True)
    if remove_so:
        for so in out_dir.glob(f"{base}.cpython-*.so"):
            so.unlink(missing_ok=True)


def phase_compile(package_dir: Path, nuitka_python: str, jobs: int,
                  encrypt: bool = True) -> int:
    targets = [p for p in _iter_py(package_dir) if _should_compile(p, package_dir)]
    # Faz B: seçili crown-jewel modüllerin string literal'lerini derlemeden ÖNCE
    # şifrele (yerinde .py; nasılsa compile sonrası silinecek). rotating-XOR +
    # inline çözücü -> derlenince strings/.so düz metni GÖRMEZ. Şifreleme kimlik
    # dönüşümü (encrypt->decrypt = orijinal) -> davranış korunur (A/B ile teyit).
    if encrypt and encrypt_strings is not None:
        enc_mods = enc_str = 0
        for py in targets:
            if _should_encrypt(py, package_dir):
                try:
                    n = encrypt_strings.transform_file(py)
                except Exception as e:  # noqa - bir modül şifrelenemezse compile'ı düşürme
                    print(f"[compile] !! string şifreleme atlandı ({py.name}): {e}")
                    continue
                if n:
                    enc_mods += 1
                    enc_str += n
        print(f"[compile] Faz B string şifreleme: {enc_mods} modül, {enc_str} string")
    print(f"[compile] {len(targets)} modül .so'ya derlenecek ({jobs} paralel)")
    t0 = time.time()
    ok = fail = 0
    failures: list[tuple[str, str]] = []
    work = [(str(p), nuitka_python, "") for p in targets]
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(_compile_one, w): w[0] for w in work}
        done = 0
        for fut in as_completed(futs):
            path, success, info = fut.result()
            done += 1
            rel = Path(path).relative_to(package_dir.parent).as_posix()
            if success:
                ok += 1
            else:
                fail += 1
                failures.append((rel, info))
            if done % 20 == 0 or not success:
                mark = "OK " if success else "!! "
                print(f"  [{done}/{len(targets)}] {mark}{rel}"
                      + ("" if success else f"  -> {info}"))
    dt = time.time() - t0
    print(f"[compile] bitti: {ok} .so, {fail} başarısız, {dt:.0f}s")
    if failures:
        # NOT: başarısız modülün .py'si KORUNUR (modül kaybı yok) -> compileall
        # onu .pyc'ler, strip fazı .pyc-only'e düşürür. Ama build script fail-fast:
        # tek hata bile build'i abort eder (beklenmeyen Nuitka edge-case sessizce
        # korumasız SHIP edilmesin). İstenirse _COMPILE_DENYLIST'e alınıp tolere edilir.
        print("[compile] BAŞARISIZLAR (.py korundu; build abort edecek):")
        for rel, info in failures:
            print(f"    - {rel}: {info}")
    # M3: ham 'fail' sayısını DÖNDÜRME -> SystemExit(256) => OS'ta 256&0xFF=0 =
    # sahte BAŞARI (tam 256 hata build'i geçirir). 0/1 döndür.
    return 1 if fail else 0


def phase_strip(package_dir: Path) -> int:
    """Derlenmemiş (.pyc-only) modüller için: compileall'ın ürettiği
    ``__pycache__/X.cpython-VER.pyc``'yi sourceless yan-yana ``X.pyc`` konumuna
    TAŞI, sonra ``.py``'yi sil.

    NEDEN taşıma (ölçülmüş bug): Python ``__pycache__``'teki .pyc'yi ancak yanında
    kaynak ``.py`` VARSA kullanır. ``.py`` silinip .pyc ``__pycache__``'te kalırsa
    modül BULUNAMAZ -> paket PEP-420 namespace'e düşer, ``__init__`` kodu HİÇ
    çalışmaz (bundle'da ölçüldü: ``karadul.__version__``/``Config``/``Pipeline``
    top-level'dan kayboldu, ``__file__=None``). Sourceless yan-yana ``X.pyc`` ise
    ``SourcelessFileLoader`` ile doğrudan yüklenir + çalışma zamanında YENİDEN
    YAZILMAZ (kaynak yok -> derleme yok -> mühür güvenli)."""
    relocated = anomaly = kept_source = 0
    problems: list[str] = []
    for py in _iter_py(package_dir):
        if _keep_as_source(py, package_dir):
            # ghidra/scripts/** -> .py HAM KALIR (Ghidra kaynak dosya bekler).
            # compileall'ın ürettiği __pycache__ .pyc'yi temizle: bundle'da bu
            # modüller için tek doğru dosya .py olsun (kafa karışıklığı + gereksiz
            # .pyc yok). .py silinMEZ.
            cache = Path(importlib.util.cache_from_source(str(py)))
            if cache.is_file():
                cache.unlink()
            kept_source += 1
            continue
        # m4: compileall'ın ürettiği KESİN .pyc yolunu al (glob değil, cache-tag tam eşleşme)
        cache = Path(importlib.util.cache_from_source(str(py)))
        if not cache.is_file():
            anomaly += 1
            problems.append(py.relative_to(package_dir.parent).as_posix())
            continue
        dest = py.with_suffix(".pyc")           # yan yana, sourceless konum
        shutil.move(str(cache), str(dest))
        py.unlink()
        relocated += 1
    # boşalan __pycache__ dizinlerini kaldır (bundle temiz kalsın)
    for pc in sorted(package_dir.rglob("__pycache__"), reverse=True):
        try:
            pc.rmdir()  # yalnız boşsa siler
        except OSError:
            pass
    print(f"[strip] {relocated} modül .pyc-only (sourceless yan-yana), "
          f"{kept_source} .py ham korundu (ghidra/scripts), {anomaly} anomali")
    if anomaly:
        # m5: .pyc'si üretilmemiş .py = ANOMALİ (compileall onu atladı?). Sessizce
        # .py bırakmak -> kaynak sızıntısı + runtime .pyc yazımı (mühür kırılması).
        # Normalleştirme YOK: build'i düşür ki sebep araştırılsın. Mutlu yolda
        # compileall her .py'yi derler -> anomaly=0.
        print("[strip] !! .pyc üretilmemiş .py (compileall atladı? incele):")
        for p in problems[:20]:
            print(f"    - {p}")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Black Widow motor koruma")
    ap.add_argument("--package", required=True, help="karadul paket dizini (bundle içi)")
    ap.add_argument("--phase", required=True, choices=["compile", "strip", "both"])
    ap.add_argument("--nuitka-python", default=sys.executable,
                    help="nuitka kurulu python (varsayılan: bu python)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--no-encrypt", action="store_true",
                    help="Faz B string şifrelemeyi atla (debug/karşılaştırma)")
    args = ap.parse_args()

    package_dir = Path(args.package).resolve()
    if package_dir.name != "karadul" or not package_dir.is_dir():
        print(f"HATA: --package bir 'karadul' dizini olmalı: {package_dir}", file=sys.stderr)
        return 2

    print(f"ABI: {sysconfig.get_config_var('SOABI')}  python={sys.version.split()[0]}")
    rc = 0
    if args.phase in ("compile", "both"):
        rc |= phase_compile(package_dir, args.nuitka_python, args.jobs,
                            encrypt=not args.no_encrypt)
    if args.phase in ("strip", "both"):
        rc |= phase_strip(package_dir)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
