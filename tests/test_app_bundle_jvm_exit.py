"""JVM ana olmayan thread'de doğarsa süreç çıkışta asılmamalı.

Bug (2026-09-25, .app analizi): analiz bitip sonuç tablosu basılıyor, sonra süreç
asılı kalıyordu (timeout 300 -> rc=124). Kök sebep: AppBundleAnalyzer bileşenleri
ThreadPoolExecutor işçisinde analiz ediyordu; Ghidra JVM'i (JNI_CreateJavaVM)
o işçi thread'inde başlıyordu. JVM'i yaratan thread JVM'de daemon OLMAYAN "main"
thread'i olarak kayıtlı kalır; işçi bitince JVM'den ayrılmaz (JPype otomatik
ayırmaz). Çıkışta ana thread'deki JPype atexit -> DestroyJavaVM, daemon olmayan
thread sayısının 1'e inmesini sonsuza kadar bekler.

jstack kanıtı: daemon olmayan yalnız "main" #1 (OS thread'i ölü, cpu=-0.00ms) ve
Monitor::wait'teki "DestroyJavaVM". H2/MVStore/GTimer thread'leri daemon'dı.

Düzeltme: karadul.ghidra.headless._ensure_pyghidra_started JVM'i ana olmayan bir
thread'de başlattıysa o thread'i JVM'den ayırır (sonraki Java çağrısında JPype onu
DAEMON olarak yeniden bağlar). AppBundleAnalyzer ayrıca bileşenleri artık çağıran
thread'de analiz eder (test_app_bundle_pipeline.py).
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from karadul.ghidra import headless


class _FakeLauncher:
    def __init__(self, install_dir=None, **_kw):
        self.vmargs: list[str] = []

    def add_vmargs(self, *args: str) -> None:
        self.vmargs.extend(args)

    def start(self) -> None:
        pass


@pytest.fixture
def fake_jvm(monkeypatch):
    """pyghidra + jpype taklidi: detach çağrılarını (hangi thread) kaydeder."""
    detached: list[str] = []

    class _FakeJavaThread:
        @staticmethod
        def detach() -> None:
            detached.append(threading.current_thread().name)

    jpype_mod = types.ModuleType("jpype")
    jpype_mod.JClass = lambda name: _FakeJavaThread if name == "java.lang.Thread" else None
    pyghidra_mod = types.ModuleType("pyghidra")
    pyghidra_mod.started = lambda: False
    launcher_mod = types.ModuleType("pyghidra.launcher")
    launcher_mod.HeadlessPyGhidraLauncher = _FakeLauncher
    pyghidra_mod.launcher = launcher_mod
    monkeypatch.setitem(sys.modules, "jpype", jpype_mod)
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra_mod)
    monkeypatch.setitem(sys.modules, "pyghidra.launcher", launcher_mod)
    monkeypatch.setattr(headless, "_PYGHIDRA_STARTED", False)
    return detached


def test_worker_thread_that_creates_jvm_is_detached(fake_jvm, tmp_path):
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="bundle") as pool:
        pool.submit(headless._ensure_pyghidra_started, tmp_path).result()
    assert len(fake_jvm) == 1 and fake_jvm[0].startswith("bundle")


def test_main_thread_is_not_detached(fake_jvm, tmp_path):
    # DestroyJavaVM'i ana thread çağırır; onu ayırmak gereksiz ve yanlış olur.
    headless._ensure_pyghidra_started(tmp_path)
    assert fake_jvm == []


def _real_jvm_available() -> bool:
    try:
        import jpype

        jpype.getDefaultJVMPath()
    except Exception:
        return False
    return True


_EXIT_SCRIPT = textwrap.dedent(
    """
    import sys, types
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path

    import jpype


    class _Launcher:
        # HeadlessPyGhidraLauncher yerine: GERÇEK JVM'i başlatır (Ghidra'sız).
        def __init__(self, install_dir=None, **kw):
            self.vmargs = []

        def add_vmargs(self, *args):
            self.vmargs.extend(args)

        def start(self):
            jpype.startJVM(*[a for a in self.vmargs if a.startswith("-D")])


    pg = types.ModuleType("pyghidra")
    pg.started = jpype.isJVMStarted
    pl = types.ModuleType("pyghidra.launcher")
    pl.HeadlessPyGhidraLauncher = _Launcher
    pg.launcher = pl
    sys.modules["pyghidra"] = pg
    sys.modules["pyghidra.launcher"] = pl

    from karadul.ghidra import headless

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(headless._ensure_pyghidra_started, Path("/nonexistent")).result()
        # Ayrılan işçi Java'yı yine kullanabilmeli (JPype daemon olarak bağlar).
        ver = pool.submit(
            lambda: str(jpype.JClass("java.lang.System").getProperty("java.version"))
        ).result()
    print("OK", ver, flush=True)
    """
)


@pytest.mark.skipif(not _real_jvm_available(), reason="JPype/JVM yok")
def test_process_exits_when_jvm_started_in_worker_thread(tmp_path):
    """Gerçek JVM: işçi thread'de başlatılınca süreç temiz çıkmalı (asılmamalı)."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _EXIT_SCRIPT],
            capture_output=True, text=True, timeout=60, cwd=tmp_path,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            "Süreç çıkışta asılı kaldı (DestroyJavaVM, JVM'i yaratan işçi "
            f"thread'i ayrılmamış): stdout={exc.stdout!r}",
        )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.startswith("OK"), proc.stdout
