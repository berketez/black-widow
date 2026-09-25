"""PyGhidra JVM'i headless başlatılıyor mu? (macOS AWT kilitlenmesi regresyonu)

2026-09-25: HeadlessPyGhidraLauncher java.awt.headless vermiyor (VM argümanlarını
yalnız Ghidra'nın launch.properties'inden okur, orada da yok). AWT'ye dokunan bir Java
kodu macOS'ta LWCToolkit.initAppkit ile AppKit'in ana thread'de başlamasını bekliyor,
ana thread Python'da bir kilitte beklediği için süreç kalıcı kilitleniyordu (.app
hedefinde %0 CPU ile asılı; stack örneğiyle doğrulandı).

Kural: JVM'i başlatan her yol karadul.ghidra.headless._ensure_pyghidra_started'dan
geçer ve bayrak orada verilir.
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

import pytest

import karadul
from karadul.ghidra import headless


class _FakeLauncher:
    instances: list["_FakeLauncher"] = []

    def __init__(self, install_dir=None, **_kw):
        self.install_dir = install_dir
        self.vmargs: list[str] = []
        self.started = False
        _FakeLauncher.instances.append(self)

    def add_vmargs(self, *args: str) -> None:
        self.vmargs.extend(args)

    def start(self) -> None:
        self.started = True


@pytest.fixture
def fake_pyghidra(monkeypatch):
    """Gerçek JVM başlatmadan pyghidra'yı taklit et."""
    _FakeLauncher.instances.clear()
    pyghidra_mod = types.ModuleType("pyghidra")
    pyghidra_mod.started = lambda: False
    launcher_mod = types.ModuleType("pyghidra.launcher")
    launcher_mod.HeadlessPyGhidraLauncher = _FakeLauncher
    pyghidra_mod.launcher = launcher_mod
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra_mod)
    monkeypatch.setitem(sys.modules, "pyghidra.launcher", launcher_mod)
    monkeypatch.setattr(headless, "_PYGHIDRA_STARTED", False)
    return _FakeLauncher


def test_jvm_is_started_headless(fake_pyghidra, tmp_path):
    headless._ensure_pyghidra_started(tmp_path)
    (launcher,) = fake_pyghidra.instances
    assert launcher.started
    assert launcher.install_dir == tmp_path
    assert "-Djava.awt.headless=true" in launcher.vmargs


def test_only_headless_module_starts_the_jvm():
    """headless.py dışında hiçbir karadul modülü JVM'i doğrudan başlatmamalı.

    pyghidra.start() ve çıplak HeadlessPyGhidraLauncher(...) headless bayrağını
    atlar; bu yollar _ensure_pyghidra_started'ı kullanmalı.
    """
    root = Path(karadul.__file__).resolve().parent
    starter = root / "ghidra" / "headless.py"
    offenders: list[str] = []
    for py in sorted(root.rglob("*.py")):
        # Ghidra'nın İÇİNDE koşan script'ler (currentProgram global'i) JVM başlatmaz.
        if py == starter or (root / "ghidra" / "scripts") in py.parents:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            direct_launcher = isinstance(fn, ast.Name) and fn.id == "HeadlessPyGhidraLauncher"
            pyghidra_start = (
                isinstance(fn, ast.Attribute) and fn.attr == "start"
                and isinstance(fn.value, ast.Name) and fn.value.id == "pyghidra"
            )
            jpype_start = isinstance(fn, ast.Attribute) and fn.attr == "startJVM"
            if direct_launcher or pyghidra_start or jpype_start:
                offenders.append(f"{py.relative_to(root)}:{node.lineno}")
    assert not offenders, f"JVM headless bayrağı olmadan başlatılıyor: {offenders}"
