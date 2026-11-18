"""P16a / MEK-02: ``karadul diff`` incelenen ikilinin dizinine hiçbir şey yazmaz.

Eski davranış (kulvar_MEK, MEK-02): ``python -m karadul diff /bin/ls /bin/cat`` →
``Operation not permitted: '/bin/diff_prog1'``; yazılabilir dizinde ikilinin yanına
``diff_prog1`` / ``diff_prog2`` Ghidra projeleri ve rapor bırakılıyordu.

Ghidra yok: sahte ``pyghidra`` modülü ``open_program``'ı kaydeder ve pyghidra'nın gerçek
davranışını taklit eder (``project_location`` verilmezse proje ikilinin dizinine kurulur).
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

from karadul.config import Config
from karadul.ghidra import headless as headless_mod
from karadul.ghidra import program_diff as pd


class _Iter:
    def hasNext(self):
        return False


class _Prog:
    def getFunctionManager(self):
        return self

    def getFunctions(self, ileri):
        return _Iter()


class _Flat:
    def getCurrentProgram(self):
        return _Prog()


def test_diff_ikilinin_dizinine_yazmaz_projeler_gecici(tmp_path, monkeypatch):
    kanit = tmp_path / "kanit"
    kanit.mkdir()
    a, b = kanit / "a.bin", kanit / "b.bin"
    a.write_bytes(b"\x7fELF-a")
    b.write_bytes(b"\x7fELF-b")
    kanit.chmod(0o555)  # salt okur kanıt dizini: eski kod burada düşüyordu
    calisma = tmp_path / "calisma"
    calisma.mkdir()
    monkeypatch.chdir(calisma)

    gorulen: list[Path] = []

    class _Ctx:
        def __init__(self, binary_path, project_location=None, project_name=None, **kw):
            # pyghidra'nın kendisi: project_location yoksa ikilinin dizini
            yer = Path(project_location) if project_location else Path(binary_path).parent
            gorulen.append(yer)
            (yer / project_name).mkdir(parents=True)

        def __enter__(self):
            return _Flat()

        def __exit__(self, *a):
            return False

    sahte = types.ModuleType("pyghidra")
    sahte.open_program = lambda binary_path, **kw: _Ctx(binary_path, **kw)
    monkeypatch.setitem(sys.modules, "pyghidra", sahte)
    monkeypatch.setattr(pd, "_check_pyghidra", lambda: True)
    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", lambda install: None)

    try:
        rapor = pd.GhidraProgramDiff(Config()).diff(a, b)
    finally:
        kanit.chmod(0o755)
    assert sorted(os.listdir(kanit)) == ["a.bin", "b.bin"]
    assert len(gorulen) == 2 and all(kanit not in p.parents and p != kanit for p in gorulen)
    assert not any(p.exists() for p in gorulen), "geçici proje dizini silinmeli"
    assert rapor.summary.total_functions_1 == 0
    assert list(calisma.glob("*.json")), "rapor çalışma dizinine yazılmalı"
