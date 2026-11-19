"""P-S4: Python paketinde hiçbir .pyc çözülemediyse reconstruct bunu söyler.

Gerçek örnek (yt-dlp_macos / yt-dlp.exe, Python 3.14): decompile zincirine giren 1338
.pyc'nin 1338'i 'failed' (decompile / disasm 0); aşama hatasız 'başarılı' görünüyor,
sayı yalnız manifest notundaydı. Artık ``failed_count`` + hata satırı (aşama kısmi).
"""

from __future__ import annotations

import py_compile
from pathlib import Path

import pytest

from karadul.analyzers.python_binary import PythonBinaryAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


def _hedef(tmp_path: Path) -> tuple[TargetInfo, Workspace]:
    src = tmp_path / "m.py"
    src.write_text("x = 1\n", encoding="utf-8")
    pyc = tmp_path / "m.pyc"
    py_compile.compile(str(src), cfile=str(pyc))
    ws = Workspace(base_dir=tmp_path / "ws", target_name="m")
    ws.create()
    ws.save_json("static", "python_packer", {"packer": "pyc"})
    ws.save_json("static", "python_version", {"version": "3.12"})
    t = TargetInfo(path=pyc, name="m", target_type=TargetType.PYTHON_PACKED,
                   language=Language.PYTHON, file_size=pyc.stat().st_size,
                   file_hash="e" * 64, metadata={"format": "pyc", "packer": "pyc"})
    return t, ws


@pytest.mark.parametrize("ozet,hata_beklenir", [
    ({"total_pyc": 1, "failed": 1, "decompiled": 0, "partial": 0, "disasm": 0}, True),
    ({"total_pyc": 1, "failed": 0, "decompiled": 1, "partial": 0, "disasm": 0}, False),
    ({"total_pyc": 2, "failed": 1, "decompiled": 0, "partial": 0, "disasm": 1}, False),
])
def test_hicbiri_cozulemediyse_hata_satiri(tmp_path, monkeypatch, ozet, hata_beklenir):
    monkeypatch.setattr(PythonBinaryAnalyzer, "_decompile_pyc_files",
                        lambda self, files, out, py_version=None: dict(ozet))
    t, ws = _hedef(tmp_path)
    res = PythonBinaryAnalyzer(Config()).reconstruct(t, ws)
    assert res is not None
    assert res.stats["failed_count"] == ozet["failed"]
    hatali = [e for e in res.errors if "hiçbiri çözülemedi" in e]
    assert bool(hatali) is hata_beklenir
    if hata_beklenir:
        assert "Python 3.12" in hatali[0]
