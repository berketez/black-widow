"""P-S1 kalem 3 (P19 yaması, BICIM-10'un ``stages.py`` kısmı).

Tanınan ama analiz hattı olmayan kapsayıcı (wheel, nupkg, IPA …: tür UNKNOWN +
``metadata["container"]``) reconstruct aşamasında JS hattına düşüp
"Deobfuscate edilmis dosya bulunamadi" hatası vermiyor; açıkça "atlandı"
diyor. Hedef tanıma gerçek ``TargetDetector`` ile yapılır.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.core.target import TargetDetector, TargetType
from karadul.stages import ReconstructionStage

_NATIVE = Path.home() / "karadul_olcum" / "dogrulama_native"
_REAL = [p for p in [
    _NATIVE / "wheel" / "six-1.16.0-py2.py3-none-any" / "six-1.16.0-py2.py3-none-any.whl",
    _NATIVE / "dotnet" / "humanizer.core.2.14.1" / "humanizer.core.2.14.1.nupkg",
] if p.is_file()]


def _wheel(tmp_path: Path) -> Path:
    p = tmp_path / "ornek-1.0-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("ornek/__init__.py", "x = 1\n")
        z.writestr("ornek-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n")
        z.writestr("ornek-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: ornek\n"
                                                   "Version: 1.0\n")
        z.writestr("ornek-1.0.dist-info/RECORD", "ornek/__init__.py,,\n")
    return p


def _run(target, monkeypatch):
    called = []
    monkeypatch.setattr(ReconstructionStage, "_execute_js",
                        lambda self, ctx, start: called.append(True) or "JS_HATTI")
    ctx = MagicMock()
    ctx.target = target
    return ReconstructionStage().execute(ctx), called


def test_synthetic_wheel_is_skipped_not_js(tmp_path, monkeypatch) -> None:
    target = TargetDetector().detect(_wheel(tmp_path))
    assert target.target_type == TargetType.UNKNOWN
    assert target.metadata.get("container") == "python_wheel"
    res, called = _run(target, monkeypatch)
    assert called == []  # JS hattina dusmedi
    assert res.skipped is True and res.success is False
    assert res.errors == []
    assert res.stats["container"] == "python_wheel"
    assert "python_wheel" in res.stats["skip_reason"]
    assert "wheel" in res.stats["skip_reason"].lower()
    assert res.stats["container_executables_total"] == 0


@pytest.mark.parametrize("path", _REAL, ids=lambda p: p.name)
def test_real_containers_are_skipped(path, monkeypatch) -> None:
    target = TargetDetector().detect(path)
    assert target.target_type == TargetType.UNKNOWN
    res, called = _run(target, monkeypatch)
    assert called == []
    assert res.skipped is True
    assert res.stats["container"] in ("python_wheel", "nuget_package")
    assert res.stats["skip_reason"]


def test_unknown_without_container_still_goes_js(tmp_path, monkeypatch) -> None:
    """Kapsayici kaniti olmayan UNKNOWN hedef eski yolu izler (davranis degismez)."""
    p = tmp_path / "duz.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("not.txt", "merhaba\n")
    target = TargetDetector().detect(p)
    assert target.target_type == TargetType.UNKNOWN
    assert not (target.metadata or {}).get("container")
    res, called = _run(target, monkeypatch)
    assert called == [True] and res == "JS_HATTI"
