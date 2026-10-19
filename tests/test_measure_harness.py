"""measure.py yardımcıları: koşu künyesine giren git bilgisinin doğruluğu."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

_MEASURE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "measure.py"


def _load_measure():
    spec = importlib.util.spec_from_file_location("measure_harness_under_test", _MEASURE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_porcelain_first_line_keeps_leading_space(tmp_path: Path) -> None:
    # Değiştirilmiş ama stage'lenmemiş dosya porcelain'de " M yol" biçiminde başlar;
    # baştaki boşluk düşerse ilk satırın durumu "stage'lenmiş" gibi okunur.
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.txt").write_text("1\n", encoding="utf-8")
    _git(tmp_path, "add", "a.txt")
    _git(tmp_path, "commit", "-q", "-m", "ilk")
    (tmp_path / "a.txt").write_text("2\n", encoding="utf-8")

    out = _load_measure()._git(tmp_path, "status", "--porcelain", "--untracked-files=no")

    assert out.splitlines() == [" M a.txt"]
