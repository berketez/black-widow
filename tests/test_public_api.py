"""Public API smoke testleri (Batch 5C-1).

`import karadul` sonrasinda API yuzeyi kararli olmali:
- `karadul.__version__`, `karadul.__codename__`
- `karadul.analyze`, `karadul.Pipeline`, `karadul.Config`
- `karadul.__all__` icindeki her isim gercekten mevcut.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import karadul
from karadul import Config, Pipeline, analyze


def test_version_is_string() -> None:
    assert isinstance(karadul.__version__, str)
    assert karadul.__version__ == "1.10.0"


def test_codename() -> None:
    assert karadul.__codename__ == "Karadul"


def test_all_exports_present() -> None:
    for name in karadul.__all__:
        assert hasattr(karadul, name), f"karadul.__all__ iceren {name!r} yok"


def test_all_expected_names() -> None:
    expected = {"analyze", "Pipeline", "Config", "__version__", "__codename__"}
    assert expected.issubset(set(karadul.__all__))


def test_analyze_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        analyze("/nonexistent/path/that/should/not/exist/binary")


def test_analyze_rejects_directory(tmp_path: Path) -> None:
    # tmp_path bir dizin; file olmadigi icin FileNotFoundError almaliyiz
    with pytest.raises(FileNotFoundError):
        analyze(tmp_path)


def test_pipeline_class_importable() -> None:
    assert Pipeline is not None
    # Pipeline constructor Config alir
    cfg = Config.load()
    pipeline = Pipeline(cfg)
    assert pipeline is not None


def test_config_importable() -> None:
    cfg = Config.load()
    assert cfg is not None


def test_analyze_signature_accepts_path_and_str(tmp_path: Path) -> None:
    """analyze() hem str hem Path kabul etmeli (erken donustan once)."""
    fake = tmp_path / "notthere"
    # Path nesnesi:
    with pytest.raises(FileNotFoundError):
        analyze(fake)
    # String:
    with pytest.raises(FileNotFoundError):
        analyze(str(fake))
