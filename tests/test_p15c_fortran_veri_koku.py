"""P15c kalem 7 (P15b kalanı, GHIDRA-14): FortranParamDB ``sigs/fortran_params*.json``'u veri
kökünden okur (``KARADUL_SIG_DATA_DIR`` ya da paket kökü); eskiden yalnız paket kökü.
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.config import DATA_ROOT_ENV, resolve_data_root
from karadul.reconstruction.fortran_param_db import FortranParamDB


def _veri(kok: Path) -> Path:
    (kok / "sigs").mkdir(parents=True)
    (kok / "sigs" / "fortran_params_p15c.json").write_text(
        json.dumps({"_p15c_ozel_": ["girdi", "cikti"]}), encoding="utf-8")
    return kok


def test_ortam_degiskeni_veri_kokunu_izler(tmp_path, monkeypatch):
    kok = _veri(tmp_path / "veri")
    monkeypatch.setenv(DATA_ROOT_ENV, str(kok))
    db = FortranParamDB()
    assert db.data_root == kok.resolve()
    assert db.get_param_names("_p15c_ozel_") == ["girdi", "cikti"]
    assert db.loaded_files == [str(kok.resolve() / "sigs" / "fortran_params_p15c.json")]


def test_ortam_degiskeni_yoksa_paket_koku(tmp_path, monkeypatch):
    _veri(tmp_path / "veri")
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    db = FortranParamDB()
    assert db.data_root == resolve_data_root()[0]
    assert db.get_param_names("_p15c_ozel_") is None


def test_acik_veri_koku(tmp_path, monkeypatch):
    kok = _veri(tmp_path / "acik")
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    assert FortranParamDB(data_root=kok).get_param_names("_p15c_ozel_") == ["girdi", "cikti"]
