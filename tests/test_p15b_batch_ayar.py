"""P15b kalem 8 — `karadul batch` ayar dosyasını hiç yüklemiyordu.

Taban: ``batch.analyze_single_target`` ``Config()`` kuruyordu: çalışma dizinindeki
``karadul.yaml`` okunmuyor, ``--config`` seçeneği yoktu; hatalı ayar dosyası katı
yükleyiciden (P15a / GHIDRA-04) geçmiyordu.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import karadul.batch as batch
from karadul.cli import main

GECERLI = "binary_reconstruction:\n  enable_byte_pattern_matching: false\n"
HATALI = "binary_reconstruction:\n  enable_byte_patern_matching: false\n"


class _Yakala:
    cfgs: list = []

    def __init__(self, cfg) -> None:
        _Yakala.cfgs.append(cfg)

    def register_stage(self, *_a) -> None:
        pass

    def run(self, *_a):
        raise RuntimeError("test: pipeline koşturulmadı")


@pytest.fixture()
def hedef(tmp_path: Path) -> Path:
    p = tmp_path / "ikili"
    p.write_bytes(b"\x7fELF")
    return p


def test_isci_ayar_dosyasini_yukler(tmp_path: Path, hedef: Path) -> None:
    yml = tmp_path / "k.yaml"
    yml.write_text(GECERLI, encoding="utf-8")
    _Yakala.cfgs.clear()
    with patch("karadul.core.pipeline.Pipeline", _Yakala):
        r = batch._worker(("h", str(hedef), tmp_path / "cikti", True, str(yml)))
    assert r.success is False  # sahte pipeline hata verdi
    (cfg,) = _Yakala.cfgs
    assert cfg.binary_reconstruction.enable_byte_pattern_matching is False
    assert cfg.project_root == tmp_path / "cikti"


def test_calisma_dizinindeki_karadul_yaml_tek_analizdeki_gibi(
    tmp_path: Path, hedef: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "karadul.yaml").write_text(GECERLI, encoding="utf-8")
    _Yakala.cfgs.clear()
    with patch("karadul.core.pipeline.Pipeline", _Yakala):
        batch.analyze_single_target("h", str(hedef), tmp_path / "cikti")
    assert _Yakala.cfgs[0].binary_reconstruction.enable_byte_pattern_matching is False


def test_dort_ogeli_isci_argumani_hala_gecerli(tmp_path: Path, hedef: Path) -> None:
    _Yakala.cfgs.clear()
    with patch("karadul.core.pipeline.Pipeline", _Yakala):
        batch._worker(("h", str(hedef), tmp_path, True))
    assert _Yakala.cfgs[0].binary_reconstruction.enable_byte_pattern_matching is True


def test_cli_hatali_ayar_hicbir_hedef_kosmadan_durur(tmp_path: Path, hedef: Path) -> None:
    yml = tmp_path / "hatali.yaml"
    yml.write_text(HATALI, encoding="utf-8")
    with patch("karadul.batch.resolve_targets", return_value={"h": str(hedef)}), \
         patch("karadul.batch.analyze_parallel") as ap:
        res = CliRunner().invoke(main, ["batch", "analyze", "-t", "h", "--output-dir",
                                        str(tmp_path / "o"), "--config", str(yml)])
    assert res.exit_code == 2
    assert "ayar dosyası yüklenemedi" in res.output
    assert "enable_byte_patern_matching" in res.output
    ap.assert_not_called()


def test_cli_gecerli_ayar_iscilere_mutlak_yolla_gider(
    tmp_path: Path, hedef: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "k.yaml").write_text(GECERLI, encoding="utf-8")
    with patch("karadul.batch.resolve_targets", return_value={"h": str(hedef)}), \
         patch("karadul.batch.analyze_parallel", return_value=[]) as ap:
        CliRunner().invoke(main, ["batch", "analyze", "-t", "h", "--output-dir",
                                  str(tmp_path / "o"), "--config", "k.yaml"])
    assert ap.call_args.kwargs["config_path"] == str((tmp_path / "k.yaml").resolve())
