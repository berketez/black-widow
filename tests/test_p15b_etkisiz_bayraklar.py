"""P15b kalem 3 — BORU-13 + P-S2 notu: okunmayan alanlar ve etkisiz bayraklar.

P15a (MEK-05) etkisiz kaydını kurdu; bu dosya paket metnindeki listeyi tek tek kilitler:
her alan ya okunuyor (bağlı) ya da ``INERT_SETTINGS``'te gerekçesiyle duruyor; kullanıcı
YAML'ı kırılmıyor (alan silinmedi, yazılırsa uyarı); yardım metinleri gerçeği söylüyor.
Ana oturum notu: ``enable_rtti_recovery``, ``rtti_abi``, ``deep_trace.*`` KALDIRILMAZ
(P13b bağlayacak).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from karadul.cli import main
from karadul.config import INERT_SETTINGS, Config, PipelineConfig

ETKISIZ = (
    "analysis.use_deep_deobfuscation",
    "binary_reconstruction.function_id_db_paths",
    "computation_recovery.formula_min_complexity",
    "computation_recovery.cfg_iso_vf2_node_cap",
    "deep_trace.enable_dispatch_resolution",
    "deep_trace.enable_data_flow",
    "deep_trace.enable_composition",
    "deep_trace.enable_deep_trace",
)
BAGLI = (
    "binary_reconstruction.max_decompile_timeout_per_func",  # ghidra/headless.py
    "binary_reconstruction.rtti_abi",  # `karadul rtti` öntanımı (P15a)
    "binary_reconstruction.enable_rtti_recovery",  # pipeline/steps/rtti_recovery.py (P-ÜV4)
)


@pytest.mark.parametrize("anahtar", ETKISIZ)
def test_etkisiz_alan_kayitta_ve_yaml_kirilmiyor(anahtar: str, tmp_path: Path) -> None:
    assert anahtar in INERT_SETTINGS
    bolum, alan = anahtar.split(".")
    deger = getattr(getattr(Config(), bolum), alan)
    yml = tmp_path / "k.yaml"
    yml.write_text(f"{bolum}:\n  {alan}: {str(deger).lower() if isinstance(deger, bool) else deger if not isinstance(deger, list) else '[]'}\n",
                   encoding="utf-8")
    cfg = Config.load(yml)  # emekli anahtar politikası: alan duruyor → hata yok
    assert any(w.startswith(f"{anahtar} etkisiz") for w in cfg.inert_setting_warnings())


@pytest.mark.parametrize("anahtar", BAGLI)
def test_bagli_alan_etkisiz_sayilmaz(anahtar: str) -> None:
    bolum, alan = anahtar.split(".")
    assert hasattr(getattr(Config(), bolum), alan)
    assert anahtar not in INERT_SETTINGS


def test_p_s2_notu_ve_adim_kosucusu_belgesi() -> None:
    assert "P-S2" in INERT_SETTINGS["analysis.use_deep_deobfuscation"]
    belge = PipelineConfig.__doc__ or ""
    assert "TEK yol" in belge and "monolith'i\n    (obsolete" not in belge


def test_yardim_metinleri_gercegi_soyler() -> None:
    out = CliRunner().invoke(main, ["analyze", "--help"], terminal_width=400).output
    assert "--experimental-step-registry" in out and "Etkisiz (geriye uyum)" in out
    assert "Derin çağrı izlemeyi değiştirmez" in out
