"""Plan v2.2 N1 adım 3 yapılandırma bayrakları: öntanımlı kapalı, YAML'dan okunur.

Bayraklar kapalıyken ürünün ad haritası değişmez; davranışı açan tek yer "aç" commit'idir.
Öntanımlıyı sessizce çeviren bir değişiklik bu testi kırar.
"""
from __future__ import annotations

import dataclasses

import pytest

from karadul.config import BinaryReconstructionConfig, Config

BAYRAKLAR = ("enable_ks1_anchors", "enable_subchannel_silencing", "apply_global_naming_threshold")


def test_bayraklar_ontanimli_kapali():
    cfg = Config()
    for ad in BAYRAKLAR:
        assert getattr(cfg.binary_reconstruction, ad) is False, ad
    alanlar = {f.name: f for f in dataclasses.fields(BinaryReconstructionConfig)}
    for ad in BAYRAKLAR:
        assert alanlar[ad].default is False and alanlar[ad].type in (bool, "bool")


@pytest.mark.parametrize("ad", BAYRAKLAR)
def test_bayrak_yamldan_okunur(tmp_path, ad):
    yol = tmp_path / "karadul.yaml"
    yol.write_text(f"binary_reconstruction:\n  {ad}: true\n", encoding="utf-8")
    cfg = Config.load(yol)
    assert getattr(cfg.binary_reconstruction, ad) is True
    for oteki in BAYRAKLAR:
        if oteki != ad:
            assert getattr(cfg.binary_reconstruction, oteki) is False   # biri öbürünü açmaz


def test_urun_esigi_degismedi():
    assert Config().binary_reconstruction.min_naming_confidence == 0.7


# --------------------------------------------------------------------------------------------
# Config.load ve Ghidra arama sıkılığı (sürüm öncesi sağlamlaştırma)


def test_config_load_dizgi_yol_kabul_eder(tmp_path):
    yol = tmp_path / "karadul.yaml"
    yol.write_text("binary_reconstruction:\n  min_naming_confidence: 0.55\n", encoding="utf-8")
    assert Config.load(str(yol)).binary_reconstruction.min_naming_confidence == 0.55
    assert Config.load(yol).binary_reconstruction.min_naming_confidence == 0.55


def test_config_load_olmayan_yolda_uyarir(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)          # ./karadul.yaml yok: yerleşik varsayılanlar
    with caplog.at_level("WARNING", logger="karadul.config"):
        cfg = Config.load(tmp_path / "yok.yaml")
    assert cfg.binary_reconstruction.min_naming_confidence == 0.7
    assert any("bulunamadı" in r.getMessage() and "yok.yaml" in r.getMessage() for r in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING", logger="karadul.config"):
        Config.load()                    # yol verilmedi: uyarı yok
    assert not caplog.records


def _ghidra_kur(kok):
    (kok / "support").mkdir(parents=True)
    (kok / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    return kok


def test_ghidra_siki_kipte_baska_kuruluma_dusulmez(tmp_path, monkeypatch):
    from karadul import config as cfg_mod
    gomulu = _ghidra_kur(tmp_path / "paket" / "ghidra")
    baska = _ghidra_kur(tmp_path / "baska")
    monkeypatch.setattr(cfg_mod, "_GHIDRA_KNOWN_DIR", str(baska))      # makinedeki başka kurulum
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    # sıkı kip, gömülü kurulum sağlam: o bulunur
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(gomulu))
    monkeypatch.setenv(cfg_mod.GHIDRA_STRICT_ENV, "1")
    bulunan = cfg_mod._find_ghidra_tool("support/analyzeHeadless", "analyzeHeadless")
    assert bulunan == (gomulu / "support" / "analyzeHeadless").resolve()
    # sıkı kip, gömülü kurulum bozuk: başka kuruluma düşülmez, var olmayan gömülü yol döner
    (gomulu / "support" / "analyzeHeadless").unlink()
    bulunan = cfg_mod._find_ghidra_tool("support/analyzeHeadless", "analyzeHeadless")
    assert bulunan == gomulu / "support" / "analyzeHeadless" and not bulunan.exists()
    # sıkı kip kapalı: bugünkü davranış, sabitlenen/bilinen kuruluma düşülür
    monkeypatch.delenv(cfg_mod.GHIDRA_STRICT_ENV)
    bulunan = cfg_mod._find_ghidra_tool("support/analyzeHeadless", "analyzeHeadless")
    assert bulunan == (baska / "support" / "analyzeHeadless").resolve()
    # sıkı kip yalnız "1" ile açılır
    monkeypatch.setenv(cfg_mod.GHIDRA_STRICT_ENV, "0")
    assert cfg_mod._find_ghidra_tool("support/analyzeHeadless", "analyzeHeadless") == \
        (baska / "support" / "analyzeHeadless").resolve()
