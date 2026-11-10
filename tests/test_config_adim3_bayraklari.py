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
