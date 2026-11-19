"""P12c kalem 5 (P13a kalanı a; AD-07): ön adın güveni tek kuraldan.

``c_namer.measured_pre_name_confidence``: kanalın ölçülmüş kesinliğinin Wilson alt sınırı
(``naming_labels.MEASURED_PRE_NAME_PRECISION``), ölçülmemiş kanalda ``None``. c_namer'ın ön ad
yolu bunu kullanır; c_namer koşmadığında birleştiriciye giden ön adlar da (yama
``yamalar/P12c___feedback_naming_candidates.py.patch``) aynı kuralı okur.
"""
from __future__ import annotations

from karadul.core.naming_labels import MEASURED_PRE_NAME_PRECISION, STRATEGY_KS1
from karadul.reconstruction.c_namer import measured_pre_name_confidence, pre_name_strategy


def test_olculmus_kanal_wilson_alt_siniri():
    assert measured_pre_name_confidence({"kind": "gnulib", "name": "x"}) == \
        MEASURED_PRE_NAME_PRECISION["on_ad:gnulib"][2]
    assert measured_pre_name_confidence({"kind": "elf_onyuk", "name": "x"}) == \
        MEASURED_PRE_NAME_PRECISION["on_ad:elf_onyuk"][2]
    ks1 = {"kind": "ks1", "name": "x", STRATEGY_KS1: {"satirlar": ["func_kalibi"]}}
    assert measured_pre_name_confidence(ks1) == MEASURED_PRE_NAME_PRECISION["ks1:func_kalibi"][2]
    assert pre_name_strategy(ks1) == STRATEGY_KS1


def test_olculmemis_kanal_none():
    assert measured_pre_name_confidence(None) is None          # künyesiz ön ad
    assert measured_pre_name_confidence({"kind": "faz1", "name": "x"}) is None
    assert measured_pre_name_confidence({"kind": "elle", "name": "x"}) is None
    assert pre_name_strategy(None) == "binary_extract"
