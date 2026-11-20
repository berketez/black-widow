"""MUTBAKIM (2026-11-20): tam ad iddiası geçerli tanımlayıcı değilse temizlenip ön ad olarak verilir.

``tests/test_c_namer_susturma.py::test_tam_ad_gecerli_tanimlayici_degilse_temizlenir`` yalnız
"adda boşluk yok ve ad ham metin değil" diyor. ``93a2956`` (ad geçerliliği) sonrası ham metin
ön ad yolunda zaten reddediliyor; bu yüzden ``EXACT_NAME_PATTERN`` denetimi kalkınca
(``mutation_specs_adim3_c_namer.json`` ``cn_tam_ad_bicim_denetimsiz``) o test yine geçiyordu:
ön ad temizlenip verilmek yerine reddediliyor, anahtar başka bir adaydan ad alıyordu. Burada
asıl davranış kilitlenir: tam ad iddialı ama geçersiz tanımlayıcı olan ön ad temizlenir ve
ön ad olarak (``pre_names`` kökeniyle) verilir; ad geçerliliği reddi sayılmaz.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_c_namer_determinism as T  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.c_namer import CVariableNamer  # noqa: E402
from karadul.reconstruction.tarif import baglama  # noqa: E402


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _kos(ws, out, *, pre_names, meta):
    namer = CVariableNamer(Config(), min_confidence=0.15)
    res = namer.analyze_and_rename(ws["decompiled"], ws["functions"], ws["strings"], ws["call_graph"],
                                   out, pre_names=pre_names, pre_name_meta=meta)
    assert res.success, res.errors
    prov = json.loads((out / c_namer.NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))
    harita = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    return res, prov, harita


def test_gecersiz_tam_ad_temizlenip_on_ad_olarak_verilir(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    meta = {"FUN_00001000": {"kind": baglama.KIND_MANUAL, "name": "iki sozcuk", "exact": True}}
    res, prov, harita = _kos(ws, tmp_path / "out", pre_names={"FUN_00001000": "iki sozcuk"},
                             meta=meta)
    assert harita["global"]["FUN_00001000"] == "iki_sozcuk"
    kayit = prov["global"]["FUN_00001000"]
    assert kayit["source"] == "pre_names"
    assert kayit["pre_name_kind"] == baglama.KIND_MANUAL
    assert "invalid_c_identifier" not in res.rejected_name_counts
