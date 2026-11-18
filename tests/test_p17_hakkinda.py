"""P17 / ARAYUZ-03: Hakkında notundaki ad ölçümü tek kaynaktan gelir.

Eski not "F1 ~0.45-0.49" diyordu (yalnız LTO'lu Ubuntu coreutils ölçümü). Yeni not son ürün
ölçümünün JSON'undaki sayıları taşır; bu test her sayının kaynak dosyadakiyle aynı olduğunu ve
metnin o sayılardan üretildiğini denetler.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"


@pytest.fixture(scope="module")
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_about", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def olcum(srv):
    path = _ROOT / srv._NAME_MEASUREMENT["source"]
    if not path.is_file():
        pytest.skip("ölçüm JSON'u depoda yok")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["kollar"][srv._NAME_MEASUREMENT["arm"]]


def test_no_stale_f1_claim(srv):
    joined = " ".join(srv._ABOUT_NOTES)
    assert "F1" not in joined
    assert "0.45" not in joined and "0,45" not in joined


def test_measurement_values_match_source(srv, olcum):
    m = srv._NAME_MEASUREMENT
    havuz = olcum["toplam"]["havuz"]
    assert olcum["kol"]["ad"] == m["arm_name"]
    assert m["named"] == havuz["ad_verilen"]
    assert m["wrong"] == havuz["yanlis"]
    assert m["wrong"] == havuz["yanlis_orani"]["k"]
    assert m["population"] == havuz["dogru_kapsam"]["n"]
    assert m["exact_correct"] == havuz["dogru_kapsam"]["k"]
    assert m["macro_wrong"] == olcum["toplam"]["makro"]["yanlis_orani"]["makro"]
    kesin = olcum["kesin_etiket"]["havuz"]
    assert m["certain_named"] == kesin["ad_verilen"]
    assert m["certain_correct"] == kesin["dogru"]


def test_note_text_carries_source_numbers(srv, olcum):
    havuz = olcum["toplam"]["havuz"]
    text = " ".join(srv._ABOUT_NOTES)
    # oranlar kaynaktaki k/n'den, belgelerdeki yazımla (%29,7)
    assert srv._tr_pct(havuz["yanlis_orani"]["oran"]) in text
    assert srv._tr_pct(olcum["toplam"]["makro"]["yanlis_orani"]["makro"]) in text
    assert srv._tr_pct(havuz["dogru_kapsam"]["oran"]) in text
    assert srv._tr_pct(olcum["kesin_etiket"]["havuz"]["kesinlik"]["oran"]) in text
    assert srv._tr_int(havuz["ad_verilen"]) in text
    assert srv._tr_int(havuz["yanlis"]) in text
    assert srv._NAME_MEASUREMENT["source"] in text
    assert srv._tr_pct(0.297214) == "%29,7"
    assert srv._tr_int(21371) == "21 371"


def test_about_endpoint_serves_the_notes(srv):
    static = srv._about_static()
    assert static["notes"] == list(srv._ABOUT_NOTES)
    assert srv._about_fallback()["notes"][: len(srv._ABOUT_NOTES)] == list(srv._ABOUT_NOTES)
