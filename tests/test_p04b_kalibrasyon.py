"""P04b / MUH-05: güven "kalibrasyonu" hiçbir veri setine uydurulmadığı ve hiçbir karara
girmediği için yapıtlara "kalibre" skor / kademe yazılmaz; ham kanıt sayıları yazılır.

Eski kod `engineering_calibrated.json`'a `calibrated_confidence`, `tier`, `avg_confidence`
yazıyordu. Bu testler eski kodda kırmızıdır.
"""
from __future__ import annotations

import json

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.engineering import ConfidenceCalibrator
from karadul.reconstruction.engineering import confidence_calibrator as CC


def _m(name: str, func: str, conf: float, method: str, ev: list[str]) -> AlgorithmMatch:
    return AlgorithmMatch(name=name, category="fea_integration", confidence=conf,
                          detection_method=method, evidence=ev, function_name=func,
                          address="0x1")


def _calibrated():
    matches = [
        _m("gauss_quadrature_3pt", "_e_c3d_se_", 0.9, "constant",
           ["float: 0.774596669241483", "float: 0.555555555555555", "float: 0.888888888888888"]),
        _m("lu_factorization", "_spooles_factor_", 0.9, "api", ["API call: dgetrf_"]),
    ]
    return ConfidenceCalibrator().calibrate(matches, {}, ["_e_c3d_se_", "_spooles_factor_"])


def test_kayit_kalibre_skor_ve_kademe_yazmaz():
    cal = _calibrated()
    assert cal
    d = cal[0].to_dict()
    assert "calibrated_confidence" not in d and "tier" not in d
    assert d["calibration"] == CC.CALIBRATION_STATUS
    assert d["raw_confidence"] == cal[0].original.confidence
    assert d["evidence_count"] == len(cal[0].original.evidence)
    assert "n_independent_sources" in d and "negative_evidence_count" in d
    json.dumps(d)


def test_ozet_ham_sayilar():
    cal = _calibrated()
    s = ConfidenceCalibrator.summarize(cal)
    for eski in ("by_tier", "avg_confidence", "avg_delta"):
        assert eski not in s
    assert s["total"] == len(cal)
    assert sum(s["by_independent_sources"].values()) == len(cal)
    assert s["calibration"] == CC.CALIBRATION_STATUS
    for row in s["top_5"]:
        assert "tier" not in row and "confidence" not in row


def test_bos_ozet_sahte_sifir_yazmaz():
    s = ConfidenceCalibrator.summarize([])
    assert s["total"] == 0
    assert s["avg_raw_confidence"] is None
    assert "avg_confidence" not in s


def test_olu_ikiz_modul_yok():
    import importlib.util
    assert importlib.util.find_spec(
        "karadul.reconstruction.engineering.confidence_calibration") is None
