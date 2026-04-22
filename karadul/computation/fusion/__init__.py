"""Signature fusion — log-odds ensemble + Platt calibration (v1.10.0 M4 v1.4.0.rc1).

Bu paket, binary signature eslesmelerinden gelen coklu sinyalleri (byte,
yapisal/CFG, prototype, callgraph/context) TEK bir calibrated confidence'a
birlestirir.

Neden log-odds (NAIVE BAYES / DEMPSTER-SHAFER DEGIL):
    Byte skoru ve CFG skoru KORELEDIR. Bagimsizlik varsayan yontemler
    (Dempster-Shafer carpma, naive Bayes odds carpma) overconfident
    olur (double-counting). Log-odds ensemble feature'lari TOPLAR ve
    interaction term ile korelasyonu decorrelate eder; Platt scaling
    ise olasilik kalibrasyonu yapar.

Hedef metrikler:
    precision@coverage_0.5 >= 0.90
    precision@coverage_0.2 >= 0.95
    precision@full_coverage >= 0.95 ISTEMEK FANTAZI -- abstain kullan.

Public API:
    SignatureCandidate, FusedMatch  -- I/O dataclass'lar
    FusionWeights, DecisionConfig    -- model konfigurasyonu
    LogOddsEnsemble                  -- feature -> logit -> proba
    PlattCalibrator                  -- logit -> calibrated prob
    SignatureFuser                   -- orchestrator
    FusionEvaluator                  -- precision@coverage egrisi
    shape_features, proto_features, context_features, interaction_features
"""

from __future__ import annotations

from karadul.computation.fusion.calibration import PlattCalibrator
from karadul.computation.fusion.evaluator import FusionEvaluator
from karadul.computation.fusion.features import (
    context_features,
    interaction_features,
    proto_features,
    shape_features,
)
from karadul.computation.fusion.fuser import DecisionConfig, SignatureFuser
from karadul.computation.fusion.model import FusionWeights, LogOddsEnsemble
from karadul.computation.fusion.types import FusedMatch, SignatureCandidate

__all__ = [
    "SignatureCandidate",
    "FusedMatch",
    "FusionWeights",
    "DecisionConfig",
    "LogOddsEnsemble",
    "PlattCalibrator",
    "SignatureFuser",
    "FusionEvaluator",
    "shape_features",
    "proto_features",
    "context_features",
    "interaction_features",
]
