"""Log-odds ensemble modeli — feature -> logit -> olasilik.

Neden log-odds + TOPLAMA (Bayesian carpma DEGIL):
    Carpma yontemleri (D-S, naive Bayes odds) feature bagimsizligi varsayar.
    Bizim sinyallerimiz KORELEDIR (byte ve CFG aynı CFG + compiler
    yuzunden). Toplam log-odds + interaction feature ile decorrelate
    daha guvenli.

Model:
    logit = bias + sum_family(w_family . feature_family)
          + sum_ij(w_interaction_ij * x_i * x_j)   <- opsiyonel
    proba = sigmoid(logit)

Default weights:
    Empirik tune olmadan makul baslangic degerleri. weights dosyasindan
    yuklenebilir veya eğitim pipeline'inda optimize edilebilir (bu RC'de
    sadece default + save/load; fit Platt'a birakilir).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from math import exp
from pathlib import Path
from typing import Iterable

from karadul.computation.fusion.features import all_features
from karadul.computation.fusion.types import SignatureCandidate


def _sigmoid(x: float) -> float:
    # Overflow-safe sigmoid.
    if x >= 0:
        z = exp(-x)
        return 1.0 / (1.0 + z)
    z = exp(x)
    return z / (1.0 + z)


@dataclass
class FusionWeights:
    """Log-odds ensemble agirlik tasiyicisi.

    Dikkat: Toplam shape agirlik toplami, context'ten KUCUK olmalidir.
    Aksi halde shape overwhelm eder -- byte+CFG double-counting riski
    artar. Default'lar bu dengeyi korur.
    """

    # Shape -- byte ve CFG korele, koleksiyon olarak dikkatli olcekle.
    w_shape: dict[str, float] = field(default_factory=lambda: {
        "byte_score": 1.8,
        "cfg_hash_similarity": 1.2,
        "func_size_normalized": 0.3,
        "compiler_match": 0.4,
    })
    # Proto -- bagimsiz evidence, daha yuksek agirlik.
    w_proto: dict[str, float] = field(default_factory=lambda: {
        "param_count_match": 1.5,
        "return_type_match": 1.0,
        "cc_match": 0.8,
        "decompiler_conf": 0.6,
    })
    # Context -- korelasyon kiran evidence.
    w_context: dict[str, float] = field(default_factory=lambda: {
        "callgraph_position": 1.6,
        "caller_callee_overlap": 0.9,
        "import_context_similarity": 1.2,
    })
    # Interaction -- shape x context guclendirici.
    w_interaction: dict[str, float] = field(default_factory=lambda: {
        "shape_x_context": 1.4,
        "proto_x_context": 1.0,
        "shape_weighted_context": 0.8,
    })
    bias: float = -3.5  # Default dusuk prior -- false positive'ler suspect.

    @classmethod
    def default(cls) -> FusionWeights:
        """Makul bir default agirlik seti."""
        return cls()

    def save(self, path: Path) -> None:
        """JSON olarak kaydet (human-readable, diff-friendly)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: Path) -> FusionWeights:
        with open(Path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            w_shape=data.get("w_shape", {}),
            w_proto=data.get("w_proto", {}),
            w_context=data.get("w_context", {}),
            w_interaction=data.get("w_interaction", {}),
            bias=float(data.get("bias", 0.0)),
        )

    def _all_named_weights(self) -> Iterable[tuple[str, dict[str, float]]]:
        yield "shape", self.w_shape
        yield "proto", self.w_proto
        yield "context", self.w_context
        yield "interaction", self.w_interaction


class LogOddsEnsemble:
    """logit = bias + sum(w_i * x_i); proba = sigmoid(logit)."""

    def __init__(self, weights: FusionWeights | None = None):
        self.weights = weights or FusionWeights.default()

    def predict_logit(self, features: dict[str, float]) -> float:
        """Tum feature aileleri icin dogrusal kombinasyon + bias."""
        total = self.weights.bias
        for _family, wdict in self.weights._all_named_weights():
            for fname, w in wdict.items():
                x = features.get(fname, 0.0)
                total += w * x
        return total

    def predict_proba(self, logit: float) -> float:
        """sigmoid(logit) -> [0,1]."""
        return _sigmoid(logit)

    def feature_contributions(
        self, features: dict[str, float],
    ) -> dict[str, float]:
        """Her feature icin ``w_i * x_i`` katkisini dondur (explainability).

        Bias kendi satiri olarak eklenir (``__bias__``).
        """
        out: dict[str, float] = {"__bias__": self.weights.bias}
        for _family, wdict in self.weights._all_named_weights():
            for fname, w in wdict.items():
                x = features.get(fname, 0.0)
                out[fname] = w * x
        return out

    def predict_from_candidate(
        self, candidate: SignatureCandidate,
    ) -> tuple[float, float, dict[str, float]]:
        """Convenience: candidate -> (logit, proba, contributions).

        Feature extraction burada yapilir; fuser bu metodu kullanir.
        """
        feats = all_features(candidate)
        logit = self.predict_logit(feats)
        proba = self.predict_proba(logit)
        contribs = self.feature_contributions(feats)
        return logit, proba, contribs
