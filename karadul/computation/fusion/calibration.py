"""Platt scaling -- raw logit -> calibrated olasilik.

Platt scaling:
    P_calibrated(y=1 | logit) = sigmoid(A * logit + B)

    A=1 ve B=0 -> identity sigmoid (default).
    MLE ile validation set'ten (logit, label) cifti uzerinde A, B ogrenilir.

Fit metodu (gradient descent + damped Newton geri-dusum):
    Az veri durumunda (100 civari) kararli sonuc icin gradient descent
    kullanilir. Buyuk validation set'te Newton daha hizli ama bagimli
    degiliz -- bu RC'de GD, sklearn'a dependency yok.

Smoothing (Platt 1999):
    Asiri guveni azaltmak icin etiketler clamp edilir:
        y_plus  = (N+ + 1) / (N+ + 2)
        y_minus = 1 / (N- + 2)
    Bu, validation set kucukken convergence'i stabil tutar.
"""

from __future__ import annotations

from math import exp, log
from typing import Sequence


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = exp(-x)
        return 1.0 / (1.0 + z)
    z = exp(x)
    return z / (1.0 + z)


class PlattCalibrator:
    """Platt scaling: P = sigmoid(A * logit + B).

    Default ``A=1, B=0`` identity sigmoid -- ``LogOddsEnsemble`` zaten
    positive logit uretir (yuksek logit = yuksek guven), Platt'in
    geleneksel SVM konvansiyonundaki ``A<0`` inversion'u bizde
    GEREKSIZ. Bu yuzden identity sigmoid uygulaniyor, ``fit()``
    cagrilmadigi surece ``calibrate(logit) == sigmoid(logit)``.

    ``fit()`` calibration data varsa A ve B'yi MLE ile gunceller.
    """

    def __init__(self, A: float = 1.0, B: float = 0.0):
        self.A = A
        self.B = B

    # ------------------------------------------------------------------
    def calibrate(self, logit: float) -> float:
        """Ham logit -> calibrated olasilik."""
        return _sigmoid(self.A * logit + self.B)

    # ------------------------------------------------------------------
    def fit(
        self,
        logits: Sequence[float],
        labels: Sequence[int],
        max_iter: int = 200,
        lr: float = 0.05,
        tol: float = 1e-6,
    ) -> None:
        """MLE ile A, B ogren (damped gradient descent).

        Args:
            logits: Raw logit degerleri (herhangi bir reel).
            labels: 0 veya 1.
            max_iter: Maksimum iterasyon.
            lr: Ogrenme orani (adaptive degil, damped).
            tol: |delta_loss| < tol -> dur.

        Raises:
            ValueError: len(logits) != len(labels) veya bos girdi.
        """
        if len(logits) != len(labels):
            raise ValueError(
                f"logits ({len(logits)}) ve labels ({len(labels)}) farkli uzunlukta",
            )
        if not logits:
            raise ValueError("Bos validation set -- fit yapilamaz")

        # Platt smoothing: N_plus, N_minus hesapla
        n_plus = sum(1 for y in labels if y == 1)
        n_minus = sum(1 for y in labels if y == 0)
        if n_plus == 0 or n_minus == 0:
            raise ValueError(
                "Fit icin hem pozitif hem negatif ornek gerekli "
                f"(pos={n_plus}, neg={n_minus})",
            )
        y_plus = (n_plus + 1.0) / (n_plus + 2.0)
        y_minus = 1.0 / (n_minus + 2.0)

        targets = [y_plus if y == 1 else y_minus for y in labels]

        A, B = self.A, self.B
        prev_loss = float("inf")

        for _it in range(max_iter):
            # Loss: cross-entropy
            loss = 0.0
            grad_A = 0.0
            grad_B = 0.0
            for logit, t in zip(logits, targets):
                z = A * logit + B
                p = _sigmoid(z)
                # Numerical-safe log
                eps = 1e-12
                loss -= t * log(p + eps) + (1 - t) * log(1 - p + eps)
                # gradient: dL/dz = (p - t), dz/dA = logit, dz/dB = 1
                err = p - t
                grad_A += err * logit
                grad_B += err

            n = len(logits)
            grad_A /= n
            grad_B /= n
            loss /= n

            A -= lr * grad_A
            B -= lr * grad_B

            if abs(prev_loss - loss) < tol:
                break
            prev_loss = loss

        self.A = A
        self.B = B

    # ------------------------------------------------------------------
    def is_identity(self, atol: float = 1e-6) -> bool:
        """Bu calibrator identity mi? (A=1, B=0 etrafinda)."""
        return abs(self.A - 1.0) < atol and abs(self.B) < atol

    def as_dict(self) -> dict:
        return {"A": self.A, "B": self.B}

    @classmethod
    def from_dict(cls, d: dict) -> "PlattCalibrator":
        return cls(A=float(d.get("A", 1.0)), B=float(d.get("B", 0.0)))
