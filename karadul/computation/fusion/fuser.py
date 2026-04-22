"""SignatureFuser -- 4-aile sinyali tek calibrated probability'e birlestirir.

Pipeline:
    candidate -> features (4 aile) -> LogOddsEnsemble -> raw_logit
              -> PlattCalibrator -> calibrated_probability
              -> DecisionConfig -> accept / reject / abstain

Decision seviyeleri (sinirlar simetrik — esit degerler kabul/ret'e gider):
    [0, reject_threshold]          -> "reject"
    (reject_threshold, accept)     -> "abstain"   (recall trade-off)
    [accept_threshold, 1]          -> "accept"

Abstain DESTEKLEN ZORUNLUDUR -- precision@coverage hedefine ulasmak icin
orta-guven adaylari reddedip recall'dan feragat etmek tek yol.
"""

from __future__ import annotations

from dataclasses import dataclass

from karadul.computation.fusion.calibration import PlattCalibrator
from karadul.computation.fusion.model import FusionWeights, LogOddsEnsemble
from karadul.computation.fusion.types import FusedMatch, SignatureCandidate


@dataclass
class DecisionConfig:
    """Karar esikleri.

    Default (0.90 / 0.30) karadul.computation.config'ten okunabilir;
    bu dataclass fuser'a direkt cagri icin convenience tasir.
    """

    accept_threshold: float = 0.90
    reject_threshold: float = 0.30

    def __post_init__(self) -> None:
        if not (0.0 <= self.reject_threshold <= self.accept_threshold <= 1.0):
            raise ValueError(
                "Thresholds 0 <= reject <= accept <= 1 olmali: "
                f"reject={self.reject_threshold}, accept={self.accept_threshold}",
            )


class SignatureFuser:
    """Ana orkestratör -- aday listesini FusedMatch listesine cevirir."""

    def __init__(
        self,
        weights: FusionWeights | None = None,
        calibrator: PlattCalibrator | None = None,
        decision: DecisionConfig | None = None,
        calibration_enabled: bool = True,
    ):
        self.ensemble = LogOddsEnsemble(weights or FusionWeights.default())
        self.calibrator = calibrator or PlattCalibrator()  # identity default
        self.decision = decision or DecisionConfig()
        self.calibration_enabled = calibration_enabled

    # ------------------------------------------------------------------
    def fuse_one(self, candidate: SignatureCandidate) -> FusedMatch:
        logit, raw_proba, contribs = self.ensemble.predict_from_candidate(
            candidate,
        )
        if self.calibration_enabled:
            p = self.calibrator.calibrate(logit)
        else:
            p = raw_proba

        # C4: sinir noktalari simetrik olmali -- hem accept hem reject
        # dahil (>= ve <=). Mevcut asimetri (p < reject, p >= accept)
        # sınır noktasinda (p == reject_threshold) asimetrik davranis
        # uretiyordu. Simdi p == reject -> "reject", p == accept -> "accept".
        if p >= self.decision.accept_threshold:
            dec = "accept"
        elif p <= self.decision.reject_threshold:
            dec = "reject"
        else:
            dec = "abstain"

        return FusedMatch(
            symbol_name=candidate.symbol_name,
            raw_logit=logit,
            calibrated_probability=p,
            decision=dec,
            feature_contributions=contribs,
        )

    # ------------------------------------------------------------------
    def fuse(
        self, candidates: list[SignatureCandidate],
    ) -> list[FusedMatch]:
        """Her aday icin fuse_one cagir. Sirasi korunur."""
        return [self.fuse_one(c) for c in candidates]

    # ------------------------------------------------------------------
    @classmethod
    def from_computation_config(cls, cfg) -> "SignatureFuser":
        """``ComputationConfig``'ten threshold'lari yukle.

        cfg: karadul.computation.config.ComputationConfig

        weights_path None ise FusionWeights.default().
        """
        weights = FusionWeights.default()
        weights_path = getattr(cfg, "fusion_weights_path", None)
        if weights_path:
            from pathlib import Path
            p = Path(weights_path)
            if p.exists():
                weights = FusionWeights.load(p)
        decision = DecisionConfig(
            accept_threshold=getattr(cfg, "fusion_accept_threshold", 0.90),
            reject_threshold=getattr(cfg, "fusion_reject_threshold", 0.30),
        )
        return cls(
            weights=weights,
            calibrator=PlattCalibrator(),
            decision=decision,
            calibration_enabled=getattr(cfg, "fusion_calibration_enabled", True),
        )
