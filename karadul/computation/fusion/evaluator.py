"""Fusion output icin precision@coverage egrisi + matematik verifiyer.

precision@coverage:
    Adaylari calibrated_probability'e gore azalan sirada siralarsak,
    ilk N=coverage*len(all) kadarini kabul ettigimizde precision ne
    olur?

Matematik (codex teyit):
    Precision = pi*TPR / (pi*TPR + (1-pi)*FPR)
    0.95 hedefi icin:
        FPR <= pi*TPR*0.05 / ((1-pi)*0.95)
    pi=0.20, TPR=0.80 -> FPR <= 0.0105
    pi=0.02, TPR=0.80 -> FPR <= 0.00086

Evaluator bu formülü ``required_fpr_for_precision`` icinde expose eder.
"""

from __future__ import annotations

from karadul.computation.fusion.types import FusedMatch


class FusionEvaluator:
    """Precision@coverage + teorik FPR butce hesabi."""

    def precision_at_coverage(
        self,
        matches: list[FusedMatch],
        ground_truth: dict[str, bool],
        coverage_levels: list[float] | None = None,
    ) -> dict[float, float]:
        """Azalan probability siralamasinda ilk coverage*N'in precision'i.

        Args:
            matches: FusedMatch listesi (sira onemli degil, icerde siralanir).
            ground_truth: {symbol_name: True/False} -- gercek etiket.
            coverage_levels: [0.1, 0.2, 0.5, 0.8, 1.0] default.

        Returns:
            {coverage: precision}. ground_truth eksik sembol -> False kabul.
        """
        if coverage_levels is None:
            coverage_levels = [0.1, 0.2, 0.5, 0.8, 1.0]

        if not matches:
            return {cv: 0.0 for cv in coverage_levels}

        # En guvenden az guvene sirala
        ordered = sorted(
            matches,
            key=lambda m: m.calibrated_probability,
            reverse=True,
        )
        n = len(ordered)

        out: dict[float, float] = {}
        for cv in coverage_levels:
            cv_clamped = max(0.0, min(1.0, cv))
            k = max(1, int(round(cv_clamped * n)))
            top_k = ordered[:k]
            if not top_k:
                out[cv] = 0.0
                continue
            tp = sum(
                1 for m in top_k if ground_truth.get(m.symbol_name, False)
            )
            out[cv] = tp / len(top_k)
        return out

    # ------------------------------------------------------------------
    @staticmethod
    def required_fpr_for_precision(
        target_precision: float,
        tpr: float,
        prevalence: float,
    ) -> float:
        """Hedef precision icin maksimum tolere edilen FPR.

        Formul (codex teyit):
            FPR <= pi*TPR*(1-P) / ((1-pi)*P)

        Args:
            target_precision: Hedef precision (0-1).
            tpr: True positive rate / recall (0-1).
            prevalence: Pozitif sinif orani (0-1).

        Returns:
            Izin verilen maksimum FPR.
        """
        if not (0 < target_precision < 1):
            raise ValueError(
                f"target_precision (0,1) araliginda olmali: {target_precision}",
            )
        if not (0 <= tpr <= 1):
            raise ValueError(f"tpr [0,1] olmali: {tpr}")
        if not (0 < prevalence < 1):
            raise ValueError(
                f"prevalence (0,1) araliginda olmali: {prevalence}",
            )
        numerator = prevalence * tpr * (1.0 - target_precision)
        denominator = (1.0 - prevalence) * target_precision
        return numerator / denominator

    # ------------------------------------------------------------------
    @staticmethod
    def precision_from_rates(
        tpr: float, fpr: float, prevalence: float,
    ) -> float:
        """Precision = pi*TPR / (pi*TPR + (1-pi)*FPR)."""
        pi = prevalence
        num = pi * tpr
        den = num + (1 - pi) * fpr
        if den <= 0:
            return 0.0
        return num / den

    # ------------------------------------------------------------------
    def acceptance_stats(
        self, matches: list[FusedMatch],
    ) -> dict[str, int]:
        """accept/reject/abstain sayaci."""
        acc = sum(1 for m in matches if m.decision == "accept")
        rej = sum(1 for m in matches if m.decision == "reject")
        absn = sum(1 for m in matches if m.decision == "abstain")
        return {"accept": acc, "reject": rej, "abstain": absn, "total": len(matches)}

    # ------------------------------------------------------------------
    def precision_of_accepted(
        self,
        matches: list[FusedMatch],
        ground_truth: dict[str, bool],
    ) -> float:
        """Sadece ``decision == accept`` olanlar uzerinde precision."""
        accepted = [m for m in matches if m.decision == "accept"]
        if not accepted:
            return 0.0
        tp = sum(
            1 for m in accepted if ground_truth.get(m.symbol_name, False)
        )
        return tp / len(accepted)
