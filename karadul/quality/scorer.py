"""ReadabilityScorer -- decompiled C kod okunabilirlik skorlayicisi.

6 boyuta ayrilmis skorlama:
    1. Fonksiyon isimleri   (weight 0.25)
    2. Parametre isimleri   (weight 0.15)
    3. Lokal degiskenler    (weight 0.15)
    4. Tip kalitesi         (weight 0.20)
    5. Yorumlar             (weight 0.10)
    6. Kod yapisi           (weight 0.15)

Toplam skor agirlikli toplamdir (0-100).

Kullanim:
    from karadul.quality import ReadabilityScorer

    scorer = ReadabilityScorer()
    result = scorer.score_directory(Path("reconstructed/src"))
    print(result.total_score, result.dimensions)

    # Debug binary ile karsilastir
    baseline = scorer.score_ground_truth(Path("debug_binary"))
    delta = scorer.compare(baseline, result)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.quality.config import GROUND_TRUTH_SCORE, ScorerConfig
from karadul.quality.dwarf_baseline import DwarfBaseline, DwarfBaselineResult
from karadul.quality.metrics import (
    CodeStructureMetric,
    CommentsMetric,
    FunctionNamesMetric,
    LocalVarsMetric,
    ParamNamesMetric,
    TypeQualityMetric,
)

logger = logging.getLogger(__name__)

# Tarama icin hedef uzantilar
_SOURCE_EXTENSIONS: tuple[str, ...] = (".c", ".h")


@dataclass
class ScoreResult:
    """Readability skor sonucu.

    Attributes:
        total_score: Agirlikli toplam skor (0-100).
        dimensions: Her boyut icin skor (0-100).
        details: Ham sayilar ve detaylar.
        source: Kaynak dizini veya binary yolu.
    """

    total_score: float
    dimensions: dict[str, float]
    details: dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def summary(self) -> str:
        """Kisa ozet stringi (CLI cikisi icin)."""
        lines = [f"Total: {self.total_score:.2f}/100"]
        for name, score in self.dimensions.items():
            lines.append(f"  - {name}: {score:.2f}")
        return "\n".join(lines)


@dataclass
class CompareResult:
    """Baseline (debug) vs reconstructed skor karsilastirmasi.

    Attributes:
        baseline_score: Ground truth (debug) skoru -- tanim geregi 100.
        reconstructed_score: Olculen skor.
        delta: baseline - reconstructed.
        normalized: reconstructed / baseline * 100 (yani dogrudan yuzde).
        dimension_deltas: Her boyut icin (baseline, reconstructed, delta).
    """

    baseline_score: float
    reconstructed_score: float
    delta: float
    normalized: float
    dimension_deltas: dict[str, dict[str, float]]


class ReadabilityScorer:
    """Ana skorlayici -- 6 boyutu birlestirip agirlikli toplam hesaplar."""

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()
        # Validation: agirliklar toplamı 1.0 olmali
        self.config.validate()

        self._metrics = {
            "function_names": (
                FunctionNamesMetric(self.config),
                self.config.weight_function_names,
            ),
            "param_names": (
                ParamNamesMetric(self.config),
                self.config.weight_param_names,
            ),
            "local_vars": (
                LocalVarsMetric(self.config),
                self.config.weight_local_vars,
            ),
            "type_quality": (
                TypeQualityMetric(self.config),
                self.config.weight_type_quality,
            ),
            "comments": (
                CommentsMetric(self.config),
                self.config.weight_comments,
            ),
            "code_structure": (
                CodeStructureMetric(self.config),
                self.config.weight_code_structure,
            ),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_directory(
        self,
        directory: Path,
        extensions: tuple[str, ...] = _SOURCE_EXTENSIONS,
        file_cache: dict[str, str] | None = None,
    ) -> ScoreResult:
        """Bir dizindeki tum C kaynaklarini skorla.

        Args:
            directory: Taranacak dizin. Recursive.
            extensions: Hedef uzantilar.
            file_cache: v1.10.0 C2 -- ``dosya_adi -> kaynak`` onbellek.
                Verilirse 6 metric tek-okuma ile skorlanir (disk I/O ~6×
                azalir). Cache miss disk fallback.

        Returns:
            ScoreResult.
        """
        directory = Path(directory)
        if not directory.exists():
            return ScoreResult(
                total_score=0.0,
                dimensions={name: 0.0 for name in self._metrics},
                details={"error": f"Dizin yok: {directory}"},
                source=str(directory),
            )

        c_files = self._collect_files(directory, extensions)
        return self._score_files(
            c_files, source=str(directory), file_cache=file_cache,
        )

    def score_files(
        self,
        files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> ScoreResult:
        """Verilen dosya listesini skorla.

        v1.10.0 C2: ``file_cache`` ile 6× disk I/O tasarrufu.
        """
        return self._score_files(
            list(files), source="files", file_cache=file_cache,
        )

    def score_ground_truth(self, binary_path: Path) -> DwarfBaselineResult:
        """Debug binary'sinden ground truth baseline dondur.

        Debug bilgisi varsa score=100 (tanim geregi). Yoksa available=False.
        """
        baseline = DwarfBaseline(Path(binary_path))
        return baseline.result()

    def compare(
        self,
        baseline: DwarfBaselineResult,
        reconstructed: ScoreResult,
    ) -> CompareResult:
        """Baseline (debug) vs reconstructed karsilastirma.

        Baseline skoru tanim geregi 100'dur. Normalized skor zaten
        reconstructed'in kendisi (0-100 oldugu icin).
        """
        baseline_score = GROUND_TRUTH_SCORE if baseline.available else 0.0
        recon_score = reconstructed.total_score

        dimension_deltas: dict[str, dict[str, float]] = {}
        for name, score in reconstructed.dimensions.items():
            # Baseline her boyutta 100 varsayilir
            bl = GROUND_TRUTH_SCORE if baseline.available else 0.0
            dimension_deltas[name] = {
                "baseline": bl,
                "reconstructed": score,
                "delta": bl - score,
            }

        return CompareResult(
            baseline_score=baseline_score,
            reconstructed_score=recon_score,
            delta=baseline_score - recon_score,
            normalized=recon_score if baseline_score > 0 else 0.0,
            dimension_deltas=dimension_deltas,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_files(
        directory: Path, extensions: tuple[str, ...],
    ) -> list[Path]:
        """Recursive .c/.h dosya toplama."""
        files: list[Path] = []
        for ext in extensions:
            files.extend(directory.rglob(f"*{ext}"))
        # Deterministik siralama
        return sorted(files)

    def _score_files(
        self,
        files: list[Path],
        source: str,
        file_cache: dict[str, str] | None = None,
    ) -> ScoreResult:
        """Iç: dosya listesini metric'lerden gecir ve agirlikli toplam uret.

        v1.10.0 C2: ``file_cache`` metric'lere iletilir. Metric
        ``score(files, file_cache=None)`` signature'ini kabul etmiyorsa
        (geriye uyumluluk) TypeError yakalanir ve cache'siz dusulur.
        """
        dimensions: dict[str, float] = {}
        details: dict[str, Any] = {"file_count": len(files)}

        weighted_sum = 0.0
        for name, (metric, weight) in self._metrics.items():
            try:
                try:
                    result = metric.score(files, file_cache=file_cache)
                except TypeError:
                    # Eski signature: score(files) — cache desteklemiyor
                    result = metric.score(files)
            except Exception as exc:
                logger.warning("Metric %s hata: %s", name, exc)
                dimensions[name] = 0.0
                details[name] = {"error": str(exc)}
                continue
            dimensions[name] = result.score
            details[name] = result.details
            weighted_sum += result.score * weight

        return ScoreResult(
            total_score=round(weighted_sum, 4),
            dimensions={k: round(v, 4) for k, v in dimensions.items()},
            details=details,
            source=source,
        )

    # ------------------------------------------------------------------
    # Tanimlayici
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        metric_names = list(self._metrics.keys())
        return (
            "ReadabilityScorer("
            f"metrics={metric_names}, "
            f"weights_total={self.config.total_weight():.2f})"
        )
