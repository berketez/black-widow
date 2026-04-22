"""Readability skorlama paketi.

Decompiled C kaynaginin okunabilirligini 6 boyutta 0-100 arasinda olcer.

Public API:
    ReadabilityScorer  -- Ana sinif
    ScoreResult        -- Skor sonucu
    CompareResult      -- Baseline karsilastirma sonucu
    ScorerConfig       -- Agirlik/esik konfigurasyonu
    DwarfBaseline      -- Debug binary baseline saglayici
"""

from __future__ import annotations

from karadul.quality.config import ScorerConfig
from karadul.quality.dwarf_baseline import DwarfBaseline, DwarfBaselineResult
from karadul.quality.scorer import (
    CompareResult,
    ReadabilityScorer,
    ScoreResult,
)

__all__ = [
    "ReadabilityScorer",
    "ScoreResult",
    "CompareResult",
    "ScorerConfig",
    "DwarfBaseline",
    "DwarfBaselineResult",
]
