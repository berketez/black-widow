"""Struct layout MaxSMT kurtarma — v1.4.0.alpha.

Public API:
    - StructLayoutSolver: Ana cozucu sinif.
    - AliasingAnalyzer: same_object vs same_type ayirimiyla alias analizi.
    - CandidateSynthesizer: Access pattern -> aday struct listesi.
    - Dataclass'lar: MemoryAccess, StructField, StructCandidate,
      AliasClass, RecoveredStructLayout.
"""

from __future__ import annotations

from karadul.computation.struct_recovery.aliasing import AliasingAnalyzer
from karadul.computation.struct_recovery.candidate_synthesizer import (
    CandidateSynthesizer,
    collect_accesses_per_family,
)
from karadul.computation.struct_recovery.solver import StructLayoutSolver
from karadul.computation.struct_recovery.types import (
    AliasClass,
    MemoryAccess,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
)

__all__ = [
    "AliasClass",
    "AliasingAnalyzer",
    "CandidateSynthesizer",
    "MemoryAccess",
    "RecoveredStructLayout",
    "StructCandidate",
    "StructField",
    "StructLayoutSolver",
    "collect_accesses_per_family",
]
