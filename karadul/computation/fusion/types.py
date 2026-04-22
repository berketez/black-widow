"""Fusion paketi icin giris/cikis dataclass'lari.

SignatureCandidate: fonksiyon basina coklu sinyal (byte, CFG, proto, context).
FusedMatch: fuser ciktisi -- raw logit, calibrated probability, decision,
    feature contribution detayi.

Tum alanlar opsiyonel tutulur ki farkli kaynaklarin eksik sinyalleri
(ornek: CFG hash'i hesaplanamamis, import context bulunamamis) pipeline'i
patlatmasin. Missing feature -> fallback prior (0.5 katki ~ logit 0)
model tarafinda ele alinir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SignatureCandidate:
    """Tek bir sembol/fonksiyon icin aday signature eslesmesi.

    Alanlar 4 aile halinde gruplanir (bkz. ``features.py``):
        shape (byte_score, cfg_hash, func_size, compiler_bucket)
        proto (param_count, return_type, cc_match, decompiler_conf)
        context (callgraph_pos, caller_overlap, import_context)

    Eksik sinyaller None olur -> feature extractor o aileyi 0 katki ile
    doldurur (neutral prior).
    """

    symbol_name: str
    # --- shape ---
    byte_score: float = 0.0  # 0-1, FLIRT / byte pattern eslesme gucu
    cfg_hash: str = ""  # WL fingerprint hex
    func_size: int = 0  # Byte cinsinden fonksiyon boyutu
    compiler_bucket: str = "unknown"  # gcc | clang | msvc | unknown
    # --- proto ---
    param_count: Optional[int] = None
    return_type: Optional[str] = None
    cc_match: Optional[bool] = None  # Calling convention uyuyor mu
    decompiler_conf: Optional[float] = None  # 0-1, decompiler'in kendi guveni
    # --- context ---
    callgraph_pos: Optional[dict] = None  # {"callers": [...], "callees": [...]}
    caller_overlap: Optional[float] = None  # 0-1, caller set Jaccard
    import_context: Optional[list[str]] = None  # Binary'nin import ettigi API'lar

    # Referans icin expected/reference prototype bilgileri (candidate
    # 'beklenen' prototipi bilirse, match buradan hesaplanir)
    reference_param_count: Optional[int] = None
    reference_return_type: Optional[str] = None
    reference_cfg_hash: Optional[str] = None
    reference_callers: Optional[list[str]] = None
    reference_callees: Optional[list[str]] = None
    reference_imports: Optional[list[str]] = None

    def has_shape(self) -> bool:
        return self.byte_score > 0.0 or bool(self.cfg_hash) or self.func_size > 0

    def has_proto(self) -> bool:
        return (
            self.param_count is not None
            or self.return_type is not None
            or self.cc_match is not None
            or self.decompiler_conf is not None
        )

    def has_context(self) -> bool:
        return (
            self.callgraph_pos is not None
            or self.caller_overlap is not None
            or bool(self.import_context)
        )


@dataclass
class FusedMatch:
    """Fuser ciktisi -- tek bir aday icin final karar + explainability."""

    symbol_name: str
    raw_logit: float
    calibrated_probability: float  # 0-1
    decision: str  # "accept" | "reject" | "abstain"
    feature_contributions: dict[str, float] = field(default_factory=dict)

    def is_accepted(self) -> bool:
        return self.decision == "accept"

    def is_rejected(self) -> bool:
        return self.decision == "reject"

    def is_abstained(self) -> bool:
        return self.decision == "abstain"

    def top_contributions(self, k: int = 5) -> list[tuple[str, float]]:
        """En etkili k feature (|contribution| sirali)."""
        items = sorted(
            self.feature_contributions.items(),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        return items[:k]
