"""CFG Isomorphism hibrit matching paketi (v1.10.0 M4 v1.4.0.beta).

Hibrit pipeline: WL fingerprint + LSH aday üretimi → VF2++ exact rerank →
Anchor doğrulama (küçük CFG false-positive koruması).

Public API:
    AttributedCFG, CFGNode, AlgorithmTemplate, CFGMatch -- dataclass'lar
    HybridCFGMatcher  -- orchestrator
    weisfeiler_lehman_hash  -- deterministic graph fingerprint
    default_template_bank  -- elle kurulu 8+ algoritma template'i
"""

from __future__ import annotations

from .fingerprint import (
    AttributedCFG,
    CFGNode,
    weisfeiler_lehman_hash,
)
from .lsh_index import LSHIndex
from .vf2_matcher import vf2_match, vf2_match_with_timeout, to_networkx
from .anchor_check import AnchorValidator
from .template_db import AlgorithmTemplate, default_template_bank
from .matcher import CFGMatch, HybridCFGMatcher

__all__ = [
    "AttributedCFG",
    "CFGNode",
    "AlgorithmTemplate",
    "CFGMatch",
    "HybridCFGMatcher",
    "LSHIndex",
    "AnchorValidator",
    "weisfeiler_lehman_hash",
    "vf2_match",
    "vf2_match_with_timeout",
    "to_networkx",
    "default_template_bank",
]
