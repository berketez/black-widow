"""Coklu kaynak isim birlestirme modulu -- Bayesian fusion.

Birden fazla naming kaynagindan gelen isimleri korelasyon-aware
Bayesian log-odds birlestiricisi ile birlestirip en iyi ismi secer.

Kaynaklar:
- c_namer.py (6 heuristik + LLM4Decompile)
- binary_name_extractor.py (debug string, RTTI, build path)
- string_intelligence.py (error msg, protocol handler)
- signature_db.py (library function matching)
- source_matcher (npm package matching)
- swift_demangle (Swift symbol demangling)
- byte_pattern (library function byte pattern matching)

Birlestirme stratejisi (Bayesian):
    Her kaynak bir log-likelihood ratio (LR) uretir. Korelasyonlu
    kaynaklar icin LR, w_i < 1 ustu ile zayiflatilir:

        log_odds = log(prior / (1-prior))
                   + SUM_i  w_i * log(conf_i / (1 - conf_i))

        P(dogru) = sigmoid(log_odds)

    w_i = 1 -> tamamen bagimsiz (naive Bayes)
    w_i < 1 -> korelasyon duzeltmesi

    Bkz: docs/IMPOSSIBLE-RE-MATH-ANALYSIS.md Bolum 4.4

Gruplandirma:
    Adaylar once normalize isim bazli gruplara ayrilir
    (exact, partial, semantic). Her gruptaki adaylar
    birlikte Bayesian merge'e girer.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from karadul.config import NameMergerConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class NamingCandidate:
    """Tek bir kaynaktan gelen isim onerisi."""
    name: str
    confidence: float
    source: str  # "c_namer", "binary_extractor", "string_intel", "signature_db", "source_matcher", "llm4decompile", ...
    reason: str = ""


@dataclass
class MergedName:
    """Birlestirilmis final isim."""
    original_name: str  # FUN_xxx, var_N, etc.
    final_name: str
    final_confidence: float
    sources: list[str] = field(default_factory=list)
    all_candidates: list[NamingCandidate] = field(default_factory=list)
    merge_method: str = ""  # "bayesian_multi", "bayesian_partial", "bayesian_semantic", "bayesian_voting", "bayesian_single", "unk"


@dataclass
class MergeResult:
    """Tum birlestirme sonucu."""
    total_symbols: int = 0
    total_merged: int = 0
    total_unk: int = 0  # UNK: yeterli guven saglanamayan semboller
    merged_names: dict[str, MergedName] = field(default_factory=dict)  # old_name -> MergedName
    conflicts_resolved: int = 0
    exact_multi_matches: int = 0
    partial_matches: int = 0
    voting_wins: int = 0


# Semantic similarity icin kelime gruplamalari
_SEMANTIC_GROUPS = {
    frozenset({"send", "transmit", "write", "emit", "dispatch", "post"}),
    frozenset({"recv", "receive", "read", "get", "fetch"}),
    frozenset({"init", "initialize", "setup", "create", "construct", "new", "alloc"}),
    frozenset({"destroy", "cleanup", "teardown", "free", "delete", "release", "close", "dispose"}),
    frozenset({"parse", "decode", "deserialize", "unmarshal", "extract"}),
    frozenset({"serialize", "encode", "marshal", "format", "stringify"}),
    frozenset({"handle", "process", "on", "dispatch", "callback", "handler"}),
    frozenset({"check", "validate", "verify", "test", "assert", "is", "has"}),
    frozenset({"lock", "acquire", "enter", "begin", "grab"}),
    frozenset({"unlock", "release", "leave", "end", "drop"}),
    frozenset({"add", "insert", "append", "push", "enqueue", "put"}),
    frozenset({"remove", "delete", "erase", "pop", "dequeue", "take"}),
    frozenset({"size", "length", "count", "num", "len", "total"}),
    frozenset({"buf", "buffer", "data", "bytes", "payload", "blob"}),
    frozenset({"msg", "message", "packet", "frame", "request", "response"}),
    frozenset({"err", "error", "fault", "failure", "exception"}),
    frozenset({"ctx", "context", "state", "env", "session"}),
    frozenset({"cfg", "config", "configuration", "settings", "options", "prefs"}),
    frozenset({"conn", "connection", "socket", "link", "channel"}),
    frozenset({"log", "print", "trace", "debug", "info", "warn"}),
}


# ---------------------------------------------------------------------------
# Bayesian core
# ---------------------------------------------------------------------------

def bayesian_merge(
    confidences: list[float],
    sources: list[str],
    cfg: NameMergerConfig,
) -> float:
    """Korelasyon-aware Bayesian birlestirme.

    Log-odds formunda:
        log_odds = log(prior/(1-prior))
                   + SUM_i  w_i * log(conf_i / (1 - conf_i))

    w_i kaynak bazli agirlik -- korelasyonu absorbe eder.
    w_i = 1 -> tamamen bagimsiz kaynak.
    w_i < 1 -> diger kaynaklarla korelasyonlu.

    Args:
        confidences: Her adayin confidence degeri (0-1 arasi)
        sources: Her adayin kaynak ismi
        cfg: NameMergerConfig (weights, thresholds)

    Returns:
        Birlestirilmis posterior olasilik [min_confidence, max_confidence]
    """
    if not confidences:
        return cfg.multi_source_prior

    # Prior: uniform (0.5) -> log_odds = 0
    log_odds = math.log(cfg.multi_source_prior / (1.0 - cfg.multi_source_prior))

    for conf, source in zip(confidences, sources):
        # Confidence'i [0.01, 0.99] araligina klipleyelim ki log(0) patlamamsin
        conf = max(cfg.min_confidence, min(cfg.max_confidence, conf))
        w = cfg.source_weights.get(source, cfg.default_weight)

        # Log-likelihood ratio
        lr = conf / (1.0 - conf)
        # Korelasyon duzeltmesi: LR^w
        # w < 1 ise bilgi kazanci azaltilir
        effective_log_lr = w * math.log(lr)
        log_odds += effective_log_lr

    # Sigmoid: log_odds -> probability
    # Overflow koruması: cok buyuk/kucuk degerler icin
    if log_odds > 20.0:
        p = 1.0
    elif log_odds < -20.0:
        p = 0.0
    else:
        p = 1.0 / (1.0 + math.exp(-log_odds))

    return max(cfg.min_confidence, min(cfg.max_confidence, p))


# ---------------------------------------------------------------------------
# NameMerger
# ---------------------------------------------------------------------------

class NameMerger:
    """Coklu kaynak isim birlestirme motoru -- Bayesian fusion."""

    def __init__(
        self,
        min_confidence: float = 0.3,
        merger_config: Optional[NameMergerConfig] = None,
    ):
        self._min_confidence = min_confidence
        self._cfg = merger_config or NameMergerConfig()
        # v1.6.7: UNK threshold = config'deki unk_threshold (0.30).
        # Eski kod max(unk_threshold, min_confidence) yapiyordu ki 0.70'e cikiyordu.
        # Bayesian fusion zaten bilgi birlestirip dogru posterior veriyor --
        # 0.70 esigi tum tek-kaynakli computation candidate'leri olduruyordu
        # (612/612 rejected cunku fused posterior 0.50-0.61 arasi).
        # min_confidence parametresi artik sadece loglama icin tutuluyor.
        self._unk_threshold = self._cfg.unk_threshold
        # Kelime -> semantic group lookup
        self._word_to_group: dict[str, frozenset] = {}
        for group in _SEMANTIC_GROUPS:
            for word in group:
                self._word_to_group[word] = group

    def merge(
        self,
        candidates_by_symbol: dict[str, list[NamingCandidate]],
    ) -> MergeResult:
        """Tum semboller icin isim birlestirme yap.

        Args:
            candidates_by_symbol: {old_name: [NamingCandidate, ...]}

        Returns:
            MergeResult
        """
        result = MergeResult(total_symbols=len(candidates_by_symbol))

        for old_name, candidates in candidates_by_symbol.items():
            if not candidates:
                continue

            merged = self._merge_candidates(old_name, candidates)
            if merged is None:
                continue

            # UNK check: yeterli guven yoksa isim verme
            if merged.final_confidence < self._unk_threshold:
                result.total_unk += 1
                logger.debug(
                    "UNK: %s -> %s (conf=%.3f < threshold=%.3f)",
                    old_name, merged.final_name,
                    merged.final_confidence, self._unk_threshold,
                )
                continue

            result.merged_names[old_name] = merged
            result.total_merged += 1

            if merged.merge_method == "bayesian_multi":
                result.exact_multi_matches += 1
            elif merged.merge_method == "bayesian_partial":
                result.partial_matches += 1
            elif merged.merge_method == "bayesian_voting":
                result.voting_wins += 1
            elif merged.merge_method == "bayesian_single":
                result.conflicts_resolved += 1

        return result

    def _merge_candidates(
        self,
        old_name: str,
        candidates: list[NamingCandidate],
    ) -> Optional[MergedName]:
        """Tek bir sembol icin Bayesian birlestirme.

        Gruplandirma mantigi:
        1. Exact multi-match: Ayni isim 2+ kaynaktan -> Bayesian merge
        2. Partial match: prefix/suffix varyanti -> Bayesian merge (hafif penalty)
        3. Semantic merge: Benzer anlamli isimler -> Bayesian merge
        4. Voting: 3+ kaynak ayni ismi -> Bayesian merge
        5. Single source: Tek aday -> confidence'i aynen kullan
        """
        if not candidates:
            return None

        # Normalize edilmis isimlerle grupla
        name_groups: dict[str, list[NamingCandidate]] = {}
        for c in candidates:
            norm = self._normalize(c.name)
            name_groups.setdefault(norm, []).append(c)

        # 1. Exact multi-match: Ayni isim 2+ FARKLI kaynaktan
        for norm_name, group in name_groups.items():
            if len(group) >= 2:
                sources = set(c.source for c in group)
                if len(sources) >= 2:
                    conf = bayesian_merge(
                        [c.confidence for c in group],
                        [c.source for c in group],
                        self._cfg,
                    )
                    return MergedName(
                        original_name=old_name,
                        final_name=group[0].name,
                        final_confidence=conf,
                        sources=list(sources),
                        all_candidates=candidates,
                        merge_method="bayesian_multi",
                    )

        # 1b. Partial match: Bir isim digerinin prefix/suffix varyanti
        partial = self._find_partial_match(name_groups)
        if partial:
            partial.original_name = old_name
            partial.all_candidates = candidates
            return partial

        # 2. Semantic merge: Benzer anlamli isimler
        semantic_groups = self._group_by_semantics(candidates)
        if semantic_groups:
            largest_group = max(semantic_groups, key=lambda g: len(g))
            if len(largest_group) >= 2:
                best = max(largest_group, key=lambda c: c.confidence)
                group_sources = list(set(c.source for c in largest_group))
                # Semantic match'te adaylar FARKLI isim verdigi icin
                # "ayni sey mi diyorlar" belirsizligi var.
                # Penalty: tum w_i'leri 0.7x ile carp
                conf = bayesian_merge(
                    [c.confidence * 0.85 for c in largest_group],
                    [c.source for c in largest_group],
                    self._cfg,
                )
                return MergedName(
                    original_name=old_name,
                    final_name=best.name,
                    final_confidence=conf,
                    sources=group_sources,
                    all_candidates=candidates,
                    merge_method="bayesian_semantic",
                )

        # 3. Voting: 3+ kaynak herhangi bir isim icin uyusuyorsa
        if len(candidates) >= 3:
            name_votes = Counter(self._normalize(c.name) for c in candidates)
            most_common_name, most_common_count = name_votes.most_common(1)[0]
            if most_common_count >= 3:
                winners = [
                    c for c in candidates
                    if self._normalize(c.name) == most_common_name
                ]
                conf = bayesian_merge(
                    [c.confidence for c in winners],
                    [c.source for c in winners],
                    self._cfg,
                )
                best_winner = max(winners, key=lambda c: c.confidence)
                return MergedName(
                    original_name=old_name,
                    final_name=best_winner.name,
                    final_confidence=conf,
                    sources=list(set(c.source for c in candidates)),
                    all_candidates=candidates,
                    merge_method="bayesian_voting",
                )

        # 4. Fallback: En yuksek confidence'li tek aday
        best = max(candidates, key=lambda c: c.confidence)
        # Tek kaynak: Bayesian merge yapmaya gerek yok,
        # ama weight ile duzelt (overconfident kaynak icin)
        w = self._cfg.source_weights.get(best.source, self._cfg.default_weight)
        if w < 1.0:
            # Tek kaynagin confidence'ini korelasyon agirligi ile duzelt
            # log_odds = w * log(conf / (1-conf))
            conf_clipped = max(self._cfg.min_confidence, min(self._cfg.max_confidence, best.confidence))
            lr = conf_clipped / (1.0 - conf_clipped)
            log_odds = w * math.log(lr)
            if log_odds > 20.0:
                adjusted_conf = self._cfg.max_confidence
            elif log_odds < -20.0:
                adjusted_conf = self._cfg.min_confidence
            else:
                adjusted_conf = 1.0 / (1.0 + math.exp(-log_odds))
            adjusted_conf = max(self._cfg.min_confidence, min(self._cfg.max_confidence, adjusted_conf))
        else:
            adjusted_conf = best.confidence

        return MergedName(
            original_name=old_name,
            final_name=best.name,
            final_confidence=adjusted_conf,
            sources=[best.source],
            all_candidates=candidates,
            merge_method="bayesian_single",
        )

    def _find_partial_match(
        self,
        name_groups: dict[str, list[NamingCandidate]],
    ) -> Optional[MergedName]:
        """Farkli normalized isimler arasinda partial match (prefix/suffix varyanti) ara.

        Ornek:
            "cycle_sizes_default" ve "cycle_size" -> partial match
            "active_event_monitor" ve "event_monitor" -> partial match

        Partial match bulunursa, daha kisa (base) ismi secilir ve
        Bayesian merge uygulanir (hafif penalty ile -- isimler tam eslesmiyor).

        Returns:
            MergedName veya None.
        """
        norms = list(name_groups.keys())
        if len(norms) < 2:
            return None

        best_match: Optional[MergedName] = None
        best_overlap = 0.0

        for i, norm_a in enumerate(norms):
            for norm_b in norms[i + 1:]:
                overlap = self._partial_overlap(norm_a, norm_b)
                if overlap > best_overlap and overlap >= 0.5:
                    best_overlap = overlap

                    group_a = name_groups[norm_a]
                    group_b = name_groups[norm_b]
                    all_in_pair = group_a + group_b

                    # Daha kisa (base class) ismi sec
                    shorter_norm = min(norm_a, norm_b, key=len)
                    shorter_group = name_groups[shorter_norm]
                    best_candidate = max(shorter_group, key=lambda c: c.confidence)
                    sources = list(set(c.source for c in all_in_pair))

                    # Partial match penalty: confidence'lari overlap oraniyla carpilir
                    # Tam substring (overlap=1.0) -> az penalty
                    # Kismi overlap (overlap=0.5) -> cok penalty
                    penalty = 0.7 + 0.3 * overlap  # 0.85 - 1.0 arasi
                    conf = bayesian_merge(
                        [c.confidence * penalty for c in all_in_pair],
                        [c.source for c in all_in_pair],
                        self._cfg,
                    )

                    best_match = MergedName(
                        original_name="",  # Caller dolduracak
                        final_name=best_candidate.name,
                        final_confidence=conf,
                        sources=sources,
                        all_candidates=[],  # Caller dolduracak
                        merge_method="bayesian_partial",
                    )

        return best_match

    @staticmethod
    def _partial_overlap(norm_a: str, norm_b: str) -> float:
        """Iki normalize isim arasinda partial overlap skoru hesapla.

        Suffix/prefix kaldirma sonucu birbirinin base class'i olup olmadigini olcer.

        Returns:
            0.0-1.0 arasi overlap skoru. 0.5+ partial match kabul edilir.
        """
        # Tam esit -> exact, partial degil
        if norm_a == norm_b:
            return 0.0

        # Biri digerini iciyor mu? (substring)
        shorter, longer = sorted([norm_a, norm_b], key=len)
        if shorter in longer:
            return len(shorter) / len(longer)

        # Kelime bazli kesisim: "cycle_sizes_default" vs "cycle_size"
        words_a = set(norm_a.split("_"))
        words_b = set(norm_b.split("_"))
        if not words_a or not words_b:
            return 0.0

        common = words_a & words_b
        if not common:
            return 0.0

        union = words_a | words_b
        jaccard = len(common) / len(union)

        return jaccard

    def _normalize(self, name: str) -> str:
        """Ismi normalize et (lowercase, snake_case)."""
        # camelCase -> snake_case
        name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
        # Prefix'leri kaldir (m_, s_, g_, p_)
        name = re.sub(r"^[msgp]_", "", name)
        return name.lower().strip("_")

    def _group_by_semantics(
        self,
        candidates: list[NamingCandidate],
    ) -> list[list[NamingCandidate]]:
        """Semantik olarak benzer isimleri grupla."""
        groups: list[list[NamingCandidate]] = []
        used: set[int] = set()

        for i, c1 in enumerate(candidates):
            if i in used:
                continue
            group = [c1]
            used.add(i)

            for j, c2 in enumerate(candidates):
                if j in used:
                    continue
                if self._is_semantically_similar(c1.name, c2.name):
                    group.append(c2)
                    used.add(j)

            if len(group) >= 2:
                groups.append(group)

        return groups

    def _is_semantically_similar(self, name1: str, name2: str) -> bool:
        """Iki isim semantik olarak benzer mi?"""
        words1 = set(self._normalize(name1).split("_"))
        words2 = set(self._normalize(name2).split("_"))

        # Kelime kesisimi
        common = words1 & words2
        if common and len(common) / max(len(words1), len(words2)) >= 0.5:
            return True

        # Semantic group kesisimi
        expanded1: set[str] = set()
        for w in words1:
            if w in self._word_to_group:
                expanded1 |= self._word_to_group[w]
            expanded1.add(w)

        expanded2: set[str] = set()
        for w in words2:
            if w in self._word_to_group:
                expanded2 |= self._word_to_group[w]
            expanded2.add(w)

        overlap = expanded1 & expanded2
        union = expanded1 | expanded2
        if union and len(overlap) / len(union) >= 0.3:
            return True

        return False

    def to_naming_map(self, merge_result: MergeResult) -> dict[str, str]:
        """MergeResult'i basit naming_map'e cevir (c_namer uyumlu)."""
        return {
            old_name: merged.final_name
            for old_name, merged in merge_result.merged_names.items()
        }
