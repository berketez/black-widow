"""name_merger.py Bayesian fusion testleri.

Bayesian log-odds birlestirme formulu:
    log_odds = log(prior/(1-prior)) + SUM_i w_i * log(conf_i / (1-conf_i))
    P = sigmoid(log_odds)

Test edilen davranislar:
- bayesian_merge() dogrudan matematik testi
- NameMerger.merge() ile multi-source, partial, semantic, voting, single
- UNK class (dusuk confidence -> isim verilmez)
- Config'den source_weights okunmasi
- Eski merge_method isimleri guncel mi (bayesian_*)
"""

from __future__ import annotations

import math

import pytest

from karadul.config import NameMergerConfig
from karadul.reconstruction.name_merger import (
    MergeResult,
    MergedName,
    NameMerger,
    NamingCandidate,
    bayesian_merge,
)


# ---------------------------------------------------------------------------
# Yardimci
# ---------------------------------------------------------------------------

def _sigmoid(x: float) -> float:
    """Test icin sigmoid fonksiyonu."""
    if x > 20:
        return 1.0
    if x < -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


def _expected_bayesian(confs: list[float], sources: list[str], cfg: NameMergerConfig) -> float:
    """bayesian_merge'in beklenen sonucunu hesapla (el ile dogrulama)."""
    log_odds = math.log(cfg.multi_source_prior / (1.0 - cfg.multi_source_prior))
    for conf, src in zip(confs, sources):
        conf = max(cfg.min_confidence, min(cfg.max_confidence, conf))
        w = cfg.source_weights.get(src, cfg.default_weight)
        lr = conf / (1.0 - conf)
        log_odds += w * math.log(lr)
    p = _sigmoid(log_odds)
    return max(cfg.min_confidence, min(cfg.max_confidence, p))


# ---------------------------------------------------------------------------
# bayesian_merge() unit testleri
# ---------------------------------------------------------------------------

class TestBayesianMerge:
    """Bayesian merge fonksiyonunun matematik dogrulugu."""

    def test_single_source_high_confidence(self):
        """Tek kaynak, yuksek confidence -> yaklasik ayni confidence (w=1)."""
        cfg = NameMergerConfig()
        result = bayesian_merge([0.90], ["binary_extractor"], cfg)
        # w=1.0 icin: log_odds = 0 + 1.0 * log(0.9/0.1) = log(9) ~ 2.197
        # sigmoid(2.197) ~ 0.9
        assert abs(result - 0.90) < 0.01

    def test_single_source_low_weight(self):
        """Tek kaynak, w<1 -> confidence dusurulur."""
        cfg = NameMergerConfig()
        result = bayesian_merge([0.90], ["llm4decompile"], cfg)
        # w=0.5: log_odds = 0 + 0.5 * log(9) ~ 1.099
        # sigmoid(1.099) ~ 0.75
        assert result < 0.90
        assert 0.70 < result < 0.80

    def test_two_independent_sources_boost(self):
        """Iki bagimsiz kaynak ayni ismi oneriyor -> confidence artar."""
        cfg = NameMergerConfig()
        result = bayesian_merge(
            [0.80, 0.80],
            ["binary_extractor", "signature_db"],
            cfg,
        )
        # Her ikisi de w=1.0:
        # log_odds = 0 + log(4) + log(4) = 2*log(4) ~ 2.773
        # sigmoid(2.773) ~ 0.941
        assert result > 0.90
        assert result < 0.99

    def test_two_correlated_sources_less_boost(self):
        """Iki korelasyonlu kaynak -> boostlanma daha az."""
        cfg = NameMergerConfig()
        result_correlated = bayesian_merge(
            [0.80, 0.80],
            ["c_namer", "llm4decompile"],
            cfg,
        )
        result_independent = bayesian_merge(
            [0.80, 0.80],
            ["binary_extractor", "signature_db"],
            cfg,
        )
        # Korelasyonlu < bagimsiz
        assert result_correlated < result_independent

    def test_prior_uniform(self):
        """Hic sinyal yokken prior = 0.5."""
        cfg = NameMergerConfig()
        result = bayesian_merge([], [], cfg)
        assert result == 0.5

    def test_extreme_confidence_clipped(self):
        """conf=1.0 veya conf=0.0 patlamamali (clipping)."""
        cfg = NameMergerConfig()
        result_high = bayesian_merge([1.0], ["binary_extractor"], cfg)
        result_low = bayesian_merge([0.0], ["binary_extractor"], cfg)
        assert 0.01 <= result_high <= 0.99
        assert 0.01 <= result_low <= 0.99

    def test_many_sources_high_confidence(self):
        """5 bagimsiz kaynak, hepsi 0.7 -> cok yuksek guven."""
        cfg = NameMergerConfig()
        result = bayesian_merge(
            [0.7, 0.7, 0.7, 0.7, 0.7],
            ["binary_extractor", "signature_db", "byte_pattern",
             "swift_demangle", "source_matcher"],
            cfg,
        )
        # 5 bagimsiz 0.7 kaynak: cok guclu sinyal
        assert result > 0.95

    def test_matches_manual_calculation(self):
        """El ile hesaplanan degerle eslesiyor mu?"""
        cfg = NameMergerConfig()
        confs = [0.85, 0.70]
        sources = ["binary_extractor", "c_namer"]
        result = bayesian_merge(confs, sources, cfg)
        expected = _expected_bayesian(confs, sources, cfg)
        assert abs(result - expected) < 1e-10

    def test_opposing_signals_cancel(self):
        """Bir kaynak yuksek, diger dusuk -> ortaya yakin."""
        cfg = NameMergerConfig()
        result = bayesian_merge(
            [0.90, 0.10],
            ["binary_extractor", "signature_db"],
            cfg,
        )
        # log(9) + log(1/9) = 0 -> sigmoid(0) = 0.5
        assert abs(result - 0.5) < 0.01


# ---------------------------------------------------------------------------
# NameMerger entegrasyon testleri
# ---------------------------------------------------------------------------

class TestNameMergerExactMulti:
    """Exact multi-match: ayni isim birden fazla kaynaktan."""

    def test_two_sources_same_name(self):
        """Iki kaynak ayni ismi veriyor -> bayesian_multi."""
        merger = NameMerger()
        candidates = {
            "FUN_001": [
                NamingCandidate("initSocket", 0.80, "binary_extractor"),
                NamingCandidate("initSocket", 0.75, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        assert result.total_merged == 1
        merged = result.merged_names["FUN_001"]
        assert merged.merge_method == "bayesian_multi"
        assert merged.final_name == "initSocket"
        # Bayesian: iki kaynak (w=1.0, w=0.7) 0.80 ve 0.75 ile
        # Kesinlikle > max(0.80, 0.75)
        assert merged.final_confidence > 0.80

    def test_three_sources_same_name(self):
        """Uc kaynak ayni ismi veriyor -> daha yuksek confidence."""
        merger = NameMerger()
        candidates = {
            "FUN_002": [
                NamingCandidate("sendPacket", 0.70, "binary_extractor"),
                NamingCandidate("sendPacket", 0.65, "c_namer"),
                NamingCandidate("sendPacket", 0.80, "signature_db"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_002"]
        assert merged.merge_method == "bayesian_multi"
        assert merged.final_confidence > 0.90


class TestNameMergerPartialMatch:
    """Partial match: prefix/suffix varyantlari."""

    def test_substring_match(self):
        """EventMonitor ve ActiveEventMonitor -> partial match."""
        merger = NameMerger()
        candidates = {
            "FUN_003": [
                NamingCandidate("EventMonitor", 0.75, "binary_extractor"),
                NamingCandidate("ActiveEventMonitor", 0.70, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_003"]
        assert merged.merge_method == "bayesian_partial"
        # Kisa isim secilmeli
        assert merged.final_name == "EventMonitor"

    def test_word_overlap_match(self):
        """CycleSize ve CycleSizesDefault -> partial match."""
        merger = NameMerger()
        candidates = {
            "FUN_004": [
                NamingCandidate("CycleSize", 0.80, "binary_extractor"),
                NamingCandidate("CycleSizesDefault", 0.60, "string_intel"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_004"]
        assert merged.merge_method == "bayesian_partial"
        assert merged.final_name == "CycleSize"


class TestNameMergerSemantic:
    """Semantic merge: benzer anlamli isimler."""

    def test_semantic_synonyms(self):
        """initSystem ve setupEngine -> semantic match (init/setup, no word overlap)."""
        merger = NameMerger()
        # normalize: init_system, setup_engine
        # Partial overlap: {init, system} vs {setup, engine}
        #   substring: "init_system" not in "setup_engine", vice versa
        #   jaccard: common={}, union={init,system,setup,engine} -> 0/4 = 0
        # -> Partial match YOK
        # Semantic: init ve setup ayni grupta -> semantic match
        candidates = {
            "FUN_005": [
                NamingCandidate("initSystem", 0.70, "binary_extractor"),
                NamingCandidate("setupEngine", 0.65, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_005"]
        assert merged.merge_method == "bayesian_semantic"
        assert merged.final_name == "initSystem"

    def test_semantic_verb_groups(self):
        """writeBuffer ve emitPacket -> semantic group (write/emit share 'send' group)."""
        merger = NameMerger()
        # normalize: write_buffer, emit_packet
        # Partial overlap: {write, buffer} vs {emit, packet} -> 0/4 = 0
        # -> Partial match YOK
        # Semantic: write ve emit ayni grupta (send/transmit/write/emit...)
        #   buffer ve packet: buffer in {buf, buffer, data, bytes, payload, blob},
        #   packet in {msg, message, packet, frame, request, response}
        #   expanded overlap yeterli olmali
        candidates = {
            "FUN_006": [
                NamingCandidate("writeBuffer", 0.75, "binary_extractor"),
                NamingCandidate("emitPacket", 0.70, "string_intel"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_006"]
        assert merged.merge_method == "bayesian_semantic"


class TestNameMergerVoting:
    """Voting: 3+ kaynak ayni ismi veriyor."""

    def test_three_votes_same_name(self):
        """3 kaynak ayni ismi veriyorsa -> bayesian_voting."""
        merger = NameMerger()
        candidates = {
            "FUN_007": [
                NamingCandidate("parseJSON", 0.60, "binary_extractor"),
                NamingCandidate("parseJSON", 0.55, "c_namer"),
                NamingCandidate("parseJSON", 0.50, "string_intel"),
                NamingCandidate("decodeData", 0.80, "signature_db"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_007"]
        # Exact multi burada 3 farkli kaynaktan geldigi icin
        # bayesian_multi olabilir (3 kaynak ayni ismi exact veriyor)
        assert "bayesian" in merged.merge_method
        assert merged.final_name == "parseJSON"


class TestNameMergerSingle:
    """Single source: tek aday."""

    def test_single_high_confidence(self):
        """Tek kaynak, yuksek confidence -> bayesian_single."""
        merger = NameMerger()
        candidates = {
            "FUN_008": [
                NamingCandidate("malloc", 0.95, "signature_db"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_008"]
        assert merged.merge_method == "bayesian_single"
        assert merged.final_name == "malloc"
        # w=1.0 icin confidence hemen hemen ayni kalmali
        assert abs(merged.final_confidence - 0.95) < 0.02

    def test_single_correlated_source_reduced(self):
        """Tek korelasyonlu kaynak -> confidence dusurulur."""
        merger = NameMerger()
        candidates = {
            "FUN_009": [
                NamingCandidate("processData", 0.80, "llm4decompile"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_009"]
        # llm4decompile w=0.5 -> confidence 0.80'den dusuk olacak
        assert merged.final_confidence < 0.80


class TestNameMergerUNK:
    """UNK class: dusuk confidence -> isim verilmez."""

    def test_below_threshold_rejected(self):
        """Confidence < unk_threshold -> merge'e eklenmez."""
        cfg = NameMergerConfig(unk_threshold=0.5)
        merger = NameMerger(min_confidence=0.3, merger_config=cfg)
        candidates = {
            "FUN_010": [
                NamingCandidate("maybeFunc", 0.25, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        assert result.total_merged == 0
        assert result.total_unk == 1
        assert "FUN_010" not in result.merged_names

    def test_above_threshold_accepted(self):
        """Confidence >= unk_threshold -> merge'e eklenir."""
        cfg = NameMergerConfig(unk_threshold=0.3)
        merger = NameMerger(min_confidence=0.3, merger_config=cfg)
        candidates = {
            "FUN_011": [
                NamingCandidate("readConfig", 0.80, "binary_extractor"),
            ],
        }
        result = merger.merge(candidates)
        assert result.total_merged == 1


class TestNameMergerConfig:
    """Config entegrasyonu."""

    def test_custom_weights(self):
        """Ozel agirliklar sonucu etkiler."""
        # binary_extractor'a dusuk agirlik ver
        cfg = NameMergerConfig(
            source_weights={
                "binary_extractor": 0.3,
                "signature_db": 1.0,
            },
        )
        merger = NameMerger(merger_config=cfg)

        # Ayni confidence, farkli agirlik
        candidates = {
            "FUN_012": [
                NamingCandidate("funcA", 0.80, "binary_extractor"),
            ],
            "FUN_013": [
                NamingCandidate("funcB", 0.80, "signature_db"),
            ],
        }
        result = merger.merge(candidates)

        # signature_db w=1.0 oldugu icin confidence daha yuksek olmali
        conf_a = result.merged_names["FUN_012"].final_confidence
        conf_b = result.merged_names["FUN_013"].final_confidence
        assert conf_b > conf_a

    def test_default_weight_for_unknown_source(self):
        """Bilinmeyen kaynak icin default_weight kullanilir."""
        cfg = NameMergerConfig(default_weight=0.5)
        result = bayesian_merge([0.80], ["totally_new_source"], cfg)
        # w=0.5 ile 0.80 -> ~0.67
        assert 0.60 < result < 0.75


class TestNameMergerEdgeCases:
    """Edge case'ler ve regresyon testleri."""

    def test_empty_candidates(self):
        """Bos candidates listesi -> hata yok."""
        merger = NameMerger()
        result = merger.merge({})
        assert result.total_merged == 0
        assert result.total_symbols == 0

    def test_empty_candidates_for_symbol(self):
        """Symbol icin bos adaylar -> atlanir."""
        merger = NameMerger()
        result = merger.merge({"FUN_999": []})
        assert result.total_merged == 0

    def test_to_naming_map(self):
        """to_naming_map() dogru calisir."""
        merger = NameMerger()
        candidates = {
            "FUN_A": [NamingCandidate("alpha", 0.90, "signature_db")],
            "FUN_B": [NamingCandidate("beta", 0.85, "binary_extractor")],
        }
        result = merger.merge(candidates)
        naming_map = merger.to_naming_map(result)
        assert naming_map["FUN_A"] == "alpha"
        assert naming_map["FUN_B"] == "beta"

    def test_camelcase_normalization(self):
        """CamelCase -> snake_case normalizasyonu dogru."""
        merger = NameMerger()
        candidates = {
            "FUN_CC": [
                NamingCandidate("initSocket", 0.80, "binary_extractor"),
                NamingCandidate("InitSocket", 0.75, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_CC"]
        # "initSocket" ve "InitSocket" normalize edilince ayni olmali
        assert merged.merge_method == "bayesian_multi"

    def test_prefix_stripping_normalization(self):
        """m_/s_/g_/p_ prefix'leri kaldirilir."""
        merger = NameMerger()
        candidates = {
            "FUN_PX": [
                NamingCandidate("m_count", 0.80, "binary_extractor"),
                NamingCandidate("count", 0.75, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_PX"]
        # m_count -> count, ikisi de "count" olarak normalize edilmeli
        assert merged.merge_method == "bayesian_multi"

    def test_conflict_resolution(self):
        """Farkli isimler, farkli kaynaklar -> en yuksek confidence kazanir."""
        merger = NameMerger()
        candidates = {
            "FUN_CR": [
                NamingCandidate("openFile", 0.90, "signature_db"),
                NamingCandidate("loadData", 0.60, "c_namer"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_CR"]
        # Isimler farkli, semantic de degil -> fallback (bayesian_single)
        # openFile (0.90, w=1.0) > loadData (0.60, w=0.7)
        assert merged.final_name == "openFile"

    def test_no_overconfidence(self):
        """Hicbir sonuc 0.99'u gecmemeli."""
        merger = NameMerger()
        candidates = {
            "FUN_OC": [
                NamingCandidate("definitelyThis", 0.99, "binary_extractor"),
                NamingCandidate("definitelyThis", 0.99, "signature_db"),
                NamingCandidate("definitelyThis", 0.99, "byte_pattern"),
                NamingCandidate("definitelyThis", 0.99, "swift_demangle"),
                NamingCandidate("definitelyThis", 0.99, "source_matcher"),
            ],
        }
        result = merger.merge(candidates)
        merged = result.merged_names["FUN_OC"]
        assert merged.final_confidence <= 0.99

    def test_merge_result_counters(self):
        """MergeResult istatistik sayaclari dogru."""
        merger = NameMerger()
        candidates = {
            "FUN_S1": [
                NamingCandidate("funcA", 0.80, "binary_extractor"),
                NamingCandidate("funcA", 0.75, "c_namer"),
            ],
            "FUN_S2": [
                NamingCandidate("funcB", 0.90, "signature_db"),
            ],
        }
        result = merger.merge(candidates)
        assert result.total_symbols == 2
        assert result.total_merged == 2
        assert result.exact_multi_matches == 1


class TestBayesianMathProperties:
    """Bayesian formülün matematiksel özellik testleri."""

    def test_monotonicity(self):
        """Daha yuksek confidence -> daha yuksek sonuc (ayni kaynak)."""
        cfg = NameMergerConfig()
        r1 = bayesian_merge([0.60], ["binary_extractor"], cfg)
        r2 = bayesian_merge([0.70], ["binary_extractor"], cfg)
        r3 = bayesian_merge([0.80], ["binary_extractor"], cfg)
        assert r1 < r2 < r3

    def test_more_sources_better(self):
        """Daha fazla uyusan kaynak -> daha yuksek confidence."""
        cfg = NameMergerConfig()
        r1 = bayesian_merge([0.70], ["binary_extractor"], cfg)
        r2 = bayesian_merge([0.70, 0.70], ["binary_extractor", "signature_db"], cfg)
        r3 = bayesian_merge(
            [0.70, 0.70, 0.70],
            ["binary_extractor", "signature_db", "byte_pattern"],
            cfg,
        )
        assert r1 < r2 < r3

    def test_weight_ordering(self):
        """Daha yuksek agirlik -> daha fazla etki."""
        cfg = NameMergerConfig()
        # binary_extractor (w=1.0) vs llm4decompile (w=0.5)
        r_high_w = bayesian_merge([0.80], ["binary_extractor"], cfg)
        r_low_w = bayesian_merge([0.80], ["llm4decompile"], cfg)
        assert r_high_w > r_low_w

    def test_symmetry(self):
        """Kaynak sirasi sonucu etkilememeli (commutative)."""
        cfg = NameMergerConfig()
        r1 = bayesian_merge(
            [0.80, 0.70], ["binary_extractor", "c_namer"], cfg,
        )
        r2 = bayesian_merge(
            [0.70, 0.80], ["c_namer", "binary_extractor"], cfg,
        )
        assert abs(r1 - r2) < 1e-10

    def test_50_50_is_neutral(self):
        """Confidence=0.5 olan kaynak hicbir bilgi eklemez."""
        cfg = NameMergerConfig()
        r_with = bayesian_merge(
            [0.80, 0.50], ["binary_extractor", "signature_db"], cfg,
        )
        r_without = bayesian_merge(
            [0.80], ["binary_extractor"], cfg,
        )
        # 0.50 -> LR=1.0 -> log(1)=0 -> hic bilgi eklemiyor
        assert abs(r_with - r_without) < 1e-10
