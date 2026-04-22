"""KARADUL v1.10.0 M4 v1.4.0.rc1 -- Signature Fusion test suite.

Kapsam:
    1. SignatureCandidate / FusedMatch dataclass'lari
    2. FusionWeights default + save/load
    3. Feature extraction (shape, proto, context, interaction)
    4. LogOddsEnsemble (logit + sigmoid proba)
    5. PlattCalibrator (identity + fit MLE)
    6. SignatureFuser (accept / reject / abstain kararlari)
    7. FusionEvaluator (precision@coverage + FPR butce)
    8. Double-counting guard (interaction feature devrede)

Bayesian/Dempster-Shafer CARPMA YOK -- sadece log-odds toplam (codex teyit).
"""

from __future__ import annotations

import math
import random
from pathlib import Path

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.fusion import (
    DecisionConfig,
    FusedMatch,
    FusionEvaluator,
    FusionWeights,
    LogOddsEnsemble,
    PlattCalibrator,
    SignatureCandidate,
    SignatureFuser,
    context_features,
    interaction_features,
    proto_features,
    shape_features,
)


# ---------------------------------------------------------------------------
# Yardimci: sentetik yuksek / dusuk guven aday uretici
# ---------------------------------------------------------------------------


def _high_confidence_candidate(name: str = "memcpy") -> SignatureCandidate:
    return SignatureCandidate(
        symbol_name=name,
        byte_score=0.95,
        cfg_hash="abc123",
        reference_cfg_hash="abc123",
        func_size=256,
        compiler_bucket="clang",
        param_count=3,
        reference_param_count=3,
        return_type="void*",
        reference_return_type="void*",
        cc_match=True,
        decompiler_conf=0.9,
        caller_overlap=0.8,
        callgraph_pos={"callers": ["f1", "f2"], "callees": ["f3"]},
        reference_callers=["f1", "f2"],
        reference_callees=["f3"],
        import_context=["libc", "write"],
        reference_imports=["libc", "write"],
    )


def _low_confidence_candidate(name: str = "unknown_fn") -> SignatureCandidate:
    return SignatureCandidate(
        symbol_name=name,
        byte_score=0.05,
        cfg_hash="aaa000",
        reference_cfg_hash="zzz999",
        func_size=120,
        compiler_bucket="unknown",
        param_count=1,
        reference_param_count=5,
        return_type="int",
        reference_return_type="void*",
        cc_match=False,
        decompiler_conf=0.1,
        caller_overlap=0.05,
        callgraph_pos={"callers": ["x"], "callees": []},
        reference_callers=["y"],
        reference_callees=["z"],
        import_context=["foo"],
        reference_imports=["bar"],
    )


def _mid_confidence_candidate(name: str = "mid_fn") -> SignatureCandidate:
    return SignatureCandidate(
        symbol_name=name,
        byte_score=0.55,
        cfg_hash="aaaa",
        reference_cfg_hash="aaab",  # kismi eslesme
        func_size=500,
        compiler_bucket="gcc",
        param_count=2,
        reference_param_count=3,  # 1 fark -> 0.5
        return_type="int",
        reference_return_type="int",
        cc_match=None,
        decompiler_conf=0.5,
        caller_overlap=0.4,
        callgraph_pos={"callers": ["a", "b"], "callees": ["c"]},
        reference_callers=["a", "x"],
        reference_callees=["c", "y"],
        import_context=["lib1", "lib2"],
        reference_imports=["lib1", "lib3"],
    )


# ---------------------------------------------------------------------------
# 1. Dataclass
# ---------------------------------------------------------------------------


class TestSignatureCandidateDataclass:
    def test_signature_candidate_dataclass(self) -> None:
        """Minimum alanlar ile SignatureCandidate olusturulabilir."""
        c = SignatureCandidate(symbol_name="foo")
        assert c.symbol_name == "foo"
        assert c.byte_score == 0.0
        assert c.cfg_hash == ""
        assert c.param_count is None
        assert not c.has_proto()
        assert not c.has_context()

    def test_signature_candidate_has_flags(self) -> None:
        c = _high_confidence_candidate()
        assert c.has_shape()
        assert c.has_proto()
        assert c.has_context()

    def test_fused_match_decision_helpers(self) -> None:
        m = FusedMatch(
            symbol_name="x",
            raw_logit=5.0,
            calibrated_probability=0.95,
            decision="accept",
            feature_contributions={"a": 1.2, "b": -0.3, "c": 0.8},
        )
        assert m.is_accepted()
        assert not m.is_rejected()
        top = m.top_contributions(k=2)
        assert len(top) == 2
        # |1.2| en buyuk
        assert top[0][0] == "a"


# ---------------------------------------------------------------------------
# 2. FusionWeights
# ---------------------------------------------------------------------------


class TestFusionWeights:
    def test_fusion_weights_default(self) -> None:
        w = FusionWeights.default()
        assert "byte_score" in w.w_shape
        assert "param_count_match" in w.w_proto
        assert "callgraph_position" in w.w_context
        assert "shape_x_context" in w.w_interaction
        # Bias negatif (dusuk prior) -- false positive'e suspect davran
        assert w.bias < 0

    def test_fusion_weights_save_load(self, tmp_path: Path) -> None:
        w = FusionWeights.default()
        w.bias = -2.17
        w.w_shape["byte_score"] = 3.14
        p = tmp_path / "weights.json"
        w.save(p)
        assert p.exists()

        w2 = FusionWeights.load(p)
        assert w2.bias == -2.17
        assert w2.w_shape["byte_score"] == 3.14
        assert w2.w_context == w.w_context


# ---------------------------------------------------------------------------
# 3. Feature extraction
# ---------------------------------------------------------------------------


class TestFeatureExtraction:
    def test_shape_features_extraction(self) -> None:
        c = _high_confidence_candidate()
        f = shape_features(c)
        assert "byte_score" in f
        assert f["byte_score"] == pytest.approx(0.95)
        assert f["cfg_hash_similarity"] == pytest.approx(1.0)  # tam esleme
        assert 0.0 < f["func_size_normalized"] <= 1.0
        assert f["compiler_match"] == 1.0  # clang -> known

    def test_shape_features_missing(self) -> None:
        c = SignatureCandidate(symbol_name="x")
        f = shape_features(c)
        assert f["byte_score"] == 0.0
        assert f["cfg_hash_similarity"] == 0.0
        assert f["func_size_normalized"] == 0.0
        # Unknown compiler -> 0.5 neutral
        assert f["compiler_match"] == 0.5

    def test_proto_features_extraction(self) -> None:
        c = _high_confidence_candidate()
        f = proto_features(c)
        assert f["param_count_match"] == 1.0
        assert f["return_type_match"] == 1.0
        assert f["cc_match"] == 1.0
        assert f["decompiler_conf"] == pytest.approx(0.9)

    def test_proto_features_partial(self) -> None:
        c = _mid_confidence_candidate()
        f = proto_features(c)
        # param farki 1 -> 0.5
        assert f["param_count_match"] == pytest.approx(0.5)
        assert f["return_type_match"] == 1.0
        # cc_match None -> 0
        assert f["cc_match"] == 0.0

    def test_context_features_extraction(self) -> None:
        c = _high_confidence_candidate()
        f = context_features(c)
        assert f["callgraph_position"] == pytest.approx(1.0)  # tam Jaccard
        assert f["import_context_similarity"] == pytest.approx(1.0)

    def test_interaction_features(self) -> None:
        """Interaction = shape_mean * ctx_mean. Yuksek shape + yuksek context
        = yuksek interaction."""
        c_high = _high_confidence_candidate()
        c_low = _low_confidence_candidate()
        f_high = interaction_features(c_high)
        f_low = interaction_features(c_low)
        assert f_high["shape_x_context"] > f_low["shape_x_context"]
        assert f_high["shape_weighted_context"] > f_low["shape_weighted_context"]


# ---------------------------------------------------------------------------
# 4. LogOddsEnsemble
# ---------------------------------------------------------------------------


class TestLogOddsEnsemble:
    def test_log_odds_predict_logit(self) -> None:
        """Logit = bias + sum(w_i * x_i). All-zero feature -> bias donmeli."""
        ens = LogOddsEnsemble()
        feats = {}  # bos -> her feature 0.0 okunacak
        logit = ens.predict_logit(feats)
        assert logit == pytest.approx(ens.weights.bias)

    def test_log_odds_predict_proba_sigmoid(self) -> None:
        """predict_proba(0) == 0.5, pozitif logit -> >0.5."""
        ens = LogOddsEnsemble()
        assert ens.predict_proba(0.0) == pytest.approx(0.5)
        assert ens.predict_proba(10.0) > 0.99
        assert ens.predict_proba(-10.0) < 0.01

    def test_log_odds_contributions_sum(self) -> None:
        """feature_contributions toplami = logit (bias dahil)."""
        ens = LogOddsEnsemble()
        c = _high_confidence_candidate()
        logit, _p, contribs = ens.predict_from_candidate(c)
        total = sum(contribs.values())
        assert total == pytest.approx(logit, abs=1e-6)

    def test_log_odds_high_vs_low(self) -> None:
        ens = LogOddsEnsemble()
        high_logit, high_p, _ = ens.predict_from_candidate(
            _high_confidence_candidate(),
        )
        low_logit, low_p, _ = ens.predict_from_candidate(
            _low_confidence_candidate(),
        )
        assert high_logit > low_logit
        assert high_p > low_p


# ---------------------------------------------------------------------------
# 5. PlattCalibrator
# ---------------------------------------------------------------------------


class TestPlattCalibrator:
    def test_platt_calibrator_identity(self) -> None:
        """Default A=1, B=0 -> calibrate(x) == sigmoid(x)."""
        cal = PlattCalibrator()
        for logit in [-3.0, -1.0, 0.0, 1.0, 3.0]:
            expected = 1.0 / (1.0 + math.exp(-logit))
            assert cal.calibrate(logit) == pytest.approx(expected, abs=1e-9)
        assert cal.is_identity()

    def test_platt_calibrator_fit(self) -> None:
        """100 ornek; fit sonrasi loss azalmali, A degeri guncellenmeli."""
        rng = random.Random(42)
        # Sentetik: logit yuksekse label 1, dusukse label 0 (triviyal ayrilabilir)
        logits = []
        labels = []
        for _ in range(100):
            L = rng.uniform(-5, 5)
            p_true = 1.0 / (1.0 + math.exp(-L))
            y = 1 if rng.random() < p_true else 0
            logits.append(L)
            labels.append(y)
        # Ensure mixed
        if sum(labels) in (0, 100):
            labels[0] = 1 - labels[0]

        cal = PlattCalibrator(A=0.5, B=0.0)  # Kotu baslangic
        cal.fit(logits, labels, max_iter=300, lr=0.1)

        # fit sonrasi A identity'e (~1.0) dogru hareket etmeli
        # En azindan fit onceki A=0.5'ten buyumus olmali
        assert cal.A > 0.5
        # Calibrated degerler [0,1] araliginda kalmalidir
        for L in [-5.0, 0.0, 5.0]:
            p = cal.calibrate(L)
            assert 0.0 <= p <= 1.0

    def test_platt_calibrator_fit_refuses_single_class(self) -> None:
        cal = PlattCalibrator()
        with pytest.raises(ValueError):
            cal.fit([1.0, 2.0, 3.0], [1, 1, 1])

    def test_platt_calibrator_fit_mismatched_lengths(self) -> None:
        cal = PlattCalibrator()
        with pytest.raises(ValueError):
            cal.fit([1.0, 2.0], [1])


# ---------------------------------------------------------------------------
# 6. SignatureFuser (accept / reject / abstain)
# ---------------------------------------------------------------------------


class TestSignatureFuser:
    def test_fuser_accept_high_conf(self) -> None:
        fuser = SignatureFuser()
        r = fuser.fuse_one(_high_confidence_candidate())
        assert r.decision == "accept"
        assert r.calibrated_probability >= 0.90

    def test_fuser_reject_low_conf(self) -> None:
        fuser = SignatureFuser()
        r = fuser.fuse_one(_low_confidence_candidate())
        assert r.decision == "reject"
        assert r.calibrated_probability < 0.30

    def test_fuser_abstain_mid_conf(self) -> None:
        """Orta konfigure -- threshold'lari sikilastir, mid aday abstain."""
        fuser = SignatureFuser(
            decision=DecisionConfig(accept_threshold=0.98, reject_threshold=0.02),
        )
        r = fuser.fuse_one(_mid_confidence_candidate())
        assert r.decision == "abstain"

    def test_fuser_preserves_order(self) -> None:
        fuser = SignatureFuser()
        cs = [
            _high_confidence_candidate("a"),
            _low_confidence_candidate("b"),
            _mid_confidence_candidate("c"),
        ]
        out = fuser.fuse(cs)
        assert [m.symbol_name for m in out] == ["a", "b", "c"]

    def test_decision_config_invariant(self) -> None:
        with pytest.raises(ValueError):
            DecisionConfig(accept_threshold=0.5, reject_threshold=0.8)

    def test_fuser_from_computation_config(self, tmp_path: Path) -> None:
        cfg = ComputationConfig(
            fusion_accept_threshold=0.92,
            fusion_reject_threshold=0.25,
            fusion_calibration_enabled=True,
        )
        fuser = SignatureFuser.from_computation_config(cfg)
        assert fuser.decision.accept_threshold == 0.92
        assert fuser.decision.reject_threshold == 0.25
        # Hic aday yok -> bos liste
        assert fuser.fuse([]) == []


# ---------------------------------------------------------------------------
# 7. FusionEvaluator
# ---------------------------------------------------------------------------


class TestFusionEvaluator:
    def test_evaluator_precision_at_coverage(self) -> None:
        """Sentetik: ilk 5 pozitif, son 5 negatif; dogru siralama -> 0.5 cov @ 1.0."""
        matches = []
        for i in range(5):
            matches.append(FusedMatch(
                symbol_name=f"pos_{i}", raw_logit=5.0,
                calibrated_probability=0.9 + i * 0.01,
                decision="accept",
            ))
        for i in range(5):
            matches.append(FusedMatch(
                symbol_name=f"neg_{i}", raw_logit=-5.0,
                calibrated_probability=0.1 + i * 0.01,
                decision="reject",
            ))
        gt = {f"pos_{i}": True for i in range(5)}
        gt.update({f"neg_{i}": False for i in range(5)})

        ev = FusionEvaluator()
        res = ev.precision_at_coverage(
            matches, gt, coverage_levels=[0.1, 0.2, 0.5, 1.0],
        )
        # cov 0.5 -> top 5 hepsi pos
        assert res[0.5] == pytest.approx(1.0)
        # cov 1.0 -> 5/10 pos
        assert res[1.0] == pytest.approx(0.5)
        # cov 0.1 -> top 1, pos
        assert res[0.1] == pytest.approx(1.0)

    def test_required_fpr_for_precision(self) -> None:
        """codex formul teyit: pi=0.20, TPR=0.80, P=0.95 -> FPR <= 0.0105."""
        ev = FusionEvaluator()
        fpr = ev.required_fpr_for_precision(
            target_precision=0.95, tpr=0.80, prevalence=0.20,
        )
        assert fpr == pytest.approx(0.010526, abs=1e-4)

        # pi=0.02, TPR=0.80, P=0.95 -> FPR <= 0.000860
        fpr2 = ev.required_fpr_for_precision(
            target_precision=0.95, tpr=0.80, prevalence=0.02,
        )
        assert fpr2 == pytest.approx(0.000860, abs=1e-4)

    def test_precision_from_rates_inverse(self) -> None:
        """Precision formulu tersi ile dogrulama (round-trip)."""
        ev = FusionEvaluator()
        fpr = ev.required_fpr_for_precision(0.90, 0.80, 0.20)
        p = ev.precision_from_rates(tpr=0.80, fpr=fpr, prevalence=0.20)
        assert p == pytest.approx(0.90, abs=1e-6)

    def test_acceptance_stats_and_accepted_precision(self) -> None:
        matches = [
            FusedMatch("a", 5.0, 0.95, "accept"),
            FusedMatch("b", -5.0, 0.05, "reject"),
            FusedMatch("c", 1.0, 0.6, "abstain"),
            FusedMatch("d", 5.5, 0.97, "accept"),
        ]
        gt = {"a": True, "b": False, "c": True, "d": False}
        ev = FusionEvaluator()
        stats = ev.acceptance_stats(matches)
        assert stats == {"accept": 2, "reject": 1, "abstain": 1, "total": 4}
        # Accepted: a (TP), d (FP) -> precision 0.5
        assert ev.precision_of_accepted(matches, gt) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# 8. Double-counting guard
# ---------------------------------------------------------------------------


class TestNoDoubleCounting:
    def test_no_double_counting(self) -> None:
        """Byte ve CFG birlikte yukselirse, interaction feature'i olmadan
        confidence overestimate olurdu. Interaction devrede olmali.

        Test stratejisi: ayni candidate'in interaction_features dict'inde
        shape_x_context alanini 0'a zorlarsak (manuel feature vektoru),
        ensemble confidence'i DAHA DUSUK hesaplar -- yani interaction
        feature pozitif katkida bulunuyor, decorrelation dinamik.
        """
        from karadul.computation.fusion.features import all_features
        c = _high_confidence_candidate()
        feats_full = all_features(c)
        feats_nointer = dict(feats_full)
        # Interaction feature'larini sifirla
        for k in ("shape_x_context", "proto_x_context", "shape_weighted_context"):
            feats_nointer[k] = 0.0

        ens = LogOddsEnsemble()
        l_full = ens.predict_logit(feats_full)
        l_nointer = ens.predict_logit(feats_nointer)
        # Interaction pozitif katki ettiginde logit daha yuksek olmali
        assert l_full > l_nointer
        # Fark sifirdan anlamli farkli olmali (feature agirligi 1.0+ civari)
        assert (l_full - l_nointer) > 0.5

    def test_shape_alone_not_enough_for_accept(self) -> None:
        """Yuksek byte + CFG AMA context bos -> confidence tam 0.99 olmamali."""
        c = SignatureCandidate(
            symbol_name="x",
            byte_score=0.98,
            cfg_hash="abcd",
            reference_cfg_hash="abcd",
            func_size=200,
            compiler_bucket="clang",
            # proto / context yok
        )
        ens = LogOddsEnsemble()
        _l, p, _ = ens.predict_from_candidate(c)
        # Shape'e DAYALI proba kriti bir esik altinda kalmalı
        # (context + proto yoksa kesin guven verilmez)
        assert p < 0.95

    def test_config_fusion_threshold_invariant(self) -> None:
        """ComputationConfig fusion threshold tutarlilik kontrolu."""
        with pytest.raises(ValueError):
            ComputationConfig(
                fusion_accept_threshold=0.3,
                fusion_reject_threshold=0.9,  # reject > accept
            )
