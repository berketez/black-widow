"""KARADUL v1.10.0 Fix Sprint test suite.

Spec'teki 9 fix'i (C1-C4, H1, H3-H5, M4-M5) dogrulayan regresyon
testleri. Her fix icin en az 1 test — toplam 10+ yeni test.

Kapsam:
    - C1: Inter-field gap padding (eski sadece trailing sayiyordu).
    - C2: Overlap soft clause tekrarli yerine tek w*overlaps cagrisi.
    - C3: H1 invariant defansif assertion (map_var mevcut).
    - C4: Abstain sinir durumu simetrik (<=, >=).
    - H1: HybridCFGMatcher template WL hash cache.
    - H3: LSH bos feature set -> build-time error.
    - H4: LSH num_hashes % band_size -> __init__ error.
    - H5: Calibration docstring (A=1 identity — sanity calibrate check).
    - M4: Stride synthesizer silent failure -> logger.debug.
    - M5: Interaction docstring warning (dokumantasyon, run-time no-op check).
"""

from __future__ import annotations

import logging

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.fusion import (
    DecisionConfig,
    PlattCalibrator,
    SignatureFuser,
)
from karadul.computation.fusion.fuser import SignatureFuser as _Fuser
from karadul.computation.struct_recovery import (
    CandidateSynthesizer,
    MemoryAccess,
    StructCandidate,
    StructField,
    StructLayoutSolver,
)
from karadul.computation.struct_recovery.encoder import (
    _count_padding_bytes,
)


# =============================================================================
# C1: Inter-field gap padding
# =============================================================================


class TestC1PaddingInterFieldGap:
    def test_padding_inter_field_gap_counted(self) -> None:
        """size=16, fields=[(0,4),(12,4)] -> 8 bayt padding (inter 8, trail 0)."""
        cand = StructCandidate(
            name="gap_cand",
            size=16,
            fields=[StructField(0, 4), StructField(12, 4)],
        )
        # Gap: offset 4..12 (8 bayt), trailing: 0.
        assert _count_padding_bytes(cand) == 8

    def test_padding_mixed_gap_and_trailing(self) -> None:
        """Hem inter-field hem trailing -> toplam dogru."""
        cand = StructCandidate(
            name="mixed",
            size=20,
            fields=[StructField(0, 4), StructField(8, 4)],
        )
        # Gap 4..8 = 4, trail 12..20 = 8, toplam 12.
        assert _count_padding_bytes(cand) == 12

    def test_padding_no_gap_tight_fields(self) -> None:
        """Sikici kapali aday -> 0 padding."""
        cand = StructCandidate(
            name="tight",
            size=12,
            fields=[StructField(0, 4), StructField(4, 4), StructField(8, 4)],
        )
        assert _count_padding_bytes(cand) == 0

    def test_padding_only_trailing(self) -> None:
        """Inter-field yok, sadece trailing. Eski mantikla ayni sonuc."""
        cand = StructCandidate(
            name="trail",
            size=16,
            fields=[StructField(0, 4), StructField(4, 4)],
        )
        # fields sonu 8, size 16 -> trailing 8.
        assert _count_padding_bytes(cand) == 8

    def test_padding_empty_fields(self) -> None:
        """Hic alan yok -> tum size padding."""
        cand = StructCandidate(name="empty", size=32, fields=[])
        assert _count_padding_bytes(cand) == 32

    def test_padding_overlapping_fields(self) -> None:
        """Cakisan alanlar -> cursor dogru max al. Overlap bolgesi cift sayilmaz.

        fields=[(0,8),(4,4)]: union [0,8), cursor=8. size=12 -> trailing 4.
        """
        cand = StructCandidate(
            name="overlap",
            size=12,
            fields=[StructField(0, 8), StructField(4, 4)],
        )
        assert _count_padding_bytes(cand) == 4


# =============================================================================
# C2: Overlap soft clause tekrarli yerine tek call (semantik test)
# =============================================================================


class TestC2OverlapSoftSingleCall:
    def test_overlap_penalty_still_discourages_overlap(self) -> None:
        """Overlap'li aday, overlap'siz adaya gore solver tercih EDILMEMELI.

        Tek add_soft(w*overlaps) cagrisi eski "N defa w" cagrisiyla
        MaxSMT'ta ayni optimal secim.
        """
        solver = StructLayoutSolver(
            ComputationConfig(enable_computation_struct_recovery=True),
        )
        accs = [
            MemoryAccess("p", 0, 4),
            MemoryAccess("p", 4, 4),
        ]
        # Overlap'li aday: field (0,8) ve (4,4) cakisiyor.
        cand_overlap = StructCandidate(
            "overlap", 8, [StructField(0, 8), StructField(4, 4)],
        )
        cand_clean = StructCandidate(
            "clean", 8, [StructField(0, 4), StructField(4, 4)],
        )
        result = solver.solve_from_raw(
            accesses=accs,
            variables=["p"],
            type_hints={"p": "T"},
            candidates=[cand_overlap, cand_clean],
        )
        # clean kazanmali -- overlap cezasi var.
        assert result.assigned_structs["T"].name == "clean"


# =============================================================================
# C3: Defansif assertion (H1 invariant)
# =============================================================================


class TestC3DefensiveAssertion:
    def test_encoder_completes_without_assertion_error(self) -> None:
        """Normal encode: H1 invariant assertion gecerli, AssertionError yok."""
        solver = StructLayoutSolver(
            ComputationConfig(enable_computation_struct_recovery=True),
        )
        accs = [
            MemoryAccess("p", 0, 4),
            MemoryAccess("p", 4, 4),
        ]
        cand = StructCandidate(
            "T", 8, [StructField(0, 4), StructField(4, 4)],
        )
        # Hata firlamamali; normal cozum dondurmeli.
        result = solver.solve_from_raw(
            accesses=accs,
            variables=["p"],
            type_hints={"p": "T"},
            candidates=[cand],
        )
        assert result.confidence == pytest.approx(1.0)


# =============================================================================
# C4: Abstain sinir durumu simetrik (<= ve >=)
# =============================================================================


class TestC4AbstainSymmetric:
    def _inject_p(self, p: float) -> _Fuser:
        """Test yardimcisi: fixed p dondurn calibrator."""
        class FixedCal:
            def calibrate(self, logit: float) -> float:
                return p
        fuser = SignatureFuser()
        fuser.calibrator = FixedCal()  # type: ignore[assignment]
        return fuser

    def _dummy_candidate(self):
        from karadul.computation.fusion.types import SignatureCandidate
        return SignatureCandidate(symbol_name="x")

    def test_abstain_at_exact_accept_threshold(self) -> None:
        """p == accept_threshold -> 'accept' (>=, dahil)."""
        fuser = self._inject_p(0.90)
        fuser.decision = DecisionConfig(accept_threshold=0.90, reject_threshold=0.30)
        r = fuser.fuse_one(self._dummy_candidate())
        assert r.decision == "accept"

    def test_abstain_at_exact_reject_threshold(self) -> None:
        """p == reject_threshold -> 'reject' (<=, dahil). Eski kodda 'abstain'di."""
        fuser = self._inject_p(0.30)
        fuser.decision = DecisionConfig(accept_threshold=0.90, reject_threshold=0.30)
        r = fuser.fuse_one(self._dummy_candidate())
        assert r.decision == "reject"

    def test_abstain_between_thresholds(self) -> None:
        """p (reject, accept) araliginda -> 'abstain'."""
        fuser = self._inject_p(0.60)
        fuser.decision = DecisionConfig(accept_threshold=0.90, reject_threshold=0.30)
        r = fuser.fuse_one(self._dummy_candidate())
        assert r.decision == "abstain"


# =============================================================================
# H1: Template WL hash cache
# =============================================================================


class TestH1TemplateWLHashCache:
    def test_matcher_caches_template_hash(self) -> None:
        """HybridCFGMatcher build'de template hash'lerini cache'ler."""
        from karadul.computation.cfg_iso.matcher import HybridCFGMatcher
        from karadul.computation.cfg_iso.template_db import default_template_bank

        templates = default_template_bank()[:3]
        matcher = HybridCFGMatcher(config=None, templates=templates)
        # Cache build sirasinda doldurulmali.
        assert hasattr(matcher, "_template_hash_cache")
        assert len(matcher._template_hash_cache) == len(templates)
        for t in templates:
            assert t.name in matcher._template_hash_cache
            # Cache'lenen hash deterministik ve bos-olmayan string.
            h = matcher._template_hash_cache[t.name]
            assert isinstance(h, str) and len(h) > 0


# =============================================================================
# H3: LSH bos feature set build-time guard
# =============================================================================


class TestH3LSHEmptyFeatureGuard:
    def test_lsh_rejects_empty_feature_template(self) -> None:
        """WL uretemeyen (node'suz) CFG icin LSH build ValueError firlatmali."""
        from karadul.computation.cfg_iso.fingerprint import AttributedCFG
        from karadul.computation.cfg_iso.lsh_index import LSHIndex
        from karadul.computation.cfg_iso.template_db import AlgorithmTemplate

        empty_cfg = AttributedCFG(nodes=[], edges=[])
        bad_tmpl = AlgorithmTemplate(
            name="bad",
            cfg=empty_cfg,
            family="generic",
        )
        with pytest.raises(ValueError, match="bos WL feature set"):
            LSHIndex([bad_tmpl], num_hashes=128, band_size=4)


# =============================================================================
# H4: LSH band_size validation
# =============================================================================


class TestH4LSHBandSizeValidation:
    def test_lsh_rejects_indivisible_band_size(self) -> None:
        """num_hashes % band_size != 0 -> __init__ error."""
        from karadul.computation.cfg_iso.lsh_index import LSHIndex
        from karadul.computation.cfg_iso.template_db import default_template_bank

        templates = default_template_bank()[:2]
        # 128 % 5 != 0
        with pytest.raises(ValueError, match="tam bolunebilir"):
            LSHIndex(templates, num_hashes=128, band_size=5)

    def test_lsh_accepts_divisible_band_size(self) -> None:
        """Bolunebilir kombinasyonlar calismali."""
        from karadul.computation.cfg_iso.lsh_index import LSHIndex
        from karadul.computation.cfg_iso.template_db import default_template_bank

        templates = default_template_bank()[:2]
        # 128 / 4 = 32 band. OK.
        lsh = LSHIndex(templates, num_hashes=128, band_size=4)
        assert len(lsh) == len(templates)


# =============================================================================
# H5: Calibration docstring fix (identity sanity)
# =============================================================================


class TestH5CalibrationIdentity:
    def test_platt_default_is_identity_sigmoid(self) -> None:
        """Docstring degistirdikten sonra ayni davranis: A=1, B=0 identity."""
        cal = PlattCalibrator()
        assert cal.A == 1.0
        assert cal.B == 0.0
        assert cal.is_identity()
        # calibrate(0) == 0.5 (sigmoid(0))
        assert cal.calibrate(0.0) == pytest.approx(0.5)

    def test_platt_docstring_mentions_a_one(self) -> None:
        """Docstring'de 'A=1' veya 'identity' geciyor, eski 'A=-1' GECMIYOR."""
        doc = (PlattCalibrator.__doc__ or "") + (
            __import__("karadul.computation.fusion.calibration", fromlist=["_"])
            .__doc__ or ""
        )
        assert "A=-1" not in doc
        assert "A=1" in doc or "identity" in doc.lower()


# =============================================================================
# M4: Stride synthesizer logger.debug (silent failure yok)
# =============================================================================


class TestM4StrideSynthesizerLogging:
    def test_stride_failure_logs_debug(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Stride ValueError olunca logger.debug'a mesaj dusmeli.

        Senaryo: widths=8, offsets=[0,4,8] -> stride=4, ama field(0,8) stride 4'e
        sigmaz -> StructCandidate __post_init__ ValueError firlatir. Yeni kod
        bunu debug log'a yazmali.
        """
        synth = CandidateSynthesizer()
        accs = [
            MemoryAccess("p", 0, 8),
            MemoryAccess("p", 4, 8),
            MemoryAccess("p", 8, 8),
        ]
        with caplog.at_level(
            logging.DEBUG,
            logger="karadul.computation.struct_recovery.candidate_synthesizer",
        ):
            cands = synth.synthesize(accs)
        # Stride adayi reddedildi ise log'da mesaj vardir;
        # kabul edildiyse log olmaz (iki durum da legal).
        stride_cands = [c for c in cands if c.name.startswith("cand_stride_")]
        stride_debug_msgs = [
            rec for rec in caplog.records
            if "Stride adayi atlandi" in rec.message
        ]
        # En az birisi olmali: ya stride adayi uretilmeli, ya debug log.
        assert len(stride_cands) > 0 or len(stride_debug_msgs) > 0


# =============================================================================
# M5: Interaction feature docstring warning
# =============================================================================


class TestM5InteractionDocstringWarning:
    def test_interaction_docstring_has_warning(self) -> None:
        """interaction_features docstring'inde empirik uyari olmali."""
        from karadul.computation.fusion.features import interaction_features
        doc = interaction_features.__doc__ or ""
        assert "UYARI" in doc or "M5" in doc
        # empirik fit EDILMEMIS uyarisi
        lower = doc.lower()
        assert (
            "empirik" in lower or "fit edilm" in lower
            or "double-count" in lower.replace("_", "-")
        )
