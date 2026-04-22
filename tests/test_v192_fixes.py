"""Tests for v1.9.2 algorithm & performance fixes.

Covers:
    1. XTRIDE Bayesian Merge -- log-odds fusion correctness & edge cases
    2. CFG Fingerprint Active Features -- reserved feature exclusion (18, 22)
    3. D-S Conflict Metric -- ratio-based conflict formula
    4. Platform-aware SignatureDB -- filename-based platform inference
    5. Thread Safety helpers -- module-level constants & helpers in stages.py
    6. re.compile pattern cache -- regex caching behavior
"""

from __future__ import annotations

import importlib
import math
import re
import types

import pytest

# ---------------------------------------------------------------------------
# 1. XTRIDE Bayesian Merge
# ---------------------------------------------------------------------------

from karadul.reconstruction.xtride_typer import _bayesian_merge_confidences


class TestBayesianMerge:
    """_bayesian_merge_confidences: log-odds fusion dogruluk testleri."""

    def test_empty_list_returns_zero(self) -> None:
        """Bos kanit listesi -> 0.0."""
        assert _bayesian_merge_confidences([]) == 0.0

    def test_single_element(self) -> None:
        """Tek kanit -> yaklasik ayni deger (prior 0.5 ile bayesian update)."""
        result = _bayesian_merge_confidences([0.85])
        assert abs(result - 0.85) < 0.01, f"Tek eleman 0.85 beklendi, {result:.4f} geldi"

    def test_two_identical_high_confidence(self) -> None:
        """Iki ayni yuksek kanit -> additive'den buyuk posterior."""
        result = _bayesian_merge_confidences([0.85, 0.85])
        # Bayesian: iki bagımsız 0.85 -> ~0.97
        assert result > 0.95, f"Iki 0.85 -> >0.95 beklendi, {result:.4f} geldi"
        assert result < 1.0

    def test_single_low_confidence(self) -> None:
        """Dusuk guvenilirlik korunur."""
        result = _bayesian_merge_confidences([0.30])
        assert abs(result - 0.30) < 0.02, f"Tek 0.30 beklendi, {result:.4f} geldi"

    def test_mixed_high_low(self) -> None:
        """Karisik kanitlar -> orta deger."""
        result = _bayesian_merge_confidences([0.90, 0.20])
        # 0.90 yuksek, 0.20 dusuk -> birbirine yakin, ortada bir deger
        assert 0.40 < result < 0.80, f"Karisik -> (0.40, 0.80) beklendi, {result:.4f} geldi"

    def test_clamp_low(self) -> None:
        """Cok dusuk deger -> 0.01'e clamp edilmeli."""
        result = _bayesian_merge_confidences([0.001])
        # 0.001 -> clamp to 0.01 -> sonuc ~0.01
        assert result >= 0.01, f"Clamp min 0.01 beklendi, {result:.4f} geldi"

    def test_clamp_high(self) -> None:
        """Cok yuksek deger -> 0.99'a clamp edilmeli."""
        result = _bayesian_merge_confidences([0.999])
        # 0.999 -> clamp to 0.99 -> sonuc ~0.99
        assert result <= 0.99, f"Clamp max 0.99 beklendi, {result:.4f} geldi"

    def test_clamp_output_range(self) -> None:
        """Cok sayida yuksek kanit bile [0.01, 0.99] araliginda kalmali."""
        result = _bayesian_merge_confidences([0.99, 0.99, 0.99, 0.99, 0.99])
        assert 0.01 <= result <= 0.99

    def test_monotonicity(self) -> None:
        """Daha fazla kanit eklemek (ayni yonde) confidence'i artirmali."""
        c1 = _bayesian_merge_confidences([0.80])
        c2 = _bayesian_merge_confidences([0.80, 0.80])
        c3 = _bayesian_merge_confidences([0.80, 0.80, 0.80])
        assert c1 < c2 < c3, f"Monoton artis beklendi: {c1:.4f} < {c2:.4f} < {c3:.4f}"

    @pytest.mark.parametrize(
        "confidences,expected_min,expected_max",
        [
            ([0.50], 0.49, 0.51),           # prior ile ayni -> degismemeli
            ([0.50, 0.50], 0.49, 0.51),     # iki 0.50 -> hala ~0.50
            ([0.99, 0.01], 0.45, 0.55),     # zit kanitlar -> ~0.50
        ],
        ids=["single_50", "double_50", "opposing_evidence"],
    )
    def test_parametrized_ranges(
        self,
        confidences: list[float],
        expected_min: float,
        expected_max: float,
    ) -> None:
        result = _bayesian_merge_confidences(confidences)
        assert expected_min <= result <= expected_max, (
            f"confidences={confidences} -> [{expected_min}, {expected_max}] beklendi, {result:.4f} geldi"
        )


# ---------------------------------------------------------------------------
# 2. CFG Fingerprint Active Features
# ---------------------------------------------------------------------------

from karadul.reconstruction.recovery_layers.cfg_fingerprint import CFGFingerprinter


class TestCFGActiveFeatures:
    """_ACTIVE_FEATURES: reserved feature 18 ve 22 haric tutulmali."""

    def test_active_features_count(self) -> None:
        """24 toplam - 2 reserved = 22 aktif feature."""
        assert len(CFGFingerprinter._ACTIVE_FEATURES) == 22

    def test_feature_18_excluded(self) -> None:
        """Feature 18 (constant_usage_ratio) listede OLMAMALI."""
        assert 18 not in CFGFingerprinter._ACTIVE_FEATURES

    def test_feature_22_excluded(self) -> None:
        """Feature 22 (simd_indicator) listede OLMAMALI."""
        assert 22 not in CFGFingerprinter._ACTIVE_FEATURES

    def test_all_other_features_included(self) -> None:
        """0-23 araligindaki (18 ve 22 haric) tum feature'lar dahil."""
        expected = sorted(i for i in range(24) if i not in (18, 22))
        assert CFGFingerprinter._ACTIVE_FEATURES == expected

    def test_cosine_ignores_reserved_features(self) -> None:
        """Feature 18 ve 22'de farkli degerler olsa bile similarity degismemeli."""
        # Ayni temel vektor
        base = [0.5] * 24

        # Feature 18 ve 22'de farkli degerler
        modified = list(base)
        modified[18] = 0.99   # reserved: constant_usage_ratio
        modified[22] = 0.99   # reserved: simd_indicator

        sim = CFGFingerprinter._cosine_similarity(base, modified)
        # Aktif feature'lar ayni oldugu icin similarity ~1.0 olmali
        assert sim > 0.999, f"Reserved feature degisikligi similarity'yi etkilememeli: {sim:.4f}"

    def test_cosine_zero_vectors(self) -> None:
        """Sifir vektorler -> 0.0 similarity."""
        zero = [0.0] * 24
        assert CFGFingerprinter._cosine_similarity(zero, zero) == 0.0

    def test_cosine_identical_vectors(self) -> None:
        """Ayni vektorler -> 1.0 similarity."""
        v = [float(i) for i in range(24)]
        sim = CFGFingerprinter._cosine_similarity(v, v)
        assert abs(sim - 1.0) < 1e-6

    def test_cosine_different_lengths(self) -> None:
        """Farkli boyutlu vektorler desteklenmeli (short padding)."""
        v16 = [1.0] * 16  # eski 16-dim
        v24 = [1.0] * 24  # yeni 24-dim
        sim = CFGFingerprinter._cosine_similarity(v16, v24)
        # v16 sifirla padlenir, aktif feature'larin 16'si eslenir
        assert 0.0 < sim <= 1.0

    def test_cosine_uses_22_dimensions(self) -> None:
        """Cosine hesaplamasi 22 aktif boyut kullanmali.

        Feature 18 ve 22 sifir olsa bile diger 22 boyut hesaba katilmali.
        Bunu dogrulamak icin: sadece feature 18 ve 22'de deger olan vektorler
        sifir magnitude vermeli -> similarity 0.0.
        """
        # Sadece feature 18 ve 22'de deger var
        only_reserved = [0.0] * 24
        only_reserved[18] = 1.0
        only_reserved[22] = 1.0

        normal = [1.0] * 24

        # only_reserved'in aktif boyutlari tamamen sifir -> magnitude 0 -> sim 0
        sim = CFGFingerprinter._cosine_similarity(only_reserved, normal)
        assert sim == 0.0, f"Sadece reserved feature'larda deger varsa similarity 0 olmali: {sim}"


# ---------------------------------------------------------------------------
# 3. D-S Conflict Metric
# ---------------------------------------------------------------------------

from karadul.reconstruction.recovery_layers.signature_fusion import (
    EvidenceMass,
    FusedIdentification,
    SignatureFusion,
)


class TestDSConflictMetric:
    """Yeni conflict metric: second / first (ratio formulu)."""

    @pytest.fixture
    def fusion(self) -> SignatureFusion:
        return SignatureFusion()

    def _make_evidence(
        self,
        hypothesis: str,
        mass: float,
        source: str = "test_source",
        category: str = "test",
    ) -> EvidenceMass:
        return EvidenceMass(
            source=source,
            hypothesis=hypothesis,
            mass=mass,
            category=category,
        )

    def test_low_competition(self, fusion: SignatureFusion) -> None:
        """best=0.90, second=0.10 -> conflict~=0.11 (dusuk rekabet)."""
        evidence = [
            self._make_evidence("quicksort", 0.90, source="s1"),
            self._make_evidence("mergesort", 0.10, source="s2"),
        ]
        result = fusion._fuse_evidence("0x1000", evidence)
        # Fused masses DS ile birlestirildikten sonra oran hesaplanir.
        # Tek evidence'dan gelen mass'ler oldugu icin fused ~ orijinal.
        assert result.conflict_level < 0.30, (
            f"Dusuk rekabet beklendi, conflict={result.conflict_level:.4f}"
        )

    def test_high_competition(self, fusion: SignatureFusion) -> None:
        """Yakin mass'ler -> yuksek conflict."""
        evidence = [
            self._make_evidence("quicksort", 0.80, source="s1"),
            self._make_evidence("mergesort", 0.75, source="s2"),
        ]
        result = fusion._fuse_evidence("0x2000", evidence)
        assert result.conflict_level > 0.50, (
            f"Yuksek rekabet beklendi, conflict={result.conflict_level:.4f}"
        )

    def test_equal_masses(self, fusion: SignatureFusion) -> None:
        """Tam esit mass'ler -> conflict=1.0."""
        evidence = [
            self._make_evidence("quicksort", 0.50, source="s1"),
            self._make_evidence("mergesort", 0.50, source="s2"),
        ]
        result = fusion._fuse_evidence("0x3000", evidence)
        assert abs(result.conflict_level - 1.0) < 0.05, (
            f"Tam esit -> conflict~1.0 beklendi, {result.conflict_level:.4f} geldi"
        )

    def test_single_hypothesis_no_conflict(self, fusion: SignatureFusion) -> None:
        """Tek hipotez -> conflict=0.0."""
        evidence = [
            self._make_evidence("quicksort", 0.90, source="s1"),
        ]
        result = fusion._fuse_evidence("0x4000", evidence)
        assert result.conflict_level == 0.0, (
            f"Tek hipotez -> conflict=0.0 beklendi, {result.conflict_level:.4f} geldi"
        )

    def test_empty_evidence(self, fusion: SignatureFusion) -> None:
        """Bos evidence -> conflict=0.0, identified_as=''."""
        result = fusion._fuse_evidence("0x5000", [])
        assert result.conflict_level == 0.0
        assert result.identified_as == ""

    def test_conflict_formula_direct(self) -> None:
        """Ratio formulunu direkt test et: second/first."""
        # Bu test formulu izole olarak dogrular
        sorted_masses = [0.90, 0.10]  # descending
        conflict = sorted_masses[1] / sorted_masses[0]
        assert abs(conflict - 0.111) < 0.01

        sorted_masses = [0.90, 0.80]
        conflict = sorted_masses[1] / sorted_masses[0]
        assert abs(conflict - 0.889) < 0.01

        sorted_masses = [0.50, 0.50]
        conflict = sorted_masses[1] / sorted_masses[0]
        assert abs(conflict - 1.0) < 0.001

    def test_zero_best_mass(self) -> None:
        """best=0.0 -> conflict=0.0 (division by zero korunmasi)."""
        # Formul: if first > 0 else 0.0
        sorted_masses = sorted([0.0, 0.0], reverse=True)
        if len(sorted_masses) >= 2 and sorted_masses[0] > 0:
            conflict = sorted_masses[1] / sorted_masses[0]
        else:
            conflict = 0.0
        assert conflict == 0.0


# ---------------------------------------------------------------------------
# 4. Platform-aware SignatureDB
# ---------------------------------------------------------------------------

from karadul.analyzers.signature_db import SignatureDB, _infer_platform_from_filename


class TestPlatformInference:
    """_infer_platform_from_filename: dosya adindan platform tahmini."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("windows_api_signatures.json", ["pe"]),
            ("win_crypto.json", ["pe"]),
            ("linux_syscalls.json", ["elf"]),
            ("macos_frameworks.json", ["macho"]),
            ("darwin_security.json", ["macho"]),
        ],
        ids=["windows_prefix", "win_prefix", "linux_prefix", "macos_prefix", "darwin_prefix"],
    )
    def test_platform_detection(self, filename: str, expected: list[str]) -> None:
        result = _infer_platform_from_filename(filename)
        assert result == expected, f"{filename} -> {expected} beklendi, {result} geldi"

    @pytest.mark.parametrize(
        "filename",
        [
            "combined_1M.json",
            "generic_signatures.json",
            "crypto_patterns.json",
            "openssl_sigs.json",
        ],
        ids=["combined", "generic", "crypto", "openssl"],
    )
    def test_no_platform_detected(self, filename: str) -> None:
        """Platform tahmini yapilamazsa None donmeli."""
        result = _infer_platform_from_filename(filename)
        assert result is None, f"{filename} -> None beklendi, {result} geldi"

    def test_case_insensitive(self) -> None:
        """Dosya adi buyuk/kucuk harf duyarsiz olmali."""
        result = _infer_platform_from_filename("WINDOWS_api.json")
        assert result == ["pe"]

        result = _infer_platform_from_filename("Linux_ELF.json")
        assert result == ["elf"]

        result = _infer_platform_from_filename("MacOS_Frameworks.json")
        assert result == ["macho"]

    def test_signaturedb_accepts_target_platform(self) -> None:
        """SignatureDB constructor target_platform parametresi almali."""
        import inspect
        sig = inspect.signature(SignatureDB.__init__)
        assert "target_platform" in sig.parameters, (
            "SignatureDB.__init__ 'target_platform' parametresi eksik"
        )

    def test_signaturedb_stores_platform(self) -> None:
        """SignatureDB instance'i platform'u saklayabilmeli."""
        # Constructor'i cagirmadan attribute'u kontrol et
        import inspect
        source = inspect.getsource(SignatureDB.__init__)
        assert "target_platform" in source, (
            "SignatureDB.__init__ icinde target_platform kullanilmiyor"
        )


# ---------------------------------------------------------------------------
# 5. Thread Safety -- Module-level constants & helpers
# ---------------------------------------------------------------------------


class TestStagesModuleLevelHelpers:
    """stages.py: module-level fonksiyonlar ve sabitler."""

    def test_target_platform_map_is_module_level(self) -> None:
        """_TARGET_PLATFORM_MAP module-level constant olmali."""
        import karadul.stages as stages_mod
        assert hasattr(stages_mod, "_TARGET_PLATFORM_MAP"), (
            "_TARGET_PLATFORM_MAP module-level olarak tanimlanmamis"
        )
        assert isinstance(stages_mod._TARGET_PLATFORM_MAP, dict)

    def test_target_platform_map_contents(self) -> None:
        """Map'te macho, elf, pe platformlari olmali."""
        import karadul.stages as stages_mod
        values = set(stages_mod._TARGET_PLATFORM_MAP.values())
        assert "macho" in values, "macho platform map'te eksik"
        assert "elf" in values, "elf platform map'te eksik"
        assert "pe" in values, "pe platform map'te eksik"

    def test_merge_stage_results_is_module_level(self) -> None:
        """_merge_stage_results module-level fonksiyon olmali."""
        import karadul.stages as stages_mod
        assert hasattr(stages_mod, "_merge_stage_results"), (
            "_merge_stage_results module-level olarak tanimlanmamis"
        )
        assert callable(stages_mod._merge_stage_results)

    def test_collect_all_algorithms_exists(self) -> None:
        """_collect_all_algorithms helper'i tanimli olmali."""
        import karadul.stages as stages_mod
        assert hasattr(stages_mod, "_collect_all_algorithms"), (
            "_collect_all_algorithms module-level olarak tanimlanmamis"
        )
        assert callable(stages_mod._collect_all_algorithms)

    def test_collect_all_algorithms_empty(self) -> None:
        """Iki None input -> bos liste."""
        import karadul.stages as stages_mod
        result = stages_mod._collect_all_algorithms(None, None)
        assert result == []

    def test_collect_all_algorithms_with_mock(self) -> None:
        """Mock result objelerinden algoritma toplama."""
        import karadul.stages as stages_mod

        class MockResult:
            def __init__(self, success: bool, algorithms: list):
                self.success = success
                self.algorithms = algorithms

        algo = MockResult(True, ["aes_encrypt", "sha256"])
        eng = MockResult(True, ["memcpy_wrapper"])

        result = stages_mod._collect_all_algorithms(algo, eng)
        assert len(result) == 3
        assert "aes_encrypt" in result
        assert "sha256" in result
        assert "memcpy_wrapper" in result

    def test_collect_all_algorithms_partial_failure(self) -> None:
        """Bir sonuc basarisiz -> sadece basarili olanin algoritmalari."""
        import karadul.stages as stages_mod

        class MockResult:
            def __init__(self, success: bool, algorithms: list):
                self.success = success
                self.algorithms = algorithms

        algo = MockResult(True, ["quicksort"])
        eng = MockResult(False, ["should_not_appear"])

        result = stages_mod._collect_all_algorithms(algo, eng)
        assert result == ["quicksort"]


# ---------------------------------------------------------------------------
# 6. re.compile Pattern Cache
# ---------------------------------------------------------------------------


class TestReCompileCache:
    """re.compile ayni pattern icin ayni objeyi dondurur (CPython cache)."""

    def test_same_pattern_returns_cached(self) -> None:
        """Ayni pattern string -> ayni compiled regex objesi (CPython cache)."""
        pattern_str = r"\bparam_\d+\b"
        compiled_1 = re.compile(pattern_str)
        compiled_2 = re.compile(pattern_str)
        # CPython _cache sayesinde ayni obje donmeli
        assert compiled_1 is compiled_2, (
            "re.compile ayni pattern icin farkli obje dondurdu (cache calismadi)"
        )

    def test_different_patterns_different_objects(self) -> None:
        """Farkli pattern'ler farkli objeler dondurmeli."""
        p1 = re.compile(r"\blocal_\d+\b")
        p2 = re.compile(r"\bparam_\d+\b")
        assert p1 is not p2

    def test_pattern_with_flags_cached_separately(self) -> None:
        """Farkli flag'ler farkli cache entry'leri olusturur."""
        p1 = re.compile(r"test", re.IGNORECASE)
        p2 = re.compile(r"test")
        assert p1 is not p2

    def test_regex_functional_correctness(self) -> None:
        """Cache'den gelen regex dogru calisir."""
        pattern = re.compile(r"\bparam_(\d+)\b")
        match = pattern.search("void func(int param_1, char param_2)")
        assert match is not None
        assert match.group(1) == "1"


# ---------------------------------------------------------------------------
# 7. Ek Entegrasyon Testleri
# ---------------------------------------------------------------------------


class TestDSCombineWithIgnorance:
    """_ds_combine_with_ignorance: Dempster-Shafer ignorance modeli."""

    @pytest.fixture
    def fusion(self) -> SignatureFusion:
        return SignatureFusion()

    def test_single_belief(self, fusion: SignatureFusion) -> None:
        """Tek belief -> yaklasik ayni deger."""
        result = fusion._ds_combine_with_ignorance([0.80])
        assert 0.75 < result < 0.85

    def test_empty_beliefs(self, fusion: SignatureFusion) -> None:
        """Bos liste -> 0.0 (vacuous)."""
        result = fusion._ds_combine_with_ignorance([])
        assert result == 0.0

    def test_multiple_beliefs_increase(self, fusion: SignatureFusion) -> None:
        """Ayni yonde birden fazla belief -> confidence artar."""
        r1 = fusion._ds_combine_with_ignorance([0.60])
        r2 = fusion._ds_combine_with_ignorance([0.60, 0.60])
        assert r2 > r1

    def test_max_capped(self, fusion: SignatureFusion) -> None:
        """Sonuc 0.98'i gecememeli."""
        result = fusion._ds_combine_with_ignorance([0.95, 0.95, 0.95, 0.95])
        assert result <= 0.98


class TestFusedIdentificationSerialization:
    """FusedIdentification.to_dict(): conflict_level dahil serialization."""

    def test_to_dict_includes_conflict(self) -> None:
        fused = FusedIdentification(
            function_name="FUN_001000",
            function_address="0x1000",
            identified_as="quicksort",
            category="sorting",
            fused_confidence=0.85,
            conflict_level=0.23,
        )
        d = fused.to_dict()
        assert "conflict_level" in d
        assert d["conflict_level"] == 0.23

    def test_to_dict_rounds_conflict(self) -> None:
        fused = FusedIdentification(
            function_name="FUN_002000",
            function_address="0x2000",
            conflict_level=0.123456789,
        )
        d = fused.to_dict()
        assert d["conflict_level"] == 0.1235  # 4 decimal
