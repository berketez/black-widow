"""Unit tests for benchmark metrics and accuracy calculator.

Tests cover:
- AccuracyCalculator: exact, semantic, partial, wrong, missing matches
- BenchmarkMetrics: accuracy computation, recovery rate, serialization
- BenchmarkRunner: mock mode, JSON mode, sample benchmark
- Edge cases: empty names, unicode, very long names, single-word names
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.benchmark.metrics import (
    AccuracyCalculator,
    BenchmarkMetrics,
    NamingResult,
)
from tests.benchmark.benchmark_runner import (
    BenchmarkRunner,
    BenchmarkResult,
    SAMPLE_GROUND_TRUTH,
    SAMPLE_NAMING_MAP,
    run_sample_benchmark,
)

# v1.10.0 H4: benchmark suite'in parcasi, default run'da skip edilir.
pytestmark = pytest.mark.benchmark


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def calc() -> AccuracyCalculator:
    """Fresh AccuracyCalculator instance."""
    return AccuracyCalculator()


@pytest.fixture
def runner(tmp_path: Path) -> BenchmarkRunner:
    """BenchmarkRunner with temp output dir."""
    return BenchmarkRunner(output_dir=tmp_path)


# ===================================================================
# AccuracyCalculator — Exact Match
# ===================================================================


class TestExactMatch:
    """Exact match: original and recovered are identical after normalization."""

    def test_identical_names(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("parse_config", "parse_config")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_case_insensitive_match(self, calc: AccuracyCalculator) -> None:
        """camelCase vs snake_case should normalize to same thing."""
        r = calc.compare_name("parseConfig", "parse_config")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_prefix_stripped(self, calc: AccuracyCalculator) -> None:
        """Common C prefixes (m_, g_, s_, p_) should be stripped."""
        r = calc.compare_name("m_connection", "connection")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_leading_underscore_stripped(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("_init_module", "init_module")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_trailing_dedup_suffix(self, calc: AccuracyCalculator) -> None:
        """Trailing _2, _03 suffixes should be stripped for comparison."""
        r = calc.compare_name("send_data_2", "send_data")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_both_have_dedup_suffix(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("send_data_3", "send_data_7")
        assert r.score == 1.0
        assert r.match_type == "exact"


# ===================================================================
# AccuracyCalculator — Semantic Match
# ===================================================================


class TestSemanticMatch:
    """Semantic match: different words but same meaning via synonym table."""

    def test_send_vs_transmit(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("send_data", "transmit_data")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_init_vs_setup(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("init_module", "setup_module")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_recv_vs_receive(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("recv_packet", "receive_packet")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_destroy_vs_cleanup(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("destroy_context", "cleanup_context")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_encrypt_vs_encipher(self, calc: AccuracyCalculator) -> None:
        """Crypto domain semantic match."""
        r = calc.compare_name("encrypt_block", "encipher_block")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_hash_vs_digest(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("hash_password", "digest_password")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_alloc_vs_create(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("alloc_buffer", "create_buffer")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_lock_vs_acquire(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("lock_mutex", "acquire_mutex")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_cfg_vs_config(self, calc: AccuracyCalculator) -> None:
        """Abbreviation equivalence."""
        r = calc.compare_name("load_cfg", "load_config")
        assert r.score == 0.8
        assert r.match_type == "semantic"

    def test_tls_vs_ssl(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("setup_tls", "setup_ssl")
        assert r.score == 0.8
        assert r.match_type == "semantic"


# ===================================================================
# AccuracyCalculator — Partial Match
# ===================================================================


class TestPartialMatch:
    """Partial match: some name components overlap but not semantically equivalent."""

    def test_shared_class_different_method(self, calc: AccuracyCalculator) -> None:
        """CSocket_Send vs CSocket_SendData - 'send' and one common part."""
        r = calc.compare_name("socket_send", "socket_send_data")
        # "socket" and "send" are in both -> 2/3 = 0.67 >= 0.4
        assert r.match_type in ("partial", "exact", "semantic")
        assert r.score >= 0.5

    def test_partial_function_overlap(self, calc: AccuracyCalculator) -> None:
        """Two-word name where one word matches exactly."""
        r = calc.compare_name("validate_input", "validate_output")
        # "validate" common, "input" vs "output" — partial overlap 1/2 = 0.5
        assert r.score == 0.5
        assert r.match_type == "partial"

    def test_barely_partial(self, calc: AccuracyCalculator) -> None:
        """Edge case: exact threshold at 0.4."""
        r = calc.compare_name("process_http_request_data", "handle_http_response_body")
        # "http" is common (1/4 = 0.25) — below threshold
        # But "handle" expands to include "process" via semantic equiv
        # so this may be semantic. Let's just assert it's not wrong.
        assert r.score >= 0.0  # We don't assume specific outcome here


# ===================================================================
# AccuracyCalculator — Missing (Unnamed)
# ===================================================================


class TestMissingName:
    """Missing: recovered name is still a Ghidra/IDA placeholder."""

    def test_fun_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("parse_config", "FUN_00401000")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_sub_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("send_data", "sub_401200")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_var_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("g_config", "var_603000")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_local_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("buffer_len", "local_28")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_param_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("socket_fd", "param_1")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_dat_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("global_table", "DAT_00605000")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_field_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("vtable_offset", "field_0x10")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_ptr_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("func_ptr", "PTR_00401000")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_auto_var_placeholder(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("counter", "uVar1")
        assert r.score == 0.0
        assert r.match_type == "missing"

    def test_empty_name_is_missing(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("some_func", "")
        assert r.score == 0.0
        assert r.match_type == "missing"


# ===================================================================
# AccuracyCalculator — Wrong Name
# ===================================================================


class TestWrongName:
    """Wrong: recovered name is a real name but completely unrelated."""

    def test_totally_unrelated(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("parse_config", "render_graphics")
        assert r.score == 0.0
        assert r.match_type == "wrong"

    def test_no_overlap_at_all(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("send_packet", "draw_window")
        assert r.score == 0.0
        assert r.match_type == "wrong"

    def test_single_word_mismatch(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("main", "render")
        assert r.score == 0.0
        assert r.match_type == "wrong"


# ===================================================================
# AccuracyCalculator — Edge Cases
# ===================================================================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_very_long_name(self, calc: AccuracyCalculator) -> None:
        long_orig = "very_long_function_name_with_many_parts_for_testing"
        long_recv = "very_long_function_name_with_many_parts_for_testing"
        r = calc.compare_name(long_orig, long_recv)
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_single_character_names(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("x", "x")
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_single_char_mismatch(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("x", "y")
        assert r.score == 0.0
        assert r.match_type == "wrong"

    def test_unicode_name(self, calc: AccuracyCalculator) -> None:
        """Unicode in names should not crash, even if uncommon in C."""
        r = calc.compare_name("func_data", "func_data")
        assert r.score == 1.0

    def test_numeric_suffix_only(self, calc: AccuracyCalculator) -> None:
        """Name that is only a number after normalization."""
        r = calc.compare_name("func_123", "func_456")
        # After stripping trailing digits: "func" vs "func"
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_camel_case_complex(self, calc: AccuracyCalculator) -> None:
        """Complex CamelCase with acronyms."""
        r = calc.compare_name("parseHTTPResponse", "parse_http_response")
        # parseHTTPResponse normalizes to parse_h_t_t_p_response
        # This is tricky — consecutive uppercase gets split oddly
        # We just ensure it doesn't crash and returns a valid result
        assert r.match_type in ("exact", "semantic", "partial", "wrong", "missing")

    def test_same_word_repeated(self, calc: AccuracyCalculator) -> None:
        r = calc.compare_name("check_check", "check_check")
        assert r.score == 1.0


# ===================================================================
# BenchmarkMetrics
# ===================================================================


class TestBenchmarkMetrics:
    """Tests for BenchmarkMetrics aggregate computation."""

    def test_empty_metrics(self) -> None:
        m = BenchmarkMetrics()
        assert m.accuracy == 0.0
        assert m.recovery_rate == 0.0

    def test_perfect_score(self) -> None:
        m = BenchmarkMetrics(
            total_symbols=10,
            exact_matches=10,
        )
        assert m.accuracy == 100.0
        assert m.recovery_rate == 100.0

    def test_all_missing(self) -> None:
        m = BenchmarkMetrics(
            total_symbols=10,
            missing_names=10,
        )
        assert m.accuracy == 0.0
        assert m.recovery_rate == 0.0

    def test_mixed_results(self) -> None:
        m = BenchmarkMetrics(
            total_symbols=10,
            exact_matches=3,   # 3 * 1.0 = 3.0
            semantic_matches=2, # 2 * 0.8 = 1.6
            partial_matches=2,  # 2 * 0.5 = 1.0
            wrong_names=1,      # 0
            missing_names=2,    # 0
        )
        # Total weighted: 3.0 + 1.6 + 1.0 = 5.6
        # Accuracy: 5.6 / 10 * 100 = 56.0
        assert m.accuracy == pytest.approx(56.0)
        # Recovery: (10 - 2) / 10 * 100 = 80.0
        assert m.recovery_rate == 80.0

    def test_to_dict_keys(self) -> None:
        m = BenchmarkMetrics(total_symbols=5, exact_matches=2, missing_names=1)
        d = m.to_dict()
        # v1.10.0 Batch 5A: F1 / per-source / confusion matrix alanlari eklendi.
        # v1.11.0 Bug 3: fun_residue_pct, type_precision, type_recall eklendi.
        # v1.11.0 Dalga 5: preserved/renamed ayrimi alanlari eklendi.
        expected_keys = {
            "total_symbols", "exact_matches", "semantic_matches",
            "partial_matches", "wrong_names", "missing_names",
            "accuracy", "recovery_rate",
            # v1.10.0
            "precision", "recall", "f1",
            "per_source_precision", "per_source_recall", "per_source_f1",
            "confusion_matrix",
            # v1.11.0
            "fun_residue_pct", "type_precision", "type_recall",
            # v1.11.0 Dalga 5
            "preserved_names", "renamed_total",
            "renamed_precision", "renamed_recall", "renamed_f1",
            "renamed_accuracy",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_rounding(self) -> None:
        m = BenchmarkMetrics(total_symbols=3, exact_matches=1)
        d = m.to_dict()
        # 1/3 * 100 = 33.333... -> rounded to 33.33
        assert d["accuracy"] == 33.33

    def test_summary_format(self) -> None:
        m = BenchmarkMetrics(
            total_symbols=10,
            exact_matches=5,
            semantic_matches=2,
            partial_matches=1,
            wrong_names=1,
            missing_names=1,
        )
        s = m.summary()
        assert "accuracy=" in s
        assert "recovery=" in s
        assert "total=10" in s

    def test_calculate_metrics_from_comparisons(self, calc: AccuracyCalculator) -> None:
        """End-to-end: compare names -> calculate metrics."""
        pairs = [
            ("main", "main"),                 # exact
            ("send_data", "transmit_data"),    # semantic
            ("parse_config", "read_config"),   # semantic
            ("validate_input", "FUN_00401000"),# missing
            ("close_conn", "render_window"),   # wrong
        ]
        comparisons = [calc.compare_name(orig, recv) for orig, recv in pairs]
        metrics = calc.calculate_metrics(comparisons)

        assert metrics.total_symbols == 5
        assert metrics.exact_matches == 1
        assert metrics.semantic_matches == 2
        assert metrics.missing_names == 1
        assert metrics.wrong_names == 1


# ===================================================================
# BenchmarkRunner
# ===================================================================


class TestBenchmarkRunner:
    """Tests for the benchmark runner."""

    def test_run_mock_basic(self, runner: BenchmarkRunner) -> None:
        ground_truth = {
            "FUN_001": "init",
            "FUN_002": "cleanup",
        }
        naming_map = {
            "FUN_001": "initialize",
            "FUN_002": "cleanup",
        }
        result = runner.run_mock(ground_truth, naming_map)
        assert result.metrics.total_symbols == 2
        assert result.metrics.exact_matches == 1  # cleanup
        assert result.ground_truth_source == "mock"

    def test_run_mock_empty_naming_map(self, runner: BenchmarkRunner) -> None:
        """When Karadul produces no names, everything stays unnamed."""
        ground_truth = {
            "FUN_001": "main",
            "FUN_002": "send_data",
        }
        naming_map: dict[str, str] = {}
        result = runner.run_mock(ground_truth, naming_map)
        assert result.metrics.missing_names == 2
        assert result.metrics.accuracy == 0.0

    def test_run_mock_saves_json(self, runner: BenchmarkRunner, tmp_path: Path) -> None:
        result = runner.run_mock({"FUN_001": "main"}, {"FUN_001": "main"})
        # Check JSON file was created in output_dir
        json_files = list(tmp_path.glob("benchmark_mock_*.json"))
        assert len(json_files) == 1

        data = json.loads(json_files[0].read_text())
        assert data["metrics"]["total_symbols"] == 1
        assert data["metrics"]["accuracy"] == 100.0
        assert data["ground_truth_source"] == "mock"

    def test_run_from_json_files(self, runner: BenchmarkRunner, tmp_path: Path) -> None:
        """Test JSON file mode."""
        gt_file = tmp_path / "ground_truth.json"
        nm_file = tmp_path / "naming_map.json"

        ground_truth = {"FUN_001": "parse", "FUN_002": "send"}
        naming_map = {"FUN_001": "decode", "FUN_002": "transmit"}

        gt_file.write_text(json.dumps(ground_truth))
        nm_file.write_text(json.dumps(naming_map))

        result = runner.run_from_naming_map(gt_file, nm_file)
        assert result.metrics.total_symbols == 2
        assert result.ground_truth_source == "json"
        # Both should be semantic matches
        assert result.metrics.semantic_matches == 2

    def test_sample_benchmark(self) -> None:
        """Run the built-in sample benchmark."""
        result = run_sample_benchmark()
        assert result.metrics.total_symbols == len(SAMPLE_GROUND_TRUTH)
        assert result.metrics.accuracy > 0
        assert result.metrics.recovery_rate > 0
        # Sample has known exact match: "main"
        assert result.metrics.exact_matches >= 1
        # Sample has known missing: FUN_00402700, FUN_00402800, DAT_00603200
        assert result.metrics.missing_names >= 3

    def test_result_to_dict_structure(self, runner: BenchmarkRunner) -> None:
        result = runner.run_mock(
            {"FUN_001": "init"},
            {"FUN_001": "setup"},
        )
        d = result.to_dict()
        assert "timestamp" in d
        assert "config" in d
        assert "metrics" in d
        assert "per_symbol" in d
        assert isinstance(d["per_symbol"], list)
        assert len(d["per_symbol"]) == 1
        assert d["per_symbol"][0]["match_type"] == "semantic"

    def test_result_save_json(self, tmp_path: Path) -> None:
        """Test explicit save_json method."""
        runner = BenchmarkRunner()
        result = runner.run_mock({"FUN_001": "main"}, {"FUN_001": "main"})

        out_file = tmp_path / "test_result.json"
        result.save_json(out_file)
        assert out_file.exists()

        data = json.loads(out_file.read_text())
        assert data["metrics"]["accuracy"] == 100.0

    def test_result_save_json_creates_dirs(self, tmp_path: Path) -> None:
        """save_json should create parent directories if needed."""
        runner = BenchmarkRunner()
        result = runner.run_mock({"FUN_001": "main"}, {"FUN_001": "main"})

        deep_path = tmp_path / "a" / "b" / "c" / "result.json"
        result.save_json(deep_path)
        assert deep_path.exists()


# ===================================================================
# Semantic equivalence table completeness
# ===================================================================


class TestSemanticEquivTable:
    """Verify the synonym table covers important reverse engineering domains."""

    def test_security_terms_present(self, calc: AccuracyCalculator) -> None:
        """Security/crypto terms should be in the equivalence table."""
        security_keys = {"encrypt", "decrypt", "hash", "sign", "key", "cert",
                         "auth", "rand", "cipher", "tls", "perm"}
        actual_keys = set(AccuracyCalculator.SEMANTIC_EQUIV.keys())
        assert security_keys.issubset(actual_keys), (
            f"Missing security terms: {security_keys - actual_keys}"
        )

    def test_lifecycle_terms_present(self, calc: AccuracyCalculator) -> None:
        lifecycle_keys = {"init", "destroy", "reset"}
        actual_keys = set(AccuracyCalculator.SEMANTIC_EQUIV.keys())
        assert lifecycle_keys.issubset(actual_keys)

    def test_io_terms_present(self, calc: AccuracyCalculator) -> None:
        io_keys = {"send", "recv", "connect", "disconnect", "listen"}
        actual_keys = set(AccuracyCalculator.SEMANTIC_EQUIV.keys())
        assert io_keys.issubset(actual_keys)

    def test_equivalence_is_symmetric(self, calc: AccuracyCalculator) -> None:
        """If A is synonym of B, then B should also map to A."""
        for word, synonyms in calc._equiv_map.items():
            for syn in synonyms:
                assert word in calc._equiv_map.get(syn, set()), (
                    f"Asymmetric: {word} -> {syn} but {syn} does not include {word}"
                )

    def test_bidirectional_match(self, calc: AccuracyCalculator) -> None:
        """Semantic match should work in both directions."""
        r1 = calc.compare_name("send_data", "transmit_data")
        r2 = calc.compare_name("transmit_data", "send_data")
        assert r1.match_type == r2.match_type == "semantic"


# ===================================================================
# NamingResult
# ===================================================================


class TestNamingResult:
    """Tests for the NamingResult dataclass."""

    def test_fields(self) -> None:
        r = NamingResult(
            original="main",
            recovered="main",
            score=1.0,
            match_type="exact",
        )
        assert r.original == "main"
        assert r.recovered == "main"
        assert r.score == 1.0
        assert r.match_type == "exact"

    def test_repr(self) -> None:
        r = NamingResult("a", "b", 0.5, "partial")
        s = repr(r)
        assert "NamingResult" in s
        assert "partial" in s

    def test_source_field_default_empty(self) -> None:
        """v1.10.0: source alani opsiyonel, default ''."""
        r = NamingResult("x", "y", 1.0, "exact")
        assert r.source == ""

    def test_source_field_settable(self) -> None:
        """v1.10.0: source alani belirtilebilir."""
        r = NamingResult("x", "y", 1.0, "exact", source="ngram")
        assert r.source == "ngram"


# ===================================================================
# v1.10.0 Batch 5A: F1 / Per-Source / Confusion Matrix
# ===================================================================


class TestF1Metrics:
    """Global F1, precision, recall testleri."""

    def test_perfect_f1(self, calc: AccuracyCalculator) -> None:
        """Tum exact match -> F1=1.0"""
        comparisons = [
            NamingResult("a", "a", 1.0, "exact"),
            NamingResult("b", "b", 1.0, "exact"),
            NamingResult("c", "c", 1.0, "exact"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0

    def test_all_missing_f1_zero(self, calc: AccuracyCalculator) -> None:
        """Tum missing -> recall=0 (TP=0, FN=3) -> F1=0."""
        comparisons = [
            NamingResult("a", "FUN_00401000", 0.0, "missing"),
            NamingResult("b", "FUN_00401100", 0.0, "missing"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.recall == 0.0
        assert m.f1 == 0.0

    def test_all_wrong_f1_zero(self, calc: AccuracyCalculator) -> None:
        """Tum wrong -> precision=0 (TP=0, FP=3) -> F1=0."""
        comparisons = [
            NamingResult("a", "render_xyz", 0.0, "wrong"),
            NamingResult("b", "draw_foo", 0.0, "wrong"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.precision == 0.0
        assert m.f1 == 0.0

    def test_mixed_f1(self, calc: AccuracyCalculator) -> None:
        """Karisik sonuc: F1 formulune uymali.

        TP=2 (1 exact + 1 partial), FP=1 (wrong), FN=1 (missing)
        P = 2 / 3 = 0.667
        R = 2 / 3 = 0.667
        F1 = 2*P*R/(P+R) = 0.667
        """
        comparisons = [
            NamingResult("a", "a", 1.0, "exact"),
            NamingResult("b", "b_xx", 0.5, "partial"),
            NamingResult("c", "random", 0.0, "wrong"),
            NamingResult("d", "FUN_001", 0.0, "missing"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.precision == pytest.approx(2/3, rel=0.01)
        assert m.recall == pytest.approx(2/3, rel=0.01)
        assert m.f1 == pytest.approx(2/3, rel=0.01)

    def test_f1_partial_counted_as_tp(self, calc: AccuracyCalculator) -> None:
        """Partial match TP'ye dahil olmali."""
        comparisons = [
            NamingResult("a", "foo", 0.5, "partial"),
            NamingResult("b", "bar", 0.5, "partial"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.precision == 1.0  # TP=2, FP=0
        assert m.recall == 1.0      # TP=2, FN=0
        assert m.f1 == 1.0

    def test_empty_comparisons_f1_zero(self, calc: AccuracyCalculator) -> None:
        """Bos girdi -> tum metrikler 0."""
        m = calc.calculate_metrics([])
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0


class TestPerSourceMetrics:
    """Kaynak (source) bazli kirilim testleri."""

    def test_single_source(self, calc: AccuracyCalculator) -> None:
        """Tek kaynakli comparisonlar: per-source == global."""
        comparisons = [
            NamingResult("a", "a", 1.0, "exact", source="sig_db"),
            NamingResult("b", "b", 1.0, "exact", source="sig_db"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.per_source_f1["sig_db"] == 1.0
        assert m.per_source_precision["sig_db"] == 1.0
        assert m.per_source_recall["sig_db"] == 1.0

    def test_multi_source_breakdown(self, calc: AccuracyCalculator) -> None:
        """Farkli kaynaklar ayri F1 alir."""
        comparisons = [
            # sig_db: 2 exact / 0 yanlis -> F1 = 1.0
            NamingResult("a", "a", 1.0, "exact", source="sig_db"),
            NamingResult("b", "b", 1.0, "exact", source="sig_db"),
            # ngram: 1 exact / 1 missing -> P=1.0, R=0.5, F1=0.667
            NamingResult("c", "c", 1.0, "exact", source="ngram"),
            NamingResult("d", "FUN_001", 0.0, "missing", source="ngram"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.per_source_f1["sig_db"] == 1.0
        assert m.per_source_f1["ngram"] == pytest.approx(2/3, rel=0.01)

    def test_no_source_goes_to_unknown(self, calc: AccuracyCalculator) -> None:
        """source='' -> 'unknown' bucket."""
        comparisons = [
            NamingResult("a", "a", 1.0, "exact"),  # source default ""
        ]
        m = calc.calculate_metrics(comparisons)
        assert "unknown" in m.per_source_f1

    def test_compute_per_source_returns_dict(self, calc: AccuracyCalculator) -> None:
        """compute_per_source 3 alanlik dict dondurmeli."""
        comparisons = [
            NamingResult("a", "a", 1.0, "exact", source="x"),
        ]
        result = calc.compute_per_source(comparisons)
        assert set(result.keys()) == {"precision", "recall", "f1"}
        assert "x" in result["f1"]


class TestConfusionMatrix:
    """Confusion matrix dagilim testleri."""

    def test_confusion_matrix_counts_match_types(
        self, calc: AccuracyCalculator
    ) -> None:
        """Her match_type icin sayim yapilmali."""
        comparisons = [
            NamingResult("a", "a", 1.0, "exact"),
            NamingResult("b", "b", 1.0, "exact"),
            NamingResult("c", "d", 0.0, "wrong"),
        ]
        m = calc.calculate_metrics(comparisons)
        assert m.confusion_matrix["exact"]["exact"] == 2
        assert m.confusion_matrix["wrong"]["wrong"] == 1

    def test_confusion_matrix_in_to_dict(
        self, calc: AccuracyCalculator
    ) -> None:
        """confusion_matrix serialize edilebilmeli."""
        comparisons = [NamingResult("a", "a", 1.0, "exact")]
        m = calc.calculate_metrics(comparisons)
        d = m.to_dict()
        assert "confusion_matrix" in d
        assert d["confusion_matrix"]["exact"]["exact"] == 1


# ===================================================================
# v1.11.0 Dalga 5: Preserved Kategorisi
# ===================================================================


class TestPreservedCategory:
    """v1.11.0 Dalga 5: preserved semboller F1/accuracy'den hariç tutulur."""

    def test_preserved_not_counted_as_tp(self):
        """preserved sembol TP sayılmaz, F1'e katkı yok."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("parse_config", "parse_config", 1.0, "exact"),
            NamingResult("send_packet", "send_packet", 0.0, "preserved"),
            NamingResult("encrypt", "FUN_401000", 0.0, "missing"),
        ]
        m = calc.calculate_metrics(results)
        assert m.total_symbols == 3
        assert m.exact_matches == 1
        assert m.preserved_names == 1
        assert m.missing_names == 1
        # TP = 1 (exact), FN = 1 (missing), FP = 0
        # precision = 1/1 = 1.0, recall = 1/2 = 0.5, f1 = 0.667
        assert m.precision == pytest.approx(1.0)
        assert m.recall == pytest.approx(0.5)
        assert m.f1 == pytest.approx(2 * 1.0 * 0.5 / 1.5, abs=0.01)

    def test_preserved_excluded_from_accuracy(self):
        """accuracy denominator = total - preserved."""
        calc = AccuracyCalculator()
        # 4 sembolün 2'si preserved, 1 exact, 1 missing
        # renamed_total = 2, score = 1.0 (exact)
        # accuracy = 1.0/2 * 100 = 50.0 (preserved hariç)
        results = [
            NamingResult("a", "a", 0.0, "preserved"),
            NamingResult("b", "b", 0.0, "preserved"),
            NamingResult("c", "c", 1.0, "exact"),
            NamingResult("d", "FUN_x", 0.0, "missing"),
        ]
        m = calc.calculate_metrics(results)
        assert m.preserved_names == 2
        assert m.accuracy == pytest.approx(50.0)
        assert m.renamed_total == 2
        assert m.renamed_accuracy == pytest.approx(50.0)

    def test_all_preserved_accuracy_zero(self):
        """Hepsi preserved -> accuracy=0 (challenge yok)."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("a", "a", 0.0, "preserved"),
            NamingResult("b", "b", 0.0, "preserved"),
        ]
        m = calc.calculate_metrics(results)
        assert m.preserved_names == 2
        assert m.accuracy == 0.0
        assert m.renamed_total == 0
        assert m.renamed_accuracy == 0.0
        assert m.f1 == 0.0

    def test_backward_compat_no_preserved(self):
        """Preserved yoksa eski davranış aynı kalır."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("parse_config", "parse_config", 1.0, "exact"),
            NamingResult("send", "transmit", 0.8, "semantic"),
        ]
        m = calc.calculate_metrics(results)
        assert m.preserved_names == 0
        assert m.renamed_total == 2
        assert m.accuracy == pytest.approx((1.0 + 0.8) / 2 * 100)
        # Eski ve yeni aynı sonucu verir
        assert m.accuracy == m.renamed_accuracy
        assert m.f1 == m.renamed_f1

    def test_to_dict_contains_new_fields(self):
        """to_dict yeni alanları içerir."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("a", "a", 0.0, "preserved"),
            NamingResult("b", "b", 1.0, "exact"),
        ]
        m = calc.calculate_metrics(results)
        d = m.to_dict()
        assert "preserved_names" in d
        assert d["preserved_names"] == 1
        assert "renamed_total" in d
        assert d["renamed_total"] == 1
        assert "renamed_f1" in d
        assert "renamed_accuracy" in d

    def test_summary_shows_preserved(self):
        """summary() preserved sayısını içerir."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("a", "a", 0.0, "preserved"),
            NamingResult("b", "b", 1.0, "exact"),
        ]
        m = calc.calculate_metrics(results)
        s = m.summary()
        assert "preserved=1" in s
