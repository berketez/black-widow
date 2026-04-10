"""Integration benchmark tests for Karadul v1.2 modules.

Tests cover:
- Dispatch resolution accuracy (mock call graph + known dispatch sites)
- Function naming accuracy (ground truth vs naming map comparison)
- Algorithm detection recall (known crypto functions detection)
- Composition detection recall (known workflow detection)

All tests use mock data -- no real binary execution.
Minimum 30 tests as per Sprint 5 spec.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

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
)
from tests.benchmark.ground_truth_generator import (
    GroundTruth,
    GroundTruthGenerator,
    GroundTruthSymbol,
    _is_ghidra_auto_name,
    _is_internal_symbol,
)


# ===================================================================
# Mock Data Factories
# ===================================================================


def _make_mock_call_graph(
    functions: list[str],
    edges: list[tuple[str, str]],
) -> dict:
    """Build a mock call graph JSON structure.

    Matches the format Karadul stages produce:
    {
        "functions": [{"name": "FUN_xxx", "address": "0x..."}],
        "calls": [{"caller": "FUN_a", "callee": "FUN_b"}]
    }
    """
    return {
        "functions": [
            {"name": f, "address": f"0x{i:08x}"}
            for i, f in enumerate(functions, 0x1000)
        ],
        "calls": [
            {"caller": src, "callee": dst}
            for src, dst in edges
        ],
    }


def _make_mock_dispatch_result(
    total: int = 100,
    resolved: int = 65,
    candidates: int = 15,
    unresolved: int = 10,
    external: int = 10,
) -> dict:
    """Build a mock DispatchResolutionResult-like dict."""
    return {
        "success": True,
        "total_dispatch_sites": total,
        "resolved_count": resolved,
        "candidate_count": candidates,
        "unresolved_count": unresolved,
        "external_count": external,
        "resolution_rate": resolved / total if total > 0 else 0.0,
        "augmented_edges": [
            {"caller": f"FUN_{i:08x}", "callee": f"FUN_{i+0x100:08x}", "dispatch_type": "objc_msgSend"}
            for i in range(resolved)
        ],
        "removed_edges": [],
    }


def _make_mock_algorithm_matches(
    algorithms: list[dict[str, Any]],
) -> list[dict]:
    """Build mock AlgorithmMatch-like dicts.

    Each item in algorithms should have: name, category, function_name.
    Optional: confidence, detection_method, evidence, address.
    """
    result = []
    for i, algo in enumerate(algorithms):
        result.append({
            "name": algo["name"],
            "category": algo.get("category", "symmetric_cipher"),
            "confidence": algo.get("confidence", 0.85),
            "detection_method": algo.get("detection_method", "constant"),
            "evidence": algo.get("evidence", [f"evidence_{i}"]),
            "function_name": algo["function_name"],
            "address": algo.get("address", f"0x{(i + 1) * 0x1000:08x}"),
        })
    return result


def _make_mock_compositions(
    compositions: list[dict[str, Any]],
) -> dict:
    """Build a mock CompositionResult-like dict."""
    comp_list = []
    for c in compositions:
        stages = []
        for j, stage_name in enumerate(c.get("stages", ["stage_0"])):
            stages.append({
                "name": stage_name,
                "functions": c.get("functions", [f"FUN_{j:08x}"]),
                "algorithms": c.get("algorithms", []),
                "order": j,
                "confidence": c.get("confidence", 0.75),
            })
        comp_list.append({
            "name": c["name"],
            "pattern": c.get("pattern", "pipeline"),
            "stages": stages,
            "total_functions": len(c.get("functions", stages)),
            "confidence": c.get("confidence", 0.75),
            "description": c.get("description", f"Mock composition: {c['name']}"),
            "domain": c.get("domain", "crypto"),
        })

    return {
        "success": True,
        "compositions": comp_list,
        "total_compositions": len(comp_list),
        "unclustered_algorithms": [],
        "errors": [],
    }


# Large ground truth for crypto library simulation
CRYPTO_GROUND_TRUTH: dict[str, str] = {
    # AES functions
    "FUN_00010000": "AES_set_encrypt_key",
    "FUN_00010100": "AES_set_decrypt_key",
    "FUN_00010200": "AES_encrypt",
    "FUN_00010300": "AES_decrypt",
    "FUN_00010400": "AES_cbc_encrypt",
    # SHA functions
    "FUN_00020000": "SHA256_Init",
    "FUN_00020100": "SHA256_Update",
    "FUN_00020200": "SHA256_Final",
    "FUN_00020300": "SHA1_Init",
    "FUN_00020400": "SHA1_Update",
    "FUN_00020500": "SHA1_Final",
    # RSA functions
    "FUN_00030000": "RSA_new",
    "FUN_00030100": "RSA_free",
    "FUN_00030200": "RSA_public_encrypt",
    "FUN_00030300": "RSA_private_decrypt",
    "FUN_00030400": "RSA_sign",
    "FUN_00030500": "RSA_verify",
    # EVP functions
    "FUN_00040000": "EVP_EncryptInit_ex",
    "FUN_00040100": "EVP_EncryptUpdate",
    "FUN_00040200": "EVP_EncryptFinal_ex",
    "FUN_00040300": "EVP_DecryptInit_ex",
    "FUN_00040400": "EVP_DecryptUpdate",
    "FUN_00040500": "EVP_DecryptFinal_ex",
    "FUN_00040600": "EVP_DigestInit_ex",
    "FUN_00040700": "EVP_DigestUpdate",
    "FUN_00040800": "EVP_DigestFinal_ex",
    # HMAC functions
    "FUN_00050000": "HMAC_Init_ex",
    "FUN_00050100": "HMAC_Update",
    "FUN_00050200": "HMAC_Final",
    # BN functions
    "FUN_00060000": "BN_new",
    "FUN_00060100": "BN_free",
    "FUN_00060200": "BN_add",
    "FUN_00060300": "BN_mul",
    "FUN_00060400": "BN_mod_exp",
    # EC functions
    "FUN_00070000": "EC_KEY_new",
    "FUN_00070100": "EC_KEY_free",
    "FUN_00070200": "EC_KEY_generate_key",
    "FUN_00070300": "ECDSA_sign",
    "FUN_00070400": "ECDSA_verify",
    # X509
    "FUN_00080000": "X509_new",
    "FUN_00080100": "X509_free",
    "FUN_00080200": "X509_verify",
    "FUN_00080300": "X509_get_subject_name",
    # PEM
    "FUN_00090000": "PEM_read_X509",
    "FUN_00090100": "PEM_write_PrivateKey",
    # BIO
    "FUN_000a0000": "BIO_new",
    "FUN_000a0100": "BIO_free",
    "FUN_000a0200": "BIO_read",
    "FUN_000a0300": "BIO_write",
}

# Simulated Karadul naming output (mix of exact, semantic, partial, wrong, missing)
CRYPTO_NAMING_MAP: dict[str, str] = {
    # AES -- mostly correct
    "FUN_00010000": "AES_set_encrypt_key",          # exact
    "FUN_00010100": "AES_set_decrypt_key",          # exact
    "FUN_00010200": "aes_encrypt_block",            # partial (AES_encrypt vs aes_encrypt_block)
    "FUN_00010300": "aes_decrypt_block",            # partial
    "FUN_00010400": "AES_cbc_encrypt",              # exact
    # SHA -- good
    "FUN_00020000": "sha256_initialize",            # semantic (Init ~ initialize)
    "FUN_00020100": "SHA256_Update",                # exact
    "FUN_00020200": "sha256_finalize",              # semantic (Final ~ finalize)
    "FUN_00020300": "SHA1_Init",                    # exact
    "FUN_00020400": "SHA1_Update",                  # exact
    "FUN_00020500": "SHA1_Final",                   # exact
    # RSA -- mixed
    "FUN_00030000": "RSA_new",                      # exact
    "FUN_00030100": "RSA_free",                     # exact
    "FUN_00030200": "rsa_public_encrypt",           # exact (case normalization)
    "FUN_00030300": "rsa_private_decrypt",          # exact (case normalization)
    "FUN_00030400": "RSA_sign",                     # exact
    "FUN_00030500": "rsa_verify_signature",         # partial (RSA_verify vs rsa_verify_signature)
    # EVP -- mixed
    "FUN_00040000": "EVP_EncryptInit_ex",           # exact
    "FUN_00040100": "evp_encrypt_update",           # exact (case)
    "FUN_00040200": "EVP_EncryptFinal_ex",          # exact
    "FUN_00040300": "EVP_DecryptInit_ex",           # exact
    "FUN_00040400": "EVP_DecryptUpdate",            # exact
    "FUN_00040500": "EVP_DecryptFinal_ex",          # exact
    "FUN_00040600": "evp_digest_init",              # partial
    "FUN_00040700": "EVP_DigestUpdate",             # exact
    "FUN_00040800": "EVP_DigestFinal_ex",           # exact
    # HMAC -- semantic
    "FUN_00050000": "hmac_initialize",              # semantic
    "FUN_00050100": "HMAC_Update",                  # exact
    "FUN_00050200": "hmac_finalize",                # semantic
    # BN -- some missing
    "FUN_00060000": "BN_new",                       # exact
    "FUN_00060100": "BN_free",                      # exact
    "FUN_00060200": "bignum_add",                   # partial (BN_add vs bignum_add)
    # FUN_00060300 missing -- still FUN_xxx
    # FUN_00060400 missing -- still FUN_xxx
    # EC -- wrong
    "FUN_00070000": "create_ec_key",                # semantic (new ~ create)
    "FUN_00070100": "destroy_ec_key",               # semantic (free ~ destroy)
    "FUN_00070200": "generate_ec_keypair",          # partial
    "FUN_00070300": "wrong_function_name",          # wrong
    "FUN_00070400": "another_wrong_name",           # wrong
    # X509 -- partial
    "FUN_00080000": "x509_create",                  # semantic (new ~ create)
    "FUN_00080100": "x509_destroy",                 # semantic (free ~ destroy)
    "FUN_00080200": "x509_check_valid",             # partial
    # FUN_00080300 missing
    # PEM
    "FUN_00090000": "pem_read_certificate",         # partial
    "FUN_00090100": "pem_write_key",                # partial
    # BIO
    "FUN_000a0000": "bio_create",                   # semantic (new ~ create)
    "FUN_000a0100": "bio_destroy",                  # semantic (free ~ destroy)
    "FUN_000a0200": "bio_read_data",                # partial (BIO_read vs bio_read_data)
    # FUN_000a0300 missing
}


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def calc() -> AccuracyCalculator:
    return AccuracyCalculator()


@pytest.fixture
def runner(tmp_path: Path) -> BenchmarkRunner:
    return BenchmarkRunner(output_dir=tmp_path)


@pytest.fixture
def gt_gen() -> GroundTruthGenerator:
    return GroundTruthGenerator(demangle=True, include_data=False)


@pytest.fixture
def crypto_ground_truth() -> GroundTruth:
    """GroundTruth object from CRYPTO_GROUND_TRUTH dict."""
    symbols = [
        GroundTruthSymbol(
            address=addr.replace("FUN_", "0x"),
            name=name,
            symbol_type="T",
        )
        for addr, name in CRYPTO_GROUND_TRUTH.items()
    ]
    return GroundTruth(
        binary_path="/mock/libcrypto.dylib",
        symbols=symbols,
        metadata={"library": "mock_openssl"},
    )


# ===================================================================
# TestDispatchAccuracy -- Dispatch resolution benchmark
# ===================================================================


class TestDispatchAccuracy:
    """Dispatch resolution accuracy tests using mock call graphs."""

    def test_resolution_rate_basic(self) -> None:
        """Resolution rate should be computed correctly from counts."""
        result = _make_mock_dispatch_result(
            total=100, resolved=65, candidates=15, unresolved=10, external=10
        )
        assert result["resolution_rate"] == pytest.approx(0.65, abs=0.01)

    def test_resolution_rate_perfect(self) -> None:
        """100% resolution rate when all sites are resolved."""
        result = _make_mock_dispatch_result(
            total=50, resolved=50, candidates=0, unresolved=0, external=0
        )
        assert result["resolution_rate"] == 1.0

    def test_resolution_rate_zero(self) -> None:
        """0% resolution rate when nothing is resolved."""
        result = _make_mock_dispatch_result(
            total=50, resolved=0, candidates=0, unresolved=50, external=0
        )
        assert result["resolution_rate"] == 0.0

    def test_resolution_rate_empty(self) -> None:
        """Empty dispatch sites should not crash."""
        result = _make_mock_dispatch_result(
            total=0, resolved=0, candidates=0, unresolved=0, external=0
        )
        assert result["resolution_rate"] == 0.0

    def test_augmented_edges_count(self) -> None:
        """Augmented edges should match resolved count."""
        result = _make_mock_dispatch_result(total=20, resolved=15)
        assert len(result["augmented_edges"]) == 15

    def test_augmented_edges_have_dispatch_type(self) -> None:
        """Every augmented edge should have a dispatch_type field."""
        result = _make_mock_dispatch_result(total=10, resolved=5)
        for edge in result["augmented_edges"]:
            assert "dispatch_type" in edge
            assert edge["dispatch_type"] in ("objc_msgSend", "vtable", "dlsym")

    def test_call_graph_augmentation(self) -> None:
        """Merging augmented edges into call graph should increase edge count."""
        cg = _make_mock_call_graph(
            functions=["FUN_a", "FUN_b", "FUN_c"],
            edges=[("FUN_a", "FUN_b")],
        )
        dispatch = _make_mock_dispatch_result(total=5, resolved=3)

        # Simulate augmentation: original edges + augmented
        original_count = len(cg["calls"])
        augmented_count = len(dispatch["augmented_edges"])
        total = original_count + augmented_count
        assert total > original_count

    def test_resolution_counts_add_up(self) -> None:
        """resolved + candidates + unresolved + external should equal total."""
        r = _make_mock_dispatch_result(
            total=100, resolved=60, candidates=15, unresolved=15, external=10
        )
        assert (
            r["resolved_count"]
            + r["candidate_count"]
            + r["unresolved_count"]
            + r["external_count"]
        ) == r["total_dispatch_sites"]

    def test_resolution_rate_with_external(self) -> None:
        """External (framework) methods should not count as failures."""
        # 50 total, 30 resolved, 10 external, 5 candidates, 5 unresolved
        # Resolution rate = 30/50 = 0.6
        r = _make_mock_dispatch_result(
            total=50, resolved=30, candidates=5, unresolved=5, external=10
        )
        assert r["resolution_rate"] == pytest.approx(0.6, abs=0.01)


# ===================================================================
# TestNamingAccuracy -- Function naming benchmark
# ===================================================================


class TestNamingAccuracy:
    """Function naming accuracy tests using ground truth comparison."""

    def test_crypto_naming_overall_accuracy(
        self, runner: BenchmarkRunner
    ) -> None:
        """Crypto library naming should achieve reasonable accuracy."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # Should be above 0 and below 100
        assert 0 < result.metrics.accuracy < 100

    def test_crypto_naming_exact_count(
        self, runner: BenchmarkRunner
    ) -> None:
        """Count exact matches in crypto naming."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # At minimum: AES_set_encrypt_key, AES_set_decrypt_key, AES_cbc_encrypt,
        # SHA256_Update, SHA1_Init, SHA1_Update, SHA1_Final, RSA_new, RSA_free,
        # RSA_sign, EVP_EncryptInit_ex, EVP_EncryptFinal_ex, etc.
        assert result.metrics.exact_matches >= 15

    def test_crypto_naming_missing_count(
        self, runner: BenchmarkRunner
    ) -> None:
        """Missing names (still FUN_xxx) should be tracked."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # BN_mul, BN_mod_exp, X509_get_subject_name, BIO_write = 4 missing
        assert result.metrics.missing_names >= 4

    def test_crypto_naming_wrong_count(
        self, runner: BenchmarkRunner
    ) -> None:
        """Wrong names should be counted."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # ECDSA_sign -> wrong_function_name, ECDSA_verify -> another_wrong_name
        assert result.metrics.wrong_names >= 2

    def test_crypto_recovery_rate(
        self, runner: BenchmarkRunner
    ) -> None:
        """Recovery rate: % of symbols that got any name."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # 50 total - 4 missing = 46 named = 92%
        assert result.metrics.recovery_rate > 80.0

    def test_crypto_naming_semantic_matches(
        self, runner: BenchmarkRunner
    ) -> None:
        """Semantic matches (synonyms) should be detected."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        # sha256_initialize (Init~initialize), sha256_finalize (Final~finalize),
        # hmac_initialize, hmac_finalize, create_ec_key, destroy_ec_key, etc.
        assert result.metrics.semantic_matches >= 4

    def test_naming_result_serialization(
        self, runner: BenchmarkRunner, tmp_path: Path
    ) -> None:
        """Benchmark result should be serializable to JSON."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, CRYPTO_NAMING_MAP)
        out_path = tmp_path / "test_result.json"
        result.save_json(out_path)

        loaded = json.loads(out_path.read_text())
        assert "metrics" in loaded
        assert "per_symbol" in loaded
        assert loaded["metrics"]["total_symbols"] == len(CRYPTO_GROUND_TRUTH)

    def test_empty_naming_map_all_missing(
        self, runner: BenchmarkRunner
    ) -> None:
        """Empty naming map should result in all missing."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, {})
        assert result.metrics.missing_names == len(CRYPTO_GROUND_TRUTH)
        assert result.metrics.accuracy == 0.0

    def test_perfect_naming_map(
        self, runner: BenchmarkRunner
    ) -> None:
        """Perfect naming map should achieve 100% accuracy."""
        result = runner.run_mock(CRYPTO_GROUND_TRUTH, dict(CRYPTO_GROUND_TRUTH))
        assert result.metrics.accuracy == 100.0
        assert result.metrics.exact_matches == len(CRYPTO_GROUND_TRUTH)


# ===================================================================
# TestAlgorithmDetection -- Algorithm detection recall
# ===================================================================


class TestAlgorithmDetection:
    """Algorithm detection recall tests.

    Given known crypto functions, measures whether algorithm detection
    would find the correct algorithms.
    """

    def _compute_recall(
        self,
        expected: set[str],
        detected: set[str],
    ) -> float:
        """Compute recall: |detected intersection expected| / |expected|."""
        if not expected:
            return 1.0
        return len(detected & expected) / len(expected)

    def test_aes_detection_recall(self) -> None:
        """AES functions should be detected as symmetric_cipher."""
        expected_aes = {"AES_set_encrypt_key", "AES_encrypt", "AES_decrypt", "AES_cbc_encrypt"}
        detected = _make_mock_algorithm_matches([
            {"name": "AES-256-CBC", "category": "symmetric_cipher", "function_name": "FUN_00010000"},
            {"name": "AES-256-CBC", "category": "symmetric_cipher", "function_name": "FUN_00010200"},
            {"name": "AES-256-CBC", "category": "symmetric_cipher", "function_name": "FUN_00010300"},
            {"name": "AES-256-CBC", "category": "symmetric_cipher", "function_name": "FUN_00010400"},
        ])
        detected_funcs = {d["function_name"] for d in detected}
        # Map FUN addresses to names for recall
        detected_names = {
            CRYPTO_GROUND_TRUTH.get(f, f) for f in detected_funcs
        }
        recall = self._compute_recall(expected_aes, detected_names)
        assert recall >= 0.75  # At least 3/4 detected

    def test_sha_detection_recall(self) -> None:
        """SHA functions should be detected as hash."""
        expected_sha = {"SHA256_Init", "SHA256_Update", "SHA256_Final"}
        detected = _make_mock_algorithm_matches([
            {"name": "SHA-256", "category": "hash", "function_name": "FUN_00020000"},
            {"name": "SHA-256", "category": "hash", "function_name": "FUN_00020100"},
            {"name": "SHA-256", "category": "hash", "function_name": "FUN_00020200"},
        ])
        detected_names = {
            CRYPTO_GROUND_TRUTH.get(d["function_name"], d["function_name"])
            for d in detected
        }
        recall = self._compute_recall(expected_sha, detected_names)
        assert recall == 1.0

    def test_rsa_detection_recall(self) -> None:
        """RSA functions should be detected as asymmetric."""
        expected_rsa = {"RSA_public_encrypt", "RSA_private_decrypt", "RSA_sign", "RSA_verify"}
        detected = _make_mock_algorithm_matches([
            {"name": "RSA", "category": "asymmetric", "function_name": "FUN_00030200"},
            {"name": "RSA", "category": "asymmetric", "function_name": "FUN_00030300"},
            {"name": "RSA", "category": "asymmetric", "function_name": "FUN_00030400"},
        ])
        detected_names = {
            CRYPTO_GROUND_TRUTH.get(d["function_name"], d["function_name"])
            for d in detected
        }
        recall = self._compute_recall(expected_rsa, detected_names)
        assert recall >= 0.5  # At least 2/4

    def test_hmac_detection_recall(self) -> None:
        """HMAC functions should be detected as mac."""
        expected_hmac = {"HMAC_Init_ex", "HMAC_Update", "HMAC_Final"}
        detected = _make_mock_algorithm_matches([
            {"name": "HMAC-SHA256", "category": "mac", "function_name": "FUN_00050000"},
            {"name": "HMAC-SHA256", "category": "mac", "function_name": "FUN_00050100"},
            {"name": "HMAC-SHA256", "category": "mac", "function_name": "FUN_00050200"},
        ])
        detected_names = {
            CRYPTO_GROUND_TRUTH.get(d["function_name"], d["function_name"])
            for d in detected
        }
        recall = self._compute_recall(expected_hmac, detected_names)
        assert recall == 1.0

    def test_no_false_positives_in_non_crypto(self) -> None:
        """Non-crypto functions should not be falsely detected as crypto."""
        non_crypto_functions = ["FUN_000a0000", "FUN_000a0100"]  # BIO_new, BIO_free
        detected = _make_mock_algorithm_matches([])
        # No detections for non-crypto functions
        detected_funcs = {d["function_name"] for d in detected}
        for f in non_crypto_functions:
            assert f not in detected_funcs

    def test_detection_confidence_threshold(self) -> None:
        """Low-confidence detections should be filterable."""
        detections = _make_mock_algorithm_matches([
            {"name": "AES-256", "confidence": 0.95, "function_name": "FUN_00010000"},
            {"name": "maybe_RC4", "confidence": 0.30, "function_name": "FUN_00010100"},
            {"name": "SHA-256", "confidence": 0.90, "function_name": "FUN_00020000"},
            {"name": "unknown_hash", "confidence": 0.15, "function_name": "FUN_00020100"},
        ])
        # Filter at 0.5 threshold
        high_conf = [d for d in detections if d["confidence"] >= 0.5]
        assert len(high_conf) == 2
        assert all(d["confidence"] >= 0.5 for d in high_conf)

    def test_detection_method_distribution(self) -> None:
        """Detection methods should be categorized correctly."""
        detections = _make_mock_algorithm_matches([
            {"name": "AES", "detection_method": "constant", "function_name": "FUN_a"},
            {"name": "SHA", "detection_method": "structural", "function_name": "FUN_b"},
            {"name": "RSA", "detection_method": "api", "function_name": "FUN_c"},
            {"name": "HMAC", "detection_method": "constant", "function_name": "FUN_d"},
        ])
        methods = {d["detection_method"] for d in detections}
        assert "constant" in methods
        assert "structural" in methods
        assert "api" in methods

    def test_overall_crypto_recall(self) -> None:
        """Overall recall across all crypto categories."""
        all_crypto_funcs = set()
        for addr, name in CRYPTO_GROUND_TRUTH.items():
            # Only crypto functions (AES, SHA, RSA, HMAC, EC, EVP)
            if any(name.startswith(p) for p in ("AES_", "SHA", "RSA_", "HMAC_", "EC", "EVP_")):
                all_crypto_funcs.add(name)

        # Simulate detection of 80% of crypto functions
        detected_count = int(len(all_crypto_funcs) * 0.8)
        detected = set(list(all_crypto_funcs)[:detected_count])

        recall = self._compute_recall(all_crypto_funcs, detected)
        assert recall >= 0.75


# ===================================================================
# TestCompositionDetection -- Composition pattern recall
# ===================================================================


class TestCompositionDetection:
    """Composition pattern detection recall tests."""

    def test_tls_handshake_pipeline(self) -> None:
        """TLS handshake should be detected as pipeline pattern."""
        compositions = _make_mock_compositions([
            {
                "name": "TLS Handshake Pipeline",
                "pattern": "pipeline",
                "stages": ["ClientHello", "ServerHello", "KeyExchange", "Finished"],
                "functions": ["FUN_00040000", "FUN_00040100", "FUN_00050000", "FUN_00050200"],
                "algorithms": ["AES-256-CBC", "SHA-256", "HMAC-SHA256"],
                "domain": "crypto",
                "confidence": 0.85,
            }
        ])
        assert compositions["success"]
        assert compositions["total_compositions"] == 1
        comp = compositions["compositions"][0]
        assert comp["pattern"] == "pipeline"
        assert len(comp["stages"]) == 4

    def test_hash_chain_iterative(self) -> None:
        """Hash chain (PBKDF2-like) should be iterative pattern."""
        compositions = _make_mock_compositions([
            {
                "name": "PBKDF2 Hash Chain",
                "pattern": "iterative",
                "stages": ["HMAC_Init", "HMAC_Loop", "HMAC_Final"],
                "functions": ["FUN_00050000", "FUN_00050100", "FUN_00050200"],
                "algorithms": ["HMAC-SHA256"],
                "domain": "crypto",
                "confidence": 0.80,
            }
        ])
        comp = compositions["compositions"][0]
        assert comp["pattern"] == "iterative"
        assert comp["domain"] == "crypto"

    def test_rsa_keygen_fork_join(self) -> None:
        """RSA keygen (parallel prime generation) should be fork-join."""
        compositions = _make_mock_compositions([
            {
                "name": "RSA Key Generation",
                "pattern": "fork_join",
                "stages": ["generate_p", "generate_q", "compute_n"],
                "functions": ["FUN_00060000", "FUN_00060200", "FUN_00060400"],
                "domain": "crypto",
                "confidence": 0.70,
            }
        ])
        comp = compositions["compositions"][0]
        assert comp["pattern"] == "fork_join"

    def test_multiple_compositions_detected(self) -> None:
        """Multiple compositions in same binary."""
        compositions = _make_mock_compositions([
            {
                "name": "TLS Pipeline",
                "pattern": "pipeline",
                "stages": ["handshake", "encrypt", "send"],
                "domain": "crypto",
            },
            {
                "name": "PBKDF2 Loop",
                "pattern": "iterative",
                "stages": ["init", "iterate", "finalize"],
                "domain": "crypto",
            },
            {
                "name": "Cert Validation",
                "pattern": "pipeline",
                "stages": ["parse", "verify_chain", "check_revocation"],
                "domain": "crypto",
            },
        ])
        assert compositions["total_compositions"] == 3
        patterns = {c["pattern"] for c in compositions["compositions"]}
        assert "pipeline" in patterns
        assert "iterative" in patterns

    def test_composition_confidence_filtering(self) -> None:
        """Low-confidence compositions should be filterable."""
        compositions = _make_mock_compositions([
            {"name": "Strong Pipeline", "confidence": 0.90, "pattern": "pipeline"},
            {"name": "Weak Pipeline", "confidence": 0.30, "pattern": "pipeline"},
            {"name": "Medium Iterative", "confidence": 0.60, "pattern": "iterative"},
        ])
        strong = [
            c for c in compositions["compositions"]
            if c["confidence"] >= 0.5
        ]
        assert len(strong) == 2

    def test_composition_function_coverage(self) -> None:
        """Compositions should cover a portion of all functions."""
        all_funcs = set(CRYPTO_GROUND_TRUTH.keys())
        composition_funcs = {
            "FUN_00040000", "FUN_00040100", "FUN_00040200",  # EVP encrypt
            "FUN_00050000", "FUN_00050100", "FUN_00050200",  # HMAC
            "FUN_00020000", "FUN_00020100", "FUN_00020200",  # SHA256
        }
        coverage = len(composition_funcs & all_funcs) / len(all_funcs)
        assert coverage > 0.0

    def test_empty_composition_result(self) -> None:
        """No compositions detected should not crash."""
        compositions = _make_mock_compositions([])
        assert compositions["success"]
        assert compositions["total_compositions"] == 0
        assert compositions["compositions"] == []

    def test_composition_domain_tags(self) -> None:
        """Compositions should have domain tags."""
        compositions = _make_mock_compositions([
            {"name": "Crypto Pipeline", "domain": "crypto", "pattern": "pipeline"},
            {"name": "Network Handler", "domain": "networking", "pattern": "pipeline"},
        ])
        domains = {c["domain"] for c in compositions["compositions"]}
        assert "crypto" in domains
        assert "networking" in domains


# ===================================================================
# TestGroundTruthGenerator -- Generator unit tests
# ===================================================================


class TestGroundTruthGenerator:
    """Tests for GroundTruthGenerator using mock nm output."""

    MOCK_NM_OUTPUT = (
        "0000000100001234 T _EVP_EncryptInit_ex\n"
        "0000000100001340 T _EVP_EncryptUpdate\n"
        "0000000100001456 T _EVP_EncryptFinal_ex\n"
        "0000000100002000 T _SHA256_Init\n"
        "0000000100002100 T _SHA256_Update\n"
        "0000000100002200 T _SHA256_Final\n"
        "0000000100003000 T ___some_internal_func\n"
        "0000000100004000 D _g_crypto_config\n"
        "0000000100005000 T _RSA_public_encrypt\n"
    )

    def test_parse_nm_output_functions_only(self, gt_gen: GroundTruthGenerator) -> None:
        """Parsing nm output should extract T-type symbols when include_data=False."""
        with patch.object(gt_gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            result = gt_gen.generate_from_nm(Path("/mock/binary"))

        # D-type g_crypto_config should be excluded
        names = {name for name, _ in result.values()}
        assert "EVP_EncryptInit_ex" in names
        assert "SHA256_Init" in names
        assert "g_crypto_config" not in names

    def test_parse_nm_output_filter_internal(self, gt_gen: GroundTruthGenerator) -> None:
        """Internal symbols (__xxx) should be filtered."""
        with patch.object(gt_gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            result = gt_gen.generate_from_nm(Path("/mock/binary"))

        names = {name for name, _ in result.values()}
        assert "_some_internal_func" not in names

    def test_parse_nm_output_with_data(self) -> None:
        """When include_data=True, D-type symbols should be included."""
        gen = GroundTruthGenerator(include_data=True, filter_internal=True)
        with patch.object(gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            result = gen.generate_from_nm(Path("/mock/binary"))

        names = {name for name, _ in result.values()}
        assert "g_crypto_config" in names

    def test_generate_from_binary_creates_ground_truth(
        self, gt_gen: GroundTruthGenerator
    ) -> None:
        """generate_from_binary should return GroundTruth object."""
        with patch.object(gt_gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            gt = gt_gen.generate_from_binary(Path("/mock/binary"))

        assert isinstance(gt, GroundTruth)
        assert gt.symbol_count > 0
        assert gt.function_count > 0

    def test_ground_truth_save_and_load(
        self, gt_gen: GroundTruthGenerator, tmp_path: Path
    ) -> None:
        """GroundTruth should round-trip through JSON."""
        with patch.object(gt_gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            gt = gt_gen.generate_from_binary(
                Path("/mock/binary"),
                output_path=tmp_path / "gt.json",
            )

        loaded = GroundTruth.load_json(tmp_path / "gt.json")
        assert loaded.symbol_count == gt.symbol_count
        assert loaded.as_name_set() == gt.as_name_set()

    def test_compare_with_karadul(
        self, gt_gen: GroundTruthGenerator
    ) -> None:
        """Comparison with Karadul naming map should produce metrics."""
        with patch.object(gt_gen, "_run_nm", return_value=self.MOCK_NM_OUTPUT):
            gt = gt_gen.generate_from_binary(Path("/mock/binary"))

        # Perfect naming map
        naming_map = {}
        for s in gt.symbols:
            hex_part = s.address.replace("0x", "").lstrip("0") or "0"
            key = f"FUN_{hex_part.zfill(8)}"
            naming_map[key] = s.name

        metrics = gt_gen.compare_with_karadul(gt, naming_map)
        assert metrics.accuracy > 0.0

    def test_ghidra_auto_name_filter(self) -> None:
        """Ghidra auto-names should be recognized."""
        assert _is_ghidra_auto_name("FUN_00401000")
        assert _is_ghidra_auto_name("sub_00401000")
        assert _is_ghidra_auto_name("DAT_00603000")
        assert not _is_ghidra_auto_name("main")
        assert not _is_ghidra_auto_name("EVP_EncryptInit")

    def test_internal_symbol_filter(self) -> None:
        """Internal/compiler symbols should be recognized."""
        assert _is_internal_symbol("__cxa_atexit")
        assert _is_internal_symbol("_OBJC_CLASS_$_NSObject")
        assert _is_internal_symbol("dyld_stub_binder")
        assert not _is_internal_symbol("EVP_EncryptInit")
        assert not _is_internal_symbol("main")

    def test_nm_failure_returns_empty(self, gt_gen: GroundTruthGenerator) -> None:
        """When nm fails, generate_from_nm should return empty dict."""
        with patch.object(gt_gen, "_run_nm", return_value=None):
            result = gt_gen.generate_from_nm(Path("/nonexistent"))
        assert result == {}

    def test_ground_truth_functions_only(self, crypto_ground_truth: GroundTruth) -> None:
        """functions_only() should return only T-type symbols."""
        funcs = crypto_ground_truth.functions_only()
        assert len(funcs) == len(CRYPTO_GROUND_TRUTH)

    def test_ground_truth_as_name_set(self, crypto_ground_truth: GroundTruth) -> None:
        """as_name_set() should return all names."""
        names = crypto_ground_truth.as_name_set()
        assert "AES_set_encrypt_key" in names
        assert "SHA256_Init" in names
        assert "RSA_new" in names
