"""Binary Intelligence modulu testleri.

BinaryIntelligence'in string clustering, subsystem tespiti,
algoritma tespiti, guvenlik mekanizmasi tespiti ve
uygulama tipi cikarimi isleflerini test eder.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from karadul.analyzers.binary_intelligence import (
    BinaryIntelligence,
    IntelligenceReport,
    ArchitectureMap,
    Subsystem,
    Algorithm,
    SecurityMechanism,
    Protocol,
    FunctionAnalysis,
    STRING_PATTERNS,
    ALGORITHM_PATTERNS,
    SECURITY_PATTERNS,
    PROTOCOL_PATTERNS,
)
from karadul.config import Config


@pytest.fixture
def config() -> Config:
    """Varsayilan config."""
    return Config()


@pytest.fixture
def intelligence(config: Config) -> BinaryIntelligence:
    """BinaryIntelligence instance."""
    return BinaryIntelligence(config)


# ---------------------------------------------------------------------------
# Pattern coverage
# ---------------------------------------------------------------------------

class TestPatternCoverage:
    """Pattern sayisinin yeterliligi."""

    def test_total_patterns_above_500(self) -> None:
        """Toplam pattern sayisi 500'den fazla olmali."""
        total = 0
        for group in STRING_PATTERNS.values():
            total += len(group["patterns"])
        total += len(ALGORITHM_PATTERNS)
        total += len(SECURITY_PATTERNS)
        total += len(PROTOCOL_PATTERNS)
        assert total > 500, f"Toplam pattern sayisi 500'den az: {total}"

    def test_all_groups_have_required_fields(self) -> None:
        """Her pattern grubu zorunlu alanlara sahip olmali."""
        for name, group in STRING_PATTERNS.items():
            assert "patterns" in group, f"{name}: patterns eksik"
            assert "subsystem" in group, f"{name}: subsystem eksik"
            assert "description" in group, f"{name}: description eksik"
            assert "category" in group, f"{name}: category eksik"
            assert len(group["patterns"]) > 0, f"{name}: bos pattern listesi"


# ---------------------------------------------------------------------------
# String clustering
# ---------------------------------------------------------------------------

class TestStringClustering:
    """String clustering testleri."""

    def test_empty_strings(self, intelligence: BinaryIntelligence) -> None:
        """Bos string listesiyle cakma yapilmamali."""
        clusters = intelligence._cluster_strings([])
        assert clusters == {}

    def test_short_strings_ignored(self, intelligence: BinaryIntelligence) -> None:
        """3 karakterden kisa string'ler atlanmali."""
        clusters = intelligence._cluster_strings(["ab", "x", ""])
        assert clusters == {}

    def test_antivirus_strings_detected(self, intelligence: BinaryIntelligence) -> None:
        """Antivirus string'leri scanning grubunda cikamali."""
        strings = [
            "com.avast.scanning.engine",
            "virus_detected",
            "quarantine_file",
            "MalwareSignature",
            "heuristic_analysis",
        ]
        clusters = intelligence._cluster_strings(strings)
        assert "scanning" in clusters
        assert len(clusters["scanning"]) >= 3

    def test_crypto_strings_detected(self, intelligence: BinaryIntelligence) -> None:
        """Kriptografi string'leri tespit edilmeli."""
        strings = [
            "SHA256_Init",
            "AES_encrypt",
            "RSA_public_key",
            "HMAC_SHA256",
        ]
        clusters = intelligence._cluster_strings(strings)
        assert "hashing" in clusters or "encryption" in clusters

    def test_case_insensitive(self, intelligence: BinaryIntelligence) -> None:
        """Pattern esleme case-insensitive olmali."""
        clusters_lower = intelligence._cluster_strings(["sqlite_open"])
        clusters_upper = intelligence._cluster_strings(["SQLITE_OPEN"])
        # Ikisi de database grubunda cikamali
        assert "database" in clusters_lower
        assert "database" in clusters_upper

    def test_evidence_limit(self, intelligence: BinaryIntelligence) -> None:
        """Evidence sayisi 50 ile sinirli olmali."""
        strings = [f"virus_variant_{i}" for i in range(100)]
        clusters = intelligence._cluster_strings(strings)
        assert "scanning" in clusters
        assert len(clusters["scanning"]) <= 50


# ---------------------------------------------------------------------------
# Subsystem detection
# ---------------------------------------------------------------------------

class TestSubsystemDetection:
    """Alt sistem tespit testleri."""

    def test_antivirus_subsystems(self, intelligence: BinaryIntelligence) -> None:
        """Antivirus string'lerinden scanning subsystem tespiti."""
        strings = [
            "AvastScanEngine", "virus_definitions", "quarantine_path",
            "scan_file", "real_time_shield", "malware_detected",
            "signature_update", "heuristic_result", "trojan_generic",
            "worm_detected",
        ]
        report = intelligence.analyze(strings, [], [], "Avast")
        subsystem_names = [s.name for s in report.architecture.subsystems]
        assert "Scanning Engine" in subsystem_names

    def test_terminal_subsystems(self, intelligence: BinaryIntelligence) -> None:
        """Terminal emulator string'lerinden tespit."""
        strings = [
            "pseudo_terminal", "pty_open", "vt100_escape",
            "cursor_position", "terminal_size", "xterm_256color",
            "shell_command", "bash_history", "ansi_color",
        ]
        report = intelligence.analyze(strings, [], [], "Terminal")
        subsystem_names = [s.name for s in report.architecture.subsystems]
        assert "Terminal Emulator" in subsystem_names

    def test_confidence_decreases_with_few_matches(self, intelligence: BinaryIntelligence) -> None:
        """Az esleme = dusuk confidence."""
        few = ["virus_scan"]
        many = ["virus_scan", "malware_detected", "quarantine_file",
                "heuristic_analysis", "signature_db", "trojan_generic"]

        report_few = intelligence.analyze(few, [], [], "test")
        report_many = intelligence.analyze(many, [], [], "test")

        if report_few.architecture.subsystems and report_many.architecture.subsystems:
            # "Scanning Engine" her ikisinde de varsa, many daha yuksek conf olmali
            few_conf = next(
                (s.confidence for s in report_few.architecture.subsystems
                 if s.name == "Scanning Engine"), 0)
            many_conf = next(
                (s.confidence for s in report_many.architecture.subsystems
                 if s.name == "Scanning Engine"), 0)
            assert many_conf >= few_conf


# ---------------------------------------------------------------------------
# Algorithm detection
# ---------------------------------------------------------------------------

class TestAlgorithmDetection:
    """Algoritma tespit testleri."""

    def test_sha256_detected(self, intelligence: BinaryIntelligence) -> None:
        """SHA-256 tespiti."""
        strings = ["CC_SHA256_Init", "sha256_digest", "SHA256_Final"]
        report = intelligence.analyze(strings, [], [], "test")
        algo_names = [a.name for a in report.architecture.algorithms]
        assert "SHA-256" in algo_names

    def test_aes_detected(self, intelligence: BinaryIntelligence) -> None:
        """AES tespiti."""
        strings = ["AES_encrypt", "kCCAlgorithmAES128", "aes_key"]
        report = intelligence.analyze(strings, [], [], "test")
        algo_names = [a.name for a in report.architecture.algorithms]
        assert "AES" in algo_names

    def test_algorithm_evidence_present(self, intelligence: BinaryIntelligence) -> None:
        """Tespit edilen algoritmalarin evidence'i olmali."""
        strings = ["sha256_hash_compute"]
        report = intelligence.analyze(strings, [], [], "test")
        sha = next(
            (a for a in report.architecture.algorithms if a.name == "SHA-256"), None
        )
        if sha:
            assert len(sha.evidence) > 0


# ---------------------------------------------------------------------------
# Security mechanism detection
# ---------------------------------------------------------------------------

class TestSecurityDetection:
    """Guvenlik mekanizmasi tespit testleri."""

    def test_endpoint_security_detected(self, intelligence: BinaryIntelligence) -> None:
        """Endpoint Security API tespiti."""
        strings = ["es_new_client", "endpoint_security_framework", "es_event_type_auth"]
        report = intelligence.analyze(strings, [], [], "test")
        sec_names = [s.name for s in report.architecture.security]
        assert "Endpoint Security API" in sec_names

    def test_code_signing_detected(self, intelligence: BinaryIntelligence) -> None:
        """Code signing tespiti."""
        strings = ["codesign", "SecStaticCodeRef", "csreq_matches"]
        report = intelligence.analyze(strings, [], [], "test")
        sec_names = [s.name for s in report.architecture.security]
        assert "Code Signing" in sec_names

    def test_kernel_level_flagged(self, intelligence: BinaryIntelligence) -> None:
        """Kernel seviyesi mekanizmalar 'kernel' risk level almali."""
        strings = ["es_new_client", "endpoint_security_t"]
        report = intelligence.analyze(strings, [], [], "test")
        es = next(
            (s for s in report.architecture.security
             if s.name == "Endpoint Security API"), None
        )
        if es:
            assert es.risk_level == "kernel"


# ---------------------------------------------------------------------------
# Protocol detection
# ---------------------------------------------------------------------------

class TestProtocolDetection:
    """Protokol tespit testleri."""

    def test_https_detected(self, intelligence: BinaryIntelligence) -> None:
        """HTTPS tespiti."""
        strings = ["https://api.example.com", "NSURLSession"]
        report = intelligence.analyze(strings, [], [], "test")
        proto_names = [p.name for p in report.architecture.protocols]
        assert "HTTPS" in proto_names

    def test_xpc_detected(self, intelligence: BinaryIntelligence) -> None:
        """XPC tespiti."""
        strings = ["NSXPCConnection", "xpc_connection_create"]
        report = intelligence.analyze(strings, [], [], "test")
        proto_names = [p.name for p in report.architecture.protocols]
        assert "XPC" in proto_names

    def test_grpc_detected(self, intelligence: BinaryIntelligence) -> None:
        """gRPC tespiti."""
        strings = ["grpc_init", "protobuf_message"]
        report = intelligence.analyze(strings, [], [], "test")
        proto_names = [p.name for p in report.architecture.protocols]
        assert "gRPC" in proto_names


# ---------------------------------------------------------------------------
# App type inference
# ---------------------------------------------------------------------------

class TestAppTypeInference:
    """Uygulama tipi cikarim testleri."""

    def test_antivirus_detected(self, intelligence: BinaryIntelligence) -> None:
        """Antivirus uygulamasi tespiti."""
        # Scanning Engine icin en az 10+ antivirus-spesifik string
        strings = [
            "antivirus_engine", "virus_definitions_update", "quarantine_path",
            "malware_detected", "trojan_generic_found", "worm_propagation",
            "ransomware_block", "spyware_scan_result", "rootkit_detector",
            "heuristic_analysis_complete", "yara_rule_match", "scan_engine_init",
            "real_time_shield", "file_shield_active", "behavior_shield_monitor",
            "endpoint_security_framework", "system_extension_active",
            "web_shield_proxy", "url_filter_block", "firewall_rule_engine",
            "signature_update_check", "definition_update_download",
        ]
        report = intelligence.analyze(strings, [], [], "Avast")
        assert report.architecture.app_type == "antivirus"

    def test_terminal_detected(self, intelligence: BinaryIntelligence) -> None:
        """Terminal uygulamasi tespiti."""
        # Terminal Emulator icin yeterli sayida spesifik string
        strings = [
            "pseudo_terminal_open", "pty_master_fd", "vt100_escape_code",
            "xterm_256color_mode", "cursor_position_report", "ansi_escape",
            "terminal_size_changed", "tty_device", "tcgetattr_call",
            "tcsetattr_mode", "forkpty_spawn", "openpty_result",
            "shell_integration_hook", "command_palette_open",
            "bash_completion_data", "tab_completion_popup",
            "fuzzy_find_match", "history_search",
        ]
        report = intelligence.analyze(strings, [], [], "Warp")
        assert report.architecture.app_type == "terminal"

    def test_generic_for_unknown(self, intelligence: BinaryIntelligence) -> None:
        """Bilinmeyen tip icin 'generic' donmeli."""
        strings = ["hello", "world", "test_string"]
        report = intelligence.analyze(strings, [], [], "Unknown")
        assert report.architecture.app_type == "generic"


# ---------------------------------------------------------------------------
# Full analyze
# ---------------------------------------------------------------------------

class TestFullAnalyze:
    """Tam analiz testi."""

    def test_report_structure(self, intelligence: BinaryIntelligence) -> None:
        """Rapor dogru yapida olmali."""
        strings = ["SHA256_Init", "virus_scan", "https://api.com"]
        report = intelligence.analyze(strings, ["_main"], ["/usr/lib/libSystem.B.dylib"], "test")

        assert isinstance(report, IntelligenceReport)
        assert isinstance(report.architecture, ArchitectureMap)
        assert report.total_strings_analyzed == 3
        assert report.total_symbols_analyzed == 1
        assert report.total_dylibs_analyzed == 1

    def test_report_serializable(self, intelligence: BinaryIntelligence) -> None:
        """Rapor JSON'a donusturulebilmeli."""
        strings = ["SHA256_Init", "virus_scan", "sqlite_open"]
        report = intelligence.analyze(strings, [], [], "test")

        # to_dict calismali
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "architecture" in d

        # JSON serializasyonu calismali
        json_str = json.dumps(d, indent=2, ensure_ascii=True)
        assert len(json_str) > 100

        # Geri parse edilebilmeli
        parsed = json.loads(json_str)
        assert parsed["architecture"]["app_name"] == "test"

    def test_symbols_merged_with_strings(self, intelligence: BinaryIntelligence) -> None:
        """Symbol'ler de string havuzuna eklenmeli."""
        # Sadece symbol'lerde olan bir pattern
        report = intelligence.analyze(
            strings=[],
            symbols=["_SHA256_Init", "_AES_encrypt"],
            dylibs=[],
            target_name="test",
        )
        algo_names = [a.name for a in report.architecture.algorithms]
        assert "SHA-256" in algo_names or "AES" in algo_names

    def test_summary_generated(self, intelligence: BinaryIntelligence) -> None:
        """Mimari ozet bos olmamali."""
        strings = ["virus_scan", "SHA256_Init", "https://api.com"]
        report = intelligence.analyze(strings, [], [], "TestApp")
        assert report.architecture.architecture_summary
        assert "TestApp" in report.architecture.architecture_summary


# ---------------------------------------------------------------------------
# Ghidra decompiled analysis
# ---------------------------------------------------------------------------

class TestDecompiledAnalysis:
    """Ghidra decompile ciktisi analiz testleri."""

    def test_analyze_decompiled_empty_dir(self, intelligence: BinaryIntelligence) -> None:
        """Bos dizin icin bos liste donmeli."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = intelligence.analyze_decompiled(Path(tmpdir))
            assert results == []

    def test_analyze_decompiled_nonexistent(self, intelligence: BinaryIntelligence) -> None:
        """Varolmayan dizin icin bos liste donmeli."""
        results = intelligence.analyze_decompiled(Path("/nonexistent/dir"))
        assert results == []

    def test_analyze_decompiled_with_c_file(self, intelligence: BinaryIntelligence) -> None:
        """C dosyasindan fonksiyon analizi yapilmali."""
        with tempfile.TemporaryDirectory() as tmpdir:
            c_file = Path(tmpdir) / "encrypt_data.c"
            c_file.write_text(
                'void encrypt_data(char *buf, int len) {\n'
                '    AES_encrypt(buf, len);\n'
                '    memcpy(output, buf, len);\n'
                '    printf("encryption complete");\n'
                '}\n'
            )
            results = intelligence.analyze_decompiled(Path(tmpdir))
            assert len(results) == 1
            assert results[0].name == "encrypt_data"
            assert "AES" in results[0].algorithms
            assert "memcpy" in results[0].system_calls

    def test_vulnerability_detection(self, intelligence: BinaryIntelligence) -> None:
        """Guvenlik aciklari tespit edilmeli."""
        with tempfile.TemporaryDirectory() as tmpdir:
            c_file = Path(tmpdir) / "unsafe_func.c"
            c_file.write_text(
                'void unsafe(char *input) {\n'
                '    char buf[64];\n'
                '    strcpy(buf, input);\n'
                '    sprintf(msg, "hello %s", buf);\n'
                '    system("/bin/sh");\n'
                '}\n'
            )
            results = intelligence.analyze_decompiled(Path(tmpdir))
            assert len(results) == 1
            vuln_text = " ".join(results[0].vulnerabilities)
            assert "Buffer Overflow" in vuln_text
            assert "Format String" in vuln_text
            assert "Command Injection" in vuln_text


# ---------------------------------------------------------------------------
# Data class serialization
# ---------------------------------------------------------------------------

class TestDataclasses:
    """Dataclass to_dict testleri."""

    def test_subsystem_to_dict(self) -> None:
        s = Subsystem("Test", "desc", ["ev1"], 0.5, "core")
        d = s.to_dict()
        assert d["name"] == "Test"
        assert d["confidence"] == 0.5

    def test_algorithm_to_dict(self) -> None:
        a = Algorithm("AES", "encryption", ["ev1"], "block cipher")
        d = a.to_dict()
        assert d["name"] == "AES"
        assert d["category"] == "encryption"

    def test_architecture_map_to_dict(self) -> None:
        arch = ArchitectureMap(
            app_name="TestApp",
            app_type="generic",
            subsystems=[Subsystem("X", "desc", [], 0.5, "core")],
            algorithms=[Algorithm("AES", "enc", [], "cipher")],
        )
        d = arch.to_dict()
        assert d["app_name"] == "TestApp"
        assert len(d["subsystems"]) == 1
        assert len(d["algorithms"]) == 1
