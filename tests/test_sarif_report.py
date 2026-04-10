"""SARIF 2.1.0 reporter testleri.

SARIFReporter ciktisinin SARIF 2.1.0 standardina uygunlugunu,
kural tanimlarini, result uretimini ve pipeline entegrasyonunu test eder.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from karadul import __version__
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.reporting.sarif_report import SARIFReporter


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Test workspace olustur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_target")
    ws.create()
    return ws


@pytest.fixture
def pipeline_result(workspace: Workspace) -> PipelineResult:
    """Kripto algoritma ve YARA tespitleri iceren PipelineResult."""
    result = PipelineResult(
        target_name="malware_sample.exe",
        target_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        workspace_path=workspace.path,
    )

    # Identify stage
    result.add_stage_result(StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.1,
        stats={
            "target_type": "pe_executable",
            "language": "c_cpp",
            "file_size": 524288,
            "mime_type": "application/x-dosexec",
        },
    ))

    # Static stage -- kripto algoritma + yara tespitleri
    result.add_stage_result(StageResult(
        stage_name="static",
        success=True,
        duration_seconds=8.5,
        stats={
            "functions_found": 312,
            "strings_found": 4500,
            "imports_found": 87,
            "algorithms_detected": [
                {
                    "name": "AES-256 CBC",
                    "address": "0x00401000",
                    "confidence": 0.95,
                    "category": "symmetric_cipher",
                    "method": "constant_based",
                },
                {
                    "name": "SHA-256",
                    "address": "0x00402000",
                    "confidence": 0.88,
                    "category": "hash_function",
                    "method": "constant_based",
                },
            ],
            "yara_matches": [
                {
                    "rule": "UPX_packed",
                    "tags": ["packer", "upx"],
                    "description": "UPX packer signature",
                    "meta": {"author": "test"},
                },
                {
                    "rule": "anti_debug_check",
                    "tags": ["anti_debug"],
                    "description": "Anti-debug technique detected",
                    "meta": {},
                },
            ],
            "detected_tech": [
                {"name": "UPX 3.96", "type": "packer"},
            ],
        },
    ))

    # Deobfuscate stage
    result.add_stage_result(StageResult(
        stage_name="deobfuscate",
        success=True,
        duration_seconds=15.3,
        stats={
            "steps_completed": 2,
            "low_confidence_names": 14,
        },
    ))

    # Reconstruct stage
    result.add_stage_result(StageResult(
        stage_name="reconstruct",
        success=True,
        duration_seconds=22.0,
        stats={
            "modules_extracted": 5,
            "variables_renamed": 120,
            "coverage_percent": 25,
            "avg_naming_confidence": 0.35,
        },
    ))

    result.total_duration = 45.9
    return result


@pytest.fixture
def empty_pipeline_result(workspace: Workspace) -> PipelineResult:
    """Hicbir tespit icermeyen minimal PipelineResult."""
    result = PipelineResult(
        target_name="clean_binary.elf",
        target_hash="deadbeef" * 8,
        workspace_path=workspace.path,
    )
    result.add_stage_result(StageResult(
        stage_name="identify",
        success=True,
        duration_seconds=0.05,
        stats={"target_type": "elf_executable", "language": "c_cpp", "file_size": 10240},
    ))
    result.add_stage_result(StageResult(
        stage_name="static",
        success=True,
        duration_seconds=2.0,
        stats={"functions_found": 50, "strings_found": 200, "imports_found": 10},
    ))
    result.total_duration = 2.05
    return result


def _load_sarif(path: Path) -> dict[str, Any]:
    """SARIF dosyasini oku ve parse et."""
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------
# Test sinifi
# ------------------------------------------------------------------


class TestSARIFSchemaAndVersion:
    """SARIF ust-duzey yapi testleri."""

    def test_sarif_schema_version(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """$schema ve version alanlari SARIF 2.1.0 olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)

        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"
        assert data["version"] == "2.1.0"

    def test_sarif_valid_json(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Cikti gecerli JSON olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, dict)
        assert "runs" in data
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) == 1


class TestSARIFToolDriver:
    """tool.driver testleri."""

    def test_sarif_tool_driver(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """tool.driver name=Black Widow, version=__version__ olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        driver = data["runs"][0]["tool"]["driver"]

        assert driver["name"] == "Black Widow"
        assert driver["version"] == __version__
        assert driver["semanticVersion"] == __version__
        assert "informationUri" in driver


class TestSARIFRules:
    """Kural tanimi testleri."""

    def test_sarif_rules_defined(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """5 kural tanimlanmis olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        rules = data["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) == 5

    def test_sarif_rule_ids(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """KRDL001-005 ID'leri mevcut olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}

        expected = {"KRDL001", "KRDL002", "KRDL003", "KRDL004", "KRDL005"}
        assert rule_ids == expected

    def test_sarif_rules_have_descriptions(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Her kuralin shortDescription ve fullDescription'i olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        rules = data["runs"][0]["tool"]["driver"]["rules"]

        for rule in rules:
            assert "shortDescription" in rule
            assert "text" in rule["shortDescription"]
            assert "fullDescription" in rule
            assert "text" in rule["fullDescription"]
            assert "defaultConfiguration" in rule
            assert "level" in rule["defaultConfiguration"]


class TestSARIFResults:
    """SARIF result uretim testleri."""

    def test_sarif_results_from_algorithms(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Kripto algoritma tespitleri KRDL001 result'lari olusturmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        algo_results = [r for r in results if r["ruleId"] == "KRDL001"]
        assert len(algo_results) == 2

        # AES-256 result kontrolu
        aes_result = [r for r in algo_results if "AES-256" in r["message"]["text"]]
        assert len(aes_result) == 1
        assert aes_result[0]["level"] == "note"

    def test_sarif_results_from_yara(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """YARA eslesmeleri KRDL003/004 result'lari olusturmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        # UPX_packed -> KRDL004 (packer tag'i ile)
        packer_results = [r for r in results if r["ruleId"] == "KRDL004"]
        assert len(packer_results) >= 1

        # anti_debug_check -> KRDL003
        suspicious_results = [r for r in results if r["ruleId"] == "KRDL003"]
        assert len(suspicious_results) >= 1

    def test_sarif_results_level_mapping(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Result seviyesi kural tanimiyla uyumlu olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        level_map = {
            "KRDL001": "note",
            "KRDL002": "warning",
            "KRDL003": "warning",
            "KRDL004": "warning",
            "KRDL005": "note",
        }

        for r in results:
            expected_level = level_map.get(r["ruleId"])
            if expected_level:
                assert r["level"] == expected_level, (
                    f"{r['ruleId']} beklenen level={expected_level}, "
                    f"gercek level={r['level']}"
                )

    def test_sarif_empty_results(
        self, empty_pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Tespit yoksa results bos liste olmali."""
        path = SARIFReporter().generate(empty_pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        assert isinstance(results, list)
        assert len(results) == 0

    def test_sarif_properties_confidence(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Algoritma result'larinda confidence property'si olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        algo_results = [r for r in results if r["ruleId"] == "KRDL001"]
        for r in algo_results:
            assert "properties" in r
            assert "confidence" in r["properties"]
            assert isinstance(r["properties"]["confidence"], (int, float))
            assert 0.0 <= r["properties"]["confidence"] <= 1.0

    def test_sarif_naming_results(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Dusuk naming confidence KRDL002 result'i olusturmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        naming_results = [r for r in results if r["ruleId"] == "KRDL002"]
        # Reconstruct (avg_confidence=0.35 < 0.5) + deobfuscate (low_confidence_names=14)
        assert len(naming_results) >= 1


class TestSARIFArtifact:
    """Artifact (analiz edilen dosya) testleri."""

    def test_sarif_artifact_location(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Artifact location hedef dosya adini icermeli."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        artifacts = data["runs"][0]["artifacts"]

        assert len(artifacts) == 1
        assert artifacts[0]["location"]["uri"] == "malware_sample.exe"

    def test_sarif_artifact_hash(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Artifact SHA-256 hash icermeli."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        artifact = data["runs"][0]["artifacts"][0]

        assert "hashes" in artifact
        assert "sha-256" in artifact["hashes"]
        assert artifact["hashes"]["sha-256"] == pipeline_result.target_hash

    def test_sarif_artifact_size(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Identify stage varsa artifact dosya boyutu icermeli."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)
        artifact = data["runs"][0]["artifacts"][0]

        assert artifact["length"] == 524288


class TestSARIFOutputPath:
    """Dosya yolu testleri."""

    def test_sarif_output_path(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """SARIF dosyasi workspace/reports/ altinda olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)

        assert path.exists()
        assert path.name == "report.sarif.json"
        assert path.parent == workspace.get_stage_dir("reports")

    def test_generate_returns_path(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """generate() Path nesnesi donmeli."""
        result_path = SARIFReporter().generate(pipeline_result, workspace)

        assert isinstance(result_path, Path)
        assert result_path.is_file()


class TestSARIFWithRealPipelineResult:
    """Mock PipelineResult ile kapsamli entegrasyon testi."""

    def test_sarif_with_real_pipeline_result(
        self, pipeline_result: PipelineResult, workspace: Workspace
    ) -> None:
        """Tam PipelineResult ile SARIF rapor uretimi tutarli olmali."""
        path = SARIFReporter().generate(pipeline_result, workspace)
        data = _load_sarif(path)

        run = data["runs"][0]

        # Ust-duzey yapi kontrolu
        assert data["$schema"].endswith("sarif-2.1.0-rtm.5.json")
        assert data["version"] == "2.1.0"

        # Tool
        assert run["tool"]["driver"]["name"] == "Black Widow"
        assert len(run["tool"]["driver"]["rules"]) == 5

        # Results -- en az kripto(2) + yara(2) + detected_tech(1) + naming(2) = 7
        assert len(run["results"]) >= 7

        # Artifacts
        assert len(run["artifacts"]) == 1

        # Invocations
        assert len(run["invocations"]) == 1
        assert run["invocations"][0]["executionSuccessful"] is True

        # Properties
        assert run["properties"]["karadul_version"] == __version__
        assert run["properties"]["total_duration_seconds"] == 45.9


class TestSARIFStagesIntegration:
    """stages.py entegrasyon testi (import ve cagri)."""

    def test_stages_sarif_integration(self, workspace: Workspace) -> None:
        """SARIFReporter stages.py pattern'i ile cagrilabilmeli."""
        # stages.py'deki pattern'i simule et
        pipeline_result = PipelineResult(
            target_name="integration_test.bin",
            target_hash="0" * 64,
            workspace_path=workspace.path,
        )
        pipeline_result.add_stage_result(StageResult(
            stage_name="identify",
            success=True,
            duration_seconds=0.01,
            stats={"target_type": "elf_executable"},
        ))
        pipeline_result.total_duration = 0.01

        # stages.py'deki try/except pattern'ini takip et
        try:
            from karadul.reporting.sarif_report import SARIFReporter as _Reporter
            sarif_path = _Reporter().generate(pipeline_result, workspace)
        except ImportError:
            pytest.fail("SARIFReporter import edilemedi")
        except Exception as exc:
            pytest.fail(f"SARIFReporter.generate() hata verdi: {exc}")

        assert sarif_path.exists()
        assert sarif_path.name == "report.sarif.json"

        # Gecerli SARIF kontrolu
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "Black Widow"


class TestSARIFStringAlgorithms:
    """Algoritma listesi string olarak gelirse de calismalii."""

    def test_string_algorithms(self, workspace: Workspace) -> None:
        """algorithms_detected string listesi olarak gelince de calismalii."""
        result = PipelineResult(
            target_name="str_test.bin",
            target_hash="f" * 64,
            workspace_path=workspace.path,
        )
        result.add_stage_result(StageResult(
            stage_name="static",
            success=True,
            duration_seconds=1.0,
            stats={
                "algorithms_detected": ["AES", "RSA-2048"],
            },
        ))
        result.total_duration = 1.0

        path = SARIFReporter().generate(result, workspace)
        data = _load_sarif(path)
        results = data["runs"][0]["results"]

        algo_results = [r for r in results if r["ruleId"] == "KRDL001"]
        assert len(algo_results) == 2
