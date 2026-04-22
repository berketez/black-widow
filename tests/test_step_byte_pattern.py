"""v1.10.0 M1 T3.2 — BytePatternStep testleri.

stages.py L1361-1451'den tasindi. Test kapsamlari:
- enable_byte_pattern_matching=False icin bos donus
- BytePatternMatcher ImportError yakalanir
- Uretilen byte_pattern_names dict'i dogru formatta
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.byte_pattern import BytePatternStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(return_value=tmp_path / "x.json")
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_byte_pattern_matching = True
    pc.config.binary_reconstruction.min_naming_confidence = 0.6
    pc.config.binary_reconstruction.external_signature_paths = []
    pc.config.project_root = tmp_path
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "binary_for_byte_match": tmp_path / "bin",
        "functions_json_path": tmp_path / "functions.json",
    })
    return ctx


class TestByteRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("byte_pattern")
        assert "binary_for_byte_match" in spec.requires
        assert "byte_pattern_names" in spec.produces
        assert "byte_pattern_result" in spec.produces


class TestDisabled:
    def test_disabled_returns_empty(self, fake_pc, base_ctx) -> None:
        fake_pc.config.binary_reconstruction.enable_byte_pattern_matching = False
        out = BytePatternStep().run(base_ctx)
        assert out["byte_pattern_result"] is None
        assert out["byte_pattern_names"] == {}
        assert "timing_byte_pattern" in base_ctx.stats


class TestImportError:
    def test_import_error_swallowed(self, base_ctx) -> None:
        """BytePatternMatcher import edilemezse bos donulur."""
        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher",
            side_effect=ImportError,
        ):
            out = BytePatternStep().run(base_ctx)
        assert out["byte_pattern_names"] == {}
        assert out["byte_pattern_result"] is None


class TestSuccessfulMatch:
    def test_bpm_matches_propagated(self, base_ctx, fake_pc, tmp_path) -> None:
        """bp_result.total_matched > 0 ise byte_pattern_names doldurulur."""
        fake_bp_result = MagicMock()
        fake_bp_result.total_matched = 3
        fake_bp_result.total_unknown = 5
        fake_bp_result.match_rate = 0.6
        fake_bp_result.duration_seconds = 1.0
        fake_bp_result.matches = []
        fake_bp_result.errors = []

        fake_bpm = MagicMock()
        fake_bpm.return_value.match_unknown_functions.return_value = fake_bp_result
        fake_bpm.return_value.to_naming_map.return_value = {
            "FUN_1000": "strlen", "FUN_2000": "memcpy",
        }

        fake_fp = MagicMock()
        fake_fp.return_value.extract_from_binary.return_value = [
            MagicMock()  # bir signature yeter ki all_byte_sigs bos olmasin
        ]
        fake_fp.return_value.load_json_signatures.return_value = []
        fake_fp.return_value.load_directory.return_value = []

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", fake_bpm,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fake_fp,
        ):
            out = BytePatternStep().run(base_ctx)

        assert out["byte_pattern_names"] == {
            "FUN_1000": "strlen", "FUN_2000": "memcpy",
        }
        assert base_ctx.stats["byte_pattern_matched"] == 3
        assert base_ctx.stats["byte_pattern_total_unknown"] == 5
        # pending artifact pc.metadata'ya yazilmali
        assert "byte_pattern_matches" in fake_pc.metadata["artifacts_pending"]

    def test_bp_errors_propagated_to_ctx(self, base_ctx) -> None:
        fake_bp_result = MagicMock()
        fake_bp_result.total_matched = 0
        fake_bp_result.errors = ["disk okunamadi"]

        fake_bpm = MagicMock()
        fake_bpm.return_value.match_unknown_functions.return_value = fake_bp_result

        fake_fp = MagicMock()
        fake_fp.return_value.extract_from_binary.return_value = [MagicMock()]
        fake_fp.return_value.load_json_signatures.return_value = []
        fake_fp.return_value.load_directory.return_value = []

        with patch(
            "karadul.analyzers.byte_pattern_matcher.BytePatternMatcher", fake_bpm,
        ), patch(
            "karadul.analyzers.flirt_parser.FLIRTParser", fake_fp,
        ):
            BytePatternStep().run(base_ctx)

        assert "disk okunamadi" in base_ctx.errors
