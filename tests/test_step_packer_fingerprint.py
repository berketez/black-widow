"""v1.13 Dalga 1 — PackerFingerprintStep testleri.

Kapsam:
- Registry kaydi (requires/produces dogru)
- Disabled flag -> bos donus + status=disabled
- Binary path bulunamaz -> status=no_binary
- ImportError yakalanir -> status=module_missing
- Detector hatasi -> errors'a eklenir, status=error
- Smoke (temiz binary): fingerprints=[] + JSON yazildi
- UPX mock: fingerprint listesi + stats (top_name, top_layers, kategori)
- target.path fallback (binary_for_byte_match yoksa)
- produce_artifact mirror'i pc.metadata'ya yazilir
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.packer_fingerprint import (
    PackerFingerprintStep,
)


@pytest.fixture
def real_binary(tmp_path: Path) -> Path:
    p = tmp_path / "dummy.bin"
    # Minimum PE/MZ benzeri header (gercek parse beklenmiyor — analyzer mocked)
    p.write_bytes(b"MZ\x00\x00" + b"\x00" * 512)
    return p


@pytest.fixture
def fake_pc(tmp_path: Path, real_binary: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(
        return_value=tmp_path / "packer_fingerprints.json",
    )
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_packer_fingerprint = True
    pc.target = MagicMock()
    pc.target.path = real_binary
    return pc


@pytest.fixture
def base_ctx(fake_pc, real_binary: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "binary_for_byte_match": real_binary,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("packer_fingerprint")
        assert "binary_for_byte_match" in spec.requires
        assert "packer_fingerprints" in spec.produces
        assert "packer_top_match" in spec.produces
        assert "packer_fingerprints_path" in spec.produces


class TestDisabled:
    def test_disabled_returns_empty(self, fake_pc, base_ctx) -> None:
        fake_pc.config.binary_reconstruction.enable_packer_fingerprint = False
        out = PackerFingerprintStep().run(base_ctx)
        assert out["packer_fingerprints"] == []
        assert out["packer_top_match"] is None
        assert out["packer_fingerprints_path"] is None
        assert base_ctx.stats["packer_fingerprint_status"] == "disabled"
        assert "timing_packer_fingerprint" in base_ctx.stats
        fake_pc.workspace.save_json.assert_not_called()


class TestNoBinary:
    def test_missing_binary_skips(self, fake_pc) -> None:
        fake_pc.target.path = None
        ctx = StepContext(pipeline_context=fake_pc)
        out = PackerFingerprintStep().run(ctx)
        assert out["packer_fingerprints"] == []
        assert ctx.stats["packer_fingerprint_status"] == "no_binary"

    def test_nonexistent_binary_skips(
        self, fake_pc, tmp_path: Path,
    ) -> None:
        ghost = tmp_path / "ghost.bin"
        fake_pc.target.path = ghost
        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"binary_for_byte_match": ghost})
        out = PackerFingerprintStep().run(ctx)
        assert ctx.stats["packer_fingerprint_status"] == "no_binary"


class TestSmoke:
    def test_clean_binary_no_fingerprints(self, base_ctx, fake_pc) -> None:
        fake_detector = MagicMock()
        fake_detector.return_value.detect.return_value = []
        with patch(
            "karadul.analyzers.packer_fingerprint.PackerFingerprintDetector",
            fake_detector,
        ):
            out = PackerFingerprintStep().run(base_ctx)
        assert out["packer_fingerprints"] == []
        assert out["packer_top_match"] is None
        assert base_ctx.stats["packer_total"] == 0
        assert base_ctx.stats["packer_fingerprint_status"] == "ok"
        # JSON yazilmali (sahte dahi olsa)
        fake_pc.workspace.save_json.assert_called_once()
        args, _ = fake_pc.workspace.save_json.call_args
        assert args[0] == "static"
        assert args[1] == "packer_fingerprints"


class TestUPXMock:
    def test_upx_fingerprint_propagated(self, base_ctx, fake_pc) -> None:
        """UPX fingerprint mock: stats top_name=UPX, layers=2, kategori=compressor."""
        fp1 = MagicMock()
        fp1.to_dict.return_value = {
            "packer_name": "UPX",
            "version": "3.96",
            "confidence": 0.97,
            "evidence": ["section adi: UPX0", "section adi: UPX1"],
            "category": "compressor",
            "platform": "pe",
            "layers_matched": 2,
        }
        fp2 = MagicMock()
        fp2.to_dict.return_value = {
            "packer_name": "VMProtect",
            "version": None,
            "confidence": 0.78,
            "evidence": ["string: VMProtect"],
            "category": "vm-protector",
            "platform": "pe",
            "layers_matched": 1,
        }
        fake_detector = MagicMock()
        # detect() confidence DESC sirali; UPX once
        fake_detector.return_value.detect.return_value = [fp1, fp2]
        with patch(
            "karadul.analyzers.packer_fingerprint.PackerFingerprintDetector",
            fake_detector,
        ):
            out = PackerFingerprintStep().run(base_ctx)

        assert len(out["packer_fingerprints"]) == 2
        assert out["packer_top_match"]["packer_name"] == "UPX"
        assert base_ctx.stats["packer_total"] == 2
        assert base_ctx.stats["packer_top_name"] == "UPX"
        assert base_ctx.stats["packer_top_confidence"] == 0.97
        assert base_ctx.stats["packer_top_layers"] == 2
        cats = base_ctx.stats["packer_categories"]
        assert cats["compressor"] == 1
        assert cats["vm-protector"] == 1
        # produce_artifact mirror
        assert "packer_fingerprints" in fake_pc.metadata["artifacts_pending"]


class TestImportError:
    def test_import_error_swallowed(self, base_ctx) -> None:
        with patch(
            "karadul.analyzers.packer_fingerprint.PackerFingerprintDetector",
            side_effect=ImportError,
        ):
            out = PackerFingerprintStep().run(base_ctx)
        assert out["packer_fingerprints"] == []
        assert base_ctx.stats["packer_fingerprint_status"] == "module_missing"


class TestDetectorRaises:
    def test_runtime_error_recorded(self, base_ctx) -> None:
        fake_detector = MagicMock()
        fake_detector.return_value.detect.side_effect = RuntimeError(
            "section parse hatasi",
        )
        with patch(
            "karadul.analyzers.packer_fingerprint.PackerFingerprintDetector",
            fake_detector,
        ):
            out = PackerFingerprintStep().run(base_ctx)
        assert out["packer_fingerprints"] == []
        assert any(
            "section parse hatasi" in e for e in base_ctx.errors
        )
        assert base_ctx.stats["packer_fingerprint_status"] == "error"


class TestTargetPathFallback:
    def test_uses_target_path_when_artifact_missing(
        self, fake_pc, real_binary: Path,
    ) -> None:
        ctx = StepContext(pipeline_context=fake_pc)
        # binary_for_byte_match enjekte etmiyoruz
        fake_detector = MagicMock()
        fake_detector.return_value.detect.return_value = []
        with patch(
            "karadul.analyzers.packer_fingerprint.PackerFingerprintDetector",
            fake_detector,
        ):
            out = PackerFingerprintStep().run(ctx)
        assert out["packer_fingerprints"] == []
        assert ctx.stats["packer_fingerprint_status"] == "ok"
        # Detector real_binary path'i ile init edilmeli
        args, _ = fake_detector.call_args
        assert args[0] == real_binary


class TestProducesContract:
    def test_produces_subset_of_declared(self, base_ctx, fake_pc) -> None:
        spec = get_step("packer_fingerprint")
        fake_pc.config.binary_reconstruction.enable_packer_fingerprint = False
        out = PackerFingerprintStep().run(base_ctx)
        for k in out:
            assert k in spec.produces, f"{k} not in produces"
