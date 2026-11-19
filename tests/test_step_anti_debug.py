"""v1.13 Dalga 1 — AntiDebugStep testleri.

Kapsam:
- Registry kaydi (requires/produces dogru)
- Disabled flag -> bos donus + status=kapali (JSON yine yazilir; P-S1)
- Binary path bulunamaz -> status=hata + neden
- ImportError yakalanir -> status=arac_yok
- Detector hatasi -> errors'a eklenir, status=hata
- Smoke (temiz binary): findings=[] + JSON artifact yazilir
- Mock detector findings -> stats + artifact
- target.path fallback (binary_for_byte_match yoksa)
- produce_artifact -> ctx.stage_artifacts (yeni kanal)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.anti_debug import AntiDebugStep


@pytest.fixture
def real_binary(tmp_path: Path) -> Path:
    """Disk'te var olan kucuk dummy binary (4 byte ELF magic vb.)."""
    p = tmp_path / "dummy.bin"
    p.write_bytes(b"\x7fELF\x00\x01\x02\x03" * 64)
    return p


@pytest.fixture
def fake_pc(tmp_path: Path, real_binary: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(
        return_value=tmp_path / "anti_debug_findings.json",
    )
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_anti_debug_detection = True
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


def _fake_detector() -> MagicMock:
    """Taklit dedektor sinifi; ``detect()`` gercegi gibi uc katmani cagirir.

    P-S1: adim katman cagrilarini gozleyerek durum yazar; katman cagirmayan
    bir taklit "katman calismadi" (hata) sayilir. Yerlesim x86-64 (bayt
    katmani uygulanabilir), okuma siniri gercek dedektorun ontanimlisi.
    """
    from karadul.analyzers.anti_debug_detector import (
        AntiDebugDetector, CodeLayout, CodeRegion,
    )
    cls = MagicMock()
    inst = cls.return_value
    inst.max_bytes_scan = AntiDebugDetector(binary_path=Path("/dev/null")).max_bytes_scan
    inst._code_layout.return_value = CodeLayout(
        "elf", "x86_64", (CodeRegion(".text", 0, 16, 0x1000),))
    for meth in ("detect_by_imports", "detect_by_strings", "detect_by_bytes"):
        getattr(inst, meth).return_value = []
    findings: list = []

    def detect():
        inst.detect_by_imports()
        inst.detect_by_strings()
        inst.detect_by_bytes()
        return list(findings)

    def scan():
        # P02b kalem 3: adim durumu dedektorun scan()'inden alir; taklit
        # detect()'i cagirir ki detect.side_effect hatasi scan'e de yansisin.
        from karadul.analyzers.anti_debug_detector import AntiDebugScan
        bulunan = inst.detect()
        return AntiDebugScan(
            bulunan, "calisti", "",
            {ad: {"status": "calisti", "reason": ""}
             for ad in ("imports", "strings", "bytes")},
            16, 16)

    inst.detect.side_effect = detect
    inst.scan.side_effect = scan
    cls.findings = findings  # testler bulgu listesini buradan doldurur
    return cls


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("anti_debug")
        assert "binary_for_byte_match" in spec.requires
        assert "anti_debug_findings" in spec.produces
        assert "anti_debug_summary" in spec.produces
        assert "anti_debug_findings_path" in spec.produces


class TestDisabled:
    def test_disabled_returns_empty(self, fake_pc, base_ctx) -> None:
        fake_pc.config.binary_reconstruction.enable_anti_debug_detection = False
        out = AntiDebugStep().run(base_ctx)
        assert out["anti_debug_findings"] == []
        assert out["anti_debug_summary"] == {}
        assert base_ctx.stats["anti_debug_status"] == "kapali"
        assert "timing_anti_debug" in base_ctx.stats
        # P-S1: kapaliyken de durum JSON'a yazilir ("taranmadi" != "temiz")
        args, _ = fake_pc.workspace.save_json.call_args
        assert args[2]["status"] == "kapali"
        assert args[2]["total_findings"] is None


class TestNoBinary:
    def test_missing_binary_skips(self, fake_pc, tmp_path: Path) -> None:
        """binary_for_byte_match yok ve target.path da yok -> status=hata + neden."""
        fake_pc.target.path = None
        ctx = StepContext(pipeline_context=fake_pc)
        # binary_for_byte_match enjekte etmiyoruz
        out = AntiDebugStep().run(ctx)
        assert out["anti_debug_findings"] == []
        assert ctx.stats["anti_debug_status"] == "hata"
        assert "ikili yok" in ctx.stats["anti_debug_status_reason"]

    def test_nonexistent_binary_skips(self, fake_pc, tmp_path: Path) -> None:
        """binary_for_byte_match path mevcut degil -> status=hata + neden."""
        ghost = tmp_path / "ghost.bin"
        fake_pc.target.path = ghost
        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"binary_for_byte_match": ghost})
        out = AntiDebugStep().run(ctx)
        assert out["anti_debug_findings"] == []
        assert ctx.stats["anti_debug_status"] == "hata"
        assert "ikili yok" in ctx.stats["anti_debug_status_reason"]


class TestSmoke:
    def test_clean_binary_no_findings(self, base_ctx, fake_pc) -> None:
        """Detector boş list dondurse pipeline kirilmamali, JSON yazilmali."""
        fake_detector = _fake_detector()
        fake_detector.return_value.summary.return_value = {}
        with patch(
            "karadul.analyzers.anti_debug_detector.AntiDebugDetector",
            fake_detector,
        ):
            out = AntiDebugStep().run(base_ctx)
        assert out["anti_debug_findings"] == []
        assert base_ctx.stats["anti_debug_total"] == 0
        assert base_ctx.stats["anti_debug_status"] == "calisti"
        # JSON yazilmali (artifact path None olmamali)
        fake_pc.workspace.save_json.assert_called_once()
        args, _ = fake_pc.workspace.save_json.call_args
        assert args[0] == "static"
        assert args[1] == "anti_debug_findings"
        assert args[2]["total_findings"] == 0


class TestDetectionResults:
    def test_findings_propagated_to_stats(self, base_ctx, fake_pc) -> None:
        """Mock detector findings -> stats + JSON payload + produce_artifact."""
        # AntiDebugFinding-vari objeler
        f1 = MagicMock()
        f1.to_dict.return_value = {
            "technique": "IsDebuggerPresent",
            "category": "windows_api",
            "confidence": 0.95,
            "evidence": "import: IsDebuggerPresent",
            "platform": "windows",
            "description": "Windows API anti-debug",
        }
        f2 = MagicMock()
        f2.to_dict.return_value = {
            "technique": "ptrace_traceme",
            "category": "ptrace",
            "confidence": 0.85,
            "evidence": "import: ptrace",
            "platform": "linux",
            "description": "Linux ptrace anti-debug",
        }
        fake_detector = _fake_detector()
        fake_detector.findings.extend([f1, f2])
        fake_detector.return_value.summary.return_value = {
            "total_findings": 2, "categories": ["windows_api", "ptrace"],
        }
        with patch(
            "karadul.analyzers.anti_debug_detector.AntiDebugDetector",
            fake_detector,
        ):
            out = AntiDebugStep().run(base_ctx)

        assert len(out["anti_debug_findings"]) == 2
        assert out["anti_debug_summary"]["total_findings"] == 2
        assert base_ctx.stats["anti_debug_total"] == 2
        assert base_ctx.stats["anti_debug_top_technique"] == "IsDebuggerPresent"
        assert base_ctx.stats["anti_debug_top_confidence"] == 0.95
        # Kategori dagilimi
        cats = base_ctx.stats["anti_debug_categories"]
        assert cats["windows_api"] == 1
        assert cats["ptrace"] == 1
        # produce_artifact stage_artifacts kanalina yazmali
        assert "anti_debug_findings" in base_ctx.stage_artifacts


class TestImportError:
    def test_import_error_swallowed(self, base_ctx, monkeypatch) -> None:
        """AntiDebugDetector modulu yoksa durum ``arac_yok``; JSON yine yazilir."""
        import sys
        monkeypatch.setitem(sys.modules, "karadul.analyzers.anti_debug_detector", None)
        out = AntiDebugStep().run(base_ctx)
        assert out["anti_debug_findings"] == []
        assert base_ctx.stats["anti_debug_status"] == "arac_yok"


class TestDetectorRaises:
    def test_runtime_error_recorded(self, base_ctx) -> None:
        """Detector.detect() patlasa errors'a eklenir, pipeline kirilmaz."""
        fake_detector = _fake_detector()
        fake_detector.return_value.detect.side_effect = RuntimeError(
            "lief patladi",
        )
        with patch(
            "karadul.analyzers.anti_debug_detector.AntiDebugDetector",
            fake_detector,
        ):
            out = AntiDebugStep().run(base_ctx)
        assert out["anti_debug_findings"] == []
        assert any("lief patladi" in e for e in base_ctx.errors)
        assert base_ctx.stats["anti_debug_status"] == "hata"


class TestTargetPathFallback:
    def test_uses_target_path_when_artifact_missing(
        self, fake_pc, real_binary: Path,
    ) -> None:
        """binary_for_byte_match artifact yok -> target.path kullanilir."""
        ctx = StepContext(pipeline_context=fake_pc)
        # binary_for_byte_match enjekte etmiyoruz
        fake_detector = _fake_detector()
        fake_detector.return_value.summary.return_value = {}
        with patch(
            "karadul.analyzers.anti_debug_detector.AntiDebugDetector",
            fake_detector,
        ):
            out = AntiDebugStep().run(ctx)
        # target.path dogru sekilde kullanildi
        assert out["anti_debug_findings"] == []
        assert ctx.stats["anti_debug_status"] == "calisti"
        # Detector'in init'inde binary_path kwarg dogru gecilmeli
        _, kwargs = fake_detector.call_args
        assert kwargs["binary_path"] == real_binary



class TestProducesContract:
    def test_produces_subset_of_declared(self, base_ctx, fake_pc) -> None:
        spec = get_step("anti_debug")
        fake_pc.config.binary_reconstruction.enable_anti_debug_detection = False
        out = AntiDebugStep().run(base_ctx)
        for k in out:
            assert k in spec.produces, f"{k} not in produces"
