"""v1.10.0 M1 T3.2 — GhidraMetadataStep testleri.

Step davranisi (stages.py L1242-1359'dan tasindi):
- Ghidra JSON yollarini deobf/static tercih sirasiyla resolve et
- functions/strings/call_graph JSON'larini bir kez parse edip cache'le
- SignatureDB matching (platform-aware) calistir
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_workspace(tmp_path: Path):
    ws = MagicMock()
    dirs = {
        "static": tmp_path / "static",
        "deobfuscated": tmp_path / "deobfuscated",
        "reconstructed": tmp_path / "reconstructed",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    ws.get_stage_dir.side_effect = lambda s: dirs[s]
    ws.save_json = MagicMock(return_value=tmp_path / "reconstructed" / "x.json")
    return ws, dirs


@pytest.fixture
def fake_target():
    from karadul.core.target import TargetType
    t = MagicMock()
    t.target_type = TargetType.ELF_BINARY
    t.name = "sample"
    return t


@pytest.fixture
def fake_pc(fake_workspace, fake_target, tmp_path):
    ws, _ = fake_workspace
    pc = MagicMock()
    pc.target = fake_target
    pc.workspace = ws
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.project_root = tmp_path
    pc.report_progress = MagicMock()
    return pc


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestGhidraMetadataRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("ghidra_metadata")
        assert "decompiled_dir" in spec.requires
        assert "functions_json_path" in spec.produces
        assert "sig_matches" in spec.produces
        assert "functions_data" in spec.produces


# ---------------------------------------------------------------------------
# JSON path resolution
# ---------------------------------------------------------------------------


class TestJsonPathResolution:
    def test_deobfuscated_over_static(
        self, fake_workspace, fake_pc, tmp_path: Path,
    ) -> None:
        """deobfuscated/'te varsa static/'te olsa bile onceligi alir."""
        ws, dirs = fake_workspace
        # Hem static hem deobf'a yaz — deobf kazanmali
        (dirs["static"] / "ghidra_functions.json").write_text("{}")
        (dirs["deobfuscated"] / "ghidra_functions.json").write_text('{"x": 1}')
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["functions_json_path"] == (
            dirs["deobfuscated"] / "ghidra_functions.json"
        )
        # functions_data'nin deobf dosyasindan geldigini dogrula
        assert out["functions_data"] == {"x": 1}

    def test_fallback_to_static(
        self, fake_workspace, fake_pc, tmp_path: Path,
    ) -> None:
        """deobfuscated/'te yoksa static/'e duser."""
        ws, dirs = fake_workspace
        (dirs["static"] / "ghidra_functions.json").write_text('{"y": 2}')
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["functions_json_path"] == (
            dirs["static"] / "ghidra_functions.json"
        )
        assert out["functions_data"] == {"y": 2}

    def test_decompiled_json_ghidra_output_fallback(
        self, fake_workspace, fake_pc, tmp_path: Path,
    ) -> None:
        """decompiled.json icin static/ghidra_output/ fallback'i calisir."""
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()
        ghidra_out = dirs["static"] / "ghidra_output"
        ghidra_out.mkdir()
        (ghidra_out / "decompiled.json").write_text("{}")

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["decompiled_json_path"] == ghidra_out / "decompiled.json"


# ---------------------------------------------------------------------------
# Parse cache
# ---------------------------------------------------------------------------


class TestParseCache:
    def test_malformed_json_recorded_as_error(
        self, fake_workspace, fake_pc,
    ) -> None:
        """Bozuk JSON ctx.errors'a eklenir, step crash etmez."""
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()
        (dirs["deobfuscated"] / "ghidra_strings.json").write_text("not json {")

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["strings_data"] is None
        assert any("strings_json parse hatasi" in e for e in ctx.errors)

    def test_missing_json_stays_none(
        self, fake_workspace, fake_pc,
    ) -> None:
        """JSON dosyasi yoksa None doner, hata yok."""
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["functions_data"] is None
        assert out["strings_data"] is None
        assert out["call_graph_data"] is None


# ---------------------------------------------------------------------------
# Signature DB integration
# ---------------------------------------------------------------------------


class TestSignatureDbIntegration:
    def test_sigdb_import_error_skipped(
        self, fake_workspace, fake_pc,
    ) -> None:
        """SignatureDB import edilemezse ImportError yakalanir, sig_matches=[]."""
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["sig_matches"] == []
        assert ctx.stats.get("timing_signature_db") is not None

    def test_sigdb_exception_recorded_as_error(
        self, fake_workspace, fake_pc,
    ) -> None:
        """SignatureDB runtime hatasi ctx.errors'a eklenir."""
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        fake_sigdb = MagicMock()
        fake_sigdb.return_value.match_all.side_effect = RuntimeError("boom")
        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            fake_sigdb,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["sig_matches"] == []
        assert any("Signature DB hatasi" in e for e in ctx.errors)


# ---------------------------------------------------------------------------
# output_dir olusturuluyor mu?
# ---------------------------------------------------------------------------


class TestOutputDir:
    def test_output_dir_created(
        self, fake_workspace, fake_pc,
    ) -> None:
        ws, dirs = fake_workspace
        (dirs["deobfuscated"] / "decompiled").mkdir()

        ctx = StepContext(pipeline_context=fake_pc)
        ctx._write_artifacts({"decompiled_dir": dirs["deobfuscated"] / "decompiled"})

        with patch(
            "karadul.analyzers.signature_db.SignatureDB",
            side_effect=ImportError,
        ):
            out = GhidraMetadataStep().run(ctx)

        assert out["output_dir"].exists()
        assert out["output_dir"] == dirs["reconstructed"] / "src"
