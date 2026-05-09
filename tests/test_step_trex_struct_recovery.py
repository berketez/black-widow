"""v1.15 Dalga 1 — TrexStructRecoveryStep testleri.

Kapsam:
- Registry kaydi (requires/produces dogru)
- Disabled flag -> status=disabled, JSON yazilmaz
- TRex binary yok -> status=binary_missing
- Ghidra IL artifact yok -> status=no_lifted_il
- Smoke (mock adapter): 2 struct -> JSON artifact yazilir, stats dolar
- Adapter exception -> status=error, errors'a eklenir
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.trex_struct_recovery import TrexStructRecoveryStep


@pytest.fixture
def real_binary(tmp_path: Path) -> Path:
    p = tmp_path / "dummy.bin"
    p.write_bytes(b"\x7fELF\x00\x01\x02\x03" * 64)
    return p


@pytest.fixture
def real_lifted(tmp_path: Path) -> Path:
    """Sahte Ghidra IL (lifted) dosyasi."""
    p = tmp_path / "lifted.json"
    p.write_text('{"functions": []}', encoding="utf-8")
    return p


@pytest.fixture
def fake_pc(tmp_path: Path, real_binary: Path):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(
        return_value=tmp_path / "trex_structs.json",
    )
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_trex = True
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
        spec = get_step("trex_struct_recovery")
        assert "binary_for_byte_match" in spec.requires
        assert "trex_structs" in spec.produces
        assert "trex_structs_path" in spec.produces
        assert "trex_status" in spec.produces


class TestDisabled:
    def test_disabled_returns_empty(self, fake_pc, base_ctx) -> None:
        fake_pc.config.binary_reconstruction.enable_trex = False
        out = TrexStructRecoveryStep().run(base_ctx)
        assert out["trex_structs"] == []
        assert out["trex_structs_path"] is None
        assert out["trex_status"] == "disabled"
        assert base_ctx.stats["trex_status"] == "disabled"
        assert "timing_trex_struct_recovery" in base_ctx.stats
        # Disabled iken save_json cagrilmamali
        fake_pc.workspace.save_json.assert_not_called()


class TestBinaryMissing:
    def test_trex_binary_unavailable_skips(self, fake_pc, base_ctx) -> None:
        """TRexAdapter.is_available()=False -> status=binary_missing."""
        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = False
        with patch(
            "karadul.analyzers.trex_adapter.TRexAdapter", fake_adapter,
        ):
            out = TrexStructRecoveryStep().run(base_ctx)
        assert out["trex_structs"] == []
        assert out["trex_status"] == "binary_missing"
        assert base_ctx.stats["trex_status"] == "binary_missing"
        # Adapter calistirilmis ama analyze cagrilmamali
        fake_adapter.return_value.analyze.assert_not_called()
        fake_pc.workspace.save_json.assert_not_called()


class TestNoLiftedIL:
    def test_lifted_il_artifact_missing_skips(self, fake_pc, base_ctx) -> None:
        """ghidra_lifted_il_path artifact yok -> status=no_lifted_il."""
        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = True
        with patch(
            "karadul.analyzers.trex_adapter.TRexAdapter", fake_adapter,
        ):
            out = TrexStructRecoveryStep().run(base_ctx)
        assert out["trex_structs"] == []
        assert out["trex_status"] == "no_lifted_il"
        # Analiz cagrilmamali
        fake_adapter.return_value.analyze.assert_not_called()

    def test_lifted_il_path_nonexistent(
        self, fake_pc, base_ctx, tmp_path: Path,
    ) -> None:
        """Lifted IL artifact var ama dosya yok -> skip."""
        ghost = tmp_path / "ghost_lifted.json"
        base_ctx._write_artifacts({"ghidra_lifted_il_path": ghost})
        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = True
        with patch(
            "karadul.analyzers.trex_adapter.TRexAdapter", fake_adapter,
        ):
            out = TrexStructRecoveryStep().run(base_ctx)
        assert out["trex_status"] == "no_lifted_il"


class TestSmoke:
    def test_two_structs_extracted(
        self, fake_pc, base_ctx, real_lifted: Path,
    ) -> None:
        """Mock adapter 2 struct dondurur, JSON artifact yazilir."""
        from karadul.analyzers.trex_adapter import TRexResult, TRexStruct

        base_ctx._write_artifacts({"ghidra_lifted_il_path": real_lifted})

        fake_struct1 = TRexStruct(
            name="config_t",
            fields=[{"offset": "0x0", "type": "int32_t", "name": "version"}],
            function="main",
        )
        fake_struct2 = TRexStruct(
            name="header_t",
            fields=[
                {"offset": "0x0", "type": "uint32_t", "name": "magic"},
                {"offset": "0x4", "type": "uint16_t", "name": "len"},
            ],
            function="parse_header",
        )
        fake_result = TRexResult(
            structs=[fake_struct1, fake_struct2],
            return_code=0,
            duration_ms=120.0,
        )

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.analyze.return_value = fake_result

        fake_adapter = MagicMock(return_value=fake_adapter_inst)
        with patch(
            "karadul.analyzers.trex_adapter.TRexAdapter", fake_adapter,
        ):
            out = TrexStructRecoveryStep().run(base_ctx)

        assert out["trex_status"] == "ok"
        assert len(out["trex_structs"]) == 2
        assert out["trex_structs"][0]["name"] == "config_t"
        assert out["trex_structs"][1]["name"] == "header_t"
        assert len(out["trex_structs"][1]["fields"]) == 2
        assert base_ctx.stats["trex_total_structs"] == 2
        assert base_ctx.stats["trex_return_code"] == 0
        assert base_ctx.stats["trex_duration_ms"] == 120.0
        # JSON yazilmali
        fake_pc.workspace.save_json.assert_called_once()
        args, _ = fake_pc.workspace.save_json.call_args
        assert args[0] == "static"
        assert args[1] == "trex_structs"


class TestErrorHandling:
    def test_analyze_exception_recorded(
        self, fake_pc, base_ctx, real_lifted: Path,
    ) -> None:
        """adapter.analyze() exception -> status=error, errors'a eklenir."""
        base_ctx._write_artifacts({"ghidra_lifted_il_path": real_lifted})

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.analyze.side_effect = RuntimeError("trex crashed")
        fake_adapter = MagicMock(return_value=fake_adapter_inst)

        with patch(
            "karadul.analyzers.trex_adapter.TRexAdapter", fake_adapter,
        ):
            out = TrexStructRecoveryStep().run(base_ctx)

        assert out["trex_status"] == "error"
        assert out["trex_structs"] == []
        assert any(
            "trex crashed" in e or "trex_struct_recovery" in e
            for e in base_ctx.errors
        ), "Hata mesaji errors listesinde olmali"
