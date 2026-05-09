"""v1.15 Dalga 1 — BinaryNinjaAnalysisStep testleri.

Berke karari (2026-05-09): BN lisansi alinmiyor, experimental kalir.
Default ``enable_binaryninja=False`` -> opt-in. Lisanssiz makinelerde
sessizce skip.

Kapsam:
- Registry kaydi
- Default disabled (opt-in flag)
- enable=True ama is_available=False -> status=not_available
- Smoke (mock adapter, 2 fn + 1 type) -> status=ok, JSON artifacts
- Adapter exception -> status=error
- No binary -> status=no_binary
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.binaryninja_analysis import (
    BinaryNinjaAnalysisStep,
)


@pytest.fixture
def real_binary(tmp_path: Path) -> Path:
    p = tmp_path / "app"
    p.write_bytes(b"\x7fELF\x00" * 64)
    return p


def _make_pc(target_path: Path, enable_bn: bool = True):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(
        return_value=target_path.parent / "out.json",
    )
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_binaryninja = enable_bn
    pc.target = MagicMock()
    pc.target.path = target_path
    return pc


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("binaryninja_analysis")
        assert "binary_for_byte_match" in spec.requires
        for produced in [
            "bn_functions", "bn_types",
            "bn_functions_path", "bn_types_path",
            "bn_status",
        ]:
            assert produced in spec.produces


class TestDefaultDisabled:
    def test_default_disabled_opt_in(self, real_binary: Path) -> None:
        """Default enable_binaryninja=False (Berke 2026-05-09 karari)."""
        pc = _make_pc(real_binary, enable_bn=False)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_binary})
        out = BinaryNinjaAnalysisStep().run(ctx)
        assert out["bn_status"] == "disabled"
        assert out["bn_functions"] == []
        assert out["bn_types"] == []
        pc.workspace.save_json.assert_not_called()


class TestNotAvailable:
    def test_bn_module_not_loaded(self, real_binary: Path) -> None:
        """enable=True ama BinaryNinjaAdapter.is_available()=False."""
        pc = _make_pc(real_binary, enable_bn=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_binary})

        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = False
        with patch(
            "karadul.analyzers.binaryninja_adapter.BinaryNinjaAdapter",
            fake_adapter,
        ):
            out = BinaryNinjaAnalysisStep().run(ctx)
        assert out["bn_status"] == "not_available"
        fake_adapter.return_value.extract_all.assert_not_called()


class TestNoBinary:
    def test_missing_binary_skips(self, tmp_path: Path) -> None:
        ghost = tmp_path / "ghost.bin"
        pc = _make_pc(ghost, enable_bn=True)
        pc.target.path = None  # binary_for_byte_match yok + target.path None
        ctx = StepContext(pipeline_context=pc)
        out = BinaryNinjaAnalysisStep().run(ctx)
        assert out["bn_status"] == "no_binary"


class TestSmoke:
    def test_extracts_functions_and_types(self, real_binary: Path) -> None:
        from karadul.analyzers.binaryninja_adapter import (
            BNFunction, BNResult, BNType,
        )

        pc = _make_pc(real_binary, enable_bn=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_binary})

        fn1 = BNFunction(
            name="main", address=0x1000, size=128,
            return_type="int32_t",
            parameters=[{"name": "argc", "type": "int32_t"}],
        )
        fn2 = BNFunction(
            name="helper", address=0x1100, size=64,
            return_type="void",
            is_imported=False, is_thunk=False,
        )
        typ = BNType(
            name="Header", kind="struct", size=16,
            fields=[{"name": "magic", "offset": 0, "type": "uint32_t"}],
        )
        result = BNResult(
            binary_path=real_binary,
            functions=[fn1, fn2], types=[typ],
            arch="x86_64", platform="linux",
            duration_ms=2400.0,
        )

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.extract_all.return_value = result
        fake_adapter = MagicMock(return_value=fake_adapter_inst)

        with patch(
            "karadul.analyzers.binaryninja_adapter.BinaryNinjaAdapter",
            fake_adapter,
        ):
            out = BinaryNinjaAnalysisStep().run(ctx)

        assert out["bn_status"] == "ok"
        assert len(out["bn_functions"]) == 2
        assert out["bn_functions"][0]["name"] == "main"
        assert out["bn_functions"][0]["return_type"] == "int32_t"
        assert len(out["bn_types"]) == 1
        assert out["bn_types"][0]["kind"] == "struct"
        assert ctx.stats["bn_total_functions"] == 2
        assert ctx.stats["bn_total_types"] == 1
        assert ctx.stats["bn_arch"] == "x86_64"
        assert ctx.stats["bn_platform"] == "linux"
        # Iki ayri JSON artifact
        assert pc.workspace.save_json.call_count == 2


class TestErrorHandling:
    def test_extract_exception(self, real_binary: Path) -> None:
        pc = _make_pc(real_binary, enable_bn=True)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_binary})

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.extract_all.side_effect = RuntimeError(
            "BN crashed",
        )
        fake_adapter = MagicMock(return_value=fake_adapter_inst)

        with patch(
            "karadul.analyzers.binaryninja_adapter.BinaryNinjaAdapter",
            fake_adapter,
        ):
            out = BinaryNinjaAnalysisStep().run(ctx)

        assert out["bn_status"] == "error"
        assert out["bn_functions"] == []
        assert any(
            "binaryninja_analysis" in e or "BN crashed" in e
            for e in ctx.errors
        )
