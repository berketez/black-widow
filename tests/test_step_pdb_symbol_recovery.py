"""v1.15 Dalga 1 — PdbSymbolRecoveryStep testleri.

Kapsam:
- Registry kaydi
- Disabled flag -> status=disabled
- PE olmayan target -> status=not_pe_target
- PDB dosyasi yok -> status=no_pdb_file
- llvm-pdbutil yok -> status=tool_missing
- Smoke (mock adapter, 2 symbol + 1 type) -> status=ok, JSON artifacts
- Sibling .pdb cozumu (binary_for_byte_match komsusu)
- Adapter exception -> status=error
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.pdb_symbol_recovery import PdbSymbolRecoveryStep


@pytest.fixture
def real_pe(tmp_path: Path) -> Path:
    p = tmp_path / "app.exe"
    p.write_bytes(b"MZ" + b"\x00" * 1024)
    return p


@pytest.fixture
def real_pdb(tmp_path: Path) -> Path:
    """Sahte PDB dosyasi (sadece varlik testi icin)."""
    p = tmp_path / "app.pdb"
    p.write_bytes(b"Microsoft C/C++ MSF 7.00\x00" + b"\x00" * 64)
    return p


def _make_pc(
    target_path: Path,
    target_type_name: str = "PE_BINARY",
    save_json_return: Path | None = None,
):
    pc = MagicMock()
    pc.workspace.save_json = MagicMock(
        return_value=save_json_return or (target_path.parent / "out.json"),
    )
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.binary_reconstruction.enable_pdb = True
    pc.target = MagicMock()
    pc.target.path = target_path
    # target_type'i name attr'i olan bir mock yapalim
    tt = MagicMock()
    tt.name = target_type_name
    pc.target.target_type = tt
    return pc


class TestRegistry:
    def test_registered(self) -> None:
        import karadul.pipeline  # noqa: F401
        spec = get_step("pdb_symbol_recovery")
        assert "binary_for_byte_match" in spec.requires
        for produced in [
            "pdb_symbols", "pdb_types",
            "pdb_symbols_path", "pdb_types_path",
            "pdb_status",
        ]:
            assert produced in spec.produces


class TestDisabled:
    def test_disabled(self, real_pe: Path) -> None:
        pc = _make_pc(real_pe)
        pc.config.binary_reconstruction.enable_pdb = False
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})
        out = PdbSymbolRecoveryStep().run(ctx)
        assert out["pdb_status"] == "disabled"
        assert out["pdb_symbols"] == []
        assert out["pdb_types"] == []
        pc.workspace.save_json.assert_not_called()


class TestNonPETarget:
    def test_macho_target_skipped(self, real_pe: Path) -> None:
        pc = _make_pc(real_pe, target_type_name="MACHO_BINARY")
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})
        out = PdbSymbolRecoveryStep().run(ctx)
        assert out["pdb_status"] == "not_pe_target"
        pc.workspace.save_json.assert_not_called()

    def test_elf_target_skipped(self, real_pe: Path) -> None:
        pc = _make_pc(real_pe, target_type_name="ELF_BINARY")
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})
        out = PdbSymbolRecoveryStep().run(ctx)
        assert out["pdb_status"] == "not_pe_target"


class TestNoPdbFile:
    def test_no_pdb_anywhere(self, real_pe: Path) -> None:
        """Sibling .pdb yok, explicit artifact da yok -> status=no_pdb_file."""
        pc = _make_pc(real_pe)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})
        out = PdbSymbolRecoveryStep().run(ctx)
        assert out["pdb_status"] == "no_pdb_file"
        assert out["pdb_symbols"] == []


class TestToolMissing:
    def test_llvm_pdbutil_unavailable(self, real_pe: Path, real_pdb: Path) -> None:
        pc = _make_pc(real_pe)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "binary_for_byte_match": real_pe,
        })
        # Sibling .pdb otomatik bulunur (real_pe ile real_pdb ayni dizinde)
        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = False
        with patch(
            "karadul.analyzers.pdb_parser.PDBAdapter", fake_adapter,
        ):
            out = PdbSymbolRecoveryStep().run(ctx)
        assert out["pdb_status"] == "tool_missing"
        fake_adapter.return_value.extract_all.assert_not_called()


class TestSmoke:
    def test_extracts_symbols_and_types(
        self, real_pe: Path, real_pdb: Path,
    ) -> None:
        from karadul.analyzers.pdb_parser import PDBResult, PDBSymbol, PDBType

        pc = _make_pc(real_pe)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})

        sym1 = PDBSymbol(
            name="MyFunction", address=0x10010, size=64,
            section=1, kind="function",
        )
        sym2 = PDBSymbol(
            name="g_counter", address=0x20000, size=4,
            section=2, kind="global",
        )
        typ1 = PDBType(
            type_id=0x1004, kind="Struct", name="Point",
            size=8,
            fields=[
                {"name": "x", "type_id": 0x74, "offset": 0},
                {"name": "y", "type_id": 0x74, "offset": 4},
            ],
        )
        fake_result = PDBResult(
            symbols=[sym1, sym2], types=[typ1],
            return_code=0, duration_ms=85.0,
            pdb_version="7.0",
        )

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.extract_all.return_value = fake_result
        fake_adapter = MagicMock(return_value=fake_adapter_inst)

        with patch("karadul.analyzers.pdb_parser.PDBAdapter", fake_adapter):
            out = PdbSymbolRecoveryStep().run(ctx)

        assert out["pdb_status"] == "ok"
        assert len(out["pdb_symbols"]) == 2
        assert out["pdb_symbols"][0]["name"] == "MyFunction"
        assert out["pdb_symbols"][0]["kind"] == "function"
        assert len(out["pdb_types"]) == 1
        assert out["pdb_types"][0]["name"] == "Point"
        assert ctx.stats["pdb_total_symbols"] == 2
        assert ctx.stats["pdb_total_types"] == 1
        assert ctx.stats["pdb_version"] == "7.0"
        # Iki ayri JSON artifact yazilmali (pdb_symbols + pdb_types)
        assert pc.workspace.save_json.call_count == 2


class TestErrorHandling:
    def test_extract_all_exception(
        self, real_pe: Path, real_pdb: Path,
    ) -> None:
        pc = _make_pc(real_pe)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({"binary_for_byte_match": real_pe})

        fake_adapter_inst = MagicMock()
        fake_adapter_inst.is_available.return_value = True
        fake_adapter_inst.extract_all.side_effect = RuntimeError("pdb dump failed")
        fake_adapter = MagicMock(return_value=fake_adapter_inst)

        with patch("karadul.analyzers.pdb_parser.PDBAdapter", fake_adapter):
            out = PdbSymbolRecoveryStep().run(ctx)

        assert out["pdb_status"] == "error"
        assert any("pdb_symbol_recovery" in e or "pdb dump failed" in e
                   for e in ctx.errors)


class TestPdbResolution:
    def test_explicit_pdb_artifact_preferred(
        self, real_pe: Path, tmp_path: Path,
    ) -> None:
        """Explicit pdb_path artifact, sibling'e oncelikli."""
        # Sibling yok, explicit var
        explicit_pdb = tmp_path / "explicit.pdb"
        explicit_pdb.write_bytes(b"MSF\x00")
        pc = _make_pc(real_pe)
        ctx = StepContext(pipeline_context=pc)
        ctx._write_artifacts({
            "binary_for_byte_match": real_pe,
            "pdb_path": explicit_pdb,
        })
        # is_available False -> tool_missing'e dusmesi yine de PDB cozumlemesini test eder
        fake_adapter = MagicMock()
        fake_adapter.return_value.is_available.return_value = False
        with patch("karadul.analyzers.pdb_parser.PDBAdapter", fake_adapter):
            out = PdbSymbolRecoveryStep().run(ctx)
        # PDB cozumlendi (no_pdb_file degil), sonra tool eksik
        assert out["pdb_status"] == "tool_missing"
        # PDBAdapter constructor'a explicit pdb path verilmis olmali
        fake_adapter.assert_called_once()
        call_kwargs = fake_adapter.call_args
        assert call_kwargs.kwargs.get("pdb_path") == explicit_pdb
