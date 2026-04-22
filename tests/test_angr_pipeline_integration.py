"""v1.11.0 Phase 1B — angr pipeline entegrasyonu smoke testleri.

Kapsam:
    - CLI `--decompiler-backend=angr` flag'i cfg.decompilers.primary_backend'e
      gercekten yaziyor mu?
    - Factory fallback: angr primary secilmis ama kurulu degil -> ghidra'ya
      dusuyor mu?
    - pipeline_adapter: DecompileResult -> Ghidra JSON semasi donusumu.
    - MachOAnalyzer._run_ghidra backend'i gercekten kullaniyor mu? (mock ile)
    - Ghidra default path (primary=ghidra) DOKUNULMADI (legacy korundu).

Mock-only; gercek angr calistirilmiyor (angr CI'da kurulu degil).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from karadul.config import Config, DecompilersConfig
from karadul.decompilers import (
    AngrBackend,
    GhidraBackend,
    create_backend_with_fallback,
)
from karadul.decompilers.base import DecompiledFunction, DecompileResult
from karadul.decompilers.pipeline_adapter import (
    _result_to_ghidra_call_graph,
    _result_to_ghidra_functions,
    _result_to_ghidra_strings,
    _safe_filename,
    write_ghidra_shape_artifacts,
)


# ---------------------------------------------------------------------------
# Config / CLI flag plumbing
# ---------------------------------------------------------------------------


class TestConfigAndCLI:
    def test_fallback_chain_default(self) -> None:
        """Yeni fallback_chain field'i varsayilan olarak ['ghidra']."""
        dc = DecompilersConfig()
        assert dc.fallback_chain == ["ghidra"]

    def test_fallback_chain_from_dict(self) -> None:
        """YAML'dan fallback_chain okunur."""
        data = {
            "decompilers": {
                "primary_backend": "angr",
                "fallback_chain": ["ghidra", "angr"],
            }
        }
        cfg = Config._from_dict(data)
        assert cfg.decompilers.primary_backend == "angr"
        assert cfg.decompilers.fallback_chain == ["ghidra", "angr"]

    def test_cli_flag_option_registered(self) -> None:
        """`--decompiler-backend` click option olarak kayitli ve choice ghidra/angr."""
        from karadul import cli as cli_mod

        analyze_cmd = cli_mod.main.get_command(None, "analyze")
        assert analyze_cmd is not None
        opt = next(
            (p for p in analyze_cmd.params if p.name == "decompiler_backend"),
            None,
        )
        assert opt is not None, "decompiler-backend CLI flag kayitli degil"
        # Click choice: ghidra + angr
        assert set(opt.type.choices) == {"ghidra", "angr"}

    def test_cli_flag_sets_primary_backend(self, tmp_path: Path) -> None:
        """`--decompiler-backend=angr` cfg.decompilers.primary_backend'e yaziyor.

        Click entry'yi CliRunner ile aciyoruz ama resolve_target/Pipeline'i
        mock'luyoruz -- tek amac flag'in cfg'ye yaziligini dogrulamak.
        """
        from karadul import cli as cli_mod

        # Gercek binary yerine tmp'de sahte dosya
        fake_bin = tmp_path / "fake_bin"
        fake_bin.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 32)

        captured: dict = {}

        class _FakePipeline:
            def __init__(self, cfg):
                captured["cfg"] = cfg

            def run(self, *args, **kwargs):
                return MagicMock(
                    success=True, errors=[], stats={},
                    final_output_dir=tmp_path, artifacts={},
                )

        with patch(
            "karadul.core.pipeline.Pipeline", _FakePipeline,
        ), patch.object(
            cli_mod, "_load_config", return_value=Config(),
        ), patch(
            "karadul.core.target_resolver.resolve_target",
            return_value=fake_bin,
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli_mod.main,
                ["analyze", "--decompiler-backend=angr", str(fake_bin)],
                catch_exceptions=True,
            )

        # Flag cfg'ye yazildi mi?
        assert "cfg" in captured, (
            f"Pipeline olusturulmadi; exit={result.exit_code}, "
            f"out={result.output!r}, exc={result.exception!r}"
        )
        assert captured["cfg"].decompilers.primary_backend == "angr"


# ---------------------------------------------------------------------------
# Factory fallback
# ---------------------------------------------------------------------------


class TestFactoryFallback:
    def test_fallback_ghidra_when_angr_missing(self) -> None:
        """angr primary + angr kurulu degil -> Ghidra'ya dusuyor."""
        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        cfg.decompilers.fallback_chain = ["ghidra"]

        # angr availability False, ghidra True
        with patch.object(
            AngrBackend, "is_available", return_value=False,
        ), patch.object(
            GhidraBackend, "is_available", return_value=True,
        ):
            backend, tried = create_backend_with_fallback(cfg)

        assert backend.name == "ghidra"
        assert tried == ["angr", "ghidra"]

    def test_primary_used_when_available(self) -> None:
        """Primary kullanilabilir ise fallback denenmez."""
        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        cfg.decompilers.fallback_chain = ["ghidra"]

        with patch.object(AngrBackend, "is_available", return_value=True):
            backend, tried = create_backend_with_fallback(cfg)

        assert backend.name == "angr"
        assert tried == ["angr"]

    def test_ghidra_default_no_double_try(self) -> None:
        """Default config (primary=ghidra, chain=[ghidra]) -> tek deneme."""
        cfg = Config()
        with patch.object(GhidraBackend, "is_available", return_value=True):
            backend, tried = create_backend_with_fallback(cfg)

        assert backend.name == "ghidra"
        assert tried == ["ghidra"]  # 'ghidra' iki kere gorunmez

    def test_all_backends_unavailable_raises(self) -> None:
        """Hicbiri kullanilabilir degilse RuntimeError."""
        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        cfg.decompilers.fallback_chain = ["ghidra"]

        with patch.object(
            AngrBackend, "is_available", return_value=False,
        ), patch.object(
            GhidraBackend, "is_available", return_value=False,
        ):
            with pytest.raises(RuntimeError, match="Hic bir decompiler backend"):
                create_backend_with_fallback(cfg)

    def test_unknown_backend_in_chain_skipped(self) -> None:
        """fallback_chain'de bilinmeyen isim varsa atlanir, crash olmaz."""
        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        cfg.decompilers.fallback_chain = ["nonexistent_backend", "ghidra"]

        with patch.object(
            AngrBackend, "is_available", return_value=False,
        ), patch.object(
            GhidraBackend, "is_available", return_value=True,
        ):
            backend, tried = create_backend_with_fallback(cfg)

        assert backend.name == "ghidra"
        assert "nonexistent_backend" in tried
        assert "ghidra" in tried


# ---------------------------------------------------------------------------
# Pipeline adapter — DecompileResult -> Ghidra JSON schema
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_result() -> DecompileResult:
    """Kucuk tipik angr-benzeri DecompileResult."""
    funcs = [
        DecompiledFunction(
            address="0x401000",
            name="main",
            pseudocode="int main() { return helper(); }",
            calls=["0x401100"],
            backend_specific={"size": 40, "is_plt": False},
        ),
        DecompiledFunction(
            address="0x401100",
            name="helper",
            pseudocode="int helper() { return 42; }",
            calls=[],
            backend_specific={"size": 12, "is_plt": False},
        ),
        DecompiledFunction(
            address="0x401200",
            name="plt_stub",
            pseudocode="",  # PLT -- pseudocode yok
            calls=[],
            backend_specific={"is_plt": True},
        ),
    ]
    return DecompileResult(
        functions=funcs,
        call_graph={"0x401000": ["0x401100"], "0x401100": [], "0x401200": []},
        strings=[{"addr": "0x402000", "value": "hello", "encoding": "ascii"}],
        errors=["WARN: partial_string_decode"],
        backend_name="angr",
        duration_seconds=5.7,
    )


class TestAdapterConversion:
    def test_functions_block_schema(self, sample_result: DecompileResult) -> None:
        block = _result_to_ghidra_functions(sample_result)
        assert block["total"] == 3
        names = [f["name"] for f in block["functions"]]
        assert "main" in names and "helper" in names
        main = next(f for f in block["functions"] if f["name"] == "main")
        assert main["address"] == "0x401000"
        assert main["size"] == 40
        assert main["source"] == "ANGR_AUTO"  # backend_name -> source tag

    def test_call_graph_schema(self, sample_result: DecompileResult) -> None:
        block = _result_to_ghidra_call_graph(sample_result)
        nodes = block["nodes"]
        assert "0x401000" in nodes
        # main -> helper
        callees = nodes["0x401000"]["callees"]
        assert any(c["address"] == "0x401100" for c in callees)
        # helper'in callers'inda main olmali (reverse index)
        helper_callers = nodes["0x401100"]["callers"]
        assert any(c["address"] == "0x401000" for c in helper_callers)
        # edges listesi
        assert {"from": "0x401000", "to": "0x401100"} in block["edges"]

    def test_strings_schema(self, sample_result: DecompileResult) -> None:
        block = _result_to_ghidra_strings(sample_result)
        assert block["total"] == 1
        s = block["strings"][0]
        assert s["address"] == "0x402000"
        assert s["value"] == "hello"
        # encoding -> type field
        assert s["type"] == "ascii"

    def test_write_artifacts_creates_ghidra_shape(
        self, sample_result: DecompileResult, tmp_path: Path,
    ) -> None:
        """End-to-end: yazilan dosyalar ghidra_metadata step'inin bekledigi
        yolda + semada."""
        result_dict = write_ghidra_shape_artifacts(sample_result, tmp_path)

        # Uc ana JSON olustu
        assert (tmp_path / "ghidra_functions.json").exists()
        assert (tmp_path / "ghidra_strings.json").exists()
        assert (tmp_path / "ghidra_call_graph.json").exists()
        # Decompiled dizini + 2 pseudocode (plt_stub hariç)
        dec_dir = tmp_path / "ghidra_output" / "decompiled"
        assert dec_dir.exists()
        c_files = list(dec_dir.glob("*.c"))
        assert len(c_files) == 2  # main + helper; plt_stub yok
        # Icerik kontrolu
        main_file = next(p for p in c_files if "main" in p.name)
        assert "return helper()" in main_file.read_text()

        # Dict shape: Ghidra analyze() ile uyumlu
        assert result_dict["success"] is True
        assert result_dict["mode"] == "angr_adapter"
        so = result_dict["scripts_output"]
        assert so["functions"]["total"] == 3
        assert so["decompiled"]["success"] == 2
        assert so["combined_results"]["summary"]["function_count"] == 3
        assert so["combined_results"]["summary"]["string_count"] == 1

    def test_ghidra_metadata_step_can_parse_adapter_output(
        self, sample_result: DecompileResult, tmp_path: Path,
    ) -> None:
        """Adapter cikisini GhidraMetadataStep._parse_core_jsons okuyabilmeli."""
        write_ghidra_shape_artifacts(sample_result, tmp_path)

        # Direkt JSON parse (step'in yaptigi is)
        functions_data = json.loads(
            (tmp_path / "ghidra_functions.json").read_text(),
        )
        strings_data = json.loads(
            (tmp_path / "ghidra_strings.json").read_text(),
        )
        cg_data = json.loads(
            (tmp_path / "ghidra_call_graph.json").read_text(),
        )

        # Ghidra'nin bekledigi kok alanlar
        assert "functions" in functions_data and "total" in functions_data
        assert "strings" in strings_data and "total" in strings_data
        assert "nodes" in cg_data and "edges" in cg_data

    def test_safe_filename_sanitizes_unsafe_chars(self) -> None:
        """Isim icinde slash/quote/space olsa bile FS-safe uretir."""
        out = _safe_filename("std::vector<int>::push back", "0x401000")
        assert "/" not in out
        assert out.endswith(".c")
        assert "0x401000" in out


# ---------------------------------------------------------------------------
# MachOAnalyzer._run_ghidra backend-agnostic davranisi
# ---------------------------------------------------------------------------


class TestMachOAnalyzerBackendDispatch:
    def test_ghidra_primary_uses_legacy_path(self) -> None:
        """primary=ghidra + ghidra kurulu -> eski Ghidra kod yoluna gidiliyor."""
        from karadul.analyzers.macho import MachOAnalyzer

        cfg = Config()
        cfg.decompilers.primary_backend = "ghidra"

        with patch.object(MachOAnalyzer, "__init__", lambda self, c: None):
            analyzer = MachOAnalyzer(cfg)
            analyzer.config = cfg
            analyzer.ghidra = MagicMock()
            analyzer.ghidra.is_available.return_value = True
            analyzer._run_ghidra_legacy = MagicMock(
                return_value={"success": True, "mode": "ghidra_legacy"},
            )

            workspace = MagicMock()
            result = analyzer._run_ghidra(Path("/tmp/bin"), workspace)

        analyzer._run_ghidra_legacy.assert_called_once()
        assert result["mode"] == "ghidra_legacy"

    def test_angr_primary_runs_backend_and_writes_adapter(
        self, tmp_path: Path,
    ) -> None:
        """primary=angr + angr kurulu -> backend.decompile() + adapter yazimi."""
        from karadul.analyzers.macho import MachOAnalyzer

        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        cfg.decompilers.fallback_chain = []  # primary'de kal

        # Fake angr result
        fake_result = DecompileResult(
            functions=[DecompiledFunction("0x1000", "f", "int f(){}", [], None)],
            call_graph={"0x1000": []},
            strings=[],
            errors=[],
            backend_name="angr",
            duration_seconds=1.0,
        )

        # static/ icin sahte workspace
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        workspace = MagicMock()
        workspace.get_stage_dir.return_value = static_dir

        fake_backend = MagicMock()
        fake_backend.name = "angr"
        fake_backend.is_available.return_value = True
        fake_backend.decompile.return_value = fake_result

        with patch.object(MachOAnalyzer, "__init__", lambda self, c: None):
            analyzer = MachOAnalyzer(cfg)
            analyzer.config = cfg
            analyzer.ghidra = MagicMock()
            # Primary != ghidra => factory path'e girer
            with patch(
                "karadul.decompilers.create_backend_with_fallback",
                return_value=(fake_backend, ["angr"]),
            ):
                result = analyzer._run_ghidra(Path("/tmp/bin"), workspace)

        fake_backend.decompile.assert_called_once()
        assert result["success"] is True
        assert result["mode"] == "angr_adapter"
        # Dosyalar yazildi mi?
        assert (static_dir / "ghidra_functions.json").exists()

    def test_angr_crash_falls_back_to_ghidra(self, tmp_path: Path) -> None:
        """angr backend decompile() cokerse Ghidra legacy yoluna duser."""
        from karadul.analyzers.macho import MachOAnalyzer

        cfg = Config()
        cfg.decompilers.primary_backend = "angr"

        fake_backend = MagicMock()
        fake_backend.name = "angr"
        fake_backend.is_available.return_value = True
        fake_backend.decompile.side_effect = RuntimeError("angr exploded")

        with patch.object(MachOAnalyzer, "__init__", lambda self, c: None):
            analyzer = MachOAnalyzer(cfg)
            analyzer.config = cfg
            analyzer.ghidra = MagicMock()
            analyzer.ghidra.is_available.return_value = True
            analyzer._run_ghidra_legacy = MagicMock(
                return_value={"success": True, "mode": "ghidra_legacy"},
            )

            workspace = MagicMock()
            workspace.get_stage_dir.return_value = tmp_path

            with patch(
                "karadul.decompilers.create_backend_with_fallback",
                return_value=(fake_backend, ["angr"]),
            ):
                result = analyzer._run_ghidra(Path("/tmp/bin"), workspace)

        # angr denendi ama cokta; legacy Ghidra cagrildi
        fake_backend.decompile.assert_called_once()
        analyzer._run_ghidra_legacy.assert_called_once()
        assert result["mode"] == "ghidra_legacy"
