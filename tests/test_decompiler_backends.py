"""v1.10.0 M2 T10 — Decompiler backend abstraction testleri.

Kapsam:
    - base.py dataclass/Protocol (2)
    - Protocol runtime check (1)
    - GhidraBackend adapter (3)
    - AngrBackend opsiyonel (2)
    - Factory (3)
    - Config entegrasyonu (1)
    - Ghidra dict -> DecompileResult donusum (2+)

Toplam: 15 test (hedef 12+).

Testler mock-only — gercek Ghidra/angr calistirmiyor.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import Config, DecompilersConfig
from karadul.decompilers import (
    AngrBackend,
    DecompiledFunction,
    DecompileResult,
    DecompilerBackend,
    GhidraBackend,
    available_backends,
    create_backend,
)
from karadul.decompilers.ghidra_backend import GhidraBackend as _GB


# ---------------------------------------------------------------------------
# base.py — dataclass + Protocol
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_decompile_result_dataclass(self) -> None:
        result = DecompileResult(
            functions=[],
            call_graph={},
            strings=[],
            errors=[],
            backend_name="ghidra",
            duration_seconds=1.5,
        )
        assert result.backend_name == "ghidra"
        assert result.duration_seconds == pytest.approx(1.5)
        assert result.functions == []
        assert result.call_graph == {}

    def test_decompiled_function_fields(self) -> None:
        func = DecompiledFunction(
            address="0x1000",
            name="main",
            pseudocode="int main(){return 0;}",
            calls=["0x2000", "0x3000"],
            backend_specific={"size": 42},
        )
        assert func.address == "0x1000"
        assert func.name == "main"
        assert "return 0" in func.pseudocode
        assert len(func.calls) == 2
        assert func.backend_specific["size"] == 42

    def test_decompiled_function_default_calls(self) -> None:
        func = DecompiledFunction(address="0x1", name="f", pseudocode="")
        assert func.calls == []
        assert func.backend_specific is None


# ---------------------------------------------------------------------------
# Protocol runtime check
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_protocol_runtime_check_ghidra(self) -> None:
        config = Config()
        backend = GhidraBackend(config)
        assert isinstance(backend, DecompilerBackend)

    def test_protocol_runtime_check_angr(self) -> None:
        config = Config()
        backend = AngrBackend(config)
        assert isinstance(backend, DecompilerBackend)


# ---------------------------------------------------------------------------
# GhidraBackend
# ---------------------------------------------------------------------------


class TestGhidraBackend:
    def test_ghidra_backend_name(self) -> None:
        config = Config()
        backend = GhidraBackend(config)
        assert backend.name == "ghidra"

    def test_ghidra_backend_supports_platforms(self) -> None:
        config = Config()
        backend = GhidraBackend(config)
        assert backend.supports_platform("macho")
        assert backend.supports_platform("elf")
        assert backend.supports_platform("pe")
        assert backend.supports_platform("raw")
        assert not backend.supports_platform("unknown_platform")

    def test_ghidra_backend_is_available_delegates(self) -> None:
        """is_available() GhidraHeadless'e delege eder."""
        config = Config()
        backend = GhidraBackend(config)
        fake = MagicMock()
        fake.is_available.return_value = True
        backend._ghidra = fake

        assert backend.is_available() is True
        fake.is_available.assert_called_once()

    def test_ghidra_to_standard_result_conversion(self) -> None:
        """Ghidra dict sonucu DecompileResult'a cevrilir."""
        ghidra_dict = {
            "success": True,
            "ghidra_log": "OK: 10 functions\nWARN: string extraction partial",
            "duration_seconds": 2.3,
            "mode": "pyghidra",
            "scripts_output": {
                "functions": {
                    "total": 2,
                    "functions": [
                        {
                            "name": "main",
                            "address": "0x100003abc",
                            "size": 120,
                            "param_count": 2,
                            "return_type": "int",
                            "is_thunk": False,
                            "is_external": False,
                            "calling_convention": "__cdecl",
                            "parameters": [],
                            "source": "USER_DEFINED",
                        },
                        {
                            "name": "helper",
                            "address": "0x100003def",
                            "size": 50,
                            "param_count": 1,
                            "return_type": "void",
                            "is_thunk": False,
                            "is_external": False,
                            "calling_convention": "__cdecl",
                            "parameters": [],
                            "source": "DEFAULT",
                        },
                    ],
                },
                "call_graph": {
                    "nodes": {
                        "0x100003abc": {
                            "name": "main",
                            "callers": [],
                            "callees": [{"name": "helper", "address": "0x100003def"}],
                        },
                        "0x100003def": {
                            "name": "helper",
                            "callers": [],
                            "callees": [],
                        },
                    },
                    "edges": [],
                },
                "strings": {
                    "total": 1,
                    "strings": [
                        {
                            "address": "0x200000000",
                            "value": "Hello",
                            "length": 5,
                            "type": "string",
                            "function": "main",
                        },
                    ],
                },
                "decompiled": {
                    "success": 2,
                    "total_attempted": 2,
                    "decompiled_dir": None,
                },
            },
        }

        result = _GB._to_standard_result(ghidra_dict, duration_seconds=2.3)

        assert isinstance(result, DecompileResult)
        assert result.backend_name == "ghidra"
        assert result.duration_seconds == pytest.approx(2.3)
        assert len(result.functions) == 2
        main = next(f for f in result.functions if f.name == "main")
        assert main.address == "0x100003abc"
        assert main.calls == ["0x100003def"]
        assert main.backend_specific["size"] == 120
        assert main.backend_specific["return_type"] == "int"
        assert result.call_graph["0x100003abc"] == ["0x100003def"]
        assert result.call_graph["0x100003def"] == []
        assert len(result.strings) == 1
        assert result.strings[0]["addr"] == "0x200000000"
        assert result.strings[0]["value"] == "Hello"
        # WARN satiri errors'a alinir, OK alinmaz
        assert any("WARN" in e for e in result.errors)
        assert not any("OK:" in e for e in result.errors)

    def test_ghidra_to_standard_result_empty_scripts_output(self) -> None:
        """scripts_output bos ise sonuc bos ama saglam olur."""
        result = _GB._to_standard_result(
            {"success": False, "scripts_output": {}, "ghidra_log": ""},
            duration_seconds=0.1,
        )
        assert result.functions == []
        assert result.call_graph == {}
        assert result.strings == []
        assert result.errors == []
        assert result.backend_name == "ghidra"

    def test_ghidra_to_standard_result_missing_keys(self) -> None:
        """scripts_output anahtarlari yoksa bile cokmez."""
        result = _GB._to_standard_result({}, duration_seconds=0.0)
        assert isinstance(result, DecompileResult)
        assert result.backend_name == "ghidra"


# ---------------------------------------------------------------------------
# AngrBackend
# ---------------------------------------------------------------------------


class TestAngrBackend:
    def test_angr_backend_name(self) -> None:
        config = Config()
        backend = AngrBackend(config)
        assert backend.name == "angr"

    def test_angr_backend_supports_platforms(self) -> None:
        config = Config()
        backend = AngrBackend(config)
        assert backend.supports_platform("macho")
        assert backend.supports_platform("elf")
        assert backend.supports_platform("pe")
        assert not backend.supports_platform("raw")
        assert not backend.supports_platform("coff")

    def test_angr_backend_availability_when_not_installed(self) -> None:
        """angr kurulu degilse is_available False doner.

        Test: sys.modules'a None mock koyarak ImportError tetikle.
        """
        config = Config()
        backend = AngrBackend(config)
        # angr gercek kuruluysa bu test False olmaz -- atla.
        try:
            import angr  # noqa: F401
            pytest.skip("angr gercekten kurulu, ImportError simule edilemez")
        except ImportError:
            assert backend.is_available() is False

    def test_angr_decompile_raises_when_unavailable(self) -> None:
        """angr kurulu degilse decompile() RuntimeError atar."""
        config = Config()
        backend = AngrBackend(config)
        try:
            import angr  # noqa: F401
            pytest.skip("angr kurulu, hata simule edilemez")
        except ImportError:
            with pytest.raises(RuntimeError, match="angr kurulu degil"):
                backend.decompile(Path("/tmp/nonexistent"), Path("/tmp"))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class TestFactory:
    def test_factory_creates_ghidra_default(self) -> None:
        config = Config()
        backend = create_backend(config)
        assert isinstance(backend, GhidraBackend)
        assert backend.name == "ghidra"

    def test_factory_creates_angr_when_configured(self) -> None:
        config = Config()
        config.decompilers.primary_backend = "angr"
        backend = create_backend(config)
        assert isinstance(backend, AngrBackend)
        assert backend.name == "angr"

    def test_factory_explicit_name_override(self) -> None:
        """name parametresi config'i override eder."""
        config = Config()
        assert config.decompilers.primary_backend == "ghidra"
        backend = create_backend(config, name="angr")
        assert isinstance(backend, AngrBackend)

    def test_factory_unknown_backend_raises(self) -> None:
        config = Config()
        with pytest.raises(ValueError, match="Bilinmeyen decompiler backend"):
            create_backend(config, name="ida")

    def test_factory_available_backends(self) -> None:
        backends = available_backends()
        assert "ghidra" in backends
        assert "angr" in backends
        assert backends == sorted(backends)


# ---------------------------------------------------------------------------
# Config entegrasyonu
# ---------------------------------------------------------------------------


class TestConfigIntegration:
    def test_decompilers_config_defaults(self) -> None:
        dc = DecompilersConfig()
        assert dc.primary_backend == "ghidra"
        assert dc.enable_parallel_decomp is False
        assert dc.secondary_backend is None

    def test_config_has_decompilers_field(self) -> None:
        config = Config()
        assert hasattr(config, "decompilers")
        assert isinstance(config.decompilers, DecompilersConfig)
        assert config.decompilers.primary_backend == "ghidra"

    def test_config_from_dict_parses_decompilers(self) -> None:
        """YAML'dan decompilers bolumu okunur."""
        data = {
            "decompilers": {
                "primary_backend": "angr",
                "enable_parallel_decomp": True,
                "secondary_backend": "ghidra",
            }
        }
        config = Config._from_dict(data)
        assert config.decompilers.primary_backend == "angr"
        assert config.decompilers.enable_parallel_decomp is True
        assert config.decompilers.secondary_backend == "ghidra"
