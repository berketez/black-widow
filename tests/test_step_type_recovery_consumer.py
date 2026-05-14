"""TypeRecoveryConsumerStep testleri (v1.15-B7).

Test kapsami:
    1. Tum artifact'ler yok -> graceful skip ("no-data")
    2. Sadece PDB sembol -> consumed_symbols PDB icerir
    3. PDB + BN cakismasi -> PDB kazanir (oncelik)
    4. PDB + BN + TRex hepsi -> PDB > BN > TRex priority
    5. Sembol formati: adres -> FUN_<hex> dogru
    6. Type birlesimi (consumed_types) -- PDB > BN > TRex
    7. is_thunk / is_imported BN fonksiyonlarinin SKIP edilmesi
    8. Stat'lar: total counts + per-source counts
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

# Step import: registry'e kayit yan etkisi icin
from karadul.pipeline.steps import type_recovery_consumer  # noqa: F401
from karadul.pipeline.steps.type_recovery_consumer import (
    TypeRecoveryConsumerStep,
    _camel_to_snake,
)


def _make_ctx(artifacts: dict[str, Any]) -> SimpleNamespace:
    """Step'in beklediği minimum stub ctx."""
    pc = SimpleNamespace(
        target=SimpleNamespace(path=Path("/tmp/fake_bin")),
        workspace=MagicMock(),
        config=SimpleNamespace(),
        metadata={},
    )
    ctx = SimpleNamespace(
        pipeline_context=pc,
        stats={},
        errors=[],
        artifacts=artifacts,
    )

    def _produce_artifact(key: str, value: Any) -> None:
        pass

    ctx.produce_artifact = _produce_artifact  # type: ignore[attr-defined]
    return ctx


class TestTypeRecoveryConsumerStep:
    """Step run() davranis testleri."""

    def test_no_artifacts_no_data_status(self) -> None:
        """Hicbir kaynak artifact'i yok -> status 'no-data'."""
        ctx = _make_ctx({"binary_for_byte_match": Path("/tmp/fake")})
        step = TypeRecoveryConsumerStep()
        result = step.run(ctx)  # type: ignore[arg-type]

        assert result["consumed_symbols"] == {}
        assert result["consumed_types"] == {}
        assert result["type_recovery_status"] == "no-data"
        assert ctx.stats["type_recovery_consumer_status"] == "no-data"

    def test_pdb_only_symbols_merge(self) -> None:
        """PDB sembolleri consumed_symbols'a girer."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "pdb_symbols": [
                {
                    "name": "WinMain",
                    "address": 0x401000,
                    "kind": "S_GPROC32",
                    "section": ".text",
                    "size": 100,
                    "type_index": 4096,
                },
                {
                    "name": "InitializeApp",
                    "address": "0x402000",
                    "kind": "S_GPROC32",
                    "section": ".text",
                },
            ],
        }
        ctx = _make_ctx(artifacts)
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]

        symbols = result["consumed_symbols"]
        assert "FUN_401000" in symbols
        assert "FUN_402000" in symbols
        assert symbols["FUN_401000"]["name"] == "WinMain"
        assert symbols["FUN_401000"]["source"] == "pdb"
        assert symbols["FUN_401000"]["confidence"] == pytest.approx(0.95)
        assert result["type_recovery_status"] == "active"
        assert ctx.stats["consumed_symbols_pdb"] == 2

    def test_pdb_priority_over_bn(self) -> None:
        """Ayni adrese hem PDB hem BN isim verirse PDB kazanir."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "pdb_symbols": [
                {"name": "real_main", "address": 0x401000},
            ],
            "bn_functions": [
                {
                    "name": "bn_guessed_main",
                    "address": 0x401000,
                    "is_thunk": False,
                    "is_imported": False,
                },
            ],
        }
        ctx = _make_ctx(artifacts)
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]

        sym = result["consumed_symbols"]["FUN_401000"]
        assert sym["name"] == "real_main"
        assert sym["source"] == "pdb"
        # Stats: bir tane PDB, BN sayisi 0 (cakisma yenildi)
        assert ctx.stats["consumed_symbols_pdb"] == 1
        assert ctx.stats["consumed_symbols_bn"] == 0

    def test_priority_pdb_bn_trex_full_chain(self) -> None:
        """3 kaynak birlikte: PDB > BN > TRex priority dogrulanir."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "pdb_symbols": [
                {"name": "pdb_only", "address": 0x401000},
            ],
            "bn_functions": [
                {"name": "bn_only", "address": 0x402000},
                # 0x401000'e BN da ekleyecek ama PDB kazanir
                {"name": "bn_loser", "address": 0x401000},
            ],
            "trex_structs": [
                # 0x402000'e TRex iddiali ama BN kazanir
                {
                    "name": "TrexLoser",
                    "function": "FUN_402000",
                    "fields": [],
                },
                # 0x403000'da yalniz TRex
                {
                    "name": "TrexWinner",
                    "function": "FUN_403000",
                    "fields": [],
                },
            ],
        }
        ctx = _make_ctx(artifacts)
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]

        symbols = result["consumed_symbols"]
        assert symbols["FUN_401000"]["source"] == "pdb"
        assert symbols["FUN_401000"]["name"] == "pdb_only"
        assert symbols["FUN_402000"]["source"] == "bn"
        assert symbols["FUN_402000"]["name"] == "bn_only"
        assert symbols["FUN_403000"]["source"] == "trex"
        assert symbols["FUN_403000"]["name"] == "trex_winner"

    def test_bn_thunk_and_imported_skipped(self) -> None:
        """is_thunk veya is_imported BN fonksiyonlari atlanır."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "bn_functions": [
                {"name": "real_func", "address": 0x401000},
                {"name": "thunk_x", "address": 0x402000, "is_thunk": True},
                {
                    "name": "imp_open", "address": 0x403000,
                    "is_imported": True,
                },
                # BN auto-name skip
                {"name": "sub_404000", "address": 0x404000},
                {"name": "FUN_405000", "address": 0x405000},
            ],
        }
        ctx = _make_ctx(artifacts)
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]

        symbols = result["consumed_symbols"]
        assert "FUN_401000" in symbols
        assert "FUN_402000" not in symbols  # thunk
        assert "FUN_403000" not in symbols  # imported
        assert "FUN_404000" not in symbols  # sub_ placeholder
        assert "FUN_405000" not in symbols  # FUN_ placeholder
        assert ctx.stats["consumed_symbols_bn"] == 1

    def test_consumed_types_priority(self) -> None:
        """consumed_types: PDB > BN > TRex."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "pdb_types": [
                {
                    "type_id": 4096,
                    "kind": "LF_STRUCTURE",
                    "name": "FileHandle",
                    "size": 24,
                    "fields": [{"name": "fd", "offset": 0}],
                },
            ],
            "bn_types": [
                {
                    "name": "FileHandle",     # cakisir, PDB kazanir
                    "kind": "struct",
                    "size": 16,
                    "fields": [],
                },
                {
                    "name": "Config",         # yalniz BN
                    "kind": "struct",
                    "size": 32,
                    "fields": [],
                },
            ],
            "trex_structs": [
                {
                    "name": "Config",         # BN kazanir
                    "function": "FUN_500000",
                    "fields": [],
                },
                {
                    "name": "TrexOnly",       # yalniz TRex
                    "function": "FUN_600000",
                    "fields": [],
                },
            ],
        }
        ctx = _make_ctx(artifacts)
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]

        types = result["consumed_types"]
        assert types["FileHandle"]["source"] == "pdb"
        assert types["FileHandle"]["size"] == 24
        assert types["Config"]["source"] == "bn"
        assert types["TrexOnly"]["source"] == "trex"

    def test_idempotent_run(self) -> None:
        """Step iki kez calistirilirsa ayni cikti dondurur."""
        artifacts = {
            "binary_for_byte_match": Path("/tmp/fake"),
            "pdb_symbols": [{"name": "f1", "address": 0x401000}],
        }
        step = TypeRecoveryConsumerStep()
        r1 = step.run(_make_ctx(artifacts))  # type: ignore[arg-type]
        r2 = step.run(_make_ctx(artifacts))  # type: ignore[arg-type]
        assert r1["consumed_symbols"] == r2["consumed_symbols"]
        assert r1["consumed_types"] == r2["consumed_types"]


class TestCamelToSnake:
    """_camel_to_snake helper."""

    def test_camel_case(self) -> None:
        assert _camel_to_snake("FooHandler") == "foo_handler"

    def test_single_word(self) -> None:
        assert _camel_to_snake("Parser") == "parser"

    def test_acronym_block(self) -> None:
        # Ardisik buyuk harfler arasinda underscore yok
        assert _camel_to_snake("ARGB32") == "argb32"

    def test_empty(self) -> None:
        assert _camel_to_snake("") == ""


class TestRegistryAndContract:
    """Registry kaydi ve produces sozlesmesi."""

    def test_step_registered(self) -> None:
        from karadul.pipeline.registry import get_step

        spec = get_step("type_recovery_consumer")
        assert spec.name == "type_recovery_consumer"
        assert "binary_for_byte_match" in spec.requires
        assert "consumed_symbols" in spec.produces
        assert "consumed_types" in spec.produces
        assert "type_recovery_status" in spec.produces

    def test_requires_does_not_force_optional_inputs(self) -> None:
        """Opsiyonel artifact'ler requires'a konmamis (graceful skip).

        Eger requires'a pdb_symbols/bn_functions/trex_structs koyulsaydi,
        runner her durumda RuntimeError firlatirdi.
        """
        from karadul.pipeline.registry import get_step

        spec = get_step("type_recovery_consumer")
        for forbidden in ("pdb_symbols", "bn_functions", "trex_structs"):
            assert forbidden not in spec.requires, (
                f"{forbidden} opsiyonel olmali, requires'ta olmamali"
            )
