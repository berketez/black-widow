"""TypeRecoveryConsumerStep testleri.

P13b / BORU-14 (b): adım üreticilerinden (PDB / BN / TRex) sonra koşar ve yalnız onların
getirdiğini sayar. Eskiden ürettiği ``consumed_symbols`` / ``consumed_types``'ı okuyan yoktu;
üretimleri kaldırıldı (öncelik seçimi testleri onlarla birlikte gitti; adlar birleştiricide aday
olur: ``tests/test_p13b_kanallar.py``). Koşucu sırası: ``tests/test_p13b_tuketici.py``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

# Step import: registry'e kayit yan etkisi icin
from karadul.pipeline.steps import type_recovery_consumer  # noqa: F401
from karadul.pipeline.steps.type_recovery_consumer import (
    PRODUCER_ARTIFACTS,
    TypeRecoveryConsumerStep,
)


def _make_ctx(artifacts: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        pipeline_context=SimpleNamespace(config=SimpleNamespace(), metadata={}),
        stats={}, errors=[], artifacts=artifacts,
    )


class TestTypeRecoveryConsumerStep:

    def test_no_artifacts_no_data_status(self) -> None:
        ctx = _make_ctx({"binary_for_byte_match": Path("/tmp/fake")})
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]
        assert result == {"type_recovery_status": "no-data"}
        assert ctx.stats["type_recovery_consumer_status"] == "no-data"
        assert ctx.stats["type_recovery_inputs"]["pdb"] == {
            "status": None, "symbols": 0, "types": 0}

    def test_counts_every_source(self) -> None:
        ctx = _make_ctx({
            "pdb_symbols": [{"name": "WinMain", "address": 0x1000}, {"name": "x"}],
            "pdb_types": [{"name": "T"}],
            "pdb_status": "ok",
            "bn_functions": [{"name": "f"}],
            "bn_types": [],
            "bn_status": "ok",
            "trex_structs": [{"name": "S"}, "bozuk"],
            "trex_status": "ok",
        })
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]
        assert result == {"type_recovery_status": "active"}
        assert ctx.stats["type_recovery_inputs"] == {
            "pdb": {"status": "ok", "symbols": 2, "types": 1},
            "bn": {"status": "ok", "functions": 1, "types": 0},
            "trex": {"status": "ok", "structs": 1},
        }

    def test_status_only_without_data_is_no_data(self) -> None:
        ctx = _make_ctx({"pdb_status": "no_pdb_file", "trex_status": "no_lifted_il",
                         "bn_status": "disabled", "pdb_symbols": []})
        result = TypeRecoveryConsumerStep().run(ctx)  # type: ignore[arg-type]
        assert result["type_recovery_status"] == "no-data"
        assert ctx.stats["type_recovery_inputs"]["trex"]["status"] == "no_lifted_il"

    def test_idempotent_run(self) -> None:
        arts = {"pdb_symbols": [{"name": "a", "address": 1}], "pdb_status": "ok"}
        r1 = TypeRecoveryConsumerStep().run(_make_ctx(arts))  # type: ignore[arg-type]
        r2 = TypeRecoveryConsumerStep().run(_make_ctx(arts))  # type: ignore[arg-type]
        assert r1 == r2


class TestRegistryAndContract:

    def test_step_registered(self) -> None:
        from karadul.pipeline.registry import get_step

        spec = get_step("type_recovery_consumer")
        assert spec.name == "type_recovery_consumer"
        assert "binary_for_byte_match" in spec.requires
        assert list(spec.produces) == ["type_recovery_status"]

    def test_requires_every_producer_artifact(self) -> None:
        """Üreticilerin yapıtları requires'ta: koşucu tüketiciyi onlardan sonra koşturur."""
        from karadul.pipeline.registry import get_step

        spec = get_step("type_recovery_consumer")
        for name in ("pdb_symbols", "bn_functions", "trex_structs"):
            assert name in spec.requires
        assert set(PRODUCER_ARTIFACTS) <= set(spec.requires)
        for producer in ("pdb_symbol_recovery", "binaryninja_analysis", "trex_struct_recovery"):
            assert set(get_step(producer).produces) & set(PRODUCER_ARTIFACTS)
