"""P13b / BORU-14 (b): ``type_recovery_consumer`` üreticilerinden SONRA koşar; iki kip aynı.

Eski davranış (kulvar BORU-14 denemesi, burada yinelendi): tüketici yalnız
``binary_for_byte_match``'i ``requires`` ettiği için koşucu onu ``pdb_symbol_recovery`` ile aynı
düzeye koyuyordu; ``parallel_steps=True`` → üreticinin sembolünü görmüyor (``no-data``),
``False`` → görüyor (``active``). Ürettiği ``consumed_symbols`` / ``consumed_types``'ı da okuyan
yoktu.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.pipeline.registry import get_step
from karadul.pipeline.runner import PipelineRunner
from karadul.pipeline.steps import (  # noqa: F401 — kayıt yan etkisi
    binaryninja_analysis,
    pdb_symbol_recovery,
    trex_struct_recovery,
    type_recovery_consumer,
)
from karadul.pipeline.steps.pdb_symbol_recovery import PdbSymbolRecoveryStep

STEPS = [
    "pdb_symbol_recovery", "trex_struct_recovery", "binaryninja_analysis",
    "type_recovery_consumer",
]


def _pc(parallel: bool, tmp_path: Path):
    return SimpleNamespace(
        metadata={},
        target=SimpleNamespace(path=tmp_path / "hedef.exe", target_type="PE"),
        config=SimpleNamespace(
            pipeline=SimpleNamespace(parallel_steps=parallel, parallel_max_workers=None),
            binary_reconstruction=SimpleNamespace(
                enable_pdb=True, enable_trex=False, enable_binaryninja=False),
        ),
    )


@pytest.fixture
def fake_pdb(monkeypatch):
    def run(self, ctx):
        return {
            "pdb_symbols": [{"name": "WinMain", "address": 0x1000, "section": 1}],
            "pdb_types": [], "pdb_symbols_path": None, "pdb_types_path": None,
            "pdb_status": "ok",
        }
    monkeypatch.setattr(PdbSymbolRecoveryStep, "run", run)


def _run(parallel: bool, tmp_path: Path) -> dict:
    bin_path = tmp_path / "hedef.exe"
    bin_path.write_bytes(b"MZ")
    ctx = PipelineRunner(STEPS).run(
        _pc(parallel, tmp_path), seed_artifacts={"binary_for_byte_match": bin_path})
    return {
        "status": ctx.stats.get("type_recovery_consumer_status"),
        "inputs": ctx.stats.get("type_recovery_inputs"),
        "artifact": ctx.artifacts.get("type_recovery_status"),
    }


def test_consumer_sees_producer_in_both_modes(fake_pdb, tmp_path) -> None:
    par = _run(True, tmp_path)
    seq = _run(False, tmp_path)
    assert par["status"] == "active", par
    assert par == seq
    assert par["inputs"]["pdb"] == {"status": "ok", "symbols": 1, "types": 0}
    assert par["inputs"]["bn"]["status"] == "disabled"
    assert par["inputs"]["trex"]["status"] == "disabled"


def test_consumer_is_in_a_later_level_than_producers() -> None:
    specs = [get_step(n) for n in STEPS]
    levels = PipelineRunner._topological_levels(specs)
    level_of = {s.name: i for i, lvl in enumerate(levels) for s in lvl}
    for producer in STEPS[:3]:
        assert level_of["type_recovery_consumer"] > level_of[producer], levels


def test_no_unread_artifacts_produced() -> None:
    """Okuyanı olmayan ``consumed_symbols`` / ``consumed_types`` artık üretilmiyor."""
    spec = get_step("type_recovery_consumer")
    assert "consumed_symbols" not in spec.produces
    assert "consumed_types" not in spec.produces
