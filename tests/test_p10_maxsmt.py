"""P10 kalem 1 (BORU-04): MaxSMT yapı adayları yapı kurtarma motoruna adım tarafından iletilir.

Önceden adayları motora ileten tek yol ``stages.py``'deki "eski monolit" kopyaydı (çözücüyü
ikinci kez koşturuyordu); ``struct_recovery`` adımı ``recovered_struct_candidates``'i hiç
okumuyordu. Bu testler adım yolunu kilitler: blok silindiğinde ``--maxsmt-struct`` çalışmaya
devam etmeli.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery import (
    MemoryAccess,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
)
from karadul.pipeline.registry import get_step
from karadul.pipeline.runner import PipelineRunner
from karadul.pipeline.steps.struct_recovery import maxsmt_structs_for_engine


def _layout(name: str = "cand_0") -> RecoveredStructLayout:
    cand = StructCandidate(
        name=name, size=16,
        fields=[StructField(offset=0, size=8, type_hint="int64"),
                StructField(offset=8, size=4, type_hint="int32")],
    )
    return RecoveredStructLayout(
        classes=[], assigned_structs={"fam_a": cand}, unknown_accesses=[],
        confidence=1.0, solver_time_seconds=0.0,
    )


class TestRegistry:
    def test_struct_recovery_requires_maxsmt_artifacts(self) -> None:
        spec = get_step("struct_recovery")
        assert "recovered_struct_candidates" in spec.requires
        assert "computation_struct_result" in spec.requires

    def test_phase2_order_maxsmt_before_struct_recovery(self) -> None:
        runner = PipelineRunner(steps=[
            "feedback_loop", "computation_struct_recovery", "struct_recovery",
        ])
        levels = [[s.name for s in lv] for lv in runner._topological_levels(runner._specs)]
        idx = {n: i for i, lv in enumerate(levels) for n in lv}
        assert idx["computation_struct_recovery"] < idx["struct_recovery"]


class TestConversion:
    def test_per_function_keys_and_types(self) -> None:
        out = maxsmt_structs_for_engine({"FUN_00101000": _layout(), "main": _layout()}, [])
        assert [d["source_functions"] for d in out] == [["FUN_00101000"], ["main"]]
        # motorun okuduğu anahtarlar (eski stages.py kopyası size/type_hint yazıyordu)
        assert all(d["total_size"] == 16 for d in out)
        assert out[0]["fields"][0]["type"] == "undefined8"
        assert out[0]["fields"][1]["type"] == "undefined4"
        assert out[0]["fields"][1]["offset"] == 8
        # aynı aday adı iki fonksiyonda çakışmaz (motor aynı adlı ikinciyi atlar)
        assert len({d["name"] for d in out}) == 2

    def test_flat_candidates_without_per_fn(self) -> None:
        cand = _layout().assigned_structs["fam_a"]
        out = maxsmt_structs_for_engine(None, [cand])
        assert len(out) == 1 and out[0]["source_functions"] == []
        assert out[0]["total_size"] == 16

    def test_flag_off_empty(self) -> None:
        assert maxsmt_structs_for_engine(None, []) == []


@pytest.fixture
def phase2(tmp_path: Path, monkeypatch):
    """Bayrak açık; çıkarıcı ve çözücü sahte (z3 gerekmez, çağrı sayılır)."""
    import karadul.computation.struct_recovery as sr_pkg
    import karadul.pipeline.steps.computation_struct_recovery as csr

    calls: list[int] = []

    class FakeSolver:
        def __init__(self, cfg) -> None:
            pass

        def solve_from_raw(self, accesses, max_time_seconds=None):
            calls.append(len(accesses))
            return _layout()

        solve_parallel = solve_from_raw

    monkeypatch.setattr(sr_pkg, "StructLayoutSolver", FakeSolver)
    monkeypatch.setattr(csr, "_extract_accesses_per_function", lambda _p: {
        "FUN_00101000": [MemoryAccess(var_name="v", offset=0, width=8),
                         MemoryAccess(var_name="v", offset=8, width=4)],
    })

    dec = tmp_path / "typed"
    dec.mkdir()
    (dec / "FUN_00101000.c").write_text(
        "void FUN_00101000(long param_1)\n{\n  return;\n}\n", encoding="utf-8")
    rec = tmp_path / "reconstructed"
    rec.mkdir()
    pc = MagicMock()
    pc.metadata = {}
    pc.config = SimpleNamespace(
        computation=ComputationConfig(enable_computation_struct_recovery=True),
        binary_reconstruction=SimpleNamespace(enable_struct_recovery=True),
        pipeline=SimpleNamespace(parallel_steps=False, parallel_max_workers=None),
    )
    pc.workspace.get_stage_dir = MagicMock(return_value=rec)
    seed = {
        "pcode_result": object(),
        "final_decompiled_dir": dec,
        "functions_json_path": tmp_path / "f.json",
        "ghidra_types_json_path": tmp_path / "gt.json",
        "call_graph_json_path": tmp_path / "cg.json",
        "updated_algo_result": None,
        "updated_eng_result": SimpleNamespace(success=True, algorithms=[]),
        "computation_result": None,
    }
    return SimpleNamespace(pc=pc, seed=seed, calls=calls, rec=rec)


class TestStepPath:
    def test_candidate_reaches_engine_report(self, phase2) -> None:
        runner = PipelineRunner(steps=["computation_struct_recovery", "struct_recovery"])
        ctx = runner.run(phase2.pc, seed_artifacts=phase2.seed)
        rapor = (phase2.rec / "struct_recovered" / "struct_recovery.json").read_text(
            encoding="utf-8")
        data = json.loads(rapor)
        adlar = {s["name"] for key in ("enriched_structs", "candidate_structs")
                 for s in data.get(key, [])}
        assert "maxsmt_FUN_00101000_cand_0" in adlar
        assert ctx.stats["struct_maxsmt_candidates_passed"] == 1
        # aday, kaynak fonksiyonu ve doğru boyutla motora girdi
        hepsi = [s for key in ("enriched_structs", "candidate_structs")
                 for s in data.get(key, [])]
        s = next(x for x in hepsi if x["name"] == "maxsmt_FUN_00101000_cand_0")
        assert s["total_size"] == 16
        assert s["source_functions"] == ["FUN_00101000"]

    def test_solver_called_once_per_function(self, phase2) -> None:
        runner = PipelineRunner(steps=["computation_struct_recovery", "struct_recovery"])
        runner.run(phase2.pc, seed_artifacts=phase2.seed)
        assert phase2.calls == [2]

    def test_flag_off_no_candidates(self, phase2) -> None:
        phase2.pc.config.computation = ComputationConfig(
            enable_computation_struct_recovery=False)
        runner = PipelineRunner(steps=["computation_struct_recovery", "struct_recovery"])
        ctx = runner.run(phase2.pc, seed_artifacts=phase2.seed)
        assert phase2.calls == []
        assert "struct_maxsmt_candidates_passed" not in ctx.stats
        rapor = phase2.rec / "struct_recovered" / "struct_recovery.json"
        assert not rapor.exists() or "maxsmt_" not in rapor.read_text(encoding="utf-8")
