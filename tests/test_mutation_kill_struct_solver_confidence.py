"""Mutasyon-oldurucu test: solver.py oversized-component confidence formulu.

Faz-1 mutasyon denetimi 1 GERCEK deligi (tam-suite survived) buldu:

  C  solver.py:428  oversized-cap recursion dalinda:
       `confidence=(explained / total_accesses) if total_accesses else 0.0`
       -> `confidence=(1.0 if total_accesses else 0.0)`

Bu dal ancak bir alias-class > _MAX_COMPONENT_VARIABLES (500) oldugunda
tetiklenir; o component'in erisimleri "skipped" olur, geri kalanlar filtrelenip
RECURSIVE ``self.solve`` ile cozulur. Confidence = acilanan / TOPLAM erisim.

Z3'e bagli kalmamak icin RECURSIVE cagriyi (instance-level ``solve`` attribute)
deterministik bir stub ile araya giriyoruz; DIS cagri gercek kodu (satir 428
dahil) kosar. 4 erisimin 3'u acilir (stub unknown=[]), 1'i oversized-skip ->
confidence = 3/4 = 0.75.

Mutant `1.0 if ...` -> confidence 1.0 -> assert patlar (KILLED).

Kanit (mutation_probe, TUM suite):
  python scripts/mutation_probe.py --spec docs/mutation_specs.json \
      --id c_solver_oversized_confidence
"""
from __future__ import annotations

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery.solver import StructLayoutSolver
from karadul.computation.struct_recovery.types import (
    AliasClass,
    MemoryAccess,
    RecoveredStructLayout,
)


def test_oversized_recursion_confidence_is_explained_over_total() -> None:
    cfg = ComputationConfig(enable_computation_struct_recovery=True)
    solver = StructLayoutSolver(cfg)

    # 501 degiskenli component -> _MAX_COMPONENT_VARIABLES (500) asilir -> oversized.
    big = AliasClass(
        variables=[f"b{i}" for i in range(501)], type_family="F_BIG",
    )
    small = AliasClass(variables=["s0"], type_family="F_SMALL")

    # 4 erisim: 1'i oversized 'b0' (skip), 3'u 's0' (filtrelenip recursion'a gider).
    accesses = [
        MemoryAccess(var_name="b0", offset=0, width=4),
        MemoryAccess(var_name="s0", offset=0, width=4),
        MemoryAccess(var_name="s0", offset=4, width=4),
        MemoryAccess(var_name="s0", offset=8, width=4),
    ]

    # Recursive solve stub: 3 filtreli erisimi TAMAMEN acar (unknown=[]).
    stub_result = RecoveredStructLayout(
        classes=[small],
        assigned_structs={},
        unknown_accesses=[],
        confidence=1.0,
        solver_time_seconds=0.0,
    )

    # DIS cagri = gercek fonksiyon (satir 428'i kosar); IC (recursive) cagri = stub.
    real_solve = StructLayoutSolver.solve
    solver.solve = lambda **kw: stub_result  # type: ignore[method-assign]

    result = real_solve(
        solver,
        accesses=accesses,
        classes=[big, small],
        candidates=[],
    )

    # explained = total(4) - merged_unknown(0 stub + 1 skipped) = 3 ; 3/4 = 0.75
    assert result.confidence == pytest.approx(0.75), (
        f"oversized recursion confidence explained/total = 3/4 = 0.75 olmaliydi, "
        f"donen: {result.confidence}"
    )
