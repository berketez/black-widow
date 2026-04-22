"""Testler — StructLayoutSolver.solve_parallel (v1.10.0 Batch 6D FIX 5 full).

Kapsam:
    - Tek component -> sequential fallback (spawn overhead engellendi).
    - Coklu component paralel cozulup merge ediliyor.
    - Oversized component skip + diger component'ler cozuluyor.
    - Worker timeout -> graceful degradation (unknown dolduruluyor).
    - ``enable_parallel_solve=False`` -> sequential solve_from_raw.
    - Determinizm: ayni girdi -> ayni sonuc (aynen pipeline step).
    - find_connected_components: disjoint family -> farkli component.
    - partition_accesses_by_component: orphan access'ler dogru ayrilir.
"""

from __future__ import annotations

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery import (
    AliasingAnalyzer,
    MemoryAccess,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
    StructLayoutSolver,
)


def _enabled_cfg(**kwargs) -> ComputationConfig:
    params = {"enable_computation_struct_recovery": True}
    params.update(kwargs)
    return ComputationConfig(**params)


# ---------------------------------------------------------------------------
# 1) find_connected_components / partition_accesses_by_component
# ---------------------------------------------------------------------------

def test_components_empty_classes() -> None:
    analyzer = AliasingAnalyzer()
    assert analyzer.find_connected_components([]) == []


def test_components_disjoint_families() -> None:
    """Farkli type_family -> farkli component.

    T ve U ailelerinden iki class, variable paylasmiyor -> iki component.
    """
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q", "r", "s"],
        must_alias=[],
        type_hints={"p": "T", "q": "T", "r": "U", "s": "U"},
    )
    # 4 class (p, q, r, s herbiri ayri instance) ama 2 family.
    comps = analyzer.find_connected_components(classes)
    # Ayni family'deki class'lar ayni component, farkli family ayri
    # component -> 2 component.
    assert len(comps) == 2
    # Her component 2 class icerir.
    assert sorted(len(c) for c in comps) == [2, 2]


def test_components_same_family_couples() -> None:
    """Ayni type_family'deki iki class -> ayni component (H4 birbirine baglar)."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q"],
        must_alias=[],
        type_hints={"p": "T", "q": "T"},
    )
    comps = analyzer.find_connected_components(classes)
    assert len(comps) == 1
    assert len(comps[0]) == 2


def test_components_unknown_family_are_unique() -> None:
    """Type-hint'siz her class kendi __unknown_<hash>__ family'sine duser -> her biri ayri component."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q", "r"],
        must_alias=[],
        type_hints={},  # hepsi unknown
    )
    comps = analyzer.find_connected_components(classes)
    # 3 class, hepsi farkli __unknown_ family -> 3 component.
    assert len(comps) == 3


def test_partition_accesses_and_orphans() -> None:
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q"],
        must_alias=[],
        type_hints={"p": "T", "q": "U"},
    )
    comps = analyzer.find_connected_components(classes)
    accesses = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("q", 0, 4),
        MemoryAccess("orphan", 0, 4),  # hic bir class'ta yok
    ]
    per_cls, per_acc, orphans = analyzer.partition_accesses_by_component(
        classes, comps, accesses,
    )
    assert len(per_cls) == 2
    assert len(per_acc) == 2
    total_in_comps = sum(len(a) for a in per_acc)
    assert total_in_comps == 2
    assert len(orphans) == 1
    assert orphans[0].var_name == "orphan"


# ---------------------------------------------------------------------------
# 2) solve_parallel — davranis testleri
# ---------------------------------------------------------------------------

def test_solve_parallel_single_component_falls_back() -> None:
    """Tek component -> sequential fallback (spawn overhead engellenmesi).

    Davranissal test: sonuc dogru olmali. Spawn sayisini direkt olcmuyoruz
    ama tek component icin ``_PARALLEL_MIN_COMPONENTS=2`` nedeniyle
    ProcessPool YARATILMADAN solve_from_raw'a duser.
    """
    cfg = _enabled_cfg(enable_parallel_solve=True)
    solver = StructLayoutSolver(cfg)
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 8, 4),
    ]
    cand = StructCandidate(
        "T_12B", 12,
        [StructField(0, 4), StructField(4, 4), StructField(8, 4)],
    )
    # solve_parallel sadece variables+must_alias+type_hints aliyor; adaylari
    # kendi sentezliyor. Bu test sequential'a dusecek bir senaryo.
    result = solver.solve_parallel(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
    )
    assert isinstance(result, RecoveredStructLayout)
    assert 0.0 <= result.confidence <= 1.0
    # Fallback solve_from_raw cagriyor, struct family T cozulmus olmali.
    assert "T" in result.assigned_structs
    del cand  # unused warning bastir


def test_solve_parallel_multiple_components() -> None:
    """3 disjoint component -> paralel cozulup merge ediliyor.

    Her biri ayri type_family, disjoint variable -> 3 component.
    Tum access'ler cozulmus olmali (toy adaylar).
    """
    cfg = _enabled_cfg(
        enable_parallel_solve=True,
        max_parallel_workers=3,
        component_timeout_s=30.0,
    )
    solver = StructLayoutSolver(cfg)
    accs = [
        # 3 farkli family, herbirinde 2 access.
        MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 4), MemoryAccess("q", 4, 4),
        MemoryAccess("r", 0, 4), MemoryAccess("r", 4, 4),
    ]
    result = solver.solve_parallel(
        accesses=accs,
        variables=["p", "q", "r"],
        type_hints={"p": "T", "q": "U", "r": "V"},
    )
    assert isinstance(result, RecoveredStructLayout)
    # 3 family hepsi cozulmus olmali.
    assert set(result.assigned_structs.keys()) == {"T", "U", "V"}
    # Confidence yuksek (sentezlenmis adaylar tam sigacagindan 1.0 beklenir).
    assert result.confidence == pytest.approx(1.0)
    assert result.unknown_accesses == []


def test_solve_parallel_disabled_falls_back_to_sequential() -> None:
    """enable_parallel_solve=False -> solve_from_raw direkt cagrilir."""
    cfg = _enabled_cfg(enable_parallel_solve=False)
    solver = StructLayoutSolver(cfg)
    accs = [
        MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 4), MemoryAccess("q", 4, 4),
    ]
    result = solver.solve_parallel(
        accesses=accs,
        variables=["p", "q"],
        type_hints={"p": "T", "q": "U"},
    )
    assert isinstance(result, RecoveredStructLayout)
    assert result.confidence == pytest.approx(1.0)
    # Hem T hem U cozulmus olmali.
    assert "T" in result.assigned_structs
    assert "U" in result.assigned_structs


def test_solve_parallel_oversized_component_skipped() -> None:
    """>500 variable'li component skip, digerleri cozulur.

    Cap _MAX_COMPONENT_VARIABLES'i test suresince dusurup 'oversized'
    senaryosunu tetikliyoruz.
    """
    from karadul.computation.struct_recovery import solver as solver_mod

    original_cap = solver_mod._MAX_COMPONENT_VARIABLES
    try:
        # 3 variable'i 'oversized' kabul et (cap=2).
        solver_mod._MAX_COMPONENT_VARIABLES = 2

        cfg = _enabled_cfg(
            enable_parallel_solve=True,
            max_parallel_workers=2,
        )
        solver = StructLayoutSolver(cfg)
        # Component 1 (T): 3 variable (oversized, skip).
        # Component 2 (U): 1 variable (safe).
        # Component 3 (V): 1 variable (safe).
        accs = [
            MemoryAccess("a", 0, 4), MemoryAccess("b", 4, 4),
            MemoryAccess("c", 0, 4),
            MemoryAccess("q", 0, 4), MemoryAccess("q", 4, 4),
            MemoryAccess("r", 0, 4), MemoryAccess("r", 4, 4),
        ]
        # a, b, c hepsi T ailesinden ama ayri instance -> 3 class ama ayni
        # component (family birlestiriyor). Toplam variable = 3 > cap=2.
        result = solver.solve_parallel(
            accesses=accs,
            variables=["a", "b", "c", "q", "r"],
            type_hints={"a": "T", "b": "T", "c": "T", "q": "U", "r": "V"},
        )
        # T atanmamali (oversized skip); U ve V atanmali.
        assert "T" not in result.assigned_structs
        assert "U" in result.assigned_structs
        assert "V" in result.assigned_structs
        # Oversized access'ler unknown'da.
        unknown_names = {a.var_name for a in result.unknown_accesses}
        assert "a" in unknown_names
        assert "b" in unknown_names
        assert "c" in unknown_names
    finally:
        solver_mod._MAX_COMPONENT_VARIABLES = original_cap


def test_solve_parallel_feature_flag_off() -> None:
    """enable_computation_struct_recovery=False -> empty layout."""
    cfg = ComputationConfig(enable_computation_struct_recovery=False)
    solver = StructLayoutSolver(cfg)
    accs = [MemoryAccess("p", 0, 4), MemoryAccess("q", 0, 4)]
    result = solver.solve_parallel(
        accesses=accs,
        variables=["p", "q"],
        type_hints={"p": "T", "q": "U"},
    )
    assert result.assigned_structs == {}
    assert result.unknown_accesses == []
    assert result.confidence == pytest.approx(1.0)


def test_solve_parallel_empty_input() -> None:
    """Bos input -> empty layout, confidence=1.0."""
    cfg = _enabled_cfg(enable_parallel_solve=True)
    solver = StructLayoutSolver(cfg)
    result = solver.solve_parallel(accesses=[])
    assert result.assigned_structs == {}
    assert result.unknown_accesses == []
    assert result.confidence == pytest.approx(1.0)


def test_solve_parallel_deterministic() -> None:
    """Ayni input -> ayni sonuc (iki kez calistirip karsilastir).

    Deterministik davranis kritik — CI'da re-run'lar, cache karsilastirma
    icin gerekli. Paralel scheduling'in sonucu ETKILEMEMESI gerekir
    cunku component'ler birbirinden bagimsiz.
    """
    cfg = _enabled_cfg(
        enable_parallel_solve=True,
        max_parallel_workers=2,
    )
    accs = [
        MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 4), MemoryAccess("q", 4, 4),
        MemoryAccess("r", 0, 4), MemoryAccess("r", 4, 4),
    ]
    hints = {"p": "T", "q": "U", "r": "V"}

    solver1 = StructLayoutSolver(cfg)
    r1 = solver1.solve_parallel(
        accesses=accs, variables=["p", "q", "r"], type_hints=hints,
    )
    solver2 = StructLayoutSolver(cfg)
    r2 = solver2.solve_parallel(
        accesses=accs, variables=["p", "q", "r"], type_hints=hints,
    )
    assert set(r1.assigned_structs.keys()) == set(r2.assigned_structs.keys())
    assert r1.confidence == pytest.approx(r2.confidence)
    # Atanan adaylar ayni olmali (adlar).
    for fam in r1.assigned_structs:
        assert r1.assigned_structs[fam].name == r2.assigned_structs[fam].name


def test_solve_parallel_matches_sequential_result() -> None:
    """Paralel solve ciktisi sequential solve_from_raw ile ayni olmali.

    Ayni access'ler icin hem solve_parallel hem solve_from_raw cagirilir;
    ikisi de ayni struct atamasini + confidence'i uretmeli.
    """
    cfg_par = _enabled_cfg(enable_parallel_solve=True, max_parallel_workers=2)
    cfg_seq = _enabled_cfg(enable_parallel_solve=False)
    accs = [
        MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 4), MemoryAccess("q", 4, 4),
    ]
    hints = {"p": "T", "q": "U"}

    r_par = StructLayoutSolver(cfg_par).solve_parallel(
        accesses=accs, variables=["p", "q"], type_hints=hints,
    )
    r_seq = StructLayoutSolver(cfg_seq).solve_from_raw(
        accesses=accs, variables=["p", "q"], type_hints=hints,
    )
    # Ayni confidence.
    assert r_par.confidence == pytest.approx(r_seq.confidence)
    # Ayni family seti.
    assert set(r_par.assigned_structs.keys()) == set(r_seq.assigned_structs.keys())


def test_config_validation_negative_timeout() -> None:
    """component_timeout_s <= 0 -> ValueError."""
    with pytest.raises(ValueError):
        ComputationConfig(component_timeout_s=0.0)
    with pytest.raises(ValueError):
        ComputationConfig(component_timeout_s=-1.0)


def test_config_validation_invalid_workers() -> None:
    """max_parallel_workers < 1 -> ValueError (None OK)."""
    with pytest.raises(ValueError):
        ComputationConfig(max_parallel_workers=0)
    # None geçerli (auto).
    cfg = ComputationConfig(max_parallel_workers=None)
    assert cfg.max_parallel_workers is None
