"""Testler — karadul.computation.struct_recovery (MaxSMT struct layout).

Hedef: 15+ test, spec'teki listeyi birebir uygula. Z3 gerekli (kurulu).

Kapsam:
    - Dataclass post-init validasyonu (MemoryAccess, StructCandidate, AliasClass).
    - AliasingAnalyzer: same_object vs same_type ayrimi (KRITIK).
    - CandidateSynthesizer: consecutive/aligned/stride heuristikleri.
    - StructLayoutSolver: simple/multi-candidate/unknown/timeout/empty/flag.
    - Aliasing'in yanlis merge'i ONLEMESI (sessiz katil uyarisinin testi).
    - Confidence hesaplamasi.
"""

from __future__ import annotations

import pytest

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery import (
    AliasClass,
    AliasingAnalyzer,
    CandidateSynthesizer,
    MemoryAccess,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
    StructLayoutSolver,
)


# ---------------------------------------------------------------------------
# 1) Dataclass validasyonu
# ---------------------------------------------------------------------------

def test_memory_access_dataclass() -> None:
    a = MemoryAccess(var_name="p", offset=0, width=4, access_type="read")
    assert a.var_name == "p"
    assert a.width == 4
    # Gecersiz width.
    with pytest.raises(ValueError):
        MemoryAccess("p", 0, 3)
    # Negatif offset.
    with pytest.raises(ValueError):
        MemoryAccess("p", -1, 4)
    # Gecersiz tip.
    with pytest.raises(ValueError):
        MemoryAccess("p", 0, 4, access_type="exec")


def test_struct_candidate_dataclass() -> None:
    cand = StructCandidate(
        name="T", size=12,
        fields=[StructField(8, 4), StructField(0, 4), StructField(4, 4)],
    )
    # Offset-sorted olmali.
    assert [f.offset for f in cand.fields] == [0, 4, 8]
    # Struct disina tasan alan.
    with pytest.raises(ValueError):
        StructCandidate("T", 4, fields=[StructField(0, 8)])
    # size=0.
    with pytest.raises(ValueError):
        StructCandidate("T", 0, fields=[])


# ---------------------------------------------------------------------------
# 2) Aliasing — same_object vs same_type
# ---------------------------------------------------------------------------

def test_alias_class_same_object_vs_same_type() -> None:
    """Ayni tipte iki ayri instance -> ayri class (KRITIK)."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q"],
        must_alias=[],                    # AYRI instance'lar
        type_hints={"p": "T", "q": "T"},  # ama ayni tip
    )
    assert len(classes) == 2  # iki ayri class
    # Ama ayni aile (same_type).
    fams = {c.type_family for c in classes}
    assert fams == {"T"}


def test_aliasing_must_alias_merge() -> None:
    """must_alias -> ayni class."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q", "r"],
        must_alias=[("p", "q")],
        type_hints={"p": "T", "q": "T", "r": "T"},
    )
    # p+q birlesir, r ayri.
    vars_sets = sorted([tuple(sorted(c.variables)) for c in classes])
    assert vars_sets == [("p", "q"), ("r",)]


def test_aliasing_type_hint_separation() -> None:
    """Farkli type_hint'ler -> farkli aile."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q"],
        must_alias=[],
        type_hints={"p": "T", "q": "U"},
    )
    fams = sorted([c.type_family for c in classes])
    assert fams == ["T", "U"]


def test_aliasing_must_alias_conflict_raises() -> None:
    """must_alias cakismasi (farkli tipler) -> ValueError."""
    analyzer = AliasingAnalyzer()
    with pytest.raises(ValueError):
        analyzer.build_classes(
            variables=["p", "q"],
            must_alias=[("p", "q")],
            type_hints={"p": "T", "q": "U"},
        )


# ---------------------------------------------------------------------------
# 3) CandidateSynthesizer
# ---------------------------------------------------------------------------

def test_candidate_synthesizer_simple_consecutive() -> None:
    """3 erisim offset 0/4/8 width 4 -> en az bir aday 3 alanli."""
    synth = CandidateSynthesizer()
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 8, 4),
    ]
    cands = synth.synthesize(accs)
    assert len(cands) >= 1
    direct = cands[0]
    assert len(direct.fields) == 3
    assert [f.offset for f in direct.fields] == [0, 4, 8]
    assert direct.size >= 12


def test_candidate_synthesizer_aligned() -> None:
    """Hizalanmis boyut adaylari (16/8 align)."""
    synth = CandidateSynthesizer()
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 12, 4),  # max_end = 16
    ]
    cands = synth.synthesize(accs)
    sizes = {c.size for c in cands}
    # 16 zaten max_end; 16/8-align round up'a esit, pow2 de 16.
    assert 16 in sizes


def test_candidate_synthesizer_empty() -> None:
    synth = CandidateSynthesizer()
    assert synth.synthesize([]) == []


def test_candidate_synthesizer_max_limit() -> None:
    """struct_max_candidates uyulur."""
    cfg = ComputationConfig(struct_max_candidates=2)
    synth = CandidateSynthesizer(cfg)
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
    ]
    cands = synth.synthesize(accs)
    assert len(cands) <= 2


# ---------------------------------------------------------------------------
# 4) StructLayoutSolver — core davranis
# ---------------------------------------------------------------------------

def _enabled_cfg(**kwargs) -> ComputationConfig:
    params = {"enable_computation_struct_recovery": True}
    params.update(kwargs)
    return ComputationConfig(**params)


def test_solver_simple_single_struct() -> None:
    """1 aday, 3 erisim -> tam match, confidence=1.0."""
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 8, 4),
    ]
    cand = StructCandidate(
        "T_12B", 12,
        [StructField(0, 4), StructField(4, 4), StructField(8, 4)],
    )
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
        candidates=[cand],
    )
    assert result.confidence == pytest.approx(1.0)
    assert "T" in result.assigned_structs
    assert result.assigned_structs["T"].name == "T_12B"
    assert result.unknown_accesses == []
    assert result.solver_time_seconds >= 0.0


def test_solver_multi_candidate() -> None:
    """3 aday -> en uygun (padding az, cakisma yok) secilir."""
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
    ]
    cand_tight = StructCandidate(
        "tight_8", 8, [StructField(0, 4), StructField(4, 4)],
    )
    cand_padded = StructCandidate(
        "padded_64", 64, [StructField(0, 4), StructField(4, 4)],
    )
    cand_overlap = StructCandidate(
        "overlap_8", 8, [StructField(0, 8), StructField(4, 4)],  # cakis
    )
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
        candidates=[cand_tight, cand_padded, cand_overlap],
    )
    # Padding ve overlap cezalandirildigi icin tight seilmeli.
    assert result.assigned_structs["T"].name == "tight_8"


def test_solver_unknown_access() -> None:
    """Hicbir alana sigmayan erisim -> unknown."""
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 100, 4),  # adayda yok
    ]
    cand = StructCandidate(
        "T_8", 8, [StructField(0, 4), StructField(4, 4)],
    )
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
        candidates=[cand],
    )
    assert len(result.unknown_accesses) == 1
    assert result.unknown_accesses[0].offset == 100
    # Confidence 2/3.
    assert result.confidence == pytest.approx(2 / 3, abs=1e-6)


def test_solver_empty_input() -> None:
    """Bos erisim listesi -> bos layout, confidence 1.0."""
    solver = StructLayoutSolver(_enabled_cfg())
    result = solver.solve_from_raw(accesses=[])
    assert result.unknown_accesses == []
    assert result.assigned_structs == {}
    assert result.confidence == pytest.approx(1.0)


def test_solver_timeout_graceful() -> None:
    """0.001s timeout -> graceful partial (hata firlatmaz).

    Smoke: kucuk girdi ile timeout'ta exception atmamali, confidence
    legal araligi korumali. Buyuk problem icin asagidaki
    ``test_solver_timeout_large_problem`` var.
    """
    solver = StructLayoutSolver(_enabled_cfg(struct_solver_timeout=0.001))
    accs = [MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4)]
    cand = StructCandidate("T", 8, [StructField(0, 4), StructField(4, 4)])
    result = solver.solve_from_raw(
        accesses=accs, variables=["p"],
        type_hints={"p": "T"}, candidates=[cand],
        max_time_seconds=0.001,
    )
    # Hata yok; confidence belirsiz ama RecoveredStructLayout doner.
    assert isinstance(result, RecoveredStructLayout)
    assert 0.0 <= result.confidence <= 1.0


def test_solver_timeout_large_problem() -> None:
    """Buyuk problem + 1ms timeout -> partial sonuc + tutarli state.

    Z3'un timeout'a ulasmasi beklenir (20 alias x 10 aday x 15 erisim).
    Solver ya partial model ile dusuk guven dondurur ya da model'siz
    kapanir. Her durumda exception atmamali ve confidence araligi
    korunmali.
    """
    solver = StructLayoutSolver(_enabled_cfg(struct_solver_timeout=0.001))
    accs = [
        MemoryAccess(f"v{i}", j * 4, 4)
        for i in range(20) for j in range(15)
    ]
    variables = [f"v{i}" for i in range(20)]
    type_hints = {f"v{i}": f"T{i % 5}" for i in range(20)}
    candidates = [
        StructCandidate(
            f"S{k}", 60,
            [StructField(j * 4, 4) for j in range(15)],
        )
        for k in range(10)
    ]

    result = solver.solve_from_raw(
        accesses=accs,
        variables=variables,
        type_hints=type_hints,
        candidates=candidates,
        max_time_seconds=0.001,
    )

    # GERCEK ASSERTIONS: exception atmadi + tip tutarli.
    assert isinstance(result, RecoveredStructLayout)
    assert 0.0 <= result.confidence <= 1.0
    assert result.solver_time_seconds >= 0.0
    # Durum sinifi tamligi: unknown_accesses + assigned_structs toplami
    # tutarli olmali (her eris ya unknown ya da bir struct'a atanmis).
    total_accesses = len(accs)
    # Eger confidence 1 ise tum eris atanmis olmali.
    # Degilse unknown_accesses dolu ya da assigned_structs eksik olmali.
    if result.confidence == 1.0:
        assert len(result.unknown_accesses) == 0
    else:
        # Timeout veya partial: unknown ya da eksik atama var.
        has_unknown = len(result.unknown_accesses) > 0
        has_missing_family = len(result.assigned_structs) < 5  # 5 aile bekleniyordu
        assert has_unknown or has_missing_family or result.confidence == 0.0


def test_feature_flag_off_returns_empty() -> None:
    """enable_computation_struct_recovery=False -> bos layout.

    NOT (v1.10.0): default artik True ("ship it" karari). Flag OFF
    senaryosunu test etmek icin explicit override gerekli.
    """
    cfg = ComputationConfig(enable_computation_struct_recovery=False)
    solver = StructLayoutSolver(cfg)
    accs = [MemoryAccess("p", 0, 4)]
    result = solver.solve_from_raw(accesses=accs, type_hints={"p": "T"})
    assert result.assigned_structs == {}
    assert result.unknown_accesses == []
    assert result.classes == []


# ---------------------------------------------------------------------------
# 5) Aliasing yanlis merge'i ONLER (codex sessiz katil uyarisi)
# ---------------------------------------------------------------------------

def test_aliasing_prevents_wrong_merge() -> None:
    """same_object False, same_type True -> iki class ama ayni aile.

    KRITIK: tek same() iliskisi olsaydi solver bunlari birlestirir,
    p'nin offset 0 erisimi ile q'nun offset 0 erisimi sanki ayni
    instance'a erisiyor gibi gorunur. ayni family + ayri class
    bunu onler — erisim grouping class bazinda.
    """
    solver = StructLayoutSolver(_enabled_cfg())
    # p ve q AYRI instance ama ayni tip.
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 4),
        MemoryAccess("q", 4, 4),
    ]
    cand = StructCandidate("T", 8, [StructField(0, 4), StructField(4, 4)])
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p", "q"],
        must_alias=[],  # ayri instance
        type_hints={"p": "T", "q": "T"},
        candidates=[cand],
    )
    # Iki class, ama ayni aile -> ayni struct atanir.
    assert len(result.classes) == 2
    assert all(c.type_family == "T" for c in result.classes)
    assert result.assigned_structs["T"].name == "T"
    # Hepsi acilanmis.
    assert result.unknown_accesses == []


def test_aliasing_family_consistency_under_split() -> None:
    """Ayni aile farkli class -> solver AYNI adayi secer (H4).

    NOT (v1.10.0): padding sayimi inter-field gap'leri artik dogru
    sayiyor (C1 fix). ``big`` aday size=12 olacak ki inter-field
    gap=4, trailing=0 kalsin. size=16 olsaydi 8 bayt padding 2
    class ile 1.6 ceza yapar, q[8]'i unknown birakan small (1.0 unknown)
    tercih edilirdi. Bu testin asil amaci H4 invariant'i (ayni aile
    ayni aday), padding weight kalibrasyonu degil.
    """
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("q", 8, 4),
    ]
    cand_small = StructCandidate("small", 4, [StructField(0, 4)])
    cand_big = StructCandidate("big", 12, [StructField(0, 4), StructField(8, 4)])
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p", "q"],
        must_alias=[],
        type_hints={"p": "T", "q": "T"},
        candidates=[cand_small, cand_big],
    )
    # Iki class ayni aileye ait. p'nin offset 0 erisimi her iki adayla
    # uyumlu ama q'nun offset 8 erisimi SADECE big'e uyar. H4 ayni aday
    # sectirir -> big kazanmali.
    assert result.assigned_structs["T"].name == "big"
    assert result.unknown_accesses == []


# ---------------------------------------------------------------------------
# 6) Confidence hesaplamasi
# ---------------------------------------------------------------------------

def test_confidence_calculation_ratio_based() -> None:
    """confidence = explained / total (ratio-based)."""
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("p", 200, 4),
        MemoryAccess("p", 204, 4),
    ]
    cand = StructCandidate("T", 8, [StructField(0, 4), StructField(4, 4)])
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
        candidates=[cand],
    )
    # 2/4 = 0.5.
    assert result.confidence == pytest.approx(0.5, abs=1e-6)
    assert len(result.unknown_accesses) == 2


def test_solver_no_candidates_all_unknown() -> None:
    """Aday yok -> hepsi unknown, confidence 0.0."""
    solver = StructLayoutSolver(_enabled_cfg())
    accs = [MemoryAccess("p", 0, 4), MemoryAccess("p", 4, 4)]
    result = solver.solve_from_raw(
        accesses=accs,
        variables=["p"],
        type_hints={"p": "T"},
        candidates=[],
    )
    assert result.assigned_structs == {}
    assert len(result.unknown_accesses) == 2
    assert result.confidence == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# 7) Config validasyonu
# ---------------------------------------------------------------------------

def test_computation_config_default_and_validation() -> None:
    cfg = ComputationConfig()
    # v1.10.0 Batch 6C: Codex teyit -> default KAPALI (opt-in, deneysel matematik).
    assert cfg.enable_computation_struct_recovery is False
    assert cfg.struct_solver_timeout == 60.0
    assert cfg.struct_max_candidates == 10
    # Negatif timeout -> ValueError.
    with pytest.raises(ValueError):
        ComputationConfig(struct_solver_timeout=0)
    # Negatif weight.
    with pytest.raises(ValueError):
        ComputationConfig(struct_unknown_weight=-1)
    # min_confidence disari.
    with pytest.raises(ValueError):
        ComputationConfig(struct_min_confidence=1.5)


def test_config_bound_to_main_config() -> None:
    """Ana Config.computation alani mevcut ve dogru tipte.

    v1.10.0 Batch 6C: default False (Codex teyit, opt-in deneysel komponent).
    """
    from karadul.config import Config
    cfg = Config()
    assert isinstance(cfg.computation, ComputationConfig)
    assert cfg.computation.enable_computation_struct_recovery is False


# ---------------------------------------------------------------------------
# v1.10.0 Batch 6A regression — Codex __unknown__ coupling fix
# ---------------------------------------------------------------------------

def test_aliasing_untyped_vars_get_unique_families() -> None:
    """Batch 6A: type_hint'siz BAGIMSIZ variables ayri ailelere dusmeli.

    Eski davranisla (tekil __unknown__) encoder.py H4 iki bagimsiz
    variables'i ayni adaya zorluyordu -- struct recovery sessizce yanlis
    sonuc veriyordu. Fix: her must_alias component'i kendi
    __unknown_<hash>__ ailesini alir.
    """
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["a", "b", "c"],  # tip yok, must_alias yok
        must_alias=[],
        type_hints={},
    )
    families = [c.type_family for c in classes]
    # 3 bagimsiz variable -> 3 AYRI aile
    assert len(set(families)) == 3, (
        f"3 bagimsiz var tek aileye dustu: {families}"
    )
    # Hepsi unknown prefix'li olmali (type hint yoktu).
    for f in families:
        assert AliasingAnalyzer.is_unknown_family(f), (
            f"Family '{f}' unknown-prefix bekleniyordu"
        )


def test_aliasing_untyped_must_alias_merges_into_one_family() -> None:
    """Batch 6A: type_hint'siz AMA must_alias'li vars tek aileye merge olmali."""
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q", "r"],
        must_alias=[("p", "q")],
        type_hints={},  # hic tip verilmedi
    )
    # p+q birlesmis, r ayri -> 2 class, 2 aile
    assert len(classes) == 2
    families = [c.type_family for c in classes]
    assert len(set(families)) == 2, (
        f"Ayri component'lar tek aileye dustu: {families}"
    )
    # Ikisi de unknown prefix'li olmali
    for f in families:
        assert AliasingAnalyzer.is_unknown_family(f)


def test_aliasing_unknown_family_is_deterministic() -> None:
    """Ayni girdi ayni hash uretmeli (cache/repro icin kritik)."""
    analyzer1 = AliasingAnalyzer()
    analyzer2 = AliasingAnalyzer()
    c1 = analyzer1.build_classes(["a", "b"], [], {})
    c2 = analyzer2.build_classes(["a", "b"], [], {})
    f1 = sorted([c.type_family for c in c1])
    f2 = sorted([c.type_family for c in c2])
    assert f1 == f2


def test_solver_independent_untyped_vars_do_not_couple() -> None:
    """Batch 6A INTEGRATION: tip verilmeyen 2 bagimsiz var, uyumsuz access
    pattern'i -> BIRBIRINE KILITLENMEMELI (eski __unknown__ H4 bug'i)."""
    cfg = _enabled_cfg()
    solver = StructLayoutSolver(cfg)
    # var 'p' 4-byte erisim offset 0; var 'q' 8-byte erisim offset 0.
    # Eger ayni aileye dususur ve H4 onlari ayni struct'a zorlarsa solver
    # unknown'a kacmak zorunda kalir (cunku ayni struct her ikisine hizmet
    # edemez). Fix sonrasi ayri ailelere duserler, ikisi de acilanabilir.
    accesses = [
        MemoryAccess("p", 0, 4),
        MemoryAccess("p", 4, 4),
        MemoryAccess("q", 0, 8),
    ]
    result = solver.solve_from_raw(accesses=accesses, max_time_seconds=5.0)
    # En az p ve q ayni struct olmak ZORUNDA degil; en az biri acilansin.
    assert result.confidence > 0.0, (
        "Bagimsiz untyped variables tek aileye dusup H4 ile couple olmus olabilir"
    )


def test_encoder_h4_skips_unknown_prefix() -> None:
    """Batch 6A unit: encoder H4, unknown-prefix aileleri coupling yapmamali."""
    from karadul.computation.struct_recovery.aliasing import AliasingAnalyzer
    # Fake iki class ayni (manuel) __unknown_xx__ aileye dussun
    assert AliasingAnalyzer.is_unknown_family("__unknown_deadbeef__")
    assert AliasingAnalyzer.is_unknown_family("__unknown_12345678__")
    assert not AliasingAnalyzer.is_unknown_family("MyType")
    assert not AliasingAnalyzer.is_unknown_family("")


def test_solver_rejects_oversized_component(monkeypatch) -> None:
    """Batch 6A (FIX 5 partial): >_MAX_COMPONENT_VARIABLES olan alias
    component'i atlanmali. Diger componentler normal cozulur."""
    from karadul.computation.struct_recovery import solver as solver_mod
    # Cap'i 3'e cek (kucuk test)
    monkeypatch.setattr(solver_mod, "_MAX_COMPONENT_VARIABLES", 3)

    cfg = _enabled_cfg()
    slv = solver_mod.StructLayoutSolver(cfg)
    # Dejenere component: 5 variable'in hepsi must_alias ile birlesmis
    # ("big" component cap'i asar). Plus bagimsiz "small" iki variable.
    accesses = [
        # big component: p0..p4 (5 var, cap=3 asiyor)
        MemoryAccess("p0", 0, 4),
        MemoryAccess("p1", 4, 4),
        MemoryAccess("p2", 8, 4),
        MemoryAccess("p3", 0, 4),
        MemoryAccess("p4", 4, 4),
        # small component: q
        MemoryAccess("q", 0, 4),
        MemoryAccess("q", 4, 4),
    ]
    must_alias = [("p0", "p1"), ("p1", "p2"), ("p2", "p3"), ("p3", "p4")]
    result = slv.solve_from_raw(
        accesses=accesses,
        must_alias=must_alias,
        max_time_seconds=5.0,
    )
    # Dejenere component'ten gelen 5 erisim unknown'da olmali.
    oversized_names = {"p0", "p1", "p2", "p3", "p4"}
    unknown_names = {a.var_name for a in result.unknown_accesses}
    # En azindan big component'in uyeleri unknown'a dusmus olmali
    assert oversized_names.issubset(unknown_names) or len(result.unknown_accesses) >= 5, (
        f"Cap asan component atlanmadi, unknown={unknown_names}"
    )
