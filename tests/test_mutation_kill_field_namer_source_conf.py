"""Mutation-kill testi -- FieldNamer kaynak-guven siralamasi (TAM-SUITE delik).

field_namer._collect_candidates FLIRT/API-DB adayina ``confidence=0.85`` verir.
Bu deger kaynak-oncelik siralamasinin bir parcasidir:
    rtti(0.90) > flirt(0.85) > algorithm_template(0.80) > struct_context(0.60)

Mevcut testler flirt'in DEGERINI (0.85) hicbir rakip karsisinda BELIRLEYICI
olacak sekilde kurmuyordu (test_conflicting_sources rtti 0.90 vs context 0.60
kullaniyor; flirt hic yaris etmiyor). Mutant flirt=0.5 TAM suite'e karsi HAYATTA
kaliyordu. Bu test flirt(0.85)'i algorithm_template(0.80) karsisinda yaristirir:
    orijinal: 0.85 > 0.80 -> flirt adi secilir
    mutant:   0.50 < 0.80 -> template adi secilir  (assertion KIRMIZI)
"""

from __future__ import annotations

import pytest

from karadul.computation.struct_recovery.field_namer import (
    FieldNamer,
    StructContext,
)
from karadul.computation.struct_recovery.types import (
    AliasClass,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
)


@pytest.fixture
def one_field_layout() -> RecoveredStructLayout:
    struct = StructCandidate(
        name="s",
        size=8,
        fields=[StructField(offset=0, size=8)],
    )
    return RecoveredStructLayout(
        classes=[AliasClass(variables=["p1"], type_family="s")],
        assigned_structs={"s": struct},
        unknown_accesses=[],
        confidence=1.0,
        solver_time_seconds=0.01,
    )


def test_flirt_confidence_outranks_algorithm_template(
    one_field_layout: RecoveredStructLayout,
) -> None:
    """flirt(0.85) offset 0'da algorithm_template(0.80)'i yenmeli.

    Iki kaynak FARKLI isim onerir (cross-source bonus tetiklenmez, tek-kaynak
    max yarisi). flirt guveni 0.80'in ALTINA dusurulurse (mutant 0.5) secim
    template'e kayar -> yakalanir.
    """
    namer = FieldNamer(algorithm_templates={"myalgo": {0: "tmpl_field"}})
    ctx = StructContext(
        flirt_callees=[("some_fn", 0, 1, "flirt_field")],  # flirt: 0.85
        matched_algorithm="myalgo",                          # template: 0.80
    )
    result = namer.name_fields(one_field_layout, ctx)
    names = result.__dict__["field_names"]["s"]
    assert names[0] == "flirt_field", (
        "flirt(0.85) template(0.80)'i yenmeli; secilen="
        f"{names[0]!r} -- flirt guveni dusurulmus olabilir"
    )
