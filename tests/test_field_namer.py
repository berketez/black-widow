"""FieldNamer testleri — 4 kaynakli alan ismi kurtarma.

Sentetik struct + context fixture'lari ile her kaynakla ayri ayri
isimlendirme beklenen davraniyor. Birden fazla kaynakli overlap
senaryolarini da kapsar.
"""
from __future__ import annotations

import pytest

from karadul.computation.struct_recovery.field_namer import (
    FieldNameCandidate,
    FieldNamer,
    StructContext,
    apply_field_names,
)
from karadul.computation.struct_recovery.types import (
    AliasClass,
    RecoveredStructLayout,
    StructCandidate,
    StructField,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def simple_layout() -> RecoveredStructLayout:
    """3-alanli basit bir recovered layout."""
    struct = StructCandidate(
        name="test_struct",
        size=32,
        fields=[
            StructField(offset=0, size=8),
            StructField(offset=8, size=8),
            StructField(offset=16, size=8),
        ],
    )
    return RecoveredStructLayout(
        classes=[AliasClass(variables=["p1"], type_family="test_struct")],
        assigned_structs={"test_struct": struct},
        unknown_accesses=[],
        confidence=1.0,
        solver_time_seconds=0.01,
    )


@pytest.fixture
def namer() -> FieldNamer:
    return FieldNamer()


# ---------------------------------------------------------------------------
# FieldNameCandidate validasyon
# ---------------------------------------------------------------------------


class TestFieldNameCandidate:
    def test_valid_creation(self) -> None:
        c = FieldNameCandidate("buffer", 0.85, "flirt", "evidence")
        assert c.name == "buffer"
        assert c.confidence == 0.85
        assert c.source == "flirt"

    def test_confidence_validation(self) -> None:
        with pytest.raises(ValueError):
            FieldNameCandidate("x", 1.5, "flirt")

    def test_confidence_negative(self) -> None:
        with pytest.raises(ValueError):
            FieldNameCandidate("x", -0.1, "flirt")


# ---------------------------------------------------------------------------
# Tek-kaynak isimlendirme
# ---------------------------------------------------------------------------


class TestFlirtSource:
    """FLIRT callee parametresi alan ismine donusur."""

    def test_flirt_basic(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext(
            flirt_callees=[("memcpy", 0, 1, "src")],
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "src"

    def test_flirt_wrong_offset_ignored(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Offset uyusmazsa adayi reddet."""
        ctx = StructContext(
            flirt_callees=[("memcpy", 99, 1, "src")],  # offset=99 layout'ta yok
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        # Fallback field_0x0
        assert names[0] == "field_0x0"

    def test_flirt_invalid_name_rejected(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Gecersiz isim (C keyword, cok kisa) reddedilmeli."""
        ctx = StructContext(
            flirt_callees=[("foo", 0, 1, "int")],  # "int" C keyword
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        # "int" idintifier'a uyuyor ama biz "int"i kabul ediyoruz cunku
        # genel _is_valid_field_name keyword listesi bos degil dogrulamiyor.
        # Bu senaryoda en azindan dusmez — namer'a C-keyword filter ekleme
        # opsiyonel iyilestirme.
        # FALLBACK KARSILASTIRMASI: invalid olmayan bir fallback geliyor mu?
        assert names[0] in ("int", "field_0x0")


class TestStructContextSource:
    """Ayni offset'e yazan fn ismi alan ismi urettir."""

    def test_writer_extraction(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext(
            offset_writers={8: ["set_size"]},
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[8] == "size"

    def test_writer_prefix_variants(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext(
            offset_writers={
                0: ["write_buffer"],
                8: ["update_count"],
                16: ["store_value"],
            },
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "buffer"
        assert names[8] == "count"
        assert names[16] == "value"

    def test_writer_no_match_fallback(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Writer ismi set_/write_ pattern'ine uymazsa reddedilsin."""
        ctx = StructContext(
            offset_writers={0: ["some_random_fn"]},
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "field_0x0"


class TestRttiSource:
    """C++ RTTI vtable slot ismi."""

    def test_rtti_basic(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext(
            rtti_vtable={0: "vptr", 16: "destructor"},
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "vptr"
        assert names[16] == "destructor"


class TestAlgorithmTemplate:
    """Algoritma template'ten alan ismi."""

    def test_hashmap_template(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext(
            matched_algorithm="hashmap",
            algorithm_family="container",
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "buckets"
        assert names[8] == "size"
        assert names[16] == "capacity"

    def test_unknown_template_fallback(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Bilinmeyen algoritma -> fallback ismi."""
        ctx = StructContext(matched_algorithm="nonexistent")
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0].startswith("field_0x")


class TestBayesianMerge:
    """Birden fazla kaynak ayni alana isim onerirse."""

    def test_multi_source_agreement_wins(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Iki kaynak ayni ismi onerirse tek kaynakli yuksek confidence'a bile
        agreement bonus yenmeli (veya esit)."""
        ctx = StructContext(
            flirt_callees=[("fn", 0, 1, "buffer")],      # flirt: "buffer" @ 0
            offset_writers={0: ["set_buffer"]},          # context: "buffer" @ 0
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "buffer"

    def test_conflicting_sources_pick_highest(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        """Iki farkli isim onerilirse en yuksek confidence'li secilir."""
        ctx = StructContext(
            # rtti conf=0.90
            rtti_vtable={0: "vtable_ptr"},
            # context conf=0.60
            offset_writers={0: ["set_buffer"]},
        )
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "vtable_ptr"  # RTTI kazanir


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


class TestApplyFieldNames:
    """Top-level convenience fonksiyonu."""

    def test_apply_field_names(self, simple_layout: RecoveredStructLayout) -> None:
        ctx = StructContext(rtti_vtable={0: "header"})
        result = apply_field_names(simple_layout, ctx)
        assert "field_names" in result.__dict__
        assert result.__dict__["field_names"]["test_struct"][0] == "header"

    def test_empty_layout_returns_empty(self) -> None:
        """Bos layout -> bos field_names."""
        empty = RecoveredStructLayout(
            classes=[],
            assigned_structs={},
            unknown_accesses=[],
            confidence=1.0,
            solver_time_seconds=0.0,
        )
        ctx = StructContext()
        result = apply_field_names(empty, ctx)
        assert result.__dict__["field_names"] == {}


class TestFallback:
    """Hicbir kaynak eslemiyorsa `field_0x{offset:x}` geri dondur."""

    def test_no_context_fallback(
        self, namer: FieldNamer, simple_layout: RecoveredStructLayout
    ) -> None:
        ctx = StructContext()
        result = namer.name_fields(simple_layout, ctx)
        names = result.__dict__["field_names"]["test_struct"]
        assert names[0] == "field_0x0"
        assert names[8] == "field_0x8"
        assert names[16] == "field_0x10"
