"""Struct alan isim kurtarici — MaxSMT solver sonucunu genisletir.

``StructLayoutSolver`` Z3-MaxSMT ile OFFSET + SIZE kurtariyor (layout),
ancak alan isimleri `field_0x18` gibi placeholder kalıyor. Bu modul dort
kaynaktan kanit toplar ve Bayesian birlesim ile her alana en iyi ismi
verir:

    1. FLIRT callee parameter   — alan yazma/okuma yapan fn'in api_param_db
                                   parametresi varsa onu oner.
    2. struct_context           — ayni offset'e yazan baska fn'lerin adi.
    3. RTTI / C++ virtual table — ayni offset vtable slot'una denk gelen
                                   virtual metod ismi.
    4. Algorithm template       — ``ALGORITHM_PARAM_TEMPLATES``'teki alan
                                   ismi (state.round_key vb).

Her kaynak bir ``FieldNameCandidate`` dondurur (confidence + evidence);
``name_merger.NameMerger`` Bayesian birlesimle final isim secer.

Feature flag: ``BinaryReconstructionConfig.enable_struct_recovery`` zaten
var — bu namer onun bir alt componenti. Ayri flag gerekmez.

API:
    namer = FieldNamer()
    recovered = namer.name_fields(struct, context)
    # StructCandidate'in field isimlerini inplace gunceller.

Varsayılan davranış: hiçbir kaynak isim onermemişse alan isimi
``field_0x{offset:x}`` fallback'i alır.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from karadul.computation.struct_recovery.types import (
    RecoveredStructLayout,
    StructCandidate,
    StructField,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class FieldNameCandidate:
    """Bir alana onerilen isim + kaynak + guven.

    Attributes:
        name: Onerilen alan ismi (ornegin "buffer", "size", "round_key").
        confidence: [0.0, 1.0] arasi guven skoru.
        source: "flirt" | "rtti" | "struct_context" | "algorithm_template".
        evidence: Aciklayici metin (debug/log icin).
    """
    name: str
    confidence: float
    source: str
    evidence: str = ""

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence [0,1] disinda: {self.confidence}",
            )


@dataclass
class StructContext:
    """Alan isimlendirme icin dis baglam.

    Tumu opsiyonel — ne kadar doluysa o kadar iyi isim kurtar.
    """
    # FLIRT / signature DB eslesmeleri: fn ismi -> (offset, param_idx, param_name)
    flirt_callees: list[tuple[str, int, int, str]] = field(default_factory=list)

    # Struct context: offset -> fn isimleri (ayni offset'e yazanlar)
    offset_writers: dict[int, list[str]] = field(default_factory=dict)

    # C++ RTTI bilgisi: offset -> virtual metod ismi (vtable slot'u)
    rtti_vtable: dict[int, str] = field(default_factory=dict)

    # Algoritma template bilgisi: (template_name, algorithm_family)
    # Boyle bir tahmin varsa algorithm_template kaynagi tetiklenir.
    matched_algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None


# Ad dogrulama: gecersiz C identifier veya yaygin placeholder'lar reddedilir.
_INVALID_PLACEHOLDERS = frozenset({
    "param_1", "param_2", "param_3", "param_4", "param_5",
    "arg", "arg0", "arg1", "arg2", "local_0", "local_10",
    "field", "unnamed",
})


def _is_valid_field_name(name: str) -> bool:
    if not name or len(name) < 2:
        return False
    if not name.isidentifier():
        return False
    if name in _INVALID_PLACEHOLDERS:
        return False
    # Saf sayi olmamali
    if name.isdigit():
        return False
    return True


# ---------------------------------------------------------------------------
# FieldNamer
# ---------------------------------------------------------------------------


# Algorithm template'lerden alan ismi tahmin etmek icin kucuk bir harita.
# Genisletme noktasi: `reconstruction/recovery_layers/templates/known_algorithms.json`'dan
# okunacak sekilde ileride lazy-load edilebilir.
_ALGORITHM_FIELD_TEMPLATES: dict[str, dict[int, str]] = {
    # AES: offset -> field name
    "aes_context": {0: "round_keys", 240: "rounds", 244: "mode"},
    "hashmap": {0: "buckets", 8: "size", 16: "capacity", 24: "load_factor"},
    "rb_tree_node": {0: "key", 8: "value", 16: "left", 24: "right", 32: "color"},
    "linked_list_node": {0: "data", 8: "next", 16: "prev"},
    "dynamic_array": {0: "data", 8: "length", 16: "capacity"},
    # Feel free: diger template'ler icin offset -> field
}


class FieldNamer:
    """Dort kaynaktan kanit toplayan alan isimlendirici.

    Kullanim:
        namer = FieldNamer()
        layout = namer.name_fields(layout, context)
    """

    def __init__(
        self,
        *,
        algorithm_templates: Optional[dict[str, dict[int, str]]] = None,
        merger: Optional[Callable[[list[FieldNameCandidate]], Optional[str]]] = None,
    ) -> None:
        """Args:
            algorithm_templates: Override template dict (test icin).
            merger: Custom Bayesian birlestirici. None -> dahili _default_merge.
        """
        self._templates = algorithm_templates or dict(_ALGORITHM_FIELD_TEMPLATES)
        self._merger = merger or self._default_merge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def name_fields(
        self,
        layout: RecoveredStructLayout,
        context: StructContext,
    ) -> RecoveredStructLayout:
        """Her assigned struct icin alan isimlerini kurtarir.

        Inplace ``StructCandidate.fields[i].type_hint`` ve yeni bir attribute
        ``name`` ayarlanmaz — types.py'deki `StructField` dataclass'i `name`
        alanina sahip degil. Bu sebeple bu fonksiyon isim eslemesini
        **disaridan** bir dict olarak dondurur ve RecoveredStructLayout'u
        yeni bir ``field_names`` attribute'u ile donebilir (ileride
        types.py'ye `StructField.name` eklenmesi onerisi — dokumante edildi).

        Returns:
            Ayni layout (inplace ``type_hint`` sadece guncellenebilir) +
            `layout.field_names` dict'i: struct_family -> {offset: name}.
        """
        # type_hint yerine ayri bir field_names yapi kur — backward compat.
        field_names: dict[str, dict[int, str]] = {}

        for family, struct in layout.assigned_structs.items():
            names_for_struct: dict[int, str] = {}
            for fld in struct.fields:
                candidates = self._collect_candidates(fld, context)
                chosen = self._merger(candidates)
                if chosen is None:
                    chosen = f"field_0x{fld.offset:x}"
                names_for_struct[fld.offset] = chosen
            field_names[family] = names_for_struct

        # Dynamic attribute — downstream consumer icin kullanışlı.
        # (types.py'ye kalıcı alan eklemiyoruz, backward-compat icin.)
        layout.__dict__["field_names"] = field_names
        return layout

    # ------------------------------------------------------------------
    # Kanit toplayicilar
    # ------------------------------------------------------------------
    def _collect_candidates(
        self,
        fld: StructField,
        context: StructContext,
    ) -> list[FieldNameCandidate]:
        out: list[FieldNameCandidate] = []

        # 1) FLIRT callee parameter
        for fn_name, offset, param_idx, param_name in context.flirt_callees:
            if offset != fld.offset:
                continue
            if not _is_valid_field_name(param_name):
                continue
            out.append(FieldNameCandidate(
                name=param_name,
                confidence=0.85,  # FLIRT/API DB tamamen bagimsiz + guvenilir
                source="flirt",
                evidence=f"{fn_name}.param[{param_idx}] @ offset 0x{offset:x}",
            ))

        # 2) Struct context (ayni offset'e yazan fn ismi)
        writers = context.offset_writers.get(fld.offset, [])
        for writer_name in writers:
            # Fn ismi `set_foo`, `write_bar` pattern'inden alani cikar
            name = self._extract_field_from_writer(writer_name)
            if name and _is_valid_field_name(name):
                out.append(FieldNameCandidate(
                    name=name,
                    confidence=0.60,
                    source="struct_context",
                    evidence=f"writer: {writer_name}()",
                ))

        # 3) C++ RTTI vtable
        rtti_name = context.rtti_vtable.get(fld.offset)
        if rtti_name and _is_valid_field_name(rtti_name):
            out.append(FieldNameCandidate(
                name=rtti_name,
                confidence=0.90,  # RTTI kesin kaynak
                source="rtti",
                evidence=f"vtable slot @ 0x{fld.offset:x}",
            ))

        # 4) Algorithm template
        if context.matched_algorithm:
            tmpl = self._templates.get(context.matched_algorithm, {})
            tmpl_name = tmpl.get(fld.offset)
            if tmpl_name and _is_valid_field_name(tmpl_name):
                out.append(FieldNameCandidate(
                    name=tmpl_name,
                    confidence=0.80,
                    source="algorithm_template",
                    evidence=(
                        f"template={context.matched_algorithm}"
                        f" @ 0x{fld.offset:x}"
                    ),
                ))

        return out

    @staticmethod
    def _extract_field_from_writer(fn_name: str) -> Optional[str]:
        """`set_foo`, `write_bar`, `update_baz` -> `foo`/`bar`/`baz`."""
        for pfx in ("set_", "write_", "update_", "store_", "put_"):
            if fn_name.startswith(pfx) and len(fn_name) > len(pfx):
                return fn_name[len(pfx):]
        return None

    # ------------------------------------------------------------------
    # Bayesian birlesim
    # ------------------------------------------------------------------
    @staticmethod
    def _default_merge(
        candidates: list[FieldNameCandidate],
    ) -> Optional[str]:
        """Naive Bayes / max-confidence fallback.

        Ayni isim birden fazla kaynaktan gelirse confidence'lar toplanir
        (log-odds benzeri basit toplama — tam Bayesian icin
        name_merger.NameMerger kullanilmali). Tek kaynakli adaylar
        icinde en yuksek confidence'li olan secilir.
        """
        if not candidates:
            return None

        # Isim bazli toplam skor.
        name_scores: dict[str, float] = {}
        name_sources: dict[str, set[str]] = {}
        for c in candidates:
            name_scores[c.name] = name_scores.get(c.name, 0.0) + c.confidence
            name_sources.setdefault(c.name, set()).add(c.source)

        # Birden fazla kaynaktan onaylanan isimler bonus alir.
        for name in name_scores:
            if len(name_sources[name]) >= 2:
                name_scores[name] *= 1.2  # %20 bonus cross-source agreement

        # En yuksek skorlu
        best = max(name_scores.items(), key=lambda x: x[1])
        return best[0]


# ---------------------------------------------------------------------------
# Convenience: auto-invoke from StructLayoutSolver (entegrasyon)
# ---------------------------------------------------------------------------


def apply_field_names(
    layout: RecoveredStructLayout,
    context: StructContext,
) -> RecoveredStructLayout:
    """Bir layout + context ikilisi icin field_namer'i tetikle (pratik wrap).

    Bu fonksiyon ``solver.py::_decode`` sonrasi caller tarafindan veya
    downstream pipeline'da cagirilir. Feature flag kontrolu caller'a
    birakir.
    """
    namer = FieldNamer()
    return namer.name_fields(layout, context)
