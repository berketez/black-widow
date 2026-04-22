"""Z3 MaxSMT encoding — Codex'in matematiksel planina gore.

Degiskenler:
    type_c_k  : alias-class c icin aday k secildi mi (Bool)
    map_i_k_j : erisim i, aday k'nin alan j'sine dusuyor mu (Bool)
    unknown_i : erisim i acilanmiyor mu (Bool)

Hard constraint'ler:
    (H1) Sum_j map_i_k_j + unknown_i = 1  (erisim tek yere/unknown).
    (H2) map_i_k_j aktifse: off_i alanin icine sigar VE type_c_k aktif.
    (H3) Her class c icin Sum_k type_c_k = 1.
    (H4) same_type kisiti: ayni type_family'deki TUM class'lar ayni
         aday'i secer (type_c_k <-> type_c'_k). KRITIK — codex uyarisi.

Objective (MaxSMT soft):
    w_unk * #unknown + w_union * #overlap + w_pad * #padding.
    w_split icin H4 zaten hard; ilerideki relax icin hazirda.

Tipik kompleksite: 50 erisim x 10 aday x 5 alan ~= 2500 Bool,
yuzler clause. Z3 Optimize, CPU-only, ms-dusuk saniyede coser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:  # pragma: no cover
    _Z3_AVAILABLE = False
    z3 = None  # type: ignore

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery.aliasing import AliasingAnalyzer
from karadul.computation.struct_recovery.types import (
    AliasClass,
    MemoryAccess,
    StructCandidate,
)


@dataclass
class EncodedProblem:
    """Encoder ciktisi — solver'in tuketecegi Z3 nesneleri.

    Attributes:
        optimize: Z3 Optimize nesnesi (add_soft dahil).
        type_vars: (class_idx, cand_idx) -> Bool. type_c_k.
        map_vars: (access_idx, cand_idx, field_idx) -> Bool. map_i_k_j.
        unknown_vars: access_idx -> Bool. unknown_i.
        class_to_accesses: class_idx -> access index listesi.
        family_to_classes: family -> class indeksleri (H4 icin).
        candidates_for_family: family -> aday indeksleri (solver'a sinirli arama).
        all_candidates: Tum aday listesi (global index -> StructCandidate).
        num_accesses: Toplam erisim sayisi.
    """
    optimize: Any  # z3.Optimize (Any — z3 kurulu degilse type check bozulmasin)
    type_vars: dict[tuple[int, int], Any] = field(default_factory=dict)
    map_vars: dict[tuple[int, int, int], Any] = field(default_factory=dict)
    unknown_vars: dict[int, Any] = field(default_factory=dict)
    class_to_accesses: dict[int, list[int]] = field(default_factory=dict)
    family_to_classes: dict[str, list[int]] = field(default_factory=dict)
    candidates_for_family: dict[str, list[int]] = field(default_factory=dict)
    all_candidates: list[StructCandidate] = field(default_factory=list)
    num_accesses: int = 0


def ensure_z3_available() -> None:
    """Z3 yoksa aciklayici hata firlat."""
    if not _Z3_AVAILABLE:  # pragma: no cover
        raise RuntimeError(
            "z3-solver kurulu degil. `pip install z3-solver>=4.12` "
            "veya `pip install black-widow[deobf]` ile kur.",
        )


def encode(
    accesses: list[MemoryAccess],
    classes: list[AliasClass],
    class_to_accesses: dict[int, list[int]],
    candidates_by_family: dict[str, list[StructCandidate]],
    config: ComputationConfig,
    opt: Any = None,
) -> EncodedProblem:
    """MaxSMT problemi encode et.

    v1.10.0 H1 (perf fix): ``opt`` parametresi verilirse yeni
    ``z3.Optimize()`` yaratmak yerine onu kullanir. Solver bunu kendi
    ``push()``/``pop()`` cercevesinde yonetir -- her ``solve()`` cagrisinda
    yeni Z3 context init'i ~50-200 ms maliyet.

    Args:
        accesses: Tum bellek erisimleri (index onemli, stabil tut).
        classes: Alias class listesi.
        class_to_accesses: class_idx -> bu class'a ait erisim indeksleri.
            (AliasingAnalyzer.group_accesses_by_class ciktisi.)
        candidates_by_family: family -> aday struct listesi.
        config: Weight'ler ve timeout icin.
        opt: Opsiyonel onceden yaratilmis ``z3.Optimize`` nesnesi. ``None``
            ise yeni bir tane yaratilir (eski davranis).

    Returns:
        EncodedProblem — solver'a aktarilmaya hazir.
    """
    ensure_z3_available()
    if opt is None:
        opt = z3.Optimize()

    # Aday havuzunu tek listede topla (global index).
    all_candidates: list[StructCandidate] = []
    family_cand_global_idx: dict[str, list[int]] = {}
    for family, cands in candidates_by_family.items():
        family_cand_global_idx[family] = []
        for c in cands:
            family_cand_global_idx[family].append(len(all_candidates))
            all_candidates.append(c)

    # family -> class indeksleri.
    family_to_classes: dict[str, list[int]] = {}
    for ci, cls in enumerate(classes):
        family_to_classes.setdefault(cls.type_family, []).append(ci)

    # ---- Degiskenleri yarat ----
    type_vars: dict[tuple[int, int], Any] = {}
    map_vars: dict[tuple[int, int, int], Any] = {}
    unknown_vars: dict[int, Any] = {}

    for ci, cls in enumerate(classes):
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        for k in cand_idxs:
            type_vars[(ci, k)] = z3.Bool(f"type_c{ci}_k{k}")

    for ai in range(len(accesses)):
        unknown_vars[ai] = z3.Bool(f"unknown_a{ai}")

    for ci, access_list in class_to_accesses.items():
        if ci >= len(classes):
            continue
        cls = classes[ci]
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        for ai in access_list:
            for k in cand_idxs:
                cand = all_candidates[k]
                for j in range(len(cand.fields)):
                    map_vars[(ai, k, j)] = z3.Bool(f"map_a{ai}_k{k}_f{j}")

    # ---- HARD CONSTRAINT'LER ----

    # (H3) Her class tam bir aday secer.
    for ci, cls in enumerate(classes):
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        if not cand_idxs:
            # Bu aile icin aday yok — ilgili erisimler unknown olmak zorunda.
            continue
        type_bools = [type_vars[(ci, k)] for k in cand_idxs]
        opt.add(z3.PbEq([(b, 1) for b in type_bools], 1))

    # (H4) same_type: ayni aile -> tum class'lar ayni adaya baglanir.
    # v1.10.0 Batch 6A (Codex matematik audit): __unknown_<hash>__ aileleri
    # her component icin BENZERSIZ uretiliyor (aliasing.py). Yine de eski
    # yollardan (manuel test, eski cache) "__unknown__" tekil ismi gelirse
    # VEYA bir binary'de ayni hash collision olusursa (astronomik) H4
    # bilinmeyenleri birbirine KILITLEMESIN — explicit skip.
    for family, class_idxs in family_to_classes.items():
        if len(class_idxs) < 2:
            continue
        if AliasingAnalyzer.is_unknown_family(family) or family == "__unknown__":
            # Unknown aileleri H4'ten ciktart: bagimsiz instance'lar ayni
            # aday'a zorlanmasin. type_hint veren cagri yollari bu skip'ten
            # etkilenmez cunku onlarin family'si kullanici tarafindan verilir.
            continue
        cand_idxs = family_cand_global_idx.get(family, [])
        c0 = class_idxs[0]
        for c_other in class_idxs[1:]:
            for k in cand_idxs:
                # type_c0_k <-> type_c_other_k
                opt.add(type_vars[(c0, k)] == type_vars[(c_other, k)])

    # (H1) Her erisim: tam bir alana atanir veya unknown.
    # (H2) map_i_k_j aktifse alan icine sigar ve type_c_k aktif.
    for ci, access_list in class_to_accesses.items():
        if ci >= len(classes):
            continue
        cls = classes[ci]
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        for ai in access_list:
            acc = accesses[ai]
            # Tum olasi (k, j) map'leri.
            disjuncts: list[Any] = [unknown_vars[ai]]
            for k in cand_idxs:
                cand = all_candidates[k]
                for j, fld in enumerate(cand.fields):
                    mv = map_vars[(ai, k, j)]
                    disjuncts.append(mv)
                    # (H2) alan icine siga.
                    fits = (
                        fld.offset <= acc.offset and
                        acc.offset + acc.width <= fld.offset + fld.size
                    )
                    if not fits:
                        # Geometrik olarak sigmiyor — bu map yasaktir.
                        opt.add(z3.Not(mv))
                    else:
                        # mv -> type_c_k
                        opt.add(z3.Implies(mv, type_vars[(ci, k)]))
            # (H1) Tam olarak bir tanesi secilir (unknown dahil).
            opt.add(z3.PbEq([(d, 1) for d in disjuncts], 1))

    # Class'a bagli olmayan erisimler (var bilinmiyor) zorunlu unknown.
    claimed: set[int] = set()
    for al in class_to_accesses.values():
        claimed.update(al)
    for ai in range(len(accesses)):
        if ai not in claimed:
            opt.add(unknown_vars[ai])
        else:
            # C3: H1 invariant defansif kontrol. Bir erisim bir class'a
            # bagliysa, o class'in tum (k,j) map_vars'lari yaratilmis
            # olmali. Gelecek refactor'da (ornegin lazy-eval aday ekleme)
            # bir erisim claimed'ta goruntu ama map_var uretilmemisse
            # H1 PbEq bozulur ve UNSAT dondurur — bu assertion o durumu
            # test zamaninda yakalar.
            for ci, access_list in class_to_accesses.items():
                if ai not in access_list or ci >= len(classes):
                    continue
                cls_fam = classes[ci].type_family
                cand_idxs = family_cand_global_idx.get(cls_fam, [])
                if not cand_idxs:
                    # Aday yok, map_var zaten yok -- gecerli.
                    continue
                assert any(
                    (ai, k, j) in map_vars
                    for k in cand_idxs
                    for j in range(len(all_candidates[k].fields))
                ), f"H1 invariant kirildi: access {ai} class {ci} icin map_var yok"

    # ---- SOFT CONSTRAINT'LER (objective) ----

    # w_unk * unknown_i
    for ai, uv in unknown_vars.items():
        opt.add_soft(z3.Not(uv), weight=config.struct_unknown_weight)

    # w_union: aday icinde CAKISAN alanlar. Aday sabit oldugundan bu
    # (type_c_k) secimine bagli statik ceza olarak eklenir.
    # C2: tek add_soft(weight=w_union * overlaps) cagrisi — Z3'te N defa
    # agirlik=w ile N defa cagrila esdeger semantik ama 1 obje + N*w
    # daha az alloc. MaxSMT cozumu ayni.
    for ci, cls in enumerate(classes):
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        for k in cand_idxs:
            cand = all_candidates[k]
            overlaps = _count_overlapping_fields(cand)
            if overlaps > 0:
                opt.add_soft(
                    z3.Not(type_vars[(ci, k)]),
                    weight=config.struct_union_weight * overlaps,
                )

    # w_pad: aday'da referans edilmeyen bayt sayisi (padding).
    # Referansli alan toplami << size ise ceza. Statik, aday sabit.
    for ci, cls in enumerate(classes):
        cand_idxs = family_cand_global_idx.get(cls.type_family, [])
        for k in cand_idxs:
            cand = all_candidates[k]
            pad = _count_padding_bytes(cand)
            if pad > 0:
                opt.add_soft(
                    z3.Not(type_vars[(ci, k)]),
                    weight=config.struct_padding_weight * pad,
                )

    # w_split: H4 zaten hard olarak split'i engelliyor. Soft ceza olarak
    # burada 0 tutuyoruz (H4 kaldirilsa bu agirlik devreye girer).
    # Bu yer ilerideki relax icin hazir.

    return EncodedProblem(
        optimize=opt,
        type_vars=type_vars,
        map_vars=map_vars,
        unknown_vars=unknown_vars,
        class_to_accesses=class_to_accesses,
        family_to_classes=family_to_classes,
        candidates_for_family=family_cand_global_idx,
        all_candidates=all_candidates,
        num_accesses=len(accesses),
    )


def _count_overlapping_fields(cand: StructCandidate) -> int:
    """Adayda cakisan alan ciftlerinin sayisi."""
    n = 0
    fs = cand.fields
    for i in range(len(fs)):
        for j in range(i + 1, len(fs)):
            a, b = fs[i], fs[j]
            if a.offset < b.end and b.offset < a.end:
                n += 1
    return n


def _count_padding_bytes(cand: StructCandidate) -> int:
    """Aday'da alanlar arasinda/sonunda referanssiz bayt sayisi.

    C1 fix: Hem inter-field gap'leri hem de trailing padding'i sayar.
    Ornek: ``size=16, fields=[(0,4),(12,4)]`` -> offset 4..12 arasinda
    8 bayt gap var, trailing 0 -> toplam 8 bayt padding.

    Eski surum sadece trailing bos alan sayiyordu, solver overlap ve
    siki adaylari yanlis degerlendirebiliyordu.
    """
    if not cand.fields:
        return cand.size
    padding = 0
    cursor = 0
    # Alanlar __post_init__'te zaten offset-sorted, yine de savunmaci sirala.
    for f in sorted(cand.fields, key=lambda x: x.offset):
        if f.offset > cursor:
            # Inter-field gap
            padding += f.offset - cursor
        cursor = max(cursor, f.offset + f.size)
    # Trailing padding (size > cursor ise)
    if cand.size > cursor:
        padding += cand.size - cursor
    return padding
