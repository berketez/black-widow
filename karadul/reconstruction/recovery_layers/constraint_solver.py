"""Constraint Solver -- Z3/heuristic ile struct layout dogrulama ve array tanima.

Mevcut ``c_type_recoverer.py`` regex'lerini GENISLETIR (degistirmez).
Ek olarak:
    - Overlap ve alignment kontrolu
    - Cok-boyutlu array tanima (``ptr[i*N+j]`` patterni)
    - Z3 ile tutarlilik dogrulamasi (Z3 yoksa heuristic fallback)
    - Call graph uzerinde BFS ile struct kimlik yayilimi (type propagation)
    - Bitfield extraction (bit shift+mask pattern'leri)
    - Dispatch table detection (function pointer table)
    - Linked list detection (self-referencing struct)

Z3 opsiyoneldir -- kurulu degilse ``_solve_heuristic()`` devreye girer.

Kullanim:
    solver = ConstraintSolver(config)
    result = solver.solve(decompiled_dir, functions_json, existing_structs)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# v1.8.0: DOTALL regex'ler icin chunk-bazli islem.
# Buyuk content'i tamamen atlamak yerine, anahtar kelime (while/for/*)
# etrafinda sinirli pencereler cikarip DOTALL regex'i sadece o pencerede
# calistiririz.  Hicbir dosya atlanmaz.
# ---------------------------------------------------------------------------

_DOTALL_CHUNK_SIZE = 5_000  # Pencere boyutu (karakter)


def _iter_loop_chunks(text: str, chunk_size: int = _DOTALL_CHUNK_SIZE) -> list[str]:
    """text icinde while/for keyword'leri etrafinda chunk'lar cikar.

    Her loop keyword'u icin keyword pozisyonundan baslayan chunk_size
    karakterlik bir pencere dondurur.  DOTALL regex bu pencerede calisir.
    """
    chunks: list[str] = []
    search_start = 0
    text_len = len(text)
    while search_start < text_len:
        # while veya for keyword'unu bul
        pos_while = text.find("while", search_start)
        pos_for = text.find("for", search_start)
        # En yakini sec
        candidates = [p for p in (pos_while, pos_for) if p >= 0]
        if not candidates:
            break
        pos = min(candidates)
        # Pencere: keyword'den chunk_size kadar
        chunk_end = min(pos + chunk_size, text_len)
        chunks.append(text[pos:chunk_end])
        # Sonraki arama: overlap'i onlemek icin ileri sar
        search_start = pos + 1
    return chunks


def _iter_deref_chunks(text: str, chunk_size: int = _DOTALL_CHUNK_SIZE) -> list[str]:
    """text icinde pointer dereference pattern'leri (*(  ) etrafinda chunk'lar cikar.

    Go slice/interface DOTALL pattern'leri icin kullanilir.
    """
    chunks: list[str] = []
    seen_starts: set[int] = set()
    search_start = 0
    text_len = len(text)
    while search_start < text_len:
        pos = text.find("*(", search_start)
        if pos < 0:
            break
        # Pencere basini satir basina hizala (daha iyi esleme icin)
        line_start = text.rfind("\n", max(0, pos - 200), pos)
        if line_start < 0:
            line_start = max(0, pos - 200)
        if line_start not in seen_starts:
            chunk_end = min(line_start + chunk_size, text_len)
            chunks.append(text[line_start:chunk_end])
            seen_starts.add(line_start)
        search_start = pos + 2
    return chunks


# ---------------------------------------------------------------------------
# Z3 import guard
# ---------------------------------------------------------------------------
try:
    import z3

    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False

# ---------------------------------------------------------------------------
# Regex Pattern'leri (c_type_recoverer.py'dekilerden BAGIMSIZ, genisletilmis)
# ---------------------------------------------------------------------------

# *(TYPE *)(ptr + OFFSET) -- hem okuma hem yazma
_CAST_DEREF = re.compile(
    r"\*\(\s*"
    r"(?P<type>[a-zA-Z_][\w\s]*\*{0,2})\s*\*?\s*\)"
    r"\(\s*"
    r"(?P<base>\w+)"
    r"\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)"
    r"\s*\)",
)

# Sizeof heuristic: malloc(N) veya calloc(N, M)
_MALLOC_SIZE = re.compile(
    r"(?:malloc|calloc)\s*\(\s*(?:(?P<count>\w+)\s*[,*]\s*)?"
    r"(?P<size>0x[0-9a-fA-F]+|\d+)\s*\)",
)

# Array indeksleme: ptr[i * STRIDE + j]  veya  ptr[i * STRIDE]
_ARRAY_INDEX = re.compile(
    r"(?P<base>\w+)\s*\["
    r"\s*(?P<idx1>\w+)\s*\*\s*(?P<stride>0x[0-9a-fA-F]+|\d+)"
    r"(?:\s*\+\s*(?P<idx2>\w+))?"
    r"\s*\]",
)

# Basit array: ptr[EXPR] (genel)
_SIMPLE_ARRAY = re.compile(
    r"(?P<base>\w+)\s*\[\s*(?P<index>[^\]]+)\s*\]",
)

# Tip boyut haritasi (byte)
_TYPE_SIZES: dict[str, int] = {
    "char": 1,
    "uchar": 1,
    "byte": 1,
    "ubyte": 1,
    "bool": 1,
    "undefined": 1,
    "short": 2,
    "ushort": 2,
    "int": 4,
    "uint": 4,
    "float": 4,
    "undefined4": 4,
    "long": 8,
    "ulong": 8,
    "longlong": 8,
    "ulonglong": 8,
    "double": 8,
    "undefined8": 8,
    "void *": 8,
    "code *": 8,
    "code **": 8,
}

# ---------------------------------------------------------------------------
# Bitfield Regex'leri
# ---------------------------------------------------------------------------

# Extract: (var >> N) & MASK
_BITFIELD_EXTRACT_RE = re.compile(
    r"\(\s*(?P<var>\w+)\s*>>\s*(?P<shift>0x[0-9a-fA-F]+|\d+)\s*\)"
    r"\s*&\s*(?P<mask>0x[0-9a-fA-F]+|\d+)",
)

# Set: var |= (1 << N)  veya  var |= MASK
_BITFIELD_SET_RE = re.compile(
    r"(?P<var>\w+)\s*\|=\s*"
    r"(?:"
    r"\(\s*1\s*<<\s*(?P<bit>0x[0-9a-fA-F]+|\d+)\s*\)"
    r"|(?P<mask>0x[0-9a-fA-F]+|\d+)"
    r")",
)

# Test: if (var & MASK)
# Not: (?P<var>\w+) dogrudan & islemcisine bitisik olmali.
# [^)&]* ile sadece &'ye kadar tara, boylece tam degisken ismi yakalanir.
_BITFIELD_TEST_RE = re.compile(
    r"(?:if|while)\s*\(\s*[^)&]*\b(?P<var>\w+)\s*&\s*(?P<mask>0x[0-9a-fA-F]+|\d+)",
)

# ---------------------------------------------------------------------------
# Dispatch Table Regex'leri
# ---------------------------------------------------------------------------

# Computed function call: (*(code **)(TABLE + idx * 8))(args)
# veya: (*(code *)(DAT_XXX + offset))(args)
_DISPATCH_COMPUTED_RE = re.compile(
    r"\(\s*\*\s*\(\s*code\s*\*{1,2}\s*\)\s*\("
    r"\s*(?P<table>\w+)\s*\+\s*(?P<idx>\w+)\s*\*\s*(?P<stride>0x[0-9a-fA-F]+|\d+)"
    r"\s*\)\s*\)",
)

# Global dispatch: (*(code*)(DAT_XXX + off))(args)
_DISPATCH_GLOBAL_RE = re.compile(
    r"\(\s*\*\s*\(\s*code\s*\*{1,2}\s*\)\s*\("
    r"\s*(?P<base>DAT_[0-9a-fA-F]+)\s*\+\s*(?P<offset>\w+)"
    r"\s*\)\s*\)",
)

# Switch-like jump table: case N: goto/call (via computed address)
_DISPATCH_SWITCH_RE = re.compile(
    r"\(\s*\*\s*\(\s*code\s*\*{1,2}\s*\)\s*\("
    r"[^)]*\)\s*\)\s*\(",
)

# ---------------------------------------------------------------------------
# Go-Specific Regex'leri
# ---------------------------------------------------------------------------

# Go Slice: 24 byte struct (ptr, len, cap) -- *(long*)(p+0), *(long*)(p+8), *(long*)(p+0x10)
_GO_SLICE_RE = re.compile(
    r"\*\(\s*(?:long|ulong|undefined8)\s*\*\)\s*\(\s*(\w+)\s*\+\s*(?:0x0|0)\s*\)"
    r".*?"
    r"\*\(\s*(?:long|ulong|undefined8|int)\s*\*\)\s*\(\s*\1\s*\+\s*(?:0x8|8)\s*\)"
    r".*?"
    r"\*\(\s*(?:long|ulong|undefined8|int)\s*\*\)\s*\(\s*\1\s*\+\s*(?:0x10|16)\s*\)",
    re.DOTALL,
)

# Go Interface: 16 byte struct (itab, data) -- *(long*)(p+0), *(long*)(p+8)
_GO_INTERFACE_RE = re.compile(
    r"\*\(\s*(?:long|ulong|undefined8|code\s*\*)\s*\*?\)\s*\(\s*(\w+)\s*\+\s*(?:0x0|0)\s*\)"
    r".*?"
    r"\*\(\s*(?:long|ulong|undefined8)\s*\*\)\s*\(\s*\1\s*\+\s*(?:0x8|8)\s*\)",
    re.DOTALL,
)

# Go Map: runtime.makemap veya runtime.makemap_small cagrilari
_GO_MAP_RE = re.compile(
    r"(?:runtime[._]makemap|runtime[._]makemap_small)\s*\(",
)

# Go Channel: runtime.makechan veya runtime.makechan64 cagrilari
_GO_CHANNEL_RE = re.compile(
    r"runtime[._]makechan(?:64)?\s*\(",
)

# ---------------------------------------------------------------------------
# C++ Vtable Dispatch Regex'i
# ---------------------------------------------------------------------------

# (*(code*)(*(long*)obj + VOFF))(obj, args)
# Cift dereference: once obj'nin isaret ettigi vtable pointer'i, sonra vtable entry
_VTABLE_DISPATCH_RE = re.compile(
    r"\(\s*\*\s*\(\s*code\s*\*{1,2}\s*\)\s*"
    r"\(\s*\*\s*\(\s*(?:long|code)\s*\*{1,2}\s*\)\s*"
    r"(?P<obj>\w+)\s*"
    r"(?:\+\s*(?P<voff>0x[0-9a-fA-F]+|\d+))?\s*\)\s*\)",
)

# ---------------------------------------------------------------------------
# Linked List Regex'leri
# ---------------------------------------------------------------------------

# Self-referencing pointer update: var = *(TYPE*)(var + OFFSET)
# Ayni degisken hem sol hem sag tarafta + dereference = next pointer
# v1.7.6: [\w\s]* -> (?:\w+\s*)* -- orijinal [\w\s]* quantifier'i
# \s* ile overlap yaparak O(n^2) backtracking yaratiyordu.
# (?:\w+\s*)* her adimda en az 1 \w tuketir, backtracking sinirlar.
_LINKED_LIST_RE = re.compile(
    r"(?P<var>\w+)\s*=\s*\*\s*\(\s*"
    r"(?P<type>[a-zA-Z_](?:\w+\s*)*\*{0,2})\s*\*?\s*\)\s*\(\s*"
    r"(?P=var)\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)",
)

# Loop ile linked list traversal: while (ptr != NULL) { ... ptr = *(... ptr + off ...) ... }
# Not: .*? (non-greedy, DOTALL) kullanilir, boylece backreference dogru calisir.
_LINKED_LIST_LOOP_RE = re.compile(
    r"(?:while|for)\s*\([^)]*\b(?P<var>\w+)\s*!=\s*(?:0|NULL|0x0)\b[^)]*\)"
    r"\s*\{.*?"
    r"(?P=var)\s*=\s*\*\s*\(.*?(?P=var)\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)",
    re.DOTALL,
)


def _parse_offset(s: str) -> int:
    """Hex veya decimal offset string'ini int'e donustur."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def _guess_type_size(type_str: str) -> int:
    """Tip string'inden boyut tahmin et (byte).

    Ghidra ``*(TYPE *)(base + OFFSET)`` pattern'inde yakalanan TYPE
    genellikle sonunda bir pointer ``*`` icerr (cast'in pointer kismi).
    Bu ``*`` dereference edildigi icin gercek veri tipi ``*`` haric kismdir.
    Ornegin ``int *`` -> gercek tip ``int`` (4 byte).
    """
    # Cast pointer'ini cikar: "int *" -> "int", "char **" -> "char *"
    clean = type_str.strip()
    if clean.endswith("*"):
        clean = clean[:-1].strip()
    # Hala pointer ise (orn: "char **" -> "char *") gercekten pointer'dir
    if "*" in clean:
        return 8
    return _TYPE_SIZES.get(clean, 8)  # Bilinmiyorsa 8 (64-bit default)


def _count_set_bits(mask: int) -> int:
    """Mask'teki set bit sayisini hesapla (bitfield width)."""
    count = 0
    while mask:
        count += mask & 1
        mask >>= 1
    return count


def _find_lowest_set_bit(mask: int) -> int:
    """Mask'teki en dusuk set bit pozisyonunu bul."""
    if mask == 0:
        return 0
    pos = 0
    while (mask & 1) == 0:
        mask >>= 1
        pos += 1
    return pos


# ---------------------------------------------------------------------------
# Veri Yapilari
# ---------------------------------------------------------------------------


@dataclass
class FieldConstraint:
    """Tek bir field constraint'i -- 'bu offset'te bu tip var'.

    Attributes:
        base_var: Kaynak pointer degisken adi (orn: ``param_1``).
        offset: Byte offset.
        type_str: C tipi string (orn: ``long``, ``int *``).
        size: Byte boyutu.
        confidence: Tespit guven skoru (0.0-1.0).
        source_function: Hangi fonksiyonda tespit edildigi.
        is_write: Yazma erisimi mi.
    """
    base_var: str
    offset: int
    type_str: str
    size: int
    confidence: float = 0.8
    source_function: str = ""
    is_write: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization."""
        return {
            "base_var": self.base_var,
            "offset": self.offset,
            "type_str": self.type_str,
            "size": self.size,
            "confidence": self.confidence,
            "source_function": self.source_function,
            "is_write": self.is_write,
        }


@dataclass
class ConstraintStruct:
    """Constraint cozumunden uretilen struct tanimi.

    Attributes:
        name: Struct adi (orn: ``comp_struct_001``).
        fields: (offset, type, size, confidence) tuple'lari.
        total_size: Toplam boyut tahimini (byte).
        source_functions: Hangi fonksiyonlarda goruldugu.
        has_overlap: Overlap (union) iceriyor mu.
        is_union: Z3/heuristic overlap tespiti sonucu union olarak siniflandirildi mi.
        alignment: Alignment (varsayilan 8 -- ARM64).
        nested_children: Icerisinde tespit edilen child struct indexleri.
    """
    name: str
    fields: list[tuple[int, str, int, float]]  # (offset, type, size, conf)
    total_size: int = 0
    source_functions: list[str] = field(default_factory=list)
    has_overlap: bool = False
    is_union: bool = False
    alignment: int = 8
    nested_children: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization."""
        return {
            "name": self.name,
            "fields": [
                {"offset": o, "type": t, "size": s, "confidence": c}
                for o, t, s, c in self.fields
            ],
            "total_size": self.total_size,
            "source_functions": self.source_functions,
            "has_overlap": self.has_overlap,
            "is_union": self.is_union,
            "alignment": self.alignment,
            "nested_children": self.nested_children,
        }


@dataclass
class ArrayDetection:
    """Tespit edilen cok-boyutlu array.

    Attributes:
        base_var: Kaynak pointer degisken adi.
        dimensions: Boyut sayisi (1D, 2D, 3D).
        strides: Her boyut icin stride (byte).
        element_type: Eleman tipi.
        source_function: Hangi fonksiyonda tespit edildigi.
        confidence: Tespit guven skoru.
    """
    base_var: str
    dimensions: int = 1
    strides: list[int] = field(default_factory=list)
    element_type: str = "undefined8"
    source_function: str = ""
    confidence: float = 0.7

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization."""
        return {
            "base_var": self.base_var,
            "dimensions": self.dimensions,
            "strides": self.strides,
            "element_type": self.element_type,
            "source_function": self.source_function,
            "confidence": self.confidence,
        }


@dataclass
class ConstraintSolverResult:
    """Constraint Solver sonucu.

    Attributes:
        structs: Cozulen struct tanimlari.
        arrays: Tespit edilen cok-boyutlu array'ler.
        propagated_types: BFS ile yayilan tipler {func_addr: struct_name}.
        structs_refined: Rafine edilen struct sayisi.
        arrays_detected: Tespit edilen array sayisi.
        types_propagated: Yayilan tip sayisi.
        elapsed_seconds: Gecen sure.
        used_z3: Z3 kullanildi mi.
        param_type_inferences: Fonksiyon parametre tip cikarimlari
            {func_name: {param_name: inferred_type}}.
        return_type_inferences: Fonksiyon return tip cikarimlari
            {func_name: inferred_return_type}.
        global_variables: Tespit edilen DAT_ global degiskenler.
        bitfield_detections: Tespit edilen bitfield struct'lari.
        dispatch_tables: Tespit edilen dispatch/function pointer table'lari.
        linked_lists: Tespit edilen linked list pattern'leri.
        go_types: Tespit edilen Go-specific tipler (slice, interface, map, channel).
        vtable_dispatches: Tespit edilen C++ vtable dispatch cagrilari.
    """
    structs: list[ConstraintStruct] = field(default_factory=list)
    arrays: list[ArrayDetection] = field(default_factory=list)
    propagated_types: dict[str, str] = field(default_factory=dict)
    structs_refined: int = 0
    arrays_detected: int = 0
    types_propagated: int = 0
    elapsed_seconds: float = 0.0
    used_z3: bool = False
    param_type_inferences: dict[str, dict[str, str]] = field(default_factory=dict)
    return_type_inferences: dict[str, str] = field(default_factory=dict)
    global_variables: list[dict[str, Any]] = field(default_factory=list)
    bitfield_detections: list[dict[str, Any]] = field(default_factory=list)
    dispatch_tables: list[dict[str, Any]] = field(default_factory=list)
    linked_lists: list[dict[str, Any]] = field(default_factory=list)
    go_types: list[dict[str, Any]] = field(default_factory=list)
    vtable_dispatches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON serialization."""
        return {
            "structs": [s.to_dict() for s in self.structs],
            "arrays": [a.to_dict() for a in self.arrays],
            "propagated_types": self.propagated_types,
            "structs_refined": self.structs_refined,
            "arrays_detected": self.arrays_detected,
            "types_propagated": self.types_propagated,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "used_z3": self.used_z3,
            "param_type_inferences": self.param_type_inferences,
            "return_type_inferences": self.return_type_inferences,
            "global_variables": self.global_variables,
            "bitfield_detections": self.bitfield_detections,
            "dispatch_tables": self.dispatch_tables,
            "linked_lists": self.linked_lists,
            "go_types": self.go_types,
            "vtable_dispatches": self.vtable_dispatches,
        }


# ---------------------------------------------------------------------------
# ConstraintSolver sinifi
# ---------------------------------------------------------------------------


class ConstraintSolver:
    """Struct constraint cozucu -- Z3 veya heuristic ile layout dogrulama.

    Decompile edilmis C kodundan field erisim pattern'lerini cikarir,
    cok-boyutlu array'leri tespit eder, Z3 ile tutarlilik dogrular
    (Z3 yoksa heuristic fallback) ve call graph uzerinde BFS ile
    struct kimlik yayilimi yapar.

    Args:
        config: Karadul ana konfigurasyonu.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._comp_config = config.computation_recovery

    def solve(
        self,
        decompiled_dir: Path,
        functions_json: Optional[Path] = None,
        existing_structs: Optional[list[dict[str, Any]]] = None,
        call_graph_json: Optional[Path] = None,
        is_go: bool = False,
    ) -> ConstraintSolverResult:
        """Ana constraint cozum pipeline'i.

        Sirayla:
            1. C kodundan field constraint cikarimi
            2. Array indeksleme tespiti
            3. Z3/heuristic ile tutarlilik cozumu (union detection dahil)
            4. Call graph uzerinde BFS ile struct kimlik yayilimi
            5. Fonksiyon parametre tip cikarimi
            6. Return value tip cikarimi
            7. Global degisken tespiti
            8. Bitfield extraction
            9. Dispatch table detection
            10. Linked list detection
            11. Go-specific pattern detection (is_go=True ise)
            12. C++ vtable dispatch detection
            13. Nested struct detection (heuristic)

        Args:
            decompiled_dir: Ghidra decompile C dosyalari dizini.
            functions_json: Ghidra fonksiyon listesi JSON.
            existing_structs: Mevcut tespit edilmis struct'lar.
            call_graph_json: Ghidra call graph JSON.
            is_go: Binary Go dilinde mi (True ise Go-specific pattern'lar aranir).

        Returns:
            Cozum sonucu.
        """
        t0 = time.monotonic()
        result = ConstraintSolverResult()

        if not decompiled_dir.is_dir():
            logger.warning("Decompiled dizin bulunamadi: %s", decompiled_dir)
            result.elapsed_seconds = time.monotonic() - t0
            return result

        # 1. C kodundan field constraint cikarimi
        constraints = self._extract_field_constraints(decompiled_dir)
        logger.info("Cikarilan constraint sayisi: %d", len(constraints))

        # 2. Array indeksleme tespiti
        arrays = self._detect_arrays(decompiled_dir)
        result.arrays = arrays
        result.arrays_detected = len(arrays)
        logger.info("Tespit edilen array sayisi: %d", len(arrays))

        # 3. Constraint'leri coz (Z3 veya heuristic)
        if constraints:
            structs = self._solve_constraints(constraints, existing_structs or [])
            result.structs = structs
            result.structs_refined = len(structs)
            result.used_z3 = _Z3_AVAILABLE

        # 4. Call graph uzerinde BFS ile struct kimlik yayilimi
        if call_graph_json and call_graph_json.exists() and result.structs:
            propagated = self._propagate_types(result.structs, call_graph_json)
            result.propagated_types = propagated
            result.types_propagated = len(propagated)

        # 5. Fonksiyon parametre tip cikarimi
        param_types = self._infer_param_types(decompiled_dir, call_graph_json)
        result.param_type_inferences = param_types
        logger.info("Parametre tip cikarimi: %d fonksiyon", len(param_types))

        # 6. Return value tip cikarimi
        return_types = self._infer_return_types(decompiled_dir)
        result.return_type_inferences = return_types
        logger.info("Return tip cikarimi: %d fonksiyon", len(return_types))

        # 7. Global degisken tespiti
        globals_detected = self._detect_globals(decompiled_dir)
        result.global_variables = globals_detected
        logger.info("Global degisken tespiti: %d degisken", len(globals_detected))

        # 8. Bitfield extraction
        bitfields = self._detect_bitfields(decompiled_dir)
        result.bitfield_detections = bitfields
        logger.info("Bitfield tespiti: %d bitfield", len(bitfields))

        # 9. Dispatch table detection
        dispatch_tables = self._detect_dispatch_tables(decompiled_dir)
        result.dispatch_tables = dispatch_tables
        logger.info("Dispatch table tespiti: %d table", len(dispatch_tables))

        # 10. Linked list detection
        linked_lists = self._detect_linked_lists(decompiled_dir)
        result.linked_lists = linked_lists
        logger.info("Linked list tespiti: %d list", len(linked_lists))

        # 11. Go-specific pattern detection (sadece is_go=True ise)
        if is_go:
            go_types = self._detect_go_patterns(decompiled_dir)
            result.go_types = go_types
            logger.info("Go tip tespiti: %d go_type", len(go_types))

        # 12. C++ vtable dispatch detection
        vtable_dispatches = self._detect_vtable_dispatch(decompiled_dir)
        result.vtable_dispatches = vtable_dispatches
        logger.info("Vtable dispatch tespiti: %d vtable", len(vtable_dispatches))

        # 13. Nested struct detection (heuristic, in-place)
        if result.structs and constraints:
            self._detect_nested_structs(result.structs, constraints)
            nested_count = sum(len(s.nested_children) for s in result.structs)
            logger.info("Nested struct tespiti: %d nested", nested_count)

        result.elapsed_seconds = time.monotonic() - t0
        logger.info(
            "Constraint solver tamamlandi: %.1fs, %d struct, %d array, "
            "%d propagated, %d bitfield, %d dispatch, %d linked_list, "
            "%d go_type, %d vtable (z3=%s)",
            result.elapsed_seconds,
            result.structs_refined,
            result.arrays_detected,
            result.types_propagated,
            len(bitfields),
            len(dispatch_tables),
            len(linked_lists),
            len(result.go_types),
            len(vtable_dispatches),
            result.used_z3,
        )
        return result

    # ------------------------------------------------------------------
    # Adim 1: Field Constraint Cikarimi
    # ------------------------------------------------------------------

    def _extract_field_constraints(
        self, decompiled_dir: Path,
    ) -> list[FieldConstraint]:
        """Decompile edilmis C kodundan field erisim constraint'lerini cikar.

        ``*(TYPE *)(ptr + OFFSET)`` pattern'ini arar ve her match icin
        bir ``FieldConstraint`` uretir.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Cikarilan constraint listesi.
        """
        constraints: list[FieldConstraint] = []
        c_files = sorted(decompiled_dir.glob("*.c"))

        if not c_files:
            logger.debug("Decompiled dizinde C dosyasi bulunamadi: %s", decompiled_dir)
            return constraints

        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            for line in content.splitlines():
                # *(TYPE *)(base + OFFSET) pattern'i
                for m in _CAST_DEREF.finditer(line):
                    try:
                        offset = _parse_offset(m.group("offset"))
                    except (ValueError, TypeError):
                        continue

                    raw_type = m.group("type").strip()
                    # Cast pointer'ini cikar: *(int *)(ptr+N) -> gercek tip "int"
                    type_str = raw_type.rstrip("*").strip() if raw_type.endswith("*") else raw_type
                    size = _guess_type_size(raw_type)
                    is_write = "=" in line[m.end():][:5] if m.end() < len(line) else False

                    constraints.append(FieldConstraint(
                        base_var=m.group("base"),
                        offset=offset,
                        type_str=type_str,
                        size=size,
                        confidence=0.85,
                        source_function=func_name,
                        is_write=is_write,
                    ))

        return constraints

    # ------------------------------------------------------------------
    # Adim 2: Array Tespiti
    # ------------------------------------------------------------------

    def _detect_arrays(self, decompiled_dir: Path) -> list[ArrayDetection]:
        """Decompile edilmis C kodundan cok-boyutlu array pattern'lerini tespit et.

        ``ptr[i * STRIDE + j]`` gibi pattern'leri arar ve
        boyut/stride bilgilerini cikarir.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Tespit edilen array listesi.
        """
        arrays: list[ArrayDetection] = []
        # Ayni base_var icin tekrarlayan tespit'leri onle
        seen: set[tuple[str, str]] = set()  # (func_name, base_var)
        c_files = sorted(decompiled_dir.glob("*.c"))

        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            for m in _ARRAY_INDEX.finditer(content):
                base_var = m.group("base")
                key = (func_name, base_var)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    stride = _parse_offset(m.group("stride"))
                except (ValueError, TypeError):
                    continue

                idx2 = m.group("idx2")
                if idx2:
                    # 2D array: ptr[i * COLS + j]
                    arrays.append(ArrayDetection(
                        base_var=base_var,
                        dimensions=2,
                        strides=[stride],
                        element_type=self._guess_element_type(stride),
                        source_function=func_name,
                        confidence=0.80,
                    ))
                else:
                    # 1D strided array: ptr[i * STRIDE]
                    arrays.append(ArrayDetection(
                        base_var=base_var,
                        dimensions=1,
                        strides=[stride],
                        element_type=self._guess_element_type(stride),
                        source_function=func_name,
                        confidence=0.70,
                    ))

        return arrays

    @staticmethod
    def _guess_element_type(stride: int) -> str:
        """Stride degerinden eleman tipini tahmin et."""
        stride_to_type = {
            1: "char",
            2: "short",
            4: "int",
            8: "double",
            16: "long double",
        }
        return stride_to_type.get(stride, f"byte[{stride}]")

    # ------------------------------------------------------------------
    # Adim 3: Constraint Cozumu
    # ------------------------------------------------------------------

    def _solve_constraints(
        self,
        constraints: list[FieldConstraint],
        existing_structs: list[dict[str, Any]],
    ) -> list[ConstraintStruct]:
        """Constraint'leri coz -- Z3 varsa Z3 ile, yoksa heuristic ile.

        Args:
            constraints: Cikarilan field constraint'leri.
            existing_structs: Mevcut tespit edilmis struct'lar (Ghidra'dan).

        Returns:
            Cozulmus struct tanimlari listesi.
        """
        # Constraint'leri base_var'a gore grupla
        groups: dict[str, list[FieldConstraint]] = defaultdict(list)
        for c in constraints:
            groups[c.base_var].append(c)

        min_fields = self._comp_config.constraint_min_fields
        min_conf = self._comp_config.constraint_min_confidence

        # Minimum field sayisinin altindakileri ele
        filtered_groups = {
            base: cs for base, cs in groups.items()
            if len(cs) >= min_fields
        }

        if not filtered_groups:
            return []

        if _Z3_AVAILABLE:
            return self._solve_z3(filtered_groups, existing_structs, min_conf)
        else:
            return self._solve_heuristic(filtered_groups, existing_structs, min_conf)

    def _solve_z3(
        self,
        groups: dict[str, list[FieldConstraint]],
        existing_structs: list[dict[str, Any]],
        min_confidence: float,
    ) -> list[ConstraintStruct]:
        """Z3 ile constraint tutarlilik dogrulamasi.

        Her base_var grubu icin offset + size constraint'lerini Z3'e verir.
        Overlap varsa union olarak isaretler.  Tutarsiz constraint'ler
        dusuk confidence ile raporlanir.

        Args:
            groups: base_var -> constraint listesi.
            existing_structs: Mevcut struct tanimlari.
            min_confidence: Minimum guven esigi.

        Returns:
            Dogrulanmis struct listesi.
        """
        structs: list[ConstraintStruct] = []
        struct_idx = 0

        for base_var, constraints in groups.items():
            # Offset'e gore sirala
            sorted_cs = sorted(constraints, key=lambda c: c.offset)

            # Z3 solver olustur
            solver = z3.Solver()
            solver.set("timeout", 30000)  # 30 saniye limit

            # Her constraint icin Z3 degiskenleri
            z3_offsets = []
            z3_sizes = []
            for i, c in enumerate(sorted_cs):
                off_var = z3.Int(f"off_{i}")
                sz_var = z3.Int(f"sz_{i}")
                solver.add(off_var == c.offset)
                solver.add(sz_var == c.size)
                solver.add(sz_var > 0)
                z3_offsets.append(off_var)
                z3_sizes.append(sz_var)

            # Non-overlap constraint'leri: off[i] + sz[i] <= off[i+1]
            has_overlap = False
            is_union = False
            for i in range(len(z3_offsets) - 1):
                non_overlap = z3_offsets[i] + z3_sizes[i] <= z3_offsets[i + 1]
                solver.add(non_overlap)

            check = solver.check()
            if check == z3.sat:
                # Tutarli -- struct olarak kaydet
                fields = []
                for c in sorted_cs:
                    fields.append((c.offset, c.type_str, c.size, c.confidence))
                fields = self._deduplicate_fields(fields)
            elif check == z3.unsat:
                # Tutarsiz -- overlap var, UNION olarak siniflandir.
                # Eskiden confidence dusuruluyordu; artik union tespiti
                # kendi basina gecerli bir sonuc (confidence 0.75).
                has_overlap = True
                is_union = True
                fields = []
                for c in sorted_cs:
                    # Union field'lari icin confidence: base_confidence veya 0.75, hangisi buyukse
                    fields.append((c.offset, c.type_str, c.size, max(c.confidence, 0.75)))
                fields = self._deduplicate_fields(fields)
                logger.debug(
                    "Z3 tutarsizlik: base=%s, %d constraint -- UNION olarak siniflandirildi",
                    base_var, len(sorted_cs),
                )
            else:
                # Timeout veya bilinmeyen -- heuristic fallback
                fields = self._heuristic_fields(sorted_cs)
                has_overlap = self._check_overlap(fields)

            # Minimum confidence kontrolu
            avg_conf = sum(f[3] for f in fields) / len(fields) if fields else 0.0
            if avg_conf < min_confidence:
                continue

            # Toplam boyut tahmini
            if fields:
                last = max(fields, key=lambda f: f[0])
                total_size = last[0] + last[2]
                # Alignment'a yuvarla
                alignment = 8
                total_size = ((total_size + alignment - 1) // alignment) * alignment
            else:
                total_size = 0

            source_funcs = sorted(set(c.source_function for c in sorted_cs))

            struct_idx += 1
            structs.append(ConstraintStruct(
                name=f"comp_struct_{struct_idx:03d}",
                fields=fields,
                total_size=total_size,
                source_functions=source_funcs,
                has_overlap=has_overlap,
                is_union=is_union,
                alignment=8,
            ))

        return structs

    def _solve_heuristic(
        self,
        groups: dict[str, list[FieldConstraint]],
        existing_structs: list[dict[str, Any]],
        min_confidence: float,
    ) -> list[ConstraintStruct]:
        """Z3 olmadan heuristic ile constraint cozumu.

        Offset'leri siralar, overlap varsa union olarak isaretler.

        Args:
            groups: base_var -> constraint listesi.
            existing_structs: Mevcut struct tanimlari.
            min_confidence: Minimum guven esigi.

        Returns:
            Cozulmus struct listesi.
        """
        structs: list[ConstraintStruct] = []
        struct_idx = 0

        for base_var, constraints in groups.items():
            sorted_cs = sorted(constraints, key=lambda c: c.offset)
            fields = self._heuristic_fields(sorted_cs)
            has_overlap = self._check_overlap(fields)
            is_union = False

            if has_overlap:
                # Overlap varsa -> union olarak siniflandir
                is_union = True
                fields = [
                    (o, t, s, max(0.3, c - 0.2))
                    for o, t, s, c in fields
                ]

            avg_conf = sum(f[3] for f in fields) / len(fields) if fields else 0.0
            if avg_conf < min_confidence:
                continue

            if fields:
                last = max(fields, key=lambda f: f[0])
                total_size = last[0] + last[2]
                alignment = 8
                total_size = ((total_size + alignment - 1) // alignment) * alignment
            else:
                total_size = 0

            source_funcs = sorted(set(c.source_function for c in sorted_cs))

            struct_idx += 1
            structs.append(ConstraintStruct(
                name=f"comp_struct_{struct_idx:03d}",
                fields=fields,
                total_size=total_size,
                source_functions=source_funcs,
                has_overlap=has_overlap,
                is_union=is_union,
                alignment=8,
            ))

        return structs

    @staticmethod
    def _heuristic_fields(
        sorted_constraints: list[FieldConstraint],
    ) -> list[tuple[int, str, int, float]]:
        """Constraint listesinden deduplicate edilmis field listesi uret.

        Ayni offset'teki constraint'ler icin en yuksek confidence'i sec.
        """
        offset_map: dict[int, tuple[str, int, float]] = {}
        for c in sorted_constraints:
            existing = offset_map.get(c.offset)
            if existing is None or c.confidence > existing[2]:
                offset_map[c.offset] = (c.type_str, c.size, c.confidence)

        fields = [
            (offset, t, s, conf)
            for offset, (t, s, conf) in sorted(offset_map.items())
        ]
        return fields

    @staticmethod
    def _deduplicate_fields(
        fields: list[tuple[int, str, int, float]],
    ) -> list[tuple[int, str, int, float]]:
        """Ayni offset'teki field'lari birlestir (en yuksek confidence)."""
        offset_map: dict[int, tuple[str, int, float]] = {}
        for offset, t, s, conf in fields:
            existing = offset_map.get(offset)
            if existing is None or conf > existing[2]:
                offset_map[offset] = (t, s, conf)
        return [
            (offset, t, s, conf)
            for offset, (t, s, conf) in sorted(offset_map.items())
        ]

    @staticmethod
    def _check_overlap(fields: list[tuple[int, str, int, float]]) -> bool:
        """Field'lar arasinda overlap var mi kontrol et."""
        sorted_fields = sorted(fields, key=lambda f: f[0])
        for i in range(len(sorted_fields) - 1):
            curr_end = sorted_fields[i][0] + sorted_fields[i][2]
            next_start = sorted_fields[i + 1][0]
            if curr_end > next_start:
                return True
        return False

    # ------------------------------------------------------------------
    # Adim 4: Tip Yayilimi (BFS)
    # ------------------------------------------------------------------

    def _propagate_types(
        self,
        structs: list[ConstraintStruct],
        call_graph_json: Path,
    ) -> dict[str, str]:
        """Call graph uzerinde BFS ile struct kimlik yayilimi.

        Bir fonksiyonda struct tespit edilmisse, o fonksiyonun cagirdigi
        ve onu cagiran fonksiyonlara da ayni struct'in kullaniyor olabilecegi
        bilgisini yayar.

        Args:
            structs: Tespit edilen struct'lar.
            call_graph_json: Ghidra call graph JSON dosyasi.

        Returns:
            {fonksiyon_adresi: struct_adi} esleme sozlugu.
        """
        max_depth = self._comp_config.type_propagation_max_depth

        # Call graph'i yukle
        try:
            with open(call_graph_json) as f:
                cg_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Call graph okunamadi: %s -- %s", call_graph_json, e)
            return {}

        # Adjacency list olustur (bidirectional)
        adj: dict[str, set[str]] = defaultdict(set)
        edges = cg_data if isinstance(cg_data, list) else cg_data.get("edges", [])
        for edge in edges:
            src = str(edge.get("from", edge.get("source", "")))
            dst = str(edge.get("to", edge.get("target", edge.get("to_block", ""))))
            if src and dst:
                adj[src].add(dst)
                adj[dst].add(src)

        # Seed: struct'larin source_functions'lari
        propagated: dict[str, str] = {}
        for s in structs:
            for func in s.source_functions:
                propagated[func] = s.name

        # BFS
        queue: deque[tuple[str, int]] = deque()
        for func in propagated:
            queue.append((func, 0))

        visited: set[str] = set(propagated.keys())

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            struct_name = propagated.get(current)
            if not struct_name:
                continue

            for neighbor in adj.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    propagated[neighbor] = struct_name
                    queue.append((neighbor, depth + 1))

        # Seed'leri cikar -- sadece yayilmis olanlar
        seed_funcs = set()
        for s in structs:
            seed_funcs.update(s.source_functions)

        return {
            func: name
            for func, name in propagated.items()
            if func not in seed_funcs
        }

    # ------------------------------------------------------------------
    # Adim 5: Fonksiyon Parametre Tip Cikarimi
    # ------------------------------------------------------------------

    # Parametre tip cikarim regex'leri
    _RE_MALLOC_PARAM = re.compile(
        r"(?:malloc|calloc|realloc)\s*\(\s*(\w+)",
    )
    _RE_FREE_PARAM = re.compile(
        r"free\s*\(\s*(\w+)\s*\)",
    )
    _RE_ARRAY_ACCESS = re.compile(
        r"(\w+)\s*\[[^\]]+\]",
    )
    _RE_PTR_DEREF = re.compile(
        r"\*\s*\(\s*(\w+)\s*\+",
    )
    _RE_NULL_CHECK = re.compile(
        r"(?:if|while)\s*\([^)]*(\w+)\s*(?:==|!=)\s*(?:0|NULL|0x0)[^)]*\)",
    )
    _RE_LOOP_BOUND = re.compile(
        r"for\s*\([^;]*;\s*\w+\s*[<>]=?\s*(\w+)\s*;",
    )
    _RE_FLOAT_ARITH = re.compile(
        r"(\w+)\s*[+\-*/]\s*(?:\d+\.\d+|(?:double|float)\s*\))",
    )
    _RE_PRINTF_FORMAT = re.compile(
        r'printf\s*\(\s*"[^"]*%([\w.]+)[^"]*"\s*,[^)]*?(\w+)',
    )

    def _infer_param_types(
        self,
        decompiled_dir: Path,
        call_graph_json: Optional[Path] = None,
    ) -> dict[str, dict[str, str]]:
        """Fonksiyon parametrelerinin tipini kullanim pattern'lerinden cikar.

        Her fonksiyondaki param_N degiskenlerinin kullanilma sekline bakarak
        tip tahmininde bulunur:

        - malloc(param_X) veya calloc(param_X, ...) -> param_X: size_t
        - free(param_X) -> param_X: void*
        - param_X[i] veya *(param_X + ...) -> param_X: pointer
        - param_X + 1.0 veya (double) context -> param_X: double
        - if (param_X == 0) veya if (param_X != NULL) -> param_X: pointer
        - for(i=0; i<param_X; i++) -> param_X: size_t (loop bound)
        - printf("%d", param_X) -> format string'den tip cikar

        Args:
            decompiled_dir: Decompile C dosyalari dizini.
            call_graph_json: Opsiyonel call graph (ileride callee propagation icin).

        Returns:
            {func_name: {param_name: inferred_type}} eslesmesi.
        """
        results: dict[str, dict[str, str]] = {}
        c_files = sorted(decompiled_dir.glob("*.c"))

        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # v1.8.0: Parametre tip cikarim regex'leri hep O(n) safe
            # (negated char class, \w, \s).  Boyut siniri kaldirildi.

            # Sadece param_ ile baslayan degiskenleri tara
            params_in_code = set(re.findall(r"\b(param_\d+)\b", content))
            if not params_in_code:
                continue

            inferred: dict[str, str] = {}

            for param in sorted(params_in_code):
                candidates: dict[str, float] = {}  # tip -> toplam guven

                # malloc/calloc/realloc argumani -> size_t
                for m in self._RE_MALLOC_PARAM.finditer(content):
                    if m.group(1) == param:
                        candidates["size_t"] = candidates.get("size_t", 0) + 0.9

                # free argumani -> void*
                for m in self._RE_FREE_PARAM.finditer(content):
                    if m.group(1) == param:
                        candidates["void *"] = candidates.get("void *", 0) + 0.9

                # Array erisimleri -> pointer
                for m in self._RE_ARRAY_ACCESS.finditer(content):
                    if m.group(1) == param:
                        candidates["pointer"] = candidates.get("pointer", 0) + 0.7

                # Pointer dereference -> pointer
                for m in self._RE_PTR_DEREF.finditer(content):
                    if m.group(1) == param:
                        candidates["pointer"] = candidates.get("pointer", 0) + 0.8

                # NULL karsilastirma -> pointer
                for m in self._RE_NULL_CHECK.finditer(content):
                    if m.group(1) == param:
                        candidates["pointer"] = candidates.get("pointer", 0) + 0.75

                # Loop bound -> size_t
                for m in self._RE_LOOP_BOUND.finditer(content):
                    if m.group(1) == param:
                        candidates["size_t"] = candidates.get("size_t", 0) + 0.8

                # Float arithmetic context -> double
                for m in self._RE_FLOAT_ARITH.finditer(content):
                    if m.group(1) == param:
                        candidates["double"] = candidates.get("double", 0) + 0.7

                # printf format string'den cikarim
                _PRINTF_TYPE_MAP = {
                    "d": "int", "i": "int", "u": "unsigned int",
                    "ld": "long", "lu": "unsigned long",
                    "lld": "long long", "llu": "unsigned long long",
                    "f": "double", "lf": "double", "e": "double",
                    "s": "char *", "c": "char", "p": "void *",
                    "x": "unsigned int", "lx": "unsigned long",
                    "zu": "size_t",
                }
                for m in self._RE_PRINTF_FORMAT.finditer(content):
                    if m.group(2) == param:
                        fmt = m.group(1)
                        if fmt in _PRINTF_TYPE_MAP:
                            t = _PRINTF_TYPE_MAP[fmt]
                            candidates[t] = candidates.get(t, 0) + 0.85

                # En yuksek guvenli tipi sec
                if candidates:
                    best_type = max(candidates, key=lambda t: candidates[t])
                    inferred[param] = best_type

            if inferred:
                results[func_name] = inferred

        return results

    # ------------------------------------------------------------------
    # Adim 6: Return Value Tip Cikarimi
    # ------------------------------------------------------------------

    _RE_RETURN_LITERAL = re.compile(
        r"\breturn\s+([-]?\d+)\s*;",
    )
    _RE_RETURN_MALLOC = re.compile(
        r"\breturn\s+(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
    )
    _RE_RETURN_EXPR = re.compile(
        r"\breturn\s+([^;]+);",
    )
    _RE_RETURN_VOID = re.compile(
        r"\breturn\s*;",
    )

    def _infer_return_types(
        self,
        decompiled_dir: Path,
    ) -> dict[str, str]:
        """Fonksiyonun return degerinin tipini cikar.

        Analiz stratejisi:
        - return 0/1/-1 -> int (status code)
        - return malloc(...) -> void* (allocated memory)
        - return param_1 + ... (arithmetic) -> ayni tip
        - return EXPR with floating literal -> double
        - sadece return; veya return yok -> void

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            {func_name: inferred_return_type} eslesmesi.
        """
        results: dict[str, str] = {}
        c_files = sorted(decompiled_dir.glob("*.c"))

        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # v1.8.0: Return-tip cikarim regex'leri [^;]+, \w+ kullanir -> O(n) safe.
            # Boyut siniri kaldirildi.

            # return malloc(...) -> void*
            if self._RE_RETURN_MALLOC.search(content):
                results[func_name] = "void *"
                continue

            # Tum return literal'leri topla
            literal_returns = self._RE_RETURN_LITERAL.findall(content)
            if literal_returns:
                # Hepsi 0, 1, -1 gibi kucuk degerler mi?
                all_status = all(
                    int(v) in range(-1, 256) for v in literal_returns
                )
                if all_status:
                    results[func_name] = "int"
                    continue

            # Void return (sadece "return;" veya hic return yok)
            void_returns = self._RE_RETURN_VOID.findall(content)
            expr_returns = self._RE_RETURN_EXPR.findall(content)
            if void_returns and not expr_returns:
                results[func_name] = "void"
                continue
            if not expr_returns and not literal_returns and not void_returns:
                results[func_name] = "void"
                continue

            # Return expression analizi
            if expr_returns:
                has_float_literal = False
                has_pointer_op = False
                for expr in expr_returns:
                    expr = expr.strip()
                    # Float literal iceriyor mu?
                    if re.search(r"\d+\.\d+", expr):
                        has_float_literal = True
                    # Pointer cast veya NULL iceriyor mu?
                    if "NULL" in expr or re.search(r"\(\s*\w+\s*\*\s*\)", expr):
                        has_pointer_op = True

                if has_pointer_op:
                    results[func_name] = "void *"
                elif has_float_literal:
                    results[func_name] = "double"

        return results

    # ------------------------------------------------------------------
    # Adim 7: Global Degisken Tespiti
    # ------------------------------------------------------------------

    _RE_DAT_ACCESS = re.compile(
        r"\b(DAT_[0-9a-fA-F]{4,16})\b",
    )
    _RE_MUTEX_PATTERN = re.compile(
        r"(?:pthread_mutex_lock|pthread_mutex_unlock|EnterCriticalSection"
        r"|LeaveCriticalSection|_lock|_unlock)\s*\(",
    )

    def _detect_globals(
        self,
        decompiled_dir: Path,
    ) -> list[dict[str, Any]]:
        """DAT_ prefix'li Ghidra global degiskenlerini tani ve siniflandir.

        Ghidra decompiler, global degiskenleri DAT_XXXX formatiyla adlandirir.
        Her global degisken icin:
        - Hangi fonksiyonlardan erisildigi
        - Sadece okunuyor mu yoksa yaziliyor mu
        - Birden fazla fonksiyondan yaziliyorsa shared state
        - Mutex ile korunuyorsa thread-safe

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {name, readers, writers, access_type, is_const,
            is_shared, is_thread_safe} iceren dict listesi.
        """
        # DAT_ degiskenlerini topla: {dat_name: {readers: set, writers: set, mutex: bool}}
        dat_info: dict[str, dict[str, Any]] = {}
        c_files = sorted(decompiled_dir.glob("*.c"))

        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # Bu fonksiyonda mutex pattern'i var mi?
            has_mutex = bool(self._RE_MUTEX_PATTERN.search(content))

            # Tum DAT_ referanslarini bul
            dat_names = set(self._RE_DAT_ACCESS.findall(content))

            for dat_name in dat_names:
                if dat_name not in dat_info:
                    dat_info[dat_name] = {
                        "readers": set(),
                        "writers": set(),
                        "mutex_funcs": set(),
                    }

                # Yazma tespiti: DAT_XXX = ... (basit heuristic)
                # "DAT_XXX =" ama "== DAT_XXX" veya "!= DAT_XXX" degil
                write_re = re.compile(
                    rf"\b{re.escape(dat_name)}\s*=[^=]",
                )
                if write_re.search(content):
                    dat_info[dat_name]["writers"].add(func_name)
                else:
                    dat_info[dat_name]["readers"].add(func_name)

                if has_mutex:
                    dat_info[dat_name]["mutex_funcs"].add(func_name)

        # Sonuclari derle
        results: list[dict[str, Any]] = []
        for dat_name, info in sorted(dat_info.items()):
            readers = sorted(info["readers"])
            writers = sorted(info["writers"])
            mutex_funcs = sorted(info["mutex_funcs"])

            is_const = len(writers) == 0
            is_shared = len(writers) > 1 or (
                len(writers) >= 1 and len(readers) >= 1
                and not info["readers"].issubset(info["writers"])
            )
            is_thread_safe = len(mutex_funcs) > 0

            # Erisim tipini belirle
            if is_const:
                access_type = "read_only"
            elif len(readers) == 0:
                access_type = "write_only"
            else:
                access_type = "read_write"

            results.append({
                "name": dat_name,
                "readers": readers,
                "writers": writers,
                "access_type": access_type,
                "is_const": is_const,
                "is_shared": is_shared,
                "is_thread_safe": is_thread_safe,
                "mutex_protected_in": mutex_funcs,
                "total_refs": len(readers) + len(writers),
            })

        return results

    # ------------------------------------------------------------------
    # Adim 8: Bitfield Extraction
    # ------------------------------------------------------------------

    def _detect_bitfields(self, decompiled_dir: Path) -> list[dict[str, Any]]:
        """Bit shift+mask pattern'lerinden bitfield struct'lari cikar.

        Decompiled kodda bitfield erisimleri su pattern'lerde gorunur:
        - Extract: ``(var >> N) & MASK`` -- N. bit'ten itibaren MASK genisliginde oku
        - Set: ``var |= (1 << N)`` -- N. bit'i set et
        - Test: ``if (var & MASK)`` -- MASK ile maskelenmis bitleri test et

        Ayni degisken uzerindeki birden fazla bitfield erisimini gruplayarak
        bir bitfield struct olusturur.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {var, fields: [{shift, mask, width, name}], source_functions,
            confidence} iceren dict listesi.
        """
        # var -> {(shift, mask_or_bit): {funcs, ops}}
        bf_map: dict[str, dict[tuple[int, int], dict[str, Any]]] = defaultdict(
            lambda: defaultdict(lambda: {"funcs": set(), "ops": set()})
        )

        c_files = sorted(decompiled_dir.glob("*.c"))
        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # Extract: (var >> N) & MASK
            for m in _BITFIELD_EXTRACT_RE.finditer(content):
                var = m.group("var")
                try:
                    shift = _parse_offset(m.group("shift"))
                    mask = _parse_offset(m.group("mask"))
                except (ValueError, TypeError):
                    continue
                bf_map[var][(shift, mask)]["funcs"].add(func_name)
                bf_map[var][(shift, mask)]["ops"].add("extract")

            # Set: var |= (1 << N) veya var |= MASK
            for m in _BITFIELD_SET_RE.finditer(content):
                var = m.group("var")
                bit_str = m.group("bit")
                mask_str = m.group("mask")
                try:
                    if bit_str:
                        bit = _parse_offset(bit_str)
                        bf_map[var][(bit, 1)]["funcs"].add(func_name)
                        bf_map[var][(bit, 1)]["ops"].add("set")
                    elif mask_str:
                        mask = _parse_offset(mask_str)
                        lowest = _find_lowest_set_bit(mask)
                        bf_map[var][(lowest, mask >> lowest)]["funcs"].add(func_name)
                        bf_map[var][(lowest, mask >> lowest)]["ops"].add("set")
                except (ValueError, TypeError):
                    continue

            # Test: if (var & MASK)
            for m in _BITFIELD_TEST_RE.finditer(content):
                var = m.group("var")
                try:
                    mask = _parse_offset(m.group("mask"))
                except (ValueError, TypeError):
                    continue
                lowest = _find_lowest_set_bit(mask)
                bf_map[var][(lowest, mask >> lowest)]["funcs"].add(func_name)
                bf_map[var][(lowest, mask >> lowest)]["ops"].add("test")

        # Sonuclari birlestir -- en az 2 bitfield erisimi olan degiskenleri raporla
        results: list[dict[str, Any]] = []
        for var, field_map in sorted(bf_map.items()):
            if len(field_map) < 2:
                # Tek erisim bitfield demek degil, ama yine de sinyal olabilir
                # En az 2 farkli shift/mask kombinasyonu aransin
                continue

            fields: list[dict[str, Any]] = []
            all_funcs: set[str] = set()
            all_ops: set[str] = set()

            for (shift, mask), info in sorted(field_map.items()):
                width = _count_set_bits(mask)
                fields.append({
                    "shift": shift,
                    "mask": mask,
                    "width": width,
                    "name": f"bit_{shift}_{shift + width - 1}",
                })
                all_funcs.update(info["funcs"])
                all_ops.update(info["ops"])

            # Confidence: extract + set/test = en yuksek guven
            confidence = 0.75
            if "extract" in all_ops and ("set" in all_ops or "test" in all_ops):
                confidence = 0.88
            if len(fields) >= 4:
                confidence = min(confidence + 0.07, 0.95)

            results.append({
                "var": var,
                "fields": fields,
                "source_functions": sorted(all_funcs),
                "operations": sorted(all_ops),
                "confidence": confidence,
            })

        return results

    # ------------------------------------------------------------------
    # Adim 9: Dispatch Table Detection
    # ------------------------------------------------------------------

    def _detect_dispatch_tables(self, decompiled_dir: Path) -> list[dict[str, Any]]:
        """Function pointer table pattern'lerini bul.

        Ghidra decompiled kodda dispatch table'lar su sekilde gorunur:
        - Computed call: ``(*(code **)(TABLE + idx * 8))(args)``
          idx bir degisken, TABLE sabit adres veya DAT_ degiskeni.
        - Global dispatch: ``(*(code*)(DAT_XXX + off))(args)``
        - Switch-like: Genel code** dereference + call pattern'i.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {table_var, index_var, stride, source_function,
            dispatch_type, confidence} iceren dict listesi.
        """
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()  # (func, table_var) tekrarini onle

        c_files = sorted(decompiled_dir.glob("*.c"))
        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # Computed function call: (*(code**)(TABLE + idx * STRIDE))(...)
            for m in _DISPATCH_COMPUTED_RE.finditer(content):
                table_var = m.group("table")
                idx_var = m.group("idx")
                key = (func_name, table_var)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    stride = _parse_offset(m.group("stride"))
                except (ValueError, TypeError):
                    stride = 8  # default 64-bit pointer

                confidence = 0.85
                # DAT_ prefix = global sabit tablo -> daha yuksek guven
                if table_var.startswith("DAT_"):
                    confidence = 0.90

                results.append({
                    "table_var": table_var,
                    "index_var": idx_var,
                    "stride": stride,
                    "source_function": func_name,
                    "dispatch_type": "computed_call",
                    "confidence": confidence,
                })

            # Global dispatch: (*(code*)(DAT_XXX + off))(...)
            for m in _DISPATCH_GLOBAL_RE.finditer(content):
                base_dat = m.group("base")
                offset_var = m.group("offset")
                key = (func_name, base_dat)
                if key in seen:
                    continue
                seen.add(key)

                results.append({
                    "table_var": base_dat,
                    "index_var": offset_var,
                    "stride": 8,  # pointer-sized dispatch
                    "source_function": func_name,
                    "dispatch_type": "global_dispatch",
                    "confidence": 0.80,
                })

            # Genel switch-like dispatch (dusuk guven)
            switch_matches = list(_DISPATCH_SWITCH_RE.finditer(content))
            # Yukaridakilerde yakalanmayan genel pattern'ler
            for m in switch_matches:
                # Zaten yukaridaki pattern'lerden yakalanmis mi kontrol et
                snippet = content[m.start():m.end()]
                already_caught = False
                for prev in results:
                    if prev["source_function"] == func_name:
                        if prev["table_var"] in snippet:
                            already_caught = True
                            break
                if not already_caught:
                    key_generic = (func_name, f"_switch_{m.start()}")
                    if key_generic not in seen:
                        seen.add(key_generic)
                        results.append({
                            "table_var": "unknown",
                            "index_var": "unknown",
                            "stride": 8,
                            "source_function": func_name,
                            "dispatch_type": "switch_like",
                            "confidence": 0.60,
                        })

        return results

    # ------------------------------------------------------------------
    # Adim 10: Linked List Detection
    # ------------------------------------------------------------------

    def _detect_linked_lists(self, decompiled_dir: Path) -> list[dict[str, Any]]:
        """Self-referencing struct (linked list next pointer) pattern'ini bul.

        Linked list traversal'i Ghidra decompiled kodda su sekilde gorunur:
        - ``ptr = *(TYPE*)(ptr + OFFSET)`` -- ayni degisken hem kaynak hem hedef.
          Bu "next pointer follow" islemidir: ptr = ptr->next.
        - ``while (ptr != NULL) { ... ptr = *(ptr + OFF) ... }`` -- loop ile traversal.

        Ayni degiskenin kendi degerini bir offset'ten guncellemesi, struct'in
        kendi tipine pointer icerdiginin (self-referencing) kaniti.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {pointer_var, next_offset, type_str, source_function,
            has_loop, confidence} iceren dict listesi.
        """
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()  # (func, var, offset)

        c_files = sorted(decompiled_dir.glob("*.c"))
        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # v1.8.0: _LINKED_LIST_RE O(n) safe (negated char class).
            # DOTALL pattern'leri (_LINKED_LIST_LOOP_RE) icin
            # loop keyword etrafinda 5KB pencere kullanilir.

            # Pattern 1: var = *(TYPE*)(var + OFFSET) -- self-update
            for m in _LINKED_LIST_RE.finditer(content):
                var = m.group("var")
                type_str = m.group("type").strip()
                try:
                    offset = _parse_offset(m.group("offset"))
                except (ValueError, TypeError):
                    continue

                key = (func_name, var, offset)
                if key in seen:
                    continue
                seen.add(key)

                # Loop icinde mi kontrol et -> traversal pattern
                # v1.8.0: DOTALL regex'i tam content yerine loop keyword
                # etrafinda 5KB pencere ile calistirilir.
                has_loop = False
                for _loop_chunk in _iter_loop_chunks(content, 5000):
                    loop_match = _LINKED_LIST_LOOP_RE.search(_loop_chunk)
                    if loop_match and loop_match.group("var") == var:
                        has_loop = True
                        break

                # Confidence
                confidence = 0.80
                if has_loop:
                    confidence = 0.92
                # NULL check varsa guven artar
                if re.search(rf"\b{re.escape(var)}\s*!=\s*(?:0|NULL|0x0)\b", content):
                    confidence = min(confidence + 0.05, 0.95)

                results.append({
                    "pointer_var": var,
                    "next_offset": offset,
                    "type_str": type_str,
                    "source_function": func_name,
                    "has_loop": has_loop,
                    "confidence": confidence,
                })

            # Pattern 2: Loop-only match (DOTALL -> chunk-based)
            for _loop_chunk in _iter_loop_chunks(content, 5000):
                for m in _LINKED_LIST_LOOP_RE.finditer(_loop_chunk):
                    var = m.group("var")
                    try:
                        offset = _parse_offset(m.group("offset"))
                    except (ValueError, TypeError):
                        continue

                    key = (func_name, var, offset)
                    if key in seen:
                        continue
                    seen.add(key)

                    results.append({
                        "pointer_var": var,
                        "next_offset": offset,
                        "type_str": "unknown",
                        "source_function": func_name,
                        "has_loop": True,
                        "confidence": 0.88,
                    })

        return results

    # ------------------------------------------------------------------
    # Adim 11: Go-Specific Pattern Detection
    # ------------------------------------------------------------------

    def _detect_go_patterns(self, decompiled_dir: Path) -> list[dict[str, Any]]:
        """Go dilinin runtime yapilarini decompiled C kodunda tespit et.

        Go binary'leri decompile edildiginde su yapilar C'de gorunur:
        - Slice: 24 byte struct (data ptr, len, cap) -- uc ardisik 8-byte field
        - Interface: 16 byte struct (itab ptr, data ptr)
        - Map: runtime.makemap() cagrilari
        - Channel: runtime.makechan() cagrilari

        Bu metod sadece is_go=True oldugunda cagrilir.

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {go_type, base_var/call_site, source_function, confidence,
            details} iceren dict listesi.
        """
        results: list[dict[str, Any]] = []
        seen_slices: set[tuple[str, str]] = set()  # (func, base_var)
        seen_ifaces: set[tuple[str, str]] = set()

        c_files = sorted(decompiled_dir.glob("*.c"))
        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            # Go Slice: 24-byte struct (ptr @0, len @8, cap @16)
            # v1.8.0: DOTALL regex chunk-bazli calistirilir
            for _chunk in _iter_deref_chunks(content):
                for m in _GO_SLICE_RE.finditer(_chunk):
                    base_var = m.group(1)
                    key = (func_name, base_var)
                    if key in seen_slices:
                        continue
                    seen_slices.add(key)
                    results.append({
                        "go_type": "slice",
                        "base_var": base_var,
                        "source_function": func_name,
                        "confidence": 0.88,
                        "details": {
                            "total_size": 24,
                            "fields": [
                                {"name": "data", "offset": 0, "size": 8},
                                {"name": "len", "offset": 8, "size": 8},
                                {"name": "cap", "offset": 16, "size": 8},
                            ],
                        },
                    })

            # Go Interface: 16-byte struct (itab @0, data @8)
            for _chunk in _iter_deref_chunks(content):
                for m in _GO_INTERFACE_RE.finditer(_chunk):
                    base_var = m.group(1)
                    key = (func_name, base_var)
                    if key in seen_ifaces:
                        continue
                    # Slice zaten match ettiyse, slice daha spesifik -> interface'i atla
                    if (func_name, base_var) in seen_slices:
                        continue
                    seen_ifaces.add(key)
                    results.append({
                        "go_type": "interface",
                        "base_var": base_var,
                        "source_function": func_name,
                        "confidence": 0.85,
                        "details": {
                            "total_size": 16,
                            "fields": [
                                {"name": "itab", "offset": 0, "size": 8},
                                {"name": "data", "offset": 8, "size": 8},
                            ],
                        },
                    })

            # Go Map: runtime.makemap() cagrilari
            for m in _GO_MAP_RE.finditer(content):
                results.append({
                    "go_type": "map",
                    "base_var": None,
                    "source_function": func_name,
                    "confidence": 0.80,
                    "details": {"call_site": content[max(0, m.start() - 20):m.end() + 30].strip()},
                })

            # Go Channel: runtime.makechan() cagrilari
            for m in _GO_CHANNEL_RE.finditer(content):
                results.append({
                    "go_type": "channel",
                    "base_var": None,
                    "source_function": func_name,
                    "confidence": 0.78,
                    "details": {"call_site": content[max(0, m.start() - 20):m.end() + 30].strip()},
                })

        return results

    # ------------------------------------------------------------------
    # Adim 12: C++ Vtable Dispatch Detection
    # ------------------------------------------------------------------

    def _detect_vtable_dispatch(self, decompiled_dir: Path) -> list[dict[str, Any]]:
        """C++ vtable dispatch pattern'ini tespit et.

        Ghidra decompiled kodda vtable dispatch su sekilde gorunur:
            (*(code*)(*(long*)obj + VOFF))(obj, args)
        Bu pattern, obj'nin vtable pointer'ini takip edip,
        vtable'daki VOFF offset'teki fonksiyon pointer'ini cagirmaktir.

        Bu, mevcut dispatch table pattern'larindan FARKLI:
        - Dispatch table: TABLE[idx] -- runtime index ile call
        - Vtable: *(*(obj))+OFF -- cift dereference (obj->vtable->method)

        Args:
            decompiled_dir: Decompile C dosyalari dizini.

        Returns:
            Her biri {obj_var, vtable_offset, vtable_index, source_function,
            confidence} iceren dict listesi.
        """
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()  # (func, obj, voff)

        c_files = sorted(decompiled_dir.glob("*.c"))
        max_funcs = self._comp_config.max_functions_per_layer
        if max_funcs > 0:
            c_files = c_files[:max_funcs]

        for c_file in c_files:
            func_name = c_file.stem
            try:
                content = c_file.read_text(errors="replace")
            except OSError:
                continue

            for m in _VTABLE_DISPATCH_RE.finditer(content):
                obj_var = m.group("obj")
                voff_str = m.group("voff")
                try:
                    voff = _parse_offset(voff_str) if voff_str else 0
                except (ValueError, TypeError):
                    voff = 0

                key = (func_name, obj_var, voff)
                if key in seen:
                    continue
                seen.add(key)

                # Confidence: DAT_ prefix (global vtable) -> daha yuksek
                confidence = 0.82
                if obj_var.startswith("DAT_"):
                    confidence = 0.87

                # Vtable index = offset / pointer_size
                vtable_index = voff // 8 if voff > 0 else 0

                results.append({
                    "obj_var": obj_var,
                    "vtable_offset": voff,
                    "vtable_index": vtable_index,
                    "source_function": func_name,
                    "confidence": confidence,
                })

        return results

    # ------------------------------------------------------------------
    # Adim 13: Nested Struct Detection (Heuristic)
    # ------------------------------------------------------------------

    def _detect_nested_structs(
        self,
        structs: list[ConstraintStruct],
        constraints: list[FieldConstraint],
    ) -> None:
        """Struct field'lari icerisinde nested (child) struct'lari tespit et.

        Bir field'in boyutu >= 16 byte ise ve o field'in offset araligi
        icerisinde baska field dereference'lari varsa, child struct olarak
        isaretlenir. Bu Z3 KULLANMAZ, sadece heuristic.

        Sonuc dogrudan struct'larin ``nested_children`` field'ina yazilir (in-place).

        Args:
            structs: Mevcut cozulmus struct listesi (in-place degistirilir).
            constraints: Tum cikarilmis field constraint listesi.
        """
        for struct in structs:
            if not struct.fields:
                continue

            # Her field icin nested child kontrolu
            for i, (field_off, field_type, field_size, field_conf) in enumerate(struct.fields):
                if field_size < 16:
                    continue

                # Bu field'in kapsadigi range: [field_off, field_off + field_size)
                range_start = field_off
                range_end = field_off + field_size

                # Daha basit yaklasim: struct'in kendi field'larina bak
                # field_off < child_off < field_off + field_size olan child field'lar
                child_fields: list[dict[str, Any]] = []
                for j, (cf_off, cf_type, cf_size, cf_conf) in enumerate(struct.fields):
                    if j == i:
                        continue
                    if range_start < cf_off < range_end:
                        child_fields.append({
                            "offset": cf_off,
                            "relative_offset": cf_off - field_off,
                            "type": cf_type,
                            "size": cf_size,
                            "confidence": cf_conf,
                        })

                if len(child_fields) >= 2:
                    # Bu field icerisinde birden fazla sub-field tespit edildi -> nested struct
                    struct.nested_children.append({
                        "parent_field_offset": field_off,
                        "parent_field_size": field_size,
                        "parent_field_type": f"struct child_{i}",
                        "child_fields": child_fields,
                        "confidence": min(field_conf, 0.75),
                    })
                    logger.debug(
                        "Nested struct tespit: %s field@%d (%d byte) -> %d child field",
                        struct.name, field_off, field_size, len(child_fields),
                    )
