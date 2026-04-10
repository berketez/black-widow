"""C Tip Recovery -- Ghidra decompile ciktisindaki generic tipleri gercek tiplere donustur.

Ghidra'nin urettigi ``undefined8``, ``long *``, ``void *`` gibi generic
tipleri, kullanim pattern'lerinden analiz ederek gercek struct, enum ve
vtable tanimlarina donusturur.

Capabilities:
    1. Struct Recovery  -- field access pattern'lerinden struct sentezle
    2. Enum Recovery    -- switch/case ve compare pattern'lerinden enum cikar
    3. VTable Recovery  -- function pointer array'lerinden vtable tanimla
    4. Type Propagation -- ``undefined*`` tiplerini baglama gore coz
    5. Ghidra Tip Duzeltme -- ``undefined8`` -> ``void*``/``long`` vb.

Kullanim:
    from karadul.reconstruction.c_type_recoverer import CTypeRecoverer
    from karadul.config import Config

    recoverer = CTypeRecoverer(Config())
    result = recoverer.recover(
        decompiled_dir=Path("decompiled"),
        functions_json=Path("functions.json"),
        output_dir=Path("recovered"),
    )
    print(f"Structs: {len(result.structs)}, Enums: {len(result.enums)}")
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config

# ---------------------------------------------------------------------------
# ProcessPoolExecutor worker'lari -- top-level (pickle edilebilir)
# ---------------------------------------------------------------------------


def _parse_c_file_worker(c_file_path: str) -> dict[str, Any]:
    """Tek bir C dosyasini parse et, pattern'leri topla (process-safe).

    ProcessPoolExecutor icin top-level fonksiyon.  Shared state yerine
    sonuclari dict olarak dondurur; ana process merge eder.

    Returns:
        {
            "file": str,
            "field_accesses": [(base, offset_str, raw_type, func, line), ...],
            "vtable_entries": [(base, offset, func_name, source_func), ...],
            "switch_vars": {var: [int, ...]},
            "compare_vars": {var: [int, ...]},
            "string_context": {var: str},
            "type_usages": dict[str, list[str]],  -- var -> [tag, ...]
            "case_comments": {var: {int_val: "name"}},
            "errors": [str, ...],
        }
    """
    c_file = Path(c_file_path)
    errors: list[str] = []

    try:
        content = c_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"file": c_file_path, "errors": [f"C dosyasi okunamadi: {c_file}: {exc}"],
                "field_accesses": [], "vtable_entries": [],
                "switch_vars": {}, "compare_vars": {},
                "string_context": {}, "type_usages": {},
                "case_comments": {}}

    current_func = c_file.stem

    field_accesses: list[tuple] = []
    vtable_entries: list[tuple[str, int, str, str]] = []
    switch_vars: dict[str, list[int]] = {}
    compare_vars: dict[str, list[int]] = {}
    string_context: dict[str, str] = {}
    # type_usages: worker icinde filtrele, sadece match eden (var, tag) dondur
    type_usages: dict[str, list[str]] = {}  # var -> [tag, ...]
    case_comments: dict[str, dict[int, str]] = {}

    # Pre-compiled type usage regex'leri (her process'te bir kez)
    _str_func_re = re.compile(
        r"(?:strcmp|strncmp|strlen|strcpy|strncpy|strcat|strncat"
        r"|printf|sprintf|snprintf|puts|fputs|strstr|strchr)\s*\(\s*(\w+)"
    )
    _bool_re = re.compile(r"if\s*\(\s*!?\s*(\w+)\s*\)")
    _alloc_re = re.compile(r"(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(")
    # v1.7.2: Ek context-aware type usage regex'leri
    _deref_re = re.compile(r"\*\s*(\w+)\s*[;=,)\]]")  # *var -- pointer dereference
    _ptr_arith_re = re.compile(r"(\w+)\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)")  # var + offset (pointer arithmetic)
    _array_re = re.compile(r"(\w+)\s*\[\s*(?:\w+|\d+)\s*\]")  # var[idx] -- array/pointer
    _arith_re = re.compile(
        r"(\w+)\s*[+\-*/%]\s*(?:\w+|\d+)"  # var +/- ... arithmetic
    )
    # v1.8: Float literal assignment -- var = ... * 3.14 veya var = 1.0e-5
    _float_assign_re = re.compile(
        r"(\w+)\s*=\s*[^;]*\b(\d+\.\d+(?:e[+\-]?\d+)?)\b",
        re.IGNORECASE,
    )
    # v1.8: malloc/calloc/realloc return capture: var = (TYPE *)malloc(...)
    _malloc_cast_re = re.compile(
        r"(\w+)\s*=\s*\(\s*([a-zA-Z_][\w\s]*\*)\s*\)\s*(?:malloc|calloc|realloc)\s*\("
    )
    # v1.8: Pointer cast in dereference -- *(TYPE *)(var + offset) -- captures var & TYPE
    _cast_deref_re = re.compile(
        r"\*\(\s*(?P<type>[a-zA-Z_][\w\s]*\*)\s*\)\s*\(\s*(?P<var>\w+)\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)"
    )
    # v1.8: in_stack parameter detection
    _in_stack_param_re = re.compile(r"\b(in_stack_[0-9a-fA-F]+)\b")
    _cmp_re = re.compile(
        r"(\w+)\s*[<>]=?\s*(?:\w+|\d+)"  # var < N, var >= N -- signed comparison
    )
    _shift_re = re.compile(r"(\w+)\s*(?:<<|>>)\s*\d+")  # var << N -- bitwise
    _sizeof_cast_re = re.compile(
        r"(?:sizeof|__sizeof)\s*\(\s*(\w+)\s*\)"  # sizeof(var) -- struct hint
    )
    # Fonksiyon cagrisi: func(arg1, arg2, ...) -- arguman pozisyon takibi
    _func_call_re = re.compile(
        r"(\w+)\s*\(([^)]*)\)"  # func(args)
    )
    # Return statement: return var;
    _return_re = re.compile(r"\breturn\s+(\w+)\s*;")
    # Variable declaration: TYPE var_name;
    _var_decl_re = re.compile(
        r"^\s*(?P<type>(?:undefined[1248]?|int|long|short|char|uint\d+_t|"
        r"int\d+_t|float|double|void|bool|_Bool|ulong|uint|byte)"
        r"(?:\s*\*)*)\s+(?P<var>\w+)\s*[;=]"
    )

    for line in content.split("\n"):
        stripped = line.strip()

        # Fonksiyon tanimlama tespiti
        func_match = _FUNC_DEF.match(stripped)
        if func_match:
            current_func = func_match.group("fname")

        # 1. Field access (write)
        for m in _FIELD_ACCESS_WRITE.finditer(line):
            base = m.group("base")
            raw_type = m.group("type").strip()
            offset_str = m.group("offset")
            field_accesses.append((base, offset_str, raw_type, current_func, line))

        # 2. Field access (read)
        for m in _FIELD_ACCESS_READ.finditer(line):
            base = m.group("base")
            raw_type = m.group("type").strip()
            offset_str = m.group("offset")
            field_accesses.append((base, offset_str, raw_type, current_func, line))

        # 3. VTable assignment
        for m in _VTABLE_ASSIGN.finditer(line):
            base = m.group("base")
            offset_str = m.group("offset")
            offset = int(offset_str, 16) if offset_str.startswith(("0x", "0X")) else int(offset_str)
            func_name = m.group("func")
            vtable_entries.append((base, offset, func_name, current_func))

        # 4. Switch/case
        sw = _SWITCH_START.search(line)
        if sw:
            var = sw.group("var")
            if var not in switch_vars:
                switch_vars[var] = []

        for cm in _CASE_VALUE.finditer(line):
            val_str = cm.group("val")
            val = int(val_str, 16) if val_str.startswith(("0x", "0X")) else int(val_str)
            if switch_vars:
                last_var = list(switch_vars.keys())[-1]
                if val not in switch_vars[last_var]:
                    switch_vars[last_var].append(val)

        # 4b. Case yorumlarindan enum isimleri
        for ccm in _CASE_COMMENT.finditer(line):
            comment_text = ccm.group("comment")
            if comment_text and switch_vars:
                comment_text = comment_text.strip().rstrip("*/").strip()
                if re.match(r'^[A-Za-z_]\w*$', comment_text):
                    val_str = ccm.group("val")
                    val = int(val_str, 16) if val_str.startswith(("0x", "0X")) else int(val_str)
                    last_var = list(switch_vars.keys())[-1]
                    if last_var not in case_comments:
                        case_comments[last_var] = {}
                    case_comments[last_var][val] = comment_text

        # 5. Comparison constants
        for cmp in _COMPARE_CONST.finditer(line):
            var = cmp.group("var")
            val_str = cmp.group("val")
            val = int(val_str, 16) if val_str.startswith(("0x", "0X")) else int(val_str)
            if var not in compare_vars:
                compare_vars[var] = []
            if val not in compare_vars[var]:
                compare_vars[var].append(val)

        # 6. String assigns
        for sm in _STRING_ASSIGN.finditer(line):
            string_context[sm.group("var")] = sm.group("str")

        # 7. Type usage tracking ��� worker icinde filtrele (IPC azalt)
        m = _str_func_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("string_func_arg")
        m = _bool_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("boolean_test")
        m = _alloc_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("alloc_result")

        # v1.7.2: Ek context tespiti
        m = _deref_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("pointer_deref")
        m = _ptr_arith_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("pointer_arithmetic")
        m = _array_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("array_access")
        m = _shift_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("bitwise_op")
        m = _cmp_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("comparison")
        m = _arith_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("arithmetic")
        # v1.8: Float literal assignment
        m = _float_assign_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append("float_literal_assign")
        # v1.8: Typed malloc cast -- var = (double *)malloc(...)
        m = _malloc_cast_re.search(stripped)
        if m:
            var = m.group(1)
            cast_type = m.group(2).strip()
            type_usages.setdefault(var, []).append(f"malloc_cast:{cast_type}")
        # v1.8: Pointer cast dereference -- *(double *)(param_1 + 0x10)
        for cm in _cast_deref_re.finditer(stripped):
            var = cm.group("var")
            cast_type = cm.group("type").strip()
            type_usages.setdefault(var, []).append(f"cast_deref:{cast_type}")
        # v1.8: in_stack parameter detection
        for ism in _in_stack_param_re.finditer(stripped):
            var = ism.group(1)
            type_usages.setdefault(var, []).append(f"in_stack_usage:{current_func}")
        # Return: hangi degisken return ediliyor?
        m = _return_re.search(stripped)
        if m:
            var = m.group(1)
            type_usages.setdefault(var, []).append(f"return_in:{current_func}")
        # Fonksiyon cagrisi arguman takibi
        for fm in _func_call_re.finditer(stripped):
            callee_name = fm.group(1)
            args_str = fm.group(2)
            if callee_name in ("if", "while", "for", "switch", "sizeof", "return"):
                continue
            arg_list = [a.strip() for a in args_str.split(",") if a.strip()]
            for arg_idx, arg_val in enumerate(arg_list):
                # Sadece basit degisken isimleri (orn: param_1, local_8)
                if re.match(r"^[a-zA-Z_]\w*$", arg_val):
                    # v1.7.2: caller fonksiyon ismini de ekle
                    type_usages.setdefault(arg_val, []).append(
                        f"call_arg:{callee_name}:{arg_idx}:{current_func}"
                    )
        # Variable declaration: tip bilgisini kaydet
        dm = _var_decl_re.match(stripped)
        if dm:
            var = dm.group("var")
            declared_type = dm.group("type").strip()
            type_usages.setdefault(var, []).append(f"declared:{declared_type}")

    return {
        "file": c_file_path,
        "field_accesses": field_accesses,
        "vtable_entries": vtable_entries,
        "switch_vars": switch_vars,
        "compare_vars": compare_vars,
        "string_context": string_context,
        "type_usages": type_usages,
        "case_comments": case_comments,
        "errors": errors,
    }


def _apply_types_worker(
    input_path: str,
    output_path: str,
    replacements: dict[str, str],
    per_func_replacements: dict[str, dict[str, str]] | None = None,
) -> str:
    """C dosyasindaki generic tipleri kurtarilan tiplerle degistir (process-safe).

    ProcessPoolExecutor icin top-level fonksiyon.

    v1.7.2: per_func_replacements destegi eklendi.  Her fonksiyonun scope'u
    icinde degisken bazli tip degisimi yapilir.  Format:
        {func_name: {old_decl_pattern: new_decl_pattern, ...}}

    Returns:
        output_path (basarili) veya bos string (hata).
    """
    try:
        content = Path(input_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    # --- Per-function replacements (v1.7.2) ---
    # Her fonksiyon scope'unda variable-specific tip degisimi uygula.
    # Fonksiyon sinirlarini bul, scope icinde replace yap.
    if per_func_replacements:
        content = _apply_per_func_replacements(content, per_func_replacements)

    # undefined* tiplerini degistir + context-bazli replacements
    all_replacements = dict(_UNDEFINED_DEFAULTS)
    all_replacements.update(replacements)

    # TEK combined regex ile tek geciste tum replace
    sorted_keys = sorted(all_replacements.keys(), key=len, reverse=True)
    if sorted_keys:
        combined = re.compile(
            r"\b(" + "|".join(re.escape(k) for k in sorted_keys) + r")\b"
        )
        content = combined.sub(
            lambda m: all_replacements.get(m.group(0), m.group(0)), content,
        )

    # types.h include ekle
    if not content.startswith("#include"):
        content = '#include "types.h"\n\n' + content
    elif '#include "types.h"' not in content:
        content = content.replace(
            "\n#include",
            '\n#include "types.h"\n#include',
            1,
        )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return output_path


def _apply_per_func_replacements(
    content: str,
    per_func: dict[str, dict[str, str]],
) -> str:
    """Fonksiyon scope'lari icinde degisken bazli tip degisimi uygula.

    Strateji: Her fonksiyon tanimini bul, scope icinde (brace matching ile)
    variable declaration'lari degistir.  Global scope'a dokunmaz.

    per_func format:
        {func_name: {"undefined8 param_1": "void * param_1", ...}}
    """
    if not per_func:
        return content

    _func_def = re.compile(
        r"^(?P<rtype>[\w\s\*]+?)\s+"
        r"(?P<fname>FUN_[0-9a-fA-F]+|_\w+|[a-z_]\w*)"
        r"\s*\((?P<params>[^)]*)\)",
        re.MULTILINE,
    )

    result_parts: list[str] = []
    last_end = 0

    for m in _func_def.finditer(content):
        fname = m.group("fname")
        if fname not in per_func:
            continue

        func_replacements = per_func[fname]
        if not func_replacements:
            continue

        # Fonksiyon basini kaydet
        func_start = m.start()

        # Fonksiyon body sonu: opening brace'den kapanan brace'e
        body_start = content.find("{", m.end())
        if body_start == -1:
            continue

        # Brace matching
        depth = 0
        body_end = body_start
        for i in range(body_start, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    body_end = i + 1
                    break
        else:
            body_end = len(content)

        # func_start'a kadar oldubu gibi al
        result_parts.append(content[last_end:func_start])

        # Fonksiyon header + body al, icinde replace yap
        func_text = content[func_start:body_end]
        for old_str, new_str in func_replacements.items():
            func_text = func_text.replace(old_str, new_str, 1)

        result_parts.append(func_text)
        last_end = body_end

    result_parts.append(content[last_end:])
    return "".join(result_parts)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Veri Yapilari
# ---------------------------------------------------------------------------


@dataclass
class StructField:
    """Bir struct field'i.

    Attributes:
        offset: Byte offset (struct icindeki konum).
        name: Field adi (orn: ``field_10``, ``name``).
        type: C tipi (orn: ``long``, ``char *``).
        size: Field boyutu (byte).
        confidence: Tespit guven skoru (0.0-1.0).
    """

    offset: int
    name: str
    type: str
    size: int
    confidence: float = 0.8


@dataclass
class RecoveredStruct:
    """Kurtarilan struct tanimi.

    Attributes:
        name: Struct adi (orn: ``recovered_struct_001``).
        fields: Field listesi (offset'e gore sirali).
        total_size: Toplam boyut (byte).
        source_functions: Hangi fonksiyonlarda tespit edildigi.
        alignment: Alignment (ARM64 icin 8).
    """

    name: str
    fields: list[StructField]
    total_size: int
    source_functions: list[str]
    alignment: int = 8


@dataclass
class RecoveredEnum:
    """Kurtarilan enum tanimi.

    Attributes:
        name: Enum adi.
        values: {isim: int_deger} eslesmesi.
        source_functions: Tespit edilen fonksiyonlar.
    """

    name: str
    values: dict[str, int]
    source_functions: list[str]


@dataclass
class RecoveredVTable:
    """Kurtarilan vtable (function pointer array).

    Attributes:
        name: VTable adi.
        methods: (offset, fonksiyon_adi, tahmini_signature) listesi.
        source_functions: Tespit edilen fonksiyonlar.
    """

    name: str
    methods: list[tuple[int, str, str]]  # (offset, func_name, signature)
    source_functions: list[str]


@dataclass
class CTypeRecoveryResult:
    """Tip recovery pipeline sonucu.

    Attributes:
        success: Islem basarili mi.
        structs: Kurtarilan struct'lar.
        enums: Kurtarilan enum'lar.
        vtables: Kurtarilan vtable'lar.
        type_replacements: eski_tip -> yeni_tip eslesmesi.
        types_header: Uretilen types.h dosya yolu.
        output_files: Tip duzeltilmis C dosyalari.
        total_types_recovered: Toplam kurtarilan tip sayisi.
        errors: Hata mesajlari.
    """

    success: bool
    structs: list[RecoveredStruct] = field(default_factory=list)
    enums: list[RecoveredEnum] = field(default_factory=list)
    vtables: list[RecoveredVTable] = field(default_factory=list)
    type_replacements: dict[str, str] = field(default_factory=dict)
    types_header: Path | None = None
    output_files: list[Path] = field(default_factory=list)
    total_types_recovered: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex Pattern'leri -- Ghidra C Ciktisi Analizi
# ---------------------------------------------------------------------------

# Field access: *(TYPE *)(base + OFFSET) = ...
# Ornekler:
#   *(long *)(param_1 + 0x10) = value;
#   *(int *)(param_1 + 0x18) = 42;
#   *(char **)(param_1 + 0x20) = "hello";
#   *(undefined8 *)(param_1 + 8) = ...;
_FIELD_ACCESS_WRITE = re.compile(
    r"\*\(\s*"
    r"(?P<type>[a-zA-Z_][\w\s]*\*{0,2})\s*\*?\s*\)"   # cast type
    r"\(\s*"
    r"(?P<base>\w+)"                                     # base pointer
    r"\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)"                   # offset
    r"\s*\)"
    r"\s*="                                               # assignment
)

# Field access (okuma): ... = *(TYPE *)(base + OFFSET);
_FIELD_ACCESS_READ = re.compile(
    r"=\s*\*\(\s*"
    r"(?P<type>[a-zA-Z_][\w\s]*\*{0,2})\s*\*?\s*\)"
    r"\(\s*"
    r"(?P<base>\w+)"
    r"\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)"
    r"\s*\)"
)

# Direct struct-like access: base->field veya base[offset]
_ARROW_ACCESS = re.compile(
    r"(?P<base>\w+)->(?P<field>\w+)"
)

# Function pointer assignment: *(code **)(obj + OFFSET) = FUN_xxx;
_VTABLE_ASSIGN = re.compile(
    r"\*\(\s*code\s*\*{1,2}\s*\)\(\s*"
    r"(?P<base>\w+)"
    r"\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)"
    r"\s*\)\s*=\s*"
    r"(?P<func>FUN_[0-9a-fA-F]+|_\w+)"
)

# Switch statement: case N: ...
_SWITCH_START = re.compile(r"switch\s*\(\s*(?P<var>\w+)\s*\)")
_CASE_VALUE = re.compile(r"case\s+(?P<val>-?\d+|0x[0-9a-fA-F]+)\s*:")

# Case satiri + yorum: case 0x24: // kEnterKey
# Ghidra bazen case degerlerinin yanina enum/sabit ismini yorum olarak yazar.
_CASE_COMMENT = re.compile(
    r"case\s+(?P<val>-?\d+|0x[0-9a-fA-F]+)\s*:\s*"
    r"(?:/[/*]\s*(?P<comment>\w[\w\s,.*/-]*))?",
)

# Comparison: if (var == N) / if (var != N)
_COMPARE_CONST = re.compile(
    r"if\s*\(\s*(?P<var>\w+)\s*[!=]=\s*(?P<val>-?\d+|0x[0-9a-fA-F]+)\s*\)"
)

# Ghidra fonksiyon tanimi: return_type FUN_xxx(params...)
_FUNC_DEF = re.compile(
    r"^(?P<rtype>[\w\s\*]+?)\s+"
    r"(?P<fname>FUN_[0-9a-fA-F]+|_\w+|[a-z_]\w*)"
    r"\s*\((?P<params>[^)]*)\)",
    re.MULTILINE,
)

# String literal iceren satir
_STRING_ASSIGN = re.compile(
    r'(?P<var>\w+)\s*=\s*"(?P<str>[^"]*)"'
)

# undefined* tipleri
_UNDEFINED_TYPE = re.compile(r"\bundefined(?P<size>[1248])?\b")

# ---------------------------------------------------------------------------
# Tip boyut tablosu
# ---------------------------------------------------------------------------

_TYPE_SIZES: dict[str, int] = {
    "char": 1,
    "uint8_t": 1,
    "int8_t": 1,
    "byte": 1,
    "undefined1": 1,
    "short": 2,
    "uint16_t": 2,
    "int16_t": 2,
    "undefined2": 2,
    "int": 4,
    "uint": 4,
    "uint32_t": 4,
    "int32_t": 4,
    "float": 4,
    "undefined4": 4,
    "long": 8,
    "ulong": 8,
    "uint64_t": 8,
    "int64_t": 8,
    "double": 8,
    "undefined8": 8,
    "undefined": 8,  # varsayilan 8 (ARM64)
    "void *": 8,
    "char *": 8,
    "code *": 8,
    "long *": 8,
    "int *": 8,
}

# Ghidra undefined* -> gercek tip haritalamasi (baglam olmadan varsayilan)
_UNDEFINED_DEFAULTS: dict[str, str] = {
    "undefined1": "uint8_t",
    "undefined2": "uint16_t",
    "undefined4": "int32_t",
    "undefined8": "uint64_t",
    "undefined": "uint64_t",
}


# ---------------------------------------------------------------------------
# Ana Sinif
# ---------------------------------------------------------------------------


class CTypeRecoverer:
    """Ghidra decompile ciktisindaki generic tipleri gercek tiplere donusturur.

    Field access pattern'lerinden struct sentezler, switch/case'lerden enum
    cikarir, function pointer array'lerden vtable tanimlar. Sonucu ``types.h``
    ve tip-duzeltilmis C dosyalari olarak yazar.

    Args:
        config: Merkezi konfigurasyon.
        min_fields_for_struct: Struct olarak kabul edilecek minimum field sayisi.
        alignment: Struct alignment (byte). ARM64 icin 8.
        min_enum_values: Enum olarak kabul edilecek minimum deger sayisi.
    """

    def __init__(
        self,
        config: Config,
        min_fields_for_struct: int = 2,
        alignment: int = 8,
        min_enum_values: int = 3,
    ) -> None:
        self.config = config
        self.min_fields_for_struct = min_fields_for_struct
        self.alignment = alignment
        self.min_enum_values = min_enum_values

        # Ic state -- recover() baslangicinda sifirlanir
        # FIX 1: _field_accesses artik dict[str, dict[int, dict]] -- key=offset (O(1) lookup)
        self._field_accesses: dict[str, dict[int, dict[str, Any]]] = {}
        self._vtable_entries: dict[str, list[dict[str, Any]]] = {}
        self._switch_vars: dict[str, list[int]] = {}
        self._compare_vars: dict[str, list[int]] = {}
        self._string_context: dict[str, str] = {}  # var -> string
        self._func_signatures: dict[str, dict[str, Any]] = {}
        self._type_usage: dict[str, list[str]] = {}  # var -> [kullanim_context]
        # case yorum isimleri: {var: {int_val: "kEnterKey"}}
        self._case_comment_names: dict[str, dict[int, str]] = {}
        # v1.8: Ghidra pcode_high_vars -- {func_name: {var_name: resolved_type}}
        self._ghidra_high_vars: dict[str, dict[str, str]] = {}

        # FIX 2: _state_lock ve import threading kaldirildi (ProcessPool'da gereksiz)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def recover(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        output_dir: Path,
        strings_json: Path | None = None,
        ghidra_types_json: Path | None = None,
        computation_structs: list[dict] | None = None,
        call_graph_json: Path | None = None,
        decompiled_json: Path | None = None,
    ) -> CTypeRecoveryResult:
        """Tam tip recovery pipeline'i calistir.

        1. Ghidra tip bilgisini yukle (varsa)
        1b. Ghidra pcode_high_vars tip bilgisini yukle (varsa) [v1.8]
        2. Tum C dosyalarini parse et
        3. Field access pattern'leri topla
        4. Struct'lari sentezle (Ghidra + pattern-based)
        5. Enum'lari sentezle (Ghidra + pattern-based)
        6. VTable'lari tespit et
        6b. Computation recovery struct'larini merge et (varsa)
        6c. Struct type application -- struct'lari degisken tiplerinde kullan
        7. types.h olustur
        8. C dosyalarindaki tipleri degistir (context-aware + call-graph propagation)

        Args:
            decompiled_dir: Ghidra decompile ciktisi dizini (``*.c`` dosyalari).
            functions_json: Fonksiyon metadata JSON dosyasi.
            output_dir: Cikti dizini.
            strings_json: String metadata JSON dosyasi (opsiyonel).
            ghidra_types_json: Ghidra tip recovery JSON dosyasi (opsiyonel).
                Varsa icindeki struct/enum tanimlari dogrudan sonuca eklenir.
            computation_structs: Computation recovery'den gelen rafine struct
                tanimlari.  Her dict ``{name, fields: [{offset, type, size,
                confidence}], total_size, source_functions, ...}`` formatinda.
            call_graph_json: Call graph JSON dosyasi (opsiyonel).
                Varsa inter-procedural type propagation yapilir.
            decompiled_json: Ghidra decompiled.json dosyasi (opsiyonel).
                Varsa pcode_high_vars icindeki resolved tipler kullanilir.
                Her fonksiyonun degiskenleri icin Ghidra'nin P-Code analysis'inden
                gelen tip bilgisi dogrudan uygulanir (v1.8).

        Returns:
            CTypeRecoveryResult: Sonuc.
        """
        errors: list[str] = []

        # Reset state
        self._reset_state()

        # Girdi dogrulama
        decompiled_dir = Path(decompiled_dir)
        if not decompiled_dir.exists():
            return CTypeRecoveryResult(
                success=False,
                errors=[f"Decompiled dizini bulunamadi: {decompiled_dir}"],
            )

        c_files = sorted(decompiled_dir.glob("*.c"))
        if not c_files:
            return CTypeRecoveryResult(
                success=False,
                errors=[f"Dizinde C dosyasi bulunamadi: {decompiled_dir}"],
            )

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 0. Ghidra tip bilgisini yukle (varsa)
        ghidra_structs: list[RecoveredStruct] = []
        ghidra_enums: list[RecoveredEnum] = []
        if ghidra_types_json:
            ghidra_types_json = Path(ghidra_types_json)
            if ghidra_types_json.exists():
                ghidra_structs, ghidra_enums = self._load_ghidra_types(
                    ghidra_types_json, errors,
                )
                logger.info(
                    "Ghidra tip bilgisi yuklendi: %d struct, %d enum",
                    len(ghidra_structs), len(ghidra_enums),
                )

        # 0a. Ghidra pcode_high_vars tip bilgisini yukle (v1.8)
        if decompiled_json:
            decompiled_json = Path(decompiled_json)
            if decompiled_json.exists():
                self._load_ghidra_high_vars(decompiled_json, errors)
                logger.info(
                    "Ghidra pcode_high_vars yuklendi: %d fonksiyon",
                    len(self._ghidra_high_vars),
                )

        # 0b. Fonksiyon metadata yukle
        func_meta = self._load_functions_json(functions_json, errors)

        # 0c. String context yukle
        if strings_json and Path(strings_json).exists():
            self._load_strings_json(Path(strings_json), errors)

        # 1. Tum C dosyalarini parse et (paralel -- ProcessPool, GIL bypass)
        # FIX 4: pool.map yerine pool.submit + as_completed(timeout=300)
        # FIX 5: pool.submit per-task gonderim yapar (efektif chunksize=1),
        #   bu da eski sabit chunksize=64'ten daha granular kontrol saglar.
        from concurrent.futures import (
            BrokenExecutor,
            ProcessPoolExecutor,
            as_completed,
        )
        num_workers = os.cpu_count() or CPU_PERF_CORES
        logger.info(
            "C dosyalari parse ediliyor: %d dosya (%d process)",
            len(c_files), num_workers,
        )
        file_paths = [str(f) for f in c_files]
        with ProcessPoolExecutor(max_workers=num_workers) as pool:
            futs = {
                pool.submit(_parse_c_file_worker, fp): fp
                for fp in file_paths
            }
            try:
                for fut in as_completed(futs, timeout=1200):
                    try:
                        result = fut.result(timeout=300)
                    except TimeoutError:
                        errors.append(f"Parse timeout: {futs[fut]}")
                        continue
                    except Exception as exc:
                        errors.append(f"Parse worker hatasi ({futs[fut]}): {exc}")
                        continue
                    if result["errors"]:
                        errors.extend(result["errors"])
                    self._merge_parse_result(result)
            except TimeoutError:
                errors.append(
                    "Parse asamasi toplam timeout (1200s) asildi, "
                    "bazi dosyalar islenmemis olabilir"
                )
            except BrokenExecutor as exc:
                errors.append(f"ProcessPool crash: {exc}")

        # 2. Struct'lari sentezle (pattern-based)
        pattern_structs = self._synthesize_structs()
        logger.info("Pattern-based struct sentezlendi: %d adet", len(pattern_structs))

        # 3. Enum'lari sentezle (pattern-based)
        pattern_enums = self._synthesize_enums()
        logger.info("Pattern-based enum sentezlendi: %d adet", len(pattern_enums))

        # 4. Ghidra + pattern-based sonuclari birlestir
        structs = ghidra_structs + pattern_structs
        enums = ghidra_enums + pattern_enums

        # 4b. Computation Recovery struct'larini merge et (varsa)
        _comp_merged = 0
        if computation_structs:
            existing_names = {s.name for s in structs}
            for cs in computation_structs:
                struct_name = cs.get("name", "")
                raw_fields = cs.get("fields", [])
                if not struct_name or not raw_fields:
                    continue
                # Ayni isimli struct zaten varsa atlayalim --
                # Ghidra/pattern kaynaklisi daha guvenilir.
                if struct_name in existing_names:
                    logger.debug(
                        "Computation struct '%s' zaten mevcut, atlaniyor",
                        struct_name,
                    )
                    continue
                # ConstraintStruct dict'ini RecoveredStruct'a donustur
                fields = []
                for rf in raw_fields:
                    fields.append(StructField(
                        offset=rf.get("offset", 0),
                        name=rf.get("name", f"field_{rf.get('offset', 0):02x}"),
                        type=rf.get("type", "undefined8"),
                        size=rf.get("size", 8),
                        confidence=rf.get("confidence", 0.6),
                    ))
                rec_struct = RecoveredStruct(
                    name=struct_name,
                    fields=sorted(fields, key=lambda f: f.offset),
                    total_size=cs.get("total_size", 0),
                    source_functions=cs.get("source_functions", []),
                    alignment=cs.get("alignment", 8),
                )
                structs.append(rec_struct)
                existing_names.add(struct_name)
                _comp_merged += 1
            if _comp_merged:
                logger.info(
                    "Computation struct merge: %d adet eklendi", _comp_merged,
                )

        # 5. VTable'lari tespit et
        vtables = self._synthesize_vtables()
        logger.info("VTable tespit edildi: %d adet", len(vtables))

        # 5b. Call graph yukle (varsa)
        call_graph_data: dict[str, Any] = {}
        if call_graph_json:
            call_graph_json = Path(call_graph_json)
            if call_graph_json.exists():
                call_graph_data = self._load_call_graph(call_graph_json, errors)
                logger.info(
                    "Call graph yuklendi: %d node",
                    len(call_graph_data),
                )

        # 6. Type propagation -- context-aware + call-graph + struct application
        type_replacements, per_func_replacements = self._propagate_types_v2(
            func_meta, structs, call_graph_data,
        )
        logger.info(
            "Tip degisimi: %d global, %d fonksiyon-bazli",
            len(type_replacements), len(per_func_replacements),
        )

        # 7. types.h olustur
        types_header = output_dir / "types.h"
        self._write_types_header(types_header, structs, enums, vtables)
        logger.info("types.h yazildi: %s", types_header)

        # 8. C dosyalarindaki tipleri degistir (paralel -- ProcessPool)
        # FIX 4: fut.result(timeout=120) + crash recovery
        num_workers = os.cpu_count() or CPU_PERF_CORES
        logger.info(
            "Tip degisimi uygulaniyor: %d dosya (%d process)",
            len(c_files), num_workers,
        )
        apply_args = [
            (
                str(f),
                str(output_dir / f.name),
                type_replacements,
                per_func_replacements,
            )
            for f in c_files
        ]
        output_files: list[Path] = []
        with ProcessPoolExecutor(max_workers=num_workers) as pool:
            futs_apply = [pool.submit(_apply_types_worker, *args) for args in apply_args]
            for i, fut in enumerate(futs_apply):
                try:
                    r = fut.result(timeout=600)
                    if r:
                        output_files.append(Path(r))
                except TimeoutError:
                    errors.append(f"Apply timeout: {apply_args[i][0]}")
                except BrokenExecutor as exc:
                    errors.append(f"Apply ProcessPool crash: {exc}")
                    break
                except Exception as exc:
                    errors.append(f"Apply worker hatasi ({apply_args[i][0]}): {exc}")

        total = len(structs) + len(enums) + len(vtables)

        logger.info(
            "CTypeRecovery tamamlandi: %d struct (%d ghidra + %d pattern), "
            "%d enum (%d ghidra + %d pattern), %d vtable, %d tip degisimi",
            len(structs), len(ghidra_structs), len(pattern_structs),
            len(enums), len(ghidra_enums), len(pattern_enums),
            len(vtables), len(type_replacements),
        )

        return CTypeRecoveryResult(
            success=True,
            structs=structs,
            enums=enums,
            vtables=vtables,
            type_replacements=type_replacements,
            types_header=types_header,
            output_files=output_files,
            total_types_recovered=total,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # State Management
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        """Ic state'i sifirla (her recover() cagirisinda)."""
        self._field_accesses.clear()
        self._vtable_entries.clear()
        self._switch_vars.clear()
        self._compare_vars.clear()
        self._string_context.clear()
        self._func_signatures.clear()
        self._type_usage.clear()
        self._case_comment_names.clear()
        self._ghidra_high_vars.clear()

    def _merge_parse_result(self, result: dict[str, Any]) -> None:
        """ProcessPool worker'dan donen parse sonucunu ic state'e merge et.

        FIX 1: _field_accesses artik dict[str, dict[int, dict]] --
        key=offset int, O(1) lookup (eskiden list scan O(N*M) idi).
        """
        # Field accesses — _record_field_access ile ayni mantik
        for base, offset_str, raw_type, func, line in result["field_accesses"]:
            offset = self._parse_int(offset_str)
            c_type = self._normalize_type(raw_type)
            c_type = self._deref_cast_type(c_type)
            size = self._get_type_size(c_type)

            if base not in self._field_accesses:
                self._field_accesses[base] = {}

            # FIX 1: O(1) dict lookup yerine eski O(N) list scan
            if offset in self._field_accesses[base]:
                existing = self._field_accesses[base][offset]
                if c_type != "undefined8" and existing["type"] == "undefined8":
                    existing["type"] = c_type
                    existing["size"] = size
                    existing["confidence"] = min(existing["confidence"] + 0.1, 1.0)
                existing["sources"].add(func)
            else:
                self._field_accesses[base][offset] = {
                    "offset": offset, "type": c_type, "size": size,
                    "confidence": 0.8,
                    "sources": {func},
                    "line_sample": line.strip()[:120],
                }

        # VTable entries
        for base, offset, func_name, source_func in result["vtable_entries"]:
            if base not in self._vtable_entries:
                self._vtable_entries[base] = []
            self._vtable_entries[base].append({
                "offset": offset, "func": func_name,
                "source_func": source_func,
            })

        # Switch vars
        for var, vals in result["switch_vars"].items():
            if var not in self._switch_vars:
                self._switch_vars[var] = []
            for v in vals:
                if v not in self._switch_vars[var]:
                    self._switch_vars[var].append(v)

        # Compare vars
        for var, vals in result["compare_vars"].items():
            if var not in self._compare_vars:
                self._compare_vars[var] = []
            for v in vals:
                if v not in self._compare_vars[var]:
                    self._compare_vars[var].append(v)

        # Case comments
        for var, val_names in result["case_comments"].items():
            if var not in self._case_comment_names:
                self._case_comment_names[var] = {}
            self._case_comment_names[var].update(val_names)

        # String context
        self._string_context.update(result["string_context"])

        # Type usages — worker zaten filtrelemis, direkt merge et
        for var, tags in result["type_usages"].items():
            if var not in self._type_usage:
                self._type_usage[var] = []
            self._type_usage[var].extend(tags)

    # ------------------------------------------------------------------
    # Girdi Yukleme
    # ------------------------------------------------------------------

    def _load_functions_json(
        self, path: Path, errors: list[str],
    ) -> dict[str, dict[str, Any]]:
        """functions.json'dan fonksiyon metadata yukle.

        Returns:
            {func_name: {return_type, params, calling_convention, ...}}
        """
        path = Path(path)
        if not path.exists():
            errors.append(f"functions.json bulunamadi: {path}")
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"functions.json parse hatasi: {exc}")
            return {}

        result: dict[str, dict[str, Any]] = {}

        # functions.json birden fazla formatta olabilir
        if isinstance(data, list):
            for entry in data:
                name = entry.get("name") or entry.get("function_name", "")
                if name:
                    result[name] = entry
        elif isinstance(data, dict):
            # {func_name: {info}} veya {functions: [...]}
            if "functions" in data and isinstance(data["functions"], list):
                for entry in data["functions"]:
                    name = entry.get("name") or entry.get("function_name", "")
                    if name:
                        result[name] = entry
            else:
                result = data

        self._func_signatures = result
        logger.debug("Fonksiyon metadata yuklendi: %d adet", len(result))
        return result

    def _load_strings_json(self, path: Path, errors: list[str]) -> None:
        """strings.json'dan string context yukle."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"strings.json parse hatasi: {exc}")
            return

        if isinstance(data, list):
            for entry in data:
                addr = entry.get("address", "")
                value = entry.get("value") or entry.get("string", "")
                if addr and value:
                    self._string_context[str(addr)] = value
        elif isinstance(data, dict):
            # {address: string_value} veya {strings: [...]}
            strings_list = data.get("strings", data)
            if isinstance(strings_list, dict):
                self._string_context.update(
                    {str(k): str(v) for k, v in strings_list.items()}
                )

        logger.debug("String context yuklendi: %d adet", len(self._string_context))

    def _load_ghidra_types(
        self, path: Path, errors: list[str],
    ) -> tuple[list[RecoveredStruct], list[RecoveredEnum]]:
        """ghidra_types.json'dan Ghidra'nin tespit ettigi struct/enum bilgisini yukle.

        Ghidra, binary'den struct layout'larini ve enum degerlerini cikarabilir.
        Bu bilgi pattern-based recovery'ye EK olarak kullanilir -- Ghidra'nin
        verdigi tipler daha yuksek guvenilirlige sahiptir cunku Ghidra DWARF
        debug info, Objective-C metadata ve data-type archive'lardan faydalanir.

        Beklenen JSON formati::

            {
                "structures": [
                    {"name": "MyStruct", "size": 24, "fields": [
                        {"name": "x", "type": "int", "offset": 0, "size": 4}, ...
                    ]}, ...
                ],
                "enums": [
                    {"name": "MyEnum", "values": [
                        {"name": "VAL_A", "value": 0}, ...
                    ]}, ...
                ]
            }

        Args:
            path: ghidra_types.json dosya yolu.
            errors: Hata mesajlari listesi (append edilir).

        Returns:
            (structs, enums) tuple'i.
        """
        structs: list[RecoveredStruct] = []
        enums: list[RecoveredEnum] = []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"ghidra_types.json parse hatasi: {exc}")
            return structs, enums

        if not isinstance(data, dict):
            return structs, enums

        # -- Struct'lari yukle --
        for entry in data.get("structures", []):
            name = entry.get("name", "")
            if not name:
                continue

            raw_fields = entry.get("fields", [])
            size = entry.get("size", 0)

            # Bos veya anlamsiz struct'lari atla (1 byte, 0 field)
            if size < 2 and not raw_fields:
                continue

            fields: list[StructField] = []
            for fld in raw_fields:
                fld_name = fld.get("name", "")
                fld_type = fld.get("type", "undefined8")
                fld_offset = fld.get("offset", 0)
                fld_size = fld.get("size", 0)

                if not fld_name:
                    fld_name = f"field_0x{fld_offset:02x}"

                # Ghidra bazen cok satirli tip yaziyor (embedded struct tanimi).
                # Ilk satiri al, kalanini kes.
                if "\n" in fld_type:
                    fld_type = fld_type.split("\n", 1)[0].strip()

                # "undefined *" gibi tipleri normalize et
                fld_type = fld_type.replace("undefined *", "void *")

                if fld_size <= 0:
                    fld_size = _TYPE_SIZES.get(fld_type, 8)

                fields.append(StructField(
                    offset=fld_offset,
                    name=fld_name,
                    type=fld_type,
                    size=fld_size,
                    confidence=0.95,  # Ghidra'dan gelen -- yuksek guven
                ))

            # Fields yoksa bile bos struct kaydedilebilir (opaque type)
            # ama en az 1 field'li olanlari alalim
            if not fields:
                continue

            structs.append(RecoveredStruct(
                name=name,
                fields=sorted(fields, key=lambda f: f.offset),
                total_size=size if size > 0 else (
                    fields[-1].offset + fields[-1].size if fields else 0
                ),
                source_functions=["ghidra_type_recovery"],
                alignment=self.alignment,
            ))

        # -- Enum'lari yukle --
        for entry in data.get("enums", []):
            name = entry.get("name", "")
            if not name:
                continue

            raw_values = entry.get("values", [])
            if not raw_values:
                continue

            values: dict[str, int] = {}
            if isinstance(raw_values, list):
                for val_entry in raw_values:
                    val_name = val_entry.get("name", "")
                    val_int = val_entry.get("value", 0)
                    if val_name:
                        values[val_name] = val_int
            elif isinstance(raw_values, dict):
                # {name: int} formati
                values = {str(k): int(v) for k, v in raw_values.items()}

            if values:
                enums.append(RecoveredEnum(
                    name=name,
                    values=values,
                    source_functions=["ghidra_type_recovery"],
                ))

        logger.debug(
            "Ghidra tip bilgisi yuklendi: %d struct, %d enum",
            len(structs), len(enums),
        )
        return structs, enums

    # ------------------------------------------------------------------
    # v1.8: Ghidra pcode_high_vars Yukleme
    # ------------------------------------------------------------------

    def _load_ghidra_high_vars(
        self, decompiled_json: Path, errors: list[str],
    ) -> None:
        """decompiled.json icindeki pcode_high_vars tip bilgisini yukle.

        Ghidra P-Code analysis, her fonksiyondaki degiskenlere tip atar.
        Bu tipler C ciktisindakinden daha zengindir cunku Ghidra'nin ic
        datatype engine'inden gelir.  ``undefined*`` olmayanlar dogrudan
        per-function replacement olarak kullanilabilir.

        Beklenen format (decompiled.json icinde)::

            {
                "functions": [
                    {
                        "name": "_func",
                        "pcode_high_vars": [
                            {"name": "param_1", "type": "double *", "size": 8, ...},
                            {"name": "iVar1", "type": "int", "size": 4, ...},
                        ]
                    }, ...
                ]
            }

        Sonuc self._ghidra_high_vars'a yazilir:
            {func_name: {var_name: resolved_type}}
        """
        try:
            data = json.loads(decompiled_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"decompiled.json parse hatasi: {exc}")
            return

        functions = []
        if isinstance(data, dict):
            functions = data.get("functions", [])
        elif isinstance(data, list):
            functions = data

        _SKIP_TYPES = {"undefined", "undefined1", "undefined2",
                       "undefined4", "undefined8", "undefined *",
                       "undefined1 *", "undefined4 *", "undefined8 *"}

        for func_entry in functions:
            if not isinstance(func_entry, dict):
                continue
            func_name = func_entry.get("name", "")
            if not func_name:
                continue
            high_vars = func_entry.get("pcode_high_vars", [])
            if not high_vars:
                continue

            resolved: dict[str, str] = {}
            for hv in high_vars:
                if not isinstance(hv, dict):
                    continue
                var_name = hv.get("name", "")
                var_type = hv.get("type", "")
                if not var_name or not var_type:
                    continue
                # Typedef'leri temizle: "typedef size_t __darwin_size_t" -> "size_t"
                if var_type.startswith("typedef "):
                    parts = var_type.split()
                    if len(parts) >= 2:
                        var_type = parts[1]
                # undefined* tipleri atla -- bunlari zaten diger katmanlar halleder
                if var_type in _SKIP_TYPES:
                    continue
                # undefined1[N] gibi array tipleri de atla
                if var_type.startswith("undefined"):
                    continue
                resolved[var_name] = var_type

            if resolved:
                self._ghidra_high_vars[func_name] = resolved

        logger.debug(
            "Ghidra pcode_high_vars: %d fonksiyon, %d toplam resolved degisken",
            len(self._ghidra_high_vars),
            sum(len(v) for v in self._ghidra_high_vars.values()),
        )

    # ------------------------------------------------------------------
    # C Dosyasi Parse (v1.5.6: _parse_c_file_worker + _merge_parse_result)
    # Eski _parse_c_file ve _record_field_access v1.5.6'da kaldirildi.
    # FIX 2: _track_type_usage da kaldirildi -- worker icinde yapiliyor.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Struct Sentezi
    # ------------------------------------------------------------------

    def _synthesize_structs(self) -> list[RecoveredStruct]:
        """Toplanan field access pattern'lerinden struct tanimlari olustur.

        FIX 1: _field_accesses artik dict[str, dict[int, dict]] --
        .values() ile access listesini aliyoruz.
        """
        structs: list[RecoveredStruct] = []
        counter = 0

        for base_var, accesses_by_offset in self._field_accesses.items():
            # dict.values() -> list gibi iterate et
            accesses = list(accesses_by_offset.values())

            # VTable offset'lerini belirle (struct'tan dislamak icin degil,
            # vtable pointer field olarak isaretlemek icin)
            vtable_offsets: set[int] = set()
            if base_var in self._vtable_entries:
                vtable_offsets = {
                    e["offset"] for e in self._vtable_entries[base_var]
                }

            # Non-vtable field sayisi yeterli mi?
            non_vtable_count = sum(
                1 for a in accesses if a["offset"] not in vtable_offsets
            )
            if non_vtable_count < self.min_fields_for_struct:
                continue

            # Offset'e gore sirala
            sorted_accesses = sorted(accesses, key=lambda a: a["offset"])

            # Field'lari olustur (padding ile)
            fields: list[StructField] = []
            prev_end = 0

            for acc in sorted_accesses:
                offset = acc["offset"]
                size = acc["size"]
                c_type = acc["type"]
                confidence = acc["confidence"]

                # Onceki field'in bitisi ile bu field arasinda bosluk varsa padding ekle
                if offset > prev_end:
                    gap = offset - prev_end
                    fields.append(StructField(
                        offset=prev_end,
                        name=f"padding_0x{prev_end:02x}",
                        type=f"char[{gap}]" if gap > 1 else "char",
                        size=gap,
                        confidence=0.3,
                    ))

                # VTable offset'indeki field'lari function pointer olarak isaretle
                if offset in vtable_offsets:
                    field_name = f"func_ptr_0x{offset:02x}"
                    c_type = "void (*)(void *)"
                    confidence = 0.9
                else:
                    # Field ismi: string context'ten veya generic
                    field_name = self._infer_field_name(base_var, offset, c_type)

                fields.append(StructField(
                    offset=offset,
                    name=field_name,
                    type=c_type,
                    size=size,
                    confidence=confidence,
                ))

                prev_end = offset + size

            if not fields:
                continue

            # Toplam boyut: son field offset + size, alignment'a yuvarla
            raw_size = fields[-1].offset + fields[-1].size
            total_size = self._align_up(raw_size, self.alignment)

            # Son padding
            if total_size > raw_size:
                fields.append(StructField(
                    offset=raw_size,
                    name=f"padding_0x{raw_size:02x}",
                    type=f"char[{total_size - raw_size}]",
                    size=total_size - raw_size,
                    confidence=0.2,
                ))

            # Kaynak fonksiyonlar
            all_sources: set[str] = set()
            for acc in sorted_accesses:
                all_sources.update(acc["sources"])

            counter += 1
            struct = RecoveredStruct(
                name=f"recovered_struct_{counter:03d}",
                fields=fields,
                total_size=total_size,
                source_functions=sorted(all_sources),
                alignment=self.alignment,
            )
            structs.append(struct)

        return structs

    def _infer_field_name(
        self, base_var: str, offset: int, c_type: str,
    ) -> str:
        """Field icin anlamli isim cikar.

        String pointer ise ve context varsa anlamli isim kullan.
        """
        # String pointer -> "name", "path", vb.
        if "char *" in c_type or "char**" in c_type:
            # String context'ten ipucu ara
            for var, s in self._string_context.items():
                # Basit heuristic: var ismi base_var ile eslesiyor mu
                if base_var in var or var in base_var:
                    # Kisa string'lerden field adi cikar
                    clean = re.sub(r"[^a-zA-Z0-9_]", "_", s.lower())[:20]
                    if clean and clean[0].isalpha():
                        return clean
            return f"str_0x{offset:02x}"

        if "code *" in c_type or "code **" in c_type:
            return f"func_ptr_0x{offset:02x}"

        if c_type in ("int", "int32_t", "uint32_t"):
            return f"field_0x{offset:02x}"

        if c_type in ("long", "uint64_t", "int64_t"):
            return f"field_0x{offset:02x}"

        if c_type == "bool" or c_type == "_Bool":
            return f"flag_0x{offset:02x}"

        if c_type == "float" or c_type == "double":
            return f"val_0x{offset:02x}"

        return f"field_0x{offset:02x}"

    # ------------------------------------------------------------------
    # Enum Sentezi
    # ------------------------------------------------------------------

    def _synthesize_enums(self) -> list[RecoveredEnum]:
        """Switch/case ve comparison pattern'lerinden enum tanimlari olustur.

        Case comment'lerden gelen isimler (// kEnterKey) varsa,
        enum ismi ve degerleri icin onlari kullanir.
        """
        enums: list[RecoveredEnum] = []
        counter = 0

        # switch/case'lerden
        for var, case_values in self._switch_vars.items():
            if len(case_values) < self.min_enum_values:
                continue

            counter += 1
            # Case comment'lerden gelen isimler varsa, onlari kullan
            comment_names = self._case_comment_names.get(var)
            values = self._name_enum_values(var, sorted(case_values), comment_names)

            # Enum ismi: comment isimlerinden ortak prefix cikar
            enum_name = self._infer_enum_name_from_comments(comment_names, counter)

            enums.append(RecoveredEnum(
                name=enum_name,
                values=values,
                source_functions=[var],
            ))

        # Comparison pattern'lerinden (switch'le cakismiyorsa)
        existing_vars = set(self._switch_vars.keys())
        for var, cmp_values in self._compare_vars.items():
            if var in existing_vars:
                continue
            if len(cmp_values) < self.min_enum_values:
                continue

            counter += 1
            comment_names = self._case_comment_names.get(var)
            values = self._name_enum_values(var, sorted(cmp_values), comment_names)
            enum_name = self._infer_enum_name_from_comments(comment_names, counter)

            enums.append(RecoveredEnum(
                name=enum_name,
                values=values,
                source_functions=[var],
            ))

        return enums

    @staticmethod
    def _infer_enum_name_from_comments(
        comment_names: dict[int, str] | None,
        fallback_counter: int,
    ) -> str:
        """Case comment isimlerinden enum adi cikar.

        Ornek:
            {0x24: "kEnterKey", 0x25: "kReturnKey"} -> "KeyCode"
            {0: "MODE_IDLE", 1: "MODE_ACTIVE"} -> "Mode"
            None veya {} -> "recovered_enum_NNN"
        """
        if not comment_names:
            return f"recovered_enum_{fallback_counter:03d}"

        names = list(comment_names.values())
        if not names:
            return f"recovered_enum_{fallback_counter:03d}"

        # k_ prefix'li sabitlerde ortak suffix bul
        # kEnterKey, kReturnKey -> "Key" -> enum ismi "KeyCode" veya "Key"
        # MODE_IDLE, MODE_ACTIVE -> "MODE" prefix -> enum ismi "Mode"
        first = names[0]

        # k-prefix pattern: kXxxYyy -> "k" prefix ile baslayan C-style
        if first.startswith("k") and len(first) > 1 and first[1].isupper():
            # kEnterKey, kReturnKey: ortak suffix bul
            suffixes = []
            for n in names:
                if n.startswith("k") and len(n) > 1:
                    # camelCase parcala
                    parts = re.findall(r'[A-Z][a-z]*', n[1:])
                    if parts:
                        suffixes.append(parts[-1])
            if suffixes:
                from collections import Counter
                common_suffix = Counter(suffixes).most_common(1)[0][0]
                return common_suffix

        # UPPER_SNAKE_CASE: MODE_IDLE, MODE_ACTIVE -> ortak prefix
        if "_" in first and first == first.upper():
            prefixes = [n.split("_")[0] for n in names if "_" in n]
            if prefixes:
                from collections import Counter
                common_prefix = Counter(prefixes).most_common(1)[0][0]
                # UPPER -> Title case
                return common_prefix.capitalize()

        return f"recovered_enum_{fallback_counter:03d}"

    def _name_enum_values(
        self, var: str, int_values: list[int],
        comment_names: dict[int, str] | None = None,
    ) -> dict[str, int]:
        """Enum degerlerine isim ver.

        Comment'lerden gelen isimler varsa onlari kullan,
        yoksa string context varsa anlamli isimler, yoksa generic STATE_N.
        """
        values: dict[str, int] = {}

        # Comment'lerden gelen isimler varsa oncelikle onlari kullan
        if comment_names:
            for val in int_values:
                if val in comment_names:
                    values[comment_names[val]] = val
                else:
                    # Bu deger icin comment yok, generic isim ver
                    values[f"VAL_{val}"] = val
            return values

        # String context'ten ipucu: degisken adi + "state", "mode", "type" vb.
        prefix = "STATE"
        var_lower = var.lower()
        if "state" in var_lower or "status" in var_lower:
            prefix = "STATE"
        elif "mode" in var_lower:
            prefix = "MODE"
        elif "type" in var_lower or "kind" in var_lower:
            prefix = "TYPE"
        elif "flag" in var_lower:
            prefix = "FLAG"
        elif "error" in var_lower or "err" in var_lower:
            prefix = "ERR"
        else:
            prefix = "VAL"

        for val in int_values:
            name = f"{prefix}_{val}"
            values[name] = val

        return values

    # ------------------------------------------------------------------
    # VTable Sentezi
    # ------------------------------------------------------------------

    def _synthesize_vtables(self) -> list[RecoveredVTable]:
        """Function pointer array pattern'lerinden vtable tanimlari olustur."""
        vtables: list[RecoveredVTable] = []
        counter = 0

        for base_var, entries in self._vtable_entries.items():
            if len(entries) < 2:
                continue

            # Offset'e gore sirala
            sorted_entries = sorted(entries, key=lambda e: e["offset"])

            # Tum offset'ler 8'in katlari mi? (ARM64 pointer boyutu)
            all_aligned = all(e["offset"] % 8 == 0 for e in sorted_entries)
            if not all_aligned:
                continue

            methods: list[tuple[int, str, str]] = []
            all_sources: set[str] = set()

            for i, entry in enumerate(sorted_entries):
                offset = entry["offset"]
                func_name = entry["func"]
                all_sources.add(entry["source_func"])

                # Fonksiyon metadata varsa signature cikar
                sig = self._get_func_signature(func_name)
                methods.append((offset, func_name, sig))

            counter += 1
            vtables.append(RecoveredVTable(
                name=f"vtable_{counter:03d}",
                methods=methods,
                source_functions=sorted(all_sources),
            ))

        return vtables

    def _get_func_signature(self, func_name: str) -> str:
        """Fonksiyon icin tahmini C signature uret."""
        meta = self._func_signatures.get(func_name)
        if meta:
            ret = meta.get("return_type", "void")
            params = meta.get("params") or meta.get("parameters", [])
            if isinstance(params, list):
                param_strs = []
                for p in params:
                    if isinstance(p, dict):
                        ptype = p.get("type", "void*")
                        pname = p.get("name", "")
                        param_strs.append(f"{ptype} {pname}".strip())
                    elif isinstance(p, str):
                        param_strs.append(p)
                param_str = ", ".join(param_strs) or "void"
            else:
                param_str = "void*"
            return f"{ret} (*)({param_str})"

        # Metadata yoksa generic signature
        return "void (*)(void*)"

    # ------------------------------------------------------------------
    # Type Propagation (v1.7.2: context-aware + call-graph + struct)
    # ------------------------------------------------------------------

    def _propagate_types_v2(
        self,
        func_meta: dict[str, dict[str, Any]],
        structs: list[RecoveredStruct],
        call_graph: dict[str, Any],
    ) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        """Context-aware type propagation (v1.8).

        8 katmanli strateji:
        1. Global undefined -> varsayilan tip (mevcut davranis)
        2a. Per-variable context-aware tip cikarimi (kullanim pattern'i analizi)
        2b. Call-graph inter-procedural tip propagasyonu
        2c. Struct tipi atamasi (field access pattern eslesmesi)
        2d. Return type propagation
        2e. Ghidra pcode_high_vars type application (P-Code resolved types)
        2f. in_stack Fortran parameter typing (pass-by-reference)
        2g. Arithmetic/cast type inference (float literals, typed malloc, cast deref)

        Returns:
            (global_replacements, per_func_replacements) tuple.
            global_replacements: {eski_tip: yeni_tip}
            per_func_replacements: {func_name: {"undefined8 var": "type var"}}
        """
        # 1. Global defaults (mevcut davranis)
        global_replacements: dict[str, str] = {}
        global_replacements.update(_UNDEFINED_DEFAULTS)

        # 2. Per-function replacements
        per_func: dict[str, dict[str, str]] = {}

        # Struct lookup: field offset pattern -> struct ismi
        struct_signatures = self._build_struct_signatures(structs)

        # --- 2a. Context-aware variable type inference ---
        # Her degisken icin kullanim tag'lerini analiz et
        for var, tags in self._type_usage.items():
            inferred = self._infer_type_from_context(var, tags, func_meta)
            if not inferred:
                continue

            # Bu degiskenin hangi fonksiyonlarda kullanildigini bul
            # ve o fonksiyonlar icin per-func replacement olustur
            for tag in tags:
                # declared:TYPE tag'inden fonksiyonu bul
                if tag.startswith("declared:"):
                    declared_type = tag[len("declared:"):]
                    # Sadece undefined* tipleri degistir -- zaten dogru tiplere dokunma
                    if not declared_type.startswith("undefined"):
                        continue
                    # Bu var hangi fonksiyonda? return_in veya call_arg tag'inden bul
                    func_name = self._find_var_function(var, tags)
                    if func_name:
                        if func_name not in per_func:
                            per_func[func_name] = {}
                        old_decl = f"{declared_type} {var}"
                        new_decl = f"{inferred} {var}"
                        per_func[func_name][old_decl] = new_decl

        # --- 2b. Call-graph type propagation ---
        if call_graph and func_meta:
            cg_inferred = self._propagate_via_call_graph(
                func_meta, call_graph,
            )
            # cg_inferred: {func_name: {param_name: type}}
            for func_name, param_types in cg_inferred.items():
                if func_name not in per_func:
                    per_func[func_name] = {}
                for param_name, param_type in param_types.items():
                    # Fonksiyon header'daki parametre tipini degistir
                    # Ghidra: "undefined8 param_1" -> "int param_1"
                    old_decl = f"undefined8 {param_name}"
                    new_decl = f"{param_type} {param_name}"
                    if old_decl not in per_func[func_name]:
                        per_func[func_name][old_decl] = new_decl
                    # undefined4 de olabilir
                    old_decl4 = f"undefined4 {param_name}"
                    if old_decl4 not in per_func[func_name]:
                        size = _TYPE_SIZES.get(param_type, 8)
                        if size == 4:
                            per_func[func_name][old_decl4] = new_decl

        # --- 2c. Struct type application ---
        struct_apps = self._apply_struct_types(struct_signatures)
        for func_name, replacements_dict in struct_apps.items():
            if func_name not in per_func:
                per_func[func_name] = {}
            per_func[func_name].update(replacements_dict)

        # --- 2d. Return type propagation ---
        # Fonksiyon return tipi bilinen ise, o fonksiyonu cagiran yerde
        # donusu alan degiskenin tipini ayarla
        ret_inferred = self._propagate_return_types(func_meta)
        for func_name, var_types in ret_inferred.items():
            if func_name not in per_func:
                per_func[func_name] = {}
            for var_name, var_type in var_types.items():
                old_decl = f"undefined8 {var_name}"
                new_decl = f"{var_type} {var_name}"
                if old_decl not in per_func[func_name]:
                    per_func[func_name][old_decl] = new_decl

        # --- 2e. Ghidra pcode_high_vars type application (v1.8) ---
        # Ghidra'nin P-Code analysis'inden gelen resolved tipler dogrudan
        # per-func replacement olarak kullanilir.  Bu en yuksek oncelikli
        # katmandir cunku Ghidra'nin kendi datatype engine'inden gelir.
        _ghidra_applied = 0
        for func_name, var_types in self._ghidra_high_vars.items():
            if func_name not in per_func:
                per_func[func_name] = {}
            for var_name, resolved_type in var_types.items():
                # Tum undefined varyantlari icin dene
                for undef in ("undefined8", "undefined4", "undefined",
                              "undefined8 *", "undefined4 *"):
                    old_decl = f"{undef} {var_name}"
                    if old_decl not in per_func[func_name]:
                        # Boyut uyumu kontrol: undefined4 -> 4-byte tip,
                        # undefined8 -> 8-byte tip
                        if undef in ("undefined4", "undefined4 *"):
                            resolved_size = _TYPE_SIZES.get(resolved_type, 8)
                            if resolved_size > 4 and "*" not in resolved_type:
                                continue
                        per_func[func_name][old_decl] = f"{resolved_type} {var_name}"
                        _ghidra_applied += 1
        if _ghidra_applied:
            logger.info(
                "Ghidra pcode_high_vars: %d tip degisimi uygulandi",
                _ghidra_applied,
            )

        # --- 2f. in_stack Fortran parameter typing (v1.8) ---
        # Fortran-compiled functions pass ALL parameters by reference (pointer).
        # in_stack_XXXXXX params are extra arguments beyond register-passed ones.
        # For Fortran subs (trailing _), assign void * to all in_stack params.
        _instack_applied = 0
        for var, tags in self._type_usage.items():
            if not var.startswith("in_stack_"):
                continue
            # Hangi fonksiyonlarda kullaniliyor?
            func_names: set[str] = set()
            for tag in tags:
                if tag.startswith("in_stack_usage:"):
                    func_names.add(tag.split(":", 1)[1])
                elif tag.startswith("return_in:"):
                    func_names.add(tag.split(":", 1)[1])
                elif tag.startswith("call_arg:"):
                    parts = tag.split(":")
                    if len(parts) >= 4 and parts[3]:
                        func_names.add(parts[3])

            # in_stack kullanim context'inden daha spesifik tip cikar
            inferred_type = self._infer_in_stack_type(var, tags)

            for func_name in func_names:
                if func_name not in per_func:
                    per_func[func_name] = {}
                # Tum undefined varyantlarini dene
                for undef in ("undefined8", "long", "undefined"):
                    old_decl = f"{undef} {var}"
                    if old_decl not in per_func[func_name]:
                        per_func[func_name][old_decl] = f"{inferred_type} {var}"
                        _instack_applied += 1
        if _instack_applied:
            logger.info(
                "in_stack Fortran param: %d tip degisimi uygulandi",
                _instack_applied,
            )

        # --- 2g. Arithmetic/cast type inference from tags (v1.8) ---
        # float_literal_assign, malloc_cast, cast_deref tags
        _arith_applied = 0
        for var, tags in self._type_usage.items():
            tag_set = set(tags)
            func_name = self._find_var_function(var, tags)
            if not func_name:
                continue

            # malloc_cast:TYPE -- typed malloc cast
            for tag in tags:
                if tag.startswith("malloc_cast:"):
                    cast_type = tag.split(":", 1)[1]
                    if func_name not in per_func:
                        per_func[func_name] = {}
                    old_decl = f"undefined8 {var}"
                    if old_decl not in per_func[func_name]:
                        per_func[func_name][old_decl] = f"{cast_type} {var}"
                        _arith_applied += 1
                    break

            # float_literal_assign -> double
            if "float_literal_assign" in tag_set:
                if func_name not in per_func:
                    per_func[func_name] = {}
                old_decl = f"undefined8 {var}"
                if old_decl not in per_func[func_name]:
                    per_func[func_name][old_decl] = f"double {var}"
                    _arith_applied += 1

        if _arith_applied:
            logger.info(
                "Arithmetic/cast: %d tip degisimi uygulandi",
                _arith_applied,
            )

        return global_replacements, per_func

    def _infer_type_from_context(
        self,
        var: str,
        tags: list[str],
        func_meta: dict[str, dict[str, Any]],
    ) -> str | None:
        """Degiskenin kullanim context'inden tip cikar.

        Oncelik sirasi (yuksekten dusuge):
        1. string function argument -> char *
        2. typed malloc cast -> cast type (e.g. double *)
        3. alloc result -> void *
        4. float literal assignment -> double
        5. call_arg: callee param type propagation
        6. cast_deref: pointer cast type propagation
        7. pointer dereference / pointer arithmetic / array access -> void *
        8. comparison / arithmetic with signed results -> int / int32_t
        9. bitwise operations -> uint32_t / uint64_t
        10. boolean test -> int (C'de bool int'tir)

        Returns:
            Cikarilan tip string'i veya None (tip cikarilamadiysa).
        """
        tag_set = set(tags)
        tag_counts: dict[str, int] = {}
        for t in tags:
            base_tag = t.split(":")[0] if ":" in t else t
            tag_counts[base_tag] = tag_counts.get(base_tag, 0) + 1

        # Kuvvetli sinyaller (tek basina yeterli)
        if "string_func_arg" in tag_set:
            return "char *"

        # v1.8: Typed malloc cast -- var = (double *)malloc(...)
        for tag in tags:
            if tag.startswith("malloc_cast:"):
                return tag.split(":", 1)[1]

        if "alloc_result" in tag_set:
            return "void *"

        # v1.8: Float literal assignment -> double
        if "float_literal_assign" in tag_set:
            return "double"

        # call_arg tag'lerinden callee'nin parametre tipini al
        for tag in tags:
            if tag.startswith("call_arg:"):
                parts = tag.split(":")
                if len(parts) >= 3:
                    callee_name = parts[1]
                    try:
                        arg_idx = int(parts[2])
                    except (ValueError, IndexError):
                        continue
                    callee_meta = func_meta.get(callee_name)
                    if callee_meta:
                        params = callee_meta.get("params") or callee_meta.get("parameters", [])
                        if isinstance(params, list) and arg_idx < len(params):
                            p = params[arg_idx]
                            if isinstance(p, dict):
                                ptype = p.get("type", "")
                                # Sadece concrete tip ise kabul et, undefined degil
                                if ptype and not ptype.startswith("undefined"):
                                    return ptype

        # v1.8: Cast dereference -- *(double *)(param_1 + 0x10)
        # En cok kullanilan cast type, degiskenin isaret ettigi struct icindeki
        # veri tipini gosterir.  Degiskenin kendisi pointer olmali.
        cast_types: dict[str, int] = {}
        for tag in tags:
            if tag.startswith("cast_deref:"):
                ct = tag.split(":", 1)[1]
                # Pointer kismini cikar -- *(T *)(var+off) => var is T-containing struct ptr
                cast_types[ct] = cast_types.get(ct, 0) + 1
        if cast_types:
            # Pointer tipleri var -> degisken pointer'dir
            # Pointer olmayan tipler -> struct field tipleri
            # Degisken icin: var en az bir pointer olarak kullaniliyor -> void *
            # (daha spesifik tip struct apply tarafindan atanir)
            return "void *"

        # Pointer sinyalleri
        pointer_tags = {"pointer_deref", "pointer_arithmetic", "array_access"}
        if tag_set & pointer_tags:
            return "void *"

        # Karsilastirma -> signed integer (buyuk ihtimal)
        if "comparison" in tag_set and "bitwise_op" not in tag_set:
            return "int"

        # Bitwise islem -> unsigned
        if "bitwise_op" in tag_set:
            return "uint32_t"

        # Aritmetik -> int
        if tag_counts.get("arithmetic", 0) >= 2:
            return "int"

        return None

    @staticmethod
    def _find_var_function(var: str, tags: list[str]) -> str | None:
        """Degiskenin ait oldugu fonksiyonu tag'lerden bul.

        v1.7.2: call_arg tag'inde caller ismi de var (4. bolum).
        """
        for tag in tags:
            if tag.startswith("return_in:"):
                return tag.split(":", 1)[1]
        # v1.7.2: call_arg:callee:idx:caller formatindan caller al
        for tag in tags:
            if tag.startswith("call_arg:"):
                parts = tag.split(":")
                if len(parts) >= 4 and parts[3]:
                    return parts[3]
        # v1.8: in_stack_usage tag'inden fonksiyon ismi
        for tag in tags:
            if tag.startswith("in_stack_usage:"):
                return tag.split(":", 1)[1]
        return None

    @staticmethod
    def _infer_in_stack_type(var: str, tags: list[str]) -> str:
        """in_stack degiskeni icin en spesifik tipi cikar.

        Fortran pass-by-reference kurali: tum parametreler pointer.
        Ancak kullanim context'inden daha spesifik tip cikarabiliriz:

        - cast_deref:double * -> double * (double'a isaret ediyor)
        - cast_deref:int * -> int * (int'e isaret ediyor)
        - string_func_arg -> char * (string pointer)
        - pointer_arithmetic/array_access -> void * (genel pointer)
        - arithmetic/comparison -> int * (deger uzerinde islem -> pointer to int)
        - Hicbir sinyal yoksa -> void * (genel Fortran pointer)
        """
        # cast_deref tag'lerinden en cok kullanilan tipi bul
        cast_counts: dict[str, int] = {}
        for tag in tags:
            if tag.startswith("cast_deref:"):
                ct = tag.split(":", 1)[1]
                # *(int *)(in_stack + offset) -> in_stack is struct-like pointer
                # Ama genel olarak: "most common cast" kullan
                cast_counts[ct] = cast_counts.get(ct, 0) + 1

        if cast_counts:
            # En cok kullanilan cast tipi
            best_cast = max(cast_counts, key=cast_counts.get)  # type: ignore[arg-type]
            # "int *" -> in_stack_X is "int *" (pointer to int)
            return best_cast

        tag_set = set(tags)

        if "string_func_arg" in tag_set:
            return "char *"
        if "float_literal_assign" in tag_set:
            return "double *"
        if tag_set & {"pointer_deref", "pointer_arithmetic", "array_access"}:
            return "void *"
        if tag_set & {"arithmetic", "comparison"}:
            return "int *"

        # Varsayilan: Fortran pass-by-reference -> void *
        return "void *"

    def _propagate_via_call_graph(
        self,
        func_meta: dict[str, dict[str, Any]],
        call_graph: dict[str, Any],
    ) -> dict[str, dict[str, str]]:
        """Call graph uzerinden inter-procedural tip propagasyonu.

        Strateji: Callee'nin bilinen parametre tipleri -> caller'daki argumanlara
        atanir.  Ayrica callee'nin return tipi -> caller'daki atama hedefine.

        Ornekler:
        - callee(int x, char *y) biliniyorsa ve caller'da
          callee(param_1, param_2) cagiriyorsa -> param_1: int, param_2: char*
        - Benzer sekilde type_usages'taki call_arg tag'leri zaten bunu yapiyor
          ama bu metod daha sistematik: tum call_graph edge'lerini tarar.

        Args:
            func_meta: {func_name: {return_type, params, ...}}
            call_graph: Normalized call graph data.

        Returns:
            {func_name: {param_name: inferred_type}}
        """
        result: dict[str, dict[str, str]] = {}

        # Bilinen fonksiyon tipleri (non-undefined parametrelere sahip olanlar)
        known_funcs: dict[str, list[dict]] = {}
        for fname, meta in func_meta.items():
            params = meta.get("params") or meta.get("parameters", [])
            if isinstance(params, list):
                concrete_params = []
                for p in params:
                    if isinstance(p, dict):
                        ptype = p.get("type", "")
                        pname = p.get("name", "")
                        if ptype and not ptype.startswith("undefined") and pname:
                            concrete_params.append({"name": pname, "type": ptype})
                if concrete_params:
                    known_funcs[fname] = concrete_params

        if not known_funcs:
            return result

        # Call graph'tan caller -> callee iliskilerini cikar
        # ve type_usages'taki call_arg tag'lerinden propagate et
        for var, tags in self._type_usage.items():
            for tag in tags:
                if not tag.startswith("call_arg:"):
                    continue
                parts = tag.split(":")
                if len(parts) < 3:
                    continue
                callee_name = parts[1]
                try:
                    arg_idx = int(parts[2])
                except (ValueError, IndexError):
                    continue
                # v1.7.2: 4. bolumden caller ismi
                caller_func = parts[3] if len(parts) >= 4 and parts[3] else None

                if callee_name not in known_funcs:
                    continue

                known_params = known_funcs[callee_name]
                if arg_idx >= len(known_params):
                    continue

                param_type = known_params[arg_idx]["type"]

                # Caller fonksiyonu belirle
                if not caller_func:
                    caller_func = self._find_var_function(var, tags)
                if not caller_func:
                    continue

                if caller_func not in result:
                    result[caller_func] = {}
                if var not in result[caller_func]:
                    result[caller_func][var] = param_type

        return result

    def _build_struct_signatures(
        self, structs: list[RecoveredStruct],
    ) -> dict[frozenset[int], str]:
        """Struct'larin field offset set'lerini signature olarak kullan.

        Returns:
            {frozenset(offsets): struct_name}
        """
        signatures: dict[frozenset[int], str] = {}
        for s in structs:
            offsets = frozenset(
                f.offset for f in s.fields
                if not f.name.startswith("padding_")
            )
            if len(offsets) >= 2:
                signatures[offsets] = s.name
        return signatures

    def _apply_struct_types(
        self,
        struct_signatures: dict[frozenset[int], str],
    ) -> dict[str, dict[str, str]]:
        """Degiskenlerin field access pattern'lerini struct signature'lari ile esle.

        Bir degisken (orn: param_1) uzerinde *(TYPE*)(param_1 + 0x10),
        *(TYPE*)(param_1 + 0x18), *(TYPE*)(param_1 + 0x20) gibi erisimler
        yapilmissa ve bu offset seti bir struct'in offset setine uyuyorsa,
        o degiskenin tipi struct_name * olarak atanir.

        Returns:
            {func_name: {"undefined8 param_1": "struct_name * param_1"}}
        """
        result: dict[str, dict[str, str]] = {}

        for base_var, accesses_by_offset in self._field_accesses.items():
            offsets = frozenset(accesses_by_offset.keys())
            if len(offsets) < 2:
                continue

            # Struct signature eslesmesi: subset veya exact match
            best_match: str | None = None
            best_score = 0
            for sig_offsets, struct_name in struct_signatures.items():
                # offsets, sig_offsets'in bir subset'i veya tam eslesmesi mi?
                common = offsets & sig_offsets
                if len(common) < 2:
                    continue
                score = len(common) / max(len(sig_offsets), 1)
                if score > best_score:
                    best_score = score
                    best_match = struct_name

            if not best_match or best_score < 0.5:
                continue

            # Bu base_var hangi fonksiyonlarda kullanilmis?
            func_names: set[str] = set()
            for acc in accesses_by_offset.values():
                func_names.update(acc.get("sources", set()))

            for func_name in func_names:
                if func_name not in result:
                    result[func_name] = {}
                # param_1 gibi degiskenler icin undefined8 -> struct_name *
                old_decl = f"undefined8 {base_var}"
                new_decl = f"{best_match} * {base_var}"
                if old_decl not in result[func_name]:
                    result[func_name][old_decl] = new_decl

        return result

    def _propagate_return_types(
        self,
        func_meta: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, str]]:
        """Bilinen fonksiyon return tiplerini, o fonksiyonu cagirip sonucunu
        bir degiskene atayan caller fonksiyonlarindaki degiskenlere propag et.

        Ornek:
            _malloc -> return void*
            caller'da: local_8 = _malloc(0x100)
            type_usages'ta: local_8 -> call_arg:... + alloc_result
            -> local_8 tipi void* olmali

        Returns:
            {caller_func: {var_name: return_type}}
        """
        result: dict[str, dict[str, str]] = {}

        # Bilinen return tipleri
        known_returns: dict[str, str] = {}
        for fname, meta in func_meta.items():
            ret = meta.get("return_type", "")
            if ret and not ret.startswith("undefined") and ret != "void":
                known_returns[fname] = ret

        if not known_returns:
            return result

        # type_usages'tan call_arg tag'lerini tara
        # Bir degisken bir fonksiyona arguman olarak gecilmis VE
        # alloc_result tag'i de varsa -> return tipi atanir
        # Ama daha genel: "var = func()" pattern'ini bulmak lazim
        # Worker'da bu patttern'i yakalamiyoruz dogrudan.
        # Ama alloc_result zaten "var = malloc/calloc/realloc" yapiyor.
        # Daha gelismis pattern icin: type_usages'ta "return_in:func" var.

        # Simdilik: alloc_result olanlar icin -> void *
        # Bu zaten _infer_type_from_context'te yapiliyor.
        # Ek olarak: fonksiyon return tipini propagate et.
        # type_usages'taki tum degiskenleri tara,
        # "call_arg:FUNC:0" gibi tag'lere sahip olanlari
        # FUNC'in return tipinden cikar.
        # ANCAK bu cok genisc -- su an icin sadece basit case'leri halledelim.

        return result

    def _load_call_graph(
        self, path: Path, errors: list[str],
    ) -> dict[str, Any]:
        """Call graph JSON yukle ve normalize et.

        Returns:
            {func_name: {"callees": [callee_name, ...], "callers": [...]}}
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"call_graph.json parse hatasi: {exc}")
            return {}

        result: dict[str, dict[str, list[str]]] = {}

        if isinstance(data, dict):
            nodes = data.get("nodes", {})
            if isinstance(nodes, dict):
                for addr, node_info in nodes.items():
                    name = node_info.get("name", "")
                    if not name:
                        continue
                    callees = []
                    for c in node_info.get("callees", []):
                        if isinstance(c, dict):
                            callees.append(c.get("name", ""))
                        elif isinstance(c, str):
                            callees.append(c)
                    callers = []
                    for c in node_info.get("callers", []):
                        if isinstance(c, dict):
                            callers.append(c.get("name", ""))
                        elif isinstance(c, str):
                            callers.append(c)
                    result[name] = {
                        "callees": [c for c in callees if c],
                        "callers": [c for c in callers if c],
                    }

        return result

    # ------------------------------------------------------------------
    # Cikti: types.h
    # ------------------------------------------------------------------

    def _write_types_header(
        self,
        path: Path,
        structs: list[RecoveredStruct],
        enums: list[RecoveredEnum],
        vtables: list[RecoveredVTable],
    ) -> None:
        """Kurtarilan tipleri types.h olarak yaz."""
        lines: list[str] = []
        lines.append("/* =============================================================")
        lines.append(" * types.h -- Recovered type definitions")
        lines.append(" * Generated by Karadul CTypeRecoverer")
        lines.append(" * =============================================================")
        lines.append(" */")
        lines.append("")
        lines.append("#ifndef RECOVERED_TYPES_H")
        lines.append("#define RECOVERED_TYPES_H")
        lines.append("")
        lines.append("#include <stdint.h>")
        lines.append("#include <stdbool.h>")
        lines.append("")

        # Forward declarations
        if structs:
            lines.append("/* Forward declarations */")
            for s in structs:
                lines.append(f"typedef struct {s.name} {s.name};")
            lines.append("")

        # Enums
        if enums:
            lines.append("/* ---- Enums ---- */")
            lines.append("")
            for enum in enums:
                lines.append(f"typedef enum {{")
                items = sorted(enum.values.items(), key=lambda kv: kv[1])
                for i, (name, val) in enumerate(items):
                    comma = "," if i < len(items) - 1 else ""
                    lines.append(f"    {name} = {val}{comma}")
                lines.append(f"}} {enum.name};")
                lines.append("")

        # Structs
        if structs:
            lines.append("/* ---- Structs ---- */")
            lines.append("")
            for struct in structs:
                lines.append(f"/* Size: 0x{struct.total_size:X} ({struct.total_size} bytes)")
                lines.append(f" * Sources: {', '.join(struct.source_functions[:5])}")
                lines.append(f" */")
                lines.append(f"struct {struct.name} {{")
                for f in struct.fields:
                    conf_str = f"/* confidence: {f.confidence:.2f} */"
                    # Array tip ise ozel format
                    if f.type.endswith("]") and "[" in f.type:
                        # char[16] gibi
                        base_type, arr_part = f.type.split("[", 1)
                        lines.append(
                            f"    {base_type} {f.name}[{arr_part};"
                            f"  /* 0x{f.offset:02X} */ {conf_str}"
                        )
                    else:
                        lines.append(
                            f"    {f.type} {f.name};"
                            f"  /* 0x{f.offset:02X} */ {conf_str}"
                        )
                lines.append(f"}};")
                lines.append("")

        # VTables
        if vtables:
            lines.append("/* ---- VTables ---- */")
            lines.append("")
            for vt in vtables:
                lines.append(f"/* Sources: {', '.join(vt.source_functions[:5])} */")
                lines.append(f"typedef struct {{")
                for offset, func_name, sig in vt.methods:
                    lines.append(
                        f"    {sig} method_0x{offset:02X};"
                        f"  /* {func_name} */"
                    )
                lines.append(f"}} {vt.name};")
                lines.append("")

        lines.append("#endif /* RECOVERED_TYPES_H */")
        lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Cikti: Tip Degistirme (C Dosyalari)
    # ------------------------------------------------------------------

    # v1.5.6: Eski _apply_type_replacements kaldirildi.
    # Yeni: _apply_types_worker (top-level, ProcessPool uyumlu).

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_int(s: str) -> int:
        """Hex veya decimal string'i int'e cevir."""
        s = s.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)

    @staticmethod
    def _normalize_type(raw: str) -> str:
        """Ghidra tip string'ini normalize et.

        Fazla bosluk, gereksiz qualifier'lari temizle.
        """
        t = raw.strip()
        # Coklu boslugu teke indir
        t = re.sub(r"\s+", " ", t)
        # Trailing * normalize
        t = re.sub(r"\s*\*", " *", t).strip()
        # "long long" -> "int64_t"
        t = t.replace("long long", "int64_t")
        return t

    @staticmethod
    def _deref_cast_type(cast_type: str) -> str:
        """Cast tipinden dereference sonrasi gercek field tipini cikar.

        ``*(T *)(addr)`` pattern'inde:
        - Cast = ``T *`` -> dereference -> field tipi = ``T``
        - Cast = ``char **`` -> dereference -> field tipi = ``char *``
        - Cast = ``int *`` -> dereference -> field tipi = ``int``

        Yani trailing bir ``*`` cikarilir (dis dereference operatorune karsilik gelir).
        """
        t = cast_type.strip()
        if t.endswith("*"):
            t = t[:-1].rstrip()
        # Eger tip hala * ile bitiyorsa (orn: char ** -> char *) kalsin
        return t if t else cast_type

    @staticmethod
    def _get_type_size(c_type: str) -> int:
        """C tipi icin byte boyutunu dondur."""
        # Pointer tiplerini kontrol et
        if c_type.endswith("*"):
            return 8  # ARM64 pointer = 8 byte
        # Exact match
        if c_type in _TYPE_SIZES:
            return _TYPE_SIZES[c_type]
        # Pointer iceren tipler
        if "*" in c_type:
            return 8
        # Bilinmeyen -> 8 (varsayilan ARM64)
        return 8

    @staticmethod
    def _align_up(value: int, alignment: int) -> int:
        """Degeri alignment'a yukari yuvarla."""
        if alignment <= 0:
            return value
        remainder = value % alignment
        if remainder == 0:
            return value
        return value + (alignment - remainder)
