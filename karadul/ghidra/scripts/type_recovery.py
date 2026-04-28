# Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
# @category BlackWidow
# @description Extract struct/enum/typedef type information from DataTypeManager
#
# v1.11.0 Jython Sunset Faz 1.2: Jython 2.7 bagimliligi kaldirildi.
# Jython 2.7 orijinal backup: karadul/ghidra/scripts/legacy/type_recovery.py
# Feature flag: config.perf.use_legacy_jython_scripts=True -> legacy'e dusturur.
#
# UYARI: Bu script Ghidra JVM icinde PyGhidra engine altinda calisir. Ghidra API
# objeleri (currentProgram, DataTypeManager vb.) global scope'ta mevcuttur.
# JPype tipleri (java.lang.String, java.lang.Long vb.) -> Python tiplerine
# explicit donusum (str/int/bool) defansif olarak uygulanir.
#
# PERFORMANS NOTU: Buyuk binary'lerde DataTypeManager binlerce tip icerebilir.
# getAllDataTypes() 4 ayri dongude cagrilir (structures, enums, typedefs,
# func_defs); bu bilincli secim cunku Ghidra iterator'leri tek-gecisli (forward
# only) ve tekrar iterate edilemez. Memory footprint kucuk (iterator lazy).

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from ghidra.program.model.data import Enum
from ghidra.program.model.data import FunctionDefinition
from ghidra.program.model.data import Pointer  # noqa: F401
from ghidra.program.model.data import Structure
from ghidra.program.model.data import TypeDef
from ghidra.program.model.data import Union


def get_output_dir() -> str:
    """KARADUL_OUTPUT ortam degiskeninden cikti dizinini al (CWE-377 guvenli).

    v1.10.0 Batch 5B HIGH-10: KARADUL_WORKSPACE_ROOT path traversal koruma.
    """
    env_val = os.environ.get("KARADUL_OUTPUT", "")
    workspace_root = os.environ.get("KARADUL_WORKSPACE_ROOT", "")
    # v1.10.0 Fix Sprint MED-4: tempfile.mkdtemp() ile rastgele isim.
    if env_val:
        output = env_val
        if workspace_root:
            try:
                real_out = os.path.realpath(output)
                real_root = os.path.realpath(workspace_root)
                if not (real_out == real_root or real_out.startswith(real_root + os.sep)):
                    raise ValueError(
                        "KARADUL_OUTPUT workspace disinda: %s not in %s"
                        % (real_out, real_root)
                    )
            except OSError:
                pass
        if not os.path.exists(output):
            os.makedirs(output)
    else:
        output = tempfile.mkdtemp(prefix="karadul_ghidra_")
    return output


def extract_structures(dtm) -> list:
    """DataTypeManager'dan tum composite (struct/union) tipleri cikar.

    PyGhidra 3.0 notu: Her Java donusu (getName, getDescription vb.)
    explicit str()/int() wrap -- java.lang.String instance'lari JSON
    serializer'da TypeError atar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: struct bilgileri listesi.
    """
    structures: list = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, Structure) or isinstance(dt, Union):
            is_union = isinstance(dt, Union)
            entry: dict[str, Any] = {
                "name": str(dt.getName()),
                "category": str(dt.getCategoryPath()),
                "kind": "union" if is_union else "struct",
                "size": int(dt.getLength()),
                "alignment": int(dt.getAlignment()),
                "description": str(dt.getDescription() or ""),
                "field_count": int(dt.getNumComponents()),
                "fields": [],
            }

            # Field detaylari
            components = dt.getComponents()
            for comp in components:
                field_entry = {
                    "name": str(comp.getFieldName() or "(unnamed)"),
                    "type": str(comp.getDataType()),
                    "offset": int(comp.getOffset()),
                    "size": int(comp.getLength()),
                    "comment": str(comp.getComment() or ""),
                    "ordinal": int(comp.getOrdinal()),
                }
                entry["fields"].append(field_entry)

            structures.append(entry)

    return structures


def extract_enums(dtm) -> list:
    """DataTypeManager'dan tum enum tiplerini cikar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: enum bilgileri listesi.
    """
    enums: list = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, Enum):
            entry: dict[str, Any] = {
                "name": str(dt.getName()),
                "category": str(dt.getCategoryPath()),
                "size": int(dt.getLength()),
                "description": str(dt.getDescription() or ""),
                "value_count": int(dt.getCount()),
                "values": [],
            }

            # Enum degerlerini cikar. getNames() -> java.lang.String[]
            for name in dt.getNames():
                name_py = str(name)
                value = dt.getValue(name)
                entry["values"].append({
                    "name": name_py,
                    "value": int(value),
                })

            enums.append(entry)

    return enums


def extract_typedefs(dtm) -> list:
    """DataTypeManager'dan tum typedef bilgilerini cikar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: typedef bilgileri listesi.
    """
    typedefs: list = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, TypeDef):
            base_type = dt.getBaseDataType()
            entry = {
                "name": str(dt.getName()),
                "category": str(dt.getCategoryPath()),
                "base_type": str(base_type),
                "base_type_name": str(base_type.getName()),
                "size": int(dt.getLength()),
                "description": str(dt.getDescription() or ""),
            }
            typedefs.append(entry)

    return typedefs


def extract_function_definitions(dtm) -> list:
    """DataTypeManager'dan fonksiyon tanimlarini cikar.

    Bunlar gercek fonksiyonlar degil, DataTypeManager'daki
    fonksiyon tip tanimlaridir (callback, function pointer vb.).

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: fonksiyon tanimi bilgileri listesi.
    """
    func_defs: list = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, FunctionDefinition):
            entry: dict[str, Any] = {
                "name": str(dt.getName()),
                "category": str(dt.getCategoryPath()),
                "return_type": str(dt.getReturnType()),
                "calling_convention": str(dt.getCallingConventionName() or ""),
                "param_count": int(len(dt.getArguments())),
                "parameters": [],
            }

            for arg in dt.getArguments():
                entry["parameters"].append({
                    "name": str(arg.getName() or "(unnamed)"),
                    "type": str(arg.getDataType()),
                })

            func_defs.append(entry)

    return func_defs


def summarize_categories(
    structures: list,
    enums: list,
    typedefs: list,
    func_defs: list,
) -> list:
    """Tip kategorilerinin dagitimini hesapla.

    Args:
        structures: struct listesi.
        enums: enum listesi.
        typedefs: typedef listesi.
        func_defs: function definition listesi.

    Returns:
        list: [{"path": str, "count": int}, ...] azalan siralamada.
    """
    cat_counts: dict = {}

    for item_list in [structures, enums, typedefs, func_defs]:
        for item in item_list:
            cat = item.get("category", "/")
            if cat not in cat_counts:
                cat_counts[cat] = 0
            cat_counts[cat] += 1

    # En buyukten kucuge sirala
    sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"path": k, "count": v} for k, v in sorted_cats]


def main() -> None:
    output_dir = get_output_dir()
    dtm = currentProgram.getDataTypeManager()  # type: ignore[name-defined]

    structures = extract_structures(dtm)
    enums = extract_enums(dtm)
    typedefs = extract_typedefs(dtm)
    func_defs = extract_function_definitions(dtm)

    categories = summarize_categories(structures, enums, typedefs, func_defs)

    result = {
        "program": str(currentProgram.getName()),  # type: ignore[name-defined]
        "total_structures": len(structures),
        "total_enums": len(enums),
        "total_typedefs": len(typedefs),
        "total_function_definitions": len(func_defs),
        "total_types": len(structures) + len(enums) + len(typedefs) + len(func_defs),
        "category_summary": categories,
        "structures": structures,
        "enums": enums,
        "typedefs": typedefs,
        "function_definitions": func_defs,
    }

    output_path = os.path.join(output_dir, "types.json")
    # PyGhidra 3.0: encoding=utf-8 + ensure_ascii=False Unicode tip isimlerini
    # (C++ demangled template'ler, Unicode identifier'lar) korur.
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("BlackWidow: Type recovery: %d structs, %d enums, %d typedefs, %d func_defs -> %s" % (
        len(structures), len(enums), len(typedefs), len(func_defs), output_path,
    ))


main()
