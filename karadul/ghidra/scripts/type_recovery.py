# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract struct/enum/typedef type information from DataTypeManager

# UYARI: Bu script Ghidra JVM icinde calisir. Ghidra API objeleri
# (currentProgram, DataTypeManager vb.) global scope'ta mevcuttur.
# Python 3 syntax'i KULLANILMAMALIDIR (f-string yok, print statement).

import json
import os
import tempfile

from ghidra.program.model.data import Structure
from ghidra.program.model.data import Union
from ghidra.program.model.data import Enum
from ghidra.program.model.data import TypeDef
from ghidra.program.model.data import FunctionDefinition
from ghidra.program.model.data import Pointer


def get_output_dir():
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


def extract_structures(dtm):
    """DataTypeManager'dan tum composite (struct/union) tipleri cikar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: struct bilgileri listesi.
    """
    structures = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, Structure) or isinstance(dt, Union):
            is_union = isinstance(dt, Union)
            entry = {
                "name": dt.getName(),
                "category": str(dt.getCategoryPath()),
                "kind": "union" if is_union else "struct",
                "size": dt.getLength(),
                "alignment": dt.getAlignment(),
                "description": dt.getDescription() or "",
                "field_count": dt.getNumComponents(),
                "fields": [],
            }

            # Field detaylari
            components = dt.getComponents()
            for comp in components:
                field_entry = {
                    "name": comp.getFieldName() or "(unnamed)",
                    "type": str(comp.getDataType()),
                    "offset": comp.getOffset(),
                    "size": comp.getLength(),
                    "comment": comp.getComment() or "",
                    "ordinal": comp.getOrdinal(),
                }
                entry["fields"].append(field_entry)

            structures.append(entry)

    return structures


def extract_enums(dtm):
    """DataTypeManager'dan tum enum tiplerini cikar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: enum bilgileri listesi.
    """
    enums = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, Enum):
            entry = {
                "name": dt.getName(),
                "category": str(dt.getCategoryPath()),
                "size": dt.getLength(),
                "description": dt.getDescription() or "",
                "value_count": dt.getCount(),
                "values": [],
            }

            # Enum degerlerini cikar
            for name in dt.getNames():
                value = dt.getValue(name)
                entry["values"].append({
                    "name": name,
                    "value": int(value),
                })

            enums.append(entry)

    return enums


def extract_typedefs(dtm):
    """DataTypeManager'dan tum typedef bilgilerini cikar.

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: typedef bilgileri listesi.
    """
    typedefs = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, TypeDef):
            base_type = dt.getBaseDataType()
            entry = {
                "name": dt.getName(),
                "category": str(dt.getCategoryPath()),
                "base_type": str(base_type),
                "base_type_name": base_type.getName(),
                "size": dt.getLength(),
                "description": dt.getDescription() or "",
            }
            typedefs.append(entry)

    return typedefs


def extract_function_definitions(dtm):
    """DataTypeManager'dan fonksiyon tanimlarini cikar.

    Bunlar gercek fonksiyonlar degil, DataTypeManager'daki
    fonksiyon tip tanimlaridir (callback, function pointer vb.).

    Args:
        dtm: Ghidra DataTypeManager nesnesi.

    Returns:
        list: fonksiyon tanimi bilgileri listesi.
    """
    func_defs = []
    all_types = dtm.getAllDataTypes()

    while all_types.hasNext():
        dt = all_types.next()

        if isinstance(dt, FunctionDefinition):
            entry = {
                "name": dt.getName(),
                "category": str(dt.getCategoryPath()),
                "return_type": str(dt.getReturnType()),
                "calling_convention": str(dt.getCallingConventionName() or ""),
                "param_count": len(dt.getArguments()),
                "parameters": [],
            }

            for arg in dt.getArguments():
                entry["parameters"].append({
                    "name": arg.getName() or "(unnamed)",
                    "type": str(arg.getDataType()),
                })

            func_defs.append(entry)

    return func_defs


def summarize_categories(structures, enums, typedefs, func_defs):
    """Tip kategorilerinin dagitimini hesapla.

    Args:
        structures: struct listesi.
        enums: enum listesi.
        typedefs: typedef listesi.
        func_defs: function definition listesi.

    Returns:
        dict: kategori -> sayi eslesmesi.
    """
    cat_counts = {}

    for item_list in [structures, enums, typedefs, func_defs]:
        for item in item_list:
            cat = item.get("category", "/")
            if cat not in cat_counts:
                cat_counts[cat] = 0
            cat_counts[cat] += 1

    # En buyukten kucuge sirala
    sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"path": k, "count": v} for k, v in sorted_cats]


def main():
    output_dir = get_output_dir()
    dtm = currentProgram.getDataTypeManager()

    structures = extract_structures(dtm)
    enums = extract_enums(dtm)
    typedefs = extract_typedefs(dtm)
    func_defs = extract_function_definitions(dtm)

    categories = summarize_categories(structures, enums, typedefs, func_defs)

    result = {
        "program": str(currentProgram.getName()),
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
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: Type recovery: %d structs, %d enums, %d typedefs, %d func_defs -> %s" % (
        len(structures), len(enums), len(typedefs), len(func_defs), output_path,
    ))


main()
