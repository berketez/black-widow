# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract all defined strings from binary

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR.

import json
import os
import tempfile

# Ghidra API imports
from ghidra.program.model.data import StringDataType
from ghidra.program.util import DefinedDataIterator


def get_output_dir():
    """KARADUL_OUTPUT ortam degiskeninden cikti dizinini al (CWE-377 guvenli)."""
    env_val = os.environ.get("KARADUL_OUTPUT", "")
    if env_val:
        output = env_val
    else:
        output = os.path.join(tempfile.gettempdir(), "karadul_ghidra_%d" % os.getpid())
    if not os.path.exists(output):
        os.makedirs(output)
    return output


def extract_strings():
    """Tum tanimli string'leri cikar.

    DefinedDataIterator ile program icindeki tum string veri
    tiplerini (ASCII, Unicode, UTF-8) bulur.
    """
    strings = []
    seen_addrs = set()

    # DefinedDataIterator.definedStrings ile tum string'leri bul
    for data in DefinedDataIterator.definedStrings(currentProgram):
        addr = str(data.getAddress())
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)

        value = data.getDefaultValueRepresentation()
        # Ghidra string representation'dan tirnakları kaldir
        if value and len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or \
               (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        entry = {
            "address": addr,
            "value": value,
            "length": data.getLength(),
            "type": str(data.getDataType().getName()),
        }

        # Cross-referanslar (bu string'e kimler referans veriyor)
        xrefs = []
        ref_mgr = currentProgram.getReferenceManager()
        fm = currentProgram.getFunctionManager()
        refs = ref_mgr.getReferencesTo(data.getAddress())
        for ref in refs:
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            xrefs.append({
                "from_address": str(ref.getFromAddress()),
                "from_function": from_func.getName() if from_func else None,
                "from_func_addr": str(from_func.getEntryPoint()) if from_func else None,
            })
        entry["xrefs"] = xrefs
        entry["xref_count"] = len(xrefs)

        # String hangi fonksiyondan referans alıyor? (xref-based, rodata fix)
        # getFunctionContaining string adresi icin calismaz (.rodata != .text)
        # Bunun yerine ilk xref'teki fonksiyonu kullan
        if xrefs and xrefs[0].get("from_function"):
            entry["function"] = xrefs[0]["from_function"]
            entry["function_addr"] = xrefs[0]["from_func_addr"]
        else:
            # Fallback: fiziksel konum (nadiren calısır)
            func = fm.getFunctionContaining(data.getAddress())
            entry["function"] = func.getName() if func else None
            entry["function_addr"] = str(func.getEntryPoint()) if func else None

        strings.append(entry)

    return strings


def categorize_strings(strings):
    """String'leri kategorilere ayir (URL, path, API, error vb.)."""
    categories = {
        "urls": [],
        "paths": [],
        "api_keys": [],
        "error_messages": [],
        "format_strings": [],
        "other": [],
    }

    for s in strings:
        val = s.get("value", "")
        if not val:
            continue

        if val.startswith(("http://", "https://", "ftp://", "ws://", "wss://")):
            categories["urls"].append(s)
        elif val.startswith(("/", "C:\\", "~/")) or "/../" in val:
            categories["paths"].append(s)
        elif any(kw in val.lower() for kw in ("api_key", "secret", "token", "password", "bearer")):
            categories["api_keys"].append(s)
        elif any(kw in val.lower() for kw in ("error", "fail", "exception", "panic", "abort")):
            categories["error_messages"].append(s)
        elif "%" in val and any(c in val for c in "dsfxplu"):
            categories["format_strings"].append(s)
        else:
            categories["other"].append(s)

    return categories


def main():
    output_dir = get_output_dir()
    strings = extract_strings()
    categories = categorize_strings(strings)

    # Kategori istatistikleri
    category_stats = {}
    for cat, items in categories.items():
        category_stats[cat] = len(items)

    result = {
        "total": len(strings),
        "program": str(currentProgram.getName()),
        "category_stats": category_stats,
        "strings": strings,
    }

    output_path = os.path.join(output_dir, "strings.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: Extracted %d strings (%s) -> %s" % (
        len(strings),
        ", ".join("%s=%d" % (k, v) for k, v in category_stats.items()),
        output_path,
    ))


main()
