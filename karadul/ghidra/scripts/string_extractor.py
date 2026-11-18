# Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
# @category BlackWidow
# @description Extract all defined strings from binary
#
# v1.11.0 Jython Sunset Faz 1.2: Jython 2.7 bagimliligi kaldirildi.
# Jython 2.7 yedegi 2026-11-18'de silindi (K-3 A2; Ghidra 12.1.2'de Jython yok).
#
# UYARI: Bu script Ghidra JVM icinde PyGhidra engine altinda calisir. Ghidra API
# objeleri (currentProgram vb.) global scope'ta mevcuttur. JPype tipleri
# (java.lang.String vb.) -> Python tiplerine explicit donusum (str/int/bool)
# defansif olarak uygulanir.

from __future__ import annotations

import json
import os
import tempfile

# Ghidra API imports
from ghidra.program.model.data import StringDataType  # noqa: F401
from ghidra.program.util import DefinedDataIterator


def get_output_dir() -> str:
    """KARADUL_OUTPUT ortam degiskeninden cikti dizinini al (CWE-377 guvenli).

    v1.10.0 Fix Sprint MED-4: tempfile.mkdtemp() ile rastgele isim.
    v1.10.0 Batch 5B HIGH-10: KARADUL_WORKSPACE_ROOT path traversal koruma.
    """
    env_val = os.environ.get("KARADUL_OUTPUT", "")
    workspace_root = os.environ.get("KARADUL_WORKSPACE_ROOT", "")
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


def extract_strings() -> list:
    """Tum tanimli string'leri cikar.

    DefinedDataIterator ile program icindeki tum string veri
    tiplerini (ASCII, Unicode, UTF-8) bulur.

    PyGhidra 3.0 notu: JPype Java proxy objelerinde str()/int() wrap
    ZORUNLU -- aksi halde downstream JSON serialization'da java.lang.String
    instance'lari gorulebilir ve json.dumps TypeError atar.
    """
    strings: list = []
    seen_addrs: set = set()

    # DefinedDataIterator.definedStrings ile tum string'leri bul
    for data in DefinedDataIterator.definedStrings(currentProgram):  # type: ignore[name-defined]
        # JPype boundary: Address -> str explicit
        addr = str(data.getAddress())
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)

        # getDefaultValueRepresentation() -> java.lang.String -> Python str
        raw_value = data.getDefaultValueRepresentation()
        value = str(raw_value) if raw_value is not None else ""
        # Ghidra string representation'dan tirnaklari kaldir
        if value and len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or \
               (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        entry = {
            "address": addr,
            "value": value,
            "length": int(data.getLength()),
            "type": str(data.getDataType().getName()),
        }

        # Cross-referanslar (bu string'e kimler referans veriyor)
        xrefs: list = []
        ref_mgr = currentProgram.getReferenceManager()  # type: ignore[name-defined]
        fm = currentProgram.getFunctionManager()  # type: ignore[name-defined]
        refs = ref_mgr.getReferencesTo(data.getAddress())
        for ref in refs:
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            xrefs.append({
                "from_address": str(ref.getFromAddress()),
                "from_function": str(from_func.getName()) if from_func else None,
                "from_func_addr": str(from_func.getEntryPoint()) if from_func else None,
            })
        entry["xrefs"] = xrefs
        entry["xref_count"] = len(xrefs)

        # String hangi fonksiyondan referans aliyor? (xref-based, rodata fix)
        # getFunctionContaining string adresi icin calismaz (.rodata != .text)
        # Bunun yerine ilk xref'teki fonksiyonu kullan
        if xrefs and xrefs[0].get("from_function"):
            entry["function"] = xrefs[0]["from_function"]
            entry["function_addr"] = xrefs[0]["from_func_addr"]
        else:
            # Fallback: fiziksel konum (nadiren calisir)
            func = fm.getFunctionContaining(data.getAddress())
            entry["function"] = str(func.getName()) if func else None
            entry["function_addr"] = str(func.getEntryPoint()) if func else None

        strings.append(entry)

    return strings


def categorize_strings(strings: list) -> dict:
    """String'leri kategorilere ayir (URL, path, API, error vb.)."""
    categories: dict = {
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


def main() -> None:
    output_dir = get_output_dir()
    strings = extract_strings()
    categories = categorize_strings(strings)

    # Kategori istatistikleri
    category_stats: dict = {}
    for cat, items in categories.items():
        category_stats[cat] = len(items)

    result = {
        "total": len(strings),
        "program": str(currentProgram.getName()),  # type: ignore[name-defined]
        "category_stats": category_stats,
        "strings": strings,
    }

    output_path = os.path.join(output_dir, "strings.json")
    # PyGhidra 3.0: encoding=utf-8 + ensure_ascii=False non-ASCII string'leri
    # korur (Unicode literal'lar, UTF-8 icerik, mangled C++ demangled halleri).
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("BlackWidow: Extracted %d strings (%s) -> %s" % (
        len(strings),
        ", ".join("%s=%d" % (k, v) for k, v in category_stats.items()),
        output_path,
    ))


main()
