# Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
# @category BlackWidow
# @description Extract all functions with metadata (name, address, size, params)
#
# v1.11.0 Jython Sunset Faz 1: Jython 2.7 bagimliligi kaldirildi.
# Jython 2.7 yedegi 2026-11-18'de silindi (K-3 A2; Ghidra 12.1.2'de Jython yok).
#
# UYARI: Bu script Ghidra JVM icinde PyGhidra engine altinda calisir. Ghidra API
# objeleri (currentProgram, FunctionManager vb.) global scope'ta mevcuttur.
# JPype tipleri (java.lang.String, java.lang.Long vb.) -> Python tiplerine
# explicit donusum (str/int/list) defansif olarak uygulanir.

from __future__ import annotations

import json
import os
import sys
import tempfile


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


def extract_functions() -> list:
    """Tum fonksiyonlari meta verileriyle birlikte cikar.

    PyGhidra 3.0 notu: JPype Java proxy objelerinde str()/int() wrap
    ZORUNLU -- aksi halde downstream JSON serialization'da java.lang.String
    instance'lari gorulebilir ve json.dumps TypeError atar.
    """
    fm = currentProgram.getFunctionManager()  # type: ignore[name-defined]
    functions: list = []

    for func in fm.getFunctions(True):  # True = forward iterator
        # JPype boundary: her Java donusu explicit Python tipine wrap
        entry = {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "param_count": int(func.getParameterCount()),
            "return_type": str(func.getReturnType()),
            "is_thunk": bool(func.isThunk()),
            "calling_convention": str(func.getCallingConventionName()),
            "is_external": bool(func.isExternal()),
        }

        # Parametre detaylari
        params: list = []
        for i in range(int(func.getParameterCount())):
            param = func.getParameter(i)
            params.append({
                "name": str(param.getName()),
                "type": str(param.getDataType()),
                "ordinal": int(param.getOrdinal()),
            })
        entry["parameters"] = params

        # Fonksiyonun kaynak bilgisi (SourceType enum -> str)
        source = func.getSymbol().getSource()
        entry["source"] = str(source)

        functions.append(entry)

    return functions


def main() -> None:
    output_dir = get_output_dir()
    functions = extract_functions()

    result = {
        "total": len(functions),
        "program": str(currentProgram.getName()),  # type: ignore[name-defined]
        "functions": functions,
    }

    output_path = os.path.join(output_dir, "functions.json")
    # PyGhidra 3.0: encoding=utf-8 + ensure_ascii=False non-ASCII isimleri korur
    # (mangled C++ demangled halleri, Unicode identifier'lar vb.)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("BlackWidow: Extracted %d functions -> %s" % (len(functions), output_path))


main()
