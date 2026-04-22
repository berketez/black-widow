# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract all functions with metadata (name, address, size, params)

# UYARI: Bu script Ghidra JVM icinde calisir. Ghidra API objeleri
# (currentProgram, FunctionManager vb.) global scope'ta mevcuttur.
# Python 3 syntax'i KULLANILMAMALIDIR (f-string yok, print statement).

import json
import os
import sys
import tempfile

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


def extract_functions():
    """Tum fonksiyonlari meta verileriyle birlikte cikar."""
    fm = currentProgram.getFunctionManager()
    functions = []

    for func in fm.getFunctions(True):  # True = forward iterator
        entry = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "param_count": func.getParameterCount(),
            "return_type": str(func.getReturnType()),
            "is_thunk": func.isThunk(),
            "calling_convention": str(func.getCallingConventionName()),
            "is_external": func.isExternal(),
        }

        # Parametre detaylari
        params = []
        for i in range(func.getParameterCount()):
            param = func.getParameter(i)
            params.append({
                "name": param.getName(),
                "type": str(param.getDataType()),
                "ordinal": param.getOrdinal(),
            })
        entry["parameters"] = params

        # Fonksiyonun kaynak bilgisi (varsa)
        source = func.getSymbol().getSource()
        entry["source"] = str(source)

        functions.append(entry)

    return functions


def main():
    output_dir = get_output_dir()
    functions = extract_functions()

    result = {
        "total": len(functions),
        "program": str(currentProgram.getName()),
        "functions": functions,
    }

    output_path = os.path.join(output_dir, "functions.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: Extracted %d functions -> %s" % (len(functions), output_path))


main()
