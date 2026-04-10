# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract FunctionID matches (library function identification)

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR (f-string yok, type hints yok).
# Ghidra'nin otomatik analizinden sonra FunctionID tarafindan
# taninan kutuphane fonksiyonlarini cikarir.

import json
import os
import tempfile


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


def extract_function_id_matches():
    """FunctionID tarafindan taninan fonksiyonlari cikar.

    Ghidra'nin otomatik analizi sirasinda FunctionID analyzer
    calistiysa, taninan kutuphane fonksiyonlari SourceType.ANALYSIS
    ile isaretlenir. Bu fonksiyonlari bulur ve listeler.

    FUN_ ile baslayan fonksiyonlar taninmamis demektir.
    SourceType.ANALYSIS + non-FUN_ isim = FunctionID eslesmesi.
    """
    from ghidra.program.model.symbol import SourceType

    fm = currentProgram.getFunctionManager()
    matches = []
    total_functions = 0
    skipped_fun = 0

    for func in fm.getFunctions(True):
        total_functions += 1
        func_name = func.getName()

        # FUN_ ile baslayan = taninmamis
        if func_name.startswith("FUN_"):
            skipped_fun += 1
            continue

        # Thunk ve external fonksiyonlari atla
        if func.isThunk() or func.isExternal():
            continue

        # Symbol kaynagini kontrol et
        symbol = func.getSymbol()
        if symbol is None:
            continue

        source = symbol.getSource()

        # ANALYSIS veya IMPORTED kaynaklari FunctionID eslesmesi olabilir
        is_analysis = (source == SourceType.ANALYSIS)
        is_imported = (source == SourceType.IMPORTED)

        if not (is_analysis or is_imported):
            continue

        # Library bilgisini comment'ten cikar (varsa)
        library = ""
        comment = func.getComment()
        if comment:
            library = comment

        # Namespace'ten library bilgisi
        namespace = func.getParentNamespace()
        if namespace and namespace.getName() != "Global":
            if not library:
                library = namespace.getName()

        match_entry = {
            "name": func_name,
            "address": str(func.getEntryPoint()),
            "source": str(source),
            "library": library,
            "size": int(func.getBody().getNumAddresses()),
            "param_count": func.getParameterCount(),
        }
        matches.append(match_entry)

    result = {
        "program": currentProgram.getName(),
        "total_functions": total_functions,
        "total_unnamed": skipped_fun,
        "total_matches": len(matches),
        "matches": matches,
    }

    # Cikti dosyasina yaz
    output_dir = get_output_dir()
    output_path = os.path.join(output_dir, "function_id.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("FunctionID: %d / %d fonksiyon tanimlandi" % (len(matches), total_functions))
    return result


# Ana calisma
if __name__ == "__main__" or True:
    try:
        extract_function_id_matches()
    except Exception as e:
        print("HATA: FunctionID extraction basarisiz: %s" % str(e))
