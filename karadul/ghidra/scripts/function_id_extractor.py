# Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
# @category BlackWidow
# @description Extract FunctionID matches (library function identification)
#
# v1.11.0 Jython Sunset Faz 1.4 (Dalga 6B): Jython 2.7 bagimliligi kaldirildi.
# Jython 2.7 yedegi 2026-11-18'de silindi (K-3 A2; Ghidra 12.1.2'de Jython yok).
#
# NOT: Ghidra'nin otomatik analizinden sonra FunctionID tarafindan
# taninan kutuphane fonksiyonlarini cikarir.
#
# UYARI: Bu script Ghidra JVM icinde PyGhidra engine altinda calisir. Ghidra API
# objeleri (currentProgram, FunctionManager vb.) global scope'ta mevcuttur.
# JPype tipleri (java.lang.String, java.lang.Long vb.) -> Python tiplerine
# explicit donusum (str/int/bool) defansif olarak uygulanir.

from __future__ import annotations

import json
import os
import tempfile

from ghidra.program.model.symbol import SourceType


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


def extract_function_id_matches() -> dict:
    """FunctionID tarafindan taninan fonksiyonlari cikar.

    Ghidra'nin otomatik analizi sirasinda FunctionID analyzer
    calistiysa, taninan kutuphane fonksiyonlari SourceType.ANALYSIS
    ile isaretlenir. Bu fonksiyonlari bulur ve listeler.

    FUN_ ile baslayan fonksiyonlar taninmamis demektir.
    SourceType.ANALYSIS + non-FUN_ isim = FunctionID eslesmesi.

    PyGhidra 3.0 notu: `from ghidra.program.model.symbol import SourceType`
    artik modul seviyesine tasindi. Jython 2.7'deki lazy import kaldirildi;
    PyGhidra 3.0 eager import'u tercih eder (JPype proxy resolution daha
    hizli). Davranis degismez -- SourceType enum karsilastirmasi aynidir.
    """
    fm = currentProgram.getFunctionManager()  # type: ignore[name-defined]
    matches: list = []
    total_functions = 0
    skipped_fun = 0

    for func in fm.getFunctions(True):
        total_functions += 1
        func_name = str(func.getName())

        # FUN_ ile baslayan = taninmamis
        if func_name.startswith("FUN_"):
            skipped_fun += 1
            continue

        # Thunk ve external fonksiyonlari atla
        if bool(func.isThunk()) or bool(func.isExternal()):
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
            library = str(comment)

        # Namespace'ten library bilgisi
        namespace = func.getParentNamespace()
        if namespace is not None and str(namespace.getName()) != "Global":
            if not library:
                library = str(namespace.getName())

        match_entry: dict = {
            "name": func_name,
            "address": str(func.getEntryPoint()),
            "source": str(source),
            "library": library,
            "size": int(func.getBody().getNumAddresses()),
            "param_count": int(func.getParameterCount()),
        }
        matches.append(match_entry)

    result: dict = {
        "program": str(currentProgram.getName()),  # type: ignore[name-defined]
        "total_functions": total_functions,
        "total_unnamed": skipped_fun,
        "total_matches": len(matches),
        "matches": matches,
    }

    # Cikti dosyasina yaz
    output_dir = get_output_dir()
    output_path = os.path.join(output_dir, "function_id.json")
    # PyGhidra 3.0: encoding=utf-8 + ensure_ascii=False non-ASCII isimleri korur
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("FunctionID: %d / %d fonksiyon tanimlandi" % (len(matches), total_functions))
    return result


# Ana calisma
if __name__ == "__main__" or True:
    try:
        extract_function_id_matches()
    except Exception as e:
        print("HATA: FunctionID extraction basarisiz: %s" % str(e))
