# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Combine all analysis results into a single JSON

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR.
# Bu script en son calistirilmalidir (diger scriptlerin ciktilarini birlestirir).

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


def load_json_safe(path):
    """JSON dosyasini guvenli yukle, hata durumunda None dondur."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (ValueError, IOError) as e:
        print("BlackWidow: JSON yukleme hatasi: %s: %s" % (path, e))
        return None


def get_program_info():
    """Program bilgilerini topla."""
    prog = currentProgram
    lang = prog.getLanguage()
    compiler = prog.getCompilerSpec()

    info = {
        "name": str(prog.getName()),
        "path": str(prog.getExecutablePath()),
        "language": str(lang.getLanguageID()),
        "processor": str(lang.getProcessor()),
        "endian": str(lang.isBigEndian() and "big" or "little"),
        "address_size": lang.getDefaultSpace().getSize(),
        "compiler": str(compiler.getCompilerSpecID()),
        "executable_format": str(prog.getExecutableFormat()),
        "image_base": str(prog.getImageBase()),
        "min_address": str(prog.getMinAddress()),
        "max_address": str(prog.getMaxAddress()),
    }

    # Entry point
    entry_points = []
    sym_table = prog.getSymbolTable()
    for symbol in sym_table.getExternalEntryPointIterator():
        entry_points.append(str(symbol))
    info["entry_points"] = entry_points

    # Memory blokları
    memory = prog.getMemory()
    blocks = []
    for block in memory.getBlocks():
        blocks.append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": "%s%s%s" % (
                "r" if block.isRead() else "-",
                "w" if block.isWrite() else "-",
                "x" if block.isExecute() else "-",
            ),
            "type": str(block.getType()),
        })
    info["memory_blocks"] = blocks

    return info


def main():
    output_dir = get_output_dir()

    # Onceki scriptlerin ciktilarini yukle
    functions_data = load_json_safe(os.path.join(output_dir, "functions.json"))
    strings_data = load_json_safe(os.path.join(output_dir, "strings.json"))
    call_graph_data = load_json_safe(os.path.join(output_dir, "call_graph.json"))
    decompiled_data = load_json_safe(os.path.join(output_dir, "decompiled.json"))

    # Program bilgileri
    program_info = get_program_info()

    # Ozet istatistikler
    summary = {
        "program": program_info,
        "function_count": functions_data["total"] if functions_data else 0,
        "string_count": strings_data["total"] if strings_data else 0,
        "call_graph_nodes": call_graph_data["total_functions"] if call_graph_data else 0,
        "call_graph_edges": call_graph_data["total_edges"] if call_graph_data else 0,
        "decompiled_success": decompiled_data["success"] if decompiled_data else 0,
        "decompiled_failed": decompiled_data["failed"] if decompiled_data else 0,
    }

    # Birlesik sonuc
    combined = {
        "summary": summary,
        "program_info": program_info,
    }

    # Alt sonuclari ekle (cok buyuk olabilirler, sadece ozet bilgiler)
    if functions_data:
        combined["functions"] = {
            "total": functions_data["total"],
            # Ilk 100 fonksiyonu ekle (tam liste functions.json'da)
            "sample": functions_data.get("functions", [])[:100],
            "full_file": "functions.json",
        }

    if strings_data:
        combined["strings"] = {
            "total": strings_data["total"],
            "category_stats": strings_data.get("category_stats", {}),
            # Ilk 100 string'i ekle (tam liste strings.json'da)
            "sample": strings_data.get("strings", [])[:100],
            "full_file": "strings.json",
        }

    if call_graph_data:
        combined["call_graph"] = {
            "total_functions": call_graph_data["total_functions"],
            "total_edges": call_graph_data["total_edges"],
            "root_functions": call_graph_data.get("roots", []),
            "leaf_count": call_graph_data.get("leaf_functions", 0),
            "full_file": "call_graph.json",
        }

    if decompiled_data:
        combined["decompilation"] = {
            "success": decompiled_data["success"],
            "failed": decompiled_data["failed"],
            "skipped": decompiled_data.get("skipped", 0),
            "duration_seconds": decompiled_data.get("duration_seconds", 0),
            "full_file": "decompiled.json",
        }

    output_path = os.path.join(output_dir, "combined_results.json")
    with open(output_path, "w") as f:
        json.dump(combined, f, indent=2)

    print("BlackWidow: Combined results exported -> %s" % output_path)
    print("  Functions: %d" % summary["function_count"])
    print("  Strings:   %d" % summary["string_count"])
    print("  CG Nodes:  %d, Edges: %d" % (
        summary["call_graph_nodes"], summary["call_graph_edges"],
    ))
    print("  Decompiled: %d success, %d failed" % (
        summary["decompiled_success"], summary["decompiled_failed"],
    ))


main()
