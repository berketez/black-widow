# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Build cross-reference map for functions, strings, and globals

# UYARI: Bu script Ghidra JVM icinde calisir. Ghidra API objeleri
# (currentProgram, ReferenceManager vb.) global scope'ta mevcuttur.
# Python 3 syntax'i KULLANILMAMALIDIR (f-string yok, print statement).

import json
import os
import tempfile

from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SymbolType


def get_output_dir():
    """KARADUL_OUTPUT ortam degiskeninden cikti dizinini al (CWE-377 guvenli).

    v1.10.0 Batch 5B HIGH-10: Path traversal koruma. Eger
    KARADUL_WORKSPACE_ROOT tanimliysa KARADUL_OUTPUT'un realpath'i onun
    altinda olmali. "/tmp/ws" workspace + "/tmp/ws/../../etc" cikmak
    yasak.
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


def build_function_xref_map():
    """Her fonksiyon icin: kullandigi string'ler, global'ler ve xref istatistikleri.

    Her fonksiyonun body adres araligi icindeki tum referanslari tarar.
    Referans hedeflerinin tipine gore string, global ve fonksiyon
    kategorilerine ayirir.

    Returns:
        dict: fonksiyon adresi -> xref bilgileri eslesmesi.
    """
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    func_xrefs = {}

    for func in fm.getFunctions(True):
        func_name = func.getName()
        func_addr = str(func.getEntryPoint())

        entry = {
            "name": func_name,
            "address": func_addr,
            "strings_used": [],       # bu fonksiyonun referans verdigi string'ler
            "globals_accessed": [],    # bu fonksiyonun eristigi global degiskenler
            "functions_called": [],    # bu fonksiyonun cagirdigi fonksiyonlar
            "called_by": [],           # bu fonksiyonu cagiran fonksiyonlar
            "data_refs_from": 0,       # fonksiyondan cikan data referans sayisi
            "call_refs_from": 0,       # fonksiyondan cikan call referans sayisi
        }

        # Fonksiyon body'sindeki tum adreslerden cikan referanslar
        seen_strings = set()
        seen_globals = set()
        seen_callees = set()

        body = func.getBody()
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs_from = ref_mgr.getReferencesFrom(addr)

            for ref in refs_from:
                to_addr = ref.getToAddress()
                ref_type = ref.getReferenceType()

                if ref_type.isCall():
                    # Fonksiyon cagrisi
                    entry["call_refs_from"] += 1
                    callee = fm.getFunctionAt(to_addr)
                    if callee is None:
                        callee = fm.getFunctionContaining(to_addr)
                    if callee is not None:
                        callee_addr = str(callee.getEntryPoint())
                        if callee_addr not in seen_callees:
                            seen_callees.add(callee_addr)
                            entry["functions_called"].append({
                                "name": callee.getName(),
                                "address": callee_addr,
                            })
                elif ref_type.isData():
                    # Data referansi -- string mi, global mi?
                    entry["data_refs_from"] += 1

                    # Hedef adreste tanimli veri var mi kontrol et
                    data = listing.getDefinedDataAt(to_addr)
                    if data is not None:
                        dt_name = str(data.getDataType().getName()).lower()
                        to_addr_str = str(to_addr)

                        if "string" in dt_name or "cstring" in dt_name:
                            # String referansi
                            if to_addr_str not in seen_strings:
                                seen_strings.add(to_addr_str)
                                value = data.getDefaultValueRepresentation()
                                if value and len(value) >= 2:
                                    if (value[0] == '"' and value[-1] == '"') or \
                                       (value[0] == "'" and value[-1] == "'"):
                                        value = value[1:-1]
                                entry["strings_used"].append({
                                    "address": to_addr_str,
                                    "value": value,
                                    "type": str(data.getDataType().getName()),
                                })
                        else:
                            # Global degisken
                            if to_addr_str not in seen_globals:
                                seen_globals.add(to_addr_str)
                                entry["globals_accessed"].append({
                                    "address": to_addr_str,
                                    "type": str(data.getDataType().getName()),
                                    "size": data.getLength(),
                                    "access": "read",  # varsayilan, asagida guncellenir
                                })

        # Caller'lar (bu fonksiyona referans verenler)
        seen_callers = set()
        refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
        for ref in refs_to:
            if ref.getReferenceType().isCall():
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is not None:
                    caller_addr = str(caller.getEntryPoint())
                    if caller_addr != func_addr and caller_addr not in seen_callers:
                        seen_callers.add(caller_addr)
                        entry["called_by"].append({
                            "name": caller.getName(),
                            "address": caller_addr,
                        })

        func_xrefs[func_addr] = entry

    return func_xrefs


def build_string_xref_map():
    """Her string icin: hangi fonksiyonlar bu string'e referans veriyor.

    Programdaki tum tanimli string veri tiplerini bulur ve her birine
    gelen referanslari fonksiyon bazinda gruplandirir.

    Returns:
        list: string xref kayitlari listesi.
    """
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()

    string_xrefs = []
    seen_addrs = set()

    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        dt_name = str(data.getDataType().getName()).lower()

        if "string" not in dt_name and "cstring" not in dt_name:
            continue

        addr = data.getAddress()
        addr_str = str(addr)
        if addr_str in seen_addrs:
            continue
        seen_addrs.add(addr_str)

        value = data.getDefaultValueRepresentation()
        if value and len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or \
               (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        # Bu string'e referans veren fonksiyonlar
        referencing_funcs = []
        seen_funcs = set()
        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            if from_func is not None:
                from_addr = str(from_func.getEntryPoint())
                if from_addr not in seen_funcs:
                    seen_funcs.add(from_addr)
                    referencing_funcs.append({
                        "name": from_func.getName(),
                        "address": from_addr,
                        "ref_address": str(ref.getFromAddress()),
                        "ref_type": str(ref.getReferenceType()),
                    })

        entry = {
            "address": addr_str,
            "value": value,
            "length": data.getLength(),
            "type": str(data.getDataType().getName()),
            "referenced_by_count": len(referencing_funcs),
            "referenced_by": referencing_funcs,
        }

        # String hangi fonksiyon icinde tanimli?
        containing_func = fm.getFunctionContaining(addr)
        entry["defined_in_function"] = containing_func.getName() if containing_func else None

        string_xrefs.append(entry)

    return string_xrefs


def build_global_xref_map():
    """Her global degisken icin: hangi fonksiyonlar okuyor/yaziyor.

    Symbol tablosundan global label'lari bulur ve her birine gelen
    referanslari okuma/yazma olarak siniflandirir.

    Returns:
        list: global degisken xref kayitlari listesi.
    """
    sym_table = currentProgram.getSymbolTable()
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    globals_xrefs = []

    # Symbol tablosundan global label'lari tara
    sym_iter = sym_table.getAllSymbols(True)
    while sym_iter.hasNext():
        sym = sym_iter.next()

        # Sadece DATA ve LABEL sembollerini al (fonksiyonlari atla)
        sym_type = sym.getSymbolType()
        if sym_type == SymbolType.FUNCTION or sym_type == SymbolType.PARAMETER or \
           sym_type == SymbolType.LOCAL_VAR:
            continue

        # External semboller de dahil
        sym_addr = sym.getAddress()
        if sym_addr is None:
            continue

        # Bu adrese referans var mi?
        refs = ref_mgr.getReferencesTo(sym_addr)
        ref_list = []
        for ref in refs:
            ref_list.append(ref)

        if len(ref_list) == 0:
            continue  # referans yoksa atla, gereksiz veri

        # Adresteki veriyi kontrol et
        data = listing.getDefinedDataAt(sym_addr)
        data_type_name = ""
        data_size = 0
        if data is not None:
            data_type_name = str(data.getDataType().getName())
            data_size = data.getLength()
            # String'leri atla (string_xref_map'de zaten var)
            if "string" in data_type_name.lower() or "cstring" in data_type_name.lower():
                continue

        # Referanslari read/write olarak siniflandir
        readers = []     # READ referans veren fonksiyonlar
        writers = []     # WRITE referans veren fonksiyonlar
        seen_readers = set()
        seen_writers = set()

        for ref in ref_list:
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            if from_func is None:
                continue

            func_addr = str(from_func.getEntryPoint())
            ref_type = ref.getReferenceType()

            # WRITE referans tipleri
            if ref_type.isWrite():
                if func_addr not in seen_writers:
                    seen_writers.add(func_addr)
                    writers.append({
                        "name": from_func.getName(),
                        "address": func_addr,
                        "ref_address": str(ref.getFromAddress()),
                    })
            else:
                # READ (veya diger: COMPUTED, CONDITIONAL vb.)
                if func_addr not in seen_readers:
                    seen_readers.add(func_addr)
                    readers.append({
                        "name": from_func.getName(),
                        "address": func_addr,
                        "ref_address": str(ref.getFromAddress()),
                    })

        entry = {
            "name": sym.getName(),
            "address": str(sym_addr),
            "type": data_type_name or "undefined",
            "size": data_size,
            "symbol_type": str(sym_type),
            "is_external": sym.isExternalEntryPoint(),
            "reader_count": len(readers),
            "writer_count": len(writers),
            "readers": readers,
            "writers": writers,
        }

        globals_xrefs.append(entry)

    return globals_xrefs


def compute_statistics(func_xrefs, string_xrefs, global_xrefs):
    """Xref istatistiklerini hesapla.

    Args:
        func_xrefs: fonksiyon xref haritasi.
        string_xrefs: string xref listesi.
        global_xrefs: global xref listesi.

    Returns:
        dict: istatistik bilgileri.
    """
    # En cok referans alan string'ler (top 20)
    sorted_strings = sorted(string_xrefs, key=lambda s: s["referenced_by_count"], reverse=True)
    top_strings = []
    for s in sorted_strings[:20]:
        top_strings.append({
            "address": s["address"],
            "value": s["value"][:100],  # uzun stringleri kes
            "ref_count": s["referenced_by_count"],
        })

    # En cok cagrilan fonksiyonlar (top 20)
    func_call_counts = []
    for addr, fdata in func_xrefs.items():
        func_call_counts.append({
            "name": fdata["name"],
            "address": fdata["address"],
            "called_by_count": len(fdata["called_by"]),
            "calls_count": len(fdata["functions_called"]),
            "strings_count": len(fdata["strings_used"]),
        })
    sorted_funcs = sorted(func_call_counts, key=lambda f: f["called_by_count"], reverse=True)

    # En cok yazilan global'ler (top 20)
    sorted_globals = sorted(global_xrefs, key=lambda g: g["writer_count"], reverse=True)
    top_globals = []
    for g in sorted_globals[:20]:
        top_globals.append({
            "name": g["name"],
            "address": g["address"],
            "reader_count": g["reader_count"],
            "writer_count": g["writer_count"],
        })

    # Referanssiz fonksiyonlar (izole)
    isolated = [f for f in func_call_counts if f["called_by_count"] == 0 and f["calls_count"] == 0]

    # Ortalama referans sayilari
    total_call_refs = sum(f["called_by_count"] for f in func_call_counts)
    total_string_refs = sum(s["referenced_by_count"] for s in string_xrefs)

    func_count = len(func_call_counts)

    return {
        "total_functions": func_count,
        "total_strings_with_xrefs": len(string_xrefs),
        "total_globals_with_xrefs": len(global_xrefs),
        "isolated_functions": len(isolated),
        "avg_callers_per_func": round(total_call_refs / func_count, 2) if func_count > 0 else 0,
        "avg_refs_per_string": round(total_string_refs / len(string_xrefs), 2) if string_xrefs else 0,
        "most_referenced_strings": top_strings,
        "most_called_functions": sorted_funcs[:20],
        "most_written_globals": top_globals,
    }


def main():
    output_dir = get_output_dir()

    print("BlackWidow: Building function xref map...")
    func_xrefs = build_function_xref_map()

    print("BlackWidow: Building string xref map...")
    string_xrefs = build_string_xref_map()

    print("BlackWidow: Building global xref map...")
    global_xrefs = build_global_xref_map()

    print("BlackWidow: Computing xref statistics...")
    stats = compute_statistics(func_xrefs, string_xrefs, global_xrefs)

    result = {
        "program": str(currentProgram.getName()),
        "statistics": stats,
        "function_xrefs": func_xrefs,
        "string_xrefs": string_xrefs,
        "global_xrefs": global_xrefs,
    }

    output_path = os.path.join(output_dir, "xrefs.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: Xref analysis: %d functions, %d strings, %d globals -> %s" % (
        stats["total_functions"],
        stats["total_strings_with_xrefs"],
        stats["total_globals_with_xrefs"],
        output_path,
    ))


main()
