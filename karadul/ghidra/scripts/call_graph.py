# Ghidra Python Script -- PyGhidra 3.0 (Python 3.10+) uyumlu
# @category BlackWidow
# @description Extract call graph (callers and callees for each function)
#
# v1.11.0 Jython Sunset Faz 1.3 (Dalga 4): Jython 2.7 bagimliligi kaldirildi.
# Jython 2.7 yedegi 2026-11-18'de silindi (K-3 A2; Ghidra 12.1.2'de Jython yok).
#
# NOT: Bu script CLI fallback icin kullanilir. PyGhidra native path
# karadul/ghidra/headless.py:253 uzerinden bypass edilir. Yine de
# parity korumasi icin migrate edilmistir.
#
# UYARI: Bu script Ghidra JVM icinde PyGhidra engine altinda calisir. Ghidra API
# objeleri (currentProgram, FunctionManager, ReferenceManager vb.) global
# scope'ta mevcuttur. JPype tipleri (java.lang.String, java.lang.Long vb.) ->
# Python tiplerine explicit donusum (str/int/bool) defansif olarak uygulanir.

from __future__ import annotations

import json
import os
import tempfile


def get_output_dir() -> str:
    """KARADUL_OUTPUT ortam degiskeninden cikti dizinini al (CWE-377 guvenli).

    v1.10.0 Fix Sprint MED-4: tempfile.mkdtemp() ile rastgele isim.
    v1.10.0 Batch 5B HIGH-10: KARADUL_WORKSPACE_ROOT ile path traversal
    koruma.
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


def extract_call_graph() -> tuple:
    """Her fonksiyon icin caller ve callee listelerini cikar.

    Ghidra'nin referans yoneticisini kullanarak
    UNCONDITIONAL_CALL referanslarini takip eder.

    PyGhidra 3.0 notu: JPype Java proxy objelerinde str()/int() wrap
    ZORUNLU -- aksi halde downstream JSON serialization'da java.lang.String
    instance'lari gorulebilir ve json.dumps TypeError atar.
    """
    fm = currentProgram.getFunctionManager()  # type: ignore[name-defined]
    ref_mgr = currentProgram.getReferenceManager()  # type: ignore[name-defined]

    nodes: dict = {}   # addr -> {name, callers[], callees[]}
    edges: list = []   # {from, to, from_name, to_name}

    for func in fm.getFunctions(True):
        func_name = str(func.getName())
        func_addr = str(func.getEntryPoint())

        callers: list = []
        callees: list = []

        # Callers: bu fonksiyona kim cagri yapiyor?
        refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
        for ref in refs_to:
            if bool(ref.getReferenceType().isCall()):
                caller_func = fm.getFunctionContaining(ref.getFromAddress())
                if caller_func is not None:
                    caller_name = str(caller_func.getName())
                    caller_addr = str(caller_func.getEntryPoint())
                    if caller_addr != func_addr:  # self-call haric
                        callers.append({
                            "name": caller_name,
                            "address": caller_addr,
                        })

        # Callees: bu fonksiyon kimleri cagiriyor?
        body = func.getBody()
        addr_set_iter = body.getAddresses(True)
        while addr_set_iter.hasNext():
            addr = addr_set_iter.next()
            refs_from = ref_mgr.getReferencesFrom(addr)
            for ref in refs_from:
                if bool(ref.getReferenceType().isCall()):
                    callee_func = fm.getFunctionAt(ref.getToAddress())
                    if callee_func is None:
                        callee_func = fm.getFunctionContaining(ref.getToAddress())
                    if callee_func is not None:
                        callee_name = str(callee_func.getName())
                        callee_addr = str(callee_func.getEntryPoint())
                        if callee_addr != func_addr:  # self-call haric
                            callees.append({
                                "name": callee_name,
                                "address": callee_addr,
                            })
                            edges.append({
                                "from": func_addr,
                                "to": callee_addr,
                                "from_name": func_name,
                                "to_name": callee_name,
                            })

        # Unique callers/callees (adrese gore)
        seen_callers: set = set()
        unique_callers: list = []
        for c in callers:
            if c["address"] not in seen_callers:
                seen_callers.add(c["address"])
                unique_callers.append(c)

        seen_callees: set = set()
        unique_callees: list = []
        for c in callees:
            if c["address"] not in seen_callees:
                seen_callees.add(c["address"])
                unique_callees.append(c)

        nodes[func_addr] = {
            "name": func_name,
            "address": func_addr,
            "caller_count": len(unique_callers),
            "callee_count": len(unique_callees),
            "callers": unique_callers,
            "callees": unique_callees,
        }

    # Unique edges
    seen_edges: set = set()
    unique_edges: list = []
    for e in edges:
        key = (e["from"], e["to"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    return nodes, unique_edges


def find_root_functions(nodes) -> list:
    """Caller'i olmayan (root) fonksiyonlari bul."""
    roots: list = []
    for addr, node in nodes.items():
        if node["caller_count"] == 0 and node["callee_count"] > 0:
            roots.append({
                "name": node["name"],
                "address": node["address"],
                "callee_count": node["callee_count"],
            })
    return roots


def find_leaf_functions(nodes) -> list:
    """Callee'si olmayan (leaf) fonksiyonlari bul."""
    leaves: list = []
    for addr, node in nodes.items():
        if node["callee_count"] == 0 and node["caller_count"] > 0:
            leaves.append({
                "name": node["name"],
                "address": node["address"],
                "caller_count": node["caller_count"],
            })
    return leaves


def main() -> None:
    output_dir = get_output_dir()
    nodes, edges = extract_call_graph()
    roots = find_root_functions(nodes)
    leaves = find_leaf_functions(nodes)

    result = {
        "program": str(currentProgram.getName()),  # type: ignore[name-defined]
        "total_functions": len(nodes),
        "total_edges": len(edges),
        "root_functions": len(roots),
        "leaf_functions": len(leaves),
        "roots": roots,
        "leaves": leaves,
        "nodes": nodes,
        "edges": edges,
    }

    output_path = os.path.join(output_dir, "call_graph.json")
    # PyGhidra 3.0: encoding=utf-8 + ensure_ascii=False non-ASCII isimleri korur
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("BlackWidow: Call graph extracted: %d nodes, %d edges -> %s" % (
        len(nodes), len(edges), output_path,
    ))


main()
