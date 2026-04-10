# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract call graph (callers and callees for each function)

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR.

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


def extract_call_graph():
    """Her fonksiyon icin caller ve callee listelerini cikar.

    Ghidra'nin referans yoneticisini kullanarak
    UNCONDITIONAL_CALL referanslarini takip eder.
    """
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()

    nodes = {}   # addr -> {name, callers[], callees[]}
    edges = []   # {from, to, from_name, to_name}

    for func in fm.getFunctions(True):
        func_name = func.getName()
        func_addr = str(func.getEntryPoint())

        callers = []
        callees = []

        # Callers: bu fonksiyona kim cagri yapiyor?
        refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
        for ref in refs_to:
            if ref.getReferenceType().isCall():
                caller_func = fm.getFunctionContaining(ref.getFromAddress())
                if caller_func is not None:
                    caller_name = caller_func.getName()
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
                if ref.getReferenceType().isCall():
                    callee_func = fm.getFunctionAt(ref.getToAddress())
                    if callee_func is None:
                        callee_func = fm.getFunctionContaining(ref.getToAddress())
                    if callee_func is not None:
                        callee_name = callee_func.getName()
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
        seen_callers = set()
        unique_callers = []
        for c in callers:
            if c["address"] not in seen_callers:
                seen_callers.add(c["address"])
                unique_callers.append(c)

        seen_callees = set()
        unique_callees = []
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
    seen_edges = set()
    unique_edges = []
    for e in edges:
        key = (e["from"], e["to"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    return nodes, unique_edges


def find_root_functions(nodes):
    """Caller'i olmayan (root) fonksiyonlari bul."""
    roots = []
    for addr, node in nodes.items():
        if node["caller_count"] == 0 and node["callee_count"] > 0:
            roots.append({
                "name": node["name"],
                "address": node["address"],
                "callee_count": node["callee_count"],
            })
    return roots


def find_leaf_functions(nodes):
    """Callee'si olmayan (leaf) fonksiyonlari bul."""
    leaves = []
    for addr, node in nodes.items():
        if node["callee_count"] == 0 and node["caller_count"] > 0:
            leaves.append({
                "name": node["name"],
                "address": node["address"],
                "caller_count": node["caller_count"],
            })
    return leaves


def main():
    output_dir = get_output_dir()
    nodes, edges = extract_call_graph()
    roots = find_root_functions(nodes)
    leaves = find_leaf_functions(nodes)

    result = {
        "program": str(currentProgram.getName()),
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
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: Call graph extracted: %d nodes, %d edges -> %s" % (
        len(nodes), len(edges), output_path,
    ))


main()
