# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract control flow graphs (basic blocks and edges) per function

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR (f-string yok, type hints yok).

import json
import os
import tempfile

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


# Buyuk binary'lerde bellek tasmasi onlemek icin batch siniri
BATCH_SIZE = 5000


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


def classify_edge(flow_type, dest_addr, src_addr):
    """Edge tipini FlowType'a gore siniflandir.

    Args:
        flow_type: Ghidra FlowType objesi.
        dest_addr: Hedef basic block baslangic adresi (Ghidra Address).
        src_addr: Kaynak basic block bitis adresi (Ghidra Address).

    Returns:
        str: Edge tipi -- "fall_through", "conditional_jump", "unconditional_jump"
             veya "unknown".
    """
    if flow_type.isFallthrough():
        return "fall_through"
    if flow_type.isConditional():
        return "conditional_jump"
    if flow_type.isUnConditional():
        # isCall() olan unconditional dallanmalari haric tut --
        # bunlar fonksiyon cagrilari, CFG edge'i degil
        if flow_type.isCall():
            return None
        return "unconditional_jump"
    return "unknown"


def is_back_edge(src_end_addr, dest_start_addr):
    """Basit back-edge heuristigi: hedef adres < kaynak adres.

    Gercek dominator-based back-edge tespiti Python 3 tarafinda
    (cfg_analyzer.py) yapilacak. Bu sadece ipucu niteliginde.

    Args:
        src_end_addr: Kaynak block'un bitis adresi.
        dest_start_addr: Hedef block'un baslangic adresi.

    Returns:
        bool: Hedef adres kaynak adresinden kucukse True.
    """
    return dest_start_addr.compareTo(src_end_addr) < 0


def extract_function_cfg(func, block_model, monitor):
    """Tek bir fonksiyon icin CFG cikar.

    BasicBlockModel kullanarak fonksiyonun body'sindeki
    tum basic block'lari ve aralarindaki edge'leri toplar.

    Args:
        func: Ghidra Function objesi.
        block_model: BasicBlockModel instance.
        monitor: ConsoleTaskMonitor instance.

    Returns:
        dict: Fonksiyonun CFG bilgilerini iceren sozluk.
              Hata durumunda None doner.
    """
    func_name = func.getName()
    func_addr = str(func.getEntryPoint())
    body = func.getBody()

    blocks = []
    edges = []
    block_addrs = set()  # Tekrar onleme icin

    # Bu fonksiyonun body'sindeki tum basic block'lari al
    block_iter = block_model.getCodeBlocksContaining(body, monitor)
    while block_iter.hasNext():
        block = block_iter.next()
        start = block.getFirstStartAddress()
        end = block.getMaxAddress()
        start_str = str(start)

        # Ayni block'u birden fazla ekleme
        if start_str in block_addrs:
            continue
        block_addrs.add(start_str)

        block_info = {
            "start_address": start_str,
            "end_address": str(end),
            "size": int(block.getNumAddresses()),
        }
        blocks.append(block_info)

        # Bu block'tan cikan edge'leri bul
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest_ref = dest_iter.next()
            dest_block = dest_ref.getDestinationBlock()
            flow = dest_ref.getFlowType()

            if dest_block is None:
                continue

            dest_start = dest_block.getFirstStartAddress()
            dest_str = str(dest_start)

            # Edge tipini belirle
            edge_type = classify_edge(flow, dest_start, end)
            if edge_type is None:
                # Call edge -- CFG icinde gostermiyoruz
                continue

            back = is_back_edge(end, dest_start)

            edge_info = {
                "from_block": start_str,
                "to_block": dest_str,
                "edge_type": edge_type,
                "is_back_edge": back,
            }
            edges.append(edge_info)

    # Cyclomatic complexity: V(G) = E - N + 2
    num_edges = len(edges)
    num_blocks = len(blocks)
    complexity = num_edges - num_blocks + 2 if num_blocks > 0 else 0

    # Back-edge'leri ayri listele (loop ipucu)
    back_edges = []
    for e in edges:
        if e["is_back_edge"]:
            back_edges.append((e["from_block"], e["to_block"]))

    # Loop header adaylarini belirle (back-edge hedefleri)
    loop_headers = list(set(be[1] for be in back_edges))

    return {
        "name": func_name,
        "address": func_addr,
        "block_count": num_blocks,
        "edge_count": num_edges,
        "cyclomatic_complexity": complexity,
        "loop_header_count": len(loop_headers),
        "loop_headers": loop_headers,
        "back_edges": back_edges,
        "blocks": blocks,
        "edges": edges,
    }


def extract_all_cfgs():
    """Tum fonksiyonlar icin CFG cikar.

    BATCH_SIZE kadar fonksiyon isler. Tek bir fonksiyonda
    hata olursa o fonksiyonu atlar, geri kalani devam eder.

    Returns:
        tuple: (functions listesi, istatistik sozlugu).
    """
    fm = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    block_model = BasicBlockModel(currentProgram)

    functions = []
    error_count = 0
    skipped_count = 0
    processed = 0

    for func in fm.getFunctions(True):
        if processed >= BATCH_SIZE:
            skipped_count = fm.getFunctionCount() - processed
            break

        try:
            cfg = extract_function_cfg(func, block_model, monitor)
            if cfg is not None:
                functions.append(cfg)
        except Exception as e:
            error_count += 1
            print("BlackWidow CFG: HATA fonksiyon %s (%s): %s" % (
                func.getName(), str(func.getEntryPoint()), str(e),
            ))

        processed += 1

        # Her 500 fonksiyonda ilerleme raporu
        if processed % 500 == 0:
            print("BlackWidow CFG: %d / %d fonksiyon islendi..." % (
                processed, min(fm.getFunctionCount(), BATCH_SIZE),
            ))

    stats = {
        "total_processed": processed,
        "successful": len(functions),
        "errors": error_count,
        "skipped_over_batch": skipped_count,
        "batch_size": BATCH_SIZE,
    }
    return functions, stats


def compute_global_stats(functions):
    """Tum fonksiyonlar uzerinden toplu istatistikler hesapla.

    Args:
        functions: extract_all_cfgs'den donen fonksiyon listesi.

    Returns:
        dict: Toplam block, edge, complexity dagilimi vb.
    """
    total_blocks = 0
    total_edges = 0
    total_loops = 0
    complexity_sum = 0
    max_complexity = 0
    max_complexity_func = ""

    # Complexity dagilimi
    linear = 0       # complexity <= 2
    moderate = 0     # 3 <= complexity <= 10
    high = 0         # 11 <= complexity <= 20
    very_high = 0    # complexity > 20

    for f in functions:
        bc = f["block_count"]
        ec = f["edge_count"]
        cc = f["cyclomatic_complexity"]
        lc = f["loop_header_count"]

        total_blocks += bc
        total_edges += ec
        total_loops += lc
        complexity_sum += cc

        if cc > max_complexity:
            max_complexity = cc
            max_complexity_func = "%s @ %s" % (f["name"], f["address"])

        if cc <= 2:
            linear += 1
        elif cc <= 10:
            moderate += 1
        elif cc <= 20:
            high += 1
        else:
            very_high += 1

    func_count = len(functions)
    avg_complexity = (complexity_sum / float(func_count)) if func_count > 0 else 0.0

    return {
        "total_blocks": total_blocks,
        "total_edges": total_edges,
        "total_loop_headers": total_loops,
        "avg_cyclomatic_complexity": round(avg_complexity, 2),
        "max_cyclomatic_complexity": max_complexity,
        "max_complexity_function": max_complexity_func,
        "complexity_distribution": {
            "linear_le2": linear,
            "moderate_3_10": moderate,
            "high_11_20": high,
            "very_high_gt20": very_high,
        },
    }


def main():
    """Ana calisma fonksiyonu: CFG cikar, istatistik hesapla, JSON'a yaz."""
    output_dir = get_output_dir()
    functions, extraction_stats = extract_all_cfgs()
    global_stats = compute_global_stats(functions)

    result = {
        "program": str(currentProgram.getName()),
        "total_functions": len(functions),
        "extraction_stats": extraction_stats,
        "global_stats": global_stats,
        "functions": functions,
    }

    output_path = os.path.join(output_dir, "ghidra_cfg.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow CFG: %d fonksiyon islendi -> %s" % (
        len(functions), output_path,
    ))
    print("  Toplam block: %d, edge: %d, loop header: %d" % (
        global_stats["total_blocks"],
        global_stats["total_edges"],
        global_stats["total_loop_headers"],
    ))
    print("  Complexity dagilimi: linear=%d, moderate=%d, high=%d, very_high=%d" % (
        global_stats["complexity_distribution"]["linear_le2"],
        global_stats["complexity_distribution"]["moderate_3_10"],
        global_stats["complexity_distribution"]["high_11_20"],
        global_stats["complexity_distribution"]["very_high_gt20"],
    ))


main()
