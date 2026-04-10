# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Extract P-Code intermediate representation for dataflow analysis

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR.
# f-string YOK, type hints YOK, print statement/function farki yok.

import json
import os
import tempfile
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor


# Limitler
BATCH_SIZE = 5000       # Buyuk binary'ler icin batch isleme
DECOMPILE_TIMEOUT = 30  # fonksiyon basina max saniye


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


def varnode_to_dict(varnode):
    """Bir Varnode nesnesini JSON-serializable dict'e donustur.

    Varnode, P-Code'un temel veri birimi: register, constant, unique temp
    veya memory adresi olabilir.

    Args:
        varnode: Ghidra Varnode nesnesi (None olabilir).

    Returns:
        dict veya None: Varnode bilgileri.
    """
    if varnode is None:
        return None

    space = varnode.getAddress().getAddressSpace()
    space_name = space.getName() if space is not None else "unknown"

    return {
        "space": space_name,
        "offset": varnode.getOffset(),
        "size": varnode.getSize(),
        "is_constant": varnode.isConstant(),
        "is_register": varnode.isRegister(),
        "is_unique": varnode.isUnique(),
        "is_address": varnode.isAddress(),
        "high_variable": None,  # Asagida doldurulacak (HighVariable varsa)
    }


def extract_pcode_ops(high_func):
    """HighFunction'dan tum PcodeOp'lari cikar.

    Her PcodeOp icin mnemonic, sequence number, output varnode ve
    input varnode'lar toplanir. Ek olarak, HighVariable bilgisi
    (decompiler'in tanimladigi degisken isimleri) varnode'lara eklenir.

    Args:
        high_func: Ghidra HighFunction nesnesi.

    Returns:
        list: PcodeOp bilgileri listesi.
    """
    ops = []

    # HighVariable -> Varnode eslesmesi olustur (degisken isim/tip bilgisi icin)
    high_var_map = {}  # varnode_key -> {name, type}
    local_sym_map = high_func.getLocalSymbolMap()
    if local_sym_map is not None:
        symbols = local_sym_map.getSymbols()
        while symbols.hasNext():
            sym = symbols.next()
            high_var = sym.getHighVariable()
            if high_var is not None:
                var_name = sym.getName()
                var_type = str(sym.getDataType()) if sym.getDataType() is not None else "undefined"
                # HighVariable'in temsil ettigi tum varnode'lari isle
                instances = high_var.getInstances()
                if instances is not None:
                    for vn in instances:
                        key = "%s:%d:%d" % (
                            vn.getAddress().getAddressSpace().getName(),
                            vn.getOffset(),
                            vn.getSize(),
                        )
                        high_var_map[key] = {
                            "name": var_name,
                            "type": var_type,
                        }

    # Tum PcodeOp'lari topla
    pcode_iter = high_func.getPcodeOps()
    while pcode_iter.hasNext():
        pcode_op = pcode_iter.next()

        mnemonic = pcode_op.getMnemonic()
        seq = pcode_op.getSeqnum()
        seq_num = seq.getTime()
        address = str(seq.getTarget())

        # Output varnode
        output_vn = pcode_op.getOutput()
        output_dict = varnode_to_dict(output_vn)
        if output_dict is not None:
            key = "%s:%d:%d" % (output_dict["space"], output_dict["offset"], output_dict["size"])
            hv = high_var_map.get(key)
            if hv is not None:
                output_dict["high_variable"] = hv["name"]

        # Input varnode'lar
        inputs = []
        num_inputs = pcode_op.getNumInputs()
        for i in range(num_inputs):
            in_vn = pcode_op.getInput(i)
            in_dict = varnode_to_dict(in_vn)
            if in_dict is not None:
                key = "%s:%d:%d" % (in_dict["space"], in_dict["offset"], in_dict["size"])
                hv = high_var_map.get(key)
                if hv is not None:
                    in_dict["high_variable"] = hv["name"]
            inputs.append(in_dict)

        ops.append({
            "mnemonic": mnemonic,
            "seq_num": seq_num,
            "address": address,
            "output": output_dict,
            "inputs": inputs,
        })

    return ops


def extract_high_variables(high_func):
    """HighFunction'dan high-level degisken bilgilerini cikar.

    Decompiler'in tanimladigi degiskenlerin isim, tip, depolama alani
    (register, stack, unique) ve boyut bilgilerini toplar.

    Args:
        high_func: Ghidra HighFunction nesnesi.

    Returns:
        list: Degisken bilgileri listesi.
    """
    variables = []
    local_sym_map = high_func.getLocalSymbolMap()
    if local_sym_map is None:
        return variables

    symbols = local_sym_map.getSymbols()
    while symbols.hasNext():
        sym = symbols.next()
        var_entry = {
            "name": sym.getName(),
            "type": str(sym.getDataType()) if sym.getDataType() is not None else "undefined",
            "size": sym.getSize(),
            "is_parameter": sym.isParameter(),
        }

        # Depolama bilgisi (storage)
        high_var = sym.getHighVariable()
        if high_var is not None:
            rep = high_var.getRepresentative()
            if rep is not None:
                var_entry["storage_space"] = rep.getAddress().getAddressSpace().getName()
                var_entry["storage_offset"] = rep.getOffset()
            else:
                var_entry["storage_space"] = "unknown"
                var_entry["storage_offset"] = 0
        else:
            var_entry["storage_space"] = "unknown"
            var_entry["storage_offset"] = 0

        variables.append(var_entry)

    return variables


def extract_pcode_for_all_functions():
    """Tum fonksiyonlar icin P-Code bilgisini cikar.

    DecompInterface ile her fonksiyonu decompile edip HighFunction'dan
    P-Code op'lari ve high-level degisken bilgilerini toplar.
    Buyuk binary'ler icin batch isleme yapar.

    Returns:
        dict: Tum fonksiyonlarin P-Code bilgileri, istatistikler.
    """
    # DecompInterface kur
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(currentProgram)

    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()

    functions = []
    total_ops = 0
    success_count = 0
    fail_count = 0
    skip_count = 0
    start_time = time.time()

    func_iter = fm.getFunctions(True)
    func_index = 0
    batch_num = 0

    while func_iter.hasNext():
        func = func_iter.next()
        func_index += 1

        # Batch siniri: her BATCH_SIZE fonksiyonda ilerleme yazdir
        if func_index % BATCH_SIZE == 0:
            batch_num += 1
            elapsed = time.time() - start_time
            print("BlackWidow P-Code: Batch %d tamamlandi (%d fonksiyon, %.1fs)" % (
                batch_num, func_index, elapsed,
            ))

        func_name = func.getName()
        func_addr = str(func.getEntryPoint())

        try:
            # Decompile et
            decomp_result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)

            if decomp_result is None:
                fail_count += 1
                continue

            high_func = decomp_result.getHighFunction()
            if high_func is None:
                # Decompile basarisiz — genellikle thunk veya cok kucuk fonksiyonlar
                fail_count += 1
                continue

            # P-Code op'lari cikar
            ops = extract_pcode_ops(high_func)

            # High-level degisken bilgileri cikar
            high_vars = extract_high_variables(high_func)

            func_entry = {
                "name": func_name,
                "address": func_addr,
                "op_count": len(ops),
                "ops": ops,
                "high_variables": high_vars,
            }

            functions.append(func_entry)
            total_ops += len(ops)
            success_count += 1

        except Exception as e:
            # Hata olursa bu fonksiyonu atla, devam et
            fail_count += 1

    decomp.dispose()

    total_time = time.time() - start_time

    # Mnemonic dagilim istatistikleri
    mnemonic_counts = {}
    for func_entry in functions:
        for op in func_entry["ops"]:
            mn = op["mnemonic"]
            mnemonic_counts[mn] = mnemonic_counts.get(mn, 0) + 1

    # En yaygin 20 mnemonic
    sorted_mnemonics = sorted(mnemonic_counts.items(), key=lambda x: x[1], reverse=True)
    top_mnemonics = sorted_mnemonics[:20]

    return {
        "program": str(currentProgram.getName()),
        "total_functions_analyzed": success_count,
        "total_functions_failed": fail_count,
        "total_pcode_ops": total_ops,
        "duration_seconds": round(total_time, 2),
        "stats": {
            "mnemonic_distribution": dict(top_mnemonics),
            "total_high_variables": sum(len(f["high_variables"]) for f in functions),
            "avg_ops_per_function": round(float(total_ops) / max(success_count, 1), 1),
        },
        "functions": functions,
    }


def main():
    output_dir = get_output_dir()
    result = extract_pcode_for_all_functions()

    # Sonucu JSON olarak kaydet
    output_path = os.path.join(output_dir, "ghidra_pcode.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("BlackWidow: P-Code extracted: %d functions, %d ops (failed=%d, %.1fs) -> %s" % (
        result["total_functions_analyzed"],
        result["total_pcode_ops"],
        result["total_functions_failed"],
        result["duration_seconds"],
        output_path,
    ))


main()
