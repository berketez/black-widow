# Ghidra Python Script -- Jython 2.7 uyumlu
# @category BlackWidow
# @description Decompile all functions with disassembly, xrefs and stack frame info
# @keybinding
# @menupath
# @toolbar

# UYARI: Bu script Ghidra JVM icinde calisir.
# Python 3 syntax'i KULLANILMAMALIDIR.
# Limitsiz: tum fonksiyonlari decompile eder.

import json
import os
import re
import tempfile
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor


# Limitler
import logging

logger = logging.getLogger(__name__)
MAX_FUNCTIONS = 0  # 0 = limitsiz, tum fonksiyonlari isle
MAX_TIME_SECONDS = 0  # 0 = limitsiz
DECOMPILE_TIMEOUT = 30  # fonksiyon basina max 30 saniye


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


def safe_filename(name):
    """Fonksiyon adini dosya adi icin guvenli hale getir."""
    # Ozel karakterleri alt cizgi ile degistir
    safe = re.sub(r'[^\w\-.]', '_', name)
    # Bos string kontrolu
    if not safe:
        safe = "unnamed"
    # Cok uzun isimleri kirp (max 200 karakter)
    if len(safe) > 200:
        safe = safe[:200]
    return safe


def extract_disassembly(func):
    """Fonksiyonun disassembly'sini cikar.

    Listing API ile fonksiyon body'sindeki tum instruction'lari toplar.
    Her instruction icin adres, mnemonic ve operand bilgisi doner.

    Args:
        func: Ghidra Function nesnesi.

    Returns:
        list: instruction bilgileri listesi.
    """
    listing = currentProgram.getListing()
    instructions = []

    code_units = listing.getCodeUnits(func.getBody(), True)
    while code_units.hasNext():
        cu = code_units.next()
        # Sadece instruction'lari al (data unit'leri atla)
        try:
            mnemonic = cu.getMnemonicString()
        except Exception:
            logger.debug("Ghidra islemi basarisiz, atlaniyor", exc_info=True)
            continue

        instr_entry = {
            "address": str(cu.getAddress()),
            "mnemonic": mnemonic,
        }

        # Operand'lari topla
        num_operands = cu.getNumOperands()
        operands = []
        for i in range(num_operands):
            op_str = cu.getDefaultOperandRepresentation(i)
            if op_str:
                operands.append(op_str)
        instr_entry["operands"] = operands

        # Tam instruction string
        instr_entry["text"] = str(cu)

        instructions.append(instr_entry)

    return instructions


def extract_xrefs(func):
    """Fonksiyonun cross-reference bilgisini cikar.

    Callers: bu fonksiyonu kim cagiriyor
    Callees: bu fonksiyon kimleri cagiriyor

    Args:
        func: Ghidra Function nesnesi.

    Returns:
        dict: callers ve callees listeleri.
    """
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    func_addr = str(func.getEntryPoint())

    # Callers: bu fonksiyona referans verenler
    callers = []
    seen_callers = set()
    refs_to = ref_mgr.getReferencesTo(func.getEntryPoint())
    for ref in refs_to:
        if ref.getReferenceType().isCall():
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller is not None:
                ca = str(caller.getEntryPoint())
                if ca != func_addr and ca not in seen_callers:
                    seen_callers.add(ca)
                    callers.append({
                        "name": caller.getName(),
                        "address": ca,
                        "call_site": str(ref.getFromAddress()),
                    })

    # Callees: bu fonksiyonun cagirdiklari
    callees = []
    seen_callees = set()
    body = func.getBody()
    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        addr = addr_iter.next()
        refs_from = ref_mgr.getReferencesFrom(addr)
        for ref in refs_from:
            if ref.getReferenceType().isCall():
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee is None:
                    callee = fm.getFunctionContaining(ref.getToAddress())
                if callee is not None:
                    ca = str(callee.getEntryPoint())
                    if ca != func_addr and ca not in seen_callees:
                        seen_callees.add(ca)
                        callees.append({
                            "name": callee.getName(),
                            "address": ca,
                            "call_site": str(addr),
                        })

    return {
        "caller_count": len(callers),
        "callee_count": len(callees),
        "callers": callers,
        "callees": callees,
    }


def extract_stack_frame(func):
    """Fonksiyonun stack frame layout'unu cikar.

    Stack frame icindeki tum degiskenleri (lokal ve parametre)
    offset, boyut ve tip bilgileriyle doner.

    Args:
        func: Ghidra Function nesnesi.

    Returns:
        dict: stack frame bilgileri.
    """
    frame = func.getStackFrame()
    if frame is None:
        return None

    variables = []
    for var in frame.getStackVariables():
        var_entry = {
            "name": var.getName(),
            "offset": var.getStackOffset(),
            "size": var.getLength(),
            "type": str(var.getDataType()),
        }
        # Parametre mi, lokal mi?
        if var.getStackOffset() >= 0:
            var_entry["kind"] = "parameter"
        else:
            var_entry["kind"] = "local"

        comment = var.getComment()
        if comment:
            var_entry["comment"] = comment

        variables.append(var_entry)

    # Offset'e gore sirala (buyukten kucuge: stack yapisini gostermek icin)
    variables.sort(key=lambda v: v["offset"], reverse=True)

    return {
        "frame_size": frame.getFrameSize(),
        "local_size": frame.getLocalSize(),
        "parameter_offset": frame.getParameterOffset(),
        "parameter_size": frame.getParameterSize(),
        "return_address_offset": frame.getReturnAddressOffset(),
        "variable_count": len(variables),
        "variables": variables,
    }


def decompile_functions():
    """Tum fonksiyonlari decompile et, disassembly/xref/stack bilgisiyle zenginlestir.

    DecompInterface kullanarak her fonksiyonu C pseudo-koduna
    donusturur. Ek olarak disassembly, cross-reference ve stack frame
    layout bilgilerini de ekler.
    """
    output_dir = get_output_dir()
    decompiled_dir = os.path.join(output_dir, "decompiled")
    if not os.path.exists(decompiled_dir):
        os.makedirs(decompiled_dir)

    # DecompInterface kur
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(currentProgram)

    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()

    results = []
    success_count = 0
    fail_count = 0
    skipped_count = 0
    start_time = time.time()

    func_iter = fm.getFunctions(True)
    func_index = 0

    while func_iter.hasNext():
        func = func_iter.next()
        func_index += 1

        # Fonksiyon limiti (0 = limitsiz)
        if MAX_FUNCTIONS > 0 and func_index > MAX_FUNCTIONS:
            skipped_count += 1
            continue

        # Zaman limiti (0 = limitsiz)
        elapsed = time.time() - start_time
        if MAX_TIME_SECONDS > 0 and elapsed > MAX_TIME_SECONDS:
            # Kalan fonksiyonlari say
            while func_iter.hasNext():
                func_iter.next()
                skipped_count += 1
            break

        func_name = func.getName()
        func_addr = str(func.getEntryPoint())
        func_size = int(func.getBody().getNumAddresses())

        try:
            # Decompile et
            decomp_result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)

            if decomp_result is not None and decomp_result.depiledFunction() is not None:
                c_code = decomp_result.getDecompiledFunction().getC()
                if c_code:
                    # Disassembly cikar
                    disasm = extract_disassembly(func)

                    # Cross-reference bilgisi cikar
                    xrefs = extract_xrefs(func)

                    # Stack frame layout cikar
                    stack_frame = extract_stack_frame(func)

                    # Dosyaya yaz (decompile + disassembly birlikte)
                    filename = safe_filename(func_name) + ".c"
                    filepath = os.path.join(decompiled_dir, filename)
                    with open(filepath, "w") as f:
                        f.write("// Function: %s\n" % func_name)
                        f.write("// Address:  %s\n" % func_addr)
                        f.write("// Size:     %d bytes\n" % func_size)

                        # Xref ozeti
                        f.write("// Callers:  %d" % xrefs["caller_count"])
                        if xrefs["callers"]:
                            caller_names = [c["name"] for c in xrefs["callers"][:5]]
                            f.write(" (%s" % ", ".join(caller_names))
                            if xrefs["caller_count"] > 5:
                                f.write(", ...")
                            f.write(")")
                        f.write("\n")

                        f.write("// Callees:  %d" % xrefs["callee_count"])
                        if xrefs["callees"]:
                            callee_names = [c["name"] for c in xrefs["callees"][:5]]
                            f.write(" (%s" % ", ".join(callee_names))
                            if xrefs["callee_count"] > 5:
                                f.write(", ...")
                            f.write(")")
                        f.write("\n")

                        # Stack frame ozeti
                        if stack_frame is not None:
                            f.write("// Stack:    frame=%d, locals=%d, params=%d\n" % (
                                stack_frame["frame_size"],
                                stack_frame["local_size"],
                                stack_frame["parameter_size"],
                            ))

                        f.write("\n")
                        f.write(c_code)

                        # Disassembly eki
                        if disasm:
                            f.write("\n\n// --- DISASSEMBLY (%d instructions) ---\n" % len(disasm))
                            for instr in disasm:
                                f.write("// %s  %s\n" % (
                                    instr["address"],
                                    instr["text"],
                                ))

                    result_entry = {
                        "name": func_name,
                        "address": func_addr,
                        "file": filename,
                        "lines": c_code.count("\n") + 1,
                        "size": func_size,
                        "success": True,
                        "instruction_count": len(disasm),
                        "xrefs": xrefs,
                    }

                    # Stack frame bilgisini ekle (variables haric -- cok yer kaplar)
                    if stack_frame is not None:
                        result_entry["stack_frame"] = {
                            "frame_size": stack_frame["frame_size"],
                            "local_size": stack_frame["local_size"],
                            "parameter_size": stack_frame["parameter_size"],
                            "variable_count": stack_frame["variable_count"],
                        }

                    results.append(result_entry)
                    success_count += 1
                else:
                    results.append({
                        "name": func_name,
                        "address": func_addr,
                        "success": False,
                        "error": "Empty decompilation result",
                    })
                    fail_count += 1
            else:
                error_msg = "Decompilation returned None"
                if decomp_result is not None:
                    error_msg = str(decomp_result.getErrorMessage())
                results.append({
                    "name": func_name,
                    "address": func_addr,
                    "success": False,
                    "error": error_msg,
                })
                fail_count += 1

        except Exception as e:
            results.append({
                "name": func_name,
                "address": func_addr,
                "success": False,
                "error": str(e),
            })
            fail_count += 1

    decomp.dispose()

    total_time = time.time() - start_time

    return {
        "total_attempted": func_index,
        "success": success_count,
        "failed": fail_count,
        "skipped": skipped_count,
        "duration_seconds": round(total_time, 2),
        "decompiled_dir": decompiled_dir,
        "functions": results,
    }


def main():
    output_dir = get_output_dir()
    result = decompile_functions()

    # Ozet JSON kaydet
    result_copy = dict(result)
    # functions listesi cok buyuk olabilir, sadece ilk 500'u kaydet
    if len(result_copy.get("functions", [])) > 500:
        result_copy["functions"] = result_copy["functions"][:500]
        result_copy["functions_truncated"] = True

    output_path = os.path.join(output_dir, "decompiled.json")
    with open(output_path, "w") as f:
        json.dump(result_copy, f, indent=2)

    print("BlackWidow: Decompiled %d/%d functions (failed=%d, skipped=%d, %.1fs) -> %s" % (
        result["success"],
        result["total_attempted"],
        result["failed"],
        result["skipped"],
        result["duration_seconds"],
        output_path,
    ))


main()
