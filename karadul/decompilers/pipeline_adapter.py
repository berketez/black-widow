"""v1.11.0 Phase 1B — Pipeline adapter: DecompileResult -> Ghidra JSON shape.

Pipeline step'leri (ghidra_metadata.py, binary_prep.py, semantic_naming.py,
struct_recovery.py vb.) Ghidra'nin `ghidra_functions.json`,
`ghidra_strings.json`, `ghidra_call_graph.json` dosyalarini ve
`static/ghidra_output/decompiled/*.c` dizinini okuyor.

Backend-agnostic pipeline icin: hangi backend calisirsa calissin, sonucu
Ghidra-uyumlu dosya yapisina cevirmek yeterli. Boylece downstream step'lere
dokunulmaz.

API:
    write_ghidra_shape_artifacts(result, output_dir) -> dict[str, Path]

Bu fonksiyon:
    - output_dir/ghidra_functions.json yazar
    - output_dir/ghidra_strings.json yazar
    - output_dir/ghidra_call_graph.json yazar
    - output_dir/ghidra_output/decompiled/*.c yazar (pseudocode)
    - Ghidra'nin `scripts_output` ile ayni kabuga sarmalanmis dict doner.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from karadul.decompilers.base import DecompileResult

logger = logging.getLogger(__name__)


_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str, addr: str) -> str:
    """Decompiled dosya adi: <sanitized_name>_<addr>.c.

    Ghidra convention: per-function bir .c dosyasi. Pipeline'in binary_prep
    step'i `rglob('*.c')` ile yukluyor, ad formati esnek.
    """
    base = _UNSAFE_FILENAME_CHARS.sub("_", str(name) or "func")
    addr_clean = _UNSAFE_FILENAME_CHARS.sub("_", str(addr) or "0x0")
    # Cok uzun isimleri kirp (FS limit + linux ext4 guvenligi)
    base = base[:80]
    return f"{base}_{addr_clean}.c"


def _result_to_ghidra_functions(result: DecompileResult) -> dict[str, Any]:
    """DecompileResult.functions -> ghidra_functions.json schema.

    Ghidra schema (ghidra_metadata.py'de parse edilen):
        {
          "total": N,
          "functions": [
            {
              "name": str, "address": str, "size": int|None,
              "param_count": int|None, "return_type": str|None,
              "is_thunk": bool, "is_external": bool,
              "calling_convention": str|None,
              "parameters": list, "source": str,
            }, ...
          ]
        }
    """
    functions_out: list[dict[str, Any]] = []
    for func in result.functions:
        bs = func.backend_specific or {}
        functions_out.append({
            "name": func.name,
            "address": func.address,
            "size": bs.get("size"),
            "param_count": bs.get("param_count"),
            "return_type": bs.get("return_type"),
            "is_thunk": bool(bs.get("is_thunk", False)),
            "is_external": bool(bs.get("is_external", False)),
            "calling_convention": bs.get("calling_convention"),
            "parameters": bs.get("parameters") or [],
            # backend_name source alanina yazilir -- semantic_naming'in
            # "USER_DEFINED"/"DEFAULT" ayrimi korunsun (default: ANGR_AUTO).
            "source": bs.get("source", f"{result.backend_name.upper()}_AUTO"),
        })
    return {"total": len(functions_out), "functions": functions_out}


def _result_to_ghidra_call_graph(result: DecompileResult) -> dict[str, Any]:
    """DecompileResult.call_graph -> ghidra_call_graph.json schema.

    Ghidra schema:
        {
          "nodes": {addr: {"name": str, "callers": [...], "callees": [...]}},
          "edges": [{"from": addr, "to": addr}, ...],
        }
    """
    # Addr -> name haritasi
    addr_to_name: dict[str, str] = {f.address: f.name for f in result.functions}

    # Callers haritasini tersine cevir
    callers_map: dict[str, list[dict[str, str]]] = {}
    edges: list[dict[str, str]] = []
    for src, targets in result.call_graph.items():
        for tgt in targets:
            edges.append({"from": src, "to": tgt})
            callers_map.setdefault(tgt, []).append({
                "name": addr_to_name.get(src, ""),
                "address": src,
            })

    nodes: dict[str, Any] = {}
    for func in result.functions:
        callees = [
            {"name": addr_to_name.get(t, ""), "address": t}
            for t in result.call_graph.get(func.address, [])
        ]
        nodes[func.address] = {
            "name": func.name,
            "callers": callers_map.get(func.address, []),
            "callees": callees,
        }

    return {"nodes": nodes, "edges": edges}


def _result_to_ghidra_strings(result: DecompileResult) -> dict[str, Any]:
    """DecompileResult.strings -> ghidra_strings.json schema.

    Ghidra schema:
        {"total": N, "strings": [{"address", "value", "length", "type",
                                   "function"}]}
    """
    strings_out: list[dict[str, Any]] = []
    for s in result.strings:
        value = s.get("value", "")
        strings_out.append({
            "address": s.get("addr") or s.get("address", ""),
            "value": value,
            "length": s.get("length", len(str(value))),
            "type": s.get("encoding") or s.get("type", "string"),
            "function": s.get("function", ""),
        })
    return {"total": len(strings_out), "strings": strings_out}


def write_ghidra_shape_artifacts(
    result: DecompileResult,
    output_dir: Path,
) -> dict[str, Any]:
    """`DecompileResult`'i Ghidra'nin statik analiz cikti dizine yaz.

    Pipeline baslangic step'leri bu dosyalari bekliyor:
        static/ghidra_functions.json
        static/ghidra_strings.json
        static/ghidra_call_graph.json
        static/ghidra_output/decompiled/*.c

    Args:
        result: Herhangi bir backend'den (angr, Ghidra, ileride IDA) gelen
            standart DecompileResult.
        output_dir: Yazilacak dizin (tipik: workspace/static). Alt klasorler
            (ghidra_output/decompiled) otomatik olusturulur.

    Returns:
        Ghidra'nin analyze() dict'iyle uyumlu dict:
            {
              "success": bool,
              "duration_seconds": float,
              "ghidra_log": "",
              "mode": "<backend>_adapter",
              "scripts_output": {
                "functions": {...},
                "call_graph": {...},
                "strings": {...},
                "decompiled": {
                  "success": N, "total_attempted": N,
                  "decompiled_dir": "<path>"
                },
              },
            }

        MachOAnalyzer.analyze_static bu dict'i normalde Ghidra'dan bekledigi
        gibi parse edip artifact olarak saklar.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    functions_block = _result_to_ghidra_functions(result)
    call_graph_block = _result_to_ghidra_call_graph(result)
    strings_block = _result_to_ghidra_strings(result)

    # JSON yaz
    (output_dir / "ghidra_functions.json").write_text(
        json.dumps(functions_block, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "ghidra_strings.json").write_text(
        json.dumps(strings_block, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "ghidra_call_graph.json").write_text(
        json.dumps(call_graph_block, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Decompiled per-function .c dosyalari
    decompiled_dir = output_dir / "ghidra_output" / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)

    decompiled_success = 0
    decompiled_attempted = 0
    for func in result.functions:
        if not func.pseudocode:
            continue
        decompiled_attempted += 1
        fname = _safe_filename(func.name, func.address)
        try:
            (decompiled_dir / fname).write_text(
                func.pseudocode, encoding="utf-8",
            )
            decompiled_success += 1
        except OSError as exc:
            logger.warning(
                "Pseudocode yazilamadi (%s -> %s): %s",
                func.name, fname, exc,
            )

    # Tiny decompiled.json index (Ghidra'da da uretilen, fakat karadul
    # ghidra_metadata'da opsiyonel okuma).
    decompiled_index = {
        "success": decompiled_success,
        "total_attempted": decompiled_attempted,
        "decompiled_dir": str(decompiled_dir),
        "files": [
            _safe_filename(f.name, f.address)
            for f in result.functions if f.pseudocode
        ],
    }
    (decompiled_dir.parent / "decompiled.json").write_text(
        json.dumps(decompiled_index, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    logger.info(
        "Pipeline adapter [%s]: %d fonksiyon, %d string, %d pseudocode yazildi",
        result.backend_name,
        len(result.functions),
        len(result.strings),
        decompiled_success,
    )

    return {
        "success": True,
        "duration_seconds": result.duration_seconds,
        "ghidra_log": "\n".join(result.errors) if result.errors else "",
        "mode": f"{result.backend_name}_adapter",
        "returncode": 0,
        "scripts_output": {
            "functions": functions_block,
            "call_graph": call_graph_block,
            "strings": strings_block,
            "decompiled": decompiled_index,
            "combined_results": {
                "summary": {
                    "function_count": len(result.functions),
                    "string_count": len(result.strings),
                    "call_graph_edges": sum(
                        len(v) for v in result.call_graph.values()
                    ),
                    "decompiled_success": decompiled_success,
                },
            },
        },
    }
