"""v1.10.0 M2 T10 — Ghidra backend adapter.

Mevcut `karadul.ghidra.headless.GhidraHeadless`'i DecompilerBackend
Protocol'e sarmalar. Hic bir Ghidra kodunu DEGISTIRMEZ; sadece dict
dondurulen sonucu `DecompileResult` dataclass'ina cevirir.

Tasarim:
    - `GhidraHeadless.analyze()` icerik sematigi:
        scripts_output = {
            "functions": {"total": N, "functions": [ {name, address, ...} ]},
            "call_graph": {"nodes": {...}, "edges": [...]},
            "strings": {"total": N, "strings": [ {address, value, ...} ]},
            "decompiled": { "success": N, ... , per-func pseudocode dosyalar },
            ...
        }
    - Adapter bu dict'ten functions + call_graph + strings cikarir. Hatalar
      scripts_output'da yoksa `ghidra_log` icindeki WARN/FAIL satirlarindan
      toplanir.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.decompilers.base import DecompiledFunction, DecompileResult

logger = logging.getLogger(__name__)


class GhidraBackend:
    """Ghidra decompiler adapter.

    Args:
        config: Karadul merkezi konfigurasyon.

    Not: Gercek `GhidraHeadless` instance'i tembel yaratilir — config'de
    Ghidra path'i gerek olmayan testlerde import yukunu azaltir.
    """

    name: str = "ghidra"

    def __init__(self, config: Config) -> None:
        self.config = config
        self._ghidra: Any | None = None

    # ------------------------------------------------------------------
    # Lazy init
    # ------------------------------------------------------------------

    @property
    def ghidra(self):
        """GhidraHeadless instance'ini lazy yarat."""
        if self._ghidra is None:
            from karadul.ghidra.headless import GhidraHeadless

            self._ghidra = GhidraHeadless(self.config)
        return self._ghidra

    # ------------------------------------------------------------------
    # DecompilerBackend Protocol
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Ghidra mevcut mu? (analyzeHeadless path veya PyGhidra)"""
        try:
            return self.ghidra.is_available()
        except Exception as exc:
            logger.warning("Ghidra is_available sorgusu hata: %s", exc)
            return False

    def supports_platform(self, platform: str) -> bool:
        """Ghidra neredeyse her platformu destekler."""
        return platform in ("macho", "elf", "pe", "raw", "coff")

    def decompile(
        self,
        binary: Path,
        output_dir: Path,
        timeout: float = 3600.0,
    ) -> DecompileResult:
        """Binary'i Ghidra ile decompile et ve standart sonuca cevir."""
        binary = Path(binary)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        ghidra_result = self.ghidra.analyze(
            binary_path=binary,
            project_dir=output_dir / "ghidra_project",
            project_name="karadul_decompile",
            timeout=int(timeout),
            output_dir=output_dir,
        )
        duration = time.monotonic() - start

        return self._to_standard_result(ghidra_result, duration)

    # ------------------------------------------------------------------
    # Internal — Ghidra dict -> DecompileResult
    # ------------------------------------------------------------------

    @staticmethod
    def _to_standard_result(
        ghidra_result: dict[str, Any],
        duration_seconds: float,
    ) -> DecompileResult:
        """Ghidra `analyze()` dict'inden DecompileResult olustur.

        Ghidra JSON emisyon formati:
            functions: {total, functions: [ {name, address, ...} ]}
            call_graph: {nodes: {addr: {name, callers, callees}}, edges: [...]}
            strings: {total, strings: [ {address, value, length, type} ]}
            decompiled: per-function metadata (pseudocode dosya icinde ayri)
        """
        scripts_output = ghidra_result.get("scripts_output") or {}
        errors: list[str] = []

        # Non-fatal FAIL/WARN satirlari
        ghidra_log = ghidra_result.get("ghidra_log") or ""
        for line in ghidra_log.splitlines():
            if line.startswith(("FAIL", "WARN")):
                errors.append(line)

        # --- Functions ---
        func_block = scripts_output.get("functions") or {}
        raw_funcs = func_block.get("functions") or []

        # Call graph'tan calls haritasi cikar (func address -> [called addrs])
        call_graph: dict[str, list[str]] = {}
        cg_block = scripts_output.get("call_graph") or {}
        nodes = cg_block.get("nodes") or {}
        for addr, node in nodes.items():
            callees = node.get("callees") or []
            call_graph[addr] = [c.get("address", "") for c in callees if c.get("address")]

        # --- Decompiled pseudocode ---
        # Ghidra decompile.json per-function dosya listeler; dosyalari okumak
        # pahali olabilir. Adapter sadece metadata alir, pseudocode istek
        # uzerine ikinci bir API ile yuklenebilir. Burada mevcut metadata'dan
        # placeholder uretiriz.
        decompiled_block = scripts_output.get("decompiled") or {}
        decompiled_dir = decompiled_block.get("decompiled_dir")

        functions: list[DecompiledFunction] = []
        for f in raw_funcs:
            addr = str(f.get("address", ""))
            name = str(f.get("name", ""))
            pseudocode = GhidraBackend._load_pseudocode(
                decompiled_dir, name, addr,
            )
            calls = call_graph.get(addr, [])
            backend_specific = {
                "size": f.get("size"),
                "param_count": f.get("param_count"),
                "return_type": f.get("return_type"),
                "is_thunk": f.get("is_thunk"),
                "is_external": f.get("is_external"),
                "calling_convention": f.get("calling_convention"),
                "parameters": f.get("parameters"),
                "source": f.get("source"),
            }
            functions.append(
                DecompiledFunction(
                    address=addr,
                    name=name,
                    pseudocode=pseudocode,
                    calls=list(calls),
                    backend_specific=backend_specific,
                )
            )

        # --- Strings ---
        str_block = scripts_output.get("strings") or {}
        raw_strings = str_block.get("strings") or []
        strings: list[dict] = []
        for s in raw_strings:
            strings.append({
                "addr": str(s.get("address", "")),
                "value": s.get("value", ""),
                "encoding": s.get("type", "string"),
                "length": s.get("length"),
                "function": s.get("function"),
            })

        return DecompileResult(
            functions=functions,
            call_graph=call_graph,
            strings=strings,
            errors=errors,
            backend_name="ghidra",
            duration_seconds=duration_seconds,
        )

    @staticmethod
    def _load_pseudocode(
        decompiled_dir: str | Path | None,
        func_name: str,
        func_addr: str,
    ) -> str:
        """Decompiled dosyadan pseudocode'u yukle (best-effort).

        Dosya yoksa veya okunamazsa bos string doner — error field'a eklenmez
        cunku bu beklenebilir (thunk/external fonksiyonlar decompile edilmez).
        """
        if not decompiled_dir:
            return ""
        try:
            dec_dir = Path(decompiled_dir)
            if not dec_dir.exists():
                return ""
            # Ghidra convention: <name>_<addr>.c veya <addr>.c
            candidates = [
                dec_dir / f"{func_name}_{func_addr}.c",
                dec_dir / f"{func_addr}.c",
                dec_dir / f"{func_name}.c",
            ]
            for cand in candidates:
                if cand.exists():
                    return cand.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("Pseudocode yukleme hatasi (%s): %s", func_name, exc)
        return ""
