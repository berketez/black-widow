"""v1.10.0 M2 T10 — angr decompiler backend (opsiyonel).

angr Python native, OSS decompiler framework. `pip install angr` ile
opsiyonel extra olarak kurulabilir; kurulu degilse `is_available()` False
doner ve calistirma hata verir.

Tasarim:
    - Tum angr import'lari method icinde (lazy). Modul import'u sirasinda
      ImportError patlamaz; Ghidra-only kurulumlar bozulmaz.
    - decompile() gercek angr calistirir (sadece kuruluysa). CI'da angr
      yoktur -- testler sadece is_available/supports_platform/factory
      davranisini kontrol eder.
    - angr'in `Decompiler` analizi pahalidir (CFGFast + decompiler pass).
      Buyuk binary'lerde timeout kontrolu caller'a birakilir.

Limitler:
    - Windows PE + DWARF destegi ghidra'ya gore sinirli (pyvex/binja farki).
    - C++ name mangling destegi zayif.
    - PDB entegrasyonu yok.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.decompilers.base import DecompiledFunction, DecompileResult

logger = logging.getLogger(__name__)


class AngrBackend:
    """angr-based decompiler backend.

    Args:
        config: Karadul config (angr-ozgu ayarlar ileride eklenebilir).
    """

    name: str = "angr"

    def __init__(self, config: Config) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # DecompilerBackend Protocol
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """angr modulu import edilebiliyor mu?"""
        try:
            import angr  # noqa: F401
            return True
        except ImportError:
            return False
        except Exception as exc:
            # angr kurulu ama bozuk (ornegin eksik native lib). Sorun kullaniciya
            # bildirilmeli; False dondurup graceful skip yapariz.
            logger.warning("angr import hatasi: %s", exc)
            return False

    def supports_platform(self, platform: str) -> bool:
        """angr hedefli platformlar."""
        return platform in ("macho", "elf", "pe")

    def decompile(
        self,
        binary: Path,
        output_dir: Path,
        timeout: float = 3600.0,
    ) -> DecompileResult:
        """Binary'i angr ile decompile et.

        Bu method CI'da cagirilmaz -- angr kurulu degil. Kullanimda:
            backend = AngrBackend(config)
            if backend.is_available():
                result = backend.decompile(binary, out_dir)

        Args:
            binary: Girdi binary.
            output_dir: Ara ciktilar icin dizin.
            timeout: Toplam zaman asimi (saniye). angr'in kendisi sert
                timeout desteklemez -- caller'in thread/process boyutunda
                kesmesi onerilir.

        Returns:
            DecompileResult (backend_name="angr").

        Raises:
            RuntimeError: angr kurulu degilse.
        """
        if not self.is_available():
            raise RuntimeError(
                "angr kurulu degil. `pip install 'karadul[decompilers]'` "
                "veya `pip install angr` ile kurun."
            )

        binary = Path(binary)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        errors: list[str] = []

        functions, call_graph, errors_fn = self._run_angr_decompile(
            binary, timeout,
        )
        errors.extend(errors_fn)

        strings = self._extract_strings(binary)

        duration = time.monotonic() - start

        return DecompileResult(
            functions=functions,
            call_graph=call_graph,
            strings=strings,
            errors=errors,
            backend_name="angr",
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    # angr internals
    # ------------------------------------------------------------------

    def _run_angr_decompile(
        self,
        binary: Path,
        timeout: float,
    ) -> tuple[list[DecompiledFunction], dict[str, list[str]], list[str]]:
        """CFGFast + Decompiler pass. angr kurulu olmali."""
        import angr  # type: ignore

        errors: list[str] = []
        functions: list[DecompiledFunction] = []
        call_graph: dict[str, list[str]] = {}

        try:
            proj = angr.Project(str(binary), auto_load_libs=False)
        except Exception as exc:
            errors.append(f"FAIL: angr.Project load: {exc}")
            return functions, call_graph, errors

        try:
            cfg = proj.analyses.CFGFast()
        except Exception as exc:
            errors.append(f"FAIL: CFGFast: {exc}")
            return functions, call_graph, errors

        for func_addr, func in cfg.kb.functions.items():
            addr_hex = hex(func_addr)
            try:
                calls = self._get_call_addrs(func)
            except Exception as exc:
                errors.append(f"WARN: calls({func.name}): {exc}")
                calls = []

            pseudocode = self._decompile_single(proj, func, errors)

            functions.append(
                DecompiledFunction(
                    address=addr_hex,
                    name=str(func.name),
                    pseudocode=pseudocode,
                    calls=list(calls),
                    backend_specific={
                        "is_plt": getattr(func, "is_plt", False),
                        "is_simprocedure": getattr(func, "is_simprocedure", False),
                        "size": getattr(func, "size", None),
                    },
                )
            )
            call_graph[addr_hex] = list(calls)

        return functions, call_graph, errors

    @staticmethod
    def _get_call_addrs(func: Any) -> list[str]:
        """Fonksiyonun cagirdigi adresleri al (hex)."""
        call_sites = []
        try:
            for site in func.get_call_sites():
                # angr API: func.get_call_target(site) hedefi doner
                try:
                    target = func.get_call_target(site)
                    if target is not None:
                        call_sites.append(hex(target))
                except Exception:
                    # Indirect call — hedef bilinmiyor
                    call_sites.append(hex(site))
        except Exception:
            pass
        return call_sites

    @staticmethod
    def _decompile_single(proj: Any, func: Any, errors: list[str]) -> str:
        """Tek fonksiyonu decompile et (best-effort)."""
        if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
            return ""
        try:
            dec = proj.analyses.Decompiler(func)
            if dec.codegen is not None:
                return str(dec.codegen.text)
            return ""
        except Exception as exc:
            errors.append(f"WARN: decompile({func.name}): {exc}")
            return f"// angr decompile failed: {exc}"

    @staticmethod
    def _extract_strings(binary: Path) -> list[dict]:
        """Strings extraction — angr loader.main_object.strings pahali olabilir.

        Best-effort: kurulu degilse bos liste doner.
        """
        try:
            import angr  # type: ignore

            proj = angr.Project(str(binary), auto_load_libs=False)
            out: list[dict] = []
            raw_strings = getattr(proj.loader.main_object, "strings", None)
            if not raw_strings:
                return out
            for s in raw_strings:
                out.append({
                    "addr": hex(getattr(s, "addr", 0)),
                    "value": getattr(s, "value", ""),
                    "encoding": "ascii",
                })
            return out
        except Exception as exc:
            logger.debug("angr string extraction basarisiz: %s", exc)
            return []
