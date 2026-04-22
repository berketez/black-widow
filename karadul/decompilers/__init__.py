"""v1.10.0 M2 T10 — Decompiler backend abstraction paketi.

Kullanim:
    from karadul.decompilers import create_backend

    backend = create_backend(config)
    if backend.is_available():
        result = backend.decompile(binary_path, output_dir)
        for func in result.functions:
            print(func.name, func.address)

Backend'ler:
    - ghidra (varsayilan) -- karadul.ghidra.headless.GhidraHeadless sarmalar.
    - angr (opsiyonel)    -- pip install 'karadul[decompilers]' gereklidir.
"""

from karadul.decompilers.angr_backend import AngrBackend
from karadul.decompilers.base import (
    DecompiledFunction,
    DecompileResult,
    DecompilerBackend,
)
from karadul.decompilers.factory import (
    available_backends,
    create_backend,
    create_backend_with_fallback,
)
from karadul.decompilers.ghidra_backend import GhidraBackend

__all__ = [
    "DecompiledFunction",
    "DecompileResult",
    "DecompilerBackend",
    "GhidraBackend",
    "AngrBackend",
    "create_backend",
    "create_backend_with_fallback",
    "available_backends",
]
