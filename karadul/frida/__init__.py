"""Frida dynamic instrumentation modules.

Provides:
- FridaSession: Attach/spawn/script management
- FunctionTracer: Call sequence analysis from Frida messages
- MemoryScanner: Process memory scanning via Frida
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .session import FridaSession
    from .collectors.function_tracer import FunctionTracer
    from .collectors.memory_scanner import MemoryScanner

__all__ = ["FridaSession", "FunctionTracer", "MemoryScanner"]
