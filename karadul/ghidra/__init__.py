"""Ghidra integration -- headless analysis, project management, scripts."""

from karadul.ghidra.headless import GhidraHeadless
from karadul.ghidra.project import GhidraProject

__all__ = [
    "GhidraHeadless",
    "GhidraProject",
    "BSimDatabase",
    "GhidraProgramDiff",
    "DebuggerBridge",
]


def __getattr__(name: str):
    """Lazy import: agir moduller sadece gerektiginde yuklenir."""
    if name == "BSimDatabase":
        from karadul.ghidra.bsim import BSimDatabase
        return BSimDatabase
    if name == "GhidraProgramDiff":
        from karadul.ghidra.program_diff import GhidraProgramDiff
        return GhidraProgramDiff
    if name == "DebuggerBridge":
        from karadul.ghidra.debugger_bridge import DebuggerBridge
        return DebuggerBridge
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
