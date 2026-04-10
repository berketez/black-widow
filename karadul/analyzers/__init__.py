"""
Analyzer registry — hedef turune gore analyzer eslestirme.

Kullanim:
    @register_analyzer(TargetType.JS_BUNDLE)
    class JSAnalyzer:
        ...

    analyzer_cls = get_analyzer(TargetType.JS_BUNDLE)
"""

from __future__ import annotations

from typing import Any

from karadul.core.target import TargetType

_ANALYZERS: dict[TargetType, type] = {}


def register_analyzer(target_type: TargetType):
    """Bir analyzer class'ini belirli bir TargetType'a kaydet."""
    def decorator(cls: type) -> type:
        _ANALYZERS[target_type] = cls
        return cls
    return decorator


def get_analyzer(target_type: TargetType) -> type:
    """TargetType icin kayitli analyzer class'ini dondur."""
    analyzer_cls = _ANALYZERS.get(target_type)
    if analyzer_cls is None:
        raise ValueError(f"No analyzer registered for {target_type}")
    return analyzer_cls


def list_analyzers() -> dict[TargetType, type]:
    """Kayitli tum analyzer'lari dondur."""
    return dict(_ANALYZERS)


# Analyzer modüllerini import et — @register_analyzer decorator'ları çalışsın
from karadul.analyzers import javascript  # noqa: F401, E402
from karadul.analyzers import electron  # noqa: F401, E402
from karadul.analyzers import macho  # noqa: F401, E402
from karadul.analyzers import go_binary  # noqa: F401, E402
from karadul.analyzers import swift_binary  # noqa: F401, E402
from karadul.analyzers import java_binary  # noqa: F401, E402
from karadul.analyzers import dotnet_binary  # noqa: F401, E402
from karadul.analyzers import rust_binary  # noqa: F401, E402
from karadul.analyzers import delphi_binary  # noqa: F401, E402
from karadul.analyzers import app_bundle  # noqa: F401, E402
try:
    from karadul.analyzers import python_binary  # noqa: F401, E402
except ImportError:
    pass  # python_binary.py henuz eklenmemis olabilir

# v1.9.0: DWARF debug info extractor (analyzer degil, utility)
from karadul.analyzers.dwarf_extractor import (  # noqa: F401, E402
    DwarfExtractor,
    DwarfFunction,
    DwarfVariable,
)
