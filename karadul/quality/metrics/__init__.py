"""Readability skorlama metric'leri.

Her metric modulu 0-100 arasinda float skor ve detay bilgisi dondurur.
"""

from __future__ import annotations

from karadul.quality.metrics.code_structure import CodeStructureMetric
from karadul.quality.metrics.comments import CommentsMetric
from karadul.quality.metrics.function_names import FunctionNamesMetric
from karadul.quality.metrics.local_vars import LocalVarsMetric
from karadul.quality.metrics.param_names import ParamNamesMetric
from karadul.quality.metrics.type_quality import TypeQualityMetric

__all__ = [
    "FunctionNamesMetric",
    "ParamNamesMetric",
    "LocalVarsMetric",
    "TypeQualityMetric",
    "CommentsMetric",
    "CodeStructureMetric",
]
