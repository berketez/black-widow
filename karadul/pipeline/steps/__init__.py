"""Step tanimlamalari — bu paket import edilince decorator'lar registry'e kayit olur.

Import sirasi onemli degil (registry global), ama okunurlugu icin
orijinal pipeline'in calistigi sirada listelendi.
"""

from __future__ import annotations

# Her modul kendi @register_step dekorator'unu calistirarak _REGISTRY'ye
# eklenir. F401 (import edilmis ama kullanilmiyor) kasitli — yan etki icin.
from karadul.pipeline.steps import (  # noqa: F401
    binary_prep,
    ghidra_metadata,
    byte_pattern,
    pcode_cfg_analysis,
    algorithm_id,
    parallel_algo_eng,
    confidence_filter,
    assembly_analysis,
    feedback_loop,
    struct_recovery,
    inline_detection,
    semantic_naming,
    flow_simplify,
    comment_generation,
    capa_annotation,
    engineering_annotation,
    project_build,
    engineering_analysis,
    deep_tracing,
    finalize,
    # v1.10.0 M4 entegrasyon: computation paketleri
    cfg_iso_match,
    computation_struct_recovery,
    computation_fusion,
)

__all__ = [
    "algorithm_id",
    "assembly_analysis",
    "binary_prep",
    "byte_pattern",
    "capa_annotation",
    "cfg_iso_match",
    "comment_generation",
    "computation_fusion",
    "computation_struct_recovery",
    "confidence_filter",
    "deep_tracing",
    "engineering_analysis",
    "engineering_annotation",
    "feedback_loop",
    "finalize",
    "flow_simplify",
    "ghidra_metadata",
    "inline_detection",
    "parallel_algo_eng",
    "pcode_cfg_analysis",
    "project_build",
    "semantic_naming",
    "struct_recovery",
]
