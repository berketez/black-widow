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
    bsim_match,
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
    # v1.13 Dalga 1: anti-debug + packer fingerprint
    anti_debug,
    packer_fingerprint,
    # v1.15 Dalga 1: TRex struct recovery (Ghidra IL bekler, graceful skip)
    trex_struct_recovery,
    # v1.15 Dalga 1: PDB symbol/type kurtarma (PE only, llvm-pdbutil)
    pdb_symbol_recovery,
)

__all__ = [
    "algorithm_id",
    "anti_debug",
    "assembly_analysis",
    "binary_prep",
    "bsim_match",
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
    "packer_fingerprint",
    "parallel_algo_eng",
    "pcode_cfg_analysis",
    "project_build",
    "pdb_symbol_recovery",
    "semantic_naming",
    "struct_recovery",
    "trex_struct_recovery",
]
