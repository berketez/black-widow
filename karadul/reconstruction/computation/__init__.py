"""Hesaplama bazli kurtarma (Computation Recovery) -- v1.4.0.

Decompile edilmis C kodunda hesaplama gucu ile yapisal analiz yaparak
struct layout'larini dogrular, bilinen algoritma CFG sablonlariyla eslestirir,
coklu sinyal kaynagini Dempster-Shafer ile birlestirip matematiksel formul cikarir.

4 Katman:
    1. ConstraintSolver  -- Z3/heuristic struct constraint + array detection
       + param type inference + return type inference + global detection
    2. CFGFingerprinter  -- CFG feature vector + template matching
    3. SignatureFusion   -- Dempster-Shafer evidence fusion + xref boost
       + string validation + callee-based inference
    4. FormulaExtractor  -- C code -> math formula (9 dedektor)

Kullanim:
    from karadul.reconstruction.computation import ComputationRecoveryEngine

    engine = ComputationRecoveryEngine(config)
    result = engine.recover(decompiled_dir, functions_json, ...)
"""

from karadul.reconstruction.computation.engine import (
    ComputationRecoveryEngine,
    ComputationRecoveryResult,
)
from karadul.reconstruction.computation.constraint_solver import (
    ConstraintSolver,
    ConstraintStruct,
    FieldConstraint,
    ArrayDetection,
    ConstraintSolverResult,
)
from karadul.reconstruction.computation.cfg_fingerprint import (
    CFGFingerprinter,
    CFGFingerprint,
    CFGTemplate,
    CFGMatch,
)
from karadul.reconstruction.computation.signature_fusion import (
    SignatureFusion,
    FusedIdentification,
    EvidenceMass,
    NamingCandidate,
)
from karadul.reconstruction.computation.callee_profile_propagator import (
    CalleeProfilePropagator,
    PropagatedName,
    PropagationResult,
)
from karadul.reconstruction.computation.formula_extractor import (
    FormulaExtractor,
    ExtractedFormula,
)

__all__ = [
    "ComputationRecoveryEngine",
    "ComputationRecoveryResult",
    "ConstraintSolver",
    "ConstraintStruct",
    "FieldConstraint",
    "ArrayDetection",
    "ConstraintSolverResult",
    "CFGFingerprinter",
    "CFGFingerprint",
    "CFGTemplate",
    "CFGMatch",
    "SignatureFusion",
    "FusedIdentification",
    "EvidenceMass",
    "NamingCandidate",
    "CalleeProfilePropagator",
    "PropagatedName",
    "PropagationResult",
    "FormulaExtractor",
    "ExtractedFormula",
]
