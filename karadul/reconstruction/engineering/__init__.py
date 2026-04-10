"""Karadul Engineering Algorithm Analyzer -- multi-domain algorithm detection.

Decompile edilmis C kodunda muhendislik, finans, ML, DSP algoritmalarini
tespit eder. Mevcut kripto dedektorunu (CAlgorithmIdentifier) tamamlar.

Kullanim:
    from karadul.reconstruction.engineering import EngineeringAlgorithmAnalyzer

    analyzer = EngineeringAlgorithmAnalyzer()
    result = analyzer.identify(decompiled_dir, functions_json)
"""

from karadul.reconstruction.engineering.analyzer import EngineeringAlgorithmAnalyzer
from karadul.reconstruction.engineering.domain_classifier import (
    DomainClassifier,
    DomainClassification,
    DomainReport,
)
from karadul.reconstruction.engineering.formula_reconstructor import (
    FormulaReconstructor,
    FormulaInfo,
)
from karadul.reconstruction.engineering.struct_recovery import (
    StructRecoveryEngine,
    StructRecoveryResult,
    EnrichedStruct,
    EnrichedField,
)
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
)
from karadul.reconstruction.engineering.block_annotator import (
    CodeBlockAnnotator,
    AnnotationResult,
)
from karadul.reconstruction.engineering.confidence_calibrator import (
    ConfidenceCalibrator,
    CalibratedMatch,
)
from karadul.reconstruction.engineering.data_flow import (
    InterProceduralDataFlow,
    DataFlowEdge,
    DataFlowGraph,
    DataFlowResult,
    PropagatedParamName,
)
from karadul.reconstruction.engineering.dispatch_resolver import (
    VirtualDispatchResolver,
    DispatchResolverConfig,
    DispatchSite,
    DispatchResolutionResult,
    MethodImpl,
)
from karadul.reconstruction.engineering.composition_analyzer import (
    AlgorithmCompositionAnalyzer,
    AlgorithmComposition,
    CompositionStage,
    CompositionResult,
)
from karadul.reconstruction.engineering.deep_tracer import (
    DeepCallChainTracer,
    TraceNode,
    TraceResult,
)

__all__ = [
    "EngineeringAlgorithmAnalyzer",
    "DomainClassifier",
    "DomainClassification",
    "DomainReport",
    "FormulaReconstructor",
    "FormulaInfo",
    "StructRecoveryEngine",
    "StructRecoveryResult",
    "EnrichedStruct",
    "EnrichedField",
    "SemanticParameterNamer",
    "CodeBlockAnnotator",
    "AnnotationResult",
    "ConfidenceCalibrator",
    "CalibratedMatch",
    "InterProceduralDataFlow",
    "DataFlowEdge",
    "DataFlowGraph",
    "DataFlowResult",
    "PropagatedParamName",
    "VirtualDispatchResolver",
    "DispatchResolverConfig",
    "DispatchSite",
    "DispatchResolutionResult",
    "MethodImpl",
    "AlgorithmCompositionAnalyzer",
    "AlgorithmComposition",
    "CompositionStage",
    "CompositionResult",
    "DeepCallChainTracer",
    "TraceNode",
    "TraceResult",
]
