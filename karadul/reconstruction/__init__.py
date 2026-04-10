"""Source reconstruction modules -- deobfuscate edilmis kodu calistiriilabilir projeye donustur.

Moduller:
- VariableRenamer: Tek harfli degiskenleri anlamli isimlere donusturur
- ModuleSplitter: Webpack modullerini mantiksal dosyalara ayirir
- TypeInferrer: JSDoc tip yorumlari ekler
- CommentGenerator: Fonksiyon basina yorum ekler
- GapFiller: Statik + dinamik analiz sonuclarini birlestirir
- ProjectBuilder: Calistiriilabilir proje urtur (package.json, README, Dockerfile)
- DependencyResolver: Gercek npm paket bagimlilikdarini tespit eder
- ProjectReconstructor: Tam proje reconstruction (modulleri gercek dosya yapisina donustur)
- NamingPipeline: 5 katmanli hybrid modul isimlendirme (npm fingerprint, source match, structural, llm)
- SourceMatcher: Minified fonksiyonlari orijinal kaynakla eslestirip isim recovery
- InlineExtractor: Inline Anthropic kodunu anchor pattern'lerle cikar
- CTypeRecoverer: Ghidra C ciktisindaki generic tipleri gercek struct/enum/vtable'a donustur
- CAlgorithmIdentifier: Decompile edilmis C kodunda sabit+yapi+API bazli algoritma tespiti
- CCommentGenerator: Ghidra decompile ciktisina akilli yorumlar ekler
- StringIntelligence: Binary string'lerden assert/error/protocol/telemetry bazli isim cikarimi
"""

from karadul.reconstruction.comment_generator import CommentGenerator
from karadul.reconstruction.dependency_resolver import DependencyResolver
from karadul.reconstruction.gap_filler import GapFillResult, GapFiller
from karadul.reconstruction.module_splitter import ModuleSplitter, SplitResult
from karadul.reconstruction.naming import (
    ClaudeLLMNamer,
    LLMNamingResult,
    NamingManifest,
    NamingPipeline,
    NamingResult,
)
from karadul.reconstruction.project_builder import (
    BuildResult,
    ProjectBuilder,
    NODE_BUILTINS,
)
from karadul.reconstruction.project_reconstructor import (
    ProjectReconstructor,
    ReconstructionResult,
)
from karadul.reconstruction.type_inferrer import InferResult, TypeInferrer
from karadul.reconstruction.inline_extractor import InlineExtractionResult, InlineExtractor
from karadul.reconstruction.c_namer import CNamingResult, CVariableNamer
from karadul.reconstruction.context_namer import ContextNamer, NamingResult as ContextNamingResult
from karadul.reconstruction.param_recovery import ParamRecovery, ParamRecoveryResult
from karadul.reconstruction.c_type_recoverer import (
    CTypeRecoverer,
    CTypeRecoveryResult,
    RecoveredEnum,
    RecoveredStruct,
    RecoveredVTable,
    StructField,
)
from karadul.reconstruction.c_algorithm_id import (
    AlgorithmMatch,
    CAlgorithmIdentifier,
    CAlgorithmResult,
)
from karadul.reconstruction.c_comment_generator import CCommentGenerator, CCommentResult
from karadul.reconstruction.string_intelligence import StringIntelligence, StringIntelResult
from karadul.reconstruction.fortran_param_db import (
    FortranParamDB,
    FortranSourceEntry,
    FortranSourceParser,
    InStackMapping,
    InStackReconstructor,
    InStackResult,
)
from karadul.reconstruction.reference_differ import (
    Detection,
    FunctionMatch,
    ReferenceDB,
    ReferenceDiffer,
    ReferenceMatchResult,
    VersionDetector,
)
from karadul.reconstruction.variable_renamer import RenameResult, VariableRenamer
from karadul.reconstruction.xtride_typer import (
    TypeInference,
    XTrideResult,
    XTrideTyper,
)
from karadul.reconstruction.ngram_namer import (
    NgramNamer,
    NgramNamerResult,
    NgramPrediction,
)
from karadul.reconstruction.dynamic_namer import (
    DynamicNamer,
    DynamicNameSuggestion,
)
from karadul.reconstruction.source_matcher import (
    ASTFingerprinter,
    FunctionFingerprint,
    ResolvedSource,
    SourceResolver,
)

__all__ = [
    "CNamingResult",
    "CVariableNamer",
    "ContextNamer",
    "ContextNamingResult",
    "VariableRenamer",
    "RenameResult",
    "ModuleSplitter",
    "SplitResult",
    "TypeInferrer",
    "InferResult",
    "CommentGenerator",
    "GapFiller",
    "GapFillResult",
    "ProjectBuilder",
    "BuildResult",
    "NODE_BUILTINS",
    "DependencyResolver",
    "ProjectReconstructor",
    "ReconstructionResult",
    "NamingPipeline",
    "NamingManifest",
    "NamingResult",
    "ParamRecovery",
    "ParamRecoveryResult",
    "ClaudeLLMNamer",
    "LLMNamingResult",
    "InlineExtractor",
    "InlineExtractionResult",
    "ASTFingerprinter",
    "FunctionFingerprint",
    "ResolvedSource",
    "SourceResolver",
    "CTypeRecoverer",
    "CTypeRecoveryResult",
    "RecoveredStruct",
    "RecoveredEnum",
    "RecoveredVTable",
    "StructField",
    "AlgorithmMatch",
    "CAlgorithmIdentifier",
    "CAlgorithmResult",
    "CCommentGenerator",
    "CCommentResult",
    "StringIntelligence",
    "StringIntelResult",
    "FortranParamDB",
    "FortranSourceEntry",
    "FortranSourceParser",
    "InStackMapping",
    "InStackReconstructor",
    "InStackResult",
    "Detection",
    "FunctionMatch",
    "ReferenceDB",
    "ReferenceDiffer",
    "ReferenceMatchResult",
    "VersionDetector",
    "TypeInference",
    "XTrideResult",
    "XTrideTyper",
    "NgramNamer",
    "NgramNamerResult",
    "NgramPrediction",
    "DynamicNamer",
    "DynamicNameSuggestion",
]
