"""Source matcher -- npm paketlerinin orijinal kodunu bulup fonksiyon fingerprint'leriyle karsilastir.

Alt moduller:
- SourceResolver: unpkg.com'dan orijinal kaynak kod ceker (diske yazmaz)
- ASTFingerprinter: JS fonksiyonlarini regex tabanli fingerprint'le
- FunctionFingerprint: Yapisal parmak izi dataclass + similarity hesaplama
- StructuralMatcher: Fingerprint tabanli greedy fonksiyon eslestirme
- NameMapper: Eslesmelerden degisken/fonksiyon isim haritasi olusturma
- SourceMatchingPipeline: End-to-end orchestrator

LLM YOK -- tamamen deterministik, bedava.

Kullanim:
    from karadul.reconstruction.source_matcher import (
        SourceResolver,
        ASTFingerprinter,
        FunctionFingerprint,
        StructuralMatcher,
    )
"""

from karadul.reconstruction.source_matcher.ast_fingerprinter import (
    ASTFingerprinter,
    FunctionFingerprint,
)
from karadul.reconstruction.source_matcher.source_resolver import (
    ResolvedSource,
    SourceResolver,
)
from karadul.reconstruction.source_matcher.structural_matcher import (
    FunctionMatch,
    ModuleMatchResult,
    StructuralMatcher,
)
from karadul.reconstruction.source_matcher.name_mapper import NameMapper
from karadul.reconstruction.source_matcher.applier import SourceMatchApplier

# pipeline.py henuz yazilmamis olabilir -- import hatasini yut
try:
    from karadul.reconstruction.source_matcher.pipeline import (
        SourceMatchingPipeline,
        SourceMatchResult,
    )
except ImportError:
    SourceMatchingPipeline = None  # type: ignore[assignment,misc]
    SourceMatchResult = None  # type: ignore[assignment,misc]

__all__ = [
    "ASTFingerprinter",
    "FunctionFingerprint",
    "ResolvedSource",
    "SourceResolver",
    "StructuralMatcher",
    "FunctionMatch",
    "ModuleMatchResult",
    "NameMapper",
    "SourceMatchApplier",
    "SourceMatchingPipeline",
    "SourceMatchResult",
]
