"""3 Katmanli Hybrid Naming Pipeline -- deobfuscate edilmis webpack modullerini isimlendirir.

Katmanlar:
1. NpmFingerprinter  -- bilinen npm paketlerini string imzalariyla eslestirir
2. StructuralAnalyzer -- export/class/function isimlerini cikarir
3. Conflict Resolution -- dosya adi cakismalarini cozer

NOT (2026-05-13): LLMNamer/ClaudeLLMNamer kaldirildi (B11, feedback_no_llm.md).

Kullanim:
    from karadul.reconstruction.naming import NamingPipeline
    pipeline = NamingPipeline()
    manifest = pipeline.run(modules_dir)
    pipeline.apply(modules_dir, output_dir, manifest)
"""

from .npm_fingerprinter import NpmFingerprinter
from .pipeline import NamingPipeline
from .result import NamingManifest, NamingResult
from .structural_analyzer import StructuralAnalyzer

__all__ = [
    "NamingPipeline",
    "NamingManifest",
    "NamingResult",
    "NpmFingerprinter",
    "StructuralAnalyzer",
]
