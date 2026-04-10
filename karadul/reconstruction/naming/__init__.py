"""4 Katmanli Hybrid Naming Pipeline -- deobfuscate edilmis webpack modullerini isimlendirir.

Katmanlar:
1. NpmFingerprinter  -- bilinen npm paketlerini string imzalariyla eslestirir
2. StructuralAnalyzer -- export/class/function isimlerini cikarir
3. LLMNamer          -- Codex CLI veya heuristic ile kalan modulleri isimlendirir
4. Conflict Resolution -- dosya adi cakismalarini cozer

Kullanim:
    from karadul.reconstruction.naming import NamingPipeline
    pipeline = NamingPipeline()
    manifest = pipeline.run(modules_dir)
    pipeline.apply(modules_dir, output_dir, manifest)
"""

from .llm_namer import LLMNamer
from .llm_naming import ClaudeLLMNamer, LLMNamingResult
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
    "LLMNamer",
    "ClaudeLLMNamer",
    "LLMNamingResult",
]
