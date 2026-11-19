"""Deobfuscator modules.

Bilesenler:
1. SynchronyWrapper: synchrony CLI wrapper
2. DeobfuscationManager: eski zincir orkestrasyonu (synchrony -> webpack_unpack /
   deep_pipeline; ``beautify`` ve ``babel_transforms`` adımları P20b'de silindi,
   BabelPipeline modülüyle birlikte)
3. DeepDeobfuscationPipeline: Gelismis 9-phase deobfuscation + akilli modul cikarma
"""

from .deep_pipeline import DeepDeobfuscationPipeline, DeepDeobfuscationResult
from .manager import DeobfuscationManager, DeobfuscationResult
from .synchrony_wrapper import SynchronyWrapper

__all__ = [
    "SynchronyWrapper",
    "DeobfuscationManager",
    "DeobfuscationResult",
    "DeepDeobfuscationPipeline",
    "DeepDeobfuscationResult",
]
