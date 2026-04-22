"""Hesaplama bazli (LLM'siz) kurtarma paketi — v1.4.0.alpha.

Blackhat-film esinli felsefe: binary'nin kendinden gelen HESAPLANABILIR
ipuclarindan (SSA, bellek erisim pattern'leri, CFG topolojisi) struct
layout ve tip bilgisini kurtar. LLM'e ihtiyac yok.

Alt paketler:
    - struct_recovery: Z3-MaxSMT struct layout solver.
    - (ileride) cfg_iso: CFG isomorphism matching.
    - (ileride) signature_fusion: Dempster-Shafer tabanli kanit birlestirme.

CPU-ONLY — GPU hype YOK. Z3 tek cekirdekte ms-dusuk saniye araliginda
tipik problemleri cozer.
"""

from __future__ import annotations

from karadul.computation.config import ComputationConfig

__all__ = ["ComputationConfig"]
