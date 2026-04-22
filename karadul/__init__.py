"""Karadul (Black Widow): Reverse Engineering Suite -- Public API.

Inspired by NSA's forensic reconstruction tool from Blackhat (2015).
Educational/Research use only. No redistribution.
"""

from __future__ import annotations

# NOTE: __version__ BIR sinif/fonksiyon importundan ONCE tanimlanmali.
# `karadul.core.report_generator` gibi alt moduller `from karadul import
# __version__` yaptiginda kismen-yuklenmis-modul hatasi almayalim diye.
__version__ = "1.10.0"
__codename__ = "Karadul"

from pathlib import Path  # noqa: E402
from typing import TYPE_CHECKING, Union  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.core.pipeline import Pipeline  # noqa: E402

if TYPE_CHECKING:
    from karadul.core.result import PipelineResult


def analyze(
    binary_path: Union[str, Path],
    *,
    config: Union[Config, None] = None,
    stages: Union[list[str], None] = None,
) -> "PipelineResult":
    """Binary'yi analiz et, sonucu dondur.

    Public API entry point. Minimal boilerplate ile tek cagride
    tum pipeline calistirilir (target detection + tum stage'ler).

    Args:
        binary_path: Analiz edilecek binary yolu.
        config: Istege bagli Config; None ise Config.load() default.
        stages: Istege bagli stage alt kumesi (None = hepsi).

    Returns:
        PipelineResult -- success, errors, artifacts, stage ciktilari.

    Raises:
        FileNotFoundError: binary_path yoksa.
        karadul.exceptions.KaradulError: Analiz tamamen basarisizsa.

    Ornek:
        >>> import karadul
        >>> result = karadul.analyze("/bin/ls")
        >>> print(result.success)
    """
    path = Path(binary_path)
    if not path.is_file():
        raise FileNotFoundError(f"Binary bulunamadi: {path}")

    cfg = config if config is not None else Config.load()
    pipeline = Pipeline(cfg)
    return pipeline.run(path, stages=stages)


__all__ = [
    "analyze",
    "Pipeline",
    "Config",
    "__version__",
    "__codename__",
]
