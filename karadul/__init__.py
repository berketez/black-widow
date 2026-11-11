"""Karadul (Black Widow): Reverse Engineering Suite -- Public API.

Inspired by NSA's forensic reconstruction tool from Blackhat (2015).
Educational/Research use only. No redistribution.
"""

from __future__ import annotations

# NOTE: __version__ BIR sinif/fonksiyon importundan ONCE tanimlanmali.
# `karadul.core.report_generator` gibi alt moduller `from karadul import
# __version__` yaptiginda kismen-yuklenmis-modul hatasi almayalim diye.
__version__ = "1.21.2"
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

    Aşamalar CLI'ın (`karadul analyze`) kullandığı kurucuyla,
    `karadul.cli_common.build_pipeline` ile kaydedilir; varsayılan sıra
    `karadul.cli_common.DEFAULT_STAGE_ORDER`'dır. Dinamik aşama kayıtlıdır
    ama `config.security.allow_target_execution` açılmadıkça hedefi
    çalıştırmaz (atlanır).

    Args:
        binary_path: Analiz edilecek binary yolu.
        config: Istege bagli Config; None ise Config.load() default.
        stages: Istege bagli stage alt kumesi (None = hepsi).

    Returns:
        PipelineResult -- success, stages (aşama adı -> StageResult),
        workspace_path, total_duration; artefaktlar için
        `result.get_all_artifacts()`.

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
    # Aşamalar CLI ile aynı kurucudan gelir. Çıplak `Pipeline(cfg)` hiçbir
    # aşama kaydetmez; `run` hedef tespitinden sonra aşama sonucu olmadan döner.
    # İçe aktarma burada: `import karadul` aşama modüllerini yüklemesin.
    from karadul.cli_common import build_pipeline

    pipeline = build_pipeline(cfg)
    return pipeline.run(path, stages=stages)


__all__ = [
    "analyze",
    "Pipeline",
    "Config",
    "__version__",
    "__codename__",
]
