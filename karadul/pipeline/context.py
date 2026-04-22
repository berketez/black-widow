"""StepContext — step'ler arasi artifact/stats/error tasiyicisi.

PipelineContext'e proxy (target/workspace/config/metadata).
artifacts dict'i immutable view olarak sunulur (runner disinda yazim yasak).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from karadul.core.pipeline import PipelineContext


@dataclass
class StepContext:
    """Step'lerin ortak paylastigi baglam.

    Attributes:
        pipeline_context: Mevcut PipelineContext (target/workspace/config).
        stats: Birikimli istatistikler (her step kendi key'lerini ekler).
        errors: Birikimli hatalar.

    Note:
        artifacts runner tarafindan yazilir. Step'ler `run()` return'unde
        yeni artifact'lari dict olarak verir; runner bunlari merge eder.
    """

    pipeline_context: PipelineContext
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    _artifacts: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def artifacts(self) -> Mapping[str, Any]:
        """Read-only artifact view.

        Step'ler artifact'lari okurken bu property'yi kullanir.
        Yazma girisimi TypeError firlatir.
        """
        return MappingProxyType(self._artifacts)

    def _write_artifacts(self, new_artifacts: dict[str, Any]) -> None:
        """Sadece runner tarafindan cagrilmasi gerekir (private).

        Kural: bir key zaten varsa ustune yazar (downstream override'a
        izin ver ama loglansin — M2'de ekle).
        """
        self._artifacts.update(new_artifacts)
