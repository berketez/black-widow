"""StepContext — step'ler arasi artifact/stats/error tasiyicisi.

PipelineContext'e proxy (target/workspace/config/metadata).
artifacts dict'i immutable view olarak sunulur (runner disinda yazim yasak).
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from karadul.core.pipeline import PipelineContext

logger = logging.getLogger(__name__)


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

        `produce_artifact(key, value)` ise "stage-level" side artifact'lari
        (JSON yol, rapor dosyasi vb.) StageResult'a yayar. Pipeline
        artifact'lariyla karismaz — ayri bir kanaldir.
    """

    pipeline_context: PipelineContext
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    _artifacts: dict[str, Any] = field(default_factory=dict, repr=False)
    # v1.11.0 Phase 1C: produce_artifact() ile yazilan side artifact'lar.
    # Finalize step sonunda StageResult.artifacts'a kopyalanir.
    _stage_artifacts: dict[str, Any] = field(default_factory=dict, repr=False)
    # Mevcut step'in spec'i (runner enjekte eder). produce_artifact icin
    # opsiyonel registry validation; None ise sessizce gec.
    _current_step_meta: Any = field(default=None, repr=False)

    @property
    def artifacts(self) -> Mapping[str, Any]:
        """Read-only artifact view.

        Step'ler artifact'lari okurken bu property'yi kullanir.
        Yazma girisimi TypeError firlatir.
        """
        return MappingProxyType(self._artifacts)

    @property
    def stage_artifacts(self) -> Mapping[str, Any]:
        """StageResult'a gidecek side artifact'larin read-only view'i."""
        return MappingProxyType(self._stage_artifacts)

    def produce_artifact(self, key: str, value: Any) -> None:
        """Step ciktisini StageResult.artifacts'a yayar.

        Bu metod, eski `pc.metadata["artifacts_pending"][key] = value`
        pattern'ini degistirir. Avantajlar:
            - Step izolasyonu: shared metadata dict'e dokunulmuyor.
            - Overwrite detection: ayni key iki kez yazilirsa uyari loglanir.
            - Registry validation: step_meta varsa ve `produces` listesinde
              degilse uyari (hata degil — geriye uyumluluk icin soft check).

        Args:
            key: Artifact ismi (StageResult.artifacts key'i).
            value: Artifact degeri (genellikle Path veya dict).

        Note:
            Geriye uyumluluk icin `pc.metadata["artifacts_pending"]` icine
            de yazilir (stages.py shim'i ve finalize.py eski yol hala okuyor).
            v1.12.0'da bu mirror davranis kaldirilacak.
        """
        # Registry validation (soft): step_meta.produces listesinde yoksa warn.
        # Not: produces contract pipeline artifact'lari icin; stage artifact'lar
        # tipik olarak burada degil — bu yuzden sadece uyari, hata degil.
        step_meta = self._current_step_meta
        if step_meta is not None and hasattr(step_meta, "produces"):
            produces = step_meta.produces or ()
            if key not in produces and key not in self._stage_artifacts:
                # Sessizce ilerle — produce_artifact stage-level artifact'lar
                # icin; produces tipik olarak pipeline artifact'lari icerir.
                logger.debug(
                    "produce_artifact: %r, step %r'nin produces listesinde "
                    "yok (stage-level artifact varsayiliyor)",
                    key, getattr(step_meta, "name", "?"),
                )

        # Overwrite check
        if key in self._stage_artifacts:
            logger.warning(
                "produce_artifact: %r zaten yazilmis, uzerine yaziliyor", key,
            )

        self._stage_artifacts[key] = value

        # Geriye uyumluluk mirror'i: stages.py shim'i ve finalize.py eski
        # yol pc.metadata["artifacts_pending"]'i okuyor. v1.12.0'da kalkacak.
        pc = self.pipeline_context
        if getattr(pc, "metadata", None) is None:
            pc.metadata = {}
        pc.metadata.setdefault("artifacts_pending", {})[key] = value

    def _write_artifacts(self, new_artifacts: dict[str, Any]) -> None:
        """Sadece runner tarafindan cagrilmasi gerekir (private).

        Kural: bir key zaten varsa ustune yazar (downstream override'a
        izin ver ama loglansin — M2'de ekle).
        """
        self._artifacts.update(new_artifacts)


def _warn_legacy_artifacts_pending(caller_hint: str = "") -> None:
    """`pc.metadata['artifacts_pending']` dogrudan kullanimi icin uyari.

    Migration'da yardim icin: v1.11.0 Phase 1C'de produce_artifact API'si
    geldi; eski pattern'i cagiran kodlar icin DeprecationWarning.
    """
    warnings.warn(
        f"pc.metadata['artifacts_pending'] DEPRECATED "
        f"({caller_hint or 'dogrudan erisim'}); "
        f"StepContext.produce_artifact(key, value) kullanin. "
        f"v1.12.0'da kaldirilacak.",
        DeprecationWarning,
        stacklevel=3,
    )
