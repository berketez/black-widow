"""PipelineRunner — topological sort + sequential execution.

M1: sadece sequential. Paralelizasyon M2'de eklenecek.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.core.pipeline import PipelineContext
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import StepSpec, get_step

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Step listesini requires/produces grafina gore siralar ve calistirir.

    Hata modu:
        - Missing requires → RuntimeError (calistirmadan once)
        - Produces disinda artifact → RuntimeError (step sonrasi)
        - Step exception → hata StepContext.errors'a eklenir, devam
          edilmez (fail-fast, sonrakileri iptal).
    """

    def __init__(self, steps: list[str]) -> None:
        if not steps:
            raise ValueError("steps bos olamaz")
        self._step_names = list(steps)
        self._specs: list[StepSpec] = [get_step(n) for n in self._step_names]

    # --- public API ----------------------------------------------------

    def run(
        self,
        pipeline_context: PipelineContext,
        seed_artifacts: dict[str, Any] | None = None,
    ) -> StepContext:
        """Tum step'leri sirayla calistir. Immutable artifact view dondur.

        Args:
            pipeline_context: Paylasilan PipelineContext.
            seed_artifacts: Step'ler icin on-yuklenmis artifact'lar. T3.5
                shim'inde feedback_loop gibi henuz step'e donusmemis eski
                kod bloklarinin ciktilarini post-feedback step'lere beslemek
                icin kullanilir. Requires kontrolunde "mevcut" sayilir.

        Not:
            seed_artifacts key'i pipeline_context.metadata key'iyle cakisirsa
            seed_artifacts kazanir (runtime'da verilen veri, kalici
            metadata'dan guncel).
        """
        ordered = self._topological_sort(self._specs)
        ctx = StepContext(pipeline_context=pipeline_context)

        # pipeline_context.metadata'dan gelen onceki artifact'lari import et.
        # Boylece shim modunda eski yoldan gelen veriler de kullanilabilir.
        if pipeline_context.metadata:
            ctx._write_artifacts(dict(pipeline_context.metadata))

        # seed_artifacts — T3.5 shim koprusu. Metadata'dan sonra yazilir ki
        # runtime injection metadata'yi override edebilsin.
        if seed_artifacts:
            ctx._write_artifacts(dict(seed_artifacts))

        produced_so_far: set[str] = set(ctx.artifacts.keys())

        for spec in ordered:
            # requires kontrolu
            missing = [r for r in spec.requires if r not in produced_so_far]
            if missing:
                raise RuntimeError(
                    f"Step '{spec.name}' eksik girdi: {missing}. "
                    f"Mevcut artifact'lar: {sorted(produced_so_far)}",
                )

            step = spec.cls()
            t0 = time.monotonic()
            # v1.11.0 Phase 1C: produce_artifact() icin current step meta
            # enjekte et; step.run() bitince geri al (degismez baska step'e
            # sizmasin).
            ctx._current_step_meta = spec
            try:
                new_artifacts = step.run(ctx)
            except Exception as exc:
                ctx.errors.append(f"{spec.name}: {exc}")
                logger.exception("Step '%s' basarisiz", spec.name)
                raise
            finally:
                ctx._current_step_meta = None

            duration = time.monotonic() - t0
            ctx.stats[f"{spec.name}_duration_s"] = round(duration, 4)

            if not isinstance(new_artifacts, dict):
                raise RuntimeError(
                    f"Step '{spec.name}' dict dondurmeli, "
                    f"aldim: {type(new_artifacts).__name__}",
                )

            # produces disinda key varsa hata
            extra_keys = [k for k in new_artifacts if k not in spec.produces]
            if extra_keys:
                raise RuntimeError(
                    f"Step '{spec.name}' produces disinda artifact "
                    f"yazdi: {extra_keys}. Beklenen: {list(spec.produces)}",
                )

            ctx._write_artifacts(new_artifacts)
            produced_so_far.update(new_artifacts.keys())
            logger.info(
                "Step '%s' tamam (%.3fs, %d artifact)",
                spec.name, duration, len(new_artifacts),
            )

        return ctx

    # --- internals -----------------------------------------------------

    @staticmethod
    def _topological_sort(specs: list[StepSpec]) -> list[StepSpec]:
        """Kahn algoritmasi — requires/produces grafindan sirala.

        Bir step ya onceden var olan (pipeline_context'ten) ya da
        baska bir step'in produces'u tarafindan saglanan artifact'lara
        ihtiyac duyar.
        """
        name_to_spec = {s.name: s for s in specs}
        # Her step'in produces'unu uretici olarak isaretle.
        # v1.10.0 M14: ayni artifact'i iki step uretiyorsa SESSIZ DOGEME.
        # Eski kodda `setdefault` ikinci uretimi gormezden geliyor; bu,
        # downstream hangi uretimi kullanacagini belirsiz kiliyor.  Artik
        # aciktan hata veriyoruz ki konfigurasyon hatalari erken yakalansin.
        producer_of: dict[str, str] = {}
        for s in specs:
            for p in s.produces:
                if p in producer_of:
                    raise ValueError(
                        f"Artifact '{p}' iki step tarafindan produces "
                        f"ediliyor: '{producer_of[p]}' ve '{s.name}'. "
                        f"Her artifact'in tek bir ureticisi olmali.",
                    )
                producer_of[p] = s.name

        # Edge: A 'requires' R varsa ve R'yi producer_of[R] uretiyor
        # ve producer_of[R] listedeki BASKA bir step ise A o step'e bagli.
        in_degree: dict[str, int] = {s.name: 0 for s in specs}
        adj: dict[str, list[str]] = {s.name: [] for s in specs}

        for s in specs:
            for r in s.requires:
                producer = producer_of.get(r)
                if producer and producer in name_to_spec and producer != s.name:
                    adj[producer].append(s.name)
                    in_degree[s.name] += 1

        ordered: list[StepSpec] = []
        # Deterministik: in-degree 0 olanlari alfabetik sirada isle
        ready = sorted([n for n, d in in_degree.items() if d == 0])
        while ready:
            n = ready.pop(0)
            ordered.append(name_to_spec[n])
            for m in sorted(adj[n]):
                in_degree[m] -= 1
                if in_degree[m] == 0:
                    # Sirali ekle
                    import bisect
                    bisect.insort(ready, m)

        if len(ordered) != len(specs):
            # Cycle var
            remaining = [s.name for s in specs if s not in ordered]
            raise RuntimeError(
                f"Step grafinda cycle: {remaining}",
            )

        return ordered
