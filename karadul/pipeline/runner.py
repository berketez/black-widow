"""PipelineRunner — topological sort + (M2) paralel level scheduling.

M1: sequential for-loop.
M2 (v1.15-B16): topological order'i level'lara ayir, ayni level'daki
bagimsiz step'leri ThreadPoolExecutor ile paralel calistir.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from karadul.core.pipeline import PipelineContext
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import StepSpec, get_step

logger = logging.getLogger(__name__)

# Berke kurali: paralel ajan max 7 ile aynı felsefe — paralel step de 7 ile cap.
_HARD_PARALLEL_CAP = 7


class PipelineRunner:
    """Step listesini requires/produces grafina gore siralar ve calistirir.

    M1: sequential.  M2: topological level'lar, level icinde paralel.

    Hata modu:
        - Missing requires → RuntimeError (calistirmadan once)
        - Produces disinda artifact → RuntimeError (step sonrasi)
        - Step exception (sequential): fail-fast, hata raise edilir, kalan
          step'ler iptal.
        - Step exception (parallel): paralel grup icindeki diger future'lar
          tamamlanana kadar beklenir, sonra ilk hata raise edilir
          (errors listesinde hepsi gorunur).
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
        levels = self._topological_levels(self._specs)
        ctx = StepContext(pipeline_context=pipeline_context)

        # pipeline_context.metadata'dan gelen onceki artifact'lari import et.
        if pipeline_context.metadata:
            ctx._write_artifacts(dict(pipeline_context.metadata))

        # seed_artifacts — T3.5 shim koprusu.
        if seed_artifacts:
            ctx._write_artifacts(dict(seed_artifacts))

        # Config'i oku — parallel_steps + parallel_max_workers
        # Defansif: MagicMock veya garip attribute'lar gelirse sequential mod.
        cfg = getattr(pipeline_context, "config", None)
        pcfg = getattr(cfg, "pipeline", None) if cfg is not None else None
        raw_flag = getattr(pcfg, "parallel_steps", False)
        parallel_enabled = isinstance(raw_flag, bool) and raw_flag
        raw_workers = getattr(pcfg, "parallel_max_workers", None)
        configured_workers: int | None = (
            raw_workers if isinstance(raw_workers, int) else None
        )

        produced_so_far: set[str] = set(ctx.artifacts.keys())

        for level_idx, level in enumerate(levels):
            # Requires kontrolu: bu level'daki her step icin
            for spec in level:
                missing = [
                    r for r in spec.requires if r not in produced_so_far
                ]
                if missing:
                    raise RuntimeError(
                        f"Step '{spec.name}' eksik girdi: {missing}. "
                        f"Mevcut artifact'lar: "
                        f"{sorted(produced_so_far)}",
                    )

            if len(level) == 1 or not parallel_enabled:
                # Sequential: tek step veya paralel kapali
                for spec in level:
                    new_artifacts = self._execute_step(spec, ctx)
                    ctx._write_artifacts(new_artifacts)
                    produced_so_far.update(new_artifacts.keys())
            else:
                # Paralel: ayni level'daki step'leri ThreadPool ile calistir
                level_results = self._execute_level_parallel(
                    level, ctx, level_idx, configured_workers,
                )
                # Merge artifact'lar deterministik sirayla (step adina gore)
                for spec_name in sorted(level_results.keys()):
                    new_artifacts = level_results[spec_name]
                    ctx._write_artifacts(new_artifacts)
                    produced_so_far.update(new_artifacts.keys())

        return ctx

    # --- internals -----------------------------------------------------

    def _execute_step(
        self, spec: StepSpec, ctx: StepContext,
    ) -> dict[str, Any]:
        """Tek bir step calistir, artifact dict dondur (write etme!).

        Stats ve _current_step_meta'yi yonetir. Hata firlatirsa errors'a
        ekler ve raise eder (sequential fail-fast).
        """
        step = spec.cls()
        t0 = time.monotonic()
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

        extra_keys = [k for k in new_artifacts if k not in spec.produces]
        if extra_keys:
            raise RuntimeError(
                f"Step '{spec.name}' produces disinda artifact "
                f"yazdi: {extra_keys}. Beklenen: {list(spec.produces)}",
            )

        logger.info(
            "Step '%s' tamam (%.3fs, %d artifact)",
            spec.name, duration, len(new_artifacts),
        )
        return new_artifacts

    def _execute_level_parallel(
        self,
        level: list[StepSpec],
        ctx: StepContext,
        level_idx: int,
        configured_workers: int | None,
    ) -> dict[str, dict[str, Any]]:
        """Bir level'daki step'leri ThreadPoolExecutor ile paralel calistir.

        Returns:
            {step_name: produced_artifacts_dict} — basarili step'ler.

        Raises:
            Level'daki herhangi bir step exception firlatirsa: TUM future'lar
            tamamlanana kadar beklenir, sonra ilk hata raise edilir.
        """
        # Worker sayisi: min(level_size, configured, HARD_CAP)
        level_size = len(level)
        if configured_workers is not None and configured_workers > 0:
            workers = min(level_size, configured_workers, _HARD_PARALLEL_CAP)
        else:
            workers = min(level_size, _HARD_PARALLEL_CAP)

        names = [s.name for s in level]
        logger.info(
            "Pipeline level %d: %d paralel step baslatiliyor (%d worker): %s",
            level_idx, level_size, workers, names,
        )

        # Stats key'leri thread-safe yazim icin lock
        stats_lock = threading.Lock()

        def _run_one(spec: StepSpec) -> tuple[str, dict[str, Any]]:
            """Worker thread: tek step calistir, isim + artifact dondur."""
            t_start = time.monotonic()
            logger.info("  -> '%s' BAŞLADI", spec.name)
            new_artifacts = self._execute_step_parallel_safe(
                spec, ctx, stats_lock,
            )
            t_end = time.monotonic()
            logger.info(
                "  <- '%s' BİTTİ (%.3fs)", spec.name, t_end - t_start,
            )
            return spec.name, new_artifacts

        results: dict[str, dict[str, Any]] = {}
        errors: list[tuple[str, BaseException]] = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_spec: dict[Future[Any], StepSpec] = {
                pool.submit(_run_one, spec): spec for spec in level
            }
            # as_completed: hangi sirayla biterse o sirada topla.
            # Bir tanesi fail olsa bile digerlerini bekle (cancel etmeyiz —
            # subprocess'ler zaten baslamis olabilir, temiz kapanma onemli).
            for fut in as_completed(future_to_spec):
                spec = future_to_spec[fut]
                try:
                    name, new_artifacts = fut.result()
                    results[name] = new_artifacts
                except Exception as fut_exc:
                    errors.append((spec.name, fut_exc))
                    logger.error(
                        "Paralel level %d, step '%s' basarisiz: %s",
                        level_idx, spec.name, fut_exc,
                    )

        if errors:
            # Tum hatalari errors listesinde topla, ilkini raise et.
            for name, e in errors:
                ctx.errors.append(f"{name}: {e}")
            first_name, first_exc = errors[0]
            raise RuntimeError(
                f"Paralel level {level_idx}'de {len(errors)} step basarisiz "
                f"(ilki: '{first_name}'): {first_exc}",
            ) from first_exc

        return results

    def _execute_step_parallel_safe(
        self,
        spec: StepSpec,
        ctx: StepContext,
        stats_lock: threading.Lock,
    ) -> dict[str, Any]:
        """Paralel mod step calistirma (thread-safe).

        _current_step_meta thread-local oldugu icin sorun yok. stats'i
        kilit altinda yaziyoruz cunku dict.__setitem__ teknik olarak
        GIL-safe ama gozlemcinin tutarli okumasi icin defansif.
        """
        step = spec.cls()
        t0 = time.monotonic()
        # ctx._current_step_meta property setter -> thread-local
        ctx._current_step_meta = spec
        try:
            new_artifacts = step.run(ctx)
        except Exception as exc:
            # NOT: errors append GIL altinda atomic, lock'a gerek yok.
            ctx.errors.append(f"{spec.name}: {exc}")
            logger.exception("Step '%s' basarisiz", spec.name)
            raise
        finally:
            ctx._current_step_meta = None

        duration = time.monotonic() - t0
        with stats_lock:
            ctx.stats[f"{spec.name}_duration_s"] = round(duration, 4)

        if not isinstance(new_artifacts, dict):
            raise RuntimeError(
                f"Step '{spec.name}' dict dondurmeli, "
                f"aldim: {type(new_artifacts).__name__}",
            )

        extra_keys = [k for k in new_artifacts if k not in spec.produces]
        if extra_keys:
            raise RuntimeError(
                f"Step '{spec.name}' produces disinda artifact "
                f"yazdi: {extra_keys}. Beklenen: {list(spec.produces)}",
            )

        logger.info(
            "Step '%s' tamam (%.3fs, %d artifact)",
            spec.name, duration, len(new_artifacts),
        )
        return new_artifacts

    # --- DAG / topological --------------------------------------------

    @staticmethod
    def _topological_levels(specs: list[StepSpec]) -> list[list[StepSpec]]:
        """Kahn algoritmasi — DAG'i BFS level'larina ayir.

        Her level: in-degree=0 olan step'lerin (calismak icin bir onceki
        level'in tamamlanmasini bekleyenlerin) snapshot'i. Ayni level'daki
        step'ler birbirinden bagimsiz → paralel calistirilabilir.

        Returns:
            [[step1, step2], [step3], [step4, step5, step6], ...]
            Level icinde alfabetik sirali (deterministik).
        """
        name_to_spec = {s.name: s for s in specs}
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

        in_degree: dict[str, int] = {s.name: 0 for s in specs}
        adj: dict[str, list[str]] = {s.name: [] for s in specs}

        for s in specs:
            for r in s.requires:
                producer = producer_of.get(r)
                if (
                    producer
                    and producer in name_to_spec
                    and producer != s.name
                ):
                    adj[producer].append(s.name)
                    in_degree[s.name] += 1

        levels: list[list[StepSpec]] = []
        remaining = dict(in_degree)
        total_processed = 0

        while remaining:
            # Bu level'da calistirilabilecek: in_degree=0 olanlar
            current_level_names = sorted(
                [n for n, d in remaining.items() if d == 0],
            )
            if not current_level_names:
                # Cycle
                raise RuntimeError(
                    f"Step grafinda cycle: {sorted(remaining.keys())}",
                )
            current_level = [name_to_spec[n] for n in current_level_names]
            levels.append(current_level)
            total_processed += len(current_level)

            # Bu level'in node'larini cikar, edge'leri azalt
            for n in current_level_names:
                for m in adj[n]:
                    if m in remaining:
                        remaining[m] -= 1
                del remaining[n]

        if total_processed != len(specs):
            # Defansif — yukaridaki cycle check yakalamali ama yine de
            raise RuntimeError(
                f"Topological levels: {total_processed}/{len(specs)} step "
                f"islendi (cycle?)",
            )

        return levels

    @staticmethod
    def _topological_sort(specs: list[StepSpec]) -> list[StepSpec]:
        """Eski API (M1 ile uyumluluk) — level'lari duzlestirir.

        v1.15-B16: artik _topological_levels uzerine kurulu, ama eski test
        kodu ve disardan cagiranlar icin korunuyor.
        """
        levels = PipelineRunner._topological_levels(specs)
        return [spec for level in levels for spec in level]
