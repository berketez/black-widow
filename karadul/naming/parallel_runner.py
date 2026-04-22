"""ParallelNamingRunner — file-level ThreadPool naming orkestratoru (M2 T2).

c_files -> 256'lik chunk'lar -> ThreadPoolExecutor -> deterministik merge.

Tasarim ozeti:
  - Namer-agnostic: `rename_c_file(path, content)` veya
    `extract_names_from_file(path, content)` imzasina guvenir.
  - Thread-safety: thread-local accumulator + chunk sonunda tek lock merge.
  - Chunk timeout: future.result(timeout=...); asim halinde chunk atlanir.
  - Graceful shutdown: KeyboardInterrupt'ta cancel_futures=True.
  - Deterministik sira: c_files orjinal sirasiyla chunk'lanir, merge
    idx-sorted iterasyonla yapilir (as_completed degil).
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeoutError,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from karadul.config import CPU_PERF_CORES, Config

logger = logging.getLogger(__name__)


@dataclass
class NamingChunkResult:
    """Run ciktisi: merge edilmis isimler, hatalar, metrikler."""

    extracted_names: dict[str, list] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


NamerCallable = Callable[[Path, str], dict[str, list]]


class ParallelNamingRunner:
    """C dosyalarini ThreadPool uzerinden paralel naming'e tabi tutar."""

    def __init__(
        self,
        config: Config,
        max_workers: int | None = None,
        chunk_size: int | None = None,
        chunk_timeout: float | None = None,
    ) -> None:
        self._config = config
        perf = getattr(config, "perf", None)
        cfg_max = getattr(perf, "naming_max_workers", None) if perf else None
        cfg_chunk = getattr(perf, "naming_chunk_size", 256) if perf else 256
        cfg_timeout = getattr(perf, "naming_chunk_timeout", 60.0) if perf else 60.0

        eff_max = max_workers if max_workers is not None else cfg_max
        self._max_workers = max(1, eff_max if eff_max is not None else CPU_PERF_CORES)
        self._chunk_size = max(1, chunk_size if chunk_size is not None else cfg_chunk)
        ct = chunk_timeout if chunk_timeout is not None else cfg_timeout
        self._chunk_timeout = ct if ct > 0 else 60.0
        self._merge_lock = threading.Lock()

    # Public properties — read-only erisim icin
    max_workers = property(lambda self: self._max_workers)
    chunk_size = property(lambda self: self._chunk_size)
    chunk_timeout = property(lambda self: self._chunk_timeout)

    def run(
        self,
        c_files: list[Path],
        namer: Any,
        file_cache: dict[str, str] | None = None,
    ) -> NamingChunkResult:
        """Paralel naming calistir.

        Args:
            c_files: Islenecek .c dosyalari (sirali, determinizm icin).
            namer: `rename_c_file` veya `extract_names_from_file` metoduna
                sahip obje.  Yoksa bos sonuc + error dondurur.
            file_cache: {str(path): content}.  None ise disk'ten okunur.
        """
        result = NamingChunkResult()
        start = time.monotonic()

        if not c_files:
            result.stats.update(
                chunk_count=0, file_count=0, elapsed_s=0.0,
            )
            return result

        file_cache = file_cache or {}
        chunks = [
            c_files[i : i + self._chunk_size]
            for i in range(0, len(c_files), self._chunk_size)
        ]
        result.stats.update(
            chunk_count=len(chunks),
            file_count=len(c_files),
            max_workers=self._max_workers,
            chunk_size=self._chunk_size,
        )

        namer_callable = self._resolve_namer_callable(namer)
        if namer_callable is None:
            result.errors.append(
                "ParallelNamingRunner: namer has no usable method "
                "(rename_c_file / extract_names_from_file)",
            )
            result.stats["elapsed_s"] = round(time.monotonic() - start, 3)
            return result

        executor = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="karadul-naming",
        )
        futures: list[tuple[int, Any]] = []
        try:
            for idx, chunk in enumerate(chunks):
                fut = executor.submit(
                    self._process_chunk,
                    chunk, namer_callable, file_cache, idx,
                )
                futures.append((idx, fut))
            self._collect_futures(futures, result)
        except KeyboardInterrupt:
            logger.warning("ParallelNamingRunner: SIGINT, shutting down")
            executor.shutdown(wait=False, cancel_futures=True)
            result.errors.append("ParallelNamingRunner: interrupted (SIGINT)")
        finally:
            executor.shutdown(wait=True)

        result.stats["elapsed_s"] = round(time.monotonic() - start, 3)
        result.stats["error_count"] = len(result.errors)
        result.stats["names_extracted"] = len(result.extracted_names)
        return result

    # -------- Internal --------

    def _resolve_namer_callable(self, namer: Any) -> NamerCallable | None:
        for attr in ("rename_c_file", "extract_names_from_file"):
            cand = getattr(namer, attr, None)
            if callable(cand):
                return cand  # type: ignore[no-any-return]
        return None

    def _process_chunk(
        self,
        chunk: list[Path],
        namer_callable: NamerCallable,
        file_cache: dict[str, str],
        chunk_idx: int,
    ) -> tuple[int, dict[str, list], list[str]]:
        """Tek chunk isle; thread-local accumulator'u dondurur."""
        local_names: dict[str, list] = {}
        local_errors: list[str] = []

        for cf in chunk:
            try:
                content = file_cache.get(str(cf))
                if content is None:
                    try:
                        content = cf.read_text(
                            encoding="utf-8", errors="replace",
                        )
                    except OSError as exc:
                        local_errors.append(
                            f"[chunk {chunk_idx}] read failed: "
                            f"{cf.name}: {exc}"
                        )
                        continue

                file_names = namer_callable(cf, content)
                if not file_names:
                    continue

                for key, cands in file_names.items():
                    if not key:
                        continue
                    existing = local_names.setdefault(key, [])
                    if isinstance(cands, list):
                        existing.extend(cands)
                    else:
                        existing.append(cands)
            except Exception as exc:
                local_errors.append(
                    f"[chunk {chunk_idx}] namer failed: "
                    f"{cf.name}: {type(exc).__name__}: {exc}"
                )

        return chunk_idx, local_names, local_errors

    def _collect_futures(
        self,
        futures: list[tuple[int, Any]],
        result: NamingChunkResult,
    ) -> None:
        """Future'lari idx-sorted sirada tuket ve merge et."""
        per_chunk_timings: list[float] = []

        for idx, fut in futures:
            t0 = time.monotonic()
            try:
                _, local_names, local_errors = fut.result(
                    timeout=self._chunk_timeout,
                )
            except FuturesTimeoutError:
                msg = (
                    f"ParallelNamingRunner: chunk {idx} timed out "
                    f"after {self._chunk_timeout:.1f}s"
                )
                logger.warning(msg)
                result.errors.append(msg)
                fut.cancel()
                continue
            except Exception as exc:
                msg = (
                    f"ParallelNamingRunner: chunk {idx} failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                logger.warning(msg)
                result.errors.append(msg)
                continue

            per_chunk_timings.append(time.monotonic() - t0)
            with self._merge_lock:
                for key, cands in local_names.items():
                    existing = result.extracted_names.setdefault(key, [])
                    existing.extend(cands)
                if local_errors:
                    result.errors.extend(local_errors)

        if per_chunk_timings:
            result.stats["per_chunk_s_avg"] = round(
                sum(per_chunk_timings) / len(per_chunk_timings), 3,
            )
            result.stats["per_chunk_s_max"] = round(
                max(per_chunk_timings), 3,
            )


__all__ = ["NamingChunkResult", "ParallelNamingRunner"]
