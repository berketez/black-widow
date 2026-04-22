"""Karadul naming paketi — M2 T2.

`ParallelNamingRunner`: C dosyalarini chunk'lara bolup ThreadPoolExecutor
uzerinden paralel isler. Feature flag `config.perf.parallel_naming` ile
etkinlestirilir; default False (eski ProcessPool yolu korunur).

Genel fikir ve matematik:
  - File-level paralellik GIL problemini dosya I/O ile gizler (naming
    asamasi agirlikli disk + regex + string-replace).
  - ProcessPool yerine ThreadPool tercih edildi: SignatureDB/func_info
    yapilari 3GB mertebesinde, pickle overhead'i katastrofik olurdu.
  - Chunk size 256 cache-friendly ve ThreadPool overhead'ini amorti eder
    (32-core M4 Max'te ideal).

Kullanim:
    from karadul.naming import ParallelNamingRunner, NamingChunkResult

    runner = ParallelNamingRunner(
        config=config,
        max_workers=None,       # None -> CPU_PERF_CORES
        chunk_size=256,
        chunk_timeout=60.0,
    )
    result: NamingChunkResult = runner.run(
        c_files=c_files,
        namer=namer,            # onceden olusturulmus CVariableNamer
        file_cache=file_cache,  # {str(path): content}
    )
"""

from __future__ import annotations

from karadul.naming.parallel_runner import (  # noqa: F401
    NamingChunkResult,
    ParallelNamingRunner,
)

__all__ = ["NamingChunkResult", "ParallelNamingRunner"]
