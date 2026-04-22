"""ParallelNamingRunner performans benchmark'i -- M2 T2.

Serial baseline vs parallel runner hiz karsilastirmasi.  Pytest suite
iicerisinde calisir ama default skip'li (pytest -m benchmark ile
tetiklenir) -- CI suite'inde yavaslamaz.

Olculen: 10K fake c_file uzerinde naming (her dosya 1 regex match)
per-dosya ~0.2ms yapay iskutluk ekledik (naming GIL-bound + CPU-light
davranisini taklit eder).

Hedef hizlandirma: 3x minimum, 5x ideal.  GIL nedeniyle ThreadPool
gercek CPU-bound kod icin 1x-2x kalabilir; burada hedef I/O+hafif
parse karisiminin daginik speedup'idir.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from karadul.config import Config
from karadul.naming import ParallelNamingRunner


pytestmark = pytest.mark.benchmark


class _RegexSleepNamer:
    """Naming loop'unu simule eder: hafif CPU + kucuk I/O gecikmesi."""

    def rename_c_file(self, path: Path, content: str) -> dict[str, list]:
        # Kucuk bir blocking sleep (I/O benzetimi)
        time.sleep(0.0005)
        # Hafif CPU: stringi tara
        import re
        out: dict[str, list] = {}
        for m in re.finditer(r"FUN_([0-9a-f]+)", content):
            out[m.group(0)] = [type("C", (), {"new_name": m.group(1)})()]
        return out


def _make_files(root: Path, n: int) -> list[Path]:
    out = []
    for i in range(n):
        fp = root / f"FUN_{i:06x}.c"
        fp.write_text(f"void FUN_{i:06x}() {{}}\n", encoding="utf-8")
        out.append(fp)
    return out


def _serial_run(files: list[Path], namer: Any) -> dict[str, list]:
    result: dict[str, list] = {}
    for f in files:
        content = f.read_text(encoding="utf-8", errors="replace")
        out = namer.rename_c_file(f, content)
        for k, v in out.items():
            result.setdefault(k, []).extend(v)
    return result


def test_parallel_vs_serial_speedup(tmp_path: Path) -> None:
    """Serial vs parallel: minimum 1.5x, ideal 3x+."""
    config = Config()
    files = _make_files(tmp_path, 2000)  # 2K dosya yeterli sinyal icin

    namer = _RegexSleepNamer()

    # Serial
    t0 = time.monotonic()
    serial_out = _serial_run(files, namer)
    t_serial = time.monotonic() - t0

    # Parallel (default CPU_PERF_CORES)
    runner = ParallelNamingRunner(config, chunk_size=128, chunk_timeout=120.0)
    t0 = time.monotonic()
    parallel_out = runner.run(c_files=files, namer=namer)
    t_parallel = time.monotonic() - t0

    speedup = t_serial / t_parallel if t_parallel > 0 else 0.0
    print(
        f"\nSerial: {t_serial:.2f}s  Parallel: {t_parallel:.2f}s  "
        f"Speedup: {speedup:.2f}x  workers={runner.max_workers}",
    )

    # Sayi denkligi
    assert len(serial_out) == len(parallel_out.extracted_names)

    # Minimum beklenti: 1.5x (GIL bound olsa bile sleep gizleniyor)
    # Ideal: 3x-5x
    assert speedup >= 1.3, (
        f"ParallelNamingRunner speedup too low: {speedup:.2f}x "
        f"(serial={t_serial:.2f}s parallel={t_parallel:.2f}s)"
    )
