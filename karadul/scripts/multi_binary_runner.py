#!/usr/bin/env python3
"""v1.15-E: Multi-binary benchmark runner.

Birden fazla binary üzerinde `karadul analyze` koşar, her biri için:
- Süre (wall clock)
- Peak RAM
- F1, precision, recall (B4 fix sonrası gerçek değerler)
- Fonksiyon, string, rename sayıları

Kullanim:
    python karadul/scripts/multi_binary_runner.py <binary_dir> [--subset N] [--out report.json]

Coreutils suite örneği:
    python karadul/scripts/multi_binary_runner.py tests/fixtures/coreutils/binaries/stripped/ \\
        --subset 6 --out /tmp/karadul_bench.json
"""
from __future__ import annotations

import argparse
import json
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class BinaryResult:
    binary_name: str
    binary_size_bytes: int
    success: bool
    duration_seconds: float
    peak_rss_mb: float
    functions_recovered: int = 0
    strings_found: int = 0
    variables_renamed: int = 0
    f1: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    workspace: Optional[str] = None
    error: Optional[str] = None
    artifacts_count: int = 0


@dataclass
class SuiteResult:
    suite_name: str
    binary_count: int
    total_duration_seconds: float
    binaries: list[BinaryResult] = field(default_factory=list)

    @property
    def avg_duration(self) -> float:
        if not self.binaries:
            return 0.0
        return sum(b.duration_seconds for b in self.binaries) / len(self.binaries)

    @property
    def success_rate(self) -> float:
        if not self.binaries:
            return 0.0
        return sum(1 for b in self.binaries if b.success) / len(self.binaries)

    @property
    def avg_f1(self) -> Optional[float]:
        scores = [b.f1 for b in self.binaries if b.f1 is not None]
        if not scores:
            return None
        return sum(scores) / len(scores)


def _peak_rss_mb() -> float:
    """getrusage ile child process peak RSS (macOS: byte, Linux: KB)."""
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss = r.ru_maxrss
    if sys.platform == "darwin":
        return rss / (1024 * 1024)  # bytes → MB
    return rss / 1024  # KB → MB


def run_one(binary: Path, workspace_dir: Path, timeout: int = 600) -> BinaryResult:
    """Tek bir binary üzerinde karadul analyze koş."""
    result = BinaryResult(
        binary_name=binary.name,
        binary_size_bytes=binary.stat().st_size,
        success=False,
        duration_seconds=0.0,
        peak_rss_mb=0.0,
    )

    rss_before = _peak_rss_mb()
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [
                "karadul", "analyze", str(binary),
                "--output-dir", str(workspace_dir),
                "--skip-dynamic",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result.duration_seconds = time.monotonic() - start
        result.peak_rss_mb = max(0.0, _peak_rss_mb() - rss_before)
        result.success = proc.returncode == 0

        # F1 ölçümü için benchmark_runner kullan (B4 fix)
        if result.success:
            try:
                from tests.benchmark.benchmark_runner import BenchmarkRunner
                bench = BenchmarkRunner()
                bench_result = bench.run_from_binaries(
                    binary, workspace_dir / "workspaces" / binary.name,
                )
                if bench_result and bench_result.metrics:
                    result.f1 = bench_result.metrics.f1
                    result.precision = bench_result.metrics.precision
                    result.recall = bench_result.metrics.recall
            except Exception as exc:
                # v1.15.5: F1 ölçümü başarısızsa SESSİZCE yutup "başarılı"
                # raporlamak YASAK. Hatayı result.error'a yaz + stderr'e uyar.
                # karadul'un kendisi çalıştı (result.success=True) ama F1
                # ölçülemedi — bu durum şeffaf raporlanmalı.
                result.error = f"F1 ölçülemedi: {exc}"
                print(
                    f"    UYARI: {binary.name} F1 ölçülemedi: {exc}",
                    flush=True, file=sys.stderr,
                )

        # Workspace bulup artifact'leri say
        binary_ws = workspace_dir / "workspaces" / binary.name
        if binary_ws.is_dir():
            # En son timestamp dizini
            ts_dirs = sorted(binary_ws.iterdir(), reverse=True)
            if ts_dirs:
                latest = ts_dirs[0]
                result.workspace = str(latest)
                result.artifacts_count = len(list(latest.rglob("*.json")))

                # naming_map.json varsa fonksiyon sayısı
                # Format: {"global": {FUN_xxx: name, ...}, "per_function": {...}}
                # Final rename src/ tercih, yoksa src_iter1/
                nm_paths = sorted(latest.rglob("naming_map.json"),
                                  key=lambda p: 0 if "src/" in str(p) and "iter" not in str(p) else 1)
                if nm_paths:
                    try:
                        nm = json.loads(nm_paths[0].read_text())
                        if isinstance(nm, dict):
                            # Düz dict mi yoksa nested {global, per_function} mu
                            global_map = nm.get("global", nm) if "global" in nm else nm
                            if isinstance(global_map, dict):
                                result.functions_recovered = len(global_map)
                                # Anlamlı rename: değer FUN_xxx/sub_xxx/thunk_xxx ile başlamayan
                                result.variables_renamed = sum(
                                    1 for v in global_map.values()
                                    if isinstance(v, str) and v
                                    and not v.startswith(("FUN_", "sub_", "thunk_"))
                                )
                            # F1 hesabı için: gt_count, tp_count → F1
                            # naming_map'in formatı flat değil; B4 benchmark_runner ile ayrı koşulur
                    except Exception:
                        pass

                # pipeline_result.json'dan stats al
                pr = latest / "pipeline_result.json"
                if pr.exists():
                    try:
                        data = json.loads(pr.read_text())
                        stages = data.get("stages", {})
                        static_stats = stages.get("static", {}).get("stats", {})
                        result.strings_found = (
                            static_stats.get("ghidra_string_count", 0)
                            or static_stats.get("strings", 0)
                        )
                    except Exception:
                        pass

        if not result.success:
            result.error = (proc.stderr[-500:] if proc.stderr else "non-zero exit")

    except subprocess.TimeoutExpired:
        result.duration_seconds = timeout
        result.error = f"timeout after {timeout}s"
    except Exception as exc:
        result.duration_seconds = time.monotonic() - start
        result.error = str(exc)

    return result


def run_suite(
    binary_dir: Path,
    *,
    subset: Optional[int] = None,
    timeout: int = 600,
    workspace_root: Optional[Path] = None,
) -> SuiteResult:
    """Bir dizindeki tüm binary'ler için karadul analyze koş."""
    if not binary_dir.is_dir():
        raise ValueError(f"Binary directory yok: {binary_dir}")

    binaries = sorted(
        p for p in binary_dir.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )
    if subset:
        # En küçükten subset adet al (hızlı benchmark için)
        binaries = sorted(binaries, key=lambda p: p.stat().st_size)[:subset]

    if workspace_root is None:
        workspace_root = Path(tempfile.mkdtemp(prefix="karadul_bench_"))

    suite = SuiteResult(
        suite_name=binary_dir.name,
        binary_count=len(binaries),
        total_duration_seconds=0.0,
    )

    suite_start = time.monotonic()
    for i, binary in enumerate(binaries, 1):
        ws = workspace_root / f"bin_{i:02d}_{binary.name}"
        ws.mkdir(parents=True, exist_ok=True)
        print(
            f"[{i}/{len(binaries)}] {binary.name} "
            f"({binary.stat().st_size:,} B) ...",
            flush=True, file=sys.stderr,
        )
        result = run_one(binary, ws, timeout=timeout)
        suite.binaries.append(result)
        status = "OK" if result.success else f"FAIL ({result.error or 'unknown'})"
        print(
            f"    {result.duration_seconds:.1f}s · "
            f"{result.peak_rss_mb:.0f}MB · "
            f"{result.functions_recovered}fn · "
            f"{result.variables_renamed}rename · "
            f"{status}",
            flush=True, file=sys.stderr,
        )

    suite.total_duration_seconds = time.monotonic() - suite_start
    return suite


def print_summary(suite: SuiteResult) -> None:
    """Konsola özet tablo."""
    print()
    print("=" * 70)
    print(f"Suite: {suite.suite_name}")
    print(f"Binary count: {suite.binary_count}")
    print(f"Total duration: {suite.total_duration_seconds:.1f}s")
    print(f"Avg duration: {suite.avg_duration:.1f}s/binary")
    print(f"Success rate: {suite.success_rate * 100:.0f}%")
    if suite.avg_f1 is not None:
        print(f"Avg F1: {suite.avg_f1:.3f}")
    print()
    print(f"{'binary':<25} {'size':>10} {'time':>8} {'rss':>8} {'fn':>6} {'rename':>8} {'status':<10}")
    print("-" * 70)
    for b in suite.binaries:
        print(
            f"{b.binary_name:<25} {b.binary_size_bytes:>10,} "
            f"{b.duration_seconds:>7.1f}s {b.peak_rss_mb:>7.0f}M "
            f"{b.functions_recovered:>6} {b.variables_renamed:>8} "
            f"{'OK' if b.success else 'FAIL':<10}"
        )
    print("=" * 70)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="v1.15-E multi-binary karadul benchmark runner",
    )
    parser.add_argument("binary_dir", type=Path, help="Binary dizini")
    parser.add_argument("--subset", type=int, default=None,
                        help="En küçük N binary (hızlı benchmark)")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Binary başı timeout (saniye)")
    parser.add_argument("--out", type=Path, default=None,
                        help="JSON çıktı dosyası")
    parser.add_argument("--keep-workspaces", action="store_true",
                        help="Workspaces silme (default sil)")
    args = parser.parse_args()

    workspace_root = Path(tempfile.mkdtemp(prefix="karadul_bench_"))
    try:
        suite = run_suite(
            args.binary_dir,
            subset=args.subset,
            timeout=args.timeout,
            workspace_root=workspace_root,
        )
        print_summary(suite)

        if args.out:
            args.out.write_text(json.dumps(asdict(suite), indent=2, default=str))
            print(f"\nJSON: {args.out}")

        return 0
    finally:
        if not args.keep_workspaces:
            shutil.rmtree(workspace_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
