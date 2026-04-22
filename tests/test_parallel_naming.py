"""ParallelNamingRunner testleri — M2 T2.

Runner'in:
  - init varsayilanlari (CPU_PERF_CORES, chunk_size=256, timeout=60s)
  - bos/tek-chunk/multi-chunk isleyisi
  - chunk timeout + error handling
  - deterministik merge sirasi
  - threading.Lock altinda shared-state guvenligi
  - feature flag davranisi (_feedback_naming shim)
davranisini kapsar.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from karadul.config import CPU_PERF_CORES, Config
from karadul.naming import NamingChunkResult, ParallelNamingRunner


# ---------------------------------------------------------------------------
# Yardimci fake namer'lar
# ---------------------------------------------------------------------------


class _FakeCandidate:
    """Minimal NamingCandidate stand-in — new_name attribute'u yeter."""

    __slots__ = ("new_name", "confidence", "source")

    def __init__(self, new_name: str, confidence: float = 0.8,
                 source: str = "test") -> None:
        self.new_name = new_name
        self.confidence = confidence
        self.source = source


class _FakeNamer:
    """rename_c_file verilen icerigi parse edip fake candidate uretir.

    Basit kural: dosya icinde 'FUN_<hex>' gecen her eski isim icin
    'renamed_<hex>' adayi uret.
    """

    def __init__(self) -> None:
        self.call_count = 0
        self.last_paths: list[Path] = []

    def rename_c_file(self, path: Path, content: str) -> dict[str, list]:
        self.call_count += 1
        self.last_paths.append(path)
        # "FUN_1234" -> "renamed_1234"
        import re
        out: dict[str, list] = {}
        for match in re.finditer(r"FUN_([0-9a-fA-F]+)", content):
            key = match.group(0)
            out.setdefault(key, []).append(
                _FakeCandidate(f"renamed_{match.group(1)}"),
            )
        return out


class _SlowFakeNamer:
    """Chunk timeout testi icin -- her dosyada uyur."""

    def __init__(self, sleep_s: float) -> None:
        self.sleep_s = sleep_s

    def rename_c_file(self, path: Path, content: str) -> dict[str, list]:
        time.sleep(self.sleep_s)
        return {}


class _NamelessNamer:
    """Per-file metod vermeyen namer (fallback path testi)."""

    def analyze_and_rename(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Runner bu cagriyi yapmamaliydi")


# ---------------------------------------------------------------------------
# Test fixture'lari
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> Config:
    return Config()


def _make_c_files(root: Path, count: int, fun_prefix: str = "1000") -> list[Path]:
    """count adet FUN_xxxx.c dosyasi olustur."""
    files: list[Path] = []
    for i in range(count):
        hex_id = f"{int(fun_prefix, 16) + i:x}"
        fp = root / f"FUN_{hex_id}.c"
        fp.write_text(f"void FUN_{hex_id}() {{ /* stub */ }}\n", encoding="utf-8")
        files.append(fp)
    return files


# ---------------------------------------------------------------------------
# 1. init
# ---------------------------------------------------------------------------


def test_parallel_runner_init(config: Config) -> None:
    runner = ParallelNamingRunner(config)
    assert runner.max_workers == CPU_PERF_CORES
    assert runner.chunk_size == 256
    assert runner.chunk_timeout == 60.0

    # Argument override
    runner2 = ParallelNamingRunner(
        config, max_workers=4, chunk_size=10, chunk_timeout=5.0,
    )
    assert runner2.max_workers == 4
    assert runner2.chunk_size == 10
    assert runner2.chunk_timeout == 5.0

    # Negative -> minimum
    runner3 = ParallelNamingRunner(
        config, max_workers=0, chunk_size=0, chunk_timeout=-1.0,
    )
    assert runner3.max_workers == 1
    assert runner3.chunk_size == 1
    assert runner3.chunk_timeout == 60.0  # fallback


# ---------------------------------------------------------------------------
# 2. empty input
# ---------------------------------------------------------------------------


def test_empty_c_files(config: Config) -> None:
    runner = ParallelNamingRunner(config, max_workers=2)
    result = runner.run(c_files=[], namer=_FakeNamer())
    assert isinstance(result, NamingChunkResult)
    assert result.extracted_names == {}
    assert result.errors == []
    assert result.stats["file_count"] == 0
    assert result.stats["chunk_count"] == 0


# ---------------------------------------------------------------------------
# 3. single chunk (<256 files)
# ---------------------------------------------------------------------------


def test_single_chunk(tmp_path: Path, config: Config) -> None:
    files = _make_c_files(tmp_path, 50)
    namer = _FakeNamer()
    runner = ParallelNamingRunner(config, max_workers=4, chunk_size=256)
    result = runner.run(c_files=files, namer=namer)

    assert result.stats["chunk_count"] == 1
    assert result.stats["file_count"] == 50
    assert namer.call_count == 50
    assert len(result.extracted_names) == 50
    # Her isim renamed_ prefixli, 1 candidate
    for old, cands in result.extracted_names.items():
        assert old.startswith("FUN_")
        assert len(cands) == 1
        assert cands[0].new_name.startswith("renamed_")


# ---------------------------------------------------------------------------
# 4. multi-chunk (1000 files / 4 chunk @ 256)
# ---------------------------------------------------------------------------


def test_multi_chunk(tmp_path: Path, config: Config) -> None:
    files = _make_c_files(tmp_path, 1000)
    namer = _FakeNamer()
    runner = ParallelNamingRunner(config, max_workers=4, chunk_size=256)
    result = runner.run(c_files=files, namer=namer)

    # ceil(1000/256) = 4
    assert result.stats["chunk_count"] == 4
    assert result.stats["file_count"] == 1000
    assert namer.call_count == 1000
    assert len(result.extracted_names) == 1000


# ---------------------------------------------------------------------------
# 5. lock contention: ayni key'e birden fazla chunk yazsa extend yapilir
# ---------------------------------------------------------------------------


def test_lock_contention_merge(tmp_path: Path, config: Config) -> None:
    # Ayni "FUN_cafe" gecen 10 dosya yarat -- hepsi ayni key icin
    # candidate uretir, merge sirasinda extend olur.
    for i in range(10):
        fp = tmp_path / f"file_{i}.c"
        fp.write_text(f"void FUN_cafe() {{ /* {i} */ }}", encoding="utf-8")

    files = sorted(tmp_path.glob("*.c"))
    namer = _FakeNamer()
    runner = ParallelNamingRunner(
        config, max_workers=8, chunk_size=2,  # 5 chunk
    )
    result = runner.run(c_files=files, namer=namer)

    assert "FUN_cafe" in result.extracted_names
    # Her dosya 1 candidate verdi, 10 dosya -> 10 candidate
    assert len(result.extracted_names["FUN_cafe"]) == 10
    # Hepsi ayni new_name uretir (documented behavior: son yazan degil
    # tumu extend edilir)
    for cand in result.extracted_names["FUN_cafe"]:
        assert cand.new_name == "renamed_cafe"


# ---------------------------------------------------------------------------
# 6. chunk timeout
# ---------------------------------------------------------------------------


def test_chunk_timeout(tmp_path: Path, config: Config) -> None:
    files = _make_c_files(tmp_path, 4)
    # Her dosyada 0.2s uyusun, chunk_size=4 -> 1 chunk 0.8s sursun
    # timeout=0.2s -> kesin timeout.
    namer = _SlowFakeNamer(sleep_s=0.2)
    runner = ParallelNamingRunner(
        config, max_workers=1, chunk_size=4, chunk_timeout=0.2,
    )
    result = runner.run(c_files=files, namer=namer)

    # Timeout mesaji errors'da olmali
    assert any("timed out" in e for e in result.errors), result.errors
    assert result.stats["error_count"] >= 1
    # Extracted names bos olmali (chunk atildi)
    assert result.extracted_names == {}


# ---------------------------------------------------------------------------
# 7. max_workers=None -> CPU_PERF_CORES
# ---------------------------------------------------------------------------


def test_max_workers_none_defaults_to_cpu_cores(config: Config) -> None:
    runner = ParallelNamingRunner(config, max_workers=None)
    assert runner.max_workers == CPU_PERF_CORES

    # Config'den None geldiginde de ayni davranis
    config.perf.naming_max_workers = None
    runner2 = ParallelNamingRunner(config)
    assert runner2.max_workers == CPU_PERF_CORES

    # Config'den explicit deger geldiginde onu kullan
    config.perf.naming_max_workers = 3
    runner3 = ParallelNamingRunner(config)
    assert runner3.max_workers == 3


# ---------------------------------------------------------------------------
# 8. deterministic output
# ---------------------------------------------------------------------------


def test_deterministic_output(tmp_path: Path, config: Config) -> None:
    files = _make_c_files(tmp_path, 500)
    runner = ParallelNamingRunner(config, max_workers=8, chunk_size=100)

    result1 = runner.run(c_files=files, namer=_FakeNamer())
    result2 = runner.run(c_files=files, namer=_FakeNamer())

    # Ayni input ayni output vermeli (key'ler ve candidate sayilari)
    assert set(result1.extracted_names.keys()) == set(
        result2.extracted_names.keys(),
    )
    for key in result1.extracted_names:
        names_1 = [c.new_name for c in result1.extracted_names[key]]
        names_2 = [c.new_name for c in result2.extracted_names[key]]
        assert names_1 == names_2, f"non-deterministic output for {key}"


# ---------------------------------------------------------------------------
# 9. feature flag OFF -> serial path
# ---------------------------------------------------------------------------


def test_feature_flag_off_uses_serial(config: Config) -> None:
    from karadul.pipeline.steps._feedback_naming_parallel import (
        _should_use_parallel_runner,
    )

    config.perf.parallel_naming = False

    class _Namer:
        def rename_c_file(self, p: Any, c: Any) -> dict[str, list]:
            return {}

    assert _should_use_parallel_runner(config, _Namer()) is False


# ---------------------------------------------------------------------------
# 10. feature flag ON -> parallel path
# ---------------------------------------------------------------------------


def test_feature_flag_on_uses_parallel(config: Config) -> None:
    from karadul.pipeline.steps._feedback_naming_parallel import (
        _should_use_parallel_runner,
    )

    config.perf.parallel_naming = True

    class _GoodNamer:
        def rename_c_file(self, p: Any, c: Any) -> dict[str, list]:
            return {}

    class _BadNamer:
        pass

    # Namer per-file metoda sahip -> True
    assert _should_use_parallel_runner(config, _GoodNamer()) is True
    # Namer metoda sahip degil -> False (fallback)
    assert _should_use_parallel_runner(config, _BadNamer()) is False
    # c_namer None -> False
    assert _should_use_parallel_runner(config, None) is False


# ---------------------------------------------------------------------------
# Bonus: extract_names_from_file fallback
# ---------------------------------------------------------------------------


def test_extract_names_from_file_fallback(
    tmp_path: Path, config: Config,
) -> None:
    """Namer'da rename_c_file yoksa extract_names_from_file kullanilir."""

    files = _make_c_files(tmp_path, 10)

    class _ExtractOnly:
        def __init__(self) -> None:
            self.called = 0

        def extract_names_from_file(
            self, path: Path, content: str,
        ) -> dict[str, list]:
            self.called += 1
            return {"X": [_FakeCandidate("y")]}

    namer = _ExtractOnly()
    runner = ParallelNamingRunner(config, max_workers=2, chunk_size=5)
    result = runner.run(c_files=files, namer=namer)
    assert namer.called == 10
    assert "X" in result.extracted_names


# ---------------------------------------------------------------------------
# Bonus: nameless namer -> graceful error
# ---------------------------------------------------------------------------


def test_nameless_namer_graceful(tmp_path: Path, config: Config) -> None:
    files = _make_c_files(tmp_path, 5)
    runner = ParallelNamingRunner(config, max_workers=2, chunk_size=5)
    result = runner.run(c_files=files, namer=_NamelessNamer())
    assert result.extracted_names == {}
    assert any("no usable method" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Bonus: file_cache kullanimi (disk okuma bypass)
# ---------------------------------------------------------------------------


def test_file_cache_bypasses_disk_read(
    tmp_path: Path, config: Config,
) -> None:
    fp = tmp_path / "FUN_babe.c"
    fp.write_text("void old(){}", encoding="utf-8")
    # Cache ile disk'teki icerigi override ediyoruz (disk'te FUN_ yok)
    cache = {str(fp): "void FUN_beef() {}"}
    namer = _FakeNamer()
    runner = ParallelNamingRunner(config, max_workers=1, chunk_size=1)
    result = runner.run(c_files=[fp], namer=namer, file_cache=cache)
    # Cache'deki FUN_beef bulundu
    assert "FUN_beef" in result.extracted_names
