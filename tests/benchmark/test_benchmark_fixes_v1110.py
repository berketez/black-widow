"""v1.11.0 Benchmark Fix Regression Tests.

3 kritik bug için birim testler:
  - Bug 1: CLI benchmark komutu /dev/null placeholder JSONDecodeError
  - Bug 2: _compare_maps key-space uyuşmazlığı (FUN_<addr> vs symbol_name)
  - Bug 3: fun_residue_pct + type_precision/recall eksik metrikler

Bu dosya dar kapsamlıdır; mevcut test_benchmark_integration.py /
test_metrics.py'yi çökertmemek için yeni modülde toplanmıştır.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.benchmark.benchmark_runner import (
    BenchmarkRunner,
    _addr_to_fun_key,
    find_symbol_mapping,
)
from tests.benchmark.metrics import AccuracyCalculator


# ---------------------------------------------------------------------------
# Bug 1: CLI benchmark komutu crash etmemeli
# ---------------------------------------------------------------------------


def test_cli_benchmark_does_not_crash_on_scoped_naming_map(tmp_path: Path) -> None:
    """v1.11.0 Bug 1: Önceden `run_from_naming_map(Path('/dev/null'),...)`
    çağrısı JSONDecodeError atıyordu. Artık CLI `run_mock` kullanmalı ve
    v1.5.5 scoped format'ı sorunsuz kabul etmeli.
    """
    nm_path = tmp_path / "naming_map.json"
    nm_path.write_text(
        json.dumps(
            {
                "global": {"FUN_00401000": "main"},
                "per_function": {"main": {"iVar1": "result"}},
            }
        ),
        encoding="utf-8",
    )
    gt_map = {"FUN_00401000": "main"}

    runner = BenchmarkRunner()
    nm_raw = json.loads(nm_path.read_text(encoding="utf-8"))
    # Crash olmamalı, sayı üretmeli.
    result = runner.run_mock(gt_map, nm_raw)

    assert result.metrics.total_symbols == 1
    assert result.metrics.exact_matches == 1
    assert result.metrics.f1 == 1.0


def test_run_mock_accepts_flat_naming_map() -> None:
    """Geriye uyumluluk: düz `{placeholder: name}` formatı da kabul edilmeli."""
    runner = BenchmarkRunner()
    gt = {"FUN_1": "main", "FUN_2": "init"}
    nm = {"FUN_1": "main", "FUN_2": "initialize"}
    result = runner.run_mock(gt, nm)
    assert result.metrics.exact_matches == 1  # main
    assert result.metrics.semantic_matches == 1  # init/initialize


# ---------------------------------------------------------------------------
# Bug 2: Key-space mismatch — adres ↔ sembol cross-ref
# ---------------------------------------------------------------------------


def test_addr_to_fun_key_normalization() -> None:
    """Adres normalizasyonu: 0x, leading zeros, zfill."""
    assert _addr_to_fun_key("100000460") == "FUN_100000460"
    assert _addr_to_fun_key("0x100000460") == "FUN_100000460"
    assert _addr_to_fun_key("0000000000400100") == "FUN_00400100"
    assert _addr_to_fun_key("") == ""


def test_find_symbol_mapping_from_workspace(tmp_path: Path) -> None:
    """ghidra_functions.json + symbols.json üzerinden adres↔sembol haritası."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (tmp_path / "reconstructed").mkdir()  # workspace detector için

    (static_dir / "ghidra_functions.json").write_text(
        json.dumps(
            {
                "functions": [
                    {"name": "_add", "address": "100000460"},
                    {"name": "_print_info", "address": "1000004ac"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (static_dir / "symbols.json").write_text(
        json.dumps(
            {
                "symbols": [
                    {"name": "_main", "address": "1000004e0", "type": "T"},
                ]
            }
        ),
        encoding="utf-8",
    )

    mapping = find_symbol_mapping(tmp_path)
    # Çift yönlü: FUN_<addr> -> name ve name -> FUN_<addr>
    assert mapping["FUN_100000460"] == "_add"
    assert mapping["_add"] == "FUN_100000460"
    assert mapping["FUN_1000004ac"] == "_print_info"
    # symbols.json'dan gelen _main
    assert mapping["FUN_1000004e0"] == "_main"


def test_compare_maps_cross_ref_via_symbol_mapping() -> None:
    """Bug 2: GT FUN_<addr> tarafında, naming_map sembol adında olunca
    symbol_mapping ile köprüleme yapılmalı.

    v1.11.0 Dalga 5: Sembol haritasında preserved olan (karadul rename
    yapmamış, binary export'u korunmuş) semboller artık "exact" değil
    "preserved" olarak işaretlenir. macOS strip sahte-stripping
    sorununu önlemek için F1/accuracy'den hariç tutulur.
    """
    runner = BenchmarkRunner()
    gt = {"FUN_100000460": "_add"}
    # Naming map fonksiyon adını ANAHTAR olarak tutuyor, değer yok.
    # Symbol mapping preserved case: karadul ismi bozmamış, binary'den geldi.
    nm = {"global": {}, "per_function": {"_add": {"iVar1": "result"}}}
    sym_map = {"FUN_100000460": "_add", "_add": "FUN_100000460"}

    comparisons = runner._compare_maps(gt, nm, sym_map)
    assert len(comparisons) == 1
    # _add sembol haritasında preserve edilmiş → preserved (challenge değil)
    assert comparisons[0].match_type == "preserved"
    assert comparisons[0].score == 0.0
    assert comparisons[0].recovered == "_add"


def test_compare_maps_without_symbol_mapping_falls_back_to_missing() -> None:
    """Symbol mapping verilmezse ve naming_map'te placeholder yoksa missing."""
    runner = BenchmarkRunner()
    gt = {"FUN_100000460": "_add"}
    nm = {"global": {}, "per_function": {"_add": {"iVar1": "result"}}}
    comparisons = runner._compare_maps(gt, nm, symbol_mapping=None)
    assert comparisons[0].match_type == "missing"


# ---------------------------------------------------------------------------
# Bug 3: Eksik metrikler — fun_residue_pct, type P/R
# ---------------------------------------------------------------------------


def test_calculate_fun_residue_empty() -> None:
    calc = AccuracyCalculator()
    assert calc.calculate_fun_residue({}) == 0.0


def test_calculate_fun_residue_all_named() -> None:
    """Hiç placeholder kalmamış → %0 residue."""
    calc = AccuracyCalculator()
    nm = {"a": "buffer", "b": "length", "c": "process_data"}
    assert calc.calculate_fun_residue(nm) == 0.0


def test_calculate_fun_residue_partial() -> None:
    """Yarısı placeholder, yarısı isimli → %50."""
    calc = AccuracyCalculator()
    nm = {
        "k1": "FUN_00401000",  # placeholder
        "k2": "sub_00401100",  # placeholder
        "k3": "main",  # named
        "k4": "parse_config",  # named
    }
    assert calc.calculate_fun_residue(nm) == 50.0


def test_calculate_fun_residue_var_patterns() -> None:
    """uVar1, iVar2, DAT_xxx, local_xxx gibi varyantlar da placeholder sayılır."""
    calc = AccuracyCalculator()
    nm = {
        "a": "uVar1",
        "b": "iVar2",
        "c": "DAT_00603000",
        "d": "local_10",
        "e": "var_4",
    }
    assert calc.calculate_fun_residue(nm) == 100.0


def test_calculate_type_precision_recall_perfect() -> None:
    """Tüm tahminler ground truth ile uyuşuyor."""
    calc = AccuracyCalculator()
    pred = {"v1": "int", "v2": "char *"}
    gt = {"v1": "int", "v2": "char *"}
    p, r = calc.calculate_type_precision_recall(pred, gt)
    assert p == 1.0
    assert r == 1.0


def test_calculate_type_precision_recall_aliases() -> None:
    """unsigned int ↔ uint32_t gibi yaygın C tip eşanlamları kabul edilmeli."""
    calc = AccuracyCalculator()
    pred = {"v1": "unsigned int", "v2": "unsigned long"}
    gt = {"v1": "uint32_t", "v2": "uint64_t"}
    p, r = calc.calculate_type_precision_recall(pred, gt)
    assert p == 1.0
    assert r == 1.0


def test_calculate_type_precision_recall_partial() -> None:
    """Tahminlerin yarısı doğru → P=0.5; GT'nin üçte ikisi tahmin → R=~0.33."""
    calc = AccuracyCalculator()
    pred = {"v1": "int", "v2": "char"}  # v2 yanlış
    gt = {"v1": "int", "v2": "int", "v3": "long"}  # v3 tahmin edilmemiş
    p, r = calc.calculate_type_precision_recall(pred, gt)
    assert p == pytest.approx(0.5, rel=1e-3)
    assert r == pytest.approx(1.0 / 3.0, rel=1e-3)


def test_benchmark_metrics_fun_residue_field_propagates() -> None:
    """run_mock sonunda metrics.fun_residue_pct doldurulmalı."""
    runner = BenchmarkRunner()
    gt = {"FUN_1": "main"}
    # Naming map: bir isim + bir placeholder → %50 residue
    nm = {"global": {"FUN_1": "main", "FUN_2": "sub_00401000"}}
    result = runner.run_mock(gt, nm)
    assert result.metrics.fun_residue_pct == 50.0
