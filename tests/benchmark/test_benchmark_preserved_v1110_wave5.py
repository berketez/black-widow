"""v1.11.0 Dalga 5: benchmark_runner _compare_maps preserved işaretleme.

macOS strip sahte-stripping sorunu: export sembolleri korunur, step 4 bunları
"exact" sayıyordu. Artık "preserved" olarak işaretlenir ve F1/accuracy'den
hariç tutulur."""
from __future__ import annotations

import pytest

from tests.benchmark.benchmark_runner import BenchmarkRunner
from tests.benchmark.metrics import AccuracyCalculator

# v1.10.0 H4: benchmark suite'in parcasi, default run'da skip edilir.
pytestmark = pytest.mark.benchmark


class TestPreservedStepFour:
    """_compare_maps step 4: symbol_mapping üzerinden korunan isimler
    preserved olarak işaretlenmeli, exact SAYILMAMALI."""

    def _make_runner(self) -> BenchmarkRunner:
        """Minimal runner: __init__ bypass, sadece _compare_maps için gerekli
        attribute'ları manuel bağla. _compare_maps sadece self.calculator ve
        self._flatten_naming_map (staticmethod) kullanır."""
        runner = BenchmarkRunner.__new__(BenchmarkRunner)
        runner.calculator = AccuracyCalculator()
        runner.output_dir = None
        return runner

    def test_preserved_symbol_tagged_preserved_not_exact(self) -> None:
        """Export korunan sembol preserved olarak işaretlenmeli."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        naming_map: dict[str, str] = {}  # Karadul hiç rename etmedi
        sym_map = {"FUN_401000": "parse_config"}  # Export korunmuş

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        assert len(results) == 1
        assert results[0].match_type == "preserved"
        assert results[0].original == "parse_config"
        assert results[0].recovered == "parse_config"

    def test_genuinely_renamed_still_exact(self) -> None:
        """Karadul naming_map'te isim varsa (step 1) hala exact."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        naming_map = {"FUN_401000": "parse_config"}  # Karadul rename etti
        sym_map: dict[str, str] = {}

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        assert len(results) == 1
        assert results[0].match_type == "exact"

    def test_missing_when_no_source(self) -> None:
        """Hem naming_map hem sym_map boş -> missing."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        results = runner._compare_maps(ground_truth, {}, {})
        assert len(results) == 1
        assert results[0].match_type == "missing"

    def test_wrong_name_still_wrong(self) -> None:
        """Karadul yanlış isim vermiş -> wrong."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        naming_map = {"FUN_401000": "totally_unrelated_xyz"}
        sym_map: dict[str, str] = {}

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        assert len(results) == 1
        assert results[0].match_type == "wrong"

    def test_mixed_preserved_and_renamed(self) -> None:
        """Karışık: bazı preserved, bazı rename, bazı missing."""
        runner = self._make_runner()
        ground_truth = {
            "FUN_401000": "parse_config",
            "FUN_401100": "send_packet",
            "FUN_401200": "encrypt_buffer",
        }
        naming_map = {"FUN_401100": "send_packet"}  # Bu rename (exact)
        sym_map = {"FUN_401000": "parse_config"}  # Bu preserved
        # FUN_401200 -> missing

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        kinds = sorted(r.match_type for r in results)
        assert kinds == ["exact", "missing", "preserved"]

    def test_preserved_has_score_zero(self) -> None:
        """Preserved sonucun score'u 0.0 olmalı (F1 TP sayılmaması için)."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        naming_map: dict[str, str] = {}
        sym_map = {"FUN_401000": "parse_config"}

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        assert results[0].score == 0.0

    def test_preserved_skipped_when_sym_name_is_placeholder(self) -> None:
        """sym_map değeri FUN_ ile başlıyorsa preserved değil, missing devam."""
        runner = self._make_runner()
        ground_truth = {"FUN_401000": "parse_config"}
        naming_map: dict[str, str] = {}
        # sym_map'te yine placeholder var — korunmuş sembol değil
        sym_map = {"FUN_401000": "FUN_401000"}

        results = runner._compare_maps(ground_truth, naming_map, sym_map)
        assert len(results) == 1
        # Preserved tetiklenmemeli; step 5 placeholder düşer -> missing/wrong
        assert results[0].match_type != "preserved"
