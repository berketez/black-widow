"""v1.15.5 F1-bug fix testleri.

Berke 2026-05-13: v1.11.0 P4 "preserved" patch yetersiz buldu. GT dongusu
sadece nm export sembollerini geziyordu; karadul'un asil rename ettigi
FUN_xxx fonksiyonlari hic olculmuyordu. renamed_total=0 iken renamed_f1 =
global_f1 atanmasi YALAN ÖLÇÜMDÜ. Bu test dosyasi 4 yeni davranisi
dogrulanir:

1. `unresolved_funs` GT'ye katiliyor mu? (asil challenge)
2. `renamed_total=0` iken `renamed_f1 = None` (NaN) — global kopyalama YOK.
3. `calculate_fun_residue_from_ghidra` ghidra listesi uzerinden olcuyor mu?
4. `ground_truth_breakdown` JSON'da dogru sayilar gosteriyor mu?
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.benchmark.benchmark_runner import BenchmarkRunner
from tests.benchmark.metrics import AccuracyCalculator, NamingResult


class TestUnresolvedFunsInGT:
    """v1.15.5: Ghidra'nin FUN_xxx olarak biraktigi fonksiyonlar GT'ye girer."""

    def _runner(self) -> BenchmarkRunner:
        r = BenchmarkRunner.__new__(BenchmarkRunner)
        r.calculator = AccuracyCalculator()
        r.output_dir = None
        return r

    def test_unresolved_fun_missing_when_not_renamed(self) -> None:
        """Karadul rename etmediyse missing sayilir."""
        runner = self._runner()
        gt: dict[str, str] = {}  # nm exports yok (stripped binary)
        naming_map: dict[str, str] = {}
        unresolved = {"FUN_100000460", "FUN_100000500"}
        results = runner._compare_maps(gt, naming_map, {}, unresolved_funs=unresolved)
        assert len(results) == 2
        assert all(r.match_type == "missing" for r in results)

    def test_unresolved_fun_partial_when_renamed_meaningfully(self) -> None:
        """BUG #4: Karadul anlamli isim verdi ama GT YOK -> unverified (TP degil).

        Dogrulanamayan isim precision/recall'a girmez (score 0.0, ayri kategori).
        Eskiden partial=0.5 TP sayilip challenge setinde F1'i yapay sisiriyordu.
        """
        runner = self._runner()
        gt: dict[str, str] = {}
        naming_map = {"FUN_100000460": "process_packet"}
        unresolved = {"FUN_100000460", "FUN_100000500"}
        results = runner._compare_maps(gt, naming_map, {}, unresolved_funs=unresolved)
        types = sorted(r.match_type for r in results)
        assert types == ["missing", "unverified"]
        # process_packet anlamli ama GT'si yok -> unverified (dogrulanamaz)
        recovered_names = {r.recovered for r in results}
        assert "process_packet" in recovered_names

    def test_unresolved_does_not_double_count_with_nm(self) -> None:
        """FUN_xxx hem nm hem unresolved'da varsa cift sayilmaz."""
        runner = self._runner()
        gt = {"FUN_100000460": "main"}  # nm de bunu biliyor
        naming_map = {"FUN_100000460": "main"}
        unresolved = {"FUN_100000460", "FUN_100000500"}
        results = runner._compare_maps(gt, naming_map, {}, unresolved_funs=unresolved)
        # Sadece 2 sonuc: nm'den main (exact) + unresolved'dan 500 (missing)
        assert len(results) == 2

    def test_unresolved_empty_does_not_break(self) -> None:
        """unresolved_funs=None / boş -> eski davranis."""
        runner = self._runner()
        gt = {"FUN_401000": "parse"}
        results = runner._compare_maps(gt, {"FUN_401000": "parse"}, {}, unresolved_funs=None)
        assert len(results) == 1
        assert results[0].match_type == "exact"


class TestRenamedF1NoneWhenZeroTotal:
    """v1.15.5: renamed_total=0 iken renamed_f1=None (global kopyalama YASAK)."""

    def test_all_missing_renamed_f1_is_zero_not_global(self) -> None:
        """Hepsi missing -> renamed_total=N>0 ama TP=0 -> f1=0.0 (None değil)."""
        calc = AccuracyCalculator()
        results = [
            NamingResult("FUN_1", "FUN_1", 0.0, "missing"),
            NamingResult("FUN_2", "FUN_2", 0.0, "missing"),
        ]
        m = calc.calculate_metrics(results)
        assert m.renamed_total == 2
        assert m.renamed_f1 == 0.0  # gercek olcum

    def test_all_preserved_renamed_f1_is_none(self) -> None:
        """Hepsi preserved -> renamed_total=0 -> renamed_f1=None.

        Berke'nin asıl bug ornegi: nm export sembolleri preserved
        isaretleniyor, naming_map'te baska sembol yok -> renamed_total=0.
        Eski kod: renamed_f1 = global_f1 (TANIMSIZ -> 0.0 ama F1=1.0
        ortaya cikiyordu eger TP varsa). Yeni kod: None.
        """
        calc = AccuracyCalculator()
        results = [
            NamingResult("a", "a", 0.0, "preserved"),
            NamingResult("b", "b", 0.0, "preserved"),
        ]
        m = calc.calculate_metrics(results)
        assert m.renamed_total == 0
        assert m.renamed_f1 is None
        assert m.renamed_precision is None
        assert m.renamed_recall is None
        assert m.renamed_accuracy is None

    def test_to_dict_renamed_f1_is_nan_string(self) -> None:
        """JSON'da renamed_f1=None ise 'NaN' string'i olarak yazilir."""
        calc = AccuracyCalculator()
        results = [NamingResult("a", "a", 0.0, "preserved")]
        m = calc.calculate_metrics(results)
        d = m.to_dict()
        assert d["renamed_f1"] == "NaN"
        assert d["renamed_precision"] == "NaN"
        assert d["renamed_recall"] == "NaN"
        assert d["renamed_accuracy"] == "NaN"

    def test_summary_shows_nan(self) -> None:
        """summary() string'inde NaN gozukmeli."""
        calc = AccuracyCalculator()
        m = calc.calculate_metrics([NamingResult("a", "a", 0.0, "preserved")])
        s = m.summary()
        assert "NaN" in s


class TestFunResidueFromGhidra:
    """v1.15.5: calculate_fun_residue_from_ghidra ghidra listesi uzerinden."""

    def test_empty_ghidra_list(self) -> None:
        calc = AccuracyCalculator()
        assert calc.calculate_fun_residue_from_ghidra([], {"FUN_1": "main"}) == 0.0

    def test_all_renamed(self) -> None:
        """Tum FUN_xxx isimlendirilmis -> %0 residue."""
        calc = AccuracyCalculator()
        ghidra = ["FUN_100000460", "FUN_100000500"]
        naming_map = {"FUN_100000460": "process_pkt", "FUN_100000500": "validate"}
        assert calc.calculate_fun_residue_from_ghidra(ghidra, naming_map) == 0.0

    def test_half_renamed(self) -> None:
        calc = AccuracyCalculator()
        ghidra = ["FUN_100000460", "FUN_100000500"]
        naming_map = {"FUN_100000460": "process_pkt"}  # 500 hala FUN_xxx
        assert calc.calculate_fun_residue_from_ghidra(ghidra, naming_map) == 50.0

    def test_ghidra_already_named_not_residue(self) -> None:
        """Ghidra zaten '_main' verdi -> residue degil, denominator'da kalir."""
        calc = AccuracyCalculator()
        ghidra = ["_main", "FUN_100000460"]
        naming_map: dict[str, str] = {}  # karadul hicbir sey rename etmedi
        # _main residue degil, FUN_460 residue. 1/2 = %50.
        assert calc.calculate_fun_residue_from_ghidra(ghidra, naming_map) == 50.0

    def test_renamed_to_placeholder_still_residue(self) -> None:
        """Karadul rename etti ama yine placeholder verdi -> residue sayilir."""
        calc = AccuracyCalculator()
        ghidra = ["FUN_100000460"]
        naming_map = {"FUN_100000460": "sub_460"}  # yine placeholder pattern
        assert calc.calculate_fun_residue_from_ghidra(ghidra, naming_map) == 100.0


class TestGroundTruthBreakdownInJSON:
    """v1.15.5: ground_truth_breakdown JSON'da kaynak dagilimini gosterir."""

    def test_breakdown_in_metrics_to_dict(self) -> None:
        calc = AccuracyCalculator()
        m = calc.calculate_metrics([NamingResult("a", "a", 1.0, "exact")])
        m.ground_truth_breakdown = {"from_nm": 5, "from_fun_xxx": 100, "total": 105}
        d = m.to_dict()
        assert d["ground_truth_breakdown"] == {
            "from_nm": 5, "from_fun_xxx": 100, "total": 105,
        }

    def test_breakdown_populated_by_runner(self, tmp_path: Path) -> None:
        """run_mock workspace_dir varsa breakdown'i doldurur."""
        ws = tmp_path / "ws"
        (ws / "static").mkdir(parents=True)
        # ghidra_functions.json: 1 named + 2 unresolved
        (ws / "static" / "ghidra_functions.json").write_text(json.dumps({
            "functions": [
                {"name": "_main", "address": "0x100000460"},
                {"name": "FUN_100000500", "address": "0x100000500"},
                {"name": "FUN_100000600", "address": "0x100000600"},
            ],
        }))

        runner = BenchmarkRunner()
        gt = {"FUN_100000460": "main"}  # nm'den 1
        naming_map = {"FUN_100000500": "validate_input"}  # 500'u rename etti

        result = runner.run_mock(gt, naming_map, workspace_dir=ws)
        bd = result.metrics.ground_truth_breakdown
        assert bd["from_nm"] == 1
        assert bd["from_fun_xxx"] == 2  # FUN_500 + FUN_600
        assert bd["total"] == 3

    def test_breakdown_top_level_in_result_dict(self, tmp_path: Path) -> None:
        """BenchmarkResult.to_dict top-level olarak da gosterir."""
        runner = BenchmarkRunner()
        result = runner.run_mock({"FUN_1": "main"}, {"FUN_1": "main"})
        d = result.to_dict()
        assert "ground_truth_breakdown" in d
        assert d["ground_truth_breakdown"]["from_nm"] == 1
        assert d["ground_truth_breakdown"]["from_fun_xxx"] == 0


class TestCollectUnresolvedFuns:
    """v1.15.5: workspace'den FUN_xxx isimlerini cikarmak."""

    def test_no_workspace_empty_set(self) -> None:
        assert BenchmarkRunner.collect_unresolved_funs(None) == set()

    def test_missing_file_empty_set(self, tmp_path: Path) -> None:
        # static/ var ama ghidra_functions.json yok
        (tmp_path / "static").mkdir()
        assert BenchmarkRunner.collect_unresolved_funs(tmp_path) == set()

    def test_collects_only_fun_prefixed(self, tmp_path: Path) -> None:
        (tmp_path / "static").mkdir()
        (tmp_path / "static" / "ghidra_functions.json").write_text(json.dumps({
            "functions": [
                {"name": "FUN_100000460", "address": "0x100000460"},
                {"name": "_main", "address": "0x100000500"},
                {"name": "FUN_100000600", "address": "0x100000600"},
                {"name": "sub_700", "address": "0x100000700"},
            ],
        }))
        result = BenchmarkRunner.collect_unresolved_funs(tmp_path)
        assert result == {"FUN_100000460", "FUN_100000600"}


@pytest.mark.benchmark
class TestEndToEndF1NoLongerOne:
    """v1.15.5 entegrasyon: Eski sahte F1=1.0 senaryosu artık dogru olculur.

    Senaryo: nm export'lardan 2 sembol preserved (challenge degil), karadul
    naming_map BOSTUR (rename hicbir sey yapmadi), ama ghidra 100 FUN_xxx
    listeliyor. Eski davranis: renamed_total=0 -> renamed_f1 = global_f1
    = (preserved'in cesidine gore) 1.0 veya 0. Yeni davranis: 100 FUN_xxx
    missing olarak GT'ye giriyor -> renamed_f1 = 0.0 (gerçek).
    """

    def test_stripped_binary_no_renames_yields_zero_f1(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        (ws / "static").mkdir(parents=True)
        # 100 unresolved FUN_xxx
        funs = [
            {"name": f"FUN_{0x400000 + i*16:x}", "address": f"0x{0x400000 + i*16:x}"}
            for i in range(100)
        ]
        (ws / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": funs}))

        runner = BenchmarkRunner()
        # nm GT bos (gercekte stripped binary'de export bile cikabilir ama
        # bu test icin temel senaryo: hicbir sey bilinmiyor).
        gt: dict[str, str] = {}
        naming_map: dict[str, str] = {}  # Karadul rename etmedi

        result = runner.run_mock(gt, naming_map, workspace_dir=ws)
        m = result.metrics
        # 100 FUN_xxx GT'ye girdi, hepsi missing
        assert m.total_symbols == 100
        assert m.missing_names == 100
        assert m.preserved_names == 0
        # renamed_total > 0 → renamed_f1 hesaplanir (None degil) ama 0.0
        assert m.renamed_total == 100
        assert m.renamed_f1 == 0.0
        # Global F1 de 0
        assert m.f1 == 0.0
        # Breakdown dogru
        assert m.ground_truth_breakdown == {
            "from_nm": 0, "from_fun_xxx": 100, "total": 100,
        }
