"""v1.15-A: CoreutilsSuite + parse_nm_dynamic_output testleri.

Sentetik nm cikti ile dynamic symbol parse + suite discovery + aggregate.
Gercek nm subprocess (Linux ELF Mac'te calisamayabilir) sadece smoke skip
testinde dokunulur.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from tests.benchmark.coreutils_suite import (
    CoreutilsBinaryGroundTruth,
    CoreutilsEntry,
    CoreutilsSuite,
    CoreutilsSymbol,
    SuiteAggregate,
    extract_ground_truth,
    parse_nm_dynamic_output,
)


# ---------------------------------------------------------------------------
# nm cikti parse
# ---------------------------------------------------------------------------

class TestNmParse:
    """parse_nm_dynamic_output: ham nm -D ciktisindan symbol cikar."""

    def test_empty_input_returns_empty(self) -> None:
        assert parse_nm_dynamic_output("") == []

    def test_undefined_symbol_no_address(self) -> None:
        out = "                 U __libc_start_main@GLIBC_2.34"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1
        sym = result[0]
        assert sym.name == "__libc_start_main"
        assert sym.symbol_type == "U"
        assert sym.address is None
        assert sym.glibc_version == "GLIBC_2.34"
        assert sym.binding == "GLOBAL"

    def test_defined_text_symbol_with_address(self) -> None:
        out = "0000000000001a3f T main"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1
        sym = result[0]
        assert sym.name == "main"
        assert sym.symbol_type == "T"
        assert sym.address == "0x0000000000001a3f"

    def test_weak_symbol_lowercase_binding(self) -> None:
        out = "                 w _ITM_deregisterTMCloneTable"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1
        sym = result[0]
        assert sym.name == "_ITM_deregisterTMCloneTable"
        assert sym.symbol_type == "W"  # canonicalized uppercase
        assert sym.binding == "WEAK"

    def test_multiple_lines(self) -> None:
        out = (
            "                 U malloc@GLIBC_2.17\n"
            "                 U free@GLIBC_2.17\n"
            "0000000000001234 T do_work\n"
            "                 w __cxa_finalize@GLIBC_2.17\n"
        )
        result = parse_nm_dynamic_output(out)
        assert len(result) == 4
        assert {s.name for s in result} == {
            "malloc", "free", "do_work", "__cxa_finalize",
        }
        assert sum(1 for s in result if s.symbol_type == "T") == 1
        assert sum(1 for s in result if s.symbol_type == "U") == 2
        assert sum(1 for s in result if s.symbol_type == "W") == 1

    def test_blank_lines_ignored(self) -> None:
        out = "\n\n   \n0000000000001000 T foo\n\n"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1

    def test_malformed_lines_skipped(self) -> None:
        out = "this is not nm output\n0000000000001000 T good_symbol\n"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1
        assert result[0].name == "good_symbol"

    def test_glibc_versioned_with_double_at(self) -> None:
        # Sometimes nm uses @@ for default version
        out = "                 U realloc@@GLIBC_2.17"
        result = parse_nm_dynamic_output(out)
        assert len(result) == 1
        assert result[0].name == "realloc"
        assert result[0].glibc_version == "GLIBC_2.17"


# ---------------------------------------------------------------------------
# CoreutilsSuite discovery
# ---------------------------------------------------------------------------


class TestSuiteDiscovery:
    def test_discover_real_fixtures(self) -> None:
        """tests/fixtures/coreutils/binaries/stripped/ -> 30 binary."""
        fixture_dir = (
            Path(__file__).parent / "fixtures" / "coreutils"
            / "binaries" / "stripped"
        )
        if not fixture_dir.is_dir():
            pytest.skip("Coreutils fixture build edilmemis")
        suite = CoreutilsSuite.discover(fixture_dir)
        assert suite.count == 31  # Dockerfile'daki 31 isim listesi
        assert "ls" in suite.names()
        assert "cat" in suite.names()
        assert "cp" in suite.names()
        assert suite.total_size_bytes > 1_000_000  # 1MB+

    def test_discover_with_whitelist(self, tmp_path: Path) -> None:
        # Sahte fixture
        for name in ("a", "b", "c"):
            (tmp_path / name).write_bytes(b"\x7fELF\x00" * 16)
        suite = CoreutilsSuite.discover(tmp_path, whitelist=["a", "c"])
        assert suite.count == 2
        assert suite.names() == ["a", "c"]

    def test_discover_missing_dir_raises(self, tmp_path: Path) -> None:
        ghost = tmp_path / "ghost"
        with pytest.raises(FileNotFoundError):
            CoreutilsSuite.discover(ghost)

    def test_find_returns_entry(self, tmp_path: Path) -> None:
        (tmp_path / "ls").write_bytes(b"\x7fELF" * 16)
        suite = CoreutilsSuite.discover(tmp_path)
        entry = suite.find("ls")
        assert entry is not None
        assert entry.name == "ls"

    def test_find_missing_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / "ls").write_bytes(b"\x7fELF" * 16)
        suite = CoreutilsSuite.discover(tmp_path)
        assert suite.find("nonexistent") is None

    def test_to_dict_serializable(self, tmp_path: Path) -> None:
        (tmp_path / "ls").write_bytes(b"\x7fELF" * 16)
        suite = CoreutilsSuite.discover(tmp_path)
        d = suite.to_dict()
        assert d["count"] == 1
        entries = d["entries"]
        assert isinstance(entries, list)
        assert entries[0]["name"] == "ls"


# ---------------------------------------------------------------------------
# Ground truth (gerçek nm subprocess) — Mac'te skip eğer nm yoksa
# ---------------------------------------------------------------------------


class TestGroundTruthExtraction:
    def test_extract_real_ls_smoke(self, tmp_path: Path) -> None:
        """Gercek ls binary'sinden nm -D ile ground truth cikar (Mac'te
        gnm gerekebilir)."""
        import shutil
        nm_bin = shutil.which("nm") or shutil.which("gnm")
        if nm_bin is None:
            pytest.skip("nm/gnm bulunamadi (binutils kurulu degil)")

        fixture_dir = (
            Path(__file__).parent / "fixtures" / "coreutils"
            / "binaries" / "stripped"
        )
        if not fixture_dir.is_dir():
            pytest.skip("Coreutils fixture build edilmemis")

        ls_path = fixture_dir / "ls"
        if not ls_path.exists():
            pytest.skip("ls fixture eksik")

        entry = CoreutilsEntry(
            name="ls", path=ls_path, size_bytes=ls_path.stat().st_size,
        )
        try:
            gt = extract_ground_truth(entry)
        except RuntimeError as exc:
            # Mac'in default nm'i Linux ELF okuyamayabilir
            pytest.skip(f"nm Linux ELF okuyamadi: {exc}")

        # ls'in dynamic symbol sayisi tipik ~120-130
        # (libc imports + birkac export)
        assert gt.symbol_count > 50
        assert gt.binary_name == "ls"
        # SHA256 deterministic
        assert len(gt.binary_sha256) == 64

    def test_ground_truth_to_dict(self) -> None:
        gt = CoreutilsBinaryGroundTruth(
            binary_name="cat",
            binary_path="/tmp/cat",
            binary_sha256="a" * 64,
            symbols=[
                CoreutilsSymbol(name="malloc", raw_name="malloc",
                                symbol_type="U"),
                CoreutilsSymbol(name="main", raw_name="main",
                                symbol_type="T", address="0x1000"),
            ],
        )
        d = gt.to_dict()
        assert d["symbol_count"] == 2
        assert d["export_count"] == 1
        assert d["import_count"] == 1
        symbols = d["symbols"]
        assert isinstance(symbols, list)
        assert len(symbols) == 2

    def test_name_set_and_imports_set(self) -> None:
        gt = CoreutilsBinaryGroundTruth(
            binary_name="cat",
            binary_path="/tmp/cat",
            binary_sha256="a" * 64,
            symbols=[
                CoreutilsSymbol(name="malloc", raw_name="malloc",
                                symbol_type="U"),
                CoreutilsSymbol(name="free", raw_name="free",
                                symbol_type="U"),
                CoreutilsSymbol(name="main", raw_name="main",
                                symbol_type="T"),
            ],
        )
        assert gt.name_set() == {"malloc", "free", "main"}
        assert gt.imports_set() == {"malloc", "free"}


# ---------------------------------------------------------------------------
# Aggregate metric
# ---------------------------------------------------------------------------


class TestSuiteAggregate:
    def _make_gt(
        self, name: str, sym_types: list[str],
    ) -> CoreutilsBinaryGroundTruth:
        return CoreutilsBinaryGroundTruth(
            binary_name=name,
            binary_path=f"/tmp/{name}",
            binary_sha256="a" * 64,
            symbols=[
                CoreutilsSymbol(name=f"{name}_{i}", raw_name=f"{name}_{i}",
                                symbol_type=t)
                for i, t in enumerate(sym_types)
            ],
        )

    def test_empty_suite_aggregate(self) -> None:
        agg = SuiteAggregate.from_ground_truths([])
        assert agg.binary_count == 0
        assert agg.total_symbols == 0

    def test_aggregate_three_binaries(self) -> None:
        gts = [
            self._make_gt("ls", ["T", "U", "U"]),       # 3 sym
            self._make_gt("cat", ["U", "U"]),           # 2 sym
            self._make_gt("cp", ["T", "T", "U", "W"]),  # 4 sym
        ]
        agg = SuiteAggregate.from_ground_truths(gts)
        assert agg.binary_count == 3
        assert agg.total_symbols == 9
        assert agg.total_exports == 3  # 1 + 0 + 2
        assert agg.total_imports == 5  # 2 + 2 + 1
        assert agg.min_symbols == 2
        assert agg.max_symbols == 4
        assert agg.avg_symbols_per_binary == pytest.approx(3.0)

    def test_to_dict_keys(self) -> None:
        gts = [self._make_gt("ls", ["T"])]
        agg = SuiteAggregate.from_ground_truths(gts)
        d = agg.to_dict()
        for key in [
            "binary_count", "total_symbols", "total_exports",
            "total_imports", "avg_symbols_per_binary",
            "min_symbols", "max_symbols",
        ]:
            assert key in d
