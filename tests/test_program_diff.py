"""ProgramDiff modulu testleri.

Gercek Ghidra/PyGhidra gerektirmez -- tum testler mock data veya
gecici JSON fixture'larla calisir.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.config import Config
from karadul.ghidra.program_diff import (
    DiffReport,
    DiffSummary,
    FunctionDiff,
    GhidraProgramDiff,
    _FuncInfo,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Varsayilan Config."""
    return Config()


@pytest.fixture
def differ(config: Config) -> GhidraProgramDiff:
    """GhidraProgramDiff instance'i."""
    return GhidraProgramDiff(config)


@pytest.fixture
def sample_funcs_v1() -> list[dict[str, Any]]:
    """V1 binary icin ornek fonksiyon listesi."""
    return [
        {"name": "main", "entry_point": "0x1000", "size": 256, "instruction_count": 42},
        {"name": "helper", "entry_point": "0x1100", "size": 128, "instruction_count": 20},
        {"name": "old_func", "entry_point": "0x1200", "size": 64, "instruction_count": 10},
        {"name": "stable_func", "entry_point": "0x1300", "size": 32, "instruction_count": 5},
    ]


@pytest.fixture
def sample_funcs_v2() -> list[dict[str, Any]]:
    """V2 binary icin ornek fonksiyon listesi (main degismis, old_func silinmis, new_func eklenmis)."""
    return [
        {"name": "main", "entry_point": "0x1000", "size": 300, "instruction_count": 50},
        {"name": "helper", "entry_point": "0x1100", "size": 128, "instruction_count": 20},
        {"name": "new_func", "entry_point": "0x1400", "size": 96, "instruction_count": 15},
        {"name": "stable_func", "entry_point": "0x1300", "size": 32, "instruction_count": 5},
    ]


@pytest.fixture
def v1_json(tmp_path: Path, sample_funcs_v1: list[dict]) -> Path:
    """V1 fonksiyon JSON fixture dosyasi."""
    path = tmp_path / "v1_functions.json"
    path.write_text(json.dumps(sample_funcs_v1, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def v2_json(tmp_path: Path, sample_funcs_v2: list[dict]) -> Path:
    """V2 fonksiyon JSON fixture dosyasi."""
    path = tmp_path / "v2_functions.json"
    path.write_text(json.dumps(sample_funcs_v2, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def identical_json(tmp_path: Path, sample_funcs_v1: list[dict]) -> Path:
    """V1 ile ayni fonksiyon JSON (degisiklik yok)."""
    path = tmp_path / "v1_copy_functions.json"
    path.write_text(json.dumps(sample_funcs_v1, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def empty_json(tmp_path: Path) -> Path:
    """Bos fonksiyon JSON dosyasi."""
    path = tmp_path / "empty_functions.json"
    path.write_text(json.dumps([], indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Dataclass testleri
# ---------------------------------------------------------------------------

class TestFunctionDiff:
    """FunctionDiff dataclass testleri."""

    def test_valid_statuses(self) -> None:
        """Gecerli status degerleri kabul edilmeli."""
        for status in ("added", "removed", "modified", "unchanged"):
            fd = FunctionDiff(name="f", address1="0x1", address2="0x2", status=status)
            assert fd.status == status

    def test_invalid_status_raises(self) -> None:
        """Gecersiz status ValueError vermeli."""
        with pytest.raises(ValueError, match="Gecersiz status"):
            FunctionDiff(name="f", address1="0x1", address2="0x2", status="invalid")

    def test_added_function_has_no_address1(self) -> None:
        """Eklenen fonksiyonun address1'i None olmali."""
        fd = FunctionDiff(name="new_f", address1=None, address2="0x2000", status="added")
        assert fd.address1 is None
        assert fd.address2 == "0x2000"

    def test_removed_function_has_no_address2(self) -> None:
        """Silinen fonksiyonun address2'si None olmali."""
        fd = FunctionDiff(name="old_f", address1="0x1000", address2=None, status="removed")
        assert fd.address1 == "0x1000"
        assert fd.address2 is None

    def test_size_change_default(self) -> None:
        """size_change varsayilan 0 olmali."""
        fd = FunctionDiff(name="f", address1="0x1", address2="0x2", status="unchanged")
        assert fd.size_change == 0

    def test_instruction_diff_default_none(self) -> None:
        """instruction_diff varsayilan None olmali."""
        fd = FunctionDiff(name="f", address1="0x1", address2="0x2", status="unchanged")
        assert fd.instruction_diff is None

    def test_asdict_roundtrip(self) -> None:
        """asdict ile serializasyon dogru calismali."""
        fd = FunctionDiff(
            name="test", address1="0x100", address2="0x200",
            status="modified", size_change=16, instruction_diff=3,
        )
        d = asdict(fd)
        assert d["name"] == "test"
        assert d["size_change"] == 16
        assert d["instruction_diff"] == 3


class TestDiffSummary:
    """DiffSummary dataclass testleri."""

    def test_defaults_are_zero(self) -> None:
        """Tum degerler varsayilan 0 olmali."""
        s = DiffSummary()
        assert s.functions_added == 0
        assert s.functions_removed == 0
        assert s.functions_modified == 0
        assert s.functions_unchanged == 0
        assert s.total_functions_1 == 0
        assert s.total_functions_2 == 0

    def test_change_rate_no_functions(self) -> None:
        """Fonksiyon yoksa change_rate 0.0 olmali."""
        s = DiffSummary()
        assert s.change_rate == 0.0

    def test_change_rate_with_changes(self) -> None:
        """Degisiklik varsa change_rate dogru hesaplanmali."""
        s = DiffSummary(
            functions_added=1,
            functions_removed=1,
            functions_modified=2,
            functions_unchanged=6,
            total_functions_1=10,
            total_functions_2=10,
        )
        # changed = 1 + 1 + 2 = 4, max(10, 10) = 10 -> 0.4
        assert abs(s.change_rate - 0.4) < 1e-9

    def test_change_rate_all_new(self) -> None:
        """Tamamen yeni binary: tum fonksiyonlar eklenmis."""
        s = DiffSummary(
            functions_added=5,
            total_functions_1=0,
            total_functions_2=5,
        )
        assert s.change_rate == 1.0


class TestDiffReport:
    """DiffReport dataclass testleri."""

    def test_basic_creation(self) -> None:
        """Temel DiffReport olusturma."""
        report = DiffReport(
            binary1_name="v1.bin",
            binary2_name="v2.bin",
            summary=DiffSummary(functions_added=2),
        )
        assert report.binary1_name == "v1.bin"
        assert report.binary2_name == "v2.bin"
        assert report.summary.functions_added == 2
        assert report.function_diffs == []
        assert report.duration_seconds == 0.0

    def test_with_diffs(self) -> None:
        """DiffReport function_diffs ile."""
        diffs = [
            FunctionDiff("f1", "0x1", "0x1", "unchanged"),
            FunctionDiff("f2", None, "0x2", "added"),
        ]
        report = DiffReport(
            binary1_name="a.bin",
            binary2_name="b.bin",
            summary=DiffSummary(functions_added=1, functions_unchanged=1),
            function_diffs=diffs,
        )
        assert len(report.function_diffs) == 2


# ---------------------------------------------------------------------------
# _match_functions testleri
# ---------------------------------------------------------------------------

class TestMatchFunctions:
    """Fonksiyon eslestirme algoritmasi testleri."""

    def test_exact_match_by_name(self) -> None:
        """Ayni isimli fonksiyonlar eslestirilmeli."""
        f1 = [
            _FuncInfo("main", "0x1000", 100),
            _FuncInfo("helper", "0x2000", 50),
        ]
        f2 = [
            _FuncInfo("main", "0x1000", 120),
            _FuncInfo("helper", "0x2000", 50),
        ]
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 2
        assert len(added) == 0
        assert len(removed) == 0

    def test_added_functions(self) -> None:
        """Yeni fonksiyonlar 'added' listesinde olmali."""
        f1 = [_FuncInfo("main", "0x1000", 100)]
        f2 = [
            _FuncInfo("main", "0x1000", 100),
            _FuncInfo("new_func", "0x3000", 80),
        ]
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 1
        assert len(added) == 1
        assert added[0].name == "new_func"
        assert len(removed) == 0

    def test_removed_functions(self) -> None:
        """Silinen fonksiyonlar 'removed' listesinde olmali."""
        f1 = [
            _FuncInfo("main", "0x1000", 100),
            _FuncInfo("old_func", "0x2000", 60),
        ]
        f2 = [_FuncInfo("main", "0x1000", 100)]
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 1
        assert len(added) == 0
        assert len(removed) == 1
        assert removed[0].name == "old_func"

    def test_modified_detection(self, differ: GhidraProgramDiff) -> None:
        """Boyut degisen fonksiyon modified olarak islenmeli (diff_from_json uzerinden)."""
        f1 = [_FuncInfo("main", "0x1000", 100, 20)]
        f2 = [_FuncInfo("main", "0x1000", 150, 30)]
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 1
        f1_m, f2_m = matched[0]
        assert f2_m.size - f1_m.size == 50
        assert f2_m.instruction_count - f1_m.instruction_count == 10

    def test_empty_lists(self) -> None:
        """Bos listeler hata vermemeli."""
        matched, added, removed = GhidraProgramDiff._match_functions([], [])
        assert matched == []
        assert added == []
        assert removed == []

    def test_address_proximity_matching(self) -> None:
        """Farkli isimli ama yakin adresli fonksiyonlar eslestirilmeli."""
        # f1'de FUN_1000, f2'de renamed_1010 -- adres farki 16 (< 256 threshold)
        f1 = [_FuncInfo("FUN_00001000", "0x1000", 100)]
        f2 = [_FuncInfo("renamed_func", "0x1010", 110)]
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 1
        assert len(added) == 0
        assert len(removed) == 0

    def test_address_too_far_no_match(self) -> None:
        """Cok uzak adresli fonksiyonlar eslesmemeli."""
        f1 = [_FuncInfo("func_a", "0x1000", 100)]
        f2 = [_FuncInfo("func_b", "0x9000", 100)]  # 0x8000 = 32768 > 256
        matched, added, removed = GhidraProgramDiff._match_functions(f1, f2)
        assert len(matched) == 0
        assert len(added) == 1
        assert len(removed) == 1


# ---------------------------------------------------------------------------
# diff_from_json testleri
# ---------------------------------------------------------------------------

class TestDiffFromJson:
    """JSON-based diff testleri."""

    def test_identical_files(
        self, differ: GhidraProgramDiff, v1_json: Path, identical_json: Path,
    ) -> None:
        """Ayni fonksiyon JSON'lari karsilastirildiginda degisiklik olmamali."""
        report = differ.diff_from_json(v1_json, identical_json)
        assert report.summary.functions_added == 0
        assert report.summary.functions_removed == 0
        assert report.summary.functions_modified == 0
        assert report.summary.functions_unchanged == 4

    def test_with_changes(
        self, differ: GhidraProgramDiff, v1_json: Path, v2_json: Path,
    ) -> None:
        """Farkli JSON'lar: 1 eklenmis, 1 silinmis, 1 degismis, 1 ayni."""
        report = differ.diff_from_json(v1_json, v2_json)
        assert report.summary.functions_added == 1  # new_func
        assert report.summary.functions_removed == 1  # old_func
        assert report.summary.functions_modified == 1  # main (boyut degisti)
        assert report.summary.functions_unchanged == 2  # helper, stable_func

    def test_empty_vs_populated(
        self, differ: GhidraProgramDiff, empty_json: Path, v1_json: Path,
    ) -> None:
        """Bos JSON vs dolu JSON: tum fonksiyonlar eklenmis olmali."""
        report = differ.diff_from_json(empty_json, v1_json)
        assert report.summary.functions_added == 4
        assert report.summary.functions_removed == 0
        assert report.summary.total_functions_1 == 0
        assert report.summary.total_functions_2 == 4

    def test_populated_vs_empty(
        self, differ: GhidraProgramDiff, v1_json: Path, empty_json: Path,
    ) -> None:
        """Dolu JSON vs bos JSON: tum fonksiyonlar silinmis olmali."""
        report = differ.diff_from_json(v1_json, empty_json)
        assert report.summary.functions_added == 0
        assert report.summary.functions_removed == 4
        assert report.summary.total_functions_1 == 4
        assert report.summary.total_functions_2 == 0

    def test_empty_vs_empty(
        self, differ: GhidraProgramDiff, empty_json: Path, tmp_path: Path,
    ) -> None:
        """Iki bos JSON: hicbir degisiklik yok."""
        empty2 = tmp_path / "empty2.json"
        empty2.write_text("[]", encoding="utf-8")
        report = differ.diff_from_json(empty_json, empty2)
        assert report.summary.functions_added == 0
        assert report.summary.functions_removed == 0
        assert report.summary.functions_modified == 0
        assert report.summary.functions_unchanged == 0

    def test_dict_format_json(
        self, differ: GhidraProgramDiff, tmp_path: Path,
    ) -> None:
        """Dict formatinda JSON ({"functions": [...]}) desteklenmeli."""
        json1 = tmp_path / "dict_v1.json"
        json2 = tmp_path / "dict_v2.json"
        json1.write_text(json.dumps({
            "functions": [
                {"name": "f1", "entry_point": "0x100", "size": 50},
            ]
        }), encoding="utf-8")
        json2.write_text(json.dumps({
            "functions": [
                {"name": "f1", "entry_point": "0x100", "size": 80},
                {"name": "f2", "entry_point": "0x200", "size": 30},
            ]
        }), encoding="utf-8")
        report = differ.diff_from_json(json1, json2)
        assert report.summary.functions_added == 1  # f2
        assert report.summary.functions_modified == 1  # f1 boyut degisti

    def test_file_not_found(self, differ: GhidraProgramDiff, tmp_path: Path) -> None:
        """Olmayan dosya FileNotFoundError vermeli."""
        fake = tmp_path / "nonexistent.json"
        real = tmp_path / "real.json"
        real.write_text("[]", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            differ.diff_from_json(fake, real)

    def test_report_has_duration(
        self, differ: GhidraProgramDiff, v1_json: Path, v2_json: Path,
    ) -> None:
        """Rapor duration_seconds >= 0 olmali."""
        report = differ.diff_from_json(v1_json, v2_json)
        assert report.duration_seconds >= 0.0

    def test_report_binary_names(
        self, differ: GhidraProgramDiff, v1_json: Path, v2_json: Path,
    ) -> None:
        """Rapor binary isimlerini JSON dosya stem'lerinden almali."""
        report = differ.diff_from_json(v1_json, v2_json)
        assert report.binary1_name == "v1_functions"
        assert report.binary2_name == "v2_functions"


# ---------------------------------------------------------------------------
# _generate_json_report testi
# ---------------------------------------------------------------------------

class TestGenerateJsonReport:
    """JSON rapor uretim testleri."""

    def test_generates_json_file(self, tmp_path: Path) -> None:
        """diff_report.json dosyasi olusturulmali."""
        report = DiffReport(
            binary1_name="a.bin",
            binary2_name="b.bin",
            summary=DiffSummary(
                functions_added=2,
                functions_removed=1,
                functions_modified=3,
                functions_unchanged=10,
                total_functions_1=14,
                total_functions_2=15,
            ),
            function_diffs=[
                FunctionDiff("new_f", None, "0x2000", "added", size_change=100),
                FunctionDiff("old_f", "0x1000", None, "removed", size_change=-50),
                FunctionDiff("mod_f", "0x1100", "0x1100", "modified", size_change=20, instruction_diff=5),
            ],
            duration_seconds=1.234,
        )

        result_path = GhidraProgramDiff._generate_json_report(report, tmp_path)

        assert result_path.exists()
        assert result_path.name == "diff_report.json"

        data = json.loads(result_path.read_text(encoding="utf-8"))
        assert data["binary1"] == "a.bin"
        assert data["binary2"] == "b.bin"
        assert data["summary"]["functions_added"] == 2
        assert data["summary"]["functions_removed"] == 1
        assert len(data["function_diffs"]) == 3
        assert data["duration_seconds"] == 1.234
        assert "change_rate" in data

    def test_output_dir_created(self, tmp_path: Path) -> None:
        """Cikti dizini yoksa olusturulmali."""
        nested = tmp_path / "a" / "b" / "c"
        report = DiffReport(
            binary1_name="x", binary2_name="y", summary=DiffSummary(),
        )
        result_path = GhidraProgramDiff._generate_json_report(report, nested)
        assert result_path.exists()


# ---------------------------------------------------------------------------
# CLI entegrasyon testi
# ---------------------------------------------------------------------------

class TestCliDiffCommand:
    """CLI diff komutu testleri."""

    def test_diff_command_exists(self) -> None:
        """CLI'da 'diff' komutu tanimli olmali."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        assert "Iki binary arasindaki farklari goster" in result.output

    def test_diff_json_mode_flag(self) -> None:
        """--json-mode flag'i help'te gorunmeli."""
        from click.testing import CliRunner
        from karadul.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--help"])
        assert "--json-mode" in result.output

    def test_diff_json_mode_integration(
        self, v1_json: Path, v2_json: Path, tmp_path: Path,
    ) -> None:
        """JSON modunda diff CLI'dan calistirilabilmeli."""
        from click.testing import CliRunner
        from karadul.cli import main

        output_dir = tmp_path / "cli_output"
        runner = CliRunner()
        result = runner.invoke(main, [
            "diff",
            str(v1_json),
            str(v2_json),
            "--json-mode",
            "-o", str(output_dir),
        ])
        # Rich output icinde raporun yazildigini kontrol et
        # Komut basarisiz olsa bile (config yoksa vb.) en azindan parse etmis olmali
        # Exit code 0 bekleriz (json-mode Ghidra gerektirmez)
        assert result.exit_code == 0, f"CLI hatasi: {result.output}"
        # diff_report.json olusmus olmali
        assert (output_dir / "diff_report.json").exists()
