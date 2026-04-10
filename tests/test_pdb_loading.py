"""PDB otomatik yukleme testleri.

Mock-based testler -- gercek Ghidra JVM gerektirmez.
GhidraHeadless._load_pdb_if_available() metodunu test eder.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from karadul.config import Config
from karadul.ghidra.headless import GhidraHeadless


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Varsayilan config."""
    return Config()


@pytest.fixture
def ghidra(config: Config) -> GhidraHeadless:
    """GhidraHeadless instance."""
    return GhidraHeadless(config)


def _make_mock_program():
    """Ghidra Program mock'u olustur."""
    program = MagicMock()
    opts = MagicMock()
    program.getOptions.return_value = opts
    program.startTransaction.return_value = 42
    return program


# ---------------------------------------------------------------------------
# Test: PDB bulunamadiginda False doner
# ---------------------------------------------------------------------------

class TestPdbNotFound:
    """PDB dosyasi yoksa graceful False."""

    def test_pdb_not_found_same_dir(self, ghidra: GhidraHeadless, tmp_path: Path) -> None:
        """Binary dizininde .pdb yoksa False donmeli."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        # .pdb yok
        program = _make_mock_program()
        result = ghidra._load_pdb_if_available(program, binary)
        assert result is False

    def test_pdb_not_found_search_paths(self, tmp_path: Path) -> None:
        """Search path'lerde de PDB yoksa False donmeli."""
        cfg = Config()
        cfg.binary_reconstruction.pdb_search_paths = [
            str(tmp_path / "symbols"),
            str(tmp_path / "other"),
        ]
        gh = GhidraHeadless(cfg)

        binary = tmp_path / "app.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)

        # Dizinleri olustur ama PDB yok
        (tmp_path / "symbols").mkdir()
        (tmp_path / "other").mkdir()

        program = _make_mock_program()
        result = gh._load_pdb_if_available(program, binary)
        assert result is False


# ---------------------------------------------------------------------------
# Test: PDB bulundugunda
# ---------------------------------------------------------------------------

class TestPdbFound:
    """PDB dosyasi bulundugunda yukleme."""

    def test_pdb_found_same_directory(self, ghidra: GhidraHeadless, tmp_path: Path) -> None:
        """Binary ile ayni dizindeki .pdb bulunmali."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ")
        pdb = tmp_path / "test.pdb"
        pdb.write_bytes(b"PDB_DATA")

        program = _make_mock_program()

        # PdbUniversalAnalyzer import hatasini tolere et
        with patch.dict("sys.modules", {
            "ghidra.app.plugin.core.analysis": None,
        }):
            result = ghidra._load_pdb_if_available(program, binary)

        assert result is True
        # Program options'a PDB path set edilmis olmali
        program.getOptions.assert_called_with("Program Information")
        opts = program.getOptions.return_value
        opts.setString.assert_called_once()
        call_args = opts.setString.call_args
        assert call_args[0][0] == "PDB File"
        assert "test.pdb" in call_args[0][1]

    def test_pdb_found_in_search_paths(self, tmp_path: Path) -> None:
        """Config search_paths'teki dizinde PDB bulunmali."""
        sym_dir = tmp_path / "symbols"
        sym_dir.mkdir()

        cfg = Config()
        cfg.binary_reconstruction.pdb_search_paths = [str(sym_dir)]
        gh = GhidraHeadless(cfg)

        binary = tmp_path / "myapp.exe"
        binary.write_bytes(b"MZ")
        # Binary dizininde PDB yok ama search path'te var
        pdb = sym_dir / "myapp.pdb"
        pdb.write_bytes(b"PDB_DATA")

        program = _make_mock_program()
        with patch.dict("sys.modules", {
            "ghidra.app.plugin.core.analysis": None,
        }):
            result = gh._load_pdb_if_available(program, binary)

        assert result is True

    def test_pdb_same_dir_takes_priority(self, tmp_path: Path) -> None:
        """Binary dizinindeki PDB, search path'teki PDB'den once bulunmali."""
        sym_dir = tmp_path / "symbols"
        sym_dir.mkdir()

        cfg = Config()
        cfg.binary_reconstruction.pdb_search_paths = [str(sym_dir)]
        gh = GhidraHeadless(cfg)

        binary = tmp_path / "app.exe"
        binary.write_bytes(b"MZ")

        # Her iki yerde de PDB var
        pdb_local = tmp_path / "app.pdb"
        pdb_local.write_bytes(b"LOCAL")
        pdb_remote = sym_dir / "app.pdb"
        pdb_remote.write_bytes(b"REMOTE")

        program = _make_mock_program()
        with patch.dict("sys.modules", {
            "ghidra.app.plugin.core.analysis": None,
        }):
            result = gh._load_pdb_if_available(program, binary)

        assert result is True
        # Local PDB set edilmis olmali
        opts = program.getOptions.return_value
        set_path = opts.setString.call_args[0][1]
        assert str(tmp_path) in set_path  # local dizin


# ---------------------------------------------------------------------------
# Test: Hata toleransi
# ---------------------------------------------------------------------------

class TestPdbErrorGraceful:
    """PDB yukleme hatalari pipeline'i kirmamali."""

    def test_pdb_load_error_returns_false(self, ghidra: GhidraHeadless, tmp_path: Path) -> None:
        """Program options hata verirse False donmeli, exception firlatmamali."""
        binary = tmp_path / "crash.exe"
        binary.write_bytes(b"MZ")
        pdb = tmp_path / "crash.pdb"
        pdb.write_bytes(b"PDB")

        program = _make_mock_program()
        # startTransaction exception firlatsin
        program.startTransaction.side_effect = RuntimeError("JVM error")

        result = ghidra._load_pdb_if_available(program, binary)
        assert result is False

    def test_pdb_options_write_error(self, ghidra: GhidraHeadless, tmp_path: Path) -> None:
        """setString hatasi graceful handle edilmeli."""
        binary = tmp_path / "broken.exe"
        binary.write_bytes(b"MZ")
        pdb = tmp_path / "broken.pdb"
        pdb.write_bytes(b"PDB")

        program = _make_mock_program()
        opts = program.getOptions.return_value
        opts.setString.side_effect = Exception("Options locked")

        result = ghidra._load_pdb_if_available(program, binary)
        assert result is False
        # endTransaction(False) ile rollback yapilmis olmali
        program.endTransaction.assert_called_with(42, False)


# ---------------------------------------------------------------------------
# Test: Config ile devre disi birakma
# ---------------------------------------------------------------------------

class TestPdbDisabled:
    """pdb_auto_load=False ise PDB aranmamali."""

    def test_pdb_disabled_in_config(self, tmp_path: Path) -> None:
        """pdb_auto_load=False ise _load_pdb_if_available cagrilmamali.

        Bu davranisi _analyze_pyghidra'daki if kontrolu saglar.
        Burada config degerini dogruluyoruz.
        """
        cfg = Config()
        cfg.binary_reconstruction.pdb_auto_load = False
        assert cfg.binary_reconstruction.pdb_auto_load is False

        # pdb_auto_load True ise varsayilan
        cfg2 = Config()
        assert cfg2.binary_reconstruction.pdb_auto_load is True
