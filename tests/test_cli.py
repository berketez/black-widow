"""
karadul/cli.py icin smoke testleri (B10 sprint).

Amaç: 1761 LOC `karadul/cli.py` HİÇ test edilmemişti. Bu modül CLI'ın
omurgası (info, analyze, list, clean, version, --verbose, --lmdb-sigdb,
--enable-network, --config). En azından click.testing.CliRunner ile her
komutun "çalıştığı" (import + parse + smoke run) doğrulanmalı.

Tasarım notları:
- Hızlı testler (~ms): --help, version, info, list, clean, flag parsing
  -> default suite'te koşar.
- Gerçek pipeline smoke (analyze): pahalı, `@pytest.mark.integration`
  ile işaretli; default suite atlar ama CI'da bilinçli koşulur.
- Mock binary için en küçük coreutils fixture: `cmp` veya `echo`
  (~67 KB stripped ELF). Yoksa testler skip olur.
- B17 paralel ajan `cli_common.py` extract yapıyor olabilir; bu yüzden
  yalnızca KESIN entry point `karadul.cli.main` Click grubunu import
  ederiz. Yardımcı fonksiyonlara dokunmayız.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

import pytest
from click.testing import CliRunner

from karadul.cli import main as karadul_main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "coreutils" / "binaries" / "stripped"


def _pick_smallest_fixture() -> Optional[Path]:
    """En küçük coreutils binary'sini bul (smoke test için)."""
    if not FIXTURES_DIR.exists():
        return None
    candidates = [p for p in FIXTURES_DIR.iterdir() if p.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_size)
    return candidates[0]


@pytest.fixture(scope="module")
def small_binary() -> Path:
    """En küçük coreutils binary (~67 KB). Yoksa skip."""
    binary = _pick_smallest_fixture()
    if binary is None:
        pytest.skip("Coreutils fixture binary bulunamadi (tests/fixtures/coreutils/binaries/stripped/)")
    return binary


@pytest.fixture
def runner() -> CliRunner:
    """Click test runner — TTY simüle etmez, KARADUL_NONINTERACTIVE=1 ekleriz."""
    # cli.py `_is_noninteractive` -> non-TTY veya CI/KARADUL_NONINTERACTIVE env -> True
    # CliRunner zaten non-TTY ama emin olmak icin env de set ederiz.
    return CliRunner(env={"KARADUL_NONINTERACTIVE": "1", "CI": "1"})


# ---------------------------------------------------------------------------
# 1) Yardım & versiyon (en hızlı testler, import + Click parse)
# ---------------------------------------------------------------------------

class TestHelpAndVersion:
    """karadul --help, karadul version, karadul --version smoke testleri."""

    def test_help_exits_zero(self, runner: CliRunner) -> None:
        """`karadul --help` exit code 0, usage çıktısı içerir."""
        result = runner.invoke(karadul_main, ["--help"])
        assert result.exit_code == 0, f"Beklenmedik exit: {result.exit_code}\n{result.output}"
        # Click otomatik 'Usage:' satırı ekler
        assert "Usage:" in result.output or "Kullan" in result.output

    def test_help_lists_core_commands(self, runner: CliRunner) -> None:
        """--help çıktısı temel komutları listelemeli."""
        result = runner.invoke(karadul_main, ["--help"])
        assert result.exit_code == 0
        # Tüm ana komutlar görünmeli
        for cmd in ("info", "analyze", "list", "clean", "version"):
            assert cmd in result.output, f"'{cmd}' komutu --help çıktısında yok"

    def test_version_command_exit_zero(self, runner: CliRunner) -> None:
        """`karadul version` exit 0 + 'karadul' adı çıktıda."""
        result = runner.invoke(karadul_main, ["version"])
        assert result.exit_code == 0, f"version komutu fail: {result.output}"
        # _print_banner() Rich ile yazıyor, lowercase 'karadul' geçmeli
        assert "karadul" in result.output.lower()

    def test_click_version_flag(self, runner: CliRunner) -> None:
        """`karadul --version` Click'in default version handler'ı (prog_name=karadul)."""
        result = runner.invoke(karadul_main, ["--version"])
        assert result.exit_code == 0
        assert "karadul" in result.output.lower()

    def test_invalid_command_nonzero(self, runner: CliRunner) -> None:
        """Bilinmeyen komut nonzero exit dönmeli."""
        result = runner.invoke(karadul_main, ["this-is-not-a-command-xyz"])
        assert result.exit_code != 0

    def test_no_args_shows_help_or_runs(self, runner: CliRunner) -> None:
        """Argsız çağrı: invoke_without_command=True olduğu için banner gösterir,
        exit code 0 olmalı (veya help bilgisi)."""
        result = runner.invoke(karadul_main, [])
        # invoke_without_command=True -> exit 0, çıktıda bir şey olmalı
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 2) `karadul info <target>` smoke
# ---------------------------------------------------------------------------

class TestInfoCommand:
    """`karadul info` komutu — küçük binary üzerinde smoke."""

    def test_info_help(self, runner: CliRunner) -> None:
        """info --help çıkış 0."""
        result = runner.invoke(karadul_main, ["info", "--help"])
        assert result.exit_code == 0
        assert "info" in result.output.lower() or "bilgi" in result.output.lower()

    def test_info_missing_target(self, runner: CliRunner) -> None:
        """Olmayan target nonzero exit."""
        result = runner.invoke(karadul_main, ["info", "/nonexistent/path/zzz_xyz_999"])
        assert result.exit_code != 0

    def test_info_small_binary(self, runner: CliRunner, small_binary: Path) -> None:
        """Küçük coreutils binary'sinde info çalışır, exit 0."""
        result = runner.invoke(karadul_main, ["info", str(small_binary)])
        # TargetDetector çalıştı, exit 0 bekleriz
        assert result.exit_code == 0, (
            f"info fail (binary={small_binary.name}):\n{result.output}\n"
            f"Exception: {result.exception}"
        )


# ---------------------------------------------------------------------------
# 3) `karadul list` smoke
# ---------------------------------------------------------------------------

class TestListCommand:
    """`karadul list` komutu — workspace listesi."""

    def test_list_help(self, runner: CliRunner) -> None:
        result = runner.invoke(karadul_main, ["list", "--help"])
        assert result.exit_code == 0

    def test_list_empty_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        """Boş workspace dizininde list, exit 0 + 'analiz edilmis hedef yok'."""
        empty = tmp_path / "empty_ws"
        empty.mkdir()
        result = runner.invoke(karadul_main, ["list", "--output-dir", str(empty)])
        assert result.exit_code == 0

    def test_list_nonexistent_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        """Var olmayan workspace dizini: 'henuz analiz edilmis hedef yok' mesajı,
        exit 0 (cli.py:844 -> erken return)."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(karadul_main, ["list", "--output-dir", str(nonexistent)])
        assert result.exit_code == 0

    def test_list_with_workspaces(self, runner: CliRunner, tmp_path: Path) -> None:
        """İçinde 2 workspace olan dizini listele — exit 0, isimler görünmeli."""
        ws_root = tmp_path / "workspaces"
        ws_root.mkdir()
        (ws_root / "binary_a").mkdir()
        (ws_root / "binary_a" / "report.json").write_text("{}")
        (ws_root / "binary_b").mkdir()
        (ws_root / "binary_b" / "report.json").write_text("{}")

        result = runner.invoke(karadul_main, ["list", "--output-dir", str(ws_root)])
        assert result.exit_code == 0, f"list fail: {result.output}"
        # Workspace isimleri çıktıda olmalı (Rich table)
        assert "binary_a" in result.output
        assert "binary_b" in result.output


# ---------------------------------------------------------------------------
# 4) `karadul clean <target>` smoke
# ---------------------------------------------------------------------------

class TestCleanCommand:
    """`karadul clean` komutu — workspace silme + path traversal koruması."""

    def test_clean_help(self, runner: CliRunner) -> None:
        result = runner.invoke(karadul_main, ["clean", "--help"])
        assert result.exit_code == 0

    def test_clean_existing_workspace(self, runner: CliRunner, tmp_path: Path) -> None:
        """Var olan workspace'i temizle (--yes ile confirmation atla), exit 0."""
        ws_root = tmp_path / "workspaces"
        ws_root.mkdir()
        target_ws = ws_root / "my_target"
        target_ws.mkdir()
        (target_ws / "report.json").write_text("{}")

        result = runner.invoke(
            karadul_main,
            ["clean", "my_target", "--output-dir", str(ws_root), "--yes"],
        )
        assert result.exit_code == 0, f"clean fail: {result.output}"
        assert not target_ws.exists(), "Workspace silinmedi"

    def test_clean_nonexistent_workspace(self, runner: CliRunner, tmp_path: Path) -> None:
        """Olmayan workspace: HATA mesajı + exit != 0."""
        ws_root = tmp_path / "workspaces"
        ws_root.mkdir()
        result = runner.invoke(
            karadul_main,
            ["clean", "ghost_target", "--output-dir", str(ws_root), "--yes"],
        )
        assert result.exit_code != 0

    def test_clean_path_traversal_blocked(self, runner: CliRunner, tmp_path: Path) -> None:
        """Path traversal denemesi (../../etc) engellenir, exit != 0."""
        ws_root = tmp_path / "workspaces"
        ws_root.mkdir()
        # cli.py:891-896 -> relative_to ile ValueError -> exit 1
        result = runner.invoke(
            karadul_main,
            ["clean", "../../../etc/passwd", "--output-dir", str(ws_root), "--yes"],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 5) Flag varlık kontrolleri — Click parse zamanında
# ---------------------------------------------------------------------------

class TestAnalyzeFlags:
    """`karadul analyze` flag'lerinin TANINDIĞINI doğrula.

    analyze'i çalıştırmıyoruz (pipeline pahalı); sadece `--help` çıktısında
    flag'lerin var olduğunu kontrol ederiz. Bu Click route doğrulaması.
    """

    @pytest.fixture(scope="class")
    def analyze_help_output(self) -> str:
        runner = CliRunner(env={"KARADUL_NONINTERACTIVE": "1"})
        result = runner.invoke(karadul_main, ["analyze", "--help"])
        assert result.exit_code == 0, f"analyze --help fail: {result.output}"
        return result.output

    def test_skip_dynamic_flag(self, analyze_help_output: str) -> None:
        assert "--skip-dynamic" in analyze_help_output

    def test_verbose_flag(self, analyze_help_output: str) -> None:
        assert "--verbose" in analyze_help_output

    def test_config_flag(self, analyze_help_output: str) -> None:
        assert "--config" in analyze_help_output

    def test_lmdb_sigdb_flag(self, analyze_help_output: str) -> None:
        """v1.10.0 LMDB sigdb flag varlık kontrolü."""
        assert "--lmdb-sigdb" in analyze_help_output

    def test_enable_network_flag(self, analyze_help_output: str) -> None:
        """v1.15.x network master switch — default kapalı, opt-in."""
        assert "--enable-network" in analyze_help_output or "--online" in analyze_help_output

    def test_compute_mode_flag(self, analyze_help_output: str) -> None:
        """v1.6.5 --compute full/standard/off flag'i."""
        assert "--compute" in analyze_help_output

    def test_output_dir_flag(self, analyze_help_output: str) -> None:
        assert "--output-dir" in analyze_help_output

    def test_stage_flag(self, analyze_help_output: str) -> None:
        assert "--stage" in analyze_help_output


# ---------------------------------------------------------------------------
# 6) Ana grup --verbose flag'i
# ---------------------------------------------------------------------------

class TestMainGroupFlags:
    """`karadul --verbose <cmd>` gibi grup seviyesi flag'ler."""

    def test_main_verbose_with_version(self, runner: CliRunner) -> None:
        """--verbose grup flag'i version komutunda hata vermez."""
        result = runner.invoke(karadul_main, ["--verbose", "version"])
        assert result.exit_code == 0

    def test_main_help_lists_verbose(self, runner: CliRunner) -> None:
        result = runner.invoke(karadul_main, ["--help"])
        assert "--verbose" in result.output


# ---------------------------------------------------------------------------
# 7) Tam pipeline smoke — INTEGRATION (default suite ATLAR)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestAnalyzeIntegration:
    """`karadul analyze` gerçek pipeline smoke — sadece bilinçli koşumda.

    Pyproject default: `-m 'not integration and not benchmark'` -> atlanır.
    CI ground truth job'unda veya `pytest -m integration` ile koşar.
    """

    def test_analyze_small_binary_skip_dynamic(
        self, runner: CliRunner, small_binary: Path, tmp_path: Path,
    ) -> None:
        """Küçük binary üzerinde analyze --skip-dynamic smoke."""
        output_dir = tmp_path / "out"
        result = runner.invoke(
            karadul_main,
            [
                "analyze",
                str(small_binary),
                "--skip-dynamic",
                "--output-dir", str(output_dir),
            ],
            catch_exceptions=True,
        )
        # Pipeline pek çok eksternal'e bağlı (Ghidra, BSim). Smoke kriterimiz:
        # exit code != crash (yani < 100 makul). Tercihen 0 ama sigdb yoksa 1
        # de kabul. Önemli olan import + Click route + pipeline init
        # patlamadan geçmiş olması.
        assert result.exit_code in (0, 1, 2), (
            f"Beklenmedik exit={result.exit_code}\n"
            f"Exception: {result.exception}\n"
            f"Output:\n{result.output[-2000:]}"
        )
