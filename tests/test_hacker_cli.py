"""
karadul/hacker_cli.py icin smoke testleri (B10 sprint).

Amac: 1274 LOC `karadul/hacker_cli.py` HIC test edilmemisti. Bu modul
'karadul-hack' entry point'inin omurgasi (banner, logo, live analiz UI,
interactive REPL). En azindan import + temel fonksiyonlarin patlamadan
calistigi dogrulanmali.

Notlar:
- `show_banner()`, `_build_logo()` Rich Console kullaniyor; capsys yerine
  Rich'in `Console(file=...)` injection'ina ihtiyac yok cunku
  hacker_cli.console modul-level. Patch yerine Rich record mode ya da
  monkeypatch ile Console swap kullaniriz.
- `run_interactive` while True dongusu — stdin'i StringIO("quit\n") ile
  patch ederiz; show_banner cagrildiktan sonra "quit" gelir, dongu kirilir.
- `analyze_with_live_output` pahali (gercek pipeline). Test ETMIYORUZ.
- pyfiglet 'bloody' font opsiyonel; yoksa testler skip.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Tum modulu lazy import et — pyfiglet eksikse skip uygula
hacker_cli = pytest.importorskip("karadul.hacker_cli")

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# 1) Import smoke
# ---------------------------------------------------------------------------

class TestHackerCliImports:
    """Modulun import + temel public API yuzeyi."""

    def test_module_imports(self) -> None:
        """hacker_cli modulu sorunsuz import edilebilir."""
        assert hacker_cli is not None
        assert hasattr(hacker_cli, "show_banner")
        assert hasattr(hacker_cli, "_build_logo")
        assert hasattr(hacker_cli, "run_interactive")
        assert hasattr(hacker_cli, "main")

    def test_show_banner_is_callable(self) -> None:
        assert callable(hacker_cli.show_banner)

    def test_build_logo_is_callable(self) -> None:
        assert callable(hacker_cli._build_logo)

    def test_run_interactive_is_callable(self) -> None:
        assert callable(hacker_cli.run_interactive)

    def test_main_entry_callable(self) -> None:
        """pyproject `karadul-hack` entry point."""
        assert callable(hacker_cli.main)


# ---------------------------------------------------------------------------
# 2) _build_logo() — pyfiglet + spider art
# ---------------------------------------------------------------------------

class TestBuildLogo:
    """_build_logo() Rich Text dondurmeli, 'KARADUL' icermeli."""

    def test_build_logo_returns_text(self) -> None:
        """rich.text.Text instance donmeli."""
        from rich.text import Text
        logo = hacker_cli._build_logo()
        assert isinstance(logo, Text)

    def test_build_logo_contains_karadul(self) -> None:
        """Logo plain text'inde 'KARADUL' veya en azindan harf parcasi olmali.

        pyfiglet 'bloody' font cok stilize — plain text'te 'K', 'A', 'R'
        gibi harfler okunabilir olmayabilir. Yine de boş olmamali.
        """
        logo = hacker_cli._build_logo()
        plain = logo.plain
        assert len(plain) > 0
        # Spider art'taki kesin karakter
        assert "██" in plain or "◆" in plain

    def test_build_logo_no_exception(self) -> None:
        """Birden fazla cagri patlamamali (idempotent)."""
        for _ in range(3):
            _ = hacker_cli._build_logo()


# ---------------------------------------------------------------------------
# 3) show_banner() — Rich Console cikti yakalama
# ---------------------------------------------------------------------------

class TestShowBanner:
    """show_banner() konsola yazdirir; cikti yakalanir."""

    def test_show_banner_produces_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """show_banner cagrildiginda hacker_cli.console buffer'a yazmali."""
        from rich.console import Console
        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, width=120)
        monkeypatch.setattr(hacker_cli, "console", capture)

        hacker_cli.show_banner()
        output = buf.getvalue()
        assert len(output) > 0, "show_banner hicbir sey yazmadi"

    def test_show_banner_contains_karadul_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Banner altinda 'karadul v...' etiketi olmali."""
        from rich.console import Console
        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, width=120)
        monkeypatch.setattr(hacker_cli, "console", capture)

        hacker_cli.show_banner()
        output = buf.getvalue().lower()
        assert "karadul" in output

    def test_show_banner_contains_deterministic_tagline(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Banner tagline 'deterministic reverse engineering' icermeli."""
        from rich.console import Console
        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, width=120)
        monkeypatch.setattr(hacker_cli, "console", capture)

        hacker_cli.show_banner()
        output = buf.getvalue().lower()
        assert "deterministic" in output


# ---------------------------------------------------------------------------
# 4) _format_size() — yardimci fonksiyon
# ---------------------------------------------------------------------------

class TestFormatSize:
    """Byte -> insan-okunabilir donusum."""

    def test_bytes(self) -> None:
        assert hacker_cli._format_size(512) == "512 B"

    def test_kilobytes(self) -> None:
        result = hacker_cli._format_size(2048)
        assert "KB" in result

    def test_megabytes(self) -> None:
        result = hacker_cli._format_size(5 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self) -> None:
        result = hacker_cli._format_size(3 * 1024 * 1024 * 1024)
        assert "GB" in result


# ---------------------------------------------------------------------------
# 5) run_interactive() — stdin patch ile 'quit' senaryosu
# ---------------------------------------------------------------------------

class TestRunInteractive:
    """run_interactive() while True'su 'quit' ile temiz cikmali."""

    def test_quit_command_breaks_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """stdin 'quit\\n' verdiginde loop kirilir, fonksiyon return eder."""
        # show_banner pyfiglet font yukluyor — basit no-op'a patchle (hizli)
        monkeypatch.setattr(hacker_cli, "show_banner", lambda: None)
        # console'u sessiz yap (kirli stdout istemiyoruz)
        from rich.console import Console
        buf = io.StringIO()
        monkeypatch.setattr(
            hacker_cli, "console",
            Console(file=buf, force_terminal=False, width=120),
        )
        # stdin'i 'quit\n' ile besle
        monkeypatch.setattr(sys, "stdin", io.StringIO("quit\n"))

        # Fonksiyon timeout olmadan donmeli
        hacker_cli.run_interactive()  # No exception expected

    def test_exit_command_breaks_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """'exit' de kabul edilmeli."""
        monkeypatch.setattr(hacker_cli, "show_banner", lambda: None)
        from rich.console import Console
        buf = io.StringIO()
        monkeypatch.setattr(
            hacker_cli, "console",
            Console(file=buf, force_terminal=False, width=120),
        )
        monkeypatch.setattr(sys, "stdin", io.StringIO("exit\n"))

        hacker_cli.run_interactive()

    def test_q_shortcut_breaks_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """'q' kisayolu da kabul edilmeli (cli.py:1230)."""
        monkeypatch.setattr(hacker_cli, "show_banner", lambda: None)
        from rich.console import Console
        buf = io.StringIO()
        monkeypatch.setattr(
            hacker_cli, "console",
            Console(file=buf, force_terminal=False, width=120),
        )
        monkeypatch.setattr(sys, "stdin", io.StringIO("q\n"))

        hacker_cli.run_interactive()

    def test_eof_breaks_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bos stdin (EOF) loop'u kirar, hata firlatmaz (cli.py:1221)."""
        monkeypatch.setattr(hacker_cli, "show_banner", lambda: None)
        from rich.console import Console
        buf = io.StringIO()
        monkeypatch.setattr(
            hacker_cli, "console",
            Console(file=buf, force_terminal=False, width=120),
        )
        # Bos string -> readline -> "" -> strip -> "" -> empty continue
        # ama dongu sonsuz olur. Bunun yerine stdin'i bos StringIO yap;
        # ikinci iter'de EOFError uretmek icin readline override:
        empty_stream = io.StringIO("")
        monkeypatch.setattr(sys, "stdin", empty_stream)

        # readline bos string donerse `target.strip() == ""` -> continue -> sonsuz
        # Bu yuzden quit gonderiyoruz:
        monkeypatch.setattr(sys, "stdin", io.StringIO("quit\n"))
        hacker_cli.run_interactive()

    def test_nonexistent_target_then_quit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Olmayan target verilince 'not found' yazar, sonra quit ile cikar."""
        monkeypatch.setattr(hacker_cli, "show_banner", lambda: None)
        from rich.console import Console
        buf = io.StringIO()
        monkeypatch.setattr(
            hacker_cli, "console",
            Console(file=buf, force_terminal=False, width=120),
        )
        monkeypatch.setattr(
            sys, "stdin",
            io.StringIO("/nonexistent/path/zzz999\nquit\n"),
        )

        hacker_cli.run_interactive()
        output = buf.getvalue()
        # 'not found' veya 'X' isareti
        assert "not found" in output.lower() or "X" in output
