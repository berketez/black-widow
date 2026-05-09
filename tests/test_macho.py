"""MachOAnalyzer unit testleri.

Test gruplari:
1. ``_stat_is_regular`` -- TOCTOU yardimci, regular/symlink/dir/missing branch'leri
2. ``MachOAnalyzer.__init__`` -- Backend factory chain, fallback davranisi
3. ``_run_otool_libs`` -- otool -L parse, library path extraction
4. ``_run_otool_load_commands`` -- LC_LOAD_DYLIB / LC_RPATH parse, malformed
5. ``_run_nm`` -- Symbol parsing (T/D/B/U flag), undefined sym
6. ``_run_lief`` -- LIEF available/missing, exception path
7. ``_extract_bun_js`` -- BUN bundle regex, raw + zlib branch
8. ``_extract_strings_mmap`` -- mmap edge case, ASCII filter
9. ``_run_ghidra`` + ``_run_ghidra_legacy`` -- pipeline outputs, fallback
10. ``analyze_static`` -- 5 target type dispatch, 7-stage pipeline integration
11. ``deobfuscate`` -- Stub davranis (smoke)

Mock prensipleri:
- subprocess.run / safe_run: monkeypatch ile fake output
- lief: import edilmeden once attribute patch (sys.modules / module attr)
- GhidraHeadless: FakeGhidraHeadless class ile constructor patch

Tum sentetik veri test_macho.py icinde (conftest.py'a yeni helper eklenmedi).
"""

from __future__ import annotations

import io
import json
import logging
import os
import stat as _stat_module
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.macho import MachOAnalyzer, _stat_is_regular
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# ---------------------------------------------------------------------------
# Test yardimcilari
# ---------------------------------------------------------------------------


def _make_target(
    path: Path,
    target_type: TargetType = TargetType.MACHO_BINARY,
    file_size: int | None = None,
) -> TargetInfo:
    """Test icin TargetInfo olustur."""
    if file_size is None:
        try:
            file_size = path.stat().st_size
        except OSError:
            file_size = 0
    return TargetInfo(
        path=path,
        name=path.name,
        target_type=target_type,
        language=Language.C,
        file_size=file_size,
        file_hash="0" * 64,
        metadata={},
    )


def _make_workspace(base: Path) -> Workspace:
    """Test icin Workspace olustur ve dizinleri hazirla."""
    ws = Workspace(base, "test_target")
    ws.create()
    return ws


class _FakeStat:
    """Minimal os.stat_result benzeri sahte nesne."""

    def __init__(self, mode: int, size: int = 0) -> None:
        self.st_mode = mode
        self.st_size = size


class _FakeRunResult:
    """subprocess.run sonucu benzeri minimal nesne."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str | bytes = "",
        stderr: str | bytes = "",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeGhidraHeadless:
    """GhidraHeadless'in test icin fake versiyonu."""

    def __init__(
        self,
        config: Any = None,
        available: bool = True,
        analyze_result: dict[str, Any] | None = None,
        raise_on_analyze: bool = False,
    ) -> None:
        self._config = config
        self._available = available
        self._analyze_result = analyze_result
        self._raise = raise_on_analyze

    def is_available(self) -> bool:
        return self._available

    def get_default_scripts(self) -> list[Path]:
        return [Path("/fake/script.py")]

    def analyze(self, **_kw: Any) -> dict[str, Any]:
        if self._raise:
            raise RuntimeError("fake analyze cokuyor")
        if self._analyze_result is None:
            return {
                "success": True,
                "duration_seconds": 1.5,
                "scripts_output": {
                    "combined_results": {
                        "summary": {
                            "function_count": 5,
                            "string_count": 12,
                            "call_graph_edges": 7,
                            "decompiled_success": 4,
                        },
                    },
                },
                "returncode": 0,
            }
        return self._analyze_result


# ---------------------------------------------------------------------------
# 1. _stat_is_regular
# ---------------------------------------------------------------------------


class TestStatIsRegular:
    def test_regular_file_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"hello")
        st = f.stat()
        assert _stat_is_regular(st) is True

    def test_directory_returns_false(self, tmp_path: Path) -> None:
        st = tmp_path.stat()
        assert _stat_is_regular(st) is False

    def test_symlink_target_regular_true(self, tmp_path: Path) -> None:
        # Sembolik linkin hedefi normal dosya. os.stat() symlink'i takip eder.
        target = tmp_path / "real.bin"
        target.write_bytes(b"data")
        link = tmp_path / "link.bin"
        link.symlink_to(target)
        # follow=True (default)
        assert _stat_is_regular(link.stat()) is True
        # follow=False -> symlink olarak gorunur
        lst = link.lstat()
        assert _stat_is_regular(lst) is False

    def test_attribute_error_returns_false(self) -> None:
        class _NoMode:
            pass

        assert _stat_is_regular(_NoMode()) is False

    def test_fake_stat_with_regular_mode(self) -> None:
        st = _FakeStat(mode=_stat_module.S_IFREG | 0o644)
        assert _stat_is_regular(st) is True

    def test_fake_stat_with_fifo_mode(self) -> None:
        st = _FakeStat(mode=_stat_module.S_IFIFO | 0o644)
        assert _stat_is_regular(st) is False


# ---------------------------------------------------------------------------
# 2. MachOAnalyzer.__init__
# ---------------------------------------------------------------------------


class TestMachOAnalyzerInit:
    def test_init_uses_backend_factory(
        self, monkeypatch: pytest.MonkeyPatch, config: Config,
    ) -> None:
        """Normal yol: create_backend basarili, ghidra attribute set olur."""

        class _FakeBackend:
            name = "ghidra"
            ghidra = _FakeGhidraHeadless(available=True)

        def _fake_create(_cfg: Config) -> _FakeBackend:
            return _FakeBackend()

        monkeypatch.setattr(
            "karadul.decompilers.create_backend", _fake_create, raising=True,
        )
        analyzer = MachOAnalyzer(config)
        assert analyzer._backend is not None
        # ghidra attribute backend'in ghidra property'si ile ayni instance
        backend_ghidra = getattr(analyzer._backend, "ghidra", None)
        assert analyzer.ghidra is backend_ghidra

    def test_init_falls_back_when_factory_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config: Config,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Factory exception firlatirsa GhidraHeadless direkt kullanilir."""

        def _broken_create(_cfg: Config) -> Any:
            raise RuntimeError("factory broken")

        monkeypatch.setattr(
            "karadul.decompilers.create_backend", _broken_create, raising=True,
        )
        with caplog.at_level(logging.DEBUG, logger="karadul.analyzers.macho"):
            analyzer = MachOAnalyzer(config)
        assert analyzer._backend is None
        # ghidra attribute mutlaka var (fallback)
        assert analyzer.ghidra is not None

    def test_init_backend_without_ghidra_attr(
        self, monkeypatch: pytest.MonkeyPatch, config: Config,
    ) -> None:
        """Backend'in ghidra attribute'u yoksa yeni GhidraHeadless olusturulur."""

        class _NoGhidraBackend:
            name = "angr"
            # ghidra attribute YOK

        def _fake_create(_cfg: Config) -> _NoGhidraBackend:
            return _NoGhidraBackend()

        monkeypatch.setattr(
            "karadul.decompilers.create_backend", _fake_create, raising=True,
        )
        analyzer = MachOAnalyzer(config)
        assert analyzer._backend is not None
        # GhidraHeadless instance fallback
        assert analyzer.ghidra is not None

    def test_init_runner_attached(
        self, monkeypatch: pytest.MonkeyPatch, config: Config,
    ) -> None:
        """SubprocessRunner instance __init__ icinde set ediliyor."""
        analyzer = MachOAnalyzer(config)
        assert analyzer.runner is not None
        assert analyzer.runner._config is config


# ---------------------------------------------------------------------------
# 3. _run_otool_libs
# ---------------------------------------------------------------------------


class TestRunOtoolLibs:
    def _make_analyzer(
        self, monkeypatch: pytest.MonkeyPatch, config: Config,
    ) -> MachOAnalyzer:
        # Backend factory'yi sade tutalim ki __init__ zincirleri test'i kirmasin
        monkeypatch.setattr(
            "karadul.analyzers.macho.GhidraHeadless",
            lambda _cfg: _FakeGhidraHeadless(),
            raising=True,
        )
        return MachOAnalyzer(config)

    def test_parses_dynamic_libraries(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        analyzer = self._make_analyzer(monkeypatch, config)
        fake_output = (
            f"{sample_macho_file}:\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, "
            "current version 1319.0.0)\n"
            "\t@rpath/libfoo.dylib (compatibility version 1.0.0, "
            "current version 2.0.0)\n"
        )

        def _fake_run_otool(
            _self: Any, _bp: Path, flags: list[str] | None = None,
        ) -> str:
            return fake_output

        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_otool",
            _fake_run_otool,
            raising=True,
        )
        result = analyzer._run_otool_libs(sample_macho_file)
        assert result is not None
        assert result["total"] == 2
        paths = [lib["path"] for lib in result["libraries"]]
        assert "/usr/lib/libSystem.B.dylib" in paths
        assert "@rpath/libfoo.dylib" in paths

    def test_returns_none_on_empty_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        analyzer = self._make_analyzer(monkeypatch, config)
        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_otool",
            lambda _self, _bp, flags=None: "",
            raising=True,
        )
        assert analyzer._run_otool_libs(sample_macho_file) is None

    def test_skips_blank_lines(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        analyzer = self._make_analyzer(monkeypatch, config)
        fake_output = (
            "binary:\n"
            "\n"
            "   \n"
            "\t/usr/lib/libc.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
        )
        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_otool",
            lambda _self, _bp, flags=None: fake_output,
            raising=True,
        )
        result = analyzer._run_otool_libs(sample_macho_file)
        assert result is not None
        assert result["total"] == 1


# ---------------------------------------------------------------------------
# 4. _run_otool_load_commands
# ---------------------------------------------------------------------------


class TestRunOtoolLoadCommands:
    def test_parses_byte_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        # safe_run bytes dondurur (text=False)
        sample = b"Load command 0\n  cmd LC_SEGMENT_64\n  cmdsize 72\nLoad command 1\n  cmd LC_LOAD_DYLIB\n"

        def _fake_safe_run(
            _cmd: list[str], **_kw: Any,
        ) -> _FakeRunResult:
            return _FakeRunResult(returncode=0, stdout=sample)

        monkeypatch.setattr(
            "karadul.analyzers.macho.safe_run", _fake_safe_run, raising=True,
        )
        monkeypatch.setattr(
            "karadul.analyzers.macho.resolve_tool",
            lambda name: "/usr/bin/otool",
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        out = analyzer._run_otool_load_commands(sample_macho_file)
        assert "LC_SEGMENT_64" in out
        assert "LC_LOAD_DYLIB" in out

    def test_truncates_oversized_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        # max_otool_output_bytes'tan buyuk yapay byte uret
        max_bytes = config.security.max_otool_output_bytes
        big = b"A" * (max_bytes + 1024)

        def _fake_safe_run(_cmd: list[str], **_kw: Any) -> _FakeRunResult:
            return _FakeRunResult(returncode=0, stdout=big)

        monkeypatch.setattr(
            "karadul.analyzers.macho.safe_run", _fake_safe_run, raising=True,
        )
        monkeypatch.setattr(
            "karadul.analyzers.macho.resolve_tool",
            lambda name: "/usr/bin/otool",
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        out = analyzer._run_otool_load_commands(sample_macho_file)
        # Kirpilmis olmali
        assert len(out.encode("utf-8", errors="replace")) <= max_bytes + 16

    def test_returns_empty_on_filenotfound(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        def _raise(_cmd: list[str], **_kw: Any) -> _FakeRunResult:
            raise FileNotFoundError("otool yok")

        monkeypatch.setattr(
            "karadul.analyzers.macho.safe_run", _raise, raising=True,
        )
        monkeypatch.setattr(
            "karadul.analyzers.macho.resolve_tool", lambda name: None, raising=True,
        )
        analyzer = MachOAnalyzer(config)
        assert analyzer._run_otool_load_commands(sample_macho_file) == ""

    def test_returns_empty_on_timeout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        import subprocess as _sp

        def _timeout(_cmd: list[str], **_kw: Any) -> _FakeRunResult:
            raise _sp.TimeoutExpired(cmd="otool", timeout=60)

        monkeypatch.setattr(
            "karadul.analyzers.macho.safe_run", _timeout, raising=True,
        )
        monkeypatch.setattr(
            "karadul.analyzers.macho.resolve_tool",
            lambda name: "/usr/bin/otool",
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        assert analyzer._run_otool_load_commands(sample_macho_file) == ""


# ---------------------------------------------------------------------------
# 5. _run_nm
# ---------------------------------------------------------------------------


class TestRunNm:
    def test_parses_global_symbols(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        from karadul.core.subprocess_runner import SubprocessResult

        nm_output = (
            "0000000100000a00 T _main\n"
            "0000000100001000 D _g_var\n"
            "0000000100002000 B _g_buf\n"
            "                 U _printf\n"
        )

        def _fake_run_command(
            _self: Any, _cmd: list[str], **_kw: Any,
        ) -> SubprocessResult:
            return SubprocessResult(
                success=True, returncode=0, stdout=nm_output, stderr="",
                duration_seconds=0.01,
            )

        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_command",
            _fake_run_command,
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        result = analyzer._run_nm(sample_macho_file)
        assert result is not None
        names = [s["name"] for s in result["symbols"]]
        assert "_main" in names
        assert "_printf" in names
        # undefined sym icin address None
        undef = [s for s in result["symbols"] if s["name"] == "_printf"]
        assert len(undef) == 1
        assert undef[0]["address"] is None
        assert undef[0]["type"] == "U"

    def test_returns_none_on_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        from karadul.core.subprocess_runner import SubprocessResult

        def _fake_run_command(
            _self: Any, _cmd: list[str], **_kw: Any,
        ) -> SubprocessResult:
            return SubprocessResult(
                success=False, returncode=1, stdout="", stderr="nm: stripped",
                duration_seconds=0.01,
            )

        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_command",
            _fake_run_command,
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        assert analyzer._run_nm(sample_macho_file) is None

    def test_handles_empty_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        from karadul.core.subprocess_runner import SubprocessResult

        def _fake_run_command(
            _self: Any, _cmd: list[str], **_kw: Any,
        ) -> SubprocessResult:
            return SubprocessResult(
                success=True, returncode=0, stdout="", stderr="",
                duration_seconds=0.01,
            )

        monkeypatch.setattr(
            "karadul.core.subprocess_runner.SubprocessRunner.run_command",
            _fake_run_command,
            raising=True,
        )
        analyzer = MachOAnalyzer(config)
        result = analyzer._run_nm(sample_macho_file)
        assert result is not None
        assert result["total"] == 0
        assert result["symbols"] == []


# ---------------------------------------------------------------------------
# 6. _run_lief
# ---------------------------------------------------------------------------


class TestRunLief:
    def test_lief_missing_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        """lief import edilemezse None doner."""
        import builtins
        real_import = builtins.__import__

        def _fake_import(
            name: str, *a: Any, **kw: Any,
        ) -> Any:
            if name == "lief":
                raise ImportError("lief yok")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        analyzer = MachOAnalyzer(config)
        assert analyzer._run_lief(sample_macho_file) is None

    def test_lief_parse_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        """lief.parse() None donerse method da None doner."""
        import builtins
        import sys
        import types

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)
        analyzer = MachOAnalyzer(config)
        assert analyzer._run_lief(sample_macho_file) is None

    def test_lief_parse_returns_dict(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        """Sahte lief Binary objesi ile dict yapisi dogrulanir."""
        import sys
        import types

        # Sahte segment / section / library nesneleri
        class _FakeSeg:
            name = "__TEXT"
            virtual_address = 0x100000000
            virtual_size = 0x1000
            file_offset = 0
            file_size = 0x1000

        class _FakeSecSegRef:
            name = "__TEXT"

        class _FakeSec:
            name = "__text"
            segment = _FakeSecSegRef()
            size = 0x500
            offset = 0x1000

        class _FakeLib:
            name = "/usr/lib/libSystem.dylib"

        class _FakeHeader:
            magic = "MH_MAGIC_64"
            cpu_type = "x86_64"
            file_type = "EXECUTE"
            flags = 0x12

        class _FakeBinary:
            format = "MACH_O"
            header = _FakeHeader()
            segments = [_FakeSeg()]
            sections = [_FakeSec()]
            libraries = [_FakeLib()]

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: _FakeBinary()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        result = analyzer._run_lief(sample_macho_file)
        assert result is not None
        assert "header" in result
        assert "segments" in result
        assert "sections" in result
        assert len(result["segments"]) == 1
        assert result["segments"][0]["name"] == "__TEXT"
        assert "/usr/lib/libSystem.dylib" in result["libraries"]

    def test_lief_parse_exception_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        """lief.parse() exception firlatirsa None doner."""
        import sys
        import types

        def _broken_parse(_p: Any) -> Any:
            raise ValueError("corrupted binary")

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = _broken_parse  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        assert analyzer._run_lief(sample_macho_file) is None


# ---------------------------------------------------------------------------
# 7. _extract_bun_js
# ---------------------------------------------------------------------------


class TestExtractBunJs:
    def test_lief_missing_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        import builtins
        real_import = builtins.__import__

        def _fake_import(name: str, *a: Any, **kw: Any) -> Any:
            if name == "lief":
                raise ImportError("lief yok")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        assert analyzer._extract_bun_js(sample_macho_file, ws) is None

    def test_no_bun_segment_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        import sys
        import types

        class _FakeSeg:
            name = "__TEXT"

        class _FakeBinary:
            segments = [_FakeSeg()]

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: _FakeBinary()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        assert analyzer._extract_bun_js(sample_macho_file, ws) is None

    def test_extracts_raw_bun_segment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """Compress edilmemis __BUN segmenti raw kaydedilir."""
        import sys
        import types

        # Binary'yi sentetik olarak hazirla: prefix + payload
        prefix = b"\x00" * 32
        payload = b"console.log('hello bun')"
        binary_bytes = prefix + payload + b"\x00" * 16
        bin_file = tmp_path / "bun.bin"
        bin_file.write_bytes(binary_bytes)

        class _FakeSeg:
            name = "__BUN"
            file_offset = len(prefix)
            file_size = len(payload)

        class _FakeBinary:
            segments = [_FakeSeg()]

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: _FakeBinary()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        out = analyzer._extract_bun_js(bin_file, ws)
        assert out is not None
        assert out.exists()
        # zlib decompress basarisiz olur, raw kaydedilir
        assert out.read_bytes() == payload

    def test_invalid_segment_bounds_returns_none(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """offset+size dosya disinda ise None doner."""
        import sys
        import types

        bin_file = tmp_path / "tiny.bin"
        bin_file.write_bytes(b"AAAA")

        class _FakeSeg:
            name = "__BUN"
            file_offset = 0
            file_size = 1024  # dosyadan buyuk

        class _FakeBinary:
            segments = [_FakeSeg()]

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: _FakeBinary()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        assert analyzer._extract_bun_js(bin_file, ws) is None

    def test_extracts_zlib_compressed_segment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """zlib compressed __BUN segmenti decompress edilir."""
        import sys
        import types
        import zlib

        plain = b"const greet = () => 'merhaba';" * 10
        compressed = zlib.compress(plain)

        prefix = b"\x00" * 8
        bin_file = tmp_path / "bun_z.bin"
        bin_file.write_bytes(prefix + compressed + b"\x00" * 4)

        class _FakeSeg:
            name = "__bun"  # lowercase variant
            file_offset = len(prefix)
            file_size = len(compressed)

        class _FakeBinary:
            segments = [_FakeSeg()]

        fake_lief = types.ModuleType("lief")
        fake_lief.parse = lambda _p: _FakeBinary()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "lief", fake_lief)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        out = analyzer._extract_bun_js(bin_file, ws)
        assert out is not None
        assert out.read_bytes() == plain


# ---------------------------------------------------------------------------
# 8. _extract_strings_mmap
# ---------------------------------------------------------------------------


class TestExtractStringsMmap:
    def test_extracts_ascii_strings(self, tmp_path: Path) -> None:
        bin_file = tmp_path / "strings.bin"
        # Karisik icerik: ASCII + binary noise
        content = (
            b"\x00\x01"
            + b"Hello World"
            + b"\x00\x00"
            + b"version 1.2.3"
            + b"\xff\x00"
            + b"\x00abc"  # 3 char, default min_length=4'un altinda
        )
        bin_file.write_bytes(content)
        result = MachOAnalyzer._extract_strings_mmap(bin_file, min_length=4)
        assert "Hello World" in result
        assert "version 1.2.3" in result
        # Kisa string (3 char) elenir
        assert "abc" not in result

    def test_respects_max_strings_limit(self, tmp_path: Path) -> None:
        bin_file = tmp_path / "many.bin"
        # 100 farkli string, her biri 5 char + null separator
        parts = [f"str{i:03d}".encode() + b"\x00" for i in range(100)]
        bin_file.write_bytes(b"".join(parts))
        result = MachOAnalyzer._extract_strings_mmap(
            bin_file, min_length=4, max_strings=10,
        )
        assert len(result) == 10

    def test_min_length_clamped_to_one(self, tmp_path: Path) -> None:
        bin_file = tmp_path / "single.bin"
        bin_file.write_bytes(b"x\x00y\x00abc\x00")
        # min_length=0 -> 1'e clamp edilmeli
        result = MachOAnalyzer._extract_strings_mmap(bin_file, min_length=0)
        assert "x" in result or "abc" in result

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        ghost = tmp_path / "ghost.bin"
        # Dosya yok -- OSError yakalanmali, bos liste donmeli
        result = MachOAnalyzer._extract_strings_mmap(ghost, min_length=4)
        assert result == []

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        bin_file = tmp_path / "empty.bin"
        bin_file.write_bytes(b"")
        # Bos dosya mmap'lenemez, ValueError yakalanmali, bos liste donmeli
        result = MachOAnalyzer._extract_strings_mmap(bin_file, min_length=4)
        assert result == []


# ---------------------------------------------------------------------------
# 9. _run_ghidra ve _run_ghidra_legacy
# ---------------------------------------------------------------------------


class TestRunGhidra:
    def test_legacy_path_when_primary_ghidra(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """primary_backend=ghidra ve is_available=True ise legacy yolu calisir."""
        analyzer = MachOAnalyzer(config)
        analyzer.ghidra = _FakeGhidraHeadless(available=True)
        config.decompilers.primary_backend = "ghidra"

        # GhidraProject.create()/cleanup() icin patch
        class _FakeProject:
            def __init__(self, ws: Any, cfg: Any) -> None:
                self.project_dir = tmp_path / "ghidra_proj"
                self.project_dir.mkdir(parents=True, exist_ok=True)

            def create(self) -> None:
                pass

            def get_output_dir(self) -> Path:
                d = self.project_dir / "output"
                d.mkdir(parents=True, exist_ok=True)
                return d

            def cleanup(self) -> None:
                pass

        monkeypatch.setattr(
            "karadul.analyzers.macho.GhidraProject", _FakeProject, raising=True,
        )
        ws = _make_workspace(tmp_path)
        result = analyzer._run_ghidra(sample_macho_file, ws)
        assert result is not None
        assert result["success"] is True
        assert "scripts_output" in result

    def test_legacy_returns_none_when_unavailable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        analyzer = MachOAnalyzer(config)
        analyzer.ghidra = _FakeGhidraHeadless(available=False)
        ws = _make_workspace(tmp_path)
        # legacy direkt cagrilirsa None
        assert analyzer._run_ghidra_legacy(sample_macho_file, ws) is None

    def test_legacy_handles_analyze_exception(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        analyzer = MachOAnalyzer(config)
        analyzer.ghidra = _FakeGhidraHeadless(
            available=True, raise_on_analyze=True,
        )

        class _FakeProject:
            def __init__(self, ws: Any, cfg: Any) -> None:
                self.project_dir = tmp_path / "ghidra_proj"
                self.project_dir.mkdir(parents=True, exist_ok=True)

            def create(self) -> None:
                pass

            def get_output_dir(self) -> Path:
                d = self.project_dir / "output"
                d.mkdir(parents=True, exist_ok=True)
                return d

            def cleanup(self) -> None:
                pass

        monkeypatch.setattr(
            "karadul.analyzers.macho.GhidraProject", _FakeProject, raising=True,
        )
        ws = _make_workspace(tmp_path)
        result = analyzer._run_ghidra_legacy(sample_macho_file, ws)
        assert result is not None
        assert result["success"] is False
        assert "error" in result

    def test_run_ghidra_factory_failure_falls_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """primary != ghidra ama factory cokerse legacy fallback."""
        analyzer = MachOAnalyzer(config)
        analyzer.ghidra = _FakeGhidraHeadless(available=True)
        config.decompilers.primary_backend = "angr"

        def _broken_factory(_cfg: Config) -> Any:
            raise RuntimeError("factory broken")

        monkeypatch.setattr(
            "karadul.decompilers.create_backend_with_fallback",
            _broken_factory,
            raising=True,
        )

        class _FakeProject:
            def __init__(self, ws: Any, cfg: Any) -> None:
                self.project_dir = tmp_path / "ghidra_proj"
                self.project_dir.mkdir(parents=True, exist_ok=True)

            def create(self) -> None:
                pass

            def get_output_dir(self) -> Path:
                d = self.project_dir / "output"
                d.mkdir(parents=True, exist_ok=True)
                return d

            def cleanup(self) -> None:
                pass

        monkeypatch.setattr(
            "karadul.analyzers.macho.GhidraProject", _FakeProject, raising=True,
        )
        ws = _make_workspace(tmp_path)
        result = analyzer._run_ghidra(sample_macho_file, ws)
        # legacy fallback calistigi icin success=True dict beklenir
        assert result is not None
        assert result.get("success") is True


# ---------------------------------------------------------------------------
# 10. analyze_static (entegrasyon -- mid-level mock)
# ---------------------------------------------------------------------------


class TestAnalyzeStatic:
    def _patch_pipeline(
        self,
        monkeypatch: pytest.MonkeyPatch,
        ghidra_result: dict[str, Any] | None = None,
        intel_raise: bool = False,
    ) -> None:
        """analyze_static icin tum yan etkileri (otool, nm, lief, ghidra, intel) mockla."""
        # otool -L
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_libs",
            lambda self, p: {"binary": str(p), "total": 1, "libraries": [
                {"path": "/usr/lib/libSystem.dylib", "version_info": "1"},
            ]},
            raising=True,
        )
        # otool -l
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_load_commands",
            lambda self, p: "Load command 0\n",
            raising=True,
        )
        # nm
        monkeypatch.setattr(
            MachOAnalyzer, "_run_nm",
            lambda self, p: {
                "binary": str(p), "total": 1,
                "symbols": [{"address": "0x100", "type": "T", "name": "_main"}],
            },
            raising=True,
        )
        # lief
        monkeypatch.setattr(
            MachOAnalyzer, "_run_lief",
            lambda self, p: {"format": "MACH_O", "header": {}, "segments": [],
                             "sections": [], "libraries": []},
            raising=True,
        )
        # strings (subprocess yolu)
        from karadul.core.subprocess_runner import SubprocessRunner
        monkeypatch.setattr(
            SubprocessRunner, "run_strings",
            lambda self, p, min_length=None: ["hello", "world"],
            raising=True,
        )
        # ghidra
        monkeypatch.setattr(
            MachOAnalyzer, "_run_ghidra",
            lambda self, p, ws: ghidra_result,
            raising=True,
        )
        # Binary intelligence
        if intel_raise:
            class _BIBroken:
                def __init__(self, *a: Any, **kw: Any) -> None:
                    raise RuntimeError("BI patladi")

            monkeypatch.setattr(
                "karadul.analyzers.binary_intelligence.BinaryIntelligence",
                _BIBroken,
                raising=True,
            )
        else:
            class _BIFake:
                def __init__(self, *a: Any, **kw: Any) -> None:
                    pass

                def analyze(self, **kw: Any) -> Any:
                    class _Report:
                        class architecture:
                            app_type = "cli"
                            subsystems: list[Any] = []
                            algorithms: list[Any] = []
                            security: list[Any] = []
                            protocols: list[Any] = []
                            function_analyses: list[Any] = []

                        def to_dict(self) -> dict[str, Any]:
                            return {"summary": "test"}

                    return _Report()

                def analyze_decompiled(self, _d: Path) -> list[Any]:
                    return []

            monkeypatch.setattr(
                "karadul.analyzers.binary_intelligence.BinaryIntelligence",
                _BIFake,
                raising=True,
            )

    def test_macho_pipeline_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        ghidra_res = {
            "success": True,
            "duration_seconds": 1.0,
            "scripts_output": {
                "combined_results": {
                    "summary": {
                        "function_count": 3, "string_count": 5,
                        "call_graph_edges": 2, "decompiled_success": 3,
                    },
                },
            },
            "returncode": 0,
        }
        self._patch_pipeline(monkeypatch, ghidra_result=ghidra_res)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file, TargetType.MACHO_BINARY)

        result = analyzer.analyze_static(target, ws)
        assert result.stage_name == "static"
        assert result.success is True
        # Artifact'lar uretilmis olmali
        assert "raw_binary" in result.artifacts
        assert "dynamic_libraries" in result.artifacts
        assert "symbols" in result.artifacts
        # Stats
        assert result.stats["dylib_count"] == 1
        assert result.stats["symbol_count"] == 1
        assert result.stats["ghidra_success"] is True
        assert result.stats["lief_available"] is True

    def test_elf_skips_otool(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """ELF binary icin otool stage'leri atlanir."""
        self._patch_pipeline(monkeypatch, ghidra_result=None)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file, TargetType.ELF_BINARY)
        result = analyzer.analyze_static(target, ws)
        # otool -L atlandigi icin dynamic_libraries yok
        assert "dynamic_libraries" not in result.artifacts
        assert "load_commands" not in result.artifacts
        # nm/lief/strings calisir
        assert "symbols" in result.artifacts
        assert "lief_analysis" in result.artifacts

    def test_pe_skips_otool(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        self._patch_pipeline(monkeypatch, ghidra_result=None)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file, TargetType.PE_BINARY)
        result = analyzer.analyze_static(target, ws)
        assert "dynamic_libraries" not in result.artifacts

    def test_ghidra_failure_recorded(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        ghidra_res = {"success": False, "returncode": 2}
        self._patch_pipeline(monkeypatch, ghidra_result=ghidra_res)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file, TargetType.MACHO_BINARY)
        result = analyzer.analyze_static(target, ws)
        assert result.stats["ghidra_success"] is False
        # Hata listesinde Ghidra mesaji
        assert any("Ghidra" in e for e in result.errors)

    def test_intel_exception_collected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """BinaryIntelligence cokerse error eklenir, pipeline devam eder."""
        ghidra_res = {
            "success": True,
            "duration_seconds": 0.5,
            "scripts_output": {},
        }
        self._patch_pipeline(monkeypatch, ghidra_result=ghidra_res, intel_raise=True)
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file, TargetType.MACHO_BINARY)
        result = analyzer.analyze_static(target, ws)
        assert any("Binary Intelligence" in e for e in result.errors)
        # Stage yine de basari (artifact uretildi)
        assert "raw_binary" in result.artifacts

    def test_large_binary_uses_mmap(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """file_size > threshold ise mmap yolu kullanilir."""
        self._patch_pipeline(monkeypatch, ghidra_result=None)
        # mmap yolunu kontrol etmek icin _extract_strings_mmap'i mockla
        called = {"flag": False}

        def _fake_mmap(p: Any, min_length: int = 4, **_kw: Any) -> list[str]:
            called["flag"] = True
            return ["mmapped_string"]

        monkeypatch.setattr(
            MachOAnalyzer, "_extract_strings_mmap",
            staticmethod(_fake_mmap),
            raising=True,
        )

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        # threshold'u kucult
        config.binary_reconstruction.large_binary_threshold_mb = 0  # her sey buyuk
        target = _make_target(
            sample_macho_file, TargetType.MACHO_BINARY,
            file_size=100 * 1024 * 1024,  # 100 MB
        )
        result = analyzer.analyze_static(target, ws)
        assert called["flag"] is True
        assert result.stats["string_extraction_method"] == "mmap"


# ---------------------------------------------------------------------------
# 11. deobfuscate (smoke)
# ---------------------------------------------------------------------------


class TestDeobfuscate:
    def test_deobfuscate_no_ghidra_output_records_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = _make_target(sample_macho_file)
        result = analyzer.deobfuscate(target, ws)
        assert result.stage_name == "deobfuscate"
        assert result.success is False
        assert any("Ghidra decompilation" in e for e in result.errors)

    def test_deobfuscate_copies_decompiled_dir(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        # Sentetik decompiled dizin olustur
        static_dir = ws.get_stage_dir("static")
        decompiled = static_dir / "ghidra_output" / "decompiled"
        decompiled.mkdir(parents=True, exist_ok=True)
        (decompiled / "func1.c").write_text("int func1() { return 0; }\n")
        (decompiled / "func2.c").write_text("void func2() {}\n")

        target = _make_target(sample_macho_file)
        result = analyzer.deobfuscate(target, ws)
        assert result.success is True
        assert "decompiled_dir" in result.artifacts

    def test_deobfuscate_falls_back_to_json(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """decompiled dizini yoksa ghidra_decompiled.json kopyalanir."""
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        static_dir = ws.get_stage_dir("static")
        json_path = static_dir / "ghidra_decompiled.json"
        json_path.write_text(json.dumps({"functions": []}), encoding="utf-8")

        target = _make_target(sample_macho_file)
        result = analyzer.deobfuscate(target, ws)
        assert result.success is True
        assert "decompiled_json" in result.artifacts


# ---------------------------------------------------------------------------
# 12. v1.14.5 -- Universal binary lipo dispatch (tester ajan #1, #2)
# ---------------------------------------------------------------------------


class TestUniversalBinaryLipo:
    """`analyze_static` icindeki lipo thin dispatch dali (macho.py:127-151).

    Senaryolar:
        - lipo arm64 basarisiz -> x86_64 fallback basarili
        - lipo timeout -> errors listesinde + orijinal binary kullanilir
    """

    def _make_universal_target(
        self, path: Path,
    ) -> TargetInfo:
        return TargetInfo(
            path=path,
            name=path.name,
            target_type=TargetType.UNIVERSAL_BINARY,
            language=Language.C,
            file_size=path.stat().st_size,
            file_hash="0" * 64,
            metadata={},
        )

    def _patch_basic_pipeline(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """analyze_static yan etkilerini sustur (sadece lipo dali test edilir)."""
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_libs",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_load_commands",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_nm",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_lief",
            lambda self, p: None, raising=True,
        )
        from karadul.core.subprocess_runner import SubprocessRunner
        monkeypatch.setattr(
            SubprocessRunner, "run_strings",
            lambda self, p, min_length=None: [], raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_ghidra",
            lambda self, p, ws: None, raising=True,
        )

        # Binary intelligence: stub
        class _BIFake:
            def __init__(self, *a: Any, **kw: Any) -> None:
                pass

            def analyze(self, **kw: Any) -> Any:
                class _Report:
                    class architecture:
                        app_type = "cli"
                        subsystems: list[Any] = []
                        algorithms: list[Any] = []
                        security: list[Any] = []
                        protocols: list[Any] = []
                        function_analyses: list[Any] = []

                    def to_dict(self) -> dict[str, Any]:
                        return {"summary": "test"}

                return _Report()

            def analyze_decompiled(self, _d: Path) -> list[Any]:
                return []

        monkeypatch.setattr(
            "karadul.analyzers.binary_intelligence.BinaryIntelligence",
            _BIFake, raising=True,
        )

    def test_macho_universal_lipo_arm64_then_x86_64_fallback(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """Arm64 lipo basarisiz, x86_64 basarili."""
        self._patch_basic_pipeline(monkeypatch)

        # subprocess.run: ilk cagri (arm64) returncode=1, ikinci (x86_64) =0
        call_count = {"n": 0}

        def _fake_run(cmd: Any, **kwargs: Any) -> Any:
            call_count["n"] += 1
            # cmd: ["lipo", binary, "-thin", arch, "-output", thin_path]
            arch = cmd[3] if len(cmd) > 3 else ""
            if arch == "arm64":
                return _FakeRunResult(
                    returncode=1, stdout="",
                    stderr="lipo: arm64 slice not found",
                )
            if arch == "x86_64":
                # Sahte slice dosyasini fiilen olustur
                thin_out = Path(cmd[5])
                thin_out.parent.mkdir(parents=True, exist_ok=True)
                thin_out.write_bytes(b"x86_64-thin")
                return _FakeRunResult(returncode=0, stdout="", stderr="")
            return _FakeRunResult(returncode=2)

        import subprocess as _subprocess
        monkeypatch.setattr(_subprocess, "run", _fake_run, raising=True)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = self._make_universal_target(sample_macho_file)
        result = analyzer.analyze_static(target, ws)

        assert call_count["n"] == 2, "Hem arm64 hem x86_64 denenmeli"
        # x86_64 basarili oldugu icin stats'a yazilmali
        assert result.stats.get("lipo_thin") == "x86_64"

    def test_macho_universal_lipo_timeout_recorded(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """lipo TimeoutExpired -> errors listesi + pipeline devam."""
        self._patch_basic_pipeline(monkeypatch)

        import subprocess as _subprocess

        def _fake_run_timeout(cmd: Any, **kwargs: Any) -> Any:
            raise _subprocess.TimeoutExpired(cmd=list(cmd), timeout=30)

        monkeypatch.setattr(_subprocess, "run", _fake_run_timeout, raising=True)

        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        target = self._make_universal_target(sample_macho_file)
        result = analyzer.analyze_static(target, ws)

        # Errors listesinde lipo mesaji var
        assert any("lipo thin hatasi" in e for e in result.errors)
        # Orijinal binary yine raw kopyalandi
        assert "raw_binary" in result.artifacts


# ---------------------------------------------------------------------------
# 13. v1.14.5 -- Non-Ghidra backend dispatch (tester ajan #3)
# ---------------------------------------------------------------------------


class TestNonGhidraBackendFactory:
    """`_run_ghidra` non-ghidra dali (macho.py:846-892).

    primary_backend != ghidra (veya ghidra yok) iken
    `create_backend_with_fallback` non-ghidra backend dondurur.
    `pipeline_adapter.write_ghidra_shape_artifacts` cagrilmali.
    """

    def test_macho_backend_factory_non_ghidra_path(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_macho_file: Path,
        tmp_path: Path,
        config: Config,
    ) -> None:
        # primary_backend = "angr" yapma (config'e bakmaksizin self.ghidra
        # is_available() -> False olsun ki fast path'e girilmesin).
        from karadul.decompilers.base import (
            DecompiledFunction,
            DecompileResult,
        )

        # Ghidra'yi devre disi birakan analyzer
        analyzer = MachOAnalyzer(config)

        # self.ghidra.is_available() -> False
        monkeypatch.setattr(
            analyzer.ghidra, "is_available",
            lambda: False, raising=False,
        )

        # Fake angr-benzeri backend
        class _FakeAngrBackend:
            name = "angr"

            def is_available(self) -> bool:
                return True

            def decompile(
                self,
                binary: Path,
                output_dir: Path,
                timeout: float = 3600.0,
            ) -> DecompileResult:
                # Tek fonksiyon decompile etmis gibi
                return DecompileResult(
                    functions=[
                        DecompiledFunction(
                            address="0x100003abc",
                            name="main",
                            pseudocode="int main() { return 0; }",
                            calls=[],
                        ),
                    ],
                    call_graph={"0x100003abc": []},
                    strings=[{"addr": "0x200", "value": "hello"}],
                    errors=[],
                    backend_name="angr",
                    duration_seconds=0.5,
                )

        def _fake_factory(_cfg: Any) -> tuple[Any, list[str]]:
            return _FakeAngrBackend(), ["ghidra", "angr"]

        monkeypatch.setattr(
            "karadul.decompilers.create_backend_with_fallback",
            _fake_factory, raising=True,
        )

        # write_ghidra_shape_artifacts cagrildi mi spy
        called = {"flag": False, "result": None, "out_dir": None}

        original_writer = None
        try:
            from karadul.decompilers import pipeline_adapter
            original_writer = pipeline_adapter.write_ghidra_shape_artifacts
        except ImportError:
            pytest.skip("pipeline_adapter import edilemiyor")

        def _spy_writer(result: Any, output_dir: Any) -> dict[str, Any]:
            called["flag"] = True
            called["result"] = result
            called["out_dir"] = output_dir
            return {
                "success": True,
                "duration_seconds": 0.5,
                "ghidra_log": "",
                "mode": "angr_adapter",
                "scripts_output": {
                    "functions": {"total": 1, "functions": []},
                },
                "returncode": 0,
            }

        monkeypatch.setattr(
            "karadul.decompilers.pipeline_adapter.write_ghidra_shape_artifacts",
            _spy_writer, raising=True,
        )

        ws = _make_workspace(tmp_path)
        ghidra_result = analyzer._run_ghidra(sample_macho_file, ws)

        assert called["flag"] is True, "write_ghidra_shape_artifacts cagrilmali"
        assert ghidra_result is not None
        assert ghidra_result.get("mode") == "angr_adapter"
        # DecompileResult spy'a gecmis olmali
        captured: Any = called["result"]
        assert captured is not None
        assert captured.backend_name == "angr"


# ---------------------------------------------------------------------------
# 14. v1.14.5 -- raw_copy edge cases (tester ajan #4, #5)
# ---------------------------------------------------------------------------


class TestRawBinaryCopyEdgeCases:
    """`analyze_static` icindeki raw_copy adimi (macho.py:165-198).

    - same_file: raw_copy.resolve() == binary_path.resolve() -> kopyalama
      atlanir, artifacts["raw_binary"] direkt set.
    - FIFO/device: _stat_is_regular=False -> errors'a "duzgun dosya degil".
    """

    def _patch_basic_pipeline(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """analyze_static'in yan etkilerini sustur."""
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_libs",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_otool_load_commands",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_nm",
            lambda self, p: None, raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_lief",
            lambda self, p: None, raising=True,
        )
        from karadul.core.subprocess_runner import SubprocessRunner
        monkeypatch.setattr(
            SubprocessRunner, "run_strings",
            lambda self, p, min_length=None: [], raising=True,
        )
        monkeypatch.setattr(
            MachOAnalyzer, "_run_ghidra",
            lambda self, p, ws: None, raising=True,
        )

        class _BIFake:
            def __init__(self, *a: Any, **kw: Any) -> None:
                pass

            def analyze(self, **kw: Any) -> Any:
                class _Report:
                    class architecture:
                        app_type = "cli"
                        subsystems: list[Any] = []
                        algorithms: list[Any] = []
                        security: list[Any] = []
                        protocols: list[Any] = []
                        function_analyses: list[Any] = []

                    def to_dict(self) -> dict[str, Any]:
                        return {}

                return _Report()

            def analyze_decompiled(self, _d: Path) -> list[Any]:
                return []

        monkeypatch.setattr(
            "karadul.analyzers.binary_intelligence.BinaryIntelligence",
            _BIFake, raising=True,
        )

    def test_macho_raw_copy_same_file_branch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config: Config,
    ) -> None:
        """raw_copy.resolve() == binary_path.resolve() -> direct artifact."""
        self._patch_basic_pipeline(monkeypatch)

        # Workspace olustur ve raw stage dizinini bul
        ws = _make_workspace(tmp_path)
        raw_dir = ws.get_stage_dir("raw")
        # Binary'i workspace'in raw klasorunde olustur -- target.path == raw_copy
        binary_in_raw = raw_dir / "circular_binary"
        binary_in_raw.write_bytes(b"\x7fELF" + b"\x00" * 1024)

        target = TargetInfo(
            path=binary_in_raw,
            name="circular_binary",
            target_type=TargetType.MACHO_BINARY,
            language=Language.C,
            file_size=binary_in_raw.stat().st_size,
            file_hash="0" * 64,
            metadata={},
        )
        analyzer = MachOAnalyzer(config)
        result = analyzer.analyze_static(target, ws)

        # Same-file dali: artifact set, kopyalama yapilmadi
        # (raw_copy ile binary_in_raw ayni inode)
        assert "raw_binary" in result.artifacts
        # Dosya silinmemis olmali (zaten ayni dosya)
        assert binary_in_raw.exists()

    def test_macho_raw_copy_rejects_fifo(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        sample_macho_file: Path,
        config: Config,
    ) -> None:
        """Non-regular dosya (FIFO/device) -> errors'a 'duzgun dosya' mesaji.

        Gercek FIFO yaratmiyoruz cunku `open(fifo, 'rb')` syscall'i writer
        bekler ve test sonsuz bloklar. Yerine `_stat_is_regular` kontrolunu
        False'a zorlayarak ayni kod yolunu (line 182-186) tetikliyoruz.
        FIFO mode'unun gercekten False uretmesi `TestStatIsRegular::
        test_fake_stat_with_fifo_mode` ile birim duzeyinde kanitlanmis.
        """
        self._patch_basic_pipeline(monkeypatch)
        # _stat_is_regular her cagrisinda False -> "duzgun dosya degil" branchi
        monkeypatch.setattr(
            "karadul.analyzers.macho._stat_is_regular",
            lambda _st: False,
        )

        target = TargetInfo(
            path=sample_macho_file,  # Gercek regular dosya, ama stat False mock'lu
            name="weird_fifo",
            target_type=TargetType.MACHO_BINARY,
            language=Language.C,
            file_size=64,
            file_hash="0" * 64,
            metadata={},
        )
        analyzer = MachOAnalyzer(config)
        ws = _make_workspace(tmp_path)
        result = analyzer.analyze_static(target, ws)

        # Non-regular dosya kopyasi reddedildi
        assert any(
            "duzgun dosya degil" in e or "duzgun dosya" in e
            for e in result.errors
        ), "Non-regular icin 'duzgun dosya' hatasi bekleniyor (errors: %r)" % result.errors
