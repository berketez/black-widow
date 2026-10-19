"""Ghidra sürüm sabitleme (plan v2 G3c, 2026-10-19).

Aynı ikili farklı Ghidra sürümlerinde farklı C üretir. Geliştirme CLI'ı eskiden
iCloud Masaüstü'ndeki 12.0_DEV kurulumuna düşüyordu, uygulama ve ölçüm 12.1.2
kullanıyordu. Bu testler sabitlenen sürümün varsayılan olduğunu, raporun sürümü
yazdığını, farklı sürümün uyarı verdiğini ve ölçüm hattının onu reddettiğini korur.
"""

from __future__ import annotations

import ast
import importlib.util
import logging
from pathlib import Path

import pytest

import karadul.config as cfg
from karadul.config import Config, ToolPaths
from karadul.reporting.json_report import JSONReporter

_REPO = Path(__file__).resolve().parents[1]
_MEASURE_PATH = _REPO / "scripts" / "measurement" / "measure.py"


def _fake_ghidra(root: Path, version: str, release: str = "PUBLIC") -> Path:
    """Sürüm dosyası ve analyzeHeadless'ı olan sahte bir Ghidra kurulumu."""
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(
        "# yorum satırı\n"
        f"application.release.name={release}\n"
        f"application.version={version}\n",
        encoding="utf-8",
    )
    (root / "support").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    return root


def _load_measure():
    spec = importlib.util.spec_from_file_location("measure_under_test", _MEASURE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPinnedDefault:
    def test_pinned_dir_is_the_pinned_version(self) -> None:
        assert cfg.GHIDRA_PINNED_VERSION == "12.1.2"
        assert cfg.GHIDRA_PINNED_VERSION in cfg.GHIDRA_PINNED_DIR
        assert cfg._GHIDRA_KNOWN_DIR == cfg.GHIDRA_PINNED_DIR

    def test_config_source_has_no_dev_build_path(self) -> None:
        # Eski 12.0_DEV yolu yedek (fallback) dizgilerinde de kalmamalı.
        source = Path(cfg.__file__).read_text(encoding="utf-8")
        literals = [n.value for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        assert not [s for s in literals if "12.0_DEV" in s]

    def test_known_dir_wins_over_glob_candidates_without_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pinned = _fake_ghidra(tmp_path / "pinned", "12.1.2")
        dev = _fake_ghidra(tmp_path / "dev", "12.0", "DEV")
        for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(cfg, "_GHIDRA_KNOWN_DIR", str(pinned))
        monkeypatch.setattr(cfg.glob, "glob", lambda pat: [str(dev)])
        found = cfg._find_ghidra_tool("support/analyzeHeadless", "/yok")
        assert found == (pinned / "support" / "analyzeHeadless").resolve()

    def test_env_override_still_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        pinned = _fake_ghidra(tmp_path / "pinned", "12.1.2")
        other = _fake_ghidra(tmp_path / "other", "11.4")
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(other))
        monkeypatch.setattr(cfg, "_GHIDRA_KNOWN_DIR", str(pinned))
        found = cfg._find_ghidra_tool("support/analyzeHeadless", "/yok")
        assert found == (other / "support" / "analyzeHeadless").resolve()


class TestInstallInfo:
    def test_reads_version_and_release(self, tmp_path: Path) -> None:
        info = cfg.ghidra_install_info(_fake_ghidra(tmp_path / "g", "12.1.2"))
        assert info["version"] == "12.1.2"
        assert info["release"] == "PUBLIC"

    def test_missing_properties_gives_none_without_raising(self, tmp_path: Path) -> None:
        info = cfg.ghidra_install_info(tmp_path / "yok")
        assert info["version"] is None
        assert info["release"] is None


class TestUnpinnedWarning:
    @pytest.fixture(autouse=True)
    def _reset_warned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cfg, "_UNPINNED_GHIDRA_WARNED", set())

    def test_other_version_warns_once(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        dev = _fake_ghidra(tmp_path / "dev", "12.0", "DEV")
        with caplog.at_level(logging.WARNING, logger="karadul.config"):
            cfg.warn_if_ghidra_unpinned(dev)
            cfg.warn_if_ghidra_unpinned(dev)
        warnings = [r for r in caplog.records if "sabitlenen sürüm" in r.getMessage()]
        assert len(warnings) == 1
        assert "12.0" in warnings[0].getMessage()

    def test_pinned_version_does_not_warn(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        pinned = _fake_ghidra(tmp_path / "pinned", "12.1.2")
        with caplog.at_level(logging.WARNING, logger="karadul.config"):
            cfg.warn_if_ghidra_unpinned(pinned)
        assert not [r for r in caplog.records if "sabitlenen sürüm" in r.getMessage()]

    def test_headless_wrapper_warns_on_other_version(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        from karadul.ghidra.headless import GhidraHeadless

        config = Config()
        config.tools = ToolPaths(
            ghidra_headless=_fake_ghidra(tmp_path / "dev", "12.0", "DEV") / "support" / "analyzeHeadless")
        with caplog.at_level(logging.WARNING, logger="karadul.config"):
            GhidraHeadless(config)
        assert [r for r in caplog.records if "sabitlenen sürüm" in r.getMessage()]

    def test_pyghidra_start_checks_version(self) -> None:
        # JVM testte başlatılamaz; başlatıcının sürüm denetimini çağırdığı AST'den korunur.
        import karadul.ghidra.headless as headless

        tree = ast.parse(Path(headless.__file__).read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_ensure_pyghidra_started")
        calls = {n.func.id for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "warn_if_ghidra_unpinned" in calls


class TestJsonReportEnvironment:
    def _report(self, ghidra_root: Path) -> dict:
        config = Config()
        config.tools = ToolPaths(ghidra_headless=ghidra_root / "support" / "analyzeHeadless")
        return JSONReporter(config=config)._ghidra_environment()

    def test_report_records_pinned_ghidra(self, tmp_path: Path) -> None:
        env = self._report(_fake_ghidra(tmp_path / "pinned", "12.1.2"))
        assert env["version"] == "12.1.2"
        assert env["matches_pinned"] is True
        assert env["pinned_version"] == "12.1.2"

    def test_report_flags_other_version(self, tmp_path: Path) -> None:
        env = self._report(_fake_ghidra(tmp_path / "dev", "12.0", "DEV"))
        assert env["version"] == "12.0"
        assert env["matches_pinned"] is False

    def test_build_report_has_environment_block(self, tmp_path: Path) -> None:
        from karadul.core.result import PipelineResult
        from karadul.core.workspace import Workspace

        config = Config()
        config.tools = ToolPaths(
            ghidra_headless=_fake_ghidra(tmp_path / "pinned", "12.1.2") / "support" / "analyzeHeadless")
        target = tmp_path / "hedef.bin"
        target.write_bytes(b"\x00")
        ws = Workspace(tmp_path / "ws", "hedef")
        ws.create()
        result = PipelineResult(target_name="hedef", target_hash="0" * 64, workspace_path=ws.path)
        report = JSONReporter(config=config)._build_report(result, ws)
        assert report["environment"]["ghidra"]["version"] == "12.1.2"


class TestMeasureHarness:
    def test_measure_default_is_pinned_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KARADUL_MEAS_GHIDRA", raising=False)
        measure = _load_measure()
        assert measure.DEFAULT_GHIDRA == Path(cfg.GHIDRA_PINNED_DIR).expanduser()

    def test_refuses_other_version(self) -> None:
        measure = _load_measure()
        with pytest.raises(SystemExit):
            measure.require_pinned_ghidra({"version": "12.0", "install_dir": "/x"}, allow_other=False)

    def test_allows_other_version_when_explicit(self) -> None:
        measure = _load_measure()
        measure.require_pinned_ghidra({"version": "12.0", "install_dir": "/x"}, allow_other=True)

    def test_accepts_pinned_version(self) -> None:
        measure = _load_measure()
        measure.require_pinned_ghidra({"version": "12.1.2", "install_dir": "/x"}, allow_other=False)

    def test_ghidra_info_uses_shared_reader(self, tmp_path: Path) -> None:
        measure = _load_measure()
        gi = measure.ghidra_info(_fake_ghidra(tmp_path / "g", "12.1.2"))
        assert gi["version"] == "12.1.2"
        assert gi["release"] == "PUBLIC"
