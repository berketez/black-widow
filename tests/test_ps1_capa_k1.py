"""P-S1 kalem 4: capa tüketicileri K-1 altında (koda besleme bayrağı, öntanımlı kapalı).

P03'ten sonra capa PE'lerde gerçekten çalışıyor. Ölçülene kadar sonuçları rapora
DURUMUYLA yazılır (``static/capa_scan.json``) ama ad birleştiriciye ve
``@capability`` yorumlarına girmez. Kanıt zinciri burada gerçek parçalarla
kurulur: statik aşamanın capa bloğu (``stages._run_capa_scan``) gerçek bir
``Workspace``'e yazar, ad birleştiricinin capa kaynağı
(``_confidence_helpers.run_capa_merge``) aynı çalışma alanından okur.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.analyzers import capa_scanner as cs
from karadul.analyzers.capa_scanner import CAPACapability, CAPAScanResult
from karadul.core.target import TargetType
from karadul.core.workspace import Workspace
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import _confidence_helpers as ch
from karadul.pipeline.steps.capa_annotation import (
    CAPA_CODE_FEED_DEFAULT,
    capa_code_feed_enabled,
)
from karadul.stages import _run_capa_scan

W32 = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" \
    / "site-packages" / "pip" / "_vendor" / "distlib" / "w32.exe"
try:
    import capa.loader  # noqa: F401
    HAS_CAPA = True
except ImportError:  # pragma: no cover
    HAS_CAPA = False
HAS_RULES = cs.DEFAULT_RULES_PATH.is_dir() and any(cs.DEFAULT_RULES_PATH.rglob("*.yml"))


def _br(feed):
    br = MagicMock()
    br.enable_capa = True
    br.capa_rules_path = ""
    br.capa_timeout = 600
    if feed is None:
        del br.enable_capa_code_feed  # config.py'de alan yok (bugunku durum)
    else:
        br.enable_capa_code_feed = feed
    return br


def _ctx(tmp_path: Path, feed):
    ws = Workspace(tmp_path / "ws", "hedef")
    ws.create()
    ctx = MagicMock()
    ctx.workspace = ws
    ctx.config.binary_reconstruction = _br(feed)
    return ctx


def _fake_result() -> CAPAScanResult:
    caps = {
        "0x401000": [CAPACapability(name="reference analysis tools strings",
                                    namespace="anti-analysis")],
        "0x401100": [CAPACapability(name="create process on Windows",
                                    namespace="host-interaction/process/create")],
    }
    return CAPAScanResult(success=True, function_capabilities=caps,
                          total_rules_matched=2, total_functions_matched=2,
                          status=cs.STATUS_RAN, backend="api:vivisect", format_="pe")


def _merge_names(ctx_static) -> tuple[dict, dict, dict]:
    """Ad birlestiricinin capa kaynagini ayni calisma alaniyla calistir."""
    pc = MagicMock()
    pc.workspace = ctx_static.workspace
    pc.config.binary_reconstruction = ctx_static.config.binary_reconstruction  # ayni bayrak
    step_ctx = StepContext(pipeline_context=pc)
    names: dict = {}
    caps = ch.run_capa_merge(pc=pc, extracted_names=names, ctx=step_ctx)
    return names, caps, step_ctx.stats


class TestFlag:
    def test_default_is_off(self) -> None:
        assert CAPA_CODE_FEED_DEFAULT is False

    @pytest.mark.parametrize("value,expected", [
        (None, False),          # alan yok -> ontanimli
        (False, False),
        ("true", False),        # YAML dizgisi kanali acmaz
        (1, False),
        (True, True),
    ])
    def test_only_real_true_opens(self, value, expected) -> None:
        cfg = MagicMock()
        cfg.binary_reconstruction = _br(value)
        assert capa_code_feed_enabled(cfg) is expected

    def test_mock_attribute_does_not_open(self) -> None:
        assert capa_code_feed_enabled(MagicMock()) is False


class TestStaticBlockGate:
    def _scan(self, tmp_path, monkeypatch, feed):
        monkeypatch.setattr(cs.CAPAScanner, "scan", lambda self, p, **kw: _fake_result())
        ctx = _ctx(tmp_path, feed)
        target = MagicMock()
        target.target_type = TargetType.PE_BINARY
        target.path = tmp_path / "x.exe"
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        return ctx, stats

    @pytest.mark.parametrize("feed", [None, False])
    def test_flag_off_report_only(self, tmp_path, monkeypatch, feed) -> None:
        ctx, stats = self._scan(tmp_path, monkeypatch, feed)
        assert stats["capa_status"] == "calisti"
        assert stats["capa_code_feed"] is False
        assert stats["capa_rules_matched"] == 2
        scan = ctx.workspace.load_json("static", "capa_scan")
        assert scan["status"] == "calisti"
        assert set(scan["function_capabilities"]) == {"0x401000", "0x401100"}
        assert scan["code_feed"]["enabled"] is False
        # Ad birlestiricinin ve capa_annotation'in girdisi YOK
        assert ctx.workspace.load_json("static", "capa_capabilities") is None
        names, caps, mstats = _merge_names(ctx)
        assert names == {}
        assert caps == {}
        assert "capa_names_added" not in mstats

    def test_flag_on_feeds_names(self, tmp_path, monkeypatch) -> None:
        ctx, stats = self._scan(tmp_path, monkeypatch, True)
        assert stats["capa_code_feed"] is True
        assert ctx.workspace.load_json("static", "capa_capabilities")["success"] is True
        names, caps, mstats = _merge_names(ctx)
        assert set(names) == {"0x401000", "0x401100"}
        assert names["0x401100"] == "create_process_on_windows"
        assert mstats["capa_names_added"] == 2
        assert set(caps) == {"0x401000", "0x401100"}

    def test_non_ran_status_never_feeds(self, tmp_path, monkeypatch) -> None:
        res = CAPAScanResult(success=False, status=cs.STATUS_UNSUPPORTED,
                             status_reason="Mach-O")
        monkeypatch.setattr(cs.CAPAScanner, "scan", lambda self, p, **kw: res)
        ctx = _ctx(tmp_path, True)
        target = MagicMock()
        target.target_type = TargetType.MACHO_BINARY
        target.path = tmp_path / "x"
        stats: dict = {}
        _run_capa_scan(ctx, target, stats)
        assert stats["capa_status"] == "desteklenmiyor"
        assert ctx.workspace.load_json("static", "capa_scan")["status"] == "desteklenmiyor"
        assert ctx.workspace.load_json("static", "capa_capabilities") is None


@pytest.mark.skipif(not (HAS_CAPA and HAS_RULES and W32.is_file()),
                    reason="capa, kurallar ya da distlib w32.exe yok")
def test_real_capa_on_pe_writes_nothing_to_code(tmp_path) -> None:
    """GERCEK capa, gercek PE (taklit yok): yetenekler raporda, ad haritasina 0 ad."""
    ctx = _ctx(tmp_path, None)
    target = MagicMock()
    target.target_type = TargetType.PE_BINARY
    target.path = W32
    stats: dict = {}
    _run_capa_scan(ctx, target, stats)
    assert stats["capa_status"] == "calisti", stats.get("capa_status_reason")
    scan = ctx.workspace.load_json("static", "capa_scan")
    assert scan["function_capabilities"]  # capa gercekten yetenek buldu
    assert ctx.workspace.load_json("static", "capa_capabilities") is None
    names, caps, mstats = _merge_names(ctx)
    assert names == {} and caps == {}
    assert "capa_names_added" not in mstats
