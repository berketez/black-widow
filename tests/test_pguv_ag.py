"""P-GÜV / MEK-03 (= BICIM-06 `.d.ts` kısmı): JS ad hattı ağ kapalıyken ağa çıkmaz.

Eski davranış: npm parmak izi beyaz listedeki bir paketi (chalk, semver, …)
bulup yerelde ``.d.ts`` yoksa ``DtsNamer(timeout=8)`` ağ ayarına bakmadan
unpkg.com'a gidiyordu (istek URL'si analiz edilen koddaki paket adını
taşıyor). ``NamingPipeline()`` config'siz kurulursa kaynak eşleme de açık
geliyordu (o da yalnız ağdan kaynak indirir).

Ağ bekçisi: ``urllib.request.urlopen``, ``socket.socket.connect`` /
``connect_ex`` ve ``socket.create_connection`` kaydedip ``OSError`` verir;
hiçbir test gerçekten ağa çıkmaz. Hat gerçek ``NpmFingerprinter`` ile uçtan
uca koşar (``run`` + ``apply``).
"""

from __future__ import annotations

import socket
import urllib.request
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction.dts_namer import DtsNamer
from karadul.reconstruction.naming.pipeline import NamingPipeline

# Gerçek chalk parmak izini tetikleyen küçük modül (min_match 3; burada 8/8).
_CHALK_MODULE = (
    '"use strict";\n'
    "var level = process.env.FORCE_COLOR;\n"
    'var names = ["chalk.", "ansi256", "ansi16", "bgRed", "bgGreen", "bgBlue", "chalkStderr"];\n'
    "module.exports = {a: names, b: level};\n"
)


@pytest.fixture
def net_guard(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    calls: list[tuple] = []

    def _urlopen(req, *a, **k):
        calls.append(("urlopen", getattr(req, "full_url", req)))
        raise OSError("ağ bekçisi: engellendi")

    def _connect(self, addr):
        calls.append(("connect", addr))
        raise OSError("ağ bekçisi: engellendi")

    def _connect_ex(self, addr):
        calls.append(("connect_ex", addr))
        return 111

    def _create_connection(addr, *a, **k):
        calls.append(("create_connection", addr))
        raise OSError("ağ bekçisi: engellendi")

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _connect_ex)
    monkeypatch.setattr(socket, "create_connection", _create_connection)
    return calls


def _modules(tmp_path: Path) -> Path:
    mods = tmp_path / "deob" / "webpack_modules" / "modules"
    mods.mkdir(parents=True)
    (mods / "m_chalk.js").write_text(_CHALK_MODULE, encoding="utf-8")
    (mods / "m_other.js").write_text("module.exports = {x: 1};\n", encoding="utf-8")
    return mods


def _run(pipeline: NamingPipeline, tmp_path: Path):
    mods = _modules(tmp_path)
    manifest = pipeline.run(mods)
    pipeline.apply(mods, tmp_path / "named_project", manifest)
    return manifest


class TestJsNamingOffline:
    def test_default_config_never_touches_network(self, net_guard, tmp_path: Path) -> None:
        manifest = _run(NamingPipeline(config=Config()), tmp_path)
        # Gerçek parmak izi eşleşti (hat bu katmana gerçekten girdi)
        assert manifest.results["m_chalk"].npm_package == "chalk"
        assert net_guard == []
        dts = manifest.statistics.get("dts_naming", {})
        assert dts.get("remote_skipped_network_off") == 1
        assert dts.get("remote_fetched") == 0

    def test_no_config_never_touches_network(self, net_guard, tmp_path: Path) -> None:
        _run(NamingPipeline(), tmp_path)
        assert net_guard == []

    def test_network_on_but_dts_fetch_not_allowed(self, net_guard, tmp_path: Path) -> None:
        cfg = Config()
        cfg.network.enabled = True
        cfg.network.allow_dts_fetch = False
        _run(NamingPipeline(config=cfg), tmp_path)
        assert net_guard == []

    def test_dts_fetch_allowed_but_master_switch_off(self, net_guard, tmp_path: Path) -> None:
        cfg = Config()
        cfg.network.enabled = False
        cfg.network.allow_dts_fetch = True
        _run(NamingPipeline(config=cfg), tmp_path)
        assert net_guard == []

    def test_source_match_without_network_switch(self, net_guard, tmp_path: Path) -> None:
        cfg = Config()
        cfg.source_match.enabled = True   # ana anahtar (network.enabled) kapalı
        _run(NamingPipeline(config=cfg), tmp_path)
        assert net_guard == []

    def test_dts_fetch_allowed_reaches_network(self, net_guard, tmp_path: Path) -> None:
        # Pozitif küme: iki bayrak da açıkken uzak .d.ts yolu bağlı (bekçi engeller).
        cfg = Config()
        cfg.network.enabled = True
        cfg.network.allow_dts_fetch = True
        _run(NamingPipeline(config=cfg), tmp_path)
        urls = [c[1] for c in net_guard if c[0] == "urlopen"]
        assert urls and all("unpkg.com" in u and "chalk" in u for u in urls)


class TestDtsNamerDefault:
    def test_default_namer_is_offline(self, net_guard) -> None:
        assert DtsNamer().fetch_dts_content("chalk") is None
        assert net_guard == []
        res = DtsNamer().load_dts_for_package("chalk")
        assert res.success is False
        assert any("ağ izni yok" in e for e in res.errors)

    def test_explicit_permission_goes_to_network(self, net_guard) -> None:
        assert DtsNamer(allow_network=True, timeout=1).fetch_dts_content("chalk") is None
        assert any(c[0] == "urlopen" for c in net_guard)
