"""P17 / MEK-04 (= ARAYUZ-16, K-6): güncelleme sorgusu öntanımlı KAPALI ve ağ ayarına bağlı.

Eskiden pencere her açılışta (24 saatte bir önbellekle) GitHub'a istek atıyordu; kapatma ayarı
yoktu ve `network.enabled = false` iken de gidiyordu. Artık:
- ağ erişimi kapalıyken hiçbir güncelleme isteği gitmez (menüden açık istek dahil);
- açılıştaki otomatik sorgu ayrıca "Güncelleme denetimi" tercihini ister (öntanım kapalı);
- menüden açık istek ve "İndir ve Aç" yalnız ağ erişimini ister.
Ağ kullanılmaz: urllib.request.urlopen sahte; çağrılıp çağrılmadığı sayılır.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"


class _Resp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_upd", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "_SETTINGS_YAML", tmp_path / "karadul.yaml")
    monkeypatch.setattr(mod, "_DATA_ROOT", tmp_path)
    calls: list = []

    def _fake_urlopen(req, timeout=None):
        calls.append(getattr(req, "full_url", req))
        return _Resp(json.dumps({"version": "999.0.0"}).encode())

    monkeypatch.setattr(mod.urllib.request, "urlopen", _fake_urlopen)
    mod._calls = calls
    return mod


def _network(srv, on: bool):
    srv._SETTINGS_YAML.write_text(f"network:\n  enabled: {'true' if on else 'false'}\n")


def test_default_no_request_on_startup(srv, tmp_path):
    """Hiç ayar yok (ilk açılış): açılış sorgusu ağa çıkmaz."""
    r = srv._update_check(cache_path=tmp_path / "c.json")
    assert r["status"] == "disabled"
    assert "ağ erişimi kapalı" in r["error"]
    assert srv._calls == []
    assert not (tmp_path / "c.json").exists()


def test_network_off_blocks_even_explicit(srv, tmp_path):
    _network(srv, False)
    srv._write_ui_prefs({"update_check": True})
    for explicit in (False, True):
        r = srv._update_check(force=True, cache_path=tmp_path / "c.json", explicit=explicit)
        assert r["status"] == "disabled"
    assert srv._calls == []


def test_network_on_pref_off_blocks_startup_only(srv, tmp_path):
    _network(srv, True)
    r = srv._update_check(cache_path=tmp_path / "c.json")
    assert r["status"] == "disabled"
    assert "Güncelleme denetimi" in r["error"]
    assert srv._calls == []
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json", explicit=True)
    assert r["status"] == "update_available"
    assert len(srv._calls) == 1


def test_network_on_pref_on_allows_startup(srv, tmp_path):
    _network(srv, True)
    srv._write_ui_prefs({"update_check": True})
    r = srv._update_check(cache_path=tmp_path / "c.json")
    assert r["status"] == "update_available"
    assert len(srv._calls) == 1


def test_loader_problem_counts_as_closed(srv, tmp_path):
    srv._SETTINGS_YAML.write_text("network:\n  enabled: true\nbilinmeyen:\n  x: 1\n")
    srv._write_ui_prefs({"update_check": True})
    r = srv._update_check(cache_path=tmp_path / "c.json")
    assert r["status"] == "disabled"
    assert srv._calls == []


def test_download_refused_when_network_off(srv):
    _network(srv, False)
    r = srv._start_update_download()
    assert r["status"] == "error"
    assert "ağ erişimi kapalı" in r["error"]
    assert srv._calls == []


def test_endpoint_startup_vs_menu(srv, monkeypatch):
    """Uç: force yoksa (açılış) explicit=False, force=1 (menü) explicit=True."""
    seen = []
    monkeypatch.setattr(srv, "_update_check",
                        lambda *a, **k: seen.append(k) or {"status": "disabled", "error": "x"})

    class _H(srv.Handler):
        def __init__(self, path):
            self.path = path
            self.headers = {"Host": f"127.0.0.1:{srv._PORT}", "X-Karadul-Token": srv._TOKEN}
            self.sent = None

        def _json(self, obj, code=200):
            self.sent = (code, obj)

    for path in ("/api/update-check", "/api/update-check?force=1"):
        _H(path).do_GET()
    assert seen == [{"force": False, "explicit": False}, {"force": True, "explicit": True}]


def test_prefs_roundtrip_and_bad_file(srv, tmp_path):
    assert srv._read_ui_prefs() == {"update_check": False}
    (tmp_path / "ui_prefs.json").write_text("{bozuk")
    assert srv._read_ui_prefs() == {"update_check": False}
    (tmp_path / "ui_prefs.json").write_text(json.dumps({"update_check": "true"}))
    assert srv._read_ui_prefs() == {"update_check": False}     # dizgi bool sayılmaz
    out = srv._write_settings({"update_check": True, "network_enabled": True})
    assert out["knobs"]["update_check"] is True
    assert srv._read_ui_prefs() == {"update_check": True}
    # tercih karadul.yaml'a yazılmaz (katı yükleyici bilinmeyen anahtarı reddeder)
    assert "update_check" not in srv._SETTINGS_YAML.read_text()
    assert srv._read_settings()["errors"] == []


def test_settings_panel_has_update_toggle():
    html = (_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    assert 'id="cfgUpd"' in html
    assert "update_check:$('cfgUpd')" in html


def test_menu_reports_disabled_reason():
    src = (_ROOT / "ui" / "app_window.py").read_text(encoding="utf-8")
    assert 'info.get("status") == "disabled"' in src
