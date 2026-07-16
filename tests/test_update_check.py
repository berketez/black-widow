"""ui/server.py güncelleme-kontrolü (bildirim-temelli) testleri.

KAPSAM: semver karşılaştırma mantığı (_version_key) + /api/update-check
gövdesi (_update_check). GERÇEK AĞ KULLANILMAZ -- GitHub API yanıtı
monkeypatch ile taklit edilir (urllib.request.urlopen değiştirilir).

TUZAK: ui/server.py bir paket modülü değil (ui/__init__.py yok). importlib ile
dosya yolundan yüklenir; __main__ guard'ı server'ı BAŞLATMAZ (import güvenli).
Bu, test_ui_disk_access.py ile aynı desendir.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"


@pytest.fixture(scope="module")
def srv():
    """ui/server.py'yi izole modül olarak yükle (server başlatmadan)."""
    spec = importlib.util.spec_from_file_location("bw_ui_server_upd", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeResp:
    """urllib.request.urlopen'in döndürdüğü context-manager taklidi."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _patch_github(srv, monkeypatch, payload=None, *, raise_exc=None, raw=None):
    """urlopen'i taklit et: ya JSON payload ya ham gövde ya da istisna."""
    def _fake_urlopen(req, timeout=None):
        if raise_exc is not None:
            raise raise_exc
        if raw is not None:
            return _FakeResp(raw)
        return _FakeResp(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(srv.urllib.request, "urlopen", _fake_urlopen)


# --------------------------------------------------------------------------
# _version_key: semver benzeri sıralama anahtarı
# --------------------------------------------------------------------------
def test_version_key_strips_v_prefix(srv):
    """'v' öneki normalize edilir: v1.20.0 == 1.20.0."""
    assert srv._version_key("v1.20.0") == srv._version_key("1.20.0")
    assert srv._version_key("V1.20.0") == srv._version_key("1.20.0")


def test_version_key_newer_greater(srv):
    """1.21.0 > 1.20.0 (küçük sürüm); 2.0.0 > 1.99.99 (büyük sürüm)."""
    assert srv._version_key("v1.21.0") > srv._version_key("v1.20.0")
    assert srv._version_key("2.0.0") > srv._version_key("1.99.99")
    assert srv._version_key("1.20.1") > srv._version_key("1.20.0")


def test_version_key_numeric_not_string_ordering(srv):
    """Bileşenler NUMERİK sıralanır, string DEĞİL: 1.9.0 < 1.20.0.

    String karşılaştırmada '9' > '2' olduğu için naif '1.9.0' > '1.20.0'
    doğrudur (klasik semver bug'ı). _version_key int-tuple ürettiği için
    doğru sonucu vermeli. Bu test o regresyonu yakalar.
    """
    assert srv._version_key("1.9.0") < srv._version_key("1.20.0")
    assert srv._version_key("1.20.0") > srv._version_key("1.9.0")
    assert srv._version_key("1.8.0") < srv._version_key("1.10.0")
    assert srv._version_key("1.20.0") > srv._version_key("1.19.99")
    # minör tek-hane vs çift-hane, string olsa '2' < '9' tuzağı
    assert srv._version_key("v1.9.5") < srv._version_key("v1.10.0")


def test_version_key_release_beats_prerelease(srv):
    """Yayın sürümü aynı çekirdeğin ön-sürümünden BÜYÜK: 1.20.0 > 1.20.0-pre."""
    assert srv._version_key("1.20.0") > srv._version_key("1.20.0-pre")
    assert srv._version_key("v1.20.0") > srv._version_key("v1.20.0-rc.1")


def test_version_key_prerelease_ordering(srv):
    """Ön-sürüm tanımlayıcıları semver'e göre sıralanır."""
    assert srv._version_key("1.20.0-alpha") < srv._version_key("1.20.0-beta")
    # daha çok tanımlayıcı = daha büyük öncelik (alpha < alpha.1)
    assert srv._version_key("1.20.0-alpha") < srv._version_key("1.20.0-alpha.1")
    # numerik tanımlayıcı alnum'dan düşük öncelikli (1 < pre)
    assert srv._version_key("1.20.0-1") < srv._version_key("1.20.0-pre")


def test_version_key_pads_missing_components(srv):
    """Eksik bileşenler sıfırla doldurulur: 1.2 -> (1,2,0)."""
    assert srv._version_key("1.2") == srv._version_key("1.2.0")
    assert srv._version_key("v2") == srv._version_key("2.0.0")


def test_version_key_ignores_build_metadata(srv):
    """+build metadata karşılaştırmayı etkilemez."""
    assert srv._version_key("1.20.0+abc") == srv._version_key("1.20.0")


def test_version_key_unparsable_is_none(srv):
    """Sürümsüz/anlaşılmaz girdi -> None (karşılaştırılamaz)."""
    assert srv._version_key("garbage") is None
    assert srv._version_key("") is None
    assert srv._version_key(None) is None
    assert srv._version_key("v") is None


# --------------------------------------------------------------------------
# _update_check: uçtan uca (GitHub API mock'lu, GERÇEK AĞ YOK)
# --------------------------------------------------------------------------
def test_update_available(srv, monkeypatch):
    """latest > current -> update_available + doğru alanlar."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, {
        "tag_name": "v1.21.0",
        "html_url": "https://github.com/berketez/black-widow/releases/tag/v1.21.0",
    })
    r = srv._update_check()
    assert r["status"] == "update_available"
    assert r["current"] == "v1.20.0"
    assert r["latest"] == "v1.21.0"
    assert r["url"] == "https://github.com/berketez/black-widow/releases/tag/v1.21.0"
    assert r["error"] is None


def test_up_to_date_equal(srv, monkeypatch):
    """latest == current -> up_to_date."""
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    _patch_github(srv, monkeypatch, {"tag_name": "v1.20.0"})
    r = srv._update_check()
    assert r["status"] == "up_to_date"


def test_up_to_date_when_local_newer(srv, monkeypatch):
    """Yerel sürüm release'ten yeniyse (dev önde) -> up_to_date (indirme önerilmez)."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.30.0")
    _patch_github(srv, monkeypatch, {"tag_name": "v1.20.0"})
    r = srv._update_check()
    assert r["status"] == "up_to_date"


def test_prerelease_local_gets_update(srv, monkeypatch):
    """Yüklü '1.20.0-pre', yayınlanan 'v1.20.0' -> update_available."""
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0-pre")
    _patch_github(srv, monkeypatch, {"tag_name": "v1.20.0"})
    r = srv._update_check()
    assert r["status"] == "update_available"


def test_network_error_is_unknown(srv, monkeypatch):
    """Ağ hatası -> status 'unknown' + error dolu; ASLA istisna yaymaz."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, raise_exc=srv.urllib.error.URLError("ağ yok"))
    r = srv._update_check()
    assert r["status"] == "unknown"
    assert r["error"]           # boş değil
    assert r["latest"] is None
    assert r["current"] == "v1.20.0"
    # graceful sözleşme: releases URL yine de dolu
    assert r["url"] == srv._RELEASES_URL


def test_malformed_json_is_unknown(srv, monkeypatch):
    """Bozuk JSON gövdesi -> unknown (json.loads istisnası yutulur)."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, raw=b"<html>not json</html>")
    r = srv._update_check()
    assert r["status"] == "unknown"
    assert r["error"]


def test_missing_tag_is_unknown(srv, monkeypatch):
    """tag_name/name yoksa -> unknown, 'release bulunamadi'."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, {"foo": "bar"})
    r = srv._update_check()
    assert r["status"] == "unknown"
    assert r["latest"] is None


def test_untrusted_html_url_ignored(srv, monkeypatch):
    """github.com dışı html_url yoksayılır -> güvenli varsayılan releases URL."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, {
        "tag_name": "v1.21.0",
        "html_url": "https://evil.example.com/pwn",
    })
    r = srv._update_check()
    assert r["status"] == "update_available"
    assert r["url"] == srv._RELEASES_URL   # kötü URL alınmadı


def test_falls_back_to_name_when_no_tag(srv, monkeypatch):
    """tag_name yoksa 'name' alanına düşer."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, {"name": "v1.25.0"})
    r = srv._update_check()
    assert r["latest"] == "v1.25.0"
    assert r["status"] == "update_available"


def test_result_contract_keys(srv, monkeypatch):
    """Sözleşme: her yol için gerekli anahtarlar bulunur."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_github(srv, monkeypatch, {"tag_name": "v1.20.0"})
    r = srv._update_check()
    assert set(r) >= {"status", "current", "latest", "url", "error"}
    assert r["status"] in ("update_available", "up_to_date", "unknown")
