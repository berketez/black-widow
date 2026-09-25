"""ui/server.py yerel istek koruması (Handler._guard / _read_body) testleri.

Tehdit: sunucu 127.0.0.1'e bağlı ama tarayıcıda açık herhangi bir sayfa bu porta
istek atabilir (CSRF) ve DNS rebinding ile yanıtları okuyabilir. Koruma: Host beyaz
listesi, aynı-köken Origin, /api/ping dışındaki /api/* için X-Karadul-Token, sınırlı
POST gövdesi.

Gerçek bir ThreadingHTTPServer rastgele portta başlatılır; istekler http.client ile
Host/Origin/jeton başlıkları elle verilerek atılır. Yalnız yan etkisiz uçlar kullanılır:
geçersiz adresli /api/rename (400, hiçbir şey yazmaz) ve salt okunur /api/about.

TUZAK: ui/server.py paket modülü değil (ui/__init__.py yok) -> importlib ile dosya
yolundan yüklenir; __main__ guard server'ı başlatmaz.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"
_TOKEN = "t0ken-test"
_BAD_ADDR_BODY = json.dumps({"addr": "NOT_AN_ADDR", "name": "x"})


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def srv():
    """Modülü yükle, Handler'ı gerçek bir HTTP sunucusunda rastgele portta başlat."""
    mod = _load("bw_ui_server_guard")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    mod._PORT = httpd.server_address[1]
    mod._TOKEN = _TOKEN
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield mod
    httpd.shutdown()
    httpd.server_close()


def _req(mod, method: str, path: str, *, host: str | None = None,
         origin: str | None = None, token: str | None = None,
         body: str | None = None, headers: dict | None = None):
    """(status, response headers, gövde) döndür."""
    conn = http.client.HTTPConnection("127.0.0.1", mod._PORT, timeout=10)
    h = {"Host": host or f"127.0.0.1:{mod._PORT}"}
    if origin is not None:
        h["Origin"] = origin
    if token is not None:
        h["X-Karadul-Token"] = token
    if headers:
        h.update(headers)
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.headers, data


# -- Host (DNS rebinding) ------------------------------------------------------

def test_ping_with_valid_host_returns_token(srv):
    status, _, data = _req(srv, "GET", "/api/ping")
    assert status == 200
    assert json.loads(data)["token"] == _TOKEN


def test_localhost_host_is_accepted(srv):
    status, _, _ = _req(srv, "GET", "/api/ping", host=f"localhost:{srv._PORT}")
    assert status == 200


def test_foreign_host_cannot_read_token(srv):
    """DNS rebinding: Host saldırganın alan adıdır -> jeton sızmamalı."""
    status, _, data = _req(srv, "GET", "/api/ping", host=f"evil.example:{srv._PORT}")
    assert status == 403
    assert _TOKEN.encode() not in data


def test_foreign_host_cannot_load_page(srv):
    status, _, data = _req(srv, "GET", "/", host=f"evil.example:{srv._PORT}")
    assert status == 403
    assert _TOKEN.encode() not in data


# -- Jeton ---------------------------------------------------------------------

def test_api_get_requires_token(srv):
    status, _, _ = _req(srv, "GET", "/api/about")
    assert status == 403
    status, _, _ = _req(srv, "GET", "/api/about", token=_TOKEN)
    assert status == 200


def test_wrong_token_rejected(srv):
    status, _, _ = _req(srv, "GET", "/api/about", token="yanlis")
    assert status == 403


def test_non_ascii_token_header_rejected_without_crash(srv):
    """ASCII dışı başlık compare_digest'te TypeError'a yol açmamalı; 403 dönmeli."""
    status, _, _ = _req(srv, "GET", "/api/about", token="t0ken-tésté")
    assert status == 403


def test_post_without_token_rejected(srv):
    status, _, _ = _req(srv, "POST", "/api/rename", body=_BAD_ADDR_BODY,
                        headers={"Content-Type": "text/plain"})
    assert status == 403


# -- Origin (CSRF) ---------------------------------------------------------------

def test_cross_origin_post_rejected_even_with_token(srv):
    status, _, _ = _req(srv, "POST", "/api/rename", origin="https://evil.example",
                        token=_TOKEN, body=_BAD_ADDR_BODY)
    assert status == 403


def test_same_origin_post_with_token_reaches_handler(srv):
    status, _, data = _req(srv, "POST", "/api/rename", origin=f"http://127.0.0.1:{srv._PORT}",
                           token=_TOKEN, body=_BAD_ADDR_BODY)
    assert status == 400
    assert "geçersiz adres" in json.loads(data)["error"]


# -- Gövde -----------------------------------------------------------------------

def test_oversized_body_rejected_before_reading(srv):
    status, _, _ = _req(srv, "POST", "/api/rename", token=_TOKEN,
                        headers={"Content-Length": str(srv._MAX_BODY + 1)})
    assert status == 413


def test_negative_content_length_rejected(srv):
    status, _, _ = _req(srv, "POST", "/api/rename", token=_TOKEN,
                        headers={"Content-Length": "-5"})
    assert status == 400


def test_non_object_json_body_does_not_crash(srv):
    """Liste gövdesi eskiden body.get'te AttributeError ile işleyiciyi düşürüyordu."""
    status, _, data = _req(srv, "POST", "/api/rename", token=_TOKEN, body="[1, 2]")
    assert status == 400
    assert "geçersiz adres" in json.loads(data)["error"]


# -- Sayfa -----------------------------------------------------------------------

def test_index_embeds_token_and_is_not_cached(srv):
    status, headers, data = _req(srv, "GET", "/")
    assert status == 200
    assert _TOKEN.encode() in data
    assert b"__KARADUL_TOKEN__" not in data
    assert headers.get("Cache-Control") == "no-store"


def test_default_token_is_random_when_env_missing(monkeypatch):
    """Env'de jeton yoksa (tek başına dev koşusu) boş değil, rastgele jeton üretilir."""
    monkeypatch.delenv("KARADUL_TOKEN", raising=False)
    mod = _load("bw_ui_server_guard_default_token")
    assert len(mod._TOKEN) == 32
    assert mod._TOKEN != _load("bw_ui_server_guard_default_token2")._TOKEN
