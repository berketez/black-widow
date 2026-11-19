"""P22c1 — KaradulLM kısıtlı terminalinin arayüz sunucusu uçları (``ui/server.py``; KaradulLM v2 tasarımı §4.2,
§4.3, §4.6, §4.7).

Bölümler:
  (3) tek komutluk izin listesi: ``POST /api/lm/terminal/komut`` yalnız tam ``karadullm``'i kabul eder; başka her
      girdi 400 + içeriksiz denetim kaydı; oturum açma süreç başlatmaz; tek oturum.

Gerçek model yok, Ghidra yok: arayüz sunucusu gerçek ``ThreadingHTTPServer`` olarak rastgele kapıda koşar;
çalışma alanı sentetik (``tests/test_lm_tools.py``); model işi gereken yerde sahte arka uç. Depolar (defter,
denetim, ad deposu) geçici dizinde: kullanıcının ``~/.karadul``'una yazılmaz.
Mutasyon koruması: ``scripts/measurement/mutation_specs_ui_lm_api.json``.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from karadul.core import overrides
from karadul.lm import session as S
from tests.test_lm_repl import DUSMAN
from tests.test_lm_tools import default_ws

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"
_TOKEN = "t0ken-lm-test"
SHA = "c4" * 32


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ws(root: Path, *, report: bool = True) -> Path:
    ws = default_ws(root / "ws")
    if report:
        (ws / "reports").mkdir()
        (ws / "reports" / "report.json").write_text(json.dumps({"target": {"hash": SHA}}), encoding="utf-8")
    return ws


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    """Sunucu modülü + gerçek HTTP sunucusu; depolar geçici dizinde; çalışma alanı etkin."""
    for k in ("KARADUL_LLAMA_SERVER", "KARADUL_LM_MODEL", "KARADUL_LM_SABLON"):
        monkeypatch.delenv(k, raising=False)
    mod = _load("bw_ui_server_lm_api")
    ov = tmp_path / "overrides"
    ov.mkdir()
    monkeypatch.setattr(overrides, "overrides_dir", lambda: ov)
    mod._LM_STORE_ROOT = tmp_path / "lm"
    mod._ov_dir = ov
    mod._ws_path = _ws(tmp_path)
    mod.activate_workspace(str(mod._ws_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    mod._PORT = httpd.server_address[1]
    mod._TOKEN = _TOKEN
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mod
    s = S.current_session()
    if s is not None:
        s.close()
    mod.activate_workspace(None)
    httpd.shutdown()
    httpd.server_close()


def req(mod, method: str, path: str, body=None, *, token: str | None = _TOKEN, host: str | None = None,
        origin: str | None = None, raw: bytes | None = None, timeout: float = 30):
    """(durum, JSON gövde) döndürür."""
    conn = http.client.HTTPConnection("127.0.0.1", mod._PORT, timeout=timeout)
    h = {"Host": host or f"127.0.0.1:{mod._PORT}"}
    if token is not None:
        h["X-Karadul-Token"] = token
    if origin is not None:
        h["Origin"] = origin
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode("utf-8"))
    if data is not None:
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(out)
    except ValueError:
        return resp.status, out


def komut(mod, k="karadullm"):
    return req(mod, "POST", "/api/lm/terminal/komut", {"komut": k})


# --------------------------------------------------------------------------------------------
# (3) tek komutluk izin listesi + oturum açma


def test_komut_izin_listesi_tek_oge_dusman_girdiler_reddedilir(srv):
    kotu = list(DUSMAN) + [None, 0, ["karadullm"], {"komut": "karadullm"}, "karadullm\u0000"]
    for k in kotu:
        st, b = komut(srv, k)
        assert (st, b.get("hata")) == (400, "izin verilmeyen komut"), k
        assert b["satir"] == "bu terminal yalnız `karadullm` çalıştırır"
    assert S.current_session() is None                                     # hiçbiri oturum açmadı
    # gövdesiz / bozuk JSON da komut değildir
    assert req(srv, "POST", "/api/lm/terminal/komut", raw=b"{bozuk")[0] == 400
    assert req(srv, "POST", "/api/lm/terminal/komut")[0] == 400
    # denetim kaydı içeriksiz: her ret bir satır, metin yok (yalnız uzunluk + sha256)
    kayit = (srv._LM_STORE_ROOT / "arayuz-komut.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(kayit) == len(kotu) + 2
    for satir_ in kayit:
        k = json.loads(satir_)
        assert k["olay"] == "komut_reddedildi" and set(k) == {"olay", "zaman", "uzunluk", "sha256"}
    metin = "\n".join(kayit)
    assert "ls" not in metin and "bash" not in metin and "--model" not in metin


def test_komut_karadullm_tek_oturum_acar_surec_baslatmaz(srv, monkeypatch):
    acilan = []
    monkeypatch.setattr(srv.subprocess, "Popen", lambda *a, **k: acilan.append(a) or (_ for _ in ()).throw(
        AssertionError("süreç açılmamalı")))
    st, b = komut(srv, "  karadullm ")                                    # yalnız U+0020 kırpılır
    assert st == 200 and set(b) == {"oturum"}
    s = S.current_session()
    assert s is not None and s.id == b["oturum"] and s.backend is None     # model yapılandırılmamış: modelsiz
    assert s.workspace_root == srv._ws_path and s.binary_sha256 == SHA
    ilk = s.stream.since(0)["olaylar"][0]
    assert ilk["tur"] == "oturum_basladi" and ilk["arka_uc"] == "yok"
    st, b2 = komut(srv)
    assert (st, b2["hata"]) == (400, "oturum zaten açık") and S.current_session() is s
    assert acilan == []
    # analiz sürüyorsa oturum model başlatmaz ve yazmaz (G6): oturum arayüzün süren işine bağlı
    monkeypatch.setattr(srv, "_running_job", lambda: "j1")
    assert s._analysis_running() is True


def test_komut_calisma_alani_ya_da_ozet_yoksa_acilmaz(srv, tmp_path):
    srv.activate_workspace(None)
    st, b = komut(srv)
    assert (st, b["hata"]) == (400, "çalışma alanı yok: önce bir analiz sonucu açın")
    ozetsiz = _ws(tmp_path / "b", report=False)
    srv.activate_workspace(str(ozetsiz))
    st, b = komut(srv)
    assert st == 400 and b["hata"].startswith("çalışma alanında ikilinin özeti yok")
    assert S.current_session() is None


def test_komut_model_ikilisi_denetlenir_surec_acilmaz(srv, tmp_path, monkeypatch):
    sahte = tmp_path / "bin" / "sunucu"
    sahte.parent.mkdir()
    sahte.write_text("#!/bin/sh\nexit 0\n")
    sahte.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(sahte))
    st, b = komut(srv)                                                     # model eksik
    assert st == 400 and "birlikte verilmeli" in b["hata"] and S.current_session() is None
    monkeypatch.setenv("KARADUL_LM_MODEL", str(tmp_path / "m.gguf"))
    st, b = komut(srv)                                                     # adı llama-server değil
    assert st == 400 and b["hata"].startswith("model başlatılmaz") and "llama-server" in b["hata"]
    hedef = srv._ws_path / "raw"
    hedef.mkdir()
    ici = hedef / "llama-server"                                           # çalışma alanının içinde
    ici.write_text("#!/bin/sh\nexit 0\n")
    ici.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(ici))
    st, b = komut(srv)
    assert st == 400 and "çalışma alanının içinde" in b["hata"] and S.current_session() is None
    # geçerli ad, çalışma alanı dışı: arka uç kurulur ama süreç açılmaz (ilk model isteğinde başlar)
    dogru = tmp_path / "bin" / "llama-server"
    dogru.write_text("#!/bin/sh\nexit 0\n")
    dogru.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLAMA_SERVER", str(dogru))
    monkeypatch.setattr(srv.LlamaServerBackend, "start", lambda self: (_ for _ in ()).throw(
        AssertionError("açılışta sunucu başlamamalı")))
    st, b = komut(srv)
    assert st == 200
    s = S.current_session()
    assert s.backend.kind == "yerel_llama_server" and s.backend.pid is None
    assert s.backend.state_dir == srv._LM_STORE_ROOT / "sunucu"
