"""ui/server.py disk-erişimi (FDA) mantığı testleri.

KAPSAM: yalnızca saf tespit/yönlendirme mantığı. Ghidra ÇAĞIRMAZ, ağ KULLANMAZ,
Sistem Ayarları'nı AÇMAZ (subprocess.run monkeypatch'lenir). Gerçek TCC.db'yi
OKUMAZ (probe temp dosyaya yönlendirilir) -> CI/dev makinesinin FDA durumundan
bağımsız deterministik.

TUZAK: ui/server.py bir paket modülü değil (ui/__init__.py yok). importlib ile
dosya yolundan yüklenir; __main__ guard'ı server'ı BAŞLATMAZ (import güvenli).
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_SERVER_PY = Path(__file__).resolve().parent.parent / "ui" / "server.py"


@pytest.fixture(scope="module")
def srv():
    """ui/server.py'yi izole modül olarak yükle (server başlatmadan)."""
    spec = importlib.util.spec_from_file_location("bw_ui_server", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fda_true_when_probe_readable(srv, tmp_path, monkeypatch):
    """Probe okunabiliyorsa (FDA benzeri) True."""
    probe = tmp_path / "readable.db"
    probe.write_bytes(b"x")
    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv, "_TCC_PROBE", probe)
    assert srv._full_disk_access() is True


def test_fda_false_on_permission_denied(srv, tmp_path, monkeypatch):
    """Probe okunamıyorsa (PermissionError = TCC reddi) False."""
    if os.geteuid() == 0:
        pytest.skip("root her şeyi okur; PermissionError üretilemez")
    probe = tmp_path / "denied.db"
    probe.write_bytes(b"x")
    os.chmod(probe, 0)  # sahibi bile okuyamaz
    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv, "_TCC_PROBE", probe)
    try:
        assert srv._full_disk_access() is False
    finally:
        os.chmod(probe, 0o600)  # tmp temizliği unlink edebilsin


def test_fda_false_on_missing_probe(srv, monkeypatch):
    """Probe dosyası yoksa (OSError) False -- asla exception yaymaz."""
    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv, "_TCC_PROBE", Path("/kesinlikle/olmayan/tcc.db"))
    assert srv._full_disk_access() is False


def test_fda_true_off_mac(srv, monkeypatch):
    """mac dışında TCC kavramı yok -> kısıtlama yok -> True."""
    monkeypatch.setattr(srv, "_IS_MAC", False)
    assert srv._full_disk_access() is True


def test_disk_access_shape(srv):
    """Sözleşme: gerekli anahtarlar + doğru tipler; ASLA patlamaz."""
    d = srv._disk_access()
    assert set(d) >= {"full_disk_access", "protected_folders", "is_macos", "probe"}
    assert isinstance(d["full_disk_access"], bool)
    assert isinstance(d["protected_folders"], dict)
    assert set(d["protected_folders"]) == {"desktop", "documents", "downloads"}
    for v in d["protected_folders"].values():
        assert isinstance(v, bool)
    assert isinstance(d["is_macos"], bool)


def test_open_fda_settings_off_mac(srv, monkeypatch):
    """mac dışında yönlendirme anlamsız -> 400 (Sistem Ayarları açılmaz)."""
    monkeypatch.setattr(srv, "_IS_MAC", False)
    r = srv._open_fda_settings()
    assert r.get("__code") == 400


def test_open_fda_settings_success(srv, monkeypatch):
    """`open` başarılı (rc=0) -> ok=True + doğru pane URL. GERÇEKTEN açmaz
    (subprocess.run monkeypatch'li)."""
    class _P:
        returncode = 0
        stdout = ""

    called = {}

    def _fake_run(cmd, **kw):
        called["cmd"] = cmd
        return _P()

    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv.subprocess, "run", _fake_run)
    r = srv._open_fda_settings()
    assert r["ok"] is True
    assert r["returncode"] == 0
    assert "Privacy_AllFiles" in r["pane"]
    # `open` <url> çağrıldı mı?
    assert called["cmd"][0] == "open"
    assert called["cmd"][1] == srv._FDA_PANE_URL


def test_open_fda_settings_failure(srv, monkeypatch):
    """`open` başarısız (rc!=0) -> ok=False (endpoint yine de 200 döner)."""
    class _P:
        returncode = 1
        stdout = "hata"

    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv.subprocess, "run", lambda cmd, **kw: _P())
    r = srv._open_fda_settings()
    assert r["ok"] is False
    assert "__code" not in r  # 500 değil; sadece ok=False


def test_open_fda_settings_subprocess_error(srv, monkeypatch):
    """subprocess patlarsa -> 500 döner ama exception YAYMAZ."""
    def _boom(cmd, **kw):
        raise OSError("open yok")

    monkeypatch.setattr(srv, "_IS_MAC", True)
    monkeypatch.setattr(srv.subprocess, "run", _boom)
    r = srv._open_fda_settings()
    assert r.get("__code") == 500


def test_about_payload_has_disk_access(srv):
    """/api/about sözleşmesi disk_access alanını (canlı) içerir + eski alanlar durur."""
    d = srv._about_payload()
    assert "disk_access" in d
    assert isinstance(d["disk_access"]["full_disk_access"], bool)
    # gnulib/bugün eklenen sözleşme bozulmadı:
    for k in ("app", "engine", "ghidra", "jdk", "signatures", "paths", "stats", "notes"):
        assert k in d
