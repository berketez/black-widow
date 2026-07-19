"""ui/server.py güncelleme-kontrolü + indirme testleri.

KAPSAM:
  - semver karşılaştırma mantığı (_version_key)
  - /api/update-check gövdesi (_update_check): manifest parse, SSRF guard, throttle
  - /api/update-download akışı (_download_update_worker, _start_update_download):
    sha256 doğrulama, mount, "indirme yok/izinsiz" guard'ları

GERÇEK AĞ KULLANILMAZ -- urllib.request.urlopen monkeypatch ile taklit edilir.

TUZAK: ui/server.py bir paket modülü değil (ui/__init__.py yok). importlib ile
dosya yolundan yüklenir; __main__ guard'ı server'ı BAŞLATMAZ (import güvenli).
Bu, test_ui_disk_access.py ile aynı desendir.
"""
from __future__ import annotations

import importlib.util
import json
import urllib.parse
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


@pytest.fixture
def reset_dl(srv):
    """Modül-seviyesi indirme durumunu (global _UPDATE_DL) test öncesi/sonrası sıfırla."""
    def _reset():
        with srv._UPDATE_DL_LOCK:
            srv._UPDATE_DL.update(status="idle", downloaded=0, total=0, path=None,
                                  error=None, version=None, started_at=None)
    _reset()
    yield
    _reset()


def _allowed_host(srv) -> str:
    """Manifest URL'sinin host'u -- SSRF guard'ın kabul ettiği varsayılan host."""
    return urllib.parse.urlparse(srv._UPDATE_MANIFEST_URL).hostname


def _mk_url(srv, path: str) -> str:
    """İzinli host üzerinde https URL üret (SSRF guard'dan geçer)."""
    return f"https://{_allowed_host(srv)}{path}"


class _FakeResp:
    """urllib.request.urlopen'in döndürdüğü context-manager taklidi (manifest)."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _FakeDLResp:
    """İNDİRME için parça-parça okunabilen response taklidi (worker read(n) döngüsü)."""

    def __init__(self, body: bytes, content_length=None):
        self._body = body
        self._pos = 0
        cl = len(body) if content_length is None else content_length
        self.headers = {"Content-Length": str(cl)}

    def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._body):
            return b""
        chunk = self._body[self._pos:] if (n is None or n < 0) \
            else self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _patch_manifest(srv, monkeypatch, payload=None, *, raise_exc=None, raw=None):
    """urlopen'i taklit et: ya JSON manifest ya ham gövde ya da istisna."""
    def _fake_urlopen(req, timeout=None):
        if raise_exc is not None:
            raise raise_exc
        if raw is not None:
            return _FakeResp(raw)
        return _FakeResp(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(srv.urllib.request, "urlopen", _fake_urlopen)


def _manifest(srv, version="1.21.0", **over):
    """İzinli-host'lu geçerli manifest sözlüğü üret; alanları over ile ez."""
    m = {
        "version": version,
        "dmg_url": _mk_url(srv, f"/karadul/BlackWidow-{version}.dmg"),
        "sha256": "a" * 64,
        "size_bytes": 3_500_000_000,
        "notes_url": _mk_url(srv, f"/karadul/notes-{version}.html"),
        "published_at": "2026-07-19T00:00:00Z",
        "min_os": "12.0",
    }
    m.update(over)
    return m


# ==========================================================================
# _version_key: semver benzeri sıralama anahtarı (schema-bağımsız, DEĞİŞMEDİ)
# ==========================================================================
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


# ==========================================================================
# _is_allowed_update_url: SSRF / yönlendirme enjeksiyonu guard
# ==========================================================================
def test_ssrf_allows_manifest_host(srv):
    """Manifest host'undaki https URL kabul edilir."""
    assert srv._is_allowed_update_url(_mk_url(srv, "/karadul/x.dmg")) is True


def test_ssrf_rejects_foreign_host(srv):
    """Yabancı domain reddedilir."""
    assert srv._is_allowed_update_url("https://evil.example.com/x.dmg") is False


def test_ssrf_rejects_suffix_and_userinfo_tricks(srv):
    """'host.evil.com' ve 'host@evil.com' hostname TAM-eşleşme ile reddedilir."""
    host = _allowed_host(srv)
    assert srv._is_allowed_update_url(f"https://{host}.evil.com/x") is False
    assert srv._is_allowed_update_url(f"https://{host}@evil.com/x") is False


def test_ssrf_rejects_non_https(srv):
    """https-dışı şema (http/file/ftp) reddedilir."""
    host = _allowed_host(srv)
    assert srv._is_allowed_update_url(f"http://{host}/x.dmg") is False
    assert srv._is_allowed_update_url(f"file://{host}/x.dmg") is False
    assert srv._is_allowed_update_url("") is False
    assert srv._is_allowed_update_url(None) is False


def test_ssrf_extra_hosts_from_env(srv, monkeypatch):
    """KARADUL_UPDATE_ALLOWED_HOSTS ile ek host'lar canlı okunur."""
    assert srv._is_allowed_update_url("https://cdn.berke.dev/x.dmg") is False
    monkeypatch.setenv("KARADUL_UPDATE_ALLOWED_HOSTS", "cdn.berke.dev, mirror.berke.dev")
    assert srv._is_allowed_update_url("https://cdn.berke.dev/x.dmg") is True
    assert srv._is_allowed_update_url("https://mirror.berke.dev/x.dmg") is True


# ==========================================================================
# _update_check: manifest parse + sürüm kıyası (GERÇEK AĞ YOK)
# ==========================================================================
def test_update_available(srv, monkeypatch, tmp_path):
    """latest > current -> update_available + manifest alanları taşınır."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.21.0"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "update_available"
    assert r["current"] == "v1.20.0"
    assert r["latest"] == "1.21.0"
    assert r["dmg_url"] == _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg")
    assert r["sha256"] == "a" * 64
    assert r["size_bytes"] == 3_500_000_000
    assert r["notes_url"] == _mk_url(srv, "/karadul/notes-1.21.0.html")
    assert r["url"] == r["notes_url"]      # banner notlar bağlantısı
    assert r["error"] is None


def test_up_to_date_equal(srv, monkeypatch, tmp_path):
    """latest == current -> up_to_date."""
    monkeypatch.setattr(srv, "_current_version", lambda: "1.21.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.21.0"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "up_to_date"


def test_up_to_date_when_local_newer(srv, monkeypatch, tmp_path):
    """Yerel sürüm manifest'ten yeniyse -> up_to_date (indirme önerilmez)."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.30.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.21.0"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "up_to_date"


def test_prerelease_local_gets_update(srv, monkeypatch, tmp_path):
    """Yüklü '1.20.0-pre', yayınlanan '1.20.0' -> update_available."""
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0-pre")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.20.0"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "update_available"


def test_network_error_is_unknown(srv, monkeypatch, tmp_path):
    """Ağ hatası -> status 'unknown' + error dolu; ASLA istisna yaymaz."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, raise_exc=srv.urllib.error.URLError("ağ yok"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "unknown"
    assert r["error"]
    assert r["latest"] is None
    assert r["current"] == "v1.20.0"
    assert r["url"] == srv._RELEASES_URL   # graceful: releases URL yine dolu


def test_malformed_json_is_unknown(srv, monkeypatch, tmp_path):
    """Bozuk JSON gövdesi -> unknown (json.loads istisnası yutulur)."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, raw=b"<html>not json</html>")
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "unknown"
    assert r["error"]


def test_missing_version_is_unknown(srv, monkeypatch, tmp_path):
    """Manifest'te 'version' yoksa -> unknown."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, {"dmg_url": _mk_url(srv, "/x.dmg")})
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "unknown"
    assert r["latest"] is None


def test_untrusted_dmg_url_ignored(srv, monkeypatch, tmp_path):
    """Yabancı host'lu dmg_url/notes_url None kalır; sürüm kıyası yine çalışır."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(
        srv, "1.21.0",
        dmg_url="https://evil.example.com/pwn.dmg",
        notes_url="https://evil.example.com/notes.html"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["status"] == "update_available"
    assert r["dmg_url"] is None            # SSRF guard düşürdü
    assert r["notes_url"] is None
    assert r["url"] == srv._RELEASES_URL   # notes düşünce güvenli varsayılan


def test_bad_sha256_and_size_dropped(srv, monkeypatch, tmp_path):
    """Geçersiz sha256 (64-hex değil) ve negatif/aşırı size düşürülür (None)."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(
        srv, "1.21.0", sha256="xyz", size_bytes=-5))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert r["sha256"] is None
    assert r["size_bytes"] is None


def test_result_contract_keys(srv, monkeypatch, tmp_path):
    """Sözleşme: yeni indirme alanları dahil tüm anahtarlar bulunur."""
    monkeypatch.setattr(srv, "_current_version", lambda: "v1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.20.0"))
    r = srv._update_check(force=True, cache_path=tmp_path / "c.json")
    assert set(r) >= {"status", "current", "latest", "url", "error",
                      "dmg_url", "sha256", "size_bytes", "notes_url",
                      "published_at", "min_os", "checked_at", "from_cache"}
    assert r["status"] in ("update_available", "up_to_date", "unknown")


# ==========================================================================
# Throttle: 24 saatlik cache; force=1 atlar
# ==========================================================================
def _write_cache(path: Path, last_checked: float, result: dict) -> None:
    path.write_text(json.dumps({"last_checked": last_checked, "result": result}),
                    encoding="utf-8")


def test_throttle_serves_cache_without_network(srv, monkeypatch, tmp_path):
    """Taze cache varsa AĞA HİÇ ÇIKMAZ (urlopen patlasa da cache döner)."""
    import time
    cache = tmp_path / "c.json"
    _write_cache(cache, time.time(), {
        "status": "update_available", "latest": "1.30.0", "current": "old",
        "url": "https://x", "error": None})
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    # urlopen çağrılırsa test PATLAR -> cache gerçekten ağı atlıyor mu kanıtı
    _patch_manifest(srv, monkeypatch, raise_exc=AssertionError("ağ çağrıldı!"))
    r = srv._update_check(force=False, cache_path=cache)
    assert r["from_cache"] is True
    assert r["status"] == "update_available"
    assert r["current"] == "1.20.0"        # cache'lenen 'old' değil, canlı sürüm


def test_throttle_force_bypasses_cache(srv, monkeypatch, tmp_path):
    """force=True taze cache'i atlar -> ağ denenir."""
    import time
    cache = tmp_path / "c.json"
    _write_cache(cache, time.time(), {
        "status": "update_available", "latest": "1.30.0", "current": "old",
        "url": "https://x", "error": None})
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.25.0"))
    r = srv._update_check(force=True, cache_path=cache)
    assert r["from_cache"] is False
    assert r["latest"] == "1.25.0"         # ağdan gelen taze sürüm


def test_throttle_stale_cache_refetches(srv, monkeypatch, tmp_path):
    """25 saatlik cache bayat -> ağ denenir."""
    import time
    cache = tmp_path / "c.json"
    _write_cache(cache, time.time() - 25 * 3600, {
        "status": "up_to_date", "latest": "1.20.0", "current": "old",
        "url": "https://x", "error": None})
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.40.0"))
    r = srv._update_check(force=False, cache_path=cache)
    assert r["from_cache"] is False
    assert r["latest"] == "1.40.0"


def test_successful_check_writes_cache(srv, monkeypatch, tmp_path):
    """Başarılı kontrol cache'i yazar (sonraki kontrol ağsız dönebilir)."""
    cache = tmp_path / "c.json"
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    _patch_manifest(srv, monkeypatch, _manifest(srv, "1.21.0"))
    srv._update_check(force=True, cache_path=cache)
    assert cache.is_file()
    d = json.loads(cache.read_text(encoding="utf-8"))
    assert d["result"]["latest"] == "1.21.0"
    assert isinstance(d["last_checked"], (int, float))


def test_unknown_result_not_cached(srv, monkeypatch, tmp_path):
    """Ağ hatası (unknown) cache'lenmez -> 24 saat retry bloklanmaz."""
    cache = tmp_path / "c.json"
    monkeypatch.setattr(srv, "_current_version", lambda: "1.20.0")
    _patch_manifest(srv, monkeypatch, raise_exc=srv.urllib.error.URLError("yok"))
    srv._update_check(force=True, cache_path=cache)
    assert not cache.exists()


# ==========================================================================
# İndirme: sha256 doğrulama + mount (YERİNDE-DEĞİŞTİRMESİZ)
# ==========================================================================
def _patch_download(srv, monkeypatch, body: bytes, tmp_path, mount_calls):
    """urlopen (stream) + subprocess.run (mount) + ~/Downloads'ı taklit et."""
    monkeypatch.setattr(srv.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeDLResp(body))
    monkeypatch.setattr(srv, "_downloads_dir", lambda: tmp_path)

    def _fake_run(cmd, **kw):
        mount_calls.append(cmd)
        class _R:  # subprocess.run dönüşü taklidi
            returncode = 0
        return _R()

    monkeypatch.setattr(srv.subprocess, "run", _fake_run)


def test_download_verifies_sha256_and_mounts(srv, monkeypatch, tmp_path, reset_dl):
    """Doğru sha256 -> dosya yazılır, MOUNT edilir, status 'done'."""
    import hashlib
    body = b"FAKE DMG BYTES 12345"
    sha = hashlib.sha256(body).hexdigest()
    mount_calls = []
    _patch_download(srv, monkeypatch, body, tmp_path, mount_calls)

    srv._download_update_worker(
        _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg"), sha, len(body), "1.21.0")

    snap = srv._update_dl_snapshot()
    assert snap["status"] == "done"
    assert snap["error"] is None
    final = tmp_path / "BlackWidow-1.21.0.dmg"
    assert final.is_file()
    assert final.read_bytes() == body
    assert mount_calls and mount_calls[0][0] == "open"     # `open <dmg>` ile mount
    assert str(final) in mount_calls[0]
    assert not (tmp_path / "BlackWidow-1.21.0.dmg.part").exists()  # temp temizlendi


def test_download_rejects_sha256_mismatch_no_mount(srv, monkeypatch, tmp_path, reset_dl):
    """sha256 UYUŞMAZSA: dosya reddedilir, MOUNT EDİLMEZ, status 'error'."""
    body = b"FAKE DMG BYTES 12345"
    mount_calls = []
    _patch_download(srv, monkeypatch, body, tmp_path, mount_calls)

    srv._download_update_worker(
        _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg"), "b" * 64, len(body), "1.21.0")

    snap = srv._update_dl_snapshot()
    assert snap["status"] == "error"
    assert "sha256" in (snap["error"] or "")
    assert mount_calls == []                               # MOUNT edilmedi
    assert not (tmp_path / "BlackWidow-1.21.0.dmg").exists()      # final yazılmadı
    assert not (tmp_path / "BlackWidow-1.21.0.dmg.part").exists()  # temp silindi


def test_download_reports_progress_total(srv, monkeypatch, tmp_path, reset_dl):
    """İndirme total (Content-Length) ve downloaded'ı doğru raporlar."""
    import hashlib
    body = b"x" * 1000
    sha = hashlib.sha256(body).hexdigest()
    mount_calls = []
    _patch_download(srv, monkeypatch, body, tmp_path, mount_calls)

    srv._download_update_worker(
        _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg"), sha, 1000, "1.21.0")

    snap = srv._update_dl_snapshot()
    assert snap["total"] == 1000
    assert snap["downloaded"] == 1000
    assert snap["status"] == "done"


# ==========================================================================
# _start_update_download: guard'lar (SSRF + sha256 zorunlu) + tekil çalışma
# ==========================================================================
def test_start_download_rejected_when_no_update(srv, monkeypatch, reset_dl):
    """Güncelleme yoksa indirme başlamaz."""
    monkeypatch.setattr(srv, "_update_check", lambda *a, **k: {"status": "up_to_date"})
    r = srv._start_update_download()
    assert r["status"] == "error"
    assert srv._update_dl_snapshot()["status"] == "idle"


def test_start_download_rejected_without_sha256(srv, monkeypatch, reset_dl):
    """sha256 yoksa BÜTÜNLÜK doğrulanamaz -> indirme başlamaz."""
    monkeypatch.setattr(srv, "_update_check", lambda *a, **k: {
        "status": "update_available",
        "dmg_url": _mk_url(srv, "/x.dmg"), "sha256": None, "latest": "1.21.0"})
    r = srv._start_update_download()
    assert r["status"] == "error"
    assert "sha256" in (r["error"] or "")
    assert srv._update_dl_snapshot()["status"] == "idle"


def test_start_download_rejected_untrusted_dmg_url(srv, monkeypatch, reset_dl):
    """dmg_url izinli host'ta değilse indirme başlamaz (SSRF guard)."""
    monkeypatch.setattr(srv, "_update_check", lambda *a, **k: {
        "status": "update_available",
        "dmg_url": "https://evil.example.com/x.dmg",
        "sha256": "a" * 64, "latest": "1.21.0"})
    r = srv._start_update_download()
    assert r["status"] == "error"
    assert "SSRF" in (r["error"] or "") or "izinli" in (r["error"] or "")
    assert srv._update_dl_snapshot()["status"] == "idle"


def test_start_download_happy_path_spawns_worker(srv, monkeypatch, reset_dl):
    """Geçerli güncelleme -> slot 'downloading' olur, worker doğru args ile çağrılır."""
    import threading
    monkeypatch.setattr(srv, "_update_check", lambda *a, **k: {
        "status": "update_available",
        "dmg_url": _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg"),
        "sha256": "a" * 64, "size_bytes": 123, "latest": "1.21.0"})
    seen = {}
    done = threading.Event()

    def _fake_worker(dmg_url, sha256, size_bytes, version):
        seen.update(dmg_url=dmg_url, sha256=sha256, size_bytes=size_bytes, version=version)
        done.set()

    monkeypatch.setattr(srv, "_download_update_worker", _fake_worker)
    srv._start_update_download()
    assert done.wait(2.0)                  # worker thread gerçekten koştu
    assert seen["dmg_url"] == _mk_url(srv, "/karadul/BlackWidow-1.21.0.dmg")
    assert seen["sha256"] == "a" * 64
    assert seen["size_bytes"] == 123
    assert seen["version"] == "1.21.0"


def test_start_download_no_double_start(srv, monkeypatch, reset_dl):
    """Zaten indiriyorken ikinci istek yeni worker BAŞLATMAZ."""
    monkeypatch.setattr(srv, "_update_check", lambda *a, **k: {
        "status": "update_available",
        "dmg_url": _mk_url(srv, "/x.dmg"), "sha256": "a" * 64, "latest": "1.21.0"})
    called = []
    monkeypatch.setattr(srv, "_download_update_worker",
                        lambda *a, **k: called.append(a))
    # elle "indiriliyor" durumuna sok
    with srv._UPDATE_DL_LOCK:
        srv._UPDATE_DL.update(status="downloading")
    r = srv._start_update_download()
    assert r["status"] == "downloading"
    assert called == []                    # ikinci worker başlamadı
