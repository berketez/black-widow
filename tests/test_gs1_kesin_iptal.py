"""GS-1 (A-36): arayüzün iptali kesin — süreç grubuna SIGTERM, bekle, hâlâ yaşayana SIGKILL.

Eskiden ``_kill_proc`` yalnız SIGTERM gönderiyordu. Süreç içi JVM SIGTERM'i kendi kapanışına çevirir
ve kapanış kancası GIL'i bekler; C düzeyinde takılı bir düzenli ifade GIL'i bırakmadığı için süreç
ölmüyordu (`docs/arge/2026-11-23_dalga1/GS1.md` kalem 1). Testler gerçek alt süreçlerle: SIGTERM'i yok
sayan süreç (JVM'in yerine ``SIG_IGN``), torunu, C düzeyinde takılı düzenli ifade.
"""
from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
# BA-1'in onarımdan önceki kalıbı + kapanan ayracı olmayan girdi: üstel geri izleme, dönmez.
_ESKI_KALIP = r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
_TAKILAN_SATIR = "memmove(a,b," + "x," * 30


@pytest.fixture()
def srv(tmp_path):
    spec = importlib.util.spec_from_file_location("bw_ui_server_gs1_iptal", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod._kill_jobs()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _olu_mu(pid: int, sure: float = 0.5) -> bool:
    """Süreç ölü mü (sahipsiz kalan torunun biçilmesi için kısa pay)."""
    son = time.monotonic() + sure
    while time.monotonic() < son:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return not _alive(pid)


def _job(srv, tmp_path, proc) -> str:
    log = tmp_path / ("analyze_%d.log" % proc.pid)
    log.write_text("")
    jid = "g%d" % len(srv._JOBS)
    srv._JOBS[jid] = {"proc": proc, "log": str(log), "ws_out": str(tmp_path / "ws"),
                      "run_dir": str(tmp_path), "binary": "hedef", "started": time.time(),
                      "lf": open(log, "a"), "closed": False, "cancelled": False,
                      "activated": False}
    return jid


def _baslat(tmp_path, ad: str, *, lider_yok_sayar: bool, torun_yok_sayar: bool,
            regex: bool = False):
    """Kendi süreç grubunda lider + bir torun. Hazır olunca torunun pid'i dosyaya yazılır."""
    pidfile = tmp_path / (ad + ".torun")
    torun_kodu = (
        ("import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);" if torun_yok_sayar
         else "import time;") + "time.sleep(60)")
    lider = [
        "import re,signal,subprocess,sys,time",
        "c=subprocess.Popen([sys.executable,'-c',%r])" % torun_kodu,
        "time.sleep(0.3)",  # torun işleyicisini kursun
    ]
    if lider_yok_sayar:
        lider.append("signal.signal(signal.SIGTERM,signal.SIG_IGN)")
    lider.append("open(%r,'w').write(str(c.pid))" % str(pidfile))
    if regex:
        lider.append("re.compile(%r).search(%r)" % (_ESKI_KALIP, _TAKILAN_SATIR))
    lider.append("time.sleep(60)")
    proc = subprocess.Popen([sys.executable, "-c", "\n".join(lider)], process_group=0)
    son = time.monotonic() + 20
    while time.monotonic() < son:
        if pidfile.exists() and pidfile.read_text():
            break
        time.sleep(0.02)
    torun = int(pidfile.read_text())
    if regex:
        time.sleep(0.5)  # düzenli ifadenin içinde olsun
    return proc, torun


def test_sigterm_e_uyan_surec_term_ve_iki_saniye(srv, tmp_path):
    """H3 (b): SIGTERM'e uyan süreç + torun → ``sonlandirma: "term"``, ≤ 2 sn, ikisi de ölü."""
    proc, torun = _baslat(tmp_path, "uyan", lider_yok_sayar=False, torun_yok_sayar=False)
    jid = _job(srv, tmp_path, proc)
    t0 = time.monotonic()
    r = srv.cancel_job(jid)
    gecen = time.monotonic() - t0
    assert r == {"ok": True, "job": jid, "sonlandirma": "term"}
    assert gecen <= 2.0
    assert proc.poll() is not None and proc.returncode == -signal.SIGTERM
    assert _olu_mu(torun)


def test_sigterm_i_yok_sayan_surec_ve_torunu_kill(srv, tmp_path):
    """H3 (a): SIGTERM'i yok sayan süreç + torunu → ``"kill"``, ≤ bekleme + 2 sn, ikisi de ölü."""
    proc, torun = _baslat(tmp_path, "yoksayan", lider_yok_sayar=True, torun_yok_sayar=True)
    jid = _job(srv, tmp_path, proc)
    t0 = time.monotonic()
    r = srv.cancel_job(jid)
    gecen = time.monotonic() - t0
    assert r["sonlandirma"] == "kill" and r["ok"] is True
    assert srv.IPTAL_BEKLEME_SN - 0.2 <= gecen <= srv.IPTAL_BEKLEME_SN + 2.0
    assert proc.returncode == -signal.SIGKILL
    assert _olu_mu(torun)


def test_c_duzeyinde_takili_duzenli_ifade_kill(srv, tmp_path):
    """C düzeyinde takılı düzenli ifade + SIGTERM'e yanıtsız (JVM'in yerine SIG_IGN) → ``"kill"``."""
    proc, torun = _baslat(tmp_path, "regex", lider_yok_sayar=True, torun_yok_sayar=False, regex=True)
    jid = _job(srv, tmp_path, proc)
    t0 = time.monotonic()
    r = srv.cancel_job(jid)
    gecen = time.monotonic() - t0
    assert r["sonlandirma"] == "kill"
    assert gecen <= srv.IPTAL_BEKLEME_SN + 2.0
    assert proc.returncode == -signal.SIGKILL
    assert _olu_mu(torun)


def test_lider_olur_torun_yasarsa_grup_kill(srv, tmp_path):
    """Lider SIGTERM'le ölse de gruptaki torun yaşıyorsa iptal bitmiş sayılmaz: gruba SIGKILL."""
    proc, torun = _baslat(tmp_path, "torun", lider_yok_sayar=False, torun_yok_sayar=True)
    jid = _job(srv, tmp_path, proc)
    r = srv.cancel_job(jid)
    assert proc.returncode == -signal.SIGTERM
    assert r["sonlandirma"] == "kill"
    assert _olu_mu(torun)


def test_bekleme_modul_sabitinden(srv, tmp_path, monkeypatch):
    """Bekleme ``IPTAL_BEKLEME_SN``'den (öntanım 5); kısaltılınca SIGKILL o kadar erken gelir."""
    assert srv.IPTAL_BEKLEME_SN == 5.0
    monkeypatch.setattr(srv, "IPTAL_BEKLEME_SN", 0.5)
    proc, torun = _baslat(tmp_path, "kisa", lider_yok_sayar=True, torun_yok_sayar=True)
    jid = _job(srv, tmp_path, proc)
    t0 = time.monotonic()
    r = srv.cancel_job(jid)
    assert r["sonlandirma"] == "kill"
    assert time.monotonic() - t0 < 3.0
    assert _olu_mu(torun)


def test_kendi_grubu_hic_vurulmaz(srv, monkeypatch):
    """Çocuk sunucunun grubundaysa SIGTERM de SIGKILL de killpg ile gitmez; yalnız süreç."""
    monkeypatch.setattr(srv, "IPTAL_BEKLEME_SN", 0.1)
    killpg, cagri = [], []
    monkeypatch.setattr(srv.os, "killpg", lambda pg, sig: killpg.append((pg, sig)))

    class _Ayni:
        pid = os.getpid()

        def poll(self):
            return None  # hiç ölmüyor

        def terminate(self):
            cagri.append("term")

        def kill(self):
            cagri.append("kill")

    assert srv._kill_proc(_Ayni()) == "kill"
    assert killpg == [] and cagri == ["term", "kill"]


def test_kill_jobs_tek_bekleme_ve_ayni_yol(srv, tmp_path, monkeypatch):
    """Sunucu kapanışı (``_kill_jobs``): hepsine SIGTERM, TEK bekleme, yaşayanlara SIGKILL."""
    monkeypatch.setattr(srv, "IPTAL_BEKLEME_SN", 1.0)
    p1, t1 = _baslat(tmp_path, "k1", lider_yok_sayar=True, torun_yok_sayar=True)
    p2, t2 = _baslat(tmp_path, "k2", lider_yok_sayar=True, torun_yok_sayar=False)
    p3, t3 = _baslat(tmp_path, "k3", lider_yok_sayar=False, torun_yok_sayar=False)
    for p in (p1, p2, p3):
        _job(srv, tmp_path, p)
    t0 = time.monotonic()
    srv._kill_jobs()
    gecen = time.monotonic() - t0
    assert gecen < 1.0 + 2.0 + 1.0  # üç ayrı bekleme (3 sn+) değil
    assert p1.poll() == -signal.SIGKILL and p2.poll() == -signal.SIGKILL
    assert p3.poll() == -signal.SIGTERM
    for t in (t1, t2, t3):
        assert _olu_mu(t)


def test_terminate_jobs_isleyicisi_ayni_yolu_kullanir(srv, tmp_path, monkeypatch):
    """SIGTERM / SIGINT işleyicisi (``_terminate_jobs``): SIGTERM'i yok sayan iş de ölür, sonra çıkış."""
    monkeypatch.setattr(srv, "IPTAL_BEKLEME_SN", 0.5)
    proc, torun = _baslat(tmp_path, "kapanis", lider_yok_sayar=True, torun_yok_sayar=True)
    _job(srv, tmp_path, proc)
    with pytest.raises(SystemExit):
        srv._terminate_jobs(signal.SIGTERM, None)
    assert proc.poll() == -signal.SIGKILL
    assert _olu_mu(torun)


def test_bitmis_is_409_ve_sinyal_yok(srv, tmp_path, monkeypatch):
    sinyaller = []
    monkeypatch.setattr(srv.os, "killpg", lambda pg, sig: sinyaller.append(sig))
    proc = subprocess.Popen([sys.executable, "-c", "pass"], process_group=0)
    proc.wait(10)
    jid = _job(srv, tmp_path, proc)
    assert srv.cancel_job(jid)["__code"] == 409
    assert sinyaller == []
