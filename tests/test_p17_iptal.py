"""P17 / ARAYUZ-10: analiz iptal edilebilir, yoklama hatası görünür, süren işe yeniden bağlanılır.

Eskiden: iptal ucu yoktu; `pollProgress` istek hatasında ve `{"error": "job yok"}` / 403'te hiçbir
şey göstermeden dönüyor, ekran sonsuza dek "çalışıyor…" kalıyordu; sayfa yenilenince süren işin
kimliği kayboluyordu. Ek (Küçükler): denetim ile işin eklenmesi arasında kilit yoktu (iki eşzamanlı
POST iki analiz başlatıyordu); biten işin her yoklaması çalışma alanını yeniden etkinleştiriyordu.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_INDEX = _ROOT / "ui" / "index.html"
_NODE = shutil.which("node")


@pytest.fixture()
def srv(tmp_path):
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_iptal", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod._kill_jobs()
    mod.activate_workspace(None)


def _job(srv, tmp_path, proc, **extra) -> str:
    log = tmp_path / "analyze.log"
    log.write_text("")
    jid = "j" + str(len(srv._JOBS))
    srv._JOBS[jid] = {"proc": proc, "log": str(log), "ws_out": str(tmp_path / "ws"),
                      "run_dir": str(tmp_path), "binary": "hedef", "started": time.time(),
                      "lf": open(log, "a"), "closed": False, "cancelled": False,
                      "activated": False, **extra}
    return jid


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_cancel_kills_process_group(srv, tmp_path):
    """İptal süreç grubunu götürür: torun süreç (Ghidra JVM yerine sleep) de ölür."""
    pidfile = tmp_path / "torun.pid"
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time;"
         f"c=subprocess.Popen(['sleep','60']);open({str(pidfile)!r},'w').write(str(c.pid));"
         "time.sleep(60)"], process_group=0)
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            break
        time.sleep(0.05)
    child = int(pidfile.read_text())
    jid = _job(srv, tmp_path, proc)
    assert srv.current_job()["job"] == jid
    r = srv.cancel_job(jid)
    assert r == {"ok": True, "job": jid, "sonlandirma": "term"}
    proc.wait(10)
    for _ in range(100):
        if not _alive(child):
            break
        time.sleep(0.05)
    assert not _alive(child)
    prog = srv._job_progress(jid)
    assert prog["finished"] is True and prog["cancelled"] is True
    assert srv.current_job() == {"job": None}


def test_cancel_unknown_and_finished(srv, tmp_path):
    assert srv.cancel_job("yok")["__code"] == 404
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(10)
    jid = _job(srv, tmp_path, proc)
    assert srv.cancel_job(jid)["__code"] == 409


def test_cancelled_job_workspace_not_activated(srv, tmp_path):
    ws = tmp_path / "ws" / "workspaces" / "x" / "t"
    (ws / "reconstructed" / "src").mkdir(parents=True)
    (ws / "reconstructed" / "src" / "naming_map.json").write_text("{}")
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(10)
    jid = _job(srv, tmp_path, proc, cancelled=True)
    srv.activate_workspace("/onceki")
    prog = srv._progress_and_activate(jid)
    assert prog["workspace"] == str(ws)
    assert srv.WS == "/onceki"


def test_finished_job_activates_once(srv, tmp_path):
    ws = tmp_path / "ws" / "workspaces" / "x" / "t"
    (ws / "reconstructed" / "src").mkdir(parents=True)
    (ws / "reconstructed" / "src" / "naming_map.json").write_text("{}")
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(10)
    jid = _job(srv, tmp_path, proc)
    srv._progress_and_activate(jid)
    assert srv.WS == str(ws)
    srv.activate_workspace("/baska_sekmede_acilan")
    srv._progress_and_activate(jid)          # eski işin kimliğiyle yeniden yoklama
    assert srv.WS == "/baska_sekmede_acilan"


def test_concurrent_starts_launch_one_job(srv, tmp_path, monkeypatch):
    binary = tmp_path / "hedef"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setattr(srv, "HOME", tmp_path)
    monkeypatch.setattr(srv, "_DATA_ROOT", tmp_path / "data")
    monkeypatch.setattr(srv, "_SETTINGS_YAML", tmp_path / "yok.yaml")
    launched = []

    class _P:
        # Var olmayan pid: sökümde _kill_jobs bu sahte süreci öldürmeye kalkarsa
        # (pid 0 = kendi süreç grubu!) hiçbir gerçek sürece dokunmaz.
        pid = 99_999_999
        returncode = None

        def __init__(self, *a, **k):
            time.sleep(0.3)                  # yarış penceresi
            launched.append(1)

        def poll(self):
            return None

        def terminate(self):
            pass

    monkeypatch.setattr(srv.subprocess, "Popen", _P)
    out: list = []
    ts = [threading.Thread(target=lambda: out.append(srv.start_analysis(str(binary))))
          for _ in range(2)]
    try:
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert len(launched) == 1
        assert sum(1 for o in out if "job" in o) == 1
        busy = [o for o in out if "error" in o]
        assert busy and busy[0]["running_job"] in srv._JOBS
    finally:
        srv._JOBS.clear()


def test_kill_never_targets_own_process_group(srv, monkeypatch):
    """Çocuk sunucunun grubundaysa killpg yapılmaz (sunucu kendini öldürmez)."""
    killed, terminated = [], []
    monkeypatch.setattr(srv.os, "killpg", lambda pg, sig: killed.append(pg))

    class _Same:
        pid = os.getpid()

        def terminate(self):
            terminated.append(1)

    srv._kill_proc(_Same())
    assert killed == [] and terminated == [1]


def test_endpoints_registered():
    src = _SERVER_PY.read_text(encoding="utf-8")
    assert 'elif path == "/api/cancel":' in src
    assert 'elif path == "/api/jobs/current":' in src
    html = _INDEX.read_text(encoding="utf-8")
    assert 'id="anCancel"' in html
    assert "fetch('/api/jobs/current')" in html
    assert "j.running_job" in html


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_poll_step(tmp_path):
    m = re.search(r"/\* P17-YOKLAMA-BASLA:.*?\*/(.*?)/\* P17-YOKLAMA-BITIS \*/",
                  _INDEX.read_text(encoding="utf-8"), re.S)
    assert m
    p = tmp_path / "y.js"
    p.write_text(m.group(1) + r"""
const out={};
let e=0, seq=[];
for(let i=0;i<POLL_MAX_ERR;i++){ const s=pollStep(e,{ok:false}); e=s.err; seq.push(s.stop); }
out.netseq=seq; out.netmsg=pollStep(POLL_MAX_ERR-1,{ok:false}).msg;
out.jobyok=pollStep(0,{ok:true,body:{error:'job yok'}});
out.token=pollStep(0,{ok:true,body:{error:'geçersiz jeton'}});
out.ok=pollStep(3,{ok:true,body:{stages:[]}});
out.max=POLL_MAX_ERR;
console.log(JSON.stringify(out));
""", encoding="utf-8")
    proc = subprocess.run([_NODE, str(p)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["max"] == 5
    assert out["netseq"] == [False, False, False, False, True]
    assert "sunucuya ulaşılamıyor" in out["netmsg"]
    assert out["jobyok"]["stop"] is True and "iş bulunamadı" in out["jobyok"]["msg"]
    assert out["token"]["stop"] is True and "geçersiz jeton" in out["token"]["msg"]
    assert out["ok"] == {"err": 0, "stop": False, "render": True}
