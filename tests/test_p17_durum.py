"""P17 / ARAYUZ-11: sonuç ekranı kısmi / başarısız aşamayı gösterir; çalışma alanı olmayan hedefte
doğru ileti; Ghidra'nın adlandırdığı fonksiyonlar (ve sembollü ikili) açılır.

Eskiden: (1) çalışma alanı bulununca aşamalara bakılmadan sonuç ekranına geçiliyor, başarısız /
kısmi aşamanın izi kalmıyordu; (2) çalışma alanı yoksa her durumda "analiz başarısız (pipeline
hata verdi)"; (3) model yalnız FUN_*.c sayıyordu: HEAD cat koşusunda 296 decompile dosyasının
195'i (entry, _DT_INIT, ithal taslakları) açılamıyor, sembollü ikilide model hiç kurulamıyordu.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_INDEX = _ROOT / "ui" / "index.html"
_NODE = shutil.which("node")


@pytest.fixture()
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_p17_durum", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.activate_workspace(None)


def _report(path: Path, stages: dict, target_type="elf_binary") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target": {"hash": "ab" * 32, "type": target_type},
                                "pipeline": {"stages": stages}}))
    return path


_OK = {"success": True, "skipped": False, "errors": [], "stats": {}}


def test_outcome_partial_failed_skipped(srv, tmp_path):
    rp = _report(tmp_path / "a" / "report.json", {
        "static": dict(_OK),
        "deobfuscate": {"success": True, "skipped": True, "skip_reason": "uygulanamaz"},
        "reconstruct": {"success": True, "skipped": False, "errors": [],
                        "stats": {"partial": True, "partial_reasons": ["adlandırma hatası"],
                                  "reconstruct_status": "kismi"}},
    })
    o = srv._report_outcome(rp)
    assert o["status"] == "kismi" and o["exit_code"] == 3
    assert o["partial"] == {"reconstruct": ["adlandırma hatası"]}
    assert o["skipped"] == {"deobfuscate": "uygulanamaz"}
    assert o["reconstruct_status"] == "kismi"
    rp2 = _report(tmp_path / "b" / "report.json", {
        "static": {"success": False, "skipped": False, "errors": ["Ghidra düştü"]}})
    o2 = srv._report_outcome(rp2)
    assert o2["status"] == "basarisiz" and o2["failed"] == {"static": ["Ghidra düştü"]}
    assert srv._report_outcome(tmp_path / "yok.json") is None


def test_outcome_matches_cli(srv, tmp_path):
    from types import SimpleNamespace as N

    from karadul.cli import _analysis_outcome
    stages = {"static": dict(_OK), "reconstruct": {"success": True, "skipped": False,
                                                   "errors": ["x"], "stats": {}}}
    o = srv._report_outcome(_report(tmp_path / "r.json", stages))
    cli = _analysis_outcome(N(stages={k: N(**{**v}) for k, v in stages.items()}))
    assert (o["status"], o["exit_code"], o["partial"]) == (
        cli["status"], cli["exit_code"], cli["partial"])


def _ws(root: Path, files: dict[str, str], graph_edges=None, stages=None) -> Path:
    ws = root / "ws" / "workspaces" / "t" / "20261118_000000"
    (ws / "reconstructed" / "src").mkdir(parents=True)
    (ws / "reconstructed" / "src" / "naming_map.json").write_text(json.dumps({"global": {}}))
    dec = ws / "deobfuscated" / "decompiled"
    dec.mkdir(parents=True)
    for stem, addr in files.items():
        (dec / f"{stem}.c").write_text(
            f"// Function: {stem}\n// Address:  {addr}\n// Size: 4 bytes\n\nvoid f(void){{}}\n")
    if graph_edges is not None:
        (ws / "static").mkdir()
        (ws / "static" / "ghidra_call_graph.json").write_text(json.dumps({"edges": [
            {"from": a, "to": b} for a, b in graph_edges]}))
    _report(ws / "reports" / "report.json", stages or {"static": dict(_OK)})
    return ws


def test_ghidra_named_functions_are_nodes(srv, tmp_path):
    ws = _ws(tmp_path, {"FUN_00101000": "00101000", "entry": "00100f00",
                        "operator.new": "00103554", "memcpy_00101b34": "00101b34"},
             graph_edges=[("00100f00", "00101000"), ("00101000", "00103554")])
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    cls = {f["addr"]: f["cls"] for f in m["functions"]}
    assert cls == {"FUN_00101000": "unnamed", "entry": "ghidra", "operator.new": "ghidra",
                   "memcpy_00101b34": "ghidra"}
    assert m["calls"]["entry"] == ["FUN_00101000"]
    assert m["calls"]["FUN_00101000"] == ["operator.new"]
    assert m["total"] == 1 and m["ghidra_named"] == 3 and m["unnamed"] == 1
    assert all(f["label"] is None for f in m["functions"] if f["cls"] == "ghidra")
    assert srv._known_node("operator.new") and srv._known_node("entry")
    for bad in ("../x", "a/b", ".hidden", "yok_boyle", ""):
        assert not srv._known_node(bad)
    ev = srv._evidence("entry")
    assert ev["cls"] == "ghidra" and ev["diagnosis"] is None
    assert [c["addr"] for c in ev["callees"]] == ["FUN_00101000"]


def test_symbolized_binary_builds_model(srv, tmp_path):
    """Sembollü ikili: FUN_ dosyası yok, model yine kurulur."""
    ws = _ws(tmp_path, {"_main": "100003f50", "_helper": "100003f20"})
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    assert m is not None and len(m["functions"]) == 2
    assert m["total"] == 0 and m["ghidra_named"] == 2


def test_model_carries_run_status(srv, tmp_path):
    ws = _ws(tmp_path, {"FUN_1": "1"}, stages={
        "static": dict(_OK),
        "reconstruct": {"success": False, "skipped": False, "errors": ["derleme başarısız"]}})
    srv.activate_workspace(str(ws))
    rs = srv.build_model()["run_status"]
    assert rs["status"] == "basarisiz"
    assert rs["failed"] == {"reconstruct": ["derleme başarısız"]}


def test_progress_without_workspace_reports_outcome(srv, tmp_path):
    """JS / Java hedefi: çalışma alanı (C fonksiyon görünümü) yok ama rapor var."""
    run = tmp_path / "run"
    _report(run / "ws" / "workspaces" / "app" / "t" / "reports" / "report.json",
            {"static": dict(_OK)}, target_type="js_bundle")
    (run / "clean").mkdir()
    log = run / "analyze.log"
    log.write_text("OK static: 1.0s\n")
    proc = subprocess.Popen(["true"])
    proc.wait(10)
    srv._JOBS["j1"] = {"proc": proc, "log": str(log), "ws_out": str(run / "ws"),
                       "run_dir": str(run), "binary": "app", "started": time.time(),
                       "lf": open(log, "a"), "closed": False, "cancelled": False,
                       "activated": False}
    p = srv._job_progress("j1")
    assert p["workspace"] is None
    assert p["outcome"]["status"] == "tam" and p["outcome"]["target_type"] == "js_bundle"
    assert p["clean_dir"] == str(run / "clean")


def test_html_has_no_blanket_failure_message():
    html = _INDEX.read_text(encoding="utf-8")
    assert "analiz başarısız (pipeline hata verdi)" not in html
    assert "renderRunBanner(j);" in html
    assert 'id="runBanner"' in html


@pytest.mark.skipif(_NODE is None, reason="node yok")
def test_status_js(tmp_path):
    m = re.search(r"/\* P17-DURUM-BASLA:.*?\*/(.*?)/\* P17-DURUM-BITIS \*/",
                  _INDEX.read_text(encoding="utf-8"), re.S)
    assert m
    p = tmp_path / "d.js"
    p.write_text(m.group(1) + r"""
console.log(JSON.stringify({
  tam: runStatusLines({status:'tam',failed:{},partial:{},skipped:{x:'y'}}),
  yok: runStatusLines(null),
  kismi: runStatusLines({status:'kismi',failed:{},partial:{reconstruct:['a','b']},skipped:{deobfuscate:'uygulanamaz'}}),
  bas: runStatusLines({status:'basarisiz',failed:{static:[]},partial:{},skipped:{}}),
  f_bas: finishMessage({rc:1,outcome:{status:'basarisiz',failed:{static:['Ghidra düştü']}}}),
  f_js: finishMessage({rc:0,clean_dir:'/c',outcome:{status:'tam',target_type:'js_bundle'}}),
  f_yok: finishMessage({rc:2,outcome:null}),
  f_iptal: finishMessage({cancelled:true}),
}));
""", encoding="utf-8")
    proc = subprocess.run([_NODE, str(p)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    o = json.loads(proc.stdout)
    assert o["tam"] == []
    assert o["yok"][0]["text"].startswith("Analiz durumu bilinmiyor")
    assert o["kismi"][0]["cls"] == "head" and "KISMİ" in o["kismi"][0]["text"]
    assert {"cls": "part", "text": "reconstruct kısmi: a · b"} in o["kismi"]
    assert {"cls": "skip", "text": "deobfuscate atlandı: uygulanamaz"} in o["kismi"]
    assert "BAŞARISIZ" in o["bas"][0]["text"]
    assert {"cls": "fail", "text": "static başarısız: neden bildirilmedi"} in o["bas"]
    assert o["f_bas"] == "analiz başarısız — static: Ghidra düştü"
    assert o["f_js"] == ("analiz bitti (tam) ama bu hedef türü (js_bundle) için arayüzde "
                         "fonksiyon görünümü yok — çıktı: /c")
    assert "çıkış kodu 2" in o["f_yok"]
    assert "iptal" in o["f_iptal"]
