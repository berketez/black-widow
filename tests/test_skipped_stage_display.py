"""Atlanan (skipped) aşamanın gösterim katmanında FAIL'den ayrı taşındığını kilitler.

Veri sözleşmesi (karadul/core/result.py, stages.py `_skipped`): atlanan aşama
``success=False, skipped=True, stats["skip_reason"]=<gerekçe>`` taşır ve pipeline'ı
FAILED yapmaz. Gösterim katmanı ise yalnız ``success``'e bakıyordu; bu yüzden
atlanan aşama her yerde başarısız görünüyordu:

- CLI log satırı: ``FAIL deobfuscate: 0.00s``           -> ``SKIP deobfuscate: 0.00s -- <gerekçe>``
- UI (/api/progress): status ``failed``                 -> ``skipped`` + ``skip_reason``
- report.md: ``| deobfuscate | FAIL |`` + ``Deobfuscation failed: unknown``
- report.html: kırmızı ``FAIL``; report.sarif.json: atlanan aşamadan hiç söz yok
- ``analyze --json``: ``skipped`` alanı yoktu

Testler gerçek üretici/tüketici kodunu çalıştırır: log satırı gerçek
``_log_stage_complete`` ile üretilir ve gerçek ``_parse_stage_log``'a verilir;
index.html'in ``renderStages``/``esc`` fonksiyonları dosyadan çıkarılıp node'da koşulur.

TUZAK: ui/server.py paket modülü değil -> importlib ile dosya yolundan yüklenir
(__main__ guard sunucuyu başlatmaz).
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.cli import _emit_analyze_json, _log_stage_complete
from karadul.core.result import PipelineResult, StageResult
from karadul.core.target import Language, TargetType
from karadul.core.workspace import Workspace
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.markdown_report import MarkdownReporter
from karadul.reporting.sarif_report import SARIFReporter

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_INDEX_HTML = _ROOT / "ui" / "index.html"

# stages.py DeobfuscationStage._SKIP_REASONS[PYTHON_PACKED] ile aynı metin
# (gerçek koşuda görülen gerekçe; burada yalnız örnek veri olarak).
_PY_REASON = (
    "Python paketi için ayrı bir deobfuscation adımı yok; .pyc çıkarma "
    "ve decompile reconstruct aşamasında yapılır."
)


@pytest.fixture(scope="module")
def srv():
    """ui/server.py'yi izole modül olarak yükle (sunucu başlatmadan)."""
    spec = importlib.util.spec_from_file_location("bw_ui_server_skip", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ok(name: str, dur: float = 1.5, **stats) -> StageResult:
    return StageResult(stage_name=name, success=True, duration_seconds=dur,
                       stats=dict(stats))


def _failed(name: str, err: str = "boom", dur: float = 0.2) -> StageResult:
    return StageResult(stage_name=name, success=False, duration_seconds=dur,
                       errors=[err])


def _skipped(name: str, reason: str | None = _PY_REASON,
             dur: float = 0.0) -> StageResult:
    stats = {"skip_reason": reason} if reason is not None else {}
    return StageResult(stage_name=name, success=False, skipped=True,
                       duration_seconds=dur, stats=stats)


def _pipeline(*stages: StageResult) -> PipelineResult:
    r = PipelineResult(target_name="hello", target_hash="0" * 64)
    for sr in stages:
        r.add_stage_result(sr)
    r.total_duration = sum(sr.duration_seconds for sr in stages)
    return r


# ---------------------------------------------------------------------------
# 1) CLI log satırı (karadul/cli.py::_log_stage_complete)
# ---------------------------------------------------------------------------
def _emit_lines(caplog, *results: StageResult) -> list[str]:
    seen: list[str] = []
    wrapped = _log_stage_complete(lambda name, res, i, n: seen.append(name))
    with caplog.at_level(logging.INFO, logger="karadul"):
        for i, sr in enumerate(results):
            wrapped(sr.stage_name, sr, i, len(results))
    # iç callback (rich progress) her aşama için çağrılmaya devam etmeli
    assert seen == [sr.stage_name for sr in results]
    return [rec.getMessage() for rec in caplog.records if rec.name == "karadul"]


def test_log_line_ok_fail_skip(caplog):
    lines = _emit_lines(
        caplog,
        _ok("static", 1.5),
        _failed("reconstruct", dur=0.25),
        _skipped("deobfuscate"),
    )
    assert lines == [
        "OK static: 1.50s",
        "FAIL reconstruct: 0.25s",
        f"SKIP deobfuscate: 0.00s -- {_PY_REASON}",
    ]


def test_log_line_skip_reason_is_single_line_and_optional(caplog):
    lines = _emit_lines(
        caplog,
        _skipped("dynamic", reason="Frida spawn hatasi:\n  NotSupportedError\t(x)"),
        _skipped("deobfuscate", reason=None),
    )
    assert lines == [
        "SKIP dynamic: 0.00s -- Frida spawn hatasi: NotSupportedError (x)",
        "SKIP deobfuscate: 0.00s",
    ]


# ---------------------------------------------------------------------------
# 2) UI ayrıştırıcı (ui/server.py::_parse_stage_log / _job_progress)
# ---------------------------------------------------------------------------
def _statuses(stages: list[dict]) -> dict[str, str]:
    return {s["key"]: s["status"] for s in stages}


def test_parser_distinguishes_done_failed_skipped_running(srv):
    log = (
        "22:15:12 INFO    [karadul] OK identify: 0.00s\n"
        "22:15:12 INFO    [karadul] OK static: 0.18s\n"
        f"22:15:12 INFO    [karadul] SKIP deobfuscate: 0.00s -- {_PY_REASON}\n"
        "22:15:13 INFO    [karadul.stages] naming...\n"
    )
    stages = srv._parse_stage_log(log)
    assert _statuses(stages) == {
        "identify": "done", "static": "done", "deobfuscate": "skipped",
        "reconstruct": "running", "report": "pending",
    }
    deob = next(s for s in stages if s["key"] == "deobfuscate")
    assert deob["skip_reason"] == _PY_REASON
    assert deob["time"] == 0.0
    # atlanmayan aşamalarda gerekçe yok
    assert all(s["skip_reason"] is None for s in stages if s["key"] != "deobfuscate")


def test_parser_failed_stays_failed_and_running_moves_on(srv):
    log = (
        "OK identify: 0.00s\n"
        "FAIL static: 3.20s\n"
        "SKIP deobfuscate: 0.00s\n"          # gerekçesiz SKIP
    )
    stages = srv._parse_stage_log(log)
    assert _statuses(stages) == {
        "identify": "done", "static": "failed", "deobfuscate": "skipped",
        "reconstruct": "running", "report": "pending",
    }
    assert next(s for s in stages if s["key"] == "deobfuscate")["skip_reason"] is None


def test_parser_legacy_formats_and_word_boundary(srv):
    # Eski CLI sürümü atlanan aşamayı FAIL yazıyordu -> başarısız olarak kalır
    # (log'da SKIP bilgisi yok; uydurma yapılmaz). Süresiz FAIL/ERROR da eski
    # ayrıştırıcıdaki gibi başarısız. 'LOOK' içindeki OK sayılmaz.
    log = (
        "OK identify: 0.00s\n"
        "LOOK static: 1.00s\n"
        "ERROR static: patladi\n"
        "FAIL deobfuscate: 0.00s\n"
    )
    assert _statuses(srv._parse_stage_log(log)) == {
        "identify": "done", "static": "failed", "deobfuscate": "failed",
        "reconstruct": "running", "report": "pending",
    }


def test_parser_ignores_stages_not_shown_in_ui(srv):
    # UI her zaman --skip-dynamic ile koşar; 'dynamic' satırı listede yok sayılır.
    log = "OK identify: 0.00s\nSKIP dynamic: 1.12s -- Frida yok\n"
    stages = srv._parse_stage_log(log)
    assert [s["key"] for s in stages] == srv.STAGE_ORDER
    assert _statuses(stages)["static"] == "running"


def test_cli_log_line_round_trips_through_ui_parser(srv, caplog):
    """Üretici (CLI) ile tüketici (UI) sözleşmesi: gerçek satır, gerçek biçimle."""
    results = [_ok("identify", 0.0), _ok("static", 0.18), _skipped("deobfuscate"),
               _ok("reconstruct", 0.2), _ok("report", 0.01)]
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
                            datefmt="%H:%M:%S")  # core/logging_config.setup_logging
    _emit_lines(caplog, *results)
    log = "\n".join(fmt.format(rec) for rec in caplog.records
                    if rec.name == "karadul") + "\n"
    stages = srv._parse_stage_log(log)
    assert _statuses(stages) == {
        "identify": "done", "static": "done", "deobfuscate": "skipped",
        "reconstruct": "done", "report": "done",
    }
    assert next(s for s in stages if s["key"] == "deobfuscate")["skip_reason"] == _PY_REASON


def test_job_progress_exposes_skipped(srv, tmp_path):
    log = tmp_path / "analyze.log"
    log.write_text("OK identify: 0.00s\nOK static: 0.18s\n"
                   f"SKIP deobfuscate: 0.00s -- {_PY_REASON}\n", encoding="utf-8")

    class _Running:  # süreç sürüyor -> bitiş (report.json) dalına girilmez
        def poll(self):
            return None

    srv._JOBS["t_skip"] = {"proc": _Running(), "log": str(log), "ws_out": str(tmp_path),
                           "run_dir": str(tmp_path), "binary": "hello",
                           "started": time.time(), "lf": None, "closed": False}
    try:
        p = srv._job_progress("t_skip")
    finally:
        srv._JOBS.pop("t_skip", None)
    assert p["finished"] is False
    deob = next(s for s in p["stages"] if s["key"] == "deobfuscate")
    assert deob["status"] == "skipped"
    assert deob["skip_reason"] == _PY_REASON
    assert _statuses(p["stages"])["reconstruct"] == "running"
    json.dumps(p)  # /api/progress JSON'a serileşebilmeli


# ---------------------------------------------------------------------------
# 3) Markdown rapor
# ---------------------------------------------------------------------------
def test_markdown_pipeline_summary_marks_skipped_not_fail():
    r = _pipeline(_ok("identify"), _skipped("deobfuscate"), _failed("reconstruct"))
    rows = MarkdownReporter()._section_pipeline(r)
    deob = next(line for line in rows if "| deobfuscate |" in line)
    assert deob == f"| 2 | deobfuscate | SKIPPED | 0.0s | {_PY_REASON} |"
    rec = next(line for line in rows if "| reconstruct |" in line)
    assert "| FAIL |" in rec and "boom" in rec


def test_markdown_sections_say_skipped_with_reason():
    rep = MarkdownReporter()
    r = _pipeline(_skipped("dynamic", reason="Frida yok"), _skipped("deobfuscate"))
    deob = "\n".join(rep._section_deobfuscation(r))
    assert f"*Deobfuscation skipped (not a failure): {_PY_REASON}*" in deob
    assert "failed" not in deob
    dyn = "\n".join(rep._section_dynamic(r))
    assert "*Dynamic analysis skipped (not a failure): Frida yok*" in dyn
    assert "failed" not in dyn


def test_markdown_real_failure_still_failed_and_missing_reason_is_explicit():
    rep = MarkdownReporter()
    failed = "\n".join(rep._section_deobfuscation(_pipeline(_failed("deobfuscate", "kaput"))))
    assert "*Deobfuscation failed: kaput*" in failed
    no_reason = "\n".join(rep._section_deobfuscation(
        _pipeline(_skipped("deobfuscate", reason=None))))
    assert "*Deobfuscation skipped (not a failure): no reason recorded*" in no_reason


def test_markdown_pipe_in_reason_does_not_break_table():
    r = _pipeline(_skipped("deobfuscate", reason="a | b"))
    row = next(line for line in MarkdownReporter()._section_pipeline(r)
               if "| deobfuscate |" in line)
    assert row == "| 1 | deobfuscate | SKIPPED | 0.0s | a \\| b |"


# ---------------------------------------------------------------------------
# 4) HTML + SARIF rapor
# ---------------------------------------------------------------------------
def test_html_timeline_and_dashboard_show_skipped():
    rep = HTMLReporter()
    r = _pipeline(_ok("identify"), _skipped("deobfuscate"),
                  _failed("reconstruct", err="x < y"))
    tl = rep._pipeline_timeline(r)
    assert ('<div class="timeline-item skip"><span class="stage-name">Stage 2 -- '
            'deobfuscate</span> <span class="skip">SKIPPED</span>') in tl
    assert f"skipped (not a failure): {_PY_REASON}" in tl
    assert ('<div class="timeline-item err"><span class="stage-name">Stage 3 -- '
            'reconstruct</span> <span class="fail">FAIL</span>') in tl
    # hata metni tek kez kaçışlanır (eskiden '&amp;lt;')
    assert "x &lt; y" in tl and "&amp;lt;" not in tl
    dash = rep._stats_dashboard(r)
    assert '<div class="value">1</div><div class="label">Skipped Stages</div>' in dash
    assert '<div class="value">skipped</div><div class="label">Deobf Steps</div>' in dash


def test_html_dashboard_has_no_skipped_box_without_skips():
    dash = HTMLReporter()._stats_dashboard(_pipeline(_ok("identify"), _ok("static")))
    assert "Skipped Stages" not in dash


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="hello")
    ws.create()
    return ws


def test_sarif_reports_skipped_as_note_not_failure(workspace):
    r = _pipeline(_ok("identify"), _skipped("deobfuscate"))
    run = SARIFReporter()._build_sarif(r, workspace)["runs"][0]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["toolExecutionNotifications"] == [{
        "level": "note",
        "message": {"text": f"Stage 'deobfuscate' skipped (not a failure): {_PY_REASON}"},
        "properties": {"stage": "deobfuscate", "skip_reason": _PY_REASON},
    }]
    assert run["properties"]["skipped_stages"] == ["deobfuscate"]


def test_sarif_no_notifications_without_skips(workspace):
    run = SARIFReporter()._build_sarif(
        _pipeline(_ok("identify"), _failed("static")), workspace)["runs"][0]
    assert "toolExecutionNotifications" not in run["invocations"][0]
    assert run["properties"]["skipped_stages"] == []


# ---------------------------------------------------------------------------
# 5) analyze --json (karadul/cli.py::_emit_analyze_json)
# ---------------------------------------------------------------------------
def test_analyze_json_carries_skipped(capsys):
    r = _pipeline(_ok("identify", 0.0), _ok("static", 0.18, functions_found=109),
                  _skipped("deobfuscate"), _failed("reconstruct"))
    ti = SimpleNamespace(name="hello", target_type=TargetType.PYTHON_PACKED,
                         language=Language.PYTHON, file_size=7795488)
    cfg = SimpleNamespace(computation_recovery=SimpleNamespace(enabled=False))
    _emit_analyze_json(ti, r, cfg)
    payload = json.loads(capsys.readouterr().out)
    deob = payload["stages"]["deobfuscate"]
    assert deob["skipped"] is True
    assert deob["success"] is False           # veri sözleşmesi korunur
    assert deob["skip_reason"] == _PY_REASON
    assert payload["stages"]["static"]["skipped"] is False
    assert "skip_reason" not in payload["stages"]["static"]
    assert payload["skipped_stages"] == ["deobfuscate"]
    assert payload["failed_stages"] == ["reconstruct"]


# ---------------------------------------------------------------------------
# 6) index.html: renderStages + esc (node ile gerçek fonksiyonlar)
# ---------------------------------------------------------------------------
def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    brew = "/opt/homebrew/bin/node"
    return brew if os.access(brew, os.X_OK) else None


def _js_function(src: str, name: str) -> str:
    """index.html script'inden `function <name>(...){...}` kaynağını çıkar."""
    start = src.index(f"function {name}(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"{name} kapanmadı")


_JS_HARNESS = r"""
function mkEl(tag){ return {tag, className:'', innerHTML:'', title:'', textContent:'',
  children:[], appendChild(c){ this.children.push(c); return c; }}; }
const ELS = {};
const $ = id => (ELS[id] = ELS[id] || mkEl('#'+id));
const document = { createElement: mkEl };
%(esc)s
%(render)s
const p = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
renderStages(p);
console.log(JSON.stringify({
  rows: ELS['anStages'].children.map(r => ({cls: r.className, title: r.title, html: r.innerHTML})),
  esc: esc(`<a href="x" title='y'>&</a>`),
}));
"""


@pytest.fixture(scope="module")
def render_js(tmp_path_factory):
    node = _node()
    if not node:
        pytest.skip("node yok")
    html = _INDEX_HTML.read_text(encoding="utf-8")
    script = html[html.index("<script>") + len("<script>"):html.index("</script>")]
    js = _JS_HARNESS % {"esc": _js_function(script, "esc"),
                        "render": _js_function(script, "renderStages")}
    d = tmp_path_factory.mktemp("render_js")
    (d / "h.js").write_text(js, encoding="utf-8")

    def _run(progress: dict) -> dict:
        (d / "p.json").write_text(json.dumps(progress), encoding="utf-8")
        out = subprocess.run([node, str(d / "h.js"), str(d / "p.json")],
                             capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)

    return _run


def test_render_stages_skipped_row(srv, render_js):
    reason = 'Gerekçe "tırnak" <b>kalın</b> & \'tek\''
    log = ("OK identify: 0.00s\nFAIL static: 3.20s\n"
           f"SKIP deobfuscate: 0.00s -- {reason}\n")
    out = render_js({"elapsed": 1, "stages": srv._parse_stage_log(log), "substages": []})
    rows = {r["cls"]: r for r in out["rows"]}
    skip = rows["stagerow skipped"]
    assert '<span class="skiptag">ATLANDI</span>' in skip["html"]
    assert '<div class="box">–</div>' in skip["html"]
    # gerekçe metin olarak görünür, HTML'e dönüşmez; tooltip ham metin (DOM özelliği)
    assert ("<div class=\"why\">Gerekçe &quot;tırnak&quot; &lt;b&gt;kalın&lt;/b&gt; "
            "&amp; &#39;tek&#39;</div>") in skip["html"]
    assert skip["title"] == f"Atlandı: {reason}"
    assert '<div class="box">✕</div>' in rows["stagerow failed"]["html"]
    assert "ATLANDI" not in rows["stagerow failed"]["html"]
    assert '<div class="box">✓</div>' in rows["stagerow done"]["html"]
    assert rows["stagerow running"]["title"] == ""


def test_esc_escapes_quotes_for_attribute_context(render_js):
    out = render_js({"elapsed": 0, "stages": [], "substages": []})
    assert out["esc"] == "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
