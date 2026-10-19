"""scripts/measurement/macho_measure.py — Mac ölçüm orkestratörünün birim testleri.

Hiçbir test gerçek strip/dyld_info/karadul/Ghidra çağırmaz; araçlar sahte nesnelerle
değiştirilir. Kilitlenen kurallar:
  (a) strip yalnız mutlak ``/usr/bin/strip``; göreli yol reddedilir;
  (b) export trie'de ``__mh_execute_header`` dışında ad kalırsa hat durur; dyld_info
      çıktısı tanınmazsa da durur; strip'li kopyada nm sembolü kalırsa durur;
  (c) özgün ikilinin sha256'sı korpustakinden farklıysa hat durur (strip'e geçmeden);
  (d) Ghidra sabitlenen sürüm değilse analiz başlamaz (``--farkli-ghidra-izinli`` hariç);
  (e) analiz komutu hedefi çalıştırmaz (``--skip-dynamic``), sabitlenen Ghidra'yı env ile verir;
  (f) hedef türü Mach-O değilse (15 Ekim htop'u: go_binary) koşu geçersiz, toplamlara girmez;
  (g) test seti programları korpusa giremez; varsayılan veri dizini depo içi ``workspaces/olcum_mac``.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "scripts" / "measurement"
_REPO = _DIR.parents[1]
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _DIR / "macho_measure.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


mm = _load("macho_measure_under_test")

PINNED = mm.GHIDRA_PINNED_VERSION
APPLE_EXPORTS = ("x [arm64]:\n    -exports:\n        offset      symbol\n"
                 "        0x00000000  __mh_execute_header\n")
CONDA_EXPORTS = ("x [arm64]:\n    -exports:\n        offset      symbol\n"
                 "        0x00001A6C  _Action_follow\n        0x00001784  _Action_pickFromVector\n"
                 "        0x00000000  __mh_execute_header\n")
NM_ORIG = ("0000000100000000 T __mh_execute_header\n0000000100001000 T _main\n"
           "0000000100001040 t _helper\n0000000100001080 t _helper.cold.1\n")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Korpus
# ---------------------------------------------------------------------------

def test_repo_corpus_is_valid_development_set():
    corpus = mm.load_corpus(mm.CORPUS_PATH)
    assert {"htop", "tmux"} <= set(corpus["binaries"])
    for spec in corpus["binaries"].values():
        assert spec["set"] == "gelistirme"
        assert len(spec["orig"]["sha256"]) == 64
        assert spec["homebrew"]["formula"] and spec["homebrew"]["version"]
        assert spec["homebrew"]["bottle_tag"]


def _corpus_file(tmp_path: Path, binaries: dict) -> Path:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps({"schema": mm.CORPUS_SCHEMA, "binaries": binaries}))
    return p


@pytest.mark.parametrize("key, stem, set_name, sha, msg", [
    ("vim", "vim", "gelistirme", "a" * 64, "test seti"),
    ("shell", "zsh", "dogrulama", "a" * 64, "test seti"),         # dosya adı kilitli
    ("demo", "demo", "test", "a" * 64, "izinli değil"),
    ("demo", "demo", "gelistirme", "abc", "sha256"),
])
def test_load_corpus_guards(tmp_path, key, stem, set_name, sha, msg):
    p = _corpus_file(tmp_path, {key: {"set": set_name, "orig": {"path": f"/x/{stem}", "sha256": sha}}})
    with pytest.raises(mm.MeasurementError, match=msg):
        mm.load_corpus(p)


def test_default_data_dir_is_repo_workspace_and_env_overridable(monkeypatch, tmp_path):
    monkeypatch.delenv(mm.DATA_DIR_ENV, raising=False)
    default = _load("macho_measure_default_dir_test").DEFAULT_DATA_DIR
    assert default == _REPO / "workspaces" / "olcum_mac"
    assert "karadul_olcum" not in str(default)               # Spotlight'ta dizinlenen yer değil
    monkeypatch.setenv(mm.DATA_DIR_ENV, str(tmp_path / "olcum"))
    other = _load("macho_measure_env_test")
    assert other.DEFAULT_DATA_DIR == tmp_path / "olcum"


# ---------------------------------------------------------------------------
# strip + export trie
# ---------------------------------------------------------------------------

def test_strip_uses_absolute_apple_strip(monkeypatch, tmp_path):
    assert mm.STRIP_PATH == "/usr/bin/strip"
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        Path(cmd[2]).write_bytes(b"stripped")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(mm.subprocess, "run", fake_run)
    src = tmp_path / "orig"
    src.write_bytes(b"orig")
    dst = tmp_path / "bin" / "x"
    mm.strip_binary(src, dst)
    assert calls[0][:2] == ["/usr/bin/strip", "-o"] and calls[0][3] == str(src)
    assert dst.read_bytes() == b"stripped" and src.read_bytes() == b"orig"
    with pytest.raises(mm.MeasurementError, match="mutlak"):
        mm.strip_binary(src, dst, strip_path="strip")
    assert len(calls) == 1


def test_export_trie_check_rejects_leftover_exports():
    assert mm.parse_dyld_exports(APPLE_EXPORTS) == ["__mh_execute_header"]
    mm.verify_exports(mm.parse_dyld_exports(APPLE_EXPORTS))
    mm.verify_exports([])
    with pytest.raises(mm.MeasurementError, match="export trie boşalmadı"):
        mm.verify_exports(mm.parse_dyld_exports(CONDA_EXPORTS))
    with pytest.raises(mm.MeasurementError, match="doğrulanamadı"):
        mm.parse_dyld_exports("dyld_info: unknown option: -exports\n")


# ---------------------------------------------------------------------------
# prepare
# ---------------------------------------------------------------------------

@pytest.fixture
def prep(tmp_path, monkeypatch):
    """Sahte araçlarla hazırlık ortamı: özgün dosya, korpus, veri dizini."""
    orig = tmp_path / "src" / "demo"
    orig.parent.mkdir()
    orig.write_bytes(b"ORIGINAL-MACHO")
    corpus = {"schema": mm.CORPUS_SCHEMA, "binaries": {"demo": {
        "set": "gelistirme", "orig": {"path": str(orig), "sha256": _sha(b"ORIGINAL-MACHO")},
        "homebrew": {"formula": "demo", "version": "1.0", "bottle_tag": "arm64_tahoe"}}}}
    state = {"strip_calls": 0, "exports": ["__mh_execute_header"], "stripped_nm": ""}

    def fake_strip(src, dst, strip_path=mm.STRIP_PATH):
        state["strip_calls"] += 1
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b"STRIPPED-" + Path(src).read_bytes())

    def fake_nm(path, nm_path=mm.mf.NM_PATH):
        return state["stripped_nm"] if Path(path).parent.name == "bin" else NM_ORIG

    monkeypatch.setattr(mm, "strip_binary", fake_strip)
    monkeypatch.setattr(mm, "read_exports", lambda p: list(state["exports"]))
    monkeypatch.setattr(mm.mf, "run_nm", fake_nm)
    monkeypatch.setattr(mm.mf, "nm_version", lambda nm_path=None: "fake nm")
    monkeypatch.setattr(mm, "tool_info", lambda: {"fake": True})
    return {"data": tmp_path / "data", "corpus": corpus, "state": state, "orig": orig}


def test_prepare_writes_gt_and_manifest(prep):
    m = mm.prepare(prep["data"], prep["corpus"], ["demo"])
    gt = json.loads(mm.gt_path(prep["data"], "demo").read_text())
    assert gt["counts"] == {"functions": 3, "names": 3, "program": 2, "cold": 1, "outlined": 0}
    assert gt["orig_sha256"] == _sha(b"ORIGINAL-MACHO")
    assert gt["stripped_sha256"] == _sha(b"STRIPPED-ORIGINAL-MACHO")
    assert mm.bin_path(prep["data"], "demo").read_bytes() == b"STRIPPED-ORIGINAL-MACHO"
    assert m["binaries"]["demo"]["exports_after_strip"] == ["__mh_execute_header"]
    assert json.loads((prep["data"] / "corpus" / "manifest.json").read_text())["binaries"]["demo"]


def test_prepare_rejects_sha256_mismatch(prep):
    prep["corpus"]["binaries"]["demo"]["orig"]["sha256"] = _sha(b"something else")
    with pytest.raises(mm.MeasurementError, match="sha256"):
        mm.prepare(prep["data"], prep["corpus"], ["demo"])
    assert prep["state"]["strip_calls"] == 0
    assert not mm.gt_path(prep["data"], "demo").exists()


def test_prepare_falls_back_to_verified_copy_only_with_same_sha(prep):
    mm.prepare(prep["data"], prep["corpus"], ["demo"])
    prep["orig"].unlink()                                       # kaynak klasör temizlendi
    mm.prepare(prep["data"], prep["corpus"], ["demo"])          # hazırlanmış kopyadan sürer
    assert prep["state"]["strip_calls"] == 2
    mm.orig_path(prep["data"], "demo").chmod(0o644)
    mm.orig_path(prep["data"], "demo").write_bytes(b"tampered")
    with pytest.raises(mm.MeasurementError, match="sha256"):
        mm.prepare(prep["data"], prep["corpus"], ["demo"])


def test_prepare_stops_when_export_trie_not_empty(prep):
    prep["state"]["exports"] = ["__mh_execute_header", "_Action_follow"]
    with pytest.raises(mm.MeasurementError, match="export trie"):
        mm.prepare(prep["data"], prep["corpus"], ["demo"])
    assert not mm.bin_path(prep["data"], "demo").exists()     # doğrulanmamış kopya silindi
    assert not mm.gt_path(prep["data"], "demo").exists()


def test_prepare_stops_when_symbols_survive_strip(prep):
    prep["state"]["stripped_nm"] = "0000000100001040 t _helper\n"
    with pytest.raises(mm.MeasurementError, match="sembolü kaldı"):
        mm.prepare(prep["data"], prep["corpus"], ["demo"])
    assert not mm.bin_path(prep["data"], "demo").exists()


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def _prepared(data: Path, name: str = "demo", payload: bytes = b"STRIPPED") -> None:
    b = mm.bin_path(data, name)
    b.parent.mkdir(parents=True, exist_ok=True)
    b.write_bytes(payload)
    g = mm.gt_path(data, name)
    g.parent.mkdir(parents=True, exist_ok=True)
    g.write_text(json.dumps({"binary": name, "orig_sha256": "o" * 64,
                             "stripped_sha256": _sha(payload), "functions": []}))


TREE_INFO = {"tree": "~/t", "commit": "c" * 40, "dirty_files": [], "karadul_file": "~/t/karadul/__init__.py",
             "karadul_version": "x", "runtime_data_missing": []}


@pytest.mark.parametrize("version, allow, should_run", [
    (PINNED, False, True),
    ("12.0_DEV", False, False),
    ("12.0_DEV", True, True),
])
def test_analyze_requires_pinned_ghidra(monkeypatch, tmp_path, version, allow, should_run):
    data = tmp_path / "data"
    _prepared(data)
    ran = []
    monkeypatch.setattr(mm.meas, "ghidra_info",
                        lambda g: {"install_dir": str(g), "version": version, "release": "X"})
    monkeypatch.setattr(mm.meas, "tree_info", lambda t: dict(TREE_INFO))
    monkeypatch.setattr(mm, "run_one", lambda *a, **k: ran.append(a[4]) or {"status": "ok"})
    if should_run:
        out = mm.analyze(tmp_path, "lbl", data, tmp_path / "ghidra", ["demo"], allow_other_ghidra=allow)
        assert ran == ["demo"] and out["session"]["ghidra"]["version"] == version
        assert out["session"]["tree_changed_during_run"] is False
    else:
        with pytest.raises(SystemExit, match="sabitlenen"):
            mm.analyze(tmp_path, "lbl", data, tmp_path / "ghidra", ["demo"], allow_other_ghidra=allow)
        assert ran == []


def test_build_command_never_runs_target():
    cmd = mm.build_command(Path("/d/bin/x"), Path("/d/runs/l/x"))
    assert cmd[1:5] == ["-m", "karadul", "analyze", "/d/bin/x"]
    assert "--skip-dynamic" in cmd and "--dynamic" not in cmd
    assert cmd[cmd.index("--output-dir") + 1] == "/d/runs/l/x/ws"
    assert cmd[cmd.index("--output") + 1] == "/d/runs/l/x/out"


class _FakePopen:
    seen: dict = {}

    def __init__(self, cmd, cwd=None, env=None, stdout=None, stderr=None, start_new_session=False):
        _FakePopen.seen = {"cmd": cmd, "cwd": cwd, "env": env, "new_session": start_new_session}
        ws = Path(cmd[cmd.index("--output-dir") + 1]) / "workspaces" / "x" / "t" / "static"
        ws.mkdir(parents=True)
        (ws / "ghidra_functions.json").write_text('{"functions": []}')
        self.pid = 0

    def wait(self, timeout=None):
        return 0


def test_run_one_passes_pinned_ghidra_and_tree(monkeypatch, tmp_path):
    data = tmp_path / "data"
    _prepared(data)
    monkeypatch.setattr(mm.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(mm.meas, "cfg_cache_snapshot", lambda: {})
    tree, ghidra = tmp_path / "tree", tmp_path / "ghidra_12"
    meta = mm.run_one(tree, ghidra, data, "lbl", "demo", timeout=5, force=True)
    seen = _FakePopen.seen
    assert meta["status"] == "ok" and meta["target_sha256"] == _sha(b"STRIPPED")
    assert seen["env"]["GHIDRA_INSTALL_DIR"] == str(ghidra)
    assert seen["env"]["PYTHONPATH"] == str(tree) and seen["cwd"] == tree
    assert seen["new_session"] is True
    assert json.loads((mm.run_dir(data, "lbl", "demo") / "run.json").read_text())["status"] == "ok"


def test_run_one_refuses_target_not_matching_gt(monkeypatch, tmp_path):
    data = tmp_path / "data"
    _prepared(data)
    mm.bin_path(data, "demo").write_bytes(b"conda-stripped copy")
    monkeypatch.setattr(mm.subprocess, "Popen", lambda *a, **k: pytest.fail("koşulmamalıydı"))
    with pytest.raises(mm.MeasurementError, match="strip'li kopyası değil"):
        mm.run_one(tmp_path, tmp_path, data, "lbl", "demo", timeout=5, force=True)


# ---------------------------------------------------------------------------
# score: geçerlilik denetimleri, toplama, kıyas
# ---------------------------------------------------------------------------

def _fake_run(root: Path, ttype: str, file_hash: str, ghidra_version: str = PINNED,
              ghidra: list | None = None, naming: dict | None = None) -> Path:
    run = root / "run"
    ts = run / "ws" / "workspaces" / "x" / "20261019_000000"
    for sub in ("static", "raw", "reports", "reconstructed/src"):
        (ts / sub).mkdir(parents=True, exist_ok=True)
    (run / "out").mkdir(parents=True, exist_ok=True)
    (ts / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": ghidra or []}))
    (ts / "reconstructed" / "src" / "naming_map.json").write_text(json.dumps({"global": naming or {}}))
    (ts / "raw" / "target_info.json").write_text(json.dumps({"target_type": ttype, "file_hash": file_hash}))
    (ts / "reports" / "report.json").write_text(json.dumps({
        "environment": {"ghidra": {"version": ghidra_version, "matches_pinned": ghidra_version == PINNED}},
        "target": {"type": ttype}}))
    (run / "out" / "report.json").write_text(json.dumps({
        "pipeline": {"stages": {"identify": {"stats": {"target_type": ttype}}}}}))
    return run


SHA = "a" * 64
SESSION = {"ghidra": {"version": PINNED}}


def test_run_checks_accepts_macho_and_rejects_go(tmp_path):
    ok = mm.run_checks(_fake_run(tmp_path / "ok", "macho_binary", SHA), {"stripped_sha256": SHA},
                       {"target_sha256": SHA}, SESSION)
    assert ok["valid"] and ok["target_type_ok"]
    assert set(ok["target_type"]) == {"out_report", "ws_report", "target_info"}
    go = mm.run_checks(_fake_run(tmp_path / "go", "go_binary", SHA), {"stripped_sha256": SHA},
                       {"target_sha256": SHA}, SESSION)
    assert not go["valid"] and not go["target_type_ok"]
    assert any("Mach-O değil" in r for r in go["invalid_reasons"])


def test_run_checks_rejects_wrong_file_and_other_ghidra(tmp_path):
    wrong = mm.run_checks(_fake_run(tmp_path / "w", "macho_binary", "b" * 64), {"stripped_sha256": SHA},
                          {"target_sha256": SHA}, SESSION)
    assert not wrong["valid"] and wrong["analyzed_sha256_matches_gt"] is False
    other = mm.run_checks(_fake_run(tmp_path / "g", "macho_binary", SHA, ghidra_version="12.0_DEV"),
                          {"stripped_sha256": SHA}, {"target_sha256": SHA}, SESSION)
    assert not other["valid"] and other["ghidra_report_matches_session"] is False


def _entry(name: str, valid: bool, tp: int, wrong: int, pop: int, rows=None) -> dict:
    block = {"population": pop, "named": tp + wrong, "tp": tp, "wrong": wrong,
             "unnamed": pop - tp - wrong, "lenient_tp": tp, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    zero = {k: 0 for k in block}
    return {"binary": name, "set": "gelistirme", "valid": valid, "rows": rows or [],
            "summary": {"siniflar": {"program": block, "cold": dict(zero), "outlined": dict(zero)}}}


def test_aggregate_excludes_invalid_runs():
    agg = mm.aggregate([_entry("htop", False, 50, 0, 100), _entry("tmux", True, 10, 30, 100)])
    assert agg["binaries"] == 1 and agg["excluded"] == ["htop"]
    m = agg["program"]["micro"]
    assert (m["tp"], m["wrong"], m["population"]) == (10, 30, 100)
    assert m["precision"] == 0.25 and m["recall"] == 0.1


def test_compare_reports_counts_gained_and_lost():
    def rows(statuses):
        return [{"addr": hex(0x1000 + i), "gt": [f"_f{i}"], "pred": None, "status": s, "lenient": False,
                 "sinif": "program"} for i, s in enumerate(statuses)]
    a = {"per_binary": [_entry("tmux", True, 1, 1, 4, rows(["tp", "wrong", "unnamed", "unnamed"])),
                        _entry("htop", False, 0, 0, 1)]}
    b = {"per_binary": [_entry("tmux", True, 2, 1, 4, rows(["unnamed", "tp", "tp", "wrong"])),
                        _entry("htop", True, 0, 0, 1)]}
    d = {x["binary"]: x for x in mm.compare_reports(a, b)}
    assert d["htop"]["comparable"] is False
    t = d["tmux"]
    assert t["gained_tp"] == ["_f1", "_f2"] and t["lost_tp"] == ["_f0"]
    assert t["new_wrong"] == 1 and t["fixed_wrong"] == 1 and t["population_same"]


def _synthetic_label(tmp_path: Path, **session_extra) -> tuple[Path, dict, Path]:
    """Sahte veri dizini: hazırlanmış ikili + GT + geçerli koşu + oturum dosyası."""
    data = tmp_path / "data"
    payload = b"STRIPPED"
    _prepared(data, payload=payload)
    gt = {"binary": "demo", "orig_sha256": "o" * 64, "stripped_sha256": _sha(payload),
          "functions": [{"addr": "0x100001000", "names": ["_main"]},
                        {"addr": "0x100001040", "names": ["_helper.cold.1"]}]}
    mm.gt_path(data, "demo").write_text(json.dumps(gt))
    rdir = mm.run_dir(data, "lbl", "demo")
    rdir.parent.mkdir(parents=True)
    ghidra = [{"name": "FUN_100001000", "address": "100001000", "is_thunk": False, "size": 4},
              {"name": "FUN_100001040", "address": "100001040", "is_thunk": False, "size": 4}]
    run = _fake_run(tmp_path / "tmp", "macho_binary", _sha(payload), ghidra=ghidra,
                    naming={"FUN_100001000": "main", "FUN_100001040": "helper"})
    run.rename(rdir)
    (rdir / "run.json").write_text(json.dumps({"status": "ok", "target_sha256": _sha(payload)}))
    session = {"tree": dict(TREE_INFO), "ghidra": {"version": PINNED}, "python": "3", "platform": "p",
               "jobs": 1, "timeout_s": 5, **session_extra}
    (rdir.parent / "session.json").write_text(json.dumps(session))
    return data, {"binaries": {"demo": {"set": "gelistirme"}}}, rdir


def test_score_label_end_to_end_synthetic(tmp_path, capsys):
    data, corpus, rdir = _synthetic_label(tmp_path)
    rep = mm.score_label("lbl", data, corpus, ["demo"])
    e = rep["per_binary"][0]
    assert e["valid"] and e["summary"]["siniflar"]["program"]["tp"] == 1
    assert e["summary"]["siniflar"]["cold"]["tp"] == 1
    assert (rdir / mm.SCORE_FILE_NAME).is_file()
    assert rep["aggregate"]["gelistirme"]["binaries"] == 1
    assert set(rep["harness"]) >= {"scripts/measurement/macho_f1.py",
                                   "scripts/measurement/function_f1.py"}
    out = tmp_path / "res.json"
    mm.write_report(rep, out)
    text = out.read_text(encoding="utf-8")
    assert json.loads(text)["per_binary"][0]["rows"][0]["status"] == "tp"
    assert '{"addr": "0x100001000"' in text                      # satır başına tek kayıt
    mm.print_table(rep)
    assert "| demo | gelistirme |" in capsys.readouterr().out


def test_describe_tree_change_separates_engine_paths(monkeypatch, tmp_path):
    start = {"commit": "a" * 40, "dirty_files": []}
    # measure.tree_info'nun gerçek çıktısı: ilk satırın baştaki boşluğu strip() ile düşüyor
    end = {"commit": "b" * 40, "dirty_files": ["M docs/arge/etiket_rehberi.md",
                                                " M scripts/measurement/README.md",
                                                "R  karadul/old.py -> docs/new.md"]}
    monkeypatch.setattr(mm.meas, "_git", lambda tree, *a: "docs/arge/x.md\nscripts/measurement/y.py")
    ch = mm.describe_tree_change(tmp_path, start, end, {})
    assert ch["changed"] and ch["engine_paths"] == []
    assert {"docs/arge/etiket_rehberi.md", "scripts/measurement/README.md", "docs/new.md"} <= set(ch["paths"])
    monkeypatch.setattr(mm.meas, "_git", lambda tree, *a: "karadul/stages.py\nsigs/x.json\ndocs/a.md")
    assert mm.describe_tree_change(tmp_path, start, end, {})["engine_paths"] == [
        "karadul/stages.py", "sigs/x.json"]
    # başta da sonda da kirli motor dosyası: içerik değiştiyse yakalanır, değişmediyse değil
    (tmp_path / "karadul").mkdir()
    f = tmp_path / "karadul" / "c_namer.py"
    f.write_text("v2")
    both = {"commit": "a" * 40, "dirty_files": [" M karadul/c_namer.py"]}
    assert mm.describe_tree_change(tmp_path, both, both, {"karadul/c_namer.py": "eski"})[
        "engine_paths"] == ["karadul/c_namer.py"]
    same = mm.describe_tree_change(tmp_path, both, both, {"karadul/c_namer.py": mm.f1.sha256_file(f)})
    assert not same["changed"] and same["engine_paths"] == []


def test_engine_change_during_run_invalidates(tmp_path):
    change = {"changed": True, "from": "a" * 40, "to": "b" * 40,
              "paths": ["karadul/stages.py"], "engine_paths": ["karadul/stages.py"]}
    data, corpus, _ = _synthetic_label(tmp_path, tree_change=change)
    rep = mm.score_label("lbl", data, corpus, ["demo"])
    e = rep["per_binary"][0]
    assert not e["valid"] and any("motor dosyaları" in r for r in e["checks"]["invalid_reasons"])
    assert rep["aggregate"]["gelistirme"]["binaries"] == 0
    docs_only = dict(change, paths=["docs/a.md"], engine_paths=[])
    data2, corpus2, _ = _synthetic_label(tmp_path / "b", tree_change=docs_only)
    rep2 = mm.score_label("lbl", data2, corpus2, ["demo"])
    assert rep2["per_binary"][0]["valid"]
    assert any("motor dosyaları (karadul/" in w for w in rep2["warnings"])
