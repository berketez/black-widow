"""P16c kalem 1 (GHIDRA-06 kalanı): Ghidra otomatik analizi süre sınırıyla koşar.

Eskiden ``pyghidra.open_program(analyze=True)`` analizi süresiz koşuyordu. Şimdi
``open_program(analyze=False)`` + Karadul'un ``_run_auto_analysis``'i (pyghidra'nın
``_analyze_program``'ıyla aynı adımlar, izleyici ``TimeoutTaskMonitor``). Süre dolarsa
sonuç ``analysis.status = "timeout"``, ``step_errors["analysis"]`` zaman aşımı der
(``static`` aşaması bunu hata olarak yazar → kısmi). JVM yığını
``analysis.ghidra_max_heap_mb``'den.

Ghidra / JVM gerekmez: ``ghidra.*`` ve ``java.*`` sahte modüllerle taklit edilir.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import karadul.ghidra.headless as headless_mod
from karadul.config import Config
from karadul.ghidra.headless import GhidraHeadless

TASK_TIMES = """\
-----------------------------------------------------
    ASCII Strings                              0.191 secs
    Decompiler Switch Analysis                 1.444 secs
    Stack                                      0.295 secs
-----------------------------------------------------
     Total Time   3 secs
-----------------------------------------------------
"""


class _Ghidra:
    """Sahte Ghidra analiz ortamı; çağrıları kaydeder."""

    def __init__(self, timeout_hit: bool = False, should_ask: bool = True) -> None:
        self.calls: list[str] = []
        self.timeout_hit = timeout_hit
        self.should_ask = should_ask
        self.timeout_arg = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        g = self

        class TimeUnit:
            SECONDS = "SECONDS"

        class Monitor:
            def __init__(self, t, unit) -> None:
                g.timeout_arg = (t, unit)

            def didTimeout(self):  # noqa: N802
                return g.timeout_hit

            def finished(self):
                g.calls.append("finished")

        class TimeoutTaskMonitor:
            @staticmethod
            def timeoutIn(t, unit):  # noqa: N802
                return Monitor(t, unit)

        class FlatProgramAPI:
            def __init__(self, program, monitor) -> None:
                assert isinstance(monitor, Monitor), "analiz süreli izleyiciyle koşmalı"
                g.calls.append("flat_api")

            def analyzeAll(self, program):  # noqa: N802
                g.calls.append("analyzeAll")

        class GhidraProgramUtilities:
            @staticmethod
            def shouldAskToAnalyze(program):  # noqa: N802
                return g.should_ask

            @staticmethod
            def markProgramAnalyzed(program):  # noqa: N802
                g.calls.append("mark")

        class GhidraScriptUtil:
            @staticmethod
            def acquireBundleHostReference():  # noqa: N802
                g.calls.append("acquire")

            @staticmethod
            def releaseBundleHostReference():  # noqa: N802
                g.calls.append("release")

        class AutoAnalysisManager:
            @staticmethod
            def getAnalysisManager(program):  # noqa: N802
                return types.SimpleNamespace(
                    getTaskTimesString=lambda: TASK_TIMES,
                    initializeOptions=lambda: g.calls.append("initializeOptions"))

        class Program:
            ANALYSIS_PROPERTIES = "Analyzers"

        mods = {}
        for name in ("java", "java.util", "java.util.concurrent", "ghidra", "ghidra.app",
                     "ghidra.app.script", "ghidra.app.plugin", "ghidra.app.plugin.core",
                     "ghidra.app.plugin.core.analysis", "ghidra.program",
                     "ghidra.program.flatapi", "ghidra.program.util", "ghidra.util",
                     "ghidra.util.task", "ghidra.program.model", "ghidra.program.model.listing"):
            mods[name] = types.ModuleType(name)
            monkeypatch.setitem(sys.modules, name, mods[name])
        mods["java.util.concurrent"].TimeUnit = TimeUnit
        mods["ghidra.util.task"].TimeoutTaskMonitor = TimeoutTaskMonitor
        mods["ghidra.program.flatapi"].FlatProgramAPI = FlatProgramAPI
        mods["ghidra.program.util"].GhidraProgramUtilities = GhidraProgramUtilities
        mods["ghidra.app.script"].GhidraScriptUtil = GhidraScriptUtil
        mods["ghidra.app.plugin.core.analysis"].AutoAnalysisManager = AutoAnalysisManager
        mods["ghidra.program.model.listing"].Program = Program


def _gh(cfg: Config | None = None) -> GhidraHeadless:
    gh = GhidraHeadless.__new__(GhidraHeadless)
    gh.config = cfg or Config()
    gh.analyze_headless = Path("/yok/support/analyzeHeadless")
    return gh


def test_analiz_sureli_izleyiciyle_ve_pyghidra_adimlariyla(monkeypatch) -> None:
    g = _Ghidra()
    g.install(monkeypatch)
    info = _gh()._run_auto_analysis(object(), 120)
    assert info["status"] == "ok"
    assert g.timeout_arg == (120, "SECONDS")
    assert g.calls == ["flat_api", "acquire", "analyzeAll", "mark", "release", "finished"]
    assert info["analyzer_times"] == {
        "ASCII Strings": 0.191, "Decompiler Switch Analysis": 1.444, "Stack": 0.295}
    assert info["timeout_s"] == 120 and info["duration_s"] >= 0


def test_analiz_zaman_asiminda_kismi_isaretlenmez(monkeypatch) -> None:
    g = _Ghidra(timeout_hit=True)
    g.install(monkeypatch)
    info = _gh()._run_auto_analysis(object(), 2)
    assert info["status"] == "timeout"
    assert "mark" not in g.calls
    assert g.calls.count("acquire") == g.calls.count("release") == 1
    assert "finished" in g.calls


def test_zaten_cozumlenmis_program_yeniden_cozumlenmez(monkeypatch) -> None:
    g = _Ghidra(should_ask=False)
    g.install(monkeypatch)
    info = _gh()._run_auto_analysis(object(), 60)
    assert info["status"] == "already_analyzed"
    assert "analyzeAll" not in g.calls


# ---------------------------------------------------------------------------
# _analyze_pyghidra: analyze=False, süre aktarılır, zaman aşımı adım hatası olur
# ---------------------------------------------------------------------------

class _Prog:
    def getName(self):  # noqa: N802
        return "sahte"


class _Flat:
    def getCurrentProgram(self):  # noqa: N802
        return _Prog()


class _Ctx:
    def __enter__(self):
        return _Flat()

    def __exit__(self, *a):
        return False


def _steps(monkeypatch) -> None:
    def adim(deger):
        return staticmethod(lambda *a, **kw: deger)

    monkeypatch.setattr(GhidraHeadless, "_extract_functions", adim({
        "total": 2, "program_function_count": 2, "thunk_count": 0,
        "external_count": 0, "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_strings", adim({"total": 0, "strings": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_call_graph", adim({
        "total_functions": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_decompile_functions", adim({
        "success": 2, "total_attempted": 2, "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_types", adim({
        "total_structures": 0, "total_enums": 0, "total_typedefs": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_xrefs", adim({"statistics": {
        "total_functions": 0, "total_strings_with_xrefs": 0, "total_globals_with_xrefs": 0}}))
    monkeypatch.setattr(GhidraHeadless, "_extract_pcode_stats_only", adim({
        "total_functions": 0, "mode": "stats_only"}))
    monkeypatch.setattr(GhidraHeadless, "_write_pcode_jsonl", adim({"total_functions": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_cfg", adim({
        "total_functions": 0, "total_blocks": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_get_program_info", adim({}))
    monkeypatch.setattr(GhidraHeadless, "_save_output", staticmethod(lambda *a, **kw: None))


@pytest.fixture
def sahte(monkeypatch):
    kayit: dict = {}
    mod = types.ModuleType("pyghidra")

    def open_program(**kw):
        kayit["open_kw"] = kw
        return _Ctx()

    mod.open_program = open_program
    monkeypatch.setitem(sys.modules, "pyghidra", mod)

    def baslat(install, **kw):
        kayit["jvm_kw"] = kw

    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", baslat)
    cfg = Config()
    cfg.bsim.enabled = False
    cfg.binary_reconstruction.ghidra_data_type_archives = []
    cfg.binary_reconstruction.pdb_auto_load = False
    cfg.binary_reconstruction.enable_function_id = False
    _steps(monkeypatch)
    return _gh(cfg), kayit


def test_open_program_analizsiz_acilir_ve_sure_aktarilir(sahte, monkeypatch, tmp_path) -> None:
    gh, kayit = sahte

    def analiz(self, program, t):
        kayit["analiz_t"] = t
        return {"status": "ok", "timeout_s": t, "duration_s": 1.5}

    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis", analiz)
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 321, tmp_path)
    assert kayit["open_kw"]["analyze"] is False
    assert kayit["analiz_t"] == 321
    assert sonuc["success"] is True
    assert sonuc["analysis"]["status"] == "ok"
    assert "analysis" not in sonuc["step_errors"]


def test_zaman_asimi_adim_hatasi_ve_kayit(sahte, monkeypatch, tmp_path) -> None:
    gh, _ = sahte
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, p, t: {"status": "timeout", "timeout_s": t, "duration_s": t})
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 5, tmp_path)
    assert sonuc["analysis"]["status"] == "timeout"
    assert "zaman aşımı" in sonuc["step_errors"]["analysis"]
    assert "5 sn" in sonuc["step_errors"]["analysis"]
    assert "WARN: analysis" in sonuc["ghidra_log"]
    # fonksiyonlar ve decompile varsa Ghidra başarılı ama kısmi (adım hatası kayıtta)
    assert sonuc["success"] is True


def test_analiz_dusunce_adim_hatasi(sahte, monkeypatch, tmp_path) -> None:
    gh, _ = sahte

    def patla(self, p, t):
        raise RuntimeError("AutoAnalysisManager yok")

    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis", patla)
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 5, tmp_path)
    assert sonuc["analysis"]["status"] == "failed"
    assert "AutoAnalysisManager yok" in sonuc["step_errors"]["analysis"]


def test_jvm_yigini_ayardan(sahte, monkeypatch, tmp_path) -> None:
    gh, kayit = sahte
    gh.config.analysis.ghidra_max_heap_mb = 1234
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, p, t: {"status": "ok", "timeout_s": t})
    gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 5, tmp_path)
    assert kayit["jvm_kw"]["heap_mb"] == 1234


def test_jvm_baslatici_yigin_argumani(monkeypatch) -> None:
    vmargs: list[str] = []

    class Launcher:
        def __init__(self, install_dir) -> None:
            pass

        def add_vmargs(self, *a):
            vmargs.extend(a)

        def start(self):
            pass

    pg = types.ModuleType("pyghidra")
    pg.started = lambda: False
    launcher_mod = types.ModuleType("pyghidra.launcher")
    launcher_mod.HeadlessPyGhidraLauncher = Launcher
    monkeypatch.setitem(sys.modules, "pyghidra", pg)
    monkeypatch.setitem(sys.modules, "pyghidra.launcher", launcher_mod)
    monkeypatch.setattr(headless_mod, "_PYGHIDRA_STARTED", False)
    monkeypatch.setattr(headless_mod, "warn_if_ghidra_unpinned", lambda p: {})
    monkeypatch.setattr(headless_mod, "_release_jvm_creator_thread", lambda: None)
    headless_mod._ensure_pyghidra_started(Path("/yok"), heap_mb=2048)
    assert "-Xmx2048m" in vmargs
    vmargs.clear()
    monkeypatch.setattr(headless_mod, "_PYGHIDRA_STARTED", False)
    from karadul.config import GHIDRA_HEAP_MB
    headless_mod._ensure_pyghidra_started(Path("/yok"))
    assert f"-Xmx{GHIDRA_HEAP_MB}m" in vmargs


class _OptProgram:
    """Seçenekleri ve işlemleri kaydeden program taklidi."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.opts: dict[str, bool] = {"Stack": True, "Decompiler Switch Analysis": True}

    def startTransaction(self, _ad):  # noqa: N802
        self.calls.append("tx_begin")
        return 1

    def endTransaction(self, _tx, commit):  # noqa: N802
        self.calls.append("tx_end:%s" % commit)

    def getOptions(self, kind):  # noqa: N802
        assert kind == "Analyzers"
        prog = self
        return types.SimpleNamespace(
            contains=lambda n: n in prog.opts,
            setBoolean=lambda n, v: prog.opts.__setitem__(n, v))


def test_cozumleyici_kapatma_ayari_analizden_once(monkeypatch) -> None:
    g = _Ghidra()
    g.install(monkeypatch)
    cfg = Config()
    cfg.analysis.ghidra_disabled_analyzers = ["Stack", "Yanlis Ad"]  # alan yok (yama); getattr
    prog = _OptProgram(g.calls)
    info = _gh(cfg)._run_auto_analysis(prog, 60)
    assert info["disabled_analyzers"] == {"Stack": True, "Yanlis Ad": False}
    assert prog.opts == {"Stack": False, "Decompiler Switch Analysis": True}
    assert g.calls.index("initializeOptions") < g.calls.index("analyzeAll")
    assert "tx_end:True" in g.calls


def test_cozumleyici_ayari_yoksa_dokunulmaz(monkeypatch) -> None:
    g = _Ghidra()
    g.install(monkeypatch)
    prog = _OptProgram(g.calls)
    info = _gh()._run_auto_analysis(prog, 60)
    assert "disabled_analyzers" not in info
    assert "tx_begin" not in g.calls
