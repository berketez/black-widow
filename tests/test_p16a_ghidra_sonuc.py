"""P16a / GHIDRA-09: Ghidra'nın başarısı ve hata nedeni dürüst yazılır.

Eski davranış (ölçüldü, ``P16a.md``): bozuk ELF'te Ghidra "No load spec found" ile düşüyordu,
rapordaki tek iz ``Ghidra analiz basarisiz (rc=1)`` idi (``rc`` PyGhidra yolunda uydurma) ve
``static`` aşaması ham ikili kopyası yüzünden başarılı görünüyordu. Fonksiyonsuz nesne dosyasında
Ghidra "başarılı, 0 fonksiyon" diyordu. Decompile tümden düşse de sonuç başarılıydı.

Testler Ghidra istemez: PyGhidra yolu sahte nesnelerle, ``static`` aşaması sahte Ghidra sonucuyla
çalışır.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from karadul.config import Config
from karadul.ghidra import headless as headless_mod
from karadul.ghidra.headless import GhidraHeadless


# ---------------------------------------------------------------------------
# _judge_outcome: başarı kuralı ve neden metni
# ---------------------------------------------------------------------------

def _out(total=3, dec_success=3, dec_functions=None):
    return {
        "functions": {"total": total},
        "decompiled": {
            "success": dec_success, "total_attempted": total,
            "functions": dec_functions or [],
        },
    }


def test_basari_fonksiyon_ve_decompile_varsa():
    assert GhidraHeadless._judge_outcome(_out(), {}) == (True, None)


def test_dusen_yan_adim_basariyi_bozmaz_ama_neden_kalir():
    ok, err = GhidraHeadless._judge_outcome(_out(), {"strings": "RuntimeError: x"})
    assert ok is True and err is None


def test_fatal_neden_metniyle_basarisiz():
    ok, err = GhidraHeadless._judge_outcome({}, {"fatal": "LoadException: No load spec found"})
    assert ok is False
    assert "No load spec found" in err


def test_fonksiyon_listesi_dusunce_basarisiz():
    ok, err = GhidraHeadless._judge_outcome({}, {"functions": "RuntimeError: kirik"})
    assert ok is False and "kirik" in err


def test_sifir_fonksiyon_basarisiz():
    ok, err = GhidraHeadless._judge_outcome(_out(total=0, dec_success=0), {})
    assert ok is False
    assert "hiç fonksiyon bulmadı" in err


def test_decompile_adimi_dusunce_basarisiz():
    ok, err = GhidraHeadless._judge_outcome(_out(dec_success=0), {"decompile": "OSError: decompiler yok"})
    assert ok is False and "decompiler yok" in err


def test_hicbir_fonksiyon_decompile_edilmediyse_basarisiz_ve_ilk_hata_yazilir():
    funcs = [{"name": "a", "success": False, "error": "Decompiler process died"}]
    ok, err = GhidraHeadless._judge_outcome(_out(total=5, dec_success=0, dec_functions=funcs), {})
    assert ok is False
    assert "5 denendi" in err
    assert "Decompiler process died" in err


# ---------------------------------------------------------------------------
# _analyze_pyghidra: düşen adımlar step_errors'a, neden error'a, returncode uydurulmaz
# ---------------------------------------------------------------------------

class _Prog:
    def getName(self):
        return "sahte"


class _Flat:
    def getCurrentProgram(self):
        return _Prog()


class _Ctx:
    def __enter__(self):
        return _Flat()

    def __exit__(self, *a):
        return False


@pytest.fixture
def sahte_pyghidra(monkeypatch):
    mod = types.ModuleType("pyghidra")
    mod.open_program = lambda **kw: _Ctx()
    monkeypatch.setitem(sys.modules, "pyghidra", mod)
    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", lambda install, **kw: None)
    # P16c: otomatik analiz Karadul tarafında (TimeoutTaskMonitor); sahte ortamda Ghidra yok.
    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, program, t: {"status": "ok", "timeout_s": t, "duration_s": 0.0})
    cfg = Config()
    cfg.bsim.enabled = False
    cfg.binary_reconstruction.ghidra_data_type_archives = []
    cfg.binary_reconstruction.pdb_auto_load = False
    cfg.binary_reconstruction.enable_function_id = False
    gh = GhidraHeadless.__new__(GhidraHeadless)
    gh.config = cfg
    gh.analyze_headless = Path("/yok/support/analyzeHeadless")
    return gh, mod


def _yamala_adimlar(monkeypatch, *, dusen: set[str], fonksiyon: int = 2, decompile_ok: int = 2):
    def adim(ad, deger):
        def f(*a, **kw):
            if ad in dusen:
                raise RuntimeError("%s patladi" % ad)
            return deger
        return staticmethod(f)

    monkeypatch.setattr(GhidraHeadless, "_extract_functions", adim("functions", {
        "total": fonksiyon, "program_function_count": fonksiyon, "thunk_count": 0,
        "external_count": 0, "functions": [],
    }))
    monkeypatch.setattr(GhidraHeadless, "_extract_strings", adim("strings", {"total": 0, "strings": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_call_graph", adim("call_graph", {
        "total_functions": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_decompile_functions", adim("decompile", {
        "success": decompile_ok, "total_attempted": fonksiyon, "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_types", adim("types", {
        "total_structures": 0, "total_enums": 0, "total_typedefs": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_xrefs", adim("xrefs", {"statistics": {
        "total_functions": 0, "total_strings_with_xrefs": 0, "total_globals_with_xrefs": 0}}))
    monkeypatch.setattr(GhidraHeadless, "_extract_pcode_stats_only", adim("pcode", {
        "total_functions": 0, "mode": "stats_only"}))
    monkeypatch.setattr(GhidraHeadless, "_write_pcode_jsonl", adim("pcode", {
        "total_functions": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_cfg", adim("cfg", {
        "total_functions": 0, "total_blocks": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_get_program_info", adim("combined_results", {}))
    monkeypatch.setattr(GhidraHeadless, "_save_output", staticmethod(lambda *a, **kw: None))


def test_pyghidra_jvm_baslamazsa_neden_sonuca_yazilir(sahte_pyghidra, monkeypatch, tmp_path):
    gh, _ = sahte_pyghidra

    def patla(install, **kw):
        raise RuntimeError("Ghidra JVM baslatilamadi: libjvm yok")

    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", patla)
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 10, tmp_path)
    assert sonuc["success"] is False
    assert "libjvm yok" in sonuc["error"]
    assert "libjvm yok" in sonuc["step_errors"]["fatal"]
    assert sonuc["returncode"] is None
    assert "FATAL" in sonuc["ghidra_log"]


def test_pyghidra_decompile_duserse_basarisiz(sahte_pyghidra, monkeypatch, tmp_path):
    gh, _ = sahte_pyghidra
    _yamala_adimlar(monkeypatch, dusen={"decompile"})
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 10, tmp_path)
    assert sonuc["success"] is False
    assert "decompile patladi" in sonuc["error"]
    assert "decompile" in sonuc["step_errors"]


def test_pyghidra_yan_adim_duserse_basarili_ama_kayitli(sahte_pyghidra, monkeypatch, tmp_path):
    gh, _ = sahte_pyghidra
    _yamala_adimlar(monkeypatch, dusen={"strings", "call_graph", "cfg"})
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 10, tmp_path)
    assert sonuc["success"] is True
    assert sonuc["error"] is None
    assert set(sonuc["step_errors"]) == {"strings", "call_graph", "cfg"}
    assert "strings patladi" in sonuc["step_errors"]["strings"]
    assert "WARN: strings" in sonuc["ghidra_log"]


def test_pyghidra_sifir_fonksiyon_basarisiz(sahte_pyghidra, monkeypatch, tmp_path):
    gh, _ = sahte_pyghidra
    _yamala_adimlar(monkeypatch, dusen=set(), fonksiyon=0, decompile_ok=0)
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 10, tmp_path)
    assert sonuc["success"] is False
    assert "hiç fonksiyon bulmadı" in sonuc["error"]


# ---------------------------------------------------------------------------
# static aşaması: Ghidra düşerse aşama düşer; günlük ve durum diske yazılır
# ---------------------------------------------------------------------------

def _static_kos(monkeypatch, tmp_path, ghidra_sonucu, dizgiler=()):
    from karadul.analyzers.macho import MachOAnalyzer
    from karadul.core.target import Language, TargetInfo, TargetType
    from karadul.core.workspace import Workspace
    from karadul.core.subprocess_runner import SubprocessRunner

    for ad in ("_run_otool_libs", "_run_otool_load_commands", "_run_nm", "_run_lief"):
        monkeypatch.setattr(MachOAnalyzer, ad, lambda self, p: None)
    monkeypatch.setattr(SubprocessRunner, "run_strings", lambda self, p, min_length=None: list(dizgiler))
    monkeypatch.setattr(MachOAnalyzer, "_run_ghidra", lambda self, p, ws: ghidra_sonucu)

    class _BI:
        def __init__(self, *a, **k):
            pass

        def analyze(self, **k):
            class _R:
                class architecture:
                    app_type = "cli"
                    subsystems: list = []
                    algorithms: list = []
                    security: list = []
                    protocols: list = []
                    function_analyses: list = []

                def to_dict(self):
                    return {}
            return _R()

        def analyze_decompiled(self, d):
            return []

    monkeypatch.setattr("karadul.analyzers.binary_intelligence.BinaryIntelligence", _BI)
    ikili = tmp_path / "ikili"
    ikili.write_bytes(b"\x7fELF" + b"\x00" * 60)
    cfg = Config()
    cfg.project_root = tmp_path
    ws = Workspace(tmp_path / "ws", "ikili")
    ws.create()
    hedef = TargetInfo(path=ikili, name="ikili", target_type=TargetType.ELF_BINARY,
                       language=Language.C, file_size=ikili.stat().st_size,
                       file_hash="0" * 64, metadata={})
    sonuc = MachOAnalyzer(cfg).analyze_static(hedef, ws)
    return sonuc, ws.get_stage_dir("static")


def test_static_ghidra_dusunce_asama_basarisiz_ve_neden_yazili(monkeypatch, tmp_path):
    sonuc, static = _static_kos(monkeypatch, tmp_path, {
        "success": False, "error": "Ghidra analizi düştü: LoadException: No load spec found",
        "step_errors": {"fatal": "LoadException: No load spec found"},
        "ghidra_log": "FATAL: fatal: LoadException: No load spec found", "mode": "pyghidra",
        "returncode": None, "scripts_output": {},
    })
    assert sonuc.success is False
    assert any("No load spec found" in e for e in sonuc.errors)
    assert not any("rc=" in e for e in sonuc.errors)
    assert "No load spec found" in sonuc.stats["ghidra_error"]
    durum = json.loads((static / "ghidra_status.json").read_text(encoding="utf-8"))
    assert durum["success"] is False and "No load spec found" in durum["error"]
    assert "FATAL" in (static / "ghidra_log.txt").read_text(encoding="utf-8")


def test_static_cli_yolunda_cikis_kodu_nedenle_yazilir(monkeypatch, tmp_path):
    sonuc, _ = _static_kos(monkeypatch, tmp_path, {
        "success": False, "error": "beklenen JSON yok", "returncode": 3, "scripts_output": {},
    })
    assert sonuc.success is False
    assert any("beklenen JSON yok (çıkış kodu 3)" in e for e in sonuc.errors)


def test_static_basarili_ama_dusen_adim_hata_listesinde(monkeypatch, tmp_path):
    sonuc, static = _static_kos(monkeypatch, tmp_path, {
        "success": True, "error": None, "step_errors": {"strings": "RuntimeError: x"},
        "ghidra_log": "WARN: strings: RuntimeError: x", "mode": "pyghidra", "returncode": None,
        "scripts_output": {"combined_results": {"summary": {"function_count": 2}}},
    })
    assert sonuc.success is True
    assert sonuc.stats["ghidra_success"] is True
    assert sonuc.stats["ghidra_step_errors"] == {"strings": "RuntimeError: x"}
    assert any("Ghidra adımı başarısız (strings)" in e for e in sonuc.errors)
    assert json.loads((static / "ghidra_status.json").read_text(encoding="utf-8"))["success"] is True


def test_betik_yoksa_pyghidra_yolu_yine_kosar(monkeypatch, tmp_path):
    """Betikler yalnız CLI yolunda gerekir; eskiden betik yoksa Ghidra hiç koşmuyordu."""
    from karadul.analyzers.macho import MachOAnalyzer
    from karadul.core.workspace import Workspace

    cagrildi = {}

    class _Gh:
        def is_available(self):
            return True

        def get_default_scripts(self):
            return []

        @staticmethod
        def pyghidra_available():
            return True

        def analyze(self, **kw):
            cagrildi["evet"] = True
            return {"success": True, "scripts_output": {}}

    cfg = Config()
    cfg.project_root = tmp_path
    an = MachOAnalyzer(cfg)
    an.ghidra = _Gh()
    ws = Workspace(tmp_path / "ws", "ikili")
    ws.create()
    sonuc = an._run_ghidra_legacy(tmp_path / "ikili", ws)
    assert cagrildi.get("evet") is True
    assert sonuc["success"] is True

    class _GhCli(_Gh):
        @staticmethod
        def pyghidra_available():
            return False

    an.ghidra = _GhCli()
    sonuc = an._run_ghidra_legacy(tmp_path / "ikili", ws)
    assert sonuc["success"] is False and "betikleri bulunamadı" in sonuc["error"]
