"""HZ-1: Ghidra köprüsünün ölçüm kancaları (çıktıyı değiştirmez; yalnız durum dosyasına alan).

``_analyze_pyghidra`` her adımın süresini ``adim_sureleri``'ne (adlar ``GHIDRA_ADIMLARI``'ndan),
decompile parçalarının süre özetini ``decompile_parcalari``'na yazar; ``_record_ghidra_outcome``
bunları ve otomatik analizin kaydını (``analysis``: durum, süre, ``analyzer_times``) olduğu gibi
``static/ghidra_status.json``'a geçirir. ``ghidra_output/*.json`` içerikleri değişmez.

Ghidra / JVM gerekmez: sahte program, sahte modüller (``tests/test_p16c_analiz_suresi.py``
kalıbı). Adım süreleri sahte saatle sınanır: her sahte adım saati bilinen kadar ilerletir, kayıt
tam eşitlikle karşılaştırılır (yük altında da belirlenimli).
"""

from __future__ import annotations

import json
import sys
import time
import types
from pathlib import Path

import pytest

import karadul.ghidra.headless as headless_mod
from karadul.config import Config
from karadul.ghidra.headless import (
    DURUM_SURE_ALANLARI,
    GHIDRA_ADIMLARI,
    GhidraHeadless,
    _AdimSaati,
)
from tests.test_p16a_decompile_sirasi import _fonklar, _Program, sahte_ghidra  # noqa: F401
from tests.test_p16c_analiz_suresi import _Ghidra

# ---------------------------------------------------------------------------
# Sabit liste ve kayıt sınıfı
# ---------------------------------------------------------------------------


def test_adim_listesi_tekil_ve_ilerleme_sozlesmesiyle_ayni_adlar() -> None:
    assert len(GHIDRA_ADIMLARI) == len(set(GHIDRA_ADIMLARI))
    assert all(a.startswith("ghidra.") and " " not in a for a in GHIDRA_ADIMLARI)
    # olcek/PLAN.md §1 sözleşmesinin örnek adları
    for ad in ("ghidra.otomatik_analiz", "ghidra.decompile", "ghidra.xref", "ghidra.cfg"):
        assert ad in GHIDRA_ADIMLARI
    assert [a for a in GHIDRA_ADIMLARI if a.startswith("ghidra.bsim")] == [
        "ghidra.bsim.ingest", "ghidra.bsim.query"]
    assert DURUM_SURE_ALANLARI == ("analysis", "adim_sureleri", "decompile_parcalari")


def test_adim_saati_bilinmeyen_adi_reddeder() -> None:
    with pytest.raises(ValueError, match="bilinmeyen Ghidra adımı"):
        _AdimSaati().basla("ghidra.yok_boyle")


def test_adim_saati_baslamamis_adimi_yazmaz_ve_liste_sirasinda_dondurur() -> None:
    s = _AdimSaati()
    s.bitti("ghidra.cfg")                       # başlamadı: yazılmaz
    s.basla("ghidra.cfg")
    s.basla("ghidra.functions")
    s.bitti("ghidra.cfg")
    s.bitti("ghidra.functions")
    s.bitti("ghidra.functions")                 # ikinci bitiş: değişmez
    assert list(s.sozluk()) == ["ghidra.functions", "ghidra.cfg"]
    assert all(isinstance(v, float) and v >= 0 for v in s.sozluk().values())


# ---------------------------------------------------------------------------
# _analyze_pyghidra: sahte saatle tam eşitlik
# ---------------------------------------------------------------------------

class _Saat:
    """``headless_mod.time`` yerine: ``monotonic`` elle ilerler, ``time`` gerçek."""

    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t

    def ilerle(self, sn: float) -> None:
        self.t += sn

    @staticmethod
    def time() -> float:
        return time.time()


# Her adımın sahte süresi (ikili kesirler: üç basamağa yuvarlama tam).
SURE = {
    "ghidra.jvm_baslatma": 0.5,
    "ghidra.ice_aktarma": 0.25,
    "ghidra.otomatik_analiz": 8.0,
    "ghidra.gdt": 0.375,
    "ghidra.pdb": 0.625,
    "ghidra.functions": 1.0,
    "ghidra.strings": 2.0,
    "ghidra.call_graph": 3.0,
    "ghidra.decompile": 4.0,
    "ghidra.types": 0.75,
    "ghidra.xref": 5.0,
    "ghidra.pcode": 1.5,
    "ghidra.cfg": 6.0,
    "ghidra.function_id": 0.875,
    "ghidra.bsim.ingest": 2.5,
    "ghidra.bsim.query": 3.5,
    "ghidra.combined": 0.125,
    "ghidra.kapatma": 0.125,
}
assert set(SURE) == set(GHIDRA_ADIMLARI)

PARCALAR = {"yol": "paralel", "parca_sayisi": 2, "is_parcacigi": 2, "parca_boyu": 1,
            "parca_sn": [1.0, 3.0], "sure_sn": {"en_kucuk": 1.0, "ortanca": 2.0, "en_buyuk": 3.0}}


class _Prog:
    def getName(self):  # noqa: N802
        return "sahte"


class _BSim:
    """Sahte ``karadul.ghidra.bsim.BSimDatabase``; ingest / sorgu saati ilerletir."""

    saat: _Saat
    patla: str | None = None

    def __init__(self, config) -> None:
        self.status = {"mode": "lite", "status": "ok"}

    def ingest_program(self, program, db):
        _BSim.saat.ilerle(SURE["ghidra.bsim.ingest"])
        if _BSim.patla == "ingest":
            raise RuntimeError("ingest patladi")
        return 2

    def query_all_functions(self, program, sim, db_name=None):
        _BSim.saat.ilerle(SURE["ghidra.bsim.query"])
        if _BSim.patla == "query":
            raise RuntimeError("query patladi")
        return types.SimpleNamespace(
            total_matches=0,
            to_payload=lambda: {"total_matches": 0, "matches": [], "bsim_mode": "lite",
                                "bsim_status": "ok"})

    def close(self) -> None:
        pass


@pytest.fixture
def kopru(monkeypatch):
    """Bütün adımları açık sahte köprü; dönüş: (GhidraHeadless, saat, kayıt)."""
    saat = _Saat()
    monkeypatch.setattr(headless_mod, "time", saat)
    kayit: dict = {"kaydedilen": {}}

    class _Ctx:
        def __enter__(self):
            return types.SimpleNamespace(getCurrentProgram=lambda: _Prog())

        def __exit__(self, *a):
            saat.ilerle(SURE["ghidra.kapatma"])
            return False

    def open_program(**kw):
        saat.ilerle(SURE["ghidra.ice_aktarma"])
        return _Ctx()

    pg = types.ModuleType("pyghidra")
    pg.open_program = open_program
    monkeypatch.setitem(sys.modules, "pyghidra", pg)
    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started",
                        lambda install, **kw: saat.ilerle(SURE["ghidra.jvm_baslatma"]))

    def adim(ad, deger):
        def f(*a, **kw):
            saat.ilerle(SURE[ad])
            if ad in kayit.get("dusen", ()):
                raise RuntimeError("%s patladi" % ad)
            return json.loads(json.dumps(deger))
        return staticmethod(f)

    monkeypatch.setattr(GhidraHeadless, "_run_auto_analysis",
                        lambda self, p, t: (saat.ilerle(SURE["ghidra.otomatik_analiz"]),
                                            {"status": "ok", "timeout_s": t, "duration_s": 7.5,
                                             "analyzer_times": {"Stack": 0.5}})[1])
    monkeypatch.setattr(GhidraHeadless, "_load_gdt_archives_pyghidra",
                        lambda self, *a: (saat.ilerle(SURE["ghidra.gdt"]), 1)[1])
    monkeypatch.setattr(GhidraHeadless, "_load_pdb_if_available",
                        lambda self, *a: (saat.ilerle(SURE["ghidra.pdb"]), False)[1])
    monkeypatch.setattr(GhidraHeadless, "_extract_functions", adim("ghidra.functions", {
        "total": 2, "program_function_count": 2, "thunk_count": 0, "external_count": 0,
        "functions": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_strings", adim("ghidra.strings",
                                                                 {"total": 0, "strings": []}))
    monkeypatch.setattr(GhidraHeadless, "_extract_call_graph", adim("ghidra.call_graph", {
        "total_functions": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_decompile_functions", adim("ghidra.decompile", {
        "success": 2, "total_attempted": 2, "functions": [], "_decompile_parcalari": PARCALAR}))
    monkeypatch.setattr(GhidraHeadless, "_extract_types", adim("ghidra.types", {
        "total_structures": 0, "total_enums": 0, "total_typedefs": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_xrefs", adim("ghidra.xref", {"statistics": {
        "total_functions": 0, "total_strings_with_xrefs": 0, "total_globals_with_xrefs": 0}}))
    monkeypatch.setattr(GhidraHeadless, "_extract_pcode_stats_only", adim("ghidra.pcode", {
        "total_functions": 0, "mode": "stats_only"}))
    monkeypatch.setattr(GhidraHeadless, "_write_pcode_jsonl", adim("ghidra.pcode",
                                                                   {"total_functions": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_cfg", adim("ghidra.cfg", {
        "total_functions": 0, "total_blocks": 0, "total_edges": 0}))
    monkeypatch.setattr(GhidraHeadless, "_extract_function_id_matches", adim(
        "ghidra.function_id", {"total_matches": 0}))
    monkeypatch.setattr(GhidraHeadless, "_get_program_info", adim("ghidra.combined", {}))
    monkeypatch.setattr(GhidraHeadless, "_save_output", staticmethod(
        lambda d, ad, veri: kayit["kaydedilen"].__setitem__(ad, json.loads(json.dumps(veri)))))

    bsim_mod = types.ModuleType("karadul.ghidra.bsim")
    _BSim.saat = saat
    _BSim.patla = None
    bsim_mod.BSimDatabase = _BSim
    monkeypatch.setitem(sys.modules, "karadul.ghidra.bsim", bsim_mod)
    shadow = types.ModuleType("karadul.ghidra._bsim_shadow")
    shadow.build_shadow_payload = lambda raw_data, shadow_mode: {"matches": []}
    monkeypatch.setitem(sys.modules, "karadul.ghidra._bsim_shadow", shadow)

    cfg = Config()
    cfg.bsim.enabled = True
    cfg.bsim.auto_query = True
    cfg.binary_reconstruction.ghidra_data_type_archives = ["sahte.gdt"]
    cfg.binary_reconstruction.pdb_auto_load = True
    cfg.binary_reconstruction.enable_function_id = True
    gh = GhidraHeadless.__new__(GhidraHeadless)
    gh.config = cfg
    gh.analyze_headless = Path("/yok/support/analyzeHeadless")
    return gh, saat, kayit


def _kos(gh, tmp_path):
    return gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 60, tmp_path)


def test_her_adimin_suresi_kendi_araligindan_ve_liste_sirasinda(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    sonuc = _kos(gh, tmp_path)
    assert sonuc["success"] is True
    assert sonuc["adim_sureleri"] == SURE
    assert list(sonuc["adim_sureleri"]) == list(GHIDRA_ADIMLARI)
    # adımlar ayrık ve köprü süresinin içinde: aralarda saat ilerlemediği için toplam = süre
    assert sum(sonuc["adim_sureleri"].values()) == pytest.approx(sonuc["duration_seconds"])
    assert sonuc["analysis"]["analyzer_times"] == {"Stack": 0.5}


def test_decompile_parca_ozeti_ciktiya_girmez_durum_alanina_gider(kopru, tmp_path) -> None:
    gh, _, kayit = kopru
    sonuc = _kos(gh, tmp_path)
    assert sonuc["decompile_parcalari"] == PARCALAR
    assert "_decompile_parcalari" not in sonuc["scripts_output"]["decompiled"]
    kaydedilen = kayit["kaydedilen"]
    assert "_decompile_parcalari" not in kaydedilen["decompiled.json"]
    # ghidra_output'a yazılan dosyalar eskisiyle aynı küme; hiçbirinde süre alanı yok
    assert set(kaydedilen) == {
        "functions.json", "strings.json", "call_graph.json", "decompiled.json", "types.json",
        "xrefs.json", "pcode.json", "cfg.json", "function_id.json", "bsim_matches.json",
        "bsim_shadow.json", "combined_results.json"}
    metin = json.dumps(kaydedilen)
    assert "adim_sureleri" not in metin and "decompile_parcalari" not in metin
    assert set(sonuc["scripts_output"]) == {
        "functions", "strings", "call_graph", "decompiled", "types", "xrefs", "pcode", "cfg",
        "function_id", "bsim", "combined_results"}


def test_dusen_adimin_suresi_dustugu_ana_kadar_yazilir(kopru, tmp_path) -> None:
    gh, _, kayit = kopru
    kayit["dusen"] = {"ghidra.strings", "ghidra.cfg"}
    sonuc = _kos(gh, tmp_path)
    assert set(sonuc["step_errors"]) == {"strings", "cfg"}
    assert sonuc["adim_sureleri"] == SURE


def test_bsim_ingest_duserse_sorgu_yok_ingest_yazili(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    _BSim.patla = "ingest"
    sonuc = _kos(gh, tmp_path)
    assert "ingest patladi" in sonuc["step_errors"]["bsim"]
    beklenen = {k: v for k, v in SURE.items() if k != "ghidra.bsim.query"}
    assert sonuc["adim_sureleri"] == beklenen


def test_bsim_sorgusu_duserse_iki_alt_adim_da_yazili(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    _BSim.patla = "query"
    sonuc = _kos(gh, tmp_path)
    assert "query patladi" in sonuc["step_errors"]["bsim"]
    assert sonuc["adim_sureleri"] == SURE


def test_kapali_adimlar_sozlukte_yok(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    gh.config.bsim.enabled = False
    gh.config.binary_reconstruction.ghidra_data_type_archives = []
    gh.config.binary_reconstruction.pdb_auto_load = False
    gh.config.binary_reconstruction.enable_function_id = False
    sonuc = _kos(gh, tmp_path)
    kapali = {"ghidra.gdt", "ghidra.pdb", "ghidra.function_id", "ghidra.bsim.ingest",
              "ghidra.bsim.query"}
    assert sonuc["adim_sureleri"] == {k: v for k, v in SURE.items() if k not in kapali}
    assert sum(sonuc["adim_sureleri"].values()) == pytest.approx(sonuc["duration_seconds"])


def test_sorgu_kapaliyken_yalniz_ingest(kopru, tmp_path) -> None:
    gh, _, _ = kopru
    gh.config.bsim.auto_query = False
    sonuc = _kos(gh, tmp_path)
    assert "ghidra.bsim.query" not in sonuc["adim_sureleri"]
    assert sonuc["adim_sureleri"]["ghidra.bsim.ingest"] == SURE["ghidra.bsim.ingest"]


def test_jvm_baslamazsa_yarim_adim_yazilmaz_ve_parca_alani_yok(kopru, monkeypatch, tmp_path):
    gh, saat, _ = kopru

    def patla(install, **kw):
        saat.ilerle(0.5)
        raise RuntimeError("libjvm yok")

    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", patla)
    sonuc = _kos(gh, tmp_path)
    assert sonuc["success"] is False and "fatal" in sonuc["step_errors"]
    assert sonuc["adim_sureleri"] == {}
    assert "decompile_parcalari" not in sonuc


def test_ice_aktarma_duserse_yalniz_jvm_yazili(kopru, monkeypatch, tmp_path) -> None:
    gh, saat, _ = kopru

    def acilamaz(**kw):
        saat.ilerle(0.25)
        raise RuntimeError("LoadException: No load spec found")

    monkeypatch.setattr(sys.modules["pyghidra"], "open_program", acilamaz)
    sonuc = _kos(gh, tmp_path)
    assert sonuc["adim_sureleri"] == {"ghidra.jvm_baslatma": 0.5}


def test_decompile_duserse_parca_alani_yok_sure_yazili(kopru, tmp_path) -> None:
    gh, _, kayit = kopru
    kayit["dusen"] = {"ghidra.decompile"}
    sonuc = _kos(gh, tmp_path)
    assert "decompile_parcalari" not in sonuc
    assert sonuc["adim_sureleri"]["ghidra.decompile"] == SURE["ghidra.decompile"]


def test_gercek_otomatik_analiz_cozumleyici_sureleri_sonuca_gecer(monkeypatch, tmp_path) -> None:
    """P16c'nin ``_run_auto_analysis``'i (sahte Ghidra ile) → sonuç ``analysis.analyzer_times``."""
    g = _Ghidra()
    g.install(monkeypatch)

    class _Ctx:
        def __enter__(self):
            return types.SimpleNamespace(getCurrentProgram=lambda: _Prog())

        def __exit__(self, *a):
            return False

    pg = types.ModuleType("pyghidra")
    pg.open_program = lambda **kw: _Ctx()
    monkeypatch.setitem(sys.modules, "pyghidra", pg)
    monkeypatch.setattr(headless_mod, "_ensure_pyghidra_started", lambda install, **kw: None)
    from tests.test_p16c_analiz_suresi import _steps
    _steps(monkeypatch)
    cfg = Config()
    cfg.bsim.enabled = False
    cfg.binary_reconstruction.ghidra_data_type_archives = []
    cfg.binary_reconstruction.pdb_auto_load = False
    cfg.binary_reconstruction.enable_function_id = False
    gh = GhidraHeadless.__new__(GhidraHeadless)
    gh.config = cfg
    gh.analyze_headless = Path("/yok/support/analyzeHeadless")
    sonuc = gh._analyze_pyghidra(tmp_path / "x", tmp_path / "p", "p", 60, tmp_path)
    assert sonuc["analysis"]["status"] == "ok"
    assert sonuc["analysis"]["analyzer_times"] == {
        "ASCII Strings": 0.191, "Decompiler Switch Analysis": 1.444, "Stack": 0.295}
    assert "ghidra.otomatik_analiz" in sonuc["adim_sureleri"]


# ---------------------------------------------------------------------------
# Decompile parçaları: gerçek paralel ve seri yol (sahte decompiler)
# ---------------------------------------------------------------------------

ESKI_DECOMPILE_ANAHTARLARI = {
    "total_attempted", "success", "failed", "skipped", "duration_seconds", "decompiled_dir",
    "functions_order", "functions_total", "functions_written", "functions_truncated",
    "functions", "losses", "batch_size", "total_batches",
}


def test_parca_ozeti_paralel_yol(tmp_path, sahte_ghidra) -> None:  # noqa: F811
    fonklar = _fonklar(22)                       # 22 // 4 = 5'lik parçalar: 5 parça (son parça 2)
    yavas = {f.getEntryPoint() for f in fonklar[5:10]}
    sahte_ghidra["gecikme"] = lambda f: 0.02 if f.getEntryPoint() in yavas else 0.0
    hedef = tmp_path / "d"
    hedef.mkdir()
    r = GhidraHeadless._parallel_decompile_java_threads(_Program(fonklar), hedef, 22, 30, 0, 4)
    oz = r.pop("_decompile_parcalari")
    assert set(r) == ESKI_DECOMPILE_ANAHTARLARI | {"parallel", "threads"}
    assert oz["yol"] == "paralel"
    assert (oz["parca_sayisi"], oz["is_parcacigi"], oz["parca_boyu"]) == (5, 4, 5)
    assert len(oz["parca_sn"]) == 5 and all(isinstance(s, float) for s in oz["parca_sn"])
    assert oz["parca_sn"][1] >= 0.1                # yavaş parça: 5 × 0,02 sn
    assert oz["sure_sn"]["en_buyuk"] == max(oz["parca_sn"]) >= 0.1
    assert oz["sure_sn"]["en_kucuk"] == min(oz["parca_sn"])


def test_dusen_parcanin_suresi_de_yazilir(tmp_path, sahte_ghidra, monkeypatch) -> None:  # noqa: F811
    fonklar = _fonklar(8)
    asil = GhidraHeadless._decompile_single_function

    def patlayan(decomp, func, *a, **kw):
        if func.getEntryPoint() == fonklar[2].getEntryPoint():
            raise RuntimeError("JVM parca hatasi")
        return asil(decomp, func, *a, **kw)

    monkeypatch.setattr(GhidraHeadless, "_decompile_single_function", staticmethod(patlayan))
    hedef = tmp_path / "d"
    hedef.mkdir()
    r = GhidraHeadless._parallel_decompile_java_threads(_Program(fonklar), hedef, 8, 30, 0, 4)
    assert r["losses"]["chunk_errors"][0]["chunk"] == 1
    assert None not in r["_decompile_parcalari"]["parca_sn"]


def test_parca_ozeti_seri_yol(tmp_path, sahte_ghidra) -> None:  # noqa: F811
    fonklar = _fonklar(6)
    hedef = tmp_path / "seri"
    hedef.mkdir()
    r = GhidraHeadless._serial_decompile_fallback(_Program(fonklar), hedef, 6, 30, 0)
    oz = r.pop("_decompile_parcalari")
    assert set(r) == ESKI_DECOMPILE_ANAHTARLARI | {"parallel"}
    assert (oz["yol"], oz["parca_sayisi"], oz["is_parcacigi"], oz["parca_boyu"]) == (
        "seri", 1, 1, 6)
    # tek parçanın süresi decompile'ın kendi toplam süresidir (o 2, bu 3 basamak yuvarlanır)
    assert len(oz["parca_sn"]) == 1
    assert abs(oz["parca_sn"][0] - r["duration_seconds"]) <= 0.01
    assert oz["sure_sn"]["ortanca"] == oz["parca_sn"][0]


def test_parca_ozeti_en_kucuk_ortanca_en_buyuk() -> None:
    oz = GhidraHeadless._chunk_time_summary([0.4, None, 0.1, 0.3], path="paralel", threads=3,
                                            chunk_size=7)
    assert oz == {"yol": "paralel", "parca_sayisi": 4, "is_parcacigi": 3, "parca_boyu": 7,
                  "parca_sn": [0.4, None, 0.1, 0.3],
                  "sure_sn": {"en_kucuk": 0.1, "ortanca": 0.3, "en_buyuk": 0.4}}
    bos = GhidraHeadless._chunk_time_summary([None], path="paralel", threads=1, chunk_size=1)
    assert "sure_sn" not in bos


# ---------------------------------------------------------------------------
# _record_ghidra_outcome: yeni alanlar durum dosyasına aynen; geri kalanı değişmez
# ---------------------------------------------------------------------------

def _durum_yaz(tmp_path, sonuc: dict, alt: str) -> dict:
    from karadul.analyzers.macho import MachOAnalyzer
    from karadul.core.workspace import Workspace

    ws = Workspace(tmp_path / alt, "ikili")
    ws.create()
    artifacts: dict = {}
    stats: dict = {}
    MachOAnalyzer._record_ghidra_outcome(sonuc, ws, artifacts, stats)
    yol = ws.get_stage_dir("static") / "ghidra_status.json"
    assert artifacts["ghidra_status"] == yol
    return {"durum": json.loads(yol.read_text(encoding="utf-8")), "stats": stats,
            "metin": yol.read_text(encoding="utf-8")}


ESKI_SONUC = {
    "success": True, "error": None, "step_errors": {"strings": "RuntimeError: x"},
    "mode": "pyghidra", "returncode": None, "duration_seconds": 31.5,
    "ghidra_log": "WARN: strings: RuntimeError: x",
    "scripts_output": {
        "functions": {"total": 3, "program_function_count": 2, "thunk_count": 1,
                      "external_count": 0},
        "decompiled": {"total_attempted": 3, "success": 3, "failed": 0, "skipped": 0,
                       "functions_truncated": 0},
    },
    "project": {"path": "/p", "kept": False, "reason": "silindi"},
}
YENI = {
    "analysis": {"status": "ok", "timeout_s": 60, "duration_s": 7.5,
                 "analyzer_times": {"Stack": 0.5, "ASCII Strings": 0.25}},
    "adim_sureleri": {"ghidra.functions": 1.0, "ghidra.decompile": 4.0},
    "decompile_parcalari": PARCALAR,
}


def test_durum_dosyasi_yeni_alanlari_aynen_tasir_gerisi_ayni(tmp_path) -> None:
    eski = _durum_yaz(tmp_path, dict(ESKI_SONUC), "eski")
    yeni = _durum_yaz(tmp_path, {**ESKI_SONUC, **YENI}, "yeni")
    for alan in DURUM_SURE_ALANLARI:
        assert yeni["durum"][alan] == YENI[alan]
        assert alan not in eski["durum"]
    assert {k: v for k, v in yeni["durum"].items() if k not in DURUM_SURE_ALANLARI} == eski["durum"]
    # yeni alanlar sona eklenir: eski anahtarların sırası ve içeriği aynı
    assert list(yeni["durum"])[: len(eski["durum"])] == list(eski["durum"])
    assert yeni["stats"] == eski["stats"]


def test_alan_yoksa_durum_dosyasi_eskisiyle_bayt_ayni(tmp_path) -> None:
    """CLI / başka arka uç yolu: sonuçta süre alanı yok → dosya eskisiyle aynı (alan uydurulmaz)."""
    eski = _durum_yaz(tmp_path, dict(ESKI_SONUC), "eski")
    beklenen_anahtar = ["success", "error", "step_errors", "mode", "returncode",
                        "duration_seconds", "functions", "decompile", "outputs", "project"]
    assert list(eski["durum"]) == beklenen_anahtar
    kismi = _durum_yaz(tmp_path, {**ESKI_SONUC, "analysis": YENI["analysis"]}, "kismi")
    assert list(kismi["durum"]) == beklenen_anahtar + ["analysis"]


# ---------------------------------------------------------------------------
# scripts/arge/hiz/s8_esitlik.py: hariç alanlar, fark birimleri, A/A ile sınıflama
# ---------------------------------------------------------------------------

def _s8_modulu():
    import importlib.util

    yol = Path(__file__).resolve().parents[1] / "scripts" / "arge" / "hiz" / "s8_esitlik.py"
    spec = importlib.util.spec_from_file_location("s8_esitlik_test", yol)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _kosu_kur(kok: Path, zaman: str, *, sure: float, cfg_blok: int, c_govde: str,
              yeni_alan: bool) -> None:
    ikili = kok / "debian" / "coreutils" / "cat"
    st = ikili / "ws" / "workspaces" / "cat" / zaman / "static"
    (st / "ghidra_output" / "decompiled").mkdir(parents=True)
    dec = {"success": 2, "duration_seconds": sure, "decompiled_dir": str(st / "x"),
           "functions": [{"name": "main"}]}
    (st / "ghidra_output" / "decompiled.json").write_text(json.dumps(dec), encoding="utf-8")
    (st / "ghidra_decompiled.json").write_text(json.dumps(dec), encoding="utf-8")
    (st / "ghidra_output" / "cfg.json").write_text(
        json.dumps({"functions": [{"blocks": cfg_blok}]}), encoding="utf-8")
    (st / "ghidra_output" / "bsim_shadow.json").write_text(
        json.dumps({"timestamp": sure, "bsim_detail": {"ingest_s": sure, "mode": "lite"}}),
        encoding="utf-8")
    (st / "ghidra_output" / "decompiled" / "main.c").write_text(c_govde, encoding="utf-8")
    durum = {"success": True, "duration_seconds": 10.0 + sure,
             "project": {"path": str(st / "proje"), "kept": False}}
    if yeni_alan:
        durum.update({"analysis": {"status": "ok", "analyzer_times": {"Stack": 0.5}},
                      "adim_sureleri": {"ghidra.functions": 1.0, "ghidra.decompile": 2.0},
                      "decompile_parcalari": {"parca_sayisi": 3}})
    (st / "ghidra_status.json").write_text(json.dumps(durum), encoding="utf-8")
    (ikili / "out").mkdir()
    (ikili / "out" / "naming_map.json").write_text('{"a": 1}', encoding="utf-8")
    (ikili / "BITTI").write_text("0\n", encoding="utf-8")


def test_s8_esitlik_haric_alanlar_ve_yeni_durum_alanlari_fark_sayilmaz(tmp_path) -> None:
    m = _s8_modulu()
    _kosu_kur(tmp_path / "once", "1", sure=1.5, cfg_blok=4, c_govde="int main;", yeni_alan=False)
    _kosu_kur(tmp_path / "sonra", "2", sure=9.25, cfg_blok=4, c_govde="int main;", yeni_alan=True)
    r = m.kos(tmp_path / "once", tmp_path / "sonra", None)
    s = r["ikililer"]["debian/coreutils/cat"]
    assert s["cikti_esit"] is True and s["sonraya_yuklenebilir"] == []
    assert s["sonra"]["ozet"]["durum_yeni_alanlar"] == {
        "once": [], "sonra": ["analysis", "adim_sureleri", "decompile_parcalari"]}
    k = s["sure_kaydi"]
    assert k["H3_analyzer_times_dolu"] is True and k["H4_tutarli"] is True
    assert r["ikililer"]["mac/tmux"] == {"durum": "koşu bitmedi (BITTI yok)"}
    assert r["ozet"]["kiyaslanan"] == 1


def test_s8_esitlik_farki_birimiyle_bulur_ve_aa_ile_ayirir(tmp_path) -> None:
    m = _s8_modulu()
    _kosu_kur(tmp_path / "once", "1", sure=1.0, cfg_blok=4, c_govde="int main;", yeni_alan=False)
    _kosu_kur(tmp_path / "aa", "2", sure=2.0, cfg_blok=5, c_govde="int main;", yeni_alan=False)
    _kosu_kur(tmp_path / "sonra", "3", sure=3.0, cfg_blok=5, c_govde="int main2;", yeni_alan=True)
    r = m.kos(tmp_path / "once", tmp_path / "sonra", tmp_path / "aa")
    s = r["ikililer"]["debian/coreutils/cat"]
    assert s["belirlenimsizlik"] == ["json:ghidra_output/cfg.json:functions[].blocks"]
    assert s["sonraya_yuklenebilir"] == ["c:main.c"]
    assert s["cikti_esit"] is False
    assert s["aa"]["ozet"]["json_farkli_dosya"] == 1
    md = m.markdown(r)
    assert "T-AA" in md and "`c:main.c`" in md


def test_s8_esitlik_toplam_sure_asilirsa_h4_tutmaz(tmp_path) -> None:
    m = _s8_modulu()
    _kosu_kur(tmp_path / "sonra", "1", sure=0.0, cfg_blok=1, c_govde="x", yeni_alan=True)
    st = next((tmp_path / "sonra").glob("debian/coreutils/cat/ws/workspaces/cat/*/static"))
    d = json.loads((st / "ghidra_status.json").read_text(encoding="utf-8"))
    d["adim_sureleri"]["ghidra.cfg"] = 100.0
    d["adim_sureleri"]["ghidra.yok"] = 0.0
    (st / "ghidra_status.json").write_text(json.dumps(d), encoding="utf-8")
    k = m.sure_kaydi_denetle(tmp_path / "sonra" / "debian" / "coreutils" / "cat")
    assert k["toplam_sureyi_asmiyor"] is False
    assert k["bilinmeyen_adim"] == ["ghidra.yok"]
    assert k["H4_tutarli"] is False
