"""P04a kalem 1 — bileşim şablonu bekletmesi (K-1, 2026-11-18).

Kanıt kapısından geçmeyen şablon eşleşmesi raporlayıcıların okuduğu alanlara
(``compositions``, ``total_compositions`` → ``stats["compositions"]``,
``compositions.md``) girmez; ``pending_compositions`` alanında gerekçesiyle durur.

Girdi gerçek bir ikiliden: ``debian/coreutils/cat`` (genel-tarama-2026-11-18
koşusu) — MUH-03'ün kanıtındaki adlar (``_DT_INIT``, ``__gmon_start__``,
``_ITM_deregisterTMCloneTable``, ``fflush`` …) her ELF'te bulunur.
"""
from __future__ import annotations

import json
from pathlib import Path

from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace
from karadul.pipeline.steps import _deep_tracing_helpers as dh
from karadul.reconstruction.engineering.composition_analyzer import (
    KNOWN_COMPOSITIONS,
    AlgorithmCompositionAnalyzer,
)
from karadul.reporting.html_report import HTMLReporter
from karadul.reporting.markdown_report import MarkdownReporter

SABLON_ADLARI = {t["name_template"] for t in KNOWN_COMPOSITIONS.values()}

# coreutils cat'in çağrı çizgesindeki gerçek adlar (MUH-03 kanıtı)
_CAT_ADLARI = [
    "_DT_INIT", "_DT_FINI", "_INIT_0", "__gmon_start__",
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
    "fflush", "malloc", "realloc", "free", "close", "mbsinit",
    "FUN_00103374", "FUN_00103b80",
]


def _cizge(adlar: list[str], kenarlar: list[tuple[str, str]] = ()) -> dict:
    adres = {ad: f"{0x101000 + 0x10 * i:08x}" for i, ad in enumerate(adlar)}
    nodes = {
        adres[ad]: {"name": ad, "address": adres[ad], "callers": [], "callees": []}
        for ad in adlar
    }
    for a, b in kenarlar:
        nodes[adres[a]]["callees"].append({"name": b, "address": adres[b]})
        nodes[adres[b]]["callers"].append({"name": a, "address": adres[a]})
    return {"nodes": nodes}


def _cat_cizgesi() -> dict:
    return _cizge(_CAT_ADLARI, [("_DT_INIT", "FUN_00103374"),
                                ("FUN_00103374", "fflush"),
                                ("FUN_00103374", "malloc"),
                                ("FUN_00103374", "free")])


def test_runtime_adlarindan_sablon_raporlanan_alana_girmez():
    sonuc = AlgorithmCompositionAnalyzer().analyze(
        call_graph=_cat_cizgesi(), algorithms=[])
    assert sonuc.success
    raporlanan = {c.name for c in sonuc.compositions}
    assert not (raporlanan & SABLON_ADLARI)
    assert sonuc.total_compositions == len(sonuc.compositions)


# Yalnız ad eşleşmesi taşıyan (algoritma tespiti olmayan) yerel fonksiyonlar:
# şablon adayı olur ama kanıtı yoktur → beklemede kalmalı.
_YALNIZ_AD = ["driver", "mesh_read", "stiffness_assembly", "solve_system",
              "postprocess_stress"]


def _yalniz_ad_cizgesi() -> dict:
    return _cizge(_YALNIZ_AD, [("driver", "mesh_read"),
                               ("driver", "stiffness_assembly"),
                               ("driver", "solve_system"),
                               ("driver", "postprocess_stress")])


def test_beklemedeki_sablon_gerekcesiyle_ayri_alanda():
    sonuc = AlgorithmCompositionAnalyzer().analyze(
        call_graph=_yalniz_ad_cizgesi(), algorithms=[])
    assert not ({c.name for c in sonuc.compositions} & SABLON_ADLARI)
    assert "Linear Static FEA Pipeline" in {c.name for c in sonuc.pending_compositions}
    for c in sonuc.pending_compositions:
        assert c.name in SABLON_ADLARI
        assert c.evidence_gate is not None
        assert c.evidence_gate["passed"] is False
        assert c.evidence_gate["reason"]
    d = sonuc.to_dict()
    assert d["total_pending"] == len(d["pending_compositions"])
    assert d["total_compositions"] == len(d["compositions"])
    assert not ({c["name"] for c in d["compositions"]} & SABLON_ADLARI)
    assert "K-1" in d["pending_note"]
    json.dumps(d)  # JSON'a yazılabilir


def test_generate_report_beklemedekini_yazmaz():
    an = AlgorithmCompositionAnalyzer()
    sonuc = an.analyze(call_graph=_yalniz_ad_cizgesi(), algorithms=[])
    assert sonuc.pending_compositions
    md = an.generate_report(sonuc)
    for ad in SABLON_ADLARI:
        assert ad not in md


def test_adim_yardimcisi_stats_ve_json_beklemedekini_saymaz(tmp_path: Path):
    """Ürünün çağırdığı yol: ``_deep_tracing_helpers.analyze_composition``."""
    ws = Workspace(tmp_path, "cat")
    ws.create()
    stats: dict = {}
    errors: list = []
    dh.analyze_composition(
        call_graph_data=_cat_cizgesi(), all_algos=[], data_flow_result=None,
        dispatch_result=None, reconstructed_dir=ws.get_stage_dir("reconstructed"),
        stats=stats, errors=errors, workspace=ws,
        publish_artifact=lambda k, v: None)
    assert errors == []
    kayit = ws.load_json("reconstructed", "algorithm_compositions")
    assert stats["compositions"] == len(kayit["compositions"])
    assert not ({c["name"] for c in kayit["compositions"]} & SABLON_ADLARI)
    md = (ws.get_stage_dir("reconstructed") / "compositions.md").read_text()
    for ad in SABLON_ADLARI:
        assert ad not in md


def _sahte_sonuc(stats: dict) -> PipelineResult:
    pr = PipelineResult(target_name="cat", target_hash="0" * 64)
    pr.stages["reconstruct"] = StageResult(
        stage_name="reconstruct", success=True, duration_seconds=0.0, stats=stats)
    return pr


def test_raporlayicilar_beklemedekini_gostermez(tmp_path: Path):
    """Markdown ve HTML raporlayıcı (dokunulmadan) bekleyen şablonu yazmaz."""
    ws = Workspace(tmp_path, "cat")
    ws.create()
    stats: dict = {}
    dh.analyze_composition(
        call_graph_data=_cat_cizgesi(), all_algos=[], data_flow_result=None,
        dispatch_result=None, reconstructed_dir=ws.get_stage_dir("reconstructed"),
        stats=stats, errors=[], workspace=ws, publish_artifact=lambda k, v: None)
    sonuc = _sahte_sonuc(stats)
    md = "\n".join(MarkdownReporter()._section_deep_analysis(sonuc, ws))
    html = HTMLReporter()._deep_analysis_section(sonuc, ws)
    for ad in SABLON_ADLARI:
        assert ad not in md
        assert ad not in html
    # P07: bileşimler ortak bölümde (rapor verisi katmanı); bekleyen şablon iddia değil,
    # yalnız sayısı yazılır.
    from karadul.reporting.report_data import build_report_data
    sec = build_report_data(sonuc, ws).sections["compositions"]
    assert sec.status == "clean" and sec.items == []
    full_md = MarkdownReporter()._build_markdown(sonuc, ws)
    full_html = HTMLReporter()._build_html(sonuc, ws)
    for ad in SABLON_ADLARI:
        assert ad not in full_md and ad not in full_html
