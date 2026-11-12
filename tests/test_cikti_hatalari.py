"""Çıktı dürüstlüğü ve sağlamlığı: 2026-11-11'de görülüp dokunulmayan hatalar (2026-11-12).

Kanıt ve önce/sonra sayıları: ``docs/arge/2026-11-12_cikti_hatalari/sonuc.md``.

2. ``reconstructed/signature_matches.json`` kaydı fonksiyonun adresini taşımıyordu: aynı adlı iki
   thunk (Debian ``tree``'de ``getcwd`` 00103d00 PLT ve 00135010 dış blok) iki özdeş kayıt
   üretiyordu (133 kaydın 63'ü). ``SignatureMatch.address`` zaten doluydu (``match_all``);
   kaydı yazan iki yer (etkin ``pipeline/steps/ghidra_metadata.py`` ve emekli monolit yolunun
   ``stages._run_signature_matching``'i) alanı yazmıyordu. Kayıt artık ``address`` taşır;
   okuyucular anahtarla okuduğu için davranışları değişmez.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ikili")
    ws.create()
    return ws


def _result(ws: Workspace, stages: dict[str, dict]) -> PipelineResult:
    result = PipelineResult(target_name="ikili", target_hash="0" * 64, workspace_path=ws.path)
    for name, stats in stages.items():
        result.add_stage_result(StageResult(
            stage_name=name, success=True, duration_seconds=1.0, stats=stats,
        ))
    return result


# Debian tree'deki gibi: aynı adlı iki thunk (PLT ve dış blok) ve adsız bir fonksiyon
_FUNCTIONS = {"functions": [
    {"name": "getcwd", "address": "00103d00", "size": 16},
    {"name": "getcwd", "address": "00135010", "size": 1},
    {"name": "strlen", "address": "00103e00", "size": 16},
    {"name": "FUN_00104000", "address": "00104000", "size": 64},
]}


def _ghidra_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    d = tmp_path / "girdi"
    (d / "decompiled").mkdir(parents=True)
    funcs = d / "ghidra_functions.json"
    funcs.write_text(json.dumps(_FUNCTIONS), encoding="utf-8")
    strings = d / "ghidra_strings.json"
    strings.write_text("[]", encoding="utf-8")
    cg = d / "ghidra_call_graph.json"
    cg.write_text(json.dumps({"edges": []}), encoding="utf-8")
    return funcs, strings, cg, d / "decompiled"


def _pipeline_context(ws: Workspace) -> SimpleNamespace:
    return SimpleNamespace(config=Config(), workspace=ws,
                           report_progress=lambda *a, **k: None)


def _records(ws: Workspace) -> list[dict]:
    data = ws.load_json("reconstructed", "signature_matches")
    assert data is not None
    return data["matches"]


# ---------------------------------------------------------------------------
# 2. signature_matches.json kaydı adres taşır
# ---------------------------------------------------------------------------


class TestImzaKaydiAdres:
    def test_adim_yolu_adres_yazar(self, tmp_path) -> None:
        """Etkin yol (step registry): ghidra_metadata kaydı adres taşır; aynı adlı thunk'lar ayrılır."""
        from karadul.core.target import TargetType
        from karadul.pipeline.context import StepContext
        from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        pc = _pipeline_context(ws)
        ctx = StepContext(pipeline_context=pc)
        GhidraMetadataStep._run_signature_db(
            pc=pc, target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
            functions_json=funcs, strings_json=strings, call_graph_json=cg,
            decompiled_dir=dec, ctx=ctx,
        )
        rec = _records(ws)
        getcwd = [r for r in rec if r["original"] == "getcwd"]
        assert sorted(r["address"] for r in getcwd) == ["00103d00", "00135010"]
        # İki kayıt artık özdeş değil
        assert len({json.dumps(r, sort_keys=True) for r in rec}) == len(rec)
        assert all(r["address"] for r in rec)
        assert ctx.stats["signature_matches"] == len(rec)

    def test_monolit_yolu_adres_yazar(self, tmp_path) -> None:
        """Emekli monolit yolu (``_run_signature_matching``) aynı kaydı yazar (eşlik testi)."""
        from karadul.core.target import TargetType
        from karadul.pipeline.reconstruction_context import ReconstructionContext
        from karadul.stages import ReconstructionStage

        ws = _workspace(tmp_path)
        funcs, strings, cg, dec = _ghidra_inputs(tmp_path)
        context = SimpleNamespace(
            config=Config(), workspace=ws, report_progress=lambda *a, **k: None,
            target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
        )
        rc = ReconstructionContext()
        rc.ph1_artifacts.update({
            "functions_json_path": funcs, "strings_json_path": strings,
            "call_graph_json_path": cg, "decompiled_dir": dec,
        })
        ReconstructionStage()._run_signature_matching(context, rc)
        rec = _records(ws)
        assert sorted(r["address"] for r in rec if r["original"] == "getcwd") == [
            "00103d00", "00135010"]
        assert [r["address"] for r in rec] == [m.address for m in rc.sig_matches]

    def test_okuyucular_adres_alanindan_etkilenmez(self, tmp_path) -> None:
        """Adres alanı eklenince ad haritası, HTML aday tablosu ve arayüz aday kümesi aynı kalır."""
        from karadul.core.output_formatter import OutputFormatter
        from karadul.core.report_generator import ReportGenerator

        eski = [
            {"original": "getcwd", "matched": "getcwd", "library": "libc", "confidence": 0.98,
             "purpose": "cwd"},
            {"original": "getcwd", "matched": "getcwd", "library": "libc", "confidence": 0.98,
             "purpose": "cwd"},
            {"original": "FUN_00104000", "matched": "copy_buffer", "library": "libc",
             "confidence": 0.56, "purpose": "copy"},
        ]
        yeni = [{**r, "address": a} for r, a in zip(eski, ("00103d00", "00135010", "00104000"))]

        def oku(kayit: list[dict], alt: str):
            ws = Workspace(base_dir=tmp_path / alt, target_name="ikili")
            ws.create()
            ws.save_json("reconstructed", "signature_matches",
                         {"total": len(kayit), "matches": kayit})
            res = _result(ws, {})
            harita = OutputFormatter(ws, res)._build_naming_map()
            tablo = ReportGenerator(res, ws)._naming_table()
            return harita, tablo, ws

        h_eski, t_eski, _ = oku(eski, "eski")
        h_yeni, t_yeni, ws_yeni = oku(yeni, "yeni")
        assert h_yeni == h_eski
        assert t_yeni == t_eski

        ui = pytest.importorskip("ui.server")
        old_ws = ui.WS
        try:
            ui._CACHE.clear()
            ui.WS = str(ws_yeni.path)
            assert ui._signature_candidates() == {"getcwd", "FUN_00104000"}
        finally:
            ui.WS = old_ws
            ui._CACHE.clear()
