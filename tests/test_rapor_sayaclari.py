"""Rapor sayaçları: tur sayısı, yakınsama nedeni ve ithal sayısı (2026-11-11).

Çıktı sağlamlığı denetimi (docs/arge/2026-11-10_cikti_saglamligi/rapor.md, kalem 13) üç sayacın
119 ikilinin 119'unda yanlış olduğunu ölçtü. Kök nedenler:

* ``pipeline_iterations_run``: turları Faz 2'deki ``feedback_loop`` adımı sayıyor; step-registry
  kipinde 0 tur koşan eski döngünün sonu (stages.py) değeri 0 ile eziyordu.
* ``convergence_reason``: ``feedback_loop`` nedeni Faz 2 koşucusunun yapıtına yazıyor; ``finalize``
  Faz 3 koşucusunda ve Faz 3 tohumunda bu anahtar yoktu, hep "unknown" yazılıyordu.
* ``summary.total_imports``: ``static`` istatistiklerinde ``imports_found`` hiç üretilmiyordu.

Testler sayaçları denetimin okuduğu yerden okur: aşama istatistikleri ve ``reports/report.json``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

import tests.test_macho as _tm
from karadul.analyzers.macho import MachOAnalyzer
from karadul.config import Config
from karadul.core.result import PipelineResult, StageResult
from karadul.core.target import TargetType
from karadul.core.workspace import Workspace
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import feedback_loop as _fl
from karadul.pipeline.steps._feedback_loop_iter import IterOutcome
from karadul.pipeline.steps.feedback_loop import FeedbackLoopStep
from karadul.pipeline.steps.finalize import FinalizeStep
from karadul.reporting.json_report import JSONReporter
from karadul.stages import ReconstructionStage


# ---------------------------------------------------------------------------
# 1. Tur sayısı ve yakınsama nedeni: _execute_binary üç fazla, sahte koşucuyla
# ---------------------------------------------------------------------------

_ITER_DETAILS = [
    {"iteration": 1, "new_names": 40, "total_names": 40, "duration": 2.0},
    {"iteration": 2, "new_names": 0, "total_names": 40, "duration": 1.5},
]


class _Artifacts(dict):
    """Faz 1 yapıtları: sınamada kullanılmayan anahtarlar None döner."""

    def __missing__(self, key: str):
        return None


def _phase2_outcome(tmp_path: Path, convergence_reason: str | None) -> SimpleNamespace:
    """feedback_loop'un gerçek çıktı biçimi: sayaçlar stats'ta, neden yapıtta."""
    final_dir = tmp_path / "loop_final"
    final_dir.mkdir(exist_ok=True)
    artifacts: dict[str, Any] = {
        "naming_result": None, "computation_result": None,
        "updated_algo_result": None, "updated_eng_result": None,
        "final_decompiled_dir": final_dir, "iteration_stats": list(_ITER_DETAILS),
    }
    if convergence_reason is not None:
        artifacts["convergence_reason"] = convergence_reason
    stats = {
        "pipeline_iterations_run": len(_ITER_DETAILS),
        "pipeline_iteration_details": list(_ITER_DETAILS),
        "timing_pipeline_loop": 3.5,
        "timing_c_naming_iter0": 1.0,
        "timing_c_naming_iter1": 0.8,
    }
    return SimpleNamespace(artifacts=artifacts, stats=stats, errors=[], stage_artifacts={})


def _run_three_phases(tmp_path: Path, monkeypatch, convergence_reason: str | None):
    """``_execute_binary``'yi üç faz boyunca yürüt; Faz 3'te gerçek ``finalize`` koşar.

    Dönen: (StageResult, Faz 3 tohumu).
    """
    import karadul.pipeline.runner as runner_mod

    decompiled = tmp_path / "static" / "decompiled"
    decompiled.mkdir(parents=True)
    recorded: dict[str, Any] = {}

    class _FakeRunner:
        def __init__(self, steps):
            self.steps = list(steps)

        def run(self, context, seed_artifacts=None):
            if "feedback_loop" in self.steps:
                return _phase2_outcome(tmp_path, convergence_reason)
            if "finalize" in self.steps:
                recorded["seed"] = dict(seed_artifacts)
                ctx = StepContext(pipeline_context=context)
                ctx._write_artifacts(dict(seed_artifacts))
                ctx.produce_artifact("faz3", tmp_path / "faz3")
                return SimpleNamespace(artifacts=FinalizeStep().run(ctx))
            return SimpleNamespace(
                artifacts=_Artifacts(c_files=[], decompiled_dir=decompiled, extracted_names={}),
                stats={}, errors=[], stage_artifacts={},
            )

    monkeypatch.setattr(runner_mod, "PipelineRunner", _FakeRunner)

    def stage_dir(stage: str) -> Path:
        d = tmp_path / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    context = SimpleNamespace(
        target=SimpleNamespace(path=tmp_path / "ikili", file_hash=""),
        workspace=SimpleNamespace(get_stage_dir=stage_dir, path=tmp_path),
        config=Config(), metadata={},
    )
    result = ReconstructionStage()._execute_binary(context, time.monotonic())
    assert result.success is True, result.errors
    return result, recorded["seed"]


class TestTurSayisi:
    def test_feedback_loop_tur_sayisi_ezilmez(self, tmp_path, monkeypatch) -> None:
        """Faz 2'nin saydığı tur sayısı ve ayrıntısı rapora olduğu gibi gider (0 değil)."""
        result, _seed = _run_three_phases(tmp_path, monkeypatch, "no_new_names")
        assert result.stats["pipeline_iterations_run"] == 2
        assert result.stats["pipeline_iteration_details"] == _ITER_DETAILS
        assert result.stats["timing_pipeline_loop"] == 3.5

    def test_tur_sayisi_denetimin_olcusuyle_tutarli(self, tmp_path, monkeypatch) -> None:
        """Denetim turu ``timing_c_naming_iterN`` anahtarlarından sayar; ikisi eşit."""
        result, _seed = _run_three_phases(tmp_path, monkeypatch, "no_new_names")
        turlar = [k for k in result.stats if k.startswith("timing_c_naming_iter")]
        assert result.stats["pipeline_iterations_run"] == len(turlar) == 2


class TestYakinsamaNedeni:
    def test_neden_faz3_tohumuna_ve_rapora_gider(self, tmp_path, monkeypatch) -> None:
        result, seed = _run_three_phases(tmp_path, monkeypatch, "no_new_names")
        assert seed.get("convergence_reason") == "no_new_names"
        assert result.stats["convergence_reason"] == "no_new_names"

    def test_oran_nedeni_olduğu_gibi_tasinir(self, tmp_path, monkeypatch) -> None:
        result, _seed = _run_three_phases(tmp_path, monkeypatch, "convergence_ratio_0.004")
        assert result.stats["convergence_reason"] == "convergence_ratio_0.004"

    def test_neden_yoksa_uydurulmaz(self, tmp_path, monkeypatch) -> None:
        """feedback_loop neden vermediyse tohuma anahtar girmez; finalize "unknown" yazar."""
        result, seed = _run_three_phases(tmp_path, monkeypatch, None)
        assert "convergence_reason" not in seed
        assert result.stats["convergence_reason"] == "unknown"


# ---------------------------------------------------------------------------
# 2. feedback_loop adımı: tur sayısı ve neden üretimi (sayacın kaynağı)
# ---------------------------------------------------------------------------


@pytest.fixture
def loop_ctx(tmp_path: Path):
    br = SimpleNamespace(
        pipeline_iterations=5, pipeline_convergence_threshold=0.01,
        pipeline_iteration_timeout=600.0, pipeline_min_new_names_per_iter=1,
        enable_c_naming=False, enable_type_recovery=False,
        min_naming_confidence=0.7,
    )
    pc = MagicMock()
    pc.config = SimpleNamespace(
        binary_reconstruction=br, computation_recovery=SimpleNamespace(enabled=False),
        name_merger=MagicMock(), project_root=tmp_path,
    )
    (tmp_path / "reconstructed").mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=tmp_path / "reconstructed")
    pc.metadata = {}
    pc.target.file_hash = "ab" * 32
    pc.target.target_type = None
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    keys = ("functions_json_path", "strings_json_path", "call_graph_json_path",
            "ghidra_types_json_path", "xrefs_json_path", "cfg_json_path", "fid_json_path",
            "decompiled_json_path", "functions_data", "strings_data", "sig_matches",
            "algo_result_filtered", "eng_result_filtered")
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        **{k: None for k in keys},
        "c_files": [], "file_cache": {}, "decompiled_dir": decompiled,
        "output_dir": tmp_path / "out", "call_graph_data": {}, "extracted_names": {},
        "pcode_naming_candidates": [],
    })
    return ctx, br, decompiled


def _fake_iterations(monkeypatch, decompiled: Path, named_sets: list[set[str]]) -> None:
    """Her tur ``named_sets``'ten bir küme adlandırır; gerçek tur gibi zaman anahtarı yazar."""

    def fake_run_one_iteration(*, iter_index, stats, prev_named, **_kw):
        current = set(named_sets[iter_index])
        stats[f"timing_c_naming_iter{iter_index}"] = 0.1
        return IterOutcome(
            iter_index=iter_index, iter_duration=0.01, current_named_set=current,
            newly_named=current - prev_named,
            new_iter_stats={"iteration": iter_index + 1}, decompiled_dir=decompiled,
        )

    monkeypatch.setattr(_fl, "run_one_iteration", fake_run_one_iteration)


class TestFeedbackLoopSayaclari:
    def test_yeni_ad_kalmayinca_durur(self, loop_ctx, monkeypatch) -> None:
        ctx, _br, decompiled = loop_ctx
        _fake_iterations(monkeypatch, decompiled, [{"a"}, {"a", "b"}, {"a", "b"}, {"x"}, {"y"}])
        out = FeedbackLoopStep().run(ctx)
        assert ctx.stats["pipeline_iterations_run"] == 3
        assert len(ctx.stats["pipeline_iteration_details"]) == 3
        assert len([k for k in ctx.stats if k.startswith("timing_c_naming_iter")]) == 3
        assert out["convergence_reason"] == "no_new_names"

    def test_sinira_ulasinca_max_iter(self, loop_ctx, monkeypatch) -> None:
        ctx, br, decompiled = loop_ctx
        br.pipeline_iterations = 2
        _fake_iterations(monkeypatch, decompiled, [{"a"}, {"a", "b"}])
        out = FeedbackLoopStep().run(ctx)
        assert ctx.stats["pipeline_iterations_run"] == 2
        assert out["convergence_reason"] == "max_iter"


# ---------------------------------------------------------------------------
# 3. İthal sayısı: lief'in ithal listesi -> static imports_found -> summary.total_imports
# ---------------------------------------------------------------------------


class _FakeFunction:
    def __init__(self, name: str) -> None:
        self.name = name


def _fake_lief(monkeypatch, binary: Any) -> None:
    import sys
    import types

    fake = types.ModuleType("lief")
    fake.parse = lambda _p: binary  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "lief", fake)


class _BinaryWithImports:
    format = "ELF"
    segments: list = []
    sections: list = []
    libraries = ["libc.so.6"]
    imported_functions = [_FakeFunction("memcpy"), _FakeFunction("strlen"), _FakeFunction("exit")]


class _BinaryImportsBroken:
    format = "ELF"
    segments: list = []
    sections: list = []
    libraries: list = []

    @property
    def imported_functions(self):
        raise RuntimeError("bozuk ithal tablosu")


class TestRunLiefIthal:
    def test_ithal_adlari_doner(self, monkeypatch, sample_macho_file, config) -> None:
        _fake_lief(monkeypatch, _BinaryWithImports())
        result = MachOAnalyzer(config)._run_lief(sample_macho_file)
        assert result["imported_functions"] == ["memcpy", "strlen", "exit"]

    def test_ithal_okunamazsa_anahtar_yok_ama_sonuc_doner(
        self, monkeypatch, sample_macho_file, config,
    ) -> None:
        _fake_lief(monkeypatch, _BinaryImportsBroken())
        result = MachOAnalyzer(config)._run_lief(sample_macho_file)
        assert result is not None
        assert "imported_functions" not in result
        assert result["format"] == "ELF"


def _analyze_static(monkeypatch, tmp_path, sample_macho_file, config, lief_data):
    _tm.TestAnalyzeStatic()._patch_pipeline(monkeypatch, ghidra_result=None)
    monkeypatch.setattr(MachOAnalyzer, "_run_lief", lambda self, p: lief_data, raising=True)
    ws = _tm._make_workspace(tmp_path)
    target = _tm._make_target(sample_macho_file, TargetType.ELF_BINARY)
    return MachOAnalyzer(config).analyze_static(target, ws)


_LIEF_BASE = {"format": "ELF", "header": {}, "segments": [], "sections": [], "libraries": []}


class TestStaticImportsFound:
    def test_ithal_sayisi_listenin_uzunlugu(
        self, monkeypatch, tmp_path, sample_macho_file, config,
    ) -> None:
        lief_data = dict(_LIEF_BASE, imported_functions=["memcpy", "strlen", "exit"])
        result = _analyze_static(monkeypatch, tmp_path, sample_macho_file, config, lief_data)
        assert result.stats["imports_found"] == 3

    def test_bos_liste_gercek_sifir(
        self, monkeypatch, tmp_path, sample_macho_file, config,
    ) -> None:
        """İthal listesi okundu ve boşsa (statik bağlı ikili) sayı gerçekten 0'dır."""
        lief_data = dict(_LIEF_BASE, imported_functions=[])
        result = _analyze_static(monkeypatch, tmp_path, sample_macho_file, config, lief_data)
        assert result.stats["imports_found"] == 0

    @pytest.mark.parametrize("lief_data", [dict(_LIEF_BASE), None])
    def test_liste_yoksa_sayi_yazilmaz(
        self, monkeypatch, tmp_path, sample_macho_file, config, lief_data,
    ) -> None:
        result = _analyze_static(monkeypatch, tmp_path, sample_macho_file, config, lief_data)
        assert "imports_found" not in result.stats


def _report_summary(tmp_path: Path, static_stats: dict) -> dict:
    """``reports/report.json`` yazılır ve denetimin okuduğu ``summary`` geri okunur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ikili")
    ws.create()
    result = PipelineResult(target_name="ikili", target_hash="0" * 64, workspace_path=ws.path)
    result.add_stage_result(StageResult(
        stage_name="static", success=True, duration_seconds=1.0, stats=static_stats,
    ))
    path = JSONReporter().generate(result, ws)
    return json.loads(path.read_text(encoding="utf-8"))["summary"]


class TestReportTotalImports:
    def test_rapor_imports_found_yazar(self, tmp_path) -> None:
        summary = _report_summary(tmp_path, {"ghidra_function_count": 250, "imports_found": 63})
        assert summary["total_imports"] == 63

    def test_gercek_sifir_korunur(self, tmp_path) -> None:
        summary = _report_summary(tmp_path, {"imports_found": 0})
        assert summary["total_imports"] == 0

    def test_bilinmiyorsa_sifir_degil(self, tmp_path) -> None:
        summary = _report_summary(tmp_path, {"ghidra_function_count": 250})
        assert summary["total_imports"] == "N/A"
