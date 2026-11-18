"""P-S2 (2026-11-18): ``stages.py``'den onaylı ölü kod silme (K-3 A1).

Silinenler adım kipinde hiç çalışmıyordu: eski tek gövdeli Faz 1 yolu (``_load_binary`` ve
``_run_*`` metotları), sıfır turluk döngü (``_loop_iterations = 0``), ulaşılamaz
``raise NotImplementedError`` ve ``DeobfuscationStage``'in ``use_deep=False`` /
``_execute_legacy`` yolu. Kanıt ve ölçüm: ``docs/arge/2026-11-18_onarim/P-S2.md``.

Bu dosya iki şeyi kilitler:
1. Ölü kod geri gelmez (eski kodda KIRMIZI).
2. Tek kalan yol bozulmaz: ``use_step_registry=False`` hâlâ yüksek sesle uyarıp adım
   koşucusunun üç fazını koşar (eski kodda da yeşil; mutantla sınanır).
"""

from __future__ import annotations

import ast
import inspect
import logging
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import karadul.stages as stages_mod
from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.finalize import FinalizeStep
from karadul.stages import DeobfuscationStage, ReconstructionStage

_OLU_METOTLAR = (
    "_load_binary", "_run_signature_matching", "_run_byte_pattern_matching",
    "_run_anti_debug_and_packer", "_run_pcode_analysis", "_run_cfg_analysis",
    "_run_algorithm_engineering", "_run_parallel_analysis", "_merge_analysis_results",
    "_calibrate_and_clamp", "_run_confidence_calibration", "_write_merged_algorithms",
    "_apply_match_budget", "_apply_capa_naming",
)
_OLU_MODUL_YARDIMCILARI = ("_match_budget_total", "_collect_tagged_matches", "_match_budget_sort_key")


def _execute_binary_ast() -> ast.FunctionDef:
    kaynak = textwrap.dedent(inspect.getsource(ReconstructionStage._execute_binary))
    return ast.parse(kaynak).body[0]


class TestOluKodGeriGelmez:
    @pytest.mark.parametrize("ad", _OLU_METOTLAR)
    def test_eski_faz1_metotlari_yok(self, ad: str) -> None:
        assert not hasattr(ReconstructionStage, ad)

    @pytest.mark.parametrize("ad", _OLU_MODUL_YARDIMCILARI)
    def test_butce_yardimcilari_yok(self, ad: str) -> None:
        assert not hasattr(stages_mod, ad)

    def test_deobfuscation_legacy_yolu_yok(self) -> None:
        assert not hasattr(DeobfuscationStage, "_execute_legacy")
        with pytest.raises(TypeError):
            DeobfuscationStage(use_deep=False)  # type: ignore[call-arg]

    def test_execute_binary_dongu_ve_ulasilamaz_raise_icermez(self) -> None:
        fn = _execute_binary_ast()
        # aşama düzeyinde (gövdenin en üstünde) döngü yok: eski sıfır turluk döngü
        ust_dongu = [n for n in fn.body if isinstance(n, (ast.For, ast.While))]
        assert ust_dongu == [], [ast.unparse(n)[:80] for n in ust_dongu]
        assert not [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
        adlar = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        assert not adlar & {"_loop_iterations", "_pipeline_iter", "_max_iterations"}
        # Tek dal: ``_use_step_registry`` yalnız uyarı koşulunda okunur
        okunan = [n for n in ast.walk(fn) if isinstance(n, ast.Name)
                  and n.id == "_use_step_registry" and isinstance(n.ctx, ast.Load)]
        assert len(okunan) == 1


# ---------------------------------------------------------------------------
# Üç faz, sahte koşucuyla (Ghidra'sız). Düzen tests/test_rapor_sayaclari.py ile aynı.
# ---------------------------------------------------------------------------


class _Artifacts(dict):
    def __missing__(self, key: str):
        return None


def _uc_faz(
    tmp_path: Path, monkeypatch, config: Config, *,
    faz1_artifacts: dict | None = None, faz1_stats: dict | None = None,
    faz2_artifacts: dict | None = None, faz2_stats: dict | None = None,
) -> tuple[Any, list[list[str]]]:
    import karadul.pipeline.runner as runner_mod

    decompiled = tmp_path / "static" / "decompiled"
    decompiled.mkdir(parents=True)
    final_dir = tmp_path / "loop_final"
    final_dir.mkdir()
    kosulan: list[list[str]] = []

    class _FakeRunner:
        def __init__(self, steps):
            self.steps = list(steps)

        def run(self, context, seed_artifacts=None):
            kosulan.append(self.steps)
            if "feedback_loop" in self.steps:
                return SimpleNamespace(
                    artifacts={
                        "naming_result": SimpleNamespace(success=True, errors=[]),
                        "computation_result": None, "updated_algo_result": None,
                        "updated_eng_result": None, "final_decompiled_dir": final_dir,
                        **(faz2_artifacts or {}),
                    },
                    stats={"pipeline_iterations_run": 1, **(faz2_stats or {})},
                    errors=[], stage_artifacts={},
                )
            if "finalize" in self.steps:
                ctx = StepContext(pipeline_context=context)
                ctx._write_artifacts(dict(seed_artifacts))
                ctx.produce_artifact("project_dir", tmp_path / "proje")
                return SimpleNamespace(artifacts=FinalizeStep().run(ctx))
            return SimpleNamespace(
                artifacts=_Artifacts(decompiled_dir=decompiled, extracted_names={},
                                     **(faz1_artifacts or {})),
                stats=dict(faz1_stats or {}), errors=[], stage_artifacts={},
            )

    monkeypatch.setattr(runner_mod, "PipelineRunner", _FakeRunner)

    def stage_dir(stage: str) -> Path:
        d = tmp_path / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    context = SimpleNamespace(
        target=SimpleNamespace(path=tmp_path / "ikili", file_hash=""),
        workspace=SimpleNamespace(get_stage_dir=stage_dir, path=tmp_path),
        config=config, metadata={},
    )
    sonuc = ReconstructionStage()._execute_binary(context, time.monotonic())
    return sonuc, kosulan


class TestTekYol:
    def test_step_registry_kapali_uyarir_ve_adim_yolunu_kosar(self, tmp_path, monkeypatch, caplog):
        cfg = Config()
        cfg.pipeline.use_step_registry = False
        with caplog.at_level(logging.WARNING, logger="karadul.stages"):
            sonuc, kosulan = _uc_faz(tmp_path, monkeypatch, cfg)
        assert any("use_step_registry=False" in r.getMessage() and r.levelno == logging.WARNING
                   for r in caplog.records)
        assert sonuc.success is True, sonuc.errors
        assert [("finalize" in s, "feedback_loop" in s) for s in kosulan] == [
            (False, False), (False, True), (True, False)]

    def test_step_registry_acik_uyarmaz(self, tmp_path, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="karadul.stages"):
            sonuc, kosulan = _uc_faz(tmp_path, monkeypatch, Config())
        assert not any("use_step_registry" in r.getMessage() for r in caplog.records)
        assert sonuc.success is True, sonuc.errors
        assert len(kosulan) == 3
