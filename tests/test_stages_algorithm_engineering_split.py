"""stages.py ``_run_algorithm_engineering`` Dalga 6A split parity testi.

v1.11.0 Dalga 6A: ``_run_algorithm_engineering`` metodu (382 satir, CC=73)
4 alt-adima bolundu:

1. ``_run_parallel_analysis`` -- 3 worker paralel algo ID + binary name +
   engineering analysis; raw dict sonuclar dondurur.
2. ``_merge_analysis_results`` -- paralel dict sonuclarini rc'ye aktarir
   (rc.algo_result, rc.eng_result, rc.extracted_names).
3. ``_calibrate_and_clamp`` -- confidence calibration + match budget clamp.
4. ``_apply_capa_naming`` -- byte pattern + CAPA capability merge.

**Davranis degismedi kurali**: hic bir adim kendi basina yeni bir stats
anahtari kaldirmaz / ek artifact'i kacirmaz; monolitik ``_run_algorithm_
engineering`` cagirisi (alt adimlarin kompozisyonu) mevcut parity testi
``test_run_algorithm_engineering_parity`` ile bitisik gecer.

Bu dosya split'in *yapi dogrulugu*na odaklanir:

- 4 metot da ``ReconstructionStage`` uzerinde callable.
- Her adim izole (mock rc ile) cagrilabilir ve beklenen alanlari doldurur.
- Tum feature flag'leri kapaliyken her adim sessiz/idempotent sonlanir.
- Adimlar arasi veri akisi: parallel_result dict -> rc.algo_result, vb.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.reconstruction_context import ReconstructionContext


# ---------------------------------------------------------------------------
# Ortak yardimcilar
# ---------------------------------------------------------------------------


def _make_mock_context(tmp_path: Path) -> MagicMock:
    """Hafif mock PipelineContext -- tum heavy feature flag'leri kapali."""
    ctx = MagicMock()
    cr = ctx.config.binary_reconstruction
    cr.enable_algorithm_id = False
    cr.enable_binary_name_extraction = False
    cr.enable_engineering_analysis = False
    cr.enable_capa = False
    cr.max_algo_matches = 0

    # workspace mock'u save_json/load_json cagirirsa path dondursun
    def _fake_save_json(*_args, **_kwargs):
        return tmp_path / "fake.json"

    ctx.workspace.save_json.side_effect = _fake_save_json
    ctx.workspace.load_json.side_effect = FileNotFoundError("mock")
    ctx.report_progress.return_value = None
    return ctx


def _make_rc_with_ph1(tmp_path: Path) -> ReconstructionContext:
    """``rc.ph1_artifacts`` ve ``rc.file_cache`` doldurulmus bir rc."""
    decompiled_dir = tmp_path / "decompiled"
    decompiled_dir.mkdir()
    c_file = decompiled_dir / "FUN_001.c"
    c_file.write_text("void FUN_001(void){}", encoding="utf-8")

    rc = ReconstructionContext(start=0.0, stage_name="reconstruction")
    rc.ph1_artifacts = {
        "decompiled_dir": decompiled_dir,
        "functions_json_path": tmp_path / "functions.json",
        "strings_json_path": tmp_path / "strings.json",
        "call_graph_json_path": tmp_path / "call_graph.json",
        "c_files": [c_file],
    }
    rc.file_cache = {}
    rc.byte_pattern_names = {}
    return rc


# ---------------------------------------------------------------------------
# 1. Metot mevcudiyeti
# ---------------------------------------------------------------------------


def test_dalga_6a_methods_exist() -> None:
    """4 yeni metot (+ eski top-level) ReconstructionStage uzerinde var."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    for name in (
        "_run_algorithm_engineering",
        "_run_parallel_analysis",
        "_merge_analysis_results",
        "_calibrate_and_clamp",
        "_apply_capa_naming",
    ):
        assert callable(getattr(stage, name, None)), f"Metot eksik: {name}"


# ---------------------------------------------------------------------------
# 2. _run_parallel_analysis -- tum flag'ler kapali
# ---------------------------------------------------------------------------


def test_run_parallel_analysis_all_skipped(tmp_path: Path) -> None:
    """Uc is de disabled iken dict skipped=True donmeli; timing yine set."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    result = stage._run_parallel_analysis(ctx, rc)

    # Dict sekli
    assert set(result.keys()) == {"algo_dict", "name_dict", "eng_dict"}
    for key in ("algo_dict", "name_dict", "eng_dict"):
        d = result[key]
        assert isinstance(d, dict)
        assert d.get("skipped") is True
        assert d.get("success") is False

    # Timing stat paralel bolumden set edildi
    assert "timing_algo_name_eng_parallel" in rc.stats

    # rc.algo_result / eng_result *henuz* dokunulmamis (merge'de atanir)
    assert rc.algo_result is None
    assert rc.eng_result is None


# ---------------------------------------------------------------------------
# 3. _merge_analysis_results -- skipped dict'leri sessizce gecmeli
# ---------------------------------------------------------------------------


def test_merge_analysis_results_all_skipped(tmp_path: Path) -> None:
    """Skipped dict'ler rc'ye None/bos deger yazmali, errors'e yazmamali."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    parallel_result = {
        "algo_dict": {"success": False, "skipped": True},
        "name_dict": {"success": False, "skipped": True},
        "eng_dict": {"success": False, "skipped": True},
    }

    stage._merge_analysis_results(ctx, rc, parallel_result)

    assert rc.algo_result is None
    assert rc.eng_result is None
    assert rc.extracted_names == {}
    # Skipped -> errors'e hata eklenmemeli
    assert rc.errors == []


def test_merge_analysis_results_error_dicts_append_errors(tmp_path: Path) -> None:
    """Error'lu dict'ler rc.errors listesine mesaj eklemeli (skipped degilse)."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    parallel_result = {
        "algo_dict": {"success": False, "error": "Algorithm ID hatasi: test"},
        "name_dict": {"success": False, "skipped": True},
        "eng_dict": {"success": False, "error": "Engineering hatasi: test"},
    }

    stage._merge_analysis_results(ctx, rc, parallel_result)

    assert len(rc.errors) == 2
    assert any("Algorithm ID" in e for e in rc.errors)
    assert any("Engineering" in e for e in rc.errors)


def test_merge_analysis_results_success_stats_artifacts(tmp_path: Path) -> None:
    """Success dict stats/artifacts rc'ye merge edilmeli."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    fake_path = tmp_path / "binary_names.json"
    parallel_result = {
        "algo_dict": {"success": False, "skipped": True},
        "name_dict": {
            "success": True,
            "result": {"FUN_001": "parse_header"},
            "stats": {"binary_names_extracted": 1},
            "artifacts": {"binary_names": fake_path},
        },
        "eng_dict": {"success": False, "skipped": True},
    }

    stage._merge_analysis_results(ctx, rc, parallel_result)

    assert rc.extracted_names == {"FUN_001": "parse_header"}
    assert rc.stats.get("binary_names_extracted") == 1
    assert rc.artifacts.get("binary_names") == fake_path


# ---------------------------------------------------------------------------
# 4. _calibrate_and_clamp -- eng_result None iken sessiz gecer
# ---------------------------------------------------------------------------


def test_calibrate_and_clamp_no_eng_result(tmp_path: Path) -> None:
    """eng_result None iken calibration atlar, timing yine set edilir."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    # rc.algo_result / eng_result default None -- merge'siz dogrudan
    # calibrate_and_clamp cagrisi sessiz gecmeli.

    stage._calibrate_and_clamp(ctx, rc)

    assert rc.calibrated_matches is None
    assert "timing_confidence_calibration" in rc.stats
    # merge dosyasi yazilmamali
    assert "algorithms_merged" not in rc.artifacts
    # Match budget kapali (max=0) -- clamp tetiklenmez
    assert "match_budget_original" not in rc.stats


# ---------------------------------------------------------------------------
# 5. _apply_capa_naming -- CAPA kapali + byte patterns bos
# ---------------------------------------------------------------------------


def test_apply_capa_naming_disabled(tmp_path: Path) -> None:
    """enable_capa=False ve byte_pattern_names bos iken sessiz gecer."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    # extracted_names'i once merge_analysis_results doldurur; burada
    # dogrudan atamak merge ciktisini taklit eder.
    rc.extracted_names = {}

    stage._apply_capa_naming(ctx, rc)

    assert rc.capa_capabilities == {}
    assert rc.extracted_names == {}
    assert "timing_capa_naming" in rc.stats


def test_apply_capa_naming_byte_pattern_merge(tmp_path: Path) -> None:
    """Byte pattern names mevcut extracted_names'i EZMEZ, yeni isimleri ekler."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    # binary_name_extractor zaten FUN_001'e isim vermis:
    rc.extracted_names = {"FUN_001": "parse_header"}
    # byte pattern FUN_001'i ezmeye calisiyor (redzen), FUN_002'ye yeni isim:
    rc.byte_pattern_names = {
        "FUN_001": "byte_pattern_wrong",  # mevcut oldugu icin MERGE etmez
        "FUN_002": "aes_encrypt",
    }

    stage._apply_capa_naming(ctx, rc)

    # FUN_001 korundu, FUN_002 eklendi
    assert rc.extracted_names["FUN_001"] == "parse_header"
    assert rc.extracted_names["FUN_002"] == "aes_encrypt"


# ---------------------------------------------------------------------------
# 6. Tum pipeline -- 4 adim kompozisyonu (top-level metot)
# ---------------------------------------------------------------------------


def test_full_pipeline_all_disabled(tmp_path: Path) -> None:
    """Tum 4 adim arkaya calisirken davranis monolitik halle ayni.

    Mevcut ``test_run_algorithm_engineering_parity`` ile tam ayni
    beklentileri dogrular ama mock rc ile hizli.
    """
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    stage._run_algorithm_engineering(ctx, rc)

    # Monolitik halle bit-identik alan beklentileri:
    assert rc.algo_result is None
    assert rc.eng_result is None
    assert rc.extracted_names == {}
    assert rc.calibrated_matches is None
    assert rc.capa_capabilities == {}
    # 3 timing stat'i yerinde
    assert "timing_algo_name_eng_parallel" in rc.stats
    assert "timing_confidence_calibration" in rc.stats
    assert "timing_capa_naming" in rc.stats


# ---------------------------------------------------------------------------
# 7. Top-level metot govdesi kucultuldu mu?
# ---------------------------------------------------------------------------


def test_run_algorithm_engineering_is_thin_coordinator() -> None:
    """``_run_algorithm_engineering`` artik 4 cagri + docstring'den ibaret.

    Gercek calismayi delege ediyor; 40 satirin altinda olmali
    (orjinal 382 -> Dalga 6A hedef ~20).
    """
    import inspect

    from karadul.stages import ReconstructionStage

    src = inspect.getsource(ReconstructionStage._run_algorithm_engineering)
    lines = [l for l in src.splitlines() if l.strip() and not l.strip().startswith("#")]
    assert len(lines) < 40, (
        f"_run_algorithm_engineering hala kalabalik: {len(lines)} satir "
        "(hedef <40). Alt-adima tasinmayan kod var mi?"
    )

    # 4 alt cagri mevcut olmali (body icinde self._X cagrilari sayilir).
    assert "_run_parallel_analysis" in src
    assert "_merge_analysis_results" in src
    assert "_calibrate_and_clamp" in src
    assert "_apply_capa_naming" in src
