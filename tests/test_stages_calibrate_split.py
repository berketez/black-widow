"""stages.py ``_calibrate_and_clamp`` Dalga 7 split parity testi.

v1.11.0 Dalga 7: ``_calibrate_and_clamp`` metodu (Dalga 6A'dan miras,
143 satir, CC=48) -> uc alt-adima bolundu:

1. ``_run_confidence_calibration`` -- engineering sonuclarini
   ``ConfidenceCalibrator``'dan gecir, ``rc.calibrated_matches``
   doldur ve ``timing_confidence_calibration`` stat'ini yaz.
2. ``_write_merged_algorithms`` -- crypto + engineering +
   (varsa) kalibre matches merge JSON artifact'i uret.
3. ``_apply_match_budget`` -- ``max_algo_matches`` > 0 ve toplam
   match sayisi budget'i asiyorsa en yuksek confidence'lari tut.

**Davranis degismedi kurali**: stats anahtarlari (``timing_confidence_
calibration``, ``match_budget_original``, ``match_budget_kept``),
artifact anahtarlari (``engineering_calibrated``, ``algorithms_merged``),
log satirlari ve cagri sirasi monolitik halle bit-identik.

Bu dosya split'in *yapi dogrulugu*na odaklanir:

- 3 alt metot ``ReconstructionStage`` uzerinde callable.
- Coordinator ``_calibrate_and_clamp`` sadece uc alt cagri + docstring.
- Alt adimlar izole (mock rc ile) cagrilabilir; eng_result/algo_result
  None iken sessiz gecerler; timing stat yine de yazilir.
- Kalibre matches sonrasi merge + budget adimlari rc uzerinden okur.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.reconstruction_context import ReconstructionContext


# ---------------------------------------------------------------------------
# Ortak yardimcilar
# ---------------------------------------------------------------------------


def _make_mock_context(tmp_path: Path, *, max_algo_matches: int = 0) -> MagicMock:
    """Hafif mock PipelineContext -- match budget default kapali."""
    ctx = MagicMock()
    cr = ctx.config.binary_reconstruction
    cr.max_algo_matches = max_algo_matches

    # workspace.save_json cagirisi path dondursun (artifact atamasi icin)
    def _fake_save_json(subdir, name, _payload):
        return tmp_path / f"{subdir}_{name}.json"

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
    return rc


def _make_mock_algorithm(name: str, confidence: float) -> SimpleNamespace:
    """Tek bir match mock'u -- confidence + to_dict + name."""
    return SimpleNamespace(
        name=name,
        confidence=confidence,
        to_dict=lambda n=name, c=confidence: {"name": n, "confidence": c},
    )


def _make_mock_result(algorithms: list, *, success: bool = True) -> SimpleNamespace:
    """algo_result / eng_result mock'u -- ``algorithms``, ``total_detected``,
    ``success`` alanlarina sahip."""
    return SimpleNamespace(
        algorithms=algorithms,
        total_detected=len(algorithms),
        success=success,
    )


# ---------------------------------------------------------------------------
# 1. Metot mevcudiyeti -- 3 yeni alt metot + coordinator
# ---------------------------------------------------------------------------


def test_dalga_7_methods_exist() -> None:
    """Coordinator + 3 alt metot ReconstructionStage uzerinde var."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    for name in (
        "_calibrate_and_clamp",
        "_run_confidence_calibration",
        "_write_merged_algorithms",
        "_apply_match_budget",
    ):
        assert callable(getattr(stage, name, None)), f"Metot eksik: {name}"


# ---------------------------------------------------------------------------
# 2. Coordinator _calibrate_and_clamp ince wrapper
# ---------------------------------------------------------------------------


def test_calibrate_and_clamp_is_thin_coordinator() -> None:
    """``_calibrate_and_clamp`` artik sadece docstring + 3 alt cagri.

    Orijinal 143 satir / CC=48 -> Dalga 7 hedef ~5 fonksiyonel satir.
    """
    import inspect

    from karadul.stages import ReconstructionStage

    src = inspect.getsource(ReconstructionStage._calibrate_and_clamp)
    code_lines = [
        line for line in src.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    # Signature + docstring + 3 call satiri: 25'in altinda olmali
    # (orijinal 143 satir -> docstring bile olsa coordinator < 25)
    assert len(code_lines) < 25, (
        f"_calibrate_and_clamp hala kalabalik: {len(code_lines)} satir "
        "(hedef <25). Alt-adima tasinmayan kod var mi?"
    )

    # Uc alt cagrinin hepsi govdede yer almali
    assert "_run_confidence_calibration" in src
    assert "_write_merged_algorithms" in src
    assert "_apply_match_budget" in src


def test_calibrate_and_clamp_calls_substeps_in_order() -> None:
    """Coordinator 3 alt cagriyi DOGRU SIRADA yapiyor."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = MagicMock()
    rc = MagicMock()

    call_order: list[str] = []
    stage._run_confidence_calibration = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda c, r: call_order.append("calibrate"),
    )
    stage._write_merged_algorithms = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda c, r: call_order.append("merge"),
    )
    stage._apply_match_budget = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda c, r: call_order.append("budget"),
    )

    stage._calibrate_and_clamp(ctx, rc)

    assert call_order == ["calibrate", "merge", "budget"], (
        f"Sira bozuk: {call_order} (bekleniyor: calibrate -> merge -> budget)"
    )


# ---------------------------------------------------------------------------
# 3. _run_confidence_calibration -- eng_result None iken sessiz
# ---------------------------------------------------------------------------


def test_run_confidence_calibration_no_eng_result(tmp_path: Path) -> None:
    """``eng_result`` None iken calibrator cagrilmaz; timing yine set, rc.calibrated_matches None."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    # rc.eng_result default None

    stage._run_confidence_calibration(ctx, rc)

    assert rc.calibrated_matches is None
    assert "timing_confidence_calibration" in rc.stats
    # eng_result yok -> artifact yazilmamali
    assert "engineering_calibrated" not in rc.artifacts


def test_run_confidence_calibration_eng_result_empty(tmp_path: Path) -> None:
    """``eng_result.algorithms`` bos iken calibration atlaniyor."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    rc.eng_result = _make_mock_result([])

    stage._run_confidence_calibration(ctx, rc)

    assert rc.calibrated_matches is None
    assert "timing_confidence_calibration" in rc.stats
    assert "engineering_calibrated" not in rc.artifacts


# ---------------------------------------------------------------------------
# 4. _write_merged_algorithms -- eng_result yok iken artifact yazmaz
# ---------------------------------------------------------------------------


def test_write_merged_algorithms_no_eng_result(tmp_path: Path) -> None:
    """``eng_result`` None -> merge dosyasi yazilmaz."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    # rc.eng_result / algo_result / calibrated_matches hepsi None

    stage._write_merged_algorithms(ctx, rc)

    assert "algorithms_merged" not in rc.artifacts
    # save_json cagirilmamis olmali
    ctx.workspace.save_json.assert_not_called()


def test_write_merged_algorithms_writes_artifact(tmp_path: Path) -> None:
    """``eng_result`` basarili -> ``algorithms_merged`` artifact'i yazilir."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    rc.algo_result = _make_mock_result(
        [_make_mock_algorithm("aes", 0.9)],
    )
    rc.eng_result = _make_mock_result(
        [_make_mock_algorithm("quicksort", 0.7)],
    )
    rc.calibrated_matches = None

    stage._write_merged_algorithms(ctx, rc)

    assert "algorithms_merged" in rc.artifacts
    # save_json cagrisi 1 kez (merged)
    assert ctx.workspace.save_json.call_count == 1
    call_args = ctx.workspace.save_json.call_args
    # Pozisyonel argumanlar: (subdir, name, payload)
    assert call_args.args[1] == "algorithms_merged"
    payload = call_args.args[2]
    assert payload["total"] == 2
    assert len(payload["crypto_algorithms"]) == 1
    assert len(payload["engineering_algorithms"]) == 1
    # calibrated yoksa anahtar yazilmamali
    assert "calibrated" not in payload


def test_write_merged_algorithms_includes_calibrated(tmp_path: Path) -> None:
    """Kalibre matches varsa ``calibrated`` anahtari merge JSON'a eklenir."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)
    rc.algo_result = None
    rc.eng_result = _make_mock_result(
        [_make_mock_algorithm("quicksort", 0.7)],
    )
    calibrated = SimpleNamespace(to_dict=lambda: {"name": "quicksort_cal", "conf": 0.85})
    rc.calibrated_matches = [calibrated]

    stage._write_merged_algorithms(ctx, rc)

    assert "algorithms_merged" in rc.artifacts
    payload = ctx.workspace.save_json.call_args.args[2]
    assert "calibrated" in payload
    assert len(payload["calibrated"]) == 1


# ---------------------------------------------------------------------------
# 5. _apply_match_budget -- budget 0 / asilmamis / asilmis
# ---------------------------------------------------------------------------


def test_apply_match_budget_disabled(tmp_path: Path) -> None:
    """``max_algo_matches = 0`` -> clamp tetiklenmez."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path, max_algo_matches=0)
    rc = _make_rc_with_ph1(tmp_path)
    algos = [_make_mock_algorithm(f"a{i}", 0.5 + i * 0.01) for i in range(5)]
    rc.algo_result = _make_mock_result(algos)
    rc.eng_result = None

    stage._apply_match_budget(ctx, rc)

    # Clamp edilmedi -- liste hala 5
    assert len(rc.algo_result.algorithms) == 5
    assert "match_budget_original" not in rc.stats
    assert "match_budget_kept" not in rc.stats


def test_apply_match_budget_below_threshold(tmp_path: Path) -> None:
    """Toplam match budget altinda -> clamp tetiklenmez."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path, max_algo_matches=10)
    rc = _make_rc_with_ph1(tmp_path)
    rc.algo_result = _make_mock_result(
        [_make_mock_algorithm("a", 0.9), _make_mock_algorithm("b", 0.8)],
    )
    rc.eng_result = _make_mock_result(
        [_make_mock_algorithm("c", 0.7)],
    )

    stage._apply_match_budget(ctx, rc)

    # Toplam 3 < 10 -> clamp yok
    assert len(rc.algo_result.algorithms) == 2
    assert len(rc.eng_result.algorithms) == 1
    assert "match_budget_original" not in rc.stats


def test_apply_match_budget_clamps_by_confidence(tmp_path: Path) -> None:
    """Toplam match budget'i asinca en yuksek confidence'lar tutulur."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path, max_algo_matches=3)
    rc = _make_rc_with_ph1(tmp_path)
    # 5 crypto + 3 eng = 8 total, budget 3
    rc.algo_result = _make_mock_result([
        _make_mock_algorithm("crypto1", 0.95),  # En yuksek
        _make_mock_algorithm("crypto2", 0.40),
        _make_mock_algorithm("crypto3", 0.30),
        _make_mock_algorithm("crypto4", 0.20),
        _make_mock_algorithm("crypto5", 0.10),
    ])
    rc.eng_result = _make_mock_result([
        _make_mock_algorithm("eng1", 0.90),  # 2.
        _make_mock_algorithm("eng2", 0.80),  # 3.
        _make_mock_algorithm("eng3", 0.05),
    ])

    stage._apply_match_budget(ctx, rc)

    # Toplam kesim: crypto1 (0.95), eng1 (0.90), eng2 (0.80)
    assert len(rc.algo_result.algorithms) == 1
    assert rc.algo_result.algorithms[0].name == "crypto1"
    assert len(rc.eng_result.algorithms) == 2
    kept_eng_names = {a.name for a in rc.eng_result.algorithms}
    assert kept_eng_names == {"eng1", "eng2"}

    # Stats yazildi
    assert rc.stats.get("match_budget_original") == 8
    assert rc.stats.get("match_budget_kept") == 3


# ---------------------------------------------------------------------------
# 6. Tam pipeline -- 3 adim kompozisyonu davranisi
# ---------------------------------------------------------------------------


def test_full_calibrate_and_clamp_no_data(tmp_path: Path) -> None:
    """``algo_result`` = ``eng_result`` = None iken uc adim da sessiz gecer.

    Timing stat var, artifact/stats kalintisi yok, errors bos.
    """
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path)
    rc = _make_rc_with_ph1(tmp_path)

    stage._calibrate_and_clamp(ctx, rc)

    assert rc.calibrated_matches is None
    assert "timing_confidence_calibration" in rc.stats
    assert "algorithms_merged" not in rc.artifacts
    assert "engineering_calibrated" not in rc.artifacts
    assert "match_budget_original" not in rc.stats
    assert rc.errors == []


def test_full_calibrate_and_clamp_with_matches_over_budget(tmp_path: Path) -> None:
    """eng_result + algo_result varken merge yazilir ve budget asilinca clamp olur."""
    from karadul.stages import ReconstructionStage

    stage = ReconstructionStage()
    ctx = _make_mock_context(tmp_path, max_algo_matches=2)
    rc = _make_rc_with_ph1(tmp_path)
    rc.algo_result = _make_mock_result([
        _make_mock_algorithm("c1", 0.95),
        _make_mock_algorithm("c2", 0.10),
    ])
    rc.eng_result = _make_mock_result([
        _make_mock_algorithm("e1", 0.80),
        _make_mock_algorithm("e2", 0.20),
    ])

    stage._calibrate_and_clamp(ctx, rc)

    # Merge artifact'i yazildi (eng_result.algorithms dolu)
    assert "algorithms_merged" in rc.artifacts
    # Budget: 4 > 2 -> c1 (0.95) + e1 (0.80) tutulur
    assert rc.stats.get("match_budget_original") == 4
    assert rc.stats.get("match_budget_kept") == 2
    assert [a.name for a in rc.algo_result.algorithms] == ["c1"]
    assert [a.name for a in rc.eng_result.algorithms] == ["e1"]


# ---------------------------------------------------------------------------
# 7. Module-level helper sanity
# ---------------------------------------------------------------------------


def test_match_budget_total_helper() -> None:
    """``_match_budget_total`` iki None / None-basarisiz / dolu durumu."""
    from karadul.stages import _match_budget_total

    assert _match_budget_total(None, None) == 0

    failed = SimpleNamespace(algorithms=[1, 2, 3], success=False)
    ok_single = SimpleNamespace(algorithms=[1, 2], success=True)
    assert _match_budget_total(failed, None) == 0
    assert _match_budget_total(ok_single, None) == 2
    assert _match_budget_total(ok_single, ok_single) == 4


def test_match_budget_sort_key_helper() -> None:
    """``_match_budget_sort_key`` attr / dict / fallback durumlari."""
    from karadul.stages import _match_budget_sort_key

    with_attr = ("crypto", SimpleNamespace(confidence=0.73))
    as_dict = ("eng", {"confidence": 0.42})
    as_dict_missing = ("crypto", {"name": "x"})
    as_other = ("eng", 12345)

    assert _match_budget_sort_key(with_attr) == pytest.approx(0.73)
    assert _match_budget_sort_key(as_dict) == pytest.approx(0.42)
    assert _match_budget_sort_key(as_dict_missing) == pytest.approx(0.0)
    assert _match_budget_sort_key(as_other) == pytest.approx(0.0)


def test_collect_tagged_matches_helper() -> None:
    """``_collect_tagged_matches`` tag sirasi: crypto once, sonra eng."""
    from karadul.stages import _collect_tagged_matches

    a = SimpleNamespace(algorithms=["x", "y"], success=True)
    e = SimpleNamespace(algorithms=["z"], success=True)

    tagged = _collect_tagged_matches(a, e)
    assert tagged == [("crypto", "x"), ("crypto", "y"), ("eng", "z")]

    # Basarisiz result atlaniyor
    failed = SimpleNamespace(algorithms=["w"], success=False)
    assert _collect_tagged_matches(failed, e) == [("eng", "z")]
    assert _collect_tagged_matches(None, None) == []
