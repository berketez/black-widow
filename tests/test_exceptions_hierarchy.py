"""Karadul exception hiyerarsisi -- B23 aktivasyonu testleri.

Bu modul, ``karadul.exceptions`` modulundeki sinif iliskilerini ve
gercek kullanim noktalarinda firlatilan exception'larin hem
``KaradulError`` hem de eski (``ValueError`` / ``RuntimeError``)
yakalama yollariyla yakalanabildigini dogrular.

Test seti:

1. Hiyerarsi: tum ozel sinif ``KaradulError`` subclass'i mi?
2. Geriye donuk uyumluluk: ``AnalysisError`` -> ``RuntimeError``,
   ``SignatureDBError`` / ``ConfigError`` -> ``ValueError``.
3. ``try: ... except KaradulError`` ile herhangi bir alt sinif yakalanir mi?
4. Gercek kullanim 1: ``BinaryNinjaAdapter.extract_*`` modul yokken
   ``AnalysisError`` firlatir (KaradulError + RuntimeError).
5. Gercek kullanim 2: ``SignatureDB.add_byte_signature`` bos isimle
   ``SignatureDBError`` firlatir (KaradulError + ValueError).
6. Gercek kullanim 3: ``TRexAdapter.analyze`` lifted yoksa
   ``AnalysisError`` firlatir.
7. ``raise ... from exc`` zinciri korunuyor mu (chained exception).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.exceptions import (
    AnalysisError,
    CircuitBreakerOpenError,
    ConfigError,
    DecompilationError,
    KaradulError,
    PipelineStageError,
    ReconstructionError,
    SecurityError,
    SignatureDBError,
    WorkspaceError,
)


# ---------------------------------------------------------------------------
# 1) Hiyerarsi -- tum sinif ``KaradulError`` subclass'i
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cls",
    [
        AnalysisError,
        DecompilationError,
        ReconstructionError,
        SignatureDBError,
        PipelineStageError,
        ConfigError,
        WorkspaceError,
        SecurityError,
        CircuitBreakerOpenError,
    ],
)
def test_all_subclass_karadul_error(cls: type) -> None:
    """Her ozel exception KaradulError'dan turetilmis olmalidir."""
    assert issubclass(cls, KaradulError), (
        f"{cls.__name__} KaradulError subclass'i degil -- "
        f"kullanici 'except KaradulError' ile yakalayamaz"
    )


def test_decompilation_error_subclass_analysis_error() -> None:
    """DecompilationError, AnalysisError'in alt sinifi olmalidir."""
    assert issubclass(DecompilationError, AnalysisError)
    assert issubclass(DecompilationError, KaradulError)


# ---------------------------------------------------------------------------
# 2) Geriye donuk uyumluluk -- coklu kalitim
# ---------------------------------------------------------------------------


def test_analysis_error_is_runtime_error() -> None:
    """``AnalysisError`` aynı zamanda ``RuntimeError`` olmali.

    Adapter testleri ``pytest.raises(RuntimeError)`` ile yaziliyor;
    bu varsayim bozulursa eski tum testler kirilir.
    """
    assert issubclass(AnalysisError, RuntimeError)
    # PipelineStageError ve ReconstructionError de RuntimeError olmali
    assert issubclass(PipelineStageError, RuntimeError)
    assert issubclass(ReconstructionError, RuntimeError)


def test_signature_db_error_is_value_error() -> None:
    """``SignatureDBError`` ``ValueError`` subclass'i olmali.

    Eski ``add_byte_signature`` testleri ``pytest.raises(ValueError)``
    kullaniyor; bu varsayim bozulursa onlar kirilir.
    """
    assert issubclass(SignatureDBError, ValueError)
    assert issubclass(ConfigError, ValueError)


def test_workspace_error_is_os_error() -> None:
    """``WorkspaceError`` ``OSError`` subclass'i olmali."""
    assert issubclass(WorkspaceError, OSError)


# ---------------------------------------------------------------------------
# 3) ``except KaradulError`` ile yakalama
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        AnalysisError("a"),
        SignatureDBError("b"),
        PipelineStageError("c"),
        ConfigError("d"),
        DecompilationError("e"),
        ReconstructionError("f"),
        WorkspaceError("g"),
    ],
)
def test_catch_with_karadul_error(exc: KaradulError) -> None:
    """Tum Karadul exception'lari tek ``except KaradulError`` ile yakalanir."""
    try:
        raise exc
    except KaradulError as caught:
        assert caught is exc
    else:  # pragma: no cover
        pytest.fail("exception yakalanmadi")


def test_legacy_except_still_works() -> None:
    """Eski kod ``except RuntimeError`` / ``except ValueError`` yakalamaya devam edebilir."""
    try:
        raise AnalysisError("subprocess fail")
    except RuntimeError as caught:
        assert isinstance(caught, KaradulError)
        assert isinstance(caught, AnalysisError)

    try:
        raise SignatureDBError("bos isim")
    except ValueError as caught:
        assert isinstance(caught, KaradulError)
        assert isinstance(caught, SignatureDBError)


# ---------------------------------------------------------------------------
# 4) Gercek kullanim -- BinaryNinjaAdapter modul yokken
# ---------------------------------------------------------------------------


def test_binaryninja_adapter_raises_analysis_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``binaryninja`` modulu yokken extract_* AnalysisError firlatir."""
    from karadul.analyzers import binaryninja_adapter as bn_mod

    # Modul import simulasyonu: None dondur -> license required
    monkeypatch.setattr(
        bn_mod, "_try_import_binaryninja", lambda: None,
    )

    adapter = bn_mod.BinaryNinjaAdapter(Path("/nonexistent.bin"))

    # Yeni API ile yakalama
    with pytest.raises(AnalysisError, match="license required"):
        adapter.extract_functions()

    with pytest.raises(KaradulError):
        adapter.extract_types()

    # Eski API ile geriye donuk uyumluluk
    with pytest.raises(RuntimeError):
        adapter.extract_all()


# ---------------------------------------------------------------------------
# 5) Gercek kullanim -- SignatureDB validation
# ---------------------------------------------------------------------------


def test_signature_db_validation_raises_signature_db_error() -> None:
    """add_byte_signature bos isim ile SignatureDBError firlatir."""
    from karadul.analyzers.signature_db import FunctionSignature, SignatureDB

    db = SignatureDB()
    bad_sig = FunctionSignature(
        name="",
        library="test",
        byte_pattern=b"\x01\x02",
        byte_mask=b"\xff\xff",
    )

    # Yeni hiyerarsi
    with pytest.raises(SignatureDBError, match="sig.name bos olamaz"):
        db.add_byte_signature(bad_sig)

    # Eski test'ler hala calismali (ValueError yakalanir)
    with pytest.raises(ValueError):
        db.add_byte_signature(bad_sig)

    # KaradulError ile tek noktada yakalama
    with pytest.raises(KaradulError):
        db.add_byte_signature(bad_sig)


# ---------------------------------------------------------------------------
# 6) Gercek kullanim -- TRex .lifted yoksa
# ---------------------------------------------------------------------------


def test_trex_adapter_raises_analysis_error_for_missing_lifted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TRex binary VAR ama .lifted dosyasi yoksa AnalysisError firlatir."""
    from karadul.analyzers import trex_adapter as trex_mod

    # Sahte binary path -> _binary_path set
    fake_binary = tmp_path / "fake_trex"
    fake_binary.write_text("#!/bin/sh\nexit 0\n")
    fake_binary.chmod(0o755)

    adapter = trex_mod.TRexAdapter(binary_path=fake_binary)
    nonexistent_lifted = tmp_path / "missing.lifted"

    with pytest.raises(AnalysisError, match=r"\.lifted"):
        adapter.analyze(nonexistent_lifted)

    # Backward compat: RuntimeError ile de yakalanir
    with pytest.raises(RuntimeError):
        adapter.analyze(nonexistent_lifted)


# ---------------------------------------------------------------------------
# 7) Chained exception (``raise X from exc``) korumasi
# ---------------------------------------------------------------------------


def test_chained_exception_preserves_cause() -> None:
    """``raise AnalysisError(...) from exc`` ile root cause korunur."""
    original = ValueError("subprocess stdout JSON degil")
    try:
        try:
            raise original
        except ValueError as inner:
            raise AnalysisError("TypeForge parse fail") from inner
    except AnalysisError as caught:
        assert caught.__cause__ is original
        assert str(caught) == "TypeForge parse fail"
        assert isinstance(caught.__cause__, ValueError)


def test_pipeline_stage_error_wraps_runtime_error() -> None:
    """PipelineStageError'i RuntimeError kullanan kodtan yakalanabilir.

    Pipeline integration noktasinda step fail -> PipelineStageError
    sarmalamasi.  __cause__ zinciri ile root cause kayit altinda kalir.
    """
    original = RuntimeError("step crash")
    try:
        try:
            raise original
        except RuntimeError as inner:
            raise PipelineStageError("step 'analyze' failed") from inner
    except KaradulError as caught:
        assert caught.__cause__ is original
        assert isinstance(caught, PipelineStageError)
        assert isinstance(caught, RuntimeError)  # backward-compat


# ---------------------------------------------------------------------------
# 8) Hiyerarsi exhaustive -- __all__ tutarliligi
# ---------------------------------------------------------------------------


def test_exceptions_module_all_complete() -> None:
    """exceptions.py __all__ tum public sinif isimlerini icermeli."""
    from karadul import exceptions as exc_mod

    expected = {
        "KaradulError",
        "AnalysisError",
        "DecompilationError",
        "ReconstructionError",
        "SignatureDBError",
        "PipelineStageError",
        "ConfigError",
        "WorkspaceError",
        "SecurityError",
        "CircuitBreakerOpenError",
    }
    assert set(exc_mod.__all__) == expected, (
        f"__all__ eksik veya fazla: {set(exc_mod.__all__) ^ expected}"
    )
