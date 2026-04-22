"""Karadul exception hierarchy testleri (Batch 5C-1)."""
from __future__ import annotations

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
)


class TestHierarchy:
    def test_karadul_error_is_exception(self) -> None:
        assert issubclass(KaradulError, Exception)

    def test_analysis_from_karadul(self) -> None:
        assert issubclass(AnalysisError, KaradulError)

    def test_decompilation_from_analysis(self) -> None:
        assert issubclass(DecompilationError, AnalysisError)
        assert issubclass(DecompilationError, KaradulError)

    def test_reconstruction_from_karadul(self) -> None:
        assert issubclass(ReconstructionError, KaradulError)

    def test_signaturedb_from_karadul(self) -> None:
        assert issubclass(SignatureDBError, KaradulError)

    def test_pipeline_stage_from_karadul(self) -> None:
        assert issubclass(PipelineStageError, KaradulError)

    def test_config_from_karadul(self) -> None:
        assert issubclass(ConfigError, KaradulError)

    def test_security_from_karadul(self) -> None:
        assert issubclass(SecurityError, KaradulError)

    def test_circuit_breaker_from_karadul(self) -> None:
        assert issubclass(CircuitBreakerOpenError, KaradulError)


class TestRaiseAndCatch:
    def test_raise_analysis_catch_karadul(self) -> None:
        with pytest.raises(KaradulError):
            raise AnalysisError("test")

    def test_raise_decompilation_catch_analysis(self) -> None:
        with pytest.raises(AnalysisError):
            raise DecompilationError("decompile failed")

    def test_raise_decompilation_catch_karadul(self) -> None:
        with pytest.raises(KaradulError):
            raise DecompilationError("decompile failed")

    def test_message_preserved(self) -> None:
        exc = SignatureDBError("db corrupted")
        assert "db corrupted" in str(exc)

    def test_security_error_message(self) -> None:
        exc = SecurityError("path traversal detected")
        assert "traversal" in str(exc)


class TestCircuitBreakerReexport:
    """`karadul.core.error_recovery.CircuitBreakerOpenError` exact-same
    class as `karadul.exceptions.CircuitBreakerOpenError` -- geriye
    uyumluluk garantisi."""

    def test_same_class_object(self) -> None:
        from karadul.core.error_recovery import (
            CircuitBreakerOpenError as CBOE_recovery,
        )
        assert CBOE_recovery is CircuitBreakerOpenError

    def test_core_init_reexport(self) -> None:
        from karadul.core import CircuitBreakerOpenError as CBOE_core
        assert CBOE_core is CircuitBreakerOpenError

    def test_raise_and_catch_via_old_path(self) -> None:
        from karadul.core.error_recovery import (
            CircuitBreakerOpenError as CBOE_old,
        )
        with pytest.raises(KaradulError):
            raise CBOE_old("breaker open")
