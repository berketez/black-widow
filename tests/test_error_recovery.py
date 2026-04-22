"""v1.10.0 E7: ErrorRecovery (CircuitBreaker + retry) testleri.

Bu dosya ``karadul/core/error_recovery.py`` icin unit test coverage saglar.

Kapsam:
    * CircuitBreaker state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
    * CircuitBreaker OPEN durumunda cagrilari reddetmeli.
    * HALF_OPEN basarisiz deneme -> tekrar OPEN.
    * HALF_OPEN basarili deneme -> CLOSED.
    * ``with_retry`` decorator: exponential backoff + jitter, max_retries.
    * ``ErrorRecovery.execute``: breaker + retry birlesimi.
    * ``reset`` ve ``get_stats`` yardimcilari.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from karadul.config import RetryConfig
from karadul.core.error_recovery import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    ErrorRecovery,
    _calculate_delay,
    with_retry,
)


# ===========================================================================
# CircuitBreaker: State transitions
# ===========================================================================

class TestCircuitBreakerStates:
    """CircuitBreaker state makinesi testleri."""

    def test_initial_state_closed(self) -> None:
        """Yeni olusturulan breaker CLOSED durumunda olmali."""
        cb = CircuitBreaker(threshold=3, reset_timeout=1.0, name="test")
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_closed_to_open_after_threshold(self) -> None:
        """Ardisik threshold kadar hata -> OPEN."""
        cb = CircuitBreaker(threshold=3, reset_timeout=60.0, name="test")

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 1

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 2

        cb.record_failure()
        # 3. hata sinirda -> OPEN
        assert cb.state == CircuitState.OPEN
        assert cb._failure_count == 3

    def test_open_rejects_check(self) -> None:
        """OPEN durumunda check() CircuitBreakerOpenError firlatmali."""
        cb = CircuitBreaker(threshold=1, reset_timeout=60.0, name="reject")
        cb.record_failure()  # threshold=1 -> hemen OPEN
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitBreakerOpenError):
            cb.check()

    def test_open_to_half_open_after_timeout(self) -> None:
        """reset_timeout gectikten sonra state HALF_OPEN'a gecmeli."""
        cb = CircuitBreaker(threshold=1, reset_timeout=0.05, name="timeout")
        cb.record_failure()
        assert cb._state == CircuitState.OPEN

        time.sleep(0.06)
        # state property'si zaman asimini kontrol eder
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_returns_to_closed(self) -> None:
        """HALF_OPEN'da basarili cagri -> CLOSED, failure_count=0."""
        cb = CircuitBreaker(threshold=1, reset_timeout=0.05, name="recovery")
        cb.record_failure()
        time.sleep(0.06)
        # HALF_OPEN'a gecis tetiklensin
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_half_open_failure_returns_to_open(self) -> None:
        """HALF_OPEN'da basarisiz cagri -> tekrar OPEN."""
        cb = CircuitBreaker(threshold=1, reset_timeout=0.05, name="retry_fail")
        cb.record_failure()
        time.sleep(0.06)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_failure()
        # HALF_OPEN'da failure -> OPEN (count baskin degil, state baskin)
        assert cb._state == CircuitState.OPEN

    def test_reset_clears_state(self) -> None:
        """reset() state'i ve sayaci sifirlamali."""
        cb = CircuitBreaker(threshold=2, reset_timeout=60.0, name="reset")
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_success_resets_counter(self) -> None:
        """CLOSED'dayken basari failure_count'u sifirlamali."""
        cb = CircuitBreaker(threshold=3, reset_timeout=60.0, name="ok")
        cb.record_failure()
        cb.record_failure()
        assert cb._failure_count == 2

        cb.record_success()
        assert cb._failure_count == 0
        assert cb.state == CircuitState.CLOSED


# ===========================================================================
# with_retry decorator
# ===========================================================================

class TestWithRetryDecorator:
    """``with_retry`` decorator davranisi."""

    def test_success_no_retry(self) -> None:
        """Ilk cagrida basari -> hic retry yok."""
        call_count = {"n": 0}

        @with_retry(max_retries=3, base_delay=0.001, jitter=False)
        def ok() -> int:
            call_count["n"] += 1
            return 42

        assert ok() == 42
        assert call_count["n"] == 1

    def test_retry_until_success(self) -> None:
        """Ilk N cagri basarisiz, N+1'de basarili."""
        call_count = {"n": 0}

        @with_retry(max_retries=3, base_delay=0.001, jitter=False)
        def flaky() -> str:
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise RuntimeError("transient")
            return "done"

        assert flaky() == "done"
        assert call_count["n"] == 3

    def test_max_retries_exceeded_raises(self) -> None:
        """max_retries asilirsa son exception propagate olmali."""
        call_count = {"n": 0}

        @with_retry(max_retries=2, base_delay=0.001, jitter=False)
        def always_fail() -> None:
            call_count["n"] += 1
            raise ValueError(f"iteration {call_count['n']}")

        with pytest.raises(ValueError, match="iteration 3"):
            always_fail()
        # max_retries=2 -> toplam 3 deneme (initial + 2 retry)
        assert call_count["n"] == 3

    def test_only_retryable_exceptions(self) -> None:
        """retryable_exceptions disindaki hatalar hemen propagate."""
        call_count = {"n": 0}

        @with_retry(
            max_retries=3,
            base_delay=0.001,
            jitter=False,
            retryable_exceptions=(ValueError,),
        )
        def typed_fail() -> None:
            call_count["n"] += 1
            raise TypeError("not retryable")

        with pytest.raises(TypeError):
            typed_fail()
        # TypeError -> retry denemedi
        assert call_count["n"] == 1

    def test_preserves_function_metadata(self) -> None:
        """Decorator functools.wraps ile isim/docstring korumali."""

        @with_retry(max_retries=1, base_delay=0.001)
        def my_func() -> str:
            """Dokuman."""
            return "x"

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "Dokuman."


# ===========================================================================
# _calculate_delay: Exponential backoff + jitter
# ===========================================================================

class TestCalculateDelay:
    """Backoff matematigi."""

    def test_exponential_growth_no_jitter(self) -> None:
        """Jitter kapaliyken ustel buyume tam olmali."""
        # base=1, exp_base=2 -> 1, 2, 4, 8
        assert _calculate_delay(0, 1.0, 30.0, 2.0, jitter=False) == 1.0
        assert _calculate_delay(1, 1.0, 30.0, 2.0, jitter=False) == 2.0
        assert _calculate_delay(2, 1.0, 30.0, 2.0, jitter=False) == 4.0
        assert _calculate_delay(3, 1.0, 30.0, 2.0, jitter=False) == 8.0

    def test_max_delay_cap(self) -> None:
        """max_delay uzeri degerler kirpilmali."""
        # base=1, exp_base=2, max=5 -> attempt=10 cok buyuk ama 5'te kirpilmali
        assert _calculate_delay(10, 1.0, 5.0, 2.0, jitter=False) == 5.0

    def test_jitter_range(self) -> None:
        """Jitter +/- %20 araliginda olmali."""
        for _ in range(50):
            d = _calculate_delay(2, 1.0, 30.0, 2.0, jitter=True)
            # base * 2^2 = 4, jitter +/- 0.8
            assert 3.2 <= d <= 4.8

    def test_never_negative(self) -> None:
        """Hicbir durumda negatif delay donmemeli."""
        for attempt in range(10):
            d = _calculate_delay(attempt, 0.01, 30.0, 2.0, jitter=True)
            assert d >= 0.0


# ===========================================================================
# ErrorRecovery: CircuitBreaker + retry birlesimi
# ===========================================================================

class TestErrorRecovery:
    """``ErrorRecovery.execute`` ve ``wrap`` davranislari."""

    def _fast_config(self) -> RetryConfig:
        """Testler icin hizli ve deterministik config."""
        return RetryConfig(
            max_retries=2,
            base_delay=0.001,
            max_delay=0.01,
            circuit_breaker_threshold=3,
            circuit_breaker_reset=0.05,
        )

    def test_execute_success(self) -> None:
        """Basarili operasyon direkt sonuc dondurmeli."""
        er = ErrorRecovery(self._fast_config())
        assert er.execute(lambda: 7, "op1") == 7

    def test_execute_retries_then_succeeds(self) -> None:
        """Gecici hata sonrasi basariya ulasmali."""
        er = ErrorRecovery(self._fast_config())
        count = {"n": 0}

        def flaky() -> str:
            count["n"] += 1
            if count["n"] < 2:
                raise RuntimeError("transient")
            return "ok"

        assert er.execute(flaky, "op_flaky") == "ok"
        assert count["n"] == 2
        # Basarili sonrasi breaker CLOSED olmali
        breaker = er.get_breaker("op_flaky")
        assert breaker.state == CircuitState.CLOSED

    def test_execute_raises_after_max_retries(self) -> None:
        """max_retries asilinca son exception propagate."""
        er = ErrorRecovery(self._fast_config())

        def fail() -> None:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            er.execute(fail, "op_fail")

    def test_breaker_opens_after_threshold(self) -> None:
        """circuit_breaker_threshold kadar hata -> breaker OPEN."""
        cfg = RetryConfig(
            max_retries=0,              # retry yok, her cagri 1 hata sayilir
            base_delay=0.001,
            max_delay=0.01,
            circuit_breaker_threshold=2,
            circuit_breaker_reset=60.0,
        )
        er = ErrorRecovery(cfg)

        def fail() -> None:
            raise RuntimeError("x")

        # Ilk cagri: 1 failure
        with pytest.raises(RuntimeError):
            er.execute(fail, "op_threshold")
        # Ikinci cagri: 2. failure -> OPEN
        with pytest.raises(RuntimeError):
            er.execute(fail, "op_threshold")

        breaker = er.get_breaker("op_threshold")
        assert breaker.state == CircuitState.OPEN

        # Ucuncu cagri: breaker acik, CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            er.execute(fail, "op_threshold")

    def test_wrap_decorator(self) -> None:
        """``wrap`` decorator olarak ErrorRecovery'yi uygulamali."""
        er = ErrorRecovery(self._fast_config())

        @er.wrap("wrapped_op")
        def work(x: int) -> int:
            return x * 2

        assert work(5) == 10

    def test_reset_single(self) -> None:
        """reset(op_id) sadece o breaker'i sifirlamali."""
        er = ErrorRecovery(self._fast_config())

        # Iki breaker ac
        er.get_breaker("a").record_failure()
        er.get_breaker("a").record_failure()
        er.get_breaker("a").record_failure()
        er.get_breaker("b").record_failure()

        assert er.get_breaker("a").state == CircuitState.OPEN

        er.reset("a")
        assert er.get_breaker("a").state == CircuitState.CLOSED
        assert er.get_breaker("b")._failure_count == 1

    def test_reset_all(self) -> None:
        """reset() argumansiz cagrilirsa tum breaker'lari sifirlamali."""
        er = ErrorRecovery(self._fast_config())
        for name in ("a", "b", "c"):
            for _ in range(3):
                er.get_breaker(name).record_failure()
            assert er.get_breaker(name).state == CircuitState.OPEN

        er.reset()
        for name in ("a", "b", "c"):
            assert er.get_breaker(name).state == CircuitState.CLOSED

    def test_get_stats(self) -> None:
        """get_stats butun breaker'larin ozetini dondurmeli."""
        er = ErrorRecovery(self._fast_config())
        er.get_breaker("op1").record_failure()
        er.get_breaker("op2").record_success()

        stats = er.get_stats()
        assert stats["total_breakers"] == 2
        assert "op1" in stats["breakers"]
        assert "op2" in stats["breakers"]
        assert stats["breakers"]["op1"]["failure_count"] == 1

    def test_default_config_when_none(self) -> None:
        """Config verilmezse varsayilan RetryConfig kullanilmali."""
        er = ErrorRecovery(None)
        assert er._config.max_retries == 3  # RetryConfig default
        # Basit operasyon calismali
        assert er.execute(lambda: "hello", "default_op") == "hello"

    def test_breaker_half_open_recovery_flow(self) -> None:
        """OPEN -> HALF_OPEN -> CLOSED flow execute uzerinden test."""
        cfg = RetryConfig(
            max_retries=0,
            base_delay=0.001,
            max_delay=0.01,
            circuit_breaker_threshold=2,
            circuit_breaker_reset=0.05,
        )
        er = ErrorRecovery(cfg)

        call_count = {"n": 0}

        def sometimes_fail() -> str:
            call_count["n"] += 1
            if call_count["n"] <= 2:
                raise RuntimeError("early fail")
            return "recovered"

        # Ilk iki cagri -> OPEN
        for _ in range(2):
            with pytest.raises(RuntimeError):
                er.execute(sometimes_fail, "flow")

        breaker = er.get_breaker("flow")
        assert breaker.state == CircuitState.OPEN

        # Reset timeout kadar bekle
        time.sleep(0.06)

        # state property'si HALF_OPEN'a gecisi tetikler
        assert breaker.state == CircuitState.HALF_OPEN

        # Artik basarili (call_count=3 olacak)
        result = er.execute(sometimes_fail, "flow")
        assert result == "recovered"
        assert breaker.state == CircuitState.CLOSED


# ===========================================================================
# with_retry: jitter sleep patch kontrolleri
# ===========================================================================

class TestWithRetrySleep:
    """Backoff sleep cagrilari mock'lanarak zamanlamayi test eder."""

    def test_sleep_called_between_retries(self) -> None:
        """Her basarisiz cagri sonrasi time.sleep cagrilmali."""
        call_count = {"n": 0}

        @with_retry(max_retries=2, base_delay=0.001, jitter=False)
        def flaky() -> str:
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise RuntimeError("boom")
            return "ok"

        with patch(
            "karadul.core.error_recovery.time.sleep",
        ) as mock_sleep:
            assert flaky() == "ok"
            # 2 sleep cagrisi (retry 1 ve retry 2 oncesi)
            assert mock_sleep.call_count == 2
