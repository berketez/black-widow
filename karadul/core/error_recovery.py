"""Hata kurtarma motoru.

Eski error-recovery.js'nin Python portu. Uc bilesenli:
1. CircuitBreaker: Ardisik hatalarda devreyi acar, belirli sure sonra yeniden dener.
2. with_retry decorator: Exponential backoff + jitter ile yeniden deneme.
3. ErrorRecovery: CircuitBreaker + retry birlesimi.
"""

from __future__ import annotations

import functools
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TypeVar

from ..config import RetryConfig

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitState(Enum):
    """Circuit breaker durumlari."""

    CLOSED = "closed"      # Normal calisma -- istekler gecir
    OPEN = "open"          # Devre acik -- istekleri reddet
    HALF_OPEN = "half_open"  # Deneme modu -- tek istek gecir


# CircuitBreakerOpenError artik karadul.exceptions hiyerarsisinin parcasi.
# Geriye uyumluluk icin bu modulden de yeniden ihrac ediyoruz.
from karadul.exceptions import CircuitBreakerOpenError  # noqa: E402,F401


@dataclass
class CircuitBreaker:
    """Martin Fowler pattern'i: ardisik N hatadan sonra devreyi ac.

    Devre acikken tum cagrilar CircuitBreakerOpenError ile reddedilir.
    reset_timeout suresi doldugunda devre HALF_OPEN'a gecer ve
    tek bir deneme cagrisina izin verir. Bu cagri basariliysa devre
    CLOSED'a doner, basarisizsa tekrar OPEN olur.

    Args:
        threshold: Devreyi acmak icin gereken ardisik hata sayisi.
        reset_timeout: OPEN->HALF_OPEN gecis suresi (saniye).
        name: Tanimlayici isim (loglama icin).
    """

    threshold: int = 5
    reset_timeout: float = 60.0
    name: str = "default"

    # Dahili state -- disaridan set edilmemeli
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False, repr=False)
    _failure_count: int = field(default=0, init=False, repr=False)
    _last_failure_time: float = field(default=0.0, init=False, repr=False)

    @property
    def state(self) -> CircuitState:
        """Guncel devre durumu (zamanla HALF_OPEN'a gecebilir)."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.reset_timeout:
                self._state = CircuitState.HALF_OPEN
                logger.info(
                    "CircuitBreaker [%s]: OPEN -> HALF_OPEN (%.1fs gecti)",
                    self.name, elapsed,
                )
        return self._state

    def check(self) -> None:
        """Cagri oncesi kontrol. OPEN ise CircuitBreakerOpenError firlat."""
        current = self.state  # HALF_OPEN gecisini tetikler
        if current == CircuitState.OPEN:
            raise CircuitBreakerOpenError(
                f"Circuit breaker [{self.name}] acik. "
                f"{self.reset_timeout:.0f}s sonra tekrar denenecek."
            )

    def record_success(self) -> None:
        """Basarili cagri sonrasi devreyi sifirla."""
        if self._state != CircuitState.CLOSED:
            logger.info(
                "CircuitBreaker [%s]: %s -> CLOSED (basarili cagri)",
                self.name, self._state.value,
            )
        self._failure_count = 0
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Basarisiz cagri sonrasi hata sayacini artir."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            # HALF_OPEN'daki tek deneme basarisiz -> tekrar OPEN
            self._state = CircuitState.OPEN
            logger.warning(
                "CircuitBreaker [%s]: HALF_OPEN -> OPEN (deneme basarisiz)",
                self.name,
            )
        elif self._failure_count >= self.threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "CircuitBreaker [%s]: CLOSED -> OPEN (%d ardisik hata)",
                self.name, self._failure_count,
            )

    def reset(self) -> None:
        """Devreyi tamamen sifirla."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._last_failure_time = 0.0


# ---------------------------------------------------------------------------
# Retry Decorator
# ---------------------------------------------------------------------------

def with_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[F], F]:
    """Exponential backoff + jitter ile yeniden deneme decorator'u.

    Args:
        max_retries: Maksimum yeniden deneme sayisi.
        base_delay: Ilk bekleme suresi (saniye).
        max_delay: Maksimum bekleme suresi (saniye).
        exponential_base: Ustel carpan tabani.
        jitter: Rastgele sapma eklensin mi (thundering herd onlemi).
        retryable_exceptions: Yeniden denenecek exception tipleri.

    Returns:
        Dekorator fonksiyonu.

    Kullanim:
        @with_retry(max_retries=3, base_delay=1.0)
        def risky_operation():
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exc = exc

                    if attempt >= max_retries:
                        logger.error(
                            "%s: %d deneme sonrasi basarisiz: %s",
                            func.__name__, attempt + 1, exc,
                        )
                        raise

                    delay = _calculate_delay(
                        attempt, base_delay, max_delay, exponential_base, jitter,
                    )
                    logger.warning(
                        "%s: Deneme %d basarisiz, %.1fs sonra tekrar: %s",
                        func.__name__, attempt + 1, delay, exc,
                    )
                    time.sleep(delay)

            # Buraya ulasilmamali ama tip guvenligi icin
            if last_exc is not None:
                raise last_exc  # pragma: no cover

        return wrapper  # type: ignore[return-value]

    return decorator


def _calculate_delay(
    attempt: int,
    base_delay: float,
    max_delay: float,
    exponential_base: float,
    jitter: bool,
) -> float:
    """Exponential backoff + jitter ile bekleme suresi hesapla.

    Formul: delay = base_delay * (exponential_base ^ attempt)
    Jitter: +/- %20 rastgele sapma (thundering herd onlemi)
    """
    delay = base_delay * (exponential_base ** attempt)

    if jitter:
        # Full jitter: [0, delay] arasi rastgele
        # Daha etkili: decorrelated jitter yerine basit +/- %20
        jitter_range = delay * 0.2
        delay += random.uniform(-jitter_range, jitter_range)

    return min(max(delay, 0), max_delay)


# ---------------------------------------------------------------------------
# Error Recovery (CircuitBreaker + Retry birlesimi)
# ---------------------------------------------------------------------------

class ErrorRecovery:
    """CircuitBreaker + retry mekanizmasinin birlesimidir.

    Her operasyon ID'si icin ayri bir CircuitBreaker tutar.
    Operasyon cagirildiginda: circuit breaker kontrol -> calistir -> retry.

    Args:
        config: RetryConfig instance'i (Config.retry).
    """

    def __init__(self, config: RetryConfig | None = None) -> None:
        if config is None:
            config = RetryConfig()
        self._config = config
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_breaker(self, operation_id: str) -> CircuitBreaker:
        """Operasyon icin CircuitBreaker dondur (yoksa olustur)."""
        if operation_id not in self._breakers:
            self._breakers[operation_id] = CircuitBreaker(
                threshold=self._config.circuit_breaker_threshold,
                reset_timeout=self._config.circuit_breaker_reset,
                name=operation_id,
            )
        return self._breakers[operation_id]

    def execute(
        self,
        operation: Callable[..., Any],
        operation_id: str = "default",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Operasyonu CircuitBreaker + retry ile calistir.

        Args:
            operation: Calistirilacak callable.
            operation_id: CircuitBreaker tanimlayicisi.
            *args: operation'a aktarilacak positional arglar.
            **kwargs: operation'a aktarilacak keyword arglar.

        Returns:
            operation'in donus degeri.

        Raises:
            CircuitBreakerOpenError: Devre aciksa.
            Exception: max_retries asilirsa son hata.
        """
        breaker = self.get_breaker(operation_id)
        breaker.check()

        last_exc: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                result = operation(*args, **kwargs)
                breaker.record_success()
                if attempt > 0:
                    logger.info(
                        "Operasyon [%s] %d. denemede basarili.",
                        operation_id, attempt + 1,
                    )
                return result
            except CircuitBreakerOpenError:
                raise
            except Exception as exc:
                last_exc = exc
                breaker.record_failure()

                if attempt >= self._config.max_retries:
                    logger.error(
                        "Operasyon [%s]: %d deneme sonrasi tamamen basarisiz: %s",
                        operation_id, attempt + 1, exc,
                    )
                    raise

                delay = _calculate_delay(
                    attempt,
                    self._config.base_delay,
                    self._config.max_delay,
                    exponential_base=2.0,
                    jitter=True,
                )
                logger.warning(
                    "Operasyon [%s]: Deneme %d basarisiz, %.1fs bekleniyor: %s",
                    operation_id, attempt + 1, delay, exc,
                )
                time.sleep(delay)

        # Tip guvenligi -- buraya ulasilmamali
        if last_exc is not None:
            raise last_exc  # pragma: no cover

    def wrap(self, operation_id: str) -> Callable[[F], F]:
        """Fonksiyonu ErrorRecovery ile saran decorator.

        Kullanim:
            recovery = ErrorRecovery(config)

            @recovery.wrap("ghidra_analysis")
            def run_ghidra(binary_path):
                ...
        """

        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return self.execute(func, operation_id, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def reset(self, operation_id: str | None = None) -> None:
        """CircuitBreaker'lari sifirla.

        Args:
            operation_id: Belirli bir operasyonu sifirla. None ise tumumunu.
        """
        if operation_id is not None:
            if operation_id in self._breakers:
                self._breakers[operation_id].reset()
        else:
            for breaker in self._breakers.values():
                breaker.reset()

    def get_stats(self) -> dict[str, Any]:
        """Tum CircuitBreaker durumlarini raporla."""
        stats: dict[str, Any] = {
            "total_breakers": len(self._breakers),
            "breakers": {},
        }
        for op_id, breaker in self._breakers.items():
            stats["breakers"][op_id] = {
                "state": breaker.state.value,
                "failure_count": breaker._failure_count,
            }
        return stats
