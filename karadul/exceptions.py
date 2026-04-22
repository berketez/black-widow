"""Karadul exception hierarchy.

Tek merkezi modul; diger alt paketler bu sinif hiyerarsisini yeniden
kullanarak tutarli hata tiplerine sahip olur. `KaradulError` tum
proje istisnalarinin kokudur; except yakalayicilari bu sinifi
hedefleyerek butun Karadul kaynakli hatalari sakin bir sekilde
isleyebilir.

Hiyerarsi:
    KaradulError
    |-- AnalysisError
    |   `-- DecompilationError
    |-- ReconstructionError
    |-- SignatureDBError
    |-- PipelineStageError
    |-- ConfigError
    |-- SecurityError
    `-- CircuitBreakerOpenError
"""

from __future__ import annotations


class KaradulError(Exception):
    """Karadul base exception.

    Tum Karadul tarafindan firlatilan istisnalar bu sinifi
    turetmelidir. API kullanicilari yalnizca bu sinifi yakalayarak
    butun proje hatalarini guvenli sekilde isleyebilir.
    """


class AnalysisError(KaradulError):
    """Binary analizi sirasinda olusan hata."""


class DecompilationError(AnalysisError):
    """Decompile asamasi basarisiz oldugunda."""


class ReconstructionError(KaradulError):
    """Isim/tip/struct kurtarma basarisiz oldugunda."""


class SignatureDBError(KaradulError):
    """SignatureDB yukleme, yazma veya sorgulama hatasi."""


class PipelineStageError(KaradulError):
    """Pipeline stage yurutmesi sirasinda olusan hata."""


class ConfigError(KaradulError):
    """Config parse veya dogrulama hatasi."""


class SecurityError(KaradulError):
    """Guvenlik politikasi ihlali (path traversal, zip bomb vb.)."""


class CircuitBreakerOpenError(KaradulError):
    """Circuit breaker acik -- retry engellendi.

    `karadul.core.error_recovery` tarafindan tekrar ihrac edilir;
    eski kullanici kodu `from karadul.core.error_recovery import
    CircuitBreakerOpenError` seklinde import etmeye devam edebilir.
    """


__all__ = [
    "KaradulError",
    "AnalysisError",
    "DecompilationError",
    "ReconstructionError",
    "SignatureDBError",
    "PipelineStageError",
    "ConfigError",
    "SecurityError",
    "CircuitBreakerOpenError",
]
