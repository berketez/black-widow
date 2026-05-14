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


# v1.16 B23: Geriye donuk uyumluluk icin coklu kalitim.
# Eski kod ``except ValueError`` / ``except RuntimeError`` yakalamaya
# devam edebilir; yeni kod ``except KaradulError`` ile butun Karadul
# hatalarini tek noktada yakalar. Karadul sinifi MRO'da once gelir
# ki ``isinstance(exc, KaradulError)`` her zaman True olsun.


class AnalysisError(KaradulError, RuntimeError):
    """Binary analizi sirasinda olusan hata.

    Adapter (BinaryNinja/TRex/PDB/TypeForge) subprocess fail,
    parse hatasi veya tool bulunamadi gibi runtime durumlarini kapsar.
    Backward-compat: ``except RuntimeError`` hala yakalar.
    """


class DecompilationError(AnalysisError):
    """Decompile asamasi basarisiz oldugunda."""


class ReconstructionError(KaradulError, RuntimeError):
    """Isim/tip/struct kurtarma basarisiz oldugunda."""


class SignatureDBError(KaradulError, ValueError):
    """SignatureDB yukleme, yazma veya sorgulama hatasi.

    Backward-compat: ``except ValueError`` hala yakalar (eski
    ``add_byte_signature`` testleri kirilmaz).
    """


class PipelineStageError(KaradulError, RuntimeError):
    """Pipeline stage yurutmesi sirasinda olusan hata."""


class ConfigError(KaradulError, ValueError):
    """Config parse veya dogrulama hatasi.

    Backward-compat: ``except ValueError`` hala yakalar.
    """


class WorkspaceError(KaradulError, OSError):
    """Workspace I/O hatasi (permission, disk full, path geçersiz).

    Backward-compat: ``except OSError`` hala yakalar.
    """


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
    "WorkspaceError",
    "SecurityError",
    "CircuitBreakerOpenError",
]
