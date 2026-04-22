"""Built-in signature dispatcher — kategori adi -> modul lazy import.

Bu paket v1.12.0 sig_db Faz 1 iskeletidir. 17 kategori placeholder modulu
bos ``SIGNATURES`` dict ile import compatibility saglar. Faz 2'de
``karadul/analyzers/signature_db.py`` icindeki ``_XXX_SIGNATURES`` dict'leri
bu modullere tasinacaktir.

Kullanim::

    from karadul.analyzers.sigdb_builtin import get_category
    sigs = get_category("crypto")  # dict[str, dict[str, str]]

Bilinmeyen kategori -> ``ValueError``.
"""
from __future__ import annotations

import importlib
from typing import Any

_CATEGORIES: frozenset[str] = frozenset({
    "crypto",
    "compression",
    "network",
    "database",
    "serialization",
    "posix_system",
    "linux_system",
    "windows_api",
    "macos_apple",
    "graphics_media",
    "languages",
    "runtimes",
    "event_utils",
    "game_ml",
    "logging",
    "strings_module",
    "calls",
})


def get_category(name: str) -> dict[str, Any]:
    """Lazy load kategori signatures.

    Args:
        name: Kategori adi (``_CATEGORIES`` uyelerinden biri).

    Returns:
        ``SIGNATURES`` dict'i (Faz 1'de bos, Faz 2'de dolu).

    Raises:
        ValueError: Tanimsiz kategori.
    """
    if name not in _CATEGORIES:
        raise ValueError(
            f"Unknown signature category: {name!r}. "
            f"Known: {sorted(_CATEGORIES)}"
        )
    module = importlib.import_module(f"karadul.analyzers.sigdb_builtin.{name}")
    return module.SIGNATURES  # type: ignore[no-any-return]


def list_categories() -> list[str]:
    """Bilinen tum kategori adlari (siralanmis)."""
    return sorted(_CATEGORIES)


__all__ = ["get_category", "list_categories"]
