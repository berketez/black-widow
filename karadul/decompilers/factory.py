"""v1.10.0 M2 T10 — Decompiler backend factory.

Config'deki `decompilers.primary_backend` degerine gore uygun backend'i
dondurur. Ileride birden fazla backend paralel calistirmak icin
`create_all_backends()` eklenebilir.
"""

from __future__ import annotations

from karadul.config import Config
from karadul.decompilers.angr_backend import AngrBackend
from karadul.decompilers.base import DecompilerBackend
from karadul.decompilers.ghidra_backend import GhidraBackend


_BACKEND_REGISTRY: dict[str, type] = {
    "ghidra": GhidraBackend,
    "angr": AngrBackend,
}


def create_backend(config: Config, name: str | None = None) -> DecompilerBackend:
    """Config'e gore decompiler backend olustur.

    Args:
        config: Karadul config.
        name: Override backend adi. None ise
            `config.decompilers.primary_backend` kullanilir.

    Returns:
        Secilen backend instance'i.

    Raises:
        ValueError: Bilinmeyen backend adi.
    """
    if name is None:
        name = getattr(config.decompilers, "primary_backend", "ghidra")

    name = (name or "ghidra").strip().lower()
    cls = _BACKEND_REGISTRY.get(name)
    if cls is None:
        known = ", ".join(sorted(_BACKEND_REGISTRY.keys()))
        raise ValueError(
            f"Bilinmeyen decompiler backend: '{name}'. "
            f"Bilinen: {known}"
        )
    return cls(config)


def available_backends() -> list[str]:
    """Tum kayitli backend adlari."""
    return sorted(_BACKEND_REGISTRY.keys())
