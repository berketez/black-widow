"""v1.10.0 M2 T10 — Decompiler backend factory.

Config'deki `decompilers.primary_backend` degerine gore uygun backend'i
dondurur. v1.11.0 Phase 1B'de `create_backend_with_fallback()` eklendi:
primary kullanilamazsa (is_available False) chain'deki secondary'lere duser.
"""

from __future__ import annotations

import logging

from karadul.config import Config
from karadul.decompilers.angr_backend import AngrBackend
from karadul.decompilers.base import DecompilerBackend
from karadul.decompilers.ghidra_backend import GhidraBackend

logger = logging.getLogger(__name__)


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


def create_backend_with_fallback(
    config: Config,
    name: str | None = None,
) -> tuple[DecompilerBackend, list[str]]:
    """Primary backend'i olustur; kullanilamazsa fallback chain'i dene.

    v1.11.0 Phase 1B: Graceful degradation. Ornegin Berke macOS'ta angr
    primary secti ama angr kurulu degil -> Ghidra'ya duser ve log uretir.

    Args:
        config: Karadul config.
        name: Override primary backend adi (default config.primary_backend).

    Returns:
        (backend, tried_names) -- gercekten kullanilan backend ve sirasiyla
        denenen isimler. Ornek: angr denendi ama kurulu yok, ghidra'ya dustu
        -> (GhidraBackend, ["angr", "ghidra"]).

    Raises:
        RuntimeError: Primary + fallback_chain'deki HICBIR backend kullanilabilir
            degilse. (Dev ortaminda Ghidra hep kurulu oldugu icin normalde bu
            asla olmamali.)
    """
    tried: list[str] = []

    # Primary'i belirle
    primary = name
    if primary is None:
        primary = getattr(config.decompilers, "primary_backend", "ghidra")
    primary = (primary or "ghidra").strip().lower()

    # Chain'i topla: primary + fallback_chain (duplicates filtrelenecek,
    # primary'nin chain'de yeniden denenmesi gereksiz).
    raw_chain = list(getattr(config.decompilers, "fallback_chain", ["ghidra"]) or [])
    candidates: list[str] = [primary]
    for cand in raw_chain:
        if cand is None:
            continue
        cand_norm = str(cand).strip().lower()
        if cand_norm and cand_norm not in candidates:
            candidates.append(cand_norm)

    last_error: Exception | None = None
    for cand_name in candidates:
        tried.append(cand_name)
        try:
            backend = create_backend(config, name=cand_name)
        except ValueError as exc:
            # Bilinmeyen isim -- log at ve devam et.
            logger.warning(
                "Decompiler backend '%s' kayitli degil, atlaniyor: %s",
                cand_name, exc,
            )
            last_error = exc
            continue

        try:
            available = backend.is_available()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Backend '%s' is_available() patladi, atlaniyor: %s",
                cand_name, exc,
            )
            last_error = exc
            continue

        if available:
            if cand_name != primary:
                logger.warning(
                    "Primary decompiler backend '%s' kullanilamaz durumda; "
                    "'%s' backend'ine dusuldu (fallback chain: %s).",
                    primary, cand_name, raw_chain,
                )
            return backend, tried

    raise RuntimeError(
        f"Hic bir decompiler backend kullanilabilir degil. "
        f"Denenen: {tried}. Son hata: {last_error}"
    )


def available_backends() -> list[str]:
    """Tum kayitli backend adlari."""
    return sorted(_BACKEND_REGISTRY.keys())
