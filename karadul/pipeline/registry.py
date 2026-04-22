"""Step registry — decorator-based kayit sistemi.

Kullanim:
    @register_step(
        name="binary_prep",
        requires=[],
        produces=["c_files", "file_cache"],
        parallelizable_with=[],
    )
    class BinaryPrepStep(Step):
        def run(self, ctx: StepContext) -> dict: ...

Global registry: `_REGISTRY: dict[str, StepSpec]`.
Ayni isim iki kez kayit → ValueError.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from karadul.pipeline.context import StepContext


class Step(ABC):
    """Step temel sinifi.

    Alt siniflar `run(ctx)` metodunu doldurur. Return: yeni artifact'lar.
    Runner bu artifact'lari StepContext'e yazar.
    """

    @abstractmethod
    def run(self, ctx: StepContext) -> dict[str, Any]:
        """Step'i calistir.

        Returns:
            Yeni artifact'lar (key -> value). Sadece `produces` listesindeki
            key'ler kabul edilir; fazlasi runner tarafindan RuntimeError.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class StepSpec:
    """Bir step'in metadata'si + sinifi."""

    name: str
    cls: type[Step]
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    parallelizable_with: tuple[str, ...] = ()


_REGISTRY: dict[str, StepSpec] = {}


def register_step(
    *,
    name: str,
    requires: list[str] | None = None,
    produces: list[str] | None = None,
    parallelizable_with: list[str] | None = None,
) -> Callable[[type[Step]], type[Step]]:
    """Decorator: bir Step sinifini global registry'e kaydet.

    Raises:
        ValueError: Ayni isim zaten kayitli.
    """

    def decorator(cls: type[Step]) -> type[Step]:
        if name in _REGISTRY:
            raise ValueError(
                f"Step '{name}' zaten kayitli (sinif: "
                f"{_REGISTRY[name].cls.__name__})",
            )
        spec = StepSpec(
            name=name,
            cls=cls,
            requires=tuple(requires or ()),
            produces=tuple(produces or ()),
            parallelizable_with=tuple(parallelizable_with or ()),
        )
        _REGISTRY[name] = spec
        return cls

    return decorator


def get_step(name: str) -> StepSpec:
    """Kayitli step'i isimle al.

    Raises:
        KeyError: Step kayitli degil.
    """
    if name not in _REGISTRY:
        raise KeyError(
            f"Step '{name}' kayitli degil. Mevcut: {sorted(_REGISTRY.keys())}",
        )
    return _REGISTRY[name]


def list_steps() -> list[str]:
    """Tum kayitli step isimleri."""
    return sorted(_REGISTRY.keys())


def _clear_registry_for_tests() -> None:
    """Sadece testlerde kullan (izole fixture icin)."""
    _REGISTRY.clear()
