"""Debug binary -> ground truth baseline skor saglayici.

DwarfExtractor'i kullanarak debug bilgisine sahip bir binary'den
fonksiyon/parametre/lokal/tip istatistigi cikarir. Debug ikilisinin puanı
ÖLÇÜLMEZ (TIP-10, P15b): eskiden "tanım gereği 100" yazılıyordu; artık None.

Kullanim:
    from karadul.quality.dwarf_baseline import DwarfBaseline

    bl = DwarfBaseline(Path("/path/to/debug_binary"))
    if bl.available:
        stats = bl.statistics()
        # stats: {"functions": N, "params": M, "locals": K, "types": T}
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.dwarf_extractor import DwarfExtractor

logger = logging.getLogger(__name__)


@dataclass
class DwarfBaselineResult:
    """Debug binary baseline istatistikleri.

    ``score`` ölçülmez (TIP-10, P15b): None. Eskiden "tanım gereği 100" yazılıyordu;
    debug ikilisinin okunabilirlik puanı hiç hesaplanmıyordu.
    """

    score: Optional[float]
    available: bool
    statistics: dict[str, Any]


class DwarfBaseline:
    """Debug binary uzerinden baseline saglayici.

    DWARF debug info varsa fonksiyon/parametre/lokal sayım istatistiklerini
    verir (puan ölçülmez, ``score`` None). Yoksa graceful skip.
    """

    def __init__(self, binary_path: Path) -> None:
        self.binary_path = Path(binary_path)
        self._extractor: DwarfExtractor | None = None
        self._checked = False
        self._available = False

    @property
    def available(self) -> bool:
        """Debug info mevcut mu?"""
        self._ensure_checked()
        return self._available

    def _ensure_checked(self) -> None:
        if self._checked:
            return
        self._checked = True
        if not self.binary_path.exists():
            logger.debug(
                "DwarfBaseline: binary bulunamadi %s", self.binary_path,
            )
            return
        try:
            extractor = DwarfExtractor(self.binary_path)
            if extractor.has_debug_info():
                self._extractor = extractor
                self._available = True
        except Exception as exc:  # pragma: no cover - system dep
            logger.warning("DWARF extractor hata: %s", exc)

    def result(self) -> DwarfBaselineResult:
        """Baseline sonucu: DWARF istatistikleri (puan ölçülmez), yoksa available=False."""
        self._ensure_checked()

        if not self._available or self._extractor is None:
            return DwarfBaselineResult(
                score=None,
                available=False,
                statistics={"note": "DWARF debug info bulunamadi"},
            )

        try:
            functions = self._extractor.extract_functions()
        except Exception as exc:  # pragma: no cover
            logger.warning("DWARF parse hata: %s", exc)
            return DwarfBaselineResult(
                score=None,
                available=False,
                statistics={"note": f"DWARF parse hata: {exc}"},
            )

        stats = self._compute_stats(functions)
        return DwarfBaselineResult(
            score=None,
            available=True,
            statistics=stats,
        )

    @staticmethod
    def _compute_stats(functions: list) -> dict[str, Any]:
        """DwarfFunction listesinden ozetler cikar."""
        func_count = len(functions)
        param_count = 0
        local_count = 0
        type_set: set[str] = set()

        for func in functions:
            param_count += len(func.params)
            local_count += len(func.locals)
            if func.return_type:
                type_set.add(func.return_type)
            for p in func.params:
                if p.type_name:
                    type_set.add(p.type_name)
            for lv in func.locals:
                if lv.type_name:
                    type_set.add(lv.type_name)

        return {
            "function_count": func_count,
            "param_count": param_count,
            "local_count": local_count,
            "distinct_types": len(type_set),
            "sample_types": sorted(type_set)[:10],
        }
