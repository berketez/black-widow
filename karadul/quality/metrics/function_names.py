"""Boyut 1: Fonksiyon isimleri skor metric'i.

Formul:
    (1 - FUN_XXX_count / total) * 100 * dict_similarity

Burada ``dict_similarity`` anlamli isimlerin ne kadarinin ingilizce
kok sozcuklerine benzedigidir (ornek: init, read, parse...). Boylece
"abc", "xyz42" gibi anlamsiz ama Ghidra-olmayan isimler de cezalandirilir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source
from karadul.quality.patterns import (
    RE_C_FUNCTION_DEF,
    is_ghidra_func_name,
    is_meaningful_name,
)


@dataclass
class FunctionNamesResult:
    """Boyut 1 skor sonucu."""

    score: float
    details: dict[str, Any]


class FunctionNamesMetric:
    """Fonksiyon isim kalitesi skorlayicisi.

    C kaynak dosyalarini tarar, fonksiyon tanimlarini cikarir, FUN_XXX
    kalibi ile anlamli isimlerin oranini hesaplar ve sozluk benzerligi
    ile agirliklandirir.
    """

    name: str = "function_names"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> FunctionNamesResult:
        """C dosyalarini tara ve skor dondur.

        Args:
            c_files: .c veya .h dosyalarinin listesi.
            file_cache: v1.10.0 C2 -- dosya_adi -> kaynak kod cache.
                Verilirse disk I/O yapilmaz, onbellekten okunur.

        Returns:
            FunctionNamesResult -- 0-100 arasi skor + detay.
        """
        total = 0
        generic_count = 0
        meaningful_count = 0
        dict_hits = 0
        all_names: list[str] = []

        for path in c_files:
            names = _extract_function_names(path, file_cache)
            for name in names:
                total += 1
                all_names.append(name)
                if is_ghidra_func_name(name):
                    generic_count += 1
                else:
                    if is_meaningful_name(name, self.config.min_func_name_length):
                        meaningful_count += 1
                        if _has_common_english_root(
                            name, self.config.common_english_roots,
                        ):
                            dict_hits += 1

        if total == 0:
            return FunctionNamesResult(
                score=0.0,
                details={
                    "total": 0,
                    "generic_count": 0,
                    "meaningful_count": 0,
                    "dict_similarity": 0.0,
                    "note": "Hicbir fonksiyon bulunamadi",
                },
            )

        generic_ratio = generic_count / total
        base_score = (1.0 - generic_ratio) * 100.0

        # Dict similarity: anlamli isimler icinde ingilizce kok orani
        if meaningful_count > 0:
            dict_similarity = dict_hits / meaningful_count
        else:
            dict_similarity = 0.0

        # Formul: base * dict_similarity. Hicbir isim ingilizce koke uymazsa
        # skor cok dusuk kalir; bu dogru -- "xyz42" anlamli degil.
        final_score = base_score * dict_similarity

        return FunctionNamesResult(
            score=_clamp01(final_score),
            details={
                "total": total,
                "generic_count": generic_count,
                "meaningful_count": meaningful_count,
                "dict_hits": dict_hits,
                "generic_ratio": round(generic_ratio, 4),
                "dict_similarity": round(dict_similarity, 4),
                "base_score": round(base_score, 2),
                "sample_names": all_names[:10],
            },
        )


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------

# C typedef / forward declaration gibi ilgisiz durumlari ele
_FORBIDDEN_NAMES = frozenset({
    "if", "else", "while", "for", "switch", "case", "return",
    "sizeof", "typedef", "struct", "union", "enum",
})


def _extract_function_names(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> list[str]:
    """Bir C/H dosyasindan fonksiyon isimlerini regex ile cikar.

    pycparser sart degil -- reconstruct edilmis kod genelde bozuk olabilir,
    regex daha saglam.

    v1.10.0 C2: ``file_cache`` verilirse cache'den okunur, disk I/O
    atlanir. Cache miss olursa disk fallback; cache None ise her zaman disk.
    """
    source = _read_source(path, file_cache)
    if source is None:
        return []
    # Basit onişlem: blok yorumlari cikar (yanlis eslesme olmasin)
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)

    names: list[str] = []
    for match in RE_C_FUNCTION_DEF.finditer(source):
        name = match.group(1)
        if name in _FORBIDDEN_NAMES:
            continue
        names.append(name)
    return names


def _has_common_english_root(name: str, roots: frozenset[str]) -> bool:
    """Isim herhangi bir yaygin ingilizce koku iceriyor mu?"""
    lowered = name.lower()
    for root in roots:
        if root in lowered:
            return True
    return False


def _clamp01(score: float) -> float:
    """0-100 arasinda sikistir."""
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
