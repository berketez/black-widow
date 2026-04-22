"""Boyut 4: Tip kalitesi skor metric'i.

Formul:
    (1 - undefined[N]_count / total_types) * 100

Ghidra'nin urettigi 'undefined', 'undefined1', 'undefined4', 'undefined8'
gibi placeholder tiplerin oranini olcer; dusuk oran = iyi tip recovery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source
from karadul.quality.patterns import is_ghidra_type


@dataclass
class TypeQualityResult:
    score: float
    details: dict[str, Any]


class TypeQualityMetric:
    """Tip kalitesi metric."""

    name: str = "type_quality"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> TypeQualityResult:
        total = 0
        generic = 0
        type_hist: dict[str, int] = {}

        for path in c_files:
            for type_str in _extract_type_uses(path, file_cache):
                total += 1
                if is_ghidra_type(type_str):
                    generic += 1
                # Histogram
                type_hist[type_str] = type_hist.get(type_str, 0) + 1

        if total == 0:
            return TypeQualityResult(
                score=0.0,
                details={
                    "total": 0,
                    "undefined_count": 0,
                    "note": "Tip bilgisi bulunamadi",
                },
            )

        generic_ratio = generic / total
        score_val = (1.0 - generic_ratio) * 100.0

        # En sik 10 tipi goster
        top_types = sorted(type_hist.items(), key=lambda kv: -kv[1])[:10]

        return TypeQualityResult(
            score=_clamp01(score_val),
            details={
                "total": total,
                "undefined_count": generic,
                "generic_ratio": round(generic_ratio, 4),
                "top_types": top_types,
            },
        )


# ---------------------------------------------------------------------------
# Tip cikartma
# ---------------------------------------------------------------------------

# Bir C deklarator: <type> <name>[;,=()]
# Burada tipin sadece 'undefined*' degil her seyi sayariz.
_RE_DECL_TYPE = re.compile(
    r"^\s*((?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*(?:\*+\s*)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*[;,=\(\[]",
    re.MULTILINE,
)

# Fonksiyon imzasindan donus tipi + param tipleri
_RE_FUNC_DEF_TYPE = re.compile(
    r"^((?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*\*?\s*\w+\s*\(([^;{]*)\)\s*\{",
    re.MULTILINE,
)


def _extract_type_uses(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> list[str]:
    """Bir C dosyasindan tum tip kullanimlarini dondur (deklarator + imza).

    v1.10.0 C2: ``file_cache`` varsa disk I/O atlanir.
    """
    source = _read_source(path, file_cache)
    if source is None:
        return []

    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)

    types: list[str] = []

    # 1) Fonksiyon imzalari: donus tipi + parametre tipleri
    for match in _RE_FUNC_DEF_TYPE.finditer(source):
        return_type = match.group(1).strip()
        if return_type not in _IGNORE_TYPES:
            types.append(_normalize(return_type))

        args_str = match.group(2).strip()
        if args_str and args_str != "void":
            for arg in _split_args(args_str):
                t = _extract_param_type(arg)
                if t:
                    types.append(t)

    # 2) Deklaratorler
    for match in _RE_DECL_TYPE.finditer(source):
        type_str = match.group(1).strip()
        name = match.group(2)
        if type_str in _IGNORE_TYPES:
            continue
        if name in _C_RESERVED:
            continue
        types.append(_normalize(type_str))

    return types


def _extract_param_type(arg: str) -> str:
    """Bir parametre stringinden tip kismini cikar.

    'int buffer' -> 'int', 'undefined8 count' -> 'undefined8', 'char *s' -> 'char'
    """
    cleaned = re.sub(r"\[[^\]]*\]", "", arg).strip()
    # "type *name" -> tokens = [type, *, name] or [type, *name]
    tokens = cleaned.rstrip(",").split()
    if not tokens:
        return ""
    # Parametre ismi son token ise tipten ayir.
    # Basit kural: tokens[:-1] tip
    if len(tokens) == 1:
        return ""
    type_part = " ".join(tokens[:-1]).replace("*", "").strip()
    if type_part in _IGNORE_TYPES:
        return ""
    return _normalize(type_part)


def _split_args(args_str: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _normalize(type_str: str) -> str:
    """'const  int' -> 'const int' normalize et."""
    return re.sub(r"\s+", " ", type_str).strip()


_IGNORE_TYPES = frozenset({
    "return", "if", "else", "while", "for", "do", "switch", "case",
    "break", "continue", "goto", "typedef", "static", "extern",
})

_C_RESERVED = frozenset({
    "return", "if", "else", "while", "for", "do", "switch", "case",
    "break", "continue", "goto", "sizeof", "typedef",
})


def _clamp01(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
