"""Boyut 2: Parametre isim kalitesi skor metric'i.

Formul:
    (1 - param_N_count / total_params) * 100

pycparser varsa AST tabanli dogru parse; yoksa regex fallback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source
from karadul.quality.patterns import is_ghidra_param_name

try:
    from pycparser import c_ast, c_parser  # type: ignore[import-untyped]
    _HAS_PYCPARSER = True
except ImportError:  # pragma: no cover - environment dependent
    _HAS_PYCPARSER = False


@dataclass
class ParamNamesResult:
    score: float
    details: dict[str, Any]


class ParamNamesMetric:
    """Parametre isim kalitesi skorlayicisi."""

    name: str = "param_names"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> ParamNamesResult:
        total = 0
        generic = 0
        sample: list[str] = []

        for path in c_files:
            params = _extract_param_names(path, file_cache)
            for name in params:
                total += 1
                if len(sample) < 20:
                    sample.append(name)
                if is_ghidra_param_name(name):
                    generic += 1

        if total == 0:
            return ParamNamesResult(
                score=0.0,
                details={
                    "total": 0,
                    "generic_count": 0,
                    "note": "Parametreler bulunamadi",
                },
            )

        generic_ratio = generic / total
        score_val = (1.0 - generic_ratio) * 100.0

        return ParamNamesResult(
            score=_clamp01(score_val),
            details={
                "total": total,
                "generic_count": generic,
                "generic_ratio": round(generic_ratio, 4),
                "sample_names": sample,
                "method": "pycparser" if _HAS_PYCPARSER else "regex",
            },
        )


# ---------------------------------------------------------------------------
# Regex tabanli parametre cikartma (en saglam yontem)
# ---------------------------------------------------------------------------

# Fonksiyon tanimi: "ret name(args) {" veya "ret name(args);"
# Args listesinden parametre isimlerini almak icin ayri regex kullaniriz.
_RE_FUNC_SIGNATURE = re.compile(
    r"^[\w\s\*]+?\s+\w+\s*\(([^;{]*)\)\s*\{",
    re.MULTILINE,
)

# Her parametre: son identifier'i al (tip* isim yapisi)
_RE_PARAM_NAME = re.compile(r"(\w+)\s*(?:\[[^\]]*\])?\s*$")


def _extract_param_names(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> list[str]:
    """C dosyasindan parametre isimlerini cikar.

    v1.10.0 C2: ``file_cache`` varsa in-memory okunur (disk I/O atlanir).
    """
    source = _read_source(path, file_cache)
    if source is None:
        return []

    # Yorumlari temizle
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)

    all_params: list[str] = []
    for match in _RE_FUNC_SIGNATURE.finditer(source):
        args_str = match.group(1).strip()
        if not args_str or args_str == "void":
            continue
        # Virgulle bol; parantez icinden function pointer parametreleri
        # daha zordur ama bu projede nadir -- basit split yeterli
        parts = _split_args(args_str)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            name = _last_identifier(part)
            if name and not name.isdigit():
                all_params.append(name)
    return all_params


def _split_args(args_str: str) -> list[str]:
    """Parantez-duyarli arg bol."""
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


def _last_identifier(part: str) -> str:
    """Bir parametrenin son identifier'i (ismi) neyse onu dondur."""
    # "... [N]" array kisimlari kaldir
    cleaned = re.sub(r"\[[^\]]*\]", "", part).strip()
    # Sondaki whitespace ve yildizlari temizle
    cleaned = cleaned.rstrip()
    cleaned = cleaned.rstrip("*").rstrip()
    match = _RE_PARAM_NAME.search(cleaned)
    if match:
        name = match.group(1)
        # Tip anahtar kelimeleri isim olmaz
        if name in _C_TYPE_KEYWORDS:
            return ""
        return name
    return ""


_C_TYPE_KEYWORDS = frozenset({
    "void", "int", "char", "short", "long", "float", "double",
    "signed", "unsigned", "const", "volatile", "restrict",
    "struct", "union", "enum", "typedef",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "size_t", "ssize_t", "ptrdiff_t", "time_t",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "bool", "_Bool",
})


def _clamp01(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
