"""Boyut 6: Kod yapisi skor metric'i.

Formul:
    100 - min(100, avg_nesting*NESTING_PENALTY_PER_LEVEL
                   + goto_count*GOTO_PENALTY
                   + func_len_penalty)

Kod ne kadar derin nested, ne kadar goto, fonksiyonlar ne kadar
uzunsa skor o kadar dusuk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source


@dataclass
class CodeStructureResult:
    score: float
    details: dict[str, Any]


class CodeStructureMetric:
    """Kod yapisi (nesting/goto/uzunluk) metric."""

    name: str = "code_structure"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> CodeStructureResult:
        nesting_values: list[int] = []
        goto_count = 0
        func_lengths: list[int] = []

        for path in c_files:
            metrics = _analyze_file(path, file_cache)
            nesting_values.extend(metrics["nesting"])
            goto_count += metrics["goto_count"]
            func_lengths.extend(metrics["func_lengths"])

        if not nesting_values:
            # Hicbir fonksiyon bulunamadi -> olculecek yapi yok,
            # skor 0 dondur ki toplam agirlikli skor da yanlis yuksek cikmasin.
            return CodeStructureResult(
                score=0.0,
                details={
                    "avg_nesting": 0,
                    "goto_count": goto_count,
                    "func_count": 0,
                    "note": "Fonksiyon bulunamadi",
                },
            )

        avg_nesting = sum(nesting_values) / len(nesting_values)
        max_nesting = max(nesting_values)
        avg_func_len = sum(func_lengths) / len(func_lengths) if func_lengths else 0

        # Fonksiyon uzunluk cezasi: ortalama uzunluk soft_limit alti ise 0
        #   soft ile hard arasinda linearly dogru artar, hard'ta max ceza
        func_len_penalty = _compute_func_len_penalty(
            avg_func_len,
            soft=self.config.func_len_soft_limit,
            hard=self.config.func_len_hard_limit,
            max_penalty=self.config.func_len_max_penalty,
        )

        penalty = (
            avg_nesting * self.config.nesting_penalty_per_level
            + goto_count * self.config.goto_penalty
            + func_len_penalty
        )
        penalty = min(100.0, penalty)
        score_val = 100.0 - penalty

        return CodeStructureResult(
            score=_clamp01(score_val),
            details={
                "avg_nesting": round(avg_nesting, 2),
                "max_nesting": max_nesting,
                "goto_count": goto_count,
                "func_count": len(func_lengths),
                "avg_func_len": round(avg_func_len, 2),
                "func_len_penalty": round(func_len_penalty, 2),
                "total_penalty": round(penalty, 2),
            },
        )


# ---------------------------------------------------------------------------
# Per-fonksiyon CFG analizi
# ---------------------------------------------------------------------------

# Fonksiyon imzasi **satir basindan** baslar (iç içe for/if degil!)
# Dosya basi veya \n sonrasi, bosluk/tab olmadan tip gelir.
_RE_FUNC_BODY = re.compile(
    r"(?:^|\n)(?!\s)"                     # satir basi, indent yok
    r"(?!return\b|if\b|else\b|while\b|for\b|do\b|switch\b|goto\b)"  # statement degil
    r"[A-Za-z_][\w\s\*]*?\s+\w+\s*\([^;{]*\)\s*\{",
)


def _analyze_file(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Bir dosyadaki fonksiyonlar icin metric topla.

    v1.10.0 C2: ``file_cache`` varsa disk I/O atlanir.
    """
    source = _read_source(path, file_cache)
    if source is None:
        return {"nesting": [], "goto_count": 0, "func_lengths": []}

    # Yorumlari temizle
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)

    functions = _split_functions(source)

    nesting_values: list[int] = []
    goto_count = 0
    func_lengths: list[int] = []

    for body in functions:
        nesting_values.append(_max_nesting_depth(body))
        goto_count += _count_gotos(body)
        func_lengths.append(body.count("\n") + 1)

    return {
        "nesting": nesting_values,
        "goto_count": goto_count,
        "func_lengths": func_lengths,
    }


def _split_functions(source: str) -> list[str]:
    """Kabaca fonksiyon govdelerini dondur.

    Imzanin '{' ini bul, brace-balanced escape ile sonuna kadar git.
    """
    results: list[str] = []
    for match in _RE_FUNC_BODY.finditer(source):
        start = match.end() - 1  # '{' karakterini kapsa
        body = _extract_braced(source, start)
        if body:
            results.append(body)
    return results


def _extract_braced(source: str, start: int) -> str:
    """source[start] '{' olmali; eslesen '}' a kadar govdeyi dondur.

    Basit state machine -- string ve char literal icindeki brace sayilmaz.
    """
    if start >= len(source) or source[start] != "{":
        return ""
    depth = 0
    i = start
    in_string = False
    in_char = False
    escape = False
    while i < len(source):
        ch = source[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\":
            escape = True
            i += 1
            continue
        if in_string:
            if ch == '"':
                in_string = False
        elif in_char:
            if ch == "'":
                in_char = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "'":
                in_char = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        i += 1
    return source[start:]


def _max_nesting_depth(body: str) -> int:
    """Bir fonksiyon govdesindeki maksimum brace derinligi.

    Govde zaten '{' ile baslar. Max derinlik = en derin ic scope.
    """
    depth = 0
    max_depth = 0
    in_string = False
    in_char = False
    escape = False
    for ch in body:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_string:
            if ch == '"':
                in_string = False
            continue
        if in_char:
            if ch == "'":
                in_char = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "'":
            in_char = True
        elif ch == "{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == "}":
            depth -= 1
    # Ilk '{' fonksiyon seviyesidir; nesting onun uzerine sayilir.
    return max(0, max_depth - 1)


_RE_GOTO = re.compile(r"\bgoto\s+\w+\s*;")


def _count_gotos(body: str) -> int:
    return len(_RE_GOTO.findall(body))


def _compute_func_len_penalty(
    avg_len: float, soft: int, hard: int, max_penalty: float,
) -> float:
    """Ortalama fonksiyon uzunlugundan ceza hesapla.

    avg_len <= soft: ceza 0
    avg_len >= hard: ceza max_penalty
    aradaysa: linear interpolation
    """
    if avg_len <= soft:
        return 0.0
    if avg_len >= hard:
        return max_penalty
    # Linear
    fraction = (avg_len - soft) / (hard - soft)
    return max_penalty * fraction


def _clamp01(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
