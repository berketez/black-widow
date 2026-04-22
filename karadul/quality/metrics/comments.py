"""Boyut 5: Yorum yogunlugu skor metric'i.

Formul:
    min(100, (comment_lines / function_count) / COMMENT_IDEAL_RATIO * 100)

Varsayilan ideal oran 2.0 -- fonksiyon basina 2 satir yorum %100 verir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source


@dataclass
class CommentsResult:
    score: float
    details: dict[str, Any]


class CommentsMetric:
    """Yorum yogunlugu metric."""

    name: str = "comments"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> CommentsResult:
        total_comment_lines = 0
        total_functions = 0

        for path in c_files:
            comment_lines, func_count = _analyze_file(path, file_cache)
            total_comment_lines += comment_lines
            total_functions += func_count

        if total_functions == 0:
            return CommentsResult(
                score=0.0,
                details={
                    "comment_lines": total_comment_lines,
                    "function_count": 0,
                    "note": "Fonksiyon bulunamadi",
                },
            )

        ratio = total_comment_lines / total_functions
        # Ideal orana gore normalize
        score_val = min(100.0, (ratio / self.config.comment_ideal_ratio) * 100.0)

        return CommentsResult(
            score=_clamp01(score_val),
            details={
                "comment_lines": total_comment_lines,
                "function_count": total_functions,
                "ratio_per_function": round(ratio, 4),
                "ideal_ratio": self.config.comment_ideal_ratio,
            },
        )


# ---------------------------------------------------------------------------
# Yorum ve fonksiyon sayici
# ---------------------------------------------------------------------------

_RE_LINE_COMMENT = re.compile(r"//[^\n]*")
_RE_BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.DOTALL)
_RE_FUNC_DEF = re.compile(
    r"^[\w\s\*]+?\s+\w+\s*\([^;{]*\)\s*\{",
    re.MULTILINE,
)


def _analyze_file(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> tuple[int, int]:
    """Bir dosya icin (yorum_satiri_sayisi, fonksiyon_sayisi) dondur.

    v1.10.0 C2: ``file_cache`` varsa disk I/O atlanir.
    """
    source = _read_source(path, file_cache)
    if source is None:
        return (0, 0)

    comment_lines = 0
    for match in _RE_BLOCK_COMMENT.finditer(source):
        # Blok yorumda kac satir var?
        content = match.group(0)
        comment_lines += content.count("\n") + 1

    # Tek satir yorumlar
    # Not: block yorum icindeki // sayilmamali. Once blok yorumlari cikar.
    source_no_block = _RE_BLOCK_COMMENT.sub(" ", source)
    comment_lines += len(_RE_LINE_COMMENT.findall(source_no_block))

    # Fonksiyon sayisi
    func_count = len(_RE_FUNC_DEF.findall(source))

    return (comment_lines, func_count)


def _clamp01(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
