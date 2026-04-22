"""Boyut 3: Lokal degisken isim kalitesi skor metric'i.

Formul:
    (1 - (iVar+lVar+uVar+piVar+local_N)/total_locals) * 100
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from karadul.quality.config import ScorerConfig
from karadul.quality.metrics._source_reader import read_source as _read_source
from karadul.quality.patterns import is_ghidra_local_name


@dataclass
class LocalVarsResult:
    score: float
    details: dict[str, Any]


class LocalVarsMetric:
    """Lokal degisken kalitesi metric."""

    name: str = "local_vars"

    def __init__(self, config: ScorerConfig | None = None) -> None:
        self.config = config or ScorerConfig()

    def score(
        self,
        c_files: list[Path],
        file_cache: dict[str, str] | None = None,
    ) -> LocalVarsResult:
        total = 0
        generic = 0
        sample: list[str] = []

        for path in c_files:
            locals_ = _extract_local_vars(path, file_cache)
            for name in locals_:
                total += 1
                if len(sample) < 20:
                    sample.append(name)
                if is_ghidra_local_name(name):
                    generic += 1

        if total == 0:
            return LocalVarsResult(
                score=0.0,
                details={
                    "total": 0,
                    "generic_count": 0,
                    "note": "Lokal degisken bulunamadi",
                },
            )

        generic_ratio = generic / total
        score_val = (1.0 - generic_ratio) * 100.0

        return LocalVarsResult(
            score=_clamp01(score_val),
            details={
                "total": total,
                "generic_count": generic,
                "generic_ratio": round(generic_ratio, 4),
                "sample_names": sample,
            },
        )


# ---------------------------------------------------------------------------
# Lokal degisken cikartma
# ---------------------------------------------------------------------------

# Fonksiyon govdesini kabaca bul, icindeki bildirileri cek.
# Decompiled kodda genelde sadeleştirilmis deklaratorler: "<type> <name>;"
# Ornekler:
#   int iVar1;
#   undefined8 uVar3;
#   char *pcVar2;
#   long local_28;
#   int user_count = 0;
_RE_FUNC_BODY = re.compile(
    r"(?P<head>^[\w\s\*]+?\s+\w+\s*\([^;{]*\)\s*\{)(?P<body>.*?)(?=^\})",
    re.MULTILINE | re.DOTALL,
)

# Bir satirlik deklaratorr: "type name;" veya "type name = expr;"
# Tip ve isim tek kelime; pointer '*' olabilir. Birden fazla bildirim yapilan
# satirlar (virgul) icin ayri yakala.
_RE_DECL_LINE = re.compile(
    r"^\s*(?P<type>(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s*\*+)?)\s+"
    r"(?P<names>\*?\s*[A-Za-z_][A-Za-z0-9_,\s\*\=\[\]\(\)\.\-\+]*);",
    re.MULTILINE,
)

# Isim listesi: virgulle ayri + default value expressions
_RE_NAME_ONLY = re.compile(r"^\s*\*?\s*([A-Za-z_][A-Za-z0-9_]*)")


def _extract_local_vars(
    path: Path,
    file_cache: dict[str, str] | None = None,
) -> list[str]:
    """C dosyasindaki fonksiyon govdelerinden lokal degisken isimlerini cikar.

    v1.10.0 C2: ``file_cache`` varsa in-memory okunur.
    """
    source = _read_source(path, file_cache)
    if source is None:
        return []

    # Yorumlari temizle
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", " ", source)

    all_locals: list[str] = []
    for func_match in _RE_FUNC_BODY.finditer(source):
        body = func_match.group("body")
        # Alt scope'lar olabilir, basit: tum deklaratorleri al
        for decl_match in _RE_DECL_LINE.finditer(body):
            type_str = decl_match.group("type").strip()
            names_str = decl_match.group("names")

            # Tip tek kelime mi? (statement olmamali)
            if type_str in _STATEMENT_KEYWORDS:
                continue

            # Control-flow gibi sahte eslesmeleri ele
            if _looks_like_statement(type_str):
                continue

            for part in names_str.split(","):
                part = part.strip()
                if not part or "=" in part:
                    # Atama varsa isim kismini ayir
                    part = part.split("=", 1)[0].strip()
                if not part:
                    continue
                name_match = _RE_NAME_ONLY.search(part)
                if name_match:
                    name = name_match.group(1)
                    if name in _C_KEYWORDS:
                        continue
                    all_locals.append(name)

    return all_locals


_STATEMENT_KEYWORDS = frozenset({
    "return", "if", "else", "while", "for", "do", "switch",
    "case", "break", "continue", "goto", "sizeof", "typedef",
})

_C_KEYWORDS = _STATEMENT_KEYWORDS | frozenset({
    "void", "int", "char", "short", "long", "float", "double",
    "signed", "unsigned", "const", "volatile", "restrict",
    "struct", "union", "enum", "register", "static", "auto",
    "extern", "inline",
})


def _looks_like_statement(type_str: str) -> bool:
    """Tip gibi gorunen ama aslinda statement olan kaliplari tespit et.

    Ornek: "return value" `type_str` olarak "return value" olur;
    icinde statement keyword varsa ele.
    """
    tokens = type_str.split()
    for tok in tokens:
        if tok in _STATEMENT_KEYWORDS:
            return True
    return False


def _clamp01(score: float) -> float:
    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return float(score)
