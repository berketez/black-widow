"""Basit tip cikarimi -- JSDoc yorumlari uret.

Heuristic-based tip cikarimi: degisken ve fonksiyon isimlerinden
tip bilgisi cikartir ve JSDoc yorumlari olarak dosyaya ekler.

Babel AST kullanmadan regex bazli analiz yapar (hafif, hizli).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from karadul.config import Config

logger = logging.getLogger(__name__)


@dataclass
class InferResult:
    """Tip cikarimi sonucu.

    Attributes:
        success: Islem basarili mi.
        functions_annotated: JSDoc eklenen fonksiyon sayisi.
        type_hints: Cikarilan tip bilgileri listesi.
        output_file: Cikti dosyasi yolu.
        errors: Hata mesajlari.
    """

    success: bool
    functions_annotated: int
    type_hints: list[dict[str, str]]
    output_file: Path | None
    errors: list[str] = field(default_factory=list)


# Isim-bazli tip eslestirme
_NAME_TYPE_PATTERNS: list[tuple[re.Pattern, str | None]] = [
    # Boolean
    (re.compile(r"^is[A-Z]"), "boolean"),
    (re.compile(r"^has[A-Z]"), "boolean"),
    (re.compile(r"^can[A-Z]"), "boolean"),
    (re.compile(r"^should[A-Z]"), "boolean"),
    (re.compile(r"^will[A-Z]"), "boolean"),
    (re.compile(r"^was[A-Z]"), "boolean"),
    (re.compile(r"^did[A-Z]"), "boolean"),
    (re.compile(r"^(enabled|disabled|visible|hidden|active|valid|ready|done|loading|open|closed)$"), "boolean"),
    # Number
    (re.compile(r"^(count|num|total|length|size|width|height|index|offset|max|min|limit|port|timeout|delay|duration|age|id)$", re.IGNORECASE), "number"),
    (re.compile(r"^count[A-Z]"), "number"),
    (re.compile(r"^num[A-Z]"), "number"),
    (re.compile(r"^(len|idx|pos)[A-Z]?"), "number"),
    (re.compile(r"(Count|Num|Total|Length|Size|Width|Height|Index|Offset)$"), "number"),
    # Function
    (re.compile(r"^on[A-Z]"), "Function"),
    (re.compile(r"^handle[A-Z]"), "Function"),
    (re.compile(r"(Callback|Handler|Listener|Fn)$"), "Function"),
    # Promise
    (re.compile(r"^(get|fetch|load|request|find|search|query)[A-Z]"), "Promise"),
    # Array
    (re.compile(r"(List|Array|Items|Elements|Entries|Records|Rows|Results)$"), "Array"),
    (re.compile(r"s$"), None),  # Cogul isimler -- spesifik degilse skip
    # Map/Set/Object
    (re.compile(r"(Map|Cache|Dict|Store|Registry)$"), "Object"),
    (re.compile(r"(Set)$"), "Set"),
    # Error
    (re.compile(r"^(err|error|ex|exception)$", re.IGNORECASE), "Error"),
    # Request/Response
    (re.compile(r"^(req|request)$", re.IGNORECASE), "Request"),
    (re.compile(r"^(res|response)$", re.IGNORECASE), "Response"),
    # String
    (re.compile(r"^(name|label|title|text|message|description|path|url|key|value|type|className|content|html|json|query|token|prefix|suffix|pattern|template|format|encoding|charset)$", re.IGNORECASE), "string"),
    (re.compile(r"(Name|Label|Title|Text|Message|Description|Path|Url|Key|Type)$"), "string"),
]

# Return statement pattern'leri
_RETURN_TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"return\s+true|return\s+false"), "boolean"),
    (re.compile(r"return\s+\d+"), "number"),
    (re.compile(r'return\s+["\']'), "string"),
    (re.compile(r'return\s+`'), "string"),
    (re.compile(r"return\s+\["), "Array"),
    (re.compile(r"return\s+\{"), "Object"),
    (re.compile(r"return\s+new\s+Promise"), "Promise"),
    (re.compile(r"return\s+null"), "null"),
    (re.compile(r"return\s+undefined"), "void"),
]

# Fonksiyon tespiti regex (kullanilmiyor, _match_function inline regex kullanir)
# _FUNCTION_PATTERN is handled inline in _match_function method

# Parametre cikarimi
_PARAM_PATTERN = re.compile(
    r"(?:function\s+\w*\s*|=>\s*)\(([^)]*)\)|"
    r"\(([^)]*)\)\s*(?:=>|\{)",
)


class TypeInferrer:
    """Basit tip cikarimi -- JSDoc yorumlari uret.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def infer(self, input_file: Path, output_file: Path) -> InferResult:
        """Dosyadaki fonksiyonlara JSDoc tip yorumlari ekle.

        Args:
            input_file: Girdi JS dosyasi.
            output_file: JSDoc yorumlari eklenmis cikti dosyasi.

        Returns:
            InferResult: Sonuc.
        """
        if not input_file.exists():
            return InferResult(
                success=False,
                functions_annotated=0,
                type_hints=[],
                output_file=None,
                errors=[f"Girdi dosyasi bulunamadi: {input_file}"],
            )

        try:
            content = input_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return InferResult(
                success=False,
                functions_annotated=0,
                type_hints=[],
                output_file=None,
                errors=[f"Dosya okunamadi: {exc}"],
            )

        lines = content.split("\n")
        insertions: list[tuple[int, str]] = []  # (satir_no, jsdoc_text)
        type_hints: list[dict[str, str]] = []
        functions_annotated = 0

        for i, line in enumerate(lines):
            # Zaten JSDoc var mi?
            if i > 0 and lines[i - 1].strip().endswith("*/"):
                continue

            func_match = self._match_function(line)
            if not func_match:
                continue

            indent, func_name = func_match

            # Parametre cikar
            params = self._extract_params(line, lines, i)

            # Return type cikar (fonksiyon body'sine bak)
            return_type = self._infer_return_type(lines, i)

            # JSDoc olustur
            jsdoc = self._build_jsdoc(indent, func_name, params, return_type)

            if jsdoc:
                insertions.append((i, jsdoc))
                functions_annotated += 1

                hint = {"function": func_name}
                for pname, ptype in params:
                    hint[f"param_{pname}"] = ptype
                if return_type:
                    hint["returns"] = return_type
                type_hints.append(hint)

        # Ekleme yap (sondan basa, satir numaralari kaymaz)
        for line_no, jsdoc_text in reversed(insertions):
            lines.insert(line_no, jsdoc_text)

        # Cikti yaz
        try:
            output_file.write_text("\n".join(lines), encoding="utf-8")
        except OSError as exc:
            return InferResult(
                success=False,
                functions_annotated=functions_annotated,
                type_hints=type_hints,
                output_file=None,
                errors=[f"Cikti yazilamadi: {exc}"],
            )

        logger.info(
            "Type inference: %d fonksiyona JSDoc eklendi", functions_annotated,
        )

        return InferResult(
            success=True,
            functions_annotated=functions_annotated,
            type_hints=type_hints,
            output_file=output_file,
        )

    @staticmethod
    def _match_function(line: str) -> tuple[str, str] | None:
        """Satirda fonksiyon tanimlama var mi kontrol et.

        Returns:
            (indent, fonksiyon_adi) veya None.
        """
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]

        # function name(
        match = re.match(
            r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(",
            stripped,
        )
        if match:
            return indent, match.group(1)

        # const/let/var name = function(
        match = re.match(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function",
            stripped,
        )
        if match:
            return indent, match.group(1)

        # const/let/var name = (params) => or async (params) =>
        match = re.match(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(",
            stripped,
        )
        if match:
            return indent, match.group(1)

        # name: function( or name: (params) => (object method)
        match = re.match(
            r"(\w+)\s*:\s*(?:async\s+)?(?:function\s*)?\(",
            stripped,
        )
        if match:
            return indent, match.group(1)

        return None

    @staticmethod
    def _extract_params(
        line: str, lines: list[str], line_idx: int,
    ) -> list[tuple[str, str]]:
        """Fonksiyon parametrelerini ve tiplerini cikar.

        Returns:
            [(param_adi, cikarilan_tip), ...] listesi.
        """
        # Parantez icindeki parametreleri bul
        # Birden fazla satira yayilmis olabilir
        combined = line
        for offset in range(1, min(5, len(lines) - line_idx)):
            if ")" in combined:
                break
            combined += " " + lines[line_idx + offset].strip()

        match = re.search(r"\(([^)]*)\)", combined)
        if not match:
            return []

        param_str = match.group(1).strip()
        if not param_str:
            return []

        params = []
        for p in param_str.split(","):
            p = p.strip()
            if not p:
                continue

            # Destructuring: {a, b}
            if p.startswith("{") or p.startswith("["):
                params.append((p, "Object" if p.startswith("{") else "Array"))
                continue

            # Rest: ...args
            if p.startswith("..."):
                p = p[3:].strip()
                params.append((p, "Array"))
                continue

            # Default value: x = 5
            if "=" in p:
                name_part = p.split("=")[0].strip()
                default_part = p.split("=")[1].strip()
                inferred = TypeInferrer._infer_type_from_name(name_part)
                if not inferred:
                    inferred = TypeInferrer._infer_type_from_value(default_part)
                params.append((name_part, inferred or "*"))
                continue

            # Normal parametre
            inferred = TypeInferrer._infer_type_from_name(p)
            params.append((p, inferred or "*"))

        return params

    @staticmethod
    def _infer_type_from_name(name: str) -> str | None:
        """Degisken/parametre adi patternlerinden tip cikar."""
        for pattern, type_name in _NAME_TYPE_PATTERNS:
            if type_name is None:
                continue
            if pattern.search(name):
                return type_name
        return None

    @staticmethod
    def _infer_type_from_value(value: str) -> str | None:
        """Varsayilan deger literalinden tip cikar."""
        value = value.strip()
        if value in ("true", "false"):
            return "boolean"
        if value == "null":
            return "null"
        if value == "undefined":
            return "void"
        if value.startswith(("'", '"', "`")):
            return "string"
        if value.startswith("["):
            return "Array"
        if value.startswith("{"):
            return "Object"
        try:
            float(value)
            return "number"
        except ValueError:
            pass
        return None

    def _infer_return_type(
        self, lines: list[str], func_start: int,
    ) -> str | None:
        """Fonksiyon body'sindeki return statement'lardan tip cikar.

        Fonksiyonun {} blogunun icine bakarak return tipini tahmin eder.
        """
        # async fonksiyon -> Promise
        if "async " in lines[func_start]:
            return "Promise"

        # Fonksiyon body'sini bul (basit heuristic: sonraki 30 satira bak)
        body = "\n".join(
            lines[func_start: min(func_start + 30, len(lines))]
        )

        for pattern, return_type in _RETURN_TYPE_PATTERNS:
            if pattern.search(body):
                return return_type

        return None

    @staticmethod
    def _build_jsdoc(
        indent: str,
        func_name: str,
        params: list[tuple[str, str]],
        return_type: str | None,
    ) -> str:
        """JSDoc comment blogu olustur.

        Args:
            indent: Indentation string'i.
            func_name: Fonksiyon adi.
            params: Parametre (isim, tip) listesi.
            return_type: Return tipi (varsa).

        Returns:
            JSDoc comment string'i.
        """
        lines = [f"{indent}/**"]

        # Fonksiyon aciklamasi (camelCase parse)
        description = TypeInferrer._name_to_description(func_name)
        if description:
            lines.append(f"{indent} * {description}")

        if params or return_type:
            lines.append(f"{indent} *")

        for pname, ptype in params:
            lines.append(f"{indent} * @param {{{ptype}}} {pname}")

        if return_type:
            lines.append(f"{indent} * @returns {{{return_type}}}")

        lines.append(f"{indent} */")
        return "\n".join(lines)

    @staticmethod
    def _name_to_description(name: str) -> str:
        """camelCase fonksiyon adini aciklamaya donustur.

        Ornek: handleUserClick -> Handle user click
        """
        if not name or name.startswith("<"):
            return ""

        # camelCase split
        words = re.sub(r"([A-Z])", r" \1", name).strip().split()
        if not words:
            return ""

        # Ilk harfi buyut, gerisi kucuk
        result = words[0].capitalize()
        for w in words[1:]:
            result += " " + w.lower()

        return result + "."
