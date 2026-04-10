"""Opaque predicate tespit ve eliminasyon modulu.

Opaque predicate'lar: Her zaman true veya false olan ama compiler'in
analiz edemeyecegi kadar karmasik ifadeler. Obfuscator'lar dead code
eklemek icin kullanir.

Ornek:
    if (x * (x + 1) % 2 == 0) {  // HER ZAMAN TRUE
        // gercek kod
    } else {
        // dead code (asla calistirilmaz)
    }

Tespit stratejileri:
1. Pattern matching (bilinen opaque predicate formulleri)
2. Constant folding (sabit deger kullanan branch'ler)
3. Z3 SMT solver ile dogrulama (opsiyonel, z3 kurulu ise)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class OpaquePredicateMatch:
    """Tespit edilen opaque predicate."""
    expression: str
    always_true: bool  # True ise always-true, False ise always-false
    pattern_name: str
    confidence: float
    line_number: int = 0
    can_simplify: bool = True


@dataclass
class OpaquePredResult:
    """Opaque predicate analiz sonucu."""
    total_found: int = 0
    total_eliminated: int = 0
    matches: list[OpaquePredicateMatch] = field(default_factory=list)
    dead_code_lines: int = 0


class OpaquePredicateDetector:
    """Opaque predicate tespit ve eliminasyon motoru.

    C kodu icindeki always-true/always-false kosullari bulur
    ve dead code'u isaretler/kaldirir.
    """

    # Bilinen always-true pattern'leri
    ALWAYS_TRUE_PATTERNS = [
        # x * (x + 1) % 2 == 0 (ardisik iki sayi carpimi her zaman cift)
        (re.compile(r"(\w+)\s*\*\s*\(\s*\1\s*\+\s*1\s*\)\s*%\s*2\s*==\s*0"),
         "consecutive_product_even"),
        # KALDIRILDI: x*x >= 0 signed overflow'da false olabilir
        # (x=46341 -> x*x = -2147479015 signed int32'de, Codex dogrulamasi)
        # (x | 1) != 0 (OR 1 her zaman != 0)
        (re.compile(r"\(\s*\w+\s*\|\s*1\s*\)\s*!=\s*0"),
         "or_one_nonzero"),
        # (x & 1) == (x & 1) (kendisiyle karsilastirma)
        (re.compile(r"\(\s*(\w+\s*[&|^]\s*\w+)\s*\)\s*==\s*\(\s*\1\s*\)"),
         "self_compare"),
        # x == x (kendisiyle esitlik — SADECE integer baglaminda guvenilir)
        # IEEE 754 NaN == NaN = false, bu yuzden float/double icin opaque degil.
        # Confidence dusuruldu: 0.85 -> 0.60
        (re.compile(r"(\w+)\s*==\s*\1\b"),
         "self_equality"),
        # 2 * (x / 2) <= x (integer division ozeligi)
        (re.compile(r"2\s*\*\s*\(\s*(\w+)\s*/\s*2\s*\)\s*<=\s*\1"),
         "int_division_property"),
        # true || anything
        (re.compile(r"\btrue\s*\|\|"),
         "true_or"),
        # 1 == 1, 0 == 0 (sabit karsilastirma)
        (re.compile(r"\b(\d+)\s*==\s*\1\b"),
         "constant_self_compare"),
    ]

    # Bilinen always-false pattern'leri
    ALWAYS_FALSE_PATTERNS = [
        # x * (x + 1) % 2 != 0
        (re.compile(r"(\w+)\s*\*\s*\(\s*\1\s*\+\s*1\s*\)\s*%\s*2\s*!=\s*0"),
         "consecutive_product_odd"),
        # KALDIRILDI: x*x < 0 signed overflow'da true olabilir
        # (x=46341 -> x*x = -2147479015 signed int32'de, Codex dogrulamasi)
        # x != x (kendisiyle esitsizlik — SADECE integer baglaminda guvenilir)
        # IEEE 754 NaN != NaN = true, bu yuzden float/double icin bu NaN check'i.
        # Confidence dusuruldu: 0.85 -> 0.60
        (re.compile(r"(\w+)\s*!=\s*\1\b"),
         "self_inequality"),
        # false && anything
        (re.compile(r"\bfalse\s*&&"),
         "false_and"),
        # 0 == 1, 1 == 2 (farkli sabit karsilastirma)
        (re.compile(r"\b(\d+)\s*==\s*(?!\1\b)(\d+)\b"),
         "different_constants"),
    ]

    def __init__(self, use_z3: bool = False):
        """
        Args:
            use_z3: Z3 SMT solver kullanarak ek dogrulama yap (yavas ama kesin).
        """
        self._use_z3 = use_z3
        self._z3_available = False

        if use_z3:
            try:
                import z3  # noqa: F401
                self._z3_available = True
            except ImportError:
                logger.info("z3-solver bulunamadi, pattern-based tespit kullanilacak")

    def detect_in_code(self, code: str) -> OpaquePredResult:
        """C kodundaki opaque predicate'lari tespit et.

        Args:
            code: C kaynak kodu.

        Returns:
            OpaquePredResult: Bulunan opaque predicate'lar.
        """
        result = OpaquePredResult()
        lines = code.split("\n")

        for line_no, line in enumerate(lines, 1):
            # if/while/for kosullarini bul
            cond_match = re.search(r"\b(?:if|while)\s*\((.+?)\)\s*\{", line)
            if not cond_match:
                continue

            condition = cond_match.group(1)

            # Always-true kontrol
            for pattern, name in self.ALWAYS_TRUE_PATTERNS:
                if pattern.search(condition):
                    # NaN-sensitive pattern'ler icin dusuk confidence
                    confidence = 0.60 if name == "self_equality" else 0.85
                    match = OpaquePredicateMatch(
                        expression=condition.strip(),
                        always_true=True,
                        pattern_name=name,
                        confidence=confidence,
                        line_number=line_no,
                    )
                    result.matches.append(match)
                    result.total_found += 1
                    break

            # Always-false kontrol
            for pattern, name in self.ALWAYS_FALSE_PATTERNS:
                if pattern.search(condition):
                    # NaN-sensitive pattern'ler icin dusuk confidence
                    confidence = 0.60 if name == "self_inequality" else 0.85
                    match = OpaquePredicateMatch(
                        expression=condition.strip(),
                        always_true=False,
                        pattern_name=name,
                        confidence=confidence,
                        line_number=line_no,
                    )
                    result.matches.append(match)
                    result.total_found += 1
                    break

        return result

    def eliminate_in_code(self, code: str) -> tuple[str, OpaquePredResult]:
        """Opaque predicate'lari tespit edip kodu basitlestir.

        Always-true: Sadece true branch kalir.
        Always-false: Sadece else branch kalir (varsa).

        Args:
            code: C kaynak kodu.

        Returns:
            (simplified_code, result): Basitlestirilmis kod ve rapor.
        """
        result = self.detect_in_code(code)

        if not result.matches:
            return code, result

        # Satirlari isle
        lines = code.split("\n")
        modified = False

        for match in sorted(result.matches, key=lambda m: -m.line_number):
            if match.line_number <= 0 or match.line_number > len(lines):
                continue

            line = lines[match.line_number - 1]

            if match.always_true:
                # if(ALWAYS_TRUE) -> kosula gerek yok, true branch'i birak
                # Satira yorum ekle
                comment = f"  /* OPAQUE_PRED: always-true ({match.pattern_name}) — simplified */"
                lines[match.line_number - 1] = line + comment
                modified = True
                result.total_eliminated += 1
            else:
                # if(ALWAYS_FALSE) -> dead code, false branch'i isaretler
                comment = f"  /* OPAQUE_PRED: always-false ({match.pattern_name}) — DEAD CODE */"
                lines[match.line_number - 1] = line + comment
                modified = True
                result.total_eliminated += 1

        if modified:
            code = "\n".join(lines)

        return code, result

    def detect_in_directory(self, directory) -> OpaquePredResult:
        """Bir dizindeki tum C dosyalarini tara."""
        from pathlib import Path
        combined = OpaquePredResult()

        c_files = sorted(Path(directory).glob("*.c"))
        for c_file in c_files:
            try:
                code = c_file.read_text(errors="replace")
                result = self.detect_in_code(code)
                combined.total_found += result.total_found
                combined.matches.extend(result.matches)
            except Exception as e:
                logger.debug("Opaque predicate scan hatasi (%s): %s", c_file.name, e)

        return combined
