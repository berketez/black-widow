"""Compiler inline fonksiyon tespiti -- decompiled C kodunda.

Ghidra gibi decompiler'lar ciktisinda compiler'in inline ettigi
standart kutuphane fonksiyonlari orijinal isimleriyle gorunmez.
Ornegin abs() cagrisi yerine `if (x < 0) x = -x;` seklinde acilir.

Bu modul bilinen inline pattern'leri regex ile tespit eder ve
decompiled koda yorum olarak ekler:
    /* INLINE: abs() */
    if (x < 0) x = -x;

Desteklenen pattern'ler:
- abs() -- branchless ve branch varyantlari
- strlen() -- pointer-walk loop
- memcpy() -- kucuk boyut dogrudan atama
- min/max -- ternary operator ile
- swap -- tmp degisken ile
- bswap -- endian byte-swap (32/16 bit)
- memset -- tekrar eden atama / loop
- strcmp -- karakter karsilastirma loop
- popcount -- bit sayma
- clz/ctz -- leading/trailing zero sayma
- isalpha/isdigit -- karakter sinif kontrolu
- rol/ror -- bit rotation
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class InlineMatch:
    """Tespit edilen tek bir inline fonksiyon eslesmesi.

    Attributes:
        function_name: Inline edilen fonksiyon adi (orn. "abs").
        category: Kategori -- arithmetic, string, memory, bitwise.
        confidence: Guven skoru 0.0-1.0.
        pattern_name: Hangi pattern eslesti.
        matched_text: Eslesen kod parcasi.
        line_number: Kodda kacinci satirda bulundu (0-based).
        replacement_hint: Onerilecek fonksiyon cagrisi.
    """

    function_name: str
    category: str
    confidence: float
    pattern_name: str
    matched_text: str
    line_number: int
    replacement_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "category": self.category,
            "confidence": self.confidence,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
            "line_number": self.line_number,
            "replacement_hint": self.replacement_hint,
        }


@dataclass
class InlineDetectionResult:
    """Tum inline tespit sonucu.

    Attributes:
        success: Islem basarili mi.
        matches: Bulunan inline eslesmeler.
        total_detected: Toplam tespit sayisi.
        by_category: Kategoriye gore dagilim.
        annotated_code: Yorum eklenilmis C kodu (annotate_code sonrasi).
        errors: Hata mesajlari.
    """

    success: bool = False
    matches: list[InlineMatch] = field(default_factory=list)
    total_detected: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    annotated_code: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "matches": [m.to_dict() for m in self.matches],
            "total_detected": self.total_detected,
            "by_category": self.by_category,
            "annotated_code": self.annotated_code,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Inline pattern tanimlari
# ---------------------------------------------------------------------------

# Her pattern bir dict: name, function_name, category, confidence, regex, hint
# regex bir COMPILED pattern veya COMPILED pattern listesi.
# Eger liste ise hepsi ayni satirda/blokta olmali (multiline aramada).

_INLINE_PATTERNS: list[dict[str, Any]] = [
    # --- abs() ---
    # Branch variant: if (x < 0) x = -x;
    {
        "name": "abs_branch",
        "function_name": "abs",
        "category": "arithmetic",
        "confidence": 0.90,
        "regex": re.compile(
            r"if\s*\(\s*(\w+)\s*<\s*0\s*\)\s*\1\s*=\s*-\s*\1\s*;",
        ),
        "hint": "abs({var})",
    },
    # Branchless variant: (x ^ (x >> 31)) - (x >> 31)
    {
        "name": "abs_branchless",
        "function_name": "abs",
        "category": "arithmetic",
        "confidence": 0.95,
        "regex": re.compile(
            r"\(\s*(\w+)\s*\^\s*\(\s*\1\s*>>\s*31\s*\)\s*\)\s*-\s*\(\s*\1\s*>>\s*31\s*\)",
        ),
        "hint": "abs({var})",
    },
    # Ternary variant: x < 0 ? -x : x
    # v1.10.0 M8: Confidence 0.85 -> 0.60, "abs_candidate" isimi.
    # Ternary pattern cok genel -- "distance = dx < 0 ? -dx : dx" gibi
    # local variable abs'lar abs() fonksiyon cagrisi olarak yanlislikla
    # etiketleniyordu. Dusuk confidence + candidate ismi ile false
    # positive'leri downstream filtreleyebiliriz.
    {
        "name": "abs_candidate",
        "function_name": "abs",
        "category": "arithmetic",
        "confidence": 0.60,
        "regex": re.compile(
            r"(\w+)\s*<\s*0\s*\?\s*-\s*\1\s*:\s*\1",
        ),
        "hint": "abs({var})",
    },

    # --- strlen() ---
    # while (*s++) count++; veya while (*s != '\0') { s++; count++; }
    {
        "name": "strlen_loop",
        "function_name": "strlen",
        "category": "string",
        "confidence": 0.85,
        "regex": re.compile(
            r"while\s*\(\s*\*\s*(\w+)\s*(\+\+)?\s*(!= *(?:0|'\\0'))?\s*\)",
        ),
        "hint": "strlen({var})",
    },
    # for variant: for (len = 0; s[len]; len++)
    {
        "name": "strlen_for",
        "function_name": "strlen",
        "category": "string",
        "confidence": 0.80,
        "regex": re.compile(
            r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*(\w+)\s*\[\s*\1\s*\]\s*;",
        ),
        "hint": "strlen({var})",
    },

    # --- memcpy() inline (kucuk boyut) ---
    # *(uint64_t*)dst = *(uint64_t*)src;
    {
        "name": "memcpy_cast",
        "function_name": "memcpy",
        "category": "memory",
        "confidence": 0.80,
        "regex": re.compile(
            r"\*\s*\(\s*(?:uint(?:8|16|32|64)_t|int|long|char)\s*\*\s*\)\s*(\w+)"
            r"\s*=\s*\*\s*\(\s*(?:uint(?:8|16|32|64)_t|int|long|char)\s*\*\s*\)\s*(\w+)\s*;",
        ),
        "hint": "memcpy({dst}, {src}, sizeof(...))",
    },
    # dst[0] = src[0]; dst[1] = src[1]; ...
    {
        "name": "memcpy_unrolled",
        "function_name": "memcpy",
        "category": "memory",
        "confidence": 0.70,
        "regex": re.compile(
            r"(\w+)\[\s*(\d+)\s*\]\s*=\s*(\w+)\[\s*\2\s*\]\s*;",
        ),
        "hint": "memcpy({dst}, {src}, ...)",
    },

    # --- min/max ---
    # x < y ? x : y (min)
    {
        "name": "min_ternary",
        "function_name": "min",
        "category": "arithmetic",
        "confidence": 0.85,
        "regex": re.compile(
            r"(\w+)\s*<\s*(\w+)\s*\?\s*\1\s*:\s*\2",
        ),
        "hint": "min({a}, {b})",
    },
    # x > y ? x : y (max)
    {
        "name": "max_ternary",
        "function_name": "max",
        "category": "arithmetic",
        "confidence": 0.85,
        "regex": re.compile(
            r"(\w+)\s*>\s*(\w+)\s*\?\s*\1\s*:\s*\2",
        ),
        "hint": "max({a}, {b})",
    },
    # Branchless min: y ^ ((x ^ y) & -(x < y))
    {
        "name": "min_branchless",
        "function_name": "min",
        "category": "arithmetic",
        "confidence": 0.95,
        "regex": re.compile(
            r"(\w+)\s*\^\s*\(\s*\(\s*(\w+)\s*\^\s*\1\s*\)\s*&\s*-\s*\(\s*\2\s*<\s*\1\s*\)\s*\)",
        ),
        "hint": "min({a}, {b})",
    },

    # --- swap ---
    # tmp = a; a = b; b = tmp;
    {
        "name": "swap_tmp",
        "function_name": "swap",
        "category": "arithmetic",
        "confidence": 0.90,
        "regex": re.compile(
            r"(\w+)\s*=\s*(\w+)\s*;\s*\2\s*=\s*(\w+)\s*;\s*\3\s*=\s*\1\s*;",
        ),
        "hint": "swap({a}, {b})",
    },
    # XOR swap: a ^= b; b ^= a; a ^= b;
    {
        "name": "swap_xor",
        "function_name": "swap",
        "category": "arithmetic",
        "confidence": 0.90,
        "regex": re.compile(
            r"(\w+)\s*\^=\s*(\w+)\s*;\s*\2\s*\^=\s*\1\s*;\s*\1\s*\^=\s*\2\s*;",
        ),
        "hint": "swap({a}, {b}) /* XOR swap */",
    },

    # --- bswap (endian swap) ---
    # 32-bit: ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) ...
    {
        "name": "bswap32",
        "function_name": "bswap32",
        "category": "bitwise",
        "confidence": 0.95,
        "regex": re.compile(
            r"\(\s*\(\s*(\w+)\s*>>\s*24\s*\)\s*&\s*0x[fF]{0,2}[fF]{2}\s*\)"
            r"\s*\|\s*\(\s*\(\s*\1\s*>>\s*8\s*\)\s*&\s*0x[fF]{0,4}[fF]{2}00\s*\)"
            r"\s*\|\s*\(\s*\(\s*\1\s*<<\s*8\s*\)\s*&\s*0x[fF]{0,2}[fF]{2}0000\s*\)"
            r"\s*\|\s*\(\s*\(\s*\1\s*<<\s*24\s*\)",
        ),
        "hint": "__builtin_bswap32({var})",
    },
    # 16-bit bswap: (x >> 8) | (x << 8) veya ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)
    {
        "name": "bswap16",
        "function_name": "bswap16",
        "category": "bitwise",
        "confidence": 0.85,
        "regex": re.compile(
            r"\(\s*(\w+)\s*>>\s*8\s*\)\s*\|\s*\(\s*\1\s*<<\s*8\s*\)",
        ),
        "hint": "__builtin_bswap16({var})",
    },

    # --- memset inline ---
    # dst[0] = val; dst[1] = val; dst[2] = val; ...
    {
        "name": "memset_unrolled",
        "function_name": "memset",
        "category": "memory",
        "confidence": 0.70,
        "regex": re.compile(
            r"(\w+)\[\s*0\s*\]\s*=\s*(\w+)\s*;\s*\1\[\s*1\s*\]\s*=\s*\2\s*;",
        ),
        "hint": "memset({dst}, {val}, ...)",
    },

    # --- strcmp inline ---
    # while (*s1 == *s2 && *s1) { s1++; s2++; }
    {
        "name": "strcmp_loop",
        "function_name": "strcmp",
        "category": "string",
        "confidence": 0.80,
        "regex": re.compile(
            r"while\s*\(\s*\*\s*(\w+)\s*==\s*\*\s*(\w+)\s*&&\s*\*\s*\1\s*\)",
        ),
        "hint": "strcmp({s1}, {s2})",
    },

    # --- popcount (bit sayma) ---
    # x = x - ((x >> 1) & 0x55555555);  (Hamming weight ilk adimi)
    {
        "name": "popcount_hamming",
        "function_name": "popcount",
        "category": "bitwise",
        "confidence": 0.90,
        "regex": re.compile(
            r"(\w+)\s*-\s*\(\s*\(\s*\1\s*>>\s*1\s*\)\s*&\s*0x55555555\s*\)",
        ),
        "hint": "__builtin_popcount({var})",
    },

    # --- clz (count leading zeros) ---
    # Binary search pattern: if (x & 0xFFFF0000) { ... } (leading zero count)
    {
        "name": "clz_binary_search",
        "function_name": "clz",
        "category": "bitwise",
        "confidence": 0.75,
        "regex": re.compile(
            r"if\s*\(\s*(\w+)\s*&\s*0x[fF]{4}0000\s*\)",
        ),
        "hint": "__builtin_clz({var})",
    },

    # --- isalpha ---
    # (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
    {
        "name": "isalpha_range",
        "function_name": "isalpha",
        "category": "string",
        "confidence": 0.85,
        "regex": re.compile(
            r"\(\s*(\w+)\s*>=\s*'A'\s*&&\s*\1\s*<=\s*'Z'\s*\)"
            r"\s*\|\|\s*\(\s*\1\s*>=\s*'a'\s*&&\s*\1\s*<=\s*'z'\s*\)",
        ),
        "hint": "isalpha({var})",
    },

    # --- isdigit ---
    # c >= '0' && c <= '9'
    {
        "name": "isdigit_range",
        "function_name": "isdigit",
        "category": "string",
        "confidence": 0.85,
        "regex": re.compile(
            r"(\w+)\s*>=\s*'0'\s*&&\s*\1\s*<=\s*'9'",
        ),
        "hint": "isdigit({var})",
    },

    # --- rol/ror (bit rotation) ---
    # (x << n) | (x >> (32 - n))  -- rotate left
    {
        "name": "rol32",
        "function_name": "rotl32",
        "category": "bitwise",
        "confidence": 0.90,
        "regex": re.compile(
            r"\(\s*(\w+)\s*<<\s*(\w+)\s*\)\s*\|\s*\(\s*\1\s*>>\s*\(\s*32\s*-\s*\2\s*\)\s*\)",
        ),
        "hint": "__builtin_rotl32({var}, {n})",
    },
    # (x >> n) | (x << (32 - n))  -- rotate right
    {
        "name": "ror32",
        "function_name": "rotr32",
        "category": "bitwise",
        "confidence": 0.90,
        "regex": re.compile(
            r"\(\s*(\w+)\s*>>\s*(\w+)\s*\)\s*\|\s*\(\s*\1\s*<<\s*\(\s*32\s*-\s*\2\s*\)\s*\)",
        ),
        "hint": "__builtin_rotr32({var}, {n})",
    },

    # --- sign (isaret fonksiyonu) ---
    # (x > 0) - (x < 0)
    {
        "name": "sign_expr",
        "function_name": "sign",
        "category": "arithmetic",
        "confidence": 0.90,
        "regex": re.compile(
            r"\(\s*(\w+)\s*>\s*0\s*\)\s*-\s*\(\s*\1\s*<\s*0\s*\)",
        ),
        "hint": "sign({var})",
    },
]


# ---------------------------------------------------------------------------
# InlineDetector class
# ---------------------------------------------------------------------------


class InlineDetector:
    """Decompiled C kodunda compiler inline fonksiyon pattern'lerini tespit eder.

    Kullanim:
        detector = InlineDetector()
        matches = detector.detect_in_code(c_code)
        annotated = detector.annotate_code(c_code)
    """

    def __init__(self, patterns: list[dict[str, Any]] | None = None) -> None:
        """InlineDetector olustur.

        Args:
            patterns: Ozel pattern listesi. None ise varsayilan _INLINE_PATTERNS kullanilir.
        """
        self.patterns = patterns if patterns is not None else _INLINE_PATTERNS

    def detect_in_code(self, c_code: str) -> list[InlineMatch]:
        """C kodundaki inline fonksiyon pattern'lerini tespit et.

        Kodu satirlara bolup her satirda (ve komsu satirlarda) bilinen
        inline pattern'leri regex ile arar.

        Args:
            c_code: Decompiled C kaynak kodu.

        Returns:
            Bulunan InlineMatch listesi, satirlara gore sirali.
        """
        if not c_code or not c_code.strip():
            return []

        matches: list[InlineMatch] = []
        lines = c_code.split("\n")

        # Her pattern icin tum kodu tara
        for pat in self.patterns:
            regex: re.Pattern = pat["regex"]

            # Regex'i tum kod uzerinde ara (multiline icin satir birlestirmesi)
            for m in regex.finditer(c_code):
                matched_text = m.group(0).strip()

                # Satir numarasini bul
                line_number = c_code[:m.start()].count("\n")

                # Hint'teki {var} gibi placeholder'lari gercek grup degerleriyle degistir
                hint = pat["hint"]
                groups = m.groups()
                if groups:
                    # Ilk yakalanan grup genellikle degisken adi
                    g0 = groups[0] or ""
                    hint = hint.replace("{var}", g0)
                    hint = hint.replace("{dst}", g0)
                    if len(groups) > 1:
                        g1 = groups[1] or ""
                        hint = hint.replace("{src}", g1)
                        hint = hint.replace("{a}", g0)
                        hint = hint.replace("{b}", g1)
                    if len(groups) > 2:
                        g2 = groups[2] or ""
                        hint = hint.replace("{n}", g2)

                match = InlineMatch(
                    function_name=pat["function_name"],
                    category=pat["category"],
                    confidence=pat["confidence"],
                    pattern_name=pat["name"],
                    matched_text=matched_text,
                    line_number=line_number,
                    replacement_hint=hint,
                )
                matches.append(match)

        # Satirlara gore sirala
        matches.sort(key=lambda m: m.line_number)

        # Ayni satirda birden fazla eslesme varsa, yuksek confidence olani tut
        matches = self._deduplicate(matches)

        return matches

    def annotate_code(self, c_code: str) -> str:
        """Inline tespitlerini yorum olarak koda ekle.

        Her tespit edilen inline pattern'in bulundugu satira
        `/* INLINE: func_name() */` seklinde yorum ekler.

        Args:
            c_code: Decompiled C kaynak kodu.

        Returns:
            Yorum eklenilmis C kodu.
        """
        if not c_code or not c_code.strip():
            return c_code

        matches = self.detect_in_code(c_code)
        if not matches:
            return c_code

        lines = c_code.split("\n")

        # Her satira eklenecek yorumlari topla (bir satirda birden fazla olabilir)
        annotations: dict[int, list[str]] = {}
        for m in matches:
            line_no = m.line_number
            if 0 <= line_no < len(lines):
                comment = f"/* INLINE: {m.function_name}() — {m.replacement_hint} */"
                if line_no not in annotations:
                    annotations[line_no] = []
                # Ayni yorumu tekrar ekleme
                if comment not in annotations[line_no]:
                    annotations[line_no].append(comment)

        # Satirlari tersten isle ki satir numaralari kaymasin
        result_lines = list(lines)
        for line_no in sorted(annotations.keys(), reverse=True):
            comments = annotations[line_no]
            for comment in reversed(comments):
                result_lines.insert(line_no, comment)

        return "\n".join(result_lines)

    def detect_and_report(self, c_code: str) -> InlineDetectionResult:
        """Tespit yap ve detayli sonuc dondur.

        Args:
            c_code: Decompiled C kaynak kodu.

        Returns:
            InlineDetectionResult: Detayli tespit sonucu.
        """
        result = InlineDetectionResult()

        try:
            matches = self.detect_in_code(c_code)
            result.matches = matches
            result.total_detected = len(matches)
            result.success = True

            # Kategoriye gore dagilim
            by_cat: dict[str, int] = {}
            for m in matches:
                by_cat[m.category] = by_cat.get(m.category, 0) + 1
            result.by_category = by_cat

            # Annotated code
            result.annotated_code = self.annotate_code(c_code)

            logger.info(
                "Inline detection: %d pattern bulundu (%s)",
                result.total_detected,
                ", ".join(f"{k}:{v}" for k, v in by_cat.items()),
            )

        except Exception as exc:
            result.errors.append(f"Inline detection hatasi: {type(exc).__name__}: {exc}")
            logger.exception("Inline detection exception")

        return result

    @staticmethod
    def _deduplicate(matches: list[InlineMatch]) -> list[InlineMatch]:
        """Ayni satirda ayni fonksiyon icin birden fazla eslesme varsa
        yuksek confidence olani tut.

        Farkli fonksiyonlar ayni satirda olabilir (orn. min + abs)
        — bunlar korunur.
        """
        # (line_number, function_name) -> en yuksek confidence match
        best: dict[tuple[int, str], InlineMatch] = {}
        for m in matches:
            key = (m.line_number, m.function_name)
            if key not in best or m.confidence > best[key].confidence:
                best[key] = m

        # Sirali dondur
        result = list(best.values())
        result.sort(key=lambda m: m.line_number)
        return result

    @staticmethod
    def get_supported_functions() -> list[str]:
        """Desteklenen inline fonksiyon isimlerini dondur."""
        seen: set[str] = set()
        result: list[str] = []
        for pat in _INLINE_PATTERNS:
            name = pat["function_name"]
            if name not in seen:
                seen.add(name)
                result.append(name)
        return result

    @staticmethod
    def get_pattern_count() -> int:
        """Tanimlanan pattern sayisini dondur."""
        return len(_INLINE_PATTERNS)
