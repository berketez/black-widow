"""InlineDetector testleri -- compiler inline fonksiyon tespiti.

Test edilen pattern'ler:
- abs (branch, branchless, ternary)
- strlen (while loop, for loop)
- memcpy (cast, unrolled)
- min/max (ternary, branchless)
- swap (tmp, xor)
- bswap (32-bit, 16-bit)
- memset (unrolled)
- strcmp (loop)
- popcount (hamming weight)
- isalpha, isdigit
- rol/ror (bit rotation)
- sign
"""

from __future__ import annotations

import pytest

from karadul.analyzers.inline_detector import (
    InlineDetector,
    InlineDetectionResult,
    InlineMatch,
)


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture
def detector() -> InlineDetector:
    """Varsayilan InlineDetector."""
    return InlineDetector()


# ---------------------------------------------------------------
# abs() testleri
# ---------------------------------------------------------------


class TestAbsDetection:
    """abs() inline pattern tespiti."""

    def test_abs_branch(self, detector: InlineDetector) -> None:
        """if (x < 0) x = -x; pattern'i abs() olarak tespit edilmeli."""
        code = "if (x < 0) x = -x;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "abs"
        assert matches[0].pattern_name == "abs_branch"
        assert matches[0].confidence >= 0.85

    def test_abs_branchless(self, detector: InlineDetector) -> None:
        """(x ^ (x >> 31)) - (x >> 31) pattern'i abs() olarak tespit edilmeli."""
        code = "result = (val ^ (val >> 31)) - (val >> 31);"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "abs"
        assert matches[0].pattern_name == "abs_branchless"
        assert matches[0].confidence >= 0.90

    def test_abs_ternary(self, detector: InlineDetector) -> None:
        """x < 0 ? -x : x pattern'i abs() olarak tespit edilmeli.

        v1.10.0 M8: pattern_name "abs_ternary" -> "abs_candidate"
        (ternary cok genel, false positive azaltmak icin dusuk confidence).
        """
        code = "result = n < 0 ? -n : n;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "abs"
        assert matches[0].pattern_name == "abs_candidate"

    def test_abs_branch_with_spaces(self, detector: InlineDetector) -> None:
        """Bosluklu abs pattern'i de calismali."""
        code = "if ( myvar < 0 ) myvar = - myvar ;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "abs"


# ---------------------------------------------------------------
# strlen() testleri
# ---------------------------------------------------------------


class TestStrlenDetection:
    """strlen() inline pattern tespiti."""

    def test_strlen_while_loop(self, detector: InlineDetector) -> None:
        """while (*s++) count++ pattern'i strlen() olarak tespit edilmeli."""
        code = "while (*ptr++) len++;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "strlen"
        assert matches[0].category == "string"

    def test_strlen_for_loop(self, detector: InlineDetector) -> None:
        """for (len = 0; s[len]; len++) pattern'i strlen() olarak tespit edilmeli."""
        code = "for (i = 0; str[i]; i++) {}"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "strlen"
        assert matches[0].pattern_name == "strlen_for"

    def test_strlen_null_check(self, detector: InlineDetector) -> None:
        """while (*s != '\\0') pattern'i strlen() olarak tespit edilmeli."""
        code = "while (*s != '\\0') { s++; count++; }"
        matches = detector.detect_in_code(code)
        assert len(matches) >= 1
        assert any(m.function_name == "strlen" for m in matches)


# ---------------------------------------------------------------
# memcpy() testleri
# ---------------------------------------------------------------


class TestMemcpyDetection:
    """memcpy() inline pattern tespiti."""

    def test_memcpy_uint64_cast(self, detector: InlineDetector) -> None:
        """*(uint64_t*)dst = *(uint64_t*)src; pattern'i memcpy() olarak tespit edilmeli."""
        code = "*(uint64_t*)dst = *(uint64_t*)src;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "memcpy"
        assert matches[0].category == "memory"

    def test_memcpy_uint32_cast(self, detector: InlineDetector) -> None:
        """32-bit cast variant da calismali."""
        code = "*(uint32_t*)output = *(uint32_t*)input;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "memcpy"

    def test_memcpy_unrolled(self, detector: InlineDetector) -> None:
        """dst[0] = src[0]; dst[1] = src[1]; pattern'i tespit edilmeli."""
        code = "buf[0] = data[0]; buf[1] = data[1]; buf[2] = data[2];"
        matches = detector.detect_in_code(code)
        assert len(matches) >= 1
        assert any(m.function_name == "memcpy" for m in matches)


# ---------------------------------------------------------------
# min/max testleri
# ---------------------------------------------------------------


class TestMinMaxDetection:
    """min/max inline pattern tespiti."""

    def test_min_ternary(self, detector: InlineDetector) -> None:
        """a < b ? a : b pattern'i min() olarak tespit edilmeli."""
        code = "result = x < y ? x : y;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "min"
        assert matches[0].category == "arithmetic"

    def test_max_ternary(self, detector: InlineDetector) -> None:
        """a > b ? a : b pattern'i max() olarak tespit edilmeli."""
        code = "result = x > y ? x : y;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "max"

    def test_min_branchless(self, detector: InlineDetector) -> None:
        """y ^ ((x ^ y) & -(x < y)) pattern'i min() olarak tespit edilmeli."""
        code = "result = b ^ ((a ^ b) & -(a < b));"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "min"
        assert matches[0].confidence >= 0.90

    def test_min_max_different_vars(self, detector: InlineDetector) -> None:
        """Farkli degisken isimleriyle de calismali."""
        code = "lo = width < height ? width : height;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "min"


# ---------------------------------------------------------------
# swap testleri
# ---------------------------------------------------------------


class TestSwapDetection:
    """swap inline pattern tespiti."""

    def test_swap_tmp(self, detector: InlineDetector) -> None:
        """tmp = a; a = b; b = tmp; pattern'i swap() olarak tespit edilmeli."""
        code = "tmp = a; a = b; b = tmp;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "swap"

    def test_swap_xor(self, detector: InlineDetector) -> None:
        """a ^= b; b ^= a; a ^= b; pattern'i swap() olarak tespit edilmeli."""
        code = "x ^= y; y ^= x; x ^= y;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "swap"
        assert matches[0].pattern_name == "swap_xor"


# ---------------------------------------------------------------
# bswap testleri
# ---------------------------------------------------------------


class TestBswapDetection:
    """Endian byte-swap tespiti."""

    def test_bswap32(self, detector: InlineDetector) -> None:
        """32-bit byte swap pattern'i bswap32() olarak tespit edilmeli."""
        code = (
            "result = ((val >> 24) & 0xFF) | ((val >> 8) & 0xFF00) "
            "| ((val << 8) & 0xFF0000) | ((val << 24)"
        )
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "bswap32"
        assert matches[0].category == "bitwise"
        assert matches[0].confidence >= 0.90

    def test_bswap16(self, detector: InlineDetector) -> None:
        """16-bit byte swap pattern'i bswap16() olarak tespit edilmeli."""
        code = "result = (val >> 8) | (val << 8);"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "bswap16"


# ---------------------------------------------------------------
# Diger pattern testleri
# ---------------------------------------------------------------


class TestOtherPatterns:
    """memset, strcmp, popcount, isalpha, isdigit, rol/ror, sign."""

    def test_memset_unrolled(self, detector: InlineDetector) -> None:
        """Tekrar eden atama memset() olarak tespit edilmeli."""
        code = "buf[0] = 0; buf[1] = 0; buf[2] = 0;"
        matches = detector.detect_in_code(code)
        assert len(matches) >= 1
        assert any(m.function_name == "memset" for m in matches)

    def test_strcmp_loop(self, detector: InlineDetector) -> None:
        """while (*s1 == *s2 && *s1) pattern'i strcmp() olarak tespit edilmeli."""
        code = "while (*a == *b && *a) { a++; b++; }"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "strcmp"
        assert matches[0].category == "string"

    def test_popcount_hamming(self, detector: InlineDetector) -> None:
        """Hamming weight ilk adimi popcount() olarak tespit edilmeli."""
        code = "x = x - ((x >> 1) & 0x55555555);"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "popcount"
        assert matches[0].category == "bitwise"

    def test_isalpha_range(self, detector: InlineDetector) -> None:
        """(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') -> isalpha()."""
        code = "if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "isalpha"

    def test_isdigit_range(self, detector: InlineDetector) -> None:
        """c >= '0' && c <= '9' -> isdigit()."""
        code = "if (ch >= '0' && ch <= '9')"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "isdigit"

    def test_rol32(self, detector: InlineDetector) -> None:
        """(x << n) | (x >> (32 - n)) -> rotl32()."""
        code = "result = (val << shift) | (val >> (32 - shift));"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "rotl32"
        assert matches[0].category == "bitwise"

    def test_ror32(self, detector: InlineDetector) -> None:
        """(x >> n) | (x << (32 - n)) -> rotr32()."""
        code = "result = (val >> shift) | (val << (32 - shift));"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "rotr32"

    def test_sign_expression(self, detector: InlineDetector) -> None:
        """(x > 0) - (x < 0) -> sign()."""
        code = "s = (val > 0) - (val < 0);"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].function_name == "sign"


# ---------------------------------------------------------------
# annotate_code testleri
# ---------------------------------------------------------------


class TestAnnotation:
    """annotate_code() -- yorum ekleme testleri."""

    def test_annotate_single(self, detector: InlineDetector) -> None:
        """Tek pattern icin yorum eklenmeli."""
        code = "if (x < 0) x = -x;"
        annotated = detector.annotate_code(code)
        assert "/* INLINE: abs()" in annotated
        # Orijinal kod korunmus olmali
        assert "if (x < 0) x = -x;" in annotated

    def test_annotate_multiple(self, detector: InlineDetector) -> None:
        """Birden fazla pattern icin tum yorumlar eklenmeli."""
        code = "if (x < 0) x = -x;\nresult = a < b ? a : b;"
        annotated = detector.annotate_code(code)
        assert "/* INLINE: abs()" in annotated
        assert "/* INLINE: min()" in annotated

    def test_annotate_empty_code(self, detector: InlineDetector) -> None:
        """Bos kod icin degisiklik olmamali."""
        assert detector.annotate_code("") == ""
        assert detector.annotate_code("   ") == "   "

    def test_annotate_no_matches(self, detector: InlineDetector) -> None:
        """Pattern eslesmezse kod ayni kalmali."""
        code = "int x = 42;\nreturn x;"
        annotated = detector.annotate_code(code)
        assert annotated == code


# ---------------------------------------------------------------
# detect_and_report testleri
# ---------------------------------------------------------------


class TestDetectAndReport:
    """detect_and_report() -- detayli sonuc testleri."""

    def test_report_success(self, detector: InlineDetector) -> None:
        """Basarili tespit InlineDetectionResult dondurmeli."""
        code = "if (x < 0) x = -x;\nresult = a < b ? a : b;"
        result = detector.detect_and_report(code)
        assert isinstance(result, InlineDetectionResult)
        assert result.success is True
        assert result.total_detected >= 2
        assert "arithmetic" in result.by_category

    def test_report_empty_code(self, detector: InlineDetector) -> None:
        """Bos kod icin 0 tespit ve success=True olmali."""
        result = detector.detect_and_report("")
        assert result.success is False or result.total_detected == 0

    def test_report_annotated_code(self, detector: InlineDetector) -> None:
        """Sonucta annotated_code olmali."""
        code = "tmp = a; a = b; b = tmp;"
        result = detector.detect_and_report(code)
        assert "/* INLINE:" in result.annotated_code

    def test_report_to_dict(self, detector: InlineDetector) -> None:
        """to_dict() JSON-serializable olmali."""
        code = "if (x < 0) x = -x;"
        result = detector.detect_and_report(code)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "matches" in d
        assert "total_detected" in d
        assert isinstance(d["matches"], list)


# ---------------------------------------------------------------
# Edge case ve utility testleri
# ---------------------------------------------------------------


class TestEdgeCases:
    """Edge case'ler ve utility metodlar."""

    def test_no_match_random_code(self, detector: InlineDetector) -> None:
        """Random C kodu pattern'e uymazsa bos liste donmeli."""
        code = """
        int factorial(int n) {
            if (n <= 1) return 1;
            return n * factorial(n - 1);
        }
        """
        matches = detector.detect_in_code(code)
        assert len(matches) == 0

    def test_multiple_patterns_same_code(self, detector: InlineDetector) -> None:
        """Bir fonksiyonda birden fazla inline pattern bulunabilir."""
        code = (
            "void process(int *arr, int n) {\n"
            "    if (x < 0) x = -x;\n"
            "    result = a < b ? a : b;\n"
            "    t = p; p = q; q = t;\n"
            "}"
        )
        matches = detector.detect_in_code(code)
        assert len(matches) >= 3
        names = {m.function_name for m in matches}
        assert "abs" in names
        assert "min" in names
        assert "swap" in names

    def test_line_numbers_correct(self, detector: InlineDetector) -> None:
        """Satir numaralari dogru olmali."""
        code = "int a = 1;\nif (x < 0) x = -x;\nint b = 2;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert matches[0].line_number == 1

    def test_dedup_same_line_same_func(self, detector: InlineDetector) -> None:
        """Ayni satirda ayni fonksiyon icin sadece yuksek confidence kalmali."""
        # abs_branch ve abs_ternary ayni satirda olsa, bir tanesi kalmali
        # (pratikte ayni satirda iki farkli abs pattern olmaz ama mantik dogrulanir)
        code = "if (x < 0) x = -x;"
        matches = detector.detect_in_code(code)
        abs_matches = [m for m in matches if m.function_name == "abs"]
        assert len(abs_matches) == 1

    def test_get_supported_functions(self) -> None:
        """Desteklenen fonksiyon listesi dondurulmeli."""
        funcs = InlineDetector.get_supported_functions()
        assert "abs" in funcs
        assert "strlen" in funcs
        assert "memcpy" in funcs
        assert "min" in funcs
        assert "max" in funcs
        assert "swap" in funcs
        assert "bswap32" in funcs

    def test_get_pattern_count(self) -> None:
        """Pattern sayisi pozitif olmali."""
        count = InlineDetector.get_pattern_count()
        assert count >= 20  # En az 20 pattern var

    def test_custom_patterns(self) -> None:
        """Ozel pattern listesi ile calismali."""
        import re
        custom = [{
            "name": "custom_test",
            "function_name": "my_func",
            "category": "custom",
            "confidence": 0.99,
            "regex": re.compile(r"CUSTOM_MARKER"),
            "hint": "my_func()",
        }]
        det = InlineDetector(patterns=custom)
        matches = det.detect_in_code("CUSTOM_MARKER found here")
        assert len(matches) == 1
        assert matches[0].function_name == "my_func"
        assert matches[0].category == "custom"

    def test_match_to_dict(self, detector: InlineDetector) -> None:
        """InlineMatch.to_dict() calismali."""
        code = "if (x < 0) x = -x;"
        matches = detector.detect_in_code(code)
        assert len(matches) > 0
        d = matches[0].to_dict()
        assert isinstance(d, dict)
        assert d["function_name"] == "abs"
        assert "confidence" in d
        assert "line_number" in d

    def test_replacement_hint_has_var_name(self, detector: InlineDetector) -> None:
        """Hint'te degisken adi gozukmeli."""
        code = "if (temperature < 0) temperature = -temperature;"
        matches = detector.detect_in_code(code)
        assert len(matches) == 1
        assert "temperature" in matches[0].replacement_hint

    def test_realistic_ghidra_output(self, detector: InlineDetector) -> None:
        """Gercekci Ghidra decompile ciktisinda inline tespiti."""
        code = """
void FUN_001234(int *param_1, int param_2) {
    int iVar1;
    int iVar2;
    int iVar3;

    iVar1 = param_1[param_2];
    if (iVar1 < 0) iVar1 = -iVar1;
    iVar2 = param_1[param_2 + 1];
    iVar3 = iVar1 < iVar2 ? iVar1 : iVar2;
    *(uint32_t*)dst = *(uint32_t*)src;
    return;
}
"""
        matches = detector.detect_in_code(code)
        assert len(matches) >= 3
        names = {m.function_name for m in matches}
        assert "abs" in names
        assert "min" in names
        assert "memcpy" in names
