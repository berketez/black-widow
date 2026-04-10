"""Layer 4: C kodundan matematiksel formul cikarma (LaTeX/ASCII).

Decompile edilmis C kodundaki hesaplama pattern'lerini tanimlayarak
matematiksel formuller cikarir. 35 ana pattern dedektoru:

0. BLAS/LAPACK Call -- cblas_sgemm, cblas_sdot, dgesv_ vb. (v1.4.2)
1. Matrix Operation -- icc dongu, pointer arithmetic, matris carpimi
2. Accumulator Loop -- toplam/integral approximation pattern'leri
3. Recurrence -- x[n] = f(x[n-1], x[n-2], ...) dizileri
4. ODE Discretization -- Euler, RK4, implicit Euler vb.
5. Dot Product -- <a, b> = sum a_i * b_i
6. Norm Computation -- ||x||_2 = sqrt(sum x_i^2)
7. Linear Interpolation -- y = y0 + (y1 - y0) * (x - x0) / (x1 - x0)
8. Finite Difference -- central, forward, backward, second derivative
9. Exponential Moving Average -- EMA_t = alpha * x_t + (1-alpha) * EMA_{t-1}
10. Scalar Math Chain -- zincirleme math func (exp, log, pow, sqrt, trig)
11. Discount/Exponential Decay -- exp(-rT) pattern
12. Bitwise Rotation -- (x << n) | (x >> (W - n))
13. Newton-Raphson -- x = x - f(x)/f'(x) iterasyon
14. Variance -- (x - mean)^2 toplami
15. Normal CDF -- 0.5 * (1 + erf(x / sqrt(2)))
16. FFT Butterfly -- twiddle factor ile butterfly operation (v1.5.9)
17. Convolution -- kernel[k] * input[n-k] toplami (v1.5.9)
18. Gradient Descent -- w -= lr * grad (v1.5.9)
19. Adam Optimizer -- EMA of gradient + EMA of gradient^2 (v1.5.9)
20. Horner's Method -- result = result*x + coeff chain (v1.5.9)
21. Cross Product -- 3D vektor carpimi a x b (v1.5.9)
22. Simpson's Rule -- (h/3)(f0 + 4f1 + 2f2 + ... + fn) (v1.5.9)
23. CRC / Hash Round -- shift + XOR + table lookup (v1.5.9)
24. Softmax -- exp(x_i) / sum(exp(x_j)) (v1.5.9)
25. Binary Search -- mid = (lo + hi) / 2 ile arama (v1.6.5)
26. Linked List Traversal -- ptr = ptr->next null-terminated dongu (v1.6.5)
27. Comparison Swap -- if (a > b) { tmp = a; a = b; b = tmp; } (v1.6.5)
28. Hash Table Probe -- index = hash & mask; while(table[index]) (v1.6.5)
29. Bitmask Extract -- (val >> shift) & mask pattern (v1.6.5)
30. Byte Pack/Unpack -- byte shift + OR/AND reassembly (v1.6.5)
31. Table Lookup -- result = table[index] constant array dereference (v1.6.5)
32. Min/Max Scan -- for loop icinde if (x < min) min = x (v1.6.5)
33. Counting/Frequency -- count[val]++ histogram pattern (v1.6.5)
34. Sentinel Loop -- while (*ptr != 0) ptr++ null-terminated walk (v1.6.5)

SymPy kurulu ise: sembolik basitlestirme + LaTeX rendering.
SymPy yoksa: template-based ASCII/LaTeX fallback.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# v1.8.0: DOTALL regex'ler icin chunk-bazli islem.
# Buyuk body'yi tamamen atlamak yerine, for/while keyword'u etrafinda
# sinirli pencereler cikarip DOTALL regex'i sadece o pencerede calistiririz.
# ---------------------------------------------------------------------------
_DOTALL_CHUNK_SIZE = 5_000


def _safe_dotall_search(pattern: re.Pattern, text: str) -> re.Match | None:
    """DOTALL regex'i chunk-bazli olarak calistir.

    v1.8.0: Boyut siniri yerine for/while etrafinda 5KB pencere kullanir.
    Hicbir dosya atlanmaz.
    """
    # Kisa text: dogrudan calistir
    if len(text) <= _DOTALL_CHUNK_SIZE:
        return pattern.search(text)
    # Uzun text: for/while/do keyword etrafinda pencere cikart
    for keyword in ("for", "while", "do"):
        pos = 0
        while True:
            pos = text.find(keyword, pos)
            if pos < 0:
                break
            chunk_end = min(pos + _DOTALL_CHUNK_SIZE, len(text))
            m = pattern.search(text[pos:chunk_end])
            if m is not None:
                return m
            pos += 1
    return None


# ---------------------------------------------------------------------------
# SymPy opsiyonel import
# ---------------------------------------------------------------------------

try:
    import sympy
    _SYMPY_AVAILABLE = True
except ImportError:
    _SYMPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level compiled regex patterns
# ---------------------------------------------------------------------------

# 1. Matrix Operation: Nested triple for + pointer arithmetic veya array indexing
# *(A + i*n + j) += *(B + i*k + l) * *(C + l*n + j)
# veya: A[i][j] += B[i][k] * C[k][j]
MATRIX_MUL_RE = re.compile(
    r'(?:for\s*\([^)]*\)|do)\s*\{[^{}]*(?:for\s*\([^)]*\)|do)\s*\{[^{}]*(?:for\s*\([^)]*\)|do)\s*\{[^{}]*'
    r'[\+\-]=.*\*',
    re.DOTALL,
)

# Pointer-style matris indeksleme: *(ptr + i*stride + j)
MATRIX_PTR_RE = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(\w+)\s*\*\s*(\w+)\s*\+\s*(\w+)\s*\)',
)

# Array-style matris indeksleme: arr[i][j] veya arr[i * n + j]
MATRIX_ARRAY_RE = re.compile(
    r'(\w+)\s*\[\s*(\w+)\s*\]\s*\[\s*(\w+)\s*\]'
    r'|(\w+)\s*\[\s*(\w+)\s*\*\s*(\w+)\s*\+\s*(\w+)\s*\]',
)

# 2. Accumulator Loop: for/do + sum/acc += expression
ACCUMULATOR_RE = re.compile(
    r'(?:for\s*\([^)]*;\s*\w+\s*[<>]=?\s*\w+\s*;[^)]*\)|do)\s*\{[^{}]*'
    r'(\w+)\s*\+=\s*([^;]+);',
    re.DOTALL,
)

# Agirlikli toplam: += f(x) * w veya += arr[i] * weight[i]
WEIGHTED_SUM_RE = re.compile(
    r'(\w+)\s*\+=\s*[^;]*\*\s*[^;]*;',
)

# 3. Recurrence: x[n] = ... x[n-1] ... x[n-2] ...
RECURRENCE_RE = re.compile(
    r'(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*[^;]*\1\s*\[\s*\2\s*-\s*\d+\s*\]',
)

# Recurrence degisken isimleri ve offset'leri cikarma
RECURRENCE_TERMS_RE = re.compile(
    r'(\w+)\s*\[\s*(\w+)\s*-\s*(\d+)\s*\]',
)

# Recurrence katsayi cikarma: coeff * arr[idx - offset]
RECURRENCE_COEFF_RE = re.compile(
    r'([0-9.eE+\-]+|\w+)\s*\*\s*(\w+)\s*\[\s*\w+\s*-\s*(\d+)\s*\]',
)

# Opsiyonel C tip belirteci: "double ", "float ", "int " vb.
# Decompiled kodda degisken tanimlarinda kullanilir.
_TYPE_PFX = r'(?:(?:double|float|int|long|unsigned)\s+)?'

# 4a. Forward Euler: y_new = y + h * f(t, y)
# Tip belirteci opsiyonel: "double y_new = y + h * f(...)"
EULER_RE = re.compile(
    _TYPE_PFX + r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*\*\s*\w+\s*\(',
)

# 4b. RK4: k1 = h*f(...); k2 = h*f(... k1 ...); k3 = ...; k4 = ...
# Tip belirteci opsiyonel: "double k1 = h * f(...); double k2 = ..."
RK4_RE = re.compile(
    _TYPE_PFX + r'(\w+)\s*=\s*(\w+)\s*\*\s*\w+\s*\([^)]*\);\s*'
    + _TYPE_PFX + r'(\w+)\s*=\s*\2\s*\*\s*\w+\s*\([^)]*\1',
    re.DOTALL,
)

# RK4 4 stage tespiti: k1, k2, k3, k4 seklinde 4 ardisik atama
RK4_STAGES_RE = re.compile(
    _TYPE_PFX + r'(\w+)\s*=\s*(\w+)\s*\*\s*\w+\s*\([^)]*\);\s*'
    + _TYPE_PFX + r'(\w+)\s*=\s*\2\s*\*\s*\w+\s*\([^)]*\1[^)]*\);\s*'
    + _TYPE_PFX + r'(\w+)\s*=\s*\2\s*\*\s*\w+\s*\([^)]*\3[^)]*\);\s*'
    + _TYPE_PFX + r'(\w+)\s*=\s*\2\s*\*\s*\w+\s*\([^)]*\4[^)]*\)',
    re.DOTALL,
)

# Implicit Euler / Backward Euler: Newton iteration icinde
# y_new = y + h * f(t+h, y_new)  -- y_new her iki tarafta
IMPLICIT_EULER_RE = re.compile(
    _TYPE_PFX + r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*\*\s*\w+\s*\([^)]*\1[^)]*\)',
)

# Loop counter degisken isimleri cikarma
FOR_LOOP_VAR_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=',
)

# Fonksiyon cagrisi argumanlari
FUNC_CALL_ARGS_RE = re.compile(
    r'(\w+)\s*\(([^)]*)\)',
)

# ---------------------------------------------------------------------------
# BLAS / LAPACK fonksiyon -> formul haritasi
# ---------------------------------------------------------------------------

_BLAS_FORMULA_MAP: dict[str, dict] = {
    # BLAS Level 1
    "cblas_sdot": {
        "formula_type": "inner_product",
        "latex": r"\langle x, y \rangle = \sum_{i} x_i y_i",
        "ascii": "<x, y> = sum(x_i * y_i)",
        "confidence": 0.90,
    },
    "cblas_ddot": {
        "formula_type": "inner_product",
        "latex": r"\langle x, y \rangle = \sum_{i} x_i y_i",
        "ascii": "<x, y> = sum(x_i * y_i)",
        "confidence": 0.90,
    },
    "cblas_snrm2": {
        "formula_type": "l2_norm",
        "latex": r"\|x\|_2 = \sqrt{\sum_{i} x_i^2}",
        "ascii": "||x||_2 = sqrt(sum(x_i^2))",
        "confidence": 0.90,
    },
    "cblas_dnrm2": {
        "formula_type": "l2_norm",
        "latex": r"\|x\|_2 = \sqrt{\sum_{i} x_i^2}",
        "ascii": "||x||_2 = sqrt(sum(x_i^2))",
        "confidence": 0.90,
    },
    "cblas_saxpy": {
        "formula_type": "vector_add",
        "latex": r"y = \alpha x + y",
        "ascii": "y = alpha * x + y",
        "confidence": 0.88,
    },
    "cblas_daxpy": {
        "formula_type": "vector_add",
        "latex": r"y = \alpha x + y",
        "ascii": "y = alpha * x + y",
        "confidence": 0.88,
    },
    "cblas_sscal": {
        "formula_type": "vector_scale",
        "latex": r"x = \alpha x",
        "ascii": "x = alpha * x",
        "confidence": 0.85,
    },
    "cblas_dscal": {
        "formula_type": "vector_scale",
        "latex": r"x = \alpha x",
        "ascii": "x = alpha * x",
        "confidence": 0.85,
    },
    "cblas_scopy": {
        "formula_type": "vector_copy",
        "latex": r"y \leftarrow x",
        "ascii": "y = copy(x)",
        "confidence": 0.80,
    },
    "cblas_dcopy": {
        "formula_type": "vector_copy",
        "latex": r"y \leftarrow x",
        "ascii": "y = copy(x)",
        "confidence": 0.80,
    },
    # BLAS Level 2
    "cblas_sgemv": {
        "formula_type": "matrix_vector",
        "latex": r"y = \alpha A x + \beta y",
        "ascii": "y = alpha * A * x + beta * y",
        "confidence": 0.90,
    },
    "cblas_dgemv": {
        "formula_type": "matrix_vector",
        "latex": r"y = \alpha A x + \beta y",
        "ascii": "y = alpha * A * x + beta * y",
        "confidence": 0.90,
    },
    # BLAS Level 3
    "cblas_sgemm": {
        "formula_type": "matrix_multiply",
        "latex": r"C = \alpha A B + \beta C",
        "ascii": "C = alpha * A * B + beta * C",
        "confidence": 0.92,
    },
    "cblas_dgemm": {
        "formula_type": "matrix_multiply",
        "latex": r"C = \alpha A B + \beta C",
        "ascii": "C = alpha * A * B + beta * C",
        "confidence": 0.92,
    },
    # LAPACK
    "sgesv_": {
        "formula_type": "linear_solve",
        "latex": r"Ax = b",
        "ascii": "solve(A, x, b)",
        "confidence": 0.92,
    },
    "dgesv_": {
        "formula_type": "linear_solve",
        "latex": r"Ax = b",
        "ascii": "solve(A, x, b)",
        "confidence": 0.92,
    },
    "sgetrf_": {
        "formula_type": "lu_factorization",
        "latex": r"PA = LU",
        "ascii": "LU = factorize(A)",
        "confidence": 0.90,
    },
    "dgetrf_": {
        "formula_type": "lu_factorization",
        "latex": r"PA = LU",
        "ascii": "LU = factorize(A)",
        "confidence": 0.90,
    },
    "ssyev_": {
        "formula_type": "eigenvalue",
        "latex": r"Av = \lambda v",
        "ascii": "eigenvalues(A) = lambda",
        "confidence": 0.90,
    },
    "dsyev_": {
        "formula_type": "eigenvalue",
        "latex": r"Av = \lambda v",
        "ascii": "eigenvalues(A) = lambda",
        "confidence": 0.90,
    },
    # v1.5.9: Fortran-style BLAS/LAPACK isimleri (Ghidra bunlari gorebilir)
    "sgemm_": {
        "formula_type": "matrix_multiply",
        "latex": r"C = \alpha A B + \beta C",
        "ascii": "C = alpha * A * B + beta * C",
        "confidence": 0.92,
    },
    "dgemm_": {
        "formula_type": "matrix_multiply",
        "latex": r"C = \alpha A B + \beta C",
        "ascii": "C = alpha * A * B + beta * C",
        "confidence": 0.92,
    },
    "sdot_": {
        "formula_type": "inner_product",
        "latex": r"\langle x, y \rangle = \sum_{i} x_i y_i",
        "ascii": "<x, y> = sum(x_i * y_i)",
        "confidence": 0.90,
    },
    "ddot_": {
        "formula_type": "inner_product",
        "latex": r"\langle x, y \rangle = \sum_{i} x_i y_i",
        "ascii": "<x, y> = sum(x_i * y_i)",
        "confidence": 0.90,
    },
    "snrm2_": {
        "formula_type": "l2_norm",
        "latex": r"\|x\|_2 = \sqrt{\sum_{i} x_i^2}",
        "ascii": "||x||_2 = sqrt(sum(x_i^2))",
        "confidence": 0.90,
    },
    "dnrm2_": {
        "formula_type": "l2_norm",
        "latex": r"\|x\|_2 = \sqrt{\sum_{i} x_i^2}",
        "ascii": "||x||_2 = sqrt(sum(x_i^2))",
        "confidence": 0.90,
    },
    "saxpy_": {
        "formula_type": "vector_add",
        "latex": r"y = \alpha x + y",
        "ascii": "y = alpha * x + y",
        "confidence": 0.88,
    },
    "daxpy_": {
        "formula_type": "vector_add",
        "latex": r"y = \alpha x + y",
        "ascii": "y = alpha * x + y",
        "confidence": 0.88,
    },
    "sgemv_": {
        "formula_type": "matrix_vector",
        "latex": r"y = \alpha A x + \beta y",
        "ascii": "y = alpha * A * x + beta * y",
        "confidence": 0.90,
    },
    "dgemv_": {
        "formula_type": "matrix_vector",
        "latex": r"y = \alpha A x + \beta y",
        "ascii": "y = alpha * A * x + beta * y",
        "confidence": 0.90,
    },
}


# ---------------------------------------------------------------------------
# Ghidra Normalization Layer (v1.5.9)
# ---------------------------------------------------------------------------

# Ghidra pointer dereference: *(type*)(base + offset)
_GHIDRA_CAST_DEREF_RE = re.compile(
    r'\*\(\s*(?:(?:double|float|int|uint|long|ulong|short|ushort|char|uchar|byte|'
    r'undefined[0-9]*|longlong|ulonglong|code|void)\s*\*?)\s*\*?\s*\)'
    r'\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)',
)

# Ghidra tiplerinin byte boyutlari
_GHIDRA_TYPE_SIZES: dict[str, int] = {
    'double': 8, 'float': 4, 'int': 4, 'uint': 4,
    'long': 8, 'ulong': 8, 'short': 2, 'ushort': 2,
    'char': 1, 'uchar': 1, 'byte': 1,
    'undefined8': 8, 'undefined4': 4, 'undefined2': 2, 'undefined': 1,
    'longlong': 8, 'ulonglong': 8, 'code': 8, 'void': 8,
}


def _normalize_ghidra_code(code: str) -> str:
    """Ghidra pointer-arithmetic stilini array-index stiline donustur.

    Ghidra ciktisi:  *(double*)(ptr + 0x10)
    Normalize edilmis: ptr[2]  (0x10 / sizeof(double) = 16/8 = 2)

    Bu donusum formula dedektorlerinin pattern'leriyle uyumlu hale getirir.
    Orijinal kodu DEGISTIRMEZ, sadece pattern matching icin normalize eder.
    """
    def _replace_cast_deref(m: re.Match) -> str:
        full = m.group(0)
        base = m.group(1)
        offset_str = m.group(2)

        # Offset'i parse et
        try:
            offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
        except ValueError:
            return full

        # Tip boyutunu bul (match'in basindaki cast'ten)
        type_match = re.search(
            r'(?:double|float|int|uint|long|ulong|short|ushort|char|uchar|byte|'
            r'undefined[0-9]*|longlong|ulonglong|code|void)',
            full,
        )
        if not type_match:
            return full

        type_name = type_match.group(0)
        type_size = _GHIDRA_TYPE_SIZES.get(type_name, 8)

        # Index hesapla
        if type_size > 0 and offset % type_size == 0:
            index = offset // type_size
            return f"{base}[{index}]"
        else:
            # Alignment uyumsuz, oldugu gibi birak
            return full

    # Pointer arithmetic -> array index
    result = _GHIDRA_CAST_DEREF_RE.sub(_replace_cast_deref, code)

    return result


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ExtractedFormula:
    """Cikarilan tek bir matematiksel formul.

    Attributes:
        function_name: Formulun bulundugu fonksiyon adi.
        formula_type: Formul tipi -- matrix_mul, accumulator, recurrence,
                      forward_euler, rk4, implicit_euler.
        latex: LaTeX formatinda formul (SymPy varsa simplify edilmis).
        ascii: ASCII text formatinda formul.
        c_code_snippet: Formulun cikarildigi C kodu parcasi.
        variables: Formuldeki degisken isimleri.
        confidence: Tespit guveni 0.0-1.0.
    """

    function_name: str
    formula_type: str
    latex: str
    ascii: str
    c_code_snippet: str
    variables: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Sozluk temsiline cevir (JSON serialization icin)."""
        return {
            "function_name": self.function_name,
            "formula_type": self.formula_type,
            "latex": self.latex,
            "ascii": self.ascii,
            "c_code_snippet": self.c_code_snippet,
            "variables": self.variables,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# SymPy yardimci fonksiyonlari
# ---------------------------------------------------------------------------

def _sympy_matrix_mul_latex() -> tuple[str, str]:
    """SymPy ile matris carpimi formulu uret."""
    if not _SYMPY_AVAILABLE:
        return (
            r"C_{ij} = \sum_{k} A_{ik} B_{kj}",
            "C[i][j] = sum_k( A[i][k] * B[k][j] )",
        )
    i, j, k, n = sympy.symbols("i j k n", integer=True)
    A = sympy.IndexedBase("A")
    B = sympy.IndexedBase("B")
    # C_ij = Sum(A_ik * B_kj, (k, 0, n-1))
    expr = sympy.Sum(A[i, k] * B[k, j], (k, 0, n - 1))
    return sympy.latex(expr), sympy.pretty(expr, use_unicode=False)


def _sympy_accumulator_latex(
    acc_var: str,
    body_expr: str,
) -> tuple[str, str]:
    """SymPy ile accumulator/toplam formulu uret."""
    if not _SYMPY_AVAILABLE:
        return (
            r"S = \sum_{i=0}^{n} f(x_i) \cdot w_i",
            "S = sum_{i=0}^{n} f(x_i) * w_i",
        )
    i, n = sympy.symbols("i n", integer=True)
    x = sympy.IndexedBase("x")
    w = sympy.IndexedBase("w")
    # Genel form: weighted sum
    if "*" in body_expr:
        expr = sympy.Sum(sympy.Function("f")(x[i]) * w[i], (i, 0, n))
    else:
        expr = sympy.Sum(sympy.Function("f")(x[i]), (i, 0, n))
    return sympy.latex(expr), sympy.pretty(expr, use_unicode=False)


def _sympy_recurrence_latex(
    offsets: list[int],
    coeffs: list[str],
    var_name: str,
) -> tuple[str, str]:
    """SymPy ile recurrence formulu uret."""
    if not _SYMPY_AVAILABLE:
        terms = []
        for offset, coeff in zip(offsets, coeffs):
            terms.append(f"{coeff} * {var_name}[n-{offset}]")
        ascii_str = f"{var_name}[n] = " + " + ".join(terms)
        latex_parts = []
        for offset, coeff in zip(offsets, coeffs):
            latex_parts.append(rf"{coeff} \cdot {var_name}_{{n-{offset}}}")
        latex_str = f"{var_name}_n = " + " + ".join(latex_parts)
        return latex_str, ascii_str

    n_sym = sympy.Symbol("n", integer=True)
    x = sympy.Function(var_name)
    terms = []
    for offset, coeff in zip(offsets, coeffs):
        try:
            c = sympy.Rational(coeff) if "." not in coeff else sympy.Float(coeff)
        except (ValueError, TypeError):
            c = sympy.Symbol(coeff)
        terms.append(c * x(n_sym - offset))
    expr = sympy.Add(*terms) if terms else sympy.Integer(0)
    simplified = sympy.simplify(expr)
    return sympy.latex(simplified), sympy.pretty(simplified, use_unicode=False)


def _sympy_euler_latex(y_var: str, h_var: str) -> tuple[str, str]:
    """SymPy ile Forward Euler formulu uret."""
    if not _SYMPY_AVAILABLE:
        return (
            r"y_{n+1} = y_n + h \cdot f(t_n, y_n)",
            "y[n+1] = y[n] + h * f(t[n], y[n])",
        )
    y_n, h, t_n = sympy.symbols(f"{y_var}_n {h_var} t_n")
    f = sympy.Function("f")
    expr = y_n + h * f(t_n, y_n)
    y_next = sympy.Symbol(f"{y_var}_{{n+1}}")
    eq = sympy.Eq(y_next, expr)
    return sympy.latex(eq), sympy.pretty(eq, use_unicode=False)


def _sympy_rk4_latex() -> tuple[str, str]:
    """SymPy ile RK4 formulu uret."""
    if not _SYMPY_AVAILABLE:
        latex = (
            r"y_{n+1} = y_n + \frac{h}{6}(k_1 + 2k_2 + 2k_3 + k_4)"
            r" \\ k_1 = f(t_n, y_n)"
            r" \\ k_2 = f(t_n + \frac{h}{2}, y_n + \frac{h}{2} k_1)"
            r" \\ k_3 = f(t_n + \frac{h}{2}, y_n + \frac{h}{2} k_2)"
            r" \\ k_4 = f(t_n + h, y_n + h k_3)"
        )
        ascii_ = (
            "y[n+1] = y[n] + (h/6)*(k1 + 2*k2 + 2*k3 + k4)\n"
            "k1 = f(t, y)\n"
            "k2 = f(t + h/2, y + h/2 * k1)\n"
            "k3 = f(t + h/2, y + h/2 * k2)\n"
            "k4 = f(t + h, y + h * k3)"
        )
        return latex, ascii_

    y_n, h, t_n = sympy.symbols("y_n h t_n")
    f = sympy.Function("f")
    k1 = f(t_n, y_n)
    k2 = f(t_n + h / 2, y_n + h * k1 / 2)
    k3 = f(t_n + h / 2, y_n + h * k2 / 2)
    k4 = f(t_n + h, y_n + h * k3)
    update = y_n + (h / 6) * (k1 + 2 * k2 + 2 * k3 + k4)
    eq = sympy.Eq(sympy.Symbol("y_{n+1}"), update)
    return sympy.latex(eq), sympy.pretty(eq, use_unicode=False)


def _sympy_implicit_euler_latex(y_var: str, h_var: str) -> tuple[str, str]:
    """SymPy ile Implicit Euler formulu uret."""
    if not _SYMPY_AVAILABLE:
        return (
            r"y_{n+1} = y_n + h \cdot f(t_{n+1}, y_{n+1})",
            "y[n+1] = y[n] + h * f(t[n+1], y[n+1])",
        )
    y_n, h, t_next = sympy.symbols(f"{y_var}_n {h_var} t_{{n+1}}")
    y_next = sympy.Symbol(f"{y_var}_{{n+1}}")
    f = sympy.Function("f")
    expr = y_n + h * f(t_next, y_next)
    eq = sympy.Eq(y_next, expr)
    return sympy.latex(eq), sympy.pretty(eq, use_unicode=False)


# ---------------------------------------------------------------------------
# FormulaExtractor
# ---------------------------------------------------------------------------

class FormulaExtractor:
    """Decompile edilmis C kodundan matematiksel formul cikarici.

    35 pattern dedektoru ile C kodundaki hesaplama yapilarini tanimlar
    ve LaTeX/ASCII formatinda formul uretir. Dedektor 0 (BLAS/LAPACK)
    fonksiyon cagrisi bazli, dedektor 1-24 math/eng pattern bazli,
    dedektor 25-34 genel amacli algoritma pattern bazli (v1.6.5).

    Args:
        config: Ana konfiguerasyon nesnesi. ``computation_recovery``
            alt-konfigurasyonundan ``max_functions_for_formula``
            okunur. Attribute yoksa varsayilan 200 kullanilir.
    """

    def __init__(self, config: Any = None) -> None:
        self._config = config
        # max_functions_for_formula limiti
        self._max_functions = 200  # varsayilan
        if config is not None:
            cr = getattr(config, "computation_recovery", None)
            if cr is not None:
                self._max_functions = getattr(
                    cr, "max_functions_for_formula", 200,
                )

        if _SYMPY_AVAILABLE:
            logger.debug("SymPy %s mevcut -- sembolik basitlestirme aktif", sympy.__version__)
        else:
            logger.debug("SymPy bulunamadi -- template-based fallback kullanilacak")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        decompiled_dir: Path,
        target_functions: list[str] | None = None,
        cfg_matches: list[dict[str, Any]] | None = None,
        fused_ids: dict[str, Any] | None = None,
    ) -> list[ExtractedFormula]:
        """Hedef fonksiyonlardan matematiksel formuller cikar.

        Args:
            decompiled_dir: Ghidra decompile cikti dizini.
            target_functions: Taranacak fonksiyon adi listesi.
                None ise cfg_matches ve fused_ids'den turetilir.
            cfg_matches: Layer 2 CFG fingerprint eslestirme sonuclari.
                Her eleman ``{"function_name": str, ...}`` formatinda.
            fused_ids: Layer 3 Signature Fusion sonuclari.
                ``{fonksiyon_adi: {...}, ...}`` formatinda.

        Returns:
            Cikarilan formul listesi (bos olabilir).
        """
        decompiled_dir = Path(decompiled_dir)
        if not decompiled_dir.is_dir():
            logger.warning("Decompiled dizini bulunamadi: %s", decompiled_dir)
            return []

        # Hedef fonksiyon listesini olustur
        targets = self._resolve_targets(
            target_functions, cfg_matches, fused_ids, decompiled_dir,
        )
        if not targets:
            logger.info("Formula extraction icin hedef fonksiyon bulunamadi")
            return []

        # Limit uygula
        if len(targets) > self._max_functions:
            logger.info(
                "Hedef fonksiyon sayisi (%d) limiti asiyor (%d), kirpiliyor",
                len(targets), self._max_functions,
            )
            targets = targets[: self._max_functions]

        logger.info(
            "Formula extraction basliyor: %d hedef fonksiyon", len(targets),
        )

        results: list[ExtractedFormula] = []
        files_scanned = 0

        for func_name in targets:
            code = self._load_function_code(decompiled_dir, func_name)
            if code is None:
                continue
            files_scanned += 1

            # v1.5.9: Ghidra pointer-arithmetic -> array-index normalization
            code = _normalize_ghidra_code(code)

            # v1.6.0: Buyuk fonksiyon body'lerini truncate et
            # Go binary'lerde 10K+ satirlik fonksiyonlar DOTALL regex'lerde
            # catastrophic backtracking yapabiliyor.
            # BLAS/LAPACK fonksiyon cagrisi dedektoru (liste doner)
            # NOT: BLAS tespiti sadece string `in` kullaniyor, regex yok.
            # Buyuk body'lerde de guvenle calisir.
            blas_formulas = self._detect_blas_formula(code, func_name)
            results.extend(blas_formulas)
            for bf in blas_formulas:
                logger.debug(
                    "BLAS formul bulundu: %s [%s] guven=%.2f",
                    func_name, bf.formula_type, bf.confidence,
                )

            # v1.6.5: Faz 1 — Non-DOTALL dedektorler (O(n) guvenli, buyuk
            # body'lerde de calisir). 25/35 dedektor DOTALL kullanmiyor.
            for detector in (
                self._detect_recurrence,
                self._detect_interpolation,
                self._detect_finite_difference,
                self._detect_exponential_moving_avg,
                self._detect_scalar_math_chain,
                self._detect_discount_exp,
                self._detect_bitwise_rotation,
                self._detect_variance,
                self._detect_normal_cdf,
                self._detect_gradient_descent,
                self._detect_horner,
                self._detect_cross_product,
                self._detect_crc_hash_round,
                self._detect_softmax,
                self._detect_newton_raphson,  # scalar form O(n), loop form DOTALL guarded
                # v1.6.5: Genel amacli algoritma dedektorleri
                self._detect_binary_search,
                self._detect_linked_list_traversal,
                self._detect_comparison_swap,
                self._detect_hash_table_probe,
                self._detect_bitmask_extract,
                self._detect_byte_pack_unpack,
                self._detect_table_lookup,
                self._detect_minmax_scan,
                self._detect_counting_frequency,
                self._detect_sentinel_loop,
            ):
                formula = detector(code, func_name)
                if formula is not None:
                    results.append(formula)
                    logger.debug(
                        "Formul bulundu: %s [%s] guven=%.2f",
                        func_name, formula.formula_type, formula.confidence,
                    )

            # v1.8.0: Faz 2 — DOTALL dedektorler artik chunk-bazli calisiyor.
            # _safe_dotall_search buyuk body'lerde for/while etrafinda
            # 5KB pencere cikariyor.  Boyut siniri YOK.

            for detector in (
                self._detect_matrix_operation,
                self._detect_accumulator_loop,
                self._detect_ode_discretization,
                self._detect_dot_product,
                self._detect_norm_computation,
                self._detect_fft_butterfly,
                self._detect_convolution,
                self._detect_adam_optimizer,
                self._detect_simpson_quadrature,
            ):
                formula = detector(code, func_name)
                if formula is not None:
                    results.append(formula)
                    logger.debug(
                        "Formul bulundu: %s [%s] guven=%.2f",
                        func_name, formula.formula_type, formula.confidence,
                    )

        logger.info(
            "Formula extraction tamamlandi: %d dosya tarandi, %d formul bulundu",
            files_scanned, len(results),
        )
        return results

    # ------------------------------------------------------------------
    # Hedef fonksiyon cozumleme
    # ------------------------------------------------------------------

    def _resolve_targets(
        self,
        target_functions: list[str] | None,
        cfg_matches: list[dict[str, Any]] | None,
        fused_ids: dict[str, Any] | None,
        decompiled_dir: Path | None = None,
    ) -> list[str]:
        """Taranacak fonksiyon listesini olustur.

        Oncelik: explicit target_functions > cfg_matches + fused_ids > dizindeki tum .c dosyalari.
        """
        if target_functions:
            return list(target_functions)

        targets: set[str] = set()

        if cfg_matches:
            for match in cfg_matches:
                fname = match.get("function_name") or match.get("func_name", "")
                if fname:
                    targets.add(fname)

        if fused_ids:
            for fname in fused_ids:
                if fname:
                    targets.add(fname)

        # v1.5.9: Her zaman tum .c dosyalarini da ekle (CFG/fusion listesine ek olarak)
        if decompiled_dir and decompiled_dir.is_dir():
            prev_count = len(targets)
            for c_file in sorted(decompiled_dir.glob("*.c")):
                targets.add(c_file.stem)
            added = len(targets) - prev_count
            if added > 0:
                logger.info(
                    "Dizindeki .c dosyalarindan %d ek hedef eklendi (toplam %d)",
                    added, len(targets),
                )

        return sorted(targets)

    # ------------------------------------------------------------------
    # Dosya yukleme
    # ------------------------------------------------------------------

    def _load_function_code(
        self,
        decompiled_dir: Path,
        func_name: str,
    ) -> str | None:
        """Fonksiyon adi ile decompile dosyasini yukle.

        Dosya adlandirma convention'i: ``<func_name>.c`` veya
        ``decompiled_<func_name>.c`` veya alt dizinlerde arama.
        """
        # Dogrudan dosya adi eslestirme
        candidates = [
            decompiled_dir / f"{func_name}.c",
            decompiled_dir / f"decompiled_{func_name}.c",
        ]

        # FUN_ prefix'li adresli dosyalar
        if func_name.startswith("FUN_"):
            candidates.append(decompiled_dir / f"{func_name}.c")

        for candidate in candidates:
            if candidate.is_file():
                try:
                    return candidate.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    logger.debug("Dosya okunamadi %s: %s", candidate, exc)

        # Glob ile arama (yavas ama fallback)
        pattern = f"*{func_name}*.c"
        matches = list(decompiled_dir.glob(pattern))
        if matches:
            try:
                return matches[0].read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.debug("Dosya okunamadi %s: %s", matches[0], exc)

        return None

    # ------------------------------------------------------------------
    # Pattern Dedektoru 0: BLAS / LAPACK call-to-formula
    # ------------------------------------------------------------------

    def _detect_blas_formula(
        self,
        code: str,
        func_name: str,
    ) -> list[ExtractedFormula]:
        """BLAS/LAPACK fonksiyon cagrilarindan formul cikar.

        Decompile edilmis kodda ``cblas_sgemm(...)``, ``dgesv_(...)`` vb.
        cagrilari tespit eder ve karsilik gelen matematiksel formulu
        ``_BLAS_FORMULA_MAP`` sozlugunden doner.

        Mevcut 15 inline-loop dedektorunun aksine, bu dedektor
        BLAS kullanan kutuphanelerde (FAISS, OpenBLAS, MKL) hesaplama
        yapilarini yakalamak icin tasarlanmistir.

        Returns:
            Tespit edilen formullerin listesi (bos olabilir).
            Bir fonksiyonda birden fazla BLAS cagrisi bulunabilir.
        """
        results: list[ExtractedFormula] = []

        for blas_func, info in _BLAS_FORMULA_MAP.items():
            if blas_func not in code:
                continue

            # Cagri satirini bul (argumanlariyla birlikte)
            match = re.search(
                rf'{re.escape(blas_func)}\s*\([^)]*\)', code,
            )
            snippet = match.group(0) if match else blas_func

            results.append(ExtractedFormula(
                function_name=func_name,
                formula_type=info["formula_type"],
                latex=info["latex"],
                ascii=info["ascii"],
                c_code_snippet=snippet,
                variables=[],  # TODO: BLAS arguman convention'dan cikar
                confidence=info["confidence"],
            ))

        return results

    # ------------------------------------------------------------------
    # Pattern Dedektoru 1: Matrix Operation
    # ------------------------------------------------------------------

    def _detect_matrix_operation(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Uc katmanli for dongusu + carpim -> matris operasyonu tespiti.

        Aranan pattern:
            for (...) { for (...) { for (...) { += ... * ... } } }
            -> C = A x B (matrix multiplication)
        """
        match = _safe_dotall_search(MATRIX_MUL_RE, code)
        if match is None:
            return None

        # Snippet'i cikar (eslesen bolge + biraz context)
        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degiskenleri cikar
        variables: list[str] = []

        # Loop degiskenleri
        loop_vars = FOR_LOOP_VAR_RE.findall(snippet)
        variables.extend(loop_vars)

        # Pointer-style veya array-style matris degiskenlerini bul
        ptr_matches = MATRIX_PTR_RE.findall(snippet)
        for pm in ptr_matches:
            variables.append(pm[0])  # pointer/array base ismi

        arr_matches = MATRIX_ARRAY_RE.findall(snippet)
        for am in arr_matches:
            # (arr2d, i, j, arr1d, i2, stride, j2)
            if am[0]:
                variables.append(am[0])
            if am[3]:
                variables.append(am[3])

        variables = sorted(set(variables))

        # Confidence: triple nested loop + *= veya += ... *
        confidence = 0.75
        if ptr_matches or arr_matches:
            confidence = 0.85
        # Eger += ile carpim goruyorsak guven artar
        if "+=" in snippet and "*" in snippet:
            confidence = min(confidence + 0.05, 0.95)

        # LaTeX / ASCII uret
        latex, ascii_ = _sympy_matrix_mul_latex()

        return ExtractedFormula(
            function_name=func_name,
            formula_type="matrix_mul",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 2: Accumulator Loop
    # ------------------------------------------------------------------

    def _detect_accumulator_loop(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """For dongusu + += toplam -> numerik quadrature / toplam tespiti.

        Aranan pattern:
            for (...; i < n; ...) { sum += f(x[i]) * w[i]; }
            -> S = sum_{i=0}^{n} f(x_i) * w_i
        """
        match = _safe_dotall_search(ACCUMULATOR_RE, code)
        if match is None:
            return None

        acc_var = match.group(1)
        body_expr = match.group(2).strip()

        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degiskenler
        variables = [acc_var]
        loop_vars = FOR_LOOP_VAR_RE.findall(snippet)
        variables.extend(loop_vars)

        # Body'deki degiskenleri cikar (basit identifier extraction)
        body_idents = re.findall(r'\b([a-zA-Z_]\w*)\b', body_expr)
        # C keyword'leri ve sayilari filtrele
        c_keywords = {
            "int", "float", "double", "long", "char", "void", "unsigned",
            "signed", "const", "static", "return", "if", "else", "for",
            "while", "do", "break", "continue", "sizeof",
        }
        body_idents = [v for v in body_idents if v not in c_keywords]
        variables.extend(body_idents)
        variables = sorted(set(variables))

        # Confidence
        confidence = 0.70
        is_weighted = WEIGHTED_SUM_RE.search(snippet) is not None
        if is_weighted:
            confidence = 0.80
        # Eger acc_var "sum", "total", "acc", "result" gibi bir sey ise
        if any(kw in acc_var.lower() for kw in ("sum", "total", "acc", "result", "integral")):
            confidence = min(confidence + 0.05, 0.95)

        # LaTeX / ASCII uret
        latex, ascii_ = _sympy_accumulator_latex(acc_var, body_expr)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="accumulator",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 3: Recurrence
    # ------------------------------------------------------------------

    def _detect_recurrence(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dizi recurrence tespiti: x[n] = f(x[n-1], x[n-2], ...).

        Aranan pattern:
            x[n] = a*x[n-1] + b*x[n-2]
            -> x_n = alpha * x_{n-1} + beta * x_{n-2}
        """
        match = RECURRENCE_RE.search(code)
        if match is None:
            return None

        var_name = match.group(1)
        idx_var = match.group(2)

        # Tum satiri bul (recurrence ifadesinin tamami)
        line_start = code.rfind("\n", 0, match.start()) + 1
        line_end = code.find(";", match.start())
        if line_end == -1:
            line_end = code.find("\n", match.start())
        if line_end == -1:
            line_end = match.end()
        else:
            line_end += 1  # ; dahil

        rec_line = code[line_start:line_end].strip()
        snippet = self._extract_snippet(code, match.start(), line_end)

        # Offset'leri ve katsayilari cikar
        offsets: list[int] = []
        coeffs: list[str] = []

        # Once katsayili terimleri dene
        coeff_matches = RECURRENCE_COEFF_RE.findall(rec_line)
        if coeff_matches:
            for c, _, off in coeff_matches:
                offsets.append(int(off))
                coeffs.append(c)
        else:
            # Katsayisiz terimler (implicit 1)
            term_matches = RECURRENCE_TERMS_RE.findall(rec_line)
            for _, _, off in term_matches:
                offsets.append(int(off))
                coeffs.append("1")

        if not offsets:
            offsets = [1]
            coeffs = ["1"]

        # Degiskenler
        variables = sorted({var_name, idx_var})

        # Confidence
        confidence = 0.75
        if len(offsets) >= 2:
            confidence = 0.85  # Cok terimli recurrence daha kesin
        # Bilinen recurrence isimleri
        if any(kw in func_name.lower() for kw in ("fib", "lucas", "cheby", "legendre", "recur")):
            confidence = min(confidence + 0.10, 0.95)

        # LaTeX / ASCII uret
        latex, ascii_ = _sympy_recurrence_latex(offsets, coeffs, var_name)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="recurrence",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 4: ODE Discretization
    # ------------------------------------------------------------------

    def _detect_ode_discretization(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """ODE zaman adimi tespiti: Euler, RK4, Implicit Euler.

        Aranan pattern'ler:
            Forward Euler: y_new = y + h * f(t, y)
            RK4: k1 = h*f(...); k2 = h*f(...+k1/2); ...
            Implicit Euler: y_new = y + h * f(t+h, y_new)  (y_new her iki tarafta)
        """
        # Once RK4 dene (en spesifik pattern)
        formula = self._try_rk4(code, func_name)
        if formula is not None:
            return formula

        # Implicit Euler dene
        formula = self._try_implicit_euler(code, func_name)
        if formula is not None:
            return formula

        # Forward Euler dene (en genel pattern, en son)
        formula = self._try_forward_euler(code, func_name)
        if formula is not None:
            return formula

        return None

    def _try_rk4(self, code: str, func_name: str) -> ExtractedFormula | None:
        """RK4 (4-stage Runge-Kutta) tespiti."""
        # Once 4-stage full pattern dene
        match = _safe_dotall_search(RK4_STAGES_RE, code)
        if match is not None:
            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({match.group(1), match.group(2),
                                match.group(3), match.group(4), match.group(5)})
            latex, ascii_ = _sympy_rk4_latex()
            return ExtractedFormula(
                function_name=func_name,
                formula_type="rk4",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=0.90,
            )

        # 2-stage partial match (k1 -> k2 bagimlilik)
        match = RK4_RE.search(code)
        if match is not None:
            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({match.group(1), match.group(2), match.group(3)})
            latex, ascii_ = _sympy_rk4_latex()
            return ExtractedFormula(
                function_name=func_name,
                formula_type="rk4",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=0.75,  # Sadece 2 stage gorunuyor
            )

        return None

    def _try_implicit_euler(
        self, code: str, func_name: str,
    ) -> ExtractedFormula | None:
        """Implicit (Backward) Euler tespiti.

        y_new = y + h * f(t+h, y_new) seklinde y_new her iki tarafta.
        """
        match = IMPLICIT_EULER_RE.search(code)
        if match is None:
            return None

        y_new = match.group(1)
        y_old = match.group(2)
        h_var = match.group(3)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({y_new, y_old, h_var})

        latex, ascii_ = _sympy_implicit_euler_latex(y_old, h_var)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="implicit_euler",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=0.80,
        )

    def _try_forward_euler(
        self, code: str, func_name: str,
    ) -> ExtractedFormula | None:
        """Forward Euler tespiti: y_new = y + h * f(t, y)."""
        match = EULER_RE.search(code)
        if match is None:
            return None

        y_new = match.group(1)
        y_old = match.group(2)
        h_var = match.group(3)

        # False positive filtreleme: y_new ve y_old farkli olmali
        # ve h_var bir adim boyutu gibi gorunmeli
        if y_new == y_old == h_var:
            return None

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({y_new, y_old, h_var})

        # Confidence: isim ipuclari
        confidence = 0.65
        euler_hints = ("euler", "step", "integrate", "ode", "rhs", "dt", "dy")
        if any(hint in func_name.lower() for hint in euler_hints):
            confidence = 0.80
        if any(hint in h_var.lower() for hint in ("dt", "h", "step", "ds")):
            confidence = min(confidence + 0.05, 0.95)

        latex, ascii_ = _sympy_euler_latex(y_old, h_var)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="forward_euler",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 5: Dot Product
    # ------------------------------------------------------------------

    # Dot product: for(i=0;i<n;i++) sum += a[i]*b[i]  (v1.5.9: do{} destegi)
    _DOT_PRODUCT_RE = re.compile(
        r'(?:for\s*\([^)]*;\s*\w+\s*[<>]=?\s*\w+\s*;[^)]*\)|do)\s*\{[^{}]*'
        r'(\w+)\s*\+=\s*(\w+)\s*\[\s*\w+\s*\]\s*\*\s*(\w+)\s*\[\s*\w+\s*\]',
        re.DOTALL,
    )

    def _detect_dot_product(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dot product tespiti: for(i=0;i<n;i++) sum += a[i]*b[i].

        Aranan pattern:
            sum += a[i] * b[i] bir for dongusu icinde
            -> <a, b> = sum_{i=0}^{n} a_i * b_i
        """
        match = self._DOT_PRODUCT_RE.search(code)
        if match is None:
            return None

        acc_var = match.group(1)
        arr_a = match.group(2)
        arr_b = match.group(3)

        # Iki farkli array olmali (kendisiyle carpim norm icin ayri dedektor var)
        if arr_a == arr_b:
            return None

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({acc_var, arr_a, arr_b})

        # Confidence
        confidence = 0.80
        if any(kw in func_name.lower() for kw in ("dot", "inner", "product", "scalar")):
            confidence = 0.90

        latex = r"\langle a, b \rangle = \sum_{i=0}^{n} a_i b_i"
        ascii_ = "<a, b> = sum_{i=0}^{n} a[i] * b[i]"

        if _SYMPY_AVAILABLE:
            i, n = sympy.symbols("i n", integer=True)
            a = sympy.IndexedBase(arr_a)
            b = sympy.IndexedBase(arr_b)
            expr = sympy.Sum(a[i] * b[i], (i, 0, n - 1))
            latex = sympy.latex(expr)
            ascii_ = sympy.pretty(expr, use_unicode=False)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="dot_product",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 6: Norm Computation
    # ------------------------------------------------------------------

    # L2 norm: for(i=0;i<n;i++) sum += x[i]*x[i]; ... sqrt(sum) (v1.5.9: do{} destegi)
    _NORM_LOOP_RE = re.compile(
        r'(?:for\s*\([^)]*;\s*\w+\s*[<>]=?\s*\w+\s*;[^)]*\)|do)\s*\{[^{}]*'
        r'(\w+)\s*\+=\s*(\w+)\s*\[\s*\w+\s*\]\s*\*\s*\2\s*\[\s*\w+\s*\]',
        re.DOTALL,
    )
    _SQRT_RETURN_RE = re.compile(
        r'(?:return\s+)?(?:sqrt|sqrtf|sqrtl)\s*\(\s*(\w+)\s*\)',
        re.IGNORECASE,
    )

    def _detect_norm_computation(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """L2 norm tespiti: for(i=0;i<n;i++) sum += x[i]*x[i]; sqrt(sum).

        Aranan pattern:
            sum += x[i] * x[i] bir for dongusu icinde
            return sqrt(sum)
            -> ||x||_2 = sqrt(sum_{i=0}^{n} x_i^2)
        """
        match = self._NORM_LOOP_RE.search(code)
        if match is None:
            return None

        acc_var = match.group(1)
        arr_x = match.group(2)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({acc_var, arr_x})

        # sqrt(acc_var) var mi? Confidence'i etkiler
        has_sqrt = bool(self._SQRT_RETURN_RE.search(code))

        confidence = 0.70
        if has_sqrt:
            confidence = 0.85
        if any(kw in func_name.lower() for kw in ("norm", "magnitude", "length", "abs")):
            confidence = min(confidence + 0.10, 0.95)

        if has_sqrt:
            latex = r"\|x\|_2 = \sqrt{\sum_{i=0}^{n} x_i^2}"
            ascii_ = "||x||_2 = sqrt(sum_{i=0}^{n} x[i]^2)"
        else:
            latex = r"\|x\|_2^2 = \sum_{i=0}^{n} x_i^2"
            ascii_ = "||x||_2^2 = sum_{i=0}^{n} x[i]^2"

        if _SYMPY_AVAILABLE:
            i, n = sympy.symbols("i n", integer=True)
            x = sympy.IndexedBase(arr_x)
            inner = sympy.Sum(x[i] ** 2, (i, 0, n - 1))
            if has_sqrt:
                expr = sympy.sqrt(inner)
            else:
                expr = inner
            latex = sympy.latex(expr)
            ascii_ = sympy.pretty(expr, use_unicode=False)

        return ExtractedFormula(
            function_name=func_name,
            formula_type="norm_l2",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 7: Linear Interpolation
    # ------------------------------------------------------------------

    # Linear interpolation: y = y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    # veya: result = a + (b - a) * t  (simplified lerp)
    _LERP_FULL_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*\+\s*\(\s*(\w+)\s*-\s*\2\s*\)\s*\*\s*'
        r'\(\s*(\w+)\s*-\s*(\w+)\s*\)\s*/\s*\(\s*(\w+)\s*-\s*\5\s*\)',
    )
    _LERP_SIMPLE_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*\+\s*\(\s*(\w+)\s*-\s*\2\s*\)\s*\*\s*(\w+)',
    )

    def _detect_interpolation(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Linear interpolation tespiti.

        Aranan pattern'ler:
            Full:  y = y0 + (y1 - y0) * (x - x0) / (x1 - x0)
            Lerp:  y = a + (b - a) * t
            -> y = y_0 + (y_1 - y_0) / (x_1 - x_0) * (x - x_0)
        """
        # Once full interpolation dene
        match = self._LERP_FULL_RE.search(code)
        if match is not None:
            result_var = match.group(1)
            y0 = match.group(2)
            y1 = match.group(3)
            x_var = match.group(4)
            x0 = match.group(5)
            x1 = match.group(6)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({result_var, y0, y1, x_var, x0, x1})

            confidence = 0.85
            if any(kw in func_name.lower() for kw in ("interp", "lerp", "linear")):
                confidence = 0.92

            latex = r"y = y_0 + \frac{y_1 - y_0}{x_1 - x_0}(x - x_0)"
            ascii_ = "y = y0 + (y1 - y0) * (x - x0) / (x1 - x0)"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="linear_interpolation",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Basit lerp: y = a + (b - a) * t
        match = self._LERP_SIMPLE_RE.search(code)
        if match is not None:
            result_var = match.group(1)
            a_var = match.group(2)
            b_var = match.group(3)
            t_var = match.group(4)

            # False positive filtresi: degiskenler farkli olmali
            if len({result_var, a_var, b_var, t_var}) < 3:
                return None

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({result_var, a_var, b_var, t_var})

            confidence = 0.70
            if any(kw in func_name.lower() for kw in ("interp", "lerp", "mix", "blend")):
                confidence = 0.85

            latex = r"y = a + (b - a) \cdot t"
            ascii_ = "y = a + (b - a) * t"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="lerp",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        return None

    # ------------------------------------------------------------------
    # Pattern Dedektoru 8: Finite Difference
    # ------------------------------------------------------------------

    # Central difference: (f[i+1] - f[i-1]) / (2*h)
    _CENTRAL_DIFF_RE = re.compile(
        r'\(\s*(\w+)\s*\[\s*(\w+)\s*\+\s*1\s*\]\s*-\s*\1\s*\[\s*\2\s*-\s*1\s*\]\s*\)'
        r'\s*/\s*\(\s*2\s*\*\s*(\w+)\s*\)',
    )

    # Forward difference: (f[i+1] - f[i]) / h
    _FORWARD_DIFF_RE = re.compile(
        r'\(\s*(\w+)\s*\[\s*(\w+)\s*\+\s*1\s*\]\s*-\s*\1\s*\[\s*\2\s*\]\s*\)'
        r'\s*/\s*(\w+)',
    )

    # Backward difference: (f[i] - f[i-1]) / h
    _BACKWARD_DIFF_RE = re.compile(
        r'\(\s*(\w+)\s*\[\s*(\w+)\s*\]\s*-\s*\1\s*\[\s*\2\s*-\s*1\s*\]\s*\)'
        r'\s*/\s*(\w+)',
    )

    # Second derivative: (f[i+1] - 2*f[i] + f[i-1]) / (h*h)
    _SECOND_DERIV_RE = re.compile(
        r'\(\s*(\w+)\s*\[\s*(\w+)\s*\+\s*1\s*\]\s*-\s*2\s*\*\s*\1\s*\[\s*\2\s*\]'
        r'\s*\+\s*\1\s*\[\s*\2\s*-\s*1\s*\]\s*\)'
        r'\s*/\s*\(\s*(\w+)\s*\*\s*\3\s*\)',
    )

    def _detect_finite_difference(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Finite difference tespiti: central, forward, backward, second derivative.

        Aranan pattern'ler:
            Central:  (f[i+1] - f[i-1]) / (2*h)  -> f'(x) ~ (f(x+h) - f(x-h)) / 2h
            Forward:  (f[i+1] - f[i]) / h         -> f'(x) ~ (f(x+h) - f(x)) / h
            Backward: (f[i] - f[i-1]) / h         -> f'(x) ~ (f(x) - f(x-h)) / h
            2nd:      (f[i+1] - 2*f[i] + f[i-1]) / (h*h) -> f''(x) ~ ...
        """
        # Oncelik: 2nd derivative > central > forward > backward

        # 2nd derivative
        match = self._SECOND_DERIV_RE.search(code)
        if match is not None:
            arr = match.group(1)
            idx = match.group(2)
            h_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({arr, idx, h_var})

            confidence = 0.85
            if any(kw in func_name.lower() for kw in ("laplacian", "diffusion", "d2", "second")):
                confidence = 0.92

            latex = r"f''(x) \approx \frac{f(x+h) - 2f(x) + f(x-h)}{h^2}"
            ascii_ = "f''(x) ~ (f[i+1] - 2*f[i] + f[i-1]) / h^2"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="finite_diff_2nd",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Central difference
        match = self._CENTRAL_DIFF_RE.search(code)
        if match is not None:
            arr = match.group(1)
            idx = match.group(2)
            h_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({arr, idx, h_var})

            confidence = 0.85
            if any(kw in func_name.lower() for kw in ("deriv", "gradient", "diff", "central")):
                confidence = 0.92

            latex = r"f'(x) \approx \frac{f(x+h) - f(x-h)}{2h}"
            ascii_ = "f'(x) ~ (f[i+1] - f[i-1]) / (2*h)"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="central_difference",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Forward difference
        match = self._FORWARD_DIFF_RE.search(code)
        if match is not None:
            arr = match.group(1)
            idx = match.group(2)
            h_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({arr, idx, h_var})

            confidence = 0.70
            if any(kw in func_name.lower() for kw in ("deriv", "gradient", "diff", "forward")):
                confidence = 0.80

            latex = r"f'(x) \approx \frac{f(x+h) - f(x)}{h}"
            ascii_ = "f'(x) ~ (f[i+1] - f[i]) / h"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="forward_difference",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Backward difference
        match = self._BACKWARD_DIFF_RE.search(code)
        if match is not None:
            arr = match.group(1)
            idx = match.group(2)
            h_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({arr, idx, h_var})

            confidence = 0.65
            if any(kw in func_name.lower() for kw in ("deriv", "gradient", "diff", "backward")):
                confidence = 0.78

            latex = r"f'(x) \approx \frac{f(x) - f(x-h)}{h}"
            ascii_ = "f'(x) ~ (f[i] - f[i-1]) / h"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="backward_difference",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        return None

    # ------------------------------------------------------------------
    # Pattern Dedektoru 9: Exponential Moving Average
    # ------------------------------------------------------------------

    # EMA: ema = alpha * x + (1 - alpha) * ema
    # veya: ema = ema + alpha * (x - ema)
    _EMA_FORM1_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*\+\s*'
        r'\(\s*1(?:\.0?)?\s*-\s*\2\s*\)\s*\*\s*\1',
    )
    _EMA_FORM2_RE = re.compile(
        r'(\w+)\s*=\s*\1\s*\+\s*(\w+)\s*\*\s*\(\s*(\w+)\s*-\s*\1\s*\)',
    )

    def _detect_exponential_moving_avg(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """EMA tespiti: ema = alpha * x + (1-alpha) * ema_prev.

        Aranan pattern'ler:
            Form 1: ema = alpha * x + (1 - alpha) * ema
            Form 2: ema = ema + alpha * (x - ema)  (equivalent)
            -> EMA_t = alpha * x_t + (1 - alpha) * EMA_{t-1}
        """
        # Form 1: ema = alpha * x + (1 - alpha) * ema
        match = self._EMA_FORM1_RE.search(code)
        if match is not None:
            ema_var = match.group(1)
            alpha_var = match.group(2)
            x_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({ema_var, alpha_var, x_var})

            confidence = 0.85
            if any(kw in func_name.lower() for kw in ("ema", "ewma", "smooth", "filter", "moving")):
                confidence = 0.92

            latex = r"\text{EMA}_t = \alpha x_t + (1-\alpha) \text{EMA}_{t-1}"
            ascii_ = "EMA[t] = alpha * x[t] + (1 - alpha) * EMA[t-1]"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="exponential_moving_avg",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Form 2: ema = ema + alpha * (x - ema)
        match = self._EMA_FORM2_RE.search(code)
        if match is not None:
            ema_var = match.group(1)
            alpha_var = match.group(2)
            x_var = match.group(3)

            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = sorted({ema_var, alpha_var, x_var})

            confidence = 0.80
            if any(kw in func_name.lower() for kw in ("ema", "ewma", "smooth", "filter", "moving")):
                confidence = 0.90

            latex = r"\text{EMA}_t = \text{EMA}_{t-1} + \alpha (x_t - \text{EMA}_{t-1})"
            ascii_ = "EMA[t] = EMA[t-1] + alpha * (x[t] - EMA[t-1])"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="exponential_moving_avg",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        return None

    # ------------------------------------------------------------------
    # Pattern Dedektoru 10: Scalar Math Chain
    # ------------------------------------------------------------------

    # 2+ math fonksiyonu ayni satirda veya atamada: exp, log, pow, sqrt, sin, cos, vb.
    _SCALAR_MATH_RE = re.compile(
        r'(\w+)\s*=\s*[^;]*(exp|log|pow|sqrt|sin|cos|tan|asin|acos|atan2?|fabs|cbrt|ceil|floor)\s*\([^;]+;',
        re.IGNORECASE,
    )

    # Ikinci bir math func (zincirleme kontrolu icin)
    _SCALAR_MATH_MULTI_RE = re.compile(
        r'(?:exp|log|pow|sqrt|sin|cos|tan|asin|acos|atan2?|fabs|cbrt|ceil|floor)\s*\(',
        re.IGNORECASE,
    )

    def _detect_scalar_math_chain(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Zincirleme matematik fonksiyon cagrisi tespiti.

        Aranan pattern:
            var = ... exp(...) ... log(...) ... (ayni satirda 2+ math func)
            veya tek math func ile atama (dusuk guven)
            -> y = f(g(x)) seklinde ic ice math fonksiyonlari
        """
        match = self._SCALAR_MATH_RE.search(code)
        if match is None:
            return None

        result_var = match.group(1)
        first_func = match.group(2).lower()  # v1.5.9: Ghidra buyuk harf uretebilir

        # Eslesen satiri cikar
        line_start = code.rfind("\n", 0, match.start()) + 1
        line_end = code.find(";", match.start())
        if line_end == -1:
            line_end = match.end()
        else:
            line_end += 1

        matched_line = code[line_start:line_end].strip()
        snippet = self._extract_snippet(code, match.start(), line_end)

        # Kac math func var bu satirda?
        math_funcs_found = self._SCALAR_MATH_MULTI_RE.findall(matched_line)
        num_math = len(math_funcs_found)

        if num_math >= 2:
            confidence = 0.85
        else:
            confidence = 0.65

        # Fonksiyon ismi ipuclari
        if any(kw in func_name.lower() for kw in ("math", "calc", "compute", "eval")):
            confidence = min(confidence + 0.05, 0.95)

        # Degiskenleri cikar
        variables = [result_var]
        body_idents = re.findall(r'\b([a-zA-Z_]\w*)\b', matched_line)
        math_keywords = {
            "exp", "log", "pow", "sqrt", "sin", "cos", "tan", "asin",
            "acos", "atan", "atan2", "fabs", "cbrt", "ceil", "floor",
            "double", "float", "int", "long",
        }
        variables.extend(v for v in body_idents if v.lower() not in math_keywords)
        variables = sorted(set(variables))

        # LaTeX: gosterilen fonksiyonlara gore
        unique_funcs = sorted(set(
            f.lower() for f in self._SCALAR_MATH_MULTI_RE.findall(matched_line)
        ))
        if len(unique_funcs) >= 2:
            func_chain = " \\circ ".join(
                f"\\text{{{f}}}" for f in unique_funcs[:4]
            )
            latex = f"y = ({func_chain})(x)"
            ascii_ = f"y = {'('.join(unique_funcs[:4])}(x{')'*len(unique_funcs[:4])}"
        else:
            latex = rf"y = \text{{{first_func}}}(x)"
            ascii_ = f"y = {first_func}(x)"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="scalar_math_chain",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 11: Discount / Exponential Decay
    # ------------------------------------------------------------------

    # exp(-...) pattern: discount factor, decay
    _DISCOUNT_RE = re.compile(
        r'(\w+)\s*=\s*[^;]*exp\s*\(\s*-\s*([^)]+)\)',
        re.IGNORECASE,
    )

    def _detect_discount_exp(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Exponential decay / discount factor tespiti.

        Aranan pattern:
            var = ... exp(-r * T) ...
            -> e^{-rT}  (discount factor, radioactive decay, vb.)
        """
        match = self._DISCOUNT_RE.search(code)
        if match is None:
            return None

        result_var = match.group(1)
        exponent_body = match.group(2).strip()

        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degiskenleri cikar
        variables = [result_var]
        body_idents = re.findall(r'\b([a-zA-Z_]\w*)\b', exponent_body)
        c_keywords = {"exp", "double", "float", "int", "long"}
        variables.extend(v for v in body_idents if v not in c_keywords)
        variables = sorted(set(variables))

        # Confidence
        confidence = 0.80
        if any(kw in func_name.lower() for kw in (
            "discount", "decay", "damp", "attenuate", "black", "scholes",
            "price", "option", "rate",
        )):
            confidence = 0.90

        # Exponent'teki carpim var mi (r*T seklinde)
        if "*" in exponent_body:
            confidence = min(confidence + 0.05, 0.95)

        latex = r"e^{-" + exponent_body.replace("*", r" \cdot ") + r"}"
        ascii_ = f"exp(-{exponent_body})"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="discount_exp",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 12: Bitwise Rotation
    # ------------------------------------------------------------------

    # (x << n) | (x >> (W - n))  -- ayni degisken her iki shift'te
    _BITROT_RE = re.compile(
        r'\(\s*(\w+)\s*<<\s*(\w+|\d+)\s*\)\s*\|\s*\(\s*\1\s*>>\s*\(\s*(\d+)\s*-\s*\2\s*\)\s*\)',
    )

    def _detect_bitwise_rotation(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Bitwise rotation tespiti.

        Aranan pattern:
            (x << n) | (x >> (W - n))
            -> x <<< n  (circular left rotation)
        W genellikle 32 veya 64 (register genisligi).
        """
        match = self._BITROT_RE.search(code)
        if match is None:
            return None

        rot_var = match.group(1)
        shift_amount = match.group(2)
        word_size = match.group(3)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({rot_var, shift_amount})

        # Kesin pattern -- ayni degisken her iki shift'te, complementary
        confidence = 0.92
        if any(kw in func_name.lower() for kw in (
            "rotate", "rot", "sha", "md5", "aes", "cipher", "hash", "crypt",
        )):
            confidence = 0.95

        latex = rf"{rot_var} \lll {shift_amount} \quad (W={word_size})"
        ascii_ = f"ROTL({rot_var}, {shift_amount}, W={word_size})"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="bitwise_rotation",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 13: Newton-Raphson
    # ------------------------------------------------------------------

    # Scalar form: x = x - f/g   (x self-update with division)
    _NEWTON_SCALAR_RE = re.compile(
        r'(\w+)\s*=\s*\1\s*-\s*([^;]+)/([^;]+);',
    )

    # Loop form: while/do { ... x += or -= ... ; ... fabs|abs(...)
    _NEWTON_LOOP_RE = re.compile(
        r'(?:while|do)\s*[^{]*\{[^}]*(\w+)\s*[+\-]=\s*[^;]*;[^}]*'
        r'(?:fabs|abs)\s*\(\s*\w+',
        re.DOTALL | re.IGNORECASE,
    )

    def _detect_newton_raphson(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Newton-Raphson iterasyon tespiti.

        Aranan pattern'ler:
            Scalar: x = x - f(x)/f'(x);
            Loop:   while/do { ... x -= delta; ... fabs(delta) < eps ... }
            -> x_{n+1} = x_n - f(x_n) / f'(x_n)
        """
        # Scalar form: x = x - f/g
        match = self._NEWTON_SCALAR_RE.search(code)
        if match is not None:
            iter_var = match.group(1)
            numerator = match.group(2).strip()
            denominator = match.group(3).strip()

            snippet = self._extract_snippet(code, match.start(), match.end())

            # Degiskenleri cikar
            variables = [iter_var]
            for part in (numerator, denominator):
                idents = re.findall(r'\b([a-zA-Z_]\w*)\b', part)
                variables.extend(idents)
            c_keywords = {"double", "float", "int", "long", "unsigned"}
            variables = sorted(set(v for v in variables if v not in c_keywords))

            # Confidence: loop + convergence check varsa artir
            confidence = 0.75
            has_loop = bool(self._NEWTON_LOOP_RE.search(code))
            if has_loop:
                confidence = 0.88

            if any(kw in func_name.lower() for kw in (
                "newton", "raphson", "root", "solve", "bisect", "iterate",
            )):
                confidence = min(confidence + 0.07, 0.95)

            latex = r"x_{n+1} = x_n - \frac{f(x_n)}{f'(x_n)}"
            ascii_ = "x[n+1] = x[n] - f(x[n]) / f'(x[n])"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="newton_raphson",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        # Loop-only form: while loop + update + convergence
        match = self._NEWTON_LOOP_RE.search(code)
        if match is not None:
            iter_var = match.group(1)
            snippet = self._extract_snippet(code, match.start(), match.end())
            variables = [iter_var]

            confidence = 0.70
            if any(kw in func_name.lower() for kw in (
                "newton", "raphson", "root", "solve", "iterate",
            )):
                confidence = 0.85

            latex = r"x_{n+1} = x_n - \frac{f(x_n)}{f'(x_n)}"
            ascii_ = "x[n+1] = x[n] - f(x[n]) / f'(x[n])"

            return ExtractedFormula(
                function_name=func_name,
                formula_type="newton_raphson",
                latex=latex,
                ascii=ascii_,
                c_code_snippet=snippet,
                variables=variables,
                confidence=confidence,
            )

        return None

    # ------------------------------------------------------------------
    # Pattern Dedektoru 14: Variance
    # ------------------------------------------------------------------

    # (x - mean)^2 accumulation: sum += (x[i] - mean) * (x[i] - mean)
    _VARIANCE_RE = re.compile(
        r'(\w+)\s*\+=\s*\(\s*(\w+)(?:\[\w+\])?\s*-\s*(\w+)\s*\)\s*\*\s*\(\s*\2(?:\[\w+\])?\s*-\s*\3\s*\)',
    )

    def _detect_variance(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Varyans hesabi tespiti: sum += (x[i] - mean)^2.

        Aranan pattern:
            sum += (x[i] - mean) * (x[i] - mean)
            -> sigma^2 = (1/n) * sum_{i=0}^{n} (x_i - x_bar)^2
        """
        match = self._VARIANCE_RE.search(code)
        if match is None:
            return None

        acc_var = match.group(1)
        x_var = match.group(2)
        mean_var = match.group(3)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({acc_var, x_var, mean_var})

        # Confidence
        confidence = 0.82
        if any(kw in func_name.lower() for kw in (
            "var", "variance", "std", "stddev", "stdev", "deviation",
            "spread", "moment",
        )):
            confidence = 0.92
        if any(kw in mean_var.lower() for kw in ("mean", "avg", "average", "mu")):
            confidence = min(confidence + 0.05, 0.95)

        latex = r"\sigma^2 = \frac{1}{n}\sum_{i=0}^{n}(x_i - \bar{x})^2"
        ascii_ = "sigma^2 = (1/n) * sum_{i=0}^{n} (x[i] - mean)^2"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="variance",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 15: Normal CDF (Phi)
    # ------------------------------------------------------------------

    # 0.5 * (1 + erf(... / sqrt(2))) veya erfc varyantlari
    _NORMAL_CDF_RE = re.compile(
        r'0\.5\s*\*\s*\(\s*1(?:\.0?)?\s*[+\-]\s*(?:erf|erfc)\s*\('
        r'|(?:erf|erfc)\s*\([^)]*(?:sqrt|1\.414)',
        re.IGNORECASE,
    )

    def _detect_normal_cdf(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Normal CDF (Phi) tespiti.

        Aranan pattern'ler:
            0.5 * (1 + erf(x / sqrt(2)))
            0.5 * (1 - erfc(x / sqrt(2)))
            erf(x / 1.41421...)
            -> Phi(x) = (1/2) * [1 + erf(x / sqrt(2))]
        """
        match = self._NORMAL_CDF_RE.search(code)
        if match is None:
            return None

        # Eslesen bolgeden snippet cikar
        line_start = code.rfind("\n", 0, match.start()) + 1
        line_end = code.find(";", match.start())
        if line_end == -1:
            line_end = code.find("\n", match.start())
        if line_end == -1:
            line_end = match.end()
        else:
            line_end += 1

        snippet = self._extract_snippet(code, match.start(), line_end)

        # Degiskenleri cikar
        matched_line = code[line_start:line_end].strip()
        variables: list[str] = []
        body_idents = re.findall(r'\b([a-zA-Z_]\w*)\b', matched_line)
        c_keywords = {
            "erf", "erfc", "sqrt", "double", "float", "int", "long",
            "return",
        }
        variables = sorted(set(v for v in body_idents if v.lower() not in c_keywords))

        # Confidence
        confidence = 0.88
        if any(kw in func_name.lower() for kw in (
            "normal", "cdf", "phi", "gauss", "probit", "cumulative",
            "black", "scholes",
        )):
            confidence = 0.95

        latex = (
            r"\Phi(x) = \frac{1}{2}\left[1 + \text{erf}"
            r"\left(\frac{x}{\sqrt{2}}\right)\right]"
        )
        ascii_ = "Phi(x) = 0.5 * (1 + erf(x / sqrt(2)))"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="normal_cdf",
            latex=latex,
            ascii=ascii_,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 16: FFT Butterfly (v1.5.9)
    # ------------------------------------------------------------------

    # Butterfly: temp = A +/- B; ... A = A +/- B;  (A array indexli olabilir)
    _FFT_BUTTERFLY_RE = re.compile(
        r'(\w+)\s*=\s*(\w+(?:\[\w+\])?)\s*[\-\+]\s*(\w+)\s*;'
        r'.*?'
        r'\2\s*=\s*\2\s*[\+\-]\s*\3\s*;',
        re.DOTALL,
    )
    # Twiddle factor: sin/cos cagrisi veya exp carpimi yakininda
    _FFT_TWIDDLE_RE = re.compile(
        r'(?:sin|cos|csin|ccos|__sincos)\s*\(|'
        r'\w+\s*\*\s*(?:cos|sin)\s*\(',
        re.IGNORECASE,
    )

    def _detect_fft_butterfly(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 16: FFT Butterfly pattern.

        Aranan pattern:
            temp = w * x[j]; x[j] = x[i] - temp; x[i] = x[i] + temp
            VEYA: butterfly add/sub cifti + twiddle factor (sin/cos)

        v1.6.5: Twiddle factor (sin/cos) veya FFT func name ZORUNLU.
        Onceki versiyon sadece add/sub cifti ariyordu ve her binary'de
        yuzlerce false positive uretiyordu.
        """
        match = self._FFT_BUTTERFLY_RE.search(code)
        if match is None:
            return None

        has_twiddle = self._FFT_TWIDDLE_RE.search(code) is not None
        has_fft_name = any(kw in func_name.lower() for kw in (
            "fft", "butterfly", "dft", "ifft", "fourier", "radix",
        ))

        # v1.6.5: Butterfly pattern tek basina cok genel.
        # Twiddle factor VEYA FFT-related func name olmadan false positive.
        if not has_twiddle and not has_fft_name:
            return None

        confidence = 0.85
        if has_twiddle:
            confidence = 0.90
        if has_fft_name:
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        latex = r"X_k = \sum_{n=0}^{N-1} x_n e^{-2\pi i k n / N}"
        ascii_form = "X[k] = sum_{n=0}^{N-1} x[n] * exp(-2*pi*i*k*n/N)"

        # Degiskenleri cikar -- array index'li olabilir, sadece base ismini al
        raw_vars = {match.group(1), match.group(2), match.group(3)}
        variables = sorted({v.split('[')[0] for v in raw_vars if v})

        return ExtractedFormula(
            function_name=func_name,
            formula_type="fft_butterfly",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 17: Convolution (v1.5.9)
    # ------------------------------------------------------------------

    # for(k) out[i] += kernel[k] * input[i - k + ...]  (nested for destekli)
    _CONVOLUTION_RE = re.compile(
        r'(?:for|do)\s*(?:\([^)]*\))?\s*\{.*?'
        r'(\w+(?:\[\w+\])?)\s*\+=\s*[^;]*\w+\s*\[\s*\w+\s*\]\s*\*\s*\w+\s*\[\s*[^]]*[\-\+][^]]*\]',
        re.DOTALL,
    )

    def _detect_convolution(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 17: Convolution pattern.

        Aranan pattern:
            for(k) sum += h[k] * x[n-k]
            -> (f * g)[n] = sum_k f[k] * g[n-k]
        """
        match = self._CONVOLUTION_RE.search(code)
        if match is None:
            return None

        confidence = 0.80
        if any(kw in func_name.lower() for kw in (
            "conv", "filter", "convolve", "correlate", "fir", "iir",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        acc_var = match.group(1).split('[')[0]  # out[i] -> out
        variables = [acc_var]

        latex = r"(f * g)[n] = \sum_{k} f[k] \cdot g[n-k]"
        ascii_form = "(f * g)[n] = sum_k f[k] * g[n-k]"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="convolution",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 18: Gradient Descent (v1.5.9)
    # ------------------------------------------------------------------

    # w = w - lr * grad  VEYA  param -= learning_rate * gradient
    # Basit: w = w - lr * g  |  Array: w[i] = w[i] - lr * g[i]  |  -= operatoru
    _GRADIENT_DESCENT_RE = re.compile(
        r'(\w+)\s*=\s*\1\s*-\s*(\w+)\s*\*\s*(\w+)'
        r'|(\w+)\[(\w+)\]\s*=\s*\4\[\5\]\s*-\s*(\w+)\s*\*\s*(\w+)'
        r'|(\w+)(?:\[\w+\])?\s*-=\s*(\w+)\s*\*\s*(\w+)',
    )

    def _detect_gradient_descent(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 18: Gradient Descent pattern.

        Aranan pattern:
            w = w - lr * grad
            param -= learning_rate * gradient
            -> theta_{t+1} = theta_t - alpha * nabla L(theta_t)
        """
        match = self._GRADIENT_DESCENT_RE.search(code)
        if match is None:
            return None

        confidence = 0.75
        if any(kw in func_name.lower() for kw in (
            "grad", "learn", "optim", "update", "train", "sgd", "descent",
        )):
            confidence = min(confidence + 0.07, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        # 3 regex alternatifi: basit(1,2,3) | array(4,6,7) | -=(8,9,10)
        if match.group(1) is not None:
            param_var, lr_var, grad_var = match.group(1), match.group(2), match.group(3)
        elif match.group(4) is not None:
            param_var, lr_var, grad_var = match.group(4), match.group(6), match.group(7)
        else:
            param_var, lr_var, grad_var = match.group(8), match.group(9), match.group(10)
        variables = sorted({v for v in (param_var, lr_var, grad_var) if v})

        latex = r"\theta_{t+1} = \theta_t - \alpha \nabla L(\theta_t)"
        ascii_form = "theta[t+1] = theta[t] - alpha * grad_L(theta[t])"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="gradient_descent",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 19: Adam Optimizer (v1.5.9)
    # ------------------------------------------------------------------

    # EMA of gradient: m = beta1 * m + (1-beta1) * grad
    # EMA of gradient^2: v = beta2 * v + (1-beta2) * grad * grad
    _ADAM_EMA_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*\*\s*\1\s*\+\s*[^;]*\*\s*(\w+)\s*;'
        r'.*?'
        r'(\w+)\s*=\s*(\w+)\s*\*\s*\4\s*\+\s*[^;]*\*\s*\3\s*\*\s*\3',
        re.DOTALL,
    )
    # sqrt + eps bolme: / (sqrt(v) + eps)
    _ADAM_SQRT_EPS_RE = re.compile(
        r'(?:sqrt|sqrtf)\s*\([^)]*\)\s*\+\s*\w+',
        re.IGNORECASE,
    )

    def _detect_adam_optimizer(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 19: Adam Optimizer pattern.

        Aranan pattern:
            m = b1*m + (1-b1)*g;  v = b2*v + (1-b2)*g*g;
            param -= lr * m / (sqrt(v) + eps)
        """
        match = self._ADAM_EMA_RE.search(code)
        if match is None:
            return None

        confidence = 0.80
        if self._ADAM_SQRT_EPS_RE.search(code) is not None:
            confidence = min(confidence + 0.10, 0.95)

        if any(kw in func_name.lower() for kw in (
            "adam", "optim", "update_param", "train",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        m_var = match.group(1)
        g_var = match.group(3)
        v_var = match.group(4)
        variables = sorted({m_var, g_var, v_var})

        latex = (
            r"\theta_{t+1} = \theta_t - \frac{\alpha \hat{m}_t}"
            r"{\sqrt{\hat{v}_t} + \epsilon}"
        )
        ascii_form = "theta[t+1] = theta[t] - alpha * m_hat / (sqrt(v_hat) + eps)"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="adam_optimizer",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 20: Horner's Method (v1.5.9)
    # ------------------------------------------------------------------

    # result = a[n]; for(...) result = result * x + a[i]
    # VEYA: r = c0; r = r*x + c1; r = r*x + c2; ...
    # Katsayi literal sayi (3.0, 2.5) veya degisken olabilir
    _HORNER_RE = re.compile(
        r'(\w+)\s*=\s*\1\s*\*\s*(\w+)\s*\+\s*[^;\n]+'
        r'(?:\s*;\s*\1\s*=\s*\1\s*\*\s*\2\s*\+\s*[^;\n]+){1,}',
    )

    def _detect_horner(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 20: Horner's Method pattern.

        Aranan pattern:
            r = c0; r = r*x + c1; r = r*x + c2; ...
            -> p(x) = a_0 + x(a_1 + x(a_2 + ...))
        """
        match = self._HORNER_RE.search(code)
        if match is None:
            return None

        confidence = 0.85
        # 3+ ardisik chain tespiti
        chain_text = code[match.start():match.end()]
        chain_count = chain_text.count('=')
        if chain_count >= 4:
            confidence = 0.90

        if any(kw in func_name.lower() for kw in (
            "horner", "poly", "eval", "polynomial",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        result_var = match.group(1)
        x_var = match.group(2)
        variables = sorted({result_var, x_var})

        latex = r"p(x) = a_0 + x(a_1 + x(a_2 + \cdots))"
        ascii_form = "p(x) = a[0] + x*(a[1] + x*(a[2] + ...))"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="horner",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 21: Cross Product (v1.5.9)
    # ------------------------------------------------------------------

    # r[0] = a[1]*b[2] - a[2]*b[1];
    # r[1] = a[2]*b[0] - a[0]*b[2];
    # r[2] = a[0]*b[1] - a[1]*b[0];
    # [^\n] ile satir icinde kalarak backtracking onlenir
    _CROSS_PRODUCT_RE = re.compile(
        r'(\w+)[^\n]*=\s*(\w+)[^\n]*\*\s*(\w+)[^\n]*-\s*\2[^\n]*\*\s*\3[^\n]*;'
        r'\s*'
        r'\1[^\n]*=\s*\2[^\n]*\*\s*\3[^\n]*-\s*\2[^\n]*\*\s*\3[^\n]*;',
    )

    def _detect_cross_product(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 21: 3D Cross Product pattern.

        Aranan pattern:
            r[0] = a[1]*b[2] - a[2]*b[1];
            r[1] = a[2]*b[0] - a[0]*b[2];
            r[2] = a[0]*b[1] - a[1]*b[0];
        """
        match = self._CROSS_PRODUCT_RE.search(code)
        if match is None:
            return None

        confidence = 0.90
        if any(kw in func_name.lower() for kw in (
            "cross", "product", "vec3", "vector",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        r_var = match.group(1)
        a_var = match.group(2)
        b_var = match.group(3)
        variables = sorted({r_var, a_var, b_var})

        latex = (
            r"\vec{a} \times \vec{b} = "
            r"(a_2 b_3 - a_3 b_2,\; a_3 b_1 - a_1 b_3,\; a_1 b_2 - a_2 b_1)"
        )
        ascii_form = "a x b = (a2*b3-a3*b2, a3*b1-a1*b3, a1*b2-a2*b1)"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="cross_product",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 22: Simpson's Rule Quadrature (v1.5.9)
    # ------------------------------------------------------------------

    # v1.6.5: Simpson pattern SIKILASIRILDI.
    # Eski pattern: `4 * ... 2 *` DOTALL ile HER yerde eslesiyordu.
    # Yeni: Ayni satirda/yakin satirlarda 4* ve 2* carpanlari + h/3 bolumu
    # veya ayni satirda alternating 4*f + 2*f pattern'i.
    _SIMPSON_RE = re.compile(
        # Pattern A: h/3 * (...) formunda h bolme 3 ile carpim
        r'\w+\s*/\s*(?:3|3\.0)\s*\*\s*\([^)]*(?:4\s*\*|4\.0\s*\*)[^)]*(?:2\s*\*|2\.0\s*\*)'
        r'|'
        # Pattern B: ayni satirda  += 4 * f(...) ve += 2 * f(...) (50 char icinde)
        r'(?:4\s*\*|4\.0\s*\*)\s*\w+\s*\([^)]*\)[^;\n]{0,80}(?:2\s*\*|2\.0\s*\*)\s*\w+\s*\(',
    )

    def _detect_simpson_quadrature(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 22: Simpson's Rule Quadrature pattern.

        Aranan pattern:
            (h/3) * (f0 + 4*f1 + 2*f2 + 4*f3 + ... + fn)
            -> integral_a^b f(x)dx approx (h/3)[f(a) + 4f(x1) + 2f(x2) + ... + f(b)]

        v1.6.5: Pattern sikilasirildi -- sadece h/3 ile birlikte VEYA
        ayni satirda alternating 4/2 carpanlari ile eslestir.
        Onceki DOTALL pattern her binary'de false positive uretiyordu.
        """
        match = self._SIMPSON_RE.search(code)
        if match is None:
            return None

        confidence = 0.82
        # h/3 carpani tespiti
        if re.search(r'\w+\s*/\s*(?:3|3\.0)\s*\*', code):
            confidence = min(confidence + 0.05, 0.95)

        if any(kw in func_name.lower() for kw in (
            "simpson", "quad", "integrate", "quadrature", "numerical_int",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degiskenleri cikar
        matched_text = code[match.start():match.end()]
        idents = re.findall(r'\b([a-zA-Z_]\w*)\b', matched_text)
        c_keywords = {"for", "do", "if", "int", "double", "float", "return"}
        variables = sorted(set(v for v in idents if v.lower() not in c_keywords))

        latex = (
            r"\int_a^b f(x)\,dx \approx \frac{h}{3}"
            r"\left[f(a) + 4f(x_1) + 2f(x_2) + \cdots + f(b)\right]"
        )
        ascii_form = "integral(f, a, b) ~= (h/3) * [f(a) + 4*f(x1) + 2*f(x2) + ... + f(b)]"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="simpson_quadrature",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 23: CRC / Hash Round (v1.5.9)
    # ------------------------------------------------------------------

    # CRC: (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    _CRC_HASH_RE = re.compile(
        r'(\w+)\s*=\s*\(\s*\1\s*>>\s*\d+\s*\)\s*\^\s*\w+\s*\['
        r'|(\w+)\s*=\s*\w+\s*\[\s*\(\s*\2\s*\^',
    )

    def _detect_crc_hash_round(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 23: CRC / Hash Round pattern.

        Aranan pattern:
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
        """
        match = self._CRC_HASH_RE.search(code)
        if match is None:
            return None

        confidence = 0.85
        if any(kw in func_name.lower() for kw in (
            "crc", "hash", "checksum", "digest",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degiskenleri cikar: crc veya hash degiskeni
        crc_var = match.group(1) or match.group(2)
        variables = [crc_var] if crc_var else []

        latex = (
            r"\text{CRC}(n) = (\text{CRC}(n{-}1) \gg 8) \oplus "
            r"T[(\text{CRC}(n{-}1) \oplus d_n) \wedge \text{0xFF}]"
        )
        ascii_form = "CRC[n] = (CRC[n-1] >> 8) ^ table[(CRC[n-1] ^ data[n]) & 0xFF]"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="crc_hash_round",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 24: Softmax (v1.5.9)
    # ------------------------------------------------------------------

    # exp(x[i]) / sum(exp(x[j]))
    _SOFTMAX_RE = re.compile(
        r'(?:exp|expf|EXP)\s*\([^)]*\)\s*/\s*(\w+)'
        r'|(\w+)\s*\+=\s*(?:exp|expf|EXP)\s*\(',
        re.IGNORECASE,
    )

    def _detect_softmax(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 24: Softmax pattern.

        Aranan pattern:
            sum += exp(x[i]);  ...  out[i] = exp(x[i]) / sum;
            -> softmax(x_i) = exp(x_i) / sum_j exp(x_j)
        """
        match = self._SOFTMAX_RE.search(code)
        if match is None:
            return None

        confidence = 0.85
        # Hem exp toplami hem bolme varsa daha guclu sinyal
        has_exp_sum = bool(re.search(
            r'\w+\s*\+=\s*(?:exp|expf|EXP)\s*\(', code, re.IGNORECASE,
        ))
        has_exp_div = bool(re.search(
            r'(?:exp|expf|EXP)\s*\([^)]*\)\s*/\s*\w+', code, re.IGNORECASE,
        ))
        if has_exp_sum and has_exp_div:
            confidence = 0.90

        if any(kw in func_name.lower() for kw in (
            "softmax", "attention", "probability", "logit",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        # Degisken cikarma
        sum_var = match.group(1) or match.group(2)
        variables = [sum_var] if sum_var else []

        latex = (
            r"\text{softmax}(x_i) = "
            r"\frac{e^{x_i}}{\sum_j e^{x_j}}"
        )
        ascii_form = "softmax(x[i]) = exp(x[i]) / sum_j(exp(x[j]))"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="softmax",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ==================================================================
    # v1.6.5: Genel Amacli Algoritma Dedektorleri (25-34)
    # ==================================================================
    # Bu dedektorler math/engineering formullerinden ziyade, her turlu
    # binary'de bulunan genel programlama algoritma pattern'lerini tespit
    # eder: binary search, linked list, hash table, sort, vb.
    # Hepsi Phase 1 (non-DOTALL), buyuk fonksiyonlarda da guvenle calisir.
    # ==================================================================

    # ------------------------------------------------------------------
    # Pattern Dedektoru 25: Binary Search (v1.6.5)
    # ------------------------------------------------------------------

    # mid = (lo + hi) / 2  VEYA  mid = (lo + hi) >> 1
    # Ghidra: iVar = (iVar2 + iVar3) / 2  veya  >> 1
    _BINARY_SEARCH_RE = re.compile(
        r'(\w+)\s*=\s*\(?\s*(\w+)\s*\+\s*(\w+)\s*\)?\s*(?:/\s*2|>>\s*1)',
    )

    # Loop ile birlikte: while (lo < hi) veya do { ... } while (...)
    _BINARY_SEARCH_LOOP_RE = re.compile(
        r'while\s*\([^)]*(?:<|<=|!=)[^)]*\)\s*\{'
        r'|do\s*\{',
    )

    def _detect_binary_search(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 25: Binary Search pattern.

        Aranan pattern:
            mid = (lo + hi) / 2;
            if (arr[mid] < target) lo = mid + 1;
            else hi = mid - 1;
        """
        match = self._BINARY_SEARCH_RE.search(code)
        if match is None:
            return None

        # Binary search mutlaka dongu icinde olmali
        has_loop = self._BINARY_SEARCH_LOOP_RE.search(code) is not None
        if not has_loop:
            return None

        mid_var = match.group(1)
        lo_var = match.group(2)
        hi_var = match.group(3)

        confidence = 0.88
        # Karsilastirma + boundary update varsa guven artar
        has_boundary_update = bool(re.search(
            rf'{re.escape(lo_var)}\s*=\s*{re.escape(mid_var)}|'
            rf'{re.escape(hi_var)}\s*=\s*{re.escape(mid_var)}',
            code,
        ))
        if has_boundary_update:
            confidence = 0.92

        if any(kw in func_name.lower() for kw in (
            "search", "find", "lookup", "bisect", "bsearch", "binary",
        )):
            confidence = min(confidence + 0.03, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({mid_var, lo_var, hi_var})

        latex = (
            r"\text{BinarySearch}: m = \lfloor \frac{lo + hi}{2} \rfloor, "
            r"\; \text{if } A[m] < t \Rightarrow lo = m+1 \; \text{else } hi = m-1"
        )
        ascii_form = (
            "BinarySearch: mid = (lo + hi) / 2; "
            "if A[mid] < target: lo = mid+1 else hi = mid-1"
        )

        return ExtractedFormula(
            function_name=func_name,
            formula_type="binary_search",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 26: Linked List Traversal (v1.6.5)
    # ------------------------------------------------------------------

    # ptr = *(type*)(ptr + offset)  veya  ptr = ptr->next  veya  ptr = base[index]
    # Ghidra raw: param_2 = *(long *)(lVar1 + 0x58);
    # Ghidra normalized: param_2 = lVar1[11];   (after _normalize_ghidra_code)
    _LINKED_LIST_RE = re.compile(
        # Pattern A: raw Ghidra pointer dereference (self-referencing)
        r'(\w+)\s*=\s*\*\s*\(\s*(?:long|int|void|undefined\d*)\s*\*?\s*\)\s*\(\s*\1\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)'
        # Pattern B: raw Ghidra pointer dereference (different base)
        r'|(\w+)\s*=\s*\*\s*\(\s*(?:long|int|void|undefined\d*)\s*\*?\s*\*?\s*\)\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)'
        # Pattern C: normalized array index (after Ghidra normalization)
        # ptr = base[fixed_index] inside a loop -- structural access
        r'|(\w+)\s*=\s*(\w+)\s*\[\s*\d+\s*\]',
    )

    # Null check loop: while (ptr != 0) veya do { ... } while (ptr != 0)
    _NULL_CHECK_LOOP_RE = re.compile(
        r'(?:while|do)[^{]*!=\s*(?:0(?:x0)?|NULL|\(void\s*\*\)0x0)',
    )

    def _detect_linked_list_traversal(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 26: Linked List Traversal pattern.

        Aranan pattern:
            do { cur = *(long *)(cur + OFFSET); } while (cur != 0);
        """
        match = self._LINKED_LIST_RE.search(code)
        if match is None:
            return None

        # Null-terminated loop kontrolu
        has_null_loop = self._NULL_CHECK_LOOP_RE.search(code) is not None
        if not has_null_loop:
            return None

        ptr_var = match.group(1) or match.group(2) or match.group(3) or "ptr"
        confidence = 0.85

        if any(kw in func_name.lower() for kw in (
            "list", "walk", "traverse", "iter", "next", "chain", "link",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = [ptr_var]

        latex = (
            r"\text{LinkedList}: p \leftarrow p{\to}\text{next} "
            r"\;\text{while}\; p \neq \text{NULL}"
        )
        ascii_form = "LinkedList: p = p->next while p != NULL"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="linked_list_traversal",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 27: Comparison Swap (v1.6.5)
    # ------------------------------------------------------------------

    # if (a > b) { tmp = a; a = b; b = tmp; }
    # Ghidra: if (cond) { lVar = x; x = y; y = lVar; }
    _COMPARISON_SWAP_RE = re.compile(
        r'if\s*\([^)]*[<>][^)]*\)\s*\{[^}]*'
        r'(\w+)\s*=\s*(\w+)\s*;[^}]*'
        r'\2\s*=\s*(\w+)\s*;[^}]*'
        r'\3\s*=\s*\1\s*;',
        re.DOTALL,
    )

    # Simpler swap: conditional assignment pair (no temp, e.g. XOR swap or
    # just comparison + assignment in Ghidra output)
    _COND_ASSIGN_RE = re.compile(
        r'if\s*\(\s*(\w+(?:\[[^\]]*\])?)\s*[<>]\s*(\w+(?:\[[^\]]*\])?)\s*\)',
    )

    def _detect_comparison_swap(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 27: Comparison-based Swap pattern.

        Aranan pattern:
            if (a > b) { tmp = a; a = b; b = tmp; }
            -> Sorting primitive / conditional swap
        """
        match = self._COMPARISON_SWAP_RE.search(code)
        if match is not None:
            tmp_var = match.group(1)
            a_var = match.group(2)
            b_var = match.group(3)
            confidence = 0.88
            variables = sorted({tmp_var, a_var, b_var})
        else:
            # Fallback: conditional compare + reassignment of both vars
            # Handles array-indexed comparisons: if (arr[j] > arr[j+1])
            cond_match = self._COND_ASSIGN_RE.search(code)
            if cond_match is None:
                return None
            a_full = cond_match.group(1)  # e.g. "arr[j]"
            b_full = cond_match.group(2)  # e.g. "arr[j+1]"
            a_base = a_full.split('[')[0]
            b_base = b_full.split('[')[0]
            after_code = code[cond_match.end():cond_match.end() + 300]
            # Check if both expressions (or their base) are reassigned
            # For array elements: look for base[...] = pattern
            has_a_assign = bool(re.search(
                rf'{re.escape(a_base)}\s*\[', after_code,
            )) if '[' in a_full else bool(re.search(
                rf'{re.escape(a_full)}\s*=\s*', after_code,
            ))
            has_b_assign = bool(re.search(
                rf'{re.escape(b_base)}\s*\[', after_code,
            )) if '[' in b_full else bool(re.search(
                rf'{re.escape(b_full)}\s*=\s*', after_code,
            ))
            # Also need a temp variable (tmp = ...) before reassignment
            has_temp = bool(re.search(
                r'(?:int|long|char|short|float|double)\s+\w+\s*=\s*'
                rf'{re.escape(a_base)}',
                after_code,
            ))
            if not (has_a_assign and has_b_assign and has_temp):
                return None
            match = cond_match
            confidence = 0.82
            variables = sorted({a_base, b_base})

        if any(kw in func_name.lower() for kw in (
            "sort", "swap", "partition", "qsort", "bubble", "insertion",
            "merge", "heap", "sift",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        latex = (
            r"\text{Swap}: \text{if } a > b \Rightarrow (a, b) \leftarrow (b, a)"
        )
        ascii_form = "Swap: if a > b then (a, b) = (b, a)"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="comparison_swap",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 28: Hash Table Probe (v1.6.5)
    # ------------------------------------------------------------------

    # index = hash & mask  veya  index = hash % size
    # while (table[index] != 0) index = (index + 1) & mask   (linear probe)
    _HASH_INDEX_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*[&%]\s*(\w+)',
    )
    _HASH_PROBE_RE = re.compile(
        r'(\w+)\s*=\s*\(\s*\1\s*\+\s*\d+\s*\)\s*[&%]'
        r'|(\w+)\s*=\s*\2\s*\+\s*\d+\s*;\s*(?:if|while)',
    )

    def _detect_hash_table_probe(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 28: Hash Table Probe pattern.

        Aranan pattern:
            idx = hash & mask;
            while (table[idx] != EMPTY) idx = (idx + 1) & mask;
        """
        idx_match = self._HASH_INDEX_RE.search(code)
        if idx_match is None:
            return None

        # Probe/rehash veya loop icinde array index gerektir
        has_probe = self._HASH_PROBE_RE.search(code) is not None
        idx_var = idx_match.group(1)
        has_array_loop = bool(re.search(
            rf'\w+\s*\[\s*{re.escape(idx_var)}\s*\]',
            code,
        ))
        if not has_probe and not has_array_loop:
            return None

        # En az & veya % ile hash hesaplama + loop gerektir
        has_loop = bool(re.search(r'(?:while|do|for)\s*[\({]', code))
        if not has_loop:
            return None

        confidence = 0.82
        if has_probe:
            confidence = 0.88

        if any(kw in func_name.lower() for kw in (
            "hash", "probe", "lookup", "table", "dict", "map", "find",
            "insert", "bucket",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, idx_match.start(), idx_match.end())
        hash_var = idx_match.group(2)
        mask_var = idx_match.group(3)
        variables = sorted({idx_var, hash_var, mask_var})

        latex = (
            r"\text{HashProbe}: i = h(k) \;\&\; m, "
            r"\;\text{while}\; T[i] \neq \emptyset: "
            r"i = (i+1) \;\&\; m"
        )
        ascii_form = "HashProbe: i = hash(key) & mask; while T[i] != EMPTY: i = (i+1) & mask"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="hash_table_probe",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 29: Bitmask Extract (v1.6.5)
    # ------------------------------------------------------------------

    # (val >> shift) & mask
    # Ghidra: (*(uint *)(ptr + 0x10) >> 0x11) & 1
    _BITMASK_EXTRACT_RE = re.compile(
        r'(\w+)\s*=\s*\(?[^;]*>>\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*&\s*(0x[0-9a-fA-F]+|\d+)',
    )

    def _detect_bitmask_extract(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 29: Bitmask Field Extraction pattern.

        Aranan pattern:
            field = (value >> shift) & mask
            -> Bitfield extraction: belirli bit araligini cikarma
        """
        match = self._BITMASK_EXTRACT_RE.search(code)
        if match is None:
            return None

        result_var = match.group(1)
        shift_str = match.group(2)
        mask_str = match.group(3)

        # Trivial shift=0 veya mask=0 disarida birak
        try:
            shift_val = int(shift_str, 16) if shift_str.startswith('0x') else int(shift_str)
            mask_val = int(mask_str, 16) if mask_str.startswith('0x') else int(mask_str)
        except ValueError:
            shift_val, mask_val = 1, 1

        if shift_val == 0 and mask_val == 0:
            return None

        confidence = 0.80
        # Birden fazla extract varsa (struct bitfield decode)
        extract_count = len(self._BITMASK_EXTRACT_RE.findall(code))
        if extract_count >= 3:
            confidence = 0.88
        elif extract_count >= 2:
            confidence = 0.84

        if any(kw in func_name.lower() for kw in (
            "flag", "bit", "field", "mask", "decode", "extract", "parse",
            "unpack", "header",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = [result_var]

        width = bin(mask_val).count('1') if mask_val > 0 else 1
        latex = (
            rf"\text{{BitExtract}}: {result_var} = "
            rf"(v \gg {shift_val}) \;\&\; \text{{0x{mask_val:X}}} "
            rf"\quad [{width}\text{{ bit}}]"
        )
        ascii_form = (
            f"BitExtract: {result_var} = (val >> {shift_val}) & 0x{mask_val:X} "
            f"[{width} bit]"
        )

        return ExtractedFormula(
            function_name=func_name,
            formula_type="bitmask_extract",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 30: Byte Pack/Unpack (v1.6.5)
    # ------------------------------------------------------------------

    # val = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0   (pack)
    # b0 = val & 0xFF; b1 = (val >> 8) & 0xFF; ...      (unpack)
    _BYTE_PACK_RE = re.compile(
        r'(?:<<\s*(?:8|0x8|16|0x10|24|0x18))\s*(?:\||\+)'
        r'|(?:\||\+)\s*[^;]*<<\s*(?:8|0x8|16|0x10|24|0x18)',
    )
    _BYTE_UNPACK_RE = re.compile(
        r'>>\s*(?:8|0x8|16|0x10|24|0x18)\s*\)\s*&\s*(?:0[xX][fF]{2}|255)',
    )

    def _detect_byte_pack_unpack(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 30: Byte Pack/Unpack pattern.

        Aranan pattern:
            Pack:   val = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
            Unpack: b0 = val & 0xFF; b1 = (val >> 8) & 0xFF; ...
        """
        pack_match = self._BYTE_PACK_RE.search(code)
        unpack_match = self._BYTE_UNPACK_RE.search(code)

        if pack_match is None and unpack_match is None:
            return None

        is_pack = pack_match is not None
        is_unpack = unpack_match is not None
        match = pack_match or unpack_match

        confidence = 0.82
        # Her iki yonde de varsa (encode+decode) daha kesin
        if is_pack and is_unpack:
            confidence = 0.90
        # Birden fazla shift varsa kesinlik artar
        shift_count = len(re.findall(
            r'<<\s*(?:8|0x8|16|0x10|24|0x18)', code,
        )) + len(re.findall(
            r'>>\s*(?:8|0x8|16|0x10|24|0x18)', code,
        ))
        if shift_count >= 4:
            confidence = max(confidence, 0.90)
        elif shift_count >= 2:
            confidence = max(confidence, 0.85)

        if any(kw in func_name.lower() for kw in (
            "pack", "unpack", "serialize", "deserialize", "encode", "decode",
            "ntoh", "hton", "swap_bytes", "endian", "get_byte",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = []

        if is_pack:
            op_type = "Pack"
            latex = (
                r"\text{BytePack}: v = (b_3 \ll 24) \;|\; (b_2 \ll 16) "
                r"\;|\; (b_1 \ll 8) \;|\; b_0"
            )
            ascii_form = "BytePack: val = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0"
        else:
            op_type = "Unpack"
            latex = (
                r"\text{ByteUnpack}: b_i = (v \gg 8i) \;\&\; \text{0xFF}"
            )
            ascii_form = "ByteUnpack: b[i] = (val >> 8*i) & 0xFF"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="byte_pack_unpack",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 31: Table Lookup (v1.6.5)
    # ------------------------------------------------------------------

    # result = CONST_TABLE[index]  veya  DAT_xxx + offset * stride
    # Ghidra: *(type*)(PTR_DAT_xxx + (long)index * stride)
    _TABLE_LOOKUP_RE = re.compile(
        r'(?:DAT_|PTR_|&DAT_|_DAT_)\w+\s*(?:\+\s*(?:\(long\)\s*)?\w+\s*\*\s*\d+|\[\s*\w+\s*\])',
    )
    # Alternative: constant array with literal name
    _CONST_ARRAY_LOOKUP_RE = re.compile(
        r'(?:table|tab|lut|map|xlat|lookup|charset|encoding)\w*\s*\[\s*\w+\s*\]',
        re.IGNORECASE,
    )

    def _detect_table_lookup(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 31: Table Lookup / Constant Array Access pattern.

        Aranan pattern:
            result = CONST_TABLE[index]
            result = *(type*)(DAT_xxx + index * stride)
        """
        match = self._TABLE_LOOKUP_RE.search(code)
        if match is None:
            match = self._CONST_ARRAY_LOOKUP_RE.search(code)
        if match is None:
            return None

        confidence = 0.78
        # Birden fazla lookup (switch-table veya character classification)
        lookup_count = len(self._TABLE_LOOKUP_RE.findall(code))
        if lookup_count >= 5:
            confidence = 0.88
        elif lookup_count >= 2:
            confidence = 0.83

        if any(kw in func_name.lower() for kw in (
            "lookup", "table", "xlat", "translate", "classify", "map",
            "decode", "convert",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())

        latex = r"\text{TableLookup}: r = T[\,\text{index}\,]"
        ascii_form = "TableLookup: result = TABLE[index]"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="table_lookup",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=[],
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 32: Min/Max Scan (v1.6.5)
    # ------------------------------------------------------------------

    # if (x < min) min = x;  veya  if (x > max) max = x;
    _MINMAX_SCAN_RE = re.compile(
        r'if\s*\(\s*(\w+(?:\[[^\]]*\])?)\s*([<>])\s*(\w+)\s*\)\s*(?:\{?\s*)?'
        r'\3\s*=\s*\1\s*;',
    )

    def _detect_minmax_scan(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 32: Min/Max Scan pattern.

        Aranan pattern:
            for (...) if (arr[i] < min_val) min_val = arr[i];
            -> Linear scan for minimum/maximum
        """
        match = self._MINMAX_SCAN_RE.search(code)
        if match is None:
            return None

        value_expr = match.group(1).split('[')[0]
        comparator = match.group(2)
        accum_var = match.group(3)

        is_min = comparator == '<'
        op_name = "min" if is_min else "max"

        confidence = 0.85
        # Loop icinde mi?
        has_loop = bool(re.search(r'(?:for|while|do)\s*[\({]', code))
        if has_loop:
            confidence = 0.90

        if any(kw in func_name.lower() for kw in (
            "min", "max", "minimum", "maximum", "best", "worst", "peak",
            "extreme",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({value_expr, accum_var})

        latex = (
            rf"\text{{{op_name}Scan}}: {accum_var} = "
            rf"\{op_name}_{{i}} \; x_i"
        )
        ascii_form = f"{op_name}Scan: {accum_var} = {op_name}(x[0..n])"

        return ExtractedFormula(
            function_name=func_name,
            formula_type=f"{op_name}_scan",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 33: Counting / Frequency (v1.6.5)
    # ------------------------------------------------------------------

    # count[val]++  veya  count[val] += 1
    # Histogram, frequency counting, bucket counting
    _COUNTING_RE = re.compile(
        r'(\w+)\s*\[\s*(\w+(?:\[[^\]]*\])?)\s*\]\s*(?:\+\+|\+=\s*1)',
    )

    def _detect_counting_frequency(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 33: Counting/Frequency pattern.

        Aranan pattern:
            count[val]++ veya hist[bucket] += 1
            -> Histogram / frequency counting
        """
        match = self._COUNTING_RE.search(code)
        if match is None:
            return None

        count_arr = match.group(1)
        index_expr = match.group(2).split('[')[0]

        confidence = 0.82
        # Loop icinde mi?
        has_loop = bool(re.search(r'(?:for|while|do)\s*[\({]', code))
        if has_loop:
            confidence = 0.88

        if any(kw in func_name.lower() for kw in (
            "count", "freq", "hist", "histogram", "tally", "stat",
            "distribution", "bucket",
        )):
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = sorted({count_arr, index_expr})

        latex = (
            rf"\text{{Counting}}: {count_arr}[v] \leftarrow "
            rf"{count_arr}[v] + 1"
        )
        ascii_form = f"Counting: {count_arr}[val]++"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="counting_frequency",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Pattern Dedektoru 34: Sentinel-Terminated Loop (v1.6.5)
    # ------------------------------------------------------------------

    # while (*ptr != '\0') ptr++;  (string walk)
    # while (*(ptr + offset) != 0) { ... }
    # do { ... } while (*ptr != 0);
    _SENTINEL_LOOP_RE = re.compile(
        r'while\s*\(\s*\*\s*(\w+)\s*!=\s*(?:\'\\0\'|0(?:x0)?|0x0+)\s*\)'
        r'|while\s*\(\s*\*\s*\(\s*\w+\s*\*?\s*\)\s*(\w+)\s*!=\s*(?:0(?:x0)?)\s*\)'
        r'|while\s*\(\s*(\w+)\s*\[\s*\w+\s*\]\s*!=\s*(?:\'\\0\'|0(?:x0)?|0x0+)\s*\)',
    )

    def _detect_sentinel_loop(
        self,
        code: str,
        func_name: str,
    ) -> ExtractedFormula | None:
        """Dedektoru 34: Sentinel-Terminated Loop pattern.

        Aranan pattern:
            while (*ptr != '\\0') ptr++;
            -> Null-terminated string/data walk
        """
        match = self._SENTINEL_LOOP_RE.search(code)
        if match is None:
            return None

        ptr_var = match.group(1) or match.group(2) or match.group(3) or "ptr"
        confidence = 0.80

        if any(kw in func_name.lower() for kw in (
            "str", "string", "len", "copy", "scan", "parse", "token",
            "walk", "read", "next",
        )):
            confidence = min(confidence + 0.05, 0.95)

        # Pointer increment varsa kesinlik artar
        has_increment = bool(re.search(
            rf'{re.escape(ptr_var)}\s*\+\+|{re.escape(ptr_var)}\s*\+=\s*1|'
            rf'{re.escape(ptr_var)}\s*=\s*{re.escape(ptr_var)}\s*\+\s*1',
            code,
        ))
        if has_increment:
            confidence = min(confidence + 0.05, 0.95)

        snippet = self._extract_snippet(code, match.start(), match.end())
        variables = [ptr_var]

        latex = (
            r"\text{SentinelLoop}: \text{while}\; *p \neq 0: p \leftarrow p + 1"
        )
        ascii_form = "SentinelLoop: while (*ptr != 0) ptr++"

        return ExtractedFormula(
            function_name=func_name,
            formula_type="sentinel_loop",
            latex=latex,
            ascii=ascii_form,
            c_code_snippet=snippet,
            variables=variables,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_snippet(code: str, start: int, end: int) -> str:
        """Eslesen bolge etrafinda C kodu snippet'i cikar.

        Eslesen bolgenin 2 satir oncesinden 2 satir sonrasina
        kadar context ile birlikte dondurur. Snippet 500 karakterle
        sinirlandirilir.
        """
        max_snippet = 500

        # Onceki 2 satirin baslangicini bul
        ctx_start = start
        for _ in range(2):
            prev_nl = code.rfind("\n", 0, ctx_start)
            if prev_nl == -1:
                ctx_start = 0
                break
            ctx_start = prev_nl

        # Sonraki 2 satirin sonunu bul
        ctx_end = end
        for _ in range(2):
            next_nl = code.find("\n", ctx_end + 1)
            if next_nl == -1:
                ctx_end = len(code)
                break
            ctx_end = next_nl

        snippet = code[ctx_start:ctx_end].strip()

        # Uzunluk siniri
        if len(snippet) > max_snippet:
            snippet = snippet[:max_snippet] + " ... [truncated]"

        return snippet
