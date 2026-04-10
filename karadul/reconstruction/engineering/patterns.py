"""Yapisal regex pattern'leri -- decompile edilmis C kodunda algoritma tespiti.

Ghidra decompile ciktisi C'ye benzer ama isimlendirme farkindaligi gerektirir:
- Degiskenler: param_1, local_10, iVar3, uVar5, lVar2, dVar8, fVar1 vb.
- Fonksiyonlar: FUN_00401234, _FUN_00abcdef
- Yapilar: *(long *)(param_1 + 0x18)
- Tip cast'lari: (double)DAT_00601080

Bu dosyadaki regex'ler bu sekildeki decompile ciktisinda calisacak sekilde yazildi.
Kaynak kodundaki degisken isimlerine (i, j, k, matrix, result, vb.) bagli DEGILDIR.

Her pattern pre-compile edilmis ``re.Pattern`` nesnesi olarak saklanir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StructuralPattern:
    """Decompile ciktisinda aranan yapisal pattern."""

    name: str                   # "triple_nested_loop"
    algorithm: str              # "matrix_multiply"
    category: str               # "linear_algebra"
    patterns: list[re.Pattern[str]]   # Derlenm regex'ler (herhangi biri eslesirse sayilir)
    min_matches: int            # Minimum eslesen pattern sayisi
    confidence: float           # Taban guven skoru
    bonus_per_extra: float      # Her ek esleme icin bonus
    max_confidence: float       # Tavan
    description: str
    false_positive_note: str    # Ne zaman yanlis pozitif verebilir


def _compile(patterns: list[str], flags: int = 0) -> list[re.Pattern[str]]:
    """Yardimci: string listesini derlenm regex listesine cevir."""
    return [re.compile(p, flags) for p in patterns]


# ---------------------------------------------------------------------------
# Decompile variable name fragments (Ghidra / IDA)
# ---------------------------------------------------------------------------
# Ghidra local pattern:   local_XX  (hex offset)
# Ghidra param pattern:   param_N
# IDA pattern:            v1, v2, a1, a2
# Generic decompile:      Var1, Var2
_V = r"(?:\w+)"                 # any variable name
_I = r"(?:\w+)"                 # any integer variable
_F = r"(?:\w+)"                 # any float variable
_FN = r"(?:FUN_[0-9a-fA-F]+|\w+)"  # function call


# ---------------------------------------------------------------------------
# Pattern veritabani  (25+ pattern)
# ---------------------------------------------------------------------------

ENGINEERING_PATTERNS: list[StructuralPattern] = [

    # ========================================================================
    #  LINEAR ALGEBRA
    # ========================================================================

    StructuralPattern(
        name="triple_nested_loop",
        algorithm="matrix_multiply",
        category="linear_algebra",
        patterns=_compile([
            # for(i) { for(j) { for(k) { a[...] += b[...] * c[...]; }}}
            # Ghidra'da: while/do-while olarak da cikabilir
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\*[^;]*\+[=][^;]*\*[^;]*;",
            # Daha gevsek: += ... * ... ic ice 3 dongu icinde
            r"(?:for|while)\s*\([^)]*\)\s*\{"
            r"(?:[^{}]|\{[^{}]*\})*"
            r"(?:for|while)\s*\([^)]*\)\s*\{"
            r"(?:[^{}]|\{[^{}]*\})*"
            r"(?:for|while)\s*\([^)]*\)\s*\{"
            r"(?:[^{}]|\{[^{}]*\})*"
            r"\+=\s*[^;]*\*",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="Uc ic ice dongu + multiply-accumulate = matris carpimi",
        false_positive_note="3D array traversal, tensor contraction da ayni patterne sahip olabilir",
    ),

    StructuralPattern(
        name="matrix_transpose",
        algorithm="matrix_transpose",
        category="linear_algebra",
        patterns=_compile([
            # a[j][i] = a[i][j] ya da pointer aritmetigi ile
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\*\s*\([^)]*\+[^)]*\*[^)]*\+[^)]*\)\s*=\s*"
            r"\*\s*\([^)]*\+[^)]*\*[^)]*\+[^)]*\)",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.65,
        bonus_per_extra=0.10,
        max_confidence=0.80,
        description="Ic ice 2 dongu + simetrik indeks degisimi = transpose",
        false_positive_note="Genel matris kopyalama da benzer gorunebilir",
    ),

    # TIGHTENED (2026-03-25): Removed generic 2x2 pattern (a*d - b*c) which
    # matches ANY multiply-subtract in any code.  Kept only the 3x3 cofactor
    # expansion which is highly specific.
    StructuralPattern(
        name="determinant_3x3",
        algorithm="matrix_determinant",
        category="linear_algebra",
        patterns=_compile([
            # 3x3 cofactor expansion ONLY:
            # a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)
            r"\w+\s*\*\s*\(\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*\)"
            r"\s*[-+]\s*\w+\s*\*\s*\(\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*\)"
            r"\s*[-+]\s*\w+\s*\*\s*\(\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*\)",
        ]),
        min_matches=1,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="3-term cofactor expansion a*(ei-fh) - b*(di-fg) + c*(dh-eg) = 3x3 determinant",
        false_positive_note="3x3 cofactor form is quite specific; 2x2 (a*d-b*c) removed as too generic",
    ),

    StructuralPattern(
        name="pivot_selection",
        algorithm="lu_decomposition",
        category="linear_algebra",
        patterns=_compile([
            # Partial pivoting: fabs(a[k]) > fabs(a[max])
            r"(?:fabs|abs|fabsf)\s*\([^)]+\)\s*[>]\s*(?:fabs|abs|fabsf)\s*\([^)]+\)",
            # Swap rows after pivot selection
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\*[^;]+;\s*"
            r"\*[^;]+\s*=\s*\*[^;]+;\s*"
            r"\*[^;]+\s*=\s*\w+\s*;",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.05,
        max_confidence=0.90,
        description="fabs karsilastirmasi + satir swap = LU pivot secimi",
        false_positive_note="Herhangi bir siralama algoritmasi da benzer swap yapar",
    ),

    StructuralPattern(
        name="back_substitution",
        algorithm="triangular_solve",
        category="linear_algebra",
        patterns=_compile([
            # Ters yonde dongu: for(i = n-1; i >= 0; i--)
            r"(?:for|while)\s*\([^;]*;\s*\w+\s*>=?\s*0\s*;\s*\w+\s*(?:--|-=\s*1)\s*\)",
            # x[i] = (b[i] - sum) / a[i][i]
            r"\w+\s*=\s*\([^)]*-[^)]*\)\s*/\s*\*?\s*\(",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.07,
        max_confidence=0.90,
        description="Ters dongu + (b-sum)/diag = back substitution",
        false_positive_note="Reverse iteration baska amaclarla da kullanilir",
    ),

    # ========================================================================
    #  ITERATIVE SOLVERS
    # ========================================================================

    StructuralPattern(
        name="convergence_loop",
        algorithm="iterative_solver",
        category="numerical_solver",
        patterns=_compile([
            # while (err > tol && iter < max_iter)
            r"(?:while|for)\s*\([^)]*[<>]\s*\w+\s*&&\s*\w+\s*[<>]\s*\w+\s*\)",
            # do { ... } while (norm > eps)
            r"do\s*\{(?:[^{}]|\{[^{}]*\})*\}\s*while\s*\([^)]*[<>]\s*(?:1e[-+]?\d+|(?:0\.0*[1-9]))",
            # residual = fabs(new - old); if (residual < tol) break;
            r"(?:fabs|fabsf?)\s*\([^)]*-[^)]*\)[^;]*;\s*(?:if\s*\([^)]*[<]\s*\w+\s*\)\s*break|"
            r"if\s*\([^)]*[<]\s*(?:1e[-+]?\d+|0\.0+[1-9]))",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.70,
        bonus_per_extra=0.12,
        max_confidence=0.88,
        description="Tolerans kontrollue yakinlasma dongusu = iteratif cozucu",
        false_positive_note="Herhangi bir iteratif optimizasyon da benzer gorunur",
    ),

    # DISABLED (2026-03-25): vector_norm pattern too generic -- "+= x * y" matches
    # any multiply-accumulate in any code.  Produces 10K+ false positives on
    # non-scientific binaries like text editors.  Replaced by tighter version below.
    # Original required only min_matches=1 with "+= w*w ; ... sqrt()" which matches
    # distance calculations, checksums, audio RMS, etc.
    StructuralPattern(
        name="norm_computation",
        algorithm="vector_norm",
        category="numerical_solver",
        patterns=_compile([
            # TIGHT: Require the FULL pattern: loop + sum += x*x + sqrt(sum)
            # within same scope (not scattered across functions)
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\w+\s*\*\s*\w+\s*;[^{}]*\}[^;]*;[^;]{0,200}"
            r"sqrt\s*\(",
            # pow(x, 2) accumulation in loop + sqrt
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*pow\s*\([^,]+,\s*2\s*\)[^{}]*\}[^;]*;[^;]{0,200}"
            r"sqrt\s*\(",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.45,
        bonus_per_extra=0.15,
        max_confidence=0.70,
        description="sum(x*x) in loop + sqrt(sum) in same scope = L2 norm hesabi",
        false_positive_note="Distance hesabi da ayni patterne sahip; loop+sqrt birlikte gerekli",
    ),

    # ========================================================================
    #  NEWTON-RAPHSON
    # ========================================================================

    StructuralPattern(
        name="newton_raphson",
        algorithm="newton_raphson",
        category="nonlinear_solver",
        patterns=_compile([
            # x = x - f(x)/f'(x)  veya  x -= delta
            r"\w+\s*=\s*\w+\s*-\s*\w+\s*/\s*\w+\s*;",
            # Jacobian pattern: f + h, f - h, (f_plus - f_minus) / (2*h)
            r"\([^)]*\+[^)]*\)\s*-\s*\([^)]*-[^)]*\)\s*\)\s*/\s*\(\s*2",
            # Typical: while loop + solve + update
            r"(?:while|for)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\w+\s*=\s*\w+\s*-\s*(?:\w+\s*/\s*\w+|\w+)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="x -= f/f' dongusu = Newton-Raphson iterasyonu",
        false_positive_note="x = x - step herhangi iteratif yontem olabilir",
    ),

    # ========================================================================
    #  RUNGE-KUTTA 4  (RK4)
    # ========================================================================

    StructuralPattern(
        name="rk4_stages",
        algorithm="runge_kutta_4",
        category="time_integration",
        patterns=_compile([
            # 4 ardisik fonksiyon cagirisi veya atama: k1, k2, k3, k4
            # Ghidra'da: dVar1 = FUN_*(x, y); dVar2 = FUN_*(x+h/2, y+h/2*dVar1); ...
            r"(?:\w+\s*=\s*(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*\)\s*;\s*){3,4}",
            # y_new = y + h/6 * (k1 + 2*k2 + 2*k3 + k4)
            # Ghidra: ... + ... * 2.0 * ... + ... * 2.0 * ... + ...
            r"\w+\s*\+\s*\w+\s*\*\s*\(\s*\w+\s*\+\s*(?:2\.?0?\s*\*\s*)?\w+\s*\+\s*"
            r"(?:2\.?0?\s*\*\s*)?\w+\s*\+\s*\w+\s*\)",
            # h*0.5 (midpoint eval) tekrarlayan
            r"\w+\s*\*\s*(?:0\.5|5\.0[eE][-]?0*1)\s*\*\s*\w+",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="4 ardisik stage hesabi + 1/6 agirliklama = RK4",
        false_positive_note="Genel multi-stage yontemler (RK2, RK3) benzer ama daha az stage'e sahip",
    ),

    # ========================================================================
    #  FEA ASSEMBLY
    # ========================================================================

    # TIGHTENED (2026-03-25): Pattern 2 "a * b + c" matches ANY multiply-add.
    # Removed the generic DOF mapping pattern; now requires BOTH the double-nested
    # loop with indirect += AND the element loop context.
    StructuralPattern(
        name="fea_element_assembly",
        algorithm="fea_assembly",
        category="finite_element",
        patterns=_compile([
            # Element loop + DOF scatter: K_global[dof[i]][dof[j]] += K_local[i][j]
            # Double-nested loop with indirect pointer += (the specific assembly pattern)
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\*\s*\([^)]+\+\s*\*?\s*\([^)]+\)[^;]*\)\s*\+=",
            # Triple-nested assembly: element loop > DOF i > DOF j > K_global += K_local
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\*\s*\([^)]+\)\s*\+=",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.70,
        bonus_per_extra=0.12,
        max_confidence=0.88,
        description="Double/triple nested loop + indirect pointer += = FEA global matrix assembly",
        false_positive_note="Genel sparse matrix assembly de benzer gorunur; generic a*b+c removed",
    ),

    StructuralPattern(
        name="shape_function_eval",
        algorithm="fea_shape_functions",
        category="finite_element",
        patterns=_compile([
            # N1 = (1-xi)*(1-eta)/4 gibi bilineer shape function'lar
            r"\(\s*1\.?0?\s*[-+]\s*\w+\s*\)\s*\*\s*\(\s*1\.?0?\s*[-+]\s*\w+\s*\)\s*"
            r"(?:\*\s*\(\s*1\.?0?\s*[-+]\s*\w+\s*\)\s*)?"   # optional zeta for 3D
            r"(?:\*\s*(?:0\.25|0\.125|2\.5[eE][-]?0*1))?",   # /4 or /8
            # Jacobian determinant in isoparametric mapping
            r"\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+",  # det(J) = J11*J22 - J12*J21
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.06,
        max_confidence=0.92,
        description="(1-xi)*(1-eta) tipi ifade = isoparametrik shape function",
        false_positive_note="Bilineer interpolasyon baska alanlarda da kullanilir (grafik, texture mapping)",
    ),

    # ========================================================================
    #  FFT
    # ========================================================================

    StructuralPattern(
        name="fft_butterfly",
        algorithm="fft",
        category="dsp_transform",
        patterns=_compile([
            # Butterfly: t_re = w_re * x_re - w_im * x_im
            #            t_im = w_re * x_im + w_im * x_re
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*;\s*"
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*;",
            # Bit reversal: i & (1 << k) tarzinda
            r"\w+\s*&\s*\(\s*1\s*<<\s*\w+\s*\)",
            # Twiddle factor: cos(2*pi*k/N), sin(2*pi*k/N)
            r"(?:cos|sin)\s*\(\s*(?:\w+\s*\*\s*)*\w+\s*/\s*\w+\s*\)",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Butterfly (complex mul +/-) + bit reversal/twiddle = FFT",
        false_positive_note="Complex sayi aritmetigi tek basina FFT olmayabilir",
    ),

    # ========================================================================
    #  CONVOLUTION
    # ========================================================================

    StructuralPattern(
        name="convolution_mac",
        algorithm="convolution",
        category="dsp_filter",
        patterns=_compile([
            # Sliding window: for(k=0; k<N; k++) sum += h[k] * x[n-k]
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*\+=\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*-[^)]*\)",
            # Symmetric: h[k] * (x[n+k] + x[n-k])
            r"\*?\s*\([^)]*\)\s*\*\s*\(\s*\*?\s*\([^)]*\+[^)]*\)\s*\+\s*\*?\s*\([^)]*-[^)]*\)\s*\)",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.72,
        bonus_per_extra=0.13,
        max_confidence=0.88,
        description="Sliding window multiply-accumulate = convolution/FIR filtre",
        false_positive_note="Cross-correlation da ayni pattern",
    ),

    # ========================================================================
    #  MONTE CARLO
    # ========================================================================

    # TIGHTENED (2026-03-25): "sum / N" alone matches any division.
    # Now pattern 1 specifically requires rand()/RAND_MAX or drand48() (not just
    # any call to rand).  Pattern 2 requires rand in acceptance check context.
    StructuralPattern(
        name="monte_carlo",
        algorithm="monte_carlo",
        category="stochastic",
        patterns=_compile([
            # rand()/RAND_MAX or drand48() -- uniform [0,1] generation
            r"(?:rand\s*\(\s*\)\s*/\s*(?:RAND_MAX|\(\s*(?:double|float)\s*\)\s*RAND_MAX)|"
            r"drand48\s*\(\s*\)|"
            r"(?:mt19937|genrand_?\w*)\s*\([^)]*\)\s*/\s*\w+)",
            # Random-based acceptance: if (rand_val < threshold) count++
            r"if\s*\(\s*(?:\w+|(?:rand|drand48)\s*\([^)]*\)(?:\s*/\s*\w+)?)\s*<\s*\w+\s*\)\s*"
            r"(?:\{[^{}]*)?(?:\w+\s*\+\+|\w+\s*\+=\s*1)",
            # Monte Carlo averaging: sum / (double)N at the end of a sample loop
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:rand|drand48|random)\s*\((?:[^{}]|\{[^{}]*\})*\}[^;]*;[^;]{0,300}"
            r"\w+\s*/\s*(?:\(\s*(?:double|float)\s*\)\s*)?\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.65,
        bonus_per_extra=0.10,
        max_confidence=0.82,
        description="rand()/RAND_MAX + acceptance test + sample average = Monte Carlo",
        false_positive_note="Requires specific random generation pattern, not just any division",
    ),

    # ========================================================================
    #  GRADIENT DESCENT
    # ========================================================================

    # TIGHTENED (2026-03-25): "x -= a * b" matches ANY multiply-subtract.
    # Now requires learning rate update in convergence loop + convergence check.
    StructuralPattern(
        name="gradient_descent",
        algorithm="gradient_descent",
        category="ml_optimization",
        patterns=_compile([
            # Convergence loop with param update: while/for { ... x -= lr * grad ... }
            r"(?:while|for)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\w+\s*[-]=\s*\w+\s*\*\s*\w+\s*;",
            # Convergence or loss check inside loop
            r"(?:while|for)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"if\s*\(\s*\w+\s*[<>]\s*(?:\w+|1[eE][-+]?\d+)\s*\)\s*(?:break|return)",
            # Batch update pattern: multiple -= in sequence (updating multiple params)
            r"\w+\s*[-]=\s*\w+\s*\*\s*\w+\s*;\s*"
            r"\w+\s*[-]=\s*\w+\s*\*\s*\w+\s*;",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.55,
        bonus_per_extra=0.12,
        max_confidence=0.78,
        description="Convergence loop + param -= lr*grad + loss check = gradient descent",
        false_positive_note="Requires convergence context; standalone x -= a*b no longer matches",
    ),

    # ========================================================================
    #  SOFTMAX
    # ========================================================================

    # TIGHTENED (2026-03-25): Pattern 3 "x / y" alone matches ANY division.
    # Now requires exp(x-max) and the division to be in the SAME loop context,
    # and the division must follow an exp accumulation.
    StructuralPattern(
        name="softmax",
        algorithm="softmax",
        category="ml_activation",
        patterns=_compile([
            # Phase 1: max finding loop
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*if\s*\([^)]*>\s*\w+\s*\)[^{}]*\w+\s*=",
            # Phase 2: exp(x[i] - max) -- THE key softmax signature
            r"exp\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # Phase 3: exp accumulation + normalize: sum += exp(...); ... x / sum
            # Must have exp and division in same scope
            r"\+=\s*exp\s*\([^)]*\)\s*;(?:[^;]*;){0,20}[^;]*"
            r"\w+\s*/\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="max bulma + exp(x-max) + sum(exp)/normalize = softmax",
        false_positive_note="Requires exp() call; standalone division no longer matches",
    ),

    # ========================================================================
    #  ATTENTION MECHANISM
    # ========================================================================

    StructuralPattern(
        name="attention_mechanism",
        algorithm="attention",
        category="ml_transformer",
        patterns=_compile([
            # Q * K^T (matmul + transpose)
            r"\w+\s*\*\s*\w+[^;]*;[^;]*"    # matmul
            r"(?:\/\s*(?:sqrt|sqrtf)\s*\(|"   # / sqrt(d_k)
            r"\*\s*(?:0\.125|0\.0[0-9]+))",    # veya scale factor olarak
            # Softmax ciktisi * V
            r"exp\s*\([^)]*\)[^;]*;[^;]*\*\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Q*K^T/sqrt(d) + softmax + *V = attention",
        false_positive_note="Her matmul + softmax attention olmak zorunda degil",
    ),

    # ========================================================================
    #  EIGENVALUE ITERATION (Power Method / QR)
    # ========================================================================

    # TIGHTENED (2026-03-25): eigenvalue_iteration was too generic -- "x / y" alone
    # matches any division.  Now requires ALL THREE: Rayleigh quotient pattern +
    # normalization via sqrt + convergence check.  min_matches raised to 3.
    StructuralPattern(
        name="eigenvalue_iteration",
        algorithm="eigenvalue_solver",
        category="linear_algebra",
        patterns=_compile([
            # Power method loop with sqrt normalization
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"sqrt\s*\([^)]*\)[^;]*;[^;]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+",
            # Rayleigh quotient: needs dot-product pattern before division
            # (sum += x*Ax) / (sum += x*x) -- two accumulations then division
            r"\+=\s*\w+\s*\*\s*\w+\s*;(?:[^;]*;)*[^;]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+\s*;",
            # Convergence: |lambda_new - lambda_old| < tol
            r"(?:fabs|fabsf?)\s*\(\s*\w+\s*-\s*\w+\s*\)\s*<\s*(?:\w+|1[eE][-+]?\d+)",
        ], re.DOTALL),
        min_matches=3,
        confidence=0.60,
        bonus_per_extra=0.10,
        max_confidence=0.80,
        description="Iteratif matvec + sqrt normalize + Rayleigh quotient convergence = eigenvalue solver",
        false_positive_note="All three sub-patterns required; eliminates most false positives",
    ),

    # ========================================================================
    #  SPARSE MATRIX (CSR/CSC)
    # ========================================================================

    StructuralPattern(
        name="sparse_csr_access",
        algorithm="sparse_matrix_ops",
        category="linear_algebra",
        patterns=_compile([
            # CSR SpMV: for(j = row_ptr[i]; j < row_ptr[i+1]; j++) y[i] += val[j] * x[col[j]]
            r"(?:for|while)\s*\(\s*\w+\s*=\s*\*?\s*\([^)]*\)\s*;\s*\w+\s*<\s*\*?\s*\([^)]*\+[^)]*\)\s*;",
            # Indirect indexing: x[col_ind[j]]
            r"\*\s*\([^)]+\+\s*(?:\(\s*(?:long|int|uint)\s*\))?\s*\*\s*\([^)]+\)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="row_ptr bound loop + indirect indexing = CSR/CSC sparse matrix erisimu",
        false_positive_note="Graph adjacency list traversal da ayni patterne sahip",
    ),

    # ========================================================================
    #  CONVERGENCE CHECK  (norm < tolerance)
    # ========================================================================

    StructuralPattern(
        name="convergence_check",
        algorithm="convergence_criterion",
        category="numerical_solver",
        patterns=_compile([
            # if (norm < tol) break/return
            r"if\s*\(\s*\w+\s*<\s*(?:1[eE][-]\d+|\w+)\s*\)\s*(?:break|return)",
            # relative convergence: |new - old| / |old| < tol
            r"(?:fabs|fabsf?)\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*(?:fabs|fabsf?)\s*\([^)]*\)\s*<",
            # Iteration counter: if (iter >= max_iter) { warning/break }
            r"if\s*\(\s*\w+\s*>=?\s*\w+\s*\)\s*(?:\{[^{}]*(?:break|return|printf|fprintf|puts))",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="norm < tolerance + max iteration = yakinlasma kriteri",
        false_positive_note="Generic error checking de benzer gorunebilir",
    ),

    # ========================================================================
    #  CHOLESKY DECOMPOSITION
    # ========================================================================

    StructuralPattern(
        name="cholesky_decomposition",
        algorithm="cholesky",
        category="linear_algebra",
        patterns=_compile([
            # L[j][j] = sqrt(A[j][j] - sum)
            r"sqrt\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # L[i][j] = (A[i][j] - sum) / L[j][j]
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*\w+",
            # Double nested loop with accumulator: sum += L[i][k] * L[j][k]
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*[^;]*\*[^;]*\}[^{}]*"
            r"sqrt\s*\(",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="sqrt(A-sum) + lower triangle update = Cholesky decomposition",
        false_positive_note="LDLT decomposition benzer ama sqrt yerine bolme kullanir",
    ),

    # ========================================================================
    #  QR DECOMPOSITION (Householder / Gram-Schmidt)
    # ========================================================================

    StructuralPattern(
        name="qr_decomposition",
        algorithm="qr_decomposition",
        category="linear_algebra",
        patterns=_compile([
            # Householder: v = x - ||x||*e1; H = I - 2*v*v^T/||v||^2
            r"2\.?0?\s*\*\s*\w+\s*\*\s*\w+\s*/\s*\w+",
            # Gram-Schmidt: proj = dot(u,v)/dot(u,u); v -= proj*u
            r"\w+\s*=\s*\w+\s*/\s*\w+\s*;\s*(?:[^;]*;)*[^;]*\w+\s*[-]=\s*\w+\s*\*\s*\w+",
            # Column norm: sqrt(dot(col, col))
            r"sqrt\s*\(\s*\w+\s*\)",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Householder reflection veya Gram-Schmidt projection = QR decomposition",
        false_positive_note="Genel ortogonalizasyon da benzer gorunur",
    ),

    # ========================================================================
    #  CONJUGATE GRADIENT (CG) SOLVER
    # ========================================================================

    # TIGHTENED (2026-03-25): Pattern 1 "x = y / z" and pattern 3 "x = y + z * w"
    # match virtually any arithmetic.  Now requires CG-specific paired updates.
    StructuralPattern(
        name="conjugate_gradient",
        algorithm="conjugate_gradient",
        category="numerical_solver",
        patterns=_compile([
            # CG signature: x += alpha * p; r -= alpha * Ap  (PAIRED update)
            r"\w+\s*\+=\s*\w+\s*\*\s*\w+\s*;\s*\w+\s*-=\s*\w+\s*\*\s*\w+",
            # beta ratio + direction update: p = r + beta * p
            # Must follow the paired x/r update (within ~500 chars)
            r"\w+\s*\+=\s*\w+\s*\*\s*\w+\s*;\s*\w+\s*-=\s*\w+\s*\*\s*\w+"
            r".{0,500}"
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*\s*\w+",
            # Convergence check in CG context: norm(r) < tol inside iteration
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\w+\s*\+=\s*\w+\s*\*\s*\w+\s*;\s*\w+\s*-=\s*\w+\s*\*\s*\w+"
            r"(?:[^{}]|\{[^{}]*\})*"
            r"(?:sqrt\s*\(|(?:fabs|fabsf?)\s*\()[^)]*\)\s*<",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Paired x+=alpha*p; r-=alpha*Ap + beta direction update = Conjugate Gradient",
        false_positive_note="Paired +=/-= update is the CG signature; standalone arithmetic no longer matches",
    ),

    # ========================================================================
    #  GAUSS-SEIDEL / JACOBI ITERATION
    # ========================================================================

    StructuralPattern(
        name="gauss_seidel_jacobi",
        algorithm="gauss_seidel_jacobi",
        category="numerical_solver",
        patterns=_compile([
            # x_new[i] = (b[i] - sum_j(A[i][j]*x[j])) / A[i][i]
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:if\s*\([^)]*!=\s*\w+\s*\)\s*)?"  # if (j != i) -- optional
            r"\+=\s*[^;]*\*[^;]*\}[^{}]*"
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*/",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.74,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Satir bazli (b-Ax)/diag dongusu = Gauss-Seidel veya Jacobi iterasyonu",
        false_positive_note="SOR (Successive Over-Relaxation) de benzer, + omega faktor",
    ),

    # ========================================================================
    #  BISECTION METHOD
    # ========================================================================

    StructuralPattern(
        name="bisection_method",
        algorithm="bisection",
        category="root_finding",
        patterns=_compile([
            # mid = (a + b) / 2  veya  (a + b) * 0.5
            r"\w+\s*=\s*\(\s*\w+\s*\+\s*\w+\s*\)\s*(?:/\s*2|[\*]\s*0\.5)",
            # if (f(mid) * f(a) < 0) b = mid; else a = mid;
            r"if\s*\([^)]*\*[^)]*[<>]\s*0[^)]*\)\s*(?:\{[^{}]*)?(?:\w+\s*=\s*\w+)",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Orta nokta + isaret testi = bisection method",
        false_positive_note="Binary search de (a+b)/2 kullanir ama isaret testi yoktur",
    ),

    # ========================================================================
    #  SECANT METHOD
    # ========================================================================

    StructuralPattern(
        name="secant_method",
        algorithm="secant_method",
        category="root_finding",
        patterns=_compile([
            # x_new = x1 - f(x1) * (x1 - x0) / (f(x1) - f(x0))
            r"\w+\s*-\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*\(\s*\w+\s*-\s*\w+\s*\)",
        ]),
        min_matches=1,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="x - f*(x1-x0)/(f1-f0) = secant method",
        false_positive_note="Lineer interpolasyon da benzer formul kullanir",
    ),

    # ========================================================================
    #  TRIDIAGONAL SOLVER (Thomas Algorithm)
    # ========================================================================

    StructuralPattern(
        name="thomas_algorithm",
        algorithm="tridiagonal_solve",
        category="linear_algebra",
        patterns=_compile([
            # Forward sweep: c'[i] = c[i] / (b[i] - a[i]*c'[i-1])
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\w+\s*/\s*\(\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*\)",
            # Back substitution: x[i] = d'[i] - c'[i]*x[i+1]
            r"(?:for|while)\s*\([^;]*;\s*\w+\s*>=?\s*0\s*;[^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\w+\s*-\s*\w+\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.06,
        max_confidence=0.92,
        description="Forward sweep + back sub with a,b,c bands = Thomas (tridiagonal) solver",
        false_positive_note="Banded matrix solver'lar benzer ama daha fazla band'a sahip",
    ),

    # ========================================================================
    #  NUMERICAL DIFFERENTIATION (Finite Difference)
    # ========================================================================

    StructuralPattern(
        name="finite_difference",
        algorithm="finite_difference",
        category="numerical_calculus",
        patterns=_compile([
            # Central: (f(x+h) - f(x-h)) / (2*h)
            r"\(\s*(?:\w+|FUN_[0-9a-fA-F]+\s*\([^)]*\))\s*-\s*"
            r"(?:\w+|FUN_[0-9a-fA-F]+\s*\([^)]*\))\s*\)\s*/\s*\(\s*2\.?0?\s*\*\s*\w+\s*\)",
            # Forward: (f(x+h) - f(x)) / h
            r"\(\s*(?:\w+|FUN_[0-9a-fA-F]+\s*\([^)]*\))\s*-\s*"
            r"(?:\w+|FUN_[0-9a-fA-F]+\s*\([^)]*\))\s*\)\s*/\s*\w+",
        ]),
        min_matches=1,
        confidence=0.55,
        bonus_per_extra=0.15,
        max_confidence=0.82,
        description="(f(x+h)-f(x-h))/(2h) = sonlu farklar ile turev",
        false_positive_note="Basit fark bolumu cok yaygin; central form daha ayirt edici",
    ),

    # ========================================================================
    #  SIMPSON'S RULE (Numerical Integration)
    # ========================================================================

    StructuralPattern(
        name="simpsons_rule",
        algorithm="simpsons_integration",
        category="numerical_calculus",
        patterns=_compile([
            # (h/3) * (f0 + 4*f1 + 2*f2 + 4*f3 + ... + fn)
            # Ghidra: ... * 4.0 ... * 2.0 alternating pattern
            r"(?:4\.?0?\s*\*\s*\w+|2\.?0?\s*\*\s*\w+)[^;]*"
            r"(?:4\.?0?\s*\*\s*\w+|2\.?0?\s*\*\s*\w+)",
            # h/3 or h*0.333... multiplier
            r"\w+\s*(?:/\s*3\.?0?|\*\s*(?:0\.333|3\.333[eE][-]?0*1))",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="4-2-4-2 agirliklama + h/3 = Simpson kurali",
        false_positive_note="Newton-Cotes diger formulleri de benzer agirliklama kullanir",
    ),

    # ========================================================================
    #  CROSS PRODUCT (3D)
    # ========================================================================

    StructuralPattern(
        name="cross_product_3d",
        algorithm="cross_product",
        category="geometry",
        patterns=_compile([
            # cx = ay*bz - az*by; cy = az*bx - ax*bz; cz = ax*by - ay*bx
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*;\s*"
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*;\s*"
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*;",
        ]),
        min_matches=1,
        confidence=0.80,
        bonus_per_extra=0.10,
        max_confidence=0.92,
        description="3 ardisik a*b-c*d ataması = 3D cross product",
        false_positive_note="3x3 matris satirlari da ayni patterne uyabilir",
    ),

    # ========================================================================
    #  DOT PRODUCT / BLAS-1
    # ========================================================================

    StructuralPattern(
        name="dot_product",
        algorithm="dot_product",
        category="linear_algebra",
        patterns=_compile([
            # sum += a[i] * b[i]  in a loop
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*\+=\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*\)\s*;",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.60,
        bonus_per_extra=0.15,
        max_confidence=0.80,
        description="sum += a[i]*b[i] dongusu = dot product (BLAS level 1 ddot)",
        false_positive_note="Herhangi bir icearpim (korelasyon, weighted sum) da bu patterne uyar",
    ),

    # ========================================================================
    #  BATCH NORMALIZATION
    # ========================================================================

    # TIGHTENED (2026-03-25): Pattern 1 "x / y" matched ANY division.
    # Pattern 4 "a * b + c" matched ANY fused-multiply-add.
    # Now pattern 1 requires loop+sum+division, pattern 4 removed (too generic).
    StructuralPattern(
        name="batch_normalization",
        algorithm="batch_norm",
        category="ml_normalization",
        patterns=_compile([
            # Phase 1: mean = sum(x) / N -- must be in a loop accumulation context
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\*?\s*\([^)]*\)[^{}]*\}[^;]*;[^;]{0,200}"
            r"\w+\s*/\s*(?:\(\s*(?:double|float)\s*\)\s*)?\w+",
            # Phase 2: var = sum((x - mean)^2) / N
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # Phase 3: (x - mean) / sqrt(var + eps)  -- THE key batch_norm signature
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*(?:sqrt|sqrtf)\s*\(\s*\w+\s*\+\s*\w+\s*\)",
        ]),
        min_matches=3,
        confidence=0.78,
        bonus_per_extra=0.07,
        max_confidence=0.92,
        description="loop-mean + (x-mu)^2 variance + (x-mu)/sqrt(var+eps) = batch normalization",
        false_positive_note="Z-score normalizasyonu da ayni formulu kullanir; all 3 patterns required",
    ),

    # ========================================================================
    #  ARC-LENGTH (RIKS) METHOD  -- nonlinear FEA load stepping
    # ========================================================================

    StructuralPattern(
        name="arc_length_riks",
        algorithm="arc_length_method",
        category="nonlinear_solver",
        patterns=_compile([
            # Load factor lambda update: lambda += delta_lambda
            # Constraint equation: ||du||^2 + psi^2 * (dlambda)^2 * ||f_ext||^2 = (ds)^2
            r"\w+\s*\*\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*\*\s*\w+\s*=\s*\w+\s*\*\s*\w+",
            # Quadratic equation solve for delta_lambda: a1*dl^2 + a2*dl + a3 = 0
            r"\w+\s*=\s*\(\s*-\s*\w+\s*[+-]\s*sqrt\s*\(\s*\w+\s*\*\s*\w+\s*-\s*"
            r"4\.?0?\s*\*\s*\w+\s*\*\s*\w+\s*\)\s*\)\s*/\s*\(\s*2\.?0?\s*\*\s*\w+\s*\)",
            # Displacement increment + load factor: u = u + du_bar + dl * du_hat
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\+\s*\w+\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Load factor lambda + constraint equation + quadratic solve = arc-length (Riks) method",
        false_positive_note="Genel quadratic formula cozumu de eslesmesine neden olabilir",
    ),

    # ========================================================================
    #  LINE SEARCH (Armijo Backtracking)
    # ========================================================================

    StructuralPattern(
        name="line_search_armijo",
        algorithm="line_search",
        category="optimization",
        patterns=_compile([
            # alpha *= rho  (backtracking: step size reduction)
            r"\w+\s*\*=\s*(?:0\.\d+|\w+)\s*;",
            # Armijo condition: f(x + alpha*p) <= f(x) + c * alpha * grad^T * p
            r"if\s*\([^)]*<=?\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*\*\s*\w+\s*\)",
            # while loop halving: while (alpha > min_alpha && !sufficient_decrease)
            r"(?:while|for)\s*\([^)]*\*=\s*\w+|"
            r"(?:while|for)\s*\([^)]*>\s*\w+[^)]*(?:&&|\|\|)[^)]*\)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Step size halving + sufficient decrease check = Armijo line search",
        false_positive_note="Genel backtracking strategy de benzer gorunur",
    ),

    # ========================================================================
    #  PRECONDITIONER APPLICATION  M^{-1} * r
    # ========================================================================

    StructuralPattern(
        name="preconditioner_apply",
        algorithm="preconditioner",
        category="numerical_solver",
        patterns=_compile([
            # z = M_inv * r  (preconditioning step in Krylov solvers)
            # Typical: forward/back solve pair (ILU preconditioning)
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*\w+[^{}]*\}[^{}]*"
            r"(?:for|while)\s*\([^;]*;\s*\w+\s*>=?\s*0\s*;[^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*\w+",
            # Diagonal (Jacobi) preconditioning: z[i] = r[i] / diag[i]
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\w+\s*/\s*\*?\s*\([^)]*\)\s*;",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.68,
        bonus_per_extra=0.12,
        max_confidence=0.85,
        description="Forward/back solve pair veya diagonal scaling = preconditioner application",
        false_positive_note="Back substitution tek basina da benzer gorunur; ILU pair daha ayirt edici",
    ),

    # ========================================================================
    #  REDUCED INTEGRATION (fewer Gauss points)
    # ========================================================================

    StructuralPattern(
        name="reduced_integration",
        algorithm="reduced_integration",
        category="finite_element",
        patterns=_compile([
            # Single Gauss point (1-point): w=2.0 or w=4.0 (2D) or w=8.0 (3D)
            # at xi=0, eta=0, zeta=0
            r"(?:2\.0|4\.0|8\.0)\s*\*\s*(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*"
            r"(?:0\.0|0\.?0?)\s*[,)][^)]*(?:0\.0|0\.?0?)",
            # Loop with fewer iterations than expected: nGP=1 for hex (vs 8 full)
            # or nGP=1 for quad (vs 4 full)
            r"(?:for|while)\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*1\s*;",
            # Hourglass control: anti-hourglass forces added after reduced integration
            r"\w+\s*=\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*;[^;]*"
            r"\w+\s*\+=\s*\w+\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.60,
        bonus_per_extra=0.15,
        max_confidence=0.85,
        description="Tek Gauss noktasi veya az sayida quadrature + hourglass control = reduced integration",
        false_positive_note="Single-point evaluation baska amaclarla da yapilabilir",
    ),

    # ========================================================================
    #  TIE CONSTRAINT (node matching + DOF coupling)
    # ========================================================================

    StructuralPattern(
        name="tie_constraint",
        algorithm="tie_constraint",
        category="finite_element",
        patterns=_compile([
            # Distance check: sqrt((x1-x2)^2 + (y1-y2)^2 + (z1-z2)^2) < tolerance
            r"sqrt\s*\(\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\+"
            r"\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\+"
            r"\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\)",
            # DOF equation: u_slave = u_master (direct coupling)
            # Penalty: K_tie * (u_slave - u_master) -> stiffness contribution
            r"\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Node distance check + DOF coupling = tie constraint",
        false_positive_note="Nearest-neighbor search + spring element de benzer gorunur",
    ),

    # ========================================================================
    #  MPC (Multi-Point Constraint) -- coefficient matrix assembly
    # ========================================================================

    StructuralPattern(
        name="mpc_constraint",
        algorithm="multi_point_constraint",
        category="finite_element",
        patterns=_compile([
            # MPC: sum(a_i * u_i) = 0  -> coefficient row assembly
            # Loop over constraint terms: coeff[j] * dof[node[j]*ndof + dir[j]]
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*\*[^)]*\+[^)]*\)",
            # Lagrange multiplier: K augmented with constraint rows
            # Row/column beyond original DOFs
            r"\*\s*\([^)]+\+\s*\([^)]*\+\s*\w+\s*\)\s*\*\s*\w+\s*\)\s*=\s*\w+",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.65,
        bonus_per_extra=0.15,
        max_confidence=0.85,
        description="Constraint coefficient assembly + Lagrange multiplier augmentation = MPC",
        false_positive_note="Genel constraint handling de benzer pattern kullanir",
    ),

    # ========================================================================
    #  CONTACT SURFACE-TO-SURFACE  (penetration + contact force)
    # ========================================================================

    StructuralPattern(
        name="contact_surface_to_surface",
        algorithm="contact_algorithm",
        category="finite_element",
        patterns=_compile([
            # Penetration/gap function: g = (x_slave - x_master) . n
            # Dot product with normal: sum of component * normal_component
            r"\w+\s*=\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\w+\s*\+\s*"
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\w+\s*\+\s*"
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\w+",
            # Contact force: if (gap < 0) f_contact = penalty * gap
            r"if\s*\(\s*\w+\s*<\s*0[^)]*\)\s*(?:\{[^{}]*)?\w+\s*=\s*\w+\s*\*\s*\w+",
            # Projection onto master surface: natural coords (xi, eta) search
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\(\s*1\.?0?\s*[-+]\s*\w+\s*\)\s*\*\s*\(\s*1\.?0?\s*[-+]\s*\w+\s*\)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Gap function + penalty force + surface projection = contact algorithm",
        false_positive_note="Genel closest-point projection de benzer gorunur",
    ),

    # ========================================================================
    #  ELEMENT SHAPE FUNCTION EVALUATION (general N1..Nn)
    # ========================================================================

    StructuralPattern(
        name="shape_function_general",
        algorithm="shape_function_evaluation",
        category="finite_element",
        patterns=_compile([
            # Serendipity/Lagrange higher order:
            # N_corner = (1+xi_i*xi)*(1+eta_i*eta)*(xi_i*xi+eta_i*eta-1)/4
            r"\(\s*1\.?0?\s*[+-]\s*\w+\s*\*\s*\w+\s*\)\s*\*\s*"
            r"\(\s*1\.?0?\s*[+-]\s*\w+\s*\*\s*\w+\s*\)\s*\*\s*"
            r"\(\s*\w+\s*\*\s*\w+\s*[+-]\s*\w+\s*\*\s*\w+\s*-\s*1\.?0?\s*\)",
            # Midside node: N_mid = (1 - xi^2) * (1+eta_i*eta) / 2
            r"\(\s*1\.?0?\s*-\s*\w+\s*\*\s*\w+\s*\)\s*\*\s*"
            r"\(\s*1\.?0?\s*[+-]\s*\w+\s*(?:\*\s*\w+\s*)?\)\s*"
            r"(?:\*\s*(?:0\.5|5\.0[eE][-]?0*1)|\s*/\s*2\.?0?)",
            # Tetrahedral natural coords: N1 = 1-xi-eta-zeta, N2 = xi, N3 = eta, N4 = zeta
            r"\w+\s*=\s*1\.?0?\s*-\s*\w+\s*-\s*\w+\s*-\s*\w+\s*;",
        ]),
        min_matches=1,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="Higher-order veya simplex shape function evaluation (serendipity, tet)",
        false_positive_note="Bilineer interpolasyon baska alanlarda da kullanilir",
    ),

    # ========================================================================
    #  ARNOLDI ITERATION  (orthogonalization loop for Krylov)
    # ========================================================================

    StructuralPattern(
        name="arnoldi_iteration",
        algorithm="arnoldi_iteration",
        category="linear_algebra",
        patterns=_compile([
            # Modified Gram-Schmidt within Krylov loop:
            # h[j][k] = dot(v[j], w); w -= h[j][k] * v[j]   (for j=0..k)
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*\)\s*;[^;]*"
            r"\w+\s*-=\s*\w+\s*\*\s*\w+",
            # h[k+1][k] = norm(w); v[k+1] = w / h[k+1][k]
            r"(?:sqrt\s*\([^)]*\)|(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*\))[^;]*;\s*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*\w+\s*=\s*\w+\s*/\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Gram-Schmidt loop + Hessenberg entry + normalize = Arnoldi iteration",
        false_positive_note="QR decomposition da Gram-Schmidt kullanir ama Krylov context'i farkli",
    ),

    # ========================================================================
    #  LANCZOS ITERATION  (tridiagonal reduction for symmetric)
    # ========================================================================

    StructuralPattern(
        name="lanczos_iteration",
        algorithm="lanczos_iteration",
        category="linear_algebra",
        patterns=_compile([
            # alpha[j] = dot(v[j], w)
            # w = w - alpha[j]*v[j] - beta[j]*v[j-1]
            r"\w+\s*=\s*\w+\s*-\s*\w+\s*\*\s*\w+\s*-\s*\w+\s*\*\s*\w+",
            # beta[j+1] = norm(w); v[j+1] = w / beta[j+1]
            r"\w+\s*=\s*sqrt\s*\([^)]*\)\s*;[^;]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+",
            # Three-term recurrence: w = A*v[j] - alpha*v[j] - beta*v[j-1]
            r"(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*\)\s*;[^;]*"
            r"\w+\s*-=\s*\w+\s*\*\s*\w+\s*;[^;]*"
            r"\w+\s*-=\s*\w+\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.76,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="Three-term recurrence + tridiag entries (alpha, beta) = Lanczos iteration",
        false_positive_note="Arnoldi iteration benzer ama full Hessenberg; Lanczos sadece tridiag",
    ),

    # ========================================================================
    #  POWER ITERATION  (dominant eigenvalue via Rayleigh quotient)
    # ========================================================================

    StructuralPattern(
        name="power_iteration",
        algorithm="power_iteration",
        category="linear_algebra",
        patterns=_compile([
            # y = A*x  (matvec in loop)
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:FUN_[0-9a-fA-F]+|\w+)\s*\([^)]*\)\s*;",
            # lambda = dot(x, y) / dot(x, x)  (Rayleigh quotient)
            r"\w+\s*=\s*\w+\s*/\s*\w+\s*;[^;]*"
            # x = y / norm(y)  (normalize)
            r"\w+\s*=\s*\w+\s*/\s*(?:sqrt\s*\([^)]*\)|\w+)",
            # Convergence: |lambda_new - lambda_old| < tol
            r"(?:fabs|fabsf?)\s*\(\s*\w+\s*-\s*\w+\s*\)\s*<\s*\w+",
        ]),
        min_matches=2,
        confidence=0.70,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Matvec + normalize + Rayleigh quotient convergence = power iteration",
        false_positive_note="Genel iteratif matvec de benzer gorunur; convergence check ile ayirt edilir",
    ),

    # ========================================================================
    #  INVERSE ITERATION  (shift-and-invert for eigenvalues)
    # ========================================================================

    # DISABLED (2026-03-25): inverse_iteration patterns individually too generic:
    # "x - y * z" matches any subtraction-multiplication, "f(); ... g()" matches
    # any two function calls, "x = y / z" matches any division.  Even with
    # min_matches=3, these three match virtually any C function.
    # Keeping as commented-out reference; detection should rely on API layer
    # (ARPACK dsaupd/dseupd) or constant layer (shift values).
    #
    # StructuralPattern(
    #     name="inverse_iteration",
    #     algorithm="inverse_iteration",
    #     category="linear_algebra",
    #     patterns=_compile([...]),
    #     min_matches=3,
    #     ...
    # ),
    # REPLACEMENT: Much tighter version requiring shift-invert specific structure
    StructuralPattern(
        name="inverse_iteration",
        algorithm="inverse_iteration",
        category="linear_algebra",
        patterns=_compile([
            # Shift application: diagonal subtraction in loop -- A[i][i] -= sigma
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\*\s*\([^)]+\+\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\)\s*-=\s*\w+",
            # Normalize via sqrt after a solve: sqrt(sum) then divide
            r"sqrt\s*\([^)]*\)\s*;[^;]{0,300}"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+",
            # Convergence on eigenvalue estimate: fabs(lambda - old) < tol
            r"(?:fabs|fabsf?)\s*\(\s*\w+\s*-\s*\w+\s*\)\s*<\s*(?:\w+|1[eE][-+]?\d+)",
            # Shift-invert specific: two consecutive function calls (factor + solve)
            # within an outer convergence loop
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"(?:FUN_[0-9a-fA-F]+)\s*\([^)]*\)\s*;[^;]*"
            r"(?:FUN_[0-9a-fA-F]+)\s*\([^)]*\)\s*;[^;]*"
            r"sqrt\s*\(",
        ], re.DOTALL),
        min_matches=3,
        confidence=0.65,
        bonus_per_extra=0.08,
        max_confidence=0.82,
        description="Diagonal shift + factor/solve pair + sqrt normalize + convergence = inverse iteration",
        false_positive_note="Requires 3 of 4 specific sub-patterns; much less prone to false positives",
    ),

    # ========================================================================
    #  QR ALGORITHM  (Givens/Householder + shift for eigenvalues)
    # ========================================================================

    StructuralPattern(
        name="qr_algorithm_eigen",
        algorithm="qr_algorithm",
        category="linear_algebra",
        patterns=_compile([
            # Givens rotation: c = a/r, s = b/r, r = sqrt(a^2+b^2)
            r"\w+\s*=\s*sqrt\s*\(\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*\)\s*;[^;]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+\s*;[^;]*"
            r"\w+\s*=\s*\w+\s*/\s*\w+",
            # Wilkinson shift: eigenvalue of trailing 2x2 submatrix
            r"\w+\s*=\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*2\.?0?\s*;[^;]*"
            r"(?:sqrt|sqrtf)\s*\(\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*\)",
            # QR iteration: A = R*Q (multiply back) in loop
            r"(?:for|while)\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*"
            r"\w+\s*\*\s*\w+\s*[+-]\s*\w+\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.76,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="Givens rotation + Wilkinson shift + QR iteration = QR eigenvalue algorithm",
        false_positive_note="QR decomposition pattern'i ile karisabilir; shift + iteration ayirt edici",
    ),

    # ========================================================================
    #  FINITE DIFFERENCE STENCIL (5-point / 7-point)
    # ========================================================================

    StructuralPattern(
        name="fd_stencil",
        algorithm="finite_difference_stencil",
        category="pde_solver",
        patterns=_compile([
            # 5-point 2D: u[i][j-1] + u[i][j+1] + u[i-1][j] + u[i+1][j] - 4*u[i][j]
            # In decompiled form: *(base + (i-1)*stride + j) + *(base + (i+1)*stride + j) + ...
            r"\*\s*\([^)]+[+-]\s*\w+\s*\)\s*\+\s*\*\s*\([^)]+[+-]\s*\w+\s*\)\s*\+"
            r"\s*\*\s*\([^)]+[+-]\s*\w+\s*\)\s*\+\s*\*\s*\([^)]+[+-]\s*\w+\s*\)\s*"
            r"[-]\s*(?:4\.?0?\s*\*\s*)?\*\s*\([^)]+\)",
            # 7-point 3D: adds u[i][j][k-1] + u[i][j][k+1] - 6*u[i][j][k]
            r"(?:\*\s*\([^)]+[+-]\s*\w+\s*\)\s*\+\s*){5,6}"
            r"\*\s*\([^)]+[+-]\s*\w+\s*\)\s*[-]\s*(?:6\.?0?\s*\*\s*)?\*\s*\(",
            # Laplacian coefficient: -4 or -6 center weight
            r"[-]\s*(?:4\.?0?|6\.?0?)\s*\*\s*\*?\s*\(",
        ]),
        min_matches=1,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="4-neighbor + center(-4) veya 6-neighbor + center(-6) = FD stencil (Laplacian)",
        false_positive_note="Image processing konvolusyonu da benzer stencil pattern kullanir",
    ),

    # ========================================================================
    #  UPWIND DIFFERENCING  (flow direction conditional)
    # ========================================================================

    StructuralPattern(
        name="upwind_differencing",
        algorithm="upwind_scheme",
        category="pde_solver",
        patterns=_compile([
            # if (velocity > 0) use backward diff, else use forward diff
            r"if\s*\(\s*\w+\s*>\s*0[^)]*\)\s*\{[^{}]*"
            r"\(\s*\w+\s*-\s*\*?\s*\([^)]*-[^)]*\)\s*\)\s*/\s*\w+[^{}]*\}[^{}]*"
            r"else\s*\{[^{}]*"
            r"\(\s*\*?\s*\([^)]*\+[^)]*\)\s*-\s*\w+\s*\)\s*/\s*\w+",
            # Simpler form: max(v,0)*(u[i]-u[i-1]) + min(v,0)*(u[i+1]-u[i])
            r"(?:fmax|fmaxf|max)\s*\([^,]*,\s*0[^)]*\)\s*\*\s*\([^)]*-[^)]*\)\s*\+\s*"
            r"(?:fmin|fminf|min)\s*\([^,]*,\s*0[^)]*\)\s*\*\s*\([^)]*-[^)]*\)",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Flow direction conditional + one-sided diff = upwind differencing",
        false_positive_note="Flux limiting de benzer conditionals kullanir ama daha karmasik",
    ),

    # ========================================================================
    #  SIMPLE ALGORITHM  (pressure-velocity coupling for CFD)
    # ========================================================================

    StructuralPattern(
        name="simple_algorithm",
        algorithm="simple_pressure_velocity",
        category="pde_solver",
        patterns=_compile([
            # Momentum equation solve -> intermediate velocity u*
            # Pressure correction equation solve -> p'
            # Velocity correction: u = u* - dt/rho * grad(p')
            r"\w+\s*=\s*\w+\s*-\s*\w+\s*\*\s*\(\s*\*?\s*\([^)]*\+[^)]*\)\s*-\s*"
            r"\*?\s*\([^)]*\)\s*\)\s*/\s*\w+",
            # Under-relaxation: u = alpha*u_new + (1-alpha)*u_old
            r"\w+\s*=\s*\w+\s*\*\s*\w+\s*\+\s*\(\s*1\.?0?\s*-\s*\w+\s*\)\s*\*\s*\w+",
            # Pressure update: p = p + alpha_p * p'
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*\s*\w+\s*;",
        ]),
        min_matches=2,
        confidence=0.70,
        bonus_per_extra=0.12,
        max_confidence=0.88,
        description="Momentum solve + pressure correction + under-relaxation = SIMPLE algorithm",
        false_positive_note="Genel iteratif guncelleme de benzer gorunur; 3 pattern birlikte ayirt edici",
    ),

    # ========================================================================
    #  FRACTIONAL STEP  (intermediate velocity + pressure projection)
    # ========================================================================

    StructuralPattern(
        name="fractional_step",
        algorithm="fractional_step",
        category="pde_solver",
        patterns=_compile([
            # Step 1: u* = u + dt * (advection + diffusion)
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*\s*\([^)]*\+[^)]*\)",
            # Step 2: solve Poisson for pressure: Laplacian(phi) = (1/dt) * div(u*)
            # Laplacian stencil + RHS = divergence
            r"\(\s*\*?\s*\([^)]*\+[^)]*\)\s*\+\s*\*?\s*\([^)]*-[^)]*\)\s*"
            r"[+-]\s*(?:2\.?0?\s*\*\s*)?\w+\s*\)\s*/\s*\(\s*\w+\s*\*\s*\w+\s*\)",
            # Step 3: u = u* - dt * grad(phi)
            r"\w+\s*=\s*\w+\s*-\s*\w+\s*\*\s*\(\s*\*?\s*\([^)]*\+[^)]*\)\s*-\s*"
            r"\*?\s*\([^)]*-?[^)]*\)\s*\)\s*/\s*\(\s*2\.?0?\s*\*\s*\w+\s*\)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="Intermediate velocity + Poisson pressure + projection = fractional step",
        false_positive_note="Pressure correction + velocity update CFD'ye ozgu bir kombinasyon",
    ),

    # ========================================================================
    #  CHOLESKY SAMPLING  (L * z where z ~ N(0,1))
    # ========================================================================

    StructuralPattern(
        name="cholesky_sampling",
        algorithm="cholesky_sampling",
        category="stochastic",
        patterns=_compile([
            # Step 1: Cholesky factor L (sqrt in inner loop -- reuse cholesky pattern)
            r"sqrt\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # Step 2: z = randn()  (normal random)
            r"(?:rand|drand48|random|gsl_ran_gaussian|randn|normal)\s*\(",
            # Step 3: x = L * z  (lower triangular matvec)
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*\+=\s*\*?\s*\([^)]*\)\s*\*\s*\w+",
        ], re.DOTALL),
        min_matches=3,
        confidence=0.80,
        bonus_per_extra=0.07,
        max_confidence=0.90,
        description="Cholesky factor + normal random + L*z matvec = correlated random sampling",
        false_positive_note="Cholesky + matvec tek basina sampling olmayabilir; randn gerekli",
    ),

    # ========================================================================
    #  BOX-MULLER TRANSFORM  (uniform to normal)
    # ========================================================================

    StructuralPattern(
        name="box_muller",
        algorithm="box_muller_transform",
        category="stochastic",
        patterns=_compile([
            # z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * PI * u2)
            r"sqrt\s*\(\s*-?\s*2\.?0?\s*\*\s*(?:log|logf)\s*\([^)]*\)\s*\)\s*\*\s*"
            r"(?:cos|cosf)\s*\(\s*(?:2\.?0?\s*\*\s*)?(?:3\.14159|M_PI|\w+)\s*\*\s*\w+\s*\)",
            # z1 = sqrt(-2.0 * log(u1)) * sin(2.0 * PI * u2)
            r"sqrt\s*\(\s*-?\s*2\.?0?\s*\*\s*(?:log|logf)\s*\([^)]*\)\s*\)\s*\*\s*"
            r"(?:sin|sinf)\s*\(",
        ]),
        min_matches=1,
        confidence=0.92,
        bonus_per_extra=0.05,
        max_confidence=0.97,
        description="sqrt(-2*ln(u))*cos(2*pi*v) = Box-Muller normal daginim transform",
        false_positive_note="Bu pattern cok spesifik; false positive orani dusuk",
    ),

    # ========================================================================
    #  LATIN HYPERCUBE SAMPLING
    # ========================================================================

    StructuralPattern(
        name="latin_hypercube",
        algorithm="latin_hypercube_sampling",
        category="stochastic",
        patterns=_compile([
            # Stratified: (i + rand()) / N for each dimension
            r"\(\s*(?:\(\s*(?:double|float)\s*\)\s*)?\w+\s*\+\s*"
            r"(?:rand|drand48|random)\s*\([^)]*\)[^)]*\)\s*/\s*"
            r"(?:\(\s*(?:double|float)\s*\)\s*)?\w+",
            # Permutation: swap indices for each dimension
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\w+\s*=\s*(?:rand|random)\s*\([^)]*\)\s*%\s*\w+\s*;[^;]*"
            r"\w+\s*=\s*\*?\s*\([^;]+;\s*"
            r"\*?\s*\([^;]+\s*=\s*\*?\s*\([^;]+;\s*"
            r"\*?\s*\([^;]+\s*=\s*\w+",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Stratified random + permutation per dimension = Latin Hypercube Sampling",
        false_positive_note="Stratified sampling tek basina LHS olmayabilir; permutation ayirt edici",
    ),

    # ========================================================================
    #  METROPOLIS-HASTINGS  (accept/reject with ratio)
    # ========================================================================

    StructuralPattern(
        name="metropolis_hastings",
        algorithm="metropolis_hastings",
        category="stochastic",
        patterns=_compile([
            # Acceptance ratio: alpha = min(1, p(x')/p(x))  or  exp(-(E'-E)/T)
            r"(?:exp\s*\(\s*[-]?\s*\([^)]*-[^)]*\)\s*/\s*\w+\s*\)|"
            r"\w+\s*/\s*\w+)",
            # Accept/reject: if (rand() < alpha) x = x_new
            r"if\s*\(\s*(?:rand|drand48|random)\s*\([^)]*\)\s*(?:/\s*\w+\s*)?<\s*\w+\s*\)\s*"
            r"(?:\{[^{}]*)?\w+\s*=\s*\w+",
            # Proposal: x_new = x + step * randn()
            r"\w+\s*=\s*\w+\s*[+-]\s*\w+\s*\*\s*(?:rand|drand48|random|"
            r"FUN_[0-9a-fA-F]+)\s*\(",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.10,
        max_confidence=0.92,
        description="Proposal + acceptance ratio + random accept = Metropolis-Hastings MCMC",
        false_positive_note="Simulated annealing da benzer accept/reject kullanir",
    ),

    # ========================================================================
    #  LEVENBERG-MARQUARDT  -- nonlinear least squares
    # ========================================================================

    StructuralPattern(
        name="levenberg_marquardt",
        algorithm="levenberg_marquardt",
        category="optimization",
        patterns=_compile([
            # (J^T * J + lambda * I) * delta = J^T * r
            # lambda (damping) update: lambda *= factor or lambda /= factor
            r"\w+\s*\*=\s*(?:\w+|[0-9]+\.?[0-9]*)\s*;[^;]*"
            r"(?:\w+\s*/=\s*(?:\w+|[0-9]+\.?[0-9]*)|"
            r"\w+\s*\*=\s*(?:\w+|[0-9]+\.?[0-9]*))",
            # Diagonal augmentation: for(i) A[i][i] += lambda
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\*\s*\([^)]+\+\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\)\s*\+=\s*\w+",
            # J^T * J computation: double nested loop with +=
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*\)",
        ], re.DOTALL),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="J^T*J + lambda*I + damping update = Levenberg-Marquardt",
        false_positive_note="Gauss-Newton lambda=0 durumu; diagonal augmentation ile ayirt edilir",
    ),

    # ========================================================================
    #  NELDER-MEAD (Simplex) -- derivative-free optimization
    # ========================================================================

    StructuralPattern(
        name="nelder_mead",
        algorithm="nelder_mead",
        category="optimization",
        patterns=_compile([
            # Centroid: x_bar = (1/n) * sum(x[i]) for i != worst
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:if\s*\([^)]*!=\s*\w+\s*\)\s*)?"
            r"\+=\s*\*?\s*\([^)]*\)[^{}]*\}[^;]*"
            r"\w+\s*/\s*(?:\(\s*(?:double|float)\s*\)\s*)?\w+",
            # Reflection: x_r = x_bar + alpha * (x_bar - x_worst)
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # Contraction: x_c = x_bar + rho * (x_worst - x_bar)
            # or Expansion: x_e = x_bar + gamma * (x_r - x_bar)
            r"\w+\s*=\s*\w+\s*[+-]\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.10,
        max_confidence=0.88,
        description="Centroid + reflection/expansion/contraction = Nelder-Mead simplex",
        false_positive_note="Centroid + one reflection = genel ama 3 pattern birlikte NM'ye ozgu",
    ),

    # ========================================================================
    #  ADMM  (Alternating Direction Method of Multipliers)
    # ========================================================================

    StructuralPattern(
        name="admm",
        algorithm="admm",
        category="optimization",
        patterns=_compile([
            # x-update: minimize L_rho(x, z^k, y^k)
            # z-update: proximal/shrinkage: z = shrink(x + u, lambda/rho)
            # Shrinkage operator: sign(x) * max(|x| - kappa, 0)
            r"(?:fmax|fmaxf|max)\s*\(\s*(?:fabs|fabsf?)\s*\([^)]*\)\s*-\s*\w+\s*,\s*0[^)]*\)\s*"
            r"\*\s*(?:copysign|sign)",
            # Dual update: u = u + x - z  (scaled form: y = y + rho*(x - z))
            r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*?\s*\(\s*\w+\s*-\s*\w+\s*\)",
            # Convergence: primal residual r = x - z, dual residual s = rho*(z - z_old)
            r"\w+\s*=\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*;[^;]*"
            r"(?:sqrt\s*\(|(?:fabs|fabsf?)\s*\()",
        ]),
        min_matches=2,
        confidence=0.76,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="x-update + z-update (shrinkage) + dual update = ADMM",
        false_positive_note="Proximal gradient de shrinkage kullanir; dual update ADMM'ye ozgu",
    ),

    # ========================================================================
    #  SIMULATED ANNEALING  (temperature schedule + Metropolis)
    # ========================================================================

    StructuralPattern(
        name="simulated_annealing",
        algorithm="simulated_annealing",
        category="optimization",
        patterns=_compile([
            # Temperature schedule: T *= cooling_rate  or  T = T0 / log(1+k)
            r"\w+\s*\*=\s*(?:0\.\d+|\w+)\s*;",
            # Metropolis criterion: exp(-(E_new - E_old) / T)
            r"exp\s*\(\s*[-]?\s*\(\s*\w+\s*-\s*\w+\s*\)\s*/\s*\w+\s*\)",
            # Accept if better OR if random < exp(-dE/T)
            r"if\s*\(\s*\w+\s*<\s*\w+\s*\|\|\s*"
            r"(?:rand|drand48|random)\s*\([^)]*\)\s*(?:/\s*\w+\s*)?<\s*"
            r"(?:exp\s*\([^)]*\)|\w+)\s*\)",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Temperature cooling + Metropolis accept = simulated annealing",
        false_positive_note="Metropolis-Hastings de benzer accept/reject kullanir; T schedule ayirt edici",
    ),

    # ========================================================================
    #  GAUSS QUADRATURE (generic weighted sum)
    # ========================================================================

    StructuralPattern(
        name="gauss_quadrature",
        algorithm="gauss_quadrature",
        category="numerical_calculus",
        patterns=_compile([
            # sum += w[i] * f(x[i])  (weighted evaluation at Gauss points)
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\*?\s*\([^)]*\)\s*\*\s*(?:FUN_[0-9a-fA-F]+|\w+)\s*\(",
            # Gauss point coordinates from table: specific values like 0.577350 (1/sqrt(3))
            r"(?:0\.57735|5\.7735[eE][-]?0*1|0\.774596|0\.339981|0\.861136)",
            # Weight * Jacobian determinant: w * det_J
            r"\w+\s*\*\s*\w+\s*\*\s*(?:FUN_[0-9a-fA-F]+|\w+)\s*\(",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Weighted sum at specific Gauss points = numerical quadrature",
        false_positive_note="Herhangi bir weighted sum de eslesmesine neden olabilir; Gauss point degerleri ayirt edici",
    ),

    # ========================================================================
    #  STRESS-STRAIN CONSTITUTIVE  (Hooke's law / elastoplastic)
    # ========================================================================

    StructuralPattern(
        name="stress_strain_constitutive",
        algorithm="constitutive_law",
        category="finite_element",
        patterns=_compile([
            # Hooke: sigma = D * epsilon  (6x6 or 3x3 matrix-vector multiply)
            # D-matrix specific: E/(1-nu^2) or E/((1+nu)*(1-2*nu))
            r"\w+\s*/\s*\(\s*\(\s*1\.?0?\s*\+\s*\w+\s*\)\s*\*\s*"
            r"\(\s*1\.?0?\s*-\s*2\.?0?\s*\*\s*\w+\s*\)\s*\)",
            # von Mises: sigma_eq = sqrt(0.5*((s1-s2)^2 + (s2-s3)^2 + (s3-s1)^2))
            r"sqrt\s*\(\s*(?:0\.5|5\.0[eE][-]?0*1)\s*\*\s*\(\s*"
            r"\(\s*\w+\s*-\s*\w+\s*\)\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)\s*\+",
            # Yield check: if (sigma_eq > sigma_y)
            r"if\s*\(\s*\w+\s*>\s*\w+\s*\)\s*\{",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.10,
        max_confidence=0.90,
        description="D-matrix + von Mises + yield check = stress-strain constitutive model",
        false_positive_note="D-matrix multiply tek basina genel; von Mises ile birlikte ayirt edici",
    ),

    # ========================================================================
    #  B-MATRIX (strain-displacement) for FEA
    # ========================================================================

    StructuralPattern(
        name="b_matrix_strain_displacement",
        algorithm="b_matrix_assembly",
        category="finite_element",
        patterns=_compile([
            # B-matrix entries: dN/dx, dN/dy, dN/dz arranged in Voigt notation
            # B = [dN1/dx  0      0     dN2/dx  0      0    ...]
            #     [0       dN1/dy 0     0       dN2/dy 0    ...]
            #     [0       0      dN1/dz 0      0      dN2/dz ...]
            #     [dN1/dy  dN1/dx 0     ...]
            # Pattern: alternating zero/nonzero in sparse row
            r"\*\s*\([^)]+\)\s*=\s*\w+\s*;[^;]*"
            r"\*\s*\([^)]+\)\s*=\s*0[^;]*;[^;]*"
            r"\*\s*\([^)]+\)\s*=\s*0[^;]*;",
            # K_local = B^T * D * B  (element stiffness)
            # Triple nested loop with 6x6 or 3x3 inner products
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"(?:for|while)\s*\([^)]*\)\s*\{[^{}]*"
            r"\+=\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*\)\s*\*\s*\*?\s*\([^)]*\)",
        ], re.DOTALL),
        min_matches=1,
        confidence=0.72,
        bonus_per_extra=0.12,
        max_confidence=0.88,
        description="Alternating zero/nonzero sparse rows + B^T*D*B triple product = B-matrix assembly",
        false_positive_note="Sparse matrix initialization de benzer gorunur; Voigt ordering ayirt edici",
    ),


    # ========================================================================
    #  QUANTITATIVE FINANCE (v1.2.2)
    # ========================================================================

    StructuralPattern(
        name="black_scholes_merton",
        algorithm="black_scholes_merton",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bblack_scholes\b",
            r"(?i)\bbsm\b",
            r"(?i)\bbs_call\b",
            r"(?i)\bbs_put\b",
            r"(?i)\bd1\b",
            r"(?i)\bd2\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Black-Scholes-Merton European option pricing formula. The constants are from Abramowitz-Stegun rational approximation of",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="heston_model",
        algorithm="heston_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bheston\b",
            r"(?i)\bvol_of_vol\b",
            r"(?i)\bkappa\b",
            r"(?i)\btheta\b",
            r"(?i)\bxi\b",
            r"(?i)\brho\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Heston stochastic volatility model with mean-reverting variance process. Feller condition: 2*kappa*theta > xi^2.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hull_white_1f",
        algorithm="hull_white_1f",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bhull_white\b",
            r"(?i)\bhw_1f\b",
            r"(?i)\bhw1f\b",
            r"(?i)\bmean_reversion\b",
            r"(?i)\btheta_t\b",
            r"(?i)\bshort_rate\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Hull-White one-factor short rate model. theta(t) calibrated to fit initial yield curve exactly.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hull_white_2f",
        algorithm="hull_white_2f",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bhull_white_2f\b",
            r"(?i)\bhw2f\b",
            r"(?i)\btwo_factor\b",
            r"(?i)\bg2pp\b",
            r"(?i)\bphi_t\b",
            r"(?i)\bfactor1\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Hull-White two-factor (G2++) model. Two correlated mean-reverting factors plus a deterministic shift.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cox_ingersoll_ross",
        algorithm="cox_ingersoll_ross",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bcir\b",
            r"(?i)\bcox_ingersoll_ross\b",
            r"(?i)\bcir_process\b",
            r"(?i)\bsquare_root\b",
            r"(?i)\bfeller\b",
            r"(?i)\bmean_reversion\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Cox-Ingersoll-Ross model. Square-root diffusion ensures non-negative rates when Feller condition 2*kappa*theta >= sigma^",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vasicek_model",
        algorithm="vasicek_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bvasicek\b",
            r"(?i)\bornstein_uhlenbeck\b",
            r"(?i)\bmean_reversion\b",
            r"(?i)\bvasicek_bond\b",
            r"(?i)\bvasicek_zcb\b",
            r"(?i)\bB_tT\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Vasicek short rate model. Ornstein-Uhlenbeck process, allows negative rates. Closed-form zero coupon bond price.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sabr_model",
        algorithm="sabr_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bsabr\b",
            r"(?i)\bsabr_vol\b",
            r"(?i)\bsabr_implied_vol\b",
            r"(?i)\balpha\b",
            r"(?i)\bbeta\b",
            r"(?i)\brho\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SABR stochastic alpha-beta-rho model. Hagan's asymptotic implied volatility formula widely used for swaption/cap smile.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="black_karasinski",
        algorithm="black_karasinski",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bblack_karasinski\b",
            r"(?i)\bbk_model\b",
            r"(?i)\blog_normal_rate\b",
            r"(?i)\bbk_tree\b",
            r"(?i)\bbk_calibrate\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Black-Karasinski log-normal short rate model. Guarantees positive rates. No closed-form bond price, requires tree or PDE",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="local_volatility_dupire",
        algorithm="local_volatility_dupire",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bdupire\b",
            r"(?i)\blocal_vol\b",
            r"(?i)\blocal_volatility\b",
            r"(?i)\bdupire_formula\b",
            r"(?i)\bimplied_vol_surface\b",
            r"(?i)\blvol\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Dupire's local volatility formula. Derives local vol from market call prices or implied vol surface.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cev_model",
        algorithm="cev_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bcev\b",
            r"(?i)\bconstant_elasticity\b",
            r"(?i)\bcev_price\b",
            r"(?i)\bcev_vol\b",
            r"(?i)\bbeta_cev\b",
            r"(?i)\bnoncentral_chi\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Constant Elasticity of Variance model. beta<1 gives leverage effect (skew). Pricing uses non-central chi-squared distrib",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="merton_jump_diffusion",
        algorithm="merton_jump_diffusion",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bmerton_jump\b",
            r"(?i)\bjump_diffusion\b",
            r"(?i)\bpoisson\b",
            r"(?i)\blambda_jump\b",
            r"(?i)\bjump_size\b",
            r"(?i)\bmjd\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Merton jump-diffusion model. GBM + compound Poisson jumps with log-normal jump sizes. Pricing via series expansion.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kou_double_exponential",
        algorithm="kou_double_exponential",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bkou\b",
            r"(?i)\bdouble_exponential\b",
            r"(?i)\bkou_jump\b",
            r"(?i)\beta1\b",
            r"(?i)\beta2\b",
            r"(?i)\bp_up\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Kou double-exponential jump-diffusion. Asymmetric jumps with different decay rates for up/down moves. Memoryless propert",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bates_model",
        algorithm="bates_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bbates\b",
            r"(?i)\bsvj\b",
            r"(?i)\bstochastic_vol_jump\b",
            r"(?i)\bheston_jump\b",
            r"(?i)\bbates_cf\b",
            r"(?i)\bbates_price\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Bates model = Heston stochastic volatility + Merton-style log-normal jumps. Captures both volatility smile and short-ter",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="binomial_tree_crr",
        algorithm="binomial_tree_crr",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcrr\b",
            r"(?i)\bbinomial\b",
            r"(?i)\bcox_ross_rubinstein\b",
            r"(?i)\bbinomial_tree\b",
            r"(?i)\bup_factor\b",
            r"(?i)\bdown_factor\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Cox-Ross-Rubinstein binomial tree. Recombining lattice for option pricing. Backward induction from terminal payoff.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="trinomial_tree",
        algorithm="trinomial_tree",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\btrinomial\b",
            r"(?i)\btrinomial_tree\b",
            r"(?i)\bp_up\b",
            r"(?i)\bp_mid\b",
            r"(?i)\bp_down\b",
            r"(?i)\bthree_branch\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Trinomial lattice model. Three branches (up/mid/down) per node. Better convergence than binomial for exotic options.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="longstaff_schwartz_lsmc",
        algorithm="longstaff_schwartz_lsmc",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\blongstaff_schwartz\b",
            r"(?i)\blsmc\b",
            r"(?i)\bleast_squares_mc\b",
            r"(?i)\blsm\b",
            r"(?i)\bamerican_option\b",
            r"(?i)\bcontinuation_value\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Longstaff-Schwartz Least Squares Monte Carlo for American option pricing. Regression of continuation value on basis func",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="barone_adesi_whaley",
        algorithm="barone_adesi_whaley",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bbarone_adesi\b",
            r"(?i)\bbaw\b",
            r"(?i)\bquadratic_approx\b",
            r"(?i)\bamerican_approx\b",
            r"(?i)\bearly_exercise\b",
            r"(?i)\bcritical_price\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Barone-Adesi-Whaley quadratic approximation for American options. Fast closed-form approximation using critical stock pr",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="asian_option_geometric",
        algorithm="asian_option_geometric",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\basian_geometric\b",
            r"(?i)\bgeometric_average\b",
            r"(?i)\bgeo_asian\b",
            r"(?i)\baverage_price\b",
            r"(?i)\bavg_strike\b",
            r"(?i)\bproduct_avg\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Geometric Asian option. Product average has log-normal distribution -> closed-form BSM-style pricing. Used as control va",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="asian_option_arithmetic",
        algorithm="asian_option_arithmetic",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\basian_arithmetic\b",
            r"(?i)\barithmetic_average\b",
            r"(?i)\bturnbull_wakeman\b",
            r"(?i)\blevy_approx\b",
            r"(?i)\bcontrol_variate_asian\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Arithmetic Asian option. No closed-form; priced via MC (often with geometric Asian as control variate) or moment-matchin",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="barrier_option",
        algorithm="barrier_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bbarrier\b",
            r"(?i)\bknock_in\b",
            r"(?i)\bknock_out\b",
            r"(?i)\bup_and_out\b",
            r"(?i)\bdown_and_in\b",
            r"(?i)\bup_and_in\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Barrier options (knock-in/out, up/down). Closed-form for continuous barriers. Discrete monitoring requires correction (B",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bermudan_swaption",
        algorithm="bermudan_swaption",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bbermudan\b",
            r"(?i)\bswaption\b",
            r"(?i)\bbermudan_swaption\b",
            r"(?i)\bexercise_dates\b",
            r"(?i)\bswap_rate\b",
            r"(?i)\bannuity\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Bermudan swaption - exercisable on coupon dates. Priced via LSMC, tree methods, or PDE on short-rate models.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lookback_option",
        algorithm="lookback_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\blookback\b",
            r"(?i)\bfloating_strike\b",
            r"(?i)\bfixed_strike\b",
            r"(?i)\brunning_max\b",
            r"(?i)\brunning_min\b",
            r"(?i)\bpath_dependent\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Lookback options. Fixed or floating strike based on running max/min. Goldman-Sosin-Gatto closed-form for continuous moni",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cliquet_option",
        algorithm="cliquet_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcliquet\b",
            r"(?i)\bratchet\b",
            r"(?i)\breset_option\b",
            r"(?i)\bperiodic_return\b",
            r"(?i)\blocal_cap\b",
            r"(?i)\blocal_floor\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Cliquet (ratchet) option. Sum of capped/floored periodic returns. Common in structured products. Requires stochastic vol",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rainbow_option",
        algorithm="rainbow_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\brainbow\b",
            r"(?i)\bbest_of\b",
            r"(?i)\bworst_of\b",
            r"(?i)\bmulti_asset\b",
            r"(?i)\bcorrelation_matrix\b",
            r"(?i)\bbasket\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Rainbow options on multiple assets. Best-of, worst-of, spread. 2-asset case has Margrabe/Stulz closed-form. General case",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="quanto_option",
        algorithm="quanto_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bquanto\b",
            r"(?i)\bcross_currency\b",
            r"(?i)\bfx_adjusted\b",
            r"(?i)\bquanto_correction\b",
            r"(?i)\brho_fx\b",
            r"(?i)\bsigma_fx\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Quanto option - payoff in foreign asset but settled in domestic currency at fixed FX rate. Requires FX-asset correlation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="nelson_siegel",
        algorithm="nelson_siegel",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bnelson_siegel\b",
            r"(?i)\bns_model\b",
            r"(?i)\bbeta0\b",
            r"(?i)\bbeta1\b",
            r"(?i)\bbeta2\b",
            r"(?i)\blambda_ns\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Nelson-Siegel yield curve model. Three factors: level (beta0), slope (beta1), curvature (beta2). Parsimonious and widely",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="svensson_model",
        algorithm="svensson_model",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bsvensson\b",
            r"(?i)\bnss\b",
            r"(?i)\bnelson_siegel_svensson\b",
            r"(?i)\bbeta3\b",
            r"(?i)\blambda1\b",
            r"(?i)\blambda2\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Svensson (Nelson-Siegel-Svensson) extended model. Additional curvature term with second decay factor. Used by ECB, Bunde",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="yield_curve_bootstrap",
        algorithm="yield_curve_bootstrap",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bbootstrap\b",
            r"(?i)\bstrip\b",
            r"(?i)\byield_bootstrap\b",
            r"(?i)\bdiscount_factor\b",
            r"(?i)\bzero_rate\b",
            r"(?i)\bpar_rate\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Yield curve bootstrapping. Sequential extraction of discount factors from deposits, futures, and swaps. Foundation of ra",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cubic_spline_interpolation",
        algorithm="cubic_spline_interpolation",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bcubic_spline\b",
            r"(?i)\bspline_interp\b",
            r"(?i)\bnatural_spline\b",
            r"(?i)\bnot_a_knot\b",
            r"(?i)\btridiagonal\b",
            r"(?i)\bspline_coeff\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Cubic spline interpolation for yield curves. Tridiagonal system solve. Natural or clamped boundary conditions.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="monotone_convex",
        algorithm="monotone_convex",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bmonotone_convex\b",
            r"(?i)\bhagan_west\b",
            r"(?i)\bforward_monotone\b",
            r"(?i)\bconvex_interp\b",
            r"(?i)\bpositive_forward\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Monotone convex interpolation (Hagan-West). Guarantees positive forward rates and exact repricing of input instruments.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ois_discounting",
        algorithm="ois_discounting",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bois\b",
            r"(?i)\bovernight_index\b",
            r"(?i)\bdual_curve\b",
            r"(?i)\bois_discount\b",
            r"(?i)\bcsa_discount\b",
            r"(?i)\bfed_funds\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="OIS discounting (post-2008 standard). Dual-curve framework: projection curve (LIBOR/SOFR) separate from discounting curv",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="var_historical",
        algorithm="var_historical",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bvar_historical\b",
            r"(?i)\bhistorical_var\b",
            r"(?i)\bhist_var\b",
            r"(?i)\bquantile\b",
            r"(?i)\bpercentile\b",
            r"(?i)\bpnl_sort\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Historical simulation VaR. Sort historical P&L, take quantile. No distributional assumption. 99% and 95% common confiden",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="var_parametric",
        algorithm="var_parametric",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bvar_parametric\b",
            r"(?i)\bvariance_covariance\b",
            r"(?i)\bdelta_normal\b",
            r"(?i)\bz_score\b",
            r"(?i)\bportfolio_var\b",
            r"(?i)\bcov_matrix\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Parametric (variance-covariance) VaR. Assumes normal returns. z=1.645 (95%), z=2.326 (99%). Portfolio variance via covar",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="var_monte_carlo",
        algorithm="var_monte_carlo",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bmc_var\b",
            r"(?i)\bmonte_carlo_var\b",
            r"(?i)\bsimulated_var\b",
            r"(?i)\bscenario_generation\b",
            r"(?i)\bfull_reval\b",
            r"(?i)\bfull_revaluation\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Monte Carlo VaR. Full revaluation under simulated scenarios. Handles nonlinear exposures and fat tails.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="expected_shortfall_cvar",
        algorithm="expected_shortfall_cvar",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bexpected_shortfall\b",
            r"(?i)\bcvar\b",
            r"(?i)\bes\b",
            r"(?i)\bconditional_var\b",
            r"(?i)\btail_risk\b",
            r"(?i)\bavg_var\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Expected Shortfall (CVaR). Average loss beyond VaR. Coherent risk measure (subadditive). Basel III requires ES at 97.5%.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cva_credit_valuation",
        algorithm="cva_credit_valuation",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bcva\b",
            r"(?i)\bcredit_valuation_adjustment\b",
            r"(?i)\bexpected_exposure\b",
            r"(?i)\bee\b",
            r"(?i)\bepe\b",
            r"(?i)\brecovery_rate\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Credit Valuation Adjustment. Expected loss from counterparty default. Recovery rate typically 40%. EE = expected positiv",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dva_debit_valuation",
        algorithm="dva_debit_valuation",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bdva\b",
            r"(?i)\bdebit_valuation_adjustment\b",
            r"(?i)\bown_credit\b",
            r"(?i)\bene\b",
            r"(?i)\bexpected_negative_exposure\b",
            r"(?i)\bbilateral_cva\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Debit Valuation Adjustment. Benefit from own default. Controversial. DVA = own-credit CVA from counterparty's perspectiv",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="fva_funding_valuation",
        algorithm="fva_funding_valuation",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bfva\b",
            r"(?i)\bfunding_valuation_adjustment\b",
            r"(?i)\bfunding_spread\b",
            r"(?i)\buncollateralized\b",
            r"(?i)\bfunding_cost\b",
            r"(?i)\bfunding_benefit\b",
        ]),
        min_matches=2,
        confidence=0.83,
        bonus_per_extra=0.08,
        max_confidence=0.93,
        description="Funding Valuation Adjustment. Cost of funding uncollateralized exposure. Part of XVA framework.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_delta",
        algorithm="greeks_delta",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bdelta\b",
            r"(?i)\bdelta_hedge\b",
            r"(?i)\bfinite_diff_delta\b",
            r"(?i)\bbump_delta\b",
            r"(?i)\bNd1\b",
            r"(?i)\bhedge_ratio\b",
        ]),
        min_matches=2,
        confidence=0.96,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Delta - first derivative of option value w.r.t. underlying price. BSM call delta = N(d1). Central finite difference for ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_gamma",
        algorithm="greeks_gamma",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bgamma\b",
            r"(?i)\bgamma_risk\b",
            r"(?i)\bsecond_derivative\b",
            r"(?i)\bgamma_scalp\b",
            r"(?i)\bpin_risk\b",
            r"(?i)\bconvexity_option\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Gamma - second derivative of option value w.r.t. underlying. Measures delta sensitivity. Peaks at ATM near expiry.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_vega",
        algorithm="greeks_vega",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bvega\b",
            r"(?i)\bvol_sensitivity\b",
            r"(?i)\bvega_hedge\b",
            r"(?i)\bvega_neutral\b",
            r"(?i)\bkappa_vega\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Vega - sensitivity to implied volatility. Not a Greek letter (sometimes called kappa). Maximal for ATM options.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_theta",
        algorithm="greeks_theta",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\btheta\b",
            r"(?i)\btime_decay\b",
            r"(?i)\btheta_bleed\b",
            r"(?i)\bdaily_theta\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Theta - time decay of option value. Usually negative for long options. Convention: per calendar day (/365) or per tradin",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_rho",
        algorithm="greeks_rho",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\brho\b",
            r"(?i)\brate_sensitivity\b",
            r"(?i)\brho_greek\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Rho - sensitivity to risk-free interest rate. More significant for long-dated options.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_vanna",
        algorithm="greeks_vanna",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bvanna\b",
            r"(?i)\bdvega_dspot\b",
            r"(?i)\bddelta_dvol\b",
            r"(?i)\bcross_greek\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Vanna - cross-Greek: d(delta)/d(vol) = d(vega)/d(spot). Important for volatility smile dynamics and risk management.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="greeks_volga",
        algorithm="greeks_volga",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bvolga\b",
            r"(?i)\bvomma\b",
            r"(?i)\bdvega_dvol\b",
            r"(?i)\bvol_gamma\b",
            r"(?i)\bvol_convexity\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Volga (Vomma) - second derivative w.r.t. volatility. Measures convexity of vega. Key for vanna-volga pricing method.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sobol_sequence",
        algorithm="sobol_sequence",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bsobol\b",
            r"(?i)\bquasi_random\b",
            r"(?i)\blow_discrepancy\b",
            r"(?i)\bdirection_numbers\b",
            r"(?i)\bjoe_kuo\b",
            r"(?i)\bsobol_init\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Sobol quasi-random sequence. Low-discrepancy for MC integration. Joe-Kuo direction numbers standard. Gray code generatio",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="halton_sequence",
        algorithm="halton_sequence",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bhalton\b",
            r"(?i)\bquasi_random\b",
            r"(?i)\bradical_inverse\b",
            r"(?i)\bbase_prime\b",
            r"(?i)\bhalton_seq\b",
            r"(?i)\bscrambled_halton\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Halton quasi-random sequence. Radical inverse function in different prime bases per dimension. Degrades in high dimensio",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="brownian_bridge",
        algorithm="brownian_bridge",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bbrownian_bridge\b",
            r"(?i)\bbridge_construction\b",
            r"(?i)\bpath_construction\b",
            r"(?i)\bbb_fill\b",
            r"(?i)\bconditional_gaussian\b",
            r"(?i)\bstratified_bb\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Brownian bridge path construction. Interpolates between known endpoints. Concentrates variance on important time steps. ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gauss_hermite_quadrature",
        algorithm="gauss_hermite_quadrature",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bgauss_hermite\b",
            r"(?i)\bquadrature\b",
            r"(?i)\bhermite_nodes\b",
            r"(?i)\bhermite_weights\b",
            r"(?i)\bghq\b",
            r"(?i)\bgaussian_quadrature\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Gauss-Hermite quadrature for integrating f(x)*exp(-x^2). Used in finance for expectations over normal distribution. Node",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="brent_solver",
        algorithm="brent_solver",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bbrent\b",
            r"(?i)\bbrentq\b",
            r"(?i)\broot_finding\b",
            r"(?i)\bbisection\b",
            r"(?i)\bsecant\b",
            r"(?i)\binverse_quadratic\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Brent's root-finding method. Combines bisection, secant, and inverse quadratic interpolation. Guaranteed convergence. Us",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="newton_raphson_implied_vol",
        algorithm="newton_raphson_implied_vol",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bnewton_raphson\b",
            r"(?i)\bimplied_vol\b",
            r"(?i)\biv_solver\b",
            r"(?i)\bvega_iteration\b",
            r"(?i)\bnewton_iv\b",
            r"(?i)\bvol_inversion\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Newton-Raphson for implied volatility. Iterate sigma using vega as Jacobian. Initial guess ~0.2. Jaeckel's rational appr",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="crank_nicolson_pde",
        algorithm="crank_nicolson_pde",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bcrank_nicolson\b",
            r"(?i)\bcn_scheme\b",
            r"(?i)\bimplicit_explicit\b",
            r"(?i)\btridiagonal\b",
            r"(?i)\bthomas_algorithm\b",
            r"(?i)\btdma\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Crank-Nicolson finite difference scheme for Black-Scholes PDE. O(dt^2, dS^2). Tridiagonal system solved by Thomas algori",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="adi_scheme",
        algorithm="adi_scheme",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\badi\b",
            r"(?i)\balternating_direction\b",
            r"(?i)\bdouglas_rachford\b",
            r"(?i)\bcraig_sneyd\b",
            r"(?i)\bhundsdorfer_verwer\b",
            r"(?i)\bmulti_factor_pde\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Alternating Direction Implicit for multi-factor PDEs (Heston, 2-factor rates). Douglas-Rachford, Craig-Sneyd, Hundsdorfe",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="monte_carlo_gbm",
        algorithm="monte_carlo_gbm",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bgbm\b",
            r"(?i)\bgeometric_brownian\b",
            r"(?i)\bmc_simulation\b",
            r"(?i)\blognormal\b",
            r"(?i)\beuler_maruyama\b",
            r"(?i)\bmilstein\b",
        ]),
        min_matches=2,
        confidence=0.96,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Monte Carlo GBM path simulation. Exact log-normal simulation or Euler-Maruyama discretization. Antithetic variates for v",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="antithetic_variates",
        algorithm="antithetic_variates",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bantithetic\b",
            r"(?i)\bvariance_reduction\b",
            r"(?i)\bantithetic_variate\b",
            r"(?i)\bnegate_z\b",
            r"(?i)\bmirror_path\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Antithetic variates variance reduction. For each random Z, also evaluate at -Z. Halves variance for monotone payoffs at ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="control_variates",
        algorithm="control_variates",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bcontrol_variate\b",
            r"(?i)\bvariance_reduction\b",
            r"(?i)\bbeta_cv\b",
            r"(?i)\banalytic_control\b",
            r"(?i)\bgeometric_asian_cv\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Control variates. Reduce MC variance using correlated random variable with known expectation. Geometric Asian as control",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="importance_sampling",
        algorithm="importance_sampling",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bimportance_sampling\b",
            r"(?i)\blikelihood_ratio\b",
            r"(?i)\bmeasure_change\b",
            r"(?i)\bgirsanov\b",
            r"(?i)\bdrift_shift\b",
            r"(?i)\bis_mc\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Importance sampling. Change probability measure to sample more from important regions. Girsanov theorem for drift change",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="jarrow_turnbull",
        algorithm="jarrow_turnbull",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bjarrow_turnbull\b",
            r"(?i)\breduced_form\b",
            r"(?i)\bhazard_rate\b",
            r"(?i)\bsurvival_probability\b",
            r"(?i)\bdefault_intensity\b",
            r"(?i)\blambda_default\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Jarrow-Turnbull reduced-form credit model. Default as Poisson event with hazard rate lambda. Calibrated from CDS spreads",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="merton_structural",
        algorithm="merton_structural",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bmerton_structural\b",
            r"(?i)\bstructural_model\b",
            r"(?i)\bdistance_to_default\b",
            r"(?i)\bdd\b",
            r"(?i)\bfirm_value\b",
            r"(?i)\bdefault_point\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Merton structural credit model. Equity as call on firm assets. Default when assets < liabilities at maturity. KMV distan",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cds_pricing",
        algorithm="cds_pricing",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bcds\b",
            r"(?i)\bcredit_default_swap\b",
            r"(?i)\bprotection_leg\b",
            r"(?i)\bpremium_leg\b",
            r"(?i)\bcds_spread\b",
            r"(?i)\bcds_upfront\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="CDS par spread pricing. Protection leg (default payments) = Premium leg (spread payments). Recovery assumption typically",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bond_pricing",
        algorithm="bond_pricing",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bbond_price\b",
            r"(?i)\bbond_pricing\b",
            r"(?i)\bclean_price\b",
            r"(?i)\bdirty_price\b",
            r"(?i)\baccrued_interest\b",
            r"(?i)\bcoupon\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Bond pricing. Clean vs dirty price (dirty = clean + accrued interest). Day count conventions: 30/360, ACT/360, ACT/365, ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="duration_macaulay",
        algorithm="duration_macaulay",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bduration\b",
            r"(?i)\bmacaulay_duration\b",
            r"(?i)\bmodified_duration\b",
            r"(?i)\bmod_duration\b",
            r"(?i)\bdv01\b",
            r"(?i)\bbpv\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Macaulay and modified duration. First-order price sensitivity to yield. DV01 = dollar value of 1bp = mod_duration * pric",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="convexity",
        algorithm="convexity",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bconvexity\b",
            r"(?i)\bbond_convexity\b",
            r"(?i)\bsecond_order\b",
            r"(?i)\bprice_yield\b",
            r"(?i)\bconvexity_adjustment\b",
            r"(?i)\beffective_convexity\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Bond convexity. Second-order yield sensitivity. Delta_P/P ~ -D*Delta_y + 0.5*C*(Delta_y)^2. Positive convexity benefits ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="implied_volatility_jaeckel",
        algorithm="implied_volatility_jaeckel",
        category="volatility",
        patterns=_compile([
            r"(?i)\bjaeckel\b",
            r"(?i)\blets_be_rational\b",
            r"(?i)\bimplied_vol_rational\b",
            r"(?i)\bnormalised_price\b",
            r"(?i)\biv_rational\b",
            r"(?i)\bpeter_jaeckel\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Jaeckel's 'Let's Be Rational' implied vol. Machine-precision accuracy without iteration. Rational function approximation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="svi_volatility_surface",
        algorithm="svi_volatility_surface",
        category="volatility",
        patterns=_compile([
            r"(?i)\bsvi\b",
            r"(?i)\bstochastic_volatility_inspired\b",
            r"(?i)\bgatheral\b",
            r"(?i)\bsvi_params\b",
            r"(?i)\bsvi_calibrate\b",
            r"(?i)\braw_svi\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SVI (Stochastic Volatility Inspired) parameterization by Gatheral. 5 params: a (level), b (slope), rho (rotation), m (tr",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ssvi_surface",
        algorithm="ssvi_surface",
        category="volatility",
        patterns=_compile([
            r"(?i)\bssvi\b",
            r"(?i)\bsurface_svi\b",
            r"(?i)\bgatheral_jacquier\b",
            r"(?i)\btheta_t\b",
            r"(?i)\bphi_function\b",
            r"(?i)\batm_variance\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="SSVI (Surface SVI). Arbitrage-free extension of SVI across all maturities. phi(theta) typically power-law. Gatheral-Jacq",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="realized_vol_close_to_close",
        algorithm="realized_vol_close_to_close",
        category="volatility",
        patterns=_compile([
            r"(?i)\brealized_vol\b",
            r"(?i)\bhistorical_vol\b",
            r"(?i)\bclose_to_close\b",
            r"(?i)\blog_return\b",
            r"(?i)\bannualized_vol\b",
            r"(?i)\bsample_variance\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Close-to-close realized volatility. Annualized standard deviation of log returns. 252 trading days. Simplest estimator.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="parkinson_volatility",
        algorithm="parkinson_volatility",
        category="volatility",
        patterns=_compile([
            r"(?i)\bparkinson\b",
            r"(?i)\bhigh_low_vol\b",
            r"(?i)\brange_vol\b",
            r"(?i)\bparkinson_estimator\b",
            r"(?i)\bhl_vol\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Parkinson range-based volatility estimator. Uses high-low only. ~5x more efficient than close-to-close. Assumes no drift",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="garman_klass_volatility",
        algorithm="garman_klass_volatility",
        category="volatility",
        patterns=_compile([
            r"(?i)\bgarman_klass\b",
            r"(?i)\bgk_vol\b",
            r"(?i)\bohlc_vol\b",
            r"(?i)\bgarman_klass_estimator\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Garman-Klass OHLC volatility estimator. Uses open, high, low, close. ~7.4x efficiency vs close-to-close. (2*ln2-1) = 0.3",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="yang_zhang_volatility",
        algorithm="yang_zhang_volatility",
        category="volatility",
        patterns=_compile([
            r"(?i)\byang_zhang\b",
            r"(?i)\byz_vol\b",
            r"(?i)\bovernight_vol\b",
            r"(?i)\brogers_satchell\b",
            r"(?i)\bopen_close_vol\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Yang-Zhang volatility. Combines overnight (open-close), Rogers-Satchell, and close-to-close components. Handles drift an",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="garch_1_1",
        algorithm="garch_1_1",
        category="volatility",
        patterns=_compile([
            r"(?i)\bgarch\b",
            r"(?i)\bgarch11\b",
            r"(?i)\barch\b",
            r"(?i)\bconditional_variance\b",
            r"(?i)\bomega\b",
            r"(?i)\balpha_garch\b",
        ]),
        min_matches=2,
        confidence=0.94,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="GARCH(1,1) conditional variance model. omega = long-run var weight, alpha = shock impact, beta = persistence. MLE estima",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ewma_volatility",
        algorithm="ewma_volatility",
        category="volatility",
        patterns=_compile([
            r"(?i)\bewma\b",
            r"(?i)\bexponential_weighted\b",
            r"(?i)\briskmetrics\b",
            r"(?i)\blambda_decay\b",
            r"(?i)\bewma_vol\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="EWMA (Exponentially Weighted Moving Average) volatility. Special case of GARCH with omega=0, alpha+beta=1. RiskMetrics l",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vanna_volga_pricing",
        algorithm="vanna_volga_pricing",
        category="volatility",
        patterns=_compile([
            r"(?i)\bvanna_volga\b",
            r"(?i)\bvv_method\b",
            r"(?i)\bfx_smile\b",
            r"(?i)\b25delta\b",
            r"(?i)\batm_vol\b",
            r"(?i)\brisk_reversal\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Vanna-volga pricing method. FX market standard. Adjusts BS price using vanna/volga at market pillars (ATM, 25-delta). Mo",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="markowitz_mean_variance",
        algorithm="markowitz_mean_variance",
        category="portfolio_optimization",
        patterns=_compile([
            r"(?i)\bmarkowitz\b",
            r"(?i)\bmean_variance\b",
            r"(?i)\befficient_frontier\b",
            r"(?i)\bportfolio_optimization\b",
            r"(?i)\bquadratic_programming\b",
            r"(?i)\bmin_variance\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Markowitz mean-variance optimization. Quadratic programming for efficient frontier. Tangency portfolio maximizes Sharpe ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="black_litterman",
        algorithm="black_litterman",
        category="portfolio_optimization",
        patterns=_compile([
            r"(?i)\bblack_litterman\b",
            r"(?i)\bbl_model\b",
            r"(?i)\bequilibrium_returns\b",
            r"(?i)\bviews\b",
            r"(?i)\btau\b",
            r"(?i)\bomega_matrix\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Black-Litterman model. Combines equilibrium returns (CAPM implied) with investor views. tau typically 0.025-0.05. Omega ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="risk_parity",
        algorithm="risk_parity",
        category="portfolio_optimization",
        patterns=_compile([
            r"(?i)\brisk_parity\b",
            r"(?i)\bequal_risk_contribution\b",
            r"(?i)\berc\b",
            r"(?i)\brisk_budget\b",
            r"(?i)\brc_portfolio\b",
            r"(?i)\bmarginal_risk\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Risk parity / Equal Risk Contribution. Each asset contributes equally to portfolio risk. Bridgewater All-Weather style. ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kelly_criterion",
        algorithm="kelly_criterion",
        category="portfolio_optimization",
        patterns=_compile([
            r"(?i)\bkelly\b",
            r"(?i)\bkelly_criterion\b",
            r"(?i)\boptimal_fraction\b",
            r"(?i)\bkelly_leverage\b",
            r"(?i)\bhalf_kelly\b",
            r"(?i)\blog_utility\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Kelly criterion for optimal bet sizing. Maximizes log-wealth growth. Multi-asset: f = Sigma^{-1}*(mu-r). Half-Kelly comm",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="libor_market_model_bgm",
        algorithm="libor_market_model_bgm",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\blmm\b",
            r"(?i)\bbgm\b",
            r"(?i)\blibor_market_model\b",
            r"(?i)\bbrace_gatarek_musiela\b",
            r"(?i)\bforward_libor\b",
            r"(?i)\bswaption_vol\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="LIBOR Market Model (BGM). Models evolution of forward LIBOR rates. Drift correction for terminal measure. Calibrated to ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="swap_pricing",
        algorithm="swap_pricing",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bswap_pricing\b",
            r"(?i)\birs\b",
            r"(?i)\binterest_rate_swap\b",
            r"(?i)\bpar_swap_rate\b",
            r"(?i)\bfixed_leg\b",
            r"(?i)\bfloating_leg\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Interest rate swap pricing. Fixed vs floating leg NPV. Par swap rate equates PV of legs. Annuity factor = sum of discoun",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="black76_swaption",
        algorithm="black76_swaption",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bblack76\b",
            r"(?i)\bblack_model\b",
            r"(?i)\bswaption_price\b",
            r"(?i)\bblack_formula\b",
            r"(?i)\bforward_measure\b",
            r"(?i)\bannuity\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Black-76 model for swaptions and caps. Forward-measure pricing with annuity as numeraire. Vol is lognormal (Black) or no",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bachelier_normal_model",
        algorithm="bachelier_normal_model",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bbachelier\b",
            r"(?i)\bnormal_model\b",
            r"(?i)\bnormal_vol\b",
            r"(?i)\bbasis_point_vol\b",
            r"(?i)\barithmetic_brownian\b",
            r"(?i)\bnormal_black\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Bachelier (normal) model. Arithmetic Brownian motion. Used when rates can be negative. Normal vol in bp. Standard for ra",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="copula_gaussian",
        algorithm="copula_gaussian",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bgaussian_copula\b",
            r"(?i)\bcopula\b",
            r"(?i)\bdefault_correlation\b",
            r"(?i)\bcdo_pricing\b",
            r"(?i)\bbase_correlation\b",
            r"(?i)\bone_factor\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Gaussian copula for credit portfolio modeling. Li (2000) CDO pricing. Base correlation from market. One-factor model for",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="t_copula",
        algorithm="t_copula",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bt_copula\b",
            r"(?i)\bstudent_t_copula\b",
            r"(?i)\btail_dependence\b",
            r"(?i)\bnu_degrees\b",
            r"(?i)\bheavy_tail_copula\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Student-t copula. Tail dependence unlike Gaussian copula. nu = degrees of freedom controls tail heaviness. Better for st",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="twap",
        algorithm="twap",
        category="execution_algorithm",
        patterns=_compile([
            r"(?i)\btwap\b",
            r"(?i)\btime_weighted\b",
            r"(?i)\bvwap_benchmark\b",
            r"(?i)\bslice_order\b",
            r"(?i)\bchild_order\b",
            r"(?i)\bexecution_algo\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="TWAP (Time Weighted Average Price). Execute equal quantities at regular intervals. Simplest execution algorithm. Benchma",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vwap_algorithm",
        algorithm="vwap_algorithm",
        category="execution_algorithm",
        patterns=_compile([
            r"(?i)\bvwap\b",
            r"(?i)\bvolume_weighted\b",
            r"(?i)\bvolume_profile\b",
            r"(?i)\bparticipation_rate\b",
            r"(?i)\bvolume_bucket\b",
            r"(?i)\bvolume_forecast\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="VWAP execution algorithm. Trade proportional to historical volume profile. Minimize deviation from volume-weighted avera",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="almgren_chriss",
        algorithm="almgren_chriss",
        category="execution_algorithm",
        patterns=_compile([
            r"(?i)\balmgren_chriss\b",
            r"(?i)\boptimal_execution\b",
            r"(?i)\bmarket_impact\b",
            r"(?i)\btemporary_impact\b",
            r"(?i)\bpermanent_impact\b",
            r"(?i)\btrade_trajectory\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Almgren-Chriss optimal execution. Balances execution risk vs market impact cost. kappa = urgency parameter. Exponential ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="carr_madan_fft",
        algorithm="carr_madan_fft",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcarr_madan\b",
            r"(?i)\bfft_pricing\b",
            r"(?i)\bcharacteristic_function\b",
            r"(?i)\bfourier_pricing\b",
            r"(?i)\balpha_damping\b",
            r"(?i)\bfft_option\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Carr-Madan FFT option pricing. Price entire strike spectrum at once via FFT of characteristic function. Alpha = damping ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cos_method",
        algorithm="cos_method",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcos_method\b",
            r"(?i)\bfang_oosterlee\b",
            r"(?i)\bcosine_expansion\b",
            r"(?i)\bfourier_cosine\b",
            r"(?i)\bcos_pricer\b",
            r"(?i)\btruncation_range\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="COS method (Fang-Oosterlee). Fourier-cosine series expansion for option pricing. Exponential convergence. Fast for Europ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lewis_option_pricing",
        algorithm="lewis_option_pricing",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\blewis\b",
            r"(?i)\blewis_formula\b",
            r"(?i)\bgeneralized_fourier\b",
            r"(?i)\blewis_pricing\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Lewis (2001) option pricing via generalized Fourier transform. Alternative to Carr-Madan. No damping parameter needed.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="finite_difference_explicit",
        algorithm="finite_difference_explicit",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bexplicit_fd\b",
            r"(?i)\bforward_euler\b",
            r"(?i)\bexplicit_scheme\b",
            r"(?i)\bstability_condition\b",
            r"(?i)\bcfl_condition\b",
            r"(?i)\bfd_grid\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Explicit finite difference for BSM PDE. Forward Euler in time. CFL stability condition on dt. Simple but requires small ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="finite_difference_implicit",
        algorithm="finite_difference_implicit",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bimplicit_fd\b",
            r"(?i)\bbackward_euler\b",
            r"(?i)\bimplicit_scheme\b",
            r"(?i)\blu_solve\b",
            r"(?i)\bunconditionally_stable\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Fully implicit finite difference. Backward Euler in time. Unconditionally stable. First-order time accuracy. Tridiagonal",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="psor_american_fd",
        algorithm="psor_american_fd",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bpsor\b",
            r"(?i)\bprojected_sor\b",
            r"(?i)\bfree_boundary\b",
            r"(?i)\bearly_exercise_fd\b",
            r"(?i)\bpenalty_method\b",
            r"(?i)\bamerican_fd\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Projected SOR for American options via FD. Linear complementarity problem. Over-relaxation parameter omega in (1,2). Alt",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="milstein_scheme",
        algorithm="milstein_scheme",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bmilstein\b",
            r"(?i)\bmilstein_scheme\b",
            r"(?i)\bstrong_order_1\b",
            r"(?i)\bsde_discretization\b",
            r"(?i)\bdiffusion_derivative\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Milstein SDE discretization. Strong order 1.0 (vs 0.5 for Euler). Requires derivative of diffusion coefficient. Better p",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="euler_maruyama",
        algorithm="euler_maruyama",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\beuler_maruyama\b",
            r"(?i)\beuler_scheme\b",
            r"(?i)\bsde_euler\b",
            r"(?i)\bweak_order_1\b",
            r"(?i)\bstrong_order_05\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Euler-Maruyama SDE discretization. Simplest scheme: strong order 0.5, weak order 1.0. Foundation of MC simulation in fin",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="qe_scheme_heston",
        algorithm="qe_scheme_heston",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bqe_scheme\b",
            r"(?i)\bquadratic_exponential\b",
            r"(?i)\bandersen\b",
            r"(?i)\bheston_discretization\b",
            r"(?i)\bpsi_critical\b",
            r"(?i)\bmoment_matching\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Andersen's QE (Quadratic-Exponential) scheme for Heston. Moment-matched discretization of variance process. Psi_c ~ 1.5.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="broadie_glasserman_kou",
        algorithm="broadie_glasserman_kou",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bbroadie_glasserman\b",
            r"(?i)\bdiscrete_barrier\b",
            r"(?i)\bbarrier_correction\b",
            r"(?i)\bcontinuity_correction\b",
            r"(?i)\bbeta_bgk\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Broadie-Glasserman-Kou continuity correction for discrete barrier options. Shifts barrier by beta*sigma*sqrt(dt). beta =",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="heston_semi_analytical",
        algorithm="heston_semi_analytical",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bheston_analytical\b",
            r"(?i)\bheston_cf\b",
            r"(?i)\bheston_integral\b",
            r"(?i)\bgauss_laguerre\b",
            r"(?i)\bcharacteristic_exponent\b",
            r"(?i)\bP1_P2\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Heston semi-analytical pricing via characteristic function integration. P1, P2 probabilities computed numerically (Gauss",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dv01",
        algorithm="dv01",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bdv01\b",
            r"(?i)\bpv01\b",
            r"(?i)\bbpv\b",
            r"(?i)\bbasis_point_value\b",
            r"(?i)\bdollar_duration\b",
            r"(?i)\bir01\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="DV01 / PV01 - Dollar value of one basis point. Price change for 1bp parallel shift in yield curve. Key fixed income risk",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="key_rate_duration",
        algorithm="key_rate_duration",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bkey_rate_duration\b",
            r"(?i)\bkrd\b",
            r"(?i)\bpartial_duration\b",
            r"(?i)\bbucket_risk\b",
            r"(?i)\btenor_sensitivity\b",
            r"(?i)\bkey_rate_risk\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Key rate duration. Sensitivity to individual tenor point shifts (not parallel). Decomposes DV01 across the curve. Risk b",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="monte_carlo_heston",
        algorithm="monte_carlo_heston",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bheston_mc\b",
            r"(?i)\bheston_simulation\b",
            r"(?i)\bheston_euler\b",
            r"(?i)\btruncated_euler\b",
            r"(?i)\bfull_truncation\b",
            r"(?i)\breflected_scheme\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Monte Carlo for Heston model. Discretize both spot and variance. Full truncation or reflection for variance positivity. ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mersenne_twister",
        algorithm="mersenne_twister",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bmersenne_twister\b",
            r"(?i)\bmt19937\b",
            r"(?i)\bmt_rng\b",
            r"(?i)\bgenrand\b",
            r"(?i)\binit_genrand\b",
            r"(?i)\btemper\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Mersenne Twister MT19937. Standard PRNG in finance. Period 2^19937-1. State array of 624 32-bit integers. Tempering for ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="interest_rate_cap_floor",
        algorithm="interest_rate_cap_floor",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcap\b",
            r"(?i)\bfloor\b",
            r"(?i)\bcaplet\b",
            r"(?i)\bfloorlet\b",
            r"(?i)\bcap_price\b",
            r"(?i)\bfloor_price\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Interest rate caps and floors. Sum of caplets/floorlets. Black-76 pricing per caplet. Flat vol vs spot vol. Cap-floor pa",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="digital_option",
        algorithm="digital_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bdigital\b",
            r"(?i)\bbinary\b",
            r"(?i)\bcash_or_nothing\b",
            r"(?i)\basset_or_nothing\b",
            r"(?i)\bdigital_price\b",
            r"(?i)\bheaviside\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Digital (binary) option. Cash-or-nothing pays fixed amount if ITM. Asset-or-nothing pays asset value. Hedging requires s",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="compound_option",
        algorithm="compound_option",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bcompound_option\b",
            r"(?i)\boption_on_option\b",
            r"(?i)\bgeske\b",
            r"(?i)\bbivariate_normal\b",
            r"(?i)\bN2\b",
            r"(?i)\bsplit_fee\b",
        ]),
        min_matches=2,
        confidence=0.83,
        bonus_per_extra=0.08,
        max_confidence=0.93,
        description="Compound option (option on option). Geske formula uses bivariate normal. Call-on-call, call-on-put, etc. Used in real op",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="variance_swap",
        algorithm="variance_swap",
        category="volatility",
        patterns=_compile([
            r"(?i)\bvariance_swap\b",
            r"(?i)\bvar_swap\b",
            r"(?i)\brealized_variance\b",
            r"(?i)\bfair_strike\b",
            r"(?i)\blog_contract\b",
            r"(?i)\bvix_replication\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Variance swap fair value. Replicates with strip of OTM options weighted by 1/K^2. Basis of VIX calculation. Convexity ad",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vix_calculation",
        algorithm="vix_calculation",
        category="volatility",
        patterns=_compile([
            r"(?i)\bvix\b",
            r"(?i)\bcboe_vix\b",
            r"(?i)\bfear_index\b",
            r"(?i)\bimplied_variance\b",
            r"(?i)\bvix_formula\b",
            r"(?i)\botm_options\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="CBOE VIX calculation. Model-free implied volatility from SPX options. 30-day target. OTM puts and calls weighted by 1/K^",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="holee_model",
        algorithm="holee_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bho_lee\b",
            r"(?i)\bholee\b",
            r"(?i)\bparallel_shift\b",
            r"(?i)\bho_lee_tree\b",
            r"(?i)\btheta_holee\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Ho-Lee short rate model. Simplest no-arbitrage model. Normal dynamics, rates can go negative. theta(t) fits initial yiel",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bdt_model",
        algorithm="bdt_model",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bbdt\b",
            r"(?i)\bblack_derman_toy\b",
            r"(?i)\bbdt_tree\b",
            r"(?i)\blognormal_tree\b",
            r"(?i)\bbdt_calibrate\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Black-Derman-Toy lognormal short rate model. Time-dependent vol and mean reversion. Calibrated via binomial tree to cap ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lognormal_forward_libor",
        algorithm="lognormal_forward_libor",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bforward_libor\b",
            r"(?i)\bcaplet_pricing\b",
            r"(?i)\bblack_caplet\b",
            r"(?i)\bforward_rate_vol\b",
            r"(?i)\blognormal_rate\b",
        ]),
        min_matches=2,
        confidence=0.89,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Lognormal forward LIBOR model for caplet pricing. Each forward rate follows GBM under its forward measure. Black formula",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="fx_garman_kohlhagen",
        algorithm="fx_garman_kohlhagen",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bgarman_kohlhagen\b",
            r"(?i)\bfx_option\b",
            r"(?i)\bcurrency_option\b",
            r"(?i)\bdomestic_rate\b",
            r"(?i)\bforeign_rate\b",
            r"(?i)\bfx_vol\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Garman-Kohlhagen FX option pricing. BSM adjusted for two interest rates (domestic/foreign). FX forward: F = S * exp((r_d",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="quanto_adjustment",
        algorithm="quanto_adjustment",
        category="option_pricing",
        patterns=_compile([
            r"(?i)\bquanto_adj\b",
            r"(?i)\bquanto_drift\b",
            r"(?i)\bfx_correlation\b",
            r"(?i)\bquanto_forward\b",
            r"(?i)\bcompo_option\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Quanto drift adjustment. Foreign asset drift reduced by rho*sigma_S*sigma_X under domestic measure. Appears in equity-FX",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="credit_triangle",
        algorithm="credit_triangle",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bcredit_triangle\b",
            r"(?i)\bhazard_approx\b",
            r"(?i)\bspread_lgd\b",
            r"(?i)\bdefault_intensity_approx\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Credit triangle approximation. CDS spread ~ hazard rate * (1 - recovery). Quick estimation. Exact for flat curves and co",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="transition_matrix",
        algorithm="transition_matrix",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\btransition_matrix\b",
            r"(?i)\brating_migration\b",
            r"(?i)\bgenerator_matrix\b",
            r"(?i)\bcredit_migration\b",
            r"(?i)\bmarkov_chain_credit\b",
            r"(?i)\bjarrow_lando_turnbull\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Credit rating transition matrix. Markov chain model of rating migrations. Generator matrix for continuous-time. Used in ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="delta_hedging",
        algorithm="delta_hedging",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bdelta_hedge\b",
            r"(?i)\bhedge_portfolio\b",
            r"(?i)\brebalance\b",
            r"(?i)\bhedge_frequency\b",
            r"(?i)\bpnl_explain\b",
            r"(?i)\bgamma_pnl\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Delta hedging. Maintain delta-neutral portfolio. P&L from gamma and theta: Theta + 0.5*Gamma*sigma^2*S^2*dt = 0 for BSM.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="marginal_var",
        algorithm="marginal_var",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bmarginal_var\b",
            r"(?i)\bcomponent_var\b",
            r"(?i)\bincremental_var\b",
            r"(?i)\bmvar\b",
            r"(?i)\bcvar_decomposition\b",
            r"(?i)\beuler_allocation\b",
        ]),
        min_matches=2,
        confidence=0.87,
        bonus_per_extra=0.08,
        max_confidence=0.97,
        description="Marginal and component VaR. Marginal: VaR sensitivity to position change. Component: Euler allocation, sums to total VaR",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="stress_testing_scenario",
        algorithm="stress_testing_scenario",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bstress_test\b",
            r"(?i)\bscenario_analysis\b",
            r"(?i)\btaylor_expand\b",
            r"(?i)\bstress_scenario\b",
            r"(?i)\bfactor_shock\b",
            r"(?i)\bhistorical_stress\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Stress testing via Taylor expansion or full revaluation. Historical scenarios (2008, COVID) or hypothetical. Regulatory ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="exponential_interpolation",
        algorithm="exponential_interpolation",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\blog_linear\b",
            r"(?i)\bexponential_interp\b",
            r"(?i)\bflat_forward\b",
            r"(?i)\bpiecewise_constant\b",
            r"(?i)\bstep_forward\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Log-linear (exponential) interpolation of discount factors. Equivalent to piecewise constant forward rates. Simplest yie",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="day_count_convention",
        algorithm="day_count_convention",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bday_count\b",
            r"(?i)\bact_360\b",
            r"(?i)\bact_365\b",
            r"(?i)\bthirty_360\b",
            r"(?i)\bact_act\b",
            r"(?i)\bdcf\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Day count conventions for accrual calculation. ACT/360 (money market), ACT/365 (UK), 30/360 (bonds), ACT/ACT (ISDA/ISMA)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="schedule_generation",
        algorithm="schedule_generation",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bschedule\b",
            r"(?i)\bdate_roll\b",
            r"(?i)\bbusiness_day\b",
            r"(?i)\bmodified_following\b",
            r"(?i)\bend_of_month\b",
            r"(?i)\bimm_dates\b",
        ]),
        min_matches=2,
        confidence=0.84,
        bonus_per_extra=0.08,
        max_confidence=0.94,
        description="Payment schedule generation. Business day conventions: Following, Modified Following, Preceding. End-of-month rule. Stub",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="normal_cdf_approximation",
        algorithm="normal_cdf_approximation",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bnorm_cdf\b",
            r"(?i)\bphi\b",
            r"(?i)\bcumulative_normal\b",
            r"(?i)\babramowitz_stegun\b",
            r"(?i)\bhart_approx\b",
            r"(?i)\berfc\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Normal CDF rational approximation (Abramowitz-Stegun). These specific constants are a strong fingerprint in decompiled c",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="normal_inverse_cdf",
        algorithm="normal_inverse_cdf",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bnorminv\b",
            r"(?i)\bprobit\b",
            r"(?i)\binverse_normal\b",
            r"(?i)\bquantile_normal\b",
            r"(?i)\bppf\b",
            r"(?i)\bbeasley_springer_moro\b",
        ]),
        min_matches=2,
        confidence=0.91,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Inverse normal CDF (probit). Beasley-Springer-Moro or Peter Acklam's rational approximation. Constants are distinctive s",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="feller_condition_check",
        algorithm="feller_condition_check",
        category="stochastic_model",
        patterns=_compile([
            r"(?i)\bfeller\b",
            r"(?i)\bfeller_condition\b",
            r"(?i)\bvariance_positivity\b",
            r"(?i)\b2kt_ge_xi2\b",
            r"(?i)\bvol_of_vol_bound\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Feller condition check for CIR/Heston variance processes. If violated, variance can hit zero. Reflected or truncated sch",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="girsanov_measure_change",
        algorithm="girsanov_measure_change",
        category="numerical_method",
        patterns=_compile([
            r"(?i)\bgirsanov\b",
            r"(?i)\bradon_nikodym\b",
            r"(?i)\bmeasure_change\b",
            r"(?i)\brisk_neutral\b",
            r"(?i)\bmarket_price_of_risk\b",
            r"(?i)\bchange_of_numeraire\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Girsanov theorem for measure change. P (real-world) to Q (risk-neutral). Radon-Nikodym derivative. Foundation of risk-ne",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mean_variance_hedge",
        algorithm="mean_variance_hedge",
        category="risk_measure",
        patterns=_compile([
            r"(?i)\bmv_hedge\b",
            r"(?i)\bminimum_variance_hedge\b",
            r"(?i)\bhedge_ratio\b",
            r"(?i)\bregression_hedge\b",
            r"(?i)\br_squared_hedge\b",
        ]),
        min_matches=2,
        confidence=0.83,
        bonus_per_extra=0.08,
        max_confidence=0.93,
        description="Minimum variance hedge ratio. Regression-based: delta = Cov(V,S)/Var(S). Used when perfect replication impossible (incom",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="xccy_basis_swap",
        algorithm="xccy_basis_swap",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bxccy\b",
            r"(?i)\bcross_currency\b",
            r"(?i)\bbasis_swap\b",
            r"(?i)\bfx_forward\b",
            r"(?i)\bxccy_basis\b",
            r"(?i)\bnotional_exchange\b",
        ]),
        min_matches=2,
        confidence=0.83,
        bonus_per_extra=0.08,
        max_confidence=0.93,
        description="Cross-currency basis swap. Exchange floating rates in two currencies. Basis spread reflects relative funding costs. Noti",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="fx_forward",
        algorithm="fx_forward",
        category="credit_fixed_income",
        patterns=_compile([
            r"(?i)\bfx_forward\b",
            r"(?i)\bforward_rate\b",
            r"(?i)\bcovered_interest_parity\b",
            r"(?i)\bcip\b",
            r"(?i)\bforward_points\b",
            r"(?i)\bndf\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="FX forward pricing via covered interest parity. F = S * P_domestic / P_foreign. Deviation = cross-currency basis. NDF fo",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="multi_curve_framework",
        algorithm="multi_curve_framework",
        category="yield_curve",
        patterns=_compile([
            r"(?i)\bmulti_curve\b",
            r"(?i)\bdual_curve\b",
            r"(?i)\btenor_basis\b",
            r"(?i)\b3m_6m_basis\b",
            r"(?i)\bprojection_curve\b",
            r"(?i)\bdiscounting_curve\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Multi-curve framework (post-crisis). Separate curves per tenor (1M, 3M, 6M LIBOR/SOFR) + OIS discounting. Tenor basis sp",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    # ========================================================================
    #  CRYPTOGRAPHY & SECURITY (v1.2.2)
    # ========================================================================

    StructuralPattern(
        name="aes_128",
        algorithm="aes_128",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\baes\b",
            r"(?i)\brijndael\b",
            r"(?i)\bSubBytes\b",
            r"(?i)\bShiftRows\b",
            r"(?i)\bMixColumns\b",
            r"(?i)\bAddRoundKey\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES-128 block cipher, 10 rounds, 128-bit key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_192",
        algorithm="aes_192",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\baes\b",
            r"(?i)\brijndael\b",
            r"(?i)\bNk=6\b",
            r"(?i)\bNr=12\b",
            r"(?i)\bAES_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES-192 block cipher, 12 rounds, 192-bit key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_256",
        algorithm="aes_256",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\baes\b",
            r"(?i)\brijndael\b",
            r"(?i)\bNk=8\b",
            r"(?i)\bNr=14\b",
            r"(?i)\bAES_encrypt\b",
            r"(?i)\bAES_256\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES-256 block cipher, 14 rounds, 256-bit key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_gcm",
        algorithm="aes_gcm",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bgcm\b",
            r"(?i)\bghash\b",
            r"(?i)\bgctr\b",
            r"(?i)\bgalois\b",
            r"(?i)\bgf_mul\b",
            r"(?i)\baad\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES in Galois/Counter Mode with authentication tag",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_ctr",
        algorithm="aes_ctr",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bctr\b",
            r"(?i)\bcounter\b",
            r"(?i)\bnonce\b",
            r"(?i)\bincrement\b",
            r"(?i)\bAES_ctr128_encrypt\b",
            r"(?i)\bCRYPTO_ctr128_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES in Counter mode",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_cbc",
        algorithm="aes_cbc",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bcbc\b",
            r"(?i)\biv\b",
            r"(?i)\bpadding\b",
            r"(?i)\bPKCS7\b",
            r"(?i)\bPKCS5\b",
            r"(?i)\bAES_cbc_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES in Cipher Block Chaining mode",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_xts",
        algorithm="aes_xts",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bxts\b",
            r"(?i)\btweak\b",
            r"(?i)\bgf_mulx\b",
            r"(?i)\bdisk_encrypt\b",
            r"(?i)\bsector\b",
            r"(?i)\bXTS_ENCRYPT\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES in XEX-based Tweaked-codebook mode with ciphertext Stealing",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chacha20",
        algorithm="chacha20",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bchacha\b",
            r"(?i)\bquarter_round\b",
            r"(?i)\bQR\b",
            r"(?i)\bexpand\ 32\-byte\ k\b",
            r"(?i)\bsigma\b",
            r"(?i)\bQUARTERROUND\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="ChaCha20 stream cipher, 20 rounds, 256-bit key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chacha20_poly1305",
        algorithm="chacha20_poly1305",
        category="aead",
        patterns=_compile([
            r"(?i)\bchacha20\b",
            r"(?i)\bpoly1305\b",
            r"(?i)\baead\b",
            r"(?i)\botk\b",
            r"(?i)\bone_time_key\b",
            r"(?i)\bcrypto_aead_chacha20poly1305\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="ChaCha20-Poly1305 AEAD construction (RFC 8439)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="des",
        algorithm="des",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bdes\b",
            r"(?i)\bfeistel\b",
            r"(?i)\bip_table\b",
            r"(?i)\bexpansion\b",
            r"(?i)\bpermutation\b",
            r"(?i)\bDES_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Data Encryption Standard, 16 Feistel rounds, 56-bit effective key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="triple_des",
        algorithm="triple_des",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\b3des\b",
            r"(?i)\btriple_des\b",
            r"(?i)\bede\b",
            r"(?i)\bDES_ede3\b",
            r"(?i)\btdes\b",
            r"(?i)\bDES_EDE\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Triple DES (3DES/TDES), encrypt-decrypt-encrypt with 2 or 3 keys",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="blowfish",
        algorithm="blowfish",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bblowfish\b",
            r"(?i)\bbf_encrypt\b",
            r"(?i)\bBF_set_key\b",
            r"(?i)\bp_array\b",
            r"(?i)\bsbox\b",
            r"(?i)\bfeistel\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Blowfish block cipher, 16 Feistel rounds, variable key up to 448 bits",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="twofish",
        algorithm="twofish",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\btwofish\b",
            r"(?i)\bmds\b",
            r"(?i)\bpht\b",
            r"(?i)\bq_permutation\b",
            r"(?i)\bh_function\b",
            r"(?i)\bkey_dependent_sbox\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Twofish block cipher, 16 Feistel rounds, 128/192/256-bit key",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="serpent",
        algorithm="serpent",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bserpent\b",
            r"(?i)\bsbox\b",
            r"(?i)\blinear_transform\b",
            r"(?i)\bgolden_ratio\b",
            r"(?i)\bserpent_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Serpent block cipher, 32 rounds, 128/192/256-bit key (AES finalist)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="camellia",
        algorithm="camellia",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bcamellia\b",
            r"(?i)\bfl_function\b",
            r"(?i)\bflinv\b",
            r"(?i)\bsigma\b",
            r"(?i)\bsp_box\b",
            r"(?i)\bCAMELLIA_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Camellia block cipher, 18/24 Feistel rounds, used in TLS and Japanese government",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aria",
        algorithm="aria",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\baria\b",
            r"(?i)\bsbox1\b",
            r"(?i)\bsbox2\b",
            r"(?i)\bdiffusion_layer\b",
            r"(?i)\bARIA_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="ARIA block cipher, Korean standard (NSRI), 12/14/16 rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sm4",
        algorithm="sm4",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bsm4\b",
            r"(?i)\bchinese\b",
            r"(?i)\bnational_standard\b",
            r"(?i)\btau_transform\b",
            r"(?i)\bL_transform\b",
            r"(?i)\bSM4_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SM4 (formerly SMS4), Chinese national block cipher standard, 32 rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rc4",
        algorithm="rc4",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\brc4\b",
            r"(?i)\barcfour\b",
            r"(?i)\bKSA\b",
            r"(?i)\bPRGA\b",
            r"(?i)\bkey_scheduling\b",
            r"(?i)\bRC4_set_key\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="RC4 (ARC4) stream cipher, variable key size",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rc5",
        algorithm="rc5",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\brc5\b",
            r"(?i)\bdata_dependent_rotation\b",
            r"(?i)\bmagic_constant\b",
            r"(?i)\bRC5_ENCRYPT\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="RC5 block cipher, data-dependent rotations, variable rounds/key/block",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rc6",
        algorithm="rc6",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\brc6\b",
            r"(?i)\bquadratic_function\b",
            r"(?i)\bmultiplication\b",
            r"(?i)\bRC6_ENCRYPT\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="RC6 block cipher, AES finalist, uses integer multiplication",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tea",
        algorithm="tea",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\btea\b",
            r"(?i)\btiny_encryption\b",
            r"(?i)\bdelta\b",
            r"(?i)\bTEA_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Tiny Encryption Algorithm, 64 rounds, 128-bit key, 64-bit block",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="xtea",
        algorithm="xtea",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bxtea\b",
            r"(?i)\bextended_tea\b",
            r"(?i)\bXTEA_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Extended TEA (XTEA), fixes TEA key schedule weakness",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cast5",
        algorithm="cast5",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bcast5\b",
            r"(?i)\bcast_128\b",
            r"(?i)\bCAST_encrypt\b",
            r"(?i)\bCAST_set_key\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="CAST-128 (CAST5) block cipher, 12 or 16 Feistel rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="idea",
        algorithm="idea",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bidea\b",
            r"(?i)\bmultiplication_mod\b",
            r"(?i)\b0x10001\b",
            r"(?i)\bIDEA_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="International Data Encryption Algorithm, 8.5 rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="salsa20",
        algorithm="salsa20",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bsalsa20\b",
            r"(?i)\bquarter_round\b",
            r"(?i)\bcolumnround\b",
            r"(?i)\browround\b",
            r"(?i)\bexpand\ 32\-byte\ k\b",
            r"(?i)\bexpand\ 16\-byte\ k\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Salsa20 stream cipher, 20 rounds, predecessor of ChaCha20",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gost_28147_89",
        algorithm="gost_28147_89",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bgost\b",
            r"(?i)\bmagma\b",
            r"(?i)\b28147\b",
            r"(?i)\brussian_cipher\b",
            r"(?i)\bGOST_encrypt\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="GOST 28147-89 (Magma) Russian block cipher, 32 Feistel rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kuznyechik",
        algorithm="kuznyechik",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bkuznyechik\b",
            r"(?i)\bgrasshopper\b",
            r"(?i)\b34_12_2015\b",
            r"(?i)\brussian\b",
            r"(?i)\bGOST_R_34_12\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Kuznyechik (GOST R 34.12-2015), modern Russian block cipher",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rsa_pkcs1_v15",
        algorithm="rsa_pkcs1_v15",
        category="asymmetric_encryption",
        patterns=_compile([
            r"(?i)\brsa\b",
            r"(?i)\bmodular_exponentiation\b",
            r"(?i)\bmontgomery\b",
            r"(?i)\bbignum\b",
            r"(?i)\bRSA_public_encrypt\b",
            r"(?i)\bRSA_private_decrypt\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="RSA with PKCS#1 v1.5 padding",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rsa_oaep",
        algorithm="rsa_oaep",
        category="asymmetric_encryption",
        patterns=_compile([
            r"(?i)\brsa\b",
            r"(?i)\boaep\b",
            r"(?i)\bmgf1\b",
            r"(?i)\bmask_generation\b",
            r"(?i)\bRSA_padding_add_PKCS1_OAEP\b",
            r"(?i)\blHash\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="RSA with Optimal Asymmetric Encryption Padding (OAEP)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="diffie_hellman",
        algorithm="diffie_hellman",
        category="key_exchange",
        patterns=_compile([
            r"(?i)\bdiffie_hellman\b",
            r"(?i)\bdh\b",
            r"(?i)\bgenerator\b",
            r"(?i)\bmodular_exponentiation\b",
            r"(?i)\bDH_generate_key\b",
            r"(?i)\bDH_compute_key\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Diffie-Hellman key exchange over finite field",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ecdh",
        algorithm="ecdh",
        category="key_exchange",
        patterns=_compile([
            r"(?i)\becdh\b",
            r"(?i)\belliptic_curve\b",
            r"(?i)\bscalar_multiplication\b",
            r"(?i)\bpoint_mul\b",
            r"(?i)\bEC_POINT_mul\b",
            r"(?i)\bECDH_compute_key\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Elliptic Curve Diffie-Hellman key exchange",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="elgamal",
        algorithm="elgamal",
        category="asymmetric_encryption",
        patterns=_compile([
            r"(?i)\belgamal\b",
            r"(?i)\bmodular_exponentiation\b",
            r"(?i)\brandom_k\b",
            r"(?i)\bshared_secret\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="ElGamal encryption scheme",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dsa",
        algorithm="dsa",
        category="digital_signature",
        patterns=_compile([
            r"(?i)\bdsa\b",
            r"(?i)\bdigital_signature\b",
            r"(?i)\bDSA_sign\b",
            r"(?i)\bDSA_verify\b",
            r"(?i)\bmodular_inverse\b",
            r"(?i)\bsubgroup_order\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Digital Signature Algorithm (DSA)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ecdsa",
        algorithm="ecdsa",
        category="digital_signature",
        patterns=_compile([
            r"(?i)\becdsa\b",
            r"(?i)\bECDSA_sign\b",
            r"(?i)\bECDSA_verify\b",
            r"(?i)\bsecp256r1\b",
            r"(?i)\bsecp256k1\b",
            r"(?i)\bP\-256\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Elliptic Curve Digital Signature Algorithm",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ed25519",
        algorithm="ed25519",
        category="digital_signature",
        patterns=_compile([
            r"(?i)\bed25519\b",
            r"(?i)\bEdDSA\b",
            r"(?i)\bcurve25519\b",
            r"(?i)\btwisted_edwards\b",
            r"(?i)\bbasepoint\b",
            r"(?i)\bcofactor_8\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Ed25519 signature scheme (EdDSA on Curve25519)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ed448",
        algorithm="ed448",
        category="digital_signature",
        patterns=_compile([
            r"(?i)\bed448\b",
            r"(?i)\bgoldilocks\b",
            r"(?i)\bcurve448\b",
            r"(?i)\bEdDSA\b",
            r"(?i)\bcofactor_4\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Ed448 signature scheme (EdDSA on Curve448-Goldilocks)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="x25519",
        algorithm="x25519",
        category="key_exchange",
        patterns=_compile([
            r"(?i)\bx25519\b",
            r"(?i)\bcurve25519\b",
            r"(?i)\bmontgomery_ladder\b",
            r"(?i)\bscalar_mult\b",
            r"(?i)\bX25519\b",
            r"(?i)\bcrypto_scalarmult\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="X25519 ECDH key exchange (Curve25519 Montgomery form)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sm2",
        algorithm="sm2",
        category="asymmetric_encryption",
        patterns=_compile([
            r"(?i)\bsm2\b",
            r"(?i)\bchinese_ecc\b",
            r"(?i)\bSM2_sign\b",
            r"(?i)\bSM2_verify\b",
            r"(?i)\bSM2_encrypt\b",
            r"(?i)\bsm2p256v1\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="SM2 Chinese national elliptic curve algorithm",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha1",
        algorithm="sha1",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha1\b",
            r"(?i)\bSHA1\b",
            r"(?i)\bSHA_1\b",
            r"(?i)\bCC_SHA1\b",
            r"(?i)\bsha1_update\b",
            r"(?i)\bsha1_final\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-1 hash function, 80 rounds, 160-bit digest (DEPRECATED)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha256",
        algorithm="sha256",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha256\b",
            r"(?i)\bSHA256\b",
            r"(?i)\bSHA_256\b",
            r"(?i)\bCC_SHA256\b",
            r"(?i)\bsha256_update\b",
            r"(?i)\bsha256_final\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-256 hash function, 64 rounds, 256-bit digest",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha384",
        algorithm="sha384",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha384\b",
            r"(?i)\bSHA384\b",
            r"(?i)\bSHA_384\b",
            r"(?i)\bCC_SHA384\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-384 hash function (SHA-512 with different IV, truncated output)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha512",
        algorithm="sha512",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha512\b",
            r"(?i)\bSHA512\b",
            r"(?i)\bSHA_512\b",
            r"(?i)\bCC_SHA512\b",
            r"(?i)\bsha512_update\b",
            r"(?i)\bsha512_final\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-512 hash function, 80 rounds, 512-bit digest",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha3_keccak",
        algorithm="sha3_keccak",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha3\b",
            r"(?i)\bkeccak\b",
            r"(?i)\bsponge\b",
            r"(?i)\babsorb\b",
            r"(?i)\bsqueeze\b",
            r"(?i)\btheta\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-3 (Keccak) sponge-based hash family, 24 rounds",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="md5",
        algorithm="md5",
        category="hash",
        patterns=_compile([
            r"(?i)\bmd5\b",
            r"(?i)\bMD5\b",
            r"(?i)\bMD5_Init\b",
            r"(?i)\bMD5_Update\b",
            r"(?i)\bMD5_Final\b",
            r"(?i)\bCC_MD5\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="MD5 hash function, 64 rounds, 128-bit digest (BROKEN)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="md4",
        algorithm="md4",
        category="hash",
        patterns=_compile([
            r"(?i)\bmd4\b",
            r"(?i)\bMD4\b",
            r"(?i)\bMD4_Init\b",
            r"(?i)\bMD4_Update\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="MD4 hash function, predecessor of MD5 (BROKEN)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="blake2b",
        algorithm="blake2b",
        category="hash",
        patterns=_compile([
            r"(?i)\bblake2b\b",
            r"(?i)\bBLAKE2b\b",
            r"(?i)\bblake2b_init\b",
            r"(?i)\bblake2b_update\b",
            r"(?i)\bblake2b_final\b",
            r"(?i)\bcrypto_generichash\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="BLAKE2b hash, up to 512-bit digest, optimized for 64-bit platforms",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="blake2s",
        algorithm="blake2s",
        category="hash",
        patterns=_compile([
            r"(?i)\bblake2s\b",
            r"(?i)\bBLAKE2s\b",
            r"(?i)\bblake2s_init\b",
            r"(?i)\bblake2s_update\b",
            r"(?i)\bblake2s_final\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="BLAKE2s hash, up to 256-bit digest, optimized for 32-bit platforms",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="blake3",
        algorithm="blake3",
        category="hash",
        patterns=_compile([
            r"(?i)\bblake3\b",
            r"(?i)\bBLAKE3\b",
            r"(?i)\bblake3_hasher\b",
            r"(?i)\bblake3_update\b",
            r"(?i)\bblake3_finalize\b",
            r"(?i)\bchunk\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="BLAKE3 hash, Merkle tree parallelizable, variable-length output",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ripemd160",
        algorithm="ripemd160",
        category="hash",
        patterns=_compile([
            r"(?i)\bripemd\b",
            r"(?i)\bripemd160\b",
            r"(?i)\bRIPEMD160\b",
            r"(?i)\bRIPEMD160_Init\b",
            r"(?i)\bRIPEMD160_Update\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="RIPEMD-160 hash, 160-bit, used in Bitcoin address generation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="whirlpool",
        algorithm="whirlpool",
        category="hash",
        patterns=_compile([
            r"(?i)\bwhirlpool\b",
            r"(?i)\bWHIRLPOOL\b",
            r"(?i)\bwhirlpool_init\b",
            r"(?i)\bC0_table\b",
            r"(?i)\bC1_table\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Whirlpool hash, 512-bit digest, AES-like internal structure",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sm3",
        algorithm="sm3",
        category="hash",
        patterns=_compile([
            r"(?i)\bsm3\b",
            r"(?i)\bSM3\b",
            r"(?i)\bchinese_hash\b",
            r"(?i)\bSM3_Init\b",
            r"(?i)\bSM3_Update\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SM3 Chinese national hash standard, 64 rounds, 256-bit",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="pbkdf2",
        algorithm="pbkdf2",
        category="kdf",
        patterns=_compile([
            r"(?i)\bpbkdf2\b",
            r"(?i)\bPBKDF2\b",
            r"(?i)\bPKCS5_PBKDF2_HMAC\b",
            r"(?i)\bCCKeyDerivationPBKDF\b",
            r"(?i)\biteration_count\b",
            r"(?i)\bsalt\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Password-Based Key Derivation Function 2",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bcrypt",
        algorithm="bcrypt",
        category="kdf",
        patterns=_compile([
            r"(?i)\bbcrypt\b",
            r"(?i)\beksblowfish\b",
            r"(?i)\bcost_factor\b",
            r"(?i)\bOrpheanBeholderScryDoubt\b",
            r"(?i)\bbcrypt_hashpw\b",
        ]),
        min_matches=2,
        confidence=0.93,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="bcrypt password hashing (Blowfish-based)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="scrypt",
        algorithm="scrypt",
        category="kdf",
        patterns=_compile([
            r"(?i)\bscrypt\b",
            r"(?i)\bBlockMix\b",
            r"(?i)\bROMix\b",
            r"(?i)\bSalsa20_8\b",
            r"(?i)\bmemory_hard\b",
            r"(?i)\bcrypto_pwhash_scryptsalsa208sha256\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="scrypt memory-hard password KDF",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="argon2",
        algorithm="argon2",
        category="kdf",
        patterns=_compile([
            r"(?i)\bargon2\b",
            r"(?i)\bargon2i\b",
            r"(?i)\bargon2d\b",
            r"(?i)\bargon2id\b",
            r"(?i)\bcrypto_pwhash\b",
            r"(?i)\bmemory_hard\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Argon2 memory-hard password hashing (PHC winner)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hkdf",
        algorithm="hkdf",
        category="kdf",
        patterns=_compile([
            r"(?i)\bhkdf\b",
            r"(?i)\bHKDF\b",
            r"(?i)\bhkdf_extract\b",
            r"(?i)\bhkdf_expand\b",
            r"(?i)\bHKDF_Extract\b",
            r"(?i)\bHKDF_Expand\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="HMAC-based Key Derivation Function (RFC 5869)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hmac",
        algorithm="hmac",
        category="mac",
        patterns=_compile([
            r"(?i)\bhmac\b",
            r"(?i)\bHMAC\b",
            r"(?i)\bHMAC_Init\b",
            r"(?i)\bHMAC_Update\b",
            r"(?i)\bHMAC_Final\b",
            r"(?i)\bCCHmac\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Hash-based Message Authentication Code",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cmac",
        algorithm="cmac",
        category="mac",
        patterns=_compile([
            r"(?i)\bcmac\b",
            r"(?i)\bCMAC\b",
            r"(?i)\bAES_CMAC\b",
            r"(?i)\bomac\b",
            r"(?i)\bsubkey_generation\b",
            r"(?i)\bdouble_block\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Cipher-based Message Authentication Code (AES-CMAC)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gmac",
        algorithm="gmac",
        category="mac",
        patterns=_compile([
            r"(?i)\bgmac\b",
            r"(?i)\bGMAC\b",
            r"(?i)\bghash\b",
            r"(?i)\bgalois_mac\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Galois Message Authentication Code (GCM without encryption)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="poly1305",
        algorithm="poly1305",
        category="mac",
        patterns=_compile([
            r"(?i)\bpoly1305\b",
            r"(?i)\bPoly1305\b",
            r"(?i)\bpoly1305_auth\b",
            r"(?i)\bclamp_r\b",
            r"(?i)\bcrypto_onetimeauth\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Poly1305 one-time authenticator",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="siphash",
        algorithm="siphash",
        category="mac",
        patterns=_compile([
            r"(?i)\bsiphash\b",
            r"(?i)\bSipHash\b",
            r"(?i)\bsiphash_2_4\b",
            r"(?i)\bsiphash_4_8\b",
            r"(?i)\bsipround\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SipHash-2-4 keyed hash (hash table DoS protection)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="crc32",
        algorithm="crc32",
        category="checksum",
        patterns=_compile([
            r"(?i)\bcrc32\b",
            r"(?i)\bCRC32\b",
            r"(?i)\bcrc_table\b",
            r"(?i)\bpolynomial\b",
            r"(?i)\bcrc32_update\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="CRC-32 cyclic redundancy check",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="crc16_ccitt",
        algorithm="crc16_ccitt",
        category="checksum",
        patterns=_compile([
            r"(?i)\bcrc16\b",
            r"(?i)\bccitt\b",
            r"(?i)\bCRC16\b",
            r"(?i)\bxmodem\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="CRC-16-CCITT checksum",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="adler32",
        algorithm="adler32",
        category="checksum",
        patterns=_compile([
            r"(?i)\badler32\b",
            r"(?i)\badler\b",
            r"(?i)\b65521\b",
            r"(?i)\bADLER32\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Adler-32 checksum (used in zlib)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tls12_handshake",
        algorithm="tls12_handshake",
        category="protocol",
        patterns=_compile([
            r"(?i)\btls\b",
            r"(?i)\bssl\b",
            r"(?i)\bhandshake\b",
            r"(?i)\bClientHello\b",
            r"(?i)\bServerHello\b",
            r"(?i)\bmaster_secret\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="TLS 1.2 handshake protocol",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tls13_handshake",
        algorithm="tls13_handshake",
        category="protocol",
        patterns=_compile([
            r"(?i)\btls13\b",
            r"(?i)\btls_1_3\b",
            r"(?i)\bkey_share\b",
            r"(?i)\bpsk\b",
            r"(?i)\bearly_data\b",
            r"(?i)\b0\-RTT\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="TLS 1.3 handshake protocol (RFC 8446)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="x509_certificate",
        algorithm="x509_certificate",
        category="pki",
        patterns=_compile([
            r"(?i)\bx509\b",
            r"(?i)\bcertificate\b",
            r"(?i)\bissuer\b",
            r"(?i)\bsubject\b",
            r"(?i)\bvalidity\b",
            r"(?i)\bpublic_key\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="X.509 certificate parsing and validation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="asn1_der",
        algorithm="asn1_der",
        category="pki",
        patterns=_compile([
            r"(?i)\basn1\b",
            r"(?i)\bder\b",
            r"(?i)\bber\b",
            r"(?i)\btlv\b",
            r"(?i)\bSEQUENCE\b",
            r"(?i)\bINTEGER\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="ASN.1 DER/BER encoding format",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="jwt",
        algorithm="jwt",
        category="protocol",
        patterns=_compile([
            r"(?i)\bjwt\b",
            r"(?i)\bJSON_Web_Token\b",
            r"(?i)\bheader\b",
            r"(?i)\bpayload\b",
            r"(?i)\bsignature\b",
            r"(?i)\bHS256\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="JSON Web Token (RFC 7519)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="oauth2",
        algorithm="oauth2",
        category="protocol",
        patterns=_compile([
            r"(?i)\boauth\b",
            r"(?i)\bauthorization_code\b",
            r"(?i)\baccess_token\b",
            r"(?i)\brefresh_token\b",
            r"(?i)\bclient_id\b",
            r"(?i)\bclient_secret\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="OAuth 2.0 authorization framework",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kerberos",
        algorithm="kerberos",
        category="protocol",
        patterns=_compile([
            r"(?i)\bkerberos\b",
            r"(?i)\bkrb5\b",
            r"(?i)\bTGT\b",
            r"(?i)\bTGS\b",
            r"(?i)\bAS_REQ\b",
            r"(?i)\bAS_REP\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Kerberos v5 authentication protocol",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ipsec_esp",
        algorithm="ipsec_esp",
        category="network_security",
        patterns=_compile([
            r"(?i)\bipsec\b",
            r"(?i)\besp\b",
            r"(?i)\bspi\b",
            r"(?i)\bsecurity_association\b",
            r"(?i)\bIKE\b",
            r"(?i)\bencapsulating_security_payload\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="IPsec Encapsulating Security Payload",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ipsec_ah",
        algorithm="ipsec_ah",
        category="network_security",
        patterns=_compile([
            r"(?i)\bipsec\b",
            r"(?i)\bah\b",
            r"(?i)\bauthentication_header\b",
            r"(?i)\bintegrity_check_value\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="IPsec Authentication Header",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ikev2",
        algorithm="ikev2",
        category="network_security",
        patterns=_compile([
            r"(?i)\bikev2\b",
            r"(?i)\bike\b",
            r"(?i)\bisakmp\b",
            r"(?i)\bINIT\b",
            r"(?i)\bAUTH\b",
            r"(?i)\bCHILD_SA\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="IKEv2 key exchange for IPsec",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="wireguard_noise",
        algorithm="wireguard_noise",
        category="network_security",
        patterns=_compile([
            r"(?i)\bwireguard\b",
            r"(?i)\bnoise\b",
            r"(?i)\bNoise_IKpsk2\b",
            r"(?i)\bhandshake_init\b",
            r"(?i)\bhandshake_response\b",
            r"(?i)\bwg_peer\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="WireGuard VPN (Noise IKpsk2 protocol)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ssh_key_exchange",
        algorithm="ssh_key_exchange",
        category="network_security",
        patterns=_compile([
            r"(?i)\bssh\b",
            r"(?i)\bkey_exchange\b",
            r"(?i)\bkex\b",
            r"(?i)\bcurve25519\-sha256\b",
            r"(?i)\bdiffie\-hellman\-group14\-sha256\b",
            r"(?i)\bSSH_MSG_KEXINIT\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="SSH key exchange protocol",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="stack_canary",
        algorithm="stack_canary",
        category="binary_security",
        patterns=_compile([
            r"(?i)\b__stack_chk_fail\b",
            r"(?i)\b__stack_chk_guard\b",
            r"(?i)\bstack_canary\b",
            r"(?i)\bstack_protector\b",
            r"(?i)\bstack_smashing\b",
            r"(?i)\bGS_cookie\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Stack canary / stack smashing protection",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aslr_detection",
        algorithm="aslr_detection",
        category="binary_security",
        patterns=_compile([
            r"(?i)\baslr\b",
            r"(?i)\bPIE\b",
            r"(?i)\bposition_independent\b",
            r"(?i)\bmmap\b",
            r"(?i)\brandomize_va_space\b",
            r"(?i)\b_dyld_get_image_vmaddr_slide\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Address Space Layout Randomization detection",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cfi_check",
        algorithm="cfi_check",
        category="binary_security",
        patterns=_compile([
            r"(?i)\bcfi\b",
            r"(?i)\bcontrol_flow_integrity\b",
            r"(?i)\b__cfi_check\b",
            r"(?i)\b__cfi_slowpath\b",
            r"(?i)\bindirect_call_check\b",
            r"(?i)\btype_id\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Control Flow Integrity checks",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="shadow_stack",
        algorithm="shadow_stack",
        category="binary_security",
        patterns=_compile([
            r"(?i)\bshadow_stack\b",
            r"(?i)\bCET\b",
            r"(?i)\bENDBRANCH\b",
            r"(?i)\bENDBR64\b",
            r"(?i)\bENDBR32\b",
            r"(?i)\bret_protection\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Hardware shadow stack (Intel CET)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="code_signing",
        algorithm="code_signing",
        category="binary_security",
        patterns=_compile([
            r"(?i)\bcodesign\b",
            r"(?i)\bcode_signature\b",
            r"(?i)\bSecCodeCheckValidity\b",
            r"(?i)\bCSCopySigningInformation\b",
            r"(?i)\bLC_CODE_SIGNATURE\b",
            r"(?i)\bCDHash\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Code signing verification (macOS/iOS)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="anti_debug_ptrace",
        algorithm="anti_debug_ptrace",
        category="anti_analysis",
        patterns=_compile([
            r"(?i)\bptrace\b",
            r"(?i)\bPTRACE_TRACEME\b",
            r"(?i)\bPT_DENY_ATTACH\b",
            r"(?i)\bsysctl\b",
            r"(?i)\bP_TRACED\b",
            r"(?i)\banti_debug\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Anti-debugging via ptrace",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="anti_debug_sysctl",
        algorithm="anti_debug_sysctl",
        category="anti_analysis",
        patterns=_compile([
            r"(?i)\bsysctl\b",
            r"(?i)\bCTL_KERN\b",
            r"(?i)\bKERN_PROC\b",
            r"(?i)\bKERN_PROC_PID\b",
            r"(?i)\bkp_proc\b",
            r"(?i)\bp_flag\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Anti-debugging via sysctl process flags",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vm_detection_cpuid",
        algorithm="vm_detection_cpuid",
        category="anti_analysis",
        patterns=_compile([
            r"(?i)\bcpuid\b",
            r"(?i)\bhypervisor\b",
            r"(?i)\bvmware\b",
            r"(?i)\bvirtualbox\b",
            r"(?i)\bCPUID_leaf\b",
            r"(?i)\bvm_detect\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Virtual machine detection via CPUID",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vm_detection_timing",
        algorithm="vm_detection_timing",
        category="anti_analysis",
        patterns=_compile([
            r"(?i)\brdtsc\b",
            r"(?i)\btiming_check\b",
            r"(?i)\brdtscp\b",
            r"(?i)\bclock_gettime\b",
            r"(?i)\bgettimeofday\b",
            r"(?i)\bmach_absolute_time\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="VM/debugger detection via timing side channels",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="control_flow_flattening",
        algorithm="control_flow_flattening",
        category="obfuscation",
        patterns=_compile([
            r"(?i)\bdispatcher\b",
            r"(?i)\bstate_variable\b",
            r"(?i)\bswitch\b",
            r"(?i)\bflatten\b",
            r"(?i)\bbogus_branch\b",
            r"(?i)\bOLLVM\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Control flow flattening obfuscation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="opaque_predicate",
        algorithm="opaque_predicate",
        category="obfuscation",
        patterns=_compile([
            r"(?i)\bopaque_predicate\b",
            r"(?i)\bdead_code\b",
            r"(?i)\bbogus_condition\b",
            r"(?i)\bunreachable\b",
        ]),
        min_matches=2,
        confidence=0.65,
        bonus_per_extra=0.08,
        max_confidence=0.75,
        description="Opaque predicate obfuscation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="string_encryption",
        algorithm="string_encryption",
        category="obfuscation",
        patterns=_compile([
            r"(?i)\bstring_decrypt\b",
            r"(?i)\bdecrypt_string\b",
            r"(?i)\bxor_decode\b",
            r"(?i)\bdeobfuscate\b",
            r"(?i)\bstring_table\b",
            r"(?i)\bencrypted_strings\b",
        ]),
        min_matches=2,
        confidence=0.70,
        bonus_per_extra=0.08,
        max_confidence=0.80,
        description="String encryption/obfuscation patterns",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="base64",
        algorithm="base64",
        category="encoding",
        patterns=_compile([
            r"(?i)\bbase64\b",
            r"(?i)\bb64encode\b",
            r"(?i)\bb64decode\b",
            r"(?i)\bBase64\b",
            r"(?i)\bABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Base64 encoding/decoding",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_ni",
        algorithm="aes_ni",
        category="hardware_crypto",
        patterns=_compile([
            r"(?i)\bAESENC\b",
            r"(?i)\bAESDEC\b",
            r"(?i)\bAESENCLAST\b",
            r"(?i)\bAESDECLAST\b",
            r"(?i)\bAESKEYGENASSIST\b",
            r"(?i)\bAESIMC\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES-NI hardware instructions",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="clmul",
        algorithm="clmul",
        category="hardware_crypto",
        patterns=_compile([
            r"(?i)\bPCLMULQDQ\b",
            r"(?i)\bCLMUL\b",
            r"(?i)\bcarry_less_mul\b",
            r"(?i)\b_mm_clmulepi64_si128\b",
            r"(?i)\bghash_clmul\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Carry-less multiplication (CLMUL) for GF(2^n)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha_ni",
        algorithm="sha_ni",
        category="hardware_crypto",
        patterns=_compile([
            r"(?i)\bSHA1RNDS4\b",
            r"(?i)\bSHA1NEXTE\b",
            r"(?i)\bSHA1MSG1\b",
            r"(?i)\bSHA1MSG2\b",
            r"(?i)\bSHA256RNDS2\b",
            r"(?i)\bSHA256MSG1\b",
        ]),
        min_matches=2,
        confidence=0.98,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-NI hardware instructions for SHA-1/SHA-256",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="arm_crypto_ext",
        algorithm="arm_crypto_ext",
        category="hardware_crypto",
        patterns=_compile([
            r"(?i)\bAESE\b",
            r"(?i)\bAESD\b",
            r"(?i)\bAESMC\b",
            r"(?i)\bAESIMC\b",
            r"(?i)\bSHA1C\b",
            r"(?i)\bSHA1M\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="ARM Cryptography Extensions (AES, SHA, PMULL)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="zlib_deflate",
        algorithm="zlib_deflate",
        category="compression",
        patterns=_compile([
            r"(?i)\bdeflate\b",
            r"(?i)\binflate\b",
            r"(?i)\bz_stream\b",
            r"(?i)\bdeflateInit\b",
            r"(?i)\binflateInit\b",
            r"(?i)\bcompress2\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="zlib/deflate compression",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lzma",
        algorithm="lzma",
        category="compression",
        patterns=_compile([
            r"(?i)\blzma\b",
            r"(?i)\bLZMA\b",
            r"(?i)\blzma_decode\b",
            r"(?i)\blzma2\b",
            r"(?i)\bxz\b",
            r"(?i)\b7z\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="LZMA/LZMA2/XZ compression",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="curve25519_field_ops",
        algorithm="curve25519_field_ops",
        category="elliptic_curve",
        patterns=_compile([
            r"(?i)\bfe25519\b",
            r"(?i)\bfe_mul\b",
            r"(?i)\bfe_sq\b",
            r"(?i)\bfe_invert\b",
            r"(?i)\bfe_pow22523\b",
            r"(?i)\breduce\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Curve25519 field arithmetic primitives",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="secp256k1",
        algorithm="secp256k1",
        category="elliptic_curve",
        patterns=_compile([
            r"(?i)\bsecp256k1\b",
            r"(?i)\bbitcoin\b",
            r"(?i)\becdsa\b",
            r"(?i)\bscalar_mul\b",
            r"(?i)\bpoint_add\b",
            r"(?i)\bpoint_double\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="secp256k1 elliptic curve (Bitcoin)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="secp256r1_p256",
        algorithm="secp256r1_p256",
        category="elliptic_curve",
        patterns=_compile([
            r"(?i)\bsecp256r1\b",
            r"(?i)\bP\-256\b",
            r"(?i)\bprime256v1\b",
            r"(?i)\bNIST_P256\b",
            r"(?i)\bEC_GROUP_new_by_curve_name\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="NIST P-256 (secp256r1/prime256v1) elliptic curve",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="secp384r1_p384",
        algorithm="secp384r1_p384",
        category="elliptic_curve",
        patterns=_compile([
            r"(?i)\bsecp384r1\b",
            r"(?i)\bP\-384\b",
            r"(?i)\bNIST_P384\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="NIST P-384 (secp384r1) elliptic curve",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="montgomery_multiplication",
        algorithm="montgomery_multiplication",
        category="bignum_arithmetic",
        patterns=_compile([
            r"(?i)\bmontgomery\b",
            r"(?i)\bmont_mul\b",
            r"(?i)\bmont_reduce\b",
            r"(?i)\bBN_mod_mul_montgomery\b",
            r"(?i)\bMONT_CTX\b",
            r"(?i)\bn_prime\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Montgomery modular multiplication",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chinese_remainder_theorem",
        algorithm="chinese_remainder_theorem",
        category="bignum_arithmetic",
        patterns=_compile([
            r"(?i)\bcrt\b",
            r"(?i)\bchinese_remainder\b",
            r"(?i)\bRSA_CRT\b",
            r"(?i)\bdP\b",
            r"(?i)\bdQ\b",
            r"(?i)\bqInv\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Chinese Remainder Theorem (RSA-CRT optimization)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="fortuna_csprng",
        algorithm="fortuna_csprng",
        category="random",
        patterns=_compile([
            r"(?i)\bfortuna\b",
            r"(?i)\bcsprng\b",
            r"(?i)\brandom_pool\b",
            r"(?i)\breseed\b",
            r"(?i)\bgenerator_gate\b",
            r"(?i)\baccumulator\b",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.08,
        max_confidence=0.82,
        description="Fortuna CSPRNG (Apple/FreeBSD random)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chacha20_csprng",
        algorithm="chacha20_csprng",
        category="random",
        patterns=_compile([
            r"(?i)\bchacha20_rng\b",
            r"(?i)\barc4random\b",
            r"(?i)\bgetrandom\b",
            r"(?i)\bgetentropy\b",
            r"(?i)\bSecRandomCopyBytes\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="ChaCha20-based CSPRNG",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="xorshift",
        algorithm="xorshift",
        category="random",
        patterns=_compile([
            r"(?i)\bxorshift\b",
            r"(?i)\bxorshift128\b",
            r"(?i)\bxorshift128\+\b",
            r"(?i)\bxoshiro\b",
            r"(?i)\bsplitmix64\b",
            r"(?i)\bPRNG\b",
        ]),
        min_matches=2,
        confidence=0.70,
        bonus_per_extra=0.08,
        max_confidence=0.80,
        description="XorShift family PRNG (NOT cryptographic)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="upx_packer",
        algorithm="upx_packer",
        category="packer",
        patterns=_compile([
            r"(?i)\bUPX\b",
            r"(?i)\bUPX!\b",
            r"(?i)\bupx_decompress\b",
            r"(?i)\bNRV\b",
            r"(?i)\bLZMA\b",
            r"(?i)\bstub\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="UPX packer detection",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vmprotect",
        algorithm="vmprotect",
        category="packer",
        patterns=_compile([
            r"(?i)\bvmprotect\b",
            r"(?i)\bvmp\b",
            r"(?i)\bVMProtect\b",
            r"(?i)\b\.vmp0\b",
            r"(?i)\b\.vmp1\b",
            r"(?i)\bvm_entry\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="VMProtect commercial protector",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="themida",
        algorithm="themida",
        category="packer",
        patterns=_compile([
            r"(?i)\bthemida\b",
            r"(?i)\bwinlicense\b",
            r"(?i)\boreans\b",
            r"(?i)\bSecureEngine\b",
            r"(?i)\bvm_protect\b",
            r"(?i)\bcode_virtualization\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Themida/WinLicense protector",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="saml",
        algorithm="saml",
        category="protocol",
        patterns=_compile([
            r"(?i)\bsaml\b",
            r"(?i)\bSAML\b",
            r"(?i)\bassertion\b",
            r"(?i)\bSAMLRequest\b",
            r"(?i)\bSAMLResponse\b",
            r"(?i)\bNameID\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="SAML 2.0 authentication protocol",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ocsp",
        algorithm="ocsp",
        category="pki",
        patterns=_compile([
            r"(?i)\bocsp\b",
            r"(?i)\bOCSP\b",
            r"(?i)\bOCSPRequest\b",
            r"(?i)\bOCSPResponse\b",
            r"(?i)\bBasicOCSPResponse\b",
            r"(?i)\bcertStatus\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="OCSP (Online Certificate Status Protocol)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="crl",
        algorithm="crl",
        category="pki",
        patterns=_compile([
            r"(?i)\bcrl\b",
            r"(?i)\bCRL\b",
            r"(?i)\bcertificate_revocation\b",
            r"(?i)\bX509_CRL\b",
            r"(?i)\brevokedCertificates\b",
            r"(?i)\bcrlNumber\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Certificate Revocation List",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha512_256",
        algorithm="sha512_256",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha512_256\b",
            r"(?i)\bSHA512_256\b",
            r"(?i)\bsha512t\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="SHA-512/256 hash (SHA-512 with different IV, truncated)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="streebog",
        algorithm="streebog",
        category="hash",
        patterns=_compile([
            r"(?i)\bstreebog\b",
            r"(?i)\bGOST_34_11\b",
            r"(?i)\bgost2012\b",
            r"(?i)\bstribog\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Streebog (GOST R 34.11-2012) Russian hash standard",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="shake128",
        algorithm="shake128",
        category="hash",
        patterns=_compile([
            r"(?i)\bshake128\b",
            r"(?i)\bSHAKE128\b",
            r"(?i)\bxof\b",
            r"(?i)\bextendable_output\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="SHAKE128 extendable output function (SHA-3 family)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="shake256",
        algorithm="shake256",
        category="hash",
        patterns=_compile([
            r"(?i)\bshake256\b",
            r"(?i)\bSHAKE256\b",
            r"(?i)\bxof\b",
            r"(?i)\bextendable_output\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="SHAKE256 extendable output function (SHA-3 family)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="xchacha20_poly1305",
        algorithm="xchacha20_poly1305",
        category="aead",
        patterns=_compile([
            r"(?i)\bxchacha20\b",
            r"(?i)\bhchacha20\b",
            r"(?i)\bextended_nonce\b",
            r"(?i)\bcrypto_aead_xchacha20poly1305\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="XChaCha20-Poly1305 AEAD with extended nonce",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_siv",
        algorithm="aes_siv",
        category="aead",
        patterns=_compile([
            r"(?i)\bsiv\b",
            r"(?i)\bS2V\b",
            r"(?i)\bAES_SIV\b",
            r"(?i)\bdeterministic_aead\b",
            r"(?i)\bsynthetic_iv\b",
            r"(?i)\bcmac_chain\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="AES-SIV nonce-misuse resistant AEAD (RFC 5297)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_ccm",
        algorithm="aes_ccm",
        category="aead",
        patterns=_compile([
            r"(?i)\bccm\b",
            r"(?i)\bAES_CCM\b",
            r"(?i)\bCBC_MAC\b",
            r"(?i)\bcounter_mode\b",
            r"(?i)\badata\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="AES-CCM authenticated encryption",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aegis",
        algorithm="aegis",
        category="aead",
        patterns=_compile([
            r"(?i)\baegis\b",
            r"(?i)\bAEGIS_128L\b",
            r"(?i)\bAEGIS_256\b",
            r"(?i)\baes_round\b",
            r"(?i)\bstate_update\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="AEGIS AEAD (AES-based, very fast)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ghash",
        algorithm="ghash",
        category="mac",
        patterns=_compile([
            r"(?i)\bghash\b",
            r"(?i)\bGHASH\b",
            r"(?i)\bgf128_mul\b",
            r"(?i)\bgalois_multiply\b",
            r"(?i)\bgcm_ghash\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="GHASH universal hash function (used in GCM)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chacha20_ietf",
        algorithm="chacha20_ietf",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bchacha20_ietf\b",
            r"(?i)\b96_bit_nonce\b",
            r"(?i)\b32_bit_counter\b",
            r"(?i)\bIETF_ChaCha20\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="ChaCha20-IETF with 96-bit nonce (RFC 8439)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_ecb",
        algorithm="aes_ecb",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\becb\b",
            r"(?i)\bAES_ecb_encrypt\b",
            r"(?i)\bECB_ENCRYPT\b",
            r"(?i)\bno_iv\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="AES in Electronic Codebook mode (INSECURE)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_cfb",
        algorithm="aes_cfb",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bcfb\b",
            r"(?i)\bAES_cfb_encrypt\b",
            r"(?i)\bCFB_ENCRYPT\b",
            r"(?i)\bfeedback\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="AES in Cipher Feedback mode",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_ofb",
        algorithm="aes_ofb",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bofb\b",
            r"(?i)\bAES_ofb_encrypt\b",
            r"(?i)\bOFB_ENCRYPT\b",
            r"(?i)\boutput_feedback\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="AES in Output Feedback mode",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_key_wrap",
        algorithm="aes_key_wrap",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bkey_wrap\b",
            r"(?i)\bAES_wrap_key\b",
            r"(?i)\bAES_unwrap_key\b",
            r"(?i)\bRFC3394\b",
            r"(?i)\bdefault_iv\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="AES Key Wrap (RFC 3394)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rijndael_sbox_full",
        algorithm="rijndael_sbox_full",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bsbox\b",
            r"(?i)\bS_box\b",
            r"(?i)\bSubBytes\b",
            r"(?i)\brijndael\b",
            r"(?i)\baffine_transform\b",
            r"(?i)\bgf256_inv\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES/Rijndael S-box (full 256-byte lookup table)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="des_sbox_full",
        algorithm="des_sbox_full",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bdes_sbox\b",
            r"(?i)\bDES_sbox\b",
            r"(?i)\bS1\b",
            r"(?i)\bS2\b",
            r"(?i)\bS3\b",
            r"(?i)\bS4\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="DES S-box tables (8 boxes, each 4x16)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rsa_key_generation",
        algorithm="rsa_key_generation",
        category="asymmetric_encryption",
        patterns=_compile([
            r"(?i)\bRSA_generate_key\b",
            r"(?i)\bBN_generate_prime\b",
            r"(?i)\bprimality_test\b",
            r"(?i)\bmiller_rabin\b",
            r"(?i)\bBN_is_prime\b",
            r"(?i)\bgenprime\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="RSA key pair generation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="des_key_schedule",
        algorithm="des_key_schedule",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bdes_key_schedule\b",
            r"(?i)\bPC1\b",
            r"(?i)\bPC2\b",
            r"(?i)\bkey_rotation\b",
            r"(?i)\bDES_set_key_checked\b",
        ]),
        min_matches=2,
        confidence=0.92,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="DES key schedule (PC-1, PC-2, rotations)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="aes_rcon",
        algorithm="aes_rcon",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\brcon\b",
            r"(?i)\bround_constant\b",
            r"(?i)\bkey_expansion\b",
            r"(?i)\bAES_Rcon\b",
        ]),
        min_matches=2,
        confidence=0.95,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="AES round constants (Rcon) for key expansion",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha256_k_constants",
        algorithm="sha256_k_constants",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha256_K\b",
            r"(?i)\bround_constants\b",
            r"(?i)\bcube_root_primes\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-256 round constants K[0..63]",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="md5_t_table",
        algorithm="md5_t_table",
        category="hash",
        patterns=_compile([
            r"(?i)\bmd5_T\b",
            r"(?i)\bsine_table\b",
            r"(?i)\bmd5_round_constants\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="MD5 sine-derived round constants T[1..64]",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="blowfish_p_array_full",
        algorithm="blowfish_p_array_full",
        category="symmetric_encryption",
        patterns=_compile([
            r"(?i)\bblowfish_p\b",
            r"(?i)\bP_array\b",
            r"(?i)\bpi_hex\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Blowfish P-array (18 subkeys from pi)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="keccak_round_constants_full",
        algorithm="keccak_round_constants_full",
        category="hash",
        patterns=_compile([
            r"(?i)\bkeccak_RC\b",
            r"(?i)\biota_constants\b",
            r"(?i)\bround_constants_keccak\b",
        ]),
        min_matches=2,
        confidence=0.99,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Keccak/SHA-3 all 24 round constants",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sha1_k_constants",
        algorithm="sha1_k_constants",
        category="hash",
        patterns=_compile([
            r"(?i)\bsha1_K\b",
            r"(?i)\bsha1_round_constants\b",
        ]),
        min_matches=2,
        confidence=0.97,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="SHA-1 round constants K[0..3]",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tls_prf",
        algorithm="tls_prf",
        category="protocol",
        patterns=_compile([
            r"(?i)\btls_prf\b",
            r"(?i)\bPRF\b",
            r"(?i)\bP_hash\b",
            r"(?i)\bmaster_secret\b",
            r"(?i)\bkey_expansion\b",
            r"(?i)\bclient_finished\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="TLS pseudo-random function",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="noise_protocol",
        algorithm="noise_protocol",
        category="protocol",
        patterns=_compile([
            r"(?i)\bnoise\b",
            r"(?i)\bNoise_IK\b",
            r"(?i)\bNoise_XX\b",
            r"(?i)\bNoise_NK\b",
            r"(?i)\bhandshake_state\b",
            r"(?i)\bsymmetric_state\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Noise Protocol Framework (used in WireGuard, Signal, etc.)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="signal_protocol",
        algorithm="signal_protocol",
        category="protocol",
        patterns=_compile([
            r"(?i)\bsignal\b",
            r"(?i)\bx3dh\b",
            r"(?i)\bdouble_ratchet\b",
            r"(?i)\bprekey\b",
            r"(?i)\bidentity_key\b",
            r"(?i)\bratchet_step\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Signal Protocol (X3DH + Double Ratchet)",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mte_arm",
        algorithm="mte_arm",
        category="binary_security",
        patterns=_compile([
            r"(?i)\bMTE\b",
            r"(?i)\bmemory_tagging\b",
            r"(?i)\bIRG\b",
            r"(?i)\bADDG\b",
            r"(?i)\bSUBG\b",
            r"(?i)\bSTG\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="ARM Memory Tagging Extension",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dilithium",
        algorithm="dilithium",
        category="post_quantum",
        patterns=_compile([
            r"(?i)\bdilithium\b",
            r"(?i)\bCRYSTALS\b",
            r"(?i)\bML\-DSA\b",
            r"(?i)\blattice\b",
            r"(?i)\bNTT\b",
            r"(?i)\bpqcrystals\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="CRYSTALS-Dilithium / ML-DSA post-quantum signature",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kyber",
        algorithm="kyber",
        category="post_quantum",
        patterns=_compile([
            r"(?i)\bkyber\b",
            r"(?i)\bCRYSTALS\b",
            r"(?i)\bML\-KEM\b",
            r"(?i)\blattice\b",
            r"(?i)\bNTT\b",
            r"(?i)\bpqcrystals\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="CRYSTALS-Kyber / ML-KEM post-quantum key encapsulation",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    # ========================================================================
    #  ADVANCED ENGINEERING (v1.2.2)
    # ========================================================================

    StructuralPattern(
        name="vof_volume_of_fluid",
        algorithm="vof_volume_of_fluid",
        category="cfd_multiphase",
        patterns=_compile([
            r"(?i)\bvof\b",
            r"(?i)\bvolume\ of\ fluid\b",
            r"(?i)\bfree\ surface\b",
            r"(?i)\bmultiphase\b",
            r"(?i)\binterface\b",
            r"(?i)\balpha\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Volume of Fluid method for tracking free surfaces and interfaces in multiphase flows. Alpha=1 for fluid 1, alpha=0 for f",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="level_set_method",
        algorithm="level_set_method",
        category="cfd_multiphase",
        patterns=_compile([
            r"(?i)\blevel\ set\b",
            r"(?i)\bsigned\ distance\b",
            r"(?i)\binterface\ tracking\b",
            r"(?i)\breinitialization\b",
            r"(?i)\bheaviside\b",
            r"(?i)\bphi\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Level set method for interface tracking. Phi is a signed distance function; zero level set defines the interface.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lattice_boltzmann",
        algorithm="lattice_boltzmann",
        category="cfd_mesoscale",
        patterns=_compile([
            r"(?i)\blbm\b",
            r"(?i)\blattice\ boltzmann\b",
            r"(?i)\bbgk\b",
            r"(?i)\bcollision\b",
            r"(?i)\bstreaming\b",
            r"(?i)\bdistribution\ function\b",
        ]),
        min_matches=2,
        confidence=0.90,
        bonus_per_extra=0.08,
        max_confidence=0.99,
        description="Lattice Boltzmann Method with BGK collision operator. Solves NS equations via mesoscale particle distribution functions ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="des_detached_eddy",
        algorithm="des_detached_eddy",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bdes\b",
            r"(?i)\bdetached\ eddy\b",
            r"(?i)\bhybrid\ rans\ les\b",
            r"(?i)\bddes\b",
            r"(?i)\biddes\b",
            r"(?i)\bcdes\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Detached Eddy Simulation -- hybrid RANS/LES switching based on grid spacing vs wall distance.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="standard_k_epsilon",
        algorithm="standard_k_epsilon",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bstandard\ k\ epsilon\b",
            r"(?i)\blaunder\ spalding\b",
            r"(?i)\bturbulence\ model\b",
            r"(?i)\beddy\ viscosity\b",
            r"(?i)\bcmu\b",
            r"(?i)\bsigma_k\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Standard k-epsilon turbulence model (Launder & Spalding 1974). Two-equation RANS model.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rsm_reynolds_stress",
        algorithm="rsm_reynolds_stress",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\brsm\b",
            r"(?i)\breynolds\ stress\ model\b",
            r"(?i)\bsecond\ moment\ closure\b",
            r"(?i)\bpressure\ strain\b",
            r"(?i)\breturn\ to\ isotropy\b",
            r"(?i)\banisotropy\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Reynolds Stress Model (LRR/SSG). Full second-moment closure, 7 transport equations.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="immersed_boundary_method",
        algorithm="immersed_boundary_method",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\bimmersed\ boundary\b",
            r"(?i)\bibm\b",
            r"(?i)\bdelta\ function\b",
            r"(?i)\blagrangian\b",
            r"(?i)\beulerian\b",
            r"(?i)\bpeskin\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Immersed Boundary Method (Peskin). Couples Lagrangian structure to Eulerian fluid via regularized delta function.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="piso_algorithm",
        algorithm="piso_algorithm",
        category="cfd_pressure_velocity",
        patterns=_compile([
            r"(?i)\bpiso\b",
            r"(?i)\bpressure\ implicit\ split\ operator\b",
            r"(?i)\bpredictor\b",
            r"(?i)\bcorrector\b",
            r"(?i)\bmomentum\b",
            r"(?i)\bpressure\ correction\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="PISO algorithm (Issa 1985). Pressure-velocity coupling with one predictor and two corrector steps. Used in transient CFD",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="muscl_scheme",
        algorithm="muscl_scheme",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\bmuscl\b",
            r"(?i)\bmonotone\ upstream\b",
            r"(?i)\bslope\ limiter\b",
            r"(?i)\bvan\ leer\b",
            r"(?i)\bminmod\b",
            r"(?i)\bsuperbee\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="MUSCL (Monotone Upstream-centered Schemes for Conservation Laws) reconstruction with slope limiters.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="weno_scheme",
        algorithm="weno_scheme",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\bweno\b",
            r"(?i)\bweighted\ essentially\ non\-oscillatory\b",
            r"(?i)\bsmoothness\ indicator\b",
            r"(?i)\bstencil\b",
            r"(?i)\bfifth\ order\b",
            r"(?i)\bweno5\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="WENO (Weighted Essentially Non-Oscillatory) scheme for high-order shock-capturing in compressible flows.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="roe_solver",
        algorithm="roe_solver",
        category="cfd_riemann",
        patterns=_compile([
            r"(?i)\broe\b",
            r"(?i)\bapproximate\ riemann\b",
            r"(?i)\bflux\ difference\ splitting\b",
            r"(?i)\broe\ average\b",
            r"(?i)\beigenvalue\b",
            r"(?i)\bentropy\ fix\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Roe's approximate Riemann solver for Euler/NS equations. Uses Roe-averaged states for flux computation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hllc_solver",
        algorithm="hllc_solver",
        category="cfd_riemann",
        patterns=_compile([
            r"(?i)\bhllc\b",
            r"(?i)\bhll\b",
            r"(?i)\briemann\ solver\b",
            r"(?i)\bcontact\ wave\b",
            r"(?i)\bwave\ speed\b",
            r"(?i)\btoro\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="HLLC Riemann solver (Toro). Restores contact discontinuity missing in basic HLL. Three wave speeds: S_L, S_*, S_R.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mixed_up_formulation",
        algorithm="mixed_up_formulation",
        category="fea_advanced",
        patterns=_compile([
            r"(?i)\bmixed\ formulation\b",
            r"(?i)\bu\-p\ formulation\b",
            r"(?i)\bincompressible\b",
            r"(?i)\bsaddle\ point\b",
            r"(?i)\binf\-sup\b",
            r"(?i)\bbrezzi\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Mixed u-p formulation for nearly incompressible elasticity. Displacement-pressure split avoids volumetric locking.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="b_bar_method",
        algorithm="b_bar_method",
        category="fea_advanced",
        patterns=_compile([
            r"(?i)\bb\ bar\b",
            r"(?i)\bb\-bar\b",
            r"(?i)\bselective\ reduced\ integration\b",
            r"(?i)\bvolumetric\ locking\b",
            r"(?i)\bmean\ dilatation\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="B-bar method (Hughes 1980). Replaces volumetric B-matrix with element-averaged value to prevent locking.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="reduced_integration_hourglass",
        algorithm="reduced_integration_hourglass",
        category="fea_advanced",
        patterns=_compile([
            r"(?i)\bhourglass\b",
            r"(?i)\breduced\ integration\b",
            r"(?i)\bzero\ energy\ mode\b",
            r"(?i)\bstabilization\b",
            r"(?i)\bflanagan\ belytschko\b",
            r"(?i)\bperturbation\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Hourglass control for reduced-integration elements. Adds stabilization stiffness to suppress zero-energy modes.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mortar_contact",
        algorithm="mortar_contact",
        category="fea_contact",
        patterns=_compile([
            r"(?i)\bmortar\b",
            r"(?i)\bcontact\b",
            r"(?i)\bsegment\ to\ segment\b",
            r"(?i)\blagrange\ multiplier\b",
            r"(?i)\bgap\ function\b",
            r"(?i)\bnon\-matching\ mesh\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Mortar contact method. Enforces contact constraints via Lagrange multipliers on non-matching meshes.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="xfem_extended_fem",
        algorithm="xfem_extended_fem",
        category="fea_fracture",
        patterns=_compile([
            r"(?i)\bxfem\b",
            r"(?i)\bextended\ fem\b",
            r"(?i)\benrichment\b",
            r"(?i)\bheaviside\b",
            r"(?i)\bcrack\ tip\b",
            r"(?i)\bpartition\ of\ unity\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Extended Finite Element Method (XFEM). Enriches standard FE space with Heaviside and crack-tip functions for fracture.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cohesive_zone_model",
        algorithm="cohesive_zone_model",
        category="fea_fracture",
        patterns=_compile([
            r"(?i)\bcohesive\ zone\b",
            r"(?i)\bczm\b",
            r"(?i)\btraction\ separation\b",
            r"(?i)\bdebonding\b",
            r"(?i)\bdelamination\b",
            r"(?i)\bbilinear\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Cohesive zone model for fracture/delamination. Traction-separation law relates interfacial tractions to opening displace",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="phase_field_fracture",
        algorithm="phase_field_fracture",
        category="fea_fracture",
        patterns=_compile([
            r"(?i)\bphase\ field\b",
            r"(?i)\bfracture\b",
            r"(?i)\bdamage\b",
            r"(?i)\bat1\b",
            r"(?i)\bat2\b",
            r"(?i)\bregularization\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Phase-field fracture model (AT2 formulation). Regularizes sharp crack with diffuse damage field d. l_0 is length scale p",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="neo_hookean",
        algorithm="neo_hookean",
        category="fea_hyperelastic",
        patterns=_compile([
            r"(?i)\bneo\ hookean\b",
            r"(?i)\bhyperelastic\b",
            r"(?i)\bstrain\ energy\b",
            r"(?i)\brubber\b",
            r"(?i)\blarge\ deformation\b",
            r"(?i)\binvariant\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Neo-Hookean hyperelastic model. Simplest incompressible hyperelastic law. mu=shear modulus, K=bulk modulus.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mooney_rivlin",
        algorithm="mooney_rivlin",
        category="fea_hyperelastic",
        patterns=_compile([
            r"(?i)\bmooney\ rivlin\b",
            r"(?i)\bhyperelastic\b",
            r"(?i)\brubber\b",
            r"(?i)\bstrain\ energy\b",
            r"(?i)\bc10\b",
            r"(?i)\bc01\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Mooney-Rivlin hyperelastic model. Two-parameter model for moderate strains in rubber-like materials.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ogden_model",
        algorithm="ogden_model",
        category="fea_hyperelastic",
        patterns=_compile([
            r"(?i)\bogden\b",
            r"(?i)\bhyperelastic\b",
            r"(?i)\bprincipal\ stretch\b",
            r"(?i)\brubber\b",
            r"(?i)\balpha\b",
            r"(?i)\bmu\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Ogden hyperelastic model. N-term model using principal stretches, fits rubber data over large strain range.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="arruda_boyce",
        algorithm="arruda_boyce",
        category="fea_hyperelastic",
        patterns=_compile([
            r"(?i)\barruda\ boyce\b",
            r"(?i)\beight\ chain\b",
            r"(?i)\bhyperelastic\b",
            r"(?i)\brubber\b",
            r"(?i)\bchain\ stretch\b",
            r"(?i)\blocking\ stretch\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Arruda-Boyce eight-chain hyperelastic model. Micromechanically motivated, uses chain locking stretch lambda_m.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="von_mises_plasticity",
        algorithm="von_mises_plasticity",
        category="fea_plasticity",
        patterns=_compile([
            r"(?i)\bvon\ mises\b",
            r"(?i)\bj2\ plasticity\b",
            r"(?i)\byield\ surface\b",
            r"(?i)\bradial\ return\b",
            r"(?i)\bassociative\ flow\b",
            r"(?i)\bisotropic\ hardening\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="von Mises (J2) plasticity with associative flow rule and isotropic hardening. Radial return mapping algorithm.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="drucker_prager_plasticity",
        algorithm="drucker_prager_plasticity",
        category="fea_plasticity",
        patterns=_compile([
            r"(?i)\bdrucker\ prager\b",
            r"(?i)\bpressure\ dependent\b",
            r"(?i)\bgranular\b",
            r"(?i)\bsoil\b",
            r"(?i)\bfriction\ angle\b",
            r"(?i)\bcohesion\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Drucker-Prager yield criterion. Pressure-dependent plasticity for soils, concrete, granular materials.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cam_clay",
        algorithm="cam_clay",
        category="fea_plasticity",
        patterns=_compile([
            r"(?i)\bcam\ clay\b",
            r"(?i)\bmodified\ cam\ clay\b",
            r"(?i)\bcritical\ state\b",
            r"(?i)\bsoil\ mechanics\b",
            r"(?i)\bconsolidation\b",
            r"(?i)\bpreconsolidation\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Modified Cam-Clay model for soil. Elliptical yield surface in p-q space with hardening linked to plastic volumetric stra",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="norton_creep",
        algorithm="norton_creep",
        category="fea_creep",
        patterns=_compile([
            r"(?i)\bnorton\b",
            r"(?i)\bpower\ law\ creep\b",
            r"(?i)\bsteady\ state\ creep\b",
            r"(?i)\bactivation\ energy\b",
            r"(?i)\bcreep\ exponent\b",
            r"(?i)\barrhenius\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Norton power-law creep model. Steady-state creep rate is power function of stress with Arrhenius temperature dependence.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="pid_controller",
        algorithm="pid_controller",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bpid\b",
            r"(?i)\bproportional\b",
            r"(?i)\bintegral\b",
            r"(?i)\bderivative\b",
            r"(?i)\bcontroller\b",
            r"(?i)\berror\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="PID (Proportional-Integral-Derivative) controller. Most widely used feedback controller in industrial automation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lqr_controller",
        algorithm="lqr_controller",
        category="control_systems",
        patterns=_compile([
            r"(?i)\blqr\b",
            r"(?i)\blinear\ quadratic\ regulator\b",
            r"(?i)\briccati\b",
            r"(?i)\boptimal\ control\b",
            r"(?i)\bstate\ feedback\b",
            r"(?i)\bare\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Linear Quadratic Regulator. Optimal state feedback via Algebraic Riccati Equation (ARE). Minimizes quadratic cost.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kalman_filter",
        algorithm="kalman_filter",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bkalman\b",
            r"(?i)\bkalman\ filter\b",
            r"(?i)\bpredict\b",
            r"(?i)\bupdate\b",
            r"(?i)\bcovariance\b",
            r"(?i)\binnovation\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Linear Kalman filter for optimal state estimation. Predict-update cycle with Kalman gain minimizing mean squared error.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="extended_kalman_filter",
        algorithm="extended_kalman_filter",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bekf\b",
            r"(?i)\bextended\ kalman\b",
            r"(?i)\bnonlinear\b",
            r"(?i)\bjacobian\b",
            r"(?i)\blinearization\b",
            r"(?i)\bstate\ estimation\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Extended Kalman Filter for nonlinear systems. Linearizes dynamics/observation via Jacobians at current estimate.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="unscented_kalman_filter",
        algorithm="unscented_kalman_filter",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bukf\b",
            r"(?i)\bunscented\ kalman\b",
            r"(?i)\bsigma\ points\b",
            r"(?i)\bunscented\ transform\b",
            r"(?i)\bmerwe\b",
            r"(?i)\bnonlinear\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Unscented Kalman Filter. Uses deterministic sigma points instead of Jacobians for nonlinear state estimation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mpc_model_predictive",
        algorithm="mpc_model_predictive",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bmpc\b",
            r"(?i)\bmodel\ predictive\ control\b",
            r"(?i)\breceding\ horizon\b",
            r"(?i)\bprediction\ horizon\b",
            r"(?i)\bconstraints\b",
            r"(?i)\bqp\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Model Predictive Control. Solves finite-horizon optimal control online at each timestep with constraints.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="luenberger_observer",
        algorithm="luenberger_observer",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bluenberger\b",
            r"(?i)\bobserver\b",
            r"(?i)\bstate\ observer\b",
            r"(?i)\bestimation\b",
            r"(?i)\bobserver\ gain\b",
            r"(?i)\beigenvalue\ placement\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Luenberger state observer. Estimates full state from output measurements using observer gain matrix L.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="pole_placement",
        algorithm="pole_placement",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bpole\ placement\b",
            r"(?i)\backermann\b",
            r"(?i)\beigenvalue\ assignment\b",
            r"(?i)\bstate\ feedback\b",
            r"(?i)\bcontrollability\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Pole placement (eigenvalue assignment) via state feedback. Places closed-loop poles at desired locations.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bode_analysis",
        algorithm="bode_analysis",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bbode\b",
            r"(?i)\bfrequency\ response\b",
            r"(?i)\bmagnitude\b",
            r"(?i)\bphase\b",
            r"(?i)\bgain\ margin\b",
            r"(?i)\bphase\ margin\b",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.08,
        max_confidence=0.82,
        description="Bode plot analysis. Magnitude and phase of transfer function vs frequency. Key for stability margin assessment.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="nyquist_analysis",
        algorithm="nyquist_analysis",
        category="control_systems",
        patterns=_compile([
            r"(?i)\bnyquist\b",
            r"(?i)\bstability\b",
            r"(?i)\bencirclement\b",
            r"(?i)\bcontour\b",
            r"(?i)\bopen\ loop\b",
            r"(?i)\bfrequency\ response\b",
        ]),
        min_matches=2,
        confidence=0.72,
        bonus_per_extra=0.08,
        max_confidence=0.82,
        description="Nyquist stability criterion. Number of encirclements of (-1,0) by G(jw) determines closed-loop stability.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="fft_cooley_tukey",
        algorithm="fft_cooley_tukey",
        category="dsp",
        patterns=_compile([
            r"(?i)\bfft\b",
            r"(?i)\bcooley\ tukey\b",
            r"(?i)\bradix\ 2\b",
            r"(?i)\bdit\b",
            r"(?i)\bdif\b",
            r"(?i)\bbutterfly\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="FFT Cooley-Tukey radix-2 DIT algorithm. O(N log N) complexity. Recursively splits DFT into even/odd sub-problems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dft_definition",
        algorithm="dft_definition",
        category="dsp",
        patterns=_compile([
            r"(?i)\bdft\b",
            r"(?i)\bdiscrete\ fourier\ transform\b",
            r"(?i)\bidft\b",
            r"(?i)\binverse\b",
            r"(?i)\bfrequency\ domain\b",
            r"(?i)\bspectrum\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Discrete Fourier Transform and its inverse. Maps time-domain signal to frequency-domain representation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="parks_mcclellan",
        algorithm="parks_mcclellan",
        category="dsp",
        patterns=_compile([
            r"(?i)\bparks\ mcclellan\b",
            r"(?i)\bremez\b",
            r"(?i)\bequiripple\b",
            r"(?i)\bminimax\b",
            r"(?i)\bfir\ design\b",
            r"(?i)\boptimal\ filter\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Parks-McClellan (Remez exchange) algorithm for optimal equiripple FIR filter design. Minimax approximation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="butterworth_design",
        algorithm="butterworth_design",
        category="dsp",
        patterns=_compile([
            r"(?i)\bbutterworth\b",
            r"(?i)\bmaximally\ flat\b",
            r"(?i)\biir\b",
            r"(?i)\blowpass\b",
            r"(?i)\bpoles\b",
            r"(?i)\bcutoff\ frequency\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Butterworth filter design. Maximally flat magnitude response in passband. All-pole transfer function.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="chebyshev_filter",
        algorithm="chebyshev_filter",
        category="dsp",
        patterns=_compile([
            r"(?i)\bchebyshev\b",
            r"(?i)\btype\ 1\b",
            r"(?i)\btype\ 2\b",
            r"(?i)\bequiripple\b",
            r"(?i)\bpassband\ ripple\b",
            r"(?i)\biir\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Chebyshev Type I filter. Equiripple in passband, monotonic in stopband. Sharper rolloff than Butterworth for same order.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="elliptic_filter",
        algorithm="elliptic_filter",
        category="dsp",
        patterns=_compile([
            r"(?i)\belliptic\b",
            r"(?i)\bcauer\b",
            r"(?i)\bequiripple\ passband\b",
            r"(?i)\bequiripple\ stopband\b",
            r"(?i)\biir\b",
            r"(?i)\bjacobi\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Elliptic (Cauer) filter. Equiripple in both passband and stopband. Steepest transition for given order.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hilbert_transform",
        algorithm="hilbert_transform",
        category="dsp",
        patterns=_compile([
            r"(?i)\bhilbert\b",
            r"(?i)\banalytic\ signal\b",
            r"(?i)\benvelope\b",
            r"(?i)\binstantaneous\ frequency\b",
            r"(?i)\bphase\b",
            r"(?i)\bcauchy\ principal\ value\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Hilbert transform. Produces analytic signal for envelope/instantaneous frequency extraction.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="wavelet_transform",
        algorithm="wavelet_transform",
        category="dsp",
        patterns=_compile([
            r"(?i)\bwavelet\b",
            r"(?i)\bcwt\b",
            r"(?i)\bdwt\b",
            r"(?i)\bmultiresolution\b",
            r"(?i)\bscale\b",
            r"(?i)\bdaubechies\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Continuous/Discrete Wavelet Transform. Time-frequency analysis with adaptive resolution. CWT for analysis, DWT for compr",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="welch_psd",
        algorithm="welch_psd",
        category="dsp",
        patterns=_compile([
            r"(?i)\bwelch\b",
            r"(?i)\bpsd\b",
            r"(?i)\bpower\ spectral\ density\b",
            r"(?i)\bperiodogram\b",
            r"(?i)\boverlap\b",
            r"(?i)\bwindowing\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Welch's method for PSD estimation. Averages modified periodograms of overlapping windowed segments.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="goertzel_algorithm",
        algorithm="goertzel_algorithm",
        category="dsp",
        patterns=_compile([
            r"(?i)\bgoertzel\b",
            r"(?i)\bsingle\ frequency\b",
            r"(?i)\bdtmf\b",
            r"(?i)\brecursive\b",
            r"(?i)\bdft\ bin\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Goertzel algorithm. Computes single DFT bin efficiently using second-order IIR. O(N) for one frequency.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dh_forward_kinematics",
        algorithm="dh_forward_kinematics",
        category="robotics",
        patterns=_compile([
            r"(?i)\bdenavit\ hartenberg\b",
            r"(?i)\bdh\ parameters\b",
            r"(?i)\bforward\ kinematics\b",
            r"(?i)\bhomogeneous\ transformation\b",
            r"(?i)\bjoint\b",
            r"(?i)\blink\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Denavit-Hartenberg forward kinematics. Chain of homogeneous transforms from base to end-effector using DH convention.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="inverse_kinematics_jacobian",
        algorithm="inverse_kinematics_jacobian",
        category="robotics",
        patterns=_compile([
            r"(?i)\binverse\ kinematics\b",
            r"(?i)\bjacobian\b",
            r"(?i)\bpseudoinverse\b",
            r"(?i)\bdamped\ least\ squares\b",
            r"(?i)\bend\ effector\b",
            r"(?i)\bik\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Jacobian-based inverse kinematics with damped least squares (DLS). Iteratively solves for joint angles from end-effector",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="quintic_polynomial_trajectory",
        algorithm="quintic_polynomial_trajectory",
        category="robotics",
        patterns=_compile([
            r"(?i)\bquintic\b",
            r"(?i)\btrajectory\b",
            r"(?i)\bpolynomial\b",
            r"(?i)\bsmooth\b",
            r"(?i)\bjerk\b",
            r"(?i)\bmotion\ planning\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Quintic polynomial trajectory planning. Ensures continuous position, velocity, and acceleration at start/end.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="trapezoidal_velocity_profile",
        algorithm="trapezoidal_velocity_profile",
        category="robotics",
        patterns=_compile([
            r"(?i)\btrapezoidal\b",
            r"(?i)\bvelocity\ profile\b",
            r"(?i)\bacceleration\b",
            r"(?i)\bcruise\b",
            r"(?i)\bdeceleration\b",
            r"(?i)\bmotion\ profile\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Trapezoidal velocity profile for motion planning. Three phases: acceleration, constant velocity, deceleration.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="a_star_pathfinding",
        algorithm="a_star_pathfinding",
        category="robotics",
        patterns=_compile([
            r"(?i)\ba\ star\b",
            r"(?i)\bastar\b",
            r"(?i)\bpathfinding\b",
            r"(?i)\bheuristic\b",
            r"(?i)\bopen\ set\b",
            r"(?i)\bclosed\ set\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="A* pathfinding algorithm. Best-first graph search with admissible heuristic. Optimal and complete.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rrt_rapidly_exploring",
        algorithm="rrt_rapidly_exploring",
        category="robotics",
        patterns=_compile([
            r"(?i)\brrt\b",
            r"(?i)\brapidly\ exploring\ random\ tree\b",
            r"(?i)\bmotion\ planning\b",
            r"(?i)\bsampling\b",
            r"(?i)\bcollision\ free\b",
            r"(?i)\brrt\ star\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Rapidly-exploring Random Trees (RRT). Sampling-based motion planning for high-dimensional configuration spaces.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="slam_ekf",
        algorithm="slam_ekf",
        category="robotics",
        patterns=_compile([
            r"(?i)\bslam\b",
            r"(?i)\bsimultaneous\ localization\b",
            r"(?i)\bmapping\b",
            r"(?i)\bekf\ slam\b",
            r"(?i)\blandmark\b",
            r"(?i)\bloop\ closure\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="EKF-SLAM for simultaneous localization and mapping. Joint state of robot pose and landmark positions.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="quaternion_rotation",
        algorithm="quaternion_rotation",
        category="robotics",
        patterns=_compile([
            r"(?i)\bquaternion\b",
            r"(?i)\brotation\b",
            r"(?i)\bunit\ quaternion\b",
            r"(?i)\bhamilton\b",
            r"(?i)\bconjugate\b",
            r"(?i)\bslerp\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Quaternion rotation. Gimbal-lock-free 3D rotation representation. Computationally efficient, numerically stable.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rodrigues_rotation",
        algorithm="rodrigues_rotation",
        category="robotics",
        patterns=_compile([
            r"(?i)\brodrigues\b",
            r"(?i)\baxis\ angle\b",
            r"(?i)\brotation\ formula\b",
            r"(?i)\brotation\ vector\b",
            r"(?i)\bso3\b",
            r"(?i)\bexponential\ map\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Rodrigues' rotation formula. Rotates vector v by angle theta around unit axis k. Equivalent to matrix exponential on SO(",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tsiolkovsky_rocket",
        algorithm="tsiolkovsky_rocket",
        category="aerospace",
        patterns=_compile([
            r"(?i)\btsiolkovsky\b",
            r"(?i)\brocket\ equation\b",
            r"(?i)\bdelta\ v\b",
            r"(?i)\bspecific\ impulse\b",
            r"(?i)\bmass\ ratio\b",
            r"(?i)\bexhaust\ velocity\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Tsiolkovsky rocket equation. Relates delta-v to exhaust velocity and mass ratio. Foundation of rocket propulsion.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kepler_orbit",
        algorithm="kepler_orbit",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bkepler\b",
            r"(?i)\borbit\b",
            r"(?i)\beccentricity\b",
            r"(?i)\bsemi\-major\ axis\b",
            r"(?i)\btrue\ anomaly\b",
            r"(?i)\beccentric\ anomaly\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Kepler orbital mechanics. Orbit equation, period, and Kepler's equation relating mean and eccentric anomaly.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vis_viva",
        algorithm="vis_viva",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bvis\ viva\b",
            r"(?i)\borbital\ velocity\b",
            r"(?i)\bspecific\ energy\b",
            r"(?i)\belliptic\ orbit\b",
            r"(?i)\bescape\ velocity\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Vis-viva equation. Relates orbital velocity to position and semi-major axis. Derived from energy conservation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="isa_atmosphere",
        algorithm="isa_atmosphere",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bisa\b",
            r"(?i)\binternational\ standard\ atmosphere\b",
            r"(?i)\baltitude\b",
            r"(?i)\btemperature\ lapse\b",
            r"(?i)\bpressure\b",
            r"(?i)\bdensity\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="International Standard Atmosphere. Temperature, pressure, density as functions of geopotential altitude.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="six_dof_eom",
        algorithm="six_dof_eom",
        category="aerospace",
        patterns=_compile([
            r"(?i)\b6dof\b",
            r"(?i)\bsix\ degrees\b",
            r"(?i)\bequations\ of\ motion\b",
            r"(?i)\brigid\ body\b",
            r"(?i)\beuler\ equations\b",
            r"(?i)\bangular\ momentum\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="6-DOF rigid body equations of motion. Newton-Euler formulation in body-fixed frame for flight dynamics.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="drag_coefficient",
        algorithm="drag_coefficient",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bdrag\b",
            r"(?i)\blift\b",
            r"(?i)\baerodynamic\b",
            r"(?i)\bdrag\ polar\b",
            r"(?i)\bparasitic\b",
            r"(?i)\binduced\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Aerodynamic drag model with drag polar. Total drag = parasitic + induced drag. e is Oswald efficiency factor.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hohmann_transfer",
        algorithm="hohmann_transfer",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bhohmann\b",
            r"(?i)\btransfer\ orbit\b",
            r"(?i)\bdelta\ v\b",
            r"(?i)\bcircular\ orbit\b",
            r"(?i)\bapoapsis\b",
            r"(?i)\bperiapsis\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Hohmann transfer orbit. Minimum-energy two-impulse transfer between coplanar circular orbits.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="thrust_equation",
        algorithm="thrust_equation",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bthrust\b",
            r"(?i)\bnozzle\b",
            r"(?i)\bexhaust\b",
            r"(?i)\bmass\ flow\b",
            r"(?i)\bpressure\ thrust\b",
            r"(?i)\bmomentum\ thrust\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Rocket thrust equation. Sum of momentum thrust and pressure thrust at nozzle exit.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="van_der_waals",
        algorithm="van_der_waals",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bvan\ der\ waals\b",
            r"(?i)\bequation\ of\ state\b",
            r"(?i)\breal\ gas\b",
            r"(?i)\bintermolecular\b",
            r"(?i)\bexcluded\ volume\b",
            r"(?i)\beos\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="van der Waals equation of state. Corrects ideal gas law for intermolecular attractions (a) and molecular volume (b).",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="peng_robinson_eos",
        algorithm="peng_robinson_eos",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bpeng\ robinson\b",
            r"(?i)\bequation\ of\ state\b",
            r"(?i)\bcubic\ eos\b",
            r"(?i)\bacentric\ factor\b",
            r"(?i)\bfugacity\b",
            r"(?i)\bvle\b",
        ]),
        min_matches=2,
        confidence=0.88,
        bonus_per_extra=0.08,
        max_confidence=0.98,
        description="Peng-Robinson equation of state. Industry-standard cubic EOS for VLE calculations in process engineering.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="srk_eos",
        algorithm="srk_eos",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bsoave\ redlich\ kwong\b",
            r"(?i)\bsrk\b",
            r"(?i)\bcubic\ eos\b",
            r"(?i)\bequation\ of\ state\b",
            r"(?i)\bacentric\ factor\b",
        ]),
        min_matches=2,
        confidence=0.86,
        bonus_per_extra=0.08,
        max_confidence=0.96,
        description="Soave-Redlich-Kwong equation of state. Cubic EOS widely used for hydrocarbon systems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="antoine_equation",
        algorithm="antoine_equation",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bantoine\b",
            r"(?i)\bvapor\ pressure\b",
            r"(?i)\bsaturation\b",
            r"(?i)\bboiling\ point\b",
            r"(?i)\bclausius\ clapeyron\b",
            r"(?i)\bvle\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Antoine equation for vapor pressure correlation. Three-parameter fit of saturation pressure vs temperature.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="arrhenius_equation",
        algorithm="arrhenius_equation",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\barrhenius\b",
            r"(?i)\breaction\ rate\b",
            r"(?i)\bactivation\ energy\b",
            r"(?i)\bpre\-exponential\b",
            r"(?i)\bfrequency\ factor\b",
            r"(?i)\bkinetics\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Arrhenius equation for chemical reaction rate constant. Exponential temperature dependence with activation energy.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cstr_reactor",
        algorithm="cstr_reactor",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bcstr\b",
            r"(?i)\bcontinuous\ stirred\ tank\b",
            r"(?i)\breactor\b",
            r"(?i)\bconversion\b",
            r"(?i)\bresidence\ time\b",
            r"(?i)\bbackmix\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="CSTR (Continuous Stirred-Tank Reactor) design equation. Perfect mixing: uniform concentration throughout.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="pfr_reactor",
        algorithm="pfr_reactor",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bpfr\b",
            r"(?i)\bplug\ flow\ reactor\b",
            r"(?i)\btubular\b",
            r"(?i)\bconversion\b",
            r"(?i)\bno\ mixing\b",
            r"(?i)\bresidence\ time\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="PFR (Plug Flow Reactor) design equation. No axial mixing, composition varies along reactor length.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ficks_diffusion",
        algorithm="ficks_diffusion",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bfick\b",
            r"(?i)\bdiffusion\b",
            r"(?i)\bmass\ transfer\b",
            r"(?i)\bconcentration\ gradient\b",
            r"(?i)\bdiffusivity\b",
            r"(?i)\bflux\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Fick's laws of diffusion. First law: flux proportional to concentration gradient. Second law: transient diffusion equati",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="lmtd_heat_exchanger",
        algorithm="lmtd_heat_exchanger",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\blmtd\b",
            r"(?i)\blog\ mean\ temperature\b",
            r"(?i)\bheat\ exchanger\b",
            r"(?i)\bua\b",
            r"(?i)\boverall\ heat\ transfer\b",
            r"(?i)\bcounterflow\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="LMTD method for heat exchanger design. Uses logarithmic mean temperature difference for sizing.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ntu_effectiveness",
        algorithm="ntu_effectiveness",
        category="chemical_engineering",
        patterns=_compile([
            r"(?i)\bntu\b",
            r"(?i)\beffectiveness\b",
            r"(?i)\bheat\ exchanger\b",
            r"(?i)\bcapacity\ ratio\b",
            r"(?i)\bcounterflow\b",
            r"(?i)\bcrossflow\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="NTU-effectiveness method for heat exchangers. Alternative to LMTD when outlet temperatures are unknown.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="conjugate_gradient_method",
        algorithm="conjugate_gradient_method",
        category="optimization",
        patterns=_compile([
            r"(?i)\bconjugate\ gradient\b",
            r"(?i)\bfletcher\ reeves\b",
            r"(?i)\bpolak\ ribiere\b",
            r"(?i)\bnonlinear\ cg\b",
            r"(?i)\bdirection\b",
            r"(?i)\bbeta\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Nonlinear conjugate gradient method. Fletcher-Reeves or Polak-Ribiere variants. Effective for large-scale unconstrained ",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bfgs_method",
        algorithm="bfgs_method",
        category="optimization",
        patterns=_compile([
            r"(?i)\bbfgs\b",
            r"(?i)\bquasi\ newton\b",
            r"(?i)\bhessian\ update\b",
            r"(?i)\binverse\ hessian\b",
            r"(?i)\bl\-bfgs\b",
            r"(?i)\blimited\ memory\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="BFGS quasi-Newton optimization. Rank-2 update of inverse Hessian approximation. Superlinear convergence.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="l_bfgs_method",
        algorithm="l_bfgs_method",
        category="optimization",
        patterns=_compile([
            r"(?i)\bl\-bfgs\b",
            r"(?i)\blimited\ memory\ bfgs\b",
            r"(?i)\btwo\ loop\ recursion\b",
            r"(?i)\blarge\ scale\b",
            r"(?i)\bmemory\ efficient\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="L-BFGS (Limited-memory BFGS). Stores only m vector pairs instead of full Hessian. Standard for large-scale optimization.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="simulated_annealing_opt",
        algorithm="simulated_annealing_opt",
        category="optimization",
        patterns=_compile([
            r"(?i)\bsimulated\ annealing\b",
            r"(?i)\bmetropolis\b",
            r"(?i)\bcooling\ schedule\b",
            r"(?i)\btemperature\b",
            r"(?i)\bglobal\ optimization\b",
            r"(?i)\bcombinatorial\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Simulated annealing for global optimization. Accepts uphill moves with probability decreasing with temperature.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="genetic_algorithm",
        algorithm="genetic_algorithm",
        category="optimization",
        patterns=_compile([
            r"(?i)\bgenetic\ algorithm\b",
            r"(?i)\bga\b",
            r"(?i)\bcrossover\b",
            r"(?i)\bmutation\b",
            r"(?i)\bselection\b",
            r"(?i)\bfitness\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Genetic algorithm for evolutionary optimization. Population-based metaheuristic inspired by natural selection.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="particle_swarm",
        algorithm="particle_swarm",
        category="optimization",
        patterns=_compile([
            r"(?i)\bpso\b",
            r"(?i)\bparticle\ swarm\b",
            r"(?i)\bswarm\ intelligence\b",
            r"(?i)\binertia\ weight\b",
            r"(?i)\bcognitive\b",
            r"(?i)\bsocial\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Particle Swarm Optimization (PSO). Swarm-based metaheuristic. Particles follow personal and global best positions.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sgd_optimizer",
        algorithm="sgd_optimizer",
        category="optimization",
        patterns=_compile([
            r"(?i)\bsgd\b",
            r"(?i)\bstochastic\ gradient\ descent\b",
            r"(?i)\bmini\ batch\b",
            r"(?i)\blearning\ rate\b",
            r"(?i)\bgradient\b",
            r"(?i)\bbackpropagation\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Stochastic Gradient Descent. Updates parameters using gradient of loss on random mini-batch.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="momentum_optimizer",
        algorithm="momentum_optimizer",
        category="optimization",
        patterns=_compile([
            r"(?i)\bmomentum\b",
            r"(?i)\bsgd\ momentum\b",
            r"(?i)\bpolyak\b",
            r"(?i)\bheavy\ ball\b",
            r"(?i)\baccelerated\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="SGD with momentum (Polyak heavy ball). Accumulates past gradients to dampen oscillations and accelerate convergence.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="adagrad_optimizer",
        algorithm="adagrad_optimizer",
        category="optimization",
        patterns=_compile([
            r"(?i)\badagrad\b",
            r"(?i)\badaptive\ gradient\b",
            r"(?i)\bper\ parameter\b",
            r"(?i)\blearning\ rate\ decay\b",
            r"(?i)\bsparse\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="AdaGrad optimizer. Adapts learning rate per parameter based on accumulated squared gradients.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rmsprop_optimizer",
        algorithm="rmsprop_optimizer",
        category="optimization",
        patterns=_compile([
            r"(?i)\brmsprop\b",
            r"(?i)\broot\ mean\ square\b",
            r"(?i)\badaptive\b",
            r"(?i)\bhinton\b",
            r"(?i)\bexponential\ moving\ average\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="RMSProp optimizer (Hinton). Fixes AdaGrad's diminishing learning rate with exponential moving average of squared gradien",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bayesian_optimization",
        algorithm="bayesian_optimization",
        category="optimization",
        patterns=_compile([
            r"(?i)\bbayesian\ optimization\b",
            r"(?i)\bgaussian\ process\b",
            r"(?i)\bacquisition\ function\b",
            r"(?i)\bexpected\ improvement\b",
            r"(?i)\bsurrogate\b",
            r"(?i)\bei\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Bayesian optimization. Uses Gaussian process surrogate and acquisition function (EI, UCB) for black-box optimization.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="trust_region_newton",
        algorithm="trust_region_newton",
        category="optimization",
        patterns=_compile([
            r"(?i)\btrust\ region\b",
            r"(?i)\bnewton\ cg\b",
            r"(?i)\bcauchy\ point\b",
            r"(?i)\bdogleg\b",
            r"(?i)\bradius\ update\b",
            r"(?i)\bquadratic\ model\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Trust-region Newton-CG method. Minimizes quadratic model within trust radius. Robust for non-convex problems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="admm_optimization",
        algorithm="admm_optimization",
        category="optimization",
        patterns=_compile([
            r"(?i)\badmm\b",
            r"(?i)\balternating\ direction\b",
            r"(?i)\bmethod\ of\ multipliers\b",
            r"(?i)\bsplitting\b",
            r"(?i)\bconsensus\b",
            r"(?i)\bproximal\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="ADMM (Alternating Direction Method of Multipliers). Decomposes convex optimization into tractable sub-problems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="runge_kutta_fehlberg",
        algorithm="runge_kutta_fehlberg",
        category="time_integration",
        patterns=_compile([
            r"(?i)\brkf45\b",
            r"(?i)\brunge\ kutta\ fehlberg\b",
            r"(?i)\badaptive\ step\b",
            r"(?i)\berror\ estimate\b",
            r"(?i)\bembedded\b",
            r"(?i)\bdormand\ prince\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Runge-Kutta-Fehlberg (RKF45). Embedded pair for adaptive step-size control. 4th/5th order error estimation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="adams_bashforth",
        algorithm="adams_bashforth",
        category="time_integration",
        patterns=_compile([
            r"(?i)\badams\ bashforth\b",
            r"(?i)\bmultistep\b",
            r"(?i)\bexplicit\b",
            r"(?i)\bab2\b",
            r"(?i)\bab3\b",
            r"(?i)\bab4\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Adams-Bashforth explicit multistep methods. Uses past function evaluations. AB4 is 4th-order with 4 history points.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="adams_moulton",
        algorithm="adams_moulton",
        category="time_integration",
        patterns=_compile([
            r"(?i)\badams\ moulton\b",
            r"(?i)\bimplicit\ multistep\b",
            r"(?i)\bcorrector\b",
            r"(?i)\bam2\b",
            r"(?i)\bam3\b",
            r"(?i)\bpredictor\ corrector\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Adams-Moulton implicit multistep methods. Used as corrector in predictor-corrector pairs.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="crank_nicolson",
        algorithm="crank_nicolson",
        category="time_integration",
        patterns=_compile([
            r"(?i)\bcrank\ nicolson\b",
            r"(?i)\bimplicit\b",
            r"(?i)\bsecond\ order\b",
            r"(?i)\btrapezoidal\ rule\b",
            r"(?i)\ba\-stable\b",
            r"(?i)\bheat\ equation\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Crank-Nicolson time integration. Trapezoidal rule, 2nd-order accurate, A-stable. Standard for parabolic PDEs.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="verlet_integration",
        algorithm="verlet_integration",
        category="time_integration",
        patterns=_compile([
            r"(?i)\bverlet\b",
            r"(?i)\bleapfrog\b",
            r"(?i)\bstormer\b",
            r"(?i)\bsymplectic\b",
            r"(?i)\bmolecular\ dynamics\b",
            r"(?i)\bvelocity\ verlet\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Verlet/velocity-Verlet integration. Symplectic, time-reversible, excellent energy conservation for Hamiltonian systems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sparse_direct_solver",
        algorithm="sparse_direct_solver",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bsparse\b",
            r"(?i)\bdirect\ solver\b",
            r"(?i)\bsupernodal\b",
            r"(?i)\bmultifrontal\b",
            r"(?i)\bfill\-in\b",
            r"(?i)\breordering\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Sparse direct solver (supernodal/multifrontal). Uses fill-reducing reordering (AMD/METIS) for efficiency.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="multigrid_method",
        algorithm="multigrid_method",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bmultigrid\b",
            r"(?i)\bv\-cycle\b",
            r"(?i)\bw\-cycle\b",
            r"(?i)\brestriction\b",
            r"(?i)\bprolongation\b",
            r"(?i)\bsmoothing\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Multigrid method (geometric/algebraic). O(N) solver using hierarchy of grids. V-cycle and W-cycle variants.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gmres_solver",
        algorithm="gmres_solver",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bgmres\b",
            r"(?i)\bgeneralized\ minimal\ residual\b",
            r"(?i)\bkrylov\b",
            r"(?i)\barnoldi\b",
            r"(?i)\brestart\b",
            r"(?i)\bpreconditioning\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="GMRES (Generalized Minimal Residual). Krylov subspace method for nonsymmetric linear systems. Uses Arnoldi process.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="bicgstab_solver",
        algorithm="bicgstab_solver",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bbicgstab\b",
            r"(?i)\bbiconjugate\ gradient\ stabilized\b",
            r"(?i)\bkrylov\b",
            r"(?i)\bnonsymmetric\b",
            r"(?i)\bvan\ der\ vorst\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="BiCGSTAB (Bi-Conjugate Gradient Stabilized). Krylov solver for nonsymmetric systems, smoother convergence than BiCG.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="incomplete_lu",
        algorithm="incomplete_lu",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bilu\b",
            r"(?i)\bincomplete\ lu\b",
            r"(?i)\bpreconditioner\b",
            r"(?i)\bfill\ level\b",
            r"(?i)\bilut\b",
            r"(?i)\bilu0\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Incomplete LU factorization. Sparse preconditioner that drops fill-in entries. ILU(0) preserves sparsity pattern.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="svd_decomposition",
        algorithm="svd_decomposition",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bsvd\b",
            r"(?i)\bsingular\ value\ decomposition\b",
            r"(?i)\brank\b",
            r"(?i)\bpseudoinverse\b",
            r"(?i)\blow\ rank\b",
            r"(?i)\btruncated\ svd\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Singular Value Decomposition. Fundamental factorization for rank analysis, least squares, PCA, and compression.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rayleigh_quotient",
        algorithm="rayleigh_quotient",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\brayleigh\ quotient\b",
            r"(?i)\beigenvalue\ bound\b",
            r"(?i)\bvariational\b",
            r"(?i)\bmin\ max\b",
            r"(?i)\britz\ value\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Rayleigh quotient for eigenvalue estimation. Provides best eigenvalue estimate for given eigenvector approximation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gauss_elimination",
        algorithm="gauss_elimination",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bgaussian\ elimination\b",
            r"(?i)\brow\ reduction\b",
            r"(?i)\bpivoting\b",
            r"(?i)\bback\ substitution\b",
            r"(?i)\bechelon\ form\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Gaussian elimination with partial pivoting. Direct method for linear systems. O(n^3) complexity.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="nusselt_correlation",
        algorithm="nusselt_correlation",
        category="heat_transfer",
        patterns=_compile([
            r"(?i)\bnusselt\b",
            r"(?i)\breynolds\b",
            r"(?i)\bprandtl\b",
            r"(?i)\bheat\ transfer\ coefficient\b",
            r"(?i)\bcorrelation\b",
            r"(?i)\bdittus\ boelter\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Nusselt number correlations for convective heat transfer. Dittus-Boelter for turbulent internal flow.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rayleigh_benard",
        algorithm="rayleigh_benard",
        category="heat_transfer",
        patterns=_compile([
            r"(?i)\brayleigh\b",
            r"(?i)\bbenard\b",
            r"(?i)\bnatural\ convection\b",
            r"(?i)\bbuoyancy\b",
            r"(?i)\bcritical\ rayleigh\b",
            r"(?i)\bgrashof\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Rayleigh-Benard convection. Ra number determines onset and nature of buoyancy-driven convection.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="finite_volume_method",
        algorithm="finite_volume_method",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\bfinite\ volume\b",
            r"(?i)\bfvm\b",
            r"(?i)\bconservation\b",
            r"(?i)\bflux\b",
            r"(?i)\bcell\ centered\b",
            r"(?i)\bvertex\ centered\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Finite Volume Method. Integral conservation over control volumes. Naturally conservative, standard in CFD.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="boundary_element_method",
        algorithm="boundary_element_method",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\bbem\b",
            r"(?i)\bboundary\ element\b",
            r"(?i)\bgreen\ function\b",
            r"(?i)\bfundamental\ solution\b",
            r"(?i)\bsingular\ integral\b",
            r"(?i)\blaplace\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Boundary Element Method. Reduces domain problem to boundary integral. Uses fundamental solution (Green's function).",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="spectral_method",
        algorithm="spectral_method",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\bspectral\b",
            r"(?i)\bfourier\b",
            r"(?i)\bchebyshev\b",
            r"(?i)\blegendre\b",
            r"(?i)\bspectral\ element\b",
            r"(?i)\bexponential\ convergence\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Spectral methods. Expand solution in global basis (Fourier, Chebyshev, Legendre). Exponential convergence for smooth pro",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="isogeometric_analysis",
        algorithm="isogeometric_analysis",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\biga\b",
            r"(?i)\bisogeometric\b",
            r"(?i)\bnurbs\b",
            r"(?i)\bspline\b",
            r"(?i)\bcad\ integration\b",
            r"(?i)\bhigher\ order\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Isogeometric Analysis (IGA). Uses NURBS basis from CAD geometry directly as FE shape functions. Exact geometry.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sparse_matrix_csr",
        algorithm="sparse_matrix_csr",
        category="data_structures",
        patterns=_compile([
            r"(?i)\bcsr\b",
            r"(?i)\bcsc\b",
            r"(?i)\bsparse\ matrix\b",
            r"(?i)\bcompressed\ row\b",
            r"(?i)\bcompressed\ column\b",
            r"(?i)\bcoo\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Compressed Sparse Row (CSR) format. Standard sparse matrix storage. O(nnz) memory, efficient row-slice and SpMV.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="monte_carlo_integration",
        algorithm="monte_carlo_integration",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\bmonte\ carlo\b",
            r"(?i)\bintegration\b",
            r"(?i)\brandom\ sampling\b",
            r"(?i)\bvariance\ reduction\b",
            r"(?i)\bimportance\ sampling\b",
            r"(?i)\bconvergence\ rate\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Monte Carlo integration. Convergence rate O(1/sqrt(N)) independent of dimension. Ideal for high-dimensional integrals.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="hermite_interpolation",
        algorithm="hermite_interpolation",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\bhermite\b",
            r"(?i)\binterpolation\b",
            r"(?i)\bosculating\b",
            r"(?i)\bderivative\ matching\b",
            r"(?i)\bcubic\ hermite\b",
            r"(?i)\btangent\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Hermite interpolation. Matches both function values and derivatives at nodes. Cubic Hermite uses 4 data points.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="richardson_extrapolation",
        algorithm="richardson_extrapolation",
        category="numerical_methods",
        patterns=_compile([
            r"(?i)\brichardson\b",
            r"(?i)\bextrapolation\b",
            r"(?i)\border\ improvement\b",
            r"(?i)\bromberg\b",
            r"(?i)\berror\ estimation\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Richardson extrapolation. Improves accuracy by combining results at different step sizes. Basis for Romberg integration.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="elastic_wave_equation",
        algorithm="elastic_wave_equation",
        category="structural_dynamics",
        patterns=_compile([
            r"(?i)\belastic\ wave\b",
            r"(?i)\bp\-wave\b",
            r"(?i)\bs\-wave\b",
            r"(?i)\blongitudinal\b",
            r"(?i)\btransverse\b",
            r"(?i)\bseismic\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Elastic wave equation. P-wave (compressional) and S-wave (shear) propagation in solids. Basis for seismology and NDE.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rayleigh_damping",
        algorithm="rayleigh_damping",
        category="structural_dynamics",
        patterns=_compile([
            r"(?i)\brayleigh\ damping\b",
            r"(?i)\bproportional\ damping\b",
            r"(?i)\balpha\b",
            r"(?i)\bbeta\b",
            r"(?i)\bmass\ proportional\b",
            r"(?i)\bstiffness\ proportional\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Rayleigh (proportional) damping. Damping matrix as linear combination of mass and stiffness matrices.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="wilson_theta",
        algorithm="wilson_theta",
        category="structural_dynamics",
        patterns=_compile([
            r"(?i)\bwilson\ theta\b",
            r"(?i)\bimplicit\b",
            r"(?i)\bunconditionally\ stable\b",
            r"(?i)\btime\ integration\b",
            r"(?i)\bstructural\ dynamics\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Wilson-theta method for structural dynamics. Unconditionally stable for theta >= 1.37. Extended Newmark variant.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="stress_intensity_factor",
        algorithm="stress_intensity_factor",
        category="fracture_mechanics",
        patterns=_compile([
            r"(?i)\bstress\ intensity\b",
            r"(?i)\bk_ic\b",
            r"(?i)\bfracture\ toughness\b",
            r"(?i)\bcrack\b",
            r"(?i)\bgriffith\b",
            r"(?i)\birwin\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Stress intensity factor and energy release rate. K_I characterizes crack-tip stress field. G = K^2/E' (Irwin relation).",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="j_integral",
        algorithm="j_integral",
        category="fracture_mechanics",
        patterns=_compile([
            r"(?i)\bj\ integral\b",
            r"(?i)\brice\b",
            r"(?i)\bpath\ independent\b",
            r"(?i)\benergy\ release\b",
            r"(?i)\bcrack\ driving\ force\b",
            r"(?i)\belasto\-plastic\ fracture\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="J-integral (Rice 1968). Path-independent contour integral for fracture. Equals G for linear elastic, extends to plastici",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="paris_law",
        algorithm="paris_law",
        category="fracture_mechanics",
        patterns=_compile([
            r"(?i)\bparis\b",
            r"(?i)\bfatigue\ crack\b",
            r"(?i)\bcrack\ growth\ rate\b",
            r"(?i)\bstress\ intensity\ range\b",
            r"(?i)\bda/dn\b",
            r"(?i)\bparis\ erdogan\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Paris fatigue crack growth law. Power-law relation between crack growth rate and stress intensity factor range.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="navier_stokes_compressible",
        algorithm="navier_stokes_compressible",
        category="cfd_governing",
        patterns=_compile([
            r"(?i)\bcompressible\ navier\ stokes\b",
            r"(?i)\beuler\ equations\b",
            r"(?i)\bconservation\ form\b",
            r"(?i)\bshock\b",
            r"(?i)\bmach\ number\b",
            r"(?i)\btotal\ energy\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Compressible Navier-Stokes equations in conservation form. Full system with energy equation for high-Mach flows.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="turbulence_wall_function",
        algorithm="turbulence_wall_function",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bwall\ function\b",
            r"(?i)\blog\ law\b",
            r"(?i)\bvon\ karman\b",
            r"(?i)\bbuffer\ layer\b",
            r"(?i)\bviscous\ sublayer\b",
            r"(?i)\by\ plus\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Turbulent wall functions (law of the wall). Bridges viscous sublayer to log-law region. Avoids resolving boundary layer.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="dynamic_smagorinsky",
        algorithm="dynamic_smagorinsky",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bdynamic\ smagorinsky\b",
            r"(?i)\bgermano\ identity\b",
            r"(?i)\bles\b",
            r"(?i)\btest\ filter\b",
            r"(?i)\bdynamic\ procedure\b",
            r"(?i)\blilly\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Dynamic Smagorinsky model (Germano 1991). Computes Cs dynamically from resolved scales using test filter.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="sa_ddes",
        algorithm="sa_ddes",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bddes\b",
            r"(?i)\bdelayed\ des\b",
            r"(?i)\bshielding\ function\b",
            r"(?i)\bsa\-ddes\b",
            r"(?i)\bhybrid\ rans\-les\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Delayed Detached Eddy Simulation (DDES). Adds shielding function fd to prevent grid-induced separation in boundary layer",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="ale_formulation",
        algorithm="ale_formulation",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\bale\b",
            r"(?i)\barbitrary\ lagrangian\ eulerian\b",
            r"(?i)\bmesh\ motion\b",
            r"(?i)\bmoving\ mesh\b",
            r"(?i)\bfsi\b",
            r"(?i)\bfluid\ structure\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Arbitrary Lagrangian-Eulerian formulation. Moving mesh framework for FSI and free-surface problems.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cfl_condition",
        algorithm="cfl_condition",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\bcfl\b",
            r"(?i)\bcourant\b",
            r"(?i)\bfriedrichs\b",
            r"(?i)\blewy\b",
            r"(?i)\bstability\ condition\b",
            r"(?i)\btime\ step\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Courant-Friedrichs-Lewy condition. Necessary stability condition for explicit time-stepping schemes.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="tvd_limiter",
        algorithm="tvd_limiter",
        category="cfd_numerics",
        patterns=_compile([
            r"(?i)\btvd\b",
            r"(?i)\btotal\ variation\ diminishing\b",
            r"(?i)\bflux\ limiter\b",
            r"(?i)\bminmod\b",
            r"(?i)\bsuperbee\b",
            r"(?i)\bvan\ leer\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="TVD (Total Variation Diminishing) flux limiters. Prevent oscillations near discontinuities while maintaining accuracy.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gauss_jordan_elimination",
        algorithm="gauss_jordan_elimination",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bgauss\ jordan\b",
            r"(?i)\bmatrix\ inverse\b",
            r"(?i)\baugmented\ matrix\b",
            r"(?i)\breduced\ row\ echelon\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Gauss-Jordan elimination for matrix inversion. Augments A with identity and row-reduces to RREF.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="cholesky_ldl",
        algorithm="cholesky_ldl",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bldl\b",
            r"(?i)\bldlt\b",
            r"(?i)\bcholesky\ variant\b",
            r"(?i)\bsymmetric\b",
            r"(?i)\bindefinite\b",
            r"(?i)\bpivoting\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="LDL^T factorization. Cholesky variant without square roots. Works for symmetric indefinite with pivoting.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="eigenvalue_qr_shift",
        algorithm="eigenvalue_qr_shift",
        category="linear_algebra",
        patterns=_compile([
            r"(?i)\bqr\ algorithm\b",
            r"(?i)\bwilkinson\ shift\b",
            r"(?i)\bimplicit\b",
            r"(?i)\bhessenberg\b",
            r"(?i)\beigenvalue\b",
            r"(?i)\bschur\ decomposition\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="QR algorithm with shifts for eigenvalue computation. Wilkinson shift for cubic convergence. Standard for dense matrices.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="inverse_distance_weighting",
        algorithm="inverse_distance_weighting",
        category="interpolation",
        patterns=_compile([
            r"(?i)\bidw\b",
            r"(?i)\binverse\ distance\b",
            r"(?i)\binterpolation\b",
            r"(?i)\bshepard\b",
            r"(?i)\bspatial\b",
            r"(?i)\bscattered\ data\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Inverse Distance Weighting (Shepard's method). Spatial interpolation weighted by inverse distance power p.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="kriging_interpolation",
        algorithm="kriging_interpolation",
        category="interpolation",
        patterns=_compile([
            r"(?i)\bkriging\b",
            r"(?i)\bgaussian\ process\b",
            r"(?i)\bvariogram\b",
            r"(?i)\bsemivariogram\b",
            r"(?i)\bordinary\ kriging\b",
            r"(?i)\bgeostatistics\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Kriging (Gaussian process regression). Best Linear Unbiased Predictor (BLUP) for spatial interpolation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="radial_basis_function",
        algorithm="radial_basis_function",
        category="interpolation",
        patterns=_compile([
            r"(?i)\brbf\b",
            r"(?i)\bradial\ basis\b",
            r"(?i)\bthin\ plate\ spline\b",
            r"(?i)\bmultiquadric\b",
            r"(?i)\bgaussian\ rbf\b",
            r"(?i)\bmeshfree\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Radial Basis Function interpolation. Meshfree method using distance-based basis functions.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="galerkin_weak_form",
        algorithm="galerkin_weak_form",
        category="fea_fundamentals",
        patterns=_compile([
            r"(?i)\bgalerkin\b",
            r"(?i)\bweak\ form\b",
            r"(?i)\bvirtual\ work\b",
            r"(?i)\bvariational\b",
            r"(?i)\bbilinear\ form\b",
            r"(?i)\btest\ function\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Galerkin weak form (principle of virtual work). Foundation of FEM -- weighted residual with test functions from same spa",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mass_lumping",
        algorithm="mass_lumping",
        category="fea_fundamentals",
        patterns=_compile([
            r"(?i)\bmass\ lumping\b",
            r"(?i)\blumped\ mass\b",
            r"(?i)\bdiagonal\ mass\b",
            r"(?i)\brow\ sum\b",
            r"(?i)\bexplicit\ dynamics\b",
            r"(?i)\bhmt\b",
        ]),
        min_matches=2,
        confidence=0.75,
        bonus_per_extra=0.08,
        max_confidence=0.85,
        description="Mass lumping (diagonalization). Creates diagonal mass matrix for efficient explicit time integration.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="mach_number_relations",
        algorithm="mach_number_relations",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bmach\b",
            r"(?i)\bisentropic\b",
            r"(?i)\bstagnation\b",
            r"(?i)\btotal\ pressure\b",
            r"(?i)\btotal\ temperature\b",
            r"(?i)\bcompressible\ flow\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Isentropic flow relations. Stagnation-to-static ratios as functions of Mach number for compressible flow.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="normal_shock_relations",
        algorithm="normal_shock_relations",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bnormal\ shock\b",
            r"(?i)\brankine\ hugoniot\b",
            r"(?i)\bshock\ wave\b",
            r"(?i)\bjump\ conditions\b",
            r"(?i)\bentropy\ increase\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Normal shock relations (Rankine-Hugoniot). Post-shock Mach, pressure, temperature, density ratios from pre-shock Mach.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="prandtl_meyer_expansion",
        algorithm="prandtl_meyer_expansion",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bprandtl\ meyer\b",
            r"(?i)\bexpansion\ fan\b",
            r"(?i)\bsupersonic\b",
            r"(?i)\bturning\ angle\b",
            r"(?i)\bisentropic\ expansion\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Prandtl-Meyer expansion function. Relates Mach number to turning angle in supersonic isentropic expansion.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="thin_airfoil_theory",
        algorithm="thin_airfoil_theory",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bthin\ airfoil\b",
            r"(?i)\blift\ coefficient\b",
            r"(?i)\bangle\ of\ attack\b",
            r"(?i)\baerodynamic\ center\b",
            r"(?i)\bquarter\ chord\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Thin airfoil theory. CL = 2*pi*alpha for symmetric airfoil. Aerodynamic center at quarter chord.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="panel_method",
        algorithm="panel_method",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bpanel\ method\b",
            r"(?i)\bsource\b",
            r"(?i)\bdoublet\b",
            r"(?i)\bvortex\ panel\b",
            r"(?i)\bpotential\ flow\b",
            r"(?i)\bhess\ smith\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Panel method for potential flow. Distributes sources/doublets on body surface panels. Hess-Smith formulation.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="vortex_lattice_method",
        algorithm="vortex_lattice_method",
        category="aerospace",
        patterns=_compile([
            r"(?i)\bvlm\b",
            r"(?i)\bvortex\ lattice\b",
            r"(?i)\bhorseshoe\ vortex\b",
            r"(?i)\bbiot\ savart\b",
            r"(?i)\blifting\ surface\b",
            r"(?i)\binduced\ drag\b",
        ]),
        min_matches=2,
        confidence=0.78,
        bonus_per_extra=0.08,
        max_confidence=0.88,
        description="Vortex Lattice Method. Models lifting surfaces with horseshoe vortices. Fast aerodynamic analysis for wings.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="gurson_tvergaard_needleman",
        algorithm="gurson_tvergaard_needleman",
        category="fea_damage",
        patterns=_compile([
            r"(?i)\bgurson\b",
            r"(?i)\bgtn\b",
            r"(?i)\bvoid\ growth\b",
            r"(?i)\bdamage\b",
            r"(?i)\bductile\ fracture\b",
            r"(?i)\bporosity\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Gurson-Tvergaard-Needleman (GTN) damage model. Pressure-dependent yield with void volume fraction for ductile fracture.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="johnson_cook_plasticity",
        algorithm="johnson_cook_plasticity",
        category="fea_plasticity",
        patterns=_compile([
            r"(?i)\bjohnson\ cook\b",
            r"(?i)\bstrain\ rate\b",
            r"(?i)\btemperature\b",
            r"(?i)\bdynamic\ plasticity\b",
            r"(?i)\bimpact\b",
            r"(?i)\bhigh\ strain\ rate\b",
        ]),
        min_matches=2,
        confidence=0.85,
        bonus_per_extra=0.08,
        max_confidence=0.95,
        description="Johnson-Cook plasticity model. Empirical model for strain hardening, strain rate, and temperature effects. Used for impa",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="rankine_hugoniot",
        algorithm="rankine_hugoniot",
        category="cfd_shock",
        patterns=_compile([
            r"(?i)\brankine\ hugoniot\b",
            r"(?i)\bjump\ conditions\b",
            r"(?i)\bshock\b",
            r"(?i)\bconservation\b",
            r"(?i)\bdiscontinuity\b",
        ]),
        min_matches=2,
        confidence=0.80,
        bonus_per_extra=0.08,
        max_confidence=0.90,
        description="Rankine-Hugoniot jump conditions across a shock wave. Conservation of mass, momentum, energy across discontinuity.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),

    StructuralPattern(
        name="spalding_law",
        algorithm="spalding_law",
        category="cfd_turbulence",
        patterns=_compile([
            r"(?i)\bspalding\b",
            r"(?i)\buniversal\ wall\ law\b",
            r"(?i)\bcontinuous\b",
            r"(?i)\bviscous\ sublayer\b",
            r"(?i)\blog\ layer\b",
            r"(?i)\bcomposite\ profile\b",
        ]),
        min_matches=2,
        confidence=0.82,
        bonus_per_extra=0.08,
        max_confidence=0.92,
        description="Spalding's single-formula wall law. Continuous composite profile covering viscous sublayer through log layer.",
        false_positive_note="Keyword match only -- verify with constant/structural analysis",
    ),
]
