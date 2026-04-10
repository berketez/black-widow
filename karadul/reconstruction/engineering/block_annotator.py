"""Muhendislik baglami iceren blok yorumlari ekler.

Decompile edilmis C kodundaki dongu yapilarini, yakinsama kontrollerini,
matris assembly islemlerini, bellek operasyonlarini, cagri referanslarini
ve dongu amaclarini tespit ederek uygun yorum bloklari ekler.

Mevcut CCommentGenerator'dan farki: fonksiyon seviyesinde degil,
KOD BLOKU seviyesinde calisir. Loop iceriklerini, convergence check'leri,
scatter/gather pattern'leri satirsal olarak isler.

6 dedector:
1. Algorithm Block Detector    -- tespit edilen algoritma icin header kutusu
2. Convergence Check Detector  -- while/if + tolerance karsilastirmalari
3. Assembly Operation Detector -- scatter/gather (element -> global)
4. Memory Operation Detector   -- malloc/calloc/memcpy pattern'leri
5. Cross-Reference Annotator   -- caller/callee bilgisi
6. Loop Purpose Detector       -- dongu tipi (element, DOF, Gauss, cell, face)

Kullanim:
    from karadul.reconstruction.engineering.block_annotator import CodeBlockAnnotator
    annotator = CodeBlockAnnotator(config)
    result = annotator.annotate(
        decompiled_dir, functions_json, call_graph_json, output_dir,
        algorithm_matches=algos, domain_report=report,
    )
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.engineering.domain_classifier import (
    DomainClassification,
    DomainClassifier,
    DomainReport,
)
from karadul.reconstruction.engineering.formula_reconstructor import (
    FORMULA_TEMPLATES,
    FormulaInfo,
    FormulaReconstructor,
)

logger = logging.getLogger(__name__)

# Ghidra decompile ciktisi fonksiyon baslangic pattern'i
_FUNC_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Box genisligi (karakter)
_BOX_WIDTH = 64

# Minimum confidence -- bu degerin altindaki annotation'lar atilir
_MIN_ANNOTATION_CONFIDENCE = 0.30


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BlockAnnotation:
    """Tek bir kod bloku yorumu.

    Attributes:
        annotation_type: Yorum tipi.
            "algorithm_header" | "convergence_check" | "assembly_op" |
            "memory_op" | "cross_ref" | "loop_purpose"
        text: Eklenecek yorum metni (// ile baslar).
        line_number: Ekleme noktasi (0-indexed, bu satirdan ONCE eklenir).
        confidence: Tespit guveni 0.0-1.0.
        algorithm: Iliskili algoritma adi (varsa).
        domain: Iliskili muhendislik alani (varsa).
        source: Hangi dedector uretti.
    """
    annotation_type: str
    text: str
    line_number: int
    confidence: float
    algorithm: str | None = None
    domain: str | None = None
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "annotation_type": self.annotation_type,
            "text": self.text,
            "line_number": self.line_number,
            "confidence": round(self.confidence, 3),
            "source": self.source,
        }
        if self.algorithm:
            d["algorithm"] = self.algorithm
        if self.domain:
            d["domain"] = self.domain
        return d


@dataclass
class AnnotatedFunction:
    """Blok yorumlari eklenmis fonksiyon.

    Attributes:
        function_name: Fonksiyon adi.
        annotations: Bu fonksiyona ait blok yorumlari.
        algorithm_context: Fonksiyonda tespit edilen algoritma (varsa).
        domain: Fonksiyonun muhendislik alani (varsa).
    """
    function_name: str
    annotations: list[BlockAnnotation] = field(default_factory=list)
    algorithm_context: str | None = None
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "annotation_count": len(self.annotations),
            "algorithm_context": self.algorithm_context,
            "domain": self.domain,
            "annotations": [a.to_dict() for a in self.annotations],
        }


@dataclass
class AnnotationResult:
    """Blok annotation sonucu.

    Attributes:
        success: Islem basarili mi.
        total_annotations: Toplam eklenen yorum sayisi.
        by_type: annotation_type -> sayi.
        annotated_files: Olusturulan cikti dosya yollari.
        annotated_functions: Fonksiyon bazli annotation detaylari.
        errors: Hata mesajlari.
    """
    success: bool
    total_annotations: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    annotated_files: list[Path] = field(default_factory=list)
    annotated_functions: list[AnnotatedFunction] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "total_annotations": self.total_annotations,
            "by_type": self.by_type,
            "annotated_files": [str(p) for p in self.annotated_files],
            "annotated_functions": [f.to_dict() for f in self.annotated_functions],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Convergence check patterns
# ---------------------------------------------------------------------------

CONVERGENCE_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # if (fabs(x - y) < tol) break
    (
        re.compile(r"if\s*\(\s*fabs\s*\(\s*(\w+)\s*-\s*(\w+)\s*\)\s*<\s*(\w+)"),
        "Convergence check: |{0} - {1}| < {2}",
        0.85,
    ),
    # if (norm < tolerance) break
    (
        re.compile(
            r"if\s*\(\s*(norm\w*|residual\w*|error\w*|delta\w*|err\w*)\s*<\s*"
            r"(tol\w*|eps\w*|thresh\w*|convergence\w*)"
        ),
        "Convergence test: {0} < {1}",
        0.90,
    ),
    # while (err > tol) -- iteration continues
    (
        re.compile(
            r"while\s*\(\s*(norm\w*|residual\w*|error\w*|delta\w*|err\w*)\s*>\s*"
            r"(tol\w*|eps\w*|thresh\w*)"
        ),
        "Iteration loop: continue while {0} > {1}",
        0.88,
    ),
    # do { ... } while (delta > threshold)
    (
        re.compile(
            r"while\s*\(\s*(\w+)\s*>\s*(tol\w*|eps\w*|thresh\w*|1e-\d+|0\.0+\d)"
        ),
        "Iteration continues while {0} > {1}",
        0.82,
    ),
    # Generic: if (x < SMALL_NUMBER) break
    (
        re.compile(r"if\s*\(\s*(\w+)\s*<\s*(1e-\d+|0\.0+\d+)\s*\).*break"),
        "Convergence test: {0} < {1}",
        0.70,
    ),
    # fabs(residual) < tol
    (
        re.compile(r"fabs\s*\(\s*(\w+)\s*\)\s*<\s*(\w+)"),
        "Absolute convergence: |{0}| < {1}",
        0.75,
    ),
    # sqrt(sum) < tol  (L2 norm check)
    (
        re.compile(r"sqrt\s*\(\s*(\w+)\s*\)\s*<\s*(\w+)"),
        "L2 norm convergence: sqrt({0}) < {1}",
        0.72,
    ),
    # iter >= max_iter (iteration limit)
    (
        re.compile(
            r"(iter\w*|iteration\w*|icount\w*)\s*>=?\s*(max_iter\w*|maxiter\w*|MAXITER|niter)"
        ),
        "Iteration limit: {0} >= {1}",
        0.65,
    ),
]


# ---------------------------------------------------------------------------
# Assembly operation patterns
# ---------------------------------------------------------------------------

ASSEMBLY_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # K[global_dof] += K_e[local]  (scatter)
    (
        re.compile(r"(\w+)\s*\[([^]]*)\]\s*\+=\s*(\w+)\s*\["),
        "Assembly: {0}[global] += {2}[local]",
        0.80,
    ),
    # *(ptr + offset) += value  (pointer arithmetic scatter)
    (
        re.compile(r"\*\s*\(\s*(\w+)\s*\+[^)]+\)\s*\+="),
        "Scatter to global via pointer: {0}",
        0.72,
    ),
    # Double nested DOF loop: for(i..ndof) for(j..ndof)
    (
        re.compile(
            r"for\s*\([^)]*\b(ndof|dof|neq)\b[^)]*\)\s*\{[^{}]*"
            r"for\s*\([^)]*\b(ndof|dof|neq)\b",
            re.DOTALL,
        ),
        "DOF-DOF double loop (stiffness assembly)",
        0.85,
    ),
    # matrix[i*n + j] = ...  (row-major storage pattern)
    (
        re.compile(r"(\w+)\s*\[\s*(\w+)\s*\*\s*(\w+)\s*\+\s*(\w+)\s*\]"),
        "Row-major matrix access: {0}[{1}*{2} + {3}]",
        0.60,
    ),
    # sum += A[k] * B[k]  (dot product)
    (
        re.compile(
            r"(\w+)\s*\+=\s*(\w+)\s*\[[^]]+\]\s*\*\s*(\w+)\s*\[",
        ),
        "Dot product accumulation: {0} += {1}[k] * {2}[k]",
        0.65,
    ),
]


# ---------------------------------------------------------------------------
# Memory operation patterns
# ---------------------------------------------------------------------------

MEMORY_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # malloc(n * sizeof(double))
    (
        re.compile(
            r"(\w+)\s*=\s*\(?.*\)?\s*malloc\s*\(\s*(.+?)\s*\)"
        ),
        "Allocate heap memory: {0} = malloc({1})",
        0.90,
    ),
    # calloc(n, sizeof(double))
    (
        re.compile(
            r"(\w+)\s*=\s*\(?.*\)?\s*calloc\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)"
        ),
        "Allocate zeroed memory: {0} = calloc({1}, {2})",
        0.90,
    ),
    # realloc
    (
        re.compile(
            r"(\w+)\s*=\s*\(?.*\)?\s*realloc\s*\(\s*(\w+)\s*,"
        ),
        "Reallocate: {0} = realloc({1}, ...)",
        0.85,
    ),
    # free(ptr)
    (
        re.compile(r"free\s*\(\s*(\w+)\s*\)"),
        "Free: release {0}",
        0.90,
    ),
    # memcpy(dst, src, n)
    (
        re.compile(
            r"memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
        ),
        "Copy memory: {0} <- {1}, size={2}",
        0.88,
    ),
    # memset(ptr, val, n)
    (
        re.compile(
            r"memset\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
        ),
        "Zero/fill memory: {0} set to {1}, size={2}",
        0.85,
    ),
    # memmove
    (
        re.compile(
            r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
        ),
        "Move memory (overlap-safe): {0} <- {1}, size={2}",
        0.85,
    ),
]


# ---------------------------------------------------------------------------
# Loop purpose patterns -- domain-aware
# ---------------------------------------------------------------------------

# Generic loop patterns (her domain icin)
GENERIC_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # for(i=0; i<N; i++) -- generic counted loop
    (
        re.compile(r"for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;"),
        "Counted loop (N={0})",
        0.40,
    ),
    # while(iter < max) -- iteration loop
    (
        re.compile(r"while\s*\(\s*(iter\w*|count\w*|step\w*)\s*<\s*(\w+)"),
        "Iteration loop: {0} < {1}",
        0.70,
    ),
    # do { ... } while(condition)
    (
        re.compile(r"do\s*\{"),
        "do-while loop",
        0.35,
    ),
]

# Structural mechanics domain loop patterns
STRUCTURAL_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(elem|nel|num_e|nelem)"),
        "Element loop (iterating over mesh elements)",
        0.88,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(gauss|ngp|nip|n_int|mint)"),
        "Gauss point loop (numerical integration)",
        0.90,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(ndof|dof|neq|n_dof)"),
        "DOF loop (degrees of freedom)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nnode|nnp|npe|n_node)"),
        "Node loop (mesh nodes)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*3\s*;"),
        "Spatial dimension loop (3D: x,y,z)",
        0.55,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*6\s*;"),
        "Voigt notation loop (6 stress/strain components)",
        0.60,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*(8|20|27)\s*;"),
        "Element node loop (hex element: {0} nodes)",
        0.65,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*(4|9)\s*;"),
        "Element node loop (quad element: {0} nodes)",
        0.55,
    ),
]

# Fluid dynamics domain loop patterns
FLUID_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(ncell|n_cell|num_cell)"),
        "Cell loop (iterating over mesh cells)",
        0.88,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nface|n_face|num_face)"),
        "Face loop (iterating over cell faces)",
        0.88,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nbnd|n_bnd|num_bound)"),
        "Boundary loop (iterating over boundary faces)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(dim|ndim|n_dim)"),
        "Spatial dimension loop",
        0.60,
    ),
]

# Thermal domain loop patterns
THERMAL_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(elem|nel|num_e)"),
        "Element loop (thermal elements)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nnode|nnp)"),
        "Node loop (temperature DOFs)",
        0.82,
    ),
]

# DSP domain loop patterns
DSP_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nsamp|n_sample|nfft|fft_len)"),
        "Sample loop (signal processing)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nfreq|n_freq|n_bin)"),
        "Frequency bin loop",
        0.82,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(ntap|n_tap|n_coeff)"),
        "Filter tap loop (FIR/IIR coefficient application)",
        0.85,
    ),
]

# Finance domain loop patterns
FINANCE_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(n_path|npath|nsim|n_sim)"),
        "Monte Carlo path loop",
        0.88,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(nstep|n_step|n_time)"),
        "Time step loop (price evolution)",
        0.70,
    ),
]

# ML domain loop patterns
ML_LOOP_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(batch|n_batch|batch_size)"),
        "Batch loop (mini-batch processing)",
        0.85,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(epoch|n_epoch)"),
        "Epoch loop (training iteration)",
        0.88,
    ),
    (
        re.compile(r"for\s*\([^)]*=\s*0\s*;[^)]*<\s*\w*(n_layer|nlayer|num_layer)"),
        "Layer loop (neural network forward/backward pass)",
        0.85,
    ),
]

# Domain -> patterns mapping
DOMAIN_LOOP_PATTERNS: dict[str, list[tuple[re.Pattern, str, float]]] = {
    "structural": STRUCTURAL_LOOP_PATTERNS,
    "fluid": FLUID_LOOP_PATTERNS,
    "thermal": THERMAL_LOOP_PATTERNS,
    "dsp": DSP_LOOP_PATTERNS,
    "finance": FINANCE_LOOP_PATTERNS,
    "ml": ML_LOOP_PATTERNS,
}


# ---------------------------------------------------------------------------
# Algorithm block pattern helpers
# ---------------------------------------------------------------------------

# Nested loop depth detector -- kac seviye ic ice for/while/do var
_LOOP_START_RE = re.compile(
    r"^\s*(?:for\s*\(|while\s*\(|do\s*\{)", re.MULTILINE
)

# Known algorithm categories that get header boxes
_ALGORITHM_HEADER_CATEGORIES = {
    "fea_integration", "fea_assembly", "fea_element",
    "iterative_solver", "direct_solver", "convergence",
    "time_integration", "eigenvalue", "stress_analysis",
    "cfd_turbulence", "cfd_discretization",
    "heat_transfer",
    "dsp_transform", "dsp_filter", "dsp_window",
    "finance_pricing", "finance_risk", "finance_greeks", "monte_carlo",
    "ml_activation", "ml_optimizer", "ml_layer",
    "optimization_gradient", "optimization_search",
    "linear_algebra", "sparse_matrix",
}

# Cross-reference format templates
XREF_TEMPLATES = {
    "called_by": "// -> Called by: {callers}",
    "calls":     "// -> Calls: {callees}",
    "related":   "// -> Related: {related}",
}


# ---------------------------------------------------------------------------
# Helper: box comment formatter
# ---------------------------------------------------------------------------

def _make_box_comment(
    title: str,
    formula_ascii: str | None = None,
    extra_lines: list[str] | None = None,
    width: int = _BOX_WIDTH,
) -> str:
    """Unicode box yorum olusturur.

    Ornek cikti:
        // ==================================================================
        // ||  NEWTON-RAPHSON NONLINEAR SOLVER                              ||
        // ||  x_{n+1} = x_n - J^{-1} . F(x_n)                            ||
        // ||  Confidence: 0.88                                             ||
        // ==================================================================
    """
    inner_w = width - 8  # "// ||  " prefix + "  ||" suffix
    lines_out: list[str] = []

    top_bottom = "// " + "=" * (width - 3)
    lines_out.append(top_bottom)

    def _pad_line(text: str) -> str:
        if len(text) > inner_w:
            text = text[: inner_w - 3] + "..."
        return f"// ||  {text:<{inner_w}}  ||"

    lines_out.append(_pad_line(title))

    if formula_ascii:
        lines_out.append(_pad_line(formula_ascii))

    if extra_lines:
        for extra in extra_lines:
            lines_out.append(_pad_line(extra))

    lines_out.append(top_bottom)

    return "\n".join(lines_out)


def _make_inline_comment(text: str, style: str = "---") -> str:
    """Inline yorum olusturur.

    style:
        "---" -> "// --- text ---"
        "->"  -> "// -> text"
        "plain" -> "// text"
    """
    if style == "---":
        return f"// --- {text} ---"
    elif style == "->":
        return f"// -> {text}"
    else:
        return f"// {text}"


def _get_line_indent(line: str) -> str:
    """Satirin bosluk prefix'ini dondurur."""
    stripped = line.lstrip()
    return line[: len(line) - len(stripped)]


# ---------------------------------------------------------------------------
# CodeBlockAnnotator
# ---------------------------------------------------------------------------

class CodeBlockAnnotator:
    """Muhendislik baglami iceren kod bloku yorumlaricisi.

    Decompile edilmis C kodundaki yapisal pattern'leri tespit edip
    uygun yorum bloklari ekler. 6 bagimsiz dedector calistirir:

    1. Algorithm blocks   -- tespit edilen algoritma icin header kutusu
    2. Convergence checks -- while/if + tolerance karsilastirmalari
    3. Assembly ops       -- scatter/gather (element -> global)
    4. Memory ops         -- malloc/calloc/memcpy pattern'leri
    5. Cross-references   -- caller/callee bilgisi (call graph'ten)
    6. Loop purpose       -- dongu tipi (domain'e gore)
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._formula_reconstructor = FormulaReconstructor()
        self._domain_classifier = DomainClassifier()

    # ==================================================================
    # Public API
    # ==================================================================

    def annotate(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        call_graph_json: Path,
        output_dir: Path,
        *,
        algorithm_matches: list[AlgorithmMatch] | None = None,
        domain_report: DomainReport | None = None,
        enriched_structs: Any | None = None,
    ) -> AnnotationResult:
        """Tum decompile edilmis C dosyalarini analiz edip yorum ekle.

        Args:
            decompiled_dir: Ghidra decompile ciktisinin bulundugu dizin.
            functions_json: Fonksiyon metadata JSON.
            call_graph_json: Cagri grafigi JSON.
            output_dir: Yorumlanmis dosyalarin yazilacagi dizin.
            algorithm_matches: Tespit edilen algoritmalar (opsiyonel).
            domain_report: Domain siniflandirma raporu (opsiyonel).
            enriched_structs: Zenginlestirilmis struct'lar (opsiyonel, Module 1).

        Returns:
            AnnotationResult: Yorum ekleme sonucu.
        """
        errors: list[str] = []
        all_annotated_funcs: list[AnnotatedFunction] = []
        output_files: list[Path] = []

        # Dizin kontrolu
        if not decompiled_dir.exists():
            return AnnotationResult(
                success=False,
                errors=[f"Decompiled directory not found: {decompiled_dir}"],
            )

        output_dir.mkdir(parents=True, exist_ok=True)

        # Metadata yukle
        func_meta = self._load_json(functions_json, errors)
        call_graph = self._load_json(call_graph_json, errors)
        reverse_graph = self._build_reverse_graph(call_graph)

        # Algoritma index: function_name -> [AlgorithmMatch]
        algo_index: dict[str, list[AlgorithmMatch]] = defaultdict(list)
        if algorithm_matches:
            for am in algorithm_matches:
                algo_index[am.function_name].append(am)

        # Domain index: function_name -> primary_domain
        domain_index: dict[str, str] = {}
        if domain_report:
            for dc in domain_report.classifications:
                domain_index[dc.function_name] = dc.primary_domain

        # Formula index: algorithm_name (normalized) -> FormulaInfo
        formula_index: dict[str, FormulaInfo] = {}
        if algorithm_matches:
            formulas = self._formula_reconstructor.reconstruct(algorithm_matches)
            for fi in formulas:
                formula_index[fi.algorithm.lower()] = fi

        # C dosyalarini topla
        c_files = sorted(decompiled_dir.rglob("*.c"))
        if not c_files:
            c_files = sorted(decompiled_dir.rglob("*.h"))
        if not c_files:
            return AnnotationResult(
                success=False,
                errors=errors + ["No C files found in decompiled directory"],
            )

        logger.info(
            "Block annotation: %d files to process",
            len(c_files),
        )

        total_annotations = 0
        by_type: dict[str, int] = defaultdict(int)

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append(f"Cannot read {c_file.name}: {exc}")
                continue

            lines = content.splitlines(keepends=True)
            if not lines:
                continue

            # Fonksiyonlari cikar
            functions = self._extract_functions(content, func_meta, c_file.stem)

            file_annotations: list[BlockAnnotation] = []

            for func_name, func_body, func_start_line, func_addr in functions:
                func_algos = algo_index.get(func_name, [])
                func_domain = domain_index.get(func_name)
                func_lines = func_body.splitlines()

                annotations: list[BlockAnnotation] = []

                # Detector 1: Algorithm blocks
                if func_algos:
                    alg_anns = self._detect_algorithm_blocks(
                        func_lines, func_name, func_algos,
                        formula_index, func_start_line,
                    )
                    annotations.extend(alg_anns)

                # Detector 2: Convergence checks
                conv_anns = self._detect_convergence_checks(
                    func_lines, func_name, func_start_line,
                )
                annotations.extend(conv_anns)

                # Detector 3: Assembly operations
                asm_anns = self._detect_assembly_ops(
                    func_lines, func_name, func_domain, func_start_line,
                )
                annotations.extend(asm_anns)

                # Detector 4: Memory operations
                mem_anns = self._detect_memory_ops(
                    func_lines, func_name, func_start_line,
                )
                annotations.extend(mem_anns)

                # Detector 5: Cross references
                xref_anns = self._generate_cross_refs(
                    func_name, func_addr, call_graph, reverse_graph,
                    func_algos, func_start_line,
                )
                annotations.extend(xref_anns)

                # Detector 6: Loop purpose
                loop_anns = self._detect_loop_purpose(
                    func_lines, func_name, func_domain, func_start_line,
                )
                annotations.extend(loop_anns)

                # Confidence filter
                annotations = [
                    a for a in annotations
                    if a.confidence >= _MIN_ANNOTATION_CONFIDENCE
                ]

                # Deduplicate: ayni satir+tip icin en yuksek confidence'i tut
                annotations = self._deduplicate_annotations(annotations)

                if annotations:
                    algo_ctx = func_algos[0].name if func_algos else None
                    af = AnnotatedFunction(
                        function_name=func_name,
                        annotations=annotations,
                        algorithm_context=algo_ctx,
                        domain=func_domain,
                    )
                    all_annotated_funcs.append(af)
                    file_annotations.extend(annotations)

            # Dosyaya yorum ekle
            if file_annotations:
                annotated_content = self._insert_annotations(
                    lines, file_annotations,
                )
                out_path = output_dir / c_file.name
                try:
                    out_path.write_text(annotated_content, encoding="utf-8")
                    output_files.append(out_path)
                except OSError as exc:
                    errors.append(f"Cannot write {out_path.name}: {exc}")

                for ann in file_annotations:
                    total_annotations += 1
                    by_type[ann.annotation_type] = (
                        by_type.get(ann.annotation_type, 0) + 1
                    )
            else:
                # Degisiklik yok, orijinali kopyala
                out_path = output_dir / c_file.name
                try:
                    out_path.write_text(content, encoding="utf-8")
                    output_files.append(out_path)
                except OSError as exc:
                    errors.append(f"Cannot write {out_path.name}: {exc}")

        # JSON rapor yaz
        report_path = output_dir / "block_annotations.json"
        report_data = {
            "total_annotations": total_annotations,
            "by_type": dict(by_type),
            "annotated_functions": [af.to_dict() for af in all_annotated_funcs],
        }
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        except OSError as exc:
            errors.append(f"Cannot write report: {exc}")

        logger.info(
            "Block annotation complete: %d annotations in %d files (%s)",
            total_annotations,
            len(output_files),
            ", ".join(f"{k}={v}" for k, v in by_type.items()),
        )

        return AnnotationResult(
            success=True,
            total_annotations=total_annotations,
            by_type=dict(by_type),
            annotated_files=output_files,
            annotated_functions=all_annotated_funcs,
            errors=errors,
        )

    # ==================================================================
    # Detector 1: Algorithm Blocks
    # ==================================================================

    def _detect_algorithm_blocks(
        self,
        lines: list[str],
        func_name: str,
        algorithms: list[AlgorithmMatch],
        formula_index: dict[str, FormulaInfo],
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Tespit edilen algoritma icin header box olustur.

        Eger fonksiyonda bilinen bir algoritma tespit edildiyse,
        fonksiyonun ilk satiri oncesine bir kutu yorum ekler.
        Kutuda: algoritma adi, formul (varsa), confidence.

        Ayrica fonksiyon icindeki ilk dongu yapisini bulup
        algoritmaya ozel alt-yorum ekler.
        """
        annotations: list[BlockAnnotation] = []

        # Her algoritma icin bir header box
        for algo in algorithms:
            if algo.category not in _ALGORITHM_HEADER_CATEGORIES:
                continue

            title = algo.name.upper()

            # Formula bul
            formula_text = None
            fi = formula_index.get(algo.name.lower())
            if fi:
                formula_text = fi.ascii
            else:
                # Fuzzy match -- algo.name icinde template key'i ara
                for tkey, tinfo in FORMULA_TEMPLATES.items():
                    if tkey.replace("_", " ") in algo.name.lower():
                        formula_text = tinfo.ascii
                        break

            extra_lines: list[str] = []
            extra_lines.append(f"Confidence: {algo.confidence:.2f}")
            if algo.detection_method:
                extra_lines.append(f"Detection: {algo.detection_method}")

            # FormulaInfo'dan method ve reference ekle
            if fi:
                # Method satiri cok uzun olabilir, kisalt
                method_short = fi.method
                if len(method_short) > 55:
                    method_short = method_short[:52] + "..."
                extra_lines.append(method_short)
                if fi.reference:
                    ref_short = fi.reference
                    if len(ref_short) > 55:
                        ref_short = ref_short[:52] + "..."
                    extra_lines.append(f"Ref: {ref_short}")

            box = _make_box_comment(title, formula_text, extra_lines)

            annotations.append(BlockAnnotation(
                annotation_type="algorithm_header",
                text=box,
                line_number=func_start_line,
                confidence=algo.confidence,
                algorithm=algo.name,
                domain=None,
                source="algorithm_block_detector",
            ))

            # Fonksiyon icindeki dongu yapilarina algoritma baglami ekle
            loop_anns = self._annotate_algo_inner_loops(
                lines, algo, func_start_line,
            )
            annotations.extend(loop_anns)

        return annotations

    def _annotate_algo_inner_loops(
        self,
        lines: list[str],
        algo: AlgorithmMatch,
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Algoritma icin fonksiyon icindeki dongu yapilarini yorumla.

        Gauss quadrature -> "Gauss point loop (integration point i)"
        Newton-Raphson   -> "Newton iteration loop"
        CG/GMRES/BiCGSTAB -> "Krylov iteration loop"
        """
        annotations: list[BlockAnnotation] = []
        algo_lower = algo.name.lower()

        # Hangi tur dongu ariyoruz
        loop_label = None
        if "gauss" in algo_lower or "quadrature" in algo_lower:
            loop_label = "Gauss point loop (integration point)"
        elif "newton" in algo_lower:
            loop_label = "Newton iteration loop"
        elif any(kw in algo_lower for kw in ("conjugate", "cg ", "gmres", "bicgstab", "krylov")):
            loop_label = "Krylov solver iteration"
        elif "newmark" in algo_lower or "hht" in algo_lower:
            loop_label = "Time integration step"
        elif "runge" in algo_lower or "rk4" in algo_lower:
            loop_label = "Runge-Kutta stage evaluation"
        elif any(kw in algo_lower for kw in ("lu ", "cholesky", "factori")):
            loop_label = "Matrix factorization loop"
        elif "eigenvalue" in algo_lower or "qr " in algo_lower:
            loop_label = "Eigenvalue iteration"
        elif any(kw in algo_lower for kw in ("k-epsilon", "k-omega", "sst", "turbul")):
            loop_label = "Turbulence model evaluation"
        elif "fft" in algo_lower:
            loop_label = "FFT butterfly stage"

        if loop_label is None:
            return annotations

        # Ilk dongu yapisini bul
        depth = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r"(for|while|do)\s*[\({]", stripped):
                if depth == 0:
                    annotations.append(BlockAnnotation(
                        annotation_type="algorithm_header",
                        text=_make_inline_comment(loop_label),
                        line_number=func_start_line + i,
                        confidence=algo.confidence * 0.9,
                        algorithm=algo.name,
                        source="algorithm_block_detector",
                    ))
                    # Sadece ilk iki seviye
                    depth += 1
                    if depth >= 2:
                        break
                else:
                    depth += 1
                    if depth >= 2:
                        break

        return annotations

    # ==================================================================
    # Detector 2: Convergence Checks
    # ==================================================================

    def _detect_convergence_checks(
        self,
        lines: list[str],
        func_name: str,
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Yakinsama kontrolu pattern'lerini tespit et.

        if/while satirlarinda tolerance karsilastirmalarini arar.
        Capture group'lardan degisken isimlerini cikarip okunaklir
        yorum olusturur.
        """
        annotations: list[BlockAnnotation] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Bos satir veya yorum satiriysa atla
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pattern, template, base_conf in CONVERGENCE_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    # Template'i capture group'lariyla doldur
                    groups = m.groups()
                    try:
                        text = template.format(*groups)
                    except (IndexError, KeyError):
                        text = template

                    indent = _get_line_indent(line)
                    comment = f"{indent}{_make_inline_comment(text)}"

                    annotations.append(BlockAnnotation(
                        annotation_type="convergence_check",
                        text=comment,
                        line_number=func_start_line + i,
                        confidence=base_conf,
                        source="convergence_detector",
                    ))
                    break  # Satir basina tek annotation

        return annotations

    # ==================================================================
    # Detector 3: Assembly Operations
    # ==================================================================

    def _detect_assembly_ops(
        self,
        lines: list[str],
        func_name: str,
        domain: str | None,
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Global matris/vektor assembly pattern'lerini tespit et.

        Scatter/gather operasyonlarini, dot product'lari, row-major
        matris erisimlerini bulur. Domain'e gore terminoloji degisir:
        structural -> "K[dof_i][dof_j] += K_e"
        fluid -> "flux[face] += ..."
        """
        annotations: list[BlockAnnotation] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pattern, template, base_conf in ASSEMBLY_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    groups = m.groups()
                    try:
                        text = template.format(*groups)
                    except (IndexError, KeyError):
                        text = template

                    # Domain baglami ekle
                    if domain == "structural":
                        text = f"Global assembly: {text}"
                    elif domain == "fluid":
                        text = f"Flux/residual assembly: {text}"
                    elif domain:
                        text = f"Assembly ({domain}): {text}"

                    indent = _get_line_indent(line)
                    comment = f"{indent}{_make_inline_comment(text)}"

                    annotations.append(BlockAnnotation(
                        annotation_type="assembly_op",
                        text=comment,
                        line_number=func_start_line + i,
                        confidence=base_conf,
                        domain=domain,
                        source="assembly_detector",
                    ))
                    break

        return annotations

    # ==================================================================
    # Detector 4: Memory Operations
    # ==================================================================

    def _detect_memory_ops(
        self,
        lines: list[str],
        func_name: str,
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Bellek ayirma/birakma pattern'lerini tespit et.

        malloc/calloc/realloc/free/memcpy/memset satirlarini bulur
        ve ne amacla kullanildigini yorumlar.
        """
        annotations: list[BlockAnnotation] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pattern, template, base_conf in MEMORY_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    groups = m.groups()
                    try:
                        text = template.format(*groups)
                    except (IndexError, KeyError):
                        text = template

                    # Boyut hesaplama ipuclari ekle
                    if "sizeof" in stripped:
                        sizeof_m = re.search(r"sizeof\s*\(\s*(\w+)\s*\)", stripped)
                        if sizeof_m:
                            text += f" [type: {sizeof_m.group(1)}]"

                    indent = _get_line_indent(line)
                    comment = f"{indent}{_make_inline_comment(text, style='plain')}"

                    annotations.append(BlockAnnotation(
                        annotation_type="memory_op",
                        text=comment,
                        line_number=func_start_line + i,
                        confidence=base_conf,
                        source="memory_detector",
                    ))
                    break

        return annotations

    # ==================================================================
    # Detector 5: Cross References
    # ==================================================================

    def _generate_cross_refs(
        self,
        func_name: str,
        func_addr: str,
        call_graph: dict[str, Any],
        reverse_graph: dict[str, list[str]],
        algorithms: list[AlgorithmMatch],
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Cagri grafigi'nden cross-reference yorumlari olustur.

        Fonksiyonun basina caller/callee bilgisi ekler.
        Callee'lerin tespit edilen algoritmalari da gosterilir.
        """
        annotations: list[BlockAnnotation] = []

        # Callers (kim cagiriyor)
        callers = reverse_graph.get(func_name, [])

        # Callees (kimi cagiriyor)
        callees_raw = call_graph.get(func_name, [])
        # call_graph bazen list[str] bazen list[dict] olabilir
        callees: list[str] = []
        if isinstance(callees_raw, list):
            for c in callees_raw:
                if isinstance(c, str):
                    callees.append(c)
                elif isinstance(c, dict):
                    callees.append(c.get("name", c.get("callee", str(c))))

        # Caller yoksa callee de yoksa skip
        if not callers and not callees:
            return annotations

        # Function header
        xref_lines: list[str] = []
        xref_lines.append(f"// Function: {func_name} ({func_addr})")

        if callers:
            # En fazla 5 caller goster
            shown = callers[:5]
            caller_str = ", ".join(shown)
            if len(callers) > 5:
                caller_str += f" (+{len(callers) - 5} more)"
            xref_lines.append(f"// -> Called by: {caller_str}")

        if callees:
            # Callee'lere algoritma bilgisi ekle
            callee_parts: list[str] = []
            for cname in callees[:8]:
                # Bu callee icin bilinen algoritma var mi
                algo_hint = ""
                # Bilinen fonksiyon isimleri icin ipucu
                lower = cname.lower()
                if any(kw in lower for kw in ("shape", "shp")):
                    algo_hint = " (shape functions)"
                elif any(kw in lower for kw in ("dgetrs", "dgesv", "dposv")):
                    algo_hint = " (LAPACK solve)"
                elif any(kw in lower for kw in ("dgemm", "dgemv", "dsymm")):
                    algo_hint = " (BLAS matrix op)"
                elif any(kw in lower for kw in ("malloc", "calloc", "free")):
                    algo_hint = " (memory)"
                elif "jacobian" in lower or "tangent" in lower:
                    algo_hint = " (tangent matrix)"
                elif "residual" in lower:
                    algo_hint = " (residual vector)"
                elif "assem" in lower:
                    algo_hint = " (assembly)"
                elif "boundary" in lower or "bc" in lower:
                    algo_hint = " (boundary conditions)"
                callee_parts.append(f"{cname}{algo_hint}")

            callee_str = ", ".join(callee_parts)
            if len(callees) > 8:
                callee_str += f" (+{len(callees) - 8} more)"
            xref_lines.append(f"// -> Calls: {callee_str}")

        # Caller chain: main -> solve -> this_function (depth 3)
        chain = self._find_call_chain(func_name, reverse_graph, max_depth=3)
        if chain and len(chain) > 1:
            chain_str = " -> ".join(reversed(chain))
            xref_lines.append(f"// -> Call chain: {chain_str}")

        text = "\n".join(xref_lines)

        annotations.append(BlockAnnotation(
            annotation_type="cross_ref",
            text=text,
            line_number=func_start_line,
            confidence=0.95,
            source="cross_ref_detector",
        ))

        return annotations

    def _find_call_chain(
        self,
        func_name: str,
        reverse_graph: dict[str, list[str]],
        max_depth: int = 3,
    ) -> list[str]:
        """Cagri zincirini geriye dogru takip et.

        func_name'den baslayip callers'i izleyerek kok fonksiyona ulasir.
        Max depth ile sinirlidir (sonsuz dongu korunmasi).
        """
        chain: list[str] = [func_name]
        visited: set[str] = {func_name}
        current = func_name

        for _ in range(max_depth):
            callers = reverse_graph.get(current, [])
            if not callers:
                break
            # En yaygini (veya ilki) sec
            next_caller = callers[0]
            if next_caller in visited:
                break
            visited.add(next_caller)
            chain.append(next_caller)
            current = next_caller

        return chain

    # ==================================================================
    # Detector 6: Loop Purpose
    # ==================================================================

    def _detect_loop_purpose(
        self,
        lines: list[str],
        func_name: str,
        domain: str | None,
        func_start_line: int,
    ) -> list[BlockAnnotation]:
        """Dongu amacini tespit et.

        Domain'e gore uygun pattern listesini kullanir:
        - structural: element, DOF, Gauss, node loop'lari
        - fluid: cell, face, boundary loop'lari
        - generic: counted loop, iteration loop

        Body content'ten de ipucu cikarir (orn. ici "*=" ise accumulation).
        """
        annotations: list[BlockAnnotation] = []
        already_annotated_lines: set[int] = set()

        # Domain-specific pattern'leri sec
        domain_patterns = DOMAIN_LOOP_PATTERNS.get(domain or "", [])

        # Tum pattern listesi: domain-specific + generic
        all_patterns = domain_patterns + GENERIC_LOOP_PATTERNS

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Sadece dongu satirlarini kontrol et
            if not re.match(r"(for|while|do)\s*[\({]", stripped):
                continue

            abs_line = func_start_line + i
            if abs_line in already_annotated_lines:
                continue

            best_match: tuple[str, float] | None = None

            for pattern, label_template, base_conf in all_patterns:
                m = pattern.search(stripped)
                if m:
                    groups = m.groups()
                    try:
                        label = label_template.format(*groups)
                    except (IndexError, KeyError):
                        label = label_template

                    if best_match is None or base_conf > best_match[1]:
                        best_match = (label, base_conf)

            if best_match is not None:
                label, conf = best_match

                # Body analysis ile confidence boost
                # Donguden sonraki birka satirda accumulation (+=) varsa
                # assembly/integration loop olabilir
                body_boost = self._analyze_loop_body(lines, i)
                conf = min(0.98, conf + body_boost)

                indent = _get_line_indent(line)
                comment = f"{indent}{_make_inline_comment(label)}"

                annotations.append(BlockAnnotation(
                    annotation_type="loop_purpose",
                    text=comment,
                    line_number=abs_line,
                    confidence=conf,
                    domain=domain,
                    source="loop_purpose_detector",
                ))
                already_annotated_lines.add(abs_line)

        return annotations

    @staticmethod
    def _analyze_loop_body(lines: list[str], loop_start: int) -> float:
        """Dongu body'sini analiz edip confidence boost hesapla.

        Dongu iceriginde:
        - += operatoru varsa (accumulation) -> +0.05
        - matris indexleme ([i*n+j]) varsa -> +0.05
        - fonksiyon cagrisi varsa -> +0.03
        """
        boost = 0.0
        depth = 0
        body_lines = 0
        max_body = 20  # En fazla 20 satir incele

        for j in range(loop_start, min(loop_start + max_body + 5, len(lines))):
            line = lines[j]
            depth += line.count("{") - line.count("}")

            if j > loop_start and depth <= 0:
                break

            if j > loop_start:
                body_lines += 1
                s = line.strip()
                if "+=" in s:
                    boost += 0.05
                if re.search(r"\w+\s*\[\s*\w+\s*\*", s):
                    boost += 0.05
                if re.search(r"\w+\s*\(", s) and not s.startswith("//"):
                    boost += 0.03

        return min(0.15, boost)

    # ==================================================================
    # Code Insertion Engine
    # ==================================================================

    def _insert_annotations(
        self,
        lines: list[str],
        annotations: list[BlockAnnotation],
    ) -> str:
        """Annotation yorumlarini koda ekle.

        Satirlari ters sirada (asagidan yukariya) isler, boylece
        ekleme sonrasi satir numaralari kaymaz.

        Args:
            lines: Orijinal dosyanin satirlari (keepends=True).
            annotations: Eklenecek yorumlar.

        Returns:
            Yorumlanmis dosya icerigi.
        """
        if not annotations:
            return "".join(lines)

        # Ters sirada islemek icin line_number'a gore azalan sirala
        sorted_anns = sorted(annotations, key=lambda a: -a.line_number)

        # Ayni satira birden fazla annotation varsa, bunlari grupla
        # ve tek seferde ekle (annotation'larin kendi sirasini koru)
        grouped: dict[int, list[BlockAnnotation]] = defaultdict(list)
        for ann in sorted_anns:
            grouped[ann.line_number].append(ann)

        # Ters satir sirasi ile ekle
        result_lines = list(lines)

        for line_num in sorted(grouped.keys(), reverse=True):
            group = grouped[line_num]
            # Bu gruptaki annotation'lari tip onceligi ile sirala:
            # cross_ref ve algorithm_header once gelsin
            priority = {
                "cross_ref": 0,
                "algorithm_header": 1,
                "loop_purpose": 2,
                "convergence_check": 3,
                "assembly_op": 4,
                "memory_op": 5,
            }
            group.sort(key=lambda a: priority.get(a.annotation_type, 9))

            # Ekleme noktasini belirle
            insert_idx = min(line_num, len(result_lines))

            # Mevcut yorum mu kontrol et (cift eklemeyi onle)
            insert_text_parts: list[str] = []
            for ann in group:
                ann_text = ann.text
                # Zaten dosyada var mi kontrol et
                if insert_idx > 0 and insert_idx <= len(result_lines):
                    prev_line = result_lines[insert_idx - 1].strip() if insert_idx > 0 else ""
                    first_ann_line = ann_text.strip().split("\n")[0].strip()
                    if first_ann_line and first_ann_line in prev_line:
                        continue  # Cift eklemeyi onle

                # Satir sonu uyumu: orijinal satirlarin newline stiline uy
                if not ann_text.endswith("\n"):
                    ann_text += "\n"
                insert_text_parts.append(ann_text)

            if insert_text_parts:
                combined = "".join(insert_text_parts)
                new_lines = combined.splitlines(keepends=True)
                for j, new_line in enumerate(reversed(new_lines)):
                    result_lines.insert(insert_idx, new_line)

        return "".join(result_lines)

    # ==================================================================
    # Deduplication
    # ==================================================================

    @staticmethod
    def _deduplicate_annotations(
        annotations: list[BlockAnnotation],
    ) -> list[BlockAnnotation]:
        """Ayni satir ve tip kombinasyonu icin en yuksek confidence'i tut.

        Ayni satira birden fazla ayni tipte annotation eklenmesini onler.
        Farkli tip'ler ayni satira eklenebilir (orn. loop_purpose + convergence).
        """
        best: dict[tuple[int, str], BlockAnnotation] = {}

        for ann in annotations:
            key = (ann.line_number, ann.annotation_type)
            if key not in best or ann.confidence > best[key].confidence:
                best[key] = ann

        return list(best.values())

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _load_json(
        path: Path | None,
        errors: list[str],
    ) -> dict[str, Any]:
        """JSON dosyasini yukle. Hata olursa bos dict dondur."""
        if path is None or not path.exists():
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            if isinstance(data, list):
                result: dict[str, Any] = {}
                for item in data:
                    if isinstance(item, dict):
                        name = item.get("name") or item.get("function_name", "")
                        if name:
                            result[name] = item
                return result
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Cannot load {path}: {exc}")
            return {}

    @staticmethod
    def _build_reverse_graph(
        call_graph: dict[str, Any],
    ) -> dict[str, list[str]]:
        """Call graph'ten ters graf olustur.

        call_graph: {caller: [callee1, callee2, ...]} veya
                    {caller: [{name: callee1}, ...]}

        Dondurur: {callee: [caller1, caller2, ...]}
        """
        reverse: dict[str, list[str]] = defaultdict(list)

        for caller, callees_raw in call_graph.items():
            if not isinstance(callees_raw, (list, tuple)):
                continue
            for c in callees_raw:
                callee_name: str | None = None
                if isinstance(c, str):
                    callee_name = c
                elif isinstance(c, dict):
                    callee_name = c.get("name") or c.get("callee")
                if callee_name and caller not in reverse[callee_name]:
                    reverse[callee_name].append(caller)

        return dict(reverse)

    @staticmethod
    def _extract_functions(
        content: str,
        func_meta: dict[str, Any],
        file_stem: str,
    ) -> list[tuple[str, str, int, str]]:
        """C iceriginden fonksiyonlari cikar.

        Returns:
            List of (func_name, func_body, start_line_number, address).
            start_line_number: fonksiyonun dosyadaki satir numarasi (0-indexed).
        """
        results: list[tuple[str, str, int, str]] = []

        for match in _FUNC_RE.finditer(content):
            func_name = match.group(1)

            # Body cikarma -- brace matching
            body_start = match.end() - 1
            body = _extract_body(content, body_start)

            # Satir numarasi (0-indexed)
            start_line = content[:match.start()].count("\n")

            # Adres
            address = "unknown"
            if func_name in func_meta:
                meta = func_meta[func_name]
                if isinstance(meta, dict):
                    address = meta.get("address", "unknown")
                elif isinstance(meta, str):
                    address = meta
            elif func_name.startswith("FUN_"):
                address = "0x" + func_name[4:]

            results.append((func_name, body, start_line, address))

        # Hic fonksiyon bulunamadiysa tum icerigi tek fonksiyon al
        if not results and content.strip():
            address = "unknown"
            if file_stem in func_meta:
                meta = func_meta[file_stem]
                if isinstance(meta, dict):
                    address = meta.get("address", "unknown")
            elif file_stem.startswith("FUN_"):
                address = "0x" + file_stem[4:]
            results.append((file_stem, content, 0, address))

        return results


# ---------------------------------------------------------------------------
# Body extraction helper (analyzer.py ile ayni mantik)
# ---------------------------------------------------------------------------

def _extract_body(content: str, brace_pos: int) -> str:
    """Suslu parantez eslestirme ile fonksiyon body'sini cikart.

    Maks 10000 karakter okur -- block annotator icin daha buyuk
    fonksiyonlari da islemek gerekiyor (5000 yerine 10000).
    """
    if brace_pos >= len(content) or content[brace_pos] != "{":
        return ""

    depth = 0
    limit = min(brace_pos + 10000, len(content))

    for i in range(brace_pos, limit):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[brace_pos: i + 1]

    return content[brace_pos:limit]
