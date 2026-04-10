"""Algoritma-baglam-bilinçli semantik parametre isimlendirici -- Karadul v1.7.2

Ghidra'nin otomatik parametre isimlerini (param_N, src_N, dest_N) algoritma
tespiti sonuclarina dayanarak anlamli muhendislik isimlerine donusturur.

Alti katmanli strateji (oncelik sirasina gore):
  Strateji 0: Signature-Based Naming       (conf 0.92)  -- v1.7.2: signature_db ile eslesen fonksiyonun bilinen param isimlerini kopyala
  Strateji 1: Algorithm Template Matching  (conf 0.85)  -- Tespit edilen algoritmaya gore sablon
  Strateji 2: Call Graph Propagation       (conf 0.75)  -- Caller'daki isimli arg callee'ye yayilir
  Strateji 3: Struct Field Context         (conf 0.70)  -- Module 1 struct tespitinden isim
  Strateji 4: Type + Usage Heuristic       (conf 0.60)  -- Tip ve kullanim oruntusunden isim
  Strateji 5: Call-Context Naming          (conf 0.65)  -- v1.7.2: Fonksiyonun cagirdigi API'lerden parametre ismi cikarimi

CVariableNamer'dan (c_namer.py) farkli olarak, bu modul fonksiyonun *ne yaptigini*
(algoritma tespiti) bilir ve parametre isimlerini buna gore secer.

Kullanim:
    from karadul.reconstruction.engineering.semantic_namer import SemanticParameterNamer
    from karadul.config import Config

    namer = SemanticParameterNamer(Config())
    result = namer.rename(
        decompiled_dir=Path("workspace/reconstruction/named_c"),
        functions_json=Path("workspace/static/ghidra_functions.json"),
        call_graph_json=Path("workspace/static/ghidra_call_graph.json"),
        output_dir=Path("workspace/reconstruction/semantic_named"),
        algorithm_matches=[...],
    )
"""

from __future__ import annotations

import functools
import json
import logging
import math
import re
import shutil
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config

logger = logging.getLogger(__name__)


def _replace_whole_word(text: str, old: str, new: str) -> str:
    """str.replace gibi hizli ama sadece tam kelime eslesir (word boundary).

    re.sub(r'\\b...\\b') buyuk dosyalarda catastrophic backtracking yapar.
    Bu fonksiyon O(n) garanti eder.
    """
    old_len = len(old)
    if not old_len:
        return text
    result: list[str] = []
    start = 0
    while True:
        idx = text.find(old, start)
        if idx == -1:
            result.append(text[start:])
            break
        if idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        end = idx + old_len
        if end < len(text) and (text[end].isalnum() or text[end] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        result.append(text[start:idx])
        result.append(new)
        start = end
    return "".join(result)


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class ParamTemplate:
    """Algoritma sablon parametresi."""
    position: int
    name: str
    type_hint: str       # "int *", "double *", "long", "int", "double", "void *"
    comment: str


@dataclass
class TypeUsagePattern:
    """Tip + kullanim oruntusunden isim onerisi."""
    c_type: str              # "double *", "int", "long" vb.
    loop_depth: int | None = None       # None = herhangi
    index_pattern: str | None = None    # "sequential", "2d_linear", "random"
    usage_pattern: str | None = None    # "comparison", "increment", "return_value", "single_read"
    name: str = ""
    domain_prefix: dict[str, str] | None = None   # domain -> onek
    confidence: float = 0.60


@dataclass
class SemanticName:
    """Semantik olarak kurtarilmis parametre veya degisken adi."""
    original_name: str          # "param_1", "src_2", "dest_3"
    semantic_name: str          # "K_global", "u_displacement"
    function_name: str          # "FUN_00401000" veya "newton_raphson_solve"
    confidence: float           # 0.0 - 1.0
    source: str                 # "algorithm_template" | "call_graph_propagation" | "type_heuristic" | "struct_context"
    reason: str                 # Insan-okunur aciklama
    domain: str                 # "structural", "fluid", "generic" vb.


@dataclass
class SemanticNamingResult:
    """Semantik parametre isimlendirme tam sonucu."""
    success: bool
    names: list[SemanticName] = field(default_factory=list)
    total_renamed: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    by_domain: dict[str, int] = field(default_factory=dict)
    output_files: list[Path] = field(default_factory=list)
    naming_map: dict[str, dict[str, str]] = field(default_factory=dict)  # func -> {old: new}
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ghidra otomatik isim tanima (c_namer.py ile uyumlu)
# ---------------------------------------------------------------------------

_GHIDRA_AUTO_PARAM = re.compile(r"^param_\d+$")
_GHIDRA_AUTO_SRC = re.compile(r"^src_\d+$")
_GHIDRA_AUTO_DEST = re.compile(r"^dest_\d+$")
_GHIDRA_AUTO_LOCAL = re.compile(r"^local_[0-9a-fA-F]+$")
_GHIDRA_AUTO_VAR = re.compile(r"^[a-z]Var\d+$")
_GHIDRA_AUTO_IN = re.compile(r"^in_\w+$")

# CVariableNamer tarafindan atanmis dusuk-kaliteli genel isimler
# Bunlari da yeniden isimlendirmek istiyoruz (sadece algoritma sablonu varsa)
_GENERIC_NAMER_NAMES = re.compile(
    r"^(buffer|data|ptr|value|result|arg|output|input|size|count|len|flag)(_\d+)?$"
)


def _is_auto_or_generic_name(name: str) -> bool:
    """Isim Ghidra otomatik veya dusuk-kaliteli genel isim mi."""
    return bool(
        _GHIDRA_AUTO_PARAM.match(name)
        or _GHIDRA_AUTO_SRC.match(name)
        or _GHIDRA_AUTO_DEST.match(name)
        or _GHIDRA_AUTO_LOCAL.match(name)
        or _GHIDRA_AUTO_VAR.match(name)
        or _GHIDRA_AUTO_IN.match(name)
    )


def _is_ghidra_auto_name(name: str) -> bool:
    """Saf Ghidra otomatik isim mi (generic namer ciktisi dahil degil)."""
    return _is_auto_or_generic_name(name)


def _sanitize_c_name(name: str) -> str:
    """Ismi gecerli C identifier'a donustur."""
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if name and name[0].isdigit():
        name = "_" + name
    name = re.sub(r"_+", "_", name)
    name = name.strip("_")
    return name or "unnamed"


# ---------------------------------------------------------------------------
# Fonksiyon imza parser (C kodundan)
# ---------------------------------------------------------------------------

_FUNC_SIG_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Tek parametre parser: "type name" veya "type *name" veya "type * name"
_PARAM_PARSE_RE = re.compile(
    r"^\s*"
    r"((?:const\s+)?(?:unsigned\s+)?(?:void|int|uint|long|ulong|char|uchar|short|ushort|"
    r"byte|bool|float|double|size_t|ssize_t|undefined\d?|code|"
    r"\w+)"
    r"(?:\s*\*+)?)"          # tip kismi
    r"\s+(\w+)\s*$"          # isim kismi
)


# ---------------------------------------------------------------------------
# Strateji 1: Algoritma Parametre Sablonlari (30+ algoritma)
# ---------------------------------------------------------------------------

ALGORITHM_PARAM_TEMPLATES: dict[str, list[ParamTemplate]] = {
    # === FEA / Yapisal Mekanik ===

    "Newton-Raphson": [
        ParamTemplate(0, "iter_count",      "int *",    "iteration counter"),
        ParamTemplate(1, "num_equations",    "int *",    "number of equations / DOFs"),
        ParamTemplate(2, "K_global",         "double *", "global stiffness matrix"),
        ParamTemplate(3, "u_displacement",   "double *", "displacement vector"),
        ParamTemplate(4, "f_load",           "double *", "external load vector"),
        ParamTemplate(5, "residual",         "double *", "residual force vector"),
        ParamTemplate(6, "tolerance",        "double",   "convergence tolerance"),
        ParamTemplate(7, "max_iter",         "int",      "maximum iterations"),
    ],

    "Gauss Quadrature": [
        ParamTemplate(0, "K_element",        "double *", "element stiffness output matrix"),
        ParamTemplate(1, "node_coords",      "double *", "nodal coordinates"),
        ParamTemplate(2, "material_props",   "double *", "material properties (E, nu)"),
        ParamTemplate(3, "num_gauss_pts",    "int",      "number of integration points"),
        ParamTemplate(4, "xi_coords",        "double *", "natural coordinates (xi)"),
        ParamTemplate(5, "weights",          "double *", "quadrature weights"),
        ParamTemplate(6, "elem_type",        "int",      "element type flag"),
    ],

    "LU Decomposition": [
        ParamTemplate(0, "A_matrix",         "double *", "input matrix (overwritten with L and U)"),
        ParamTemplate(1, "n_size",           "int",      "matrix dimension"),
        ParamTemplate(2, "pivot_indices",    "int *",    "pivot permutation vector"),
        ParamTemplate(3, "info",             "int *",    "return status (0 = success)"),
    ],

    "Conjugate Gradient": [
        ParamTemplate(0, "A_matrix",         "double *", "coefficient matrix (SPD)"),
        ParamTemplate(1, "b_rhs",            "double *", "right-hand side vector"),
        ParamTemplate(2, "x_solution",       "double *", "solution vector (initial guess, overwritten)"),
        ParamTemplate(3, "n_size",           "int",      "system dimension"),
        ParamTemplate(4, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(5, "tolerance",        "double",   "convergence tolerance"),
        ParamTemplate(6, "precond",          "double *", "preconditioner (optional, may be NULL)"),
    ],

    "Cholesky": [
        ParamTemplate(0, "A_matrix",         "double *", "SPD matrix (overwritten with L)"),
        ParamTemplate(1, "n_size",           "int",      "matrix dimension"),
        ParamTemplate(2, "info",             "int *",    "return status"),
    ],

    "QR Decomposition": [
        ParamTemplate(0, "A_matrix",         "double *", "input matrix (m x n)"),
        ParamTemplate(1, "m_rows",           "int",      "number of rows"),
        ParamTemplate(2, "n_cols",           "int",      "number of columns"),
        ParamTemplate(3, "Q_matrix",         "double *", "orthogonal factor Q"),
        ParamTemplate(4, "R_matrix",         "double *", "upper triangular factor R"),
        ParamTemplate(5, "tau_reflectors",   "double *", "Householder reflectors"),
    ],

    "FEA Assembly": [
        ParamTemplate(0, "K_global",         "double *", "global stiffness matrix"),
        ParamTemplate(1, "elements",         "void *",   "element array / connectivity"),
        ParamTemplate(2, "num_elements",     "int",      "total number of elements"),
        ParamTemplate(3, "num_dof",          "int",      "total degrees of freedom"),
        ParamTemplate(4, "node_coords",      "double *", "nodal coordinate array"),
        ParamTemplate(5, "material",         "double *", "material property array"),
    ],

    "Shape Function": [
        ParamTemplate(0, "N_shape",          "double *", "shape function values at point"),
        ParamTemplate(1, "dNdxi",            "double *", "shape function derivatives wrt xi"),
        ParamTemplate(2, "dNdeta",           "double *", "shape function derivatives wrt eta"),
        ParamTemplate(3, "xi",               "double",   "natural coordinate xi"),
        ParamTemplate(4, "eta",              "double",   "natural coordinate eta"),
        ParamTemplate(5, "npe",              "int",      "nodes per element"),
    ],

    "Forward Elimination": [
        ParamTemplate(0, "A_augmented",      "double *", "augmented matrix [A|b]"),
        ParamTemplate(1, "n_size",           "int",      "system size"),
        ParamTemplate(2, "pivot_row",        "int *",    "pivot row index"),
    ],

    "Back Substitution": [
        ParamTemplate(0, "U_upper",          "double *", "upper triangular matrix"),
        ParamTemplate(1, "x_solution",       "double *", "solution vector (output)"),
        ParamTemplate(2, "b_rhs",            "double *", "right-hand side"),
        ParamTemplate(3, "n_size",           "int",      "system size"),
    ],

    "Gauss Elimination": [
        ParamTemplate(0, "A_matrix",         "double *", "coefficient matrix (overwritten)"),
        ParamTemplate(1, "b_rhs",            "double *", "right-hand side (overwritten)"),
        ParamTemplate(2, "n_size",           "int",      "system size"),
        ParamTemplate(3, "x_solution",       "double *", "solution vector"),
    ],

    "Gauss-Seidel": [
        ParamTemplate(0, "A_matrix",         "double *", "coefficient matrix"),
        ParamTemplate(1, "b_rhs",            "double *", "right-hand side"),
        ParamTemplate(2, "x_solution",       "double *", "solution vector (initial guess, overwritten)"),
        ParamTemplate(3, "n_size",           "int",      "system size"),
        ParamTemplate(4, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(5, "tolerance",        "double",   "convergence tolerance"),
    ],

    "Jacobi Iteration": [
        ParamTemplate(0, "A_matrix",         "double *", "coefficient matrix"),
        ParamTemplate(1, "b_rhs",            "double *", "right-hand side"),
        ParamTemplate(2, "x_solution",       "double *", "solution vector"),
        ParamTemplate(3, "n_size",           "int",      "system size"),
        ParamTemplate(4, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(5, "tolerance",        "double",   "convergence tolerance"),
    ],

    "Eigenvalue (Power Method)": [
        ParamTemplate(0, "A_matrix",         "double *", "input matrix"),
        ParamTemplate(1, "eigenvector",      "double *", "dominant eigenvector (output)"),
        ParamTemplate(2, "n_size",           "int",      "matrix dimension"),
        ParamTemplate(3, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(4, "tolerance",        "double",   "convergence tolerance"),
        ParamTemplate(5, "eigenvalue",       "double *", "dominant eigenvalue (output)"),
    ],

    "Sparse CSR": [
        ParamTemplate(0, "values",           "double *", "non-zero values array"),
        ParamTemplate(1, "col_indices",      "int *",    "column index array"),
        ParamTemplate(2, "row_ptr",          "int *",    "row pointer array"),
        ParamTemplate(3, "n_rows",           "int",      "number of rows"),
        ParamTemplate(4, "nnz",              "int",      "number of non-zeros"),
    ],

    "Thomas Algorithm": [
        ParamTemplate(0, "a_lower",          "double *", "lower diagonal"),
        ParamTemplate(1, "b_main",           "double *", "main diagonal"),
        ParamTemplate(2, "c_upper",          "double *", "upper diagonal"),
        ParamTemplate(3, "d_rhs",            "double *", "right-hand side"),
        ParamTemplate(4, "x_solution",       "double *", "solution vector"),
        ParamTemplate(5, "n_size",           "int",      "system size"),
    ],

    # === CFD / Akiskanlar Dinamigi ===

    "k-epsilon": [
        ParamTemplate(0, "k_turb",           "double *", "turbulent kinetic energy field"),
        ParamTemplate(1, "epsilon",          "double *", "dissipation rate field"),
        ParamTemplate(2, "nu_t",             "double *", "eddy viscosity field"),
        ParamTemplate(3, "u_velocity",       "double *", "velocity field"),
        ParamTemplate(4, "mesh_volumes",     "double *", "cell volumes"),
        ParamTemplate(5, "n_cells",          "int",      "number of cells"),
        ParamTemplate(6, "dt",               "double",   "time step"),
    ],

    "SST k-omega": [
        ParamTemplate(0, "k_turb",           "double *", "turbulent kinetic energy"),
        ParamTemplate(1, "omega",            "double *", "specific dissipation rate"),
        ParamTemplate(2, "nu_t",             "double *", "eddy viscosity"),
        ParamTemplate(3, "u_velocity",       "double *", "velocity field"),
        ParamTemplate(4, "wall_dist",        "double *", "wall distance"),
        ParamTemplate(5, "n_cells",          "int",      "number of cells"),
    ],

    "Spalart-Allmaras": [
        ParamTemplate(0, "nu_tilde",         "double *", "modified eddy viscosity"),
        ParamTemplate(1, "nu_t",             "double *", "turbulent viscosity (output)"),
        ParamTemplate(2, "u_velocity",       "double *", "velocity field"),
        ParamTemplate(3, "wall_dist",        "double *", "distance to nearest wall"),
        ParamTemplate(4, "n_cells",          "int",      "number of cells"),
    ],

    "SIMPLE Algorithm": [
        ParamTemplate(0, "u_velocity",       "double *", "x-velocity field"),
        ParamTemplate(1, "v_velocity",       "double *", "y-velocity field"),
        ParamTemplate(2, "pressure",         "double *", "pressure field"),
        ParamTemplate(3, "p_correction",     "double *", "pressure correction"),
        ParamTemplate(4, "n_cells",          "int",      "number of cells"),
        ParamTemplate(5, "relaxation",       "double",   "under-relaxation factor"),
    ],

    "Finite Difference": [
        ParamTemplate(0, "field",            "double *", "solution field (overwritten)"),
        ParamTemplate(1, "nx",               "int",      "grid points in x"),
        ParamTemplate(2, "ny",               "int",      "grid points in y"),
        ParamTemplate(3, "dx",               "double",   "grid spacing x"),
        ParamTemplate(4, "dy",               "double",   "grid spacing y"),
        ParamTemplate(5, "dt",               "double",   "time step"),
        ParamTemplate(6, "alpha",            "double",   "diffusion coefficient"),
    ],

    "Finite Volume": [
        ParamTemplate(0, "phi_field",        "double *", "transported scalar field"),
        ParamTemplate(1, "flux",             "double *", "face fluxes"),
        ParamTemplate(2, "source",           "double *", "source term"),
        ParamTemplate(3, "volumes",          "double *", "cell volumes"),
        ParamTemplate(4, "n_cells",          "int",      "number of cells"),
        ParamTemplate(5, "dt",               "double",   "time step"),
    ],

    # === Zaman Integrasyonu ===

    "Runge-Kutta 4": [
        ParamTemplate(0, "y_state",          "double *", "state vector"),
        ParamTemplate(1, "dydt_func",        "void *",   "derivative function pointer"),
        ParamTemplate(2, "t_current",        "double",   "current time"),
        ParamTemplate(3, "dt",               "double",   "time step"),
        ParamTemplate(4, "n_vars",           "int",      "number of state variables"),
        ParamTemplate(5, "k1_work",          "double *", "RK4 stage 1 workspace"),
        ParamTemplate(6, "k2_work",          "double *", "RK4 stage 2 workspace"),
        ParamTemplate(7, "k3_work",          "double *", "RK4 stage 3 workspace"),
        ParamTemplate(8, "k4_work",          "double *", "RK4 stage 4 workspace"),
    ],

    "Newmark-Beta": [
        ParamTemplate(0, "M_mass",           "double *", "mass matrix"),
        ParamTemplate(1, "C_damp",           "double *", "damping matrix"),
        ParamTemplate(2, "K_stiff",          "double *", "stiffness matrix"),
        ParamTemplate(3, "u_disp",           "double *", "displacement vector"),
        ParamTemplate(4, "v_vel",            "double *", "velocity vector"),
        ParamTemplate(5, "a_accel",          "double *", "acceleration vector"),
        ParamTemplate(6, "f_ext",            "double *", "external force vector"),
        ParamTemplate(7, "dt",               "double",   "time step"),
        ParamTemplate(8, "beta",             "double",   "Newmark beta parameter"),
        ParamTemplate(9, "gamma",            "double",   "Newmark gamma parameter"),
    ],

    # === Sinyal Isleme (DSP) ===

    "FFT": [
        ParamTemplate(0, "x_real",           "double *", "real part of input signal"),
        ParamTemplate(1, "x_imag",           "double *", "imaginary part of input signal"),
        ParamTemplate(2, "N_fft",            "int",      "FFT size (power of 2)"),
        ParamTemplate(3, "twiddle_re",       "double *", "twiddle factor real parts"),
        ParamTemplate(4, "twiddle_im",       "double *", "twiddle factor imaginary parts"),
        ParamTemplate(5, "is_inverse",       "int",      "1 for IFFT, 0 for FFT"),
    ],

    "Convolution": [
        ParamTemplate(0, "signal",           "double *", "input signal"),
        ParamTemplate(1, "kernel",           "double *", "convolution kernel / filter"),
        ParamTemplate(2, "output",           "double *", "output signal"),
        ParamTemplate(3, "signal_len",       "int",      "signal length"),
        ParamTemplate(4, "kernel_len",       "int",      "kernel length"),
    ],

    "FIR Filter": [
        ParamTemplate(0, "input_signal",     "double *", "input samples"),
        ParamTemplate(1, "coefficients",     "double *", "filter coefficients"),
        ParamTemplate(2, "output_signal",    "double *", "filtered output"),
        ParamTemplate(3, "n_samples",        "int",      "number of input samples"),
        ParamTemplate(4, "n_taps",           "int",      "number of filter taps"),
        ParamTemplate(5, "delay_line",       "double *", "delay line state"),
    ],

    # === Optimizasyon ===

    "Gradient Descent": [
        ParamTemplate(0, "params",           "double *", "parameter vector (updated in place)"),
        ParamTemplate(1, "gradient",         "double *", "gradient vector"),
        ParamTemplate(2, "n_params",         "int",      "number of parameters"),
        ParamTemplate(3, "learning_rate",    "double",   "step size / learning rate"),
        ParamTemplate(4, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(5, "tolerance",        "double",   "gradient norm tolerance"),
    ],

    "BFGS": [
        ParamTemplate(0, "x_current",        "double *", "current point"),
        ParamTemplate(1, "gradient",         "double *", "gradient at current point"),
        ParamTemplate(2, "H_inverse",        "double *", "inverse Hessian approximation"),
        ParamTemplate(3, "n_vars",           "int",      "number of variables"),
        ParamTemplate(4, "func_val",         "double *", "function value"),
        ParamTemplate(5, "tolerance",        "double",   "convergence tolerance"),
    ],

    "Bisection Method": [
        ParamTemplate(0, "a_lower",          "double *", "lower bound"),
        ParamTemplate(1, "b_upper",          "double *", "upper bound"),
        ParamTemplate(2, "tolerance",        "double",   "tolerance"),
        ParamTemplate(3, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(4, "root",             "double *", "computed root (output)"),
    ],

    "Secant Method": [
        ParamTemplate(0, "x0",               "double *", "first initial guess"),
        ParamTemplate(1, "x1",               "double *", "second initial guess"),
        ParamTemplate(2, "tolerance",        "double",   "convergence tolerance"),
        ParamTemplate(3, "max_iter",         "int",      "maximum iterations"),
        ParamTemplate(4, "root",             "double *", "computed root (output)"),
    ],

    "Simpson Integration": [
        ParamTemplate(0, "f_values",         "double *", "function values at nodes"),
        ParamTemplate(1, "a_start",          "double",   "interval start"),
        ParamTemplate(2, "b_end",            "double",   "interval end"),
        ParamTemplate(3, "n_intervals",      "int",      "number of sub-intervals (even)"),
        ParamTemplate(4, "result",           "double *", "integral result (output)"),
    ],

    # === Makine Ogrenimi ===

    "Softmax": [
        ParamTemplate(0, "logits",           "double *", "input logits"),
        ParamTemplate(1, "output_probs",     "double *", "output probabilities"),
        ParamTemplate(2, "n_classes",        "int",      "number of classes"),
        ParamTemplate(3, "batch_size",       "int",      "batch size"),
    ],

    "Batch Normalization": [
        ParamTemplate(0, "input_data",       "double *", "input activations"),
        ParamTemplate(1, "output_data",      "double *", "normalized output"),
        ParamTemplate(2, "gamma",            "double *", "scale parameter"),
        ParamTemplate(3, "beta",             "double *", "shift parameter"),
        ParamTemplate(4, "running_mean",     "double *", "running mean"),
        ParamTemplate(5, "running_var",      "double *", "running variance"),
        ParamTemplate(6, "n_features",       "int",      "number of features / channels"),
        ParamTemplate(7, "epsilon",          "double",   "numerical stability epsilon"),
    ],

    "Attention": [
        ParamTemplate(0, "Q_query",          "double *", "query matrix"),
        ParamTemplate(1, "K_key",            "double *", "key matrix"),
        ParamTemplate(2, "V_value",          "double *", "value matrix"),
        ParamTemplate(3, "output",           "double *", "attention output"),
        ParamTemplate(4, "n_heads",          "int",      "number of attention heads"),
        ParamTemplate(5, "seq_len",          "int",      "sequence length"),
        ParamTemplate(6, "d_model",          "int",      "model dimension"),
        ParamTemplate(7, "scale_factor",     "double",   "1 / sqrt(d_k)"),
    ],

    "Matrix Multiply": [
        ParamTemplate(0, "A_matrix",         "double *", "left matrix (m x k)"),
        ParamTemplate(1, "B_matrix",         "double *", "right matrix (k x n)"),
        ParamTemplate(2, "C_result",         "double *", "result matrix (m x n)"),
        ParamTemplate(3, "m_rows",           "int",      "rows of A / C"),
        ParamTemplate(4, "n_cols",           "int",      "columns of B / C"),
        ParamTemplate(5, "k_inner",          "int",      "inner dimension (cols A / rows B)"),
        ParamTemplate(6, "alpha",            "double",   "scalar multiplier"),
        ParamTemplate(7, "beta",             "double",   "scalar for C accumulation"),
    ],

    "Cross Product": [
        ParamTemplate(0, "a_vec",            "double *", "first 3D vector"),
        ParamTemplate(1, "b_vec",            "double *", "second 3D vector"),
        ParamTemplate(2, "result",           "double *", "cross product result"),
    ],

    "Dot Product": [
        ParamTemplate(0, "a_vec",            "double *", "first vector"),
        ParamTemplate(1, "b_vec",            "double *", "second vector"),
        ParamTemplate(2, "n_size",           "int",      "vector length"),
        ParamTemplate(3, "result",           "double *", "dot product result"),
    ],

    # === Monte Carlo ===

    "Monte Carlo": [
        ParamTemplate(0, "samples",          "double *", "sample output array"),
        ParamTemplate(1, "n_samples",        "int",      "number of samples"),
        ParamTemplate(2, "rng_state",        "void *",   "random number generator state"),
        ParamTemplate(3, "params",           "double *", "distribution parameters"),
        ParamTemplate(4, "result",           "double *", "Monte Carlo estimate"),
    ],

    # === Finans ===

    "Black-Scholes": [
        ParamTemplate(0, "S_spot",           "double",   "spot price"),
        ParamTemplate(1, "K_strike",         "double",   "strike price"),
        ParamTemplate(2, "r_rate",           "double",   "risk-free rate"),
        ParamTemplate(3, "sigma_vol",        "double",   "volatility"),
        ParamTemplate(4, "T_maturity",       "double",   "time to maturity"),
        ParamTemplate(5, "price_out",        "double *", "option price (output)"),
        ParamTemplate(6, "is_call",          "int",      "1 = call, 0 = put"),
    ],

    "Binomial Tree": [
        ParamTemplate(0, "S_spot",           "double",   "spot price"),
        ParamTemplate(1, "K_strike",         "double",   "strike price"),
        ParamTemplate(2, "r_rate",           "double",   "risk-free rate"),
        ParamTemplate(3, "sigma_vol",        "double",   "volatility"),
        ParamTemplate(4, "T_maturity",       "double",   "time to maturity"),
        ParamTemplate(5, "n_steps",          "int",      "number of time steps"),
        ParamTemplate(6, "price_out",        "double *", "option price (output)"),
    ],

    # === Kriptografi (mevcut c_algorithm_id ile uyumlu) ===

    "AES": [
        ParamTemplate(0, "plaintext",        "unsigned char *", "input plaintext"),
        ParamTemplate(1, "ciphertext",       "unsigned char *", "output ciphertext"),
        ParamTemplate(2, "key",              "unsigned char *", "encryption key"),
        ParamTemplate(3, "key_len",          "int",             "key length (16/24/32)"),
        ParamTemplate(4, "iv",               "unsigned char *", "initialization vector"),
        ParamTemplate(5, "round_keys",       "unsigned char *", "expanded round keys"),
    ],

    "SHA-256": [
        ParamTemplate(0, "message",          "unsigned char *", "input message"),
        ParamTemplate(1, "msg_len",          "size_t",          "message length in bytes"),
        ParamTemplate(2, "digest",           "unsigned char *", "output hash (32 bytes)"),
        ParamTemplate(3, "state",            "unsigned int *",  "hash state (8 x uint32)"),
    ],

    "RSA": [
        ParamTemplate(0, "message",          "unsigned char *", "input message / plaintext"),
        ParamTemplate(1, "signature",        "unsigned char *", "output signature / ciphertext"),
        ParamTemplate(2, "n_modulus",        "void *",          "RSA modulus N"),
        ParamTemplate(3, "exponent",         "void *",          "public or private exponent"),
        ParamTemplate(4, "msg_len",          "int",             "message length"),
    ],
}


# ---------------------------------------------------------------------------
# Algoritma isim normalizasyonu -- tespit isimlerini sablon anahtarlarina esle
# ---------------------------------------------------------------------------

# Tespit edilen algoritma isimleri (analyzer.py ciktisi) her zaman sablon
# anahtarlariyla birebir eslesmiyor. Bu haritalama toleransi saglar.
_ALGO_NAME_NORMALIZE: dict[str, str] = {
    # Newton-Raphson varyasyonlari
    "newton-raphson": "Newton-Raphson",
    "newton_raphson": "Newton-Raphson",
    "newton raphson": "Newton-Raphson",
    "newton": "Newton-Raphson",
    "nr_iteration": "Newton-Raphson",
    # Gauss quadrature
    "gauss quadrature": "Gauss Quadrature",
    "gauss_quadrature": "Gauss Quadrature",
    "gaussian quadrature": "Gauss Quadrature",
    "numerical_integration": "Gauss Quadrature",
    # LU
    "lu decomposition": "LU Decomposition",
    "lu_decomposition": "LU Decomposition",
    "lu factorization": "LU Decomposition",
    "lu_factorization": "LU Decomposition",
    # CG
    "conjugate gradient": "Conjugate Gradient",
    "conjugate_gradient": "Conjugate Gradient",
    "cg_solver": "Conjugate Gradient",
    "pcg": "Conjugate Gradient",
    # Cholesky
    "cholesky": "Cholesky",
    "cholesky decomposition": "Cholesky",
    "cholesky_decomposition": "Cholesky",
    # QR
    "qr decomposition": "QR Decomposition",
    "qr_decomposition": "QR Decomposition",
    "qr factorization": "QR Decomposition",
    "householder qr": "QR Decomposition",
    # FEA Assembly
    "fea assembly": "FEA Assembly",
    "fea_assembly": "FEA Assembly",
    "stiffness assembly": "FEA Assembly",
    "global_assembly": "FEA Assembly",
    "assembly": "FEA Assembly",
    # Shape functions
    "shape function": "Shape Function",
    "shape_function": "Shape Function",
    "isoparametric": "Shape Function",
    # Back/Forward sub
    "forward elimination": "Forward Elimination",
    "forward_elimination": "Forward Elimination",
    "back substitution": "Back Substitution",
    "back_substitution": "Back Substitution",
    "backward_substitution": "Back Substitution",
    # Gauss elimination
    "gauss elimination": "Gauss Elimination",
    "gauss_elimination": "Gauss Elimination",
    "gaussian elimination": "Gauss Elimination",
    # Gauss-Seidel
    "gauss-seidel": "Gauss-Seidel",
    "gauss_seidel": "Gauss-Seidel",
    # Jacobi
    "jacobi": "Jacobi Iteration",
    "jacobi iteration": "Jacobi Iteration",
    "jacobi_iteration": "Jacobi Iteration",
    # Eigenvalue
    "eigenvalue": "Eigenvalue (Power Method)",
    "power method": "Eigenvalue (Power Method)",
    "power_method": "Eigenvalue (Power Method)",
    "eigenvalue_power": "Eigenvalue (Power Method)",
    # Sparse
    "sparse csr": "Sparse CSR",
    "sparse_csr": "Sparse CSR",
    "csr_matrix": "Sparse CSR",
    "sparse_matrix": "Sparse CSR",
    # Thomas
    "thomas algorithm": "Thomas Algorithm",
    "thomas_algorithm": "Thomas Algorithm",
    "tridiagonal": "Thomas Algorithm",
    "tridiagonal_solver": "Thomas Algorithm",
    # CFD turbulence
    "k-epsilon": "k-epsilon",
    "k_epsilon": "k-epsilon",
    "sst k-omega": "SST k-omega",
    "sst_k_omega": "SST k-omega",
    "k-omega sst": "SST k-omega",
    "spalart-allmaras": "Spalart-Allmaras",
    "spalart_allmaras": "Spalart-Allmaras",
    # CFD solvers
    "simple": "SIMPLE Algorithm",
    "simple algorithm": "SIMPLE Algorithm",
    "simple_algorithm": "SIMPLE Algorithm",
    "finite difference": "Finite Difference",
    "finite_difference": "Finite Difference",
    "fdm": "Finite Difference",
    "finite volume": "Finite Volume",
    "finite_volume": "Finite Volume",
    "fvm": "Finite Volume",
    # Time integration
    "runge-kutta": "Runge-Kutta 4",
    "runge_kutta": "Runge-Kutta 4",
    "rk4": "Runge-Kutta 4",
    "runge-kutta 4": "Runge-Kutta 4",
    "newmark-beta": "Newmark-Beta",
    "newmark_beta": "Newmark-Beta",
    "newmark": "Newmark-Beta",
    # DSP
    "fft": "FFT",
    "fast fourier transform": "FFT",
    "cooley-tukey": "FFT",
    "convolution": "Convolution",
    "fir filter": "FIR Filter",
    "fir_filter": "FIR Filter",
    # Optimization
    "gradient descent": "Gradient Descent",
    "gradient_descent": "Gradient Descent",
    "sgd": "Gradient Descent",
    "bfgs": "BFGS",
    "l-bfgs": "BFGS",
    "bisection": "Bisection Method",
    "bisection method": "Bisection Method",
    "secant": "Secant Method",
    "secant method": "Secant Method",
    "simpson": "Simpson Integration",
    "simpson integration": "Simpson Integration",
    "simpson_rule": "Simpson Integration",
    # ML
    "softmax": "Softmax",
    "batch normalization": "Batch Normalization",
    "batch_norm": "Batch Normalization",
    "batchnorm": "Batch Normalization",
    "attention": "Attention",
    "self_attention": "Attention",
    "scaled_dot_product": "Attention",
    "matrix multiply": "Matrix Multiply",
    "matrix_multiply": "Matrix Multiply",
    "matmul": "Matrix Multiply",
    "gemm": "Matrix Multiply",
    "cross product": "Cross Product",
    "cross_product": "Cross Product",
    "dot product": "Dot Product",
    "dot_product": "Dot Product",
    # Monte Carlo
    "monte carlo": "Monte Carlo",
    "monte_carlo": "Monte Carlo",
    "mc_simulation": "Monte Carlo",
    # Finans
    "black-scholes": "Black-Scholes",
    "black_scholes": "Black-Scholes",
    "binomial tree": "Binomial Tree",
    "binomial_tree": "Binomial Tree",
    "crr_tree": "Binomial Tree",
    # Kripto
    "aes": "AES",
    "aes-128": "AES",
    "aes-192": "AES",
    "aes-256": "AES",
    "aes-256-cbc": "AES",
    "sha-256": "SHA-256",
    "sha256": "SHA-256",
    "sha-2": "SHA-256",
    "rsa": "RSA",
    "rsa-2048": "RSA",
    "rsa-4096": "RSA",
}


def _normalize_algo_name(raw_name: str) -> str | None:
    """Tespit edilen algoritma ismini sablon anahtarina normalize et."""
    key = raw_name.strip().lower()
    # Direkt esleme
    if key in _ALGO_NAME_NORMALIZE:
        return _ALGO_NAME_NORMALIZE[key]
    # Tire/alt cizgi/bosluk toleransi
    for sep in ["-", "_", " "]:
        alt = key.replace("-", sep).replace("_", sep).replace(" ", sep)
        if alt in _ALGO_NAME_NORMALIZE:
            return _ALGO_NAME_NORMALIZE[alt]
    # Baslik harfi ile dene (orijinal isim zaten sablon anahtari olabilir)
    if raw_name in ALGORITHM_PARAM_TEMPLATES:
        return raw_name
    return None


# ---------------------------------------------------------------------------
# Strateji 2: Caller isim ipuclari
# ---------------------------------------------------------------------------

CALLER_NAME_HINTS: dict[str, dict[int, str]] = {
    # FEA
    "assemble_stiffness":    {0: "K_global", 1: "elements", 2: "num_elements"},
    "assemble_global":       {0: "K_global", 1: "elements", 2: "num_elements", 3: "num_dof"},
    "assemble_mass":         {0: "M_mass", 1: "elements", 2: "num_elements"},
    "compute_element_stiffness": {0: "K_element", 1: "node_coords", 2: "material_props"},
    "solve_system":          {0: "A_matrix", 1: "b_rhs", 2: "x_solution"},
    "solve_linear":          {0: "A_matrix", 1: "b_rhs", 2: "x_solution", 3: "n_size"},
    "compute_residual":      {0: "R_out", 1: "K_matrix", 2: "u_vec", 3: "f_ext"},
    "apply_bc":              {0: "K_global", 1: "f_load", 2: "bc_nodes", 3: "bc_values"},
    "apply_boundary":        {0: "K_global", 1: "f_load", 2: "bc_nodes", 3: "bc_values"},
    "compute_stress":        {0: "stress_out", 1: "strain", 2: "D_material"},
    "compute_strain":        {0: "strain_out", 1: "B_matrix", 2: "u_displacement"},
    # CFD
    "compute_flux":          {0: "flux_out", 1: "u_left", 2: "u_right", 3: "normal"},
    "update_pressure":       {0: "p_new", 1: "p_old", 2: "div_u", 3: "dt"},
    "compute_gradient":      {0: "grad_out", 1: "phi_field", 2: "mesh"},
    "compute_divergence":    {0: "div_out", 1: "u_velocity", 2: "mesh"},
    "apply_viscosity":       {0: "rhs", 1: "u_velocity", 2: "nu", 3: "mesh"},
    # Linear algebra
    "matvec":                {0: "A_matrix", 1: "x_vec", 2: "y_result", 3: "n_size"},
    "matmul":                {0: "A_matrix", 1: "B_matrix", 2: "C_result"},
    "transpose":             {0: "A_matrix", 1: "AT_result", 2: "m_rows", 3: "n_cols"},
    "compute_norm":          {0: "vec", 1: "n_size"},
    "dot_product":           {0: "a_vec", 1: "b_vec", 2: "n_size"},
    "scale_vector":          {0: "vec", 1: "alpha", 2: "n_size"},
    "axpy":                  {0: "y_vec", 1: "alpha", 2: "x_vec", 3: "n_size"},
    # ML
    "forward_pass":          {0: "input_data", 1: "weights", 2: "output", 3: "batch_size"},
    "backward_pass":         {0: "grad_output", 1: "weights", 2: "grad_input", 3: "grad_weights"},
    "update_weights":        {0: "weights", 1: "gradients", 2: "learning_rate", 3: "n_params"},
    "compute_loss":          {0: "predictions", 1: "targets", 2: "n_samples"},
    # DSP
    "apply_filter":          {0: "signal", 1: "coefficients", 2: "output", 3: "n_samples"},
    "window_function":       {0: "data", 1: "window", 2: "n_points"},
    # Finans
    "price_option":          {0: "S_spot", 1: "K_strike", 2: "r_rate", 3: "sigma_vol", 4: "T_maturity"},
    "compute_greeks":        {0: "delta", 1: "gamma", 2: "vega", 3: "theta"},
    # Generic
    "init_array":            {0: "array", 1: "value", 2: "n_size"},
    "copy_array":            {0: "dest", 1: "src", 2: "n_size"},
    "zero_array":            {0: "array", 1: "n_size"},
    "print_matrix":          {0: "matrix", 1: "rows", 2: "cols"},
    "read_input":            {0: "filename", 1: "data_out", 2: "n_size"},
    "write_output":          {0: "filename", 1: "data_in", 2: "n_size"},
}


# ---------------------------------------------------------------------------
# Strateji 4: Tip + Kullanim oruntu sablonlari
# ---------------------------------------------------------------------------

TYPE_USAGE_PATTERNS: list[TypeUsagePattern] = [
    # double * erisimleri
    TypeUsagePattern(
        c_type="double *", loop_depth=3, name="matrix",
        domain_prefix={"structural": "K_", "fluid": "A_", "generic": "M_"},
        confidence=0.50,
    ),
    TypeUsagePattern(
        c_type="double *", loop_depth=2, name="matrix",
        domain_prefix={"structural": "K_", "fluid": "A_", "generic": "M_"},
        confidence=0.45,
    ),
    TypeUsagePattern(
        c_type="double *", loop_depth=1, index_pattern="sequential", name="vector",
        domain_prefix={"structural": "u_", "fluid": "phi_", "generic": "v_"},
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="double *", usage_pattern="single_read", name="scalar_ref",
        confidence=0.50,
    ),
    # int * veya int erisimleri
    TypeUsagePattern(
        c_type="int", usage_pattern="comparison", name="count",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="int", usage_pattern="loop_bound", name="n_size",
        confidence=0.60,
    ),
    TypeUsagePattern(
        c_type="int *", usage_pattern="increment", name="counter",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="int *", loop_depth=1, name="index_array",
        confidence=0.50,
    ),
    # long -- Ghidra icinde sik pointer alias
    TypeUsagePattern(
        c_type="long", usage_pattern="array_base", name="data_ptr",
        confidence=0.50,
    ),
    TypeUsagePattern(
        c_type="long", usage_pattern="offset_access", name="struct_ptr",
        confidence=0.55,
    ),
    # void * -- opak pointer
    TypeUsagePattern(
        c_type="void *", name="context",
        confidence=0.40,
    ),
    # size_t
    TypeUsagePattern(
        c_type="size_t", usage_pattern="comparison", name="buffer_size",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="size_t", usage_pattern="loop_bound", name="count",
        confidence=0.60,
    ),
    # char *
    TypeUsagePattern(
        c_type="char *", name="str",
        confidence=0.50,
    ),
    TypeUsagePattern(
        c_type="unsigned char *", name="byte_buffer",
        confidence=0.45,
    ),

    # ---------------------------------------------------------------
    # v1.7.2: Enhanced type-based heuristics for common C patterns
    # ---------------------------------------------------------------

    # char * -- finer context
    TypeUsagePattern(
        c_type="char *", usage_pattern="single_read", name="text",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="char *", usage_pattern="comparison", name="name",
        confidence=0.55,
    ),

    # int -- common patterns
    TypeUsagePattern(
        c_type="int", usage_pattern="return_value", name="status",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="int", usage_pattern="increment", name="counter",
        confidence=0.55,
    ),
    TypeUsagePattern(
        c_type="int", usage_pattern="general", name="value",
        confidence=0.45,
    ),

    # long -- Ghidra pointer alias (very common)
    TypeUsagePattern(
        c_type="long", usage_pattern="general", name="handle",
        confidence=0.45,
    ),

    # void * -- opaque pointer refined
    TypeUsagePattern(
        c_type="void *", usage_pattern="single_read", name="userdata",
        confidence=0.45,
    ),
    TypeUsagePattern(
        c_type="void *", usage_pattern="offset_access", name="ctx",
        confidence=0.55,
    ),

    # unsigned int / uint -- often flags or bitmask
    TypeUsagePattern(
        c_type="uint", usage_pattern="comparison", name="flags",
        confidence=0.50,
    ),
    TypeUsagePattern(
        c_type="uint", name="value",
        confidence=0.40,
    ),

    # bool
    TypeUsagePattern(
        c_type="bool", name="enabled",
        confidence=0.50,
    ),

    # double (scalar, not pointer)
    TypeUsagePattern(
        c_type="double", usage_pattern="comparison", name="threshold",
        confidence=0.50,
    ),
    TypeUsagePattern(
        c_type="double", name="scalar",
        confidence=0.40,
    ),

    # float (scalar)
    TypeUsagePattern(
        c_type="float", name="factor",
        confidence=0.40,
    ),
]


# ---------------------------------------------------------------------------
# v1.7.2: First-parameter heuristics for method-like functions
# ---------------------------------------------------------------------------
# If a function's first parameter is long/void* with struct-like offset access,
# it is likely 'self' or 'ctx' (OOP pattern in C).
# This is checked separately in _infer_from_type_and_usage.

_FIRST_PARAM_SELF_TYPES: set[str] = {
    "long", "void *", "undefined8", "ulong",
}


# ---------------------------------------------------------------------------
# Tip uyumluluk -- Ghidra ciktisindaki tipler her zaman ideal degil
# ---------------------------------------------------------------------------

# Genis uyumluluk gruplari: Ghidra tipi -> potansiyel gercek tip
_TYPE_COMPAT_GROUPS: dict[str, set[str]] = {
    "double *":   {"double *", "float *", "long *", "undefined8 *", "void *", "long"},
    "float *":    {"float *", "double *", "undefined4 *", "void *"},
    "int *":      {"int *", "uint *", "undefined4 *", "void *", "long *"},
    "int":        {"int", "uint", "long", "ulong", "undefined4", "size_t", "ssize_t"},
    "long":       {"long", "ulong", "int", "uint", "undefined8", "size_t", "void *"},
    "double":     {"double", "float", "undefined8"},
    "float":      {"float", "double", "undefined4"},                            # v1.7.2
    "void *":     {"void *", "long", "undefined8 *", "undefined8", "char *", "int *", "double *"},
    "unsigned char *": {"unsigned char *", "uchar *", "char *", "void *", "undefined *"},
    "size_t":     {"size_t", "int", "uint", "long", "ulong"},
    "uint":       {"uint", "int", "unsigned int", "undefined4", "ulong"},       # v1.7.2
    "bool":       {"bool", "int", "uint", "undefined1", "byte", "char"},        # v1.7.2
    "char *":     {"char *", "unsigned char *", "void *", "undefined *"},        # v1.7.2
}


def _types_compatible(template_type: str, actual_type: str) -> bool:
    """Sablon tipi ile gercek tip uyumlu mu."""
    # Normalize: fazla bosluklari kaldir
    t_norm = " ".join(template_type.split())
    a_norm = " ".join(actual_type.split())
    if t_norm == a_norm:
        return True
    # Pointer olup olmadigi
    t_is_ptr = "*" in t_norm
    a_is_ptr = "*" in a_norm
    # Ikisi de pointer veya ikisi de deger tipi olmali (esnek mod icin long istisna)
    if t_is_ptr != a_is_ptr:
        # Ghidra bazen pointer'i 'long' olarak gosterir
        if a_norm in ("long", "ulong", "undefined8") and t_is_ptr:
            return True
        if t_norm in ("long", "ulong") and a_is_ptr:
            return True
        return False
    # Uyumluluk grubu kontrolu
    compat_set = _TYPE_COMPAT_GROUPS.get(t_norm, set())
    return a_norm in compat_set


# ---------------------------------------------------------------------------
# Kod analiz yardimcilari
# ---------------------------------------------------------------------------

# Dongü derinligi hesaplama
_FOR_LOOP_RE = re.compile(r"\bfor\s*\(")
_WHILE_LOOP_RE = re.compile(r"\bwhile\s*\(")

# Dizi erisim oruntuleri
_2D_INDEX_RE = re.compile(r"\[[\w]+\s*\*\s*[\w]+\s*\+\s*[\w]+\]")   # arr[i*n + j]
_SEQ_INDEX_RE = re.compile(r"\[[\w]+\]")                               # arr[i]
_COMPARISON_RE = re.compile(r"[<>=!]=?\s*(?:param_\d+|src_\d+|dest_\d+)\b|\b(?:param_\d+|src_\d+|dest_\d+)\s*[<>=!]=?")
_INCREMENT_RE = re.compile(r"\b(?:param_\d+|src_\d+|dest_\d+)\s*(?:\+\+|--|\+=|\-=)")
_LOOP_BOUND_RE = re.compile(r"for\s*\([^;]*;\s*\w+\s*<\s*(?:param_\d+|src_\d+|dest_\d+)")
_OFFSET_ACCESS_RE = re.compile(r"\*\s*\([^)]*\)\s*\(\s*(?:param_\d+|src_\d+|dest_\d+)\s*\+\s*0x")
_ARRAY_BASE_RE = re.compile(r"\*\s*\(\s*[^)]*\s*\*\s*\)\s*(?:param_\d+|src_\d+|dest_\d+)")
_RETURN_RE = re.compile(r"\breturn\s+(?:param_\d+|src_\d+|dest_\d+)\b")


def _get_loop_depth_for_param(code: str, param_name: str) -> int:
    """Parametrenin en derin dongü icinde kullanildigi seviyeyi bul."""
    depth = 0
    max_depth = 0
    found_at_depth = 0
    for line in code.splitlines():
        stripped = line.strip()
        depth += stripped.count("{") - stripped.count("}")
        depth = max(0, depth)
        if param_name in stripped:
            if _FOR_LOOP_RE.search(stripped) or _WHILE_LOOP_RE.search(stripped):
                continue
            found_at_depth = max(found_at_depth, depth)
        # Dongü acilislarini say
        if _FOR_LOOP_RE.search(stripped) or _WHILE_LOOP_RE.search(stripped):
            max_depth = max(max_depth, depth)
    return found_at_depth


# v1.8.0: _MAX_USAGE_BODY esigi KALDIRILDI.  Tum regex pattern'leri
# satir-bazli calistiriliyor.  Hicbir fonksiyon atlanmaz.


# v1.6.4: Pre-compiled regex cache -- param_name basina derlenen pattern setini
# lru_cache ile sakla.  Python'un dahili re cache'i 512 giris ile sinirli;
# 12K+ fonksiyon * ~3 param = binlerce unique param_name cache'i tasirir.
# Bu factory her benzersiz param_name icin 9 patterni BIR KERE derler.

@functools.lru_cache(maxsize=4096)
def _usage_patterns(param_name: str) -> tuple[
    re.Pattern[str],  # loop_bound
    re.Pattern[str],  # offset_access
    re.Pattern[str],  # array_base
    re.Pattern[str],  # comparison
    re.Pattern[str],  # increment
    re.Pattern[str],  # return_value
    re.Pattern[str],  # word_count (\b...\b)
]:
    """param_name icin _detect_usage_pattern regex'lerini derle ve cache'le."""
    p = re.escape(param_name)
    return (
        re.compile(rf"for\s*\([^;]*;\s*\w+\s*<\s*{p}"),
        re.compile(rf"\*\s*\([^)]*\)\s*\(\s*{p}\s*\+\s*0x"),
        re.compile(rf"\*\s*\(\s*[^)]*\s*\*\s*\)\s*{p}"),
        re.compile(rf"[<>=!]=?\s*{p}\b|{p}\s*[<>=!]=?"),
        re.compile(rf"{p}\s*(?:\+\+|--|\+=|\-=)"),
        re.compile(rf"\breturn\s+{p}\b"),
        re.compile(rf"\b{p}\b"),
    )


@functools.lru_cache(maxsize=4096)
def _index_patterns(param_name: str) -> tuple[
    re.Pattern[str],  # 2d_linear
    re.Pattern[str],  # sequential
]:
    """param_name icin _detect_index_pattern regex'lerini derle ve cache'le."""
    p = re.escape(param_name)
    return (
        re.compile(rf"{p}\s*\[[\w]+\s*\*\s*[\w]+\s*\+\s*[\w]+\]"),
        re.compile(rf"{p}\s*\[[\w]+\]"),
    )


def _line_search_any(pattern: re.Pattern[str], code: str) -> bool:
    """Satir-bazli regex arama.  code'u splitlines ile parcalayip
    herhangi bir satirda eslesen varsa True doner.  O(n) safe."""
    for line in code.splitlines():
        if pattern.search(line):
            return True
    return False


def _detect_usage_pattern(code: str, param_name: str) -> str:
    """Parametrenin kod icindeki kullanim oruntusunu tespit et.

    v1.8.0: Boyut siniri kaldirildi.  Tum regex'ler satir bazli calisir.
    """
    # Str.find ile hizli on-filtre: param adi yoksa "general" don.
    if param_name not in code:
        return "general"

    # v1.6.4 pre-compiled regex + v1.8.0 satir bazli arama
    (loop_bound_re, offset_re, array_re, cmp_re,
     inc_re, ret_re, word_re) = _usage_patterns(param_name)
    if _line_search_any(loop_bound_re, code):
        return "loop_bound"
    if _line_search_any(offset_re, code):
        return "offset_access"
    if _line_search_any(array_re, code):
        return "array_base"
    if _line_search_any(cmp_re, code):
        return "comparison"
    if _line_search_any(inc_re, code):
        return "increment"
    if _line_search_any(ret_re, code):
        return "return_value"
    # word_re \b...\b -- O(n) safe, findall on full code is fine
    count = len(word_re.findall(code))
    if count <= 2:
        return "single_read"
    return "general"


def _detect_index_pattern(code: str, param_name: str) -> str:
    """Parametrenin dizi erisim oruntusunu tespit et."""
    if param_name not in code:
        return "none"
    # v1.6.4: pre-compiled regex, v1.8.0: satir bazli arama
    linear_re, seq_re = _index_patterns(param_name)
    if _line_search_any(linear_re, code):
        return "2d_linear"
    if _line_search_any(seq_re, code):
        return "sequential"
    return "none"


# ---------------------------------------------------------------------------
# Paralel worker state & fonksiyonlari (ProcessPoolExecutor icin)
# ---------------------------------------------------------------------------
# ProcessPoolExecutor her worker icin ayri bir Python process baslatir.
# Worker process'ler buyuk read-only verileri (func_codes, call_graph, vb.)
# sadece initializer'da bir kez alir ve module-global'de tutar.
# Her is biriminde (chunk) sadece fonksiyon isim listesi gonderilir.

_W_FUNC_CODES: dict[str, str] = {}
_W_FUNCTIONS: dict[str, dict[str, Any]] = {}
_W_FUNC_ALGORITHMS: dict[str, list] = {}
_W_FUNC_DOMAINS: dict[str, str] = {}
_W_SIG_MATCHES: dict[str, Any] = {}
_W_API_PARAM_DB: Any = None
_W_ENRICHED_STRUCTS: list | None = None
_W_REVERSE_GRAPH: dict[str, list[str]] = {}


def _worker_init(
    func_codes: dict[str, str],
    functions: dict[str, dict[str, Any]],
    func_algorithms: dict[str, list],
    func_domains: dict[str, str],
    sig_matches: dict[str, Any],
    enriched_structs: list | None,
    reverse_graph: dict[str, list[str]],
) -> None:
    """ProcessPoolExecutor worker initializer -- buyuk verileri global'e ata."""
    global _W_FUNC_CODES, _W_FUNCTIONS, _W_FUNC_ALGORITHMS
    global _W_FUNC_DOMAINS, _W_SIG_MATCHES, _W_API_PARAM_DB
    global _W_ENRICHED_STRUCTS, _W_REVERSE_GRAPH

    _W_FUNC_CODES = func_codes
    _W_FUNCTIONS = functions
    _W_FUNC_ALGORITHMS = func_algorithms
    _W_FUNC_DOMAINS = func_domains
    _W_SIG_MATCHES = sig_matches
    _W_ENRICHED_STRUCTS = enriched_structs
    _W_REVERSE_GRAPH = reverse_graph

    # API param DB her worker'da lazy-load (pickle-safe olmayabilir)
    try:
        from karadul.reconstruction.api_param_db import APIParamDB
        _W_API_PARAM_DB = APIParamDB()
    except ImportError:
        _W_API_PARAM_DB = None


def _worker_process_chunk(func_names: list[str]) -> list[SemanticName]:
    """Worker: Bir fonksiyon chunk'i icin bagimsiz stratejileri (0,1,3,4,5) uygula.

    NOT: Strateji 2 (Call Graph Propagation) ordering-dependent oldugundan
    burada UYGULANMAZ -- ana process'te sequential yapilir.

    Returns:
        Tum chunk icin SemanticName listesi (cakisma cozumlenmemis).
    """
    all_candidates: list[SemanticName] = []

    for func_name in func_names:
        func_code = _W_FUNC_CODES.get(func_name)
        if not func_code:
            continue

        params = _worker_get_params(func_name)
        if not params:
            continue

        candidates: list[SemanticName] = []

        # Strateji 0: Signature-based naming
        if func_name in _W_SIG_MATCHES and _W_API_PARAM_DB is not None:
            candidates.extend(
                _worker_apply_signature_based(func_name, params)
            )

        # Strateji 1: Algoritma sablonu
        algos = _W_FUNC_ALGORITHMS.get(func_name, [])
        if algos:
            candidates.extend(
                _worker_apply_algorithm_templates(func_name, params, func_code, algos)
            )

        # Strateji 3: Struct field context
        if _W_ENRICHED_STRUCTS:
            candidates.extend(
                _worker_name_from_struct_context(func_name, params, func_code)
            )

        # Strateji 4: Type + usage heuristic
        domain = _W_FUNC_DOMAINS.get(func_name, "generic")
        candidates.extend(
            _worker_infer_from_type_and_usage(func_name, params, func_code, domain)
        )

        # Strateji 5: Call-context naming
        if _W_API_PARAM_DB is not None:
            candidates.extend(
                _worker_infer_from_call_context(func_name, params, func_code, domain)
            )

        all_candidates.extend(candidates)

    return all_candidates


def _worker_get_params(func_name: str) -> list[dict[str, str]]:
    """Worker: Fonksiyon parametrelerini dondur (JSON'dan veya koddan parse)."""
    func_info = _W_FUNCTIONS.get(func_name)
    if func_info and func_info.get("params"):
        return func_info["params"]

    code = _W_FUNC_CODES.get(func_name, "")
    if not code:
        return []

    sig_match = _FUNC_SIG_RE.search(code)
    if not sig_match:
        return []

    param_str = sig_match.group(2).strip()
    if not param_str or param_str == "void":
        return []

    params = []
    for i, raw in enumerate(param_str.split(",")):
        raw = raw.strip()
        if not raw:
            continue
        pm = _PARAM_PARSE_RE.match(raw)
        if pm:
            params.append({
                "name": pm.group(2),
                "type": pm.group(1).strip(),
                "position": i,
            })
        else:
            parts = raw.rsplit(None, 1)
            if len(parts) == 2:
                params.append({
                    "name": parts[1].strip("*").strip(),
                    "type": parts[0].strip(),
                    "position": i,
                })
    return params


def _worker_apply_signature_based(
    func_name: str,
    params: list[dict],
) -> list[SemanticName]:
    """Worker versiyonu: Strateji 0 -- Signature-based naming."""
    results: list[SemanticName] = []
    sig_match = _W_SIG_MATCHES.get(func_name)
    if sig_match is None or _W_API_PARAM_DB is None:
        return results

    matched_name = getattr(sig_match, "matched_name", "")
    sig_confidence = getattr(sig_match, "confidence", 0.0)
    library = getattr(sig_match, "library", "")
    if not matched_name:
        return results

    known_params = _W_API_PARAM_DB.get_param_names(matched_name)
    if known_params is None and matched_name.startswith("_"):
        known_params = _W_API_PARAM_DB.get_param_names(matched_name[1:])
    if known_params is None and not matched_name.startswith("_"):
        known_params = _W_API_PARAM_DB.get_param_names(f"_{matched_name}")
    if not known_params:
        return results

    domain = _W_FUNC_DOMAINS.get(func_name, "generic")
    base_conf = 0.92  # _BASE_CONFIDENCE["signature_based"]

    for param in params:
        param_name = param.get("name", "")
        param_pos = param.get("position", -1)
        if param_pos < 0 or param_pos >= len(known_params):
            continue
        if not _is_auto_or_generic_name(param_name):
            continue

        known_name = known_params[param_pos]
        if not known_name:
            continue

        conf = base_conf * max(0.5, min(1.0, sig_confidence))
        conf = min(0.98, conf)

        results.append(SemanticName(
            original_name=param_name,
            semantic_name=_sanitize_c_name(known_name),
            function_name=func_name,
            confidence=round(conf, 3),
            source="signature_based",
            reason=f"Signature match: {func_name} = {matched_name} ({library}), param[{param_pos}] = '{known_name}'",
            domain=domain,
        ))
    return results


def _worker_apply_algorithm_templates(
    func_name: str,
    params: list[dict],
    func_code: str,
    algorithms: list,
) -> list[SemanticName]:
    """Worker versiyonu: Strateji 1 -- Algoritma sablonu."""
    results: list[SemanticName] = []
    best_confidence = 0.0
    best_template_name: str | None = None

    sorted_algos = sorted(algorithms, key=lambda a: a.confidence, reverse=True)
    for algo in sorted_algos:
        normalized = _normalize_algo_name(algo.name)
        if normalized is None:
            continue
        if normalized not in ALGORITHM_PARAM_TEMPLATES:
            continue
        if algo.confidence > best_confidence:
            best_confidence = algo.confidence
            best_template_name = normalized

    if best_template_name is None:
        return results

    template = ALGORITHM_PARAM_TEMPLATES[best_template_name]
    domain = _W_FUNC_DOMAINS.get(func_name, "generic")

    for tmpl in template:
        if tmpl.position >= len(params):
            continue
        param = params[tmpl.position]
        param_name = param.get("name", "")
        param_type = param.get("type", "")

        if not _is_auto_or_generic_name(param_name):
            continue

        type_match = _types_compatible(tmpl.type_hint, param_type)
        conf = 0.85  # _BASE_CONFIDENCE["algorithm_template"]
        if type_match:
            conf *= min(1.0, best_confidence + 0.15)
        else:
            conf *= 0.70
        conf = min(0.98, conf)

        results.append(SemanticName(
            original_name=param_name,
            semantic_name=_sanitize_c_name(tmpl.name),
            function_name=func_name,
            confidence=round(conf, 3),
            source="algorithm_template",
            reason=f"Algorithm '{best_template_name}' template, position {tmpl.position}: {tmpl.comment}",
            domain=domain,
        ))
    return results


def _worker_name_from_struct_context(
    func_name: str,
    params: list[dict],
    func_code: str,
) -> list[SemanticName]:
    """Worker versiyonu: Strateji 3 -- Struct field context."""
    results: list[SemanticName] = []
    domain = _W_FUNC_DOMAINS.get(func_name, "generic")

    for param in params:
        param_name = param.get("name", "")
        param_type = param.get("type", "")
        if not _is_auto_or_generic_name(param_name):
            continue

        for es in _W_ENRICHED_STRUCTS:  # type: ignore[union-attr]
            struct_name = getattr(es, "name", "")
            raw_name = getattr(es, "raw_name", "")
            src_funcs = getattr(es, "source_functions", [])
            struct_conf = getattr(es, "confidence", 0.5)
            struct_domain = getattr(es, "domain", None)

            type_matches = (
                struct_name.lower() in param_type.lower()
                or raw_name.lower() in param_type.lower()
            )
            func_matches = func_name in src_funcs

            if type_matches or func_matches:
                p = re.escape(param_name)
                has_offset = bool(re.search(rf"\*\s*\([^)]*\)\s*\(\s*{p}\s*\+", func_code))
                if not has_offset and not type_matches:
                    continue

                suggested = _struct_name_to_param(struct_name)
                if not suggested:
                    continue

                conf = 0.70 * min(1.0, struct_conf + 0.1)  # _BASE_CONFIDENCE["struct_context"]
                conf = min(0.98, conf)

                results.append(SemanticName(
                    original_name=param_name,
                    semantic_name=_sanitize_c_name(suggested),
                    function_name=func_name,
                    confidence=round(conf, 3),
                    source="struct_context",
                    reason=f"Struct '{struct_name}' identified in function context",
                    domain=struct_domain or domain,
                ))
                break
    return results


def _struct_name_to_param(struct_name: str) -> str:
    """Struct ismini parametre ismine donustur (module-level copy for workers)."""
    if not struct_name:
        return ""
    parts = re.findall(r"[A-Z][a-z]*|[a-z]+|[A-Z]+(?=[A-Z][a-z]|$)", struct_name)
    if not parts:
        return struct_name.lower()
    abbreviations = {
        "element": "elem", "context": "ctx", "information": "info",
        "structure": "struct", "configuration": "cfg", "parameter": "param",
        "coordinates": "coords", "properties": "props", "material": "mat",
        "boundary": "bc", "condition": "cond", "conditions": "cond",
    }
    return "_".join(abbreviations.get(p.lower(), p.lower()) for p in parts)


def _worker_infer_from_type_and_usage(
    func_name: str,
    params: list[dict],
    func_code: str,
    domain: str,
) -> list[SemanticName]:
    """Worker versiyonu: Strateji 4 -- Type + usage heuristic."""
    results: list[SemanticName] = []
    if not domain:
        domain = "generic"

    for param in params:
        param_name = param.get("name", "")
        param_type = param.get("type", "")
        param_pos = param.get("position", -1)
        if not _is_auto_or_generic_name(param_name):
            continue

        # First-parameter self/ctx heuristic
        if param_pos == 0 and param_type in _FIRST_PARAM_SELF_TYPES:
            usage_check = _detect_usage_pattern(func_code, param_name)
            if usage_check == "offset_access":
                results.append(SemanticName(
                    original_name=param_name,
                    semantic_name="self",
                    function_name=func_name,
                    confidence=0.65,
                    source="type_heuristic",
                    reason=f"First param ({param_type}) with struct offset access -> method-like self/this",
                    domain=domain,
                ))
                continue

        best_name: str | None = None
        best_conf: float = 0.0
        best_reason: str = ""

        loop_depth = _get_loop_depth_for_param(func_code, param_name)
        usage = _detect_usage_pattern(func_code, param_name)
        idx_pattern = _detect_index_pattern(func_code, param_name)

        for tup in TYPE_USAGE_PATTERNS:
            if not _types_compatible(tup.c_type, param_type):
                continue
            if tup.loop_depth is not None:
                if tup.loop_depth == 3 and loop_depth < 3:
                    continue
                if tup.loop_depth == 2 and loop_depth < 2:
                    continue
                if tup.loop_depth == 1 and loop_depth < 1:
                    continue
            if tup.index_pattern is not None:
                if tup.index_pattern == "sequential" and idx_pattern != "sequential":
                    continue
                if tup.index_pattern == "2d_linear" and idx_pattern != "2d_linear":
                    continue
            if tup.usage_pattern is not None:
                if tup.usage_pattern != usage:
                    continue

            conf = tup.confidence
            suggested = tup.name
            if tup.domain_prefix and domain in tup.domain_prefix:
                suggested = tup.domain_prefix[domain] + tup.name
            elif tup.domain_prefix and "generic" in tup.domain_prefix:
                suggested = tup.domain_prefix["generic"] + tup.name

            if conf > best_conf:
                best_conf = conf
                best_name = suggested
                best_reason = (
                    f"Type '{param_type}', loop depth {loop_depth}, "
                    f"usage '{usage}', index '{idx_pattern}'"
                )

        if best_name:
            # Context-based pointer override
            if "matrix" in best_name and "*" in param_type:
                best_name = _worker_context_override_for_pointer(func_code, best_name)

            results.append(SemanticName(
                original_name=param_name,
                semantic_name=_sanitize_c_name(best_name),
                function_name=func_name,
                confidence=round(best_conf, 3),
                source="type_heuristic",
                reason=best_reason,
                domain=domain,
            ))
    return results


def _worker_context_override_for_pointer(func_code: str, default_name: str) -> str:
    """Worker versiyonu: pointer tipli parametreler icin context override."""
    code_lower = func_code.lower()
    if any(fn in code_lower for fn in ("memcpy", "memmove", "memset", "bzero")):
        return default_name.replace("matrix", "buffer")
    if any(fn in code_lower for fn in ("strlen", "strcmp", "strcpy", "strncpy")):
        return default_name.replace("matrix", "string")
    if any(fn in code_lower for fn in ("malloc", "calloc", "realloc")):
        return default_name.replace("matrix", "data")
    if any(fn in code_lower for fn in ("fread", "fwrite", "read(", "write(")):
        return default_name.replace("matrix", "io_buffer")
    return default_name


def _worker_infer_from_call_context(
    func_name: str,
    params: list[dict],
    func_code: str,
    domain: str,
) -> list[SemanticName]:
    """Worker versiyonu: Strateji 5 -- Call-context naming."""
    results: list[SemanticName] = []
    if _W_API_PARAM_DB is None or not func_code:
        return results
    if not domain:
        domain = "generic"

    generic_params: dict[str, dict] = {}
    for param in params:
        pname = param.get("name", "")
        if _is_auto_or_generic_name(pname):
            generic_params[pname] = param

    if not generic_params:
        return results

    renames = _W_API_PARAM_DB.propagate_params(func_code)
    base_conf = 0.65  # _BASE_CONFIDENCE["call_context"]

    for old_name, suggested_name in renames.items():
        if old_name not in generic_params:
            continue
        results.append(SemanticName(
            original_name=old_name,
            semantic_name=_sanitize_c_name(suggested_name),
            function_name=func_name,
            confidence=round(base_conf, 3),
            source="call_context",
            reason=f"API call context: param '{old_name}' passed as '{suggested_name}' to known API",
            domain=domain,
        ))
    return results


# Minimum fonksiyon sayisi -- bunun altinda paralel islem overhead yaratir
_MIN_FUNCS_FOR_PARALLEL = 500


# ---------------------------------------------------------------------------
# Ana sinif: SemanticParameterNamer
# ---------------------------------------------------------------------------

class SemanticParameterNamer:
    """Algoritma-baglam-bilinçli parametre ve degisken isimlendirici.

    CVariableNamer ve NameMerger sonrasinda ek bir isleme katmani olarak
    calisir. Yalnizca Ghidra otomatik isimlerini (param_N, local_XX) veya
    dusuk-confidence genel isimleri yeniden adlandirir.

    Dort isimlendirme stratejisi (oncelik sirasina gore):
    1. Algorithm Template Matching (conf 0.85) -- tespit edilen algoritmaya sablon uygula
    2. Call Graph Propagation    (conf 0.75) -- caller'dan callee'ye isim yay
    3. Struct Field Context      (conf 0.70) -- Module 1 struct bilgisinden isim
    4. Type+Usage Heuristic      (conf 0.60) -- tip ve kullanim oruntusunden isim

    Cakisma durumunda en yuksek confidence kazanir. Esit confidence'da
    oncelik sirasi: template > callgraph > struct > heuristic.
    """

    _STRATEGY_PRIORITY = {
        "signature_based": 5,        # v1.7.2: highest priority -- known function params
        "algorithm_template": 4,
        "call_graph_propagation": 3,
        "struct_context": 2,
        "call_context": 1,           # v1.7.2: callee-based inference
        "type_heuristic": 0,
    }

    _BASE_CONFIDENCE = {
        "signature_based": 0.92,     # v1.7.2: almost certain -- from known API signatures
        "algorithm_template": 0.85,
        "call_graph_propagation": 0.75,
        "struct_context": 0.70,
        "call_context": 0.65,        # v1.7.2: API call context
        "type_heuristic": 0.60,
    }

    # Call graph propagasyonunda her hop icin confidence carpani
    _PROPAGATION_DECAY = 0.90
    _MAX_PROPAGATION_DEPTH = 3

    def __init__(self, config: Config) -> None:
        self._config = config
        # Dahili state -- her rename() cagrisinda sifirlanir
        self._functions: dict[str, dict[str, Any]] = {}     # name -> func info from JSON
        self._call_graph: dict[str, list[str]] = {}         # caller -> [callees]
        self._reverse_graph: dict[str, list[str]] = {}      # callee -> [callers]
        self._func_codes: dict[str, str] = {}               # func_name -> C code
        self._func_algorithms: dict[str, list] = {}         # func -> [AlgorithmMatch]
        self._func_domains: dict[str, str] = {}             # func -> domain string
        self._addr_to_name: dict[str, str] = {}             # address -> func name
        self._name_to_addr: dict[str, str] = {}             # func name -> address
        # v1.7.2: signature_db -> param naming
        self._sig_matches: dict[str, Any] = {}              # func_name -> SignatureMatch
        self._api_param_db: Any = None                      # Lazy-loaded APIParamDB

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def rename(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        call_graph_json: Path,
        output_dir: Path,
        *,
        algorithm_matches: list | None = None,
        domain_report: Any | None = None,
        enriched_structs: list | None = None,
        signature_matches: list | None = None,  # v1.7.2: SignatureMatch list
    ) -> SemanticNamingResult:
        """Tum C dosyalarindaki parametreleri semantik olarak yeniden adlandir.

        Args:
            decompiled_dir: Girdi C dosyalarinin bulundugu dizin.
            functions_json: ghidra_functions.json yolu.
            call_graph_json: ghidra_call_graph.json yolu.
            output_dir: Cikti C dosyalarinin yazilacagi dizin.
            algorithm_matches: Tespit edilen algoritmalar (Step 1 ciktisi, opsiyonel).
            domain_report: Domain siniflandirma raporu (opsiyonel).
            enriched_structs: Module 1 struct tespiti (opsiyonel).
            signature_matches: v1.7.2 -- SignatureMatch listesi (signature_db ciktisi).

        Returns:
            SemanticNamingResult
        """
        errors: list[str] = []
        all_names: list[SemanticName] = []
        naming_map: dict[str, dict[str, str]] = {}

        # 1. Veri yukle
        try:
            self._load_functions(functions_json)
        except Exception as exc:
            errors.append(f"functions_json yuklenemedi: {exc}")
            return SemanticNamingResult(success=False, errors=errors)

        try:
            self._load_call_graph(call_graph_json)
        except Exception as exc:
            errors.append(f"call_graph_json yuklenemedi: {exc}")
            # Call graph olmadan da devam edebiliriz (strateji 2 atlanir)

        # 2. Algoritma eslesmelerini fonksiyon bazinda organize et
        self._func_algorithms.clear()
        if algorithm_matches:
            for match in algorithm_matches:
                fname = match.function_name
                if fname not in self._func_algorithms:
                    self._func_algorithms[fname] = []
                self._func_algorithms[fname].append(match)

        # 2b. v1.7.2: Signature eslesmelerini fonksiyon bazinda organize et
        self._sig_matches.clear()
        if signature_matches:
            for sm in signature_matches:
                orig = getattr(sm, "original_name", "")
                if orig:
                    self._sig_matches[orig] = sm

        # 2c. v1.7.2: APIParamDB lazy-load
        if self._api_param_db is None:
            try:
                from karadul.reconstruction.api_param_db import APIParamDB
                self._api_param_db = APIParamDB()
            except ImportError:
                logger.debug("APIParamDB import edilemedi, signature-based naming atlanir")

        # 3. Domain bilgisini fonksiyon bazinda kaydet
        self._func_domains.clear()
        if domain_report:
            for cls in getattr(domain_report, "classifications", []):
                self._func_domains[cls.function_name] = cls.primary_domain

        # 4. C dosyalarini oku
        self._func_codes.clear()
        c_files = sorted(decompiled_dir.glob("*.c"))
        if not c_files:
            errors.append(f"Decompiled dizininde C dosyasi bulunamadi: {decompiled_dir}")
            return SemanticNamingResult(success=False, errors=errors)

        for c_file in c_files:
            try:
                code = c_file.read_text(encoding="utf-8", errors="replace")
                self._extract_functions_from_code(code)
            except Exception as exc:
                errors.append(f"{c_file.name} okunamadi: {exc}")

        # 5. Her fonksiyon icin stratejileri uygula (2 fazli paralel yaklasim)
        #
        # Faz 1: Bagimsiz stratejiler (0,1,3,4,5) -- paralel chunk'lar
        #   ProcessPoolExecutor ile fonksiyon chunk'larini paralel isle.
        #   Strateji 2 (Call Graph Propagation) ordering-dependent oldugundan
        #   burada UYGULANMAZ.
        #
        # Faz 2: Call Graph Propagation (Strateji 2) -- sequential
        #   Faz 1 sonuclarini kullanarak her fonksiyon icin propagasyon yap.

        func_names_list = list(self._func_codes.keys())
        total_funcs = len(func_names_list)
        use_parallel = total_funcs >= _MIN_FUNCS_FOR_PARALLEL

        # --- Faz 1: Bagimsiz stratejiler ---
        phase1_candidates: list[SemanticName] = []

        if use_parallel:
            n_workers = min(CPU_PERF_CORES, max(2, total_funcs // 500))
            chunk_size = math.ceil(total_funcs / n_workers)
            chunks = [
                func_names_list[i : i + chunk_size]
                for i in range(0, total_funcs, chunk_size)
            ]
            logger.info(
                "Semantic namer Faz 1: %d fonksiyon, %d worker, %d chunk_size",
                total_funcs, n_workers, chunk_size,
            )
            try:
                with ProcessPoolExecutor(
                    max_workers=n_workers,
                    initializer=_worker_init,
                    initargs=(
                        self._func_codes,
                        self._functions,
                        self._func_algorithms,
                        self._func_domains,
                        self._sig_matches,
                        enriched_structs,
                        self._reverse_graph,
                    ),
                ) as pool:
                    for chunk_result in pool.map(_worker_process_chunk, chunks):
                        phase1_candidates.extend(chunk_result)
            except Exception as exc:
                # Paralel basarisiz olursa sequential fallback
                logger.warning(
                    "Paralel Faz 1 basarisiz (%s), sequential fallback", exc,
                )
                phase1_candidates = self._phase1_sequential(
                    func_names_list, enriched_structs,
                )
        else:
            # Az fonksiyon -- paralel overhead'e degmez
            phase1_candidates = self._phase1_sequential(
                func_names_list, enriched_structs,
            )

        # Faz 1 sonuclarini fonksiyon bazinda grupla
        phase1_by_func: dict[str, list[SemanticName]] = defaultdict(list)
        for sn in phase1_candidates:
            phase1_by_func[sn.function_name].append(sn)

        # --- Faz 2: Call Graph Propagation (Strateji 2) + cakisma cozumleme ---
        for func_name in func_names_list:
            params = self._get_function_params(func_name)
            if not params:
                # Faz 1'den gelen candidate'lari da cozumle (params olmadan da olabilir)
                faz1 = phase1_by_func.get(func_name, [])
                if faz1:
                    resolved = self._resolve_conflicts(faz1)
                    if resolved:
                        all_names.extend(resolved)
                        func_map_: dict[str, str] = {}
                        for sn in resolved:
                            func_map_[sn.original_name] = sn.semantic_name
                        if func_map_:
                            naming_map[func_name] = func_map_
                continue

            candidates = list(phase1_by_func.get(func_name, []))

            # Strateji 2: Call graph propagasyonu (sequential -- ordering-dependent)
            if self._reverse_graph:
                known_so_far = self._build_known_names(all_names, candidates)
                candidates.extend(
                    self._propagate_from_callers(func_name, params, known_so_far)
                )

            # Cakisma cozumle
            resolved = self._resolve_conflicts(candidates)
            if resolved:
                all_names.extend(resolved)
                func_map: dict[str, str] = {}
                for sn in resolved:
                    func_map[sn.original_name] = sn.semantic_name
                if func_map:
                    naming_map[func_name] = func_map

        # 6. Isimleri C dosyalarina uygula ve kaydet
        output_dir.mkdir(parents=True, exist_ok=True)
        output_files: list[Path] = []

        for c_file in c_files:
            try:
                code = c_file.read_text(encoding="utf-8", errors="replace")

                # v1.8.0: Dosyadaki tum rename'leri tek cagriyla uygula.
                # _apply_names_to_code pre-computed span'ler kullanir,
                # sadece dosyada tanimli fonksiyonlara dokunur (call site degil).
                new_code = self._apply_names_to_code(code, all_names)
                modified = new_code != code
                if modified:
                    code = new_code

                out_path = output_dir / c_file.name
                if modified:
                    out_path.write_text(code, encoding="utf-8")
                else:
                    # Degisiklik yoksa olduğu gibi kopyala
                    shutil.copy2(c_file, out_path)
                output_files.append(out_path)
            except Exception as exc:
                errors.append(f"{c_file.name} yazılamadi: {exc}")

        # 7. param_naming_map.json kaydet
        map_path = output_dir.parent / "param_naming_map.json"
        try:
            map_data = {
                "version": "1.7.2",  # v1.7.2
                "total_renamed": len(all_names),
                "functions": {},
            }
            for func_name, func_map in naming_map.items():
                map_data["functions"][func_name] = {
                    "renames": func_map,
                    "domain": self._func_domains.get(func_name, "unknown"),
                }
            map_path.write_text(
                json.dumps(map_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            errors.append(f"param_naming_map.json yazilamadi: {exc}")

        # 8. Istatistikleri hesapla
        by_source: dict[str, int] = defaultdict(int)
        by_domain: dict[str, int] = defaultdict(int)
        for sn in all_names:
            by_source[sn.source] += 1
            by_domain[sn.domain] += 1

        return SemanticNamingResult(
            success=True,
            names=all_names,
            total_renamed=len(all_names),
            by_source=dict(by_source),
            by_domain=dict(by_domain),
            output_files=output_files,
            naming_map=naming_map,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Veri yukleme
    # ------------------------------------------------------------------

    def _load_functions(self, path: Path) -> None:
        """ghidra_functions.json'u yukle."""
        if not path.exists():
            raise FileNotFoundError(f"Functions JSON bulunamadi: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        self._functions.clear()
        self._addr_to_name.clear()
        self._name_to_addr.clear()

        funcs = data if isinstance(data, list) else data.get("functions", [])
        for func in funcs:
            name = func.get("name", "")
            addr = func.get("address", "")
            if name:
                self._functions[name] = func
                if addr:
                    self._addr_to_name[addr] = name
                    self._name_to_addr[name] = addr

    def _load_call_graph(self, path: Path) -> None:
        """ghidra_call_graph.json'u yukle, caller->callee ve reverse graph olustur."""
        if not path.exists():
            logger.warning("Call graph dosyasi bulunamadi: %s", path)
            self._call_graph.clear()
            self._reverse_graph.clear()
            return

        data = json.loads(path.read_text(encoding="utf-8"))
        raw_nodes = data.get("nodes", {})
        edges = data.get("edges", [])

        # Adres -> isim haritasi
        addr_to_name: dict[str, str] = {}
        if isinstance(raw_nodes, dict):
            nodes = list(raw_nodes.values())
        elif isinstance(raw_nodes, list):
            nodes = raw_nodes
        else:
            nodes = []

        for node in nodes:
            if isinstance(node, str):
                continue
            addr = node.get("address", "")
            name = node.get("name", "")
            if addr and name:
                addr_to_name[addr] = name

        self._call_graph.clear()
        self._reverse_graph.clear()

        for edge in edges:
            src_addr = edge.get("from", "")
            dst_addr = edge.get("to", "")
            src_name = addr_to_name.get(src_addr, "")
            dst_name = addr_to_name.get(dst_addr, "")
            if src_name and dst_name:
                self._call_graph.setdefault(src_name, []).append(dst_name)
                self._reverse_graph.setdefault(dst_name, []).append(src_name)

        logger.info(
            "Semantic namer call graph: %d node, %d edge",
            len(addr_to_name), len(edges),
        )

    def _extract_functions_from_code(self, code: str) -> None:
        """C kodundan fonksiyon isimlerini ve govdelerini cikar."""
        # Fonksiyon baslangiclarini bul
        for match in _FUNC_SIG_RE.finditer(code):
            func_name = match.group(1)
            start = match.start()
            # Fonksiyon govdesi: { ile } eslestir
            brace_count = 0
            body_start = code.index("{", start)
            i = body_start
            while i < len(code):
                if code[i] == "{":
                    brace_count += 1
                elif code[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        self._func_codes[func_name] = code[start:i + 1]
                        break
                i += 1

    def _get_function_params(self, func_name: str) -> list[dict[str, str]]:
        """Fonksiyonun parametrelerini dondur.

        Oncelik: functions_json'dan. Yoksa kod imzasindan parse et.
        """
        # JSON'dan
        func_info = self._functions.get(func_name)
        if func_info and func_info.get("params"):
            return func_info["params"]

        # Koddan parse et
        code = self._func_codes.get(func_name, "")
        if not code:
            return []

        sig_match = _FUNC_SIG_RE.search(code)
        if not sig_match:
            return []

        param_str = sig_match.group(2).strip()
        if not param_str or param_str == "void":
            return []

        params = []
        for i, raw in enumerate(param_str.split(",")):
            raw = raw.strip()
            if not raw:
                continue
            pm = _PARAM_PARSE_RE.match(raw)
            if pm:
                params.append({
                    "name": pm.group(2),
                    "type": pm.group(1).strip(),
                    "position": i,
                })
            else:
                # Parse edilemezse ham haliyle kaydet
                parts = raw.rsplit(None, 1)
                if len(parts) == 2:
                    params.append({
                        "name": parts[1].strip("*").strip(),
                        "type": parts[0].strip(),
                        "position": i,
                    })

        return params

    # ------------------------------------------------------------------
    # v1.7.2 Strateji 0: Signature-Based Parameter Naming
    # ------------------------------------------------------------------

    def _apply_signature_based_naming(
        self,
        func_name: str,
        params: list[dict],
    ) -> list[SemanticName]:
        """Signature DB ile eslesen fonksiyonlarin bilinen param isimlerini kopyala.  # v1.7.2

        Ornek: FUN_00401000 -> signature_db ile "sqlite3_open" olarak tanimlandi.
        APIParamDB'de sqlite3_open(filename, ppDb) biliniyor.
        -> param_1 = "filename", param_2 = "ppDb"

        Bu strateji en yuksek onceliktedir (conf 0.92) cunku isim kaynagi
        kesindir -- orijinal kutuphanenin dokumantasyonundan gelmektedir.
        """
        results: list[SemanticName] = []
        sig_match = self._sig_matches.get(func_name)
        if sig_match is None or self._api_param_db is None:
            return results

        matched_name = getattr(sig_match, "matched_name", "")
        sig_confidence = getattr(sig_match, "confidence", 0.0)
        library = getattr(sig_match, "library", "")
        if not matched_name:
            return results

        # APIParamDB'den bilinen parametre isimlerini al
        # Orijinal isimle ve underscore-prefix versiyonuyla dene
        known_params = self._api_param_db.get_param_names(matched_name)
        if known_params is None and matched_name.startswith("_"):
            known_params = self._api_param_db.get_param_names(matched_name[1:])
        if known_params is None and not matched_name.startswith("_"):
            known_params = self._api_param_db.get_param_names(f"_{matched_name}")
        if not known_params:
            return results

        domain = self._func_domains.get(func_name, "generic")
        base_conf = self._BASE_CONFIDENCE["signature_based"]

        for param in params:
            param_name = param.get("name", "")
            param_pos = param.get("position", -1)
            if param_pos < 0 or param_pos >= len(known_params):
                continue
            if not _is_auto_or_generic_name(param_name):
                continue

            known_name = known_params[param_pos]
            if not known_name:
                continue

            # Confidence: base * signature_db confidence (minimum 0.5)
            conf = base_conf * max(0.5, min(1.0, sig_confidence))
            conf = min(0.98, conf)

            results.append(SemanticName(
                original_name=param_name,
                semantic_name=_sanitize_c_name(known_name),
                function_name=func_name,
                confidence=round(conf, 3),
                source="signature_based",
                reason=f"Signature match: {func_name} = {matched_name} ({library}), param[{param_pos}] = '{known_name}'",
                domain=domain,
            ))

        if results:
            logger.debug(
                "Signature-based naming: %s -> %s: %d params renamed",
                func_name, matched_name, len(results),
            )

        return results

    # ------------------------------------------------------------------
    # Strateji 1: Algoritma Sablon Eslestirme
    # ------------------------------------------------------------------

    def _apply_algorithm_templates(
        self,
        func_name: str,
        params: list[dict],
        func_code: str,
        algorithms: list,
    ) -> list[SemanticName]:
        """Tespit edilen algoritmaya gore parametre sablonu uygula.

        Her AlgorithmMatch icin ALGORITHM_PARAM_TEMPLATES'dan eslesen sablonu
        bul, parametreleri pozisyon ve tip uyumuna gore esle.
        """
        results: list[SemanticName] = []
        best_confidence = 0.0
        best_template_name: str | None = None

        # En yuksek confidence'li algoritmadan baslayarak sablon ara
        sorted_algos = sorted(algorithms, key=lambda a: a.confidence, reverse=True)

        for algo in sorted_algos:
            normalized = _normalize_algo_name(algo.name)
            if normalized is None:
                continue
            if normalized not in ALGORITHM_PARAM_TEMPLATES:
                continue
            if algo.confidence > best_confidence:
                best_confidence = algo.confidence
                best_template_name = normalized

        if best_template_name is None:
            return results

        template = ALGORITHM_PARAM_TEMPLATES[best_template_name]
        domain = self._func_domains.get(func_name, "generic")

        for tmpl in template:
            if tmpl.position >= len(params):
                continue

            param = params[tmpl.position]
            param_name = param.get("name", "")
            param_type = param.get("type", "")

            # Sadece Ghidra otomatik isimlerini degistir
            if not _is_auto_or_generic_name(param_name):
                continue

            # Tip uyumluluğu: eslesmezse confidence duser ama yine de isimlendir
            type_match = _types_compatible(tmpl.type_hint, param_type)
            conf = self._BASE_CONFIDENCE["algorithm_template"]
            if type_match:
                conf *= min(1.0, best_confidence + 0.15)
            else:
                conf *= 0.70  # Tip uyumsuz: %30 ceza

            conf = min(0.98, conf)

            results.append(SemanticName(
                original_name=param_name,
                semantic_name=_sanitize_c_name(tmpl.name),
                function_name=func_name,
                confidence=round(conf, 3),
                source="algorithm_template",
                reason=f"Algorithm '{best_template_name}' template, position {tmpl.position}: {tmpl.comment}",
                domain=domain,
            ))

        return results

    # ------------------------------------------------------------------
    # Strateji 2: Call Graph Propagasyonu
    # ------------------------------------------------------------------

    def _propagate_from_callers(
        self,
        func_name: str,
        params: list[dict],
        known_names: dict[str, dict[str, str]],
    ) -> list[SemanticName]:
        """Caller'daki isimli degiskenleri callee parametrelerine yay.

        Yaklasim:
        1. func_name'in caller'larini bul (reverse graph)
        2. Her caller'in kodunda func_name cagrisini ara
        3. Cagri argumanlari ile parametreleri esle
        4. Caller'daki arguman zaten isimli ise, callee parametresine yay

        Ek olarak CALLER_NAME_HINTS tablosundan da isim ipucu alinir.
        """
        results: list[SemanticName] = []
        callers = self._reverse_graph.get(func_name, [])
        domain = self._func_domains.get(func_name, "generic")

        for param in params:
            param_name = param.get("name", "")
            param_pos = param.get("position", -1)
            if param_pos < 0:
                continue
            if not _is_auto_or_generic_name(param_name):
                continue

            best_name: str | None = None
            best_conf: float = 0.0
            best_reason: str = ""

            # a) CALLER_NAME_HINTS tablosundan dogrudan ipucu
            for hint_name, hint_map in CALLER_NAME_HINTS.items():
                # func_name, hint_name olarak cagriliyorsa
                # (bu nadirdir -- genellikle func_name bir FUN_xxx'tir)
                # Ama caller'in ismi hint'lerden biriyse, arguman pozisyonu eslesir
                for caller in callers:
                    caller_lower = caller.lower().replace("fun_", "").replace("_", "")
                    hint_lower = hint_name.lower().replace("_", "")
                    if hint_lower in caller_lower or caller_lower in hint_lower:
                        if param_pos in hint_map:
                            name = hint_map[param_pos]
                            conf = self._BASE_CONFIDENCE["call_graph_propagation"]
                            if conf > best_conf:
                                best_conf = conf
                                best_name = name
                                best_reason = f"Caller hint: {caller} matches pattern '{hint_name}', arg {param_pos}"

            # b) Caller kodundaki isimli argumani propagate et
            for caller in callers:
                caller_code = self._func_codes.get(caller, "")
                if not caller_code:
                    continue
                # v1.8.0: [^)]*  negated char class -> O(n) safe, boyut siniri yok.
                if func_name not in caller_code:
                    continue

                # Caller kodunda func_name cagrisini bul
                call_pattern = re.compile(
                    rf"\b{re.escape(func_name)}\s*\(([^)]*)\)"
                )
                for call_match in call_pattern.finditer(caller_code):
                    args_str = call_match.group(1)
                    args = [a.strip() for a in args_str.split(",")]
                    if param_pos < len(args):
                        arg_name = args[param_pos].strip()
                        # Arguman anlamli bir isim mi?
                        if arg_name and not _is_auto_or_generic_name(arg_name):
                            # Ismi dogrudan al ama basit temizle
                            clean = _sanitize_c_name(arg_name)
                            if clean and len(clean) > 1:
                                conf = self._BASE_CONFIDENCE["call_graph_propagation"] * self._PROPAGATION_DECAY
                                if conf > best_conf:
                                    best_conf = conf
                                    best_name = clean
                                    best_reason = f"Propagated from caller '{caller}', arg '{arg_name}' at position {param_pos}"

                # c) Caller'da zaten bilinen isimler varsa, onlari da kontrol et
                caller_known = known_names.get(caller, {})
                if caller_known:
                    for call_match in call_pattern.finditer(caller_code):
                        args_str = call_match.group(1)
                        args = [a.strip() for a in args_str.split(",")]
                        if param_pos < len(args):
                            arg_name = args[param_pos].strip()
                            if arg_name in caller_known:
                                propagated = caller_known[arg_name]
                                conf = self._BASE_CONFIDENCE["call_graph_propagation"] * (self._PROPAGATION_DECAY ** 2)
                                if conf > best_conf:
                                    best_conf = conf
                                    best_name = propagated
                                    best_reason = f"Propagated (2-hop) from caller '{caller}': {arg_name} -> {propagated}"

            if best_name:
                results.append(SemanticName(
                    original_name=param_name,
                    semantic_name=_sanitize_c_name(best_name),
                    function_name=func_name,
                    confidence=round(best_conf, 3),
                    source="call_graph_propagation",
                    reason=best_reason,
                    domain=domain,
                ))

        return results

    # ------------------------------------------------------------------
    # Strateji 3: Struct Field Context
    # ------------------------------------------------------------------

    def _name_from_struct_context(
        self,
        func_name: str,
        params: list[dict],
        enriched_structs: list,
    ) -> list[SemanticName]:
        """Module 1 struct tespitinden parametre ismi cikar.

        Eger bir parametre EnrichedStruct olarak tanimlanmissa, struct ismini
        parametre ismi olarak kullan.

        EnrichedStruct arayuzu (v1.1_plan.md'den):
            .name: str              -- "ElementData", "SolverContext"
            .raw_name: str          -- "recovered_struct_007"
            .source_functions: list[str]
            .algorithm_context: str | None
            .domain: str | None
            .confidence: float
        """
        results: list[SemanticName] = []
        domain = self._func_domains.get(func_name, "generic")

        # Struct isimlerini fonksiyon baglamindan esle
        # Her struct icin: eger bu fonksiyon struct'in source_functions'inda ise
        # veya struct tipi ile parametre tipi eslesiyor ise isimlendir
        struct_by_raw: dict[str, Any] = {}
        for es in enriched_structs:
            raw = getattr(es, "raw_name", "")
            if raw:
                struct_by_raw[raw] = es

        code = self._func_codes.get(func_name, "")
        for param in params:
            param_name = param.get("name", "")
            param_type = param.get("type", "")
            if not _is_auto_or_generic_name(param_name):
                continue

            # a) Parametre tipi struct ismiyle eslesiyor mu?
            for es in enriched_structs:
                struct_name = getattr(es, "name", "")
                raw_name = getattr(es, "raw_name", "")
                src_funcs = getattr(es, "source_functions", [])
                struct_conf = getattr(es, "confidence", 0.5)
                struct_domain = getattr(es, "domain", None)

                # Parametre tipi, struct_name ile eslesiyor mu
                type_matches = (
                    struct_name.lower() in param_type.lower()
                    or raw_name.lower() in param_type.lower()
                )
                # Fonksiyon, struct'in source_functions'inda mi
                func_matches = func_name in src_funcs

                if type_matches or func_matches:
                    # Offset erisim kontrolu: kodda param + 0xNN pattern'i var mi
                    p = re.escape(param_name)
                    has_offset = bool(re.search(rf"\*\s*\([^)]*\)\s*\(\s*{p}\s*\+", code))
                    if not has_offset and not type_matches:
                        continue

                    # Struct ismine gore parametre ismi olustur
                    # "ElementData" -> "elem_data"
                    suggested = self._struct_name_to_param(struct_name)
                    if not suggested:
                        continue

                    conf = self._BASE_CONFIDENCE["struct_context"] * min(1.0, struct_conf + 0.1)
                    conf = min(0.98, conf)

                    results.append(SemanticName(
                        original_name=param_name,
                        semantic_name=_sanitize_c_name(suggested),
                        function_name=func_name,
                        confidence=round(conf, 3),
                        source="struct_context",
                        reason=f"Struct '{struct_name}' identified in function context",
                        domain=struct_domain or domain,
                    ))
                    break  # Her param icin en fazla 1 struct eslesmesi

        return results

    @staticmethod
    def _struct_name_to_param(struct_name: str) -> str:
        """Struct ismini parametre ismine donustur.

        "ElementData"   -> "elem_data"
        "SolverContext"  -> "solver_ctx"
        "MeshInfo"       -> "mesh_info"
        """
        if not struct_name:
            return ""
        # CamelCase'i parcala
        parts = re.findall(r"[A-Z][a-z]*|[a-z]+|[A-Z]+(?=[A-Z][a-z]|$)", struct_name)
        if not parts:
            return struct_name.lower()

        # Kisaltmalar
        abbreviations = {
            "element": "elem",
            "context": "ctx",
            "information": "info",
            "structure": "struct",
            "configuration": "cfg",
            "parameter": "param",
            "coordinates": "coords",
            "properties": "props",
            "material": "mat",
            "boundary": "bc",
            "condition": "cond",
            "conditions": "cond",
        }

        result = []
        for part in parts:
            low = part.lower()
            result.append(abbreviations.get(low, low))

        return "_".join(result)

    # ------------------------------------------------------------------
    # Strateji 4: Type + Usage Heuristic
    # ------------------------------------------------------------------

    def _infer_from_type_and_usage(
        self,
        func_name: str,
        params: list[dict],
        func_code: str,
        domain: str | None,
    ) -> list[SemanticName]:
        """Parametre tipini ve kod icindeki kullanimini inceleyerek isim oner.

        Analiz ettigi sinyaller:
        - Parametre tipi (double *, int, long, ...)
        - Dongü derinligi (triple-nested = matris, single = vektor)
        - Dizi erisim oruntusu (arr[i*n+j] = 2D, arr[i] = 1D)
        - Karsilastirma kullanimi (if param < N = boyut/sayac)
        - Domain baglami (structural -> FEA terimleri, fluid -> CFD terimleri)
        - v1.7.2: First-param self/ctx detection for method-like functions
        """
        results: list[SemanticName] = []
        if not domain:
            domain = "generic"

        for param in params:
            param_name = param.get("name", "")
            param_type = param.get("type", "")
            param_pos = param.get("position", -1)
            if not _is_auto_or_generic_name(param_name):
                continue

            # v1.7.2: First-parameter self/ctx heuristic
            # If position 0, type is long/void*/undefined8, and has offset
            # access (*(type*)(param+0xNN)), it's likely 'self' or 'ctx'
            if param_pos == 0 and param_type in _FIRST_PARAM_SELF_TYPES:
                usage_check = _detect_usage_pattern(func_code, param_name)
                if usage_check == "offset_access":
                    results.append(SemanticName(
                        original_name=param_name,
                        semantic_name="self",
                        function_name=func_name,
                        confidence=0.65,
                        source="type_heuristic",
                        reason=f"First param ({param_type}) with struct offset access -> method-like self/this",
                        domain=domain,
                    ))
                    continue  # self found, skip TYPE_USAGE_PATTERNS for this param

            # Parametre icin en iyi pattern'i bul
            best_name: str | None = None
            best_conf: float = 0.0
            best_reason: str = ""

            # Kullanim analizleri
            loop_depth = _get_loop_depth_for_param(func_code, param_name)
            usage = _detect_usage_pattern(func_code, param_name)
            idx_pattern = _detect_index_pattern(func_code, param_name)

            for tup in TYPE_USAGE_PATTERNS:
                # Tip eslesmesi
                if not _types_compatible(tup.c_type, param_type):
                    continue

                # Dongü derinligi eslesmesi
                if tup.loop_depth is not None:
                    if tup.loop_depth == 3 and loop_depth < 3:
                        continue
                    if tup.loop_depth == 2 and loop_depth < 2:
                        continue
                    if tup.loop_depth == 1 and loop_depth < 1:
                        continue

                # Index pattern eslesmesi
                if tup.index_pattern is not None:
                    if tup.index_pattern == "sequential" and idx_pattern != "sequential":
                        continue
                    if tup.index_pattern == "2d_linear" and idx_pattern != "2d_linear":
                        continue

                # Kullanim oruntusu eslesmesi
                if tup.usage_pattern is not None:
                    if tup.usage_pattern != usage:
                        continue

                # Hepsi eslesti -- isim olustur
                conf = tup.confidence
                suggested = tup.name
                if tup.domain_prefix and domain in tup.domain_prefix:
                    suggested = tup.domain_prefix[domain] + tup.name
                elif tup.domain_prefix and "generic" in tup.domain_prefix:
                    suggested = tup.domain_prefix["generic"] + tup.name

                # Pozisyon-bazli suffix (1. double* = 'a', 2. double* = 'b' vb.)
                # Ayni isimde cakisma onleme _resolve_conflicts'te yapilir

                if conf > best_conf:
                    best_conf = conf
                    best_name = suggested
                    best_reason = (
                        f"Type '{param_type}', loop depth {loop_depth}, "
                        f"usage '{usage}', index '{idx_pattern}'"
                    )

            if best_name:
                # v1.8.0: Context-based override -- "matrix" ismi pointer
                # tipli parametreler icin fonksiyondaki API cagrilarina gore
                # daha spesifik bir isimle degistirilir (buffer, string, vb.)
                if "matrix" in best_name and "*" in param_type:
                    best_name = self._context_override_for_pointer(
                        func_code, best_name,
                    )

                results.append(SemanticName(
                    original_name=param_name,
                    semantic_name=_sanitize_c_name(best_name),
                    function_name=func_name,
                    confidence=round(best_conf, 3),
                    source="type_heuristic",
                    reason=best_reason,
                    domain=domain,
                ))

        return results

    @staticmethod
    def _context_override_for_pointer(func_code: str, default_name: str) -> str:
        """Fonksiyon kodundaki API cagrilarina bakarak 'matrix' ismini daha spesifik bir isimle degistir.

        double* parametreler loop derinligine gore "matrix" ismi alir, ama
        fonksiyonda memcpy/strlen/malloc/fread gibi API'ler varsa bu pointer
        matrix degil buffer/string/data/io_buffer'dir.

        Args:
            func_code: Decompiled C kaynak kodu.
            default_name: Mevcut isim (orn. "M_matrix", "K_matrix").

        Returns:
            Override edilmis isim veya degismemis default_name.
        """
        code_lower = func_code.lower()
        if any(fn in code_lower for fn in ("memcpy", "memmove", "memset", "bzero")):
            return default_name.replace("matrix", "buffer")
        if any(fn in code_lower for fn in ("strlen", "strcmp", "strcpy", "strncpy")):
            return default_name.replace("matrix", "string")
        if any(fn in code_lower for fn in ("malloc", "calloc", "realloc")):
            return default_name.replace("matrix", "data")
        if any(fn in code_lower for fn in ("fread", "fwrite", "read(", "write(")):
            return default_name.replace("matrix", "io_buffer")
        return default_name

    # ------------------------------------------------------------------
    # v1.7.2 Strateji 5: Call-Context Naming
    # ------------------------------------------------------------------

    def _infer_from_call_context(
        self,
        func_name: str,
        params: list[dict],
        func_code: str,
        domain: str | None,
    ) -> list[SemanticName]:
        """Fonksiyonun cagirdigi bilinen API'lerden parametre ismi cikar.  # v1.7.2

        Ornek:
          void FUN_00401000(long param_1, long param_2, int param_3) {
              malloc(param_3);          // -> param_3 = size
              memcpy(local_x, param_1, param_2);  // -> param_1 = src
              send(sock, param_1, param_2, 0);     // -> param_1 = buf, param_2 = len
          }

        Bu strateji, fonksiyon body'sindeki bilinen API cagrilarini tarar ve
        arguman olarak gecirilen parametreleri API'nin bilinen param isimlerine
        gore isimlendirir.
        """
        results: list[SemanticName] = []
        if self._api_param_db is None or not func_code:
            return results
        if not domain:
            domain = "generic"

        # v1.8.0: APIParamDB.propagate_params [^)]* negated char class kullanir.
        # O(n) safe, boyut siniri yok.

        # Hangi parametreler hala generic?
        generic_params: dict[str, dict] = {}
        for param in params:
            pname = param.get("name", "")
            if _is_auto_or_generic_name(pname):
                generic_params[pname] = param

        if not generic_params:
            return results

        # APIParamDB'den bilinen tum API isimlerini al ve fonksiyon kodunda ara
        # Basit ama etkili: bilinen API cagrilarini regex ile bul
        # Performans: buyuk DB icin Aho-Corasick ideal ama burada APIParamDB
        # ~500 fonksiyon, regex yeterli.
        renames = self._api_param_db.propagate_params(func_code)

        base_conf = self._BASE_CONFIDENCE["call_context"]

        for old_name, suggested_name in renames.items():
            if old_name not in generic_params:
                continue

            # Eger ayni param birden fazla API'ye arguman olarak geciyorsa,
            # ilk eslesen kazanir (APIParamDB.propagate_params zaten bunu yapar)
            results.append(SemanticName(
                original_name=old_name,
                semantic_name=_sanitize_c_name(suggested_name),
                function_name=func_name,
                confidence=round(base_conf, 3),
                source="call_context",
                reason=f"API call context: param '{old_name}' passed as '{suggested_name}' to known API",
                domain=domain,
            ))

        return results

    # ------------------------------------------------------------------
    # Cakisma Cozumleme
    # ------------------------------------------------------------------

    def _resolve_conflicts(
        self,
        candidates: list[SemanticName],
    ) -> list[SemanticName]:
        """Ayni parametre icin birden fazla oneri varsa en iyisini sec.

        Kurallar:
        1. Confidence'a gore sirala (buyuk -> kucuk).
        2. Esit confidence'da strateji onceligi: template > callgraph > struct > heuristic.
        3. Ayni fonksiyon icerisinde isim cakismasi varsa _2, _3 ekle.
        4. Zaten anlamli isim olan parametreleri dokunma.
        """
        if not candidates:
            return []

        # Parametreye gore grupla (fonksiyon_ismi + orijinal_isim -> adaylar)
        by_param: dict[tuple[str, str], list[SemanticName]] = defaultdict(list)
        for c in candidates:
            key = (c.function_name, c.original_name)
            by_param[key].append(c)

        winners: list[SemanticName] = []
        # Fonksiyon bazinda kullanilan isimleri takip et
        used_names: dict[str, set[str]] = defaultdict(set)

        # v1.8.0 Bug 2 fix: Mevcut non-auto parametre isimlerini pre-seed et.
        # Boylece semantic rename sonucu mevcut bir parametreyle ayni isim almaz.
        seen_funcs: set[str] = set()
        for (func_name, _), _ in by_param.items():
            if func_name in seen_funcs:
                continue
            seen_funcs.add(func_name)
            for p in self._get_function_params(func_name):
                pname = p.get("name", "")
                if pname and not _is_auto_or_generic_name(pname):
                    used_names[func_name].add(pname)

        for (func_name, orig_name), param_candidates in by_param.items():
            # En iyi adayi sec
            param_candidates.sort(
                key=lambda c: (
                    -c.confidence,
                    -self._STRATEGY_PRIORITY.get(c.source, 0),
                ),
            )
            winner = param_candidates[0]

            # Isim cakismasi kontrolu
            desired = winner.semantic_name
            final_name = desired
            suffix = 2
            while final_name in used_names[func_name]:
                final_name = f"{desired}_{suffix}"
                suffix += 1

            used_names[func_name].add(final_name)
            winner.semantic_name = final_name
            winners.append(winner)

        return winners

    # ------------------------------------------------------------------
    # Kod Yeniden Yazma
    # ------------------------------------------------------------------

    @staticmethod
    def _find_all_function_spans(c_code: str) -> dict[str, tuple[int, int, int]]:
        """C kodundaki tum fonksiyon tanimlarinin span'lerini dondur.

        Returns:
            dict: func_name -> (def_start, body_open_brace, body_close_brace+1)
                  def_start: fonksiyon taniminin (return type) basladigi offset
                  body_open_brace: '{' offseti
                  body_close_brace+1: '}' + 1 offseti
        """
        spans: dict[str, tuple[int, int, int]] = {}
        for match in _FUNC_SIG_RE.finditer(c_code):
            func_name = match.group(1)
            def_start = match.start()
            # Brace matching: govde basini ve sonunu bul
            try:
                brace_start = c_code.index("{", match.end() - 1)
            except ValueError:
                continue
            brace_count = 0
            i = brace_start
            while i < len(c_code):
                if c_code[i] == "{":
                    brace_count += 1
                elif c_code[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        spans[func_name] = (def_start, brace_start, i + 1)
                        break
                i += 1
        return spans

    def _apply_names_to_code(
        self,
        c_code: str,
        names: list[SemanticName],
    ) -> str:
        """C kodundaki param_N isimlerini semantik isimlerle degistir.

        v1.8.0: Fonksiyon span'leri pre-computed, tek pass, bottom-to-top.

        Kurallar:
        - Fonksiyon imzasindaki parametre bildirimine yorum ekle:
          `double *K_global /* was: param_2 */`
        - Fonksiyon govdesindeki tum kullanimlari degistir.
        - Orijinal ismi inline yorum olarak koru (sadece ilk bildirim satirinda).
        """
        if not names:
            return c_code

        # 1. Pre-compute: tum fonksiyon span'lerini bul
        spans = self._find_all_function_spans(c_code)

        # 2. Rename'leri fonksiyon bazinda grupla
        names_by_func: dict[str, list[SemanticName]] = defaultdict(list)
        for sn in names:
            names_by_func[sn.function_name].append(sn)

        # 3. Fonksiyonlari bottom-to-top sirala (offset kaymalarini onlemek icin)
        #    En sondaki fonksiyonu once isleyerek, onceki offsetleri bozmuyoruz.
        func_order: list[tuple[str, tuple[int, int, int]]] = []
        for func_name, func_names_list in names_by_func.items():
            if func_name in spans:
                func_order.append((func_name, spans[func_name]))
            else:
                logger.debug(
                    "Semantic namer: fonksiyon span bulunamadi: %s", func_name
                )

        # def_start'a gore ters sirala (bottom-to-top)
        func_order.sort(key=lambda x: x[1][0], reverse=True)

        # 4. Her fonksiyon icin rename uygula
        for func_name, (def_start, body_open, body_close) in func_order:
            func_names_list = names_by_func[func_name]

            # Imza bolgesi: def_start .. body_open
            sig_region = c_code[def_start:body_open]
            # Govde bolgesi: body_open .. body_close
            body_region = c_code[body_open:body_close]

            for sn in func_names_list:
                orig = sn.original_name
                new = sn.semantic_name

                # Imzadaki parametre bildirimini degistir (yorum ekleyerek)
                sig_pattern = re.compile(
                    rf"(\b\w[\w\s]*\*?\s*)\b{re.escape(orig)}\b"
                )
                new_sig = sig_pattern.sub(
                    rf"\g<1>{new} /* was: {orig} */",
                    sig_region,
                    count=1,
                )
                if new_sig != sig_region:
                    sig_region = new_sig

                # Govdedeki tum kullanimlari degistir
                new_body = _replace_whole_word(body_region, orig, new)
                # "was:" yorumlarindaki yanlislikla degismis isimleri geri al
                new_body = new_body.replace(f"was: {new}", f"was: {orig}")
                body_region = new_body

            # Degisiklikleri c_code'a uygula (bottom-to-top: offset'ler bozulmaz)
            c_code = (
                c_code[:def_start]
                + sig_region
                + body_region
                + c_code[body_close:]
            )

        return c_code

    # ------------------------------------------------------------------
    # Yardimci
    # ------------------------------------------------------------------

    def _build_known_names(
        self,
        all_names: list[SemanticName],
        current_candidates: list[SemanticName],
    ) -> dict[str, dict[str, str]]:
        """Bilinen tum isimleri fonksiyon bazinda dondur (propagasyon icin)."""
        known: dict[str, dict[str, str]] = defaultdict(dict)
        for sn in all_names:
            known[sn.function_name][sn.original_name] = sn.semantic_name
        for sn in current_candidates:
            known[sn.function_name][sn.original_name] = sn.semantic_name
        return dict(known)

    def _phase1_sequential(
        self,
        func_names: list[str],
        enriched_structs: list | None,
    ) -> list[SemanticName]:
        """Faz 1 stratejilerini (0,1,3,4,5) sequential calistir.

        ProcessPoolExecutor basarisiz oldugunda veya fonksiyon sayisi
        _MIN_FUNCS_FOR_PARALLEL'in altinda oldugunda kullanilir.
        """
        all_candidates: list[SemanticName] = []

        for func_name in func_names:
            func_code = self._func_codes.get(func_name)
            if not func_code:
                continue

            params = self._get_function_params(func_name)
            if not params:
                continue

            candidates: list[SemanticName] = []

            # Strateji 0: Signature-based naming
            if func_name in self._sig_matches and self._api_param_db is not None:
                candidates.extend(
                    self._apply_signature_based_naming(func_name, params)
                )

            # Strateji 1: Algoritma sablonu
            algos = self._func_algorithms.get(func_name, [])
            if algos:
                candidates.extend(
                    self._apply_algorithm_templates(func_name, params, func_code, algos)
                )

            # Strateji 3: Struct field context
            if enriched_structs:
                candidates.extend(
                    self._name_from_struct_context(func_name, params, enriched_structs)
                )

            # Strateji 4: Type + usage heuristic
            domain = self._func_domains.get(func_name, "generic")
            candidates.extend(
                self._infer_from_type_and_usage(func_name, params, func_code, domain)
            )

            # Strateji 5: Call-context naming
            if self._api_param_db is not None:
                candidates.extend(
                    self._infer_from_call_context(func_name, params, func_code, domain)
                )

            all_candidates.extend(candidates)

        return all_candidates
