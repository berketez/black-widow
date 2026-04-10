"""Confidence calibration for engineering algorithm detection.

Analyzer'in urettigi ham Noisy-OR skorlarini kalibre eder.  Ham sistem
bagimsizlik varsayimi yapar, korelasyonu, negatif kaniti ve call-graph
tutarliligini hesaba katmaz.  Bu modul:

1. Korelasyon-duzeltmeli Noisy-OR birlestirme
2. Negatif kanit veritabani (olmamasi gereken API/string'ler)
3. Call-graph tutarliligi (Newton -> LU_solve gibi beklenen cagrilar)
4. Tier siniflandirmasi (CONFIRMED / HIGH / MEDIUM / LOW)
5. v1.6.5: GPU batch Noisy-OR -- tum match'ler icin paralel hesaplama

Kullanim:
    calibrator = ConfidenceCalibrator()
    calibrated = calibrator.calibrate(raw_matches, call_graph, all_func_names)

Entegrasyon:
    EngineeringAlgorithmAnalyzer.identify()  ->  raw matches
    ConfidenceCalibrator.calibrate()         ->  CalibratedMatch listesi
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CalibratedMatch:
    """Algorithm match with calibrated confidence.

    Attributes:
        original: Analyzer'dan gelen orijinal match.
        calibrated_confidence: Kalibrasyon sonrasi guven skoru.
        tier: CONFIRMED / HIGH / MEDIUM / LOW.
        n_independent_sources: Kac bagimsiz katman ayni algoritmaya isaret ediyor.
        negative_evidence_count: Celisken kanit sayisi.
        call_graph_consistency: 0-1 arasi caller/callee uyum skoru.
        calibration_details: Debug bilgisi.
    """

    original: AlgorithmMatch
    calibrated_confidence: float
    tier: str
    n_independent_sources: int
    negative_evidence_count: int
    call_graph_consistency: float
    calibration_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original.to_dict(),
            "calibrated_confidence": round(self.calibrated_confidence, 4),
            "tier": self.tier,
            "n_independent_sources": self.n_independent_sources,
            "negative_evidence_count": self.negative_evidence_count,
            "call_graph_consistency": round(self.call_graph_consistency, 4),
            "calibration_details": self.calibration_details,
        }


# ---------------------------------------------------------------------------
# Negative evidence database
# ---------------------------------------------------------------------------
# Her kategori icin o kategoride olmamasi gereken API/string/pattern'ler.
# Bunlarin varliginda confidence dusurulur.

NEGATIVE_EVIDENCE: dict[str, dict[str, list[str]]] = {
    "fea_integration": {
        "unlikely_apis": [
            "printf", "fprintf", "fopen", "fclose", "socket", "connect",
            "send", "recv", "pthread_create", "fork", "exec",
            "CreateWindow", "glBegin", "glEnd", "sqlite3_open",
        ],
        "unlikely_strings": [
            "http", "json", "xml", "html", "sql", "password",
            "login", "cookie", "token", "oauth",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(", r"connect\s*\(",
            r"accept\s*\(", r"bind\s*\(", r"listen\s*\(",
        ],
    },
    "fea_dynamics": {
        "unlikely_apis": [
            "fopen", "socket", "fork", "CreateWindow",
            "glBegin", "sqlite3_open", "curl_easy",
        ],
        "unlikely_strings": [
            "http", "json", "password", "login", "html", "sql",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(", r"connect\s*\(",
        ],
    },
    "linear_algebra": {
        "unlikely_apis": [
            "fopen", "socket", "fork", "CreateWindow",
            "glBegin", "sqlite3_open", "curl_easy",
            "XCreateWindow", "glutInit",
        ],
        "unlikely_strings": [
            "password", "login", "cookie", "token",
            "oauth", "html", "javascript",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(", r"accept\s*\(",
        ],
    },
    "cfd_turbulence": {
        "unlikely_apis": [
            "CreateWindow", "glBegin", "glEnd", "sqlite3_open",
            "curl_easy", "XCreateWindow", "glutInit",
            "alGenSources", "alSourcePlay",
        ],
        "unlikely_strings": [
            "password", "login", "cookie", "oauth",
            "javascript", "css", "dom",
        ],
        "unlikely_patterns": [
            r"glVertex\w+\s*\(", r"glColor\w+\s*\(",
        ],
    },
    "cfd_solver": {
        "unlikely_apis": [
            "CreateWindow", "glBegin", "sqlite3_open",
            "curl_easy", "alGenSources",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "javascript",
        ],
        "unlikely_patterns": [
            r"glVertex\w+\s*\(",
        ],
    },
    "time_integration": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow", "glBegin",
            "sqlite3_open", "curl_easy",
        ],
        "unlikely_strings": [
            "http", "json", "password", "html", "sql",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(",
        ],
    },
    "numerical_solver": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow", "glBegin",
            "sqlite3_open", "curl_easy", "XCreateWindow",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "html", "css",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(",
        ],
    },
    "nonlinear_solver": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow", "glBegin",
            "sqlite3_open", "curl_easy",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "html",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(",
        ],
    },
    "finite_element": {
        "unlikely_apis": [
            "socket", "connect", "send", "recv",
            "CreateWindow", "glBegin", "sqlite3_open",
            "curl_easy", "alGenSources",
        ],
        "unlikely_strings": [
            "http", "json", "password", "html", "sql",
            "cookie", "oauth", "javascript",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(", r"connect\s*\(",
            r"glVertex\w+\s*\(",
        ],
    },
    "dsp_transform": {
        "unlikely_apis": [
            "sqlite3_open", "CreateWindow", "fork",
            "curl_easy", "XCreateWindow",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "sql",
        ],
        "unlikely_patterns": [],
    },
    "dsp_filter": {
        "unlikely_apis": [
            "sqlite3_open", "CreateWindow", "fork",
            "curl_easy",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "sql",
        ],
        "unlikely_patterns": [],
    },
    "dsp_windowing": {
        "unlikely_apis": [
            "sqlite3_open", "CreateWindow", "fork",
        ],
        "unlikely_strings": [
            "password", "login", "sql",
        ],
        "unlikely_patterns": [],
    },
    "ml_optimization": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow",
            "sqlite3_open", "alGenSources",
        ],
        "unlikely_strings": [
            "password", "login", "html", "css",
        ],
        "unlikely_patterns": [],
    },
    "ml_activation": {
        "unlikely_apis": [
            "socket", "CreateWindow", "sqlite3_open",
            "fork", "exec",
        ],
        "unlikely_strings": [
            "password", "login", "html", "sql",
        ],
        "unlikely_patterns": [],
    },
    "ml_transformer": {
        "unlikely_apis": [
            "socket", "CreateWindow", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "ml_normalization": {
        "unlikely_apis": [
            "socket", "CreateWindow", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "ml_initialization": {
        "unlikely_apis": [
            "socket", "CreateWindow", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login",
        ],
        "unlikely_patterns": [],
    },
    "ml_regularization": {
        "unlikely_apis": [
            "socket", "CreateWindow", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login",
        ],
        "unlikely_patterns": [],
    },
    "finance": {
        "unlikely_apis": [
            "glBegin", "glEnd", "alGenSources",
            "glutInit", "XCreateWindow",
        ],
        "unlikely_strings": [
            "vertex", "shader", "texture", "opengl",
            "vulkan", "directx",
        ],
        "unlikely_patterns": [
            r"glVertex\w+\s*\(", r"glColor\w+\s*\(",
        ],
    },
    "finance_statistics": {
        "unlikely_apis": [
            "glBegin", "alGenSources", "glutInit",
        ],
        "unlikely_strings": [
            "vertex", "shader", "texture",
        ],
        "unlikely_patterns": [],
    },
    "stochastic": {
        "unlikely_apis": [
            "CreateWindow", "glBegin", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "root_finding": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow",
            "glBegin", "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html", "sql",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(",
        ],
    },
    "optimization": {
        "unlikely_apis": [
            "socket", "CreateWindow", "glBegin",
            "sqlite3_open", "alGenSources",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "pde_solver": {
        "unlikely_apis": [
            "CreateWindow", "glBegin", "sqlite3_open",
            "curl_easy", "alGenSources",
        ],
        "unlikely_strings": [
            "password", "login", "oauth", "html",
        ],
        "unlikely_patterns": [
            r"glVertex\w+\s*\(",
        ],
    },
    "interpolation": {
        "unlikely_apis": [
            "socket", "CreateWindow", "glBegin",
            "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "numerical_calculus": {
        "unlikely_apis": [
            "socket", "CreateWindow", "glBegin",
            "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "fea_contact": {
        "unlikely_apis": [
            "socket", "connect", "CreateWindow",
            "glBegin", "sqlite3_open", "curl_easy",
        ],
        "unlikely_strings": [
            "http", "json", "password", "html", "sql",
        ],
        "unlikely_patterns": [
            r"recv\s*\(", r"send\s*\(",
        ],
    },
    "fea_stabilization": {
        "unlikely_apis": [
            "socket", "CreateWindow", "glBegin",
            "sqlite3_open",
        ],
        "unlikely_strings": [
            "password", "login", "html",
        ],
        "unlikely_patterns": [],
    },
    "geometry": {
        "unlikely_apis": [
            "socket", "sqlite3_open", "curl_easy",
        ],
        "unlikely_strings": [
            "password", "login", "sql",
        ],
        "unlikely_patterns": [],
    },
    "graph_algorithm": {
        "unlikely_apis": [
            "glBegin", "alGenSources", "glutInit",
        ],
        "unlikely_strings": [
            "vertex_shader", "fragment_shader",
        ],
        "unlikely_patterns": [],
    },
}


# ---------------------------------------------------------------------------
# Expected call graph relationships
# ---------------------------------------------------------------------------
# Her algoritma icin beklenen callee/caller iliskileri.
# Eger fonksiyonun cagirdigi veya cagirildigi fonksiyonlar arasinda
# beklenenler varsa confidence boost uygulanir.

@dataclass(frozen=True, slots=True)
class CallGraphExpectation:
    """Bir algoritma icin beklenen call-graph iliskileri."""
    expected_callees: tuple[str, ...]
    expected_callers: tuple[str, ...]
    boost_per_match: float
    max_boost: float


EXPECTED_CALL_GRAPH: dict[str, CallGraphExpectation] = {
    # -- Nonlinear solvers ----------------------------------------------------
    "newton_raphson": CallGraphExpectation(
        expected_callees=(
            "lu_solve", "lu_factorization", "lu_decomposition",
            "matrix_multiply", "vector_norm", "gauss_quadrature",
            "triangular_solve", "matrix_inverse",
        ),
        expected_callers=(
            "nonlinear_static", "stiffness_assembly", "fea_assembly",
            "arc_length_method", "contact_algorithm",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "Newton-Raphson": CallGraphExpectation(
        expected_callees=(
            "lu_solve", "lu_factorization", "lu_decomposition",
            "matrix_multiply", "vector_norm", "gauss_quadrature",
            "triangular_solve",
        ),
        expected_callers=(
            "nonlinear_static", "stiffness_assembly", "fea_assembly",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),

    # -- Linear solvers -------------------------------------------------------
    "conjugate_gradient": CallGraphExpectation(
        expected_callees=(
            "axpy", "dot_product", "scalar_multiply", "vector_norm",
            "matrix_vector_multiply", "preconditioner",
        ),
        expected_callers=(
            "linear_solve", "preconditioned_solve", "iterative_solver",
            "fea_assembly",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "Conjugate Gradient": CallGraphExpectation(
        expected_callees=(
            "axpy", "dot_product", "scalar_multiply", "vector_norm",
            "matrix_vector_multiply",
        ),
        expected_callers=(
            "linear_solve", "preconditioned_solve",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "gauss_seidel_jacobi": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "vector_norm", "axpy",
            "scalar_multiply",
        ),
        expected_callers=(
            "linear_solve", "iterative_solver", "multigrid",
        ),
        boost_per_match=0.05,
        max_boost=0.12,
    ),
    "BiCGSTAB": CallGraphExpectation(
        expected_callees=(
            "axpy", "dot_product", "vector_norm",
            "matrix_vector_multiply", "preconditioner",
        ),
        expected_callers=(
            "linear_solve", "iterative_solver",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "GMRES": CallGraphExpectation(
        expected_callees=(
            "axpy", "dot_product", "vector_norm",
            "matrix_vector_multiply", "preconditioner",
            "givens_rotation", "arnoldi_iteration",
        ),
        expected_callers=(
            "linear_solve", "iterative_solver", "krylov_solve",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),

    # -- Direct solvers -------------------------------------------------------
    "lu_decomposition": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "triangular_solve", "scalar_multiply",
            "max_abs_index",
        ),
        expected_callers=(
            "linear_solve", "newton_raphson", "lu_solve",
            "matrix_inverse", "matrix_determinant",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "LU Decomposition": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "triangular_solve", "scalar_multiply",
        ),
        expected_callers=(
            "linear_solve", "newton_raphson",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "cholesky": CallGraphExpectation(
        expected_callees=(
            "triangular_solve", "dot_product", "scalar_multiply",
        ),
        expected_callers=(
            "linear_solve", "least_squares", "cholesky_solve",
            "preconditioner",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "Cholesky Decomposition": CallGraphExpectation(
        expected_callees=(
            "triangular_solve", "dot_product", "scalar_multiply",
        ),
        expected_callers=(
            "linear_solve", "least_squares",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "qr_decomposition": CallGraphExpectation(
        expected_callees=(
            "givens_rotation", "vector_norm", "scalar_multiply",
            "dot_product",
        ),
        expected_callers=(
            "least_squares", "eigenvalue_solver", "linear_solve",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "QR Factorization": CallGraphExpectation(
        expected_callees=(
            "givens_rotation", "vector_norm", "scalar_multiply",
        ),
        expected_callers=(
            "least_squares", "eigenvalue_solver",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),

    # -- FEA integration ------------------------------------------------------
    "gauss_quadrature": CallGraphExpectation(
        expected_callees=(
            "fea_shape_functions", "shape_function_evaluation",
            "b_matrix_assembly", "constitutive_law",
            "matrix_multiply", "matrix_transpose",
        ),
        expected_callers=(
            "fea_assembly", "stiffness_assembly",
            "element_stiffness", "element_mass", "element_load",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "fea_assembly": CallGraphExpectation(
        expected_callees=(
            "gauss_quadrature", "fea_shape_functions",
            "b_matrix_assembly", "constitutive_law",
            "matrix_multiply", "matrix_transpose",
        ),
        expected_callers=(
            "newton_raphson", "linear_solve", "nonlinear_solve",
            "newmark_beta", "hht_alpha",
        ),
        boost_per_match=0.04,
        max_boost=0.15,
    ),
    "fea_shape_functions": CallGraphExpectation(
        expected_callees=(),
        expected_callers=(
            "gauss_quadrature", "fea_assembly",
            "b_matrix_assembly", "isoparametric_mapping",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),

    # -- Time integration -----------------------------------------------------
    "newmark_beta": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "matrix_multiply", "axpy",
            "vector_norm", "lu_solve",
        ),
        expected_callers=(
            "fea_dynamics", "modal_analysis", "time_stepping",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "Newmark-Beta": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "matrix_multiply", "axpy", "vector_norm",
        ),
        expected_callers=(
            "fea_dynamics", "time_stepping",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "hht_alpha": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "matrix_multiply", "axpy",
            "vector_norm", "newton_raphson",
        ),
        expected_callers=(
            "fea_dynamics", "time_stepping",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "runge_kutta_4": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "axpy", "scalar_multiply",
        ),
        expected_callers=(
            "ode_solve", "time_stepping", "gravitational_sim",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "Runge-Kutta 4th Order (RK4)": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "axpy", "scalar_multiply",
        ),
        expected_callers=(
            "ode_solve", "time_stepping",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),

    # -- CFD ------------------------------------------------------------------
    "k_epsilon": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "matrix_vector_multiply",
            "under_relaxation", "wall_function",
        ),
        expected_callers=(
            "simple_pressure_velocity", "fractional_step",
            "piso_algorithm",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "k_omega_sst": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "matrix_vector_multiply",
            "under_relaxation", "wall_function",
        ),
        expected_callers=(
            "simple_pressure_velocity", "fractional_step",
            "piso_algorithm",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "simple_pressure_velocity": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "conjugate_gradient",
            "under_relaxation", "matrix_vector_multiply",
        ),
        expected_callers=(
            "navier_stokes", "cfd_main_loop",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "spalart_allmaras": CallGraphExpectation(
        expected_callees=(
            "linear_solve", "wall_function",
            "under_relaxation",
        ),
        expected_callers=(
            "simple_pressure_velocity", "fractional_step",
        ),
        boost_per_match=0.05,
        max_boost=0.12,
    ),
    "les_smagorinsky": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "fft",
        ),
        expected_callers=(
            "fractional_step", "simple_pressure_velocity",
        ),
        boost_per_match=0.05,
        max_boost=0.12,
    ),

    # -- Eigenvalue solvers ---------------------------------------------------
    "eigenvalue_solver": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "vector_norm", "qr_decomposition",
            "lanczos_iteration", "arnoldi_iteration",
        ),
        expected_callers=(
            "modal_analysis", "linear_buckling", "power_iteration",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "lanczos_iteration": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "dot_product",
            "vector_norm", "axpy",
        ),
        expected_callers=(
            "eigenvalue_solver", "modal_analysis",
        ),
        boost_per_match=0.05,
        max_boost=0.12,
    ),
    "arnoldi_iteration": CallGraphExpectation(
        expected_callees=(
            "matrix_vector_multiply", "dot_product",
            "vector_norm", "axpy",
        ),
        expected_callers=(
            "eigenvalue_solver", "GMRES",
        ),
        boost_per_match=0.05,
        max_boost=0.12,
    ),

    # -- SVD / least squares --------------------------------------------------
    "svd": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "vector_norm", "qr_decomposition",
            "givens_rotation",
        ),
        expected_callers=(
            "least_squares", "condition_number",
            "dimensionality_reduction",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),

    # -- DSP ------------------------------------------------------------------
    "fft": CallGraphExpectation(
        expected_callees=(
            "trigonometric", "complex_multiply",
        ),
        expected_callers=(
            "convolution", "spectral_analysis",
            "les_smagorinsky",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),
    "Fast Fourier Transform": CallGraphExpectation(
        expected_callees=(
            "trigonometric", "complex_multiply",
        ),
        expected_callers=(
            "convolution", "spectral_analysis",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),
    "convolution": CallGraphExpectation(
        expected_callees=(
            "fft", "ifft", "complex_multiply",
        ),
        expected_callers=(
            "dsp_filter", "signal_processing",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),

    # -- ML -------------------------------------------------------------------
    "gradient_descent": CallGraphExpectation(
        expected_callees=(
            "axpy", "scalar_multiply", "dot_product",
            "vector_norm",
        ),
        expected_callers=(
            "adam_optimizer", "sgd_optimizer", "training_loop",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "adam_optimizer": CallGraphExpectation(
        expected_callees=(
            "axpy", "scalar_multiply", "vector_norm",
            "gradient_descent",
        ),
        expected_callers=(
            "training_loop", "optimizer_step",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),
    "attention": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "softmax", "scalar_multiply",
        ),
        expected_callers=(
            "transformer_block", "encoder_layer", "decoder_layer",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "Scaled Dot-Product Attention": CallGraphExpectation(
        expected_callees=(
            "matrix_multiply", "softmax", "scalar_multiply",
        ),
        expected_callers=(
            "transformer_block", "encoder_layer",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "softmax": CallGraphExpectation(
        expected_callees=(
            "exponential", "scalar_multiply",
        ),
        expected_callers=(
            "attention", "cross_entropy", "classifier",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),
    "batch_normalization": CallGraphExpectation(
        expected_callees=(
            "vector_norm", "scalar_multiply", "axpy",
        ),
        expected_callers=(
            "conv_layer", "residual_block",
        ),
        boost_per_match=0.04,
        max_boost=0.10,
    ),

    # -- Finance --------------------------------------------------------------
    "black_scholes": CallGraphExpectation(
        expected_callees=(
            "normal_pdf", "logarithmic", "exponential",
            "abramowitz_stegun_cdf", "acklam_inv_normal",
        ),
        expected_callers=(
            "option_pricing", "greeks", "european_option",
        ),
        boost_per_match=0.05,
        max_boost=0.15,
    ),
    "monte_carlo": CallGraphExpectation(
        expected_callees=(
            "box_muller_transform", "normal_pdf",
            "cholesky_sampling",
        ),
        expected_callers=(
            "option_pricing", "risk_analysis",
            "monte_carlo_pricing",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),

    # -- Stochastic -----------------------------------------------------------
    "Monte Carlo Simulation": CallGraphExpectation(
        expected_callees=(
            "box_muller_transform", "normal_pdf",
        ),
        expected_callers=(
            "option_pricing", "risk_analysis",
        ),
        boost_per_match=0.04,
        max_boost=0.12,
    ),

    # -- Matrix operations (basic) -------------------------------------------
    "matrix_multiply": CallGraphExpectation(
        expected_callees=(),
        expected_callers=(
            "lu_decomposition", "fea_assembly", "gauss_quadrature",
            "newton_raphson", "eigenvalue_solver", "attention",
        ),
        boost_per_match=0.03,
        max_boost=0.10,
    ),
    "triangular_solve": CallGraphExpectation(
        expected_callees=(),
        expected_callers=(
            "lu_solve", "lu_decomposition", "cholesky_solve",
            "cholesky", "qr_decomposition",
        ),
        boost_per_match=0.03,
        max_boost=0.10,
    ),
    "sparse_matrix_ops": CallGraphExpectation(
        expected_callees=(),
        expected_callers=(
            "fea_assembly", "conjugate_gradient", "linear_solve",
            "newton_raphson",
        ),
        boost_per_match=0.03,
        max_boost=0.10,
    ),
}


# ---------------------------------------------------------------------------
# Confidence tier thresholds
# ---------------------------------------------------------------------------
_TIER_CONFIRMED = 0.995
_TIER_HIGH = 0.85
_TIER_MEDIUM = 0.50

# Correlation coefficients between detection layers
_RHO_CONST_STRUCT = 0.30  # constant-structural correlation
_RHO_CONST_API = 0.10     # constant-api correlation
_RHO_STRUCT_API = 0.20    # structural-api correlation

# Negative evidence penalty per hit
_NEG_PENALTY_BASE = 0.85  # Each negative hit multiplies confidence by this

# Maximum call-graph boost factor
_CG_MAX_BOOST_FACTOR = 0.15

# Hard limits
_MIN_CONFIDENCE = 0.01
_MAX_CONFIDENCE = 0.995


# ---------------------------------------------------------------------------
# Pre-compiled negative evidence patterns (lazily built)
# ---------------------------------------------------------------------------
_compiled_neg_patterns: dict[str, list[re.Pattern]] = {}


def _get_neg_patterns(category: str) -> list[re.Pattern]:
    """Category icin derlenmmis negative evidence regex'lerini dondur."""
    if category not in _compiled_neg_patterns:
        neg_info = NEGATIVE_EVIDENCE.get(category, {})
        raw = neg_info.get("unlikely_patterns", [])
        _compiled_neg_patterns[category] = [
            re.compile(p) for p in raw
        ]
    return _compiled_neg_patterns[category]


# ---------------------------------------------------------------------------
# ConfidenceCalibrator
# ---------------------------------------------------------------------------

class ConfidenceCalibrator:
    """Multi-source confidence calibration engine.

    Analyzer'in Noisy-OR ciktisini alip korelasyon duzeltmesi,
    negatif kanit ve call-graph tutarliligi ile kalibre eder.
    """

    def __init__(self) -> None:
        # Lookup tablosu: algoritma adini normalize edip call-graph
        # beklentilerini bulabilmek icin.
        self._cg_lookup: dict[str, CallGraphExpectation] = {}
        for name, exp in EXPECTED_CALL_GRAPH.items():
            self._cg_lookup[name.lower().strip()] = exp

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calibrate(
        self,
        matches: list[AlgorithmMatch],
        call_graph: dict[str, dict[str, list[str]]],
        all_function_names: list[str],
        function_bodies: dict[str, str] | None = None,
    ) -> list[CalibratedMatch]:
        """Calibrate all matches with multi-source validation.

        Args:
            matches: Analyzer'dan gelen ham AlgorithmMatch listesi.
            call_graph: Fonksiyon cagri grafigi.
                {func_name: {"callers": [...], "callees": [...]}}
            all_function_names: Binary'deki tum fonksiyon adlari.
            function_bodies: Opsiyonel -- fonksiyon kaynak kodlari.
                Negatif kanit taramas icin kullanilir.
                {func_name: code_body}

        Returns:
            Kalibre edilmis CalibratedMatch listesi, confidence'a gore
            azalan sirada sirali.
        """
        if not matches:
            return []

        # Normalize all_function_names for fuzzy lookup
        func_name_set = set(all_function_names)
        func_name_lower = {n.lower(): n for n in all_function_names}

        # Ayni (function, algorithm) cifti icin match'leri grupla
        # (analyzer zaten combine etmis olabilir ama biz tekrar bakalim)
        groups = self._group_matches(matches)

        # ------------------------------------------------------------------
        # Pass 1: Her grup icin per-layer confidence, negative evidence,
        # call-graph score'u topla.  Bu kisim GPU ile hizlandirilamaz
        # (string islemleri, regex, graph traversal).
        # ------------------------------------------------------------------
        group_keys: list[tuple[str, str]] = []
        group_data: list[dict[str, Any]] = []

        for (func_name, algo_key), group in groups.items():
            # 1. Detection method'lari ve confidence degerlerini cikar
            methods: set[str] = set()
            p_constant = 0.0
            p_structural = 0.0
            p_api = 0.0
            best_match = group[0]
            all_evidence: list[str] = []
            category = group[0].category

            for m in group:
                if m.confidence > best_match.confidence:
                    best_match = m

                for ev in m.evidence:
                    if ev not in all_evidence:
                        all_evidence.append(ev)

                # detection_method "constant+structural+api" gibi
                # birlesmis olabilir
                for method in m.detection_method.split("+"):
                    method = method.strip()
                    methods.add(method)
                    if method == "constant":
                        p_constant = max(p_constant, m.confidence)
                    elif method == "structural":
                        p_structural = max(p_structural, m.confidence)
                    elif method == "api":
                        p_api = max(p_api, m.confidence)

            # Eger combine edilmis tek match varsa, confidence'i layer'lara
            # dagitmayi deneyelim.  Evidence'tan ipucu cikarabiliriz.
            if len(group) == 1 and "+" in group[0].detection_method:
                # Birlesmis -- her layer icin tahmin yap
                base = group[0].confidence
                if "constant" in methods and p_constant == 0:
                    p_constant = min(base, 0.80)
                if "structural" in methods and p_structural == 0:
                    p_structural = min(base, 0.50)
                if "api" in methods and p_api == 0:
                    p_api = min(base, 0.90)

            n_sources = sum(1 for p in [p_constant, p_structural, p_api] if p > 0)

            # 2. Negatif kanit
            neg_count = self._count_negative_evidence(
                func_name, category, function_bodies,
            )

            # 3. Call-graph tutarliligi
            cg_score = self._compute_call_graph_consistency(
                func_name, best_match.name, call_graph, func_name_lower,
            )

            group_keys.append((func_name, algo_key))
            group_data.append({
                "best_match": best_match,
                "methods": methods,
                "p_constant": p_constant,
                "p_structural": p_structural,
                "p_api": p_api,
                "n_sources": n_sources,
                "neg_count": neg_count,
                "cg_score": cg_score,
            })

        # ------------------------------------------------------------------
        # Pass 2: Noisy-OR hesaplamasi
        # ------------------------------------------------------------------
        calibrated_confs: list[float] = [
            self._calibrate_single(
                d["p_constant"], d["p_structural"], d["p_api"],
                d["neg_count"], d["cg_score"], d["n_sources"],
            )
            for d in group_data
        ]

        # ------------------------------------------------------------------
        # Pass 3: CalibratedMatch nesnelerini olustur
        # ------------------------------------------------------------------
        results: list[CalibratedMatch] = []

        for i, d in enumerate(group_data):
            calibrated_conf = calibrated_confs[i]
            n_sources = d["n_sources"]
            neg_count = d["neg_count"]
            cg_score = d["cg_score"]
            best_match = d["best_match"]

            # 5. Tier belirle
            tier = self._assign_tier(
                calibrated_conf, n_sources, neg_count, cg_score,
            )

            # 6. Debug bilgisi
            details: dict[str, Any] = {
                "p_constant": round(d["p_constant"], 4),
                "p_structural": round(d["p_structural"], 4),
                "p_api": round(d["p_api"], 4),
                "original_confidence": round(best_match.confidence, 4),
                "methods": sorted(d["methods"]),
                "negative_hits": neg_count,
                "cg_score": round(cg_score, 4),
                "cg_boost": round(1.0 + cg_score * _CG_MAX_BOOST_FACTOR, 4),
                "neg_penalty": round(_NEG_PENALTY_BASE ** neg_count, 4),
            }

            results.append(CalibratedMatch(
                original=best_match,
                calibrated_confidence=calibrated_conf,
                tier=tier,
                n_independent_sources=n_sources,
                negative_evidence_count=neg_count,
                call_graph_consistency=cg_score,
                calibration_details=details,
            ))

        # Confidence'a gore azalan sirala
        results.sort(key=lambda x: -x.calibrated_confidence)

        # Istatistik logla
        by_tier: dict[str, int] = {}
        for r in results:
            by_tier[r.tier] = by_tier.get(r.tier, 0) + 1
        logger.info(
            "Confidence calibration: %d matches -> %s",
            len(results),
            ", ".join(f"{t}={c}" for t, c in sorted(by_tier.items())),
        )

        return results

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _group_matches(
        matches: list[AlgorithmMatch],
    ) -> dict[tuple[str, str], list[AlgorithmMatch]]:
        """Match'leri (function_name, algorithm_name) ciftine gore grupla."""
        groups: dict[tuple[str, str], list[AlgorithmMatch]] = {}
        for m in matches:
            key = (m.function_name, m.name.lower().strip())
            groups.setdefault(key, []).append(m)
        return groups

    # ------------------------------------------------------------------
    # Correlated Noisy-OR calibration
    # ------------------------------------------------------------------

    def _calibrate_single(
        self,
        p_const: float,
        p_struct: float,
        p_api: float,
        n_neg: int,
        cg_score: float,
        n_sources: int,
    ) -> float:
        """Tek bir (function, algorithm) cifti icin kalibre edilmis confidence.

        Matematiksel temeli:
            Standart Noisy-OR:  P = 1 - (1-p1)(1-p2)(1-p3)
            Bu formul bagimsizlik varsayar.

            Korelasyon duzeltmesi icin her (pi, pj) cifti arasindaki
            korelasyonu (rho) hesaba katarak effective miss probability
            hesaplariz:

                miss_ij = (1-pi)(1-pj)       # bagimsiz
                miss_ij_corr = miss_ij + rho_ij * sqrt(pi*(1-pi)*pj*(1-pj))

            Bu, pozitif korelasyon durumunda toplam P'yi azaltir
            (iki kaynak "ayni seye bakiyor" olabilir).

        Sonra negatif kanit ve call-graph boost uygulanir.
        """
        # Kucuk epsilon -- sifir problemi
        eps = 1e-10

        # Her layer'in miss probability'si
        m_c = 1.0 - p_const
        m_s = 1.0 - p_struct
        m_a = 1.0 - p_api

        # Bagimsiz Noisy-OR miss
        miss_independent = m_c * m_s * m_a

        # Korelasyon duzeltme terimi
        # Her iki layer cifti icin korelasyon kaynaklarini hesapla
        corr_cs = _RHO_CONST_STRUCT * math.sqrt(
            max(eps, p_const * m_c * p_struct * m_s)
        )
        corr_ca = _RHO_CONST_API * math.sqrt(
            max(eps, p_const * m_c * p_api * m_a)
        )
        corr_sa = _RHO_STRUCT_API * math.sqrt(
            max(eps, p_struct * m_s * p_api * m_a)
        )

        # Korelasyon, toplam miss'i arttirir (confidence duser)
        # Yani: pozitif korelasyon = bilgi kaynaklari tam bagimsiz degil
        total_corr = corr_cs + corr_ca + corr_sa

        # Duzeltilmis miss
        miss_corrected = min(1.0, miss_independent + total_corr)

        # Raw confidence
        raw = 1.0 - miss_corrected

        # -- Tek kaynak siniri -------------------------------------------------
        # Tek source ile CONFIRMED tier'a ulasilamaz
        if n_sources < 2:
            raw = min(raw, 0.94)

        # Structural-only ek sinir
        if p_const < eps and p_api < eps and p_struct > eps:
            raw = min(raw, 0.50)

        # -- Negatif kanit penalti ---------------------------------------------
        neg_penalty = _NEG_PENALTY_BASE ** n_neg

        # -- Call-graph boost --------------------------------------------------
        cg_boost = 1.0 + cg_score * _CG_MAX_BOOST_FACTOR

        # -- Final hesaplama ---------------------------------------------------
        calibrated = raw * neg_penalty * cg_boost
        calibrated = max(_MIN_CONFIDENCE, min(_MAX_CONFIDENCE, calibrated))

        return round(calibrated, 4)

    # ------------------------------------------------------------------
    # Tier assignment
    # ------------------------------------------------------------------

    @staticmethod
    def _assign_tier(
        confidence: float,
        n_sources: int,
        neg_count: int,
        cg_score: float,
    ) -> str:
        """Confidence ve ek metriklere gore tier ata.

        CONFIRMED (>= 0.995):
            - En az 2 bagimsiz kaynak
            - 0 negatif kanit
            - Call-graph tutarli (>= 0.3)

        HIGH (>= 0.85):
            - 1 guclu kaynak (API >= 0.95) VEYA 2+ orta kaynak
            - En fazla 1 negatif kanit

        MEDIUM (>= 0.50):
            - 1 orta kaynak
            - Buyuk celiske yok

        LOW (< 0.50):
            - Structural-only VEYA ciddi negatif kanit
        """
        if (
            confidence >= _TIER_CONFIRMED
            and n_sources >= 2
            and neg_count == 0
            and cg_score >= 0.3
        ):
            return "CONFIRMED"

        if confidence >= _TIER_HIGH and neg_count <= 1:
            return "HIGH"

        if confidence >= _TIER_MEDIUM:
            return "MEDIUM"

        return "LOW"

    # ------------------------------------------------------------------
    # Negative evidence counting
    # ------------------------------------------------------------------

    def _count_negative_evidence(
        self,
        func_name: str,
        category: str,
        function_bodies: dict[str, str] | None,
    ) -> int:
        """Fonksiyon iceriginde olmamasi gereken API/string/pattern say.

        function_bodies None ise negatif kanit taranamaz -> 0 doner.
        """
        if function_bodies is None:
            return 0

        body = function_bodies.get(func_name, "")
        if not body:
            return 0

        neg_info = NEGATIVE_EVIDENCE.get(category)
        if not neg_info:
            return 0

        count = 0
        body_lower = body.lower()

        # API kontrol
        for api in neg_info.get("unlikely_apis", []):
            if api.lower() in body_lower:
                count += 1

        # String kontrol
        for s in neg_info.get("unlikely_strings", []):
            if s.lower() in body_lower:
                count += 1

        # Pattern kontrol
        for pat in _get_neg_patterns(category):
            if pat.search(body):
                count += 1

        return count

    # ------------------------------------------------------------------
    # Call-graph consistency
    # ------------------------------------------------------------------

    def _compute_call_graph_consistency(
        self,
        func_name: str,
        algo_name: str,
        call_graph: dict[str, dict[str, list[str]]],
        func_name_lower: dict[str, str],
    ) -> float:
        """Fonksiyonun call-graph'ini beklenen iliskilerle kiyasla.

        Callee ve caller eslesmelerini sayarak 0-1 arasi skor uretir.

        Returns:
            0.0 -- hic eslesme yok veya call-graph bilgisi yok
            0.0-1.0 -- kismi eslesme
            1.0 -- tum beklenen iliski mevcut (nadir)
        """
        # Normalize algo name
        algo_lower = algo_name.lower().strip()
        expectation = self._cg_lookup.get(algo_lower)
        if expectation is None:
            return 0.0

        # Bu fonksiyonun call-graph bilgisi
        func_info = call_graph.get(func_name, {})
        actual_callees = set(func_info.get("callees", []))
        actual_callers = set(func_info.get("callers", []))

        # Lowercase versions for fuzzy matching
        callees_lower = {c.lower() for c in actual_callees}
        callers_lower = {c.lower() for c in actual_callers}

        matched = 0
        total_expected = (
            len(expectation.expected_callees)
            + len(expectation.expected_callers)
        )
        if total_expected == 0:
            return 0.0

        # Callee match: beklenen callee'lerden hangisi gercekten cagriliyor?
        for expected in expectation.expected_callees:
            exp_lower = expected.lower()
            # Tam eslesme
            if exp_lower in callees_lower:
                matched += 1
                continue
            # Fuzzy: fonksiyon adinin icinde geciyorsa (FUN_00401234 degil,
            # renamed fonksiyonlarda "lu_solve" substr match)
            for actual in callees_lower:
                if exp_lower in actual or actual in exp_lower:
                    matched += 1
                    break

        # Caller match
        for expected in expectation.expected_callers:
            exp_lower = expected.lower()
            if exp_lower in callers_lower:
                matched += 1
                continue
            for actual in callers_lower:
                if exp_lower in actual or actual in exp_lower:
                    matched += 1
                    break

        # Score: matched / total, ama boost_per_match ve max_boost ile sinirla
        raw_score = matched / total_expected if total_expected > 0 else 0.0

        # Ek olarak: matched count * boost_per_match, max_boost ile cap'le
        # Bu dogrudan confidence'a eklenmeyecek -- cg_score olarak donecek
        # ve _calibrate_single icinde kullanilacak.
        return min(1.0, raw_score)

    # ------------------------------------------------------------------
    # Utility: build call graph from function bodies
    # ------------------------------------------------------------------

    @staticmethod
    def build_call_graph_from_bodies(
        function_bodies: dict[str, str],
        all_function_names: list[str],
    ) -> dict[str, dict[str, list[str]]]:
        """Fonksiyon iceriklerinden basit call-graph cikar.

        Ghidra decompile ciktisinda fonksiyon cagrilari "FUN_xxxxx(...)"
        veya "func_name(...)" olarak gorunur. Bu method basit bir regex
        ile cagrilari tespit eder.

        Args:
            function_bodies: {func_name: code_body}
            all_function_names: Tum fonksiyon adlari.

        Returns:
            {func_name: {"callers": [...], "callees": [...]}}
        """
        func_set = set(all_function_names)
        # Minimum 3 karakter -- kisa isimler (ör. "a", "i") false positive
        func_set = {n for n in func_set if len(n) >= 3}

        call_graph: dict[str, dict[str, list[str]]] = {
            fn: {"callers": [], "callees": []}
            for fn in all_function_names
        }

        # Her fonksiyonun iceriginde hangi diger fonksiyonlar cagriliyor?
        # v1.8.0: \b(\w{3,})\s*\( patterni O(n) safe -- \w ve \s
        # arasinda overlap yok, boyut siniri kaldirildi.
        call_pattern = re.compile(r"\b(\w{3,})\s*\(")

        for caller, body in function_bodies.items():
            if caller not in call_graph:
                call_graph[caller] = {"callers": [], "callees": []}

            called_funcs = set(call_pattern.findall(body))
            for callee in called_funcs:
                if callee in func_set and callee != caller:
                    if callee not in call_graph[caller]["callees"]:
                        call_graph[caller]["callees"].append(callee)
                    if callee not in call_graph:
                        call_graph[callee] = {"callers": [], "callees": []}
                    if caller not in call_graph[callee]["callers"]:
                        call_graph[callee]["callers"].append(caller)

        return call_graph

    # ------------------------------------------------------------------
    # Batch summary
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(calibrated: list[CalibratedMatch]) -> dict[str, Any]:
        """Kalibrasyon sonuclarinin ozet istatistigi.

        Returns:
            {
                "total": int,
                "by_tier": {"CONFIRMED": n, "HIGH": n, ...},
                "avg_confidence": float,
                "avg_delta": float,    # ortalama |calibrated - original|
                "top_5": [...]
            }
        """
        if not calibrated:
            return {
                "total": 0,
                "by_tier": {},
                "avg_confidence": 0.0,
                "avg_delta": 0.0,
                "top_5": [],
            }

        by_tier: dict[str, int] = {}
        total_conf = 0.0
        total_delta = 0.0

        for c in calibrated:
            by_tier[c.tier] = by_tier.get(c.tier, 0) + 1
            total_conf += c.calibrated_confidence
            total_delta += abs(
                c.calibrated_confidence - c.original.confidence
            )

        n = len(calibrated)
        top_5 = [
            {
                "name": c.original.name,
                "function": c.original.function_name,
                "confidence": round(c.calibrated_confidence, 4),
                "tier": c.tier,
            }
            for c in calibrated[:5]
        ]

        return {
            "total": n,
            "by_tier": by_tier,
            "avg_confidence": round(total_conf / n, 4),
            "avg_delta": round(total_delta / n, 4),
            "top_5": top_5,
        }
