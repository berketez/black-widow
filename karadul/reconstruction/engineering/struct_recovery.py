"""Algorithm-aware struct recovery engine (Karadul v1.2).

Ghidra decompile ciktisindaki pointer arithmetic ifadelerini
semantic struct field erisimlerine donusturur:

    ONCE:  *(int *)(param_18 + 4)
    SONRA: elem->num_nodes  /* was: *(int *)(param_18 + 4) */

CTypeRecoverer'in sentezledigi struct'lari alir, EngineeringAlgorithmAnalyzer
sonuclariyla zenginlestirir, call graph uzerinden yayar ve C dosyalarini
yeniden yazar.

3 Fazli Pipeline:
    1. Template Matching  -- algoritma tespitinden struct sablonlarina esle
    2. Call Graph Propagation -- caller/callee arasinda struct kimligini yay
    3. Code Rewrite -- pointer aritmetigini -> soz dizimine cevir

Kullanim:
    from karadul.reconstruction.engineering.struct_recovery import StructRecoveryEngine
    engine = StructRecoveryEngine(config)
    result = engine.recover(
        decompiled_dir=Path("decompiled"),
        functions_json=Path("functions.json"),
        ghidra_types_json=Path("ghidra_types.json"),
        call_graph_json=Path("call_graph.json"),
        output_dir=Path("struct_recovered"),
        algorithm_matches=algo_list,
        domain_report=domain_report,
    )
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config
from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.c_type_recoverer import (
    CTypeRecoveryResult,
    RecoveredStruct,
    StructField,
)
from karadul.reconstruction.engineering.domain_classifier import (
    DomainClassification,
    DomainReport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Veri Yapilari
# ---------------------------------------------------------------------------


@dataclass
class EnrichedField:
    """Semantik isimlendirilmis struct field.

    Attributes:
        offset: Byte offset (struct icindeki konum).
        raw_name: Orijinal field adi (orn: "field_0x10").
        semantic_name: Semantik isim (orn: "num_nodes", "K_local").
        c_type: C tipi (orn: "int", "double *").
        size: Field boyutu (byte).
        confidence: Isimlendirme guven skoru (0.0-1.0).
        source: Isim kaynagi.
        comment: Aciklama (orn: "nodes per element").
    """

    offset: int
    raw_name: str
    semantic_name: str
    c_type: str
    size: int
    confidence: float = 0.5
    source: str = "usage_pattern"
    comment: str = ""


@dataclass
class EnrichedStruct:
    """Algoritma-bilinirli zenginlestirilmis struct.

    Attributes:
        name: Semantik struct adi (orn: "ElementData").
        raw_name: Orijinal adi (orn: "recovered_struct_007").
        fields: Zenginlestirilmis field listesi (offset'e gore sirali).
        total_size: Toplam boyut (byte).
        alignment: Alignment.
        source_functions: Tespit edildigi fonksiyonlar.
        algorithm_context: Algoritmik baglam (orn: "Newton-Raphson FEA solver").
        domain: Muhendislik alani (orn: "structural").
        confidence: Genel guven skoru.
        typedef_declaration: Emit'e hazir C typedef.
    """

    name: str
    raw_name: str
    fields: list[EnrichedField]
    total_size: int
    alignment: int = 8
    source_functions: list[str] = field(default_factory=list)
    algorithm_context: str | None = None
    domain: str | None = None
    confidence: float = 0.5
    typedef_declaration: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "raw_name": self.raw_name,
            "fields": [
                {
                    "offset": f.offset,
                    "raw_name": f.raw_name,
                    "semantic_name": f.semantic_name,
                    "c_type": f.c_type,
                    "size": f.size,
                    "confidence": f.confidence,
                    "source": f.source,
                    "comment": f.comment,
                }
                for f in self.fields
            ],
            "total_size": self.total_size,
            "alignment": self.alignment,
            "source_functions": self.source_functions,
            "algorithm_context": self.algorithm_context,
            "domain": self.domain,
            "confidence": self.confidence,
        }


@dataclass
class StructRecoveryResult:
    """Struct recovery engine cikti sonucu.

    Attributes:
        success: Islem basarili mi.
        enriched_structs: Zenginlestirilmis struct listesi.
        types_header_path: Uretilen types.h dosya yolu.
        rewritten_files: Yeniden yazilan C dosyalari.
        field_access_rewrites: Yapilan pointer->field donusum sayisi.
        total_structs: Toplam struct sayisi.
        errors: Hata mesajlari.
    """

    success: bool
    enriched_structs: list[EnrichedStruct] = field(default_factory=list)
    types_header_path: Path | None = None
    rewritten_files: list[Path] = field(default_factory=list)
    field_access_rewrites: int = 0
    total_structs: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "enriched_structs": [s.to_dict() for s in self.enriched_structs],
            "types_header_path": str(self.types_header_path) if self.types_header_path else None,
            "rewritten_files": [str(p) for p in self.rewritten_files],
            "field_access_rewrites": self.field_access_rewrites,
            "total_structs": self.total_structs,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Field Template -- algoritma struct sablonlari icin
# ---------------------------------------------------------------------------


@dataclass
class FieldTemplate:
    """Bir algoritma sablonundaki tek bir field tanimi.

    offset_range: (min_offset, max_offset) -- field'in beklendigi offset araligi.
    name: Semantik isim.
    c_type: Beklenen C tipi.
    comment: Aciklama.
    """

    offset_range: tuple[int, int]
    name: str
    c_type: str
    comment: str = ""


# ---------------------------------------------------------------------------
# ALGORITHM_STRUCT_TEMPLATES
# Bilinen algoritmalarin tipik struct yerlesimi.
# Key: algoritma adi (lowercase, bosluklu).
# Value: FieldTemplate listesi.
# ---------------------------------------------------------------------------

ALGORITHM_STRUCT_TEMPLATES: dict[str, dict[str, Any]] = {
    # ----- FEA / Yapisal Mekanik -----
    "newton-raphson": {
        "struct_name": "SolverContext",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "num_equations", "int", "number of DOFs"),
            FieldTemplate((4, 8), "num_nodes", "int", "nodes per element (npe)"),
            FieldTemplate((8, 12), "num_integration_pts", "int", "Gauss quadrature points"),
            FieldTemplate((16, 24), "tolerance", "double", "convergence tolerance"),
            FieldTemplate((24, 28), "max_iterations", "int", "max Newton iterations"),
            FieldTemplate((32, 40), "K_global", "double *", "global stiffness matrix pointer"),
            FieldTemplate((40, 48), "f_residual", "double *", "residual force vector"),
            FieldTemplate((48, 56), "u_displacement", "double *", "displacement solution vector"),
        ],
    },
    "gauss quadrature": {
        "struct_name": "QuadratureRule",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n_points", "int", "number of Gauss points"),
            FieldTemplate((8, 16), "weights", "double *", "integration weights"),
            FieldTemplate((16, 24), "xi_coords", "double *", "natural coordinates xi"),
            FieldTemplate((24, 32), "eta_coords", "double *", "natural coordinates eta"),
            FieldTemplate((32, 40), "zeta_coords", "double *", "natural coordinates zeta (3D)"),
        ],
    },
    "conjugate gradient": {
        "struct_name": "CGSolverData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "system size"),
            FieldTemplate((8, 16), "tolerance", "double", "convergence tolerance"),
            FieldTemplate((16, 20), "max_iter", "int", "maximum iterations"),
            FieldTemplate((24, 32), "residual_ptr", "double *", "residual vector r"),
            FieldTemplate((32, 40), "search_dir_ptr", "double *", "search direction p"),
            FieldTemplate((40, 48), "Ap_ptr", "double *", "matrix-vector product A*p"),
            FieldTemplate((48, 56), "x_solution", "double *", "solution vector x"),
        ],
    },
    "lu decomposition": {
        "struct_name": "LUFactorData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "matrix dimension"),
            FieldTemplate((8, 16), "L_matrix", "double *", "lower triangular matrix"),
            FieldTemplate((16, 24), "U_matrix", "double *", "upper triangular matrix"),
            FieldTemplate((24, 32), "pivot_indices", "int *", "pivot permutation array"),
            FieldTemplate((32, 40), "work_buffer", "double *", "workspace buffer"),
        ],
    },
    "cholesky": {
        "struct_name": "CholeskyData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "matrix dimension"),
            FieldTemplate((8, 16), "L_factor", "double *", "lower Cholesky factor"),
            FieldTemplate((16, 24), "diagonal", "double *", "diagonal elements"),
        ],
    },
    "eigenvalue": {
        "struct_name": "EigensolverData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "matrix size"),
            FieldTemplate((4, 8), "num_eigenvalues", "int", "number of requested eigenvalues"),
            FieldTemplate((8, 16), "eigenvalues", "double *", "eigenvalue array"),
            FieldTemplate((16, 24), "eigenvectors", "double *", "eigenvector matrix (column-major)"),
            FieldTemplate((24, 32), "work_buffer", "double *", "workspace"),
            FieldTemplate((32, 36), "max_iter", "int", "max iterations"),
            FieldTemplate((40, 48), "tolerance", "double", "convergence tolerance"),
        ],
    },
    "stiffness assembly": {
        "struct_name": "AssemblyContext",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "num_elements", "int", "total element count"),
            FieldTemplate((4, 8), "num_nodes", "int", "total node count"),
            FieldTemplate((8, 12), "dof_per_node", "int", "DOF per node"),
            FieldTemplate((16, 24), "K_global", "double *", "global stiffness matrix"),
            FieldTemplate((24, 32), "connectivity", "int *", "element connectivity table"),
            FieldTemplate((32, 40), "coords", "double *", "nodal coordinates"),
            FieldTemplate((40, 48), "K_element", "double *", "element stiffness buffer"),
        ],
    },
    "mass matrix": {
        "struct_name": "MassMatrixData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "num_elements", "int", "element count"),
            FieldTemplate((4, 8), "nodes_per_elem", "int", "nodes per element"),
            FieldTemplate((8, 16), "density", "double", "material density (rho)"),
            FieldTemplate((16, 24), "M_global", "double *", "global mass matrix"),
            FieldTemplate((24, 32), "M_element", "double *", "element mass buffer"),
            FieldTemplate((32, 40), "thickness", "double *", "element thickness (2D)"),
        ],
    },
    "newmark": {
        "struct_name": "NewmarkParams",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 8), "beta", "double", "Newmark beta parameter"),
            FieldTemplate((8, 16), "gamma", "double", "Newmark gamma parameter"),
            FieldTemplate((16, 24), "dt", "double", "time step"),
            FieldTemplate((24, 28), "n_steps", "int", "number of time steps"),
            FieldTemplate((32, 40), "M_ptr", "double *", "mass matrix"),
            FieldTemplate((40, 48), "C_ptr", "double *", "damping matrix"),
            FieldTemplate((48, 56), "K_ptr", "double *", "stiffness matrix"),
            FieldTemplate((56, 64), "u_ptr", "double *", "displacement vector"),
            FieldTemplate((64, 72), "v_ptr", "double *", "velocity vector"),
            FieldTemplate((72, 80), "a_ptr", "double *", "acceleration vector"),
        ],
    },
    "runge-kutta": {
        "struct_name": "RKIntegrator",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "order", "int", "RK order (2/4)"),
            FieldTemplate((8, 16), "dt", "double", "time step size"),
            FieldTemplate((16, 20), "n_equations", "int", "system size"),
            FieldTemplate((24, 32), "y_state", "double *", "state vector"),
            FieldTemplate((32, 40), "k1", "double *", "stage 1 slopes"),
            FieldTemplate((40, 48), "k2", "double *", "stage 2 slopes"),
            FieldTemplate((48, 56), "k3", "double *", "stage 3 slopes"),
            FieldTemplate((56, 64), "k4", "double *", "stage 4 slopes"),
            FieldTemplate((64, 72), "y_temp", "double *", "temporary state buffer"),
        ],
    },
    "gmres": {
        "struct_name": "GMRESData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "system size"),
            FieldTemplate((4, 8), "restart_dim", "int", "Krylov subspace dimension (m)"),
            FieldTemplate((8, 16), "tolerance", "double", "convergence tolerance"),
            FieldTemplate((16, 20), "max_iter", "int", "maximum outer iterations"),
            FieldTemplate((24, 32), "V_basis", "double *", "Arnoldi basis vectors"),
            FieldTemplate((32, 40), "H_hessenberg", "double *", "upper Hessenberg matrix"),
            FieldTemplate((40, 48), "x_solution", "double *", "solution vector"),
        ],
    },
    "bicgstab": {
        "struct_name": "BiCGStabData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "system size"),
            FieldTemplate((8, 16), "tolerance", "double", "convergence tolerance"),
            FieldTemplate((16, 20), "max_iter", "int", "maximum iterations"),
            FieldTemplate((24, 32), "r_residual", "double *", "residual"),
            FieldTemplate((32, 40), "r_hat", "double *", "shadow residual"),
            FieldTemplate((40, 48), "p_dir", "double *", "search direction"),
            FieldTemplate((48, 56), "s_vec", "double *", "intermediate vector s"),
        ],
    },
    # ----- CFD / Akiskanlar Dinamigi -----
    "k-epsilon": {
        "struct_name": "KEpsilonModel",
        "domain": "fluid",
        "fields": [
            FieldTemplate((0, 4), "num_cells", "int", "mesh cell count"),
            FieldTemplate((8, 16), "k_turb", "double *", "turbulent kinetic energy field"),
            FieldTemplate((16, 24), "epsilon", "double *", "dissipation rate field"),
            FieldTemplate((24, 32), "nu_t", "double *", "eddy viscosity field"),
            FieldTemplate((32, 40), "C_mu", "double", "model constant C_mu (0.09)"),
            FieldTemplate((40, 48), "C_1", "double", "model constant C_1 (1.44)"),
            FieldTemplate((48, 56), "C_2", "double", "model constant C_2 (1.92)"),
        ],
    },
    "k-omega": {
        "struct_name": "KOmegaModel",
        "domain": "fluid",
        "fields": [
            FieldTemplate((0, 4), "num_cells", "int", "mesh cell count"),
            FieldTemplate((8, 16), "k_turb", "double *", "turbulent kinetic energy"),
            FieldTemplate((16, 24), "omega", "double *", "specific dissipation rate"),
            FieldTemplate((24, 32), "nu_t", "double *", "eddy viscosity"),
            FieldTemplate((32, 40), "alpha_star", "double", "model coefficient"),
        ],
    },
    "sst": {
        "struct_name": "SSTModel",
        "domain": "fluid",
        "fields": [
            FieldTemplate((0, 4), "num_cells", "int", "mesh cell count"),
            FieldTemplate((8, 16), "k_turb", "double *", "turbulent kinetic energy"),
            FieldTemplate((16, 24), "omega", "double *", "specific dissipation rate"),
            FieldTemplate((24, 32), "F1_blend", "double *", "blending function F1"),
            FieldTemplate((32, 40), "F2_blend", "double *", "blending function F2"),
            FieldTemplate((40, 48), "nu_t", "double *", "eddy viscosity"),
        ],
    },
    "navier-stokes": {
        "struct_name": "FlowField",
        "domain": "fluid",
        "fields": [
            FieldTemplate((0, 4), "num_cells", "int", "mesh cell count"),
            FieldTemplate((4, 8), "ndim", "int", "spatial dimensions (2 or 3)"),
            FieldTemplate((8, 16), "u_velocity", "double *", "x-velocity field"),
            FieldTemplate((16, 24), "v_velocity", "double *", "y-velocity field"),
            FieldTemplate((24, 32), "w_velocity", "double *", "z-velocity field"),
            FieldTemplate((32, 40), "pressure", "double *", "pressure field"),
            FieldTemplate((40, 48), "density", "double *", "density field"),
            FieldTemplate((48, 56), "viscosity", "double", "kinematic viscosity (nu)"),
        ],
    },
    "upwind": {
        "struct_name": "UpwindScheme",
        "domain": "fluid",
        "fields": [
            FieldTemplate((0, 4), "num_faces", "int", "mesh face count"),
            FieldTemplate((8, 16), "flux_left", "double *", "left state flux"),
            FieldTemplate((16, 24), "flux_right", "double *", "right state flux"),
            FieldTemplate((24, 32), "face_normals", "double *", "face normal vectors"),
        ],
    },
    # ----- Termal -----
    "heat transfer": {
        "struct_name": "HeatTransferData",
        "domain": "thermal",
        "fields": [
            FieldTemplate((0, 4), "num_nodes", "int", "node count"),
            FieldTemplate((8, 16), "conductivity", "double", "thermal conductivity k"),
            FieldTemplate((16, 24), "specific_heat", "double", "specific heat capacity cp"),
            FieldTemplate((24, 32), "density", "double", "material density rho"),
            FieldTemplate((32, 40), "T_field", "double *", "temperature field"),
            FieldTemplate((40, 48), "Q_source", "double *", "heat source term"),
            FieldTemplate((48, 56), "dt", "double", "time step"),
        ],
    },
    # ----- Kontak Mekani ----------
    "contact": {
        "struct_name": "ContactData",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "num_contact_pairs", "int", "contact surface pairs"),
            FieldTemplate((4, 8), "num_slave_nodes", "int", "slave surface nodes"),
            FieldTemplate((8, 16), "gap_tolerance", "double", "penetration tolerance"),
            FieldTemplate((16, 24), "friction_coeff", "double", "Coulomb friction coefficient"),
            FieldTemplate((24, 32), "penalty_stiffness", "double", "penalty stiffness parameter"),
            FieldTemplate((32, 40), "gap_vector", "double *", "gap distance per node"),
            FieldTemplate((40, 48), "contact_force", "double *", "contact force vector"),
        ],
    },
    # ----- Malzeme Modeli -----
    "material model": {
        "struct_name": "MaterialProps",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 8), "E_modulus", "double", "Young's modulus"),
            FieldTemplate((8, 16), "nu_poisson", "double", "Poisson's ratio"),
            FieldTemplate((16, 24), "rho_density", "double", "material density"),
            FieldTemplate((24, 32), "sigma_yield", "double", "yield stress"),
            FieldTemplate((32, 40), "H_hardening", "double", "hardening modulus"),
            FieldTemplate((40, 48), "alpha_thermal", "double", "thermal expansion coefficient"),
        ],
    },
    # ----- Sparse Matrix -----
    "sparse matrix": {
        "struct_name": "SparseCSR",
        "domain": "structural",
        "fields": [
            FieldTemplate((0, 4), "n_rows", "int", "number of rows"),
            FieldTemplate((4, 8), "n_cols", "int", "number of columns"),
            FieldTemplate((8, 12), "nnz", "int", "number of non-zeros"),
            FieldTemplate((16, 24), "values", "double *", "non-zero values array"),
            FieldTemplate((24, 32), "col_indices", "int *", "column index array"),
            FieldTemplate((32, 40), "row_ptr", "int *", "row pointer array (CSR)"),
        ],
    },
    # ----- Finans -----
    "black-scholes": {
        "struct_name": "OptionParams",
        "domain": "finance",
        "fields": [
            FieldTemplate((0, 8), "spot_price", "double", "current asset price S"),
            FieldTemplate((8, 16), "strike_price", "double", "option strike price K"),
            FieldTemplate((16, 24), "risk_free_rate", "double", "risk-free interest rate r"),
            FieldTemplate((24, 32), "volatility", "double", "implied volatility sigma"),
            FieldTemplate((32, 40), "time_to_maturity", "double", "time to expiry T"),
            FieldTemplate((40, 44), "is_call", "int", "1=call, 0=put"),
        ],
    },
    "monte carlo": {
        "struct_name": "MonteCarloConfig",
        "domain": "finance",
        "fields": [
            FieldTemplate((0, 4), "n_simulations", "int", "number of MC paths"),
            FieldTemplate((4, 8), "n_steps", "int", "time steps per path"),
            FieldTemplate((8, 16), "dt", "double", "time step size"),
            FieldTemplate((16, 24), "rng_seed", "long", "random seed"),
            FieldTemplate((24, 32), "results_ptr", "double *", "simulation results array"),
        ],
    },
    # ----- ML -----
    "adam optimizer": {
        "struct_name": "AdamState",
        "domain": "ml",
        "fields": [
            FieldTemplate((0, 4), "n_params", "int", "number of parameters"),
            FieldTemplate((8, 16), "learning_rate", "double", "learning rate (alpha)"),
            FieldTemplate((16, 24), "beta1", "double", "first moment decay (0.9)"),
            FieldTemplate((24, 32), "beta2", "double", "second moment decay (0.999)"),
            FieldTemplate((32, 40), "epsilon", "double", "numerical stability (1e-8)"),
            FieldTemplate((40, 48), "m_first_moment", "double *", "first moment vector"),
            FieldTemplate((48, 56), "v_second_moment", "double *", "second moment vector"),
            FieldTemplate((56, 60), "timestep", "int", "current optimization step"),
        ],
    },
    "sgd": {
        "struct_name": "SGDState",
        "domain": "ml",
        "fields": [
            FieldTemplate((0, 4), "n_params", "int", "number of parameters"),
            FieldTemplate((8, 16), "learning_rate", "double", "learning rate"),
            FieldTemplate((16, 24), "momentum", "double", "momentum coefficient"),
            FieldTemplate((24, 32), "weight_decay", "double", "L2 regularization"),
            FieldTemplate((32, 40), "velocity_ptr", "double *", "momentum buffer"),
        ],
    },
    # ----- DSP -----
    "fft": {
        "struct_name": "FFTContext",
        "domain": "dsp",
        "fields": [
            FieldTemplate((0, 4), "n_samples", "int", "number of samples (N)"),
            FieldTemplate((4, 8), "log2_n", "int", "log2(N)"),
            FieldTemplate((8, 16), "real_ptr", "double *", "real part array"),
            FieldTemplate((16, 24), "imag_ptr", "double *", "imaginary part array"),
            FieldTemplate((24, 32), "twiddle_re", "double *", "twiddle factor real"),
            FieldTemplate((32, 40), "twiddle_im", "double *", "twiddle factor imag"),
        ],
    },
    "butterworth": {
        "struct_name": "ButterworthFilter",
        "domain": "dsp",
        "fields": [
            FieldTemplate((0, 4), "order", "int", "filter order"),
            FieldTemplate((8, 16), "cutoff_freq", "double", "cutoff frequency (Hz)"),
            FieldTemplate((16, 24), "sample_rate", "double", "sampling rate (Hz)"),
            FieldTemplate((24, 32), "a_coeffs", "double *", "feedback coefficients"),
            FieldTemplate((32, 40), "b_coeffs", "double *", "feedforward coefficients"),
            FieldTemplate((40, 48), "state_buffer", "double *", "filter state (delay line)"),
        ],
    },
    # ----- Optimizasyon -----
    "bfgs": {
        "struct_name": "BFGSState",
        "domain": "optimization",
        "fields": [
            FieldTemplate((0, 4), "n", "int", "problem dimension"),
            FieldTemplate((8, 16), "tolerance", "double", "gradient norm tolerance"),
            FieldTemplate((16, 20), "max_iter", "int", "maximum iterations"),
            FieldTemplate((24, 32), "x_current", "double *", "current point"),
            FieldTemplate((32, 40), "gradient", "double *", "gradient vector"),
            FieldTemplate((40, 48), "H_inv", "double *", "inverse Hessian approximation"),
            FieldTemplate((48, 56), "search_dir", "double *", "search direction"),
        ],
    },
    "simulated annealing": {
        "struct_name": "SAConfig",
        "domain": "optimization",
        "fields": [
            FieldTemplate((0, 8), "T_initial", "double", "initial temperature"),
            FieldTemplate((8, 16), "T_min", "double", "minimum temperature"),
            FieldTemplate((16, 24), "cooling_rate", "double", "cooling factor (alpha)"),
            FieldTemplate((24, 28), "max_iter_per_temp", "int", "iterations per temperature"),
            FieldTemplate((32, 40), "current_solution", "double *", "current state"),
            FieldTemplate((40, 48), "best_solution", "double *", "best state found"),
        ],
    },
}

# Algoritma ismi normalizasyonu icin eslesme tablosu.
# EngineeringAlgorithmAnalyzer ciktisindaki isimler cok cesitli olabiliyor:
# "Gauss Quadrature 2-point", "gauss_quadrature", "Gauss" vs.
# Bu tablo anahtar kelimeleri template isimlerine esler.
_ALGO_NAME_NORMALIZATION: list[tuple[str, str]] = [
    ("newton.raphson", "newton-raphson"),
    ("newton_raphson", "newton-raphson"),
    ("gauss.quad", "gauss quadrature"),
    ("gauss.integ", "gauss quadrature"),
    ("conjugate.grad", "conjugate gradient"),
    ("cg.solver", "conjugate gradient"),
    ("lu.decomp", "lu decomposition"),
    ("lu.factor", "lu decomposition"),
    ("cholesky", "cholesky"),
    ("eigenval", "eigenvalue"),
    ("eigen.solv", "eigenvalue"),
    ("stiffness.assembl", "stiffness assembly"),
    ("assembl.stiffness", "stiffness assembly"),
    ("mass.matrix", "mass matrix"),
    ("newmark", "newmark"),
    ("runge.kutta", "runge-kutta"),
    ("rk4", "runge-kutta"),
    ("rk2", "runge-kutta"),
    ("gmres", "gmres"),
    ("bicgstab", "bicgstab"),
    ("bi.cg.stab", "bicgstab"),
    ("k.epsilon", "k-epsilon"),
    ("k_epsilon", "k-epsilon"),
    ("k.omega", "k-omega"),
    ("k_omega", "k-omega"),
    ("sst", "sst"),
    ("navier.stokes", "navier-stokes"),
    ("upwind", "upwind"),
    ("weno", "upwind"),
    ("heat.transfer", "heat transfer"),
    ("contact", "contact"),
    ("material", "material model"),
    ("sparse", "sparse matrix"),
    ("csr", "sparse matrix"),
    ("black.scholes", "black-scholes"),
    ("monte.carlo", "monte carlo"),
    ("adam", "adam optimizer"),
    ("sgd", "sgd"),
    ("fft", "fft"),
    ("fourier", "fft"),
    ("butterworth", "butterworth"),
    ("bfgs", "bfgs"),
    ("l.bfgs", "bfgs"),
    ("simulated.anneal", "simulated annealing"),
]


# ---------------------------------------------------------------------------
# C Tipi Boyut Tablosu (CTypeRecoverer'dan bagimsiz kopya)
# ---------------------------------------------------------------------------

_TYPE_SIZES: dict[str, int] = {
    "char": 1, "uint8_t": 1, "int8_t": 1, "byte": 1, "bool": 1,
    "short": 2, "uint16_t": 2, "int16_t": 2,
    "int": 4, "uint": 4, "uint32_t": 4, "int32_t": 4, "float": 4,
    "long": 8, "ulong": 8, "uint64_t": 8, "int64_t": 8,
    "double": 8, "size_t": 8,
    "void *": 8, "char *": 8, "int *": 8, "double *": 8, "long *": 8,
    "float *": 8, "code *": 8,
    "undefined": 8, "undefined1": 1, "undefined2": 2, "undefined4": 4, "undefined8": 8,
}


# ---------------------------------------------------------------------------
# Regex Patterns -- Ghidra decompile ciktisi pointer aritmetigi
# ---------------------------------------------------------------------------

# *(type *)(base + offset) -- okuma veya yazma
# Ornekler:
#   *(int *)(param_18 + 4)
#   *(double *)(param_8 + buffer_9 * 8)
#   *(long *)(base + 0x10)
_PTR_ARITH_SIMPLE = re.compile(
    r"\*\(\s*"
    r"(?P<cast_type>[a-zA-Z_][\w\s]*?)\s*\*\s*\)"    # cast type: "int", "double" vb.
    r"\(\s*"
    r"(?P<base>\w+)"                                    # base pointer
    r"\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)"                  # sabit offset
    r"\s*\)"
)

# *(type *)(base + idx * stride) -- array access pattern
_PTR_ARITH_ARRAY = re.compile(
    r"\*\(\s*"
    r"(?P<cast_type>[a-zA-Z_][\w\s]*?)\s*\*\s*\)"
    r"\(\s*"
    r"(?P<base>\w+)"
    r"\s*\+\s*"
    r"(?P<index>\w+)"
    r"\s*\*\s*"
    r"(?P<stride>0x[0-9a-fA-F]+|\d+)"
    r"\s*\)"
)

# *(type *)base -- dogrudan base dereference (offset=0)
_PTR_DEREF_DIRECT = re.compile(
    r"\*\(\s*"
    r"(?P<cast_type>[a-zA-Z_][\w\s]*?)\s*\*\s*\)"
    r"\(\s*"
    r"(?P<base>\w+)"
    r"\s*\)"
)

# Ghidra fonksiyon tanimi
_FUNC_DEF_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Fonksiyon cagirisi: result = FUN_xxx(arg1, arg2, ...)
_FUNC_CALL_RE = re.compile(
    r"(?P<result>\w+)\s*=\s*(?P<callee>\w+)\s*\((?P<args>[^)]*)\)"
)

# Dogrudan fonksiyon cagirisi (donusu olmayan): FUN_xxx(arg1, arg2, ...)
_VOID_CALL_RE = re.compile(
    r"(?<!=)\s*(?P<callee>\w+)\s*\((?P<args>[^)]*)\)\s*;"
)


# ---------------------------------------------------------------------------
# Access Pattern veri yapisi
# ---------------------------------------------------------------------------


@dataclass
class AccessPattern:
    """Tek bir pointer aritmetigi erisim pattern'i.

    Attributes:
        base_ptr: Base pointer adi (orn: "param_18").
        offset: Byte offset (int).
        cast_type: Cast tipi (orn: "int", "double").
        is_array: Array erisimi mi (idx * stride pattern'i).
        stride: Array stride (sadece is_array=True ise).
        index_var: Index degiskeni (sadece is_array=True ise).
        line_text: Orijinal satir metni.
        line_number: Satir numarasi (0-indexed).
        func_name: Hangi fonksiyonda bulundugu.
    """

    base_ptr: str
    offset: int
    cast_type: str
    is_array: bool = False
    stride: int = 0
    index_var: str = ""
    line_text: str = ""
    line_number: int = 0
    func_name: str = ""


# ---------------------------------------------------------------------------
# Ana Sinif
# ---------------------------------------------------------------------------


class StructRecoveryEngine:
    """Algorithm-aware struct recovery engine.

    CTypeRecoverer'in urettigi struct'lari alir, EngineeringAlgorithmAnalyzer
    sonuclariyla zenginlestirir, call graph uzerinden yayar ve C dosyalarini
    yeniden yazar.

    Uc fazli pipeline:
        1. Template Matching: Tespit edilen algoritmalardan struct sablonlarina esle
        2. Call Graph Propagation: Caller/callee boyunca struct kimligini yay
        3. Code Rewrite: *(type*)(ptr+N) -> struct->field donusumu

    Args:
        config: Merkezi konfigürasyon.
        min_template_similarity: Sablon esleme minimum benzerlik esigi (0.0-1.0).
        max_propagation_iterations: Call graph yayilim maks iterasyon sayisi.
    """

    def __init__(
        self,
        config: Config,
        min_template_similarity: float = 0.45,
        max_propagation_iterations: int = 5,
    ) -> None:
        self.config = config
        self.min_template_similarity = min_template_similarity
        self.max_propagation_iterations = max_propagation_iterations
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def recover(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        ghidra_types_json: Path,
        call_graph_json: Path,
        output_dir: Path,
        *,
        existing_type_result: CTypeRecoveryResult | None = None,
        algorithm_matches: list[AlgorithmMatch] | None = None,
        domain_report: DomainReport | None = None,
        computation_structs: list[dict] | None = None,
    ) -> StructRecoveryResult:
        """Tam struct recovery pipeline'i calistir.

        Args:
            decompiled_dir: Ghidra decompile C dosyalari dizini.
            functions_json: Ghidra fonksiyon metadata JSON.
            ghidra_types_json: Ghidra tip bilgisi JSON.
            call_graph_json: Ghidra call graph JSON.
            output_dir: Cikti dizini.
            existing_type_result: CTypeRecoverer'dan gelen sonuc (opsiyonel).
            algorithm_matches: Tespit edilen algoritmalar (opsiyonel).
            domain_report: Domain siniflandirma raporu (opsiyonel).
            computation_structs: Computation Recovery constraint solver'dan gelen
                rafine edilmis struct verileri (opsiyonel). Her dict
                ``ConstraintStruct.to_dict()`` formatinda olmali:
                ``{name, fields: [{offset, type, size, confidence}], total_size,
                source_functions, has_overlap, alignment}``.

        Returns:
            StructRecoveryResult: Zenginlestirilmis struct'lar ve yeniden yazilan dosyalar.
        """
        errors: list[str] = []

        # --- Girdi dogrulama ---
        decompiled_dir = Path(decompiled_dir)
        output_dir = Path(output_dir)

        if not decompiled_dir.exists():
            return StructRecoveryResult(
                success=False,
                errors=[f"Decompiled dizini bulunamadi: {decompiled_dir}"],
            )

        c_files = sorted(decompiled_dir.rglob("*.c"))
        if not c_files:
            return StructRecoveryResult(
                success=False,
                errors=[f"Dizinde C dosyasi bulunamadi: {decompiled_dir}"],
            )

        output_dir.mkdir(parents=True, exist_ok=True)

        # --- Verileri yukle ---
        func_meta = self._load_json(functions_json, errors)
        ghidra_types = self._load_ghidra_types(ghidra_types_json, errors)
        call_graph = self._load_call_graph(call_graph_json, errors)

        # Algoritmalardan fonksiyon -> algoritma eslesmesi olustur
        func_algorithms: dict[str, list[AlgorithmMatch]] = defaultdict(list)
        if algorithm_matches:
            for am in algorithm_matches:
                func_algorithms[am.function_name].append(am)

        # Domain bilgisi: fonksiyon -> domain
        func_domains: dict[str, str] = {}
        if domain_report:
            for dc in domain_report.classifications:
                func_domains[dc.function_name] = dc.primary_domain

        # --- Faz 0: Mevcut struct'lari al (CTypeRecoverer'dan veya Ghidra'dan) ---
        base_structs: list[RecoveredStruct] = []
        if existing_type_result and existing_type_result.structs:
            base_structs = existing_type_result.structs
            logger.info(
                "CTypeRecoverer'dan %d struct alindi", len(base_structs),
            )

        # Ghidra'nin dogrudan verdigi struct'lari da ekle
        for gs in ghidra_types.get("ghidra_structs", []):
            base_structs.append(gs)

        # v1.5.2: Computation Recovery constraint solver struct'larini ekle.
        # ConstraintStruct.to_dict() formatindan RecoveredStruct'a donustur.
        # Ayni isimli struct zaten varsa ATLANIYOR (CTypeRecoverer/Ghidra oncelikli).
        if computation_structs:
            existing_names = {s.name for s in base_structs}
            _comp_added = 0
            for cs in computation_structs:
                cs_name = cs.get("name", "")
                if not cs_name or cs_name in existing_names:
                    continue
                cs_fields = []
                for fd in cs.get("fields", []):
                    cs_fields.append(StructField(
                        offset=fd.get("offset", 0),
                        name=f"field_0x{fd.get('offset', 0):x}",
                        type=fd.get("type", "undefined8"),
                        size=fd.get("size", 8),
                        confidence=fd.get("confidence", 0.5),
                    ))
                rs = RecoveredStruct(
                    name=cs_name,
                    fields=cs_fields,
                    total_size=cs.get("total_size", 0),
                    source_functions=cs.get("source_functions", []),
                    alignment=cs.get("alignment", 8),
                )
                base_structs.append(rs)
                existing_names.add(cs_name)
                _comp_added += 1
            if _comp_added:
                logger.info(
                    "Computation Recovery'den %d struct eklendi (base_structs: %d)",
                    _comp_added, len(base_structs),
                )

        # Eger hic struct yoksa, C dosyalarindan cikart
        if not base_structs:
            base_structs = self._extract_structs_from_code(c_files, func_meta, errors)
            logger.info(
                "Kod analizinden %d struct cikarildi", len(base_structs),
            )

        if not base_structs:
            logger.warning("Struct bulunamadi, bos sonuc donuluyor")
            return StructRecoveryResult(
                success=True,
                errors=errors,
            )

        # --- Faz 1: Template Matching -- struct'lari algoritma sablonlarina esle ---
        logger.info("Faz 1: Template matching (%d struct, %d algo)", len(base_structs), len(func_algorithms))
        enriched_structs: list[EnrichedStruct] = []

        for struct in base_structs:
            enriched = self._enrich_struct(struct, func_algorithms, func_domains)
            enriched_structs.append(enriched)

        # Eslestirme istatistigi
        matched_count = sum(1 for es in enriched_structs if es.algorithm_context)
        logger.info(
            "Template matching: %d/%d struct eslesti",
            matched_count, len(enriched_structs),
        )

        # --- Faz 2: Call Graph Propagation ---
        if call_graph:
            logger.info("Faz 2: Call graph propagation (max %d iter)", self.max_propagation_iterations)
            # base_ptr -> struct_name eslesmesi olustur
            base_ptr_struct_map = self._build_ptr_struct_map(c_files, enriched_structs)
            func_param_map = self._build_func_param_map(c_files, enriched_structs, base_ptr_struct_map)
            enriched_structs = self._propagate_through_call_graph(
                enriched_structs, call_graph, func_param_map, func_algorithms,
            )

        # --- Faz 3: Code Rewrite ---
        logger.info("Faz 3: Code rewrite (%d C dosyasi)", len(c_files))
        struct_map = {es.name: es for es in enriched_structs}
        # raw_name -> enriched_name eslesmesi
        name_map = {es.raw_name: es.name for es in enriched_structs}

        # base_ptr -> struct eslesmesi -- tum dosyalar icin ortak
        global_ptr_map = self._build_global_ptr_struct_map(
            c_files, enriched_structs,
        )

        total_rewrites = 0
        rewritten_files: list[Path] = []

        # Orijinal dosyalari yedekle: output_dir/originals/
        originals_dir = output_dir / "originals"
        originals_dir.mkdir(parents=True, exist_ok=True)

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append(f"Dosya okunamadi: {c_file.name}: {exc}")
                continue

            # Orijinali yedekle
            backup_path = originals_dir / c_file.name
            backup_path.write_text(content, encoding="utf-8")

            rewritten, n_rewrites = self._rewrite_access_patterns(
                content, struct_map, global_ptr_map,
            )

            out_file = output_dir / c_file.name
            out_file.write_text(rewritten, encoding="utf-8")
            rewritten_files.append(out_file)
            total_rewrites += n_rewrites

        logger.info(
            "Code rewrite: %d donusum yapildi, orijinaller: %s",
            total_rewrites, originals_dir,
        )

        # --- types.h olustur ---
        types_header = output_dir / "types.h"
        self._emit_types_header(enriched_structs, types_header)
        logger.info("Enriched types.h yazildi: %s", types_header)

        # --- struct_recovery.json ---
        report_path = output_dir / "struct_recovery.json"
        result = StructRecoveryResult(
            success=True,
            enriched_structs=enriched_structs,
            types_header_path=types_header,
            rewritten_files=rewritten_files,
            field_access_rewrites=total_rewrites,
            total_structs=len(enriched_structs),
            errors=errors,
        )
        self._write_report(result, report_path)

        logger.info(
            "StructRecoveryEngine tamamlandi: %d enriched struct, %d rewrite, %d dosya",
            len(enriched_structs), total_rewrites, len(rewritten_files),
        )

        return result

    # ------------------------------------------------------------------
    # Faz 0: Struct Extraction from Code
    # ------------------------------------------------------------------

    def _extract_structs_from_code(
        self,
        c_files: list[Path],
        func_meta: dict,
        errors: list[str],
    ) -> list[RecoveredStruct]:
        """C dosyalarindan pointer aritmetigi pattern'lerini analiz ederek struct cikar.

        CTypeRecoverer sonucu yoksa bu metod kullanilir.
        Her base_ptr icin offset+type bilgilerini toplar, yeterli field
        bulunursa struct olusturur.
        """
        # base_ptr -> [(offset, type, func_name)] toplama
        all_accesses: dict[str, list[tuple[int, str, str]]] = defaultdict(list)

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            functions = self._extract_functions(content, func_meta, c_file.stem)

            for func_name, func_body, _ in functions:
                patterns = self._extract_access_patterns(func_body, func_name)
                for pat in patterns:
                    if not pat.is_array:  # Array erisimlerini struct field olarak sayma
                        all_accesses[pat.base_ptr].append(
                            (pat.offset, pat.cast_type, pat.func_name)
                        )

        # base_ptr basina struct olustur (en az 2 farkli offset gerekli)
        structs: list[RecoveredStruct] = []
        struct_id = 0

        for base_ptr, accesses in all_accesses.items():
            # Benzersiz offset'leri topla
            offset_types: dict[int, str] = {}
            source_funcs: set[str] = set()

            for offset, cast_type, func_name in accesses:
                # Ayni offset icin en detayli tipi sec
                if offset not in offset_types:
                    offset_types[offset] = cast_type
                source_funcs.add(func_name)

            if len(offset_types) < 2:
                continue

            # Field'lari olustur
            fields: list[StructField] = []
            for offset in sorted(offset_types.keys()):
                ct = offset_types[offset].strip()
                size = _TYPE_SIZES.get(ct, _TYPE_SIZES.get(ct + " *", 8))
                field_name = f"field_0x{offset:x}"
                fields.append(StructField(
                    offset=offset,
                    name=field_name,
                    type=ct,
                    size=size,
                    confidence=0.6,
                ))

            # Toplam boyut: son field'in offset + size'i
            total_size = max(f.offset + f.size for f in fields) if fields else 0
            # Alignment'a yuvarla
            alignment = 8
            if total_size % alignment:
                total_size += alignment - (total_size % alignment)

            struct_id += 1
            structs.append(RecoveredStruct(
                name=f"recovered_struct_{struct_id:03d}",
                fields=fields,
                total_size=total_size,
                source_functions=sorted(source_funcs),
                alignment=alignment,
            ))

        return structs

    # ------------------------------------------------------------------
    # Faz 1: Template Matching -- struct'i zenginlestir
    # ------------------------------------------------------------------

    def _enrich_struct(
        self,
        struct: RecoveredStruct,
        func_algorithms: dict[str, list[AlgorithmMatch]],
        func_domains: dict[str, str],
    ) -> EnrichedStruct:
        """Tek bir struct'i algoritma sablonlariyla eslestirip zenginlestir.

        Islem sirasiz:
        1. Struct'in source fonksiyonlarindaki algoritmalari bul
        2. Her algoritma icin ALGORITHM_STRUCT_TEMPLATES'den sablon al
        3. Benzerlik skoru hesapla
        4. En iyi eslesen sablonu uygula
        5. Eslesme yoksa generic isimlendirme yap
        """
        best_match: tuple[str, str, str, float, list[EnrichedField]] | None = None
        # (template_key, struct_name, algorithm_context, similarity, enriched_fields)

        for src_func in struct.source_functions:
            algos = func_algorithms.get(src_func, [])
            for algo in algos:
                template_key = self._normalize_algo_name(algo.name)
                if template_key not in ALGORITHM_STRUCT_TEMPLATES:
                    continue

                template = ALGORITHM_STRUCT_TEMPLATES[template_key]
                similarity, enriched_fields = self._compute_template_similarity(
                    struct, template,
                )

                if similarity >= self.min_template_similarity:
                    if best_match is None or similarity > best_match[3]:
                        algo_ctx = f"{algo.name} ({algo.category})"
                        best_match = (
                            template_key,
                            template["struct_name"],
                            algo_ctx,
                            similarity,
                            enriched_fields,
                        )

        # Domain bilgisini al
        domain = None
        for src_func in struct.source_functions:
            if src_func in func_domains:
                domain = func_domains[src_func]
                break

        if best_match:
            _, struct_name, algo_ctx, similarity, enriched_fields = best_match
            template = ALGORITHM_STRUCT_TEMPLATES[best_match[0]]
            if domain is None:
                domain = template.get("domain")

            es = EnrichedStruct(
                name=struct_name,
                raw_name=struct.name,
                fields=enriched_fields,
                total_size=struct.total_size,
                alignment=struct.alignment,
                source_functions=struct.source_functions,
                algorithm_context=algo_ctx,
                domain=domain,
                confidence=similarity,
            )
            es.typedef_declaration = self._generate_typedef(es)
            return es

        # Eslesme yok: generic zenginlestirme
        enriched_fields = self._generic_enrich_fields(struct)
        es = EnrichedStruct(
            name=struct.name,
            raw_name=struct.name,
            fields=enriched_fields,
            total_size=struct.total_size,
            alignment=struct.alignment,
            source_functions=struct.source_functions,
            algorithm_context=None,
            domain=domain,
            confidence=0.3,
        )
        es.typedef_declaration = self._generate_typedef(es)
        return es

    def _compute_template_similarity(
        self,
        struct: RecoveredStruct,
        template: dict[str, Any],
    ) -> tuple[float, list[EnrichedField]]:
        """Struct ile template arasindaki benzerlik skorunu hesapla.

        Benzerlik = weighted sum:
            - offset_match * 0.4  (field offset template'in araliginda mi)
            - type_match   * 0.3  (C tipi uyumlu mu)
            - size_match   * 0.3  (boyut uyumlu mu)

        Returns:
            (similarity, enriched_fields) -- similarity: 0.0-1.0
        """
        template_fields: list[FieldTemplate] = template["fields"]
        if not template_fields or not struct.fields:
            return 0.0, []

        enriched_fields: list[EnrichedField] = []
        matched_count = 0
        total_score = 0.0

        # Her struct field'i icin en yakin template field'i bul
        matched_template_indices: set[int] = set()

        for sf in struct.fields:
            best_ft_idx = -1
            best_score = 0.0
            best_ft: FieldTemplate | None = None

            for i, ft in enumerate(template_fields):
                if i in matched_template_indices:
                    continue

                # Offset match: field offset, template range icinde mi?
                offset_score = 0.0
                if ft.offset_range[0] <= sf.offset <= ft.offset_range[1]:
                    offset_score = 1.0
                elif abs(sf.offset - ft.offset_range[0]) <= 4:
                    offset_score = 0.5  # yakin ama tam degil

                # Type match
                type_score = self._type_compatibility(sf.type, ft.c_type)

                # Size match
                ft_size = _TYPE_SIZES.get(ft.c_type, 8)
                size_score = 1.0 if sf.size == ft_size else (0.5 if abs(sf.size - ft_size) <= 4 else 0.0)

                score = offset_score * 0.4 + type_score * 0.3 + size_score * 0.3
                if score > best_score:
                    best_score = score
                    best_ft_idx = i
                    best_ft = ft

            if best_ft is not None and best_score >= 0.3:
                matched_template_indices.add(best_ft_idx)
                matched_count += 1
                total_score += best_score

                enriched_fields.append(EnrichedField(
                    offset=sf.offset,
                    raw_name=sf.name,
                    semantic_name=best_ft.name,
                    c_type=best_ft.c_type,
                    size=sf.size,
                    confidence=round(best_score, 3),
                    source="algorithm_context",
                    comment=best_ft.comment,
                ))
            else:
                # Eslesmemis field: generic isim
                enriched_fields.append(EnrichedField(
                    offset=sf.offset,
                    raw_name=sf.name,
                    semantic_name=sf.name,
                    c_type=sf.type,
                    size=sf.size,
                    confidence=0.2,
                    source="unmatched",
                    comment="",
                ))

        # Benzerlik: eslesen field orani * ortalama skor
        if len(struct.fields) == 0:
            return 0.0, enriched_fields

        match_ratio = matched_count / max(len(struct.fields), len(template_fields))
        avg_score = total_score / max(matched_count, 1)
        similarity = match_ratio * 0.6 + avg_score * 0.4

        return round(similarity, 3), enriched_fields

    def _generic_enrich_fields(self, struct: RecoveredStruct) -> list[EnrichedField]:
        """Algoritma eslesmesi olmayan struct icin generic zenginlestirme.

        3 katmanli isimlendirme stratejisi:
        1. Offset bazli: Sik gorulen struct layout'larina gore isim (orn: offset 0
           int -> "count" veya "size", offset 8 pointer -> "data_ptr").
        2. Tip bazli: C tipinden anlam cikart (int* -> index/count ptr,
           char* -> str_ptr, double* -> data_ptr, void* -> opaque_ptr).
        3. Konum/boyut bazli: Struct icindeki sira ve total_size'a gore
           ilk int -> muhtemelen size/count, son ptr -> muhtemelen next/prev.
        """
        enriched: list[EnrichedField] = []
        sorted_fields = sorted(struct.fields, key=lambda f: f.offset)
        total_fields = len(sorted_fields)

        # Tip istatistikleri: kac int, kac ptr var?
        int_count = sum(
            1 for f in sorted_fields
            if f.type.strip().lower() in (
                "int", "uint", "int32_t", "uint32_t", "long", "ulong",
                "int64_t", "uint64_t", "size_t",
            )
        )
        ptr_count = sum(1 for f in sorted_fields if "*" in f.type)
        dbl_count = sum(
            1 for f in sorted_fields
            if f.type.strip().lower() in ("double", "float")
        )

        # Kullanilmis isimler -- cakisma onleme
        used_names: set[str] = set()
        int_idx = 0
        dbl_idx = 0
        ptr_idx = 0

        for field_pos, sf in enumerate(sorted_fields):
            ct = sf.type.strip().lower()
            is_first = (field_pos == 0)
            is_last = (field_pos == total_fields - 1)
            confidence = 0.25  # generic baseline

            name: str = ""
            comment: str = ""

            # --- Katman 1: Offset bazli heuristic ---
            if sf.offset == 0 and ct in (
                "int", "uint", "int32_t", "uint32_t", "long", "ulong",
            ):
                # Struct'in ilk int'i genelde count veya size
                if int_count > 1:
                    name, comment, confidence = "n_items", "item count (first int)", 0.35
                else:
                    name, comment, confidence = "size", "size or count", 0.30
            elif sf.offset == 0 and ct in ("double", "float"):
                name, comment, confidence = "primary_scalar", "primary scalar value", 0.25
            elif sf.offset <= 8 and ct in (
                "int", "uint", "int32_t", "uint32_t",
            ) and is_first is False:
                # 2. int field (offset 4-8 civari) -> genelde dimension veya flag
                name, comment, confidence = "dimension", "dimension or flag", 0.30

            # --- Katman 2: Tip bazli isimlendirme ---
            if not name:
                if ct in ("int", "uint", "int32_t", "uint32_t"):
                    int_idx += 1
                    if sf.offset < 16:
                        name = f"n_{int_idx}" if int_count > 2 else f"count_{int_idx}"
                        comment = "integer count field"
                        confidence = 0.25
                    else:
                        name = f"flags_{int_idx}" if sf.size == 4 else f"int_val_{int_idx}"
                        comment = "integer field (flags or config)"
                        confidence = 0.20
                elif ct in ("long", "ulong", "int64_t", "uint64_t", "size_t"):
                    int_idx += 1
                    name = f"size_{int_idx}"
                    comment = "64-bit size or offset"
                    confidence = 0.25
                elif ct == "double":
                    dbl_idx += 1
                    if dbl_count == 1:
                        name = "parameter"
                        comment = "floating-point parameter"
                        confidence = 0.25
                    elif dbl_idx == 1:
                        name = "tolerance" if sf.offset > 8 else "primary_value"
                        comment = "floating-point scalar"
                        confidence = 0.25
                    else:
                        name = f"coeff_{dbl_idx}"
                        comment = "floating-point coefficient"
                        confidence = 0.20
                elif ct == "float":
                    dbl_idx += 1
                    name = f"float_val_{dbl_idx}"
                    comment = "single-precision value"
                    confidence = 0.20
                elif "*" in ct:
                    ptr_idx += 1
                    base_type = ct.replace("*", "").strip()

                    if base_type in ("char", "uchar", "uint8_t"):
                        name = f"str_ptr_{ptr_idx}" if ptr_idx > 1 else "str_ptr"
                        comment = "string or byte buffer pointer"
                        confidence = 0.35
                    elif base_type in ("double", "float"):
                        name = f"data_ptr_{ptr_idx}" if ptr_idx > 1 else "data_ptr"
                        comment = "pointer to numeric array"
                        confidence = 0.30
                    elif base_type in ("int", "int32_t", "uint32_t"):
                        name = f"index_ptr_{ptr_idx}" if ptr_idx > 1 else "index_ptr"
                        comment = "pointer to integer/index array"
                        confidence = 0.30
                    elif base_type in ("void", "undefined", "undefined8"):
                        name = f"opaque_ptr_{ptr_idx}" if ptr_idx > 1 else "opaque_ptr"
                        comment = "opaque/void pointer"
                        confidence = 0.20
                    elif base_type == "code":
                        name = f"func_ptr_{ptr_idx}" if ptr_idx > 1 else "callback"
                        comment = "function pointer (callback)"
                        confidence = 0.35
                    else:
                        name = f"ptr_{ptr_idx}"
                        comment = f"pointer to {base_type}"
                        confidence = 0.20

                    # Katman 3: Son pointer -> muhtemelen next/prev linked list
                    if is_last and base_type in (
                        "void", "undefined", "undefined8",
                    ):
                        name = "next_ptr"
                        comment = "possible linked list next pointer"
                        confidence = 0.30
                else:
                    # Bilinmeyen tip
                    name = f"field_0x{sf.offset:x}"
                    comment = f"unknown type: {sf.type}"
                    confidence = 0.15

            # Cakisma onleme
            base_name = name
            suffix = 2
            while name in used_names:
                name = f"{base_name}_{suffix}"
                suffix += 1
            used_names.add(name)

            enriched.append(EnrichedField(
                offset=sf.offset,
                raw_name=sf.name,
                semantic_name=name,
                c_type=sf.type,
                size=sf.size,
                confidence=confidence,
                source="generic_heuristic",
                comment=comment,
            ))

        return enriched

    @staticmethod
    def _type_compatibility(actual: str, expected: str) -> float:
        """Iki C tipi arasindaki uyumlulugun 0-1 skorunu dondur."""
        a = actual.strip().lower().replace("  ", " ")
        e = expected.strip().lower().replace("  ", " ")

        if a == e:
            return 1.0

        # Pointer vs pointer: her ikisi de pointer ise 0.7
        if "*" in a and "*" in e:
            return 0.7

        # Int ailesi
        int_types = {"int", "uint", "long", "ulong", "int32_t", "uint32_t", "int64_t", "uint64_t", "size_t"}
        if a in int_types and e in int_types:
            return 0.8

        # Float ailesi
        float_types = {"float", "double"}
        if a in float_types and e in float_types:
            return 0.6

        # Undefined -> herhangi biri: dusuk skor
        if a.startswith("undefined") or e.startswith("undefined"):
            return 0.3

        return 0.0

    # ------------------------------------------------------------------
    # Faz 2: Call Graph Propagation
    # ------------------------------------------------------------------

    def _build_ptr_struct_map(
        self,
        c_files: list[Path],
        enriched_structs: list[EnrichedStruct],
    ) -> dict[str, str]:
        """Her C dosyasindaki base_ptr -> struct_name eslesmesi olustur.

        Bir base_ptr'nin hangi struct'a ait oldugunu bulmak icin:
        source_functions ve struct.fields offset'lerini karsilastirir.
        """
        # struct_name -> {offset: field}
        struct_offset_map: dict[str, dict[int, EnrichedField]] = {}
        for es in enriched_structs:
            struct_offset_map[es.name] = {f.offset: f for f in es.fields}

        # Bu basit bir euristic: base_ptr'yi struct'a eslemenin kesin yolu
        # her fonksiyondaki field access offset'lerini struct ile karsilastirmak.
        # Ama bu pahaliya patlar, bu yuzden source_functions bilgisini kullan.
        return {}  # Propagasyon _build_func_param_map icinde yapilir

    def _build_func_param_map(
        self,
        c_files: list[Path],
        enriched_structs: list[EnrichedStruct],
        base_ptr_struct_map: dict[str, str],
    ) -> dict[str, dict[int, str]]:
        """fonksiyon -> {param_index: struct_name} eslesmesi olustur.

        Her fonksiyonun parametre listesindeki ptr'leri struct'larla esler.
        source_functions bilgisini kullanir.
        """
        # struct kaynagi: fonksiyon -> struct listesi
        func_to_structs: dict[str, list[EnrichedStruct]] = defaultdict(list)
        for es in enriched_structs:
            for fn in es.source_functions:
                func_to_structs[fn].append(es)

        # Parametre eslesmesi: fonksiyon signature'indaki ptr parametrelerini
        # struct'larla esle (sira ile -- ilk ptr param = ilk struct)
        func_param_map: dict[str, dict[int, str]] = {}

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for m in _FUNC_DEF_RE.finditer(content):
                func_name = m.group(1)
                params_str = m.group(2)

                if func_name not in func_to_structs:
                    continue

                # Parametre listesini parse et
                params = [p.strip() for p in params_str.split(",") if p.strip()]
                ptr_param_indices: list[int] = []
                for i, param in enumerate(params):
                    if "*" in param or "param_" in param:
                        ptr_param_indices.append(i)

                structs = func_to_structs[func_name]
                param_map: dict[int, str] = {}

                # ptr parametrelerini struct'larla esle (sira ile)
                for idx, pi in enumerate(ptr_param_indices):
                    if idx < len(structs):
                        param_map[pi] = structs[idx].name

                if param_map:
                    func_param_map[func_name] = param_map

        return func_param_map

    def _propagate_through_call_graph(
        self,
        enriched_structs: list[EnrichedStruct],
        call_graph: dict[str, list[str]],
        func_param_map: dict[str, dict[int, str]],
        func_algorithms: dict[str, list[AlgorithmMatch]],
    ) -> list[EnrichedStruct]:
        """Call graph uzerinden struct kimliklerini BFS ile yay.

        Bir fonksiyonda tanımlanan struct, cagri zincirinde hangi fonksiyonlara
        geciyorsa o fonksiyonlardaki ayni offset erisimlerine ayni field ismi
        atanir.

        BFS ile caller -> callee zincirinde yayar.
        Cakisma durumunda confidence'a gore karar verir.

        Fixpoint'e kadar veya max iterasyona kadar tekrarlar.
        """
        from collections import deque

        struct_by_name: dict[str, EnrichedStruct] = {es.name: es for es in enriched_structs}

        # Ters call graph: callee -> [callers] (iki yonlu yayilim icin)
        reverse_cg: dict[str, list[str]] = defaultdict(list)
        for caller, callees in call_graph.items():
            for callee in callees:
                reverse_cg[callee].append(caller)

        # Confidence tablosu: (func, param_idx) -> (struct_name, confidence, source_func)
        # Cakisma cozumu icin en yuksek confidence'li eslesme kazanir.
        confidence_map: dict[tuple[str, int], tuple[str, float, str]] = {}

        # Mevcut eslesmeleri confidence_map'e aktar (bunlar seed bilgi)
        for func_name, param_dict in func_param_map.items():
            for param_idx, struct_name in param_dict.items():
                es = struct_by_name.get(struct_name)
                conf = es.confidence if es else 0.5
                confidence_map[(func_name, param_idx)] = (struct_name, conf, func_name)

        for iteration in range(self.max_propagation_iterations):
            new_mappings = 0

            # BFS kuyrugu: (source_func, target_func, param_idx, struct_name, confidence)
            bfs_queue: deque[tuple[str, str, int, str, float]] = deque()

            # Seed: bilinen eslesmelerden baslat
            for caller, callees in call_graph.items():
                caller_params = func_param_map.get(caller, {})
                if not caller_params:
                    continue

                for callee in callees:
                    for param_idx, struct_name in caller_params.items():
                        es = struct_by_name.get(struct_name)
                        conf = es.confidence if es else 0.5
                        # Yayilim confidence'i her hop'ta 0.9x azalir
                        propagated_conf = conf * 0.9
                        bfs_queue.append((caller, callee, param_idx, struct_name, propagated_conf))

            # BFS ile yay
            visited: set[tuple[str, int]] = set()

            while bfs_queue:
                source_func, target_func, param_idx, struct_name, conf = bfs_queue.popleft()

                key = (target_func, param_idx)
                if key in visited:
                    continue

                # Cakisma kontrolu: bu (func, param) icin zaten bir esleme var mi?
                existing = confidence_map.get(key)
                if existing is not None:
                    existing_name, existing_conf, _ = existing
                    if existing_name == struct_name:
                        # Ayni struct, confidence'i guncelle (yuksek olan kalir)
                        if conf > existing_conf:
                            confidence_map[key] = (struct_name, conf, source_func)
                        continue
                    elif existing_conf >= conf:
                        # Mevcut esleme daha guclu, atla
                        continue
                    else:
                        # Yeni esleme daha guclu, ustune yaz
                        logger.debug(
                            "Propagation conflict: %s param %d: %s (%.2f) overrides %s (%.2f)",
                            target_func, param_idx, struct_name, conf,
                            existing_name, existing_conf,
                        )

                visited.add(key)
                confidence_map[key] = (struct_name, conf, source_func)

                # target_func icin param map guncelle
                if target_func not in func_param_map:
                    func_param_map[target_func] = {}
                func_param_map[target_func][param_idx] = struct_name
                new_mappings += 1

                # Struct'in source_functions listesine ekle
                if struct_name in struct_by_name:
                    es = struct_by_name[struct_name]
                    if target_func not in es.source_functions:
                        es.source_functions.append(target_func)

                    # Algoritma baglami yayilimi
                    if es.algorithm_context is None:
                        callee_algos = func_algorithms.get(target_func, [])
                        if callee_algos:
                            es.algorithm_context = f"propagated from {source_func}"
                            es.confidence = min(es.confidence + 0.1, 0.9)

                # target_func'in callee'lerine de yay (BFS devam)
                # Confidence her hop'ta 0.9x azalir, 0.15'in altinda durur
                next_conf = conf * 0.9
                if next_conf >= 0.15:
                    for next_callee in call_graph.get(target_func, []):
                        next_key = (next_callee, param_idx)
                        if next_key not in visited:
                            bfs_queue.append((
                                target_func, next_callee, param_idx,
                                struct_name, next_conf,
                            ))

                    # Ters yonde de yay (callee -> caller): callee'yi cagiran
                    # diger fonksiyonlara da yay (ortak struct kullanimi)
                    for reverse_caller in reverse_cg.get(target_func, []):
                        rev_key = (reverse_caller, param_idx)
                        if rev_key not in visited:
                            bfs_queue.append((
                                target_func, reverse_caller, param_idx,
                                struct_name, next_conf * 0.8,  # ters yonde daha fazla azalt
                            ))

            if new_mappings == 0:
                logger.debug(
                    "Call graph propagation fixpoint: %d iterasyon", iteration + 1,
                )
                break

            logger.debug(
                "Call graph propagation iter %d: %d yeni esleme",
                iteration + 1, new_mappings,
            )

        return list(struct_by_name.values())

    # ------------------------------------------------------------------
    # Faz 3: Code Rewrite
    # ------------------------------------------------------------------

    def _build_global_ptr_struct_map(
        self,
        c_files: list[Path],
        enriched_structs: list[EnrichedStruct],
    ) -> dict[str, EnrichedStruct]:
        """Tum dosyalar icin base_ptr -> EnrichedStruct eslesmesi olustur.

        Her C dosyasindaki pointer aritmetigi pattern'lerini analiz eder,
        base_ptr'nin offset pattern'ini enriched struct'larla karsilastirir.
        """
        # struct -> offset seti
        struct_offset_sets: dict[str, set[int]] = {}
        struct_by_name: dict[str, EnrichedStruct] = {}
        for es in enriched_structs:
            offsets = {f.offset for f in es.fields}
            struct_offset_sets[es.name] = offsets
            struct_by_name[es.name] = es

        # source_functions'dan dogrudan esleme
        func_to_structs: dict[str, list[EnrichedStruct]] = defaultdict(list)
        for es in enriched_structs:
            for fn in es.source_functions:
                func_to_structs[fn].append(es)

        # base_ptr -> struct eslesmesi: her C dosyasindaki her fonksiyonda
        # base_ptr'nin eriistigi offset'leri topla, struct'la karsilastir
        ptr_map: dict[str, EnrichedStruct] = {}

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Fonksiyonlari cikar
            for m in _FUNC_DEF_RE.finditer(content):
                func_name = m.group(1)

                # Bu fonksiyon hangi struct'larla iliskili?
                possible_structs = func_to_structs.get(func_name, [])
                if not possible_structs:
                    continue

                # Fonksiyon body'sini al
                body_start = m.end() - 1
                body = self._extract_body(content, body_start)
                if not body:
                    continue

                # base_ptr -> erisdigi offset'ler
                ptr_offsets: dict[str, set[int]] = defaultdict(set)
                for pat_m in _PTR_ARITH_SIMPLE.finditer(body):
                    base = pat_m.group("base")
                    offset_str = pat_m.group("offset")
                    offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                    ptr_offsets[base].add(offset)

                # base_ptr'yi en iyi eslesen struct'a ata
                for base_ptr, offsets in ptr_offsets.items():
                    if base_ptr in ptr_map:
                        continue

                    best_struct = None
                    best_overlap = 0

                    for es in possible_structs:
                        struct_offsets = struct_offset_sets.get(es.name, set())
                        overlap = len(offsets & struct_offsets)
                        if overlap > best_overlap:
                            best_overlap = overlap
                            best_struct = es

                    if best_struct and best_overlap >= 1:
                        ptr_map[base_ptr] = best_struct

        return ptr_map

    # Minimum confidence esigi: bu deger altindaki field'lar rewrite edilmez.
    _REWRITE_MIN_CONFIDENCE: float = 0.6

    def _rewrite_access_patterns(
        self,
        c_code: str,
        struct_map: dict[str, EnrichedStruct],
        ptr_struct_map: dict[str, EnrichedStruct],
    ) -> tuple[str, int]:
        """C kodundaki pointer aritmetigini struct->field soz dizimine cevir.

        *(int *)(param_18 + 4) -> param_18->num_nodes  /* was: *(int *)(param_18 + 4) */

        Guvenlik kurallari:
        - Sadece confidence >= 0.6 olan field'lar icin rewrite yapar.
        - Array erisimleri (idx * stride) donusturulmez -- gercek array erisimi.
        - Orijinal ifade /* was: ... */ yorumu olarak korunur.
        - Zaten rewrite edilmis satirlar (icinde "/* was:" var) tekrar islenmez.

        Returns:
            (rewritten_code, rewrite_count)
        """
        rewrite_count = 0
        min_conf = self._REWRITE_MIN_CONFIDENCE

        # Offset -> field eslesmesi icin hizli lookup
        struct_field_lookup: dict[str, dict[int, EnrichedField]] = {}
        for es in struct_map.values():
            struct_field_lookup[es.name] = {f.offset: f for f in es.fields}

        def _replace_match(m: re.Match) -> str:
            nonlocal rewrite_count

            # Zaten rewrite edilmis mi?
            original = m.group(0)
            # m.string[m.start():] satirda "/* was:" varsa atla
            line_start = m.string.rfind("\n", 0, m.start()) + 1
            line_end = m.string.find("\n", m.end())
            if line_end == -1:
                line_end = len(m.string)
            line = m.string[line_start:line_end]
            if "/* was:" in line:
                return original

            base = m.group("base")
            offset_str = m.group("offset")

            es = ptr_struct_map.get(base)
            if es is None:
                return original  # Donusturme yapma

            offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
            field_map = struct_field_lookup.get(es.name, {})
            ef = field_map.get(offset)

            if ef is None:
                return original  # Bu offset struct'ta yok

            # Confidence filtresi: dusuk guvenli field'lari rewrite etme
            if ef.confidence < min_conf:
                return original

            rewrite_count += 1
            return f"{base}->{ef.semantic_name}  /* was: {original} */"

        # Sabit offset erisimlerini degistir
        result = _PTR_ARITH_SIMPLE.sub(_replace_match, c_code)

        # Dogrudan dereference (offset=0) donusumu
        def _replace_direct(m: re.Match) -> str:
            nonlocal rewrite_count

            original = m.group(0)
            # Zaten rewrite edilmis mi?
            line_start = m.string.rfind("\n", 0, m.start()) + 1
            line_end = m.string.find("\n", m.end())
            if line_end == -1:
                line_end = len(m.string)
            line = m.string[line_start:line_end]
            if "/* was:" in line:
                return original

            base = m.group("base")

            es = ptr_struct_map.get(base)
            if es is None:
                return original

            field_map = struct_field_lookup.get(es.name, {})
            ef = field_map.get(0)  # offset 0

            if ef is None:
                return original

            if ef.confidence < min_conf:
                return original

            rewrite_count += 1
            return f"{base}->{ef.semantic_name}  /* was: {original} */"

        result = _PTR_DEREF_DIRECT.sub(_replace_direct, result)

        return result, rewrite_count

    # ------------------------------------------------------------------
    # types.h Emitter
    # ------------------------------------------------------------------

    def _emit_types_header(
        self,
        structs: list[EnrichedStruct],
        output_path: Path,
    ) -> Path:
        """Zenginlestirilmis types.h dosyasi olustur.

        Her struct icin:
        - Typedef declaration
        - Field aciklamalari (offset, boyut, confidence)
        - Algoritma baglami yorumu
        - Padding notlari

        Struct'lar isme gore sirali, yuksek confidence olanlar onde.
        """
        # Istatistik
        total_fields = sum(len(es.fields) for es in structs)
        high_conf = sum(1 for es in structs if es.confidence >= 0.6)

        lines: list[str] = [
            "/*",
            " * Enriched Type Definitions",
            " * Generated by Karadul v1.2.0 StructRecoveryEngine",
            " *",
            " * Algorithm-aware struct recovery: pointer arithmetic patterns",
            " * matched against known engineering algorithm templates.",
            " *",
            f" * Total structs: {len(structs)} ({high_conf} high-confidence)",
            f" * Total fields:  {total_fields}",
            " */",
            "",
            "#ifndef KARADUL_ENRICHED_TYPES_H",
            "#define KARADUL_ENRICHED_TYPES_H",
            "",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "",
        ]

        # Yuksek confidence once, sonra isme gore sirala
        sorted_structs = sorted(
            structs,
            key=lambda s: (-s.confidence, s.name),
        )

        for es in sorted_structs:
            lines.append(self._generate_typedef(es))
            lines.append("")

        lines.append("#endif /* KARADUL_ENRICHED_TYPES_H */")
        lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    @staticmethod
    def _generate_typedef(es: EnrichedStruct) -> str:
        """Tek bir struct icin C typedef olustur."""
        lines: list[str] = []

        # Baslangic yorumu
        if es.algorithm_context:
            lines.append(f"/* Algorithm context: {es.algorithm_context} */")
        if es.domain:
            lines.append(f"/* Domain: {es.domain} */")
        if es.raw_name != es.name:
            lines.append(f"/* Recovered from: {es.raw_name} */")
        lines.append(f"/* Confidence: {es.confidence:.2f} | Size: {es.total_size} bytes | Alignment: {es.alignment} */")

        lines.append(f"typedef struct {es.name} {{")

        for ef in sorted(es.fields, key=lambda f: f.offset):
            # Padding hesapla: onceki field ile arada bosluk var mi?
            ct = ef.c_type
            # Pointer tipi formatting
            if "*" in ct and not ct.endswith("*"):
                # "double *" -> "double *"
                pass

            field_decl = f"    {ct:<16s} {ef.semantic_name};"
            # Yorum ekle
            comments: list[str] = []
            comments.append(f"offset 0x{ef.offset:x}")
            if ef.comment:
                comments.append(ef.comment)
            if ef.source == "algorithm_context":
                comments.append(f"conf={ef.confidence:.2f}")
            if ef.raw_name != ef.semantic_name:
                comments.append(f"was: {ef.raw_name}")

            field_decl += f"  /* {' | '.join(comments)} */"
            lines.append(field_decl)

        lines.append(f"}} {es.name};")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Report Writer
    # ------------------------------------------------------------------

    @staticmethod
    def _write_report(result: StructRecoveryResult, path: Path) -> None:
        """struct_recovery.json raporunu yaz."""
        report = result.to_dict()
        try:
            path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Report yazilamadi: %s: %s", path, exc)

    # ------------------------------------------------------------------
    # Yardimci Metodlar
    # ------------------------------------------------------------------

    def _extract_access_patterns(
        self, code: str, func_name: str,
    ) -> list[AccessPattern]:
        """C kodundan tum pointer aritmetigi erisim pattern'lerini cikar.

        3 pattern tipi aranir:
        1. *(type *)(base + offset) -- sabit offset struct field erisimi
        2. *(type *)(base + idx * stride) -- array erisimi
        3. *(type *)base -- dogrudan dereference (offset=0)
        """
        patterns: list[AccessPattern] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines):
            # Pattern 1: sabit offset
            for m in _PTR_ARITH_SIMPLE.finditer(line):
                offset_str = m.group("offset")
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)

                # Array erisimi kontrolu: eger ayni satirda idx * stride varsa atla
                if _PTR_ARITH_ARRAY.search(line):
                    # Bu satir hem simple hem array pattern'e uyor olabilir
                    # Array pattern'i oncelikli: bu bir array erisimi
                    continue

                patterns.append(AccessPattern(
                    base_ptr=m.group("base"),
                    offset=offset,
                    cast_type=m.group("cast_type").strip(),
                    is_array=False,
                    line_text=line.strip(),
                    line_number=line_num,
                    func_name=func_name,
                ))

            # Pattern 2: array erisimi
            for m in _PTR_ARITH_ARRAY.finditer(line):
                stride_str = m.group("stride")
                stride = int(stride_str, 16) if stride_str.startswith("0x") else int(stride_str)

                patterns.append(AccessPattern(
                    base_ptr=m.group("base"),
                    offset=0,
                    cast_type=m.group("cast_type").strip(),
                    is_array=True,
                    stride=stride,
                    index_var=m.group("index"),
                    line_text=line.strip(),
                    line_number=line_num,
                    func_name=func_name,
                ))

            # Pattern 3: dogrudan dereference (offset=0)
            for m in _PTR_DEREF_DIRECT.finditer(line):
                # Eger bu satirda zaten offset'li veya array pattern'i bulunduysa atla
                if _PTR_ARITH_SIMPLE.search(line) or _PTR_ARITH_ARRAY.search(line):
                    continue

                patterns.append(AccessPattern(
                    base_ptr=m.group("base"),
                    offset=0,
                    cast_type=m.group("cast_type").strip(),
                    is_array=False,
                    line_text=line.strip(),
                    line_number=line_num,
                    func_name=func_name,
                ))

        return patterns

    @staticmethod
    def _normalize_algo_name(name: str) -> str:
        """Algoritma ismini ALGORITHM_STRUCT_TEMPLATES key'ine normalize et.

        "Gauss Quadrature 2-point" -> "gauss quadrature"
        "Newton-Raphson Solver" -> "newton-raphson"
        "K-epsilon Turbulence" -> "k-epsilon"
        """
        name_lower = name.lower().strip()

        for pattern, template_key in _ALGO_NAME_NORMALIZATION:
            if re.search(pattern, name_lower):
                return template_key

        # Dogrudan esleme dene
        if name_lower in ALGORITHM_STRUCT_TEMPLATES:
            return name_lower

        return name_lower

    @staticmethod
    def _load_json(path: Path, errors: list[str]) -> dict:
        """JSON dosyasini yukle, hata olursa bos dict dondur."""
        path = Path(path)
        if not path.exists():
            errors.append(f"JSON dosyasi bulunamadi: {path}")
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
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
            errors.append(f"JSON parse hatasi ({path.name}): {exc}")
            return {}

    @staticmethod
    def _load_ghidra_types(
        path: Path, errors: list[str],
    ) -> dict[str, Any]:
        """ghidra_types.json yukle, struct'lari RecoveredStruct'a cevir.

        Returns:
            {"ghidra_structs": [RecoveredStruct, ...], ...}
        """
        path = Path(path)
        if not path.exists():
            return {"ghidra_structs": []}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"ghidra_types.json parse hatasi: {exc}")
            return {"ghidra_structs": []}

        if not isinstance(data, dict):
            return {"ghidra_structs": []}

        structs: list[RecoveredStruct] = []
        for entry in data.get("structures", []):
            name = entry.get("name", "")
            if not name:
                continue

            raw_fields = entry.get("fields", [])
            size = entry.get("size", 0)

            if size < 2 and not raw_fields:
                continue

            fields: list[StructField] = []
            for fld in raw_fields:
                fld_name = fld.get("name", "unknown")
                fld_type = fld.get("type", "undefined8")
                fld_offset = fld.get("offset", 0)
                fld_size = fld.get("size", _TYPE_SIZES.get(fld_type, 8))

                fields.append(StructField(
                    offset=fld_offset,
                    name=fld_name,
                    type=fld_type,
                    size=fld_size,
                    confidence=0.9,  # Ghidra kaynaklisi yuksek guven
                ))

            structs.append(RecoveredStruct(
                name=name,
                fields=sorted(fields, key=lambda f: f.offset),
                total_size=size,
                source_functions=[],
                alignment=8,
            ))

        return {"ghidra_structs": structs}

    @staticmethod
    def _load_call_graph(
        path: Path, errors: list[str],
    ) -> dict[str, list[str]]:
        """Call graph JSON yukle.

        Beklenen format:
            {"FUN_001": ["FUN_002", "FUN_003"], ...}
        veya:
            {"edges": [{"from": "FUN_001", "to": "FUN_002"}, ...]}
        """
        path = Path(path)
        if not path.exists():
            return {}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Call graph parse hatasi: {exc}")
            return {}

        if not isinstance(data, dict):
            return {}

        # Format 1: dogrudan {caller: [callees]}
        if all(isinstance(v, list) for v in data.values() if not isinstance(v, str)):
            # Filtreleme: key'ler string, value'lar list[str] olmali
            result: dict[str, list[str]] = {}
            for k, v in data.items():
                if isinstance(v, list):
                    result[k] = [str(c) for c in v]
            return result

        # Format 2: {"edges": [...], "nodes": [...]}
        if "edges" in data:
            result = defaultdict(list)
            for edge in data["edges"]:
                if isinstance(edge, dict):
                    caller = edge.get("from") or edge.get("caller") or edge.get("source", "")
                    callee = edge.get("to") or edge.get("callee") or edge.get("target", "")
                    if caller and callee:
                        result[caller].append(callee)
            return dict(result)

        return {}

    @staticmethod
    def _extract_functions(
        content: str,
        func_meta: dict,
        file_stem: str,
    ) -> list[tuple[str, str, str]]:
        """C iceriginden (func_name, func_body, address) cikar.

        EngineeringAlgorithmAnalyzer._extract_functions ile ayni mantik.
        """
        results: list[tuple[str, str, str]] = []

        for match in _FUNC_DEF_RE.finditer(content):
            func_name = match.group(1)
            body = StructRecoveryEngine._extract_body(content, match.end() - 1)

            address = "unknown"
            if func_name in func_meta:
                meta = func_meta[func_name]
                if isinstance(meta, dict):
                    address = meta.get("address", "unknown")
            elif func_name.startswith("FUN_"):
                address = "0x" + func_name[4:]

            results.append((func_name, body, address))

        if not results and content.strip():
            address = "unknown"
            if file_stem in func_meta:
                meta = func_meta[file_stem]
                if isinstance(meta, dict):
                    address = meta.get("address", "unknown")
            elif file_stem.startswith("FUN_"):
                address = "0x" + file_stem[4:]
            results.append((file_stem, content, address))

        return results

    @staticmethod
    def _extract_body(content: str, brace_pos: int) -> str:
        """Suslu parantez eslestirme ile fonksiyon body'sini cikart.

        Maks 10000 karakter okur -- struct recovery icin daha fazla body gerekebilir.
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
                    return content[brace_pos : i + 1]

        return content[brace_pos:limit]
