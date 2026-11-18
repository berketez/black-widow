"""Algorithm Composition Analyzer -- discovers how algorithms compose into systems.

Karadul v1.1.5 Module 3.  Augmented call graph, data flow bilgisi ve
algorithm detection'lari birlestirerek daha yuksek seviyeli "composition"
yapilarini tespit eder.

Bes composition pattern:
  1. PIPELINE        -- A->B->C->D sequential (VPN setup, FEA workflow)
  2. PROTOCOL_SEQ    -- Protocol stage sequence (TLS handshake stages)
  3. ITERATIVE       -- Loop with convergence (Newton-Raphson, GMRES)
  4. FORK_JOIN       -- Parallel computation then merge
  5. PRODUCER_CONSUMER -- One produces data, another consumes

Kullanim:
    from karadul.reconstruction.engineering.composition_analyzer import (
        AlgorithmCompositionAnalyzer,
    )
    analyzer = AlgorithmCompositionAnalyzer()
    result = analyzer.analyze(
        call_graph=call_graph_dict,
        algorithms=algorithm_matches,
    )
"""
from __future__ import annotations

import bisect
import itertools
import json
import logging
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CompositionStage:
    """A single stage inside an algorithm composition."""

    name: str               # Human-readable stage name (e.g. "TLS Handshake")
    functions: list[str]    # Functions involved in this stage
    algorithms: list[str]   # Algorithm detections in this stage
    order: int              # Stage order in composition (0-based)
    confidence: float       # Aggregated confidence for this stage

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "functions": self.functions,
            "algorithms": self.algorithms,
            "order": self.order,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class AlgorithmComposition:
    """A discovered algorithm composition -- a group of functions forming
    a higher-level workflow or protocol."""

    name: str                   # "VPN Setup Pipeline"
    pattern: str                # "pipeline", "iterative", etc.
    stages: list[CompositionStage]
    total_functions: int
    confidence: float
    description: str            # Human-readable description
    domain: str = "generic"     # Dominant domain tag
    # Yalnız bilinen şablon eşleşmelerinde dolar (K-1, 2026-11-18): kanıt
    # kapısının sonucu. ``passed`` True değilse bileşim raporlayıcıların okuduğu
    # ``compositions`` alanına girmez, ``pending_compositions``'ta bekler.
    evidence_gate: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "pattern": self.pattern,
            "domain": self.domain,
            "stages": [s.to_dict() for s in self.stages],
            "total_functions": self.total_functions,
            "confidence": round(self.confidence, 4),
            "description": self.description,
        }
        if self.evidence_gate is not None:
            d["evidence_gate"] = self.evidence_gate
        return d


@dataclass
class CompositionResult:
    """Complete composition analysis output."""

    success: bool
    compositions: list[AlgorithmComposition]
    total_compositions: int
    unclustered_algorithms: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # K-1 (2026-11-18): kanıt kapısından geçmeyen şablon eşleşmeleri. Bunlar
    # iddia değildir: ``compositions`` / ``total_compositions`` alanlarına
    # (raporlayıcıların ve ``stats["compositions"]``'ın okuduğu alanlar) ve
    # ``generate_report``'a girmez; yalnız burada, kapının gerekçesiyle durur.
    pending_compositions: list[AlgorithmComposition] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "total_compositions": self.total_compositions,
            "compositions": [c.to_dict() for c in self.compositions],
            "unclustered_algorithms": self.unclustered_algorithms,
            "errors": self.errors,
            "total_pending": len(self.pending_compositions),
            "pending_compositions": [
                c.to_dict() for c in self.pending_compositions
            ],
            "pending_note": _PENDING_NOTE,
        }


_PENDING_NOTE = (
    "Template matches held back by the evidence gate (decision K-1, "
    "2026-11-18): not claims, not reported, not counted in "
    "total_compositions. Each entry carries evidence_gate.reason."
)


# ---------------------------------------------------------------------------
# Known composition templates
# ---------------------------------------------------------------------------

KNOWN_COMPOSITIONS: dict[str, dict[str, Any]] = {
    # ===== Networking / Security =====
    "vpn_setup": {
        "pattern": "pipeline",
        "name_template": "VPN Tunnel Setup Pipeline",
        "domain": "crypto",
        "stages": [
            "dns", "tls_handshake", "authentication",
            "tunnel_setup", "encryption",
        ],
        "indicators": {
            "dns": [
                "dns", "resolve", "lookup", "getaddrinfo", "gethostbyname",
                "res_query", "DNSServiceQueryRecord", "nw_resolver",
            ],
            "tls_handshake": [
                "SSL_connect", "SSL_do_handshake", "SecTrust",
                "SSLHandshake", "tls_handshake", "SSL_new", "SSL_CTX_new",
            ],
            "authentication": [
                "auth", "login", "saml", "credential", "token",
                "kerberos", "oauth", "SSO", "authenticate",
                "SecKeyCreateSignature", "certificate",
            ],
            "tunnel_setup": [
                "tunnel", "vpn", "ipsec", "NEVPNManager",
                "NEVPNConnection", "NETunnelProvider",
                "startVPNTunnel", "setupTunnel",
            ],
            "encryption": [
                "AES", "encrypt", "decrypt", "cipher", "CCCrypt",
                "AES_cbc_encrypt", "EVP_Cipher", "SecKeyEncrypt",
            ],
        },
    },
    "tls_handshake": {
        "pattern": "protocol_sequence",
        "name_template": "TLS Handshake Protocol",
        "domain": "crypto",
        "stages": [
            "client_hello", "server_hello", "certificate",
            "key_exchange", "finished",
        ],
        "indicators": {
            "client_hello": [
                "client_hello", "ClientHello", "SSL_connect",
                "SSLHandshake", "tls_write_client_hello",
            ],
            "server_hello": [
                "server_hello", "ServerHello",
                "tls_process_server_hello", "ssl_parse_server_hello",
            ],
            "certificate": [
                "certificate", "X509_verify", "SecTrustEvaluate",
                "X509_verify_cert", "ssl_parse_certificate",
                "certificate_verify", "cert_chain",
            ],
            "key_exchange": [
                "key_exchange", "DH_compute_key", "ECDH",
                "kex", "ssl_parse_server_key_exchange",
                "EC_POINT_mul", "DH_generate_key",
            ],
            "finished": [
                "finished", "Finished", "ChangeCipherSpec",
                "ssl_derive_keys", "master_secret",
            ],
        },
    },
    "ssl_session": {
        "pattern": "pipeline",
        "name_template": "SSL/TLS Session Pipeline",
        "domain": "crypto",
        "stages": ["context_init", "handshake", "data_transfer", "shutdown"],
        "indicators": {
            "context_init": [
                "SSL_CTX_new", "SSL_new", "SSL_set_fd",
                "SSLCreateContext", "SSLSetConnection",
            ],
            "handshake": [
                "SSL_connect", "SSL_accept", "SSL_do_handshake",
                "SSLHandshake",
            ],
            "data_transfer": [
                "SSL_read", "SSL_write", "SSLRead", "SSLWrite",
                "SSL_peek",
            ],
            "shutdown": [
                "SSL_shutdown", "SSL_free", "SSL_CTX_free",
                "SSLClose", "SSLDisposeContext",
            ],
        },
    },
    "certificate_validation": {
        "pattern": "pipeline",
        "name_template": "Certificate Chain Validation",
        "domain": "crypto",
        "stages": ["load_cert", "build_chain", "verify_signature", "check_revocation"],
        "indicators": {
            "load_cert": [
                "d2i_X509", "PEM_read", "SecCertificateCreateWithData",
                "X509_new",
            ],
            "build_chain": [
                "X509_STORE_CTX", "SecTrustCreateWithCertificates",
                "SSL_get_peer_cert_chain", "X509_verify_cert",
            ],
            "verify_signature": [
                "X509_verify", "RSA_verify", "ECDSA_verify",
                "SecTrustEvaluate", "SecKeyVerifySignature",
            ],
            "check_revocation": [
                "OCSP", "CRL", "X509_REVOKED", "SecTrustSetOCSPResponse",
                "X509_CRL_check",
            ],
        },
    },
    "key_derivation": {
        "pattern": "pipeline",
        "name_template": "Key Derivation Pipeline",
        "domain": "crypto",
        "stages": ["random_gen", "kdf", "key_expand", "key_use"],
        "indicators": {
            "random_gen": [
                "RAND_bytes", "SecRandomCopyBytes", "arc4random",
                "getrandom", "RAND_seed",
            ],
            "kdf": [
                "PBKDF2", "HKDF", "scrypt", "bcrypt",
                "CCKeyDerivationPBKDF", "EVP_KDF",
            ],
            "key_expand": [
                "HKDF_expand", "PRF", "tls_prf",
                "derive_master_secret", "key_material",
            ],
            "key_use": [
                "AES", "encrypt", "decrypt", "HMAC",
                "CCCrypt", "EVP_EncryptInit",
            ],
        },
    },

    # ===== FEA / Structural =====
    "fea_nonlinear_static": {
        "pattern": "iterative",
        "name_template": "Nonlinear Static FEA Solution",
        "domain": "structural",
        "stages": [
            "mesh_read", "assembly", "solve",
            "update", "convergence_check", "postprocess",
        ],
        "indicators": {
            "mesh_read": [
                "readinput", "frd", "inp", "mesh", "node",
                "element", "elset", "nset", "material",
            ],
            "assembly": [
                "mafill", "stiffness", "assembly", "e_c3d",
                "gauss", "quadrature", "B_matrix", "dgemm",
            ],
            "solve": [
                "solve", "spooles", "pardiso", "lu_factor",
                "dgesv", "factor", "MUMPS", "cholmod",
            ],
            "update": [
                "update", "increment", "delta_u", "daxpy",
                "results", "nodal",
            ],
            "convergence_check": [
                "convergence", "residual", "norm", "tolerance",
                "dnrm2", "criteria", "iterate",
            ],
            "postprocess": [
                "postprocess", "stress", "strain", "output",
                "frd_write", "results", "von_mises",
            ],
        },
    },
    "fea_linear_static": {
        "pattern": "pipeline",
        "name_template": "Linear Static FEA Pipeline",
        "domain": "structural",
        "stages": ["mesh_read", "assembly", "solve", "postprocess"],
        "indicators": {
            "mesh_read": [
                "readinput", "mesh", "node", "element", "inp",
            ],
            "assembly": [
                "mafill", "stiffness", "assembly", "e_c3d",
                "gauss", "B_matrix",
            ],
            "solve": [
                "solve", "spooles", "pardiso", "factor",
                "dgesv", "cholmod",
            ],
            "postprocess": [
                "stress", "strain", "output", "frd_write",
                "von_mises", "postprocess",
            ],
        },
    },
    "fea_eigenvalue": {
        "pattern": "pipeline",
        "name_template": "Eigenvalue Analysis (Modal / Buckling)",
        "domain": "structural",
        "stages": ["assembly", "eigensolve", "mode_extract", "postprocess"],
        "indicators": {
            "assembly": [
                "stiffness", "mass_matrix", "assembly",
                "geometric_stiffness",
            ],
            "eigensolve": [
                "arpack", "dsaupd", "dseupd", "lanczos",
                "subspace", "eigenvalue", "dsyev",
            ],
            "mode_extract": [
                "mode_shape", "eigenvector", "frequency",
                "modal", "participation_factor",
            ],
            "postprocess": [
                "output", "frd_write", "mode_plot",
                "stress", "strain",
            ],
        },
    },
    "contact_analysis": {
        "pattern": "iterative",
        "name_template": "Contact Mechanics Solution",
        "domain": "structural",
        "stages": ["detect", "enforce", "update", "iterate"],
        "indicators": {
            "detect": [
                "contact_detect", "gap", "penetration",
                "master_slave", "surface_pair",
            ],
            "enforce": [
                "lagrange", "penalty", "augmented_lagrangian",
                "contact_force", "stiffness",
            ],
            "update": [
                "update", "contact_status", "stick_slip",
                "friction",
            ],
            "iterate": [
                "newton", "convergence", "residual", "iterate",
            ],
        },
    },

    # ===== CFD / Fluid =====
    "cfd_steady_rans": {
        "pattern": "iterative",
        "name_template": "Steady RANS CFD Solution",
        "domain": "fluid",
        "stages": ["mesh_read", "init", "iterate", "turbulence", "convergence"],
        "indicators": {
            "mesh_read": [
                "mesh", "grid", "cell", "face", "boundary",
            ],
            "init": [
                "init", "field", "pressure", "velocity",
                "boundary_condition",
            ],
            "iterate": [
                "SIMPLE", "PISO", "coupled", "momentum",
                "pressure_correction", "iterate",
            ],
            "turbulence": [
                "k_epsilon", "k_omega", "SST", "spalart",
                "turbulent", "eddy_viscosity",
            ],
            "convergence": [
                "residual", "convergence", "norm", "tolerance",
                "monitor",
            ],
        },
    },
    "cfd_transient": {
        "pattern": "iterative",
        "name_template": "Transient CFD Time-Stepping",
        "domain": "fluid",
        "stages": ["init", "timestep", "spatial", "solve", "advance"],
        "indicators": {
            "init": ["init", "field", "boundary"],
            "timestep": ["dt", "time_step", "CFL", "courant"],
            "spatial": [
                "gradient", "flux", "divergence",
                "laplacian", "convection",
            ],
            "solve": [
                "solve", "GMRES", "BiCGStab", "preconditioner",
            ],
            "advance": [
                "advance", "update", "time_advance",
                "next_step",
            ],
        },
    },

    # ===== DSP / Signal Processing =====
    "fft_pipeline": {
        "pattern": "pipeline",
        "name_template": "FFT Signal Processing Pipeline",
        "domain": "dsp",
        "stages": ["window", "fft", "process", "ifft"],
        "indicators": {
            "window": [
                "window", "hann", "hamming", "blackman",
                "kaiser", "windowing",
            ],
            "fft": [
                "fft", "FFT", "fftw", "DFT", "fftw_execute",
            ],
            "process": [
                "filter", "spectrum", "magnitude", "phase",
                "frequency", "band",
            ],
            "ifft": [
                "ifft", "IFFT", "inverse_fft", "fftw_execute",
            ],
        },
    },
    "audio_codec": {
        "pattern": "pipeline",
        "name_template": "Audio Codec Pipeline",
        "domain": "dsp",
        "stages": ["decode", "transform", "quantize", "encode"],
        "indicators": {
            "decode": [
                "decode", "demux", "unpack", "bitstream",
            ],
            "transform": [
                "MDCT", "DCT", "filterbank", "subband",
                "FFT",
            ],
            "quantize": [
                "quantize", "huffman", "entropy", "scale_factor",
            ],
            "encode": [
                "encode", "mux", "pack", "bitstream_write",
            ],
        },
    },

    # ===== ML / Deep Learning =====
    "ml_training_loop": {
        "pattern": "iterative",
        "name_template": "ML Training Loop",
        "domain": "ml",
        "stages": ["forward", "loss", "backward", "optimize"],
        "indicators": {
            "forward": [
                "forward", "inference", "predict", "conv2d",
                "linear", "relu", "batch_norm",
            ],
            "loss": [
                "loss", "cross_entropy", "mse", "criterion",
                "softmax",
            ],
            "backward": [
                "backward", "gradient", "backprop", "autograd",
                "chain_rule",
            ],
            "optimize": [
                "optimizer", "adam", "sgd", "step",
                "learning_rate", "weight_update",
            ],
        },
    },
    "ml_inference": {
        "pattern": "pipeline",
        "name_template": "ML Inference Pipeline",
        "domain": "ml",
        "stages": ["preprocess", "forward", "postprocess"],
        "indicators": {
            "preprocess": [
                "preprocess", "normalize", "resize", "transform",
                "tokenize",
            ],
            "forward": [
                "forward", "inference", "predict", "model",
                "session_run",
            ],
            "postprocess": [
                "postprocess", "decode", "argmax", "threshold",
                "nms",
            ],
        },
    },

    # ===== Finance =====
    "options_pricing": {
        "pattern": "pipeline",
        "name_template": "Options Pricing Pipeline",
        "domain": "finance",
        "stages": ["market_data", "model_calibrate", "price", "greeks"],
        "indicators": {
            "market_data": [
                "market_data", "yield_curve", "volatility_surface",
                "spot_price", "rate",
            ],
            "model_calibrate": [
                "calibrate", "heston", "sabr", "local_vol",
                "implied_vol",
            ],
            "price": [
                "price", "black_scholes", "monte_carlo",
                "finite_difference", "binomial",
            ],
            "greeks": [
                "delta", "gamma", "vega", "theta", "rho",
                "greeks",
            ],
        },
    },

    # ===== General Computation =====
    "matrix_solve_pipeline": {
        "pattern": "pipeline",
        "name_template": "Matrix Solve Pipeline",
        "domain": "structural",
        "stages": ["allocate", "fill", "factor", "solve", "free"],
        "indicators": {
            "allocate": [
                "alloc", "malloc", "create_matrix", "sparse_create",
            ],
            "fill": [
                "fill", "assemble", "insert", "set_value",
                "MatSetValues",
            ],
            "factor": [
                "factor", "lu", "cholesky", "ilu",
                "dpotrf", "dgetrf",
            ],
            "solve": [
                "solve", "dgesv", "dgetrs", "dpotrs",
                "triangular_solve",
            ],
            "free": [
                "free", "destroy", "release", "deallocate",
            ],
        },
    },
    "hash_then_sign": {
        "pattern": "pipeline",
        "name_template": "Hash-then-Sign Pipeline",
        "domain": "crypto",
        "stages": ["hash", "sign", "verify"],
        "indicators": {
            "hash": [
                "SHA256", "SHA384", "SHA512", "MD5",
                "hash", "digest", "CC_SHA",
            ],
            "sign": [
                "RSA_sign", "ECDSA_sign", "SecKeyCreateSignature",
                "sign",
            ],
            "verify": [
                "RSA_verify", "ECDSA_verify", "SecKeyVerifySignature",
                "verify",
            ],
        },
    },
    "compress_then_encrypt": {
        "pattern": "pipeline",
        "name_template": "Compress-then-Encrypt Pipeline",
        "domain": "crypto",
        "stages": ["compress", "encrypt", "mac"],
        "indicators": {
            "compress": [
                "deflate", "zlib", "gzip", "lz4", "compress",
                "brotli", "zstd",
            ],
            "encrypt": [
                "AES", "encrypt", "cipher", "ChaCha20",
                "CCCrypt", "EVP_Encrypt",
            ],
            "mac": [
                "HMAC", "GCM", "Poly1305", "mac",
                "CCHmac", "authenticate",
            ],
        },
    },

    # ===== Crypto KDF =====
    "crypto_kdf": {
        "pattern": "pipeline",
        "name_template": "Cryptographic Key Derivation Pipeline",
        "domain": "crypto",
        "stages": ["salt_generate", "key_stretch", "derive_key", "encrypt"],
        "indicators": {
            "salt_generate": [
                "RAND_bytes", "SecRandomCopyBytes", "arc4random",
                "getrandom", "salt", "random", "nonce",
                "RAND_seed", "os_random",
            ],
            "key_stretch": [
                "PBKDF2", "scrypt", "bcrypt", "argon2",
                "CCKeyDerivationPBKDF", "EVP_PBE",
                "PKCS5_PBKDF2_HMAC", "iterations",
            ],
            "derive_key": [
                "HKDF", "HKDF_expand", "HKDF_extract",
                "derive", "key_material", "PRF",
                "EVP_KDF", "kdf", "master_secret",
            ],
            "encrypt": [
                "AES", "encrypt", "cipher", "ChaCha20",
                "CCCrypt", "EVP_EncryptInit", "EVP_Cipher",
                "SecKeyEncrypt", "GCM", "CBC",
            ],
        },
    },

    # ===== Aerospace / Simulation =====
    "rocket_simulation": {
        "pattern": "iterative",
        "name_template": "Rocket / Trajectory Simulation Loop",
        "domain": "aerospace",
        "stages": [
            "aero_calc", "thrust_calc", "gravity_calc",
            "integrate", "update_state",
        ],
        "indicators": {
            "aero_calc": [
                "drag", "lift", "aero", "Cd", "Cl",
                "mach", "reynolds", "dynamic_pressure",
                "atmosphere", "density", "air_density",
            ],
            "thrust_calc": [
                "thrust", "isp", "specific_impulse", "exhaust",
                "propellant", "mass_flow", "nozzle",
                "burn_rate", "chamber_pressure",
            ],
            "gravity_calc": [
                "gravity", "gravitational", "gm", "mu",
                "central_body", "J2", "oblateness",
                "geocentric", "geopotential",
            ],
            "integrate": [
                "rk4", "runge_kutta", "euler", "verlet",
                "leapfrog", "dopri", "rkf45",
                "ode_step", "integrate", "dt",
            ],
            "update_state": [
                "update", "state", "position", "velocity",
                "altitude", "trajectory", "propagate",
                "advance", "step",
            ],
        },
    },
}

# ---------------------------------------------------------------------------
# Domain inference from algorithm categories
# ---------------------------------------------------------------------------

_CATEGORY_TO_DOMAIN: dict[str, str] = {
    "symmetric_cipher": "crypto",
    "asymmetric": "crypto",
    "hash": "crypto",
    "mac": "crypto",
    "kdf": "crypto",
    "checksum": "crypto",
    "fea_integration": "structural",
    "fea_solver": "structural",
    "fea_element": "structural",
    "structural_mechanics": "structural",
    "cfd_turbulence": "fluid",
    "cfd_solver": "fluid",
    "cfd_discretization": "fluid",
    "fluid_dynamics": "fluid",
    "dsp_transform": "dsp",
    "dsp_filter": "dsp",
    "signal_processing": "dsp",
    "finance_pricing": "finance",
    "finance_risk": "finance",
    "ml_optimizer": "ml",
    "ml_layer": "ml",
    "ml_loss": "ml",
    "linear_algebra": "structural",
    "optimization": "structural",
    "aerospace": "aerospace",
    "orbital_mechanics": "aerospace",
    "propulsion": "aerospace",
}

# ---------------------------------------------------------------------------
# Edge weight constants for graph clustering
# ---------------------------------------------------------------------------

_W_CALL = 0.3       # Weight for call-graph edge
_W_DATA = 0.5       # Weight for data-flow edge
_W_DOMAIN = 0.2     # Same-domain bonus
_EDGE_THRESHOLD = 0.25  # Minimum weight to keep edge in subgraph
_MIN_COMPOSITION_SIZE = 2  # Minimum stages to count as composition
_MAX_COMPOSITION_SIZE = 200  # Sanity cap


# ---------------------------------------------------------------------------
# Şablon kanıt kapısı (MUH-03, 2026-11-18)
# ---------------------------------------------------------------------------
# Eski eşleşme göstergeyi her fonksiyon adında ALT DİZGİ olarak arıyordu:
# ``dt`` → ``_DT_INIT``, ``gm`` → ``__gmon_start__``, ``lu`` → ``fflush``,
# ``cl`` → ``_ITM_deregisterTMCloneTable``; 119 ikilinin 119'una CFD, roket
# ve matris çözücü bileşimi yazılıyordu. Kapının kuralları:
#   1. Ad eşleşmesi tam belirteçtir (``_``/noktalama/camelCase ile bölünmüş
#      parçalar; göstergenin belirteçleri ardışık ve eşit olmalı). Tek
#      belirteçli ve en az ``_GATE_INFLECTION_MIN`` harfli gösterge, bir
#      belirtecin başında çekim eki alabilir (``encrypt`` → ``encryption``).
#   2. İçe aktarılan ve derleyici çalışma zamanı adları gösterge değildir.
#   3. Bir aşama yalnız o aşamaya uyan GERÇEK bir algoritma tespitiyle
#      sayılır (ad tek başına yetmez). Gerçek tespit: yerel fonksiyonda;
#      kendi adını yineleyen "API call" değil (içe aktarım kütüğü); yalnız
#      sabit parmak izi değil (MUH-10: ``decimal: 0`` → RC4); yalnız çıplak
#      sözcük eşleşmesi değil (``isa_atmosphere: matched 'DENSITY'``).
#      Tespit aşamaya üç yoldan bağlanır: tespit adı göstergeyle eşleşir
#      (parantez içi "şunlarda kullanılır" listesi hariç), aşamanın dar
#      kategorisi (``_STAGE_CATEGORIES``) ya da fonksiyon adı göstergeyle
#      eşleşir. Her yolda tespitin alanı şablonun alanıyla aynı olmalı.
#   4. En az ``_GATE_MIN_STAGES`` aşama (ve aşamaların ``_GATE_MIN_STAGE_
#      FRACTION`` oranı), şablona adını veren aşama(lar) (``_TEMPLATE_
#      DEFINING_STAGES``), en az iki ayrı fonksiyon ve iki ayrı tespit.
#   5. Kanıtlı aşamaların fonksiyonları çağrı çizgesinde bağlı: hepsine
#      ``_GATE_LINK_DEPTH`` adımda inen ortak bir sürücü (biri öbürünü
#      çağırıyorsa sürücü odur; program girişi/çalışma zamanı sürücü olamaz).
#      Çağrı çizgesi çağrı yeri sırası taşımadığı için zaman sırası ve
#      döngü/yakınsama doğrulanmaz; açıklama bunu iddia etmez.
_GATE_MIN_STAGES = 2          # en az iki kanıtlı aşama (tek kanıtla şablon yok)
_GATE_MIN_STAGE_FRACTION = 0.4  # şablon aşamalarının en az bu oranı
_GATE_LINK_DEPTH = 2          # ortak sürücüden aşama fonksiyonuna en çok adım
_GATE_INFLECTION_MIN = 6      # çekim eki toleransı için en kısa gösterge
_GATE_MAX_STAGE_FUNCS = 10    # aşama başına raporlanan en çok fonksiyon

# Şablonu şablon yapan (adını veren) aşamalar: kanıtlı olmaları ŞART.
# Her iç demet seçeneklidir (biri yeter); dış demetin hepsi gerekir.
# Örnek: openssl'de TLS el sıkışması + sertifika + simetrik şifreleme
# kanıtlı, ama tünel aşaması yok → "VPN Tunnel Setup" denmez.
_TEMPLATE_DEFINING_STAGES: dict[str, tuple[tuple[str, ...], ...]] = {
    "vpn_setup": (("tunnel_setup",),),
    "tls_handshake": (("client_hello", "server_hello"),),
    "ssl_session": (("handshake",),),
    "certificate_validation": (("build_chain",),),
    "key_derivation": (("kdf",),),
    "fea_nonlinear_static": (("assembly",), ("convergence_check",)),
    "fea_linear_static": (("assembly",), ("solve",)),
    "fea_eigenvalue": (("eigensolve",),),
    "contact_analysis": (("detect",),),
    "cfd_steady_rans": (("turbulence",),),
    "cfd_transient": (("timestep",),),
    "fft_pipeline": (("fft",),),
    "audio_codec": (("transform",),),
    "ml_training_loop": (("backward",),),
    "ml_inference": (("forward",),),
    "options_pricing": (("price",),),
    "matrix_solve_pipeline": (("factor", "solve"),),
    "hash_then_sign": (("hash",), ("sign",)),
    "compress_then_encrypt": (("compress",), ("encrypt",)),
    "crypto_kdf": (("key_stretch",),),
    "rocket_simulation": (("thrust_calc", "gravity_calc"),),
}

# Aşama ↔ tespit kategorisi: kategorinin kendisi aşamanın işini adlandırıyorsa
# (``kdf`` kategorili tespit "kdf" aşamasını kanıtlar). Yalnız dar kategoriler;
# ``symmetric_cipher`` gibi geniş kategoriler (XOR, S-box) burada YOK.
_STAGE_CATEGORIES: dict[str, tuple[str, ...]] = {
    "kdf": ("kdf",),
    "key_stretch": ("kdf",),
    "derive_key": ("kdf",),
    "compress": ("compression",),
    "hash": ("hash",),
    "mac": ("mac",),
}

# Aşamanın kendi alanı şablonunkinden farklıysa (Compress-then-Encrypt'in
# sıkıştırma aşaması "crypto" değildir). Yoksa şablonun alanı geçerlidir.
_STAGE_DOMAINS: dict[str, tuple[str, ...]] = {
    "compress": ("compression",),
}

_TOKEN_SPLIT = re.compile(r"[^0-9A-Za-z]+")
# Tespit adındaki parantez "şunlardan biri / şunlarda kullanılır" listesidir
# ("Galois field operations (ECC, AES-GF)"): ayırt edici değil, eşleşmeye girmez.
_PARENTHETICAL = re.compile(r"\([^)]*\)")
_CAMEL_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# "isa_atmosphere: matched 'DENSITY'", "aes_cbc: matched 'iv'": yapı değil, sözcük.
_KEYWORD_ONLY_EVIDENCE = re.compile(r"^\s*[\w.+-]+: matched '[A-Za-z0-9_ ]*'\s*$")
_API_EVIDENCE = re.compile(r"^\s*API call:\s*([A-Za-z_][\w.]*)")

# Derleyici / bağlayıcı çalışma zamanı adları (ELF crt, Mach-O, PE CRT).
_RUNTIME_PREFIXES: tuple[str, ...] = (
    "_dt_", "_init_", "_fini_", "_itm_", "__gmon", "__cxa_", "__libc_",
    "__stack_chk", "__do_global", "_global_", "__x86.", "_dl_", "__imp_",
    "thunk_", "__security_", "__gshandler", "___chkstk", "__chkstk",
    "__register_frame", "__deregister_frame", "_objc_", "__objc_",
)
_RUNTIME_EXACT: frozenset[str] = frozenset({
    "_start", "start", "entry", "_init", "_fini", "frame_dummy",
    "register_tm_clones", "deregister_tm_clones", "call_weak_fn",
    "__do_global_dtors_aux", "_mh_execute_header", "dyld_stub_binder",
})
# Sık içe aktarılan C/POSIX kitaplık adları (baştaki ``_`` atılarak karşılaştırılır).
_LIBC_IMPORTS: frozenset[str] = frozenset({
    "malloc", "calloc", "realloc", "reallocarray", "free", "aligned_alloc",
    "posix_memalign", "memcpy", "memmove", "memset", "memcmp", "memchr",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strdup",
    "strchr", "strrchr", "strstr", "strtol", "strtoul", "strtod",
    "printf", "fprintf", "sprintf", "snprintf", "vfprintf", "vsnprintf",
    "puts", "fputs", "putchar", "fputc", "fwrite", "fread", "fopen",
    "fclose", "fflush", "fflush_unlocked", "fseek", "ftell", "fileno",
    "open", "close", "read", "write", "lseek", "stat", "fstat", "lstat",
    "mmap", "munmap", "exit", "_exit", "abort", "atexit", "getenv",
    "setlocale", "bindtextdomain", "textdomain", "dcgettext", "gettext",
    "mbsinit", "mbrtowc", "wcwidth", "iswprint", "clock_gettime",
    "gettimeofday", "time", "gmtime_r", "localtime_r", "strftime",
    "pthread_mutex_init", "pthread_mutex_destroy", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_create", "pthread_join",
    "pthread_sigmask", "sigaction", "signal", "raise", "kill",
    "getaddrinfo", "freeaddrinfo", "gethostbyname", "socket", "connect",
    "bind", "listen", "accept", "send", "recv", "select", "poll",
    "error", "err", "warn", "perror", "qsort", "bsearch", "rand", "srand",
})


def _name_tokens(name: str) -> tuple[str, ...]:
    """Adı küçük harfli belirteçlere böler (``_``, noktalama, camelCase)."""
    out: list[str] = []
    for part in _TOKEN_SPLIT.split(name or ""):
        if not part:
            continue
        out.extend(p.lower() for p in _CAMEL_SPLIT.split(part) if p)
    return tuple(out)


def _tokens_match(indicator: tuple[str, ...], tokens: tuple[str, ...]) -> bool:
    """Göstergenin belirteçleri adın belirteçlerinde ardışık mı (tam belirteç)."""
    n = len(indicator)
    if n == 0 or n > len(tokens):
        return False
    if n == 1:
        ind = indicator[0]
        if len(ind) >= _GATE_INFLECTION_MIN:
            return any(t == ind or t.startswith(ind) for t in tokens)
        return ind in tokens
    for i in range(len(tokens) - n + 1):
        if tokens[i:i + n] == indicator:
            return True
    return False


def _is_runtime_or_import_name(name: str) -> bool:
    """Derleyici çalışma zamanı ya da sık içe aktarılan kitaplık adı mı."""
    low = (name or "").lower()
    if not low:
        return True
    if low in _RUNTIME_EXACT or low.startswith(_RUNTIME_PREFIXES):
        return True
    bare = low.lstrip("_")
    if bare in _LIBC_IMPORTS:
        return True
    # Fortified libc (``__printf_chk``, ``___strcat_chk``)
    return low.startswith("__") and bare.endswith("_chk")


def _detection_rejection(algo: dict) -> str | None:
    """Tespit bileşim kanıtı sayılamıyorsa nedeni, sayılıyorsa None."""
    func = algo.get("function_name", "") or ""
    if not func:
        return "detection without function"
    if _is_runtime_or_import_name(func):
        return "detection in runtime/import function"
    evidence = [str(e) for e in (algo.get("evidence") or [])]
    if evidence:
        own = _name_tokens(func)
        api_names = [m.group(1) for m in (_API_EVIDENCE.match(e) for e in evidence) if m]
        if api_names and len(api_names) == len(evidence) and all(
            _name_tokens(a) == own for a in api_names
        ):
            return "detection only restates the function's own name"
        if (algo.get("detection_method") == "structural"
                and all(_KEYWORD_ONLY_EVIDENCE.match(e) for e in evidence)):
            return "structural detection matched a bare keyword"
    if algo.get("detection_method") == "constant":
        # Sabit parmak izi tek fonksiyonluk bir ipucudur; mühendislik sabit
        # katmanı bugün alt dizgiyle eşleşiyor (MUH-10: "decimal: 0" → RC4).
        # Mimari iddia (bileşim) için API çağrısı ya da kod yapısı gerekir.
        return "constant-only detection"
    return None


# Kapının alan denetimi için kategori → alan (``_CATEGORY_TO_DOMAIN``'a ek;
# ``_infer_domain`` eskisi gibi yalnız o tabloyu kullanır).
_GATE_CRYPTO_CATEGORIES: frozenset[str] = frozenset({
    "symmetric_encryption", "asymmetric_encryption", "aead", "elliptic_curve",
    "digital_signature", "key_exchange", "hardware_crypto", "pki", "protocol",
    "network_security", "random", "post_quantum",
})
_GATE_FINANCE_CATEGORIES: frozenset[str] = frozenset({
    "finance", "option_pricing", "risk_measure", "credit_fixed_income",
    "volatility", "yield_curve", "portfolio_optimization", "finance_statistics",
})
_GATE_STRUCTURAL_CATEGORIES: frozenset[str] = frozenset({
    "finite_element", "structural_dynamics", "fracture_mechanics",
})


def _category_domain(category: str) -> str:
    """Tespit kategorisinin alanı (kapının alan tutarlılığı denetimi için)."""
    cat = (category or "").lower()
    if cat == "compression":
        return "compression"
    if cat in _CATEGORY_TO_DOMAIN:
        return _CATEGORY_TO_DOMAIN[cat]
    if cat in _GATE_CRYPTO_CATEGORIES:
        return "crypto"
    if cat in _GATE_FINANCE_CATEGORIES:
        return "finance"
    if cat in _GATE_STRUCTURAL_CATEGORIES or cat.startswith("fea_"):
        return "structural"
    if cat.startswith("cfd_"):
        return "fluid"
    if cat.startswith("dsp"):
        return "dsp"
    if cat.startswith("ml_"):
        return "ml"
    return "generic"


class _TokenIndex:
    """Ad belirteçleri üstünde ters dizin: gösterge → tam belirteçle eşleşen adlar."""

    def __init__(self, names: Any) -> None:
        self._tokens: dict[str, tuple[str, ...]] = {}
        self._by_token: dict[str, set[str]] = defaultdict(set)
        for n in names:
            toks = _name_tokens(n)
            self._tokens[n] = toks
            for t in toks:
                self._by_token[t].add(n)
        self._vocab = sorted(self._by_token)
        self._cache: dict[tuple[str, ...], frozenset[str]] = {}

    def matches(self, indicator: tuple[str, ...]) -> frozenset[str]:
        hit = self._cache.get(indicator)
        if hit is not None:
            return hit
        out: set[str] = set()
        if len(indicator) == 1:
            ind = indicator[0]
            if len(ind) >= _GATE_INFLECTION_MIN:
                i = bisect.bisect_left(self._vocab, ind)
                while i < len(self._vocab) and self._vocab[i].startswith(ind):
                    out |= self._by_token[self._vocab[i]]
                    i += 1
            else:
                out |= self._by_token.get(ind, set())
        elif indicator:
            for n in self._by_token.get(indicator[0], ()):
                if _tokens_match(indicator, self._tokens[n]):
                    out.add(n)
        hit = frozenset(out)
        self._cache[indicator] = hit
        return hit


# ---------------------------------------------------------------------------
# AlgorithmCompositionAnalyzer
# ---------------------------------------------------------------------------

class AlgorithmCompositionAnalyzer:
    """Discovers how algorithms compose into larger systems.

    Analyzes call graphs, algorithm detections, and optional data flow info
    to group related functions into higher-level compositions (pipelines,
    protocols, iterative solvers, etc.).
    """

    def __init__(self, config: Any | None = None) -> None:
        self._config = config
        # Build flattened indicator lookup: word -> list[(template_key, stage)]
        self._indicator_index: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for tpl_key, tpl in KNOWN_COMPOSITIONS.items():
            for stage_name, words in tpl["indicators"].items():
                for word in words:
                    self._indicator_index[word.lower()].append((tpl_key, stage_name))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        call_graph: dict,
        algorithms: list[AlgorithmMatch] | list[dict],
        data_flow: Any | None = None,
        dispatch_result: Any | None = None,
        functions_json: Path | None = None,
    ) -> CompositionResult:
        """Discover algorithm compositions.

        Parameters
        ----------
        call_graph : dict
            Ghidra call graph (or augmented call graph) -- expects ``nodes``
            dict and optionally ``virtual_edges`` list.
        algorithms : list
            AlgorithmMatch objects (or dicts with at least ``name``,
            ``function_name``, ``category``, ``confidence``).
        data_flow : dict, optional
            Data flow graph (edges, data_objects).
        dispatch_result : dict, optional
            Virtual dispatch resolution result.
        functions_json : Path, optional
            Path to ``ghidra_functions.json`` for extra metadata.

        Returns
        -------
        CompositionResult
        """
        errors: list[str] = []
        compositions: list[AlgorithmComposition] = []
        pending: list[AlgorithmComposition] = []

        try:
            # Normalize algorithms to dicts
            algo_dicts = self._normalize_algorithms(algorithms)

            # Build helper indexes
            func_algo_map = self._build_func_algo_map(algo_dicts)
            adjacency = self._build_adjacency(call_graph)
            func_names_set = set(adjacency.keys())
            if call_graph.get("nodes"):
                for addr, info in call_graph["nodes"].items():
                    func_names_set.add(info.get("name", ""))

            # Load extra function names from JSON if provided
            if functions_json and functions_json.exists():
                try:
                    with open(functions_json) as f:
                        fdata = json.load(f)
                    for func in fdata.get("functions", []):
                        func_names_set.add(func.get("name", ""))
                except Exception as exc:
                    errors.append(f"functions_json load: {exc}")

            # Phase 1: Match known templates. K-1 (2026-11-18): kanıt
            # kapısından geçmeyen eşleşme iddia değildir; bekletilir.
            template_comps = self._match_known_templates(
                func_names_set, algo_dicts, adjacency,
            )
            for comp in template_comps:
                gate = comp.evidence_gate or {}
                if gate.get("passed") is True:
                    compositions.append(comp)
                    continue
                if not gate:
                    comp.evidence_gate = {
                        "passed": False,
                        "reason": "no evidence gate evaluated",
                    }
                pending.append(comp)

            # Phase 2: Detect pipelines from call graph + data flow
            pipeline_comps = self._detect_pipelines(
                adjacency, func_algo_map, data_flow,
            )
            compositions.extend(pipeline_comps)

            # Phase 3: Detect iterative refinement loops
            iterative_comps = self._detect_iterative(
                adjacency, func_algo_map, algo_dicts, call_graph,
            )
            compositions.extend(iterative_comps)

            # Phase 4: Detect fork-join patterns
            fj_comps = self._detect_fork_join(
                adjacency, func_algo_map,
            )
            compositions.extend(fj_comps)

            # Phase 5: Detect producer-consumer from data flow
            if data_flow:
                pc_comps = self._detect_producer_consumer(
                    data_flow, func_algo_map,
                )
                compositions.extend(pc_comps)

            # Deduplicate compositions with overlapping function sets
            compositions = self._deduplicate(compositions)

            # Sort by confidence descending
            compositions.sort(key=lambda c: c.confidence, reverse=True)

            # Find unclustered algorithms
            clustered_funcs: set[str] = set()
            for comp in compositions:
                for stage in comp.stages:
                    clustered_funcs.update(stage.functions)
            # algo_dicts zaten _normalize_algorithms cikisi -> list[dict].
            unclustered = [
                a.get("name", "")
                for a in algo_dicts
                if a.get("function_name", "") not in clustered_funcs
            ]

        except Exception as exc:
            logger.error("Composition analysis failed: %s", exc, exc_info=True)
            errors.append(str(exc))
            return CompositionResult(
                success=False,
                compositions=[],
                total_compositions=0,
                errors=errors,
            )

        return CompositionResult(
            success=True,
            compositions=compositions,
            total_compositions=len(compositions),
            unclustered_algorithms=unclustered,
            errors=errors,
            pending_compositions=pending,
        )

    def generate_report(self, result: CompositionResult) -> str:
        """Generate a Markdown report with Mermaid diagrams.

        Parameters
        ----------
        result : CompositionResult
            Output from ``analyze()``.

        Returns
        -------
        str
            Markdown-formatted report.
        """
        lines: list[str] = []
        lines.append("# Algorithm Composition Report")
        lines.append("")
        lines.append(f"**Total compositions found:** {result.total_compositions}")
        if result.errors:
            lines.append(f"**Errors:** {len(result.errors)}")
        lines.append("")

        # Summary table
        if result.compositions:
            lines.append("## Summary")
            lines.append("")
            lines.append("| # | Composition | Pattern | Stages | Confidence | Domain |")
            lines.append("|---|-----------|---------|--------|-----------|--------|")
            for i, comp in enumerate(result.compositions, 1):
                lines.append(
                    f"| {i} | {comp.name} | {comp.pattern} | "
                    f"{len(comp.stages)} | {comp.confidence:.2f} | {comp.domain} |"
                )
            lines.append("")

        # Detailed compositions
        for i, comp in enumerate(result.compositions, 1):
            lines.append(f"## {i}. {comp.name}")
            lines.append("")
            lines.append(f"**Pattern:** {comp.pattern}  ")
            lines.append(f"**Domain:** {comp.domain}  ")
            lines.append(f"**Confidence:** {comp.confidence:.2f}  ")
            lines.append(f"**Total functions:** {comp.total_functions}")
            lines.append("")
            lines.append(comp.description)
            lines.append("")

            # Stages table
            lines.append("### Stages")
            lines.append("")
            lines.append("| Order | Stage | Functions | Algorithms | Confidence |")
            lines.append("|-------|-------|-----------|-----------|-----------|")
            for stage in comp.stages:
                funcs_str = ", ".join(stage.functions[:5])
                if len(stage.functions) > 5:
                    funcs_str += f" (+{len(stage.functions) - 5})"
                algos_str = ", ".join(stage.algorithms[:3])
                if len(stage.algorithms) > 3:
                    algos_str += f" (+{len(stage.algorithms) - 3})"
                lines.append(
                    f"| {stage.order} | {stage.name} | {funcs_str} | "
                    f"{algos_str} | {stage.confidence:.2f} |"
                )
            lines.append("")

            # Mermaid diagram
            mermaid = self._render_mermaid(comp)
            if mermaid:
                lines.append("### Flow Diagram")
                lines.append("")
                lines.append("```mermaid")
                lines.append(mermaid)
                lines.append("```")
                lines.append("")

        # Unclustered algorithms
        if result.unclustered_algorithms:
            lines.append("## Unclustered Algorithms")
            lines.append("")
            for algo in result.unclustered_algorithms[:20]:
                lines.append(f"- {algo}")
            if len(result.unclustered_algorithms) > 20:
                lines.append(
                    f"- ... and {len(result.unclustered_algorithms) - 20} more"
                )
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Template matching
    # ------------------------------------------------------------------

    def _match_known_templates(
        self,
        func_names: set[str],
        algo_dicts: list[dict],
        adjacency: dict[str, list[str]],
    ) -> list[AlgorithmComposition]:
        """Bilinen şablonları kanıt kapısıyla eşle (MUH-03).

        Aday: en az iki aşamada tam belirteçli ad ya da tespit adı isabeti
        (eski eşik). Her aday ``evidence_gate`` taşır; ``passed`` yalnız
        modül başındaki kapı kurallarının hepsi tutunca True olur, aksi
        halde ``analyze`` adayı ``pending_compositions``'a koyar.
        """
        results: list[AlgorithmComposition] = []
        name_index = _TokenIndex(
            fn for fn in func_names if fn and not _is_runtime_or_import_name(fn))

        # Kanıt sayılabilen tespitler; red nedenleri kapı kaydına yazılır
        evidence_by_func: dict[str, list[dict]] = defaultdict(list)
        algos_by_name: dict[str, list[dict]] = defaultdict(list)
        algos_by_category: dict[str, list[dict]] = defaultdict(list)
        rejected: dict[str, int] = defaultdict(int)
        for a in algo_dicts:
            why = _detection_rejection(a)
            if why is None:
                evidence_by_func[a["function_name"]].append(a)
                algos_by_name[a.get("name", "")].append(a)
                algos_by_category[(a.get("category") or "").lower()].append(a)
            else:
                rejected[why] += 1
        algo_name_tokens = {
            nm: _name_tokens(_PARENTHETICAL.sub(" ", nm)) for nm in algos_by_name
        }

        reverse_adj: dict[str, list[str]] = defaultdict(list)
        for caller, callees in adjacency.items():
            for callee in callees:
                reverse_adj[callee].append(caller)

        for tpl_key, tpl in KNOWN_COMPOSITIONS.items():
            tpl_domain = tpl.get("domain", "generic")
            n_stages = len(tpl["stages"])
            need = max(_GATE_MIN_STAGES,
                       math.ceil(n_stages * _GATE_MIN_STAGE_FRACTION))

            name_hits: dict[str, list[str]] = {}
            # aşama -> [(fonksiyon, tespit adı, güven, kanıt türü)]
            backed: dict[str, list[tuple[str, str, float, str]]] = {}
            for stage_name in tpl["stages"]:
                inds = [_name_tokens(i) for i in tpl["indicators"].get(stage_name, [])]
                inds = [i for i in inds if i]
                stage_domains = _STAGE_DOMAINS.get(stage_name, (tpl_domain,))
                hit_set: set[str] = set()
                for ind in inds:
                    hit_set |= name_index.matches(ind)
                if hit_set:
                    name_hits[stage_name] = sorted(hit_set)
                ev: dict[tuple[str, str], tuple[str, str, float, str]] = {}
                for nm, toks in algo_name_tokens.items():
                    if any(_tokens_match(i, toks) for i in inds):
                        for a in algos_by_name[nm]:
                            if _category_domain(a.get("category", "")) not in stage_domains:
                                continue  # alan dışı tespit (ör. CG "gradient" → ML)
                            key = (a["function_name"], nm)
                            ev.setdefault(key, (key[0], nm, float(
                                a.get("confidence", 0.0) or 0.0), "algorithm name"))
                for fn in hit_set:
                    for a in evidence_by_func.get(fn, []):
                        if _category_domain(a.get("category", "")) not in stage_domains:
                            continue
                        key = (fn, a.get("name", ""))
                        ev.setdefault(key, (fn, key[1], float(
                            a.get("confidence", 0.0) or 0.0), "function name + domain"))
                for cat in _STAGE_CATEGORIES.get(stage_name, ()):
                    for a in algos_by_category.get(cat, []):
                        if _category_domain(a.get("category", "")) not in stage_domains:
                            continue
                        key = (a["function_name"], a.get("name", ""))
                        ev.setdefault(key, (key[0], key[1], float(
                            a.get("confidence", 0.0) or 0.0), "algorithm category"))
                if ev:
                    backed[stage_name] = sorted(
                        ev.values(), key=lambda e: (-e[2], e[0], e[1]))

            candidate_stages = [s for s in tpl["stages"] if s in name_hits or s in backed]
            if len(candidate_stages) < need:
                continue  # aday bile değil (eski eşik, tam belirteçle)

            gate = self._evaluate_template_gate(
                backed, need, _TEMPLATE_DEFINING_STAGES.get(tpl_key, ()),
                reverse_adj, rejected)

            stages: list[CompositionStage] = []
            for order, stage_name in enumerate(tpl["stages"]):
                if stage_name not in candidate_stages:
                    continue
                ev = backed.get(stage_name, [])
                funcs = list(dict.fromkeys(
                    [e[0] for e in ev] + name_hits.get(stage_name, [])))
                algos = list(dict.fromkeys(e[1] for e in ev))
                stages.append(CompositionStage(
                    name=stage_name.replace("_", " ").title(),
                    functions=funcs[:_GATE_MAX_STAGE_FUNCS],
                    algorithms=algos[:5],
                    order=order,
                    confidence=round(ev[0][2], 4) if ev else 0.0,
                ))

            backed_conf = [backed[s][0][2] for s in tpl["stages"] if s in backed]
            # Kalibre edilmemiş oran: kanıtlı aşama payı × en güçlü tespitlerin
            # ortalaması (MUH-05: güvenler bir veri setine bağlı değil).
            conf = 0.0
            if backed_conf:
                conf = (len(backed_conf) / n_stages) * (sum(backed_conf) / len(backed_conf))

            results.append(AlgorithmComposition(
                name=tpl["name_template"],
                pattern=tpl["pattern"],
                stages=stages,
                total_functions=len({f for s in stages for f in s.functions}),
                confidence=round(min(0.95, conf), 4),
                description=self._describe_template_match(tpl, stages, gate, backed),
                domain=tpl_domain,
                evidence_gate=gate,
            ))

        return results

    def _evaluate_template_gate(
        self,
        backed: dict[str, list[tuple[str, str, float, str]]],
        need: int,
        defining: tuple[tuple[str, ...], ...],
        reverse_adj: dict[str, list[str]],
        rejected: dict[str, int],
    ) -> dict[str, Any]:
        """Kanıt kapısı (modül başındaki kurallar 3-5). Sonuç JSON'a yazılır."""
        gate: dict[str, Any] = {
            "passed": False,
            "backed_stages": {
                s: [{"function": e[0], "algorithm": e[1], "kind": e[3]} for e in ev[:3]]
                for s, ev in backed.items()
            },
            "required_stages": need,
        }
        if rejected:
            gate["rejected_detections"] = dict(sorted(rejected.items()))
        if len(backed) < need:
            gate["reason"] = (
                f"{len(backed)} stage(s) backed by an algorithm detection, "
                f"{need} required; a name match alone is not evidence")
            return gate
        if not defining:
            gate["reason"] = "template has no defining stage"
            return gate
        missing = [
            "/".join(group) for group in defining
            if not any(st in backed for st in group)
        ]
        if missing:
            gate["reason"] = (
                f"defining stage not backed by an algorithm detection: "
                f"{', '.join(missing)}")
            return gate
        funcs = {e[0] for ev in backed.values() for e in ev}
        dets = {(e[0], e[1]) for ev in backed.values() for e in ev}
        if len(funcs) < 2 or len(dets) < 2:
            gate["reason"] = "single piece of evidence (needs >= 2 functions and detections)"
            return gate
        driver = self._common_driver(
            [{e[0] for e in ev} for ev in backed.values()], reverse_adj)
        if driver is None:
            gate["reason"] = (
                f"backed stages are not linked in the call graph "
                f"(no common caller within {_GATE_LINK_DEPTH} calls)")
            return gate
        gate["passed"] = True
        gate["driver"] = driver
        gate["reason"] = (
            f"{len(backed)} stages backed by algorithm detections in "
            f"{len(funcs)} functions, linked via {driver}")
        return gate

    @staticmethod
    def _common_driver(
        stage_funcs: list[set[str]],
        reverse_adj: dict[str, list[str]],
    ) -> str | None:
        """Her aşamanın en az bir fonksiyonuna ``_GATE_LINK_DEPTH`` adımda inen düğüm.

        Fonksiyonun kendisi de sayılır (biri öbürünü çağırıyorsa sürücü odur).
        Belirlenimli: aday adlara göre sıralı ilk düğüm.
        """
        common: set[str] | None = None
        for funcs in stage_funcs:
            seen: set[str] = set(funcs)
            frontier = set(funcs)
            for _ in range(_GATE_LINK_DEPTH):
                nxt: set[str] = set()
                for f in frontier:
                    for caller in reverse_adj.get(f, []):
                        if caller not in seen:
                            seen.add(caller)
                            nxt.add(caller)
                frontier = nxt
                if not frontier:
                    break
            common = seen if common is None else (common & seen)
            if not common:
                return None
        # Program girişi / çalışma zamanı (``entry``, ``_start``) bütün programa
        # iner: ortak sürücü sayılırsa bağ kanıtı anlamsızlaşır.
        common = {c for c in (common or ()) if not _is_runtime_or_import_name(c)}
        return sorted(common)[0] if common else None

    def _describe_template_match(
        self,
        template: dict,
        stages: list[CompositionStage],
        gate: dict[str, Any] | None = None,
        backed: dict[str, list[tuple[str, str, float, str]]] | None = None,
    ) -> str:
        """Şablon eşleşmesinin betimi: yalnız doğrulananı söyler.

        Çağrı çizgesi çağrı yeri sırası taşımaz: zaman sırası, döngü ve
        yakınsama doğrulanmaz, bu yüzden "repeating until convergence" ya da
        "Flow: A -> B" gibi bir iddia yazılmaz.
        """
        name = template["name_template"]
        n_total = len(template["stages"])
        backed = backed or {}
        parts = []
        for s in template["stages"]:
            if s in backed:
                fn, algo = backed[s][0][0], backed[s][0][1]
                parts.append(f"{s.replace('_', ' ').title()}: {algo} in {fn}")
        ev_str = "; ".join(parts) if parts else "none"
        gate = gate or {}
        if gate.get("passed"):
            link = f"linked in the call graph via {gate.get('driver')}"
        else:
            link = f"evidence gate not passed ({gate.get('reason', 'not evaluated')})"
        return (
            f"{name} ({template['pattern']} template): {len(backed)} of "
            f"{n_total} stages backed by algorithm detections ({ev_str}); "
            f"{link}. Call order, loops and convergence are not verified."
        )

    # ------------------------------------------------------------------
    # Pipeline detection
    # ------------------------------------------------------------------

    def _detect_pipelines(
        self,
        adjacency: dict[str, list[str]],
        func_algo_map: dict[str, list[dict]],
        data_flow: dict | None,
    ) -> list[AlgorithmComposition]:
        """Detect pipeline compositions via DAG topological sort + longest path DP.

        Strategy:
        1. Extract sub-DAG of algorithm-bearing functions from the call graph.
        2. Remove back-edges (cycles) to create a DAG.
        3. Topological sort (Kahn's algorithm).
        4. Longest-path DP to find the longest sequential chain.
        5. Also collect shorter chains (>= min_stages) via DFS fallback.
        """
        results: list[AlgorithmComposition] = []
        min_stages = _MIN_COMPOSITION_SIZE

        # Find functions with algorithms
        algo_funcs = set(func_algo_map.keys())
        if len(algo_funcs) < min_stages:
            return results

        # Build sub-DAG: only edges between algo-bearing functions
        sub_adj: dict[str, list[str]] = defaultdict(list)
        sub_in_degree: dict[str, int] = {f: 0 for f in algo_funcs}
        for func in algo_funcs:
            for callee in adjacency.get(func, []):
                if callee in algo_funcs and callee != func:
                    sub_adj[func].append(callee)
                    sub_in_degree[callee] = sub_in_degree.get(callee, 0) + 1

        # Kahn's topological sort -- detect and remove back-edges (cycles)
        topo_order: list[str] = []
        queue = [f for f in algo_funcs if sub_in_degree.get(f, 0) == 0]
        remaining_in = dict(sub_in_degree)

        while queue:
            # Sort for deterministic results
            queue.sort()
            node = queue.pop(0)
            topo_order.append(node)
            for neighbor in sub_adj.get(node, []):
                remaining_in[neighbor] -= 1
                if remaining_in[neighbor] == 0:
                    queue.append(neighbor)

        # Nodes not in topo_order are in cycles -- handle them separately
        # (they'll be picked up by _detect_iterative)
        topo_set = set(topo_order)

        # Longest path DP on the topological order
        # dist[node] = length of longest path ending at node
        # pred[node] = predecessor on that longest path
        if len(topo_order) >= min_stages:
            dist: dict[str, int] = {f: 1 for f in topo_order}
            pred: dict[str, str | None] = {f: None for f in topo_order}

            for node in topo_order:
                for neighbor in sub_adj.get(node, []):
                    if neighbor in topo_set and dist[node] + 1 > dist[neighbor]:
                        dist[neighbor] = dist[node] + 1
                        pred[neighbor] = node

            # Extract all chains of length >= min_stages
            # Start from nodes with highest dist values
            extracted_chains: list[list[str]] = []
            used_in_chain: set[str] = set()

            # Sort by distance descending to get longest chains first
            sorted_by_dist = sorted(
                topo_order, key=lambda n: dist[n], reverse=True,
            )

            for end_node in sorted_by_dist:
                if dist[end_node] < min_stages:
                    break
                if end_node in used_in_chain:
                    continue

                # Reconstruct chain by walking pred pointers
                chain: list[str] = []
                current: str | None = end_node
                while current is not None:
                    chain.append(current)
                    current = pred[current]
                chain.reverse()

                # Skip if heavily overlaps with existing chain
                chain_set = set(chain)
                if chain_set & used_in_chain:
                    overlap = len(chain_set & used_in_chain) / len(chain_set)
                    if overlap > 0.5:
                        continue

                extracted_chains.append(chain)
                used_in_chain.update(chain)

            # Also do DFS fallback for chains the DP missed
            # (multi-branch situations where DP only keeps one path)
            dfs_chains = self._find_algo_chains_dfs(
                topo_order, sub_adj, algo_funcs, used_in_chain,
            )
            extracted_chains.extend(dfs_chains)

            # Convert chains to compositions
            for chain in extracted_chains:
                comp = self._chain_to_composition(
                    chain, func_algo_map, data_flow,
                )
                if comp is not None:
                    results.append(comp)

        return results

    def _find_algo_chains_dfs(
        self,
        topo_order: list[str],
        sub_adj: dict[str, list[str]],
        algo_funcs: set[str],
        already_used: set[str],
        max_length: int = 10,
    ) -> list[list[str]]:
        """DFS fallback to find additional chains not captured by longest-path DP.

        Only searches from nodes not yet used in a chain, to avoid duplicates.
        """
        chains: list[list[str]] = []
        topo_set = set(topo_order)

        # Find root nodes (zero in-degree in sub-DAG) not already used
        reverse_count: dict[str, int] = defaultdict(int)
        for node in topo_order:
            for nb in sub_adj.get(node, []):
                if nb in topo_set:
                    reverse_count[nb] += 1

        roots = [
            f for f in topo_order
            if reverse_count[f] == 0 and f not in already_used
        ]

        for start in roots[:10]:  # Cap to avoid explosion
            self._dfs_chains(
                start, sub_adj, algo_funcs, [start], {start},
                max_length, chains,
            )

        # Filter: only chains of length >= min_stages and low overlap
        filtered: list[list[str]] = []
        used: set[str] = set(already_used)
        for chain in sorted(chains, key=len, reverse=True):
            if len(chain) < _MIN_COMPOSITION_SIZE:
                continue
            chain_set = set(chain)
            if used and chain_set & used:
                overlap = len(chain_set & used) / len(chain_set)
                if overlap > 0.5:
                    continue
            filtered.append(chain)
            used.update(chain)

        return filtered

    def _dfs_chains(
        self,
        current: str,
        sub_adj: dict[str, list[str]],
        algo_funcs: set[str],
        path: list[str],
        visited: set[str],
        max_length: int,
        result: list[list[str]],
    ) -> None:
        """Recursive DFS to enumerate chains in the sub-DAG."""
        if len(path) >= max_length:
            if len(path) >= _MIN_COMPOSITION_SIZE:
                result.append(list(path))
            return

        callees = [
            c for c in sub_adj.get(current, [])
            if c in algo_funcs and c not in visited
        ]

        if not callees:
            if len(path) >= _MIN_COMPOSITION_SIZE:
                result.append(list(path))
            return

        for callee in callees:
            visited.add(callee)
            path.append(callee)
            self._dfs_chains(
                callee, sub_adj, algo_funcs, path, visited,
                max_length, result,
            )
            path.pop()
            visited.discard(callee)

    def _chain_to_composition(
        self,
        chain: list[str],
        func_algo_map: dict[str, list[dict]],
        data_flow: dict | None,
    ) -> AlgorithmComposition | None:
        """Convert a function chain into an AlgorithmComposition object."""
        if len(chain) < _MIN_COMPOSITION_SIZE:
            return None

        stages: list[CompositionStage] = []
        total_conf = 0.0
        for order, func in enumerate(chain):
            algos = func_algo_map.get(func, [])
            algo_names = [a.get("name", "") for a in algos]
            avg_conf = (
                sum(a.get("confidence", 0.5) for a in algos) / len(algos)
                if algos else 0.3
            )
            total_conf += avg_conf
            stages.append(CompositionStage(
                name=self._clean_func_name(func),
                functions=[func],
                algorithms=algo_names,
                order=order,
                confidence=round(avg_conf, 4),
            ))

        overall_conf = total_conf / len(stages)
        # Boost confidence if data flow confirms the chain
        if data_flow:
            flow_bonus = self._check_data_flow_chain(chain, data_flow)
            overall_conf = min(0.95, overall_conf + flow_bonus * 0.15)

        # Longer chains get a small confidence bonus (max +0.05)
        length_bonus = min(0.05, (len(chain) - 2) * 0.01)
        overall_conf = min(0.95, overall_conf + length_bonus)

        domain = self._infer_domain(
            [a for func in chain for a in func_algo_map.get(func, [])]
        )
        name = self._name_from_chain(chain)

        desc_parts = " -> ".join(
            f"{s.name}({','.join(s.algorithms[:2])})" if s.algorithms
            else s.name
            for s in stages
        )
        desc = f"Pipeline ({len(stages)} stages, topological order): {desc_parts}"

        return AlgorithmComposition(
            name=name,
            pattern="pipeline",
            stages=stages,
            total_functions=len(stages),
            confidence=round(min(0.95, overall_conf), 4),
            description=desc,
            domain=domain,
        )

    # ------------------------------------------------------------------
    # Iterative refinement detection
    # ------------------------------------------------------------------

    def _detect_iterative(
        self,
        adjacency: dict[str, list[str]],
        func_algo_map: dict[str, list[dict]],
        algo_dicts: list[dict],
        call_graph: dict,
    ) -> list[AlgorithmComposition]:
        """Detect iterative refinement compositions via Tarjan SCC + convergence.

        Three-phase approach:
        1. Tarjan's SCC to find strongly connected components (cycles).
        2. Within each SCC, detect back-edges for loop structure.
        3. Score SCCs with convergence pattern keywords for confidence.

        Codex-Consultant estimate: SCC + back-edge = 75-80% accuracy,
        adding convergence pattern raises it to 88-92%.
        """
        results: list[AlgorithmComposition] = []

        convergence_keywords = {
            "convergence", "converge", "residual", "norm", "tolerance",
            "iterate", "iteration", "loop", "tol", "criteria",
            "dnrm2", "ddot", "max_iter", "epsilon", "eps",
        }
        solver_keywords = {
            "solve", "factor", "lu", "cholesky", "newton",
            "gmres", "bicgstab", "cg", "jacobi", "gauss_seidel",
            "pardiso", "spooles", "mumps",
        }

        # Collect all function names
        all_funcs: set[str] = set(adjacency.keys())
        for callees in adjacency.values():
            all_funcs.update(callees)
        if call_graph.get("nodes"):
            for addr, info in call_graph["nodes"].items():
                all_funcs.add(info.get("name", ""))

        # Classify functions by keywords
        convergence_funcs: set[str] = set()
        solver_funcs: set[str] = set()
        for func in all_funcs:
            fl = func.lower()
            if any(kw in fl for kw in convergence_keywords):
                convergence_funcs.add(func)
            if any(kw in fl for kw in solver_keywords):
                solver_funcs.add(func)

        # Also mark functions with iterative algorithm detections
        for algo in algo_dicts:
            aname = algo.get("name", "").lower()
            fname = algo.get("function_name", "")
            if any(kw in aname for kw in {"newton", "iterative", "gmres",
                                           "conjugate_gradient", "bicgstab",
                                           "gauss_seidel", "jacobi",
                                           "fixed_point", "picard"}):
                solver_funcs.add(fname)

        # --- Phase 1: Tarjan's SCC ---
        sccs = self._tarjan_scc(adjacency)

        # Filter SCCs: at least 2 nodes, at least one algo-bearing
        algo_funcs = set(func_algo_map.keys())
        scc_compositions = self._sccs_to_compositions(
            sccs, adjacency, func_algo_map, algo_funcs,
            convergence_funcs, solver_funcs,
        )
        results.extend(scc_compositions)

        # --- Phase 2: Keyword-based fallback for non-SCC iteratives ---
        # (Solver + convergence neighbor, but not in any SCC)
        scc_covered: set[str] = set()
        for comp in scc_compositions:
            for stage in comp.stages:
                scc_covered.update(stage.functions)

        keyword_comps = self._detect_iterative_keyword_fallback(
            adjacency, func_algo_map, solver_funcs,
            convergence_funcs, scc_covered,
        )
        results.extend(keyword_comps)

        return results

    def _tarjan_scc(
        self, adjacency: dict[str, list[str]],
    ) -> list[list[str]]:
        """Tarjan's algorithm for finding Strongly Connected Components.

        Returns list of SCCs, each is a list of node names.
        Only returns SCCs with 2+ nodes (actual cycles).
        Time complexity: O(V + E).
        """
        index_counter = [0]
        stack: list[str] = []
        on_stack: set[str] = set()
        index_map: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        result: list[list[str]] = []

        # Collect all nodes (including those only appearing as callees)
        all_nodes: set[str] = set(adjacency.keys())
        for callees in adjacency.values():
            all_nodes.update(callees)

        def strongconnect(v: str) -> None:
            index_map[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            for w in adjacency.get(v, []):
                if w not in index_map:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            # Root of SCC
            if lowlink[v] == index_map[v]:
                scc: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.append(w)
                    if w == v:
                        break
                if len(scc) >= 2:
                    result.append(scc)

        # Use iterative wrapper to avoid Python recursion limit on large graphs
        # For graphs with 50K+ nodes, we use an iterative version
        if len(all_nodes) > 50000:
            return self._tarjan_scc_iterative(adjacency, all_nodes)

        for node in sorted(all_nodes):  # sorted for determinism
            if node not in index_map:
                try:
                    strongconnect(node)
                except RecursionError:
                    # Fallback to iterative for deep graphs
                    return self._tarjan_scc_iterative(adjacency, all_nodes)

        return result

    def _tarjan_scc_iterative(
        self,
        adjacency: dict[str, list[str]],
        all_nodes: set[str],
    ) -> list[list[str]]:
        """Iterative Tarjan's SCC for large graphs (avoids recursion limit).

        Uses an explicit stack to simulate the recursive DFS.
        """
        index_counter = [0]
        stack: list[str] = []
        on_stack: set[str] = set()
        index_map: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        result: list[list[str]] = []

        for root in sorted(all_nodes):
            if root in index_map:
                continue

            # Simulate recursive DFS with explicit call stack
            # Each frame: (node, iterator_over_neighbors, is_returning)
            call_stack: list[tuple[str, int]] = []
            # We'll track which neighbor index we're at
            neighbors_cache: dict[str, list[str]] = {}

            def get_neighbors(v: str) -> list[str]:
                if v not in neighbors_cache:
                    neighbors_cache[v] = adjacency.get(v, [])
                return neighbors_cache[v]

            # Initialize root
            index_map[root] = index_counter[0]
            lowlink[root] = index_counter[0]
            index_counter[0] += 1
            stack.append(root)
            on_stack.add(root)
            call_stack.append((root, 0))

            while call_stack:
                v, ni = call_stack[-1]
                neighbors = get_neighbors(v)

                if ni < len(neighbors):
                    w = neighbors[ni]
                    call_stack[-1] = (v, ni + 1)  # advance iterator

                    if w not in index_map:
                        # Push new frame
                        index_map[w] = index_counter[0]
                        lowlink[w] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(w)
                        on_stack.add(w)
                        call_stack.append((w, 0))
                    elif w in on_stack:
                        lowlink[v] = min(lowlink[v], index_map[w])
                else:
                    # All neighbors processed -- pop frame
                    call_stack.pop()
                    if call_stack:
                        parent = call_stack[-1][0]
                        lowlink[parent] = min(lowlink[parent], lowlink[v])

                    # Check if v is root of SCC
                    if lowlink[v] == index_map[v]:
                        scc: list[str] = []
                        while True:
                            w = stack.pop()
                            on_stack.discard(w)
                            scc.append(w)
                            if w == v:
                                break
                        if len(scc) >= 2:
                            result.append(scc)

        return result

    def _sccs_to_compositions(
        self,
        sccs: list[list[str]],
        adjacency: dict[str, list[str]],
        func_algo_map: dict[str, list[dict]],
        algo_funcs: set[str],
        convergence_funcs: set[str],
        solver_funcs: set[str],
    ) -> list[AlgorithmComposition]:
        """Convert SCCs into iterative AlgorithmComposition objects.

        For each SCC:
        - Check if it contains solver or algo-bearing functions.
        - Detect back-edges within the SCC.
        - Score convergence pattern presence.
        """
        results: list[AlgorithmComposition] = []

        for scc in sccs:
            scc_set = set(scc)

            # Must have at least one algo-bearing or solver function
            has_algo = bool(scc_set & algo_funcs)
            has_solver = bool(scc_set & solver_funcs)
            has_convergence = bool(scc_set & convergence_funcs)

            if not (has_algo or has_solver):
                continue

            # Find back-edges within SCC (edges forming the cycle)
            back_edges: list[tuple[str, str]] = []
            for node in scc:
                for callee in adjacency.get(node, []):
                    if callee in scc_set:
                        back_edges.append((node, callee))

            if not back_edges:
                continue

            # Confidence scoring
            base_conf = 0.50  # SCC detected = base
            if has_solver:
                base_conf += 0.15
            if has_convergence:
                base_conf += 0.15  # convergence pattern = big boost
            if has_algo:
                base_conf += 0.10
            # Bonus for larger SCCs (more convincing cycle)
            if len(scc) >= 4:
                base_conf += 0.05

            base_conf = min(0.92, base_conf)

            # Build stages -- try to order them logically
            # Strategy: topological sort within the SCC after removing
            # the lightest back-edge (heuristic for loop body order)
            ordered = self._order_scc_nodes(scc, adjacency)

            stages: list[CompositionStage] = []
            involved_funcs: set[str] = set()
            for order_idx, func in enumerate(ordered):
                algos = func_algo_map.get(func, [])
                algo_names = [a.get("name", "") for a in algos]

                # Per-stage confidence
                stage_conf = 0.5
                if func in solver_funcs:
                    stage_conf = 0.75
                elif func in convergence_funcs:
                    stage_conf = 0.65
                elif algos:
                    stage_conf = 0.6

                stages.append(CompositionStage(
                    name=self._clean_func_name(func),
                    functions=[func],
                    algorithms=algo_names,
                    order=order_idx,
                    confidence=round(stage_conf, 4),
                ))
                involved_funcs.add(func)

            if len(stages) < _MIN_COMPOSITION_SIZE:
                continue

            domain = self._infer_domain(
                [a for f in involved_funcs for a in func_algo_map.get(f, [])]
            )

            # Name: use solver function if available, else first SCC node
            solver_in_scc = scc_set & solver_funcs
            if solver_in_scc:
                primary = sorted(solver_in_scc)[0]
            else:
                primary = ordered[0]

            conv_names = sorted(scc_set & convergence_funcs)[:3]
            conv_str = ", ".join(conv_names) if conv_names else "cycle structure"

            results.append(AlgorithmComposition(
                name=f"Iterative {self._clean_func_name(primary)} Loop",
                pattern="iterative",
                stages=stages,
                total_functions=len(involved_funcs),
                confidence=round(base_conf, 4),
                description=(
                    f"Strongly connected component with {len(scc)} functions. "
                    f"{len(back_edges)} cycle edges detected. "
                    f"Convergence indicators: {conv_str}. "
                    f"Pattern: iterate -> solve -> check -> repeat."
                ),
                domain=domain,
            ))

        return results

    def _order_scc_nodes(
        self,
        scc: list[str],
        adjacency: dict[str, list[str]],
    ) -> list[str]:
        """Heuristically order nodes within an SCC for display.

        Strategy: break one back-edge (the one connecting the last node
        back to the first in a DFS traversal), then topologically sort
        the resulting DAG fragment.
        """
        scc_set = set(scc)
        if len(scc) <= 2:
            return list(scc)

        # Simple BFS ordering from the node with most outgoing edges in SCC
        out_count = {
            n: sum(1 for c in adjacency.get(n, []) if c in scc_set)
            for n in scc
        }
        start = max(scc, key=lambda n: out_count.get(n, 0))

        visited: list[str] = []
        seen: set[str] = set()
        queue = [start]
        seen.add(start)
        while queue:
            node = queue.pop(0)
            visited.append(node)
            for callee in adjacency.get(node, []):
                if callee in scc_set and callee not in seen:
                    seen.add(callee)
                    queue.append(callee)

        # Any remaining (shouldn't happen but safety)
        for n in scc:
            if n not in seen:
                visited.append(n)

        return visited

    def _detect_iterative_keyword_fallback(
        self,
        adjacency: dict[str, list[str]],
        func_algo_map: dict[str, list[dict]],
        solver_funcs: set[str],
        convergence_funcs: set[str],
        already_covered: set[str],
    ) -> list[AlgorithmComposition]:
        """Keyword-based fallback for iterative patterns not in any SCC.

        Handles cases where the call graph doesn't show an explicit cycle
        but function names strongly suggest iterative behavior (e.g., the
        loop is inside one function that calls solver + convergence check).
        """
        results: list[AlgorithmComposition] = []

        # Build reverse adjacency
        reverse_adj: dict[str, set[str]] = defaultdict(set)
        for caller, callees in adjacency.items():
            for callee in callees:
                reverse_adj[callee].add(caller)

        for sfunc in solver_funcs:
            if sfunc in already_covered:
                continue

            callee_set: set[str] = set(adjacency.get(sfunc, []))
            callers = reverse_adj.get(sfunc, set())
            neighborhood = callee_set | callers
            conv_neighbors = neighborhood & convergence_funcs

            if not conv_neighbors:
                continue

            stages: list[CompositionStage] = []
            involved_funcs = {sfunc} | conv_neighbors

            # Find parent loop function
            parent_func = None
            for candidate in callers:
                candidate_callees = set(adjacency.get(candidate, []))
                if sfunc in candidate_callees and conv_neighbors & candidate_callees:
                    parent_func = candidate
                    involved_funcs.add(parent_func)
                    break

            order = 0
            if parent_func:
                algos_p = func_algo_map.get(parent_func, [])
                stages.append(CompositionStage(
                    name=self._clean_func_name(parent_func),
                    functions=[parent_func],
                    algorithms=[a.get("name", "") for a in algos_p],
                    order=order,
                    confidence=0.55,
                ))
                order += 1

            solver_algos = func_algo_map.get(sfunc, [])
            stages.append(CompositionStage(
                name=self._clean_func_name(sfunc),
                functions=[sfunc],
                algorithms=[a.get("name", "") for a in solver_algos],
                order=order,
                confidence=0.65 if solver_algos else 0.45,
            ))
            order += 1

            for cfunc in sorted(conv_neighbors):
                calgos = func_algo_map.get(cfunc, [])
                stages.append(CompositionStage(
                    name=self._clean_func_name(cfunc),
                    functions=[cfunc],
                    algorithms=[a.get("name", "") for a in calgos],
                    order=order,
                    confidence=0.5,
                ))
                order += 1

            if len(stages) < _MIN_COMPOSITION_SIZE:
                continue

            domain = self._infer_domain(
                [a for f in involved_funcs for a in func_algo_map.get(f, [])]
            )
            overall_conf = sum(s.confidence for s in stages) / len(stages)
            # Keyword-only gets lower cap than SCC-based
            overall_conf = min(0.80, overall_conf)

            results.append(AlgorithmComposition(
                name=f"Iterative {self._clean_func_name(sfunc)} Loop",
                pattern="iterative",
                stages=stages,
                total_functions=len(involved_funcs),
                confidence=round(overall_conf, 4),
                description=(
                    f"Keyword-based iterative pattern (no SCC cycle detected): "
                    f"{sfunc} is near convergence functions "
                    f"({', '.join(sorted(conv_neighbors)[:3])}). "
                    f"Pattern: solve -> check convergence -> repeat."
                ),
                domain=domain,
            ))

        return results

    # ------------------------------------------------------------------
    # Fork-join detection
    # ------------------------------------------------------------------

    def _detect_fork_join(
        self,
        adjacency: dict[str, list[str]],
        func_algo_map: dict[str, list[dict]],
    ) -> list[AlgorithmComposition]:
        """Detect fork-join patterns using dominator / post-dominator analysis.

        Strategy:
        1. Build dominator tree -- fork point = node that dominates 2+ branches.
        2. Build post-dominator tree (reverse graph) -- join point = node that
           post-dominates the same branches.
        3. Also fall back to simple intersection for cases where dominator
           analysis is too expensive or inconclusive.
        4. Look for dispatch/thread indicators (GCD, pthread, NSOperation).
        """
        results: list[AlgorithmComposition] = []
        algo_funcs = set(func_algo_map.keys())

        # Build reverse adjacency
        reverse_adj: dict[str, list[str]] = defaultdict(list)
        for caller, callees in adjacency.items():
            for callee in callees:
                reverse_adj[callee].append(caller)

        # Dispatch/thread indicators boost confidence
        parallel_keywords = {
            "dispatch", "gcd", "pthread", "thread", "nsoperation",
            "concurrent", "parallel", "fork", "spawn", "async",
            "semaphore", "barrier", "omp_", "openmp",
        }

        # --- Phase 1: Dominator-based fork-join ---
        # Build dominator tree for algo-bearing subgraph
        # Entry points: algo-bearing nodes with zero in-degree from other algo nodes
        algo_adj: dict[str, list[str]] = {}
        algo_in_degree: dict[str, int] = {f: 0 for f in algo_funcs}
        for f in algo_funcs:
            callees = [c for c in adjacency.get(f, []) if c in algo_funcs and c != f]
            algo_adj[f] = callees
            for c in callees:
                algo_in_degree[c] = algo_in_degree.get(c, 0) + 1

        entry_points = [f for f in algo_funcs if algo_in_degree.get(f, 0) == 0]
        if not entry_points:
            # No clear entries -- use nodes with highest out-degree
            entry_points = sorted(
                algo_funcs,
                key=lambda f: len(algo_adj.get(f, [])),
                reverse=True,
            )[:3]

        # Compute dominators for each entry point (simplified Cooper et al.)
        for entry in entry_points:
            dom_tree = self._compute_dominators(entry, algo_adj, algo_funcs)
            if not dom_tree:
                continue

            # Find fork points: nodes in dominator tree with 2+ children
            dom_children: dict[str, list[str]] = defaultdict(list)
            for node, idom in dom_tree.items():
                if idom is not None:
                    dom_children[idom].append(node)

            for fork_func, children in dom_children.items():
                if len(children) < 2:
                    continue

                # Check for join point: compute post-dominators (reverse graph)
                # For efficiency, just check if children share a common callee
                child_descendants: dict[str, set[str]] = {}
                for child in children:
                    desc = self._bfs_reachable(child, algo_adj, max_depth=5)
                    child_descendants[child] = desc

                # Join = intersection of all children's descendants
                if children:
                    common_desc = child_descendants.get(children[0], set()).copy()
                    for child in children[1:]:
                        common_desc &= child_descendants.get(child, set())

                    # Remove the fork itself and branches from join candidates
                    common_desc -= {fork_func}
                    common_desc -= set(children)

                join_funcs = common_desc if common_desc else set()

                # Check parallel indicators
                has_parallel = any(
                    any(kw in fork_func.lower() for kw in parallel_keywords)
                    for _ in [None]
                ) or any(
                    any(kw in c.lower() for kw in parallel_keywords)
                    for c in children
                )

                comp = self._build_fork_join_composition(
                    fork_func, children, join_funcs,
                    func_algo_map, algo_funcs, has_parallel,
                    method="dominator",
                )
                if comp is not None:
                    results.append(comp)

        # --- Phase 2: Simple intersection fallback ---
        # For nodes not covered by dominator analysis
        covered_forks: set[str] = set()
        for comp in results:
            for stage in comp.stages:
                if stage.name.startswith("Fork"):
                    covered_forks.update(stage.functions)

        for fork_func, callees in adjacency.items():
            if fork_func in covered_forks:
                continue

            algo_callees = [c for c in callees if c in algo_funcs]
            if len(algo_callees) < 2:
                continue

            # Find common children
            callee_children: dict[str, set[str]] = {}
            for ac in algo_callees:
                callee_children[ac] = set(adjacency.get(ac, []))

            common = callee_children.get(algo_callees[0], set()).copy()
            for ac in algo_callees[1:]:
                common &= callee_children.get(ac, set())

            join_funcs = common & algo_funcs
            if not join_funcs and common:
                join_funcs = common

            if not join_funcs:
                continue

            has_parallel = any(
                any(kw in fork_func.lower() for kw in parallel_keywords)
                for _ in [None]
            )

            comp = self._build_fork_join_composition(
                fork_func, algo_callees, join_funcs,
                func_algo_map, algo_funcs, has_parallel,
                method="intersection",
            )
            if comp is not None:
                results.append(comp)

        return results

    def _compute_dominators(
        self,
        entry: str,
        adjacency: dict[str, list[str]],
        all_nodes: set[str],
    ) -> dict[str, str | None]:
        """Compute immediate dominators using iterative dataflow (Cooper et al.).

        Returns dict mapping each reachable node to its immediate dominator.
        Entry node maps to None.
        """
        # BFS to find reachable nodes and their reverse postorder
        reachable: list[str] = []
        visited: set[str] = set()
        rpo_order: list[str] = []

        # DFS post-order
        stack: list[tuple[str, bool]] = [(entry, False)]
        while stack:
            node, processed = stack.pop()
            if processed:
                rpo_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for callee in adjacency.get(node, []):
                if callee in all_nodes and callee not in visited:
                    stack.append((callee, False))

        rpo_order.reverse()  # reverse post-order

        if len(rpo_order) < 2:
            return {}

        # Node index in RPO
        rpo_idx = {n: i for i, n in enumerate(rpo_order)}

        # Build predecessors (within reachable set)
        preds: dict[str, list[str]] = defaultdict(list)
        for node in rpo_order:
            for callee in adjacency.get(node, []):
                if callee in rpo_idx:
                    preds[callee].append(node)

        # Initialize dominators
        doms: dict[str, int] = {entry: 0}  # maps to RPO index of dominator

        def intersect(b1: int, b2: int) -> int:
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while finger1 > finger2:
                    finger1 = doms.get(rpo_order[finger1], finger1)
                    if rpo_order[finger1] not in doms:
                        return min(finger1, finger2)
                while finger2 > finger1:
                    finger2 = doms.get(rpo_order[finger2], finger2)
                    if rpo_order[finger2] not in doms:
                        return min(finger1, finger2)
            return finger1

        changed = True
        max_iters = 50  # Safety cap
        iteration = 0
        while changed and iteration < max_iters:
            changed = False
            iteration += 1
            for node in rpo_order[1:]:  # skip entry
                node_preds = [p for p in preds.get(node, []) if p in doms]
                if not node_preds:
                    continue

                new_idom = rpo_idx[node_preds[0]]
                for p in node_preds[1:]:
                    new_idom = intersect(new_idom, rpo_idx[p])

                if doms.get(node) != new_idom:
                    doms[node] = new_idom
                    changed = True

        # Convert to {node: immediate_dominator_name}
        result: dict[str, str | None] = {entry: None}
        for node in rpo_order[1:]:
            if node in doms:
                result[node] = rpo_order[doms[node]]

        return result

    def _bfs_reachable(
        self,
        start: str,
        adjacency: dict[str, list[str]],
        max_depth: int = 5,
    ) -> set[str]:
        """BFS to find nodes reachable from start within max_depth steps."""
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start, 0)]
        visited.add(start)
        while queue:
            node, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for callee in adjacency.get(node, []):
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, depth + 1))
        visited.discard(start)  # Don't include start itself
        return visited

    def _build_fork_join_composition(
        self,
        fork_func: str,
        branches: list[str],
        join_funcs: set[str],
        func_algo_map: dict[str, list[dict]],
        algo_funcs: set[str],
        has_parallel: bool,
        method: str = "dominator",
    ) -> AlgorithmComposition | None:
        """Build a fork-join composition from fork, branches, and join points."""
        stages: list[CompositionStage] = []
        order = 0

        # Fork node
        fork_algos = func_algo_map.get(fork_func, [])
        fork_conf = 0.65
        if has_parallel:
            fork_conf = 0.75
        stages.append(CompositionStage(
            name=f"Fork: {self._clean_func_name(fork_func)}",
            functions=[fork_func],
            algorithms=[a.get("name", "") for a in fork_algos],
            order=order,
            confidence=fork_conf,
        ))
        order += 1

        # Parallel branches (cap at 5)
        for ac in branches[:5]:
            ac_algos = func_algo_map.get(ac, [])
            branch_conf = 0.55 if not ac_algos else 0.70
            if has_parallel:
                branch_conf += 0.05
            stages.append(CompositionStage(
                name=f"Branch: {self._clean_func_name(ac)}",
                functions=[ac],
                algorithms=[a.get("name", "") for a in ac_algos],
                order=order,
                confidence=min(0.90, branch_conf),
            ))
            order += 1

        # Join node(s)
        for jf in sorted(join_funcs)[:2]:
            jf_algos = func_algo_map.get(jf, [])
            stages.append(CompositionStage(
                name=f"Join: {self._clean_func_name(jf)}",
                functions=[jf],
                algorithms=[a.get("name", "") for a in jf_algos],
                order=order,
                confidence=0.60,
            ))
            order += 1

        if len(stages) < 3:
            return None

        domain = self._infer_domain(
            [a for s in stages for f in s.functions
             for a in func_algo_map.get(f, [])]
        )
        overall_conf = sum(s.confidence for s in stages) / len(stages)
        # Dominator-based detection gets higher confidence cap
        conf_cap = 0.88 if method == "dominator" else 0.82

        return AlgorithmComposition(
            name=f"Fork-Join at {self._clean_func_name(fork_func)}",
            pattern="fork_join",
            stages=stages,
            total_functions=sum(len(s.functions) for s in stages),
            confidence=round(min(conf_cap, overall_conf), 4),
            description=(
                f"Fork-join pattern ({method}): {fork_func} dispatches to "
                f"{len(branches)} branches"
                f"{' (parallel indicators detected)' if has_parallel else ''}, "
                f"merging at {', '.join(sorted(join_funcs)[:3]) or 'inferred join'}."
            ),
            domain=domain,
        )

    # ------------------------------------------------------------------
    # Producer-consumer detection
    # ------------------------------------------------------------------

    def _detect_producer_consumer(
        self,
        data_flow: dict,
        func_algo_map: dict[str, list[dict]],
    ) -> list[AlgorithmComposition]:
        """Detect producer-consumer patterns from data flow graph.

        Three detection strategies:
        1. Data object lifecycle: explicit producer/consumer roles.
        2. Write/read frequency: functions that predominantly write vs read
           on the same struct field or global buffer.
        3. Shared buffer pattern: allocation -> fill -> use -> free chain
           mediated through a struct/global.
        """
        results: list[AlgorithmComposition] = []

        # --- Extract data flow information ---
        data_objects: list[dict] = []
        edges: list[dict] = []

        if hasattr(data_flow, "graph"):
            graph = data_flow.graph
            if hasattr(graph, "data_objects"):
                data_objects = [
                    {"name": k, "lifecycle": v}
                    for k, v in graph.data_objects.items()
                ]
            if hasattr(graph, "edges"):
                for e in graph.edges:
                    if hasattr(e, "source_func"):
                        edges.append({
                            "from_func": e.source_func,
                            "to_func": e.target_func,
                            "data_type": getattr(e, "data_type", ""),
                            "pattern": getattr(e, "pattern", ""),
                        })
                    elif isinstance(e, dict):
                        edges.append(e)
        elif isinstance(data_flow, dict):
            data_objects = data_flow.get("data_objects", [])
            edges = data_flow.get("edges", [])

        algo_funcs = set(func_algo_map.keys())

        # --- Strategy 1: Data object lifecycle ---
        lifecycle_comps = self._pc_from_lifecycle(
            data_objects, func_algo_map, algo_funcs,
        )
        results.extend(lifecycle_comps)

        # --- Strategy 2: Write/read frequency from edges ---
        freq_comps = self._pc_from_edge_frequency(
            edges, func_algo_map, algo_funcs,
        )
        results.extend(freq_comps)

        # --- Strategy 3: Shared buffer pattern from edges ---
        buffer_comps = self._pc_from_shared_buffer(
            edges, data_objects, func_algo_map, algo_funcs,
        )
        results.extend(buffer_comps)

        return results

    def _pc_from_lifecycle(
        self,
        data_objects: list[dict],
        func_algo_map: dict[str, list[dict]],
        algo_funcs: set[str],
    ) -> list[AlgorithmComposition]:
        """Producer-consumer from explicit lifecycle roles."""
        results: list[AlgorithmComposition] = []

        for dobj in data_objects:
            if not isinstance(dobj, dict):
                continue
            lifecycle = dobj.get("lifecycle", [])
            if len(lifecycle) < 2:
                continue

            producers: list[dict] = []
            consumers: list[dict] = []
            for entry in lifecycle:
                if isinstance(entry, str):
                    # lifecycle bazen str listesi olabiliyor, atla
                    continue
                if not isinstance(entry, dict):
                    continue
                role = entry.get("role", "")
                if role in ("allocator", "creator", "writer", "producer"):
                    producers.append(entry)
                elif role in ("consumer", "reader", "user"):
                    consumers.append(entry)

            if not producers or not consumers:
                continue

            producer_with_algo = any(
                p.get("function", "") in algo_funcs for p in producers
            )
            consumer_with_algo = any(
                c.get("function", "") in algo_funcs for c in consumers
            )
            if not (producer_with_algo or consumer_with_algo):
                continue

            stages: list[CompositionStage] = []
            order = 0
            all_funcs: set[str] = set()

            for p in producers:
                fname = p.get("function", "")
                if not fname or fname in all_funcs:
                    continue
                palgos = func_algo_map.get(fname, [])
                stages.append(CompositionStage(
                    name=f"Producer: {self._clean_func_name(fname)}",
                    functions=[fname],
                    algorithms=[a.get("name", "") for a in palgos],
                    order=order,
                    confidence=0.65 if palgos else 0.45,
                ))
                all_funcs.add(fname)
                order += 1

            for c in consumers:
                fname = c.get("function", "")
                if not fname or fname in all_funcs:
                    continue
                calgos = func_algo_map.get(fname, [])
                stages.append(CompositionStage(
                    name=f"Consumer: {self._clean_func_name(fname)}",
                    functions=[fname],
                    algorithms=[a.get("name", "") for a in calgos],
                    order=order,
                    confidence=0.65 if calgos else 0.45,
                ))
                all_funcs.add(fname)
                order += 1

            if len(stages) < _MIN_COMPOSITION_SIZE:
                continue

            data_name = dobj.get("name", "unknown_data")
            domain = self._infer_domain(
                [a for f in all_funcs for a in func_algo_map.get(f, [])]
            )
            overall_conf = sum(s.confidence for s in stages) / len(stages)

            results.append(AlgorithmComposition(
                name=f"Producer-Consumer: {data_name}",
                pattern="producer_consumer",
                stages=stages,
                total_functions=len(all_funcs),
                confidence=round(min(0.85, overall_conf), 4),
                description=(
                    f"Data object '{data_name}' is produced by "
                    f"{', '.join(p.get('function', '') for p in producers[:3])} "
                    f"and consumed by "
                    f"{', '.join(c.get('function', '') for c in consumers[:3])}."
                ),
                domain=domain,
            ))

        return results

    def _pc_from_edge_frequency(
        self,
        edges: list[dict],
        func_algo_map: dict[str, list[dict]],
        algo_funcs: set[str],
    ) -> list[AlgorithmComposition]:
        """Detect producer-consumer from data flow edge write/read frequency.

        A function that appears predominantly as edge source (writer) paired
        with a function that appears predominantly as edge target (reader)
        on the same data type suggests a producer-consumer relationship.
        """
        results: list[AlgorithmComposition] = []

        if not edges:
            return results

        # Count per-function write (source) and read (target) frequency
        write_count: dict[str, int] = defaultdict(int)
        read_count: dict[str, int] = defaultdict(int)
        # Track which data types flow between functions
        func_pair_data: dict[tuple[str, str], list[str]] = defaultdict(list)

        for edge in edges:
            src = edge.get("from_func", "")
            tgt = edge.get("to_func", "")
            dtype = edge.get("data_type", edge.get("pattern", ""))
            if src and tgt and src != tgt:
                write_count[src] += 1
                read_count[tgt] += 1
                func_pair_data[(src, tgt)].append(dtype)

        # Find dominant writers and readers
        # A "producer" writes 2x+ more than it reads
        # A "consumer" reads 2x+ more than it writes
        producers: set[str] = set()
        consumers: set[str] = set()
        for func in set(write_count.keys()) | set(read_count.keys()):
            w = write_count.get(func, 0)
            r = read_count.get(func, 0)
            if w >= 2 and w >= 2 * r:
                producers.add(func)
            if r >= 2 and r >= 2 * w:
                consumers.add(func)

        # Only consider algo-bearing pairs
        algo_producers = producers & algo_funcs
        algo_consumers = consumers & algo_funcs

        if not algo_producers or not algo_consumers:
            return results

        # Build compositions from connected producer-consumer pairs
        seen_pairs: set[tuple[str, str]] = set()
        for prod in sorted(algo_producers):
            for cons in sorted(algo_consumers):
                if (prod, cons) in seen_pairs:
                    continue
                # Check if there's a direct data flow edge
                data_types = func_pair_data.get((prod, cons), [])
                if not data_types:
                    continue

                seen_pairs.add((prod, cons))

                prod_algos = func_algo_map.get(prod, [])
                cons_algos = func_algo_map.get(cons, [])

                stages = [
                    CompositionStage(
                        name=f"Producer: {self._clean_func_name(prod)}",
                        functions=[prod],
                        algorithms=[a.get("name", "") for a in prod_algos],
                        order=0,
                        confidence=0.60,
                    ),
                    CompositionStage(
                        name=f"Consumer: {self._clean_func_name(cons)}",
                        functions=[cons],
                        algorithms=[a.get("name", "") for a in cons_algos],
                        order=1,
                        confidence=0.60,
                    ),
                ]

                domain = self._infer_domain(prod_algos + cons_algos)
                dtype_str = ", ".join(list(set(data_types))[:3]) or "data"

                results.append(AlgorithmComposition(
                    name=f"Producer-Consumer: {self._clean_func_name(prod)} -> {self._clean_func_name(cons)}",
                    pattern="producer_consumer",
                    stages=stages,
                    total_functions=2,
                    confidence=0.60,
                    description=(
                        f"Write/read frequency analysis: {prod} predominantly writes "
                        f"({write_count[prod]}w/{read_count.get(prod, 0)}r), "
                        f"{cons} predominantly reads "
                        f"({read_count[cons]}r/{write_count.get(cons, 0)}w). "
                        f"Data types: {dtype_str}."
                    ),
                    domain=domain,
                ))

        return results

    def _pc_from_shared_buffer(
        self,
        edges: list[dict],
        data_objects: list[dict],
        func_algo_map: dict[str, list[dict]],
        algo_funcs: set[str],
    ) -> list[AlgorithmComposition]:
        """Detect producer-consumer via shared buffer/queue pattern.

        Looks for allocation chains: alloc -> fill -> use -> free
        where the buffer mediates between algorithm-bearing functions.
        Also detects struct field mediation patterns.
        """
        results: list[AlgorithmComposition] = []

        # Detect struct field mediation from edges
        # Pattern: A writes to field X, B reads from field X
        struct_writers: dict[str, list[str]] = defaultdict(list)  # field -> [writers]
        struct_readers: dict[str, list[str]] = defaultdict(list)  # field -> [readers]

        for edge in edges:
            pattern = edge.get("pattern", "")
            src = edge.get("from_func", "")
            tgt = edge.get("to_func", "")
            data_type = edge.get("data_type", "")

            if "struct" in pattern.lower() or "field" in pattern.lower():
                field_name = data_type or pattern
                if src:
                    struct_writers[field_name].append(src)
                if tgt:
                    struct_readers[field_name].append(tgt)

        # Find fields where writers and readers are different algo-bearing functions
        for field_name in struct_writers:
            writers = set(struct_writers[field_name]) & algo_funcs
            readers = set(struct_readers.get(field_name, [])) & algo_funcs
            # Remove overlap (same function both writes and reads = not PC)
            pure_writers = writers - readers
            pure_readers = readers - writers

            if not pure_writers or not pure_readers:
                continue

            stages: list[CompositionStage] = []
            order = 0
            all_funcs: set[str] = set()

            for w in sorted(pure_writers)[:3]:
                walgos = func_algo_map.get(w, [])
                stages.append(CompositionStage(
                    name=f"Producer: {self._clean_func_name(w)}",
                    functions=[w],
                    algorithms=[a.get("name", "") for a in walgos],
                    order=order,
                    confidence=0.55,
                ))
                all_funcs.add(w)
                order += 1

            for r in sorted(pure_readers)[:3]:
                ralgos = func_algo_map.get(r, [])
                stages.append(CompositionStage(
                    name=f"Consumer: {self._clean_func_name(r)}",
                    functions=[r],
                    algorithms=[a.get("name", "") for a in ralgos],
                    order=order,
                    confidence=0.55,
                ))
                all_funcs.add(r)
                order += 1

            if len(stages) < _MIN_COMPOSITION_SIZE:
                continue

            domain = self._infer_domain(
                [a for f in all_funcs for a in func_algo_map.get(f, [])]
            )
            overall_conf = sum(s.confidence for s in stages) / len(stages)

            results.append(AlgorithmComposition(
                name=f"Shared Buffer: {field_name}",
                pattern="producer_consumer",
                stages=stages,
                total_functions=len(all_funcs),
                confidence=round(min(0.78, overall_conf), 4),
                description=(
                    f"Struct field mediation: '{field_name}' is written by "
                    f"{', '.join(sorted(pure_writers)[:3])} and read by "
                    f"{', '.join(sorted(pure_readers)[:3])}."
                ),
                domain=domain,
            ))

        return results

    # ------------------------------------------------------------------
    # Mermaid rendering
    # ------------------------------------------------------------------

    def _render_mermaid(self, comp: AlgorithmComposition) -> str:
        """Render a composition as a Mermaid flowchart."""
        lines: list[str] = []

        if comp.pattern in ("pipeline", "protocol_sequence"):
            lines.append("graph LR")
            prev_id = None
            for stage in comp.stages:
                sid = f"S{stage.order}"
                label = stage.name
                if stage.algorithms:
                    label += f"\\n({', '.join(stage.algorithms[:2])})"
                lines.append(f"    {sid}[{label}]")
                if prev_id is not None:
                    lines.append(f"    {prev_id} --> {sid}")
                prev_id = sid

        elif comp.pattern == "iterative":
            lines.append("graph TD")
            # First stage at top, loop back from last to solver
            for stage in comp.stages:
                sid = f"S{stage.order}"
                label = stage.name
                if stage.algorithms:
                    label += f"\\n({', '.join(stage.algorithms[:2])})"
                lines.append(f"    {sid}[{label}]")

            # Sequential edges
            for i in range(len(comp.stages) - 1):
                lines.append(f"    S{i} --> S{i+1}")

            # Loop back edge from convergence to solver
            if len(comp.stages) >= 2:
                last_idx = len(comp.stages) - 1
                solver_idx = 1 if len(comp.stages) > 2 else 0
                lines.append(
                    f"    S{last_idx} -->|not converged| S{solver_idx}"
                )

        elif comp.pattern == "fork_join":
            lines.append("graph TD")
            # Fork at top, branches in middle, join at bottom
            fork_stages = [s for s in comp.stages if s.name.startswith("Fork")]
            branch_stages = [s for s in comp.stages if s.name.startswith("Branch")]
            join_stages = [s for s in comp.stages if s.name.startswith("Join")]

            for stage in comp.stages:
                sid = f"S{stage.order}"
                label = stage.name.split(": ", 1)[-1] if ": " in stage.name else stage.name
                if stage.algorithms:
                    label += f"\\n({', '.join(stage.algorithms[:2])})"
                lines.append(f"    {sid}[{label}]")

            # Fork -> branches
            for fs in fork_stages:
                for bs in branch_stages:
                    lines.append(f"    S{fs.order} --> S{bs.order}")

            # Branches -> join
            for bs in branch_stages:
                for js in join_stages:
                    lines.append(f"    S{bs.order} --> S{js.order}")

        elif comp.pattern == "producer_consumer":
            lines.append("graph LR")
            producers = [s for s in comp.stages if "Producer" in s.name]
            consumers = [s for s in comp.stages if "Consumer" in s.name]

            for stage in comp.stages:
                sid = f"S{stage.order}"
                label = stage.name.split(": ", 1)[-1] if ": " in stage.name else stage.name
                if stage.algorithms:
                    label += f"\\n({', '.join(stage.algorithms[:2])})"
                lines.append(f"    {sid}[{label}]")

            for p in producers:
                for c in consumers:
                    lines.append(f"    S{p.order} -->|data| S{c.order}")

        else:
            # Fallback: sequential
            lines.append("graph LR")
            for stage in comp.stages:
                sid = f"S{stage.order}"
                lines.append(f"    {sid}[{stage.name}]")
            for i in range(len(comp.stages) - 1):
                lines.append(f"    S{i} --> S{i+1}")

        return "\n".join(lines) if lines else ""

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _normalize_algorithms(
        self,
        algorithms: list[AlgorithmMatch] | list[dict],
    ) -> list[dict]:
        """Convert AlgorithmMatch objects to dicts if needed."""
        result: list[dict] = []
        for a in algorithms:
            if isinstance(a, dict):
                # ``algorithms.json`` fonksiyonu ``function`` anahtarıyla
                # yazar; ürün nesne geçirir (``function_name``). Kayıtlı
                # yapıttan yeniden oynatma ürünle aynı haritayı kursun.
                if not a.get("function_name") and a.get("function"):
                    a = {**a, "function_name": a["function"]}
                result.append(a)
            elif hasattr(a, "name"):
                result.append({
                    "name": a.name,
                    "category": getattr(a, "category", ""),
                    "confidence": getattr(a, "confidence", 0.5),
                    "function_name": getattr(a, "function_name", ""),
                    "address": getattr(a, "address", ""),
                    "detection_method": getattr(a, "detection_method", ""),
                    "evidence": getattr(a, "evidence", []),
                })
            else:
                result.append({"name": str(a)})
        return result

    def _build_func_algo_map(
        self, algo_dicts: list[dict],
    ) -> dict[str, list[dict]]:
        """Map function_name -> list of algorithm dicts."""
        mapping: dict[str, list[dict]] = defaultdict(list)
        for a in algo_dicts:
            fname = a.get("function_name", "")
            if fname:
                mapping[fname].append(a)
        return dict(mapping)

    def _build_adjacency(
        self, call_graph: dict,
    ) -> dict[str, list[str]]:
        """Build adjacency list from call graph nodes.

        Handles both original Ghidra format and augmented format.
        """
        adjacency: dict[str, list[str]] = defaultdict(list)

        nodes = call_graph.get("nodes", {})
        for addr, info in nodes.items():
            caller = info.get("name", "")
            if not caller:
                continue
            for callee_info in info.get("callees", []):
                callee_name = callee_info.get("name", "")
                if callee_name:
                    adjacency[caller].append(callee_name)

        # Also include virtual edges from augmented graph
        for vedge in call_graph.get("virtual_edges", []):
            from_name = vedge.get("from_name", "")
            to_name = vedge.get("to_name", "")
            if from_name and to_name:
                adjacency[from_name].append(to_name)

        # Deduplicate
        return {k: list(dict.fromkeys(v)) for k, v in adjacency.items()}

    def _check_data_flow_chain(
        self,
        chain: list[str] | tuple[str, ...],
        data_flow: dict,
    ) -> float:
        """Check how well data flow confirms a function chain.

        Returns a bonus score 0.0 - 1.0.
        """
        # data_flow DataFlowResult dataclass veya dict olabilir
        if hasattr(data_flow, "graph") and hasattr(data_flow.graph, "edges"):
            edges = data_flow.graph.edges
        elif isinstance(data_flow, dict):
            edges = data_flow.get("edges", [])
        else:
            return 0.0
        chain_set = set(chain)
        chain_pairs = {
            (chain[i], chain[i + 1])
            for i in range(len(chain) - 1)
        }

        confirmed = 0
        for edge in edges:
            if hasattr(edge, "source_func"):
                pair = (edge.source_func, edge.target_func)
            elif isinstance(edge, dict):
                pair = (edge.get("from_func", ""), edge.get("to_func", ""))
            else:
                continue
            if pair in chain_pairs:
                confirmed += 1

        if not chain_pairs:
            return 0.0
        return confirmed / len(chain_pairs)

    def _infer_domain(self, algo_dicts: list[dict]) -> str:
        """Infer dominant domain from a collection of algorithm dicts."""
        if not algo_dicts:
            return "generic"

        domain_counts: dict[str, int] = defaultdict(int)
        for a in algo_dicts:
            category = a.get("category", "")
            domain = _CATEGORY_TO_DOMAIN.get(category, "generic")
            domain_counts[domain] += 1

        if not domain_counts:
            return "generic"
        return max(domain_counts, key=domain_counts.get)  # type: ignore[arg-type]

    def _clean_func_name(self, name: str) -> str:
        """Clean up a function name for display.

        Strips leading underscores and common prefixes.
        """
        # Remove leading underscores (Ghidra convention)
        clean = name.lstrip("_")
        # Remove common Obj-C prefixes
        for prefix in ("-[", "+["):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
                if clean.endswith("]"):
                    clean = clean[:-1]
                break
        return clean or name

    def _name_from_chain(self, chain: list[str] | tuple[str, ...]) -> str:
        """Generate a composition name from a chain of function names."""
        if not chain:
            return "Unknown Pipeline"

        # Try to find common substring
        cleaned = [self._clean_func_name(f) for f in chain]

        # Use the first and last names
        first = cleaned[0]
        last = cleaned[-1]

        # Find common prefix among all names
        if len(cleaned) >= 2:
            prefix = _common_prefix(cleaned)
            if len(prefix) >= 3:
                return f"{prefix.rstrip('_')} Pipeline"

        if len(chain) <= 3:
            return f"{first} -> {last} Pipeline"
        return f"{first} ... {last} Pipeline ({len(chain)} stages)"

    def _deduplicate(
        self,
        compositions: list[AlgorithmComposition],
    ) -> list[AlgorithmComposition]:
        """Remove compositions with highly overlapping function sets.

        Overlap thresholds:
        - Same pattern type: Jaccard > 0.70 -> drop lower-confidence one.
        - Different pattern types: kept regardless (different structural info).
        """
        if len(compositions) <= 1:
            return compositions

        # Extract function sets
        func_sets: list[set[str]] = []
        for comp in compositions:
            funcs: set[str] = set()
            for stage in comp.stages:
                funcs.update(stage.functions)
            func_sets.append(funcs)

        keep: list[bool] = [True] * len(compositions)

        for i in range(len(compositions)):
            if not keep[i]:
                continue
            for j in range(i + 1, len(compositions)):
                if not keep[j]:
                    continue
                # Compute Jaccard overlap
                si, sj = func_sets[i], func_sets[j]
                if not si or not sj:
                    continue
                overlap = len(si & sj) / len(si | sj)

                # Only deduplicate within the same pattern type.
                # Different patterns (pipeline vs fork_join, iterative vs
                # producer_consumer) convey fundamentally different structural
                # information, so we keep both even with full overlap.
                same_pattern = compositions[i].pattern == compositions[j].pattern
                if not same_pattern:
                    continue

                if overlap > 0.70:
                    if compositions[i].confidence >= compositions[j].confidence:
                        keep[j] = False
                    else:
                        keep[i] = False
                        break

        return [c for c, k in zip(compositions, keep) if k]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _common_prefix(strings: list[str]) -> str:
    """Find the longest common prefix among a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix
