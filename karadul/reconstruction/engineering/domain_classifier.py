"""Bayesian domain siniflandirici.

Her fonksiyonu bir muhendislik alanina atar:
structural, thermal, fluid, finance, ml, dsp, crypto, optimization, generic

Siniflandirma 3 sinyal kaynagini birlestirir:
1. Tespit edilen algoritmalarin kategorisi (en guclu sinyal)
2. Algoritma isimlerinden cikarilan ipuclari
3. Opsiyonel string referanslari (binary'deki string'lerden domain hint'leri)

Bayesian yaklasim:
    P(domain | evidence) propto P(evidence | domain) * P(domain)

Uniform prior kullanilir.  Her evidence source bagimsiz "sensor" gibi
Noisy-OR ile birlestirilir.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch


# -----------------------------------------------------------------------
# Domain dataclasses
# -----------------------------------------------------------------------

@dataclass
class DomainClassification:
    """Tek bir fonksiyonun domain siniflandirmasi.

    Attributes:
        function_name: Siniflandirilan fonksiyon.
        primary_domain: En yuksek skorlu domain.
        domain_scores: Her domain icin normalize edilmis skor (0.0-1.0).
        evidence: Siniflandirma kaniti listesi.
    """
    function_name: str
    primary_domain: str
    domain_scores: dict[str, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "primary_domain": self.primary_domain,
            "domain_scores": self.domain_scores,
            "evidence": self.evidence,
        }


@dataclass
class DomainReport:
    """Tum fonksiyonlarin domain raporu.

    Attributes:
        classifications: Her fonksiyon icin siniflandirma listesi.
        domain_summary: Domain basina fonksiyon sayisi.
        domain_avg_confidence: Domain basina ortalama confidence.
    """
    classifications: list[DomainClassification]
    domain_summary: dict[str, int]
    domain_avg_confidence: dict[str, float]

    def to_dict(self) -> dict:
        return {
            "classifications": [c.to_dict() for c in self.classifications],
            "domain_summary": self.domain_summary,
            "domain_avg_confidence": self.domain_avg_confidence,
        }


# -----------------------------------------------------------------------
# Category -> domain mapping
# -----------------------------------------------------------------------

# Engineering algorithm kategorileri -> domain eslestirmesi.
# Kategoriler ENGINEERING_CONSTANTS/PATTERNS/APIS'daki category degerleriyle
# birebir eslesmelidir.  Crypto kategorileri mevcut CAlgorithmIdentifier
# sonuclariyla uyum icin dahil edilmistir.

CATEGORY_TO_DOMAIN: dict[str, str] = {
    # -- FEA / structural mechanics --
    "fea_integration": "structural",
    "fea_assembly": "structural",
    "fea_element": "structural",
    "fea_dynamics": "structural",
    "fea_contact": "structural",
    "fea_stabilization": "structural",
    "stress_analysis": "structural",
    "iterative_solver": "structural",
    "direct_solver": "structural",
    "linear_algebra": "structural",
    "time_integration": "structural",
    "convergence": "structural",
    "eigenvalue": "structural",
    "sparse_matrix": "structural",
    "numerical_solver": "structural",
    "nonlinear_solver": "structural",
    "finite_element": "structural",
    "distributed_linear_algebra": "structural",
    "gpu_linear_algebra": "structural",
    # -- CFD / fluid dynamics --
    "cfd_turbulence": "fluid",
    "cfd_discretization": "fluid",
    "cfd_solver": "fluid",
    "pde_solver": "fluid",
    # -- Thermal --
    "heat_transfer": "thermal",
    # -- DSP --
    "dsp_transform": "dsp",
    "dsp_filter": "dsp",
    "dsp_window": "dsp",
    "dsp_windowing": "dsp",
    # -- Finance --
    "finance_pricing": "finance",
    "finance_risk": "finance",
    "finance_greeks": "finance",
    "finance": "finance",
    "finance_statistics": "finance",
    "monte_carlo": "finance",
    "stochastic": "finance",
    # -- ML --
    "ml_activation": "ml",
    "ml_optimizer": "ml",
    "ml_optimization": "ml",
    "ml_layer": "ml",
    "ml_transformer": "ml",
    "ml_normalization": "ml",
    "ml_initialization": "ml",
    "ml_regularization": "ml",
    # -- Optimization --
    "optimization_gradient": "optimization",
    "optimization_search": "optimization",
    "optimization": "optimization",
    "root_finding": "optimization",
    # -- Crypto (mevcut dedektorden) --
    "symmetric_cipher": "crypto",
    "hash": "crypto",
    "mac": "crypto",
    "asymmetric": "crypto",
    "kdf": "crypto",
    "checksum": "crypto",
    "random": "crypto",
    "protocol": "crypto",
    "key_management": "crypto",
    # -- Generic / cross-domain --
    "compression": "generic",
    "encoding": "generic",
    "numerical_calculus": "generic",
    "geometry": "generic",
    "math_constant": "generic",
    "physics_constant": "generic",
    "chemistry_constant": "generic",
    "interpolation": "generic",
    "parallel_computing": "generic",
    "gpu_computing": "generic",
    "scientific_io": "generic",
    "graph_algorithm": "generic",
}

# Tum desteklenen domain'ler
ALL_DOMAINS = (
    "structural", "thermal", "fluid", "finance",
    "ml", "dsp", "crypto", "optimization", "generic",
)

# Cross-domain kategoriler: Bu kategoriler birden fazla domain'e ait olabilir.
# Skor tek domain'e degil, ilgili tum domain'lere esit dagitilir.
CROSS_DOMAIN_CATEGORIES: dict[str, list[str]] = {
    "linear_algebra": ["structural", "ml", "optimization"],
    "eigenvalue": ["structural", "ml"],
    "sparse_matrix": ["structural", "ml", "fluid"],
    "iterative_solver": ["structural", "fluid", "optimization"],
}


# -----------------------------------------------------------------------
# String-based domain hints
# -----------------------------------------------------------------------

# Her domain icin string pattern'leri.  Binary'deki string referanslari
# bu pattern'lere karsi taranir.  Kucuk harfe cevrilmis string'ler
# uzerinde arama yapilir.

_STRING_DOMAIN_HINTS: dict[str, list[str]] = {
    "structural": [
        "stress", "strain", "displacement", "stiffness", "element",
        "node", "dof", "beam", "shell", "plate", "truss", "frame",
        "deformation", "modulus", "poisson", "young", "elasticity",
        "plasticity", "yield", "buckling", "modal", "eigenvalue",
        "mass_matrix", "stiffness_matrix", "load_vector", "assembly",
        "boundary_condition", "constraint", "abaqus", "ansys", "nastran",
        "calculix", "fem", "fea",
    ],
    "thermal": [
        "temperature", "heat", "thermal", "conductivity", "convection",
        "radiation", "insulation", "flux", "fourier", "specific_heat",
        "emissivity", "stefan_boltzmann", "nusselt", "prandtl",
        "rayleigh", "boussinesq",
    ],
    "fluid": [
        "velocity", "pressure", "turbulence", "navier", "stokes",
        "reynolds", "viscosity", "density", "incompressible", "compressible",
        "mach", "upwind", "weno", "muscl", "riemann", "flux_limiter",
        "vortex", "vorticity", "boundary_layer", "drag", "lift",
        "openfoam", "fluent", "cfd", "k_epsilon", "k_omega", "sst",
        "les", "rans", "dns", "spalart", "allmaras",
    ],
    "finance": [
        "price", "option", "portfolio", "volatility", "yield",
        "interest", "bond", "derivative", "risk", "var", "cvar",
        "sharpe", "black_scholes", "monte_carlo", "brownian",
        "geometric_brownian", "ito", "payoff", "strike", "expiry",
        "maturity", "greek", "delta", "gamma", "theta", "vega", "rho",
        "quantlib", "bloomberg",
    ],
    "ml": [
        "gradient", "loss", "weight", "batch", "epoch", "learning_rate",
        "backprop", "forward", "backward", "activation", "sigmoid",
        "relu", "softmax", "dropout", "convolution", "pooling",
        "attention", "transformer", "embedding", "optimizer", "adam",
        "sgd", "momentum", "layer_norm", "batch_norm",
        "tensorflow", "pytorch", "caffe", "onnx", "cudnn",
    ],
    "dsp": [
        "frequency", "spectrum", "filter", "sample", "sample_rate",
        "nyquist", "aliasing", "fft", "dft", "ifft", "window",
        "hamming", "hanning", "blackman", "kaiser", "firwin",
        "iir", "fir", "butterworth", "chebyshev", "bessel",
        "bandpass", "lowpass", "highpass", "notch", "resonance",
        "z_transform", "biquad", "decimation", "interpolation",
    ],
    "optimization": [
        "optimize", "minimize", "maximize", "objective", "constraint",
        "lagrange", "penalty", "gradient_descent", "conjugate_gradient",
        "newton_method", "quasi_newton", "bfgs", "lbfgs",
        "simplex", "genetic", "simulated_annealing", "particle_swarm",
        "evolution", "crossover", "mutation", "fitness",
    ],
}

# Pre-compile string hint patterns for efficiency.
# Each entry: (domain, compiled_regex)
_COMPILED_STRING_HINTS: list[tuple[str, re.Pattern]] = []
for _domain, _keywords in _STRING_DOMAIN_HINTS.items():
    # Build a single regex per domain: \b(kw1|kw2|...)\b
    _pattern = re.compile(
        r"\b(" + "|".join(re.escape(k) for k in _keywords) + r")\b",
        re.IGNORECASE,
    )
    _COMPILED_STRING_HINTS.append((_domain, _pattern))


# Algorithm name -> domain hints (kesisim durumlarinda kullanilir)
_ALGO_NAME_DOMAIN_HINTS: dict[str, str] = {
    "gauss": "structural",
    "quadrature": "structural",
    "newton-raphson": "structural",
    "newmark": "structural",
    "hht": "structural",
    "conjugate gradient": "structural",
    "gmres": "structural",
    "bicgstab": "structural",
    "cholesky": "structural",
    "lu decomposition": "structural",
    "eigenvalue": "structural",
    "svd": "structural",
    "sparse": "structural",
    "k-epsilon": "fluid",
    "k-omega": "fluid",
    "sst": "fluid",
    "spalart": "fluid",
    "upwind": "fluid",
    "weno": "fluid",
    "navier": "fluid",
    "black-scholes": "finance",
    "monte carlo": "finance",
    "option pricing": "finance",
    "greeks": "finance",
    "adam": "ml",
    "sgd": "ml",
    "softmax": "ml",
    "relu": "ml",
    "sigmoid": "ml",
    "backprop": "ml",
    "fft": "dsp",
    "convolution": "dsp",
    "fir": "dsp",
    "iir": "dsp",
    "butterworth": "dsp",
    "window function": "dsp",
    "gradient descent": "optimization",
    "simulated annealing": "optimization",
    "runge-kutta": "structural",
    "rk4": "structural",
    "heat transfer": "thermal",
    "fourier": "thermal",
    "conduction": "thermal",
}


# -----------------------------------------------------------------------
# Classifier
# -----------------------------------------------------------------------

class DomainClassifier:
    """Bayesian multi-domain classifier.

    Her fonksiyonu muhendislik alanina atar.  3 sinyal kaynagi:
    1. Tespit edilen algoritmalarin kategorisi (CATEGORY_TO_DOMAIN)
    2. Algoritma isimlerinden cikarilan ipuclari (_ALGO_NAME_DOMAIN_HINTS)
    3. String referanslari (_STRING_DOMAIN_HINTS)
    """

    def classify(
        self,
        algorithms: list[AlgorithmMatch],
        strings: list[str] | None = None,
        binary_hints: dict | None = None,
    ) -> DomainReport:
        """Tum fonksiyonlari siniflandir.

        Args:
            algorithms: Tespit edilen algoritma listesi
                (EngineeringAlgorithmAnalyzer + CAlgorithmIdentifier ciktilari).
            strings: Opsiyonel string referanslari (binary strings dump).
            binary_hints: v1.4.2 Binary-level domain override ipuclari.
                Ornek: {"domain_override": "ml"} -- binary BLAS/ML kutuphanesi.

        Returns:
            DomainReport: Her fonksiyon icin domain siniflandirmasi.
        """
        # v1.4.2: Binary-level domain override
        domain_override = None
        override_bonus = 0.0
        if binary_hints and binary_hints.get("domain_override"):
            domain_override = binary_hints["domain_override"]
            override_bonus = 0.5  # Override domain'e base bonus

        # Group algorithms by function
        func_algos: dict[str, list[AlgorithmMatch]] = defaultdict(list)
        for algo in algorithms:
            func_algos[algo.function_name].append(algo)

        classifications: list[DomainClassification] = []
        for func_name in sorted(func_algos.keys()):
            dc = self._classify_function(
                func_name, func_algos[func_name], strings,
                domain_override=domain_override,
                override_bonus=override_bonus,
            )
            classifications.append(dc)

        # Summary statistics
        domain_summary: dict[str, int] = defaultdict(int)
        domain_conf_sum: dict[str, float] = defaultdict(float)

        for dc in classifications:
            domain_summary[dc.primary_domain] += 1
            # Use the primary domain's score as the confidence for averaging
            conf = dc.domain_scores.get(dc.primary_domain, 0.0)
            domain_conf_sum[dc.primary_domain] += conf

        domain_avg_confidence: dict[str, float] = {}
        for domain, count in domain_summary.items():
            domain_avg_confidence[domain] = round(
                domain_conf_sum[domain] / count, 3
            )

        return DomainReport(
            classifications=classifications,
            domain_summary=dict(domain_summary),
            domain_avg_confidence=domain_avg_confidence,
        )

    def _classify_function(
        self,
        func_name: str,
        func_algos: list[AlgorithmMatch],
        strings: list[str] | None = None,
        domain_override: str | None = None,
        override_bonus: float = 0.0,
    ) -> DomainClassification:
        """Tek bir fonksiyonu siniflandir.

        Bayesian skor hesaplama:
        1. Her algoritma icin category -> domain eslestirmesi
           Confidence aginligi: P(domain) += algo.confidence * weight
        2. Algoritma isimlerinden domain ipuclari (dusuk agirlik: 0.3)
        3. String hint'leri (dusuk agirlik: 0.2)
        4. v1.4.2: Binary-level domain override (crypto suppress + bonus)

        En yuksek skorlu domain secilir.  Tum skorlar normalize edilir.
        """
        # Raw scores per domain
        scores: dict[str, float] = {d: 0.0 for d in ALL_DOMAINS}
        evidence: list[str] = []

        # v1.4.2 Signal 0: Binary-level domain override
        if domain_override and domain_override in ALL_DOMAINS:
            scores[domain_override] += override_bonus
            evidence.append(
                f"binary_override:{domain_override} (bonus={override_bonus:.1f})"
            )

        # Signal 1: Category-based (strongest signal)
        for algo in func_algos:
            weight = algo.confidence  # Direct confidence as weight
            # v1.4.2: Binary-level override varsa crypto skorunu bastir
            if domain_override and CATEGORY_TO_DOMAIN.get(algo.category, "generic") == "crypto":
                weight *= 0.3

            # v1.4.3: Cross-domain kategoriler -- skor birden fazla domain'e dagitilir
            if algo.category in CROSS_DOMAIN_CATEGORIES:
                domains = CROSS_DOMAIN_CATEGORIES[algo.category]
                split_weight = weight / len(domains)
                for d in domains:
                    scores[d] += split_weight
                evidence.append(
                    f"category:{algo.category}->cross{domains} "
                    f"(conf={algo.confidence:.2f}, split={split_weight:.2f}, algo={algo.name})"
                )
            else:
                domain = CATEGORY_TO_DOMAIN.get(algo.category, "generic")
                scores[domain] += weight
                evidence.append(
                    f"category:{algo.category}->{domain} "
                    f"(conf={algo.confidence:.2f}, algo={algo.name})"
                )

        # Signal 2: Algorithm name hints (medium signal, 0.3 weight)
        for algo in func_algos:
            algo_lower = algo.name.lower()
            for hint_key, hint_domain in _ALGO_NAME_DOMAIN_HINTS.items():
                if hint_key in algo_lower:
                    scores[hint_domain] += 0.3 * algo.confidence
                    evidence.append(
                        f"name_hint:'{hint_key}'->{hint_domain}"
                    )
                    break  # One hint per algorithm is enough

        # Signal 3: String-based hints (weakest signal, 0.2 weight)
        if strings:
            joined = " ".join(strings).lower()
            for domain, pattern in _COMPILED_STRING_HINTS:
                hits = pattern.findall(joined)
                if hits:
                    # Each unique hit adds 0.2 (capped at 1.0)
                    unique_hits = set(h.lower() for h in hits)
                    bonus = min(1.0, 0.2 * len(unique_hits))
                    scores[domain] += bonus
                    sample = list(unique_hits)[:3]
                    evidence.append(
                        f"string_hint:{domain} ({', '.join(sample)})"
                    )

        # Normalize scores
        total = sum(scores.values())
        if total > 0:
            normalized = {d: round(s / total, 4) for d, s in scores.items()}
        else:
            # Hic sinyal yok -> generic
            normalized = {d: (1.0 if d == "generic" else 0.0) for d in ALL_DOMAINS}

        # Primary domain
        primary = max(normalized, key=lambda d: normalized[d])

        # v1.4.3: Binary-level domain override varsa priority tiebreaker'i ATLA.
        # Override zaten kesin sinyal veriyor, priority ile degistirmeye gerek yok.
        if not (domain_override and domain_override in ALL_DOMAINS):
            # Eger iki domain esit veya cok yakinsa (fark < 0.10), birini sec:
            # Tercih sirasi: structural > fluid > thermal > dsp > finance > ml > optimization > crypto > generic
            _PRIORITY = {
                "structural": 9, "fluid": 8, "thermal": 7, "dsp": 6,
                "finance": 5, "ml": 4, "optimization": 3, "crypto": 2, "generic": 1,
            }
            top_score = normalized[primary]
            for d, s in normalized.items():
                if d != primary and abs(s - top_score) < 0.10:
                    if _PRIORITY.get(d, 0) > _PRIORITY.get(primary, 0):
                        primary = d

        # Sadece sifirdan buyuk domain'leri raporla
        filtered_scores = {
            d: s for d, s in normalized.items() if s > 0
        }

        return DomainClassification(
            function_name=func_name,
            primary_domain=primary,
            domain_scores=filtered_scores,
            evidence=evidence[:20],
        )
